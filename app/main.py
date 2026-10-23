import io
import os
import re
import csv
import json
import time
import tempfile
import threading
from typing import Optional
from contextlib import asynccontextmanager
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Request, Response, Depends
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

# Enforce Pakistan Standard Time (PKT / UTC+5) for Python datetime & logging
os.environ["TZ"] = "Asia/Karachi"
if hasattr(time, "tzset"):
    time.tzset()

from app.database import (
    init_db,
    get_connection,
    release_connection,
    hash_password,
    verify_password,
    close_connection_pool,
)

# ---------------------------------------------------------------------------
# Application Lifespan (Preserves startup SQL & adds graceful shutdown)
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    # 1. Startup: Run schema checks and pending batch cleanups
    init_db()
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SET TIME ZONE 'Asia/Karachi';")
            cur.execute("ALTER TABLE job_cards ALTER COLUMN ingestion_progress TYPE TEXT;")
            cur.execute("ALTER TABLE job_cards ALTER COLUMN status TYPE VARCHAR(100);")
            cur.execute("ALTER TABLE job_cards ADD COLUMN IF NOT EXISTS conflict_resolution VARCHAR(50) DEFAULT 'NONE';")
            cur.execute("ALTER TABLE job_cards ADD COLUMN IF NOT EXISTS conflict_details TEXT;")
            cur.execute("ALTER TABLE job_cards ADD COLUMN IF NOT EXISTS override_by VARCHAR(100);")
            cur.execute("ALTER TABLE job_cards ADD COLUMN IF NOT EXISTS override_reason TEXT;")
            
            # Auto-ensure high-speed verification indexes on startup
            cur.execute("CREATE INDEX IF NOT EXISTS idx_codes_run_val ON codes (run_id, code_value);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_codes_run_id_asc ON codes (run_id, id ASC);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_codes_run_status_id ON codes (run_id, status, id);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_codes_val_active ON codes (code_value) WHERE status != 'DELETED';")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_scan_logs_jc_id ON scan_logs (job_card_id, id DESC);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_packing_qc_jc_code ON packing_qc_logs (job_card_id, code_scanned);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_sys_audit_ts ON system_audit_logs (timestamp DESC);")
            
            # 1. Add explicit row_num column and index
            cur.execute("ALTER TABLE codes ADD COLUMN IF NOT EXISTS row_num INT;")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_codes_run_rownum ON codes (run_id, row_num);")

            # 2. Backfill row_num for any historical jobs that don't have it yet
            cur.execute("""
                UPDATE codes c
                SET row_num = sub.calc_row
                FROM (
                    SELECT id, row_number() OVER (PARTITION BY run_id ORDER BY id ASC) AS calc_row
                    FROM codes
                    WHERE row_num IS NULL
                ) sub
                WHERE c.id = sub.id;
            """)
            conn.commit()

            cur.execute("""
                UPDATE job_cards 
                SET status = 'FAILED', 
                    ingestion_progress = 'Interrupted by server restart. You can safely purge or re-upload.'
                WHERE status IN ('INGESTING', 'OVERRIDING');
            """)

            # Only calculate counts for jobs that are actually missing them
            cur.execute("""
                UPDATE job_cards j
                SET total_codes = COALESCE(sub.cnt, 0),
                    consumed_codes = COALESCE(sub.consumed_cnt, 0)
                FROM (
                    SELECT c.run_id, 
                           COUNT(*) as cnt,
                           COUNT(*) FILTER (WHERE c.status = 'CONSUMED') as consumed_cnt
                    FROM codes c
                    WHERE c.run_id IN (
                        SELECT run_id FROM job_cards 
                        WHERE (total_codes IS NULL OR total_codes = 0) 
                          AND status NOT IN ('DELETED', 'FAILED')
                    )
                    GROUP BY c.run_id
                ) sub
                WHERE j.run_id = sub.run_id;
            """)
            conn.commit()
    finally:
        release_connection(conn)

    yield  # Application handles incoming HTTP requests

    # 2. Shutdown: Cleanly release DB connections on deploy/restart
    try:
        close_connection_pool()
    except Exception:
        pass


app = FastAPI(
    title="CCL ME - PK - Variable Data Verification",
    lifespan=lifespan
)

SECRET_KEY = os.environ.get("SESSION_SECRET", "ccl-variable-data-secret-floor-key-2026")
signer = URLSafeTimedSerializer(SECRET_KEY)

# Dedicated 64-bit integer advisory lock key to serialize cross-job duplicate checks
CROSS_JOB_INGESTION_LOCK_ID = 8492049102

def release_advisory_lock_safe(conn, cur):
    """Safely releases session advisory lock even if the transaction was previously aborted."""
    try:
        cur.execute("SELECT pg_advisory_unlock(%s);", (CROSS_JOB_INGESTION_LOCK_ID,))
    except Exception:
        try:
            conn.rollback()
            with conn.cursor() as c:
                c.execute("SELECT pg_advisory_unlock(%s);", (CROSS_JOB_INGESTION_LOCK_ID,))
        except Exception:
            pass

# ---------------------------------------------------------------------------
# Rate-Limiting & Brute-Force Defense (5 failed attempts per 5 minutes)
# ---------------------------------------------------------------------------
FAILED_ATTEMPTS = {}

def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"

def check_rate_limit(request: Request, max_attempts: int = 5, window_seconds: int = 300):
    client_ip = get_client_ip(request)
    now = time.time()
    attempts = [t for t in FAILED_ATTEMPTS.get(client_ip, []) if now - t < window_seconds]
    FAILED_ATTEMPTS[client_ip] = attempts
    if len(attempts) >= max_attempts:
        minutes_remaining = int((attempts[0] + window_seconds - now) / 60) + 1
        raise HTTPException(
            status_code=429,
            detail=f"Too many failed login attempts from this terminal. Please wait {minutes_remaining} minute(s)."
        )

def record_failed_attempt(request: Request):
    client_ip = get_client_ip(request)
    FAILED_ATTEMPTS.setdefault(client_ip, []).append(time.time())

def clear_failed_attempts(request: Request):
    client_ip = get_client_ip(request)
    FAILED_ATTEMPTS.pop(client_ip, None)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
HTML_PATH = os.path.join(BASE_DIR, "templates", "index.html")
STATIC_DIR = os.path.join(BASE_DIR, "static")

if not os.path.exists(STATIC_DIR):
    os.makedirs(STATIC_DIR, exist_ok=True)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/static/logo.jpg")
@app.get("/logo.jpg")
async def get_logo():
    logo_path = os.path.join(STATIC_DIR, "logo.jpg")
    if os.path.exists(logo_path):
        return FileResponse(logo_path, media_type="image/jpeg")
    parent_logo = os.path.join(os.path.dirname(BASE_DIR), "static", "logo.jpg")
    if os.path.exists(parent_logo):
        return FileResponse(parent_logo, media_type="image/jpeg")
    raise HTTPException(status_code=404, detail="Logo not found")


@app.get("/healthz", tags=["System"])
def deployment_health_check():
    """Deployment health probe for Railway and Render."""
    conn = None
    try:
        conn = get_connection()
        with conn.cursor() as cur:
            cur.execute("SELECT 1;")
            cur.fetchone()
        return {"status": "healthy", "database": "connected"}
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Database probe failed: {e}")
    finally:
        if conn:
            release_connection(conn)

def log_system_event(cur, category: str, job_card_id: str, action: str, performed_by: str, details: str):
    cur.execute("""
        INSERT INTO system_audit_logs (category, job_card_id, action, performed_by, details)
        VALUES (%s, %s, %s, %s, %s)
    """, (category, job_card_id or "-", action, performed_by or "System", details))

def validate_password_strength(password: str):
    if len(password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters long.")
    if not re.search(r"[A-Z]", password):
        raise HTTPException(status_code=400, detail="Password must include at least one uppercase letter.")
    if not re.search(r"[a-z]", password):
        raise HTTPException(status_code=400, detail="Password must include at least one lowercase letter.")
    if not re.search(r"[0-9]", password):
        raise HTTPException(status_code=400, detail="Password must include at least one number.")

def get_current_user(request: Request):
    token = request.cookies.get("qc_session")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        data = signer.loads(token, max_age=86400 * 7)
        conn = get_connection()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT is_active, username, role FROM users WHERE LOWER(username) = LOWER(%s)", (data["username"],))
                row = cur.fetchone()
                if not row or not row[0]:
                    raise HTTPException(status_code=403, detail="Account is suspended or deactivated.")
                data["username"] = row[1]
                data["role"] = row[2]
        finally:
            release_connection(conn)
        return data
    except (BadSignature, SignatureExpired):
        raise HTTPException(status_code=401, detail="Session expired or invalid")

def require_admin(user: dict = Depends(get_current_user)):
    role = str(user.get("role", "")).lower().strip()
    if role not in ["admin", "administrator"]:
        raise HTTPException(status_code=403, detail="Admin permissions required")
    return user

def require_manager_or_admin(user: dict = Depends(get_current_user)):
    role = str(user.get("role", "")).lower().strip()
    if role not in ["admin", "administrator", "qc manager"]:
        raise HTTPException(status_code=403, detail="QC Manager or Admin permissions required")
    return user

def require_uploader(user: dict = Depends(get_current_user)):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT can_upload, role FROM users WHERE LOWER(username) = LOWER(%s)", (user["username"],))
            row = cur.fetchone()
            role_clean = str(row[1]).lower().strip() if row else ""
            if not row or (not row[0] and role_clean not in ["admin", "administrator", "qc manager"]):
                raise HTTPException(status_code=403, detail="You do not have permission to create jobs.")
            return user
    finally:
        release_connection(conn)

# ---------------------------------------------------------
# High-Speed Ingestion & Index Management Helpers
# ---------------------------------------------------------

def drop_secondary_indexes(cur):
    """No-op: Retaining persistent indexes avoids full-table rebuilds across historical jobs."""
    cur.execute("DROP INDEX IF EXISTS idx_codes_code_value;")

def restore_secondary_indexes(cur):
    """Refresh database statistics without rebuilding historical records."""
    cur.execute("ANALYZE codes;")

def stream_file_to_codes_chunked(cur, conn, run_id: int, target_tsv_path: str, total_to_insert: int):
    CHUNK_SIZE = 50_000
    inserted = 0

    with open(target_tsv_path, "r", encoding="utf-8") as tsv_file:
        chunk_buffer = io.StringIO()
        lines_in_buffer = 0

        for line in tsv_file:
            chunk_buffer.write(line)
            lines_in_buffer += 1

            if lines_in_buffer >= CHUNK_SIZE:
                chunk_buffer.seek(0)
                cur.copy_expert("COPY codes (run_id, job_card_id, code_value, status) FROM STDIN WITH (FORMAT text)", chunk_buffer)
                inserted += lines_in_buffer
                pct = int((inserted / max(1, total_to_insert)) * 100)
                progress_msg = f"Ingesting: {pct}% ({inserted:,} / {total_to_insert:,} codes)..."
                cur.execute("UPDATE job_cards SET ingestion_progress = %s WHERE run_id = %s", (progress_msg, run_id))
                conn.commit()
                chunk_buffer = io.StringIO()
                lines_in_buffer = 0

        if lines_in_buffer > 0:
            chunk_buffer.seek(0)
            cur.copy_expert("COPY codes (run_id, job_card_id, code_value, status) FROM STDIN WITH (FORMAT text)", chunk_buffer)
            inserted += lines_in_buffer
            progress_msg = f"Ingesting: 100% ({inserted:,} / {total_to_insert:,} codes)..."
            cur.execute("UPDATE job_cards SET ingestion_progress = %s WHERE run_id = %s", (progress_msg, run_id))
            conn.commit()
    
    return inserted

def process_large_job_worker(run_id: int, job_card_id: str, temp_filepath: str, is_override: bool, username: str):
    conn = None
    indexes_dropped = False
    raw_table = f"temp_raw_import_{run_id}"
    tokens_table = f"temp_tokens_{run_id}"
    incoming_table = f"temp_incoming_codes_{run_id}"
    export_table = f"temp_clean_export_{run_id}"

    try:
        conn = get_connection()
        with conn.cursor() as cur:
            cur.execute("SET synchronous_commit = off;")
            cur.execute("SET work_mem = '256MB';")
            cur.execute("SET maintenance_work_mem = '256MB';")
            conn.commit()

            cur.execute("UPDATE job_cards SET ingestion_progress = 'Streaming raw file to database memory...' WHERE run_id = %s", (run_id,))
            conn.commit()

            cur.execute(f"DROP TABLE IF EXISTS {raw_table}, {tokens_table}, {incoming_table}, {export_table};")
            
            # 1. Capture exact physical line numbers sequentially during COPY
            cur.execute(f"""
                CREATE UNLOGGED TABLE {raw_table} (
                    line_num BIGINT GENERATED ALWAYS AS IDENTITY,
                    raw_line TEXT
                );
            """)
            
            with open(temp_filepath, "r", encoding="utf-8", errors="ignore") as f:
                cur.copy_expert(f"COPY {raw_table} (raw_line) FROM STDIN WITH (FORMAT text)", f)

            cur.execute("UPDATE job_cards SET ingestion_progress = 'Extracting and ordering file tokens...' WHERE run_id = %s", (run_id,))
            conn.commit()

            # 2. Unnest pairing line_num and col_num so row sequence cannot be scrambled
            cur.execute(f"""
                CREATE UNLOGGED TABLE {tokens_table} AS
                SELECT 
                    row_number() OVER (ORDER BY t.line_num ASC, t.col_num ASC) AS original_seq,
                    t.line_num,
                    t.cleaned_val AS code_value
                FROM (
                    SELECT 
                        r.line_num,
                        u.col_num,
                        TRIM(BOTH '\"' FROM TRIM(BOTH '''' FROM TRIM(REPLACE(REPLACE(REPLACE(u.val, CHR(13), ''), CHR(10), ''), CHR(9), '')))) AS cleaned_val
                    FROM {raw_table} r,
                    LATERAL unnest(string_to_array(r.raw_line, ',')) WITH ORDINALITY AS u(val, col_num)
                    WHERE r.raw_line IS NOT NULL AND TRIM(r.raw_line) != ''
                ) t
                WHERE t.cleaned_val != ''
                  AND LOWER(t.cleaned_val) NOT IN ('code', 'url', 'qr', 'qrcode', 'serial', 'barcode', 'data', 'id', 'link');
            """)

            cur.execute(f"DROP TABLE IF EXISTS {raw_table};")

            # 3. Deduplicate preserving first appearance file sequence and track line_num
            cur.execute(f"""
                CREATE UNLOGGED TABLE {incoming_table} AS
                SELECT code_value, MIN(original_seq) AS original_seq, MIN(line_num) AS line_num
                FROM {tokens_table}
                GROUP BY code_value;
            """)

            cur.execute(f"SELECT COUNT(*) FROM {tokens_table};")
            row_raw = cur.fetchone()
            raw_token_count = row_raw[0] if row_raw else 0

            cur.execute(f"SELECT COUNT(*) FROM {incoming_table};")
            row_tot = cur.fetchone()
            total_codes = row_tot[0] if row_tot else 0

            internal_duplicates_count = max(0, raw_token_count - total_codes)

            if internal_duplicates_count > 0:
                cur.execute(f"SELECT code_value FROM {tokens_table} GROUP BY code_value HAVING COUNT(*) > 1 LIMIT 5;")
                samples = [r[0] for r in cur.fetchall()]
                sample_str = ", ".join(samples)
                error_msg = (
                    f"File Integrity Error: Found {internal_duplicates_count:,} duplicate code(s) "
                    f"within the CSV itself (Samples: {sample_str})."
                )
                cur.execute("UPDATE job_cards SET status = 'FAILED', ingestion_progress = %s WHERE run_id = %s", (error_msg, run_id))
                cur.execute(f"DROP TABLE IF EXISTS {tokens_table}, {incoming_table};")
                conn.commit()
                return

            cur.execute(f"DROP TABLE IF EXISTS {tokens_table};")

            if total_codes == 0:
                cur.execute("UPDATE job_cards SET status = 'FAILED', ingestion_progress = 'No valid codes found in uploaded file' WHERE run_id = %s", (run_id,))
                cur.execute(f"DROP TABLE IF EXISTS {incoming_table};")
                conn.commit()
                return

            cur.execute(f"CREATE INDEX idx_temp_inc_val_{run_id} ON {incoming_table} (code_value);")
            cur.execute(f"CREATE INDEX idx_temp_inc_seq_{run_id} ON {incoming_table} (original_seq);")
            cur.execute(f"ANALYZE {incoming_table};")

            cur.execute("UPDATE job_cards SET total_codes = %s, ingestion_progress = 'Waiting for verification gate...' WHERE run_id = %s", (total_codes, run_id))
            conn.commit()

            # Acquire global advisory lock: serializes the check-through-activation window
            cur.execute("SELECT pg_advisory_lock(%s);", (CROSS_JOB_INGESTION_LOCK_ID,))
            lock_acquired = True

            try:
                cur.execute("UPDATE job_cards SET ingestion_progress = 'Checking cross-job uniqueness...' WHERE run_id = %s", (run_id,))
                conn.commit()

                conflicts_found = 0
                if not is_override:
                    cur.execute("UPDATE job_cards SET ingestion_progress = 'Analyzing historical active jobs...' WHERE run_id = %s", (run_id,))
                    conn.commit()

                    cur.execute("ANALYZE codes;")

                    cur.execute("""
                        CREATE TEMP TABLE temp_active_runs ON COMMIT DROP AS
                        SELECT run_id, job_card_id, COALESCE(description, 'No Description') AS description, status 
                        FROM job_cards WHERE status IN ('ACTIVE', 'INACTIVE', 'COMPLETED');
                        CREATE INDEX idx_tmp_act_run ON temp_active_runs (run_id);
                    """)

                    cur.execute(f"""
                        CREATE TEMP TABLE temp_conflicting_codes ON COMMIT DROP AS
                        SELECT DISTINCT t.code_value, t.line_num
                        FROM {incoming_table} t
                        WHERE EXISTS (
                            SELECT 1 
                            FROM codes c
                            JOIN temp_active_runs a ON c.run_id = a.run_id
                            WHERE c.code_value = t.code_value
                              AND c.status != 'DELETED'
                        );
                        CREATE INDEX idx_tmp_conf_val ON temp_conflicting_codes (code_value);
                        ANALYZE temp_conflicting_codes;
                    """)

                    # Check if conflicts belong to line 1 (header row) vs later data lines
                    cur.execute("""
                        SELECT 
                            COUNT(*) FILTER (WHERE line_num = 1) AS r1_conflicts,
                            COUNT(*) FILTER (WHERE line_num > 1) AS body_conflicts
                        FROM temp_conflicting_codes;
                    """)
                    c_row = cur.fetchone()
                    r1_conflicts = c_row[0] if c_row else 0
                    body_conflicts = c_row[1] if c_row else 0

                    # If the first row caused conflicts, discard row 1 automatically
                    # Keep transaction uncommitted so ON COMMIT DROP tables survive for breakdown query
                    if r1_conflicts > 0:
                        cur.execute(f"DELETE FROM {incoming_table} WHERE line_num = 1;")
                        cur.execute("DELETE FROM temp_conflicting_codes WHERE line_num = 1;")
                        cur.execute(f"SELECT COUNT(*) FROM {incoming_table};")
                        total_codes = cur.fetchone()[0]
                        cur.execute("UPDATE job_cards SET total_codes = %s WHERE run_id = %s", (total_codes, run_id))

                    # Only remaining data-line conflicts are flagged
                    conflicts_found = body_conflicts

                    if conflicts_found > 0:
                        cur.execute("""
                            SELECT a.job_card_id, a.description, a.status, COUNT(c.code_value) as cnt
                            FROM temp_conflicting_codes tc
                            JOIN codes c ON c.code_value = tc.code_value
                            JOIN temp_active_runs a ON a.run_id = c.run_id
                            WHERE c.status != 'DELETED'
                            GROUP BY a.job_card_id, a.description, a.status
                            ORDER BY cnt DESC;
                        """)
                        breakdown = [
                            {"job_card_id": r[0], "description": r[1], "status": r[2], "conflict_count": r[3]}
                            for r in cur.fetchall()
                        ]

                        clean_tsv_fd, clean_tsv_path = tempfile.mkstemp(suffix=".tsv")
                        cur.execute(f"""
                            CREATE UNLOGGED TABLE {export_table} AS
                            SELECT %s::int AS run_id, %s::text AS job_card_id, code_value, 'PENDING'::text AS status, original_seq
                            FROM {incoming_table}
                            ORDER BY original_seq;
                        """, (run_id, job_card_id))

                        with os.fdopen(clean_tsv_fd, "w", encoding="utf-8") as out_f:
                            cur.copy_expert(f"COPY {export_table} TO STDOUT WITH (FORMAT text)", out_f)

                        cur.execute("""
                            UPDATE job_cards 
                            SET status = 'CONFLICT_DETECTED', 
                                conflict_count = %s, 
                                conflict_resolution = 'PENDING',
                                conflict_details = %s,
                                staged_file_path = %s,
                                ingestion_progress = 'Duplicate conflicts detected. Awaiting authorization.' 
                            WHERE run_id = %s
                        """, (conflicts_found, json.dumps(breakdown), clean_tsv_path, run_id))
                        
                        cur.execute(f"DROP TABLE IF EXISTS {incoming_table}, {export_table};")
                        conn.commit()
                        return

                cur.execute("UPDATE job_cards SET ingestion_progress = %s WHERE run_id = %s", ("Ingesting: 75% (Direct database insertion in strict file order)...", run_id))
                conn.commit()

                # Insert strictly ordered by original_seq and store 1:1 file row index explicitly
                cur.execute(f"""
                    INSERT INTO codes (run_id, job_card_id, code_value, status, row_num)
                    SELECT %s, %s, code_value, 'PENDING',
                           row_number() OVER (ORDER BY original_seq ASC)
                    FROM {incoming_table}
                    ORDER BY original_seq ASC;
                """, (run_id, job_card_id))
                actual_inserted = cur.rowcount

                cur.execute(f"DROP TABLE IF EXISTS {incoming_table};")

                cur.execute("""
                    UPDATE job_cards 
                    SET status = 'ACTIVE', 
                        total_codes = %s,
                        conflict_resolution = 'NONE',
                        ingestion_progress = %s 
                    WHERE run_id = %s
                """, (actual_inserted, '100%', run_id))

                lifecycle_reason = f"Full batch ingestion completed ({actual_inserted:,} codes" + (f", {conflicts_found:,} conflicts overridden)" if is_override else ")")
                cur.execute("""
                    INSERT INTO job_lifecycle_logs (job_card_id, action, performed_by, reason) 
                    VALUES (%s, %s, %s, %s)
                """, (job_card_id, "CREATED", username, lifecycle_reason))
                log_system_event(cur, "JOB_LIFECYCLE", job_card_id, "CREATED", username, lifecycle_reason)

                conn.commit()
            finally:
                if lock_acquired:
                    release_advisory_lock_safe(conn, cur)
                    conn.commit()
                    lock_acquired = False

            # Statistics refresh performed outside the gate to free waiting uploads immediately
            restore_secondary_indexes(cur)
            conn.commit()

    except Exception as e:
        try:
            if conn:
                conn.rollback()
                with conn.cursor() as cur:
                    cur.execute(f"DROP TABLE IF EXISTS {raw_table}, {tokens_table}, {incoming_table}, {export_table};")
                conn.commit()
        except Exception:
            pass
        fail_conn = None
        try:
            fail_conn = get_connection()
            with fail_conn.cursor() as cur:
                if indexes_dropped:
                    restore_secondary_indexes(cur)
                    fail_conn.commit()
                cur.execute("UPDATE job_cards SET status = 'FAILED', ingestion_progress = %s WHERE run_id = %s", (f"Ingestion Error: {str(e)}", run_id))
                fail_conn.commit()
        except Exception:
            pass
        finally:
            if fail_conn:
                release_connection(fail_conn)
    finally:
        if conn:
            release_connection(conn)
        try:
            if temp_filepath and os.path.exists(temp_filepath):
                os.remove(temp_filepath)
        except OSError:
            pass
def process_override_worker(run_id: int, job_card_id: str, clean_tsv_path: str, conflicts: int, total_codes: int, username: str, override_reason: str, skip_conflicts: bool = False):
    conn = None
    ovr_all_table = f"temp_override_all_{run_id}"
    ovr_filt_table = f"temp_override_filtered_{run_id}"
    ovr_chunk_table = f"temp_override_chunked_{run_id}"

    try:
        conn = get_connection()
        with conn.cursor() as cur:
            cur.execute("SET synchronous_commit = off;")
            cur.execute("SET work_mem = '256MB';")
            cur.execute("SET maintenance_work_mem = '256MB';")
            conn.commit()

            effective_total = total_codes
            source_table = ovr_all_table

            cur.execute("UPDATE job_cards SET ingestion_progress = %s WHERE run_id = %s", 
                        ("Ingesting: 15% (Streaming staged file to database memory)...", run_id))
            conn.commit()

            cur.execute(f"DROP TABLE IF EXISTS {ovr_all_table}, {ovr_filt_table}, {ovr_chunk_table};")
            cur.execute(f"CREATE UNLOGGED TABLE {ovr_all_table} (run_id INT, job_card_id TEXT, code_value TEXT, status TEXT, original_seq BIGINT);")
            with open(clean_tsv_path, "r", encoding="utf-8") as tsv_in:
                cur.copy_expert(f"COPY {ovr_all_table} FROM STDIN WITH (FORMAT text)", tsv_in)

            cur.execute("UPDATE job_cards SET ingestion_progress = %s WHERE run_id = %s", 
                        ("Waiting for verification gate...", run_id))
            conn.commit()

            # Acquire global advisory lock BEFORE active-job evaluation to prevent concurrent activation bypass
            cur.execute("SELECT pg_advisory_lock(%s);", (CROSS_JOB_INGESTION_LOCK_ID,))
            lock_acquired = True

            try:
                if skip_conflicts:
                    cur.execute("UPDATE job_cards SET ingestion_progress = %s WHERE run_id = %s", 
                                ("Ingesting: 35% (Filtering out conflicting codes)...", run_id))
                    conn.commit()

                    cur.execute(f"CREATE INDEX idx_temp_ovr_val_{run_id} ON {ovr_all_table} (code_value);")
                    cur.execute(f"ANALYZE {ovr_all_table};")

                    cur.execute("CREATE TEMP TABLE temp_active_runs ON COMMIT DROP AS SELECT run_id FROM job_cards WHERE status IN ('ACTIVE', 'INACTIVE', 'COMPLETED');")
                    cur.execute("CREATE INDEX idx_tmp_active_runs ON temp_active_runs(run_id);")

                    cur.execute(f"""
                        CREATE UNLOGGED TABLE {ovr_filt_table} AS
                        SELECT t.run_id, t.job_card_id, t.code_value, t.status, t.original_seq
                        FROM {ovr_all_table} t
                        WHERE NOT EXISTS (
                            SELECT 1 
                            FROM codes c
                            JOIN temp_active_runs a ON c.run_id = a.run_id
                            WHERE c.code_value = t.code_value
                              AND c.status != 'DELETED'
                        );
                    """)

                    cur.execute(f"SELECT COUNT(*) FROM {ovr_filt_table};")
                    row_eff = cur.fetchone()
                    effective_total = row_eff[0] if row_eff else 0

                    if effective_total == 0:
                        cur.execute("UPDATE job_cards SET status = 'FAILED', ingestion_progress = %s WHERE run_id = %s", 
                                    ("All codes conflicted and were skipped. 0 codes remaining.", run_id))
                        cur.execute(f"DROP TABLE IF EXISTS {ovr_all_table}, {ovr_filt_table};")
                        conn.commit()
                        return

                    source_table = ovr_filt_table
                    cur.execute("UPDATE job_cards SET total_codes = %s WHERE run_id = %s", (effective_total, run_id))
                    conn.commit()

                cur.execute("UPDATE job_cards SET ingestion_progress = %s WHERE run_id = %s", 
                            ("Ingesting: 50% (Clustering and indexing batch for high-speed insertion)...", run_id))
                conn.commit()

                cur.execute(f"""
                    CREATE UNLOGGED TABLE {ovr_chunk_table} AS
                    SELECT run_id, job_card_id, code_value, status, original_seq,
                           row_number() OVER (ORDER BY original_seq ASC) AS rnum
                    FROM {source_table};
                """)
                cur.execute(f"CREATE INDEX idx_tmp_chunk_rnum_{run_id} ON {ovr_chunk_table} (rnum);")
                cur.execute(f"ANALYZE {ovr_chunk_table};")
                conn.commit()

                CHUNK_SIZE = 100_000
                actual_inserted = 0
                total_chunks = (effective_total + CHUNK_SIZE - 1) // CHUNK_SIZE

                for chunk_idx, start_rnum in enumerate(range(1, effective_total + 1, CHUNK_SIZE)):
                    end_rnum = start_rnum + CHUNK_SIZE
                    
                    pct = 55 + int(((chunk_idx + 1) / total_chunks) * 40)
                    status_msg = f"Ingesting: {pct}% ({actual_inserted:,} / {effective_total:,} codes inserted)..."
                    
                    cur.execute("UPDATE job_cards SET ingestion_progress = %s WHERE run_id = %s", (status_msg, run_id))
                    conn.commit()

                    # Insert original_seq as row_num to preserve exact 1:1 physical file row numbers
                    cur.execute(f"""
                        INSERT INTO codes (run_id, job_card_id, code_value, status, row_num)
                        SELECT run_id, job_card_id, code_value, status, original_seq
                        FROM {ovr_chunk_table}
                        WHERE rnum >= %s AND rnum < %s
                        ORDER BY rnum ASC;
                    """, (start_rnum, end_rnum))
                    actual_inserted += cur.rowcount
                    conn.commit()

                cur.execute(f"DROP TABLE IF EXISTS {ovr_all_table}, {ovr_filt_table}, {ovr_chunk_table};")

                resolution_type = 'SKIPPED' if skip_conflicts else 'OVERRIDDEN'
                cur.execute("""
                    UPDATE job_cards 
                    SET status = 'ACTIVE', 
                        total_codes = %s, 
                        conflict_resolution = %s, 
                        override_by = %s,
                        override_reason = %s,
                        ingestion_progress = %s 
                    WHERE run_id = %s
                """, (actual_inserted, resolution_type, username, override_reason, '100%', run_id))

                if skip_conflicts:
                    lifecycle_reason = f"Conflicts Skipped: {actual_inserted:,} codes kept ({conflicts:,} skipped). Justification: {override_reason}"
                else:
                    lifecycle_reason = f"Duplicate Overridden: {conflicts:,} duplicates accepted ({actual_inserted:,} total codes). Justification: {override_reason}"

                cur.execute("""
                    INSERT INTO job_lifecycle_logs (job_card_id, action, performed_by, reason) 
                    VALUES (%s, %s, %s, %s)
                """, (job_card_id, "CREATED", username, lifecycle_reason))
                log_system_event(cur, "JOB_LIFECYCLE", job_card_id, "CREATED", username, lifecycle_reason)

                conn.commit()
            finally:
                if lock_acquired:
                    release_advisory_lock_safe(conn, cur)
                    conn.commit()
                    lock_acquired = False

            # Statistics refresh performed outside the gate to free waiting uploads immediately
            restore_secondary_indexes(cur)
            conn.commit()

    except Exception as e:
        try:
            if conn:
                conn.rollback()
                with conn.cursor() as cur:
                    cur.execute(f"DROP TABLE IF EXISTS {ovr_all_table}, {ovr_filt_table}, {ovr_chunk_table};")
                conn.commit()
        except Exception:
            pass
        fail_conn = None
        try:
            fail_conn = get_connection()
            with fail_conn.cursor() as cur:
                cur.execute("UPDATE job_cards SET status = 'FAILED', ingestion_progress = %s WHERE run_id = %s", 
                            (f"Override Error: {str(e)}", run_id))
                fail_conn.commit()
        except Exception:
            pass
        finally:
            if fail_conn:
                release_connection(fail_conn)
    finally:
        if conn:
            release_connection(conn)
        try:
            if clean_tsv_path and os.path.exists(clean_tsv_path):
                os.remove(clean_tsv_path)
        except OSError:
            pass




# ---------------------------------------------------------
# Application Routes & Verification API
# ---------------------------------------------------------

@app.get("/")
async def index():
    return FileResponse(HTML_PATH, media_type="text/html")

@app.post("/api/auth/login")
def login(request: Request, response: Response, username: str = Form(...), password: str = Form(...)):
    check_rate_limit(request, max_attempts=5, window_seconds=300)
    clean_username = username.strip()
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT password_hash, role, must_change_password, can_upload, is_active, username FROM users WHERE LOWER(username) = LOWER(%s)", (clean_username,))
            user = cur.fetchone()
            if not user or not verify_password(password, user[0]):
                record_failed_attempt(request)
                log_system_event(cur, "USER_MGMT", "-", "LOGIN_FAILED", clean_username, f"Failed login attempt for username '{clean_username}'")
                conn.commit()
                raise HTTPException(status_code=400, detail="Invalid username or password")
            
            if not user[4]:
                raise HTTPException(status_code=403, detail="This account has been suspended.")

            clear_failed_attempts(request)
            original_username = user[5]
            log_system_event(cur, "USER_MGMT", "-", "LOGIN_SUCCESS", original_username, f"User '{original_username}' signed in successfully")
            conn.commit()

            role_clean = str(user[1]).lower().strip()
            token = signer.dumps({"username": original_username, "role": user[1]})
            response.set_cookie(
                key="qc_session",
                value=token,
                httponly=True,
                max_age=86400 * 7,
                samesite="lax",
                secure=False
            )
            return {
                "status": "success",
                "username": original_username,
                "role": user[1],
                "must_change_password": user[2],
                "can_upload": user[3] or role_clean in ["admin", "administrator", "qc manager"]
            }
    finally:
        release_connection(conn)

@app.post("/api/auth/logout")
def logout(response: Response, request: Request):
    try:
        user = get_current_user(request)
        conn = get_connection()
        try:
            with conn.cursor() as cur:
                log_system_event(cur, "USER_MGMT", "-", "LOGOUT", user["username"], f"User '{user['username']}' signed out")
                conn.commit()
        finally:
            release_connection(conn)
    except Exception:
        pass

    response.delete_cookie("qc_session")
    return {"status": "success"}

@app.get("/api/auth/me")
def get_me(request: Request):
    try:
        user = get_current_user(request)
        conn = get_connection()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT must_change_password, can_upload, role FROM users WHERE LOWER(username) = LOWER(%s)", (user["username"],))
                row = cur.fetchone()
                must_change = row[0] if row else False
                can_upload = row[1] if row else False
                role = row[2] if row else user["role"]
                role_clean = str(role).lower().strip()
        finally:
            release_connection(conn)

        return {
            "authenticated": True,
            "username": user["username"],
            "role": role,
            "must_change_password": must_change,
            "can_upload": can_upload or role_clean in ["admin", "administrator", "qc manager"]
        }
    except HTTPException:
        return {"authenticated": False}

@app.post("/api/auth/change-password")
def change_password(
    new_password: str = Form(...),
    confirm_password: str = Form(...),
    old_password: Optional[str] = Form(None),
    user: dict = Depends(get_current_user)
):
    if new_password != confirm_password:
        raise HTTPException(status_code=400, detail="New passwords do not match.")
    validate_password_strength(new_password)

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT password_hash, must_change_password FROM users WHERE LOWER(username) = LOWER(%s)", (user["username"],))
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="User not found.")

            stored_hash, must_change = row[0], row[1]

            if not must_change:
                if not old_password:
                    raise HTTPException(status_code=400, detail="Current password is required.")
                if not verify_password(old_password, stored_hash):
                    raise HTTPException(status_code=400, detail="Current password is incorrect.")

            new_hash = hash_password(new_password)
            cur.execute(
                "UPDATE users SET password_hash = %s, must_change_password = FALSE WHERE LOWER(username) = LOWER(%s)",
                (new_hash, user["username"])
            )
            log_system_event(cur, "USER_MGMT", "-", "CHANGE_PASSWORD", user["username"], f"User '{user['username']}' updated their password")
            conn.commit()
            return {"status": "success", "message": "Password updated successfully"}
    finally:
        release_connection(conn)

@app.get("/api/users")
def list_users(admin: dict = Depends(require_admin)):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT username, role, must_change_password, can_upload, is_active, employee_name, employee_id, created_at FROM users ORDER BY created_at ASC")
            rows = cur.fetchall()
            return [{
                "username": r[0],
                "role": r[1],
                "must_change_password": r[2],
                "can_upload": True if str(r[1]).lower().strip() in ["admin", "administrator", "qc manager"] else (r[3] or False),
                "is_active": r[4] if r[4] is not None else True,
                "employee_name": r[5] or "",
                "employee_id": r[6] or "",
                "created_at": r[7].strftime("%Y-%m-%d %H:%M") if r[7] else ""
            } for r in rows]
    finally:
        release_connection(conn)

@app.post("/api/users/create")
def create_user(
    username: str = Form(...),
    password: str = Form(...),
    role: str = Form("QC officer"),
    can_upload: bool = Form(False),
    employee_name: str = Form(""),
    employee_id: str = Form(""),
    admin: dict = Depends(require_admin)
):
    clean_username = username.strip()
    validate_password_strength(password)

    if str(role).lower().strip() in ["admin", "administrator", "qc manager"]:
        can_upload = True

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT username FROM users WHERE LOWER(username) = LOWER(%s)", (clean_username,))
            if cur.fetchone():
                raise HTTPException(status_code=400, detail="User already exists")

            pw_hash = hash_password(password)
            cur.execute(
                """INSERT INTO users (username, password_hash, role, must_change_password, can_upload, is_active, employee_name, employee_id) 
                   VALUES (%s, %s, %s, TRUE, %s, TRUE, %s, %s)""",
                (clean_username, pw_hash, role, can_upload, employee_name.strip(), employee_id.strip())
            )
            log_system_event(cur, "USER_MGMT", "-", "CREATE_USER", admin["username"], f"Created new user account '{clean_username}' with role '{role}'")
            conn.commit()
            return {"status": "success"}
    finally:
        release_connection(conn)

@app.post("/api/users/{username}/role")
def update_user_role(
    username: str,
    role: str = Form(...),
    admin: dict = Depends(require_admin)
):
    role_norm = role.strip()
    valid_roles = ["QC officer", "QC operator", "QC manager", "admin", "Administrator"]
    if not any(r.lower() == role_norm.lower() for r in valid_roles):
        raise HTTPException(status_code=400, detail="Invalid role specified.")

    if username.lower() == admin["username"].lower() and role_norm.lower() not in ["admin", "administrator"]:
        raise HTTPException(status_code=400, detail="Cannot downgrade your own admin account.")

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            if role_norm.lower() in ["admin", "administrator", "qc manager"]:
                cur.execute("UPDATE users SET role = %s, can_upload = TRUE WHERE LOWER(username) = LOWER(%s)", (role_norm, username))
            else:
                cur.execute("UPDATE users SET role = %s WHERE LOWER(username) = LOWER(%s)", (role_norm, username))
            
            log_system_event(cur, "USER_MGMT", "-", "UPDATE_ROLE", admin["username"], f"Updated role for user '{username}' to '{role_norm}'")
            conn.commit()
            return {"status": "success"}
    finally:
        release_connection(conn)

@app.post("/api/users/{username}/reset-password")
def admin_reset_user_password(
    username: str,
    new_password: str = Form(...),
    admin_password: str = Form(...),
    admin: dict = Depends(require_admin)
):
    validate_password_strength(new_password)
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT password_hash FROM users WHERE LOWER(username) = LOWER(%s)", (admin["username"],))
            admin_row = cur.fetchone()
            if not admin_row or not verify_password(admin_password, admin_row[0]):
                raise HTTPException(status_code=403, detail="Invalid admin password.")

            cur.execute("SELECT username FROM users WHERE LOWER(username) = LOWER(%s)", (username,))
            if not cur.fetchone():
                raise HTTPException(status_code=404, detail="User not found.")

            new_hash = hash_password(new_password)
            cur.execute(
                "UPDATE users SET password_hash = %s, must_change_password = TRUE WHERE LOWER(username) = LOWER(%s)",
                (new_hash, username)
            )
            log_system_event(cur, "USER_MGMT", "-", "ADMIN_RESET_PASSWORD", admin["username"], f"Reset password for user '{username}'")
            conn.commit()
            return {"status": "success", "message": f"Password reset for user {username}"}
    finally:
        release_connection(conn)

@app.post("/api/users/{username}/toggle-active")
def toggle_user_active(
    username: str,
    is_active: bool = Form(...),
    admin: dict = Depends(require_admin)
):
    if username.lower() == admin["username"].lower() and not is_active:
        raise HTTPException(status_code=400, detail="Cannot suspend your own admin account.")

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("UPDATE users SET is_active = %s WHERE LOWER(username) = LOWER(%s)", (is_active, username))
            action_label = "ACTIVATE_USER" if is_active else "SUSPEND_USER"
            log_system_event(cur, "USER_MGMT", "-", action_label, admin["username"], f"{'Activated' if is_active else 'Suspended'} user account '{username}'")
            conn.commit()
            return {"status": "success"}
    finally:
        release_connection(conn)

@app.post("/api/users/{username}/toggle-upload")
def toggle_user_upload(
    username: str,
    can_upload: bool = Form(...),
    admin: dict = Depends(require_admin)
):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT role FROM users WHERE LOWER(username) = LOWER(%s)", (username,))
            row = cur.fetchone()
            if row and str(row[0]).lower().strip() in ["admin", "administrator", "qc manager"] and not can_upload:
                raise HTTPException(status_code=400, detail="Admin and QC Manager have permanent job creation rights.")

            cur.execute("UPDATE users SET can_upload = %s WHERE LOWER(username) = LOWER(%s)", (can_upload, username))
            log_system_event(cur, "USER_MGMT", "-", "TOGGLE_UPLOAD_RIGHTS", admin["username"], f"Set job creation permission for '{username}' to {can_upload}")
            conn.commit()
            return {"status": "success"}
    finally:
        release_connection(conn)

@app.get("/api/admin/audit-trail")
def get_global_audit_trail(user: dict = Depends(require_manager_or_admin)):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT category, job_card_id, action, performed_by, details, timestamp 
                FROM system_audit_logs
                ORDER BY timestamp DESC 
                LIMIT 5000
            """)
            rows = cur.fetchall()

            events = [{
                "category": r[0],
                "job_card_id": r[1] or "-",
                "activity_type": r[2],
                "user": r[3] or "System",
                "details": r[4] or "-",
                "timestamp": r[5].strftime("%Y-%m-%d %H:%M:%S") if r[5] else ""
            } for r in rows]

            return {"events": events}
    finally:
        release_connection(conn)

@app.get("/api/jobs/check-availability")
def check_job_card_availability(job_card_id: str, user: dict = Depends(get_current_user)):
    jc_id = job_card_id.strip()
    if not jc_id:
        return {"exists": False}

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT run_id, status, total_codes 
                FROM job_cards 
                WHERE LOWER(job_card_id) = LOWER(%s) AND status != 'DELETED'
                ORDER BY created_at DESC LIMIT 1
            """, (jc_id,))
            row = cur.fetchone()
            if row:
                return {
                    "exists": True,
                    "run_id": row[0],
                    "status": row[1],
                    "total_codes": row[2] or 0
                }
            return {"exists": False}
    finally:
        release_connection(conn)

@app.get("/api/jobs")
def get_jobs(query: str = "", user: dict = Depends(get_current_user)):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            base_sql = """
                SELECT j.job_card_id, j.description, j.status, j.created_at, j.run_id,
                       COALESCE(NULLIF(j.total_codes, 0), (SELECT COUNT(*) FROM codes c WHERE c.run_id = j.run_id), 0) AS total_codes,
                       COALESCE(NULLIF(j.consumed_codes, 0), (SELECT COUNT(*) FROM codes c WHERE c.run_id = j.run_id AND c.status = 'CONSUMED'), 0) AS consumed_codes
                FROM job_cards j
                WHERE j.status IN ('ACTIVE', 'COMPLETED', 'INACTIVE')
            """
            params = []
            if query.strip():
                base_sql += " AND (LOWER(j.job_card_id) LIKE %s OR LOWER(COALESCE(j.description, '')) LIKE %s)"
                search_term = f"%{query.strip().lower()}%"
                params.extend([search_term, search_term])

            base_sql += " ORDER BY j.created_at DESC LIMIT 15"
            cur.execute(base_sql, params)
            rows = cur.fetchall()
            return [{
                "id": r[0],
                "description": r[1] or "",
                "status": r[2],
                "total": r[5] or 0,
                "consumed": r[6] or 0,
                "created_at": r[3].strftime("%Y-%m-%d %H:%M") if r[3] else ""
            } for r in rows]
    finally:
        release_connection(conn)

@app.get("/api/admin/master-jobs")
def get_master_jobs_report(status_filter: str = "ALL", user: dict = Depends(require_manager_or_admin)):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            where_clause = ""
            params = []
            if status_filter in ["ACTIVE", "INACTIVE", "COMPLETED", "DELETED"]:
                where_clause = "WHERE j.status = %s"
                params.append(status_filter)
            elif status_filter == "STUCK":
                where_clause = "WHERE j.status IN ('INGESTING', 'OVERRIDING', 'CONFLICT_DETECTED', 'FAILED')"

            sql = f"""
                SELECT j.run_id, j.job_card_id, j.description, j.status,
                       COALESCE(NULLIF(j.total_codes, 0), (SELECT COUNT(*) FROM codes c WHERE c.run_id = j.run_id), 0) as total,
                       COALESCE(NULLIF(j.consumed_codes, 0), (SELECT COUNT(*) FROM codes c WHERE c.run_id = j.run_id AND c.status = 'CONSUMED'), 0) as consumed,
                       j.created_at,
                       j.deleted_by,
                       j.deleted_at,
                       j.deletion_reason,
                       COALESCE(pq.packing_qc_count, 0) as packing_qc_count,
                       j.ingestion_progress,
                       j.conflict_count,
                       COALESCE(j.conflict_resolution, 'NONE') as conflict_resolution
                FROM job_cards j
                LEFT JOIN (
                    SELECT p.job_card_id, COUNT(*) as packing_qc_count
                    FROM packing_qc_logs p
                    GROUP BY p.job_card_id
                ) pq ON j.job_card_id = pq.job_card_id
                {where_clause}
                ORDER BY 
                    CASE j.status
                        WHEN 'CONFLICT_DETECTED' THEN 1
                        WHEN 'INGESTING' THEN 2
                        WHEN 'OVERRIDING' THEN 3
                        WHEN 'FAILED' THEN 4
                        WHEN 'ACTIVE' THEN 5
                        WHEN 'INACTIVE' THEN 6
                        WHEN 'COMPLETED' THEN 7
                        WHEN 'DELETED' THEN 8
                        ELSE 9
                    END ASC,
                    j.created_at DESC
            """
            cur.execute(sql, params)
            rows = cur.fetchall()
            return [{
                "run_id": r[0],
                "job_card_id": r[1],
                "description": r[2] or "",
                "status": r[3],
                "total": r[4] or 0,
                "consumed": r[5] or 0,
                "created_at": r[6].strftime("%Y-%m-%d %H:%M") if r[6] else "",
                "deleted_by": r[7] or "",
                "deleted_at": r[8].strftime("%Y-%m-%d %H:%M") if r[8] else "",
                "deletion_reason": r[9] or "",
                "packing_qc_count": r[10] or 0,
                "ingestion_progress": r[11] or "",
                "conflict_count": r[12] or 0,
                "conflict_resolution": r[13] or "NONE"
            } for r in rows]
    finally:
        release_connection(conn)

@app.get("/api/admin/packing-qc/{job_card_id}")
def get_packing_qc_logs(job_card_id: str, user: dict = Depends(get_current_user)):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT job_card_id, code_scanned, tested_by, tested_at 
                FROM packing_qc_logs 
                WHERE job_card_id = %s 
                ORDER BY tested_at DESC
            """, (job_card_id,))
            rows = cur.fetchall()
            
            cur.execute("SELECT description FROM job_cards WHERE job_card_id = %s LIMIT 1", (job_card_id,))
            jc_row = cur.fetchone()
            desc = jc_row[0] if jc_row else ""

            return {
                "job_card_id": job_card_id,
                "description": desc or "Serialized Production Batch",
                "logs": [{
                    "code": r[1],
                    "tested_by": r[2],
                    "tested_at": r[3].strftime("%Y-%m-%d %H:%M:%S") if r[3] else ""
                } for r in rows]
            }
    finally:
        release_connection(conn)

@app.get("/api/jobs/{job_card_id}/lifecycle-logs")
def get_job_lifecycle_logs(job_card_id: str, user: dict = Depends(get_current_user)):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT job_card_id, description, status, created_at 
                FROM job_cards 
                WHERE job_card_id = %s 
                LIMIT 1
            """, (job_card_id,))
            job = cur.fetchone()
            if not job:
                raise HTTPException(status_code=404, detail="Job Card not found")

            jc_id, description, status, created_at = job

            cur.execute("""
                SELECT action, performed_by, reason, timestamp 
                FROM job_lifecycle_logs 
                WHERE job_card_id = %s 
                ORDER BY timestamp DESC
            """, (jc_id,))
            logs = [{
                "action": r[0],
                "user": r[1] or "System",
                "reason": r[2] or "-",
                "time": r[3].strftime("%Y-%m-%d %H:%M:%S") if r[3] else ""
            } for r in cur.fetchall()]

            return {
                "job_card_id": jc_id,
                "description": description or "",
                "status": status,
                "created_at": created_at.strftime("%Y-%m-%d %H:%M") if created_at else "",
                "logs": logs
            }
    finally:
        release_connection(conn)

@app.post("/api/jobs/{job_card_id}/complete")
def complete_job(job_card_id: str, user: dict = Depends(get_current_user)):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("UPDATE job_cards SET status = 'COMPLETED' WHERE job_card_id = %s RETURNING run_id", (job_card_id,))
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Job Card not found")
            
            cur.execute("INSERT INTO job_lifecycle_logs (job_card_id, action, performed_by, reason) VALUES (%s, %s, %s, %s)",
                        (job_card_id, "COMPLETED", user["username"], "Marked completed by operator"))
            log_system_event(cur, "JOB_LIFECYCLE", job_card_id, "COMPLETED", user["username"], "Marked completed by operator")
            conn.commit()
            return {"status": "success"}
    finally:
        release_connection(conn)

@app.post("/api/admin/jobs/bulk-status")
def bulk_status_change(
    job_card_ids: str = Form(...),
    target_status: str = Form(...),
    admin_password: str = Form(...),
    user: dict = Depends(require_manager_or_admin)
):
    if target_status not in ["ACTIVE", "INACTIVE", "COMPLETED"]:
        raise HTTPException(status_code=400, detail="Invalid target status.")

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT password_hash FROM users WHERE LOWER(username) = LOWER(%s)", (user["username"],))
            row = cur.fetchone()
            if not row or not verify_password(admin_password, row[0]):
                raise HTTPException(status_code=403, detail="Invalid password. Status update denied.")

            jc_ids = json.loads(job_card_ids)
            if not jc_ids:
                raise HTTPException(status_code=400, detail="No jobs selected.")

            for jc_id in jc_ids:
                cur.execute("""
                    UPDATE job_cards 
                    SET status = %s 
                    WHERE job_card_id = %s AND status != 'DELETED'
                    RETURNING run_id
                """, (target_status, jc_id))
                jc_row = cur.fetchone()
                if jc_row:
                    cur.execute(
                        "INSERT INTO job_lifecycle_logs (job_card_id, action, performed_by, reason) VALUES (%s, %s, %s, %s)",
                        (jc_id, f"STATUS_CHANGED_TO_{target_status}", user["username"], "Status updated in Job Control Center")
                    )
                    log_system_event(cur, "JOB_LIFECYCLE", jc_id, f"STATUS_CHANGED_TO_{target_status}", user["username"], "Status updated in Job Control Center")

            conn.commit()
            return {"status": "success"}
    finally:
        release_connection(conn)

@app.post("/api/jobs/create")
async def create_job(
    job_card_id: str = Form(...),
    description: str = Form(""),
    file: UploadFile = File(...),
    override_duplicate: str = Form("false"),
    uploader: dict = Depends(require_uploader)
):
    job_card_id = job_card_id.strip()
    description = description.strip()
    is_override = str(override_duplicate).strip().lower() in ("true", "1", "yes")

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT run_id, status FROM job_cards WHERE job_card_id = %s AND status != 'DELETED'", (job_card_id,))
            existing = cur.fetchone()
            if existing:
                ex_run_id, ex_status = existing
                if ex_status in ('ACTIVE', 'COMPLETED', 'INACTIVE'):
                    raise HTTPException(status_code=400, detail=f"Active Job Card '{job_card_id}' already exists in the system.")
                else:
                    cur.execute("DELETE FROM job_cards WHERE run_id = %s", (ex_run_id,))
                    conn.commit()

            cur.execute("""
                INSERT INTO job_cards (job_card_id, description, status, ingestion_progress) 
                VALUES (%s, %s, 'INGESTING', 'Receiving uploaded file on disk...') 
                RETURNING run_id
            """, (job_card_id, description))
            run_id = cur.fetchone()[0]
            conn.commit()

        spool_fd, spool_path = tempfile.mkstemp(suffix=".csv")
        with os.fdopen(spool_fd, "wb") as out_file:
            while chunk := await file.read(1024 * 1024):
                out_file.write(chunk)

        worker_thread = threading.Thread(
            target=process_large_job_worker,
            args=(run_id, job_card_id, spool_path, is_override, uploader["username"]),
            daemon=True
        )
        worker_thread.start()

        return JSONResponse(status_code=202, content={
            "status": "processing",
            "run_id": run_id,
            "job_card_id": job_card_id,
            "message": "File received. Background ingestion initialized."
        })

    except HTTPException:
        conn.rollback()
        raise
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to initiate job creation: {str(e)}")
    finally:
        release_connection(conn)

@app.get("/api/jobs/{run_id}/upload-status")
def get_upload_status(run_id: int, user: dict = Depends(get_current_user)):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT job_card_id, description, status, total_codes, conflict_count, 
                       ingestion_progress, conflict_details, conflict_resolution, override_by, override_reason 
                FROM job_cards 
                WHERE run_id = %s
            """, (run_id,))
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Job not found")

            breakdown = []
            if row[6]:
                try:
                    breakdown = json.loads(row[6])
                except Exception:
                    breakdown = []

            return {
                "job_card_id": row[0],
                "description": row[1] or "",
                "status": row[2],
                "total_codes": row[3] or 0,
                "conflict_count": row[4] or 0,
                "progress_message": row[5] or "",
                "conflict_breakdown": breakdown,
                "conflict_resolution": row[7] or "NONE",
                "override_by": row[8] or "-",
                "override_reason": row[9] or "-"
            }
    finally:
        release_connection(conn)

@app.post("/api/jobs/{run_id}/proceed-override")
def proceed_override_job(
    run_id: int, 
    skip_conflicts: str = Form("false"),
    override_reason: str = Form(...),
    user: dict = Depends(require_uploader)
):
    clean_reason = override_reason.strip()
    if not clean_reason:
        raise HTTPException(status_code=400, detail="A mandatory justification reason must be provided to authorize duplicate overrides.")

    should_skip = str(skip_conflicts).strip().lower() in ("true", "1", "yes")

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            # 1. Acquire exclusive row lock to serialize concurrent proceed or cancel requests
            cur.execute("""
                SELECT job_card_id, status, total_codes, conflict_count, staged_file_path 
                FROM job_cards 
                WHERE run_id = %s
                FOR UPDATE
            """, (run_id,))
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Job Card not found")
            
            if row[1] != 'CONFLICT_DETECTED':
                raise HTTPException(
                    status_code=409, 
                    detail=f"Job Card is currently '{row[1]}' and is no longer awaiting conflict resolution."
                )

            job_card_id, _, total_codes, conflicts, clean_tsv_path = row

            if not clean_tsv_path or not os.path.exists(clean_tsv_path):
                raise HTTPException(
                    status_code=400, 
                    detail="Staged temporary file was cleared by server restart. Please delete this job card and re-upload."
                )

            # 2. Atomic conditional state transition: guarantees single-worker execution
            cur.execute("""
                UPDATE job_cards 
                SET status = 'OVERRIDING', 
                    ingestion_progress = 'Starting background database insertion...' 
                WHERE run_id = %s AND status = 'CONFLICT_DETECTED'
            """, (run_id,))
            
            if cur.rowcount != 1:
                conn.rollback()
                raise HTTPException(status_code=409, detail="Concurrent state modification detected. Action aborted.")

            conn.commit()

            # 3. Spawn background worker only after lock release and verified state change
            override_thread = threading.Thread(
                target=process_override_worker,
                args=(run_id, job_card_id, clean_tsv_path, conflicts, total_codes, user["username"], clean_reason, should_skip),
                daemon=True
            )
            override_thread.start()

            return JSONResponse(status_code=202, content={
                "status": "processing",
                "run_id": run_id,
                "job_card_id": job_card_id,
                "message": "Override ingestion started in background."
            })
    finally:
        release_connection(conn)

@app.post("/api/jobs/{run_id}/cancel-upload")
def cancel_upload_job(run_id: int, user: dict = Depends(require_uploader)):
    file_to_cleanup = None
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            # 1. Acquire exclusive row lock to block competing proceed operations
            cur.execute("""
                SELECT staged_file_path, job_card_id, status 
                FROM job_cards 
                WHERE run_id = %s
                FOR UPDATE
            """, (run_id,))
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Job Card not found")

            staged_file_path, jc_id, status = row

            if status not in ('CONFLICT_DETECTED', 'FAILED'):
                raise HTTPException(
                    status_code=409,
                    detail=f"Cannot cancel Job Card '{jc_id}' in state '{status}'. Only pending uploads with detected conflicts or failures can be cancelled."
                )

            # 2. Record immutable system audit event
            log_system_event(
                cur, 
                "JOB_LIFECYCLE", 
                jc_id, 
                "UPLOAD_DISCARDED", 
                user["username"], 
                f"Batch upload for Job Card '{jc_id}' discarded by operator during conflict review."
            )

            # 3. Clean up database entries first within the locked transaction
            cur.execute("DELETE FROM codes WHERE run_id = %s", (run_id,))
            cur.execute("DELETE FROM job_cards WHERE run_id = %s", (run_id,))
            conn.commit()

            # 4. Stage file path for removal strictly AFTER successful database commit
            file_to_cleanup = staged_file_path
            return {"status": "success", "message": f"Upload for Job Card '{jc_id}' successfully discarded."}
    finally:
        release_connection(conn)
        # 5. Remove the physical file on disk outside the DB lock only if commit succeeded
        if file_to_cleanup and os.path.exists(file_to_cleanup):
            try:
                os.remove(file_to_cleanup)
            except OSError:
                pass

@app.post("/api/admin/jobs/{run_id}/purge")
def purge_job(
    run_id: int, 
    admin_password: str = Form(...),
    user: dict = Depends(require_manager_or_admin)
):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT password_hash FROM users WHERE LOWER(username) = LOWER(%s)", (user["username"],))
            user_row = cur.fetchone()
            if not user_row or not verify_password(admin_password, user_row[0]):
                raise HTTPException(status_code=403, detail="Invalid password. Purge authorization denied.")

            cur.execute("SELECT staged_file_path, job_card_id, consumed_codes FROM job_cards WHERE run_id = %s", (run_id,))
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Job not found")

            staged_file_path, jc_id, consumed_codes = row

            cur.execute("SELECT COUNT(*) FROM scan_logs WHERE job_card_id = %s", (jc_id,))
            scan_count = cur.fetchone()[0]

            if (consumed_codes and consumed_codes > 0) or scan_count > 0:
                raise HTTPException(
                    status_code=400,
                    detail=f"Cannot purge Job Card '{jc_id}': verification scans have already been recorded ({consumed_codes or scan_count} verified)."
                )

            if staged_file_path and os.path.exists(staged_file_path):
                try:
                    os.remove(staged_file_path)
                except OSError:
                    pass

            log_system_event(cur, "JOB_LIFECYCLE", jc_id, "PURGE_JOB", user["username"], f"Purged unused job card '{jc_id}'")

            cur.execute("DELETE FROM codes WHERE run_id = %s", (run_id,))
            cur.execute("DELETE FROM packing_qc_logs WHERE job_card_id = %s", (jc_id,))
            cur.execute("DELETE FROM job_lifecycle_logs WHERE job_card_id = %s", (jc_id,))
            cur.execute("DELETE FROM job_cards WHERE run_id = %s", (run_id,))
            conn.commit()
            return {"status": "success", "message": f"Job Card '{jc_id}' has been purged."}
    finally:
        release_connection(conn)

@app.post("/api/packing-qc/verify")
def packing_qc_verify(
    job_card_id: str = Form(...),
    code: str = Form(...),
    user: dict = Depends(get_current_user)
):
    jc_id = job_card_id.strip()
    scanned_code = code.strip().replace('\r', '').replace('\n', '')

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT j.run_id, j.status, j.description 
                FROM job_cards j 
                WHERE j.job_card_id = %s AND j.status != 'DELETED'
            """, (jc_id,))
            jc = cur.fetchone()
            if not jc:
                return JSONResponse(status_code=200, content={
                    "matched": False,
                    "message": f"Job Card '{jc_id}' does not exist or is deleted."
                })

            run_id, status, description = jc

            cur.execute("""
                SELECT code_value, status 
                FROM codes 
                WHERE run_id = %s AND code_value = %s AND status != 'DELETED'
            """, (run_id, scanned_code))
            match_row = cur.fetchone()

            if not match_row:
                return JSONResponse(status_code=200, content={
                    "matched": False,
                    "message": f"Code '{scanned_code}' does not belong to Job Card '{jc_id}'."
                })

            cur.execute("""
                SELECT id FROM packing_qc_logs 
                WHERE job_card_id = %s AND code_scanned = %s 
                LIMIT 1
            """, (jc_id, scanned_code))
            if cur.fetchone():
                return JSONResponse(status_code=200, content={
                    "matched": False,
                    "message": "Code was already validated against this job card"
                })

            cur.execute("""
                INSERT INTO packing_qc_logs (job_card_id, code_scanned, tested_by) 
                VALUES (%s, %s, %s)
            """, (jc_id, scanned_code, user["username"]))
            log_system_event(cur, "FINAL_QC", jc_id, "FINAL_QC_PACK", user["username"], f"Tested code for packing: {scanned_code}")
            conn.commit()

            return JSONResponse(status_code=200, content={
                "matched": True,
                "job_card_id": jc_id,
                "description": description or "Serialized Production Batch",
                "code": scanned_code,
                "status": status,
                "message": "Final QC Approved, OK to Pack"
            })
    finally:
        release_connection(conn)

@app.post("/api/verify")
def verify_code(
    job_card_id: str = Form(...), 
    code: str = Form(...),
    user: dict = Depends(get_current_user)
):
    job_card_id = job_card_id.strip()
    scanned = code.strip().replace('\r', '').replace('\n', '')
    operator = user["username"]

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT run_id, status 
                FROM job_cards 
                WHERE job_card_id = %s AND status != 'DELETED'
                LIMIT 1;
            """, (job_card_id,))
            active_jc = cur.fetchone()
            if not active_jc:
                return JSONResponse(status_code=200, content={
                    "result": "BLOCKED",
                    "message": f"Job Card '{job_card_id}' is deleted or does not exist."
                })

            active_run_id, jc_status = active_jc
            if jc_status != 'ACTIVE':
                return JSONResponse(status_code=200, content={
                    "result": "BLOCKED",
                    "message": f"Job Card '{job_card_id}' is {jc_status}. Scanning is disabled for non-active jobs."
                })

            def log_scan(res, msg):
                cur.execute(
                    "INSERT INTO scan_logs (job_card_id, code_scanned, result, scanned_by) VALUES (%s, %s, %s, %s)",
                    (job_card_id, scanned, res, operator)
                )
                log_system_event(cur, "SCAN_VERIFICATION", job_card_id, f"SCAN_{res}", operator, f"Scanned code: {scanned} [{res}]")
                conn.commit()

            # Select code along with its immutable, explicit file row_num
            cur.execute("""
                SELECT id, code_value, status, COALESCE(row_num, 0)
                FROM codes 
                WHERE run_id = %s AND code_value = %s
                FOR UPDATE
                LIMIT 1;
            """, (active_run_id, scanned))
            code_row = cur.fetchone()

            if code_row:
                code_id, exact_code, current_status, row_num = code_row

                # Check previous highest verified row position directly
                cur.execute("""
                    SELECT COALESCE(row_num, 0) FROM codes 
                    WHERE run_id = %s AND status = 'CONSUMED' 
                    ORDER BY row_num DESC, id DESC LIMIT 1;
                """, (active_run_id,))
                max_row = cur.fetchone()
                max_consumed_row_num = max_row[0] if max_row else 0

                out_of_sequence = max_consumed_row_num > 0 and row_num < max_consumed_row_num

                if out_of_sequence:
                    if current_status == 'CONSUMED':
                        eval_result = "Duplicate (Potential Restart)"
                        msg = f"Duplicate (Potential Restart): Code {exact_code} (row {row_num}) was verified earlier."
                        log_scan(eval_result, msg)
                        return JSONResponse(status_code=200, content={
                            "result": eval_result,
                            "message": msg,
                            "sequence_warning": True,
                            "row_num": row_num
                        })

                    # Stage updates and logs in one single transaction (no premature commit)
                    cur.execute("UPDATE codes SET status = 'CONSUMED', scanned_at = NOW() WHERE id = %s", (code_id,))
                    cur.execute("UPDATE job_cards SET consumed_codes = consumed_codes + 1 WHERE run_id = %s", (active_run_id,))

                    eval_result = "Pass (Potential Restart)"
                    msg = f"Potential file restart: row ({row_num}) is lower than previously scanned ({max_consumed_row_num})."
                    log_scan(eval_result, msg)  # Atomic single commit handles codes, job_cards, and scan_logs together
                    return JSONResponse(status_code=200, content={
                        "result": eval_result,
                        "message": msg,
                        "sequence_warning": True,
                        "row_num": row_num
                    })

                if current_status in ('PENDING', 'BLOCKED'):
                    # Stage updates and logs in one single transaction (no premature commit)
                    cur.execute("UPDATE codes SET status = 'CONSUMED', scanned_at = NOW() WHERE id = %s", (code_id,))
                    cur.execute("UPDATE job_cards SET consumed_codes = consumed_codes + 1 WHERE run_id = %s", (active_run_id,))

                    eval_result = "PASS"
                    msg = f"Verified: {exact_code}"
                    log_scan(eval_result, msg)  # Atomic single commit handles codes, job_cards, and scan_logs together
                    return JSONResponse(status_code=200, content={
                        "result": eval_result,
                        "message": msg,
                        "sequence_warning": False,
                        "row_num": row_num
                    })
                
                elif current_status == 'CONSUMED':
                    eval_result = "DUPLICATE"
                    msg = f"Code {exact_code} was verified earlier!"
                    log_scan(eval_result, msg)
                    return JSONResponse(status_code=200, content={
                        "result": eval_result,
                        "message": msg,
                        "row_num": row_num
                    })

            cur.execute("""
                SELECT j.job_card_id, j.status 
                FROM codes c
                JOIN job_cards j ON c.run_id = j.run_id
                WHERE c.code_value = %s
                  AND j.status IN ('ACTIVE', 'INACTIVE', 'COMPLETED') 
                  AND c.status != 'DELETED'
                LIMIT 10;
            """, (scanned,))
            rows = cur.fetchall()

            if not rows:
                msg = "Code Does Not Exist"
                log_scan("UNKNOWN", msg)
                return JSONResponse(status_code=200, content={
                    "result": "UNKNOWN", 
                    "message": msg,
                    "row_num": "-"
                })

            owning_jobs = ", ".join(sorted(list(set([f"{r[0]} ({r[1]})" for r in rows]))))
            msg = f"Code Belongs to Another Job Card: {owning_jobs}"
            log_scan("MISMATCH", msg)
            return JSONResponse(status_code=200, content={
                "result": "MISMATCH", 
                "message": msg,
                "row_num": "-"
            })
    except Exception as e:
        if conn:
            try:
                conn.rollback()  # Cleanly roll back any partial uncommitted changes
            except Exception:
                pass
        return JSONResponse(status_code=200, content={
            "result": "ERROR",
            "message": f"Server verification error: {str(e)}",
            "row_num": "-"
        })
    finally:
        release_connection(conn)

@app.get("/api/jobs/{job_card_id}/recent-scans")
def get_recent_scans(job_card_id: str, limit: int = 50, user: dict = Depends(get_current_user)):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT run_id FROM job_cards 
                WHERE job_card_id = %s AND status != 'DELETED' 
                ORDER BY created_at DESC LIMIT 1
            """, (job_card_id,))
            jc_row = cur.fetchone()
            active_run_id = jc_row[0] if jc_row else None

            if active_run_id:
                cur.execute("""
                    WITH recent AS (
                        SELECT s.code_scanned, s.result, s.scanned_by, s.scanned_at
                        FROM scan_logs s
                        WHERE s.job_card_id = %s
                        ORDER BY s.id DESC
                        LIMIT %s
                    )
                    SELECT r.code_scanned, r.result, r.scanned_by, r.scanned_at,
                           c.row_num
                    FROM recent r
                    LEFT JOIN codes c ON c.run_id = %s AND c.code_value = r.code_scanned
                    ORDER BY r.scanned_at DESC;
                """, (job_card_id, limit, active_run_id))
            else:
                cur.execute("""
                    SELECT s.code_scanned, s.result, s.scanned_by, s.scanned_at,
                           NULL AS row_num
                    FROM scan_logs s
                    WHERE s.job_card_id = %s 
                    ORDER BY s.scanned_at DESC 
                    LIMIT %s
                """, (job_card_id, limit))

            logs = [{
                "code": r[0],
                "result": r[1],
                "user": r[2],
                "time": r[3].strftime("%Y-%m-%d %H:%M:%S") if r[3] else "",
                "row_num": r[4] if r[4] is not None else "-"
            } for r in cur.fetchall()]
            return {"recent_logs": logs}
    finally:
        release_connection(conn)

@app.get("/api/reports/{job_card_id}")
def get_report(job_card_id: str, user: dict = Depends(get_current_user)):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT run_id, job_card_id, description, status, created_at, total_codes, consumed_codes,
                       conflict_count, conflict_resolution, override_by, override_reason, conflict_details
                FROM job_cards 
                WHERE job_card_id = %s AND status != 'DELETED' 
                ORDER BY created_at DESC 
                LIMIT 1
            """, (job_card_id,))
            job = cur.fetchone()
            if not job:
                raise HTTPException(status_code=404, detail="Active Job Card not found")

            (run_id, jc_id, jc_desc, jc_status, jc_created, total_pool, consumed_pool,
             conf_cnt, conf_res, over_by, over_reason, conf_details) = job

            if not total_pool or total_pool == 0:
                cur.execute("SELECT COUNT(*) FROM codes WHERE run_id = %s", (run_id,))
                cnt_r = cur.fetchone()
                total_pool = cnt_r[0] if cnt_r else 0
                if total_pool > 0:
                    cur.execute("UPDATE job_cards SET total_codes = %s WHERE run_id = %s", (total_pool, run_id))
                    conn.commit()

            if not consumed_pool or consumed_pool == 0:
                cur.execute("SELECT COUNT(*) FROM codes WHERE run_id = %s AND status = 'CONSUMED'", (run_id,))
                cons_r = cur.fetchone()
                real_consumed = cons_r[0] if cons_r else 0
                if real_consumed > 0:
                    consumed_pool = real_consumed
                    cur.execute("UPDATE job_cards SET consumed_codes = %s WHERE run_id = %s", (consumed_pool, run_id))
                    conn.commit()

            cur.execute("""
                SELECT result, COUNT(*) 
                FROM scan_logs 
                WHERE job_card_id = %s 
                GROUP BY result
            """, (jc_id,))
            results_breakdown = {r[0]: r[1] for r in cur.fetchall()}

            if run_id:
                cur.execute("""
                    WITH recent AS (
                        SELECT s.code_scanned, s.result, s.scanned_by, s.scanned_at
                        FROM scan_logs s
                        WHERE s.job_card_id = %s
                        ORDER BY s.id DESC
                        LIMIT 5000
                    )
                    SELECT r.code_scanned, r.result, r.scanned_by, r.scanned_at,
                           c.row_num
                    FROM recent r
                    LEFT JOIN codes c ON c.run_id = %s AND c.code_value = r.code_scanned
                    ORDER BY r.scanned_at DESC;
                """, (jc_id, run_id))
            else:
                cur.execute("""
                    SELECT s.code_scanned, s.result, s.scanned_by, s.scanned_at,
                           NULL AS row_num
                    FROM scan_logs s
                    WHERE s.job_card_id = %s 
                    ORDER BY s.scanned_at DESC 
                    LIMIT 5000
                """, (jc_id,))

            logs = [{
                "code": r[0],
                "result": r[1],
                "user": r[2],
                "time": r[3].strftime("%Y-%m-%d %H:%M:%S") if r[3] else "",
                "row_num": r[4] if r[4] is not None else "-"
            } for r in cur.fetchall()]

            pending_count = max(0, (total_pool or 0) - (consumed_pool or 0))

            conf_breakdown = []
            if conf_details:
                try:
                    conf_breakdown = json.loads(conf_details)
                except Exception:
                    conf_breakdown = []

            return {
                "job_card_id": jc_id,
                "description": jc_desc or "",
                "status": jc_status,
                "created_at": jc_created.strftime("%Y-%m-%d %H:%M") if jc_created else "",
                "total_codes": total_pool or 0,
                "consumed_codes": consumed_pool or 0,
                "blocked_codes": pending_count if jc_status == 'COMPLETED' else 0,
                "pending_codes": pending_count if jc_status != 'COMPLETED' else 0,
                "results_breakdown": results_breakdown,
                "recent_logs": logs,
                "conflict_audit": {
                    "resolution": conf_res or "NONE",
                    "conflict_count": conf_cnt or 0,
                    "authorized_by": over_by or "-",
                    "justification": over_reason or "-",
                    "colliding_batches": conf_breakdown
                }
            }
    finally:
        release_connection(conn)

@app.get("/api/reports/{job_card_id}/csv")
def export_report_csv(job_card_id: str, user: dict = Depends(get_current_user)):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT run_id, description, status, conflict_resolution, conflict_count, 
                       override_by, override_reason, conflict_details 
                FROM job_cards 
                WHERE job_card_id = %s AND status != 'DELETED' 
                ORDER BY created_at DESC LIMIT 1
            """, (job_card_id,))
            jc_row = cur.fetchone()
            if not jc_row:
                raise HTTPException(status_code=404, detail="Job Card not found")

            (run_id, jc_desc, jc_status, conf_res, conf_cnt, 
             over_by, over_reason, conf_details) = jc_row

            if run_id:
                cur.execute("""
                    SELECT s.code_scanned, c.row_num, s.result, s.scanned_by, s.scanned_at 
                    FROM scan_logs s
                    LEFT JOIN codes c ON c.run_id = %s AND c.code_value = s.code_scanned
                    WHERE s.job_card_id = %s 
                    ORDER BY s.scanned_at ASC
                """, (run_id, job_card_id))
            else:
                cur.execute("""
                    SELECT s.code_scanned, NULL AS row_num, s.result, s.scanned_by, s.scanned_at 
                    FROM scan_logs s
                    WHERE s.job_card_id = %s 
                    ORDER BY s.scanned_at ASC
                """, (job_card_id,))

            rows = cur.fetchall()

            output = io.StringIO()
            output.write('\ufeff')
            writer = csv.writer(output)

            writer.writerow(["JOB VERIFICATION REPORT & AUDIT TRAIL"])
            writer.writerow(["Job Card ID:", job_card_id])
            writer.writerow(["Description:", jc_desc or "No Description"])
            writer.writerow(["Status:", jc_status])

            if conf_res and conf_res in ('OVERRIDDEN', 'SKIPPED'):
                writer.writerow([])
                writer.writerow(["--- CONFLICT RESOLUTION AUDIT ---"])
                writer.writerow(["Resolution Type:", conf_res])
                writer.writerow(["Conflicting Codes Found:", conf_cnt or 0])
                writer.writerow(["Authorized By:", over_by or "System"])
                writer.writerow(["Justification Reason:", over_reason or "N/A"])
                
                if conf_details:
                    try:
                        breakdown = json.loads(conf_details)
                        writer.writerow(["Colliding Batches:"])
                        for b in breakdown:
                            writer.writerow([
                                "",
                                f"Job: {b.get('job_card_id')}",
                                f"Description: {b.get('description', 'N/A')}",
                                f"Status: {b.get('status')}",
                                f"Conflicts: {b.get('conflict_count')}"
                            ])
                    except Exception:
                        pass
            
            writer.writerow([])
            writer.writerow(["--- SCAN LOGS ---"])
            writer.writerow(["Job Card ID", "Scanned Code", "Row #", "Result", "Tested By", "Timestamp"])
            for r in rows:
                row_val = r[1] if r[1] is not None else "-"
                writer.writerow([job_card_id, r[0], row_val, r[2], r[3], r[4].strftime("%Y-%m-%d %H:%M:%S") if r[4] else ""])

            output.seek(0)
            return StreamingResponse(
                iter([output.getvalue()]),
                media_type="text/csv",
                headers={"Content-Disposition": f"attachment; filename=QC_Report_{job_card_id}.csv"}
            )
    finally:
        release_connection(conn)

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("app.main:app", host="0.0.0.0", port=port, reload=False)
