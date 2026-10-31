import io
import os
import re
import csv
import json
import hashlib
import logging
import secrets
import time
import tempfile
import threading
import uuid
from typing import Optional
from urllib.parse import quote
from contextlib import asynccontextmanager
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Request, Response, Depends, Query
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from app.import_utils import escape_postgres_copy_text, iter_csv_tokens, spreadsheet_safe

from app.database import (
    init_db,
    get_connection,
    release_connection,
    hash_password,
    verify_password,
    close_connection_pool,
    PoolBusyError,
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
            cur.execute("ALTER TABLE job_cards ALTER COLUMN ingestion_progress TYPE TEXT;")
            cur.execute("ALTER TABLE job_cards ALTER COLUMN status TYPE VARCHAR(100);")
            cur.execute("ALTER TABLE job_cards ADD COLUMN IF NOT EXISTS conflict_resolution VARCHAR(50) DEFAULT 'NONE';")
            cur.execute("ALTER TABLE job_cards ADD COLUMN IF NOT EXISTS conflict_details TEXT;")
            cur.execute("ALTER TABLE job_cards ADD COLUMN IF NOT EXISTS override_by VARCHAR(100);")
            cur.execute("ALTER TABLE job_cards ADD COLUMN IF NOT EXISTS override_reason TEXT;")
            
            # row_num must exist before any index that references it (fresh databases)
            cur.execute("ALTER TABLE codes ADD COLUMN IF NOT EXISTS row_num INT;")

            # Auto-ensure high-speed verification indexes on startup
            cur.execute("CREATE INDEX IF NOT EXISTS idx_codes_run_val ON codes (run_id, code_value);")
            # Partial index covering only verified rows; replaces the much larger
            # (run_id, status, id) and (run_id, id) indexes.
            cur.execute("CREATE INDEX IF NOT EXISTS idx_codes_run_consumed ON codes (run_id, row_num, id) WHERE status = 'CONSUMED';")
            cur.execute("DROP INDEX IF EXISTS idx_codes_run_id_asc;")
            cur.execute("DROP INDEX IF EXISTS idx_codes_run_status_id;")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_codes_val_active ON codes (code_value) WHERE status != 'DELETED';")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_scan_logs_jc_id ON scan_logs (job_card_id, id DESC);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_packing_qc_jc_code ON packing_qc_logs (job_card_id, code_scanned);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_sys_audit_ts ON system_audit_logs (timestamp DESC);")
            
            # 1. Add explicit row_num index
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
                UPDATE job_cards j
                SET status = 'FAILED',
                    ingestion_progress = 'Interrupted by server restart. You can safely purge or re-upload.',
                    total_codes = (
                        SELECT COUNT(*) FROM codes c WHERE c.run_id = j.run_id
                    ),
                    consumed_codes = (
                        SELECT COUNT(*) FROM codes c
                        WHERE c.run_id = j.run_id AND c.status = 'CONSUMED'
                    )
                WHERE j.status IN ('INGESTING', 'OVERRIDING')
                RETURNING j.job_card_id;
            """)
            for (interrupted_job,) in cur.fetchall():
                log_job_failure(cur, interrupted_job, "System", "Ingestion interrupted by a server restart before it finished.")
            conn.commit()

    finally:
        release_connection(conn)

    threading.Thread(target=ingestion_watchdog_loop, daemon=True).start()

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

logger = logging.getLogger(__name__)
SESSION_SECRET = os.environ.get("SESSION_SECRET", "")
if len(SESSION_SECRET) < 32:
    raise RuntimeError("SESSION_SECRET must be configured with at least 32 characters.")
signer = URLSafeTimedSerializer(SESSION_SECRET)
SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "true").strip().lower() not in {
    "0",
    "false",
    "no",
}
MAX_UPLOAD_BYTES = int(os.environ.get("MAX_UPLOAD_BYTES", 250 * 1024 * 1024))
if MAX_UPLOAD_BYTES <= 0:
    raise RuntimeError("MAX_UPLOAD_BYTES must be a positive integer.")
# Scripts and styles are served from /static/vendor, so no third-party origin is allowed. Inline scripts remain
# permitted because the pages use inline handlers; 'wasm-unsafe-eval' is required by the OCR engine.
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data: blob:; "
    "media-src 'self' blob:; "
    "connect-src 'self'; "
    "worker-src 'self' blob:; "
    "font-src 'self' data:; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none'"
)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    headers = response.headers
    headers.setdefault("Content-Security-Policy", CONTENT_SECURITY_POLICY)
    headers.setdefault("X-Content-Type-Options", "nosniff")
    headers.setdefault("X-Frame-Options", "DENY")
    headers.setdefault("Referrer-Policy", "same-origin")
    headers.setdefault("Permissions-Policy", "camera=(self), microphone=(), geolocation=()")
    if SESSION_COOKIE_SECURE:
        headers.setdefault("Strict-Transport-Security", "max-age=31536000")
    if request.url.path.startswith("/static/vendor/"):
        headers.setdefault("Cache-Control", "public, max-age=86400")
    elif request.url.path.startswith("/api/"):
        headers.setdefault("Cache-Control", "no-store")
    return response


@app.exception_handler(PoolBusyError)
async def database_busy_handler(request: Request, exc: PoolBusyError):
    logger.warning("Request rejected: all database connections busy (%s %s)", request.method, request.url.path)
    return JSONResponse(
        status_code=503,
        content={"detail": "The server is busy. Please try again in a moment."},
        headers={"Retry-After": "5"},
    )

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
# Rate-Limiting & Brute-Force Defense
# ---------------------------------------------------------------------------
# Failed logins are limited per client address and, more loosely, per username so that rotating
# addresses does not allow unlimited guessing against one account. State is per process.
FAILED_ATTEMPTS = {}
FAILED_ATTEMPTS_LOCK = threading.Lock()
IP_MAX_ATTEMPTS, IP_WINDOW_SECONDS = 5, 300
USER_MAX_ATTEMPTS, USER_WINDOW_SECONDS = 10, 900
# Number of reverse proxies in front of the app that append to X-Forwarded-For. Leave at 0 when the app is
# reached directly: the header is client-controlled and is only trusted for the hops counted here.
TRUSTED_PROXY_COUNT = int(os.environ.get("TRUSTED_PROXY_COUNT", "0"))
if TRUSTED_PROXY_COUNT < 0:
    raise RuntimeError("TRUSTED_PROXY_COUNT must not be negative.")

def get_client_ip(request: Request) -> str:
    if TRUSTED_PROXY_COUNT:
        hops = [h.strip() for h in request.headers.get("x-forwarded-for", "").split(",") if h.strip()]
        if len(hops) >= TRUSTED_PROXY_COUNT:
            return hops[-TRUSTED_PROXY_COUNT]
    return request.client.host if request.client else "unknown"

def _login_keys(request: Request, username: str = ""):
    keys = [(f"ip:{get_client_ip(request)}", IP_MAX_ATTEMPTS, IP_WINDOW_SECONDS)]
    if username:
        keys.append((f"user:{username.strip().lower()}", USER_MAX_ATTEMPTS, USER_WINDOW_SECONDS))
    return keys

def check_rate_limit(request: Request, username: str = ""):
    now = time.time()
    with FAILED_ATTEMPTS_LOCK:
        for key, max_attempts, window in _login_keys(request, username):
            attempts = [t for t in FAILED_ATTEMPTS.get(key, []) if now - t < window]
            if attempts:
                FAILED_ATTEMPTS[key] = attempts
            else:
                FAILED_ATTEMPTS.pop(key, None)
            if len(attempts) >= max_attempts:
                minutes_remaining = int((attempts[0] + window - now) / 60) + 1
                raise HTTPException(
                    status_code=429,
                    detail=f"Too many failed login attempts. Please wait {minutes_remaining} minute(s).",
                    headers={"Retry-After": str(minutes_remaining * 60)},
                )

def record_failed_attempt(request: Request, username: str = ""):
    with FAILED_ATTEMPTS_LOCK:
        for key, _, _ in _login_keys(request, username):
            FAILED_ATTEMPTS.setdefault(key, []).append(time.time())

def clear_failed_attempts(request: Request, username: str = ""):
    with FAILED_ATTEMPTS_LOCK:
        for key, _, _ in _login_keys(request, username):
            FAILED_ATTEMPTS.pop(key, None)

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
    except Exception:
        logger.exception("Database health check failed")
        raise HTTPException(status_code=503, detail="Database health check failed")
    finally:
        if conn:
            release_connection(conn)

def log_system_event(cur, category: str, job_card_id: str, action: str, performed_by: str, details: str):
    cur.execute("""
        INSERT INTO system_audit_logs (category, job_card_id, action, performed_by, details)
        VALUES (%s, %s, %s, %s, %s)
    """, (category, job_card_id or "-", action, performed_by or "System", details))

def log_job_failure(cur, job_card_id: str, performed_by: str, reason: str):
    reason = (reason or "Unknown error")[:1000]
    cur.execute(
        "INSERT INTO job_lifecycle_logs (job_card_id, action, performed_by, reason) VALUES (%s, %s, %s, %s)",
        (job_card_id, "INGESTION_FAILED", performed_by or "System", reason),
    )
    log_system_event(cur, "JOB_LIFECYCLE", job_card_id, "INGESTION_FAILED", performed_by, reason)

ACTIVE_WORKERS = {}
ACTIVE_WORKERS_LOCK = threading.Lock()
WATCHDOG_INTERVAL_SECONDS = int(os.environ.get("INGEST_WATCHDOG_INTERVAL_SECONDS", "60"))

def run_tracked_worker(run_id: int, target, *args):
    with ACTIVE_WORKERS_LOCK:
        ACTIVE_WORKERS[run_id] = threading.current_thread()
    try:
        target(*args)
    finally:
        with ACTIVE_WORKERS_LOCK:
            ACTIVE_WORKERS.pop(run_id, None)

ORPHAN_SUSPECTS = set()

def fail_orphaned_jobs():
    """Fail INGESTING/OVERRIDING jobs with no live worker, after two consecutive sightings."""
    global ORPHAN_SUSPECTS
    with ACTIVE_WORKERS_LOCK:
        live = list(ACTIVE_WORKERS.keys())
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT run_id FROM job_cards
                WHERE status IN ('INGESTING', 'OVERRIDING') AND NOT (run_id = ANY(%s))
                """,
                (live,),
            )
            current = {r[0] for r in cur.fetchall()}
            confirmed = list(current & ORPHAN_SUSPECTS)
            ORPHAN_SUSPECTS = current
            if not confirmed:
                return
            cur.execute(
                """
                UPDATE job_cards
                SET status = 'FAILED',
                    ingestion_progress = 'Processing stopped unexpectedly (no active worker). You can safely purge or re-upload.'
                WHERE status IN ('INGESTING', 'OVERRIDING')
                  AND run_id = ANY(%s)
                  AND NOT (run_id = ANY(%s))
                RETURNING job_card_id
                """,
                (confirmed, live),
            )
            for (jc_id,) in cur.fetchall():
                log_job_failure(cur, jc_id, "System", "Watchdog: job was INGESTING but no worker was running; marked as failed.")
            conn.commit()
    finally:
        release_connection(conn)

def ingestion_watchdog_loop():
    while True:
        time.sleep(WATCHDOG_INTERVAL_SECONDS)
        try:
            fail_orphaned_jobs()
        except Exception:
            logger.exception("Ingestion watchdog pass failed")

def validate_password_strength(password: str):
    if len(password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters long.")
    if len(password.encode("utf-8")) > 72:
        raise HTTPException(status_code=400, detail="Password must be no longer than 72 UTF-8 bytes.")
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
                cur.execute(
                    "SELECT is_active, username, role, must_change_password "
                    "FROM users WHERE LOWER(username) = LOWER(%s)",
                    (data["username"],),
                )
                row = cur.fetchone()
                if not row or not row[0]:
                    raise HTTPException(status_code=403, detail="Account is suspended or deactivated.")
                data["username"] = row[1]
                data["role"] = row[2]
                data["must_change_password"] = row[3]
        finally:
            release_connection(conn)
        return data
    except (BadSignature, SignatureExpired):
        raise HTTPException(status_code=401, detail="Session expired or invalid")

def require_password_change_complete(user: dict = Depends(get_current_user)):
    if user.get("must_change_password"):
        raise HTTPException(
            status_code=403,
            detail="Change your password before using this feature.",
        )
    return user

def require_admin(user: dict = Depends(require_password_change_complete)):
    role = str(user.get("role", "")).lower().strip()
    if role not in ["admin", "administrator"]:
        raise HTTPException(status_code=403, detail="Admin permissions required")
    return user

def require_manager_or_admin(user: dict = Depends(require_password_change_complete)):
    role = str(user.get("role", "")).lower().strip()
    if role not in ["admin", "administrator", "qc manager"]:
        raise HTTPException(status_code=403, detail="QC Manager or Admin permissions required")
    return user

def require_uploader(user: dict = Depends(require_password_change_complete)):
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

def strip_repeated_header_row(cur, table: str) -> int:
    """Drop row 1 when it repeats values only within itself (e.g. 'URL,URL' headings).

    Real codes never repeat inside row 1 and nowhere else, so this is a header, not data.
    Returns the number of tokens removed.
    """
    cur.execute(f"""
        SELECT EXISTS (
            SELECT 1 FROM {table}
            GROUP BY code_value
            HAVING COUNT(*) > 1 AND MAX(line_num) = 1
        );
    """)
    if not cur.fetchone()[0]:
        return 0
    cur.execute(f"DELETE FROM {table} WHERE line_num = 1;")
    return cur.rowcount

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
            
            # 1. Parse CSV records so quoted commas remain part of their code values.
            cur.execute(f"""
                CREATE UNLOGGED TABLE {raw_table} (
                    line_num BIGINT,
                    col_num BIGINT,
                    raw_line TEXT
                );
            """)

            with open(temp_filepath, "r", encoding="utf-8-sig", newline="") as csv_file:
                copy_buffer = io.StringIO()
                buffered_tokens = 0

                def flush_csv_buffer():
                    nonlocal copy_buffer, buffered_tokens
                    if not buffered_tokens:
                        return
                    copy_buffer.seek(0)
                    cur.copy_expert(
                        f"COPY {raw_table} (line_num, col_num, raw_line) FROM STDIN WITH (FORMAT text)",
                        copy_buffer,
                    )
                    copy_buffer = io.StringIO()
                    buffered_tokens = 0

                for line_num, col_num, token in iter_csv_tokens(csv_file):
                    copy_buffer.write(
                        f"{line_num}\t{col_num}\t{escape_postgres_copy_text(token)}\n"
                    )
                    buffered_tokens += 1
                    if buffered_tokens >= 50_000:
                        flush_csv_buffer()
                flush_csv_buffer()

            cur.execute("UPDATE job_cards SET ingestion_progress = 'Extracting and ordering file tokens...' WHERE run_id = %s", (run_id,))
            conn.commit()

            # 2. Preserve CSV record and column order for the verification sequence.
            cur.execute(f"""
                CREATE UNLOGGED TABLE {tokens_table} AS
                SELECT 
                    row_number() OVER (ORDER BY t.line_num ASC, t.col_num ASC) AS original_seq,
                    t.line_num,
                    t.col_num,
                    t.cleaned_val AS code_value
                FROM (
                    SELECT 
                        r.line_num,
                        r.col_num,
                        r.raw_line AS cleaned_val
                    FROM {raw_table} r
                    WHERE r.raw_line IS NOT NULL AND TRIM(r.raw_line) != ''
                ) t
                WHERE t.cleaned_val != ''
                  AND LOWER(t.cleaned_val) NOT IN ('code', 'url', 'qr', 'qrcode', 'serial', 'barcode', 'data', 'id', 'link');
            """)

            cur.execute(f"DROP TABLE IF EXISTS {raw_table};")
            strip_repeated_header_row(cur, tokens_table)

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
                cur.execute(f"""
                    WITH duplicate_occurrences AS (
                        SELECT
                            code_value,
                            line_num,
                            col_num,
                            original_seq,
                            COUNT(*) OVER (PARTITION BY code_value) AS occurrence_count,
                            ROW_NUMBER() OVER (
                                PARTITION BY code_value ORDER BY original_seq
                            ) AS occurrence_number,
                            FIRST_VALUE(line_num) OVER (
                                PARTITION BY code_value ORDER BY original_seq
                            ) AS first_source_line,
                            FIRST_VALUE(col_num) OVER (
                                PARTITION BY code_value ORDER BY original_seq
                            ) AS first_source_column
                        FROM {tokens_table}
                    )
                    INSERT INTO job_code_duplicate_rows (
                        run_id, code_value, first_source_line, first_source_column,
                        duplicate_source_line, duplicate_source_column,
                        occurrence_number, occurrence_count
                    )
                    SELECT
                        %s,
                        duplicate.code_value,
                        duplicate.first_source_line,
                        duplicate.first_source_column,
                        duplicate.line_num,
                        duplicate.col_num,
                        duplicate.occurrence_number,
                        duplicate.occurrence_count
                    FROM duplicate_occurrences duplicate
                    WHERE duplicate.occurrence_count > 1
                      AND duplicate.occurrence_number > 1;
                """, (run_id,))
                reject_msg = f"Rejected: file contains {internal_duplicates_count:,} repeated row(s). No codes were activated."
                cur.execute(
                    "UPDATE job_cards SET status = 'FAILED', ingestion_progress = %s WHERE run_id = %s",
                    (reject_msg, run_id),
                )
                log_job_failure(cur, job_card_id, username, reject_msg)
                cur.execute(f"DROP TABLE IF EXISTS {tokens_table}, {incoming_table};")
                conn.commit()
                return

            cur.execute(f"DROP TABLE IF EXISTS {tokens_table};")

            if total_codes == 0:
                cur.execute("UPDATE job_cards SET status = 'FAILED', ingestion_progress = 'No valid codes found in uploaded file' WHERE run_id = %s", (run_id,))
                log_job_failure(cur, job_card_id, username, "No valid codes found in uploaded file")
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
                        consumed_codes = 0,
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
                cur.execute("""
                    UPDATE job_cards j
                    SET status = 'FAILED',
                        ingestion_progress = %s,
                        total_codes = (SELECT COUNT(*) FROM codes c WHERE c.run_id = j.run_id),
                        consumed_codes = (
                            SELECT COUNT(*) FROM codes c
                            WHERE c.run_id = j.run_id AND c.status = 'CONSUMED'
                        )
                    WHERE j.run_id = %s
                """, (f"Ingestion Error: {str(e)}", run_id))
                log_job_failure(cur, job_card_id, username, f"Ingestion Error: {str(e)}")
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
                        log_job_failure(cur, job_card_id, username, "All codes conflicted and were skipped. 0 codes remaining.")
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
                        consumed_codes = 0,
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
                cur.execute("""
                    UPDATE job_cards j
                    SET status = 'FAILED',
                        ingestion_progress = %s,
                        total_codes = (SELECT COUNT(*) FROM codes c WHERE c.run_id = j.run_id),
                        consumed_codes = (
                            SELECT COUNT(*) FROM codes c
                            WHERE c.run_id = j.run_id AND c.status = 'CONSUMED'
                        )
                    WHERE j.run_id = %s
                """, (f"Override Error: {str(e)}", run_id))
                log_job_failure(cur, job_card_id, username, f"Override Error: {str(e)}")
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


@app.get("/phone-scanner")
async def phone_scanner_page():
    return FileResponse(
        os.path.join(BASE_DIR, "templates", "phone-scanner.html"),
        media_type="text/html",
        headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"},
    )


@app.post("/api/phone-scanner/sessions")
def create_phone_scanner_session(
    job_card_id: str = Form(...),
    scan_target: str = Form("verification"),
    user: dict = Depends(require_password_change_complete),
):
    clean_job_card_id = job_card_id.strip()
    if not clean_job_card_id:
        raise HTTPException(status_code=400, detail="Select a Job Card first.")
    if scan_target not in {"verification", "packing-qc"}:
        raise HTTPException(status_code=400, detail="Invalid phone scanner target.")

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT status FROM job_cards
                WHERE job_card_id = %s AND status != 'DELETED'
                ORDER BY created_at DESC
                LIMIT 1
                """,
                (clean_job_card_id,),
            )
            job = cur.fetchone()
            if not job or (scan_target == "verification" and job[0] != "ACTIVE"):
                raise HTTPException(
                    status_code=409,
                    detail="Select a valid Job Card before pairing a phone scanner."
                    if scan_target == "packing-qc"
                    else "Select an active Job Card before pairing a phone.",
                )

            cur.execute("DELETE FROM phone_scanner_sessions WHERE expires_at <= NOW() OR revoked_at IS NOT NULL")
            session_id = str(uuid.uuid4())
            token = secrets.token_urlsafe(32)
            token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
            cur.execute(
                """
                INSERT INTO phone_scanner_sessions
                    (session_id, token_hash, username, job_card_id, scan_target, expires_at)
                VALUES (%s, %s, %s, %s, %s, NOW() + INTERVAL '8 hours')
                """,
                (session_id, token_hash, user["username"], clean_job_card_id, scan_target),
            )
            conn.commit()
            return {
                "session_id": session_id,
                "token": token,
                "job_card_id": clean_job_card_id,
                "scan_target": scan_target,
                "expires_in_seconds": 8 * 60 * 60,
            }
    finally:
        release_connection(conn)


@app.get("/api/phone-scanner/sessions/{session_id}/scans")
def poll_phone_scanner_scans(
    session_id: str,
    after: int = Query(0, ge=0),
    user: dict = Depends(require_password_change_complete),
):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT job_card_id, scan_target, expires_at > NOW() AND revoked_at IS NULL,
                       last_seen_at > NOW() - INTERVAL '30 seconds',
                       connected_at IS NOT NULL
                FROM phone_scanner_sessions
                WHERE session_id = %s AND username = %s
                """,
                (session_id, user["username"]),
            )
            session = cur.fetchone()
            if not session:
                raise HTTPException(status_code=404, detail="Phone scanner session not found.")
            job_card_id, scan_target, is_active, is_connected, was_paired = session
            if is_active and was_paired and not is_connected:
                # The phone paired earlier but stopped sending heartbeats (browser closed or navigated away).
                cur.execute(
                    "UPDATE phone_scanner_sessions SET revoked_at = NOW() WHERE session_id = %s AND revoked_at IS NULL",
                    (session_id,),
                )
                conn.commit()
                is_active = False
            if not is_active:
                raise HTTPException(status_code=410, detail="Phone scanner session has expired or ended.")

            cur.execute(
                "DELETE FROM phone_scanner_scans WHERE session_id = %s AND id <= %s",
                (session_id, after),
            )
            cur.execute(
                """
                SELECT id, code FROM phone_scanner_scans
                WHERE session_id = %s AND id > %s
                ORDER BY id
                LIMIT 20
                """,
                (session_id, after),
            )
            scans = [{"id": row[0], "code": row[1]} for row in cur.fetchall()]
            conn.commit()
            return {
                "job_card_id": job_card_id,
                "scan_target": scan_target,
                "connected": bool(is_connected),
                "scans": scans,
            }
    finally:
        release_connection(conn)


@app.post("/api/phone-scanner/sessions/{session_id}/end")
def end_phone_scanner_session(
    session_id: str,
    user: dict = Depends(require_password_change_complete),
):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE phone_scanner_sessions
                SET revoked_at = NOW()
                WHERE session_id = %s AND username = %s AND revoked_at IS NULL
                """,
                (session_id, user["username"]),
            )
            if cur.rowcount == 0:
                raise HTTPException(status_code=404, detail="Phone scanner session not found.")
            conn.commit()
            return {"status": "ended"}
    finally:
        release_connection(conn)


def update_phone_scanner_heartbeat(cur, token: str):
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    cur.execute(
        """
        UPDATE phone_scanner_sessions
        SET connected_at = COALESCE(connected_at, NOW()), last_seen_at = NOW()
        WHERE token_hash = %s AND expires_at > NOW() AND revoked_at IS NULL
        RETURNING session_id, job_card_id, scan_target
        """,
        (token_hash,),
    )
    session = cur.fetchone()
    if not session:
        raise HTTPException(status_code=410, detail="This phone scanner link has expired or ended.")
    return session


@app.post("/api/phone-scanner/connect")
def connect_phone_scanner(token: str = Form(...)):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            session = update_phone_scanner_heartbeat(cur, token)
            conn.commit()
            return {
                "status": "connected",
                "job_card_id": session[1],
                "scan_target": session[2],
            }
    finally:
        release_connection(conn)


@app.post("/api/phone-scanner/heartbeat")
def phone_scanner_heartbeat(token: str = Form(...)):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            update_phone_scanner_heartbeat(cur, token)
            conn.commit()
            return {"status": "connected"}
    finally:
        release_connection(conn)


@app.post("/api/phone-scanner/disconnect")
def disconnect_phone_scanner(token: str = Form(...)):
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE phone_scanner_sessions
                SET revoked_at = NOW()
                WHERE token_hash = %s AND expires_at > NOW() AND revoked_at IS NULL
                RETURNING session_id
                """,
                (token_hash,),
            )
            if not cur.fetchone():
                raise HTTPException(status_code=410, detail="This phone scanner session has already ended.")
            conn.commit()
            return {"status": "ended"}
    finally:
        release_connection(conn)


@app.post("/api/phone-scanner/scan")
def receive_phone_scanner_scan(token: str = Form(...), code: str = Form(...)):
    clean_code = code.strip().replace("\r", "").replace("\n", "")
    if not clean_code or len(clean_code) > 2048:
        raise HTTPException(status_code=400, detail="Scanned code must contain 1 to 2048 characters.")

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            session_id, job_card_id, scan_target = update_phone_scanner_heartbeat(cur, token)
            cur.execute(
                "INSERT INTO phone_scanner_scans (session_id, code) VALUES (%s, %s)",
                (session_id, clean_code),
            )
            conn.commit()
            return {"status": "received", "job_card_id": job_card_id, "scan_target": scan_target}
    finally:
        release_connection(conn)


@app.post("/api/auth/login")
def login(request: Request, response: Response, username: str = Form(...), password: str = Form(...)):
    clean_username = username.strip()
    check_rate_limit(request, clean_username)
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT password_hash, role, must_change_password, can_upload, is_active, username FROM users WHERE LOWER(username) = LOWER(%s)", (clean_username,))
            user = cur.fetchone()
            if not user or not verify_password(password, user[0]):
                record_failed_attempt(request, clean_username)
                log_system_event(cur, "USER_MGMT", "-", "LOGIN_FAILED", clean_username, f"Failed login attempt for username '{clean_username}'")
                conn.commit()
                raise HTTPException(status_code=400, detail="Invalid username or password")
            
            if not user[4]:
                raise HTTPException(status_code=403, detail="This account has been suspended.")

            clear_failed_attempts(request, clean_username)
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
                secure=SESSION_COOKIE_SECURE
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

    response.delete_cookie(
        "qc_session",
        secure=SESSION_COOKIE_SECURE,
        httponly=True,
        samesite="lax",
    )
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
def check_job_card_availability(job_card_id: str, user: dict = Depends(require_password_change_complete)):
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
def get_jobs(query: str = "", user: dict = Depends(require_password_change_complete)):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            base_sql = """
                SELECT j.job_card_id, j.description, j.status, j.created_at, j.run_id,
                       j.total_codes,
                       j.consumed_codes
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
def get_master_jobs_report(
    status_filter: str = "ALL",
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    search: str = Query("", max_length=200),
    sort_by: str = Query("default", max_length=32),
    sort_desc: bool = False,
    user: dict = Depends(require_manager_or_admin),
):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            filters = []
            params = []
            if status_filter in ["ACTIVE", "INACTIVE", "COMPLETED", "DELETED"]:
                filters.append("j.status = %s")
                params.append(status_filter)
            elif status_filter == "STUCK":
                filters.append("j.status IN ('INGESTING', 'OVERRIDING', 'CONFLICT_DETECTED', 'FAILED')")

            if search.strip():
                filters.append(
                    "(LOWER(j.job_card_id) LIKE %s "
                    "OR LOWER(COALESCE(j.description, '')) LIKE %s "
                    "OR LOWER(j.status) LIKE %s)"
                )
                search_term = f"%{search.strip().lower()}%"
                params.extend([search_term, search_term, search_term])

            where_clause = f"WHERE {' AND '.join(filters)}" if filters else ""
            cur.execute(f"SELECT COUNT(*) FROM job_cards j {where_clause}", params)
            total = cur.fetchone()[0]

            urgency_order = """CASE j.status
                WHEN 'CONFLICT_DETECTED' THEN 1
                WHEN 'INGESTING' THEN 2
                WHEN 'OVERRIDING' THEN 3
                WHEN 'FAILED' THEN 4
                WHEN 'ACTIVE' THEN 5
                WHEN 'INACTIVE' THEN 6
                WHEN 'COMPLETED' THEN 7
                WHEN 'DELETED' THEN 8
                ELSE 9
            END"""
            direction = "DESC" if sort_desc else "ASC"
            if sort_by == "job_card_id":
                order_clause = (
                    f"CASE WHEN j.job_card_id ~ '^[0-9]+$' "
                    f"THEN j.job_card_id::NUMERIC END {direction} NULLS LAST, "
                    f"LOWER(j.job_card_id) {direction}, j.created_at DESC"
                )
            elif sort_by == "created_at":
                order_clause = f"j.created_at {direction}, j.run_id DESC"
            elif sort_by == "status":
                order_clause = f"{urgency_order} {direction}, j.created_at DESC"
            elif sort_by in {"consumed", "conflict_count", "packing_qc_count"}:
                order_clause = f"{sort_by} {direction}, j.created_at DESC"
            else:
                order_clause = f"{urgency_order} ASC, j.created_at DESC"

            query_params = [*params, page_size, (page - 1) * page_size]
            sql = f"""
                SELECT j.run_id, j.job_card_id, j.description, j.status,
                       j.total_codes as total,
                       j.consumed_codes as consumed,
                       j.created_at,
                       j.deleted_by,
                       j.deleted_at,
                       j.deletion_reason,
                       (SELECT COUNT(*) FROM packing_qc_logs p
                        WHERE p.run_id = j.run_id AND p.qc_stage = 'PACKING') as packing_qc_count,
                       j.ingestion_progress,
                       j.conflict_count,
                       COALESCE(j.conflict_resolution, 'NONE') as conflict_resolution
                FROM job_cards j
                {where_clause}
                ORDER BY {order_clause}
                LIMIT %s OFFSET %s
            """
            cur.execute(sql, query_params)
            rows = cur.fetchall()
            jobs = [{
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
            return {
                "jobs": jobs,
                "total": total,
                "page": page,
                "page_size": page_size,
            }
    finally:
        release_connection(conn)

@app.get("/api/admin/jobs/count-reconciliation")
def get_job_count_reconciliation(user: dict = Depends(require_manager_or_admin)):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                WITH actual_counts AS (
                    SELECT
                        j.run_id,
                        j.job_card_id,
                        COALESCE(j.total_codes, 0) AS stored_total,
                        COALESCE(j.consumed_codes, 0) AS stored_consumed,
                        COUNT(c.id) AS actual_total,
                        COUNT(c.id) FILTER (WHERE c.status = 'CONSUMED') AS actual_consumed
                    FROM job_cards j
                    LEFT JOIN codes c ON c.run_id = j.run_id
                    GROUP BY j.run_id, j.job_card_id, j.total_codes, j.consumed_codes
                ),
                drift AS (
                    SELECT *
                    FROM actual_counts
                    WHERE stored_total != actual_total
                       OR stored_consumed != actual_consumed
                )
                SELECT
                    COUNT(*) OVER () AS mismatch_count,
                    run_id,
                    job_card_id,
                    stored_total,
                    actual_total,
                    stored_consumed,
                    actual_consumed
                FROM drift
                ORDER BY job_card_id, run_id DESC
                LIMIT 100
            """)
            rows = cur.fetchall()
            return {
                "mismatch_count": rows[0][0] if rows else 0,
                "truncated": len(rows) == 100 and rows[0][0] > 100,
                "jobs": [{
                    "run_id": row[1],
                    "job_card_id": row[2],
                    "stored_total": row[3],
                    "actual_total": row[4],
                    "stored_consumed": row[5],
                    "actual_consumed": row[6],
                } for row in rows],
            }
    finally:
        release_connection(conn)

@app.get("/api/admin/packing-qc/{job_card_id}")
def get_packing_qc_logs(
    job_card_id: str,
    limit: int = Query(100, ge=1, le=200),
    before_id: Optional[int] = Query(None, ge=1),
    user: dict = Depends(require_password_change_complete),
):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT run_id, description, created_at FROM job_cards
                WHERE job_card_id = %s AND status != 'DELETED'
                ORDER BY created_at DESC LIMIT 1
            """, (job_card_id,))
            jc_row = cur.fetchone()
            if not jc_row:
                raise HTTPException(status_code=404, detail=f"Job Card '{job_card_id}' does not exist.")
            run_id, job_created_at = jc_row[0], jc_row[2]
            desc = jc_row[1] or ""
            cur.execute("""
                SELECT EXISTS (
                    SELECT 1
                    FROM scan_logs s
                    WHERE s.job_card_id = %s
                      AND UPPER(s.result) IN ('PASS', 'PASS (POTENTIAL RESTART)')
                      AND (
                          s.run_id = %s
                          OR (
                              s.run_id IS NULL
                              AND s.scanned_at >= %s
                              AND EXISTS (
                                  SELECT 1
                                  FROM codes c
                                  WHERE c.run_id = %s
                                    AND c.code_value = s.code_scanned
                                    AND c.status != 'DELETED'
                              )
                          )
                      )
                )
            """, (job_card_id, run_id, job_created_at, run_id))
            has_production_scans = cur.fetchone()[0]
            cur.execute("""
                SELECT COUNT(*)
                FROM packing_qc_logs
                WHERE run_id = %s AND qc_stage = 'PACKING'
            """, (run_id,))
            total_logs = cur.fetchone()[0]
            if before_id is None:
                cur.execute("""
                    SELECT id, job_card_id, code_scanned, tested_by, tested_at
                    FROM packing_qc_logs
                    WHERE run_id = %s AND qc_stage = 'PACKING'
                    ORDER BY id DESC
                    LIMIT %s
                """, (run_id, limit + 1))
            else:
                cur.execute("""
                    SELECT id, job_card_id, code_scanned, tested_by, tested_at
                    FROM packing_qc_logs
                    WHERE run_id = %s AND qc_stage = 'PACKING' AND id < %s
                    ORDER BY id DESC
                    LIMIT %s
                """, (run_id, before_id, limit + 1))
            rows = cur.fetchall()
            has_more = len(rows) > limit
            rows = rows[:limit]

            return {
                "job_card_id": job_card_id,
                "run_id": run_id,
                "description": desc or "Serialized Production Batch",
                "has_production_scans": has_production_scans,
                "total_logs": total_logs,
                "logs": [{
                    "id": r[0],
                    "code": r[2],
                    "tested_by": r[3],
                    "tested_at": r[4].strftime("%Y-%m-%d %H:%M:%S") if r[4] else ""
                } for r in rows],
                "next_before_id": rows[-1][0] if has_more and rows else None,
            }
    finally:
        release_connection(conn)

@app.get("/api/jobs/{job_card_id}/lifecycle-logs")
def get_job_lifecycle_logs(job_card_id: str, user: dict = Depends(require_password_change_complete)):
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
def complete_job(job_card_id: str, user: dict = Depends(require_password_change_complete)):
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

def _check_upload_size(file: UploadFile):
    size = file.size
    if size is None:
        file.file.seek(0, os.SEEK_END)
        size = file.file.tell()
        file.file.seek(0)
    if size > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"Upload exceeds the {MAX_UPLOAD_BYTES // (1024 * 1024)} MB size limit.",
        )


def _load_preview_tokens(cur, binary_file):
    binary_file.seek(0)
    cur.execute("""
        CREATE TEMP TABLE upload_preview_tokens (
            line_num BIGINT NOT NULL,
            col_num BIGINT NOT NULL,
            code_value TEXT NOT NULL
        ) ON COMMIT DROP;
    """)

    text_file = io.TextIOWrapper(binary_file, encoding="utf-8-sig", newline="")
    copy_buffer = io.StringIO()
    buffered_tokens = 0
    try:
        for line_num, col_num, token in iter_csv_tokens(text_file):
            copy_buffer.write(
                f"{line_num}\t{col_num}\t{escape_postgres_copy_text(token)}\n"
            )
            buffered_tokens += 1
            if buffered_tokens >= 50_000:
                copy_buffer.seek(0)
                cur.copy_expert(
                    "COPY upload_preview_tokens (line_num, col_num, code_value) "
                    "FROM STDIN WITH (FORMAT text)",
                    copy_buffer,
                )
                copy_buffer = io.StringIO()
                buffered_tokens = 0
        if buffered_tokens:
            copy_buffer.seek(0)
            cur.copy_expert(
                "COPY upload_preview_tokens (line_num, col_num, code_value) "
                "FROM STDIN WITH (FORMAT text)",
                copy_buffer,
            )
    finally:
        text_file.detach()

    cur.execute("""
        CREATE INDEX upload_preview_tokens_code_idx
        ON upload_preview_tokens (code_value, line_num, col_num);
    """)
    cur.execute("ANALYZE upload_preview_tokens;")


def _count_upload_duplicates(cur):
    cur.execute("""
        SELECT COUNT(*), COALESCE(SUM(occurrences - 1), 0)
        FROM (
            SELECT COUNT(*) AS occurrences
            FROM upload_preview_tokens
            GROUP BY code_value
            HAVING COUNT(*) > 1
        ) duplicates;
    """)
    return cur.fetchone()


def _duplicate_csv_stream(conn):
    report_cursor = None
    try:
        report_cursor = conn.cursor(name=f"duplicate_csv_{uuid.uuid4().hex}")
        report_cursor.itersize = 1000
        report_cursor.execute("""
            WITH duplicate_occurrences AS (
                SELECT
                    code_value,
                    line_num,
                    col_num,
                    COUNT(*) OVER (PARTITION BY code_value) AS occurrence_count,
                    ROW_NUMBER() OVER (
                        PARTITION BY code_value ORDER BY line_num, col_num
                    ) AS occurrence_number,
                    FIRST_VALUE(line_num) OVER (
                        PARTITION BY code_value ORDER BY line_num, col_num
                    ) AS first_source_line,
                    FIRST_VALUE(col_num) OVER (
                        PARTITION BY code_value ORDER BY line_num, col_num
                    ) AS first_source_column
                FROM upload_preview_tokens
            )
            SELECT
                code_value, occurrence_count, occurrence_number, line_num, col_num,
                first_source_line, first_source_column
            FROM duplicate_occurrences
            WHERE occurrence_count > 1
              AND occurrence_number > 1
            ORDER BY code_value, occurrence_number;
        """)

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "Code Value", "Total Occurrences", "Occurrence Number",
            "Source CSV Row", "Source CSV Column",
            "First Occurrence CSV Row", "First Occurrence CSV Column",
        ])
        yield "\ufeff" + output.getvalue()

        for row in report_cursor:
            output.seek(0)
            output.truncate(0)
            writer.writerow([spreadsheet_safe(value) for value in row])
            yield output.getvalue()
    finally:
        try:
            if report_cursor:
                report_cursor.close()
        finally:
            release_connection(conn)


def _stored_duplicate_csv_stream(conn, run_id: int):
    report_cursor = None
    try:
        report_cursor = conn.cursor(name=f"stored_duplicate_csv_{uuid.uuid4().hex}")
        report_cursor.itersize = 1000
        report_cursor.execute("""
            SELECT
                code_value, occurrence_count, occurrence_number,
                duplicate_source_line, duplicate_source_column,
                first_source_line, first_source_column
            FROM job_code_duplicate_rows
            WHERE run_id = %s
            ORDER BY code_value, occurrence_number;
        """, (run_id,))

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "Code Value", "Total Occurrences", "Occurrence Number",
            "Source CSV Row", "Source CSV Column",
            "First Occurrence CSV Row", "First Occurrence CSV Column",
        ])
        yield "\ufeff" + output.getvalue()

        for row in report_cursor:
            output.seek(0)
            output.truncate(0)
            writer.writerow([spreadsheet_safe(value) for value in row])
            yield output.getvalue()
    finally:
        try:
            if report_cursor:
                report_cursor.close()
        finally:
            release_connection(conn)


@app.post("/api/jobs/preview")
def preview_job_file(
    file: UploadFile = File(...),
    uploader: dict = Depends(require_uploader),
):
    _check_upload_size(file)
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            _load_preview_tokens(cur, file.file)
            strip_repeated_header_row(cur, "upload_preview_tokens")
            cur.execute("""
                SELECT COUNT(*), COUNT(DISTINCT code_value)
                FROM upload_preview_tokens;
            """)
            row = cur.fetchone()
            total_rows, unique_codes = row if row else (0, 0)
            if not total_rows:
                raise HTTPException(status_code=400, detail="No valid codes found in uploaded file.")

            duplicate_groups, duplicate_rows = _count_upload_duplicates(cur)

            cur.execute("""
                SELECT
                    grouped.code_value,
                    grouped.occurrences,
                    grouped.first_source_line,
                    ARRAY(
                        SELECT duplicate_rows.line_num
                        FROM upload_preview_tokens duplicate_rows
                        WHERE duplicate_rows.code_value = grouped.code_value
                        ORDER BY duplicate_rows.line_num, duplicate_rows.col_num
                        LIMIT 5
                    ) AS source_lines
                FROM (
                    SELECT
                        code_value,
                        COUNT(*) AS occurrences,
                        MIN(line_num) AS first_source_line
                    FROM upload_preview_tokens
                    GROUP BY code_value
                    HAVING COUNT(*) > 1
                    ORDER BY COUNT(*) DESC, code_value
                    LIMIT 10
                ) grouped;
            """)
            samples = [
                {
                    "code_value": sample[0],
                    "occurrences": sample[1],
                    "first_source_line": sample[2],
                    "source_lines": sample[3],
                }
                for sample in cur.fetchall()
            ]
            conn.commit()
            return {
                "total_rows": total_rows,
                "unique_codes": unique_codes,
                "duplicate_groups": duplicate_groups,
                "duplicate_rows": duplicate_rows,
                "samples": samples,
            }
    except (csv.Error, UnicodeDecodeError) as exc:
        conn.rollback()
        raise HTTPException(status_code=400, detail=f"Invalid CSV file: {exc}") from exc
    finally:
        release_connection(conn)


@app.post("/api/jobs/preview/duplicate-report.csv")
def download_preview_duplicate_report(
    file: UploadFile = File(...),
    uploader: dict = Depends(require_uploader),
):
    _check_upload_size(file)
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            _load_preview_tokens(cur, file.file)
            strip_repeated_header_row(cur, "upload_preview_tokens")
        return StreamingResponse(
            _duplicate_csv_stream(conn),
            media_type="text/csv; charset=utf-8",
            headers={
                "Content-Disposition": "attachment; filename=duplicate_codes_preview.csv"
            },
        )
    except (csv.Error, UnicodeDecodeError) as exc:
        conn.rollback()
        release_connection(conn)
        raise HTTPException(status_code=400, detail=f"Invalid CSV file: {exc}") from exc
    except Exception:
        conn.rollback()
        release_connection(conn)
        raise


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
    if not job_card_id:
        raise HTTPException(status_code=400, detail="Job Card ID is required.")
    _check_upload_size(file)

    conn = None
    spool_path = None
    staged_path_to_remove = None
    try:
        spool_fd, spool_path = tempfile.mkstemp(suffix=".csv")
        total_bytes = 0
        with os.fdopen(spool_fd, "wb") as out_file:
            while chunk := await file.read(1024 * 1024):
                total_bytes += len(chunk)
                if total_bytes > MAX_UPLOAD_BYTES:
                    raise HTTPException(
                        status_code=413,
                        detail=f"Upload exceeds the {MAX_UPLOAD_BYTES // (1024 * 1024)} MB size limit.",
                    )
                out_file.write(chunk)

        if total_bytes == 0:
            raise HTTPException(status_code=400, detail="The uploaded CSV file is empty.")

        conn = get_connection()
        with conn.cursor() as cur:
            with open(spool_path, "rb") as staged_file:
                _load_preview_tokens(cur, staged_file)
                strip_repeated_header_row(cur, "upload_preview_tokens")
            duplicate_groups, duplicate_rows = _count_upload_duplicates(cur)
            if duplicate_rows:
                raise HTTPException(
                    status_code=400,
                    detail=(
                        f"Job creation is blocked: the file contains {duplicate_rows:,} "
                        f"repeated row(s) across {duplicate_groups:,} code(s). "
                        "Download the duplicate report, correct the source file, and upload it again."
                    ),
                )
            cur.execute("DROP TABLE upload_preview_tokens;")

            cur.execute("SELECT run_id, status FROM job_cards WHERE job_card_id = %s AND status != 'DELETED'", (job_card_id,))
            existing = cur.fetchone()
            if existing:
                ex_run_id, ex_status = existing
                if ex_status in ('ACTIVE', 'COMPLETED', 'INACTIVE'):
                    raise HTTPException(status_code=400, detail=f"Active Job Card '{job_card_id}' already exists in the system.")
                if ex_status in ('INGESTING', 'OVERRIDING', 'CONFLICT_DETECTED'):
                    raise HTTPException(
                        status_code=409,
                        detail=f"Job Card '{job_card_id}' has an upload in progress or awaiting conflict resolution.",
                    )
                cur.execute(
                    "SELECT staged_file_path FROM job_cards WHERE run_id = %s",
                    (ex_run_id,),
                )
                staged_row = cur.fetchone()
                staged_path_to_remove = staged_row[0] if staged_row else None
                cur.execute("DELETE FROM job_cards WHERE run_id = %s", (ex_run_id,))

            cur.execute("""
                INSERT INTO job_cards (job_card_id, description, status, ingestion_progress) 
                VALUES (%s, %s, 'INGESTING', 'Receiving uploaded file on disk...') 
                RETURNING run_id
            """, (job_card_id, description))
            run_id = cur.fetchone()[0]
            conn.commit()

        if staged_path_to_remove and os.path.exists(staged_path_to_remove):
            try:
                os.remove(staged_path_to_remove)
            except OSError:
                logger.exception("Failed to remove superseded staging file")
        staged_path_to_remove = None

        worker_thread = threading.Thread(
            target=run_tracked_worker,
            args=(run_id, process_large_job_worker, run_id, job_card_id, spool_path, is_override, uploader["username"]),
            daemon=True
        )
        try:
            worker_thread.start()
        except Exception:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE job_cards SET status = 'FAILED', ingestion_progress = %s WHERE run_id = %s",
                    ("Could not start background ingestion.", run_id),
                )
                log_job_failure(cur, job_card_id, uploader["username"], "Could not start background ingestion.")
                conn.commit()
            raise
        spool_path = None

        return JSONResponse(status_code=202, content={
            "status": "processing",
            "run_id": run_id,
            "job_card_id": job_card_id,
            "message": "File received. Background ingestion initialized."
        })
    except (csv.Error, UnicodeDecodeError) as exc:
        if conn:
            conn.rollback()
        raise HTTPException(status_code=400, detail=f"Invalid CSV file: {exc}") from exc
    except HTTPException:
        if conn:
            conn.rollback()
        raise
    except Exception:
        logger.exception("Failed to initiate job creation for run %s", job_card_id)
        if conn:
            conn.rollback()
        raise HTTPException(status_code=500, detail="Failed to initiate job creation.")
    finally:
        if conn:
            release_connection(conn)
        if spool_path and os.path.exists(spool_path):
            try:
                os.remove(spool_path)
            except OSError:
                logger.exception("Failed to remove temporary upload file")
        await file.close()

@app.get("/api/jobs/{run_id}/upload-status")
def get_upload_status(run_id: int, user: dict = Depends(require_password_change_complete)):
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
                target=run_tracked_worker,
                args=(run_id, process_override_worker, run_id, job_card_id, clean_tsv_path, conflicts, total_codes, user["username"], clean_reason, should_skip),
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

@app.post("/api/admin/jobs/{run_id}/force-fail")
def force_fail_job(run_id: int, user: dict = Depends(require_manager_or_admin)):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT job_card_id, status FROM job_cards WHERE run_id = %s FOR UPDATE", (run_id,))
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Job not found")
            jc_id, status = row
            if status not in ('INGESTING', 'OVERRIDING'):
                raise HTTPException(status_code=409, detail=f"Job Card '{jc_id}' is '{status}', not processing.")
            cur.execute(
                """
                UPDATE job_cards
                SET status = 'FAILED',
                    ingestion_progress = %s
                WHERE run_id = %s
                """,
                (f"Force-failed by {user['username']}. You can safely purge or re-upload.", run_id),
            )
            log_job_failure(cur, jc_id, user["username"], f"Processing manually force-failed by {user['username']} while in state {status}.")
            conn.commit()
            return {"status": "success", "message": f"Job Card '{jc_id}' marked as FAILED."}
    finally:
        release_connection(conn)

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

            cur.execute("SELECT staged_file_path, job_card_id, consumed_codes, status FROM job_cards WHERE run_id = %s", (run_id,))
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Job not found")

            staged_file_path, jc_id, consumed_codes, current_status = row

            if current_status in ('INGESTING', 'OVERRIDING'):
                raise HTTPException(
                    status_code=409,
                    detail=f"Cannot purge Job Card '{jc_id}': batch is actively being processed ({current_status}). Wait for completion or failure before purging."
                )

            cur.execute("""
                SELECT COUNT(*)
                FROM scan_logs
                WHERE job_card_id = %s
                  AND UPPER(result) IN ('PASS', 'PASS (POTENTIAL RESTART)')
            """, (jc_id,))
            verified_scan_count = cur.fetchone()[0]

            if (consumed_codes and consumed_codes > 0) or verified_scan_count > 0:
                raise HTTPException(
                    status_code=400,
                    detail=f"Cannot purge Job Card '{jc_id}': verified scans have already been recorded ({consumed_codes or verified_scan_count} verified)."
                )

            if staged_file_path and os.path.exists(staged_file_path):
                try:
                    os.remove(staged_file_path)
                except OSError:
                    pass

            log_system_event(cur, "JOB_LIFECYCLE", jc_id, "PURGE_JOB", user["username"], f"Purged unused job card '{jc_id}'")

            cur.execute("DELETE FROM codes WHERE run_id = %s", (run_id,))
            cur.execute(
                "DELETE FROM packing_qc_logs WHERE run_id = %s OR (run_id IS NULL AND job_card_id = %s)",
                (run_id, jc_id),
            )
            cur.execute("DELETE FROM packing_qc_completions WHERE run_id = %s", (run_id,))
            cur.execute(
                "DELETE FROM scan_logs WHERE run_id = %s OR (run_id IS NULL AND job_card_id = %s)",
                (run_id, jc_id),
            )
            cur.execute("DELETE FROM phone_scanner_sessions WHERE job_card_id = %s", (jc_id,))
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
    user: dict = Depends(require_password_change_complete)
):
    jc_id = job_card_id.strip()
    scanned_code = code.strip().replace('\r', '').replace('\n', '')

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT j.run_id, j.status, j.description, j.created_at
                FROM job_cards j 
                WHERE j.job_card_id = %s AND j.status != 'DELETED'
                ORDER BY j.created_at DESC
                LIMIT 1
                FOR UPDATE
            """, (jc_id,))
            jc = cur.fetchone()
            if not jc:
                return JSONResponse(status_code=200, content={
                    "matched": False,
                    "message": f"Job Card '{jc_id}' does not exist or is deleted."
                })

            run_id, status, description, job_created_at = jc

            cur.execute("""
                SELECT EXISTS (
                    SELECT 1
                    FROM scan_logs s
                    WHERE s.job_card_id = %s
                      AND UPPER(s.result) IN ('PASS', 'PASS (POTENTIAL RESTART)')
                      AND (
                          s.run_id = %s
                          OR (
                              s.run_id IS NULL
                              AND s.scanned_at >= %s
                              AND EXISTS (
                                  SELECT 1
                                  FROM codes c
                                  WHERE c.run_id = %s
                                    AND c.code_value = s.code_scanned
                                    AND c.status != 'DELETED'
                              )
                          )
                      )
                )
            """, (jc_id, run_id, job_created_at, run_id))
            has_production_scans = cur.fetchone()[0]

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

            if has_production_scans:
                cur.execute("""
                    SELECT id FROM packing_qc_logs
                    WHERE run_id = %s AND code_scanned = %s AND qc_stage = 'PACKING'
                    LIMIT 1
                """, (run_id, scanned_code))
                if cur.fetchone():
                    return JSONResponse(status_code=200, content={
                        "matched": False,
                        "message": "Code was already validated during Packing QC for this job."
                    })

                cur.execute("""
                    INSERT INTO packing_qc_logs (run_id, job_card_id, code_scanned, tested_by, qc_stage)
                    VALUES (%s, %s, %s, %s, 'PACKING')
                """, (run_id, jc_id, scanned_code, user["username"]))
                log_system_event(cur, "FINAL_QC", jc_id, "FINAL_QC_PACK", user["username"], f"Packing QC tested code: {scanned_code}")
                conn.commit()
                message = "Code passed Packing QC and was recorded."
            else:
                message = "Code passed the pre-check."

            return JSONResponse(status_code=200, content={
                "matched": True,
                "job_card_id": jc_id,
                "description": description or "Serialized Production Batch",
                "code": scanned_code,
                "status": status,
                "qc_stage": "PACKING" if has_production_scans else "PRECHECK",
                "has_production_scans": has_production_scans,
                "message": message
            })
    finally:
        release_connection(conn)

@app.post("/api/packing-qc/complete")
def complete_packing_qc(user: dict = Depends(require_password_change_complete)):
    raise HTTPException(
        status_code=410,
        detail="Packing QC is no longer completed or locked. Continue verifying codes as needed.",
    )

@app.post("/api/verify")
def verify_code(
    job_card_id: str = Form(...), 
    code: str = Form(...),
    user: dict = Depends(require_password_change_complete)
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
                    "INSERT INTO scan_logs (run_id, job_card_id, code_scanned, result, scanned_by) VALUES (%s, %s, %s, %s, %s)",
                    (active_run_id, job_card_id, scanned, res, operator)
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
    except Exception:
        if conn:
            try:
                conn.rollback()
            except Exception:
                pass
        logger.exception("Code verification failed")
        return JSONResponse(status_code=500, content={
            "result": "ERROR",
            "message": "Verification failed due to a server error.",
            "row_num": "-"
        })
    finally:
        release_connection(conn)

@app.get("/api/jobs/{job_card_id}/recent-scans")
def get_recent_scans(
    job_card_id: str, 
    limit: int = Query(50, ge=1, le=500),
    before_id: Optional[int] = Query(None, gt=0),
    user: dict = Depends(require_password_change_complete)
):
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
                if before_id:
                    cur.execute("""
                        WITH recent AS (
                            SELECT s.id, s.code_scanned, s.result, s.scanned_by, s.scanned_at
                            FROM scan_logs s
                            WHERE s.job_card_id = %s AND s.id < %s
                            ORDER BY s.id DESC
                            LIMIT %s
                        )
                        SELECT r.id, r.code_scanned, r.result, r.scanned_by, r.scanned_at,
                               c.row_num
                        FROM recent r
                        LEFT JOIN codes c ON c.run_id = %s AND c.code_value = r.code_scanned
                        ORDER BY r.id DESC;
                    """, (job_card_id, before_id, limit, active_run_id))
                else:
                    cur.execute("""
                        WITH recent AS (
                            SELECT s.id, s.code_scanned, s.result, s.scanned_by, s.scanned_at
                            FROM scan_logs s
                            WHERE s.job_card_id = %s
                            ORDER BY s.id DESC
                            LIMIT %s
                        )
                        SELECT r.id, r.code_scanned, r.result, r.scanned_by, r.scanned_at,
                               c.row_num
                        FROM recent r
                        LEFT JOIN codes c ON c.run_id = %s AND c.code_value = r.code_scanned
                        ORDER BY r.id DESC;
                    """, (job_card_id, limit, active_run_id))
            else:
                if before_id:
                    cur.execute("""
                        SELECT s.id, s.code_scanned, s.result, s.scanned_by, s.scanned_at,
                               NULL AS row_num
                        FROM scan_logs s
                        WHERE s.job_card_id = %s AND s.id < %s
                        ORDER BY s.id DESC 
                        LIMIT %s
                    """, (job_card_id, before_id, limit))
                else:
                    cur.execute("""
                        SELECT s.id, s.code_scanned, s.result, s.scanned_by, s.scanned_at,
                               NULL AS row_num
                        FROM scan_logs s
                        WHERE s.job_card_id = %s 
                        ORDER BY s.id DESC 
                        LIMIT %s
                    """, (job_card_id, limit))

            rows = cur.fetchall()
            logs = [{
                "id": r[0],
                "code": r[1],
                "result": r[2],
                "user": r[3],
                "time": r[4].strftime("%Y-%m-%d %H:%M:%S") if r[4] else "",
                "row_num": r[5] if r[5] is not None else "-"
            } for r in rows]

            return {
                "recent_logs": logs,
                "has_more": len(logs) == limit
            }
    finally:
        release_connection(conn)

@app.get("/api/reports/{job_card_id}")
def get_report(job_card_id: str, user: dict = Depends(require_password_change_complete)):
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

            cur.execute(
                "SELECT COUNT(*) FROM job_code_duplicate_rows WHERE run_id = %s",
                (run_id,),
            )
            duplicate_rows_result = cur.fetchone()
            duplicate_rows_count = duplicate_rows_result[0] if duplicate_rows_result else 0

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
                "duplicate_rows_count": duplicate_rows_count,
                "blocked_codes": pending_count if jc_status == 'COMPLETED' else 0,
                "pending_codes": pending_count if jc_status != 'COMPLETED' else 0,
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

@app.get("/api/reports/{job_card_id}/scans")
def get_report_scans(
    job_card_id: str,
    limit: int = Query(50, ge=1, le=100),
    before_id: Optional[int] = Query(None, gt=0),
    user: dict = Depends(require_password_change_complete),
):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT run_id
                FROM job_cards
                WHERE job_card_id = %s AND status != 'DELETED'
                ORDER BY created_at DESC
                LIMIT 1
            """, (job_card_id,))
            job = cur.fetchone()
            if not job:
                raise HTTPException(status_code=404, detail="Active Job Card not found")
            run_id = job[0]

            params = [job_card_id]
            before_clause = ""
            if before_id is not None:
                before_clause = "AND s.id < %s"
                params.append(before_id)
            params.append(limit + 1)

            cur.execute(f"""
                WITH recent AS (
                    SELECT s.id, s.code_scanned, s.result, s.scanned_by, s.scanned_at
                    FROM scan_logs s
                    WHERE s.job_card_id = %s {before_clause}
                    ORDER BY s.id DESC
                    LIMIT %s
                )
                SELECT r.id, r.code_scanned, r.result, r.scanned_by, r.scanned_at,
                       c.row_num
                FROM recent r
                LEFT JOIN codes c ON c.run_id = %s AND c.code_value = r.code_scanned
                ORDER BY r.id DESC
            """, (*params, run_id))
            rows = cur.fetchall()
            has_more = len(rows) > limit
            rows = rows[:limit]
            logs = [{
                "id": r[0],
                "code": r[1],
                "result": r[2],
                "user": r[3],
                "time": r[4].strftime("%Y-%m-%d %H:%M:%S") if r[4] else "",
                "row_num": r[5] if r[5] is not None else "-"
            } for r in rows]

            return {
                "recent_logs": logs,
                "has_more": has_more,
                "next_before_id": logs[-1]["id"] if logs and has_more else None,
            }
    finally:
        release_connection(conn)

@app.get("/api/reports/{job_card_id}/duplicates.csv")
def export_duplicate_report_csv(
    job_card_id: str,
    user: dict = Depends(require_password_change_complete),
):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT run_id
                FROM job_cards
                WHERE job_card_id = %s AND status != 'DELETED'
                ORDER BY created_at DESC
                LIMIT 1
            """, (job_card_id,))
            job = cur.fetchone()
            if not job:
                raise HTTPException(status_code=404, detail="Job Card not found.")
            run_id = job[0]
            cur.execute(
                "SELECT EXISTS (SELECT 1 FROM job_code_duplicate_rows WHERE run_id = %s)",
                (run_id,),
            )
            has_duplicates = cur.fetchone()[0]
            if not has_duplicates:
                raise HTTPException(status_code=404, detail="No duplicate codes were recorded for this job.")

        return StreamingResponse(
            _stored_duplicate_csv_stream(conn, run_id),
            media_type="text/csv; charset=utf-8",
            headers={
                "Content-Disposition": (
                    f"attachment; filename*=UTF-8''Duplicate_Codes_{quote(job_card_id, safe='')}.csv"
                )
            },
        )
    except Exception:
        conn.rollback()
        release_connection(conn)
        raise

@app.get("/api/reports/{job_card_id}/csv")
def export_report_csv(job_card_id: str, user: dict = Depends(require_password_change_complete)):
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

            def write_csv_row(values):
                writer.writerow([spreadsheet_safe(value) for value in values])

            write_csv_row(["JOB VERIFICATION REPORT & AUDIT TRAIL"])
            write_csv_row(["Job Card ID:", job_card_id])
            write_csv_row(["Description:", jc_desc or "No Description"])
            write_csv_row(["Status:", jc_status])

            if conf_res and conf_res in ('OVERRIDDEN', 'SKIPPED'):
                write_csv_row([])
                write_csv_row(["--- CONFLICT RESOLUTION AUDIT ---"])
                write_csv_row(["Resolution Type:", conf_res])
                write_csv_row(["Conflicting Codes Found:", conf_cnt or 0])
                write_csv_row(["Authorized By:", over_by or "System"])
                write_csv_row(["Justification Reason:", over_reason or "N/A"])
                
                if conf_details:
                    try:
                        breakdown = json.loads(conf_details)
                        write_csv_row(["Colliding Batches:"])
                        for b in breakdown:
                            write_csv_row([
                                "",
                                f"Job: {b.get('job_card_id')}",
                                f"Description: {b.get('description', 'N/A')}",
                                f"Status: {b.get('status')}",
                                f"Conflicts: {b.get('conflict_count')}"
                            ])
                    except Exception:
                        pass
            
            write_csv_row([])
            write_csv_row(["--- SCAN LOGS ---"])
            write_csv_row(["Job Card ID", "Scanned Code", "Row #", "Result", "Tested By", "Timestamp"])
            for r in rows:
                row_val = r[1] if r[1] is not None else "-"
                write_csv_row([job_card_id, r[0], row_val, r[2], r[3], r[4].strftime("%Y-%m-%d %H:%M:%S") if r[4] else ""])

            output.seek(0)
            return StreamingResponse(
                iter([output.getvalue()]),
                media_type="text/csv",
                headers={
                    "Content-Disposition": (
                        f"attachment; filename*=UTF-8''QC_Report_{quote(job_card_id, safe='')}.csv"
                    )
                }
            )
    finally:
        release_connection(conn)

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("app.main:app", host="0.0.0.0", port=port, reload=False)
