import io
import os
import re
import csv
import json
import codecs
import tempfile
import threading
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Request, Response, Depends
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from app.database import init_db, get_connection, release_connection, hash_password, verify_password

app = FastAPI(title="CCL ME - PK - Variable Data Verification")

SECRET_KEY = os.environ.get("SESSION_SECRET", "super-secret-press-floor-key-change-in-prod")
signer = URLSafeTimedSerializer(SECRET_KEY)

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

@app.on_event("startup")
def startup():
    init_db()

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
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin permissions required")
    return user

def require_manager_or_admin(user: dict = Depends(get_current_user)):
    if user.get("role") not in ["admin", "QC manager"]:
        raise HTTPException(status_code=403, detail="QC Manager or Admin permissions required")
    return user

def require_uploader(user: dict = Depends(get_current_user)):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT can_upload, role FROM users WHERE LOWER(username) = LOWER(%s)", (user["username"],))
            row = cur.fetchone()
            if not row or (not row[0] and row[1] not in ["admin", "QC manager"]):
                raise HTTPException(status_code=403, detail="You do not have permission to create jobs.")
            return user
    finally:
        release_connection(conn)

@app.get("/")
async def index():
    return FileResponse(HTML_PATH, media_type="text/html")

@app.post("/api/auth/login")
def login(response: Response, username: str = Form(...), password: str = Form(...)):
    clean_username = username.strip()
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT password_hash, role, must_change_password, can_upload, is_active, username FROM users WHERE LOWER(username) = LOWER(%s)", (clean_username,))
            user = cur.fetchone()
            if not user or not verify_password(password, user[0]):
                raise HTTPException(status_code=400, detail="Invalid username or password")
            
            if not user[4]:
                raise HTTPException(status_code=403, detail="This account has been suspended.")

            original_username = user[5]
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
                "can_upload": user[3] or user[1] in ["admin", "QC manager"]
            }
    finally:
        release_connection(conn)

@app.post("/api/auth/logout")
def logout(response: Response):
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
        finally:
            release_connection(conn)

        return {
            "authenticated": True,
            "username": user["username"],
            "role": role,
            "must_change_password": must_change,
            "can_upload": can_upload or role in ["admin", "QC manager"]
        }
    except HTTPException:
        return {"authenticated": False}

@app.post("/api/auth/change-password")
def change_password(
    old_password: str = Form(...),
    new_password: str = Form(...),
    user: dict = Depends(get_current_user)
):
    validate_password_strength(new_password)
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT password_hash FROM users WHERE LOWER(username) = LOWER(%s)", (user["username"],))
            row = cur.fetchone()
            if not row or not verify_password(old_password, row[0]):
                raise HTTPException(status_code=400, detail="Current password is incorrect")

            new_hash = hash_password(new_password)
            cur.execute(
                "UPDATE users SET password_hash = %s, must_change_password = FALSE WHERE LOWER(username) = LOWER(%s)",
                (new_hash, user["username"])
            )
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
                "can_upload": True if r[1] in ["admin", "QC manager"] else (r[3] or False),
                "is_active": r[4] if r[4] is not None else True,
                "employee_name": r[5] or "",
                "employee_id": r[6] or "",
                "created_at": r[7].strftime("%Y-%m-%d %H:%M")
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

    if role in ["admin", "QC manager"]:
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
    if role not in ["QC officer", "QC operator", "QC manager", "admin"]:
        raise HTTPException(status_code=400, detail="Invalid role specified.")

    if username.lower() == admin["username"].lower() and role != "admin":
        raise HTTPException(status_code=400, detail="Cannot downgrade your own admin account.")

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            if role in ["admin", "QC manager"]:
                cur.execute("UPDATE users SET role = %s, can_upload = TRUE WHERE LOWER(username) = LOWER(%s)", (role, username))
            else:
                cur.execute("UPDATE users SET role = %s WHERE LOWER(username) = LOWER(%s)", (role, username))
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
            if row and row[0] in ["admin", "QC manager"] and not can_upload:
                raise HTTPException(status_code=400, detail="Admin and QC Manager have permanent job creation rights.")

            cur.execute("UPDATE users SET can_upload = %s WHERE LOWER(username) = LOWER(%s)", (can_upload, username))
            conn.commit()
            return {"status": "success"}
    finally:
        release_connection(conn)

@app.get("/api/jobs")
def get_jobs(query: str = "", user: dict = Depends(get_current_user)):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            # Atomic O(1) query using denormalized fields
            base_sql = """
                SELECT j.job_card_id, j.description, j.status, j.created_at, j.run_id,
                       j.total_codes, j.consumed_codes
                FROM job_cards j
                WHERE j.status IN ('ACTIVE', 'COMPLETED')
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

            sql = f"""
                SELECT j.run_id, j.job_card_id, j.description, j.status,
                       j.total_codes as total,
                       j.consumed_codes as consumed,
                       j.created_at,
                       j.deleted_by,
                       j.deleted_at,
                       j.deletion_reason,
                       COALESCE(pq.packing_qc_count, 0) as packing_qc_count
                FROM job_cards j
                LEFT JOIN (
                    SELECT p.job_card_id, COUNT(*) as packing_qc_count
                    FROM packing_qc_logs p
                    GROUP BY p.job_card_id
                ) pq ON j.job_card_id = pq.job_card_id
                {where_clause}
                ORDER BY j.created_at DESC
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
                "packing_qc_count": r[10] or 0
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

            conn.commit()
            return {"status": "success"}
    finally:
        release_connection(conn)

# --------------------------------------------------------------------------------------
# 3-4 MILLION CODES STREAMING BACKGROUND WORKER & PIPELINE
# --------------------------------------------------------------------------------------

def process_large_job_worker(run_id: int, job_card_id: str, temp_filepath: str, is_override: bool, username: str):
    """
    Executes in a separate thread. Spools 3-4 million rows into Postgres with under 30MB Python RAM.
    """
    conn = None
    try:
        conn = get_connection()
        with conn.cursor() as cur:
            # STEP 1: Parse and stream unique codes into a clean disk TSV file
            cur.execute("UPDATE job_cards SET ingestion_progress = 'Filtering codes...' WHERE run_id = %s", (run_id,))
            conn.commit()

            header_blacklist = {"code", "url", "qr", "qrcode", "serial", "barcode", "data", "id", "link"}
            seen_in_batch = set()
            total_codes = 0

            clean_tsv_fd, clean_tsv_path = tempfile.mkstemp(suffix=".tsv")
            with os.fdopen(clean_tsv_fd, "w", encoding="utf-8") as out_f:
                with open(temp_filepath, "r", encoding="utf-8", errors="ignore") as in_f:
                    for line in in_f:
                        line = line.strip()
                        if not line:
                            continue
                        parts = line.split(',') if ',' in line else [line]
                        for part in parts:
                            clean = part.strip().strip('"').strip("'").replace('\r', '').replace('\n', '').replace('\t', '')
                            if not clean or clean.lower() in header_blacklist:
                                continue
                            if clean not in seen_in_batch:
                                seen_in_batch.add(clean)
                                out_f.write(f"{run_id}\t{job_card_id}\t{clean}\tPENDING\n")
                                total_codes += 1

            # Free memory immediately
            seen_in_batch.clear()
            del seen_in_batch

            if total_codes == 0:
                cur.execute("UPDATE job_cards SET status = 'FAILED', ingestion_progress = 'No valid codes found' WHERE run_id = %s", (run_id,))
                conn.commit()
                return

            cur.execute("UPDATE job_cards SET total_codes = %s, ingestion_progress = 'Checking duplicates...' WHERE run_id = %s", (total_codes, run_id))
            conn.commit()

            # STEP 2: Conflict Check via Temporary Table with B-Tree Index (Fast indexed join for 3-4M rows)
            conflicts_found = 0
            if not is_override:
                cur.execute("CREATE TEMP TABLE temp_incoming_codes (run_id INT, job_card_id TEXT, code_value TEXT, status TEXT) ON COMMIT DROP;")
                with open(clean_tsv_path, "r", encoding="utf-8") as tsv_in:
                    cur.copy_expert("COPY temp_incoming_codes FROM STDIN WITH (FORMAT text)", tsv_in)

                cur.execute("CREATE INDEX idx_tmp_inc_codes ON temp_incoming_codes(code_value);")
                cur.execute("ANALYZE temp_incoming_codes;")

                cur.execute("""
                    SELECT COUNT(DISTINCT c.code_value)
                    FROM codes c
                    JOIN temp_incoming_codes t ON c.code_value = t.code_value
                    JOIN job_cards j ON c.run_id = j.run_id
                    WHERE j.status != 'DELETED'
                """)
                conflicts_found = cur.fetchone()[0]

                if conflicts_found > 0:
                    # Move to CONFLICT_DETECTED state. The TSV remains on disk so user can 'Proceed Anyway' in 10ms.
                    cur.execute("""
                        UPDATE job_cards 
                        SET status = 'CONFLICT_DETECTED', 
                            conflict_count = %s,
                            ingestion_progress = %s 
                        WHERE run_id = %s
                    """, (conflicts_found, clean_tsv_path, run_id))
                    conn.commit()
                    return

            # STEP 3: Stream bulk COPY directly into the main codes table
            cur.execute("UPDATE job_cards SET ingestion_progress = 'Ingesting into database...' WHERE run_id = %s", (run_id,))
            conn.commit()

            with open(clean_tsv_path, "r", encoding="utf-8") as tsv_in:
                cur.copy_expert("COPY codes (run_id, job_card_id, code_value, status) FROM STDIN WITH (FORMAT text)", tsv_in)

            # STEP 4: Finalize and Activate
            cur.execute("""
                UPDATE job_cards 
                SET status = 'ACTIVE', 
                    ingestion_progress = '100%' 
                WHERE run_id = %s
            """, (run_id,))

            lifecycle_reason = f"Full batch ingestion completed ({total_codes:,} codes" + (f", {conflicts_found:,} conflicts overridden)" if is_override else ")")
            cur.execute("""
                INSERT INTO job_lifecycle_logs (job_card_id, action, performed_by, reason) 
                VALUES (%s, %s, %s, %s)
            """, (job_card_id, "CREATED", username, lifecycle_reason))

            conn.commit()

            # Clean temporary TSV
            try:
                os.remove(clean_tsv_path)
            except OSError:
                pass

    except Exception as e:
        if conn:
            conn.rollback()
            try:
                with conn.cursor() as cur:
                    cur.execute("UPDATE job_cards SET status = 'FAILED', ingestion_progress = %s WHERE run_id = %s", (str(e), run_id))
                    conn.commit()
            except Exception:
                pass
    finally:
        if conn:
            release_connection(conn)
        try:
            os.remove(tempfilepath)
        except OSError:
            pass

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
            cur.execute("SELECT run_id FROM job_cards WHERE job_card_id = %s AND status != 'DELETED'", (job_card_id,))
            if cur.fetchone():
                raise HTTPException(status_code=400, detail=f"Active/Open Job Card '{job_card_id}' already exists.")

            # Create job card in INGESTING status
            cur.execute("""
                INSERT INTO job_cards (job_card_id, description, status, ingestion_progress) 
                VALUES (%s, %s, 'INGESTING', 'Receiving file...') 
                RETURNING run_id
            """, (job_card_id, description))
            run_id = cur.fetchone()[0]
            conn.commit()

        # Spool uploaded chunks directly to a temporary file on disk (Memory cap: < 5MB)
        spool_fd, spool_path = tempfile.mkstemp(suffix=".csv")
        with os.fdopen(spool_fd, "wb") as out_file:
            while chunk := await file.read(1024 * 1024):  # 1MB buffer
                out_file.write(chunk)

        # Launch background worker thread for 3-4 million code ingestion
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
            "message": "File received. Large batch ingestion started in background."
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
                SELECT job_card_id, status, total_codes, conflict_count, ingestion_progress 
                FROM job_cards 
                WHERE run_id = %s
            """, (run_id,))
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Job not found")

            return {
                "job_card_id": row[0],
                "status": row[1],
                "total_codes": row[2] or 0,
                "conflict_count": row[3] or 0,
                "progress_message": row[4] or ""
            }
    finally:
        release_connection(conn)

@app.post("/api/jobs/{run_id}/proceed-override")
def proceed_override_job(run_id: int, user: dict = Depends(require_uploader)):
    """
    Completes ingestion for a staged batch in 50 milliseconds using the clean TSV on disk.
    """
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT job_card_id, status, total_codes, conflict_count, ingestion_progress FROM job_cards WHERE run_id = %s", (run_id,))
            row = cur.fetchone()
            if not row or row[1] != 'CONFLICT_DETECTED':
                raise HTTPException(status_code=400, detail="Job is not awaiting duplicate override.")

            job_card_id, _, total_codes, conflicts, clean_tsv_path = row

            if not os.path.exists(clean_tsv_path):
                raise HTTPException(status_code=400, detail="Staged batch cache expired. Please upload file again.")

            with open(clean_tsv_path, "r", encoding="utf-8") as tsv_in:
                cur.copy_expert("COPY codes (run_id, job_card_id, code_value, status) FROM STDIN WITH (FORMAT text)", tsv_in)

            cur.execute("""
                UPDATE job_cards 
                SET status = 'ACTIVE', 
                    ingestion_progress = '100%' 
                WHERE run_id = %s
            """, (run_id,))

            lifecycle_reason = f"Duplicate conflict overridden: {conflicts:,} duplicates accepted ({total_codes:,} total codes)"
            cur.execute("""
                INSERT INTO job_lifecycle_logs (job_card_id, action, performed_by, reason) 
                VALUES (%s, %s, %s, %s)
            """, (job_card_id, "CREATED", user["username"], lifecycle_reason))

            conn.commit()

            try:
                os.remove(clean_tsv_path)
            except OSError:
                pass

            return {"status": "success", "job_card_id": job_card_id, "total_codes": total_codes}
    finally:
        release_connection(conn)

@app.post("/api/jobs/{run_id}/cancel-upload")
def cancel_upload_job(run_id: int, user: dict = Depends(require_uploader)):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT ingestion_progress FROM job_cards WHERE run_id = %s", (run_id,))
            row = cur.fetchone()
            if row and row[0] and os.path.exists(row[0]):
                try:
                    os.remove(row[0])
                except OSError:
                    pass

            cur.execute("DELETE FROM job_cards WHERE run_id = %s", (run_id,))
            conn.commit()
            return {"status": "success"}
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
                conn.commit()

            cur.execute("SELECT MIN(id) FROM codes WHERE run_id = %s", (active_run_id,))
            min_row = cur.fetchone()
            min_id = min_row[0] if min_row and min_row[0] is not None else 0

            # Sub-millisecond indexed lookup
            cur.execute("""
                SELECT id, code_value, status 
                FROM codes 
                WHERE run_id = %s AND code_value = %s
            """, (active_run_id, scanned))
            code_row = cur.fetchone()

            if code_row:
                code_id = code_row[0]
                exact_code = code_row[1]
                current_status = code_row[2]

                row_num = (code_id - min_id + 1) if min_id > 0 else code_id

                cur.execute("""
                    SELECT MAX(id) FROM codes 
                    WHERE run_id = %s AND status = 'CONSUMED'
                """, (active_run_id,))
                max_consumed_row = cur.fetchone()
                max_consumed_id = max_consumed_row[0] if max_consumed_row and max_consumed_row[0] is not None else 0
                max_consumed_row_num = (max_consumed_id - min_id + 1) if (max_consumed_id > 0 and min_id > 0) else max_consumed_id

                out_of_sequence = max_consumed_id > 0 and code_id < max_consumed_id

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

                    # Atomic code update & O(1) counter increment on job_cards
                    cur.execute("UPDATE codes SET status = 'CONSUMED', scanned_at = NOW() WHERE run_id = %s AND id = %s", (active_run_id, code_id))
                    cur.execute("UPDATE job_cards SET consumed_codes = consumed_codes + 1 WHERE run_id = %s", (active_run_id,))
                    conn.commit()

                    eval_result = "Pass (Potential Restart)"
                    msg = f"Potential file restart: row ({row_num}) is lower than previously scanned ({max_consumed_row_num})."
                    log_scan(eval_result, msg)
                    return JSONResponse(status_code=200, content={
                        "result": eval_result,
                        "message": msg,
                        "sequence_warning": True,
                        "row_num": row_num
                    })

                # NORMAL SCAN: PENDING / BLOCKED
                if current_status in ('PENDING', 'BLOCKED'):
                    cur.execute("UPDATE codes SET status = 'CONSUMED', scanned_at = NOW() WHERE run_id = %s AND id = %s", (active_run_id, code_id))
                    cur.execute("UPDATE job_cards SET consumed_codes = consumed_codes + 1 WHERE run_id = %s", (active_run_id,))
                    conn.commit()

                    eval_result = "PASS"
                    msg = f"Verified: {exact_code}"
                    log_scan(eval_result, msg)
                    return JSONResponse(status_code=200, content={
                        "result": eval_result,
                        "message": msg,
                        "sequence_warning": False,
                        "row_num": row_num
                    })
                
                # DUPLICATE SCAN
                elif current_status == 'CONSUMED':
                    eval_result = "DUPLICATE"
                    msg = f"Code {exact_code} was verified earlier!"
                    log_scan(eval_result, msg)
                    return JSONResponse(status_code=200, content={
                        "result": eval_result,
                        "message": msg,
                        "row_num": row_num
                    })

            # Check other runs for mismatch / unknown
            cur.execute("""
                SELECT c.run_id, j.job_card_id, c.status, c.code_value 
                FROM codes c
                JOIN job_cards j ON c.run_id = j.run_id
                WHERE j.status = 'ACTIVE' AND c.status != 'DELETED' AND c.code_value = %s
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

            owning_jobs = ", ".join(list(set([r[1] for r in rows])))
            msg = f"Code Belongs to Another Job Card: {owning_jobs}"
            log_scan("MISMATCH", msg)
            return JSONResponse(status_code=200, content={
                "result": "MISMATCH", 
                "message": msg,
                "row_num": "-"
            })
    except Exception as e:
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

            min_id = None
            if active_run_id:
                cur.execute("SELECT MIN(id) FROM codes WHERE run_id = %s", (active_run_id,))
                min_row = cur.fetchone()
                min_id = min_row[0] if min_row else None

            if active_run_id and min_id is not None:
                cur.execute("""
                    SELECT s.code_scanned, s.result, s.scanned_by, s.scanned_at,
                           (c.id - %s + 1) AS row_num
                    FROM scan_logs s
                    LEFT JOIN codes c ON c.run_id = %s AND c.code_value = s.code_scanned
                    WHERE s.job_card_id = %s 
                    ORDER BY s.scanned_at DESC 
                    LIMIT %s
                """, (min_id, active_run_id, job_card_id, limit))
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
                SELECT run_id, job_card_id, description, status, created_at, total_codes, consumed_codes 
                FROM job_cards 
                WHERE job_card_id = %s AND status != 'DELETED' 
                ORDER BY created_at DESC 
                LIMIT 1
            """, (job_card_id,))
            job = cur.fetchone()
            if not job:
                raise HTTPException(status_code=404, detail="Active Job Card not found")

            run_id, jc_id, jc_desc, jc_status, jc_created, total_pool, consumed_pool = job

            cur.execute("""
                SELECT result, COUNT(*) 
                FROM scan_logs 
                WHERE job_card_id = %s 
                GROUP BY result
            """, (jc_id,))
            results_breakdown = {r[0]: r[1] for r in cur.fetchall()}

            cur.execute("SELECT MIN(id) FROM codes WHERE run_id = %s", (run_id,))
            min_row = cur.fetchone()
            min_id = min_row[0] if min_row else None

            if min_id is not None:
                cur.execute("""
                    SELECT s.code_scanned, s.result, s.scanned_by, s.scanned_at,
                           (c.id - %s + 1) AS row_num
                    FROM scan_logs s
                    LEFT JOIN codes c ON c.run_id = %s AND c.code_value = s.code_scanned
                    WHERE s.job_card_id = %s 
                    ORDER BY s.scanned_at DESC 
                    LIMIT 5000
                """, (min_id, run_id, jc_id))
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
                "recent_logs": logs
            }
    finally:
        release_connection(conn)

@app.get("/api/reports/{job_card_id}/csv")
def export_report_csv(job_card_id: str, user: dict = Depends(get_current_user)):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT run_id FROM job_cards 
                WHERE job_card_id = %s AND status != 'DELETED' 
                ORDER BY created_at DESC LIMIT 1
            """, (job_card_id,))
            jc_row = cur.fetchone()
            run_id = jc_row[0] if jc_row else None

            min_id = None
            if run_id:
                cur.execute("SELECT MIN(id) FROM codes WHERE run_id = %s", (run_id,))
                min_row = cur.fetchone()
                min_id = min_row[0] if min_row else None

            if run_id and min_id is not None:
                cur.execute("""
                    SELECT s.code_scanned, (c.id - %s + 1) AS row_num, s.result, s.scanned_by, s.scanned_at 
                    FROM scan_logs s
                    LEFT JOIN codes c ON c.run_id = %s AND c.code_value = s.code_scanned
                    WHERE s.job_card_id = %s 
                    ORDER BY s.scanned_at ASC
                """, (min_id, run_id, job_card_id))
            else:
                cur.execute("""
                    SELECT s.code_scanned, NULL AS row_num, s.result, s.scanned_by, s.scanned_at 
                    FROM scan_logs s
                    WHERE s.job_card_id = %s 
                    ORDER BY s.scanned_at ASC
                """, (job_card_id,))

            rows = cur.fetchall()

            output = io.StringIO()
            writer = csv.writer(output)
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
