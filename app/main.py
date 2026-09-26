import io
import os
import csv
import codecs
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Request, Response, Depends
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from app.database import init_db, get_connection, release_connection, hash_password, verify_password

app = FastAPI(title="CCL Pakistan VDV")

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

# --- Auth Helpers ---
def get_current_user(request: Request):
    token = request.cookies.get("qc_session")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        data = signer.loads(token, max_age=86400 * 7)
        return data
    except (BadSignature, SignatureExpired):
        raise HTTPException(status_code=401, detail="Session expired or invalid")

def require_admin(user: dict = Depends(get_current_user)):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin permissions required")
    return user

def require_uploader(user: dict = Depends(get_current_user)):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT can_upload, role FROM users WHERE username = %s", (user["username"],))
            row = cur.fetchone()
            if not row or (not row[0] and row[1] != "admin"):
                raise HTTPException(status_code=403, detail="You do not have permission to create jobs.")
            return user
    finally:
        release_connection(conn)

@app.get("/")
async def index():
    return FileResponse(HTML_PATH, media_type="text/html")

# --- Authentication Endpoints ---
@app.post("/api/auth/login")
def login(response: Response, username: str = Form(...), password: str = Form(...)):
    username = username.strip().lower()
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT password_hash, role, must_change_password, can_upload FROM users WHERE username = %s", (username,))
            user = cur.fetchone()
            if not user or not verify_password(password, user[0]):
                raise HTTPException(status_code=400, detail="Invalid username or password")

            token = signer.dumps({"username": username, "role": user[1]})
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
                "username": username,
                "role": user[1],
                "must_change_password": user[2],
                "can_upload": user[3]
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
                cur.execute("SELECT must_change_password, can_upload FROM users WHERE username = %s", (user["username"],))
                row = cur.fetchone()
                must_change = row[0] if row else False
                can_upload = row[1] if row else False
        finally:
            release_connection(conn)

        return {
            "authenticated": True,
            "username": user["username"],
            "role": user["role"],
            "must_change_password": must_change,
            "can_upload": can_upload
        }
    except HTTPException:
        return {"authenticated": False}

@app.post("/api/auth/change-password")
def change_password(
    old_password: str = Form(...),
    new_password: str = Form(...),
    user: dict = Depends(get_current_user)
):
    if len(new_password) < 6:
        raise HTTPException(status_code=400, detail="New password must be at least 6 characters")

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT password_hash FROM users WHERE username = %s", (user["username"],))
            row = cur.fetchone()
            if not row or not verify_password(old_password, row[0]):
                raise HTTPException(status_code=400, detail="Current password is incorrect")

            new_hash = hash_password(new_password)
            cur.execute(
                "UPDATE users SET password_hash = %s, must_change_password = FALSE WHERE username = %s",
                (new_hash, user["username"])
            )
            conn.commit()
            return {"status": "success", "message": "Password updated successfully"}
    finally:
        release_connection(conn)

# --- User Management (Admin only) ---
@app.get("/api/users")
def list_users(admin: dict = Depends(require_admin)):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT username, role, must_change_password, can_upload, created_at FROM users ORDER BY created_at ASC")
            rows = cur.fetchall()
            return [{
                "username": r[0],
                "role": r[1],
                "must_change_password": r[2],
                "can_upload": r[3],
                "created_at": r[4].strftime("%Y-%m-%d %H:%M")
            } for r in rows]
    finally:
        release_connection(conn)

@app.post("/api/users/create")
def create_user(
    username: str = Form(...),
    password: str = Form(...),
    role: str = Form("QC Incharge"),
    can_upload: bool = Form(False),
    admin: dict = Depends(require_admin)
):
    username = username.strip().lower()
    if len(password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT username FROM users WHERE username = %s", (username,))
            if cur.fetchone():
                raise HTTPException(status_code=400, detail="User already exists")

            pw_hash = hash_password(password)
            cur.execute(
                "INSERT INTO users (username, password_hash, role, must_change_password, can_upload) VALUES (%s, %s, %s, TRUE, %s)",
                (username, pw_hash, role, can_upload)
            )
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
            cur.execute("UPDATE users SET can_upload = %s WHERE username = %s", (can_upload, username))
            conn.commit()
            return {"status": "success"}
    finally:
        release_connection(conn)

@app.post("/api/users/{username}/delete")
def delete_user_with_auth(
    username: str,
    admin_password: str = Form(...),
    admin: dict = Depends(require_admin)
):
    if username == admin["username"]:
        raise HTTPException(status_code=400, detail="Cannot delete your own account.")

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT password_hash FROM users WHERE username = %s", (admin["username"],))
            row = cur.fetchone()
            if not row or not verify_password(admin_password, row[0]):
                raise HTTPException(status_code=403, detail="Invalid admin password. User deletion aborted.")

            cur.execute("DELETE FROM users WHERE username = %s", (username,))
            conn.commit()
            return {"status": "success"}
    finally:
        release_connection(conn)

# --- Job Search & Management ---
@app.get("/api/jobs")
def get_jobs(query: str = "", user: dict = Depends(get_current_user)):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            base_sql = """
                SELECT j.job_card_id, j.description, j.status, 
                       COUNT(c.code_value) as total,
                       COUNT(CASE WHEN c.status = 'CONSUMED' THEN 1 END) as consumed,
                       j.created_at,
                       j.run_id
                FROM job_cards j
                LEFT JOIN codes c ON j.run_id = c.run_id AND c.status != 'DELETED'
                WHERE j.status = 'ACTIVE'
            """
            params = []
            if query.strip():
                base_sql += " AND (LOWER(j.job_card_id) LIKE %s OR LOWER(COALESCE(j.description, '')) LIKE %s)"
                search_term = f"%{query.strip().lower()}%"
                params.extend([search_term, search_term])

            base_sql += """
                GROUP BY j.run_id, j.job_card_id, j.description, j.status, j.created_at
                ORDER BY j.created_at DESC
            """
            cur.execute(base_sql, params)
            rows = cur.fetchall()
            return [{
                "id": r[0],
                "description": r[1] or "",
                "status": r[2],
                "total": r[3],
                "consumed": r[4],
                "created_at": r[5].strftime("%Y-%m-%d %H:%M") if r[5] else ""
            } for r in rows]
    finally:
        release_connection(conn)

@app.get("/api/admin/master-jobs")
def get_master_jobs_report(status_filter: str = "ALL", admin: dict = Depends(require_admin)):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            # Fixed: Only count non-deleted codes so deleted jobs correctly show 0 active codes
            sql = """
                SELECT j.run_id, j.job_card_id, j.description, j.status,
                       COUNT(CASE WHEN c.status != 'DELETED' THEN c.code_value END) as total,
                       COUNT(CASE WHEN c.status = 'CONSUMED' THEN 1 END) as consumed,
                       j.created_at,
                       j.deleted_by,
                       j.deleted_at,
                       j.deletion_reason
                FROM job_cards j
                LEFT JOIN codes c ON j.run_id = c.run_id
            """
            params = []
            if status_filter == "ACTIVE":
                sql += " WHERE j.status = 'ACTIVE'"
            elif status_filter == "COMPLETED":
                sql += " WHERE j.status = 'COMPLETED'"
            elif status_filter == "DELETED":
                sql += " WHERE j.status = 'DELETED'"

            sql += """
                GROUP BY j.run_id, j.job_card_id, j.description, j.status, j.created_at, j.deleted_by, j.deleted_at, j.deletion_reason
                ORDER BY j.created_at DESC
            """
            cur.execute(sql, params)
            rows = cur.fetchall()
            return [{
                "run_id": r[0],
                "job_card_id": r[1],
                "description": r[2] or "",
                "status": r[3],
                "total": r[4],
                "consumed": r[5],
                "created_at": r[6].strftime("%Y-%m-%d %H:%M") if r[6] else "",
                "deleted_by": r[7] or "",
                "deleted_at": r[8].strftime("%Y-%m-%d %H:%M") if r[8] else "",
                "deletion_reason": r[9] or ""
            } for r in rows]
    finally:
        release_connection(conn)

@app.post("/api/jobs/create")
async def create_job(
    job_card_id: str = Form(...),
    description: str = Form(""),
    file: UploadFile = File(...),
    override_deleted_warning: bool = Form(False),
    uploader: dict = Depends(require_uploader)
):
    job_card_id = job_card_id.strip()
    description = description.strip()

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT run_id FROM job_cards WHERE job_card_id = %s AND status != 'DELETED'", (job_card_id,))
            if cur.fetchone():
                raise HTTPException(status_code=400, detail=f"Active/Open Job Card '{job_card_id}' already exists.")

            utf8_reader = codecs.iterdecode(file.file, "utf-8", errors="ignore")
            csv_reader = csv.reader(utf8_reader, delimiter=",", skipinitialspace=True)

            raw_codes = []
            seen_in_batch = set()
            sample_codes = []

            for row in csv_reader:
                if not row:
                    continue
                for cell in row:
                    item = cell.strip().strip('"').strip("'").replace('\r', '').replace('\n', '').replace('\t', '')
                    if not item:
                        continue
                    if item.lower() in ["code", "url", "qr", "qrcode", "serial", "barcode", "data", "id", "link"]:
                        continue

                    if item not in seen_in_batch:
                        seen_in_batch.add(item)
                        raw_codes.append(item)
                        if len(sample_codes) < 100:
                            sample_codes.append(item)

            if not seen_in_batch:
                raise HTTPException(status_code=400, detail="No valid codes found in the file.")

            deleted_job_matches = []
            if sample_codes:
                cur.execute("""
                    SELECT j.job_card_id, c.code_value, j.status 
                    FROM codes c
                    JOIN job_cards j ON c.run_id = j.run_id
                    WHERE c.code_value = ANY(%s) AND j.status = 'DELETED'
                    LIMIT 20
                """, (sample_codes,))
                matches = cur.fetchall()
                deleted_job_matches = matches

                if deleted_job_matches and not override_deleted_warning:
                    sample_dup = deleted_job_matches[0][1]
                    conflicting_jc = deleted_job_matches[0][0]
                    return JSONResponse(status_code=409, content={
                        "status": "deleted_duplicate_warning",
                        "message": f"Code '{sample_dup}' already exists in a deleted Job Card '{conflicting_jc}'. Do you want to proceed with creating this job?",
                        "code": sample_dup,
                        "deleted_job_card": conflicting_jc
                    })

            cur.execute("""
                INSERT INTO job_cards (job_card_id, description, status) 
                VALUES (%s, %s, 'ACTIVE') 
                RETURNING run_id
            """, (job_card_id, description))
            run_id = cur.fetchone()[0]

            csv_buffer = io.StringIO()
            for code in raw_codes:
                csv_buffer.write(f"{run_id}\t{job_card_id}\t{code}\tPENDING\n")
            csv_buffer.seek(0)

            cur.copy_from(csv_buffer, 'codes', columns=('run_id', 'job_card_id', 'code_value', 'status'))

            lifecycle_reason = "Initial batch ingestion"
            if deleted_job_matches and override_deleted_warning:
                conflicting_jc = deleted_job_matches[0][0]
                lifecycle_reason = f"Reused codes from deleted Job Card '{conflicting_jc}'"

            cur.execute("""
                INSERT INTO job_lifecycle_logs (job_card_id, action, performed_by, reason) 
                VALUES (%s, %s, %s, %s)
            """, (job_card_id, "CREATED", uploader["username"], lifecycle_reason))

            conn.commit()
            return {"status": "success", "job_card_id": job_card_id, "total_extracted": len(seen_in_batch)}
    except HTTPException:
        conn.rollback()
        raise
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    finally:
        release_connection(conn)

# Soft Deletion
@app.post("/api/jobs/{job_card_id}/delete")
def soft_delete_job(
    job_card_id: str,
    admin_password: str = Form(...),
    deletion_reason: str = Form(...),
    admin: dict = Depends(require_admin)
):
    reason = deletion_reason.strip()
    if not reason:
        raise HTTPException(status_code=400, detail="A reason for deleting the job must be provided.")

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT password_hash FROM users WHERE username = %s", (admin["username"],))
            row = cur.fetchone()
            if not row or not verify_password(admin_password, row[0]):
                raise HTTPException(status_code=403, detail="Invalid admin password. Deletion aborted.")

            cur.execute("""
                UPDATE job_cards 
                SET status = 'DELETED', 
                    deletion_reason = %s, 
                    deleted_by = %s, 
                    deleted_at = NOW() 
                WHERE job_card_id = %s AND status != 'DELETED'
                RETURNING run_id
            """, (reason, admin["username"], job_card_id))
            updated = cur.fetchone()
            if not updated:
                raise HTTPException(status_code=404, detail="Active/Open Job Card not found or already deleted.")
            
            run_id = updated[0]

            cur.execute("UPDATE codes SET status = 'DELETED' WHERE run_id = %s", (run_id,))

            cur.execute("""
                INSERT INTO job_lifecycle_logs (job_card_id, action, performed_by, reason) 
                VALUES (%s, 'DELETED', %s, %s)
            """, (job_card_id, admin["username"], reason))

            conn.commit()
            return {"status": "success", "message": f"Job {job_card_id} moved to deleted status."}
    finally:
        release_connection(conn)

# Complete & Block
@app.post("/api/jobs/{job_card_id}/complete")
def complete_job(job_card_id: str, user: dict = Depends(get_current_user)):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE job_cards 
                SET status = 'COMPLETED' 
                WHERE job_card_id = %s AND status = 'ACTIVE'
                RETURNING run_id
            """, (job_card_id,))
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Active Job Card not found.")
            
            run_id = row[0]
            cur.execute("UPDATE codes SET status = 'BLOCKED' WHERE run_id = %s AND status = 'PENDING'", (run_id,))
            
            cur.execute(
                "INSERT INTO job_lifecycle_logs (job_card_id, action, performed_by) VALUES (%s, %s, %s)",
                (job_card_id, "COMPLETED_AND_BLOCKED", user["username"])
            )
            conn.commit()
            return {"status": "success"}
    finally:
        release_connection(conn)

# Reactivate & Unblock
@app.post("/api/jobs/{job_card_id}/unblock")
def unblock_job(
    job_card_id: str,
    admin_password: str = Form(...),
    admin: dict = Depends(require_admin)
):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT password_hash FROM users WHERE username = %s", (admin["username"],))
            row = cur.fetchone()
            if not row or not verify_password(admin_password, row[0]):
                raise HTTPException(status_code=403, detail="Invalid admin password. Unblocking denied.")

            cur.execute("""
                UPDATE job_cards 
                SET status = 'ACTIVE' 
                WHERE job_card_id = %s AND status = 'COMPLETED'
                RETURNING run_id
            """, (job_card_id,))
            jc_row = cur.fetchone()
            if not jc_row:
                raise HTTPException(status_code=404, detail="Completed Job Card not found.")

            run_id = jc_row[0]
            cur.execute("UPDATE codes SET status = 'PENDING' WHERE run_id = %s AND status = 'BLOCKED'", (run_id,))

            cur.execute(
                "INSERT INTO job_lifecycle_logs (job_card_id, action, performed_by) VALUES (%s, %s, %s)",
                (job_card_id, "REACTIVATED_AND_UNBLOCKED", admin["username"])
            )
            conn.commit()
            return {"status": "success"}
    finally:
        release_connection(conn)

# Lifecycle Audit Trail Endpoint
@app.get("/api/jobs/{job_card_id}/lifecycle-logs")
def get_lifecycle_logs(job_card_id: str, user: dict = Depends(get_current_user)):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT description, status, deletion_reason, deleted_by, deleted_at, created_at 
                FROM job_cards 
                WHERE job_card_id = %s 
                ORDER BY created_at DESC 
                LIMIT 1
            """, (job_card_id,))
            job = cur.fetchone()
            if not job:
                raise HTTPException(status_code=404, detail="Job Card not found")

            job_desc, job_status, del_reason, del_by, del_at, created_at = job

            cur.execute("""
                SELECT action, performed_by, reason, timestamp 
                FROM job_lifecycle_logs 
                WHERE job_card_id = %s 
                ORDER BY timestamp ASC
            """, (job_card_id,))
            rows = cur.fetchall()

            logs = [{
                "action": r[0],
                "user": r[1],
                "reason": r[2] or "",
                "time": r[3].strftime("%Y-%m-%d %H:%M:%S") if r[3] else ""
            } for r in rows]

            has_created = any(log["action"] == "CREATED" for log in logs)
            if not has_created and created_at:
                logs.insert(0, {
                    "action": "CREATED",
                    "user": "System / Admin",
                    "reason": "Job created and batch ingested",
                    "time": created_at.strftime("%Y-%m-%d %H:%M:%S")
                })

            return {
                "job_card_id": job_card_id,
                "description": job_desc or "",
                "status": job_status,
                "created_at": created_at.strftime("%Y-%m-%d %H:%M:%S") if created_at else "",
                "deletion_reason": del_reason or "",
                "deleted_by": del_by or "",
                "deleted_at": del_at.strftime("%Y-%m-%d %H:%M:%S") if del_at else "",
                "logs": logs
            }
    finally:
        release_connection(conn)

# Strict Verification with Detailed Error Reporting & Cross-Job Card Checks
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

            def log_scan(res, msg):
                cur.execute(
                    "INSERT INTO scan_logs (job_card_id, code_scanned, result, scanned_by) VALUES (%s, %s, %s, %s)",
                    (job_card_id, scanned, res, operator)
                )
                conn.commit()

            # Check for code across all non-deleted runs in the system
            cur.execute("""
                SELECT c.run_id, j.job_card_id, c.status, c.code_value 
                FROM codes c
                JOIN job_cards j ON c.run_id = j.run_id
                WHERE j.status != 'DELETED' AND c.status != 'DELETED' AND c.code_value = %s
            """, (scanned,))
            rows = cur.fetchall()

            # 1. Code does not exist anywhere in system
            if not rows:
                msg = "Code Does Not Exist"
                log_scan("UNKNOWN", msg)
                return JSONResponse(status_code=200, content={
                    "result": "UNKNOWN", 
                    "message": msg
                })

            matched_current = next((r for r in rows if r[0] == active_run_id), None)

            # 2. Code exists in another job card
            if not matched_current:
                owning_jobs = ", ".join(list(set([r[1] for r in rows])))
                msg = f"Code Belongs to Another Job Card: {owning_jobs}"
                log_scan("MISMATCH", msg)
                return JSONResponse(status_code=200, content={
                    "result": "MISMATCH", 
                    "message": msg
                })

            run_id, owning_jc, status, exact_code = matched_current

            # 3. Code was already verified earlier
            if status == "CONSUMED":
                msg = f"Code {exact_code} was verified earlier!"
                log_scan("DUPLICATE", msg)
                return JSONResponse(status_code=200, content={
                    "result": "DUPLICATE", 
                    "message": msg
                })
            elif status == "BLOCKED":
                msg = f"Code belongs to completed/blocked job '{owning_jc}'!"
                log_scan("BLOCKED", msg)
                return JSONResponse(status_code=200, content={
                    "result": "BLOCKED", 
                    "message": msg
                })
            elif status == "PENDING":
                cur.execute("""
                    UPDATE codes 
                    SET status = 'CONSUMED', scanned_at = NOW() 
                    WHERE run_id = %s AND code_value = %s
                """, (active_run_id, scanned))
                msg = f"Verified: {exact_code}"
                log_scan("PASS", msg)
                return JSONResponse(status_code=200, content={
                    "result": "PASS", 
                    "message": msg
                })
    finally:
        release_connection(conn)

# QC Reports
@app.get("/api/reports/{job_card_id}")
def get_report(job_card_id: str, user: dict = Depends(get_current_user)):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT run_id, job_card_id, description, status, created_at 
                FROM job_cards 
                WHERE job_card_id = %s AND status != 'DELETED' 
                ORDER BY created_at DESC 
                LIMIT 1
            """, (job_card_id,))
            job = cur.fetchone()
            if not job:
                raise HTTPException(status_code=404, detail="Active Job Card not found")

            run_id, jc_id, jc_desc, jc_status, jc_created = job

            cur.execute("""
                SELECT 
                    COUNT(*),
                    COUNT(CASE WHEN status = 'CONSUMED' THEN 1 END),
                    COUNT(CASE WHEN status = 'BLOCKED' THEN 1 END),
                    COUNT(CASE WHEN status = 'PENDING' THEN 1 END)
                FROM codes WHERE run_id = %s
            """, (run_id,))
            totals = cur.fetchone()

            cur.execute("""
                SELECT result, COUNT(*) 
                FROM scan_logs 
                WHERE job_card_id = %s 
                GROUP BY result
            """, (jc_id,))
            results_breakdown = {r[0]: r[1] for r in cur.fetchall()}

            cur.execute("""
                SELECT code_scanned, result, scanned_by, scanned_at 
                FROM scan_logs 
                WHERE job_card_id = %s 
                ORDER BY scanned_at DESC 
                LIMIT 500
            """, (jc_id,))
            logs = [{
                "code": r[0],
                "result": r[1],
                "user": r[2],
                "time": r[3].strftime("%Y-%m-%d %H:%M:%S")
            } for r in cur.fetchall()]

            return {
                "job_card_id": jc_id,
                "description": jc_desc or "",
                "status": jc_status,
                "created_at": jc_created.strftime("%Y-%m-%d %H:%M"),
                "total_codes": totals[0],
                "consumed_codes": totals[1],
                "blocked_codes": totals[2],
                "pending_codes": totals[3],
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
                SELECT code_scanned, result, scanned_by, scanned_at 
                FROM scan_logs 
                WHERE job_card_id = %s 
                ORDER BY scanned_at ASC
            """, (job_card_id,))
            rows = cur.fetchall()

            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(["Job Card ID", "Scanned Code", "Result", "Tested By", "Timestamp"])
            for r in rows:
                writer.writerow([job_card_id, r[0], r[1], r[2], r[3].strftime("%Y-%m-%d %H:%M:%S")])

            output.seek(0)
            return StreamingResponse(
                iter([output.getvalue()]),
                media_type="text/csv",
                headers={"Content-Disposition": f"attachment; filename=QC_Report_{job_card_id}.csv"}
            )
    finally:
        release_connection(conn)
