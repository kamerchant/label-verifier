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
                       j.created_at
                FROM job_cards j
                LEFT JOIN codes c ON j.job_card_id = c.job_card_id
                WHERE j.status != 'DELETED'
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
            sql = """
                SELECT j.run_id, j.job_card_id, j.description, j.status,
                       COUNT(c.code_value) as total,
                       COUNT(CASE WHEN c.status = 'CONSUMED' THEN 1 END) as consumed,
                       j.created_at,
                       j.deleted_by,
                       j.deleted_at,
                       j.deletion_reason
                FROM job_cards j
                LEFT JOIN codes c ON j.job_card_id = c.job_card_id
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

# --- Create Job with Soft/Hard Duplicate Handling ---
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
            # 1. Enforce unique job_card_id among currently active or completed runs
            cur.execute("SELECT job_card_id FROM job_cards WHERE job_card_id = %s AND status != 'DELETED'", (job_card_id,))
            if cur.fetchone():
                raise HTTPException(status_code=400, detail=f"Active Job Card '{job_card_id}' already exists.")

            utf8_reader = codecs.iterdecode(file.file, "utf-8", errors="ignore")
            csv_reader = csv.reader(utf8_reader, delimiter=",", skipinitialspace=True)

            csv_buffer = io.StringIO()
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
                        csv_buffer.write(f"{job_card_id}\t{item}\tPENDING\n")
                        
                        if len(sample_codes) < 100:
                            sample_codes.append(item)

            if not seen_in_batch:
                raise HTTPException(status_code=400, detail="No valid codes found in the file.")

            # 2. Check for duplicate codes across ALL database records
            deleted_job_matches = []
            if sample_codes:
                cur.execute("""
                    SELECT c.job_card_id, c.code_value, j.status 
                    FROM codes c
                    JOIN job_cards j ON c.job_card_id = j.job_card_id
                    WHERE c.code_value = ANY(%s)
                    LIMIT 20
                """, (sample_codes,))
                matches = cur.fetchall()

                active_matches = [m for m in matches if m[2] != 'DELETED']
                deleted_job_matches = [m for m in matches if m[2] == 'DELETED']

                # HARD BLOCK: Reject immediately if matched against active or completed jobs
                if active_matches:
                    conflicting_jc = active_matches[0][0]
                    sample_dup = active_matches[0][1]
                    raise HTTPException(
                        status_code=400,
                        detail=f"Upload rejected: Duplicate codes detected! Code '{sample_dup}' already exists in active/completed Job Card '{conflicting_jc}'."
                    )

                # SOFT WARNING: If only matches DELETED jobs and user hasn't confirmed yet
                if deleted_job_matches and not override_deleted_warning:
                    sample_dup = deleted_job_matches[0][1]
                    conflicting_jc = deleted_job_matches[0][0]
                    return JSONResponse(status_code=409, content={
                        "status": "deleted_duplicate_warning",
                        "message": f"Code '{sample_dup}' already exists in a deleted Job Card '{conflicting_jc}'. Do you want to proceed with creating this job?",
                        "code": sample_dup,
                        "deleted_job_card": conflicting_jc
                    })

            # 3. Insert Job Card & bulk ingest
            cur.execute(
                "INSERT INTO job_cards (job_card_id, description, status) VALUES (%s, %s, 'ACTIVE') RETURNING run_id",
                (job_card_id, description)
            )

            csv_buffer.seek(0)
            cur.copy_from(csv_buffer, 'codes', columns=('job_card_id', 'code_value', 'status'))

            lifecycle_reason = "Initial batch ingestion"
            if deleted_job_matches and override_deleted_warning:
                conflicting_jc = deleted_job_matches[0][0]
                lifecycle_reason = f"Reused codes from deleted Job Card '{conflicting_jc}'"

            cur.execute(
                "INSERT INTO job_lifecycle_logs (job_card_id, action, performed_by, reason) VALUES (%s, %s, %s, %s)",
                (job_card_id, "CREATED", uploader["username"], lifecycle_reason)
            )

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

            cur.execute("SELECT status FROM job_cards WHERE job_card_id = %s AND status != 'DELETED'", (job_card_id,))
            job_row = cur.fetchone()
            if not job_row:
                raise HTTPException(status_code=404, detail="Job Card not found or already deleted.")

            cur.execute("""
                UPDATE job_cards 
                SET status = 'DELETED', 
                    deletion_reason = %s, 
                    deleted_by = %s, 
                    deleted_at = NOW() 
                WHERE job_card_id = %s AND status != 'DELETED'
            """, (reason, admin["username"], job_card_id))

            cur.execute("UPDATE codes SET status = 'BLOCKED' WHERE job_card_id = %s AND status = 'PENDING'", (job_card_id,))

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
            cur.execute("UPDATE job_cards SET status = 'COMPLETED' WHERE job_card_id = %s AND status = 'ACTIVE'", (job_card_id,))
            cur.execute("UPDATE codes SET status = 'BLOCKED' WHERE job_card_id = %s AND status = 'PENDING'", (job_card_id,))
            
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

            cur.execute("UPDATE job_cards SET status = 'ACTIVE' WHERE job_card_id = %s AND status = 'COMPLETED'", (job_card_id,))
            cur.execute("UPDATE codes SET status = 'PENDING' WHERE job_card_id = %s AND status = 'BLOCKED'", (job_card_id,))

            cur.execute(
                "INSERT INTO job_lifecycle_logs (job_card_id, action, performed_by) VALUES (%s, %s, %s)",
                (job_card_id, "REACTIVATED_AND_UNBLOCKED", admin["username"])
            )
            conn.commit()
            return {"status": "success"}
    finally:
        release_connection(conn)

# Lifecycle Audit Trail
@app.get("/api/jobs/{job_card_id}/lifecycle-logs")
def get_lifecycle_logs(job_card_id: str, user: dict = Depends(get_current_user)):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT description, status, deletion_reason, deleted_by, deleted_at FROM job_cards WHERE job_card_id = %s ORDER BY created_at DESC LIMIT 1", (job_card_id,))
            job = cur.fetchone()
            if not job:
                raise HTTPException(status_code=404, detail="Job Card not found")

            cur.execute("""
                SELECT action, performed_by, reason, timestamp 
                FROM job_lifecycle_logs 
                WHERE job_card_id = %s 
                ORDER BY timestamp ASC
            """, (job_card_id,))
            logs = [{
                "action": r[0],
                "user": r[1],
                "reason": r[2] or "",
                "time": r[3].strftime("%Y-%m-%d %H:%M:%S")
            } for r in cur.fetchall()]

            return {
                "job_card_id": job_card_id,
                "description": job[0] or "",
                "status": job[1],
                "deletion_reason": job[2] or "",
                "deleted_by": job[3] or "",
                "deleted_at": job[4].strftime("%Y-%m-%d %H:%M:%S") if job[4] else "",
                "logs": logs
            }
    finally:
        release_connection(conn)

# Strict Verification
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
            cur.execute("SELECT status FROM job_cards WHERE job_card_id = %s", (job_card_id,))
            jc_check = cur.fetchone()
            if not jc_check or jc_check[0] == 'DELETED':
                return JSONResponse(status_code=200, content={
                    "result": "BLOCKED",
                    "message": f"Job Card '{job_card_id}' is deleted/inactive."
                })

            cur.execute("""
                SELECT c.job_card_id, c.status, c.code_value 
                FROM codes c
                JOIN job_cards j ON c.job_card_id = j.job_card_id
                WHERE j.status != 'DELETED' AND c.code_value = %s
            """, (scanned,))
            rows = cur.fetchall()

            def log_scan(res):
                cur.execute(
                    "INSERT INTO scan_logs (job_card_id, code_scanned, result, scanned_by) VALUES (%s, %s, %s, %s)",
                    (job_card_id, scanned, res, operator)
                )
                conn.commit()

            if not rows:
                log_scan("UNKNOWN")
                return JSONResponse(status_code=200, content={
                    "result": "UNKNOWN", 
                    "message": f"Code '{scanned}' does not exist in any batch."
                })

            matched_current = next((r for r in rows if r[0] == job_card_id), None)

            if not matched_current:
                owning_jobs = ", ".join(list(set([r[0] for r in rows])))
                log_scan("MISMATCH")
                return JSONResponse(status_code=200, content={
                    "result": "MISMATCH", 
                    "message": f"Code belongs to Job Card: {owning_jobs}"
                })

            owning_jc, status, exact_code = matched_current

            if status == "CONSUMED":
                log_scan("DUPLICATE")
                return JSONResponse(status_code=200, content={
                    "result": "DUPLICATE", 
                    "message": f"Code '{exact_code}' was already printed & consumed!"
                })
            elif status == "BLOCKED":
                log_scan("BLOCKED")
                return JSONResponse(status_code=200, content={
                    "result": "BLOCKED", 
                    "message": f"Code belongs to completed/blocked job '{owning_jc}'!"
                })
            elif status == "PENDING":
                cur.execute("""
                    UPDATE codes 
                    SET status = 'CONSUMED', scanned_at = NOW() 
                    WHERE job_card_id = %s AND code_value = %s
                """, (job_card_id, scanned))
                log_scan("PASS")
                return JSONResponse(status_code=200, content={
                    "result": "PASS", 
                    "message": f"Verified: {exact_code}"
                })
    finally:
        release_connection(conn)

# QC Reports
@app.get("/api/reports/{job_card_id}")
def get_report(job_card_id: str, user: dict = Depends(get_current_user)):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT job_card_id, description, status, created_at FROM job_cards WHERE job_card_id = %s ORDER BY created_at DESC LIMIT 1", (job_card_id,))
            job = cur.fetchone()
            if not job:
                raise HTTPException(status_code=404, detail="Job Card not found")

            cur.execute("""
                SELECT 
                    COUNT(*),
                    COUNT(CASE WHEN status = 'CONSUMED' THEN 1 END),
                    COUNT(CASE WHEN status = 'BLOCKED' THEN 1 END),
                    COUNT(CASE WHEN status = 'PENDING' THEN 1 END)
                FROM codes WHERE job_card_id = %s
            """, (job_card_id,))
            totals = cur.fetchone()

            cur.execute("""
                SELECT result, COUNT(*) 
                FROM scan_logs 
                WHERE job_card_id = %s 
                GROUP BY result
            """, (job_card_id,))
            results_breakdown = {r[0]: r[1] for r in cur.fetchall()}

            cur.execute("""
                SELECT code_scanned, result, scanned_by, scanned_at 
                FROM scan_logs 
                WHERE job_card_id = %s 
                ORDER BY scanned_at DESC 
                LIMIT 500
            """, (job_card_id,))
            logs = [{
                "code": r[0],
                "result": r[1],
                "user": r[2],
                "time": r[3].strftime("%Y-%m-%d %H:%M:%S")
            } for r in cur.fetchall()]

            return {
                "job_card_id": job[0],
                "description": job[1] or "",
                "status": job[2],
                "created_at": job[3].strftime("%Y-%m-%d %H:%M"),
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
