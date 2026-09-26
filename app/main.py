import io
import os
import csv
import codecs
from urllib.parse import urlparse, parse_qs
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Request, Response, Depends
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from app.database import init_db, get_connection, release_connection, hash_password, verify_password

app = FastAPI(title="Label QC Verifier")

SECRET_KEY = os.environ.get("SESSION_SECRET", "super-secret-press-floor-key-change-in-prod")
signer = URLSafeTimedSerializer(SECRET_KEY)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
HTML_PATH = os.path.join(BASE_DIR, "templates", "index.html")

@app.on_event("startup")
def startup():
    init_db()

# --- Auth Helpers ---
def get_current_user(request: Request):
    token = request.cookies.get("qc_session")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        data = signer.loads(token, max_age=86400 * 7) # 7 days
        return data  # {"username": ..., "role": ...}
    except (BadSignature, SignatureExpired):
        raise HTTPException(status_code=401, detail="Session expired or invalid")

def require_admin(user: dict = Depends(get_current_user)):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin permissions required")
    return user

@app.get("/")
async def index():
    return FileResponse(HTML_PATH, media_type="text/html")

# --- Authentication API ---
@app.post("/api/auth/login")
def login(response: Response, username: str = Form(...), password: str = Form(...)):
    username = username.strip().lower()
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT password_hash, role FROM users WHERE username = %s", (username,))
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
            return {"status": "success", "username": username, "role": user[1]}
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
        return {"authenticated": True, "username": user["username"], "role": user["role"]}
    except HTTPException:
        return {"authenticated": False}

# --- User Management (Admin only) ---
@app.get("/api/users")
def list_users(admin: dict = Depends(require_admin)):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT username, role, created_at FROM users ORDER BY created_at ASC")
            rows = cur.fetchall()
            return [{"username": r[0], "role": r[1], "created_at": r[2].strftime("%Y-%m-%d %H:%M")} for r in rows]
    finally:
        release_connection(conn)

@app.post("/api/users/create")
def create_user(
    username: str = Form(...),
    password: str = Form(...),
    role: str = Form("operator"),
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
            cur.execute("INSERT INTO users (username, password_hash, role) VALUES (%s, %s, %s)", (username, pw_hash, role))
            conn.commit()
            return {"status": "success"}
    finally:
        release_connection(conn)

@app.delete("/api/users/{username}")
def delete_user(username: str, admin: dict = Depends(require_admin)):
    if username == admin["username"]:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM users WHERE username = %s", (username,))
            conn.commit()
            return {"status": "success"}
    finally:
        release_connection(conn)

# --- Job Management ---
@app.get("/api/jobs")
def get_jobs(user: dict = Depends(get_current_user)):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT j.job_card_id, j.description, j.status, 
                       COUNT(c.code_value) as total,
                       COUNT(CASE WHEN c.status = 'CONSUMED' THEN 1 END) as consumed
                FROM job_cards j
                LEFT JOIN codes c ON j.job_card_id = c.job_card_id
                GROUP BY j.job_card_id, j.description, j.status, j.created_at
                ORDER BY j.created_at DESC
            """)
            rows = cur.fetchall()
            return [{
                "id": r[0],
                "description": r[1] or "",
                "status": r[2],
                "total": r[3],
                "consumed": r[4]
            } for r in rows]
    finally:
        release_connection(conn)

def extract_tokens_from_cell(cell_value: str):
    item = cell_value.strip().strip('"').strip("'").replace('\r', '').replace('\n', '').replace('\t', '')
    if not item:
        return None, None

    lower_item = item.lower()
    if lower_item in ["code", "url", "qr", "qrcode", "serial", "barcode", "data", "id", "link"]:
        return None, None

    if "://" in item or item.startswith("www."):
        full_url = item
        parsed = urlparse(item if "://" in item else "http://" + item)
        qs = parse_qs(parsed.query)
        extracted = None
        for key in ['c', 'code', 'id', 's', 'serial', 'token', 'v']:
            if key in qs and qs[key]:
                extracted = qs[key][0]
                break
        if not extracted:
            slugs = [s for s in parsed.path.rstrip("/").split("/") if s]
            extracted = slugs[-1] if slugs else item
        return full_url, extracted.strip().upper()
    else:
        return item, item.strip().upper()

@app.post("/api/jobs/create")
async def create_job(
    job_card_id: str = Form(...),
    description: str = Form(""),
    file: UploadFile = File(...),
    admin: dict = Depends(require_admin)
):
    job_card_id = job_card_id.strip()
    description = description.strip()

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT job_card_id FROM job_cards WHERE job_card_id = %s", (job_card_id,))
            if cur.fetchone():
                raise HTTPException(status_code=400, detail=f"Job Card '{job_card_id}' already exists.")

            cur.execute("INSERT INTO job_cards (job_card_id, description) VALUES (%s, %s)", (job_card_id, description))

            utf8_reader = codecs.iterdecode(file.file, "utf-8", errors="ignore")
            csv_reader = csv.reader(utf8_reader, delimiter=",", skipinitialspace=True)

            csv_buffer = io.StringIO()
            seen_in_batch = set()

            for row in csv_reader:
                if not row:
                    continue
                for cell in row:
                    full_val, short_val = extract_tokens_from_cell(cell)
                    if not full_val or not short_val:
                        continue
                    if short_val not in seen_in_batch:
                        seen_in_batch.add(short_val)
                        csv_buffer.write(f"{job_card_id}\t{full_val}\t{short_val}\tPENDING\n")

            if not seen_in_batch:
                raise HTTPException(status_code=400, detail="No valid codes found in the file.")

            csv_buffer.seek(0)
            cur.copy_from(csv_buffer, 'codes', columns=('job_card_id', 'code_value', 'short_code', 'status'))
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

@app.post("/api/jobs/{job_card_id}/complete")
def complete_job(job_card_id: str, admin: dict = Depends(require_admin)):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("UPDATE job_cards SET status = 'COMPLETED' WHERE job_card_id = %s", (job_card_id,))
            cur.execute("UPDATE codes SET status = 'BLOCKED' WHERE job_card_id = %s AND status = 'PENDING'", (job_card_id,))
            conn.commit()
            return {"status": "success"}
    finally:
        release_connection(conn)

# --- Verification Logic with User Logging ---
@app.post("/api/verify")
def verify_code(
    job_card_id: str = Form(...), 
    code: str = Form(...),
    user: dict = Depends(get_current_user)
):
    job_card_id = job_card_id.strip()
    scanned = code.strip().replace('\r', '').replace('\n', '')
    operator = user["username"]

    _, short_scanned = extract_tokens_from_cell(scanned)
    if not short_scanned:
        short_scanned = scanned.upper()

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT job_card_id, status, short_code, code_value 
                FROM codes 
                WHERE code_value = %s OR short_code = %s
            """, (scanned, short_scanned))
            rows = cur.fetchall()

            display_code = short_scanned

            def log_scan(res):
                cur.execute(
                    "INSERT INTO scan_logs (job_card_id, code_scanned, result, scanned_by) VALUES (%s, %s, %s, %s)",
                    (job_card_id, display_code, res, operator)
                )
                conn.commit()

            if not rows:
                log_scan("UNKNOWN")
                return JSONResponse(status_code=200, content={
                    "result": "UNKNOWN", 
                    "message": f"Code '{display_code}' does not exist in any batch."
                })

            matched_current = next((r for r in rows if r[0] == job_card_id), None)

            if not matched_current:
                owning_jobs = ", ".join(list(set([r[0] for r in rows])))
                log_scan("MISMATCH")
                return JSONResponse(status_code=200, content={
                    "result": "MISMATCH", 
                    "message": f"Code belongs to Job Card: {owning_jobs}"
                })

            owning_jc, status, found_short, found_full = matched_current
            final_label = found_short if found_short else display_code

            if status == "CONSUMED":
                log_scan("DUPLICATE")
                return JSONResponse(status_code=200, content={
                    "result": "DUPLICATE", 
                    "message": f"Code '{final_label}' already printed & consumed!"
                })
            elif status == "BLOCKED":
                log_scan("BLOCKED")
                return JSONResponse(status_code=200, content={
                    "result": "BLOCKED", 
                    "message": f"Code '{final_label}' belongs to completed/blocked job '{owning_jc}'!"
                })
            elif status == "PENDING":
                cur.execute("""
                    UPDATE codes 
                    SET status = 'CONSUMED', scanned_at = NOW() 
                    WHERE job_card_id = %s AND (code_value = %s OR short_code = %s)
                """, (job_card_id, scanned, short_scanned))
                log_scan("PASS")
                return JSONResponse(status_code=200, content={
                    "result": "PASS", 
                    "message": f"Code: {final_label}"
                })
    finally:
        release_connection(conn)

# --- Reporting Endpoints ---
@app.get("/api/reports/{job_card_id}")
def get_report(job_card_id: str, user: dict = Depends(get_current_user)):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            # Job details
            cur.execute("SELECT job_card_id, description, status, created_at FROM job_cards WHERE job_card_id = %s", (job_card_id,))
            job = cur.fetchone()
            if not job:
                raise HTTPException(status_code=404, detail="Job Card not found")

            # Totals
            cur.execute("""
                SELECT 
                    COUNT(*),
                    COUNT(CASE WHEN status = 'CONSUMED' THEN 1 END),
                    COUNT(CASE WHEN status = 'BLOCKED' THEN 1 END),
                    COUNT(CASE WHEN status = 'PENDING' THEN 1 END)
                FROM codes WHERE job_card_id = %s
            """, (job_card_id,))
            totals = cur.fetchone()

            # Breakdown of scan results
            cur.execute("""
                SELECT result, COUNT(*) 
                FROM scan_logs 
                WHERE job_card_id = %s 
                GROUP BY result
            """, (job_card_id,))
            results_breakdown = {r[0]: r[1] for r in cur.fetchall()}

            # Recent scan logs (last 500)
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
