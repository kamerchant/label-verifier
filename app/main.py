import io
from fastapi import FastAPI, UploadFile, File, Form, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from app.database import init_db, get_connection, release_connection

app = FastAPI(title="Label QC Verifier")
templates = Jinja2Templates(directory="app/templates")

@app.on_event("startup")
def startup():
    init_db()

@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/api/jobs")
def get_jobs():
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT j.job_card_id, j.status, 
                       COUNT(c.code_value) as total,
                       COUNT(CASE WHEN c.status = 'CONSUMED' THEN 1 END) as consumed
                FROM job_cards j
                LEFT JOIN codes c ON j.job_card_id = c.job_card_id
                GROUP BY j.job_card_id, j.status
                ORDER BY j.created_at DESC
            """)
            rows = cur.fetchall()
            return [{"id": r[0], "status": r[1], "total": r[2], "consumed": r[3]} for r in rows]
    finally:
        release_connection(conn)

@app.post("/api/jobs/create")
async def create_job(job_card_id: str = Form(...), file: UploadFile = File(...)):
    job_card_id = job_card_id.strip()
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT job_card_id FROM job_cards WHERE job_card_id = %s", (job_card_id,))
            if cur.fetchone():
                raise HTTPException(status_code=400, detail="Job Card ID already exists.")
            
            cur.execute("INSERT INTO job_cards (job_card_id) VALUES (%s)", (job_card_id,))

            csv_buffer = io.StringIO()
            while contents := await file.read(1024 * 1024):
                lines = contents.decode("utf-8", errors="ignore").splitlines()
                for line in lines:
                    code = line.strip().strip(",")
                    if code and not code.lower().startswith("code"):
                        csv_buffer.write(f"{job_card_id}\t{code}\tPENDING\n")

            csv_buffer.seek(0)
            cur.copy_from(csv_buffer, 'codes', columns=('job_card_id', 'code_value', 'status'))
            conn.commit()
            return {"status": "success", "job_card_id": job_card_id}
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        release_connection(conn)

@app.post("/api/jobs/{job_card_id}/complete")
def complete_job(job_card_id: str):
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("UPDATE job_cards SET status = 'COMPLETED' WHERE job_card_id = %s", (job_card_id,))
            cur.execute("UPDATE codes SET status = 'BLOCKED' WHERE job_card_id = %s AND status = 'PENDING'", (job_card_id,))
            conn.commit()
            return {"status": "success"}
    finally:
        release_connection(conn)

@app.post("/api/verify")
def verify_code(job_card_id: str = Form(...), code: str = Form(...)):
    job_card_id = job_card_id.strip()
    code = code.strip()
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT job_card_id, status FROM codes WHERE code_value = %s", (code,))
            rows = cur.fetchall()

            if not rows:
                return JSONResponse(status_code=200, content={"result": "UNKNOWN", "message": "Code not found in system."})

            matched = next((r for r in rows if r[0] == job_card_id), None)

            if not matched:
                other_jobs = ", ".join([r[0] for r in rows])
                return JSONResponse(status_code=200, content={"result": "MISMATCH", "message": f"Wrong job! Belongs to: {other_jobs}"})

            status = matched[1]
            if status == "CONSUMED":
                return JSONResponse(status_code=200, content={"result": "DUPLICATE", "message": "Code already printed & consumed!"})
            elif status == "BLOCKED":
                return JSONResponse(status_code=200, content={"result": "BLOCKED", "message": "Code is from a completed/blocked batch!"})
            elif status == "PENDING":
                cur.execute("UPDATE codes SET status = 'CONSUMED', scanned_at = NOW() WHERE job_card_id = %s AND code_value = %s", (job_card_id, code))
                conn.commit()
                return JSONResponse(status_code=200, content={"result": "PASS", "message": "Valid Code"})
    finally:
        release_connection(conn)
