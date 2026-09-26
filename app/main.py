import io
import os
import csv
import codecs
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from app.database import init_db, get_connection, release_connection

app = FastAPI(title="Label QC Verifier")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
HTML_PATH = os.path.join(BASE_DIR, "templates", "index.html")

@app.on_event("startup")
def startup():
    init_db()

@app.get("/")
async def index():
    return FileResponse(HTML_PATH, media_type="text/html")

# Helper endpoint to cleanly purge and re-initialize tables with TEXT types
@app.get("/reset-db")
def reset_database():
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                DROP TABLE IF EXISTS codes CASCADE;
                DROP TABLE IF EXISTS job_cards CASCADE;

                CREATE TABLE job_cards (
                    job_card_id TEXT PRIMARY KEY,
                    client_name TEXT,
                    status VARCHAR(20) DEFAULT 'ACTIVE',
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE codes (
                    job_card_id TEXT REFERENCES job_cards(job_card_id) ON DELETE CASCADE,
                    code_value TEXT NOT NULL,
                    short_code TEXT NOT NULL,
                    status VARCHAR(20) DEFAULT 'PENDING',
                    scanned_at TIMESTAMP WITH TIME ZONE NULL,
                    PRIMARY KEY (job_card_id, code_value)
                );

                CREATE INDEX idx_codes_value ON codes (code_value);
                CREATE INDEX idx_codes_short ON codes (short_code);
                CREATE INDEX idx_codes_status ON codes (status);
            """)
            conn.commit()
            return {"status": "success", "message": "Database tables recreated with TEXT type successfully!"}
    except Exception as e:
        conn.rollback()
        return {"status": "error", "message": str(e)}
    finally:
        release_connection(conn)

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
async def create_job(
    job_card_id: str = Form(...),
    file: UploadFile = File(...)
):
    job_card_id = job_card_id.strip()

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT job_card_id FROM job_cards WHERE job_card_id = %s", (job_card_id,))
            if cur.fetchone():
                raise HTTPException(status_code=400, detail=f"Job Card '{job_card_id}' already exists.")

            cur.execute("INSERT INTO job_cards (job_card_id) VALUES (%s)", (job_card_id,))

            # Stream through lines directly
            utf8_reader = codecs.iterdecode(file.file, "utf-8", errors="ignore")
            csv_reader = csv.reader(utf8_reader, delimiter=",", skipinitialspace=True)

            csv_buffer = io.StringIO()
            seen_in_batch = set()

            for row in csv_reader:
                if not row:
                    continue

                for cell in row:
                    item = cell.strip().strip('"').strip("'").replace('\r', '').replace('\n', '').replace('\t', '')
                    
                    if not item:
                        continue

                    # If cell is URL, extract the 12-char suffix code alongside the full URL
                    if "://" in item:
                        full_url = item
                        short = item.rstrip("/").split("/")[-1].upper()
                    else:
                        full_url = item
                        short = item.upper()

                    # Deduplicate within same batch
                    if short not in seen_in_batch:
                        seen_in_batch.add(short)
                        # Tab-separated for PostgreSQL COPY: job_card_id \t code_value \t short_code \t status
                        csv_buffer.write(f"{job_card_id}\t{full_url}\t{short}\tPENDING\n")

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
    scanned = code.strip().replace('\r', '').replace('\n', '')

    # Derive short code if operator scanned the full URL
    short_scanned = scanned.rstrip("/").split("/")[-1].upper()

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            # Match against either the full URL or the short code
            cur.execute("""
                SELECT job_card_id, status, short_code 
                FROM codes 
                WHERE code_value = %s OR short_code = %s
            """, (scanned, short_scanned))
            rows = cur.fetchall()

            if not rows:
                return JSONResponse(status_code=200, content={"result": "UNKNOWN", "message": f"Code '{scanned}' not found in system."})

            matched = next((r for r in rows if r[0] == job_card_id), None)

            if not matched:
                other_jobs = ", ".join(list(set([r[0] for r in rows])))
                return JSONResponse(status_code=200, content={"result": "MISMATCH", "message": f"Wrong job! Belongs to: {other_jobs}"})

            status = matched[1]
            found_short = matched[2]

            if status == "CONSUMED":
                return JSONResponse(status_code=200, content={"result": "DUPLICATE", "message": f"Code '{found_short}' already printed & consumed!"})
            elif status == "BLOCKED":
                return JSONResponse(status_code=200, content={"result": "BLOCKED", "message": f"Code '{found_short}' belongs to a completed/blocked batch!"})
            elif status == "PENDING":
                cur.execute("""
                    UPDATE codes 
                    SET status = 'CONSUMED', scanned_at = NOW() 
                    WHERE job_card_id = %s AND (code_value = %s OR short_code = %s)
                """, (job_card_id, scanned, short_scanned))
                conn.commit()
                return JSONResponse(status_code=200, content={"result": "PASS", "message": f"Code: {found_short}"})
    finally:
        release_connection(conn)
