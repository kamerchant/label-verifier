import os
import bcrypt
from psycopg2 import pool
from contextlib import contextmanager

DATABASE_URL = os.environ.get("DATABASE_URL")

db_pool = None

def init_db():
    global db_pool
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL environment variable is not set.")
    
    db_pool = pool.SimpleConnectionPool(1, 20, DATABASE_URL)
    
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            # Users table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(150) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    role VARCHAR(50) NOT NULL DEFAULT 'QC operator',
                    must_change_password BOOLEAN DEFAULT TRUE,
                    can_upload BOOLEAN DEFAULT FALSE,
                    is_active BOOLEAN DEFAULT TRUE,
                    employee_name VARCHAR(150),
                    employee_id VARCHAR(50),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)

            # Job Cards table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS job_cards (
                    run_id SERIAL PRIMARY KEY,
                    job_card_id VARCHAR(100) NOT NULL,
                    description TEXT,
                    status VARCHAR(50) NOT NULL DEFAULT 'ACTIVE',
                    deleted_by VARCHAR(150),
                    deleted_at TIMESTAMP,
                    deletion_reason TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)

            # Codes table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS codes (
                    id SERIAL PRIMARY KEY,
                    run_id INT REFERENCES job_cards(run_id) ON DELETE CASCADE,
                    job_card_id VARCHAR(100) NOT NULL,
                    code_value VARCHAR(255) NOT NULL,
                    status VARCHAR(50) NOT NULL DEFAULT 'PENDING',
                    scanned_at TIMESTAMP
                );
            """)

            # Scan Logs table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS scan_logs (
                    id SERIAL PRIMARY KEY,
                    job_card_id VARCHAR(100) NOT NULL,
                    code_scanned VARCHAR(255) NOT NULL,
                    result VARCHAR(50) NOT NULL,
                    scanned_by VARCHAR(150) NOT NULL,
                    scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)

            # Packing QC Logs table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS packing_qc_logs (
                    id SERIAL PRIMARY KEY,
                    job_card_id VARCHAR(100) NOT NULL,
                    code_scanned VARCHAR(255) NOT NULL,
                    tested_by VARCHAR(150) NOT NULL,
                    tested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)

            # Job Lifecycle Logs table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS job_lifecycle_logs (
                    id SERIAL PRIMARY KEY,
                    job_card_id VARCHAR(100) NOT NULL,
                    action VARCHAR(100) NOT NULL,
                    performed_by VARCHAR(150) NOT NULL,
                    reason TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)

            # HIGH-PERFORMANCE INDEXES (Prevents system hangs & table locks during validation)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_codes_code_value ON codes(code_value);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_codes_run_id ON codes(run_id);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_scan_logs_job_card ON scan_logs(job_card_id);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_packing_qc_job ON packing_qc_logs(job_card_id);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_job_cards_id ON job_cards(job_card_id);")

            # Default Admin User Check
            cur.execute("SELECT id FROM users WHERE username = 'admin'")
            if not cur.fetchone():
                default_hash = hash_password("Admin123!")
                cur.execute("""
                    INSERT INTO users (username, password_hash, role, must_change_password, can_upload, is_active)
                    VALUES ('admin', %s, 'admin', TRUE, TRUE, TRUE)
                """, (default_hash,))

            conn.commit()
    finally:
        release_connection(conn)

def get_connection():
    global db_pool
    if not db_pool:
        db_pool = pool.SimpleConnectionPool(1, 20, DATABASE_URL)
    return db_pool.getconn()

def release_connection(conn):
    global db_pool
    if db_pool and conn:
        try:
            db_pool.putconn(conn)
        except Exception:
            pass

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
