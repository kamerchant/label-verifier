import os
import bcrypt
import psycopg2
from psycopg2 import pool

DATABASE_URL = os.environ.get("DATABASE_URL")

db_pool = None

def init_db():
    global db_pool
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL environment variable is not set.")
    
    db_pool = psycopg2.pool.SimpleConnectionPool(1, 20, DATABASE_URL)
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            # Job Cards Table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS job_cards (
                    run_id SERIAL PRIMARY KEY,
                    job_card_id VARCHAR(255) NOT NULL,
                    description TEXT,
                    status VARCHAR(50) DEFAULT 'ACTIVE',
                    created_at TIMESTAMP DEFAULT NOW(),
                    deleted_at TIMESTAMP,
                    deleted_by VARCHAR(255),
                    deletion_reason TEXT
                );
            """)

            # Codes Table (Composite key / index on run_id and code_value to allow code reuse across runs)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS codes (
                    id SERIAL PRIMARY KEY,
                    run_id INT REFERENCES job_cards(run_id) ON DELETE CASCADE,
                    job_card_id VARCHAR(255) NOT NULL,
                    code_value VARCHAR(255) NOT NULL,
                    status VARCHAR(50) DEFAULT 'PENDING',
                    scanned_at TIMESTAMP
                );
                CREATE INDEX IF NOT EXISTS idx_codes_run_val ON codes(run_id, code_value);
                CREATE INDEX IF NOT EXISTS idx_codes_val ON codes(code_value);
            """)

            # Scan Logs Table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS scan_logs (
                    id SERIAL PRIMARY KEY,
                    job_card_id VARCHAR(255) NOT NULL,
                    code_scanned VARCHAR(255) NOT NULL,
                    result VARCHAR(50) NOT NULL,
                    scanned_by VARCHAR(255) NOT NULL,
                    scanned_at TIMESTAMP DEFAULT NOW()
                );
            """)

            # Job Lifecycle Logs Table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS job_lifecycle_logs (
                    id SERIAL PRIMARY KEY,
                    job_card_id VARCHAR(255) NOT NULL,
                    action VARCHAR(100) NOT NULL,
                    performed_by VARCHAR(255) NOT NULL,
                    reason TEXT,
                    timestamp TIMESTAMP DEFAULT NOW()
                );
            """)

            # Users Table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    username VARCHAR(255) PRIMARY KEY,
                    password_hash VARCHAR(255) NOT NULL,
                    role VARCHAR(50) DEFAULT 'QC Incharge',
                    must_change_password BOOLEAN DEFAULT TRUE,
                    can_upload BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMP DEFAULT NOW()
                );
            """)

            # Default Admin Account
            cur.execute("SELECT username FROM users WHERE username = 'admin'")
            if not cur.fetchone():
                default_hash = hash_password("admin123")
                cur.execute(
                    "INSERT INTO users (username, password_hash, role, must_change_password, can_upload) VALUES ('admin', %s, 'admin', FALSE, TRUE)",
                    (default_hash,)
                )

            conn.commit()
    finally:
        release_connection(conn)

def get_connection():
    return db_pool.getconn()

def release_connection(conn):
    db_pool.putconn(conn)

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
