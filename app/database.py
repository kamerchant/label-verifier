import os
import psycopg2
from psycopg2 import pool
from passlib.context import CryptContext

DATABASE_URL = os.environ.get("DATABASE_URL")

db_pool = None

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_connection():
    global db_pool
    if db_pool is None:
        if not DATABASE_URL:
            raise RuntimeError("DATABASE_URL environment variable is not set.")
        db_pool = psycopg2.pool.SimpleConnectionPool(minconn=2, maxconn=25, dsn=DATABASE_URL)
    return db_pool.getconn()

def release_connection(conn):
    global db_pool
    if db_pool and conn:
        db_pool.putconn(conn)

def init_db():
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            # Job Cards Table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS job_cards (
                    run_id SERIAL PRIMARY KEY,
                    job_card_id VARCHAR(100) NOT NULL,
                    description TEXT,
                    status VARCHAR(100) DEFAULT 'ACTIVE',
                    total_codes INTEGER DEFAULT 0,
                    consumed_codes INTEGER DEFAULT 0,
                    conflict_count INTEGER DEFAULT 0,
                    ingestion_progress TEXT DEFAULT '0%',
                    staged_file_path TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    deleted_by VARCHAR(100),
                    deleted_at TIMESTAMP,
                    deletion_reason TEXT
                );
            """)

            # Safe column additions for pre-existing tables
            cur.execute("ALTER TABLE job_cards ADD COLUMN IF NOT EXISTS total_codes INTEGER DEFAULT 0;")
            cur.execute("ALTER TABLE job_cards ADD COLUMN IF NOT EXISTS consumed_codes INTEGER DEFAULT 0;")
            cur.execute("ALTER TABLE job_cards ADD COLUMN IF NOT EXISTS conflict_count INTEGER DEFAULT 0;")
            cur.execute("ALTER TABLE job_cards ADD COLUMN IF NOT EXISTS staged_file_path TEXT;")
            cur.execute("ALTER TABLE job_cards ADD COLUMN IF NOT EXISTS ingestion_progress TEXT DEFAULT '0%';")

            cur.execute("ALTER TABLE job_cards ALTER COLUMN ingestion_progress TYPE TEXT;")
            cur.execute("ALTER TABLE job_cards ALTER COLUMN status TYPE VARCHAR(100);")

            # Codes Table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS codes (
                    id BIGSERIAL PRIMARY KEY,
                    run_id INTEGER REFERENCES job_cards(run_id) ON DELETE CASCADE,
                    job_card_id VARCHAR(100) NOT NULL,
                    code_value TEXT NOT NULL,
                    status VARCHAR(50) DEFAULT 'PENDING',
                    scanned_at TIMESTAMP
                );
            """)

            # Scan Logs Table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS scan_logs (
                    id BIGSERIAL PRIMARY KEY,
                    job_card_id VARCHAR(100) NOT NULL,
                    code_scanned TEXT NOT NULL,
                    result VARCHAR(50) NOT NULL,
                    scanned_by VARCHAR(100),
                    scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)

            # Packing QC Logs Table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS packing_qc_logs (
                    id SERIAL PRIMARY KEY,
                    job_card_id VARCHAR(100) NOT NULL,
                    code_scanned TEXT NOT NULL,
                    tested_by VARCHAR(100),
                    tested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)

            # Job Lifecycle Logs Table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS job_lifecycle_logs (
                    id SERIAL PRIMARY KEY,
                    job_card_id VARCHAR(100) NOT NULL,
                    action VARCHAR(100) NOT NULL,
                    performed_by VARCHAR(100),
                    reason TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)

            # Permanent System Audit Logs Table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS system_audit_logs (
                    id SERIAL PRIMARY KEY,
                    category VARCHAR(50) NOT NULL,
                    job_card_id VARCHAR(100),
                    action VARCHAR(100) NOT NULL,
                    performed_by VARCHAR(100),
                    details TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)

            # Users Table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(100) UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role VARCHAR(50) DEFAULT 'QC officer',
                    must_change_password BOOLEAN DEFAULT FALSE,
                    can_upload BOOLEAN DEFAULT FALSE,
                    is_active BOOLEAN DEFAULT TRUE,
                    employee_name VARCHAR(150),
                    employee_id VARCHAR(100),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)

            # High-Performance Indexes
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_job_cards_jc_id ON job_cards(job_card_id);
                CREATE INDEX IF NOT EXISTS idx_job_cards_status ON job_cards(status);
                CREATE INDEX IF NOT EXISTS idx_codes_run_id ON codes(run_id);
                CREATE INDEX IF NOT EXISTS idx_codes_run_id_status ON codes(run_id, status);
                CREATE INDEX IF NOT EXISTS idx_codes_run_id_code_val ON codes(run_id, code_value);
                CREATE INDEX IF NOT EXISTS idx_codes_code_value ON codes(code_value);
                CREATE INDEX IF NOT EXISTS idx_scan_logs_jc_time ON scan_logs(job_card_id, scanned_at DESC);
                CREATE INDEX IF NOT EXISTS idx_packing_qc_jc ON packing_qc_logs(job_card_id);
                CREATE INDEX IF NOT EXISTS idx_lifecycle_jc ON job_lifecycle_logs(job_card_id);
                CREATE INDEX IF NOT EXISTS idx_system_audit_time ON system_audit_logs(timestamp DESC);
            """)

            # Backfill migration: Pull all historical job lifecycle logs into system_audit_logs if empty
            cur.execute("SELECT COUNT(*) FROM system_audit_logs;")
            if cur.fetchone()[0] == 0:
                cur.execute("""
                    INSERT INTO system_audit_logs (category, job_card_id, action, performed_by, details, timestamp)
                    SELECT 'JOB_LIFECYCLE', job_card_id, action, performed_by, reason, timestamp
                    FROM job_lifecycle_logs;
                """)
                cur.execute("""
                    INSERT INTO system_audit_logs (category, job_card_id, action, performed_by, details, timestamp)
                    SELECT 'SCAN_VERIFICATION', job_card_id, 'SCAN_' || result, scanned_by, 'Scanned code: ' || code_scanned || ' [' || result || ']', scanned_at
                    FROM scan_logs;
                """)
                cur.execute("""
                    INSERT INTO system_audit_logs (category, job_card_id, action, performed_by, details, timestamp)
                    SELECT 'FINAL_QC', job_card_id, 'FINAL_QC_PACK', tested_by, 'Tested code for packing: ' || code_scanned, tested_at
                    FROM packing_qc_logs;
                """)

            # Seed default admin if missing
            cur.execute("SELECT id FROM users WHERE LOWER(username) = 'admin';")
            if not cur.fetchone():
                admin_hash = hash_password("Admin@123")
                cur.execute("""
                    INSERT INTO users (username, password_hash, role, must_change_password, can_upload, is_active, employee_name, employee_id)
                    VALUES ('admin', %s, 'admin', TRUE, TRUE, TRUE, 'Administrator', 'ADM-001');
                """, (admin_hash,))

            conn.commit()
    finally:
        release_connection(conn)
