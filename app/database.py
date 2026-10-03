import os
import secrets
import hashlib
import psycopg2
from psycopg2 import pool

DATABASE_URL = os.environ.get(
    "DATABASE_URL", 
    "postgresql://postgres:postgres@localhost:5432/vdata_db"
)

# Render & cloud hosted PostgreSQL instances require sslmode='require' if not localhost
if "localhost" not in DATABASE_URL and "127.0.0.1" not in DATABASE_URL and "sslmode" not in DATABASE_URL:
    if "?" in DATABASE_URL:
        DATABASE_URL += "&sslmode=require"
    else:
        DATABASE_URL += "?sslmode=require"

db_pool = None

def get_pool():
    global db_pool
    if db_pool is None:
        db_pool = pool.ThreadedConnectionPool(minconn=2, maxconn=20, dsn=DATABASE_URL)
    return db_pool

def get_connection():
    return get_pool().getconn()

def release_connection(conn):
    if conn:
        get_pool().putconn(conn)

def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), bytes.fromhex(salt), 100000)
    return f"{salt}${key.hex()}"

def verify_password(password: str, hashed: str) -> bool:
    if not hashed:
        return False
    # Backward compatibility with bcrypt hashes if already present
    if hashed.startswith('$2b$') or hashed.startswith('$2a$'):
        try:
            import bcrypt
            return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
        except ImportError:
            return False
    try:
        salt, key_hex = hashed.split('$')
        new_key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), bytes.fromhex(salt), 100000)
        return secrets.compare_digest(new_key.hex(), key_hex)
    except Exception:
        return False

def init_db():
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            # Users Table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(100) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    role VARCHAR(50) DEFAULT 'QC officer',
                    must_change_password BOOLEAN DEFAULT TRUE,
                    can_upload BOOLEAN DEFAULT FALSE,
                    is_active BOOLEAN DEFAULT TRUE,
                    employee_name VARCHAR(150),
                    employee_id VARCHAR(100),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)

            # Job Cards Table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS job_cards (
                    run_id SERIAL PRIMARY KEY,
                    job_card_id VARCHAR(100) NOT NULL,
                    description TEXT,
                    status VARCHAR(100) DEFAULT 'ACTIVE',
                    total_codes BIGINT DEFAULT 0,
                    consumed_codes BIGINT DEFAULT 0,
                    conflict_count BIGINT DEFAULT 0,
                    staged_file_path TEXT,
                    ingestion_progress TEXT,
                    deleted_by VARCHAR(100),
                    deleted_at TIMESTAMP,
                    deletion_reason TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)

            # Codes Pool Table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS codes (
                    id BIGSERIAL PRIMARY KEY,
                    run_id INT REFERENCES job_cards(run_id) ON DELETE CASCADE,
                    job_card_id VARCHAR(100) NOT NULL,
                    code_value TEXT NOT NULL,
                    status VARCHAR(50) DEFAULT 'PENDING',
                    scanned_at TIMESTAMP
                );
            """)

            # Indexes for low-latency scanning and integrity verification
            cur.execute("CREATE INDEX IF NOT EXISTS idx_codes_run_val ON codes(run_id, code_value);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_codes_run_status ON codes(run_id, status);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_codes_code_value ON codes(code_value);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_codes_run_id_id ON codes(run_id, id);")

            # Verification Scan Logs
            cur.execute("""
                CREATE TABLE IF NOT EXISTS scan_logs (
                    id BIGSERIAL PRIMARY KEY,
                    job_card_id VARCHAR(100) NOT NULL,
                    code_scanned TEXT NOT NULL,
                    result VARCHAR(100) NOT NULL,
                    scanned_by VARCHAR(100),
                    scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_scan_logs_jc_time ON scan_logs(job_card_id, scanned_at DESC);")

            # Final QC Packing Logs
            cur.execute("""
                CREATE TABLE IF NOT EXISTS packing_qc_logs (
                    id BIGSERIAL PRIMARY KEY,
                    job_card_id VARCHAR(100) NOT NULL,
                    code_scanned TEXT NOT NULL,
                    tested_by VARCHAR(100),
                    tested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_packing_qc_jc_code ON packing_qc_logs(job_card_id, code_scanned);")

            # Job Lifecycle History
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

            # Unified System Audit Logs
            cur.execute("""
                CREATE TABLE IF NOT EXISTS system_audit_logs (
                    id BIGSERIAL PRIMARY KEY,
                    category VARCHAR(100) NOT NULL,
                    job_card_id VARCHAR(100) DEFAULT '-',
                    action VARCHAR(100) NOT NULL,
                    performed_by VARCHAR(100) NOT NULL,
                    details TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)

            # Bootstrap default admin account if not present
            cur.execute("SELECT id FROM users WHERE LOWER(username) = 'admin' LIMIT 1;")
            if not cur.fetchone():
                admin_hash = hash_password("Admin@1234")
                cur.execute("""
                    INSERT INTO users (username, password_hash, role, must_change_password, can_upload, is_active, employee_name, employee_id)
                    VALUES ('admin', %s, 'admin', TRUE, TRUE, TRUE, 'System Administrator', 'ADMIN-01');
                """, (admin_hash,))

            conn.commit()
    finally:
        release_connection(conn)
