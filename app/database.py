import os
import psycopg2
from psycopg2.pool import SimpleConnectionPool
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

DATABASE_URL = os.environ.get("DATABASE_URL")

if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

pool = SimpleConnectionPool(minconn=1, maxconn=20, dsn=DATABASE_URL)

def get_connection():
    return pool.getconn()

def release_connection(conn):
    pool.putconn(conn)

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def init_db():
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            # Users table with can_upload flag
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    password_hash TEXT NOT NULL,
                    role VARCHAR(50) DEFAULT 'QC Incharge',
                    must_change_password BOOLEAN DEFAULT TRUE,
                    can_upload BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                );
                ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN DEFAULT TRUE;
                ALTER TABLE users ADD COLUMN IF NOT EXISTS can_upload BOOLEAN DEFAULT FALSE;
                UPDATE users SET role = 'QC Incharge' WHERE role = 'operator';
                UPDATE users SET can_upload = TRUE WHERE role = 'admin';
            """)

            # Job Cards
            cur.execute("""
                CREATE TABLE IF NOT EXISTS job_cards (
                    job_card_id TEXT PRIMARY KEY,
                    description TEXT,
                    client_name TEXT,
                    status VARCHAR(20) DEFAULT 'ACTIVE',
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                );
                ALTER TABLE job_cards ADD COLUMN IF NOT EXISTS description TEXT;
            """)

            # Codes table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS codes (
                    job_card_id TEXT REFERENCES job_cards(job_card_id) ON DELETE CASCADE,
                    code_value TEXT NOT NULL,
                    status VARCHAR(20) DEFAULT 'PENDING',
                    scanned_at TIMESTAMP WITH TIME ZONE NULL,
                    PRIMARY KEY (job_card_id, code_value)
                );
                CREATE INDEX IF NOT EXISTS idx_codes_value ON codes (code_value);
                CREATE INDEX IF NOT EXISTS idx_codes_status ON codes (status);
            """)

            # Scan logs
            cur.execute("""
                CREATE TABLE IF NOT EXISTS scan_logs (
                    id BIGSERIAL PRIMARY KEY,
                    job_card_id TEXT,
                    code_scanned TEXT NOT NULL,
                    result VARCHAR(20) NOT NULL,
                    scanned_by TEXT NOT NULL,
                    scanned_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                );
                CREATE INDEX IF NOT EXISTS idx_scan_logs_jc ON scan_logs (job_card_id);
                CREATE INDEX IF NOT EXISTS idx_scan_logs_time ON scan_logs (scanned_at DESC);
            """)

            # Lifecycle logs
            cur.execute("""
                CREATE TABLE IF NOT EXISTS job_lifecycle_logs (
                    id BIGSERIAL PRIMARY KEY,
                    job_card_id TEXT NOT NULL,
                    action VARCHAR(50) NOT NULL,
                    performed_by TEXT NOT NULL,
                    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                );
                CREATE INDEX IF NOT EXISTS idx_lifecycle_jc ON job_lifecycle_logs (job_card_id);
                CREATE INDEX IF NOT EXISTS idx_lifecycle_time ON job_lifecycle_logs (timestamp DESC);
            """)

            # Seed default admin
            cur.execute("SELECT COUNT(*) FROM users;")
            if cur.fetchone()[0] == 0:
                admin_hash = hash_password("admin123")
                cur.execute(
                    "INSERT INTO users (username, password_hash, role, must_change_password, can_upload) VALUES (%s, %s, %s, %s, %s)",
                    ("admin", admin_hash, "admin", True, True)
                )

            conn.commit()
    except Exception as e:
        conn.rollback()
        print(f"Database init notice: {e}")
    finally:
        release_connection(conn)
