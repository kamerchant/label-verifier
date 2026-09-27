import os
import psycopg2
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_database_url():
    url = os.environ.get("DATABASE_URL")
    if url:
        return url
    return "postgresql://postgres:postgres@localhost:5432/vdv_db"

def get_connection():
    return psycopg2.connect(get_database_url())

def release_connection(conn):
    if conn:
        conn.close()

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def init_db():
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            # Users Table with Employee Name and Employee ID
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    username VARCHAR(100) PRIMARY KEY,
                    password_hash VARCHAR(255) NOT NULL,
                    role VARCHAR(50) NOT NULL DEFAULT 'QC Incharge',
                    must_change_password BOOLEAN NOT NULL DEFAULT TRUE,
                    can_upload BOOLEAN NOT NULL DEFAULT FALSE,
                    is_active BOOLEAN NOT NULL DEFAULT TRUE,
                    employee_name VARCHAR(150),
                    employee_id VARCHAR(50),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)

            # Safely add columns if they don't exist in older DB instances
            cur.execute("""
                DO $$ 
                BEGIN 
                    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='users' and column_name='employee_name') THEN
                        ALTER TABLE users ADD COLUMN employee_name VARCHAR(150);
                    END IF;
                    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='users' and column_name='employee_id') THEN
                        ALTER TABLE users ADD COLUMN employee_id VARCHAR(50);
                    END IF;
                END $$;
            """)

            # Job Cards Table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS job_cards (
                    run_id SERIAL PRIMARY KEY,
                    job_card_id VARCHAR(100) NOT NULL,
                    description TEXT,
                    status VARCHAR(50) NOT NULL DEFAULT 'ACTIVE',
                    deletion_reason TEXT,
                    deleted_by VARCHAR(100),
                    deleted_at TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)

            # Codes Table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS codes (
                    run_id INT REFERENCES job_cards(run_id) ON DELETE CASCADE,
                    job_card_id VARCHAR(100) NOT NULL,
                    code_value TEXT NOT NULL,
                    status VARCHAR(50) NOT NULL DEFAULT 'PENDING',
                    scanned_at TIMESTAMP
                );
            """)

            # Scan Logs Table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS scan_logs (
                    id SERIAL PRIMARY KEY,
                    job_card_id VARCHAR(100) NOT NULL,
                    code_scanned TEXT NOT NULL,
                    result VARCHAR(50) NOT NULL,
                    scanned_by VARCHAR(100) NOT NULL,
                    scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)

            # Job Lifecycle Logs Table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS job_lifecycle_logs (
                    id SERIAL PRIMARY KEY,
                    job_card_id VARCHAR(100) NOT NULL,
                    action VARCHAR(100) NOT NULL,
                    performed_by VARCHAR(100) NOT NULL,
                    reason TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)

            # Create default admin if not exists
            cur.execute("SELECT username FROM users WHERE username = 'admin'")
            if not cur.fetchone():
                admin_hash = hash_password("Admin@123")
                cur.execute(
                    "INSERT INTO users (username, password_hash, role, must_change_password, can_upload, is_active, employee_name, employee_id) VALUES (%s, %s, %s, FALSE, TRUE, TRUE, %s, %s)",
                    ("admin", admin_hash, "admin", "System Administrator", "ADM-001")
                )

            conn.commit()
    finally:
        release_connection(conn)
