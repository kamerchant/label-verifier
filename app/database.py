import os
import bcrypt
import psycopg2

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/vdv_db")

def get_connection():
    return psycopg2.connect(DATABASE_URL)

def release_connection(conn):
    if conn:
        conn.close()

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def init_db():
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            # Create tables if they don't exist
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    username VARCHAR(50) PRIMARY KEY,
                    password_hash VARCHAR(255) NOT NULL,
                    role VARCHAR(50) NOT NULL DEFAULT 'QC Incharge',
                    must_change_password BOOLEAN DEFAULT TRUE,
                    can_upload BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS job_cards (
                    run_id SERIAL PRIMARY KEY,
                    job_card_id VARCHAR(100) NOT NULL,
                    description TEXT,
                    status VARCHAR(20) DEFAULT 'ACTIVE',
                    deletion_reason TEXT,
                    deleted_by VARCHAR(50),
                    deleted_at TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS codes (
                    run_id INT REFERENCES job_cards(run_id) ON DELETE CASCADE,
                    job_card_id VARCHAR(100) NOT NULL,
                    code_value TEXT NOT NULL,
                    status VARCHAR(20) DEFAULT 'PENDING',
                    scanned_at TIMESTAMP
                );
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS scan_logs (
                    id SERIAL PRIMARY KEY,
                    job_card_id VARCHAR(100) NOT NULL,
                    code_scanned TEXT,
                    result VARCHAR(20),
                    scanned_by VARCHAR(50),
                    scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS job_lifecycle_logs (
                    id SERIAL PRIMARY KEY,
                    job_card_id VARCHAR(100) NOT NULL,
                    action VARCHAR(50) NOT NULL,
                    performed_by VARCHAR(50) NOT NULL,
                    reason TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)

            # Automatically ensure admin user exists and reset password to 'admin123'
            admin_hash = hash_password("admin123")
            cur.execute("""
                INSERT INTO users (username, password_hash, role, must_change_password, can_upload)
                VALUES ('admin', %s, 'admin', FALSE, TRUE)
                ON CONFLICT (username) DO UPDATE 
                SET password_hash = %s, role = 'admin', can_upload = TRUE;
            """, (admin_hash, admin_hash))

            conn.commit()
    finally:
        release_connection(conn)
