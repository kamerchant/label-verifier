import os
import psycopg2
from passlib.hash import bcrypt

DATABASE_URL = os.environ.get(
    "DATABASE_URL", 
    "postgres://postgres:postgres@localhost:5432/ccl_vdv"
)

def get_connection():
    return psycopg2.connect(DATABASE_URL)

def release_connection(conn):
    if conn:
        conn.close()

def hash_password(password: str) -> str:
    return bcrypt.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.verify(plain_password, hashed_password)

def init_db():
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            # Users table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(150) UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role VARCHAR(50) DEFAULT 'QC operator',
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
                    job_card_id VARCHAR(100) UNIQUE NOT NULL,
                    description TEXT,
                    status VARCHAR(50) DEFAULT 'ACTIVE',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    deleted_by VARCHAR(150),
                    deleted_at TIMESTAMP,
                    deletion_reason TEXT
                );
            """)

            # Codes pool table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS codes (
                    id SERIAL PRIMARY KEY,
                    run_id INTEGER REFERENCES job_cards(run_id) ON DELETE CASCADE,
                    job_card_id VARCHAR(100) NOT NULL,
                    code_value TEXT NOT NULL,
                    status VARCHAR(50) DEFAULT 'PENDING',
                    scanned_at TIMESTAMP
                );
            """)

            # Scan logs table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS scan_logs (
                    id SERIAL PRIMARY KEY,
                    job_card_id VARCHAR(100) NOT NULL,
                    code_scanned TEXT NOT NULL,
                    result VARCHAR(50) NOT NULL,
                    scanned_by VARCHAR(150),
                    scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)

            # Job lifecycle logs table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS job_lifecycle_logs (
                    id SERIAL PRIMARY KEY,
                    job_card_id VARCHAR(100) NOT NULL,
                    action VARCHAR(100) NOT NULL,
                    performed_by VARCHAR(150),
                    reason TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)

            # Packing QC logs table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS packing_qc_logs (
                    id SERIAL PRIMARY KEY,
                    job_card_id VARCHAR(100) NOT NULL,
                    code_scanned TEXT NOT NULL,
                    tested_by VARCHAR(150),
                    tested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)

            # Seed default admin user if none exists
            cur.execute("SELECT COUNT(*) FROM users;")
            if cur.fetchone()[0] == 0:
                default_hash = hash_password("Admin@123")
                cur.execute(
                    """INSERT INTO users (username, password_hash, role, must_change_password, can_upload, is_active) 
                       VALUES (%s, %s, %s, FALSE, TRUE, TRUE)""",
                    ("Admin", default_hash, "admin")
                )

            conn.commit()
    finally:
        release_connection(conn)
