import os
import bcrypt
import psycopg2
from psycopg2 import pool
from contextlib import contextmanager

DATABASE_URL = os.environ.get("DATABASE_URL")

# Calculate optimal pool size: 
# (FastAPI workers * threads) + Background Workers + Safety Buffer
MIN_CONNECTIONS = 2
MAX_CONNECTIONS = int(os.environ.get("DB_MAX_CONNECTIONS", 25))

# Thread-safe connection pool for concurrent background threads & web requests
connection_pool = None

def init_db():
    global connection_pool
    if not connection_pool:
        try:
            connection_pool = pool.ThreadedConnectionPool(
                minconn=MIN_CONNECTIONS,
                maxconn=MAX_CONNECTIONS,
                dsn=DATABASE_URL,
                cursor_factory=psycopg2.extras.DictCursor if hasattr(psycopg2, 'extras') else None
            )
            print(f"Database connection pool initialized (Min: {MIN_CONNECTIONS}, Max: {MAX_CONNECTIONS})")
        except Exception as e:
            print(f"Failed to initialize connection pool: {e}")
            raise

    # Run essential schema initialization
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            # 1. Core tables
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT DEFAULT 'QC officer',
                    must_change_password BOOLEAN DEFAULT TRUE,
                    can_upload BOOLEAN DEFAULT FALSE,
                    is_active BOOLEAN DEFAULT TRUE,
                    employee_name TEXT,
                    employee_id TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
            
            cur.execute("""
                CREATE TABLE IF NOT EXISTS job_cards (
                    run_id SERIAL PRIMARY KEY,
                    job_card_id TEXT NOT NULL,
                    description TEXT,
                    status VARCHAR(100) DEFAULT 'ACTIVE',
                    total_codes INT DEFAULT 0,
                    consumed_codes INT DEFAULT 0,
                    conflict_count INT DEFAULT 0,
                    conflict_resolution VARCHAR(50) DEFAULT 'NONE',
                    conflict_details TEXT,
                    staged_file_path TEXT,
                    ingestion_progress TEXT,
                    deleted_by TEXT,
                    deleted_at TIMESTAMP,
                    deletion_reason TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS codes (
                    id SERIAL PRIMARY KEY,
                    run_id INT REFERENCES job_cards(run_id) ON DELETE CASCADE,
                    job_card_id TEXT NOT NULL,
                    code_value TEXT NOT NULL,
                    status TEXT DEFAULT 'PENDING',
                    scanned_at TIMESTAMP
                );
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS scan_logs (
                    id SERIAL PRIMARY KEY,
                    job_card_id TEXT NOT NULL,
                    code_scanned TEXT NOT NULL,
                    result TEXT NOT NULL,
                    scanned_by TEXT,
                    scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS packing_qc_logs (
                    id SERIAL PRIMARY KEY,
                    job_card_id TEXT NOT NULL,
                    code_scanned TEXT NOT NULL,
                    tested_by TEXT,
                    tested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS job_lifecycle_logs (
                    id SERIAL PRIMARY KEY,
                    job_card_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    performed_by TEXT,
                    reason TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS system_audit_logs (
                    id SERIAL PRIMARY KEY,
                    category TEXT NOT NULL,
                    job_card_id TEXT,
                    action TEXT NOT NULL,
                    performed_by TEXT,
                    details TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)

            # Ensure default admin account exists
            cur.execute("SELECT COUNT(*) FROM users;")
            row = cur.fetchone()
            user_count = row[0] if row else 0
            if user_count == 0:
                default_hash = bcrypt.hashpw("Admin@2026".encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                cur.execute("""
                    INSERT INTO users (username, password_hash, role, must_change_password, can_upload, is_active, employee_name, employee_id)
                    VALUES ('admin', %s, 'admin', TRUE, TRUE, TRUE, 'System Administrator', 'EMP-001')
                """, (default_hash,))

            conn.commit()
    finally:
        release_connection(conn)

def get_connection():
    """Checkout a connection from the thread-safe pool with a timeout safety check."""
    if not connection_pool:
        init_db()
    try:
        # getconn() is thread-safe in psycopg2.pool.ThreadedConnectionPool
        conn = connection_pool.getconn()
        if conn.closed:
            # Re-establish if closed by server timeout
            connection_pool.putconn(conn, close=True)
            conn = connection_pool.getconn()
        return conn
    except Exception as e:
        print(f"Error acquiring database connection: {e}")
        raise

def release_connection(conn):
    """Return a connection back to the pool safely."""
    if connection_pool and conn:
        try:
            # Reset connection state to prevent transaction pollution
            if not conn.closed:
                conn.rollback()
            connection_pool.putconn(conn)
        except Exception as e:
            print(f"Error releasing connection: {e}")

@contextmanager
def db_transaction():
    """Context manager for automatic connection checkout, commit, and release."""
    conn = get_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        release_connection(conn)

def close_connection_pool():
    global connection_pool
    if connection_pool:
        try:
            connection_pool.closeall()
            connection_pool = None
            print("Database connection pool closed successfully.")
        except Exception as e:
            print(f"Error closing connection pool: {e}")

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))
    except Exception:
        return False
