import os
import threading
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

# psycopg2's pool raises immediately when it is exhausted. This semaphore makes callers wait their turn instead,
# and the set tracks checked-out connections so a duplicate release can never free a slot twice.
POOL_WAIT_SECONDS = float(os.environ.get("DB_POOL_WAIT_SECONDS", 30))
_pool_slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
_checked_out = set()
_checked_out_lock = threading.Lock()


class PoolBusyError(Exception):
    """Raised when no database connection became available within the wait limit."""

def init_db():
    global connection_pool
    if not connection_pool:
        try:
            connection_pool = pool.ThreadedConnectionPool(
                minconn=MIN_CONNECTIONS,
                maxconn=MAX_CONNECTIONS,
                dsn=DATABASE_URL,
                options="-c timezone=UTC",
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
                CREATE TABLE IF NOT EXISTS job_code_duplicate_rows (
                    id BIGSERIAL PRIMARY KEY,
                    run_id INT NOT NULL REFERENCES job_cards(run_id) ON DELETE CASCADE,
                    code_value TEXT NOT NULL,
                    first_source_line BIGINT NOT NULL,
                    first_source_column BIGINT NOT NULL,
                    duplicate_source_line BIGINT NOT NULL,
                    duplicate_source_column BIGINT NOT NULL,
                    occurrence_number BIGINT NOT NULL,
                    occurrence_count BIGINT NOT NULL
                );
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_job_code_duplicate_rows_run
                ON job_code_duplicate_rows (run_id, code_value, occurrence_number);
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS scan_logs (
                    id SERIAL PRIMARY KEY,
                    run_id INT,
                    job_card_id TEXT NOT NULL,
                    code_scanned TEXT NOT NULL,
                    result TEXT NOT NULL,
                    scanned_by TEXT,
                    scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
            cur.execute(
                "ALTER TABLE scan_logs ADD COLUMN IF NOT EXISTS "
                "run_id INT;"
            )

            cur.execute("""
                CREATE TABLE IF NOT EXISTS packing_qc_logs (
                    id SERIAL PRIMARY KEY,
                    run_id INT REFERENCES job_cards(run_id) ON DELETE CASCADE,
                    job_card_id TEXT NOT NULL,
                    code_scanned TEXT NOT NULL,
                    tested_by TEXT,
                    qc_stage VARCHAR(20) NOT NULL DEFAULT 'PRECHECK',
                    tested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
            cur.execute(
                "ALTER TABLE packing_qc_logs ADD COLUMN IF NOT EXISTS "
                "qc_stage VARCHAR(20) NOT NULL DEFAULT 'PRECHECK';"
            )
            cur.execute(
                "ALTER TABLE packing_qc_logs ADD COLUMN IF NOT EXISTS "
                "run_id INT REFERENCES job_cards(run_id) ON DELETE CASCADE;"
            )
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_packing_qc_run_stage "
                "ON packing_qc_logs (run_id, qc_stage, tested_at DESC);"
            )
            cur.execute("""
                CREATE TABLE IF NOT EXISTS packing_qc_completions (
                    run_id INT PRIMARY KEY REFERENCES job_cards(run_id) ON DELETE CASCADE,
                    job_card_id TEXT NOT NULL,
                    completed_by TEXT NOT NULL,
                    completed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
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
            cur.execute("ALTER TABLE scan_logs ADD COLUMN IF NOT EXISTS scan_source TEXT NOT NULL DEFAULT 'DESKTOP';")
            cur.execute("ALTER TABLE packing_qc_logs ADD COLUMN IF NOT EXISTS scan_source TEXT NOT NULL DEFAULT 'DESKTOP';")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_lifecycle_jc_id ON job_lifecycle_logs (job_card_id, id DESC);")

            cur.execute("""
                CREATE TABLE IF NOT EXISTS phone_scanner_sessions (
                    session_id TEXT PRIMARY KEY,
                    token_hash CHAR(64) NOT NULL UNIQUE,
                    username TEXT NOT NULL,
                    job_card_id TEXT NOT NULL,
                    scan_target TEXT NOT NULL DEFAULT 'verification',
                    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMPTZ NOT NULL,
                    connected_at TIMESTAMPTZ,
                    last_seen_at TIMESTAMPTZ,
                    revoked_at TIMESTAMPTZ
                );
            """)
            cur.execute(
                "ALTER TABLE phone_scanner_sessions ADD COLUMN IF NOT EXISTS "
                "scan_target TEXT NOT NULL DEFAULT 'verification';"
            )
            cur.execute("""
                CREATE TABLE IF NOT EXISTS phone_scanner_scans (
                    id BIGSERIAL PRIMARY KEY,
                    session_id TEXT NOT NULL REFERENCES phone_scanner_sessions(session_id) ON DELETE CASCADE,
                    code TEXT NOT NULL,
                    received_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_phone_scanner_scans_session_id
                ON phone_scanner_scans (session_id, id);
            """)

            cur.execute("SELECT COUNT(*) FROM users;")
            row = cur.fetchone()
            if row and row[0] == 0:
                print("No users exist. Create the initial administrator by running: python seed_admin.py")

            conn.commit()
    finally:
        release_connection(conn)

def get_connection():
    """Checkout a connection from the pool, waiting up to POOL_WAIT_SECONDS for a free slot."""
    if not connection_pool:
        init_db()
    if not _pool_slots.acquire(timeout=POOL_WAIT_SECONDS):
        raise PoolBusyError("All database connections are busy.")
    try:
        conn = connection_pool.getconn()
        if conn.closed:
            # Re-establish if closed by server timeout
            connection_pool.putconn(conn, close=True)
            conn = connection_pool.getconn()
    except Exception as e:
        _pool_slots.release()
        print(f"Error acquiring database connection: {e}")
        raise
    with _checked_out_lock:
        _checked_out.add(id(conn))
    return conn

def release_connection(conn):
    """Return a connection back to the pool safely. Releasing the same connection twice is harmless."""
    if not connection_pool or not conn:
        return
    with _checked_out_lock:
        owned = id(conn) in _checked_out
        _checked_out.discard(id(conn))
    if not owned:
        return
    try:
        # Reset connection state to prevent transaction pollution
        if not conn.closed:
            conn.rollback()
        connection_pool.putconn(conn)
    except Exception as e:
        print(f"Error releasing connection: {e}")
    finally:
        _pool_slots.release()

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
