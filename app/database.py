import os
import logging
import hashlib
import secrets
from typing import Optional
from contextlib import contextmanager
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import psycopg2
from psycopg2 import pool
from psycopg2.extras import RealDictCursor

logger = logging.getLogger("app.database")

# Global connection pool instance
_connection_pool: Optional[pool.ThreadedConnectionPool] = None


# ---------------------------------------------------------------------------
# Password Security Helpers (Zero-dependency PBKDF2)
# ---------------------------------------------------------------------------
def hash_password(password: str) -> str:
    """Generates a secure salted PBKDF2-SHA256 password hash."""
    salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), 100000)
    return f"{salt}${key.hex()}"


def verify_password(password: str, hashed_value: str) -> bool:
    """Verifies a password against a stored salt$hash string."""
    try:
        salt, key_hex = hashed_value.split("$")
        computed = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), 100000)
        return secrets.compare_digest(computed.hex(), key_hex)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Connection String Sanitization (Railway & Render Safe)
# ---------------------------------------------------------------------------
def get_clean_database_url() -> str:
    """
    Cleans and standardizes the DATABASE_URL for compatibility with
    both Railway and Render environments without libpq DSN parsing crashes.
    """
    raw_url = os.getenv("DATABASE_URL", "").strip()
    if not raw_url:
        raise ValueError("DATABASE_URL environment variable is missing or empty.")

    # 1. Normalize legacy scheme (Render exports postgres:// by default)
    if raw_url.startswith("postgres://"):
        raw_url = raw_url.replace("postgres://", "postgresql://", 1)

    # 2. Parse URL components
    parsed = urlparse(raw_url)
    query_params = parse_qs(parsed.query)

    # 3. Handle SSL requirement cleanly:
    # - Railway internal networking (*.railway.internal) does not use SSL
    # - Render & Railway external public proxies require SSL
    is_railway_internal = "railway.internal" in (parsed.netloc or "")

    if is_railway_internal:
        query_params.pop("sslmode", None)
    else:
        if "sslmode" not in query_params:
            query_params["sslmode"] = ["require"]

    # 4. Reconstruct clean URL
    clean_url = urlunparse(
        parsed._replace(query=urlencode(query_params, doseq=True))
    )
    return clean_url


# ---------------------------------------------------------------------------
# Connection Pool Management
# ---------------------------------------------------------------------------
def init_connection_pool(minconn: int = 1, maxconn: int = 20) -> pool.ThreadedConnectionPool:
    """Initializes a thread-safe psycopg2 connection pool."""
    global _connection_pool
    if _connection_pool is None or _connection_pool.closed:
        dsn = get_clean_database_url()
        try:
            _connection_pool = pool.ThreadedConnectionPool(
                minconn=minconn,
                maxconn=maxconn,
                dsn=dsn
            )
            logger.info("Database connection pool initialized successfully.")
        except Exception as e:
            logger.error(f"Failed to initialize database connection pool: {e}")
            raise
    return _connection_pool


def get_connection():
    """
    Retrieves an active connection from the pool.
    Initializes the pool if it has not been started yet.
    """
    global _connection_pool
    if _connection_pool is None or _connection_pool.closed:
        init_connection_pool()
    return _connection_pool.getconn()


def release_connection(conn):
    """Returns an active connection back to the pool."""
    global _connection_pool
    if conn and _connection_pool and not _connection_pool.closed:
        try:
            _connection_pool.putconn(conn)
        except Exception as e:
            logger.warning(f"Error returning connection to pool: {e}")


def close_connection_pool():
    """Closes all connections in the pool on shutdown."""
    global _connection_pool
    if _connection_pool and not _connection_pool.closed:
        _connection_pool.closeall()
        logger.info("Database connection pool closed.")


@contextmanager
def get_db_connection():
    """Context manager for acquiring and safely returning a raw database connection."""
    conn = get_connection()
    try:
        yield conn
    finally:
        release_connection(conn)


@contextmanager
def get_db_cursor(commit: bool = False, cursor_factory=RealDictCursor):
    """
    Context manager for database transactions with automatic rollback on error
    and connection recycling. Defaults to returning dictionary-like rows.
    """
    conn = get_connection()
    cursor = conn.cursor(cursor_factory=cursor_factory)
    try:
        yield cursor
        if commit:
            conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        cursor.close()
        release_connection(conn)


# ---------------------------------------------------------------------------
# Schema Initialization & Migrations (Synchronized with main.py)
# ---------------------------------------------------------------------------
def init_db():
    """
    Initializes required database schema tables and safely applies migrations
    aligned with the exact column names queried in main.py.
    """
    schema_sql = """
    -- 1. Users Table
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(100) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        role VARCHAR(50) NOT NULL DEFAULT 'QC officer',
        can_upload BOOLEAN NOT NULL DEFAULT FALSE,
        employee_name VARCHAR(255),
        employee_id VARCHAR(100),
        is_active BOOLEAN NOT NULL DEFAULT TRUE,
        must_change_password BOOLEAN NOT NULL DEFAULT FALSE,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
    );

    ALTER TABLE users ADD COLUMN IF NOT EXISTS employee_name VARCHAR(255);
    ALTER TABLE users ADD COLUMN IF NOT EXISTS employee_id VARCHAR(100);
    ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN DEFAULT FALSE;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS can_upload BOOLEAN DEFAULT FALSE;

    -- 2. Job Cards Table (run_id is the primary identifier used across the application)
    CREATE TABLE IF NOT EXISTS job_cards (
        run_id SERIAL PRIMARY KEY,
        job_card_id VARCHAR(100) NOT NULL,
        description TEXT,
        status VARCHAR(100) NOT NULL DEFAULT 'ACTIVE',
        total_codes INTEGER DEFAULT 0,
        consumed_codes INTEGER DEFAULT 0,
        conflict_count INTEGER DEFAULT 0,
        conflict_resolution VARCHAR(50) DEFAULT 'NONE',
        ingestion_progress TEXT,
        staged_file_path TEXT,
        deleted_by VARCHAR(100),
        deleted_at TIMESTAMP WITH TIME ZONE,
        deletion_reason TEXT,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
    );

    ALTER TABLE job_cards ADD COLUMN IF NOT EXISTS staged_file_path TEXT;
    ALTER TABLE job_cards ADD COLUMN IF NOT EXISTS deleted_by VARCHAR(100);
    ALTER TABLE job_cards ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMP WITH TIME ZONE;
    ALTER TABLE job_cards ADD COLUMN IF NOT EXISTS deletion_reason TEXT;
    ALTER TABLE job_cards ADD COLUMN IF NOT EXISTS conflict_resolution VARCHAR(50) DEFAULT 'NONE';

    -- 3. Serialized Codes Table (High-speed barcode pool)
    CREATE TABLE IF NOT EXISTS codes (
        id SERIAL PRIMARY KEY,
        run_id INTEGER NOT NULL REFERENCES job_cards(run_id) ON DELETE CASCADE,
        job_card_id VARCHAR(100) NOT NULL,
        code_value VARCHAR(255) NOT NULL,
        status VARCHAR(50) NOT NULL DEFAULT 'PENDING',
        scanned_at TIMESTAMP WITH TIME ZONE
    );

    -- Base index on codes (run-specific indexes only to prevent startup disk overflow)
    CREATE INDEX IF NOT EXISTS idx_codes_run_val ON codes(run_id, code_value);
    CREATE INDEX IF NOT EXISTS idx_codes_run_status ON codes(run_id, status);
    CREATE INDEX IF NOT EXISTS idx_codes_run_id_id ON codes(run_id, id);

    -- 4. Verification Scan Logs Table
    CREATE TABLE IF NOT EXISTS scan_logs (
        id SERIAL PRIMARY KEY,
        job_card_id VARCHAR(100) NOT NULL,
        code_scanned VARCHAR(255) NOT NULL,
        result VARCHAR(50) NOT NULL,
        scanned_by VARCHAR(100) NOT NULL,
        scanned_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
    );

    CREATE INDEX IF NOT EXISTS idx_scan_logs_jc ON scan_logs(job_card_id);
    CREATE INDEX IF NOT EXISTS idx_scan_logs_code ON scan_logs(code_scanned);

    -- 5. Final Packing QC Logs Table
    CREATE TABLE IF NOT EXISTS packing_qc_logs (
        id SERIAL PRIMARY KEY,
        job_card_id VARCHAR(100) NOT NULL,
        code_scanned VARCHAR(255) NOT NULL,
        tested_by VARCHAR(100) NOT NULL,
        tested_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
    );

    CREATE INDEX IF NOT EXISTS idx_packing_qc_jc ON packing_qc_logs(job_card_id);

    -- 6. System Audit Logs Table
    CREATE TABLE IF NOT EXISTS system_audit_logs (
        id SERIAL PRIMARY KEY,
        category VARCHAR(50) NOT NULL,
        job_card_id VARCHAR(100) DEFAULT '-',
        action VARCHAR(100) NOT NULL,
        performed_by VARCHAR(100) NOT NULL,
        details TEXT,
        timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
    );

    -- 7. Job Lifecycle Audit Logs Table
    CREATE TABLE IF NOT EXISTS job_lifecycle_logs (
        id SERIAL PRIMARY KEY,
        job_card_id VARCHAR(100) NOT NULL,
        action VARCHAR(100) NOT NULL,
        performed_by VARCHAR(100),
        reason TEXT,
        timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
    );

    CREATE INDEX IF NOT EXISTS idx_system_audit_ts ON system_audit_logs(timestamp DESC);
    CREATE INDEX IF NOT EXISTS idx_lifecycle_jc ON job_lifecycle_logs(job_card_id);
    """
    with get_db_cursor(commit=True) as cursor:
        cursor.execute(schema_sql)
        logger.info("Database schema initialized and verified.")
