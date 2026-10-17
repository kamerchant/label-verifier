"""
CCL Middle East - Pakistan | Variable Data Verification System (VDV)
Database Connection Pool, Schema Migrations & Cryptography
"""

import os
import logging
from passlib.context import CryptContext
import psycopg2
from psycopg2 import pool, extras

logger = logging.getLogger("vdv.database")

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL environment variable is not configured.")

# Password hashing context (bcrypt)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    """Hashes a plaintext password using bcrypt."""
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plaintext password against a bcrypt hash."""
    return pwd_context.verify(plain_password, hashed_password)

# Threaded connection pool (handles concurrent scans and batch ingestion)
connection_pool = None

def init_connection_pool():
    global connection_pool
    if connection_pool is None or connection_pool.closed:
        try:
            connection_pool = pool.ThreadedConnectionPool(
                minconn=2,
                maxconn=25,
                dsn=DATABASE_URL,
                # Force Pakistan Standard Time and keep connections alive through Render load balancers
                options="-c timezone=Asia/Karachi",
                connect_timeout=10,
                keepalives=1,
                keepalives_idle=30,
                keepalives_interval=10,
                keepalives_count=5
            )
            logger.info("PostgreSQL Threaded Connection Pool initialized successfully.")
        except Exception as e:
            logger.error(f"Failed to initialize connection pool: {e}")
            raise e

init_connection_pool()

def get_connection():
    """Acquires a dedicated connection from the connection pool."""
    global connection_pool
    if connection_pool is None or connection_pool.closed:
        init_connection_pool()
    return connection_pool.getconn()

def release_connection(conn):
    """Safely returns a connection to the pool, resetting any uncommitted state."""
    global connection_pool
    if connection_pool and not connection_pool.closed and conn:
        try:
            if not conn.closed and conn.get_transaction_status() != psycopg2.extensions.TRANSACTION_STATUS_IDLE:
                conn.rollback()
            connection_pool.putconn(conn)
        except Exception:
            pass

def close_connection_pool():
    """Closes all active connections during application shutdown."""
    global connection_pool
    if connection_pool and not connection_pool.closed:
        connection_pool.closeall()
        logger.info("Database connection pool closed cleanly.")


# =====================================================================
# SCHEMA INITIALIZATION & MIGRATIONS
# =====================================================================

def init_db():
    """
    Provisions all tables, constraints, and performance indexes
    matching the exact schema expected by main.py.
    """
    schema_sql = [
        # 1. Users table
        """
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(100) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            role VARCHAR(50) DEFAULT 'QC officer',
            must_change_password BOOLEAN DEFAULT TRUE,
            can_upload BOOLEAN DEFAULT FALSE,
            is_active BOOLEAN DEFAULT TRUE,
            employee_name VARCHAR(150),
            employee_id VARCHAR(50),
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );
        """,

        # 2. Job Cards Master Table
        """
        CREATE TABLE IF NOT EXISTS job_cards (
            run_id SERIAL PRIMARY KEY,
            job_card_id VARCHAR(100) NOT NULL,
            description TEXT,
            status VARCHAR(100) DEFAULT 'INGESTING',
            total_codes INT DEFAULT 0,
            consumed_codes INT DEFAULT 0,
            conflict_count INT DEFAULT 0,
            conflict_resolution VARCHAR(50) DEFAULT 'NONE',
            conflict_details TEXT,
            staged_file_path TEXT,
            ingestion_progress TEXT,
            deleted_by VARCHAR(100),
            deleted_at TIMESTAMP WITH TIME ZONE,
            deletion_reason TEXT,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );
        CREATE INDEX IF NOT EXISTS idx_job_cards_jc_id ON job_cards (job_card_id);
        CREATE INDEX IF NOT EXISTS idx_job_cards_status ON job_cards (status);
        """,

        # 3. Barcode Codes Table (High-volume)
        """
        CREATE TABLE IF NOT EXISTS codes (
            id BIGSERIAL PRIMARY KEY,
            run_id INT NOT NULL REFERENCES job_cards(run_id) ON DELETE CASCADE,
            job_card_id VARCHAR(100) NOT NULL,
            code_value VARCHAR(150) NOT NULL,
            status VARCHAR(50) DEFAULT 'PENDING',
            scanned_at TIMESTAMP WITH TIME ZONE
        );
        CREATE INDEX IF NOT EXISTS idx_codes_run_val ON codes (run_id, code_value);
        CREATE INDEX IF NOT EXISTS idx_codes_run_id_asc ON codes (run_id, id ASC);
        CREATE INDEX IF NOT EXISTS idx_codes_run_status_id ON codes (run_id, status, id);
        CREATE INDEX IF NOT EXISTS idx_codes_val_active ON codes (code_value) WHERE status != 'DELETED';
        """,

        # 4. Shop Floor Inline Scan Logs
        """
        CREATE TABLE IF NOT EXISTS scan_logs (
            id BIGSERIAL PRIMARY KEY,
            job_card_id VARCHAR(100) NOT NULL,
            code_scanned VARCHAR(150) NOT NULL,
            result VARCHAR(100) NOT NULL,
            scanned_by VARCHAR(100),
            scanned_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );
        CREATE INDEX IF NOT EXISTS idx_scan_logs_jc_time ON scan_logs (job_card_id, scanned_at DESC);
        """,

        # 5. Final QC Packaging Logs
        """
        CREATE TABLE IF NOT EXISTS packing_qc_logs (
            id SERIAL PRIMARY KEY,
            job_card_id VARCHAR(100) NOT NULL,
            code_scanned VARCHAR(150) NOT NULL,
            tested_by VARCHAR(100) NOT NULL,
            tested_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );
        CREATE INDEX IF NOT EXISTS idx_packing_qc_jc ON packing_qc_logs (job_card_id);
        """,

        # 6. Job Lifecycle Audit Logs
        """
        CREATE TABLE IF NOT EXISTS job_lifecycle_logs (
            id SERIAL PRIMARY KEY,
            job_card_id VARCHAR(100) NOT NULL,
            action VARCHAR(100) NOT NULL,
            performed_by VARCHAR(100),
            reason TEXT,
            timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );
        CREATE INDEX IF NOT EXISTS idx_lifecycle_jc ON job_lifecycle_logs (job_card_id);
        """,

        # 7. Unified System Activity Audit Logs
        """
        CREATE TABLE IF NOT EXISTS system_audit_logs (
            id BIGSERIAL PRIMARY KEY,
            category VARCHAR(50) NOT NULL,
            job_card_id VARCHAR(100),
            action VARCHAR(100) NOT NULL,
            performed_by VARCHAR(100),
            details TEXT,
            timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );
        CREATE INDEX IF NOT EXISTS idx_sys_audit_time ON system_audit_logs (timestamp DESC);
        """
    ]

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            for statement in schema_sql:
                cur.execute(statement)

            # Auto-seed initial administrator account if no users exist
            cur.execute("SELECT COUNT(*) FROM users;")
            user_count = cur.fetchone()[0]
            if user_count == 0:
                default_admin_hash = hash_password("Admin@12345")
                cur.execute("""
                    INSERT INTO users (username, password_hash, role, can_upload, employee_name, employee_id, must_change_password)
                    VALUES ('admin', %s, 'admin', TRUE, 'System Administrator', 'CCL-ADM-01', TRUE);
                """, (default_admin_hash,))
                logger.info("Default administrator account 'admin' created.")

            # Performance Optimization: Lower autovacuum scale factors to prevent tuple bloat
            autovacuum_tuning = [
                "ALTER TABLE codes SET (autovacuum_vacuum_scale_factor = 0.05, autovacuum_analyze_scale_factor = 0.02);",
                "ALTER TABLE scan_logs SET (autovacuum_vacuum_scale_factor = 0.05, autovacuum_analyze_scale_factor = 0.02);",
                "ALTER TABLE job_cards SET (autovacuum_vacuum_scale_factor = 0.05, autovacuum_analyze_scale_factor = 0.02);"
            ]
            for tune_sql in autovacuum_tuning:
                try:
                    cur.execute(tune_sql)
                except Exception:
                    pass  # Non-blocking if running under restricted database permissions

            conn.commit()
            logger.info("Database schema initialized and performance tuning applied.")
    finally:
        release_connection(conn)
