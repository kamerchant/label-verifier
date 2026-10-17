"""
CCL Middle East - Pakistan | Variable Data Verification System (VDV)
Database Connection Pool, Schema Migrations & Cryptography
"""

import os
import hashlib
import logging
from passlib.context import CryptContext
import psycopg2
from psycopg2 import pool, extras, extensions

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
    """Verifies plaintext against bcrypt or legacy SHA-256 hex hashes without throwing exceptions."""
    if not hashed_password or not plain_password:
        return False
    
    # 1. Backward-compatible fallback for 64-character SHA-256 hex strings
    if len(hashed_password) == 64 and all(c in "0123456789abcdefABCDEF" for c in hashed_password):
        sha256_attempt = hashlib.sha256(plain_password.encode("utf-8")).hexdigest().lower()
        if sha256_attempt == hashed_password.lower():
            return True

    # 2. Bcrypt verification
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception:
        return False

# Threaded connection pool
connection_pool = None

def init_connection_pool():
    global connection_pool
    if connection_pool is None or connection_pool.closed:
        try:
            connection_pool = pool.ThreadedConnectionPool(
                minconn=2,
                maxconn=25,
                dsn=DATABASE_URL,
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
    """Guarantees connection is returned to the pool even if rollbacks fail."""
    global connection_pool
    if connection_pool and not connection_pool.closed and conn:
        try:
            if not conn.closed:
                # 0 corresponds to TRANSACTION_STATUS_IDLE
                if conn.get_transaction_status() != 0:
                    conn.rollback()
        except Exception:
            pass
        finally:
            try:
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
    schema_sql = [
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

            cur.execute("SELECT COUNT(*) FROM users;")
            user_count = cur.fetchone()[0]
            if user_count == 0:
                default_admin_hash = hash_password("Admin@12345")
                cur.execute("""
                    INSERT INTO users (username, password_hash, role, can_upload, employee_name, employee_id, must_change_password)
                    VALUES ('admin', %s, 'admin', TRUE, 'System Administrator', 'CCL-ADM-01', TRUE);
                """, (default_admin_hash,))
                logger.info("Default administrator account 'admin' created.")

            conn.commit()

            # Autovacuum tuning
            for tune_sql in [
                "ALTER TABLE codes SET (autovacuum_vacuum_scale_factor = 0.05, autovacuum_analyze_scale_factor = 0.02);",
                "ALTER TABLE scan_logs SET (autovacuum_vacuum_scale_factor = 0.05, autovacuum_analyze_scale_factor = 0.02);",
                "ALTER TABLE job_cards SET (autovacuum_vacuum_scale_factor = 0.05, autovacuum_analyze_scale_factor = 0.02);"
            ]:
                try:
                    cur.execute(tune_sql)
                    conn.commit()
                except Exception:
                    conn.rollback()

            logger.info("Database schema initialized and verified.")
    finally:
        release_connection(conn)
