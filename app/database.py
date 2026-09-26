import os
import psycopg2
from psycopg2.pool import SimpleConnectionPool
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

DATABASE_URL = os.environ.get("DATABASE_URL")

# Render supplies Postgres URLs prefixed with postgres://; psycopg2 requires postgresql://
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# Connection pool setup (1 to 20 concurrent connections)
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
            # 1. Users Table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    password_hash TEXT NOT NULL,
                    role VARCHAR(50) DEFAULT 'QC Incharge',
                    must_change_password BOOLEAN DEFAULT TRUE,
                    can_upload BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                );

                -- In-place column migrations
                ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN DEFAULT TRUE;
                ALTER TABLE users ADD COLUMN IF NOT EXISTS can_upload BOOLEAN DEFAULT FALSE;
                UPDATE users SET role = 'QC Incharge' WHERE role = 'operator';
                UPDATE users SET can_upload = TRUE WHERE role = 'admin';
            """)

            # 2. Job Cards Table with Soft-Delete Columns
            cur.execute("""
                CREATE TABLE IF NOT EXISTS job_cards (
                    run_id BIGSERIAL PRIMARY KEY,
                    job_card_id TEXT NOT NULL,
                    description TEXT,
                    client_name TEXT,
                    status VARCHAR(20) DEFAULT 'ACTIVE',
                    deletion_reason TEXT NULL,
                    deleted_by TEXT NULL,
                    deleted_at TIMESTAMP WITH TIME ZONE NULL,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                );

                -- In-place column migrations
                ALTER TABLE job_cards ADD COLUMN IF NOT EXISTS run_id BIGSERIAL;
                ALTER TABLE job_cards ADD COLUMN IF NOT EXISTS description TEXT;
                ALTER TABLE job_cards ADD COLUMN IF NOT EXISTS deletion_reason TEXT;
                ALTER TABLE job_cards ADD COLUMN IF NOT EXISTS deleted_by TEXT;
                ALTER TABLE job_cards ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMP WITH TIME ZONE;
            """)

            # 3. Partial Unique Index: Unique job_card_id only among non-deleted runs
            cur.execute("""
                DO $$
                BEGIN
                    -- Remove legacy constraints on job_card_id if converting an earlier schema
                    IF EXISTS (
                        SELECT 1 FROM information_schema.table_constraints 
                        WHERE table_name='job_cards' AND constraint_type='PRIMARY KEY' 
                        AND constraint_name='job_cards_pkey'
                    ) THEN
                        ALTER TABLE job_cards DROP CONSTRAINT job_cards_pkey CASCADE;
                        ALTER TABLE job_cards ADD PRIMARY KEY (run_id);
                    END IF;
                END $$;

                CREATE UNIQUE INDEX IF NOT EXISTS idx_unique_active_job_card 
                ON job_cards (job_card_id) 
                WHERE status != 'DELETED';
            """)

            # 4. Codes Table (Fast indexed lookups across large sets)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS codes (
                    id BIGSERIAL PRIMARY KEY,
                    job_card_id TEXT NOT NULL,
                    code_value TEXT NOT NULL,
                    status VARCHAR(20) DEFAULT 'PENDING',
                    scanned_at TIMESTAMP WITH TIME ZONE NULL
                );

                CREATE INDEX IF NOT EXISTS idx_codes_value ON codes (code_value);
                CREATE INDEX IF NOT EXISTS idx_codes_status ON codes (status);
                CREATE INDEX IF NOT EXISTS idx_codes_jc ON codes (job_card_id);
            """)

            # 5. Barcode Scan Logs Table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS scan_logs (
                    id BIGSERIAL PRIMARY KEY,
                    job_card_id TEXT NOT NULL,
                    code_scanned TEXT NOT NULL,
                    result VARCHAR(20) NOT NULL,
                    scanned_by TEXT NOT NULL,
                    scanned_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                );

                CREATE INDEX IF NOT EXISTS idx_scan_logs_jc ON scan_logs (job_card_id);
                CREATE INDEX IF NOT EXISTS idx_scan_logs_time ON scan_logs (scanned_at DESC);
            """)

            # 6. Job Lifecycle Audit Logs Table (Created, Completed, Reactivated, Deleted with Reasons)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS job_lifecycle_logs (
                    id BIGSERIAL PRIMARY KEY,
                    job_card_id TEXT NOT NULL,
                    action VARCHAR(50) NOT NULL,
                    performed_by TEXT NOT NULL,
                    reason TEXT NULL,
                    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                );

                ALTER TABLE job_lifecycle_logs ADD COLUMN IF NOT EXISTS reason TEXT;
                CREATE INDEX IF NOT EXISTS idx_lifecycle_jc ON job_lifecycle_logs (job_card_id);
                CREATE INDEX IF NOT EXISTS idx_lifecycle_time ON job_lifecycle_logs (timestamp DESC);
            """)

            # 7. Seed Default Admin if Database is Fresh
            cur.execute("SELECT COUNT(*) FROM users;")
            if cur.fetchone()[0] == 0:
                admin_hash = hash_password("admin123")
                cur.execute("""
                    INSERT INTO users (username, password_hash, role, must_change_password, can_upload) 
                    VALUES (%s, %s, %s, %s, %s)
                """, ("admin", admin_hash, "admin", True, True))

            conn.commit()
    except Exception as e:
        conn.rollback()
        print(f"Database initialization warning: {e}")
    finally:
        release_connection(conn)
