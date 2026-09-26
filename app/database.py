import os
import psycopg2
from psycopg2.pool import SimpleConnectionPool

DATABASE_URL = os.environ.get("DATABASE_URL")

if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

pool = SimpleConnectionPool(minconn=1, maxconn=20, dsn=DATABASE_URL)

def get_connection():
    return pool.getconn()

def release_connection(conn):
    pool.putconn(conn)

def init_db():
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            # 1. Drop existing primary key and foreign key constraints to allow type conversion
            cur.execute("""
                DO $$
                BEGIN
                    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'codes') THEN
                        ALTER TABLE codes DROP CONSTRAINT IF EXISTS codes_pkey CASCADE;
                        ALTER TABLE codes DROP CONSTRAINT IF EXISTS codes_job_card_id_fkey CASCADE;
                    END IF;
                    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'job_cards') THEN
                        ALTER TABLE job_cards DROP CONSTRAINT IF EXISTS job_cards_pkey CASCADE;
                    END IF;
                END $$;
            """)

            # 2. Create tables if they do not exist
            cur.execute("""
                CREATE TABLE IF NOT EXISTS job_cards (
                    job_card_id TEXT PRIMARY KEY,
                    client_name TEXT,
                    status VARCHAR(20) DEFAULT 'ACTIVE',
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS codes (
                    job_card_id TEXT REFERENCES job_cards(job_card_id),
                    code_value TEXT NOT NULL,
                    short_code TEXT NOT NULL,
                    status VARCHAR(20) DEFAULT 'PENDING',
                    scanned_at TIMESTAMP WITH TIME ZONE NULL
                );
            """)

            # 3. Force convert all columns to TEXT
            cur.execute("""
                ALTER TABLE job_cards ALTER COLUMN job_card_id TYPE TEXT;
                ALTER TABLE codes ALTER COLUMN job_card_id TYPE TEXT;
                ALTER TABLE codes ALTER COLUMN code_value TYPE TEXT;
                ALTER TABLE codes ADD COLUMN IF NOT EXISTS short_code TEXT;

                -- Re-add constraints
                DO $$
                BEGIN
                    IF NOT EXISTS (
                        SELECT 1 FROM pg_constraint WHERE conname = 'job_cards_pkey'
                    ) THEN
                        ALTER TABLE job_cards ADD PRIMARY KEY (job_card_id);
                    END IF;

                    IF NOT EXISTS (
                        SELECT 1 FROM pg_constraint WHERE conname = 'codes_pkey'
                    ) THEN
                        ALTER TABLE codes ADD PRIMARY KEY (job_card_id, code_value);
                    END IF;

                    IF NOT EXISTS (
                        SELECT 1 FROM pg_constraint WHERE conname = 'codes_job_card_id_fkey'
                    ) THEN
                        ALTER TABLE codes ADD CONSTRAINT codes_job_card_id_fkey 
                        FOREIGN KEY (job_card_id) REFERENCES job_cards(job_card_id) ON DELETE CASCADE;
                    END IF;
                END $$;

                CREATE INDEX IF NOT EXISTS idx_codes_value ON codes (code_value);
                CREATE INDEX IF NOT EXISTS idx_codes_short ON codes (short_code);
                CREATE INDEX IF NOT EXISTS idx_codes_status ON codes (status);
            """)
            conn.commit()
    except Exception as e:
        conn.rollback()
        print(f"Database migration note: {e}")
    finally:
        release_connection(conn)
