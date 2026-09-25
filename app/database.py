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
            cur.execute("""
                CREATE TABLE IF NOT EXISTS job_cards (
                    job_card_id VARCHAR(50) PRIMARY KEY,
                    client_name VARCHAR(100),
                    status VARCHAR(20) DEFAULT 'ACTIVE',
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS codes (
                    job_card_id VARCHAR(50) REFERENCES job_cards(job_card_id),
                    code_value VARCHAR(128) NOT NULL,
                    status VARCHAR(20) DEFAULT 'PENDING',
                    scanned_at TIMESTAMP WITH TIME ZONE NULL,
                    PRIMARY KEY (job_card_id, code_value)
                );

                CREATE INDEX IF NOT EXISTS idx_codes_value ON codes (code_value);
                CREATE INDEX IF NOT EXISTS idx_codes_status ON codes (status);
            """)
            conn.commit()
    finally:
        release_connection(conn)
