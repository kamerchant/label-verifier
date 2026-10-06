import os
import sys
from app.database import init_db, get_db_cursor, hash_password

def seed_admin(username: str = "admin", password: str = "Admin@2026"):
    # Ensure all tables and migration columns exist
    init_db()

    with get_db_cursor(commit=True) as cur:
        # Check if the admin account already exists
        cur.execute("SELECT id FROM users WHERE LOWER(username) = LOWER(%s);", (username,))
        existing = cur.fetchone()

        if existing:
            print(f"[!] User '{username}' already exists (ID: {existing['id']}). No action taken.")
            return

        pwd_hash = hash_password(password)

        cur.execute(
            """
            INSERT INTO users (
                username, password_hash, role, can_upload,
                employee_name, employee_id, is_active, must_change_password
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id;
            """,
            (
                username,
                pwd_hash,
                "admin",
                True,
                "System Administrator",
                "ADMIN-001",
                True,
                False,  # Set to True if you want to force a password change on first login
            ),
        )
        new_id = cur.fetchone()["id"]
        print(f"[✓] Admin account successfully seeded! Username: '{username}', ID: {new_id}")


if __name__ == "__main__":
    seed_admin()