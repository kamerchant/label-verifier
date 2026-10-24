import getpass

from app.database import get_connection, hash_password, init_db, release_connection


def seed_admin(username: str, password: str) -> int:
    username = username.strip()
    if not username:
        raise ValueError("Username cannot be empty.")
    if (
        len(password) < 12
        or len(password.encode("utf-8")) > 72
        or not any(c.isupper() for c in password)
        or not any(c.islower() for c in password)
        or not any(c.isdigit() for c in password)
    ):
        raise ValueError(
            "Password must be 12-72 UTF-8 bytes and include uppercase, lowercase, and numeric characters."
        )

    init_db()
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id FROM users WHERE LOWER(username) = LOWER(%s)",
                (username,),
            )
            existing = cur.fetchone()
            if existing:
                raise ValueError(f"User '{username}' already exists.")

            cur.execute(
                """
                INSERT INTO users (
                    username, password_hash, role, can_upload,
                    employee_name, employee_id, is_active, must_change_password
                )
                VALUES (%s, %s, 'admin', TRUE, 'System Administrator',
                        'ADMIN-001', TRUE, FALSE)
                RETURNING id
                """,
                (username, hash_password(password)),
            )
            user_id = cur.fetchone()[0]
        conn.commit()
        return user_id
    except Exception:
        conn.rollback()
        raise
    finally:
        release_connection(conn)


if __name__ == "__main__":
    admin_username = input("Initial administrator username [admin]: ").strip() or "admin"
    admin_password = getpass.getpass("Initial administrator password: ")
    confirm_password = getpass.getpass("Confirm password: ")
    if admin_password != confirm_password:
        raise SystemExit("Passwords do not match.")

    try:
        admin_id = seed_admin(admin_username, admin_password)
    except ValueError as error:
        raise SystemExit(str(error)) from error
    print(f"Administrator '{admin_username}' created (ID: {admin_id}).")
