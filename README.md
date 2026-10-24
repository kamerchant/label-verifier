# Label Verifier

## Initial administrator

The application does not create an administrator with a built-in password. After configuring `DATABASE_URL`, run `python seed_admin.py` in an environment that can connect to the database. The script prompts for an administrator username and password without echoing the password.

## Runtime configuration

| Variable | Requirement | Default |
| --- | --- | --- |
| `DATABASE_URL` | Required database connection string | None |
| `SESSION_SECRET` | Required signing secret of at least 32 characters | None |
| `SESSION_COOKIE_SECURE` | Keep enabled when serving over HTTPS | `true` |
| `MAX_UPLOAD_BYTES` | Maximum accepted CSV upload size | `262144000` (250 MiB) |

The Render Blueprint generates `SESSION_SECRET` and enables secure session cookies. For local development over plain HTTP, set `SESSION_COOKIE_SECURE=false`; do not disable secure cookies on a public HTTPS deployment.

The upload limit applies while the application copies the uploaded file to its temporary working directory. Background ingestion still runs in a process-local thread and uses local temporary files; use durable storage and a persistent worker queue before relying on ingestion to survive instance restarts or multiple application instances.
