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

Database timestamps are stored in UTC. Use the `TZ` control in the application footer to choose the display time zone; that preference is saved in the current browser.

Before creating a job, the upload screen previews the selected file and reports repeated code values. Job creation is blocked when any duplicate is found; download the duplicate CSV report, correct the source file, and preview it again. The server repeats the duplicate check before creating a job, so bypassing the preview does not allow a duplicate file to be ingested. Downloading the preview report reprocesses the selected file.

Final QC code checks are treated as pre-checks unless the same Job Card is loaded in the main workspace. Pre-checks are not recorded as packing QC. Packing-stage checks are recorded separately; after at least one successful check, any signed-in operator can explicitly mark Packing QC complete. The certificate is only available after that completion action and records who completed it and when.

The upload limit applies while the application copies the uploaded file to its temporary working directory. Background ingestion still runs in a process-local thread and uses local temporary files; use durable storage and a persistent worker queue before relying on ingestion to survive instance restarts or multiple application instances.
