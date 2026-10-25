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

Job creation uses one action: select the CSV and click **Create Job**. The application first checks for repeated codes within the file; if found, it blocks creation, shows repeated-code details, and offers a downloadable duplicate report. Correct the file and click **Create Job** again. If the file is internally unique, the application checks the Job Card number and continues with the existing cross-job conflict checks. The server independently repeats the within-file duplicate check before accepting a job, so the client-side check cannot be bypassed.

Final QC mode is determined by production scan history for the selected Job Card, not by which job is currently loaded on the main screen. A Job Card with production scans uses Packing Check mode; without production scans it uses Pre-check mode. Successful Pre-checks are verification-only: they are not persisted in production scan history or Packing QC logs, and the Packing QC table is hidden in Pre-check mode. Packing-stage checks are recorded separately; after at least one successful check, any signed-in operator can explicitly mark Packing QC complete. The certificate is only available after that completion action and records who completed it and when. Production scan history is not displayed in the Final QC terminal.

The camera scanner supports barcode/QR scanning and an OCR mode for printed text. OCR uses a short single-line guide and reads only the framed area; align one code line inside it. OCR results are placed in the code field for operator review and correction; they are not submitted automatically. OCR requires a network connection the first time it loads its text-recognition engine and may misread characters, so verify the result before submitting.

On a desktop, select an active Job Card and choose **Use phone scanner** to pair a phone using the displayed QR code. The pairing screen hides automatically after the phone connects. The phone scanner supports barcode/QR scanning and printed-text OCR; OCR results can be corrected on the phone before sending them to the desktop for verification against the selected Job Card. Closing the desktop pairing screen only hides the QR code; end the session from either the desktop or the phone. Camera access on the phone requires the application to be served over HTTPS. Pairing links expire after eight hours.

The upload limit applies while the application copies the uploaded file to its temporary working directory. Background ingestion still runs in a process-local thread and uses local temporary files; use durable storage and a persistent worker queue before relying on ingestion to survive instance restarts or multiple application instances.

The Job Control Center loads jobs in pages of 50 and searches across the selected status filter on the server. QC reports load the latest 50 scan records when opened; use **Load older scans** to retrieve additional history. CSV exports continue to include the full report data.

Job lists and QC report summaries use the counts stored on each job; successful ingestion and production verification update those counts. Managers and administrators can check stored counts against the code records with `GET /api/admin/jobs/count-reconciliation`. This explicit reconciliation can scan the full code table and returns up to 100 mismatched jobs; it does not modify data. Resolve any reported drift deliberately rather than adding full-table counting to normal requests.
