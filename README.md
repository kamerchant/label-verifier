# Label Verifier

## Documentation

- [User manual](docs/user-manual.md) ([PDF](docs/Label-Verifier-User-Manual.pdf)) – screenshots and step-by-step usage for every role.
- [Process flow diagrams](docs/process-flow.md) ([PDF](docs/Label-Verifier-Process-Flow.pdf)) – architecture, job ingestion, scan verification, phone pairing, status life cycle, security and backups.

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

## Test locally on macOS and deploy to a Linux VM

The app and PostgreSQL can run together with Docker Compose. This is a practical way to test on a Mac before moving the same Compose configuration to an Ubuntu VM. Install Docker Desktop, then from the repository root:

```sh
cp .env.example .env
```

Generate two different secrets with `openssl rand -hex 32` and put one in `POSTGRES_PASSWORD` and the other in `SESSION_SECRET` in `.env`. Leave `APP_BIND_ADDRESS=127.0.0.1` and `SESSION_COOKIE_SECURE=false` for local HTTP testing. Do not commit `.env`.

Start the app and database, then create the initial administrator:

```sh
docker compose up --build -d
docker compose exec app python seed_admin.py
```

Open [http://localhost:8000](http://localhost:8000). Check startup output with `docker compose logs -f app`. PostgreSQL data is kept in the `postgres_data` named volume when containers are stopped or recreated; `docker compose down` does not remove it.

For the eventual Windows Server 2016 host, run the Linux containers in an Ubuntu VM (for example, under Hyper-V), not directly as Windows containers. Install Docker Engine and the Compose plugin in the VM, copy the application and `.env` there, and run the same Compose project. Configure HTTPS with your organization's internal certificate/reverse proxy, set `SESSION_COOKIE_SECURE=true`, and restrict the VM/network firewall to the intended internal clients. Do not expose port 8000 over the LAN as plain HTTP. Set `APP_BIND_ADDRESS` to the VM's private address only if the proxy must connect over the VM network; otherwise keep it bound to loopback and run the proxy in the VM.

Treat the Mac setup as test data, not a backup. To retain data when moving to the VM, migrate PostgreSQL using `pg_dump` and restore it on the VM; create fresh secrets there rather than reusing the Mac `.env`. The app currently uses process-local background threads and temporary files, so keep it to one app instance.

## Deploy to Azure App Service (Linux container)

The Azure deployment provisions a Linux App Service, an Azure Container Registry, and a private Azure Database for PostgreSQL Flexible Server. The database is reachable only through the app's VNet integration. App Service pulls the image from ACR using its managed identity; the registry does not need an admin password. The deployment uses one App Service instance because background ingestion currently uses process-local threads and temporary files.

Requirements: an Azure subscription with permission to create resource groups and role assignments, Azure CLI, and Python 3. From the repository root, sign in and deploy:

```sh
az login
bash scripts/deploy-azure.sh <resource-group> <azure-region>
```

For example, use a unique resource-group name and a supported region such as `germanywestcentral`. The script provisions the resources, builds the Docker image in Azure, pushes it to ACR, and restarts the app. It generates the PostgreSQL administrator password and session secret locally and passes them as secure deployment parameters; neither value is printed. Review Azure pricing before deploying: the App Service plan, registry, and PostgreSQL server are billable resources.

Create the initial application administrator by running `seed_admin.py` from a host that can reach the private PostgreSQL server over the VNet. The app container does not include an SSH server, so App Service's SSH console is not enabled by this deployment. Retrieve the app's `DATABASE_URL` through an authorized Azure configuration workflow, provide it to the VNet-connected host as an environment variable, and run:

```sh
export DATABASE_URL='postgresql://...'
python seed_admin.py
```

The script prompts for the administrator username and password. Do not commit the connection string or enable public database access to seed the user.

Subsequent code deployments can be made from the repository root with:

```sh
az acr build --registry <registry-name> --image label-verifier:latest .
az webapp restart --resource-group <resource-group> --name <app-service-name>
```

The app's upload limit is 250 MiB. App Service and any upstream proxy must permit requests of that size. The database and app are deployed in the selected region; check regional availability and cost for the PostgreSQL Burstable B1ms SKU before running the provisioning script.

Database timestamps are stored in UTC. Use the `TZ` control in the application footer to choose the display time zone; that preference is saved in the current browser.

Job creation uses one action: select the CSV and click **Create Job**. The application first checks for repeated codes within the file; if found, it blocks creation, shows repeated-code details, and offers a downloadable duplicate report. Correct the file and click **Create Job** again. If the file is internally unique, the application checks the Job Card number and continues with the existing cross-job conflict checks. The server independently repeats the within-file duplicate check before accepting a job, so the client-side check cannot be bypassed.

Final QC mode is determined by production scan history for the selected Job Card, not by which job is currently loaded on the main screen. A Job Card with production scans uses Packing Check mode; without production scans it uses Pre-check mode. Successful Pre-checks are verification-only: they are not persisted in production scan history or Packing QC logs, and the Packing QC table is hidden in Pre-check mode. Packing-stage checks are recorded separately; after at least one successful check, any signed-in operator can explicitly mark Packing QC complete. The certificate is only available after that completion action and records who completed it and when. Production scan history is not displayed in the Final QC terminal.

The camera scanner supports barcode/QR scanning and an OCR mode for printed text. OCR uses a short single-line guide and reads only the framed area; align one code line inside it. OCR results are placed in the code field for operator review and correction; they are not submitted automatically. OCR requires a network connection the first time it loads its text-recognition engine and may misread characters, so verify the result before submitting.

On a desktop, select an active Job Card or validate a Job Card in the Final QC terminal and choose **Use phone scanner** to pair a phone using the displayed QR code. The pairing screen hides automatically after the phone connects. The phone scanner supports barcode/QR scanning and printed-text OCR; OCR results can be corrected on the phone before sending them to the desktop for verification in the selected terminal. Closing the desktop pairing screen only hides the QR code; end the session from either the desktop or the phone. Camera access on the phone requires the application to be served over HTTPS. Pairing links expire after eight hours.

The upload limit applies while the application copies the uploaded file to its temporary working directory. Background ingestion still runs in a process-local thread and uses local temporary files; use durable storage and a persistent worker queue before relying on ingestion to survive instance restarts or multiple application instances.

The Job Control Center loads jobs in pages of 50 and searches across the selected status filter on the server. QC reports load the latest 50 scan records when opened; use **Load older scans** to retrieve additional history. CSV exports continue to include the full report data.

Job lists and QC report summaries use the counts stored on each job; successful ingestion and production verification update those counts. Managers and administrators can check stored counts against the code records with `GET /api/admin/jobs/count-reconciliation`. This explicit reconciliation can scan the full code table and returns up to 100 mismatched jobs; it does not modify data. Resolve any reported drift deliberately rather than adding full-table counting to normal requests.
