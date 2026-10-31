# Label Verifier – System Process Flows

The diagrams below use [Mermaid](https://mermaid.js.org/). They render automatically on GitHub and in VS Code (Markdown Preview Mermaid Support extension). Pre-rendered PDF: [Label-Verifier-Process-Flow.pdf](./Label-Verifier-Process-Flow.pdf).

## 1. System architecture

```mermaid
flowchart LR
    subgraph Office["Office network (internal only)"]
        PC["Desktop browser<br/>(QC officer / manager / admin)"]
        PH["Phone browser<br/>(camera scanner)"]
        subgraph Host["Ubuntu VM / Server (Docker Compose)"]
            PX["proxy<br/>Caddy · HTTPS :443"]
            APP["app<br/>FastAPI · Python (non-root)"]
            DB[("db<br/>PostgreSQL 16<br/>volume: postgres_data")]
        end
        BK[["backups/ folder<br/>nightly pg_dump + sha256"]]
        BE["Automated backup engine"]
    end
    PC -- "HTTPS" --> PX
    PH -- "HTTPS (camera needs secure context)" --> PX
    PX -- "HTTP, X-Forwarded-For" --> APP
    APP -- "SQL (bounded pool)" --> DB
    DB -. "scripts/backup-db.sh" .-> BK
    BK -. "picked up by" .-> BE
```

## 2. End-to-end production workflow

```mermaid
flowchart TD
    A([Start]) --> B["Admin creates the user accounts<br/>Users sign in – first login forces a new password"]
    B --> D{"Can the user<br/>create jobs?"}
    D -- "Yes: admin, QC manager,<br/>or officer with permission" --> E["Create Job:<br/>Job Card # + description + CSV/TXT code file"]
    D -- "No" --> G
    E --> F{"Upload checks pass?<br/>see diagram 3"}
    F -- "No: fix the file" --> E
    F -- "Yes" --> G["Job becomes ACTIVE<br/>code pool loaded"]
    G --> H["Operator selects the Job Card<br/>and scans codes<br/>keyboard scanner or phone"]
    H --> I{"Result"}
    I -- "PASS" --> K
    I -- "Duplicate / Unknown /<br/>Restart warning" --> J["Operator investigates<br/>and re-checks the label"]
    J --> K{"All codes verified<br/>or run finished?"}
    K -- "No: keep scanning" --> H
    K -- "Yes" --> L["Mark job Completed<br/>Final QC packing checks<br/>Print certificate / QC Report / CSV"]
    L --> O([End – full history kept in the Audit Trail])
```

## 3. Job creation and code ingestion

```mermaid
flowchart TD
    S([Create Job]) --> U["Select CSV/TXT file<br/>enter Job Card #"]
    U --> P["POST /api/jobs/preview<br/>count values · find repeats"]
    P --> D1{"Repeated codes<br/>inside the file?"}
    D1 -- "Yes" --> R1["Blocked: show repeated rows<br/>+ Download Duplicate Report"]
    R1 --> FIX["Correct the source file"] --> U
    D1 -- "No" --> C1["POST /api/jobs/create<br/>file saved, status INGESTING"]
    C1 --> BG["Background thread loads codes<br/>with row numbers into PostgreSQL"]
    BG --> D2{"Codes already used<br/>by another job?"}
    D2 -- "No" --> ACT["Status ACTIVE<br/>lifecycle log: Created and Ingested"]
    D2 -- "Yes" --> CF["Status CONFLICT_DETECTED<br/>conflict report shown"]
    CF --> D3{"Uploader decision"}
    D3 -- "Cancel upload" --> CAN["Upload cancelled, nothing loaded"]
    D3 -- "Proceed with a written reason<br/>(optionally skip conflicting codes)" --> OV["Status OVERRIDING → ACTIVE<br/>reason recorded in the audit trail"]
    OV --> ACT
    BG -. "error or restart" .-> FL["Status FAILED<br/>can be cancelled or purged"]
```

## 4. Scan verification logic (per code)

```mermaid
flowchart TD
    S([Code scanned or typed]) --> J{"Job status<br/>ACTIVE?"}
    J -- "No" --> BL["BLOCKED<br/>scanning disabled"]
    J -- "Yes" --> E{"Code exists<br/>in this job's pool?"}
    E -- "No" --> UN["UNKNOWN<br/>Code Does Not Exist"]
    E -- "Yes" --> C{"Already<br/>verified?"}
    C -- "Yes, and row is lower than the highest verified row" --> DR["Duplicate (Potential Restart)"]
    C -- "Yes" --> DU["DUPLICATE"]
    C -- "No" --> Q{"Row lower than the<br/>highest verified row?"}
    Q -- "Yes" --> PR["Pass (Potential Restart)<br/>recorded, warning shown"]
    Q -- "No" --> PS["PASS<br/>code CONSUMED, counter + 1"]
    BL --> LOG
    UN --> LOG
    DR --> LOG
    DU --> LOG
    PR --> LOG
    PS --> LOG["Written to scan_logs and the audit trail<br/>(operator, time, result)"]
    LOG --> UI["Result banner + Verification Stream row"]
```

## 5. Phone scanner pairing and session lifecycle

```mermaid
sequenceDiagram
    autonumber
    actor Op as Operator (desktop)
    participant D as Desktop page
    participant S as Server
    participant P as Phone page
    Op->>D: Select active job, click "Use phone to scan"
    D->>S: POST /api/phone-scanner/sessions
    S-->>D: session id + one-time token (valid 8 h)
    D-->>Op: QR code + link (built from the HTTPS address in use)
    Op->>P: Scan QR with phone camera
    P->>S: POST /connect (token)
    S-->>P: connected, job card
    loop every 2 s
        P->>S: POST /heartbeat (token)
    end
    loop every ~0.25-0.7 s
        D->>S: GET /sessions/{id}/scans
        S-->>D: new scans + "connected" flag
    end
    P->>S: POST /scan (code)
    S-->>D: delivered on next poll → verified on desktop
    alt Operator taps "End phone session"
        P->>S: POST /disconnect
    else Page closed or navigated away
        P->>S: sendBeacon /disconnect (pagehide)
    else Phone lost / browser killed
        Note over S: No heartbeat for 30 s → session revoked on next desktop poll
    end
    S-->>D: 410 session ended
    D-->>Op: "Use phone to scan" button returns
```

## 6. Job status life cycle

```mermaid
stateDiagram-v2
    [*] --> INGESTING: Create job
    INGESTING --> ACTIVE: codes loaded, no conflicts
    INGESTING --> CONFLICT_DETECTED: codes used by another job
    INGESTING --> FAILED: error / app restart
    CONFLICT_DETECTED --> OVERRIDING: proceed with reason
    CONFLICT_DETECTED --> [*]: cancel upload
    OVERRIDING --> ACTIVE
    OVERRIDING --> FAILED
    ACTIVE --> INACTIVE: Job Control Center (manager/admin + password)
    INACTIVE --> ACTIVE: Job Control Center
    ACTIVE --> COMPLETED: "Job Completed" button
    COMPLETED --> ACTIVE: Job Control Center
    INACTIVE --> COMPLETED: Job Control Center
    ACTIVE --> DELETED: purge (manager/admin + password)
    INACTIVE --> DELETED: purge
    COMPLETED --> DELETED: purge
    FAILED --> DELETED: purge
```

## 7. User access and security flow

```mermaid
flowchart TD
    L([Open the app via HTTPS]) --> LG["Sign in"]
    LG --> RL{"Rate limit OK?<br/>5 / 5 min per IP · 10 / 15 min per user"}
    RL -- "No" --> BLK["429 Too Many Requests<br/>+ Retry-After"]
    RL -- "Yes" --> PW{"Password correct<br/>and account active?"}
    PW -- "No" --> ERR["Login failed (audited)"]
    PW -- "Yes" --> MC{"Must change password?"}
    MC -- "Yes" --> CP["Forced password change"] --> HOME
    MC -- "No" --> HOME["Signed-in session<br/>(secure cookie, 7 days)"]
    HOME --> RB{"Role"}
    RB -- "QC officer" --> O1["Scan · reports · Final QC<br/>(create jobs only if allowed)"]
    RB -- "QC manager" --> O2["Officer rights + create jobs<br/>+ Job Control Center (status changes, purge)<br/>+ global audit trail"]
    RB -- "Administrator" --> O3["Manager rights<br/>+ Manage Users (create, roles, reset, suspend)"]
```

## 8. Backup and restore flow

```mermaid
flowchart LR
    CRON["cron / scheduler<br/>nightly"] --> BS["scripts/backup-db.sh"]
    BS --> DUMP["pg_dump -Fc inside db container"]
    DUMP --> VER["Verify archive<br/>write sha256 file"]
    VER --> DIR[["BACKUP_DIR<br/>(folder watched by backup engine)"]]
    DIR --> RET["Delete files older than<br/>BACKUP_RETENTION_DAYS (14)"]
    DIR --> OFF["Backup engine copies off-host"]
    DIR -. "disaster / migration" .-> RS["scripts/restore-backup.sh<br/>checksum check + confirmation"]
    RS --> NEW[("PostgreSQL restored")]
```
