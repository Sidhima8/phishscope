# PhishScope — Dynamic Phishing Investigation & Threat Intelligence Platform

PhishScope is a dynamic, analyst-focused cybersecurity web application engineered for SOC analysts, incident responders, email security teams, and threat intelligence units.

Unlike static prototypes or mock dashboards, PhishScope implements genuine, full-lifecycle forensic analysis. Every submitted email is parsed at runtime, evaluated against multi-layer detection engines, correlated with live threat intelligence feeds, scored using explainable weighted logic, and packaged into downloadable forensic reports.

---

## Key Capabilities & Core Modules

### 1. Email Ingestion & Chain of Custody (Module A)
- **Multi-modal Ingestion:** Supports `.eml` file uploads (single or multi-file batches) and direct raw RFC 822 header/body pasting.
- **Evidence Integrity:** Automatically hashes the raw byte stream using **SHA-256** upon ingestion, ensuring tamper-evident forensic custody.
- **Robust MIME Parsing:** Recursively maps nested multipart trees (`multipart/alternative`, `multipart/mixed`, `multipart/related`) and decodes character encodings safely.
- **Fail-safe Operation:** Designed to parse malformed messages and missing headers without unhandled crashes.

### 2. Header & Authentication Forensics (Module B)
- **SPF Analysis:** Cross-references recorded `Received-SPF` and `Authentication-Results` headers with authoritative DNS TXT records.
- **DKIM Validation:** Identifies selectors, extracts cryptographic signatures, and queries DNS public keys at `selector._domainkey.domain`.
- **DMARC Enforcement & Alignment:** Evaluates domain policies (`none`, `quarantine`, `reject`) and inspects both SPF and DKIM alignment against the From domain.
- **Relay Hop Visualization:** Reconstructs the chronological delivery path, flagging unexpected RFC 1918 private IPs or anomalous routing hops.
- **Deception Detection:**
  * **Display Name Spoofing:** Detects when display names masquerade as trusted brands (Microsoft, Google, PayPal, DocuSign, etc.) using unrelated domains.
  * **Reply-To & Return-Path Mismatches:** Unmasks routing diversions typical of Business Email Compromise (BEC).
  * **Typo-Squatting Engine:** Analyzes sender domains using Levenshtein distance, tokenization, and Cyrillic/Greek homoglyphs.

### 3. URL & Domain Deep-Dive with Strict SSRF Defense (Module C)
- **Defanged Display:** Converts active links into safe observables (e.g. `hxxps[://]evil[.]com/login`).
- **Heuristic Indicators:** Detects raw IP destinations, URL shortening services (`bit.ly`, `tinyurl`), high-risk TLDs, and excessive subdomain nesting.
- **Anchor Text Mismatch Engine:** Flags deceptive hyperlinks where visible link text differs from the actual underlying destination URL.
- **Safe Redirect Expander:**
  * Strict Server-Side Request Forgery (SSRF) protection.
  * Blocks RFC 1918 private subnets, loopback (`127.0.0.1`), link-local / cloud metadata endpoints (`169.254.169.254`), and non-routable CIDRs.
  * Limits traversal to 5 hops with tight HTTP timeouts.

### 4. Threat Intelligence Integrations (Module D)
- **URLhaus (abuse.ch):** Live queries against open community feeds for confirmed malware and phishing links.
- **VirusTotal v3:** Configurable multi-engine antivirus telemetry for URLs, domains, and payload hashes.
- **RDAP / WHOIS:** Automatically queries ICANN RDAP endpoints to evaluate domain age and flag newly registered domains (&lt; 30 days old).
- **DNS Resolver:** Queries authoritative MX, A, and TXT records via `dnspython`.
- **Honest Telemetry:** Displays `Not Configured`, `Clean`, `Malicious`, or `Error` states truthfully without hardcoded or fabricated scores.

### 5. Content Analysis & Heuristic Engine (Module E)
- **Urgency & Coercion:** Identifies manufactured deadlines, punitive threats, and account suspension warnings.
- **Credential Harvesting Patterns:** Detects unauthorized login challenges, credential verification prompts, and billing update requests.
- **Financial & BEC Fraud:** Uncovers wire transfer instructions, bank detail alterations, and gift card solicitations.
- **Attachment Forensics:** Calculates SHA-256 and MD5 hashes, identifies dangerous executables (`.exe`, `.scr`, `.hta`, `.vbs`, `.ps1`), flags macro-enabled documents (`.docm`, `.xlsm`), and detects double-extension concealment (`invoice.pdf.exe`).
- **MITRE ATT&CK Mapping:** Automatically correlates evidence with MITRE ATT&CK techniques (T1566.001, T1566.002, T1036, T1204).

### 6. Explainable Weighted Risk Engine (Module F)
- Calculates a bounded score from **0 to 100** based on observed evidence points.
- Categorizes risk into **Low (0–24)**, **Medium (25–49)**, **High (50–74)**, and **Critical (75–100)**.
- Implements category caps and dampens repetitive indicators to prevent single-dimension score skewing.
- Transparently itemizes every scored indicator with severity, observed evidence, explanation, confidence, points added, and recommended SOC investigation steps.

### 7. SOC Dashboard & Investigation Management (Module G & H)
- **Real-Time SOC Overview:** KPI metrics, risk distribution charts, triage status breakdowns, top attack domains, and recent activity feeds.
- **Case Ledger:** Searchable by Case ID, subject, sender, or SHA-256; filterable by status and risk level.
- **Audit Logging & Case Notes:** Timestamped forensic notes and status changes.
- **Analyst Confirmation Safeguard:** Requires explicit confirmation and rationale before classifying a case as `CONFIRMED_MALICIOUS` or `BENIGN`.
- **Case Correlation & Comparison:** Select 2 or more cases to compute Jaccard IOC similarity and identify shared infrastructure across campaigns.
- **Safe Email Preview:** Offers both plain-text review and isolated HTML preview in a secure, sandboxed iframe.

### 8. Downloadable Forensic PDF & JSON Reports (Module I)
- **Forensic PDF:** Rendered on-demand via ReportLab with case metadata, evidence hash, authentication evaluation, indicators table, findings breakdown, analyst notes, and chain of custody disclaimer.
- **JSON Evidence Export:** Downloadable machine-readable JSON package containing all raw artefacts and findings.

---

## Architecture & Technology Stack

| Component | Technology | Rationale |
| :--- | :--- | :--- |
| **Backend Framework** | Python 3.10+ / FastAPI | High-concurrency async API with Pydantic validation |
| **Database** | SQLAlchemy 2.0 (Async) | Supports SQLite (aiosqlite) for local zero-config execution and PostgreSQL (asyncpg) for production |
| **Frontend** | React 18, TypeScript, Vite | Strongly typed, reactive analyst interface |
| **Styling & UI** | Tailwind CSS, Lucide React, Recharts | Dark SOC cyber theme with data visualizations |
| **Email Parsing** | Python `email` package | Native, RFC-compliant MIME & header parsing |
| **DNS Resolution** | `dnspython` | Direct query of authoritative MX, SPF, DKIM, and DMARC TXT records |
| **HTTP & Threat Feeds** | `httpx` with SSRF Guard | Asynchronous, security-hardened outbound HTTP client |
| **Forensic Reporting** | ReportLab | Programmatic generation of vector-quality PDF case briefs |
| **Authentication** | JWT (`python-jose`) & `passlib[bcrypt]` | Role-based access control (Admin, Analyst, Viewer) |

---

## Directory Structure

```
phishscope/
├── backend/
│   ├── app/
│   │   ├── api/v1/          # Modular API routes (auth, cases, ingest, notes, reports, indicators, dashboard)
│   │   ├── core/            # Configuration, JWT security, and SSRF guard
│   │   ├── db/              # SQLAlchemy session and schema initializer
│   │   ├── models/          # ORM models (Case, Finding, Indicator, Attachment, CaseNote, User)
│   │   ├── schemas/         # Pydantic request/response validation schemas
│   │   ├── services/        # Forensic engines (Parser, Auth, URL, Content, Intel, Risk, Report)
│   │   └── main.py          # FastAPI application entrypoint
│   ├── samples/             # Real-world labeled test email files (.eml)
│   ├── tests/               # Automated test suite (SSRF, Auth, URLs, Risk, PDF, Parser)
│   └── requirements.txt     # Python dependencies
├── frontend/
│   ├── src/
│   │   ├── components/      # Badges, modals, sidebar, navbar
│   │   ├── pages/           # Dashboard, Ingest, Cases, CaseDetail, IntelLookup, Compare, Settings
│   │   ├── services/        # API client
│   │   ├── types/           # TypeScript definitions
│   │   ├── App.tsx          # Root application and view manager
│   │   └── main.tsx         # React bootstrap
│   ├── package.json
│   ├── vite.config.ts
│   └── tailwind.config.js
├── Dockerfile               # Multi-stage production container build
├── docker-compose.yml       # Production stack (App + PostgreSQL + Redis)
├── .env.example             # Configuration template
└── README.md
```

---

## Quickstart & Execution Guide

### Option A: Local Development (Quickest Setup)

1. **Prerequisites:** Python 3.10+ and Node.js 18+.

2. **Configure Environment:**
   ```bash
   cp .env.example .env
   ```

3. **Install Backend Dependencies:**
   ```bash
   pip install -r backend/requirements.txt
   ```

4. **Run Automated Tests:**
   ```bash
   python -m pytest backend/tests/test_phishscope.py -v
   ```

5. **Start Backend Server:**
   ```bash
   cd backend
   uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
   ```

6. **Start Frontend Client:**
   In a second terminal:
   ```bash
   cd frontend
   npm install
   npm run dev
   ```
   Open your browser to: **http://localhost:5173**

---

### Option B: Standalone Full-Stack Mode (Single Port 8000)

Because the backend serves the compiled frontend assets directly from `frontend/dist`:

1. Build the frontend once:
   ```bash
   cd frontend
   npm run build
   cd ..
   ```
2. Start the backend:
   ```bash
   cd backend
   uvicorn app.main:app --host 127.0.0.1 --port 8000
   ```
3. Access the entire application at: **http://localhost:8000**

---

### Option C: Production Docker Stack

Run the full containerized stack including PostgreSQL and Redis:

```bash
docker compose up --build -d
```
Access the application at **http://localhost:8000**.

---

## Seed Accounts & RBAC

When initialized, the platform automatically provisions standard analyst credentials:

| Email | Password | Role | Permissions |
| :--- | :--- | :--- | :--- |
| `analyst@phishscope.local` | `AnalystPass123!` | `ANALYST` | Ingest emails, update cases, add notes, export forensic reports |
| `admin@phishscope.local` | `AdminPass123!` | `ADMIN` | Full administrative control, system config, user management |
| `viewer@phishscope.local` | `ViewerPass123!` | `VIEWER` | Read-only access to cases and reports |

---

## Demonstration Workflow

To verify dynamic runtime processing without manually searching for phishing samples:

1. Navigate to **New Investigation** (`/ingest`).
2. Click the **Demo Scenarios (One-Click)** tab.
3. Select any scenario:
   - **Microsoft 365 Credential Harvest:** Tests typo-squatted domain detection (`micros0ft-account-verify.com`), anchor text vs destination mismatch, display name spoofing, and SPF/DMARC failure. (Expected: **CRITICAL** risk).
   - **CEO Executive Wire Fraud (BEC):** Tests Reply-To mismatch routing, urgency detection, and financial disbursement heuristics. (Expected: **HIGH** risk).
   - **Overdue Invoice (Double Extension):** Tests detection of disguised executable attachments (`Invoice.pdf.exe`). (Expected: **CRITICAL** risk).
   - **Legitimate Tech Newsletter:** Tests valid SPF, DKIM, and DMARC alignment and clean link reputation. (Expected: **LOW** risk).
4. Click **Ingest & Run**. Watch the investigation transition from `ANALYSING` to `NEEDS_REVIEW` or `BENIGN`.
5. Review the itemized explainable risk ledger, expand redirect chains safely, add analyst notes, and click **Forensic PDF** to download the signed forensic report.

---

## Security Controls & Limitations

1. **SSRF Guard:** Outbound requests (such as redirect chain expansion) pass through IP validation against RFC 1918, RFC 3927 link-local, loopback, and cloud metadata (`169.254.169.254`).
2. **Defanged Presentation:** Observables are defanged in the UI to prevent accidental clicks.
3. **No Automatic Code Execution:** Uploaded attachments and embedded scripts in HTML bodies are never executed. HTML preview is strictly sandboxed.
4. **Telemetry Privacy:** Raw email bodies and attachments are never submitted to public cloud services.
5. **Limitations:** DKIM independent signature verification requires that the public key is actively published in DNS. If external DNS lookups time out, the system notes the check as `UNAVAILABLE` rather than guessing.
