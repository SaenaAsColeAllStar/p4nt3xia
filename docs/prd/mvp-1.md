📄 PRD: Web Pentest Tool Platform — Pribadi

Project Name: P4NT3XIA (atau kamu bisa ganti nanti) Platform: Web Application (React/Next.js frontend + Python/FastAPI backend) Target User: Diri sendiri (authorized penetration tester) Mode: Deep Scan | Attack Mode
1. 🎯 Tujuan Produk

Membangun web-based pentest tool yang:

    Tidak perlu install tool satu per satu di lokal
    Bisa diakses via browser, termasuk dari mobile/tablet
    Memiliki dua mode operasi: Deep Scan (safe, non-intrusive) dan Attack Mode (full exploitation)
    Modular dan mudah ditambah tool baru
    Menyimpan history hasil scan

2. 🏗️ Arsitektur Sistem

┌──────────────────────────────────────────────┐
│                 Frontend (Next.js)            │
│  - Dashboard                                  │
│  - Deep Scan Page                             │
│  - Attack Mode Page                           │
│  - History & Reports                          │
└─────────────────────────┬────────────────────┘
                          │ REST API / WebSocket
┌─────────────────────────▼────────────────────┐
│              Backend (FastAPI)                │
│  - Auth & Session Management                  │
│  - Target Management                          │
│  - Scan Orchestrator                          │
│  - Tool Executor (Subprocess/Sandbox)         │
│  - Report Generator                           │
└─────────────────────────┬────────────────────┘
                          │
┌─────────────────────────▼────────────────────┐
│           Execution Layer (Python/Go)         │
│  - Tool Wrappers (Nuclei, ffuf, sqlmap,dll)   │
│  - Custom Exploit Engine                      │
│  - Frida/Tools Integration (future)           │
└──────────────────────────────────────────────┘

3. 👤 User Stories & Fitur
3.1 Dashboard

    Lihat ringkasan total scan, target aktif, vulnerabilities found
    Quick action: New Deep Scan / New Attack
    Recent scan activity timeline

3.2 Manajemen Target

    Input target: URL / Domain / IP (single or list)
    Validasi target format
    Simpan target ke "Target Library" untuk re-scan

4. 🧠 Deep Scan Mode

Filosofi: Non-destructive, informasi maksimal, aman untuk production.
Fitur	Detail
Reconnaissance	Subdomain enumeration (Subfinder/Amass), DNS records, Technology detection (Wappalyzer/WhatWeb)
Port Scanning	Tcp/udp port scan via nmap/nmap wrapper (SYN scan only, safe flags)
Directory Fuzzing	ffuf dengan wordlist kecil-medium, safe status codes only
Vulnerability Scan	Nuclei templates (severity: info, low, medium only — no exploit templates)
SSL/TLS Analysis	Certificate info, cipher check, weak protocol detection
Web Technology Stack	Deteksi framework, versi, plugin/CMS
Crawl & Spider	Katana atau Gospider — no form submission, no auth brute
Output	Daftar endpoint, technology stack, potential misconfig, open ports, SSL issues

User Flow:

    Pilih target
    Pilih "Deep Scan"
    Konfigurasi opsi (optional: depth, timeout, threads)
    Klik → Start Scan
    Lihat progress real-time (WebSocket)
    Hasil: Tree view + raw data + export PDF/JSON

5. ⚔️ Attack Mode

Filosofi: Full exploitation, aggressive testing. Hanya untuk target yang sudah authorized.
Fitur	Detail
SQL Injection	sqlmap automation + manual endpoint injection
XSS Detection	Dalfox, custom payload injection, reflected/stored/DOM
Command Injection	Custom payload fuzzing, blind OS detection
LFI/RFI	Path traversal payloads, file read verification
SSRF	SSRFmap + collaborator-based detection
Auth Bypass	JWT manipulation, brute-force (hydra), session hijack test
IDOR Testing	Autorize-like: parameter tampering with auth token
File Upload Bypass	Extension bypass, magic byte manipulation, double extension
Rate Limit Testing	Brute detection, account lockout testing
Template-based	Nuclei (severity: high, critical, exploit templates)

User Flow:

    Pilih target
    Pilih "Attack Mode"
    Centang attack vectors yang ingin dijalankan
    Konfigurasi (payload file, thread count, delay, proxy)
    Klik → Launch Attack
    Progress + real-time findings
    Setiap finding: POC (Proof of Concept) — request/response + curl command copy
    Report: CVSS 3.1 scoring, remediation, exploit code jika relevan

6. 🔧 Tool Integration Matrix (Backend)
Deep Scan Tools
Tool	Fungsi	Command Example
Subfinder	Subdomain enum	subfinder -d target.com -oJ
Nmap	Port scan	nmap -sS -sV -T4 -p- --top-ports 1000
ffuf	Directory fuzz	ffuf -u https://target.com/FUZZ -w wordlist.txt -mc 200,301,302
WhatWeb	Tech detection	whatweb target.com
Nuclei	Vuln scan (safe)	nuclei -u target.com -severity info,low,medium -etags exploit
Katana	Crawler	katana -u target.com -silent
Sslscan	SSL analysis	sslscan target.com
Attack Mode Tools
Tool	Fungsi	Command Example
sqlmap	SQL injection	sqlmap -u "http://target.com?id=1" --batch --risk=3 --level=5
Dalfox	XSS scanner	dalfox url http://target.com
Nuclei	Exploit templates	nuclei -u target.com -severity high,critical -t exploits/
ffuf	Parameter fuzz	ffuf -u "http://target.com?FUZZ=test" -w params.txt -fc 403
hydra	Brute-force	hydra -l admin -P pass.txt target.com http-post-form
SSRFmap	SSRF test	ssrfmap -r request.txt -p "url"
JWT_Tool	JWT attack	python3 jwt_tool.py -t http://target.com -rh "Authorization: Bearer ..."
Custom Python	Payload fuzzing	Custom scripts for LFI, CMDi, file upload
7. 📊 Report Generator
Format	Detail
JSON	Raw data, machine-readable
PDF	Executive summary + technical detail dengan CVSS
HTML	Interactive report, filterable by severity
Markdown	Untuk copy-paste ke Notion/Obsidian

Report Content:

    Target info
    Scan date & duration
    Summary (total findings, severity breakdown)
    Technical finding detail:
        CVE ID (jika ada)
        CVSS 3.1 Score
        Request/Response (POC)
        Remediation steps
        Reference links

8. 🗄️ Database Schema

Targets
├── id (UUID)
├── url / domain / ip
├── type (web, api, android_backend)
├── created_at
├── tags[]
└── notes

Scans
├── id (UUID)
├── target_id (FK)
├── mode (deep_scan | attack)
├── status (running, completed, failed, cancelled)
├── progress (0-100)
├── started_at
├── completed_at
├── configuration (JSON)

Findings
├── id (UUID)
├── scan_id (FK)
├── title
├── severity (info, low, medium, high, critical)
├── cvss_score (float)
├── cve_id (nullable)
├── description
├── poc_request
├── poc_response
├── poc_curl
├── remediation
├── references[]
└── raw_data (JSON)

Tool_Results
├── id (UUID)
├── scan_id (FK)
├── tool_name
├── command
├── stdout (text)
├── stderr (text)
├── exit_code
├── duration_ms
└── parsed_output (JSON)

9. 🖥️ UI/UX Layout
Deep Scan Page

┌──────────────────────────────────────────┐
│  Target Input: [_____________________]   │
│  [x] Subdomain Enum   [x] Port Scan      │
│  [x] Directory Fuzz    [x] Tech Detect   │
│  [x] Safe Vuln Scan    [x] SSL Check     │
│  Threads: [3]   Timeout: [30s]           │
│  ┌────────────────────────────────────┐  │
│  │        [🚀 START DEEP SCAN]         │  │
│  └────────────────────────────────────┘  │
│                                           │
│  Progress: ████████░░ 80%                 │
│  Log: Found subdomain: admin.target.com   │
│       Port 443 open (nginx 1.24)          │
│       Tech: React, Node.js                │
│       ...                                  │
│                                           │
│  Results:                                 │
│  ┌──────────┬──────┬────────────────────┐ │
│  │ Severity │ Type │ Description        │ │
│  ├──────────┼──────┼────────────────────┤ │
│  │ Medium   │ SSL  │ TLS 1.0 enabled   │ │
│  │ Low      │ Info │ nginx version leak│ │
│  └──────────┴──────┴────────────────────┘ │
└──────────────────────────────────────────┘

Attack Mode Page

┌──────────────────────────────────────────┐
│  Target: [https://api.target.com______]  │
│  Auth Header (optional): [Bearer xxx ]  │
│                                           │
│  Attack Vectors:                          │
│  [x] SQL Injection     [x] XSS            │
│  [x] Command Injection [x] LFI/RFI        │
│  [x] SSRF              [x] IDOR           │
│  [x] JWT Attack        [x] File Upload    │
│  [x] Brute-force       [x] Nuclei Exploit │
│                                           │
│  Config: [Aggressive] Delay: [0ms]        │
│  ┌────────────────────────────────────┐  │
│  │        [⚡ LAUNCH ATTACK]           │  │
│  └────────────────────────────────────┘  │
│                                           │
│  Findings:                                │
│  🔴 Critical: SQLi @ /api/users?id=1     │
│     [📋 Copy PoC] [📄 Detail]            │
│  🟠 High: XSS @ /search?q=<script>       │
│     [📋 Copy PoC] [📄 Detail]            │
│  🟡 Medium: IDOR @ /api/orders/{id}      │
│     [📋 Copy PoC] [📄 Detail]            │
│                                           │
│  ┌────────────────────────────────────┐  │
│  │  [📊 GENERATE REPORT]              │  │
│  └────────────────────────────────────┘  │
└──────────────────────────────────────────┘

10. ⚙️ Technical Stack Recommendation
Layer	Technology	Alasan
Frontend	Next.js 14+ (React) + Tailwind CSS + ShadCN UI	Full-stack, easy auth, reusable components
Backend	FastAPI (Python 3.11+)	Async, WebSocket support, easy subprocess management
Database	SQLite (dev) / PostgreSQL (prod)	SQLite cukup untuk pribadi, PG untuk scale
ORM	SQLAlchemy + Alembic	Migration, type safety
Task Queue	Celery + Redis (opsional)	Untuk long-running scan biar tidak blocking
Auth	NextAuth.js / JWT sederhana	Cukup untuk single user
Container	Docker Compose	Isolasi tool execution dari host
Deployment	VPS (DigitalOcean/Linode) + Nginx reverse proxy	Atau local server
11. 📋 Priority Roadmap
Phase 1 (MVP) — Minggu 1-2

    Setup Next.js + FastAPI + SQLite
    Dashboard sederhana
    Deep Scan Mode: Target input, jalankan Subfinder + Nmap + ffuf
    Hasil ditampilkan di halaman
    Progress bar real-time (WebSocket atau polling)

Phase 2 — Minggu 3-4

    Attack Mode: sqlmap, Dalfox, Nuclei (exploit templates)
    Attack configuration page
    PoC copy button, finding detail page
    Report generator (JSON + HTML)

Phase 3 — Minggu 5-6

    More tools: hydra, SSRFmap, JWT_Tool, custom payload engine
    Target library & history
    PDF report export
    Docker Compose production setup

Phase 4 (Future)

    Multi-user dengan role (personal use maybe skip)
    Frida integration untuk Android dynamic analysis
    API mode: accept curl-like request from terminal
    Template custom payload builder

12. ⚠️ Security Considerations (Untuk Aplikasi Ini Sendiri)
Concern	Solusi
Tool execution safety	Semua tool jalan di container/sandbox terisolasi
Rate limiting	Jangan bombardir target tanpa delay, hormati robots.txt di Deep Scan
Credential storage	API keys, auth tokens disimpan encrypted
Logging	Jangan log payload berisi kredensial target
Authorization reminder	Tampilkan banner peringatan di Attack Mode setiap kali start scan
13. 📁 Directory Structure (Saran untuk Cursor)


p4nt3xia/
├── frontend/               # Next.js
│   ├── app/
│   │   ├── page.tsx        # Dashboard
│   │   ├── deep-scan/
│   │   ├── attack-mode/
│   │   ├── history/
│   │   └── settings/
│   ├── components/
│   ├── lib/
│   └── package.json
├── backend/                # FastAPI
│   ├── app/
│   │   ├── main.py
│   │   ├── routers/
│   │   ├── models/
│   │   ├── schemas/
│   │   ├── services/
│   │   │   ├── scanner.py      # Orchestrator
│   │   │   ├── deep_scan.py    # Deep scan logic
│   │   │   ├── attack.py       # Attack logic
│   │   │   ├── tool_runner.py  # Subprocess wrapper
│   │   │   └── report.py
│   │   └── database.py
│   ├── tools/               # Tool wrappers & configs
│   ├── requirements.txt
│   └── Dockerfile
├── docker-compose.yml
└── README.md
