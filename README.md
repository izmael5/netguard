# NetGuard

A self-hosted dashboard for **authorized** network and web security
assessment: scans hosts/devices on your network for open ports and
running services, matches detected service versions against known CVEs
(NVD database), runs passive web-security checks (missing headers, TLS
expiry, accidentally-exposed files), stores everything in MySQL, and
generates shareable HTML reports.

## ⚠️ Scope and legal use

This tool only scans targets you explicitly add to its allow-list, and
every scan is checked against that list before it runs. **Only add
devices, servers, and websites you own or have written permission to
test.** Scanning systems without authorization is illegal in most
countries (e.g. US CFAA, UK Computer Misuse Act). This project
identifies and reports known vulnerabilities — it does **not** contain
exploit code; use the CVE references in the report to patch/upgrade or
hand off to a tool like Metasploit yourself if you're doing authorized
penetration testing that calls for it.

## What it does

- **Port & service scan** — `nmap -sV` (falls back to a plain Python
  socket scan if nmap isn't available) against hosts/IPs/CIDRs on your
  allow-list.
- **CVE matching** — looks up each detected product/version against the
  NVD public API and stores matching CVEs with severity/CVSS.
- **Web checks** — missing security headers, TLS certificate expiry,
  server banner disclosure, a handful of commonly-exposed paths
  (`.env`, `.git/config`, etc.) — all passive GET requests, nothing
  destructive.
- **MySQL storage** — every scan, port, CVE match, and web finding is
  persisted so you can review history over time.
- **HTML reports** — one click generates a styled, shareable report per
  scan.

## Project layout

```
netguard/
├── app.py                   # Flask app & routes
├── config.py                 # env-driven configuration
├── scanner/
│   ├── authorization.py      # allow-list enforcement
│   ├── port_scanner.py       # nmap / socket port scan
│   ├── vuln_lookup.py        # NVD CVE lookup
│   └── web_scanner.py        # passive HTTP/TLS checks
├── report/report_generator.py
├── database/
│   ├── schema.sql
│   └── db.py
├── templates/                # Jinja2 HTML (dashboard + report)
├── static/{css,js}
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── .env.example
└── .gitignore
```

## Run it locally with Docker (recommended)

1. Install Docker Desktop (or Docker Engine + Compose) if you don't have it.
2. Copy the environment template and edit it:
   ```bash
   cp .env.example .env
   # edit .env: set real passwords, your ALLOWED_TARGETS, optional NVD_API_KEY
   ```
3. Build and start everything:
   ```bash
   docker compose up -d --build
   ```
4. Open **http://localhost:5000**. MySQL is on `localhost:3306` if you
   want to connect with a GUI client (DBeaver, TablePlus, MySQL Workbench).
5. Stop it:
   ```bash
   docker compose down          # keep data
   docker compose down -v       # wipe the MySQL volume too
   ```

## Run it without Docker

1. Install nmap on your OS (`sudo apt install nmap` / `brew install nmap`
   / Windows: install Nmap and add it to PATH). Optional — the app falls
   back to a socket scanner if it's missing.
2. Install and start MySQL locally, then load the schema:
   ```bash
   mysql -u root -p < database/schema.sql
   ```
3. Create a virtualenv and install deps:
   ```bash
   python -m venv .venv
   source .venv/bin/activate        # Windows: .venv\Scripts\activate
   pip install -r requirements.txt
   ```
4. Copy `.env.example` to `.env`, set `MYSQL_HOST=localhost` and your
   credentials, add your targets to `ALLOWED_TARGETS`.
5. Run it:
   ```bash
   python app.py
   ```
6. Open **http://localhost:5000**.

## Using the dashboard

1. **Allowed targets** — add every device/IP/CIDR/website you're
   authorized to test (e.g. `192.168.1.0/24` for your home LAN, or
   `yourdomain.com` for a site you own).
2. **Run a scan** — pick a target from the list, choose port/web/full,
   set a port range (default `1-1024`; use `1-65535` for a full sweep,
   it just takes longer).
3. Watch it move from `queued` → `running` → `completed` on the results
   page (auto-refreshes).
4. Click **Generate report** to produce a downloadable HTML file (also
   saved under `reports/`).

## Pushing this project to GitHub

From inside the `netguard/` folder:

```bash
# 1. Initialize git (skip if already a repo)
git init

# 2. Make sure secrets aren't tracked — .gitignore already excludes .env,
#    but double check before the first commit:
git status

# 3. Stage everything
git add .

# 4. First commit
git commit -m "Initial commit: NetGuard security scanning dashboard"

# 5. Create the repo on GitHub (either via the website, or with the
#    GitHub CLI if you have it installed):
gh repo create netguard --private --source=. --remote=origin
#    — or, if you created the repo on github.com first —
git remote add origin https://github.com/<your-username>/netguard.git

# 6. Push
git branch -M main
git push -u origin main
```

If `git push` asks for a password, GitHub no longer accepts your account
password for this — use a Personal Access Token
(Settings → Developer settings → Personal access tokens) or set up SSH
keys and use `git@github.com:<you>/netguard.git` as the remote instead.

**Before your first push**, double check `.env` is NOT staged
(`git status` should not list it) — it holds your DB passwords and
optional NVD API key. `.gitignore` already excludes it, but it's worth
a manual check the first time.

## Extending it

- Add scheduled scans with a cron job calling `POST /scan`.
- Add auth (Flask-Login) in front of the dashboard before exposing it
  beyond `localhost`.
- Swap the NVD keyword search for CPE-based matching if you want fewer
  false positives on CVE matches.
- PDF export: add `weasyprint` to `requirements.txt` and render the same
  Jinja2 template to PDF in `report_generator.py`.
