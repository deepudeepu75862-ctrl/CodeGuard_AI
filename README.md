# CodeGuard AI — Intelligent Code Security Scanner

A local, portfolio-ready security scanning MVP for Python projects. Upload a ZIP file, inspect findings, review risk scores, and export a JSON report.

## Features
- ZIP upload with safe extraction-free inspection (files are never executed)
- Detects common risky Python patterns and possible hard-coded secrets
- Severity levels: Critical, High, Medium, Low
- Risk score (0–100) and summary dashboard
- Scan history stored in SQLite
- JSON report download
- Optional Bandit integration for deeper Python static analysis
- Docker support and basic API tests

> This is a learning/portfolio tool, not a replacement for professional security testing. Pattern-based checks can produce false positives and miss vulnerabilities. Never upload confidential source code or real credentials to an untrusted server.

## Requirements
- Python 3.10+
- Windows, macOS, or Linux

## Run on Windows (PowerShell)
```powershell
cd CodeGuard_AI
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
uvicorn backend.main:app --reload
```
Open http://127.0.0.1:8000

If PowerShell blocks activation:
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

## Run on Windows (Git Bash)
```bash
cd CodeGuard_AI
py -3.12 -m venv .venv
source .venv/Scripts/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
uvicorn backend.main:app --reload
```

## Optional: Bandit
Install Bandit:
```bash
pip install bandit
```
CodeGuard will invoke Bandit when it is installed. It runs against a temporary copy of the uploaded Python files with a timeout.

## API
- `GET /api/health` — health check
- `POST /api/scan` — upload a `.zip` project
- `GET /api/scans` — recent scan history
- `GET /api/scans/{scan_id}` — scan details
- `GET /api/scans/{scan_id}/report` — download JSON report

## GitHub portfolio checklist
1. Add screenshots of the dashboard and a sample scan.
2. Add a short demo GIF/video.
3. Explain the detection rules and known limitations.
4. Add tests and keep sample code free of real secrets.
5. Never commit `.env`, API keys, uploaded projects, or the SQLite database.

## Project structure
```text
CodeGuard_AI/
├── backend/
│   ├── __init__.py
│   └── main.py
├── frontend/
│   ├── index.html
│   ├── styles.css
│   └── app.js
├── tests/
│   └── test_scanner.py
├── requirements.txt
├── Dockerfile
├── .gitignore
└── README.md
```
