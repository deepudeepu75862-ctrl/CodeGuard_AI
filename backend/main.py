from __future__ import annotations

import io
import json
import re
import sqlite3
import tempfile
import zipfile
import subprocess
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "codeguard.db"
MAX_ARCHIVE_BYTES = 15 * 1024 * 1024
MAX_FILES = 500
MAX_SOURCE_BYTES = 1_000_000
ALLOWED_SUFFIXES = {".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".php", ".rb", ".go", ".env.example"}

RULES = [
    ("CG001", "Possible hard-coded secret", "High",
     re.compile(r"""(?i)\b(api[_-]?key|secret|password|token)\b\s*[:=]\s*['"][^'"\n]{8,}['"]"""),
     "Move secrets to environment variables or a secret manager. Rotate any real credential that was committed."),
    ("CG002", "Use of eval()", "High", re.compile(r"\beval\s*\("),
     "Avoid eval on untrusted input. Use safe parsing or an explicit allowlist."),
    ("CG003", "Use of exec()", "High", re.compile(r"\bexec\s*\("),
     "Avoid dynamically executing strings. Refactor to explicit functions and validated inputs."),
    ("CG004", "SQL query may use string formatting", "High",
     re.compile(r"""(?i)(execute|executemany)\s*\(\s*f['"]|execute\s*\([^)]*%s"""),
     "Use parameterized SQL queries instead of string concatenation or interpolation."),
    ("CG005", "Subprocess with shell=True", "High", re.compile(r"shell\s*=\s*True"),
     "Pass an argument list to subprocess and keep shell=False."),
    ("CG006", "TLS certificate verification disabled", "High",
     re.compile(r"(?i)verify\s*=\s*False"),
     "Keep TLS certificate verification enabled; fix the trust configuration instead."),
    ("CG007", "Debug mode enabled", "Medium",
     re.compile(r"(?i)\b(debug|DEBUG)\s*=\s*True"),
     "Disable debug mode in production and keep detailed errors out of public responses."),
    ("CG008", "Potential weak hash algorithm", "Medium",
     re.compile(r"\b(md5|sha1)\s*\("),
     "Use SHA-256 or a modern password-hashing algorithm such as Argon2/bcrypt for passwords."),
    ("CG009", "Potential unsafe YAML loading", "Medium",
     re.compile(r"yaml\.load\s*\("),
     "Use yaml.safe_load for untrusted YAML input."),
    ("CG010", "Wildcard CORS configuration", "Medium",
     re.compile(r"""(?i)allow_origins\s*=\s*\[\s*['"]\*['"]"""),
     "Restrict CORS origins to the domains that need access."),
]

SEVERITY_WEIGHT = {"Critical": 25, "High": 12, "Medium": 6, "Low": 2}

app = FastAPI(title="CodeGuard AI", version="1.0.0",
              description="Upload a source ZIP and scan for common security risks.")
app.mount("/static", StaticFiles(directory=BASE_DIR / "frontend"), name="static")


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with db() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY, filename TEXT NOT NULL, created_at TEXT NOT NULL,
            risk_score INTEGER NOT NULL, finding_count INTEGER NOT NULL, result_json TEXT NOT NULL
        )""")


init_db()


def scan_source(filename: str, source: str) -> list[dict[str, Any]]:
    findings = []
    for line_no, line in enumerate(source.splitlines(), start=1):
        for rule_id, title, severity, pattern, recommendation in RULES:
            if pattern.search(line):
                findings.append({
                    "id": rule_id, "title": title, "severity": severity,
                    "file": filename, "line": line_no,
                    "evidence": line.strip()[:240],
                    "recommendation": recommendation,
                })
    return findings


def risk_score(findings: list[dict[str, Any]]) -> int:
    # Transparent weighted heuristic, not a trained ML prediction.
    total = sum(SEVERITY_WEIGHT.get(item["severity"], 0) for item in findings)
    return min(100, total)


def run_bandit(files: dict[str, str]) -> list[dict[str, Any]]:
    """Optional Bandit pass. Uses a temporary directory and never executes uploaded code."""
    executable = shutil.which("bandit")
    if not executable:
        return []
    results: list[dict[str, Any]] = []
    try:
        with tempfile.TemporaryDirectory(prefix="codeguard_") as temp:
            temp_path = Path(temp)
            for name, content in files.items():
                if not name.endswith(".py"):
                    continue
                target = temp_path / Path(name).name
                target.write_text(content, encoding="utf-8", errors="replace")
            completed = subprocess.run(
                [executable, "-r", str(temp_path), "-f", "json", "-q"],
                capture_output=True, text=True, timeout=20, check=False
            )
            if completed.stdout.strip():
                payload = json.loads(completed.stdout)
                for item in payload.get("results", []):
                    results.append({
                        "id": item.get("test_id", "BANDIT"),
                        "title": item.get("issue_text", "Bandit finding"),
                        "severity": item.get("issue_severity", "Medium").title(),
                        "file": Path(item.get("filename", "unknown")).name,
                        "line": item.get("line_number", 0),
                        "evidence": (item.get("code") or "").strip()[:240],
                        "recommendation": "Review the Bandit finding and apply the secure coding guidance for this issue.",
                    })
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
        return []
    return results


def inspect_zip(raw: bytes) -> tuple[dict[str, str], list[str]]:
    if len(raw) > MAX_ARCHIVE_BYTES:
        raise HTTPException(413, "ZIP file is too large (maximum 15 MB).")
    try:
        archive = zipfile.ZipFile(io.BytesIO(raw))
    except zipfile.BadZipFile:
        raise HTTPException(400, "Please upload a valid ZIP file.")
    source_files: dict[str, str] = {}
    skipped: list[str] = []
    infos = archive.infolist()
    if len(infos) > MAX_FILES:
        raise HTTPException(413, "ZIP contains too many entries (maximum 500).")
    for info in infos:
        path = Path(info.filename)
        # Reject traversal, absolute paths, symlinks, and oversized members.
        if path.is_absolute() or ".." in path.parts or info.filename.startswith(("/", "\\")):
            skipped.append(info.filename)
            continue
        mode = (info.external_attr >> 16) & 0o170000
        if mode == 0o120000 or info.is_dir():
            continue
        if info.file_size > MAX_SOURCE_BYTES:
            skipped.append(info.filename)
            continue
        if path.suffix.lower() not in ALLOWED_SUFFIXES:
            continue
        try:
            data = archive.read(info)
            source_files[info.filename] = data.decode("utf-8", errors="replace")
        except (RuntimeError, zipfile.BadZipFile):
            skipped.append(info.filename)
    if not source_files:
        raise HTTPException(400, "No supported source files found. Include Python, JavaScript, TypeScript, Java, PHP, Ruby, or Go files.")
    return source_files, skipped


@app.get("/")
def home():
    return FileResponse(BASE_DIR / "frontend" / "index.html")


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "CodeGuard AI", "version": "1.0.0"}


@app.post("/api/scan")
async def create_scan(file: UploadFile = File(...)):
    if not file.filename or not file.filename.lower().endswith(".zip"):
        raise HTTPException(400, "Upload a .zip file.")
    raw = await file.read()
    source_files, skipped = inspect_zip(raw)
    findings: list[dict[str, Any]] = []
    for name, content in source_files.items():
        findings.extend(scan_source(name, content))
    findings.extend(run_bandit(source_files))
    score = risk_score(findings)
    scan_id = str(uuid4())
    created_at = datetime.now(timezone.utc).isoformat()
    result = {
        "id": scan_id, "filename": file.filename, "created_at": created_at,
        "files_scanned": len(source_files), "skipped_files": skipped,
        "risk_score": score, "risk_level": "Critical" if score >= 75 else "High" if score >= 40 else "Medium" if score >= 15 else "Low",
        "finding_count": len(findings), "findings": findings,
        "severity_counts": {s: sum(1 for f in findings if f["severity"] == s) for s in ["Critical", "High", "Medium", "Low"]},
        "scanner_note": "Rule-based heuristic plus optional Bandit. Not a trained AI model or a complete security audit."
    }
    with db() as conn:
        conn.execute("INSERT INTO scans VALUES (?, ?, ?, ?, ?, ?)",
                     (scan_id, file.filename, created_at, score, len(findings), json.dumps(result)))
    return result


@app.get("/api/scans")
def list_scans():
    with db() as conn:
        rows = conn.execute("SELECT id, filename, created_at, risk_score, finding_count FROM scans ORDER BY created_at DESC LIMIT 20").fetchall()
    return [dict(row) for row in rows]


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: str):
    with db() as conn:
        row = conn.execute("SELECT result_json FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Scan not found.")
    return json.loads(row["result_json"])


@app.get("/api/scans/{scan_id}/report")
def download_report(scan_id: str):
    with db() as conn:
        row = conn.execute("SELECT result_json FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Scan not found.")
    result = json.loads(row["result_json"])
    report_path = BASE_DIR / f"report_{scan_id}.json"
    report_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    return FileResponse(report_path, media_type="application/json", filename=f"codeguard-report-{scan_id[:8]}.json")
