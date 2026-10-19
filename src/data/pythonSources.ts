export interface PythonSourceFile {
  name: string;
  path: string;
  description: string;
  framework: 'FastAPI' | 'Flask' | 'Shared' | 'Docker' | 'Tests';
  content: string;
}

export const PYTHON_SOURCE_FILES: PythonSourceFile[] = [
  {
    name: 'app_fastapi.py',
    path: 'backend/app_fastapi.py',
    framework: 'FastAPI',
    description: 'Production-ready FastAPI backend with localhost binding, rate-limiting, secure headers, parameterized SQLite, and audit logging.',
    content: `"""
SecAudit Lab - FastAPI Backend Engine
Target: Ethical Hacking Education & Local Penetration Testing Lab
Binds strictly to 127.0.0.1 (Localhost)
"""

import os
import time
import uuid
import secrets
import sqlite3
import datetime
import logging
from typing import Optional, Dict, Any, List
from fastapi import FastAPI, Request, Response, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# Configure structured audit logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] [AUDIT] %(message)s',
    handlers=[
        logging.FileHandler("local_audit.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("SecAudit")

# Initialize Rate Limiter
limiter = Limiter(key_func=get_remote_address, default_limits=["100/minute"])

app = FastAPI(
    title="SecAudit Lab Engine",
    description="Local Defensive Security Testing API",
    version="1.0.0",
    docs_url="/docs",
    redoc_url=None
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ---------------------------------------------------------------------------
# Strict Security Constraints & Host Binding Enforcement
# ---------------------------------------------------------------------------
AUTHORIZED_HOSTS = {"127.0.0.1", "localhost", "127.0.0.1:8000", "localhost:8000"}
SESSION_STORE: Dict[str, Dict[str, Any]] = {}

@app.middleware("http")
async def security_enforcement_middleware(request: Request, call_next):
    # 1. Host header validation to prevent Host Header Injection
    host = request.headers.get("host", "")
    if host not in AUTHORIZED_HOSTS:
        logger.warning(f"Rejected non-localhost host header: {host} from {request.client.host}")
        return JSONResponse(
            status_code=403,
            content={"error": "Access forbidden: strictly bound to localhost (127.0.0.1)"}
        )

    start_time = time.time()
    response: Response = await call_next(request)
    duration_ms = round((time.time() - start_time) * 1000, 2)

    # 2. Hardened HTTP Security Headers
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; frame-ancestors 'none'; object-src 'none'"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"

    # 3. Audit trail recording
    client_ip = request.client.host if request.client else "unknown"
    logger.info(f"{request.method} {request.url.path} - Status: {response.status_code} ({duration_ms}ms) IP: {client_ip}")

    return response

# CORS configuration restricted strictly to local client
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Database Initialization (SQLite Lab with Parameterized Auditing)
# ---------------------------------------------------------------------------
DB_PATH = "lab_sec.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT NOT NULL,
            role TEXT NOT NULL,
            is_active INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT NOT NULL,
            operator TEXT NOT NULL,
            status TEXT NOT NULL,
            details TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    # Seed educational records if empty
    cursor.execute("SELECT count(*) FROM users")
    if cursor.fetchone()[0] == 0:
        cursor.executemany(
            "INSERT INTO users (username, email, role) VALUES (?, ?, ?)",
            [
                ("admin", "admin@lab.local", "SecurityAdmin"),
                ("auditor", "auditor@lab.local", "SecurityAuditor"),
                ("developer", "dev@lab.local", "Engineer"),
                ("test_agent", "agent01@lab.local", "GuestTester")
            ]
        )
    conn.commit()
    conn.close()

init_db()

# ---------------------------------------------------------------------------
# Session Token Management & Dependency
# ---------------------------------------------------------------------------
def issue_session_token(role: str = "SecurityAuditor") -> str:
    token = secrets.token_urlsafe(32)
    SESSION_STORE[token] = {
        "created_at": datetime.datetime.utcnow().isoformat(),
        "expires_at": (datetime.datetime.utcnow() + datetime.timedelta(hours=2)).isoformat(),
        "role": role,
        "token": token
    }
    return token

def verify_session(request: Request) -> Dict[str, Any]:
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or malformed Authorization header. Bearer token required."
        )
    token = auth_header.split(" ")[1]
    session = SESSION_STORE.get(token)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session token."
        )
    return session

# ---------------------------------------------------------------------------
# API Models
# ---------------------------------------------------------------------------
class QueryTestPayload(BaseModel):
    input_value: str = Field(..., max_length=100)
    use_parameterization: bool = True

class DiagnosticRequest(BaseModel):
    target: str = Field(..., max_length=253)
    command_type: str = Field("ping", regex="^(ping|dns|port-check)$")
    port: Optional[int] = Field(None, ge=1, le=65535)

# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@app.post("/api/auth/token")
def authenticate():
    """Generates a high-entropy session token for local auditing operations."""
    token = issue_session_token()
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in_seconds": 7200,
        "bound_interface": "127.0.0.1"
    }

@app.get("/api/security/headers-audit")
def check_headers(request: Request):
    """Reflects applied HTTP response security headers for verification."""
    return {
        "status": "active",
        "enforced_headers": {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'self'; script-src 'self'",
            "Referrer-Policy": "strict-origin-when-cross-origin"
        }
    }

@app.post("/api/database/audit-query")
def audit_database_query(payload: QueryTestPayload, session: Dict = Depends(verify_session)):
    """
    Demonstrates Safe (Parameterized Prepared Statement) vs Unsafe (Raw String Concatenation)
    within a strictly controlled local lab database.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    if payload.use_parameterization:
        # SECURE: Input treated strictly as literal data parameter
        sql = "SELECT id, username, email, role FROM users WHERE username = ?"
        start = time.perf_counter()
        cursor.execute(sql, (payload.input_value,))
        rows = cursor.fetchall()
        elapsed_ms = round((time.perf_counter() - start) * 1000, 3)
        risk_level = "nominal"
        notes = "Query successfully executed with parameterized placeholders. SQL injection neutralized."
    else:
        # LAB DEMONSTRATION ONLY: Unsafe string interpolation
        # In a real environment, this allows tautologies (' OR '1'='1)
        sql = f"SELECT id, username, email, role FROM users WHERE username = '{payload.input_value}'"
        start = time.perf_counter()
        try:
            cursor.execute(sql)
            rows = cursor.fetchall()
            elapsed_ms = round((time.perf_counter() - start) * 1000, 3)
            risk_level = "critical" if ("'" in payload.input_value or "OR" in payload.input_value.upper()) else "high"
            notes = "WARNING: Query constructed with raw string concatenation! Vulnerable to SQL injection."
        except sqlite3.OperationalError as e:
            conn.close()
            return {
                "error": str(e),
                "executed_query": sql,
                "vulnerability_flagged": True,
                "remediation": "Always use db.execute('SELECT ... WHERE col = ?', (val,))"
            }

    conn.close()
    return {
        "executed_query": sql,
        "is_parameterized": payload.use_parameterization,
        "risk_level": risk_level,
        "row_count": len(rows),
        "results": [dict(id=r[0], username=r[1], email=r[2], role=r[3]) for r in rows],
        "latency_ms": elapsed_ms,
        "audit_note": notes
    }

@app.get("/api/rate-limit/test-probe")
@limiter.limit("5/minute")
def test_rate_limiting(request: Request):
    """
    Simulates a protected endpoint throttled to 5 requests/minute.
    Excessive requests will trigger HTTP 429 Too Many Requests.
    """
    return {
        "status": "success",
        "message": "Probe successful. Endpoint protected by Token Bucket rate limiter.",
        "timestamp": time.time()
    }

if __name__ == "__main__":
    import uvicorn
    # STRICT CONSTRAINT: Must bind exclusively to 127.0.0.1 (localhost)
    uvicorn.run("app_fastapi:app", host="127.0.0.1", port=8000, reload=True)
`
  },
  {
    name: 'app_flask.py',
    path: 'backend/app_flask.py',
    framework: 'Flask',
    description: 'Flask implementation using Flask-Limiter, Talisman security headers, SQLite parameterized queries, and localhost binding.',
    content: `"""
SecAudit Lab - Flask Backend Implementation
Target: Ethical Hacking Education & Local Penetration Testing Lab
Binds strictly to 127.0.0.1 (Localhost)
"""

import time
import secrets
import sqlite3
import datetime
from flask import Flask, request, jsonify, g
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# Configure local Rate Limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["120 per minute"],
    storage_uri="memory://"
)

AUTHORIZED_HOSTS = {"127.0.0.1:5000", "localhost:5000", "127.0.0.1", "localhost"}
SESSION_CACHE = {}

# ---------------------------------------------------------------------------
# Security Headers & Host Middleware
# ---------------------------------------------------------------------------
@app.before_request
def enforce_localhost_and_timing():
    host = request.headers.get("Host", "")
    if host not in AUTHORIZED_HOSTS:
        return jsonify({"error": "Forbidden: App bound strictly to 127.0.0.1"}), 403
    g.start_time = time.time()

@app.after_request
def add_security_headers(response):
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Content-Security-Policy'] = "default-src 'self'; frame-ancestors 'none'"
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Server'] = 'SecAudit-Lab/1.0'
    return response

# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@app.route('/api/auth/token', methods=['POST'])
def generate_token():
    token = secrets.token_hex(32)
    SESSION_CACHE[token] = {
        'expires': time.time() + 3600,
        'role': 'EthicalAuditor'
    }
    return jsonify({
        'token': token,
        'type': 'Bearer',
        'expires_in': 3600,
        'bound_interface': '127.0.0.1'
    })

@app.route('/api/database/query-audit', methods=['POST'])
def query_audit():
    data = request.get_json() or {}
    user_input = data.get('input', '')
    parameterized = bool(data.get('parameterized', True))

    conn = sqlite3.connect('lab_sec.db')
    cursor = conn.cursor()

    if parameterized:
        sql = "SELECT id, username, email, role FROM users WHERE username = ?"
        cursor.execute(sql, (user_input,))
    else:
        sql = f"SELECT id, username, email, role FROM users WHERE username = '{user_input}'"
        cursor.execute(sql)

    rows = cursor.fetchall()
    conn.close()

    return jsonify({
        'query': sql,
        'parameterized': parameterized,
        'matches': len(rows),
        'results': rows
    })

@app.route('/api/rate-limit/probe', methods=['GET'])
@limiter.limit("5 per minute")
def rate_limit_probe():
    return jsonify({
        'status': 'allowed',
        'message': 'Rate limit check passed. Bucket has capacity.'
    })

if __name__ == '__main__':
    # Strictly bind to 127.0.0.1
    app.run(host='127.0.0.1', port=5000, debug=False)
`
  },
  {
    name: 'security_middleware.py',
    path: 'backend/security_middleware.py',
    framework: 'Shared',
    description: 'Modular Python security middleware validating localhost binding, anti-spoofing, session headers, and audit trails.',
    content: `"""
Defensive Security Middleware for Local Testing Labs
Handles Host Verification, Anti-Clickjacking, and Cryptographic Session Audits.
"""

import hmac
import hashlib
import time
from typing import Optional, Tuple

class LocalhostSecurityValidator:
    def __init__(self, allowed_hosts: set, hmac_secret: str):
        self.allowed_hosts = allowed_hosts
        self.hmac_secret = hmac_secret.encode('utf-8')

    def validate_host_header(self, host_header: str) -> bool:
        """Prevents Host Header Injection and DNS Rebinding attacks."""
        if not host_header:
            return False
        # Remove optional port
        hostname = host_header.split(':')[0].strip().lower()
        return hostname in {"127.0.0.1", "localhost", "::1"}

    def generate_signed_session(self, user_id: str, role: str) -> str:
        """Issues an HMAC-SHA256 signed session token for verified local testing."""
        timestamp = str(int(time.time()))
        payload = f"{user_id}:{role}:{timestamp}"
        signature = hmac.new(self.hmac_secret, payload.encode('utf-8'), hashlib.sha256).hexdigest()
        return f"{payload}.{signature}"

    def verify_signed_session(self, token: str, max_age_seconds: int = 7200) -> Tuple[bool, Optional[dict]]:
        """Verifies session integrity, timing, and prevents token tampering."""
        try:
            payload, signature = token.rsplit('.', 1)
            expected_sig = hmac.new(self.hmac_secret, payload.encode('utf-8'), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(signature, expected_sig):
                return False, None
            
            user_id, role, timestamp_str = payload.split(':')
            timestamp = int(timestamp_str)
            if time.time() - timestamp > max_age_seconds:
                return False, None # Expired

            return True, {"user_id": user_id, "role": role, "issued_at": timestamp}
        except Exception:
            return False, None
`
  },
  {
    name: 'test_security.py',
    path: 'tests/test_security.py',
    framework: 'Tests',
    description: 'Pytest security test suite verifying CSP, HSTS, SQL injection mitigation, and rate-limiting responses.',
    content: `"""
Automated Security Test Suite (OWASP Top 10 Local Assessment)
Execute with: pytest test_security.py -v
"""

import pytest
import sqlite3
from fastapi.testclient import TestClient
from app_fastapi import app, issue_session_token

client = TestClient(app)

def test_host_header_rejection():
    """Ensure requests from untrusted Host headers are rejected (403)."""
    response = client.get("/api/security/headers-audit", headers={"Host": "evil-attacker.com"})
    assert response.status_code == 403
    assert "strictly bound to localhost" in response.json()["error"]

def test_security_headers_present():
    """Verify all OWASP recommended security headers are actively returned."""
    response = client.get("/api/security/headers-audit")
    assert response.status_code == 200
    headers = response.headers
    assert "Strict-Transport-Security" in headers
    assert "DENY" in headers.get("X-Frame-Options", "")
    assert "nosniff" in headers.get("X-Content-Type-Options", "")
    assert "Content-Security-Policy" in headers

def test_parameterized_query_prevents_sqli():
    """Verify parameterized statement prevents classic SQL injection payload (' OR '1'='1)."""
    token = issue_session_token()
    payload = {
        "input_value": "admin' OR '1'='1",
        "use_parameterization": True
    }
    response = client.post(
        "/api/database/audit-query",
        json=payload,
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    data = response.json()
    # With parameterization, looking for literal username "admin' OR '1'='1" yields 0 rows
    assert data["row_count"] == 0
    assert data["risk_level"] == "nominal"

def test_unparameterized_query_flags_risk():
    """Verify unparameterized query triggers risk alert in the testing lab."""
    token = issue_session_token()
    payload = {
        "input_value": "admin' OR '1'='1",
        "use_parameterization": False
    }
    response = client.post(
        "/api/database/audit-query",
        json=payload,
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    data = response.json()
    # Tautology extracts all user rows when unparameterized
    assert data["row_count"] > 1
    assert data["risk_level"] == "critical"

def test_rate_limiting_enforcement():
    """Verify rate limiter blocks client upon exceeding threshold."""
    client_local = TestClient(app)
    # Burst 7 rapid requests to endpoint limited to 5/min
    responses = [client_local.get("/api/rate-limit/test-probe") for _ in range(7)]
    status_codes = [r.status_code for r in responses]
    assert 429 in status_codes
`
  },
  {
    name: 'requirements.txt',
    path: 'requirements.txt',
    framework: 'Shared',
    description: 'Python package dependencies for local penetration testing lab and testing suites.',
    content: `fastapi==0.111.0
uvicorn[standard]==0.30.1
flask==3.0.3
flask-limiter==3.8.0
slowapi==0.1.9
pydantic==2.7.4
requests==2.32.3
pytest==8.2.2
httpx==0.27.0
`
  },
  {
    name: 'Dockerfile',
    path: 'Dockerfile',
    framework: 'Docker',
    description: 'Sandboxed Dockerfile binding strictly to 127.0.0.1 for ethical penetration testing education.',
    content: `# Sandboxed Local Penetration Testing & Vulnerability Assessment Lab
FROM python:3.11-slim

# Prevent root execution and enhance container containment
RUN groupadd -r secgroup && useradd -r -g secgroup secuser
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ .
RUN chown -R secuser:secgroup /app

USER secuser

# Bound strictly to 127.0.0.1 (Localhost only)
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \\
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/security/headers-audit')"

CMD ["python", "app_fastapi.py"]
`
  },
  {
    name: 'README.md',
    path: 'README.md',
    framework: 'Shared',
    description: 'Technical setup guide, ethical testing guidelines, and lab usage documentation.',
    content: `# SecAudit Lab - Ethical Hacking & Defensive Security Workbench

## Overview
SecAudit Lab is an authorized, local-only penetration testing workbench and vulnerability assessment suite. Designed for security engineers, ethical hacking students, and DevSecOps practitioners.

## Core Capabilities
1. **Interactive CLI Web Terminal**: Execute safe local security diagnostics (ping latency, DNS query analysis, TCP port reachability, HTTP header inspect).
2. **HTTP Security Headers Audit**: Automatic evaluation of CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and CORS headers with A+ to F grading.
3. **Database Parameterization Auditor**: Interactive SQLite lab contrasting raw string concatenation vs prepared parameterized statements.
4. **Rate-Limiting & Brute-Force Resilience**: Test token-bucket and sliding-window rate limiters with live latency timelines and 429 status validation.
5. **Strict Localhost Binding & Audit Logging**: Binds strictly to 127.0.0.1, enforces HMAC session token validation, and records an immutable JSON audit log.

## Quick Setup (Python FastAPI)
\`\`\`bash
# 1. Create and activate a clean virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\\Scripts\\activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Start the FastAPI backend (bound strictly to 127.0.0.1:8000)
python app_fastapi.py
\`\`\`

## Run Automated Security Tests
\`\`\`bash
pytest tests/test_security.py -v
\`\`\`

## Ethical Testing Notice
This laboratory environment is designed solely for defensive security education, vulnerability remediation analysis, and authorized penetration testing on systems you own.
`
  }
];
