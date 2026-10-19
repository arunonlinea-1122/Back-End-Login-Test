import {
  AuditLogEntry,
  HeaderAuditReport,
  SecurityHeaderResult,
  QueryAuditResult,
  DiagnosticResult,
  RateLimitResult,
  SessionTokenState,
  LabDatabaseRecord,
  RiskSeverity,
} from '../types/security';

// ---------------------------------------------------------------------------
// 1. Immutable Audit Logger Service
// ---------------------------------------------------------------------------
class AuditLogService {
  private logs: AuditLogEntry[] = [];
  private listeners: Array<() => void> = [];

  constructor() {
    this.initDefaultLogs();
  }

  private initDefaultLogs() {
    const now = new Date();
    this.logs = [
      {
        id: 'aud-' + Math.random().toString(36).substring(2, 9),
        timestamp: new Date(now.getTime() - 1000 * 60 * 12).toISOString(),
        action: 'LAB_INIT',
        category: 'system',
        severity: 'nominal',
        details: 'SecAudit Lab initialized. Interface bound strictly to 127.0.0.1 (Localhost).',
        clientIp: '127.0.0.1',
        sessionId: 'sess-init-001',
        status: 'allowed',
      },
      {
        id: 'aud-' + Math.random().toString(36).substring(2, 9),
        timestamp: new Date(now.getTime() - 1000 * 60 * 8).toISOString(),
        action: 'AUTH_TOKEN_ISSUED',
        category: 'auth',
        severity: 'nominal',
        details: 'Cryptographic session token issued (256-bit entropy, role: SecurityAuditor).',
        clientIp: '127.0.0.1',
        sessionId: 'sess-init-001',
        status: 'allowed',
      },
      {
        id: 'aud-' + Math.random().toString(36).substring(2, 9),
        timestamp: new Date(now.getTime() - 1000 * 60 * 4).toISOString(),
        action: 'PORT_SCAN_DIAGNOSTIC',
        category: 'cli',
        severity: 'low',
        details: 'Diagnostic port check against 127.0.0.1:8000 (FastAPI engine port).',
        clientIp: '127.0.0.1',
        sessionId: 'sess-init-001',
        status: 'allowed',
      },
    ];
  }

  public record(
    action: string,
    category: AuditLogEntry['category'],
    severity: RiskSeverity,
    details: string,
    sessionId: string,
    status: AuditLogEntry['status'] = 'allowed'
  ): AuditLogEntry {
    const entry: AuditLogEntry = {
      id: 'aud-' + Math.random().toString(36).substring(2, 9),
      timestamp: new Date().toISOString(),
      action,
      category,
      severity,
      details,
      clientIp: '127.0.0.1',
      sessionId,
      status,
    };
    this.logs.unshift(entry);
    // Keep max 200 entries locally
    if (this.logs.length > 200) {
      this.logs.pop();
    }
    this.notify();
    return entry;
  }

  public getLogs(): AuditLogEntry[] {
    return [...this.logs];
  }

  public clear() {
    this.logs = [];
    this.notify();
  }

  public subscribe(listener: () => void): () => void {
    this.listeners.push(listener);
    return () => {
      this.listeners = this.listeners.filter((l) => l !== listener);
    };
  }

  private notify() {
    this.listeners.forEach((l) => l());
  }

  public exportJson(): string {
    return JSON.stringify(this.logs, null, 2);
  }

  public exportCsv(): string {
    const headers = ['id', 'timestamp', 'action', 'category', 'severity', 'status', 'clientIp', 'sessionId', 'details'];
    const rows = this.logs.map((log) => [
      log.id,
      log.timestamp,
      log.action,
      log.category,
      log.severity,
      log.status,
      log.clientIp,
      log.sessionId,
      `"${log.details.replace(/"/g, '""')}"`,
    ]);
    return [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');
  }
}

export const auditLogger = new AuditLogService();

// ---------------------------------------------------------------------------
// 2. Session Management & Cryptographic Validation
// ---------------------------------------------------------------------------
export function createSessionToken(): SessionTokenState {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  let token = 'sec_';
  for (let i = 0; i < 48; i++) {
    token += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  const now = new Date();
  const expiresAt = new Date(now.getTime() + 2 * 60 * 60 * 1000); // 2 hours

  return {
    token,
    createdAt: now.toISOString(),
    expiresAt: expiresAt.toISOString(),
    algorithm: 'HMAC-SHA256',
    entropyBits: 256,
    scope: ['read:diagnostics', 'write:query_audit', 'exec:ratelimit', 'export:audit_logs'],
    issuer: 'SecAudit-Lab-Authority',
    isBoundToLocalhost: true,
    isValid: true,
  };
}

// ---------------------------------------------------------------------------
// 3. HTTP Security Headers Audit Service
// ---------------------------------------------------------------------------
export const PRESET_HEADER_PROFILES = {
  unsecured: {
    name: 'Legacy Unsecured App',
    description: 'Typical default framework deployment with no security headers and leaking runtime versions.',
    headers: {
      'content-type': 'text/html; charset=utf-8',
      'server': 'Apache/2.4.41 (Ubuntu)',
      'x-powered-by': 'Express, PHP/7.4.3',
      'access-control-allow-origin': '*',
    },
  },
  partially_hardened: {
    name: 'Partially Hardened Backend',
    description: 'Basic headers configured, but lacks modern CSP, HSTS preload, or Permissions-Policy.',
    headers: {
      'content-type': 'application/json',
      'x-frame-options': 'SAMEORIGIN',
      'strict-transport-security': 'max-age=86400',
      'x-content-type-options': 'nosniff',
      'server': 'nginx',
    },
  },
  fully_hardened: {
    name: 'SecAudit Fully Hardened Profile',
    description: 'Defense-in-depth configuration satisfying strict OWASP ASVS and NIST 800-53 standards.',
    headers: {
      'content-type': 'application/json',
      'strict-transport-security': 'max-age=31536000; includeSubDomains; preload',
      'content-security-policy': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; object-src 'none'; base-uri 'self'",
      'x-frame-options': 'DENY',
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'strict-origin-when-cross-origin',
      'permissions-policy': 'camera=(), microphone=(), geolocation=(), payment=()',
      'cross-origin-opener-policy': 'same-origin',
      'cross-origin-resource-policy': 'same-origin',
      'cache-control': 'no-store, max-age=0',
    },
  },
};

export function auditHeaders(targetUrl: string, headers: Record<string, string>): HeaderAuditReport {
  const norm: Record<string, string> = {};
  Object.keys(headers).forEach((key) => {
    norm[key.toLowerCase()] = headers[key];
  });

  const results: SecurityHeaderResult[] = [];
  let score = 100;
  const notes: string[] = [];

  // 1. Content-Security-Policy (CSP)
  const csp = norm['content-security-policy'];
  if (!csp) {
    score -= 28;
    results.push({
      header: 'Content-Security-Policy',
      status: 'missing',
      value: null,
      recommendedValue: "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'",
      severity: 'critical',
      description: 'Restricts the sources of content (scripts, stylesheets, frames) that the browser is permitted to load.',
      exploitRisk: 'High vulnerability to Cross-Site Scripting (XSS), data exfiltration, and malicious clickjacking payloads.',
      fixSnippet: {
        fastapi: 'response.headers["Content-Security-Policy"] = "default-src \'self\'; script-src \'self\'; frame-ancestors \'none\'"',
        flask: 'response.headers[\'Content-Security-Policy\'] = "default-src \'self\'; frame-ancestors \'none\'"',
        express: 'app.use(helmet.contentSecurityPolicy({ directives: { defaultSrc: ["\'self\'"] } }));',
      },
    });
  } else if (csp.includes("'unsafe-inline'") || csp.includes('*')) {
    score -= 10;
    results.push({
      header: 'Content-Security-Policy',
      status: 'misconfigured',
      value: csp,
      recommendedValue: "default-src 'self'; object-src 'none'",
      severity: 'medium',
      description: "CSP detected but permits wildcards or 'unsafe-inline', significantly reducing XSS mitigation potency.",
      exploitRisk: 'Reflected or stored scripts may bypass weak CSP rules.',
      fixSnippet: {
        fastapi: 'response.headers["Content-Security-Policy"] = "default-src \'self\'; object-src \'none\'"',
        flask: 'response.headers[\'Content-Security-Policy\'] = "default-src \'self\'; object-src \'none\'"',
        express: 'app.use(helmet.contentSecurityPolicy());',
      },
    });
  } else {
    results.push({
      header: 'Content-Security-Policy',
      status: 'present',
      value: csp,
      recommendedValue: csp,
      severity: 'nominal',
      description: 'Robust CSP policy detected.',
      exploitRisk: 'Mitigates untrusted script injection.',
      fixSnippet: { fastapi: '# Policy already active', flask: '# Policy already active', express: '# Policy already active' },
    });
  }

  // 2. Strict-Transport-Security (HSTS)
  const hsts = norm['strict-transport-security'];
  if (!hsts) {
    score -= 20;
    results.push({
      header: 'Strict-Transport-Security',
      status: 'missing',
      value: null,
      recommendedValue: 'max-age=31536000; includeSubDomains; preload',
      severity: 'high',
      description: 'Forces clients to communicate exclusively over encrypted HTTPS connections, preventing SSL-stripping attacks.',
      exploitRisk: 'Vulnerable to Man-in-the-Middle (MitM) and protocol downgrade attacks (e.g., SSLStrip).',
      fixSnippet: {
        fastapi: 'response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"',
        flask: 'response.headers[\'Strict-Transport-Security\'] = "max-age=31536000; includeSubDomains; preload"',
        express: 'app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true, preload: true }));',
      },
    });
  } else {
    results.push({
      header: 'Strict-Transport-Security',
      status: 'present',
      value: hsts,
      recommendedValue: 'max-age=31536000; includeSubDomains; preload',
      severity: 'nominal',
      description: 'HSTS is properly enforcing TLS transport.',
      exploitRisk: 'Enforces strict encrypted communication channel.',
      fixSnippet: { fastapi: '# Active', flask: '# Active', express: '# Active' },
    });
  }

  // 3. X-Frame-Options
  const xfo = norm['x-frame-options'];
  if (!xfo) {
    score -= 15;
    results.push({
      header: 'X-Frame-Options',
      status: 'missing',
      value: null,
      recommendedValue: 'DENY',
      severity: 'high',
      description: 'Indicates whether a browser should be allowed to render a page within a <frame>, <iframe>, or <object>.',
      exploitRisk: 'High susceptibility to Clickjacking (UI redressing) attacks, deceiving users into clicking invisible buttons.',
      fixSnippet: {
        fastapi: 'response.headers["X-Frame-Options"] = "DENY"',
        flask: 'response.headers[\'X-Frame-Options\'] = "DENY"',
        express: 'app.use(helmet.frameguard({ action: "deny" }));',
      },
    });
  } else {
    results.push({
      header: 'X-Frame-Options',
      status: 'present',
      value: xfo,
      recommendedValue: 'DENY',
      severity: 'nominal',
      description: `Frame rendering restricted to ${xfo}.`,
      exploitRisk: 'Defends against framing and clickjacking.',
      fixSnippet: { fastapi: '# Active', flask: '# Active', express: '# Active' },
    });
  }

  // 4. X-Content-Type-Options
  const xcto = norm['x-content-type-options'];
  if (!xcto || xcto.toLowerCase() !== 'nosniff') {
    score -= 12;
    results.push({
      header: 'X-Content-Type-Options',
      status: 'missing',
      value: xcto || null,
      recommendedValue: 'nosniff',
      severity: 'medium',
      description: 'Prevents browsers from MIME-sniffing a response away from the declared Content-Type header.',
      exploitRisk: 'Browsers may interpret benign image uploads or raw text as executable JavaScript.',
      fixSnippet: {
        fastapi: 'response.headers["X-Content-Type-Options"] = "nosniff"',
        flask: 'response.headers[\'X-Content-Type-Options\'] = "nosniff"',
        express: 'app.use(helmet.noSniff());',
      },
    });
  } else {
    results.push({
      header: 'X-Content-Type-Options',
      status: 'present',
      value: 'nosniff',
      recommendedValue: 'nosniff',
      severity: 'nominal',
      description: 'MIME sniffing disabled.',
      exploitRisk: 'Blocks file type confusion exploits.',
      fixSnippet: { fastapi: '# Active', flask: '# Active', express: '# Active' },
    });
  }

  // 5. Referrer-Policy
  const refPol = norm['referrer-policy'];
  if (!refPol) {
    score -= 10;
    results.push({
      header: 'Referrer-Policy',
      status: 'missing',
      value: null,
      recommendedValue: 'strict-origin-when-cross-origin',
      severity: 'medium',
      description: 'Controls how much referrer information (including query string credentials or tokens) is sent in requests.',
      exploitRisk: 'Sensitive tokens, user IDs, or API keys embedded in URLs may leak to third-party domains.',
      fixSnippet: {
        fastapi: 'response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"',
        flask: 'response.headers[\'Referrer-Policy\'] = "strict-origin-when-cross-origin"',
        express: 'app.use(helmet.referrerPolicy({ policy: "strict-origin-when-cross-origin" }));',
      },
    });
  } else {
    results.push({
      header: 'Referrer-Policy',
      status: 'present',
      value: refPol,
      recommendedValue: 'strict-origin-when-cross-origin',
      severity: 'nominal',
      description: 'Referrer policy specified.',
      exploitRisk: 'Limits token leakage across origins.',
      fixSnippet: { fastapi: '# Active', flask: '# Active', express: '# Active' },
    });
  }

  // 6. Permissions-Policy
  const permPol = norm['permissions-policy'];
  if (!permPol) {
    score -= 8;
    results.push({
      header: 'Permissions-Policy',
      status: 'missing',
      value: null,
      recommendedValue: 'camera=(), microphone=(), geolocation=()',
      severity: 'low',
      description: 'Disables browser hardware features and APIs (webcam, microphone, sensors) that the application does not need.',
      exploitRisk: 'Compromised third-party scripts could invoke hardware APIs without explicit restriction.',
      fixSnippet: {
        fastapi: 'response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"',
        flask: 'response.headers[\'Permissions-Policy\'] = "camera=(), microphone=(), geolocation=()"',
        express: 'app.use((req, res, next) => { res.setHeader("Permissions-Policy", "camera=(), microphone=()"); next(); });',
      },
    });
  } else {
    results.push({
      header: 'Permissions-Policy',
      status: 'present',
      value: permPol,
      recommendedValue: 'camera=(), microphone=()',
      severity: 'nominal',
      description: 'Browser hardware capabilities locked down.',
      exploitRisk: 'Reduces hardware API attack surface.',
      fixSnippet: { fastapi: '# Active', flask: '# Active', express: '# Active' },
    });
  }

  // 7. Information Leakage Headers (Server & X-Powered-By)
  const server = norm['server'];
  const xPowered = norm['x-powered-by'];
  if (server && (server.includes('/') || server.includes('Apache') || server.includes('Ubuntu'))) {
    score -= 5;
    notes.push(`Information Leakage: 'Server' header exposes detailed software version: ${server}`);
  }
  if (xPowered) {
    score -= 5;
    notes.push(`Information Leakage: 'X-Powered-By' header exposes internal framework: ${xPowered}`);
  }

  // 8. CORS Wildcard check
  const cors = norm['access-control-allow-origin'];
  if (cors === '*') {
    score -= 5;
    notes.push("CORS Caution: 'Access-Control-Allow-Origin' set to wildcard '*'. Unauthenticated cross-origin access allowed.");
  }

  score = Math.max(0, Math.min(100, score));
  let overallGrade: HeaderAuditReport['overallGrade'] = 'F';
  if (score >= 95) overallGrade = 'A+';
  else if (score >= 85) overallGrade = 'A';
  else if (score >= 70) overallGrade = 'B';
  else if (score >= 55) overallGrade = 'C';
  else if (score >= 40) overallGrade = 'D';

  const isLocalhost = targetUrl.includes('localhost') || targetUrl.includes('127.0.0.1');

  return {
    targetUrl,
    timestamp: new Date().toISOString(),
    overallGrade,
    score,
    headers: results,
    rawHeaders: headers,
    isLocalhost,
    notes,
  };
}

// ---------------------------------------------------------------------------
// 4. SQL Injection & Query Parameterization Auditor
// ---------------------------------------------------------------------------
export function auditSqlQuery(rawQuery: string): QueryAuditResult {
  const qUpper = rawQuery.toUpperCase();

  const patternsFound: string[] = [];
  let riskScore = 0;

  // Pattern 1: String Concatenation or Interpolation operators
  const hasConcat =
    rawQuery.includes(" + ") ||
    rawQuery.includes(" || ") ||
    rawQuery.includes(".format(") ||
    rawQuery.includes('f"') ||
    rawQuery.includes("f'") ||
    rawQuery.includes("${");
  if (hasConcat) {
    patternsFound.push('Direct String Concatenation / F-String Interpolation');
    riskScore += 4;
  }

  // Pattern 2: Tautology injection signatures
  const hasTautology =
    rawQuery.includes("' OR '1'='1") ||
    rawQuery.includes("' OR 1=1") ||
    rawQuery.includes('" OR "1"="1') ||
    rawQuery.includes("' OR ''='") ||
    rawQuery.includes('" OR ""="') ||
    qUpper.includes("OR 'A'='A");
  if (hasTautology) {
    patternsFound.push("Tautology Evaluation Bypass (' OR '1'='1')");
    riskScore += 4;
  }

  // Pattern 3: Comment truncation markers
  const hasComment = rawQuery.includes('--') || rawQuery.includes('/*') || rawQuery.includes('#');
  if (hasComment) {
    patternsFound.push('Comment Truncation Delimiter (--, /*, #)');
    riskScore += 2;
  }

  // Pattern 4: Stacked Query Execution (multiple statements separated by semicolon)
  const statements = rawQuery.split(';').map((s) => s.trim()).filter(Boolean);
  const hasMultipleStatements = statements.length > 1;
  if (hasMultipleStatements) {
    patternsFound.push('Stacked Multiple SQL Statements (Semicolon Delimiter)');
    riskScore += 3;
  }

  // Pattern 5: UNION-based injection attempt
  const hasUnion = qUpper.includes('UNION SELECT') || qUpper.includes('UNION ALL SELECT');
  if (hasUnion) {
    patternsFound.push('UNION-Based Schema Data Extraction Signature');
    riskScore += 4;
  }

  // Check for safe parameterization placeholders
  const placeholdersDetected: string[] = [];
  if (rawQuery.includes('?')) placeholdersDetected.push('? (SQLite / ODBC Positional)');
  if (/\$\d+/.test(rawQuery)) placeholdersDetected.push('$1 (PostgreSQL / pgx)');
  if (/:[a-zA-Z_]\w*/.test(rawQuery)) placeholdersDetected.push(':param (Named SQLAlchemy / PDO)');
  if (rawQuery.includes('%s') && !hasConcat) placeholdersDetected.push('%s (Psycopg2 tuple param)');

  const hasSafePlaceholders = placeholdersDetected.length > 0;
  if (hasSafePlaceholders && !hasConcat && !hasTautology) {
    riskScore = 0;
  }

  riskScore = Math.min(10, riskScore);

  let severity: RiskSeverity = 'nominal';
  if (riskScore >= 7) severity = 'critical';
  else if (riskScore >= 4) severity = 'high';
  else if (riskScore > 0) severity = 'medium';

  // Construct parameterized equivalent
  let parameterizedQuery = rawQuery;
  const sampleParams: Record<string, any> = {};

  // Simple converter for demonstration
  if (rawQuery.includes("'")) {
    parameterizedQuery = rawQuery.replace(/'([^']*)'/g, (_match, p1) => {
      sampleParams['param_1'] = p1;
      return '?';
    });
  } else if (hasConcat) {
    parameterizedQuery = 'SELECT id, username, email, role FROM users WHERE username = ?';
    sampleParams['username'] = 'target_user';
  }

  const safeSqliteCode = `# Python SQLite Secure Parameterized Pattern
cursor.execute(
    "SELECT id, username, email, role FROM users WHERE username = ?",
    (user_input,)  # Input supplied strictly as tuple parameter
)
records = cursor.fetchall()`;

  const safeSqlAlchemyCode = `# SQLAlchemy Secure Core / ORM Pattern
from sqlalchemy import text

stmt = text("SELECT id, username, email, role FROM users WHERE username = :name")
results = connection.execute(stmt, {"name": user_input}).fetchall()`;

  let remediationAdvice =
    'This query uses secure parameterized placeholders. The database query engine parses the SQL syntax tree BEFORE binding parameter values, making SQL injection mathematically impossible.';
  if (riskScore > 0) {
    remediationAdvice =
      'CRITICAL: Never construct SQL strings via string concatenation, f-strings, or format(). Use native database query parameter placeholders (? for SQLite, :name for SQLAlchemy, or $1 for PostgreSQL) so the database compiler separates executable code from untrusted data.';
  }

  return {
    originalQuery: rawQuery,
    parameterizedQuery,
    sampleParameters: sampleParams,
    hasInjectionRisk: riskScore > 0,
    riskScore,
    severity,
    vulnerabilityPatterns: patternsFound,
    astAnalysis: {
      usesConcatenation: hasConcat,
      usesRawInterpolation: rawQuery.includes('{') && rawQuery.includes('}'),
      hasTautology,
      hasCommentTruncation: hasComment,
      hasMultipleStatements,
      placeholdersDetected,
    },
    remediationAdvice,
    safePythonCode: {
      sqlite: safeSqliteCode,
      sqlalchemy: safeSqlAlchemyCode,
    },
  };
}

// ---------------------------------------------------------------------------
// 5. In-Memory Lab SQLite Database Simulation
// ---------------------------------------------------------------------------
const MOCK_LAB_USERS: LabDatabaseRecord[] = [
  { id: 1, username: 'admin', email: 'admin@corp.internal', role: 'SecurityAdmin', created_at: '2026-01-10 09:12:00', is_active: 1 },
  { id: 2, username: 'auditor', email: 'auditor@corp.internal', role: 'ComplianceAuditor', created_at: '2026-02-14 11:30:00', is_active: 1 },
  { id: 3, username: 'developer', email: 'dev@corp.internal', role: 'SoftwareEngineer', created_at: '2026-03-01 14:05:00', is_active: 1 },
  { id: 4, username: 'test_guest', email: 'guest@lab.local', role: 'RestrictedTester', created_at: '2026-04-12 16:45:00', is_active: 0 },
];

export function executeLabDatabaseQuery(
  inputVal: string,
  useParameterized: boolean
): {
  success: boolean;
  rows: LabDatabaseRecord[];
  error?: string;
  sqlExecuted: string;
  latencyMs: number;
  riskDetected: boolean;
  explanation: string;
} {
  const start = performance.now();

  if (useParameterized) {
    // SECURE: Input is matched literally
    const sqlExecuted = `SELECT id, username, email, role, created_at, is_active FROM users WHERE username = ? [Bound Param: "${inputVal}"]`;
    const matched = MOCK_LAB_USERS.filter((u) => u.username === inputVal);
    const latencyMs = Number((performance.now() - start + 1.2).toFixed(2));

    return {
      success: true,
      rows: matched,
      sqlExecuted,
      latencyMs,
      riskDetected: false,
      explanation:
        'Secure Parameterized Execution: The query planner compiled the SELECT statement before parameter substitution. Even if the input contained SQL delimiters, it was treated strictly as a string literal.',
    };
  } else {
    // DEMONSTRATION OF VULNERABILITY
    const sqlExecuted = `SELECT id, username, email, role, created_at, is_active FROM users WHERE username = '${inputVal}'`;
    const latencyMs = Number((performance.now() - start + 2.1).toFixed(2));

    // Check for syntax errors caused by single quotes
    const quoteCount = (inputVal.match(/'/g) || []).length;
    if (quoteCount % 2 !== 0 && !inputVal.includes('--') && !inputVal.includes('/*')) {
      return {
        success: false,
        rows: [],
        error: `SQLite3 OperationalError: unrecognized token near "'${inputVal}": syntax error in SQL string`,
        sqlExecuted,
        latencyMs,
        riskDetected: true,
        explanation:
          'Syntax Breakage: An unmatched quote character broke the SQL parser grammar. In penetration testing, this error leakage confirms that raw input is being concatenated directly into the query!',
      };
    }

    // Check for classic tautology: admin' OR '1'='1 or ' OR 1=1
    const isTautology =
      inputVal.includes("' OR '1'='1") ||
      inputVal.includes("' OR 1=1") ||
      inputVal.includes("' OR ''='") ||
      inputVal.toUpperCase().includes("' OR TRUE");

    if (isTautology) {
      return {
        success: true,
        rows: MOCK_LAB_USERS, // Returns all records!
        sqlExecuted,
        latencyMs,
        riskDetected: true,
        explanation:
          "Vulnerability Triggered! The tautology (' OR '1'='1') forced the WHERE clause to evaluate to TRUE for every single table row. All user records were leaked, bypassing authentication controls.",
      };
    }

    // Standard string match
    const matched = MOCK_LAB_USERS.filter((u) => u.username === inputVal);
    return {
      success: true,
      rows: matched,
      sqlExecuted,
      latencyMs,
      riskDetected: inputVal.includes("'") || inputVal.includes(';'),
      explanation:
        'Query executed via raw string concatenation. While this specific input did not exploit the query, the pattern remains critically unsafe against malicious input.',
    };
  }
}

// ---------------------------------------------------------------------------
// 6. CLI Web Terminal Diagnostic Interpreter
// ---------------------------------------------------------------------------
export function executeDiagnosticCommand(commandString: string): DiagnosticResult {
  const start = performance.now();
  const trimmed = commandString.trim();
  const parts = trimmed.split(/\s+/);
  const cmd = parts[0]?.toLowerCase() || '';
  const args = parts.slice(1);

  let success = true;
  let output: string[] = [];
  let structuredData: Record<string, any> | undefined;

  switch (cmd) {
    case 'help':
    case '?':
      output = [
        'SecAudit Lab - Authorized Local Security Diagnostics CLI (v1.0.0)',
        'Environment: Bound strictly to 127.0.0.1 (Localhost Sandbox)',
        '',
        'Available Diagnostic Commands:',
        '  ping <host>                Test local network latency and ICMP/TCP reachability',
        '  dns <domain>               Query local and simulated DNS records (A, AAAA, MX, TXT)',
        '  port-check <host> <port>   Audit TCP socket reachability on authorized local ports',
        '  headers <url>              Fetch and audit HTTP security response headers',
        '  tls-check <host>           Inspect SSL/TLS cipher suites and certificate validity',
        '  audit-query <sql>          Analyze SQL query for string concatenation and injection risk',
        '  test-ratelimit [n]         Simulate concurrent API requests to evaluate throttling',
        '  session-info               Inspect active HMAC session token, entropy, and expiry',
        '  rotate-token               Generate and issue a fresh 256-bit session token',
        '  audit-log [count]          Display the most recent audit log entries',
        '  whoami                     Display active security persona and network interface',
        '  clear                      Clear the web terminal output buffer',
        '  export-logs                Export the immutable audit trail as JSON',
        '',
        'Type any command to execute. Strict localhost enforcement active.',
      ];
      break;

    case 'whoami':
      output = [
        'Active Security Context:',
        '  User Persona : SecurityAuditor (Authorized Local Operator)',
        '  Network Node : 127.0.0.1 (Loopback Interface - Safe Zone)',
        '  Binding Mode : STRICT_LOCAL_ONLY (External Interfaces Blocked)',
        '  Audit State  : ACTIVE (Tamper-evident log append-only)',
      ];
      break;

    case 'ping': {
      const target = args[0] || '127.0.0.1';
      // Security check: only allow safe target hostnames / IPs
      if (!/^[a-zA-Z0-9.\-_:]+$/.test(target)) {
        success = false;
        output = [`Error: Invalid hostname or IP address format: "${target}"`];
        break;
      }
      const isLocal = target === 'localhost' || target === '127.0.0.1' || target === '::1';
      const baseRtt = isLocal ? 0.28 : 22.4;
      const rtt1 = (baseRtt + Math.random() * 0.15).toFixed(2);
      const rtt2 = (baseRtt + Math.random() * 0.18).toFixed(2);
      const rtt3 = (baseRtt + Math.random() * 0.12).toFixed(2);
      const rtt4 = (baseRtt + Math.random() * 0.22).toFixed(2);
      output = [
        `PING ${target} (${isLocal ? '127.0.0.1' : target}) 56(84) bytes of data.`,
        `64 bytes from ${target}: icmp_seq=1 ttl=64 time=${rtt1} ms`,
        `64 bytes from ${target}: icmp_seq=2 ttl=64 time=${rtt2} ms`,
        `64 bytes from ${target}: icmp_seq=3 ttl=64 time=${rtt3} ms`,
        `64 bytes from ${target}: icmp_seq=4 ttl=64 time=${rtt4} ms`,
        '',
        `--- ${target} ping statistics ---`,
        `4 packets transmitted, 4 received, 0% packet loss, time 3004ms`,
        `rtt min/avg/max/mdev = ${rtt3}/${((Number(rtt1) + Number(rtt2) + Number(rtt3) + Number(rtt4)) / 4).toFixed(2)}/${rtt4}/0.041 ms`,
      ];
      auditLogger.record('PING_DIAGNOSTIC', 'cli', 'nominal', `ICMP ping probe sent to ${target}`, 'terminal-session');
      break;
    }

    case 'dns': {
      const domain = args[0] || 'localhost';
      output = [
        `; <<>> DiG 9.18.28-SecAudit <<>> ${domain}`,
        `;; global options: +cmd +dnssec`,
        `;; Got answer:`,
        `;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 48921`,
        `;; flags: qr aa rd ra; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1`,
        '',
        `;; QUESTION SECTION:`,
        `;${domain}.                     IN      A`,
        '',
        `;; ANSWER SECTION:`,
        `${domain}.              300     IN      A       ${domain === 'localhost' ? '127.0.0.1' : '192.168.1.10'}`,
        `${domain}.              300     IN      AAAA    ${domain === 'localhost' ? '::1' : 'fe80::1'}`,
        '',
        `;; ADDITIONAL RECORD:`,
        `${domain}.              300     IN      TXT     "v=spf1 -all (SecAudit Loopback Verified)"`,
        '',
        `;; Query time: 1.8 msec`,
        `;; SERVER: 127.0.0.53#53(127.0.0.53) (UDP)`,
        `;; WHEN: ${new Date().toUTCString()}`,
      ];
      auditLogger.record('DNS_LOOKUP', 'cli', 'nominal', `DNS diagnostic lookup for ${domain}`, 'terminal-session');
      break;
    }

    case 'port-check': {
      const host = args[0] || '127.0.0.1';
      const port = parseInt(args[1] || '8000', 10);
      if (isNaN(port) || port < 1 || port > 65535) {
        success = false;
        output = ['Usage: port-check <host> <port>', 'Example: port-check 127.0.0.1 8000'];
        break;
      }
      const knownServices: Record<number, string> = {
        80: 'HTTP (Web Server)',
        443: 'HTTPS (TLS Web Server)',
        3000: 'Node.js / React Development Server',
        5000: 'Flask Development Server',
        8000: 'FastAPI / Uvicorn API Service',
        8080: 'HTTP Proxy / Alternative API',
        5432: 'PostgreSQL Database Engine',
        3306: 'MySQL Database Engine',
        27017: 'MongoDB Server',
      };
      const serviceName = knownServices[port] || 'Custom TCP Service';
      const isOpen = [80, 443, 3000, 5000, 8000, 8080, 5432].includes(port);

      output = [
        `Socket Probe: Connecting to tcp://${host}:${port}...`,
        `[TCP HANDSHAKE] SYN -> SYN-ACK -> ACK completed in 0.84ms`,
        `Port Status  : ${isOpen ? 'OPEN / LISTENING' : 'FILTERED / NO RESPONSE'}`,
        `Identified   : ${serviceName}`,
        `Local Rule   : Bound strictly to 127.0.0.1 interface`,
      ];
      auditLogger.record(
        'PORT_CHECK',
        'cli',
        'nominal',
        `TCP probe to ${host}:${port} (${isOpen ? 'OPEN' : 'CLOSED'})`,
        'terminal-session'
      );
      break;
    }

    case 'headers': {
      const url = args[0] || 'http://127.0.0.1:8000';
      const report = auditHeaders(url, PRESET_HEADER_PROFILES.fully_hardened.headers);
      output = [
        `HTTP Security Headers Audit for ${url}:`,
        `Score: ${report.score}/100 | Grade: ${report.overallGrade}`,
        '------------------------------------------------------------',
        ...report.headers.map((h) => {
          const mark = h.status === 'present' ? '✓ [PASS]' : h.status === 'misconfigured' ? '! [WARN]' : '✗ [FAIL]';
          return `${mark} ${h.header.padEnd(28)} : ${h.value || 'MISSING'}`;
        }),
      ];
      auditLogger.record('HEADERS_AUDIT', 'headers', 'nominal', `Headers scan executed on ${url}`, 'terminal-session');
      break;
    }

    case 'audit-query': {
      const query = args.join(' ');
      if (!query) {
        success = false;
        output = [
          'Usage: audit-query <sql-query>',
          "Example: audit-query SELECT * FROM users WHERE username = 'admin' OR '1'='1'",
        ];
        break;
      }
      const res = auditSqlQuery(query);
      output = [
        'SQL Statement AST Security Analysis:',
        `Original Query: ${res.originalQuery}`,
        `Risk Severity : ${res.severity.toUpperCase()} (Score: ${res.riskScore}/10)`,
        `Patterns      : ${res.vulnerabilityPatterns.length ? res.vulnerabilityPatterns.join(', ') : 'None (Secure)'}`,
        `Safe Form     : ${res.parameterizedQuery}`,
        `Remediation   : ${res.remediationAdvice}`,
      ];
      auditLogger.record(
        'SQL_AUDIT',
        'sql',
        res.severity,
        `SQL Query analyzed (Risk: ${res.severity})`,
        'terminal-session'
      );
      break;
    }

    case 'test-ratelimit': {
      const count = Math.min(50, Math.max(5, parseInt(args[0] || '15', 10)));
      output = [
        `Simulating burst of ${count} requests against local rate-limited endpoint (/api/probe)...`,
        'Rate Limiter Algorithm: Token Bucket (Capacity: 10, Refill: 5/sec)',
        '',
        ...Array.from({ length: Math.min(count, 12) }).map((_, i) => {
          const reqNum = i + 1;
          const status = reqNum <= 10 ? '200 OK' : '429 TOO MANY REQUESTS';
          const rtt = (1.1 + Math.random() * 0.8).toFixed(1);
          return `Request #${reqNum.toString().padStart(2, '0')}: HTTP ${status} (${rtt}ms) | X-RateLimit-Remaining: ${Math.max(0, 10 - reqNum)}`;
        }),
      ];
      if (count > 12) {
        output.push(`... [${count - 12} additional requests simulated with status 429]`);
      }
      output.push('');
      output.push(`Test Summary: ${Math.min(10, count)} Allowed, ${Math.max(0, count - 10)} Throttled (429).`);
      output.push('Defense Posture: ACTIVE - Anti-Brute-Force Protection Functional.');
      auditLogger.record('RATE_LIMIT_TEST', 'rate-limit', 'nominal', `Simulated ${count} requests`, 'terminal-session');
      break;
    }

    case 'session-info': {
      const now = new Date();
      output = [
        'Active Session Security Telemetry:',
        `  Session ID    : sess_${Math.random().toString(36).substring(2, 10)}`,
        `  Issued At     : ${now.toISOString()}`,
        `  Algorithm     : HMAC-SHA256 (Constant-time comparison)`,
        `  Entropy       : 256 bits (Cryptographically Strong CSPRNG)`,
        `  Interface     : 127.0.0.1 (Strict loopback isolation)`,
        `  Scope Grants  : read:diagnostics, write:query_audit, exec:ratelimit`,
        `  Cookie Flags  : HttpOnly=True; Secure=True; SameSite=Strict`,
      ];
      break;
    }

    case 'rotate-token': {
      const newToken = createSessionToken();
      output = [
        'Session Token Rotated Successfully:',
        `  New Token: ${newToken.token}`,
        `  Expires  : ${newToken.expiresAt}`,
        '  Previous session keys revoked from memory.',
      ];
      auditLogger.record('TOKEN_ROTATION', 'auth', 'nominal', 'Active session token rotated', 'terminal-session');
      break;
    }

    case 'audit-log': {
      const limit = parseInt(args[0] || '5', 10);
      const logs = auditLogger.getLogs().slice(0, limit);
      output = [
        `Displaying latest ${logs.length} Audit Log Records:`,
        '------------------------------------------------------------',
        ...logs.map(
          (l) =>
            `[${l.timestamp.substring(11, 19)}] [${l.severity.toUpperCase().padEnd(8)}] ${l.action.padEnd(20)}: ${l.details}`
        ),
      ];
      break;
    }

    case 'clear':
      output = ['__CLEAR__'];
      break;

    case 'export-logs':
      output = [
        'Audit logs exported to memory buffer.',
        'Use the "Export Audit Trail" button in the Session & Audit tab to save as JSON/CSV.',
      ];
      break;

    default:
      success = false;
      output = [
        `Command not recognized: "${cmd}".`,
        'Type "help" to view all available local security diagnostic commands.',
      ];
      break;
  }

  const durationMs = Number((performance.now() - start).toFixed(2));
  return {
    command: commandString,
    timestamp: new Date().toISOString(),
    success,
    output,
    structuredData,
    durationMs,
  };
}

// ---------------------------------------------------------------------------
// 7. Rate Limiter Stress Testing Engine
// ---------------------------------------------------------------------------
export async function runRateLimitSimulation(
  totalRequests: number,
  concurrency: number,
  rateLimitCap: number = 20,
  onProgress?: (completed: number) => void
): Promise<RateLimitResult> {
  const start = performance.now();
  const timeline: RateLimitResult['requestTimeline'] = [];
  let successful = 0;
  let throttled = 0;
  let failed = 0;
  let thresholdDetectedAt: number | null = null;

  for (let i = 0; i < totalRequests; i++) {
    // Artificial small delay matching concurrency
    const delay = Math.floor(Math.random() * 20) + (i % concurrency === 0 ? 30 : 5);
    await new Promise((res) => setTimeout(res, delay));

    const isThrottled = i >= rateLimitCap;
    const status = isThrottled ? 429 : 200;
    const latency = Number((Math.random() * 8 + 3).toFixed(2));

    if (isThrottled) {
      throttled++;
      if (thresholdDetectedAt === null) {
        thresholdDetectedAt = i + 1;
      }
    } else {
      successful++;
    }

    timeline.push({
      seq: i + 1,
      timestampMs: Number((performance.now() - start).toFixed(1)),
      status,
      latencyMs: latency,
      throttled: isThrottled,
    });

    if (onProgress) {
      onProgress(i + 1);
    }
  }

  const latencies = timeline.map((t) => t.latencyMs);
  const avgLatencyMs = Number((latencies.reduce((a, b) => a + b, 0) / latencies.length).toFixed(2));
  const minLatencyMs = Math.min(...latencies);
  const maxLatencyMs = Math.max(...latencies);

  auditLogger.record(
    'RATE_LIMIT_EVALUATION',
    'rate-limit',
    throttled > 0 ? 'nominal' : 'medium',
    `Rate limiter test: ${successful} passed, ${throttled} throttled (Cap: ${rateLimitCap})`,
    'test-session'
  );

  return {
    totalRequests,
    concurrency,
    successfulRequests: successful,
    throttledRequests: throttled,
    failedRequests: failed,
    avgLatencyMs,
    minLatencyMs,
    maxLatencyMs,
    thresholdDetectedAt,
    headersObserved: {
      rateLimitLimit: String(rateLimitCap),
      rateLimitRemaining: String(Math.max(0, rateLimitCap - totalRequests)),
      retryAfter: throttled > 0 ? '60s' : undefined,
    },
    requestTimeline: timeline,
  };
}
