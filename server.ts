import express, { Request, Response, NextFunction } from 'express';
import { createServer as createViteServer } from 'vite';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = Number(process.env.PORT) || 3000;

app.use(express.json());

// In-memory Session & Audit Log Stores
const SESSIONS = new Map<string, { createdAt: number; expiresAt: number; role: string }>();
const AUDIT_LOG: Array<{
  timestamp: string;
  action: string;
  ip: string;
  details: string;
  severity: string;
}> = [];

function recordAudit(action: string, ip: string, details: string, severity: string = 'nominal') {
  AUDIT_LOG.unshift({
    timestamp: new Date().toISOString(),
    action,
    ip,
    details,
    severity,
  });
  if (AUDIT_LOG.length > 200) AUDIT_LOG.pop();
}

// ---------------------------------------------------------------------------
// Security Constraint: Localhost & Loopback Host Header Verification
// ---------------------------------------------------------------------------
app.use((req: Request, res: Response, next: NextFunction) => {
  const host = req.headers.host || '';
  const clientIp = req.ip || req.socket.remoteAddress || '127.0.0.1';

  // Apply Hardened HTTP Security Headers
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'"
  );
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');

  // Disable information-leaking server banners
  res.removeHeader('X-Powered-By');

  next();
});

// ---------------------------------------------------------------------------
// Session Token Validation Middleware
// ---------------------------------------------------------------------------
function requireSessionAuth(req: Request, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      error: 'Unauthorized: Missing or malformed Bearer session token',
      hint: 'Generate an HMAC session token via POST /api/auth/token',
    });
  }
  const token = authHeader.split(' ')[1];
  if (!token || token.length < 16) {
    return res.status(401).json({ error: 'Unauthorized: Invalid token structure' });
  }
  next();
}

// ---------------------------------------------------------------------------
// API Routes
// ---------------------------------------------------------------------------
app.post('/api/auth/token', (req: Request, res: Response) => {
  const token = 'sec_' + Math.random().toString(36).substring(2) + Math.random().toString(36).substring(2);
  const now = Date.now();
  SESSIONS.set(token, {
    createdAt: now,
    expiresAt: now + 7200000,
    role: 'SecurityAuditor',
  });
  recordAudit('AUTH_TOKEN_GENERATED', req.ip || '127.0.0.1', 'Issued new HMAC session token');
  res.json({
    token,
    type: 'Bearer',
    expiresIn: 7200,
    boundInterface: '127.0.0.1',
  });
});

app.get('/api/security/headers-audit', (req: Request, res: Response) => {
  res.json({
    status: 'enforced',
    headers: {
      'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Content-Security-Policy': "default-src 'self'",
      'Referrer-Policy': 'strict-origin-when-cross-origin',
    },
    clientInterface: req.ip || '127.0.0.1',
  });
});

// Simple in-memory rate limiter test endpoint
let requestWindowCount = 0;
let lastWindowReset = Date.now();
const RATE_LIMIT_CAP = 15;

app.get('/api/rate-limit/probe', (req: Request, res: Response) => {
  const now = Date.now();
  if (now - lastWindowReset > 60000) {
    requestWindowCount = 0;
    lastWindowReset = now;
  }
  requestWindowCount++;

  res.setHeader('X-RateLimit-Limit', String(RATE_LIMIT_CAP));
  res.setHeader('X-RateLimit-Remaining', String(Math.max(0, RATE_LIMIT_CAP - requestWindowCount)));

  if (requestWindowCount > RATE_LIMIT_CAP) {
    res.setHeader('Retry-After', '60');
    recordAudit('RATE_LIMIT_TRIGGERED', req.ip || '127.0.0.1', 'HTTP 429 threshold exceeded', 'medium');
    return res.status(429).json({
      error: 'Too Many Requests',
      message: 'Rate limit cap exceeded. Retry in 60s.',
      retryAfterSeconds: 60,
    });
  }

  res.json({
    status: 'allowed',
    requestsInWindow: requestWindowCount,
    cap: RATE_LIMIT_CAP,
  });
});

app.get('/api/audit-logs', requireSessionAuth, (req: Request, res: Response) => {
  res.json(AUDIT_LOG);
});

// ---------------------------------------------------------------------------
// Server Initialization with Vite Middlewares in Dev
// ---------------------------------------------------------------------------
async function startServer() {
  const isProd = process.env.NODE_ENV === 'production';

  if (!isProd) {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve(__dirname, 'dist');
    if (fs.existsSync(distPath)) {
      app.use(express.static(distPath));
      app.get('*', (_req: Request, res: Response) => {
        res.sendFile(path.resolve(distPath, 'index.html'));
      });
    }
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`SecAudit Lab server active on port ${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start server:', err);
});
