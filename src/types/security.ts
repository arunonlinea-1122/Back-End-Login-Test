export type RiskSeverity = 'critical' | 'high' | 'medium' | 'low' | 'nominal';

export interface AuditLogEntry {
  id: string;
  timestamp: string;
  action: string;
  category: 'cli' | 'headers' | 'api' | 'sql' | 'rate-limit' | 'auth' | 'system';
  severity: RiskSeverity;
  details: string;
  clientIp: string;
  sessionId: string;
  status: 'allowed' | 'blocked' | 'flagged' | 'success';
}

export interface SecurityHeaderResult {
  header: string;
  status: 'present' | 'missing' | 'misconfigured';
  value: string | null;
  recommendedValue: string;
  severity: RiskSeverity;
  description: string;
  exploitRisk: string;
  fixSnippet: {
    fastapi: string;
    flask: string;
    express: string;
  };
}

export interface HeaderAuditReport {
  targetUrl: string;
  timestamp: string;
  overallGrade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';
  score: number; // 0-100
  headers: SecurityHeaderResult[];
  rawHeaders: Record<string, string>;
  isLocalhost: boolean;
  notes: string[];
}

export interface QueryAuditResult {
  originalQuery: string;
  parameterizedQuery: string;
  sampleParameters: Record<string, any>;
  hasInjectionRisk: boolean;
  riskScore: number; // 0 to 10
  severity: RiskSeverity;
  vulnerabilityPatterns: string[];
  astAnalysis: {
    usesConcatenation: boolean;
    usesRawInterpolation: boolean;
    hasTautology: boolean;
    hasCommentTruncation: boolean;
    hasMultipleStatements: boolean;
    placeholdersDetected: string[];
  };
  remediationAdvice: string;
  safePythonCode: {
    sqlite: string;
    sqlalchemy: string;
  };
}

export interface DiagnosticResult {
  command: string;
  timestamp: string;
  success: boolean;
  output: string[];
  structuredData?: Record<string, any>;
  durationMs: number;
}

export interface RateLimitResult {
  totalRequests: number;
  concurrency: number;
  successfulRequests: number;
  throttledRequests: number; // 429
  failedRequests: number;
  avgLatencyMs: number;
  minLatencyMs: number;
  maxLatencyMs: number;
  thresholdDetectedAt: number | null;
  headersObserved: {
    rateLimitLimit?: string;
    rateLimitRemaining?: string;
    retryAfter?: string;
  };
  requestTimeline: Array<{
    seq: number;
    timestampMs: number;
    status: number;
    latencyMs: number;
    throttled: boolean;
  }>;
}

export interface SessionTokenState {
  token: string;
  createdAt: string;
  expiresAt: string;
  algorithm: string;
  entropyBits: number;
  scope: string[];
  issuer: string;
  isBoundToLocalhost: boolean;
  isValid: boolean;
}

export interface LabDatabaseRecord {
  id: number;
  username: string;
  email: string;
  role: string;
  created_at: string;
  is_active: number;
}
