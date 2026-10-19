import React, { useState } from 'react';
import { Shield, Terminal, Database, Activity, Lock, Code2, FileCode, CheckCircle2 } from 'lucide-react';
import { TopNav } from './components/TopNav';
import { TerminalView } from './components/TerminalView';
import { HeadersAuditView } from './components/HeadersAuditView';
import { ApiSecurityView } from './components/ApiSecurityView';
import { DatabaseAuditorView } from './components/DatabaseAuditorView';
import { RateLimitView } from './components/RateLimitView';
import { SessionAuditView } from './components/SessionAuditView';
import { PythonLabView } from './components/PythonLabView';
import { createSessionToken, auditLogger } from './services/securityEngine';
import { SessionTokenState } from './types/security';

export default function App() {
  const [activeTab, setActiveTab] = useState<string>('terminal');
  const [sessionToken, setSessionToken] = useState<SessionTokenState>(() => createSessionToken());

  const handleRotateToken = () => {
    const newToken = createSessionToken();
    setSessionToken(newToken);
    auditLogger.record(
      'SESSION_TOKEN_ROTATED',
      'auth',
      'nominal',
      `Session token rotated (new entropy: ${newToken.entropyBits} bits)`,
      newToken.token.substring(0, 10),
      'allowed'
    );
  };

  const getBreadcrumb = () => {
    switch (activeTab) {
      case 'terminal':
        return 'Diagnostics / Central CLI Terminal';
      case 'headers':
        return 'Vulnerability Assessment / HTTP Security Headers';
      case 'api_security':
        return 'Endpoint Testing / Input Sanitization & Fuzzing';
      case 'database':
        return 'Database Security / SQLite Prepared Statement Auditor';
      case 'rate_limiting':
        return 'Resilience / Rate-Limiting & Anti-Brute-Force';
      case 'session_audit':
        return 'Compliance / Localhost Enforcement & Forensic Audit Trail';
      case 'python_sources':
        return 'Laboratory Hub / Python FastAPI & Flask Production Source Code';
      default:
        return 'SecAudit Lab';
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-cyan-500/20 selection:text-cyan-200">
      {/* Top Bar following Top Bar Contract */}
      <TopNav
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        sessionToken={sessionToken.token}
        onRotateToken={handleRotateToken}
        onOpenPythonLab={() => setActiveTab('python_sources')}
      />

      {/* Breadcrumb & Security Posture Sub-bar */}
      <div className="bg-slate-900/60 border-b border-slate-800/80 px-6 py-2.5">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs">
          <div className="flex items-center gap-2 text-slate-400 font-mono">
            <span className="text-slate-500">SecAudit Lab</span>
            <span>/</span>
            <span className="text-cyan-300 font-semibold">{getBreadcrumb()}</span>
          </div>

          <div className="flex items-center gap-4 text-[11px] text-slate-400 font-mono">
            <span className="flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
              <span>127.0.0.1 (Loopback Bound)</span>
            </span>
            <span aria-hidden="true" className="text-slate-700 hidden sm:inline">·</span>
            <span className="hidden sm:inline">HMAC-SHA256 Auth</span>
            <span aria-hidden="true" className="text-slate-700 hidden sm:inline">·</span>
            <span className="hidden sm:inline">Audit Logging: Active</span>
          </div>
        </div>
      </div>

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 py-6">
        {activeTab === 'terminal' && <TerminalView />}
        {activeTab === 'headers' && <HeadersAuditView />}
        {activeTab === 'api_security' && <ApiSecurityView />}
        {activeTab === 'database' && <DatabaseAuditorView />}
        {activeTab === 'rate_limiting' && <RateLimitView />}
        {activeTab === 'session_audit' && (
          <SessionAuditView
            sessionToken={sessionToken}
            onRotateToken={handleRotateToken}
          />
        )}
        {activeTab === 'python_sources' && <PythonLabView />}
      </main>

      {/* Minimalistic, Quiet Footer */}
      <footer className="border-t border-slate-900 bg-slate-950/80 py-4 px-6 text-xs text-slate-500">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <span className="text-slate-400 font-semibold">SecAudit Lab</span>
            <span>·</span>
            <span>Local Backend Penetration Testing & Vulnerability Assessment Platform</span>
          </div>
          <div className="flex items-center gap-3 font-mono text-[11px]">
            <span>Ethical Hacking Education</span>
            <span>·</span>
            <span>OWASP ASVS Standard</span>
            <span>·</span>
            <span className="text-slate-400">Strict Localhost 127.0.0.1</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
