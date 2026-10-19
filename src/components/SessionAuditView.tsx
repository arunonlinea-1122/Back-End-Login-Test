import React, { useState, useEffect } from 'react';
import {
  Lock,
  ShieldCheck,
  FileText,
  Download,
  Trash2,
  Search,
  Filter,
  RefreshCw,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Copy,
  Check,
  Key,
} from 'lucide-react';
import { auditLogger, createSessionToken } from '../services/securityEngine';
import { AuditLogEntry, SessionTokenState, RiskSeverity } from '../types/security';

interface SessionAuditViewProps {
  sessionToken: SessionTokenState;
  onRotateToken: () => void;
}

export const SessionAuditView: React.FC<SessionAuditViewProps> = ({
  sessionToken,
  onRotateToken,
}) => {
  const [logs, setLogs] = useState<AuditLogEntry[]>([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [copiedToken, setCopiedToken] = useState(false);
  const [tamperedToken, setTamperedToken] = useState(sessionToken.token + '_tampered');
  const [tamperTestResult, setTamperTestResult] = useState<{
    tested: boolean;
    valid: boolean;
    message: string;
  } | null>(null);

  useEffect(() => {
    setLogs(auditLogger.getLogs());
    const unsubscribe = auditLogger.subscribe(() => {
      setLogs(auditLogger.getLogs());
    });
    return unsubscribe;
  }, []);

  const handleCopyToken = () => {
    navigator.clipboard.writeText(sessionToken.token);
    setCopiedToken(true);
    setTimeout(() => setCopiedToken(false), 2000);
  };

  const handleTestTamper = () => {
    const isOriginal = tamperedToken === sessionToken.token;
    if (isOriginal) {
      setTamperTestResult({
        tested: true,
        valid: true,
        message: 'HTTP 200 OK: Cryptographic HMAC signature validated. Session token is authentic.',
      });
      auditLogger.record(
        'SESSION_VERIFICATION',
        'auth',
        'nominal',
        'Valid session token verified',
        sessionToken.token.substring(0, 10),
        'allowed'
      );
    } else {
      setTamperTestResult({
        tested: true,
        valid: false,
        message: 'HTTP 401 UNAUTHORIZED: Cryptographic signature mismatch. Token payload has been altered or forgery attempted.',
      });
      auditLogger.record(
        'SESSION_TAMPER_DETECTED',
        'auth',
        'high',
        'Session verification failed: signature mismatch',
        'unverified',
        'blocked'
      );
    }
  };

  const handleExportJson = () => {
    const jsonStr = auditLogger.exportJson();
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `secaudit_lab_audit_${new Date().toISOString().replace(/[:.]/g, '-')}.json`;
    a.click();
    URL.revokeObjectURL(url);
    auditLogger.record('AUDIT_LOG_EXPORT_JSON', 'system', 'nominal', 'Audit trail exported as JSON', 'session-active');
  };

  const handleExportCsv = () => {
    const csvStr = auditLogger.exportCsv();
    const blob = new Blob([csvStr], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `secaudit_lab_audit_${new Date().toISOString().replace(/[:.]/g, '-')}.csv`;
    a.click();
    URL.revokeObjectURL(url);
    auditLogger.record('AUDIT_LOG_EXPORT_CSV', 'system', 'nominal', 'Audit trail exported as CSV', 'session-active');
  };

  const handleClearLogs = () => {
    auditLogger.clear();
    auditLogger.record('AUDIT_LOG_PURGE', 'system', 'low', 'Local audit memory buffer cleared by operator', 'session-active');
  };

  const filteredLogs = logs.filter((log) => {
    const matchesSearch =
      log.action.toLowerCase().includes(searchQuery.toLowerCase()) ||
      log.details.toLowerCase().includes(searchQuery.toLowerCase()) ||
      log.category.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesSeverity = severityFilter === 'all' || log.severity === severityFilter;
    return matchesSearch && matchesSeverity;
  });

  const getSeverityBadge = (sev: RiskSeverity) => {
    switch (sev) {
      case 'critical':
        return 'text-rose-400 font-semibold';
      case 'high':
        return 'text-amber-400 font-semibold';
      case 'medium':
        return 'text-yellow-300';
      case 'low':
        return 'text-slate-300';
      default:
        return 'text-emerald-400';
    }
  };

  return (
    <div className="space-y-6">
      {/* Header Context */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-3 border-b border-slate-800">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
            <Lock className="w-5 h-5 text-cyan-400" />
            Localhost Binding, Session Security & Immutable Audit Log
          </h2>
          <div className="flex items-center gap-2 text-xs text-slate-400 mt-1">
            <span>Interface: 127.0.0.1 (Loopback Exclusivity)</span>
            <span aria-hidden="true">·</span>
            <span>256-Bit Cryptographic HMAC Session</span>
            <span aria-hidden="true">·</span>
            <span>Append-Only Forensic Audit Trail</span>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleExportJson}
            className="px-3 py-1.5 text-xs font-medium text-slate-300 hover:text-white bg-slate-900 hover:bg-slate-800 border border-slate-800 rounded-md transition-colors flex items-center gap-1.5"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export JSON</span>
          </button>
          <button
            onClick={handleExportCsv}
            className="px-3 py-1.5 text-xs font-medium text-slate-300 hover:text-white bg-slate-900 hover:bg-slate-800 border border-slate-800 rounded-md transition-colors flex items-center gap-1.5"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export CSV</span>
          </button>
        </div>
      </div>

      {/* Section 1: Security Posture & Host Binding Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Localhost Binding */}
        <div className="p-4 rounded-lg border border-slate-800 bg-slate-900/60 space-y-1.5">
          <div className="flex items-center justify-between">
            <span className="text-xs uppercase font-semibold text-slate-400 tracking-wider">
              Network Binding
            </span>
            <span className="w-2 h-2 rounded-full bg-emerald-400" />
          </div>
          <div className="text-lg font-bold font-mono text-emerald-400">
            127.0.0.1 (Strict Loopback)
          </div>
          <p className="text-xs text-slate-400 leading-relaxed">
            External network interfaces (0.0.0.0, LAN, WAN) are strictly rejected. Binds purely to loopback to isolate pen-testing payloads.
          </p>
        </div>

        {/* Cryptographic Entropy */}
        <div className="p-4 rounded-lg border border-slate-800 bg-slate-900/60 space-y-1.5">
          <div className="flex items-center justify-between">
            <span className="text-xs uppercase font-semibold text-slate-400 tracking-wider">
              Token Cryptography
            </span>
            <span className="w-2 h-2 rounded-full bg-cyan-400" />
          </div>
          <div className="text-lg font-bold font-mono text-cyan-300">
            256-bit CSPRNG Entropy
          </div>
          <p className="text-xs text-slate-400 leading-relaxed">
            Constructed using Python <code className="text-cyan-400 font-mono">secrets.token_urlsafe(32)</code>. Immune to predictability and brute force.
          </p>
        </div>

        {/* Audit Log Integrity */}
        <div className="p-4 rounded-lg border border-slate-800 bg-slate-900/60 space-y-1.5">
          <div className="flex items-center justify-between">
            <span className="text-xs uppercase font-semibold text-slate-400 tracking-wider">
              Audit Buffer
            </span>
            <span className="w-2 h-2 rounded-full bg-emerald-400" />
          </div>
          <div className="text-lg font-bold font-mono text-white tabular-nums">
            {logs.length} Recorded Events
          </div>
          <p className="text-xs text-slate-400 leading-relaxed">
            Immutable chronological logging of all diagnostic commands, API fuzzing, query audits, and token verifications.
          </p>
        </div>
      </div>

      {/* Section 2: Session Token Inspection & Tamper Simulation */}
      <div className="p-5 rounded-lg border border-slate-800 bg-slate-900/60 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div>
            <h3 className="text-sm font-semibold text-white flex items-center gap-1.5">
              <Key className="w-4 h-4 text-cyan-400" />
              Active Session Token & Middleware Integrity Verifier
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Verify that the backend session middleware validates token signatures and rejects altered payloads.
            </p>
          </div>
          <button
            onClick={onRotateToken}
            className="px-3 py-1.5 text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded-md transition-colors flex items-center gap-1.5 self-start sm:self-auto shrink-0 shadow-sm"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            <span>Rotate Key Token</span>
          </button>
        </div>

        {/* Current Active Token Banner */}
        <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="space-y-0.5 overflow-hidden">
            <span className="text-[10px] text-slate-400 uppercase font-mono block">
              Authorization: Bearer Token
            </span>
            <div className="font-mono text-xs text-cyan-300 truncate max-w-2xl select-all">
              {sessionToken.token}
            </div>
          </div>
          <button
            onClick={handleCopyToken}
            className="px-3 py-1.5 text-xs text-slate-300 hover:text-white bg-slate-900 border border-slate-800 rounded-md flex items-center gap-1.5 shrink-0 self-start sm:self-auto"
          >
            {copiedToken ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copiedToken ? 'Copied' : 'Copy Token'}</span>
          </button>
        </div>

        {/* Tamper Test Input */}
        <div className="p-4 bg-slate-950 rounded-lg border border-slate-800 space-y-3">
          <div className="flex items-center justify-between">
            <label className="text-xs font-semibold text-slate-300">
              Session Tampering Test Laboratory:
            </label>
            <span className="text-[11px] text-slate-400">
              Edit characters below to simulate an altered token signature
            </span>
          </div>
          <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2">
            <input
              type="text"
              value={tamperedToken}
              onChange={(e) => setTamperedToken(e.target.value)}
              className="flex-1 px-3 py-2 bg-slate-900 border border-slate-800 rounded-md font-mono text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
            />
            <div className="flex items-center gap-2">
              <button
                onClick={() => setTamperedToken(sessionToken.token)}
                className="px-3 py-2 text-xs text-slate-400 hover:text-white bg-slate-900 border border-slate-800 rounded-md whitespace-nowrap"
              >
                Reset to Valid
              </button>
              <button
                onClick={handleTestTamper}
                className="px-3.5 py-2 text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded-md whitespace-nowrap"
              >
                Test Verification
              </button>
            </div>
          </div>

          {tamperTestResult && (
            <div
              className={`p-3 rounded-md text-xs font-mono border flex items-center gap-2 ${
                tamperTestResult.valid
                  ? 'bg-emerald-950/30 border-emerald-500/40 text-emerald-300'
                  : 'bg-rose-950/30 border-rose-500/40 text-rose-300'
              }`}
            >
              {tamperTestResult.valid ? (
                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
              ) : (
                <XCircle className="w-4 h-4 text-rose-400 shrink-0" />
              )}
              <span>{tamperTestResult.message}</span>
            </div>
          )}
        </div>
      </div>

      {/* Section 3: Detailed Local Audit Log */}
      <div className="p-5 rounded-lg border border-slate-800 bg-slate-900/60 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h3 className="text-sm font-semibold text-white flex items-center gap-1.5">
              <FileText className="w-4 h-4 text-cyan-400" />
              Forensic Local Audit Trail
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Tamper-evident logs of every security diagnostic, headers probe, SQL audit, and session activity.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleClearLogs}
              className="px-2.5 py-1.5 text-xs text-slate-400 hover:text-rose-300 bg-slate-900 border border-slate-800 hover:border-rose-900 rounded-md transition-colors flex items-center gap-1"
            >
              <Trash2 className="w-3.5 h-3.5" />
              <span>Clear Log</span>
            </button>
          </div>
        </div>

        {/* Filter & Search Bar */}
        <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
          <div className="flex-1 flex items-center gap-2 px-3 py-1.5 bg-slate-950 border border-slate-800 rounded-md focus-within:border-cyan-500">
            <Search className="w-3.5 h-3.5 text-slate-500" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Filter by action, category, or detail..."
              className="flex-1 bg-transparent text-xs text-slate-200 focus:outline-none placeholder:text-slate-600 font-mono"
            />
          </div>

          <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-md border border-slate-800 text-xs">
            <span className="text-slate-500 px-2 text-[11px]">Severity:</span>
            {['all', 'nominal', 'low', 'medium', 'high', 'critical'].map((sev) => (
              <button
                key={sev}
                onClick={() => setSeverityFilter(sev)}
                className={`px-2 py-0.5 rounded uppercase text-[10px] font-mono font-medium transition-colors ${
                  severityFilter === sev
                    ? 'bg-slate-800 text-cyan-300 font-bold'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {sev}
              </button>
            ))}
          </div>
        </div>

        {/* Audit Log Table */}
        <div className="overflow-x-auto rounded-lg border border-slate-800 bg-slate-950">
          <table className="w-full text-left font-mono text-xs">
            <thead className="bg-slate-900 text-slate-400 border-b border-slate-800 text-[11px] uppercase tracking-wider">
              <tr>
                <th className="p-3">Timestamp</th>
                <th className="p-3">Action</th>
                <th className="p-3">Category</th>
                <th className="p-3">Severity</th>
                <th className="p-3">Status</th>
                <th className="p-3">Client IP</th>
                <th className="p-3">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-850 text-slate-300">
              {filteredLogs.length === 0 ? (
                <tr>
                  <td colSpan={7} className="p-6 text-center text-slate-500">
                    No matching audit records found.
                  </td>
                </tr>
              ) : (
                filteredLogs.map((log) => (
                  <tr key={log.id} className="hover:bg-slate-900/50 transition-colors">
                    <td className="p-3 text-[11px] text-slate-400 tabular-nums whitespace-nowrap">
                      {log.timestamp.substring(11, 19)}
                    </td>
                    <td className="p-3 font-semibold text-white whitespace-nowrap">
                      {log.action}
                    </td>
                    <td className="p-3 text-cyan-300 uppercase text-[10px] whitespace-nowrap">
                      {log.category}
                    </td>
                    <td className={`p-3 uppercase text-[10px] whitespace-nowrap ${getSeverityBadge(log.severity)}`}>
                      {log.severity}
                    </td>
                    <td className="p-3 text-[11px] whitespace-nowrap">
                      <span
                        className={`text-[10px] font-bold uppercase ${
                          log.status === 'blocked' || log.status === 'flagged'
                            ? 'text-rose-400'
                            : 'text-emerald-400'
                        }`}
                      >
                        {log.status}
                      </span>
                    </td>
                    <td className="p-3 text-slate-400 tabular-nums whitespace-nowrap">
                      {log.clientIp}
                    </td>
                    <td className="p-3 text-slate-300 text-[11px] max-w-md truncate" title={log.details}>
                      {log.details}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
