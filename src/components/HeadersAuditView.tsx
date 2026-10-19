import React, { useState } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  FileCode,
  Copy,
  Check,
  ExternalLink,
  RefreshCw,
  Info,
} from 'lucide-react';
import {
  auditHeaders,
  PRESET_HEADER_PROFILES,
  auditLogger,
} from '../services/securityEngine';
import { HeaderAuditReport, SecurityHeaderResult } from '../types/security';

export const HeadersAuditView: React.FC = () => {
  const [selectedPreset, setSelectedPreset] = useState<'fully_hardened' | 'partially_hardened' | 'unsecured'>('fully_hardened');
  const [targetUrl, setTargetUrl] = useState('http://127.0.0.1:8000/api/security/headers-audit');
  const [activeSnippetTab, setActiveSnippetTab] = useState<'fastapi' | 'flask' | 'express'>('fastapi');
  const [copiedHeader, setCopiedHeader] = useState<string | null>(null);

  const [report, setReport] = useState<HeaderAuditReport>(() =>
    auditHeaders('http://127.0.0.1:8000/api/security/headers-audit', PRESET_HEADER_PROFILES.fully_hardened.headers)
  );

  const handleRunAudit = (presetKey?: 'fully_hardened' | 'partially_hardened' | 'unsecured') => {
    const key = presetKey || selectedPreset;
    const profile = PRESET_HEADER_PROFILES[key];
    const newReport = auditHeaders(targetUrl, profile.headers);
    setReport(newReport);
    auditLogger.record(
      'HEADERS_AUDIT',
      'headers',
      newReport.score < 50 ? 'high' : newReport.score < 80 ? 'medium' : 'nominal',
      `Audit completed for ${targetUrl} (Score: ${newReport.score}/100, Grade: ${newReport.overallGrade})`,
      'session-active'
    );
  };

  const copyCode = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHeader(id);
    setTimeout(() => setCopiedHeader(null), 2000);
  };

  const getGradeColor = (grade: string) => {
    switch (grade) {
      case 'A+':
      case 'A':
        return 'text-emerald-400 border-emerald-500/30 bg-emerald-950/20';
      case 'B':
        return 'text-cyan-400 border-cyan-500/30 bg-cyan-950/20';
      case 'C':
        return 'text-amber-400 border-amber-500/30 bg-amber-950/20';
      default:
        return 'text-rose-400 border-rose-500/30 bg-rose-950/20';
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Header & Context */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-3 border-b border-slate-800">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
            <ShieldCheck className="w-5 h-5 text-cyan-400" />
            HTTP Security Headers & Transport Posture
          </h2>
          <div className="flex items-center gap-2 text-xs text-slate-400 mt-1">
            <span>OWASP ASVS Standard</span>
            <span aria-hidden="true">·</span>
            <span>MIME Sniffing & Clickjacking Defense</span>
            <span aria-hidden="true">·</span>
            <span>Content Security Policy Strictness</span>
          </div>
        </div>

        {/* Preset Selector */}
        <div className="flex items-center gap-1 p-1 bg-slate-900 border border-slate-800 rounded-lg">
          {(['fully_hardened', 'partially_hardened', 'unsecured'] as const).map((key) => {
            const labels = {
              fully_hardened: 'Hardened Profile',
              partially_hardened: 'Partial Profile',
              unsecured: 'Unsecured Profile',
            };
            const active = selectedPreset === key;
            return (
              <button
                key={key}
                onClick={() => {
                  setSelectedPreset(key);
                  handleRunAudit(key);
                }}
                className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${
                  active
                    ? 'bg-slate-800 text-white font-semibold shadow-sm'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {labels[key]}
              </button>
            );
          })}
        </div>
      </div>

      {/* Target URL Input Bar */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
        <div className="flex-1 flex items-center gap-2 px-3 py-2 bg-slate-900 border border-slate-800 rounded-lg focus-within:border-cyan-500 transition-colors">
          <span className="text-xs font-mono text-slate-500">TARGET:</span>
          <input
            type="text"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            className="flex-1 bg-transparent text-xs font-mono text-white focus:outline-none placeholder:text-slate-600"
            placeholder="http://127.0.0.1:8000/api/endpoint"
          />
        </div>
        <button
          onClick={() => handleRunAudit()}
          className="px-4 py-2 text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded-lg transition-colors flex items-center justify-center gap-2 shrink-0 shadow-sm"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          <span>Scan Headers</span>
        </button>
      </div>

      {/* Scorecard Hero Strip */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {/* Overall Grade Card */}
        <div className={`p-5 rounded-lg border flex items-center justify-between ${getGradeColor(report.overallGrade)}`}>
          <div>
            <div className="text-xs uppercase tracking-wider font-semibold text-slate-400">
              Security Grade
            </div>
            <div className="text-3xl font-extrabold tracking-tight mt-1 font-mono">
              {report.overallGrade}
            </div>
            <div className="text-xs text-slate-400 mt-1">
              Score: <span className="font-mono tabular-nums font-semibold text-white">{report.score}/100</span>
            </div>
          </div>
          <div className="text-right text-xs text-slate-400">
            <div>Target Host</div>
            <div className="font-mono text-slate-200 mt-0.5">127.0.0.1:8000</div>
          </div>
        </div>

        {/* Present Headers Stat */}
        <div className="p-5 rounded-lg border border-slate-800 bg-slate-900/60">
          <div className="text-xs uppercase tracking-wider font-semibold text-slate-400">
            Active Defenses
          </div>
          <div className="text-2xl font-bold tracking-tight text-emerald-400 mt-1 font-mono tabular-nums">
            {report.headers.filter((h) => h.status === 'present').length} / {report.headers.length}
          </div>
          <div className="text-xs text-slate-400 mt-1">Directives verified</div>
        </div>

        {/* Missing Headers Stat */}
        <div className="p-5 rounded-lg border border-slate-800 bg-slate-900/60">
          <div className="text-xs uppercase tracking-wider font-semibold text-slate-400">
            Missing Headers
          </div>
          <div className="text-2xl font-bold tracking-tight text-rose-400 mt-1 font-mono tabular-nums">
            {report.headers.filter((h) => h.status === 'missing').length}
          </div>
          <div className="text-xs text-slate-400 mt-1">Potential attack vectors</div>
        </div>

        {/* Information Leakage Stat */}
        <div className="p-5 rounded-lg border border-slate-800 bg-slate-900/60">
          <div className="text-xs uppercase tracking-wider font-semibold text-slate-400">
            Info Leakage Risks
          </div>
          <div className="text-2xl font-bold tracking-tight text-amber-400 mt-1 font-mono tabular-nums">
            {report.notes.length}
          </div>
          <div className="text-xs text-slate-400 mt-1">Server / Runtime banners</div>
        </div>
      </div>

      {/* Warnings & Information Leaks (if any) */}
      {report.notes.length > 0 && (
        <div className="p-4 rounded-lg bg-amber-950/20 border border-amber-500/30 text-xs text-amber-200 space-y-1.5">
          <div className="font-semibold flex items-center gap-1.5 text-amber-400">
            <AlertTriangle className="w-4 h-4" />
            Information Exposure & Configuration Alerts:
          </div>
          <ul className="list-disc list-inside space-y-1 text-slate-300 pl-1 font-mono text-[11px]">
            {report.notes.map((n, i) => (
              <li key={i}>{n}</li>
            ))}
          </ul>
        </div>
      )}

      {/* Remediation Snippet Selector */}
      <div className="flex items-center justify-between pt-2">
        <h3 className="text-sm font-semibold text-white">
          Evaluated Directives & Hardening Remediation
        </h3>
        <div className="flex items-center gap-1 text-xs bg-slate-900 border border-slate-800 p-1 rounded-md">
          <span className="text-slate-400 px-2 text-[11px]">Generate Fix for:</span>
          {(['fastapi', 'flask', 'express'] as const).map((fw) => (
            <button
              key={fw}
              onClick={() => setActiveSnippetTab(fw)}
              className={`px-2.5 py-1 rounded text-xs font-medium transition-colors uppercase ${
                activeSnippetTab === fw
                  ? 'bg-slate-800 text-cyan-300 font-semibold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {fw}
            </button>
          ))}
        </div>
      </div>

      {/* Detailed Headers Table */}
      <div className="rounded-lg border border-slate-800 overflow-hidden bg-slate-900/40">
        <div className="divide-y divide-slate-800">
          {report.headers.map((h) => {
            const isPass = h.status === 'present';
            const isWarn = h.status === 'misconfigured';
            const snippet = h.fixSnippet[activeSnippetTab];

            return (
              <div key={h.header} className="p-4 hover:bg-slate-900/50 transition-colors space-y-3">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div className="flex items-center gap-2.5">
                    {isPass ? (
                      <span className="w-5 h-5 rounded-full bg-emerald-950/80 border border-emerald-500/40 text-emerald-400 flex items-center justify-center text-xs shrink-0">
                        ✓
                      </span>
                    ) : isWarn ? (
                      <span className="w-5 h-5 rounded-full bg-amber-950/80 border border-amber-500/40 text-amber-400 flex items-center justify-center text-xs shrink-0">
                        !
                      </span>
                    ) : (
                      <span className="w-5 h-5 rounded-full bg-rose-950/80 border border-rose-500/40 text-rose-400 flex items-center justify-center text-xs shrink-0">
                        ✗
                      </span>
                    )}
                    <span className="font-mono text-sm font-semibold text-white">
                      {h.header}
                    </span>
                    <span className="text-xs text-slate-400 font-mono">
                      · {h.severity.toUpperCase()}
                    </span>
                  </div>

                  <div className="text-xs font-mono text-right">
                    {isPass ? (
                      <span className="text-emerald-400">ENFORCED</span>
                    ) : isWarn ? (
                      <span className="text-amber-400">PARTIAL</span>
                    ) : (
                      <span className="text-rose-400">NOT CONFIGURED</span>
                    )}
                  </div>
                </div>

                {/* Explanations & Threat scenario */}
                <div className="text-xs text-slate-300 grid grid-cols-1 md:grid-cols-2 gap-4 bg-slate-950/60 p-3 rounded-md border border-slate-800/80">
                  <div>
                    <span className="text-slate-400 font-medium block text-[11px] mb-0.5">
                      PURPOSE & FUNCTION:
                    </span>
                    <p className="leading-relaxed">{h.description}</p>
                  </div>
                  <div>
                    <span className="text-rose-400/90 font-medium block text-[11px] mb-0.5">
                      EXPLOIT SCENARIO IF ABSENT:
                    </span>
                    <p className="leading-relaxed text-slate-300">{h.exploitRisk}</p>
                  </div>
                </div>

                {/* Current vs Recommended */}
                <div className="text-xs font-mono grid grid-cols-1 md:grid-cols-2 gap-3 text-[11px]">
                  <div>
                    <span className="text-slate-400 block text-[10px] uppercase">Detected Value</span>
                    <div className="mt-1 p-2 bg-slate-950 rounded border border-slate-800 text-slate-300 break-all">
                      {h.value || '<None (Header omitted)>'}
                    </div>
                  </div>
                  <div>
                    <span className="text-cyan-400 block text-[10px] uppercase">Recommended Value</span>
                    <div className="mt-1 p-2 bg-slate-950 rounded border border-cyan-900/40 text-cyan-300 break-all">
                      {h.recommendedValue}
                    </div>
                  </div>
                </div>

                {/* Code Fix Snippet */}
                {!isPass && (
                  <div className="pt-1">
                    <div className="flex items-center justify-between text-[11px] text-slate-400 pb-1">
                      <span>Implementation Fix ({activeSnippetTab.toUpperCase()}):</span>
                      <button
                        onClick={() => copyCode(snippet, h.header)}
                        className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1 transition-colors"
                      >
                        {copiedHeader === h.header ? (
                          <>
                            <Check className="w-3 h-3 text-emerald-400" />
                            <span className="text-emerald-400">Copied</span>
                          </>
                        ) : (
                          <>
                            <Copy className="w-3 h-3" />
                            <span>Copy Snippet</span>
                          </>
                        )}
                      </button>
                    </div>
                    <pre className="p-2.5 rounded bg-slate-950 border border-slate-800 font-mono text-[11px] text-emerald-300 overflow-x-auto">
                      <code>{snippet}</code>
                    </pre>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
