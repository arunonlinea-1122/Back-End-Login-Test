import React, { useState } from 'react';
import {
  Database,
  ShieldCheck,
  AlertTriangle,
  Play,
  CheckCircle2,
  XCircle,
  Copy,
  Check,
  Code,
  Table,
  Layers,
  ArrowRight,
  Sparkles,
} from 'lucide-react';
import {
  auditSqlQuery,
  executeLabDatabaseQuery,
  auditLogger,
} from '../services/securityEngine';
import { QueryAuditResult, LabDatabaseRecord } from '../types/security';

interface SampleQueryPreset {
  id: string;
  name: string;
  category: 'Vulnerable String Concatenation' | 'Secure Parameterized Statement';
  query: string;
  testInput: string;
  description: string;
}

const PRESET_QUERIES: SampleQueryPreset[] = [
  {
    id: 'sqli-tautology',
    name: 'Authentication Tautology',
    category: 'Vulnerable String Concatenation',
    query: "SELECT id, username, email, role FROM users WHERE username = 'admin' OR '1'='1'",
    testInput: "admin' OR '1'='1",
    description: "Classic tautological injection where ('1'='1') forces the boolean clause to resolve true, leaking all database rows.",
  },
  {
    id: 'sqli-syntax',
    name: 'Unescaped Syntax Delimiter',
    category: 'Vulnerable String Concatenation',
    query: "SELECT id, username, email, role FROM users WHERE username = 'O'Reilly'",
    testInput: "O'Reilly",
    description: "An unescaped apostrophe terminates the SQL string prematurely, causing an internal database syntax error leak.",
  },
  {
    id: 'sqli-union',
    name: 'UNION Schema Extraction',
    category: 'Vulnerable String Concatenation',
    query: "SELECT id, username, email, role FROM users WHERE username = 'x' UNION SELECT id, name, tbl_name, sql FROM sqlite_master --",
    testInput: "x' UNION SELECT id, name, tbl_name, sql FROM sqlite_master --",
    description: "Appends a secondary SELECT query to dump database metadata from the sqlite_master catalog.",
  },
  {
    id: 'safe-positional',
    name: 'Positional Prepared Statement',
    category: 'Secure Parameterized Statement',
    query: 'SELECT id, username, email, role FROM users WHERE username = ?',
    testInput: "admin' OR '1'='1",
    description: "SQLite positional placeholder (?). The query planner treats the input strictly as a literal text parameter.",
  },
  {
    id: 'safe-named',
    name: 'Named Parameter Statement',
    category: 'Secure Parameterized Statement',
    query: 'SELECT id, username, email, role FROM users WHERE username = :target_user',
    testInput: "admin' OR '1'='1",
    description: "SQLAlchemy / Postgres named placeholder (:param). Data is isolated completely from SQL parsing grammar.",
  },
];

export const DatabaseAuditorView: React.FC = () => {
  const [selectedPreset, setSelectedPreset] = useState<SampleQueryPreset>(PRESET_QUERIES[0]);
  const [queryInput, setQueryInput] = useState(PRESET_QUERIES[0].query);
  const [labInputValue, setLabInputValue] = useState(PRESET_QUERIES[0].testInput);
  const [useParameterizedMode, setUseParameterizedMode] = useState(false);
  const [copied, setCopied] = useState<string | null>(null);

  // AST Audit Result
  const [auditResult, setAuditResult] = useState<QueryAuditResult>(() => auditSqlQuery(PRESET_QUERIES[0].query));

  // Lab Query Execution State
  const [labExecution, setLabExecution] = useState<{
    ran: boolean;
    success: boolean;
    rows: LabDatabaseRecord[];
    sqlExecuted: string;
    latencyMs: number;
    riskDetected: boolean;
    explanation: string;
    error?: string;
  }>({
    ran: false,
    success: true,
    rows: [],
    sqlExecuted: '',
    latencyMs: 0,
    riskDetected: false,
    explanation: '',
  });

  const handleSelectPreset = (preset: SampleQueryPreset) => {
    setSelectedPreset(preset);
    setQueryInput(preset.query);
    setLabInputValue(preset.testInput);
    setUseParameterizedMode(preset.category === 'Secure Parameterized Statement');
    const res = auditSqlQuery(preset.query);
    setAuditResult(res);
  };

  const handleQueryChange = (val: string) => {
    setQueryInput(val);
    const res = auditSqlQuery(val);
    setAuditResult(res);
  };

  const handleExecuteLabQuery = () => {
    const res = executeLabDatabaseQuery(labInputValue, useParameterizedMode);
    setLabExecution({
      ran: true,
      ...res,
    });
    auditLogger.record(
      'LAB_DATABASE_QUERY',
      'sql',
      res.riskDetected ? 'critical' : 'nominal',
      `Query executed (Parameterized: ${useParameterizedMode}, Rows: ${res.rows.length})`,
      'session-active',
      res.riskDetected ? 'flagged' : 'success'
    );
  };

  const copyCode = (code: string, id: string) => {
    navigator.clipboard.writeText(code);
    setCopied(id);
    setTimeout(() => setCopied(null), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-3 border-b border-slate-800">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
            <Database className="w-5 h-5 text-cyan-400" />
            Local Database Management & SQL Injection Auditor
          </h2>
          <div className="flex items-center gap-2 text-xs text-slate-400 mt-1">
            <span>SQLite Lab Database Sandbox</span>
            <span aria-hidden="true">·</span>
            <span>Prepared Statements & Parameterization Inspector</span>
            <span aria-hidden="true">·</span>
            <span>AST Syntax Validation</span>
          </div>
        </div>

        <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
          <span className="w-2 h-2 rounded-full bg-emerald-400" />
          <span>SQLITE_LOCAL_SANDBOX_ACTIVE</span>
        </div>
      </div>

      {/* Preset Query Scenario Bar */}
      <div className="flex items-center gap-2 overflow-x-auto pb-1 text-xs">
        <span className="text-slate-400 whitespace-nowrap text-[11px] font-medium uppercase tracking-wider">
          Query Scenarios:
        </span>
        {PRESET_QUERIES.map((preset) => {
          const isSelected = selectedPreset.id === preset.id;
          const isSafe = preset.category === 'Secure Parameterized Statement';
          return (
            <button
              key={preset.id}
              onClick={() => handleSelectPreset(preset)}
              className={`px-3 py-1.5 rounded-md font-mono text-xs transition-colors whitespace-nowrap border ${
                isSelected
                  ? isSafe
                    ? 'bg-emerald-950/80 border-emerald-500/50 text-emerald-300 font-semibold'
                    : 'bg-rose-950/80 border-rose-500/50 text-rose-300 font-semibold'
                  : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-slate-200 hover:bg-slate-800'
              }`}
            >
              {preset.name}
            </button>
          );
        })}
      </div>

      {/* Two Column Grid: Query Editor & AST Inspector */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Query Editor & Parameterization Analysis (7 Cols) */}
        <div className="lg:col-span-7 space-y-4">
          <div className="p-4 rounded-lg border border-slate-800 bg-slate-900/60 space-y-3">
            <div className="flex items-center justify-between">
              <label className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
                SQL Query Inspector
              </label>
              <span className="text-xs font-mono text-slate-400">
                Live AST Pattern Scanner
              </span>
            </div>

            <textarea
              rows={3}
              value={queryInput}
              onChange={(e) => handleQueryChange(e.target.value)}
              className="w-full p-3 bg-slate-950 border border-slate-800 rounded-md font-mono text-xs text-cyan-200 focus:outline-none focus:border-cyan-500 leading-relaxed resize-none"
              placeholder="SELECT * FROM users WHERE username = '...' or SELECT * FROM users WHERE username = ?"
            />

            {/* AST Scanner Metric Cards */}
            <div className="grid grid-cols-3 gap-2 pt-1 text-xs">
              <div className="p-2.5 rounded bg-slate-950 border border-slate-800/80">
                <span className="text-[10px] text-slate-400 uppercase block">Injection Risk</span>
                <span
                  className={`font-mono text-sm font-bold ${
                    auditResult.severity === 'critical'
                      ? 'text-rose-400'
                      : auditResult.severity === 'high'
                      ? 'text-amber-400'
                      : 'text-emerald-400'
                  }`}
                >
                  {auditResult.severity.toUpperCase()} ({auditResult.riskScore}/10)
                </span>
              </div>
              <div className="p-2.5 rounded bg-slate-950 border border-slate-800/80">
                <span className="text-[10px] text-slate-400 uppercase block">String Concat</span>
                <span className="font-mono text-xs text-slate-300">
                  {auditResult.astAnalysis.usesConcatenation ? 'DETECTED (!)' : 'None'}
                </span>
              </div>
              <div className="p-2.5 rounded bg-slate-950 border border-slate-800/80">
                <span className="text-[10px] text-slate-400 uppercase block">Placeholders</span>
                <span className="font-mono text-xs text-cyan-400 truncate block">
                  {auditResult.astAnalysis.placeholdersDetected.length > 0
                    ? auditResult.astAnalysis.placeholdersDetected.join(', ')
                    : 'None (Raw String)'}
                </span>
              </div>
            </div>

            {/* Pattern detections */}
            {auditResult.vulnerabilityPatterns.length > 0 && (
              <div className="p-3 rounded bg-rose-950/20 border border-rose-500/30 text-xs text-rose-300 space-y-1">
                <div className="font-semibold text-rose-400 flex items-center gap-1">
                  <AlertTriangle className="w-3.5 h-3.5" />
                  <span>Flagged Injection Signatures:</span>
                </div>
                <ul className="list-disc list-inside text-[11px] text-slate-300 space-y-0.5 font-mono">
                  {auditResult.vulnerabilityPatterns.map((pat, i) => (
                    <li key={i}>{pat}</li>
                  ))}
                </ul>
              </div>
            )}

            {/* Architectural Remediation Advice */}
            <div className="text-xs text-slate-300 bg-slate-950 p-3 rounded border border-slate-800/80 leading-relaxed">
              <span className="text-cyan-400 font-semibold block mb-0.5">Architectural Guidance:</span>
              <p>{auditResult.remediationAdvice}</p>
            </div>
          </div>

          {/* Secure Python Implementation Code (SQLite & SQLAlchemy) */}
          <div className="p-4 rounded-lg border border-slate-800 bg-slate-900/60 space-y-3">
            <div className="flex items-center justify-between text-xs">
              <span className="font-semibold text-white flex items-center gap-1.5">
                <Code className="w-4 h-4 text-cyan-400" />
                Defensive Python Code (Prepared Query Execution)
              </span>
              <button
                onClick={() => copyCode(auditResult.safePythonCode.sqlite, 'sqlite')}
                className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1 transition-colors text-[11px]"
              >
                {copied === 'sqlite' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                <span>{copied === 'sqlite' ? 'Copied' : 'Copy Python'}</span>
              </button>
            </div>
            <pre className="p-3 bg-slate-950 rounded-md border border-slate-800 font-mono text-[11px] text-emerald-300 overflow-x-auto leading-relaxed">
              <code>{auditResult.safePythonCode.sqlite}</code>
            </pre>
          </div>
        </div>

        {/* Right Column: In-Memory Lab Database Execution Sandbox (5 Cols) */}
        <div className="lg:col-span-5 space-y-4">
          <div className="p-4 rounded-lg border border-slate-800 bg-slate-900/60 space-y-3">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-sm font-semibold text-white">Lab Database Sandbox</h3>
                <p className="text-xs text-slate-400 mt-0.5">Test query execution against local SQLite table.</p>
              </div>
              <span className="text-xs font-mono text-slate-500">table: users</span>
            </div>

            {/* Test input field */}
            <div>
              <label className="block text-xs font-medium text-slate-400 mb-1">
                Simulated User Input (e.g. login form parameter):
              </label>
              <input
                type="text"
                value={labInputValue}
                onChange={(e) => setLabInputValue(e.target.value)}
                className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-md font-mono text-xs text-cyan-200 focus:outline-none focus:border-cyan-500"
              />
            </div>

            {/* Parameterization toggle switch */}
            <div className="flex items-center justify-between p-3 rounded-md bg-slate-950 border border-slate-800">
              <div className="space-y-0.5">
                <span className="text-xs font-medium text-white block">
                  Enforce Prepared Parameterization
                </span>
                <span className="text-[11px] text-slate-400 block">
                  {useParameterizedMode ? 'SECURE: Value treated as data parameter' : 'VULNERABLE: Direct string interpolation'}
                </span>
              </div>
              <button
                type="button"
                onClick={() => setUseParameterizedMode(!useParameterizedMode)}
                className={`relative inline-flex h-5 w-10 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none ${
                  useParameterizedMode ? 'bg-cyan-500' : 'bg-slate-700'
                }`}
              >
                <span
                  className={`pointer-events-none inline-block h-4 w-4 transform rounded-full bg-white shadow-lg ring-0 transition duration-200 ease-in-out ${
                    useParameterizedMode ? 'translate-x-5' : 'translate-x-0'
                  }`}
                />
              </button>
            </div>

            {/* Run Button */}
            <button
              onClick={handleExecuteLabQuery}
              className="w-full py-2.5 px-4 text-xs font-semibold rounded-md bg-cyan-400 hover:bg-cyan-300 text-slate-950 transition-colors flex items-center justify-center gap-2 shadow-sm"
            >
              <Play className="w-3.5 h-3.5" />
              <span>Execute Against Lab Database</span>
            </button>
          </div>

          {/* Execution Result Container */}
          {labExecution.ran && (
            <div className="p-4 rounded-lg border border-slate-800 bg-slate-900/60 space-y-3">
              <div className="flex items-center justify-between text-xs">
                <span className="font-semibold text-white">Execution Result</span>
                <span className="font-mono tabular-nums text-slate-400">
                  {labExecution.latencyMs}ms latency
                </span>
              </div>

              {/* Status Banner */}
              <div
                className={`p-3 rounded-md text-xs border ${
                  labExecution.error
                    ? 'bg-rose-950/30 border-rose-500/40 text-rose-300'
                    : labExecution.riskDetected
                    ? 'bg-rose-950/30 border-rose-500/40 text-rose-300'
                    : 'bg-emerald-950/30 border-emerald-500/40 text-emerald-300'
                }`}
              >
                <div className="flex items-center gap-1.5 font-semibold mb-1">
                  {labExecution.riskDetected || labExecution.error ? (
                    <XCircle className="w-4 h-4 text-rose-400 shrink-0" />
                  ) : (
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                  )}
                  <span>
                    {labExecution.error
                      ? 'SQL Syntax Execution Error'
                      : labExecution.riskDetected
                      ? 'SQL Injection Succeeded (Data Exfiltration)'
                      : 'Parameterized Query Protected (Literal Match)'}
                  </span>
                </div>
                <p className="text-[11px] leading-relaxed text-slate-300">
                  {labExecution.error || labExecution.explanation}
                </p>
              </div>

              {/* Executed SQL */}
              <div>
                <span className="text-[10px] text-slate-400 uppercase font-mono block mb-1">
                  Engine Executed String:
                </span>
                <div className="p-2 bg-slate-950 rounded border border-slate-800 font-mono text-[11px] text-slate-300 break-all">
                  {labExecution.sqlExecuted}
                </div>
              </div>

              {/* Returned Table Rows */}
              <div>
                <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
                  <span>Returned Records:</span>
                  <span className="font-mono tabular-nums font-semibold text-white">
                    {labExecution.rows.length} rows returned
                  </span>
                </div>

                {labExecution.rows.length === 0 ? (
                  <div className="p-4 text-center text-xs text-slate-500 bg-slate-950 rounded border border-slate-800">
                    0 rows matched. No user records leaked.
                  </div>
                ) : (
                  <div className="overflow-x-auto rounded border border-slate-800">
                    <table className="w-full text-[11px] font-mono text-left bg-slate-950">
                      <thead className="bg-slate-900 text-slate-400 border-b border-slate-800">
                        <tr>
                          <th className="p-2">ID</th>
                          <th className="p-2">Username</th>
                          <th className="p-2">Role</th>
                          <th className="p-2">Email</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800 text-slate-300">
                        {labExecution.rows.map((row) => (
                          <tr key={row.id} className="hover:bg-slate-900/60">
                            <td className="p-2 tabular-nums">{row.id}</td>
                            <td className="p-2 text-cyan-300 font-semibold">{row.username}</td>
                            <td className="p-2 text-amber-300">{row.role}</td>
                            <td className="p-2 text-slate-400">{row.email}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
