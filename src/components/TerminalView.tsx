import React, { useState, useRef, useEffect } from 'react';
import {
  Terminal as TerminalIcon,
  Play,
  RotateCcw,
  Copy,
  Check,
  ShieldCheck,
  Clock,
  Sparkles,
  Maximize2,
  Minimize2,
} from 'lucide-react';
import { executeDiagnosticCommand } from '../services/securityEngine';

interface HistoryItem {
  id: string;
  command: string;
  timestamp: string;
  output: string[];
  success: boolean;
  durationMs: number;
}

export const TerminalView: React.FC = () => {
  const [inputVal, setInputVal] = useState('');
  const [history, setHistory] = useState<HistoryItem[]>([
    {
      id: 'init-1',
      command: 'whoami',
      timestamp: new Date().toLocaleTimeString(),
      output: [
        'Active Security Context:',
        '  User Persona : SecurityAuditor (Authorized Local Operator)',
        '  Network Node : 127.0.0.1 (Loopback Interface - Safe Zone)',
        '  Binding Mode : STRICT_LOCAL_ONLY (External Interfaces Blocked)',
        '  Audit State  : ACTIVE (Tamper-evident log append-only)',
      ],
      success: true,
      durationMs: 0.8,
    },
    {
      id: 'init-2',
      command: 'help',
      timestamp: new Date().toLocaleTimeString(),
      output: [
        'SecAudit Lab - Authorized Local Security Diagnostics CLI (v1.0.0)',
        'Environment: Bound strictly to 127.0.0.1 (Localhost Sandbox)',
        '',
        'Type any command or click a quick action below to run security checks.',
      ],
      success: true,
      durationMs: 1.1,
    },
  ]);

  const [cmdIndex, setCmdIndex] = useState<number>(-1);
  const [savedCommands, setSavedCommands] = useState<string[]>(['whoami', 'help']);
  const [copied, setCopied] = useState(false);
  const [isExpanded, setIsExpanded] = useState(false);

  const terminalEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    terminalEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [history]);

  const runCommand = (cmdText: string) => {
    const trimmed = cmdText.trim();
    if (!trimmed) return;

    if (trimmed.toLowerCase() === 'clear') {
      setHistory([]);
      setInputVal('');
      setCmdIndex(-1);
      return;
    }

    const res = executeDiagnosticCommand(trimmed);
    if (res.output[0] === '__CLEAR__') {
      setHistory([]);
      setInputVal('');
      setCmdIndex(-1);
      return;
    }

    const newItem: HistoryItem = {
      id: Math.random().toString(36).substring(2, 9),
      command: trimmed,
      timestamp: new Date().toLocaleTimeString(),
      output: res.output,
      success: res.success,
      durationMs: res.durationMs,
    };

    setHistory((prev) => [...prev, newItem]);
    setSavedCommands((prev) => [...prev, trimmed]);
    setInputVal('');
    setCmdIndex(-1);
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    runCommand(inputVal);
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (savedCommands.length === 0) return;
      const nextIndex = cmdIndex === -1 ? savedCommands.length - 1 : Math.max(0, cmdIndex - 1);
      setCmdIndex(nextIndex);
      setInputVal(savedCommands[nextIndex] || '');
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      if (cmdIndex === -1) return;
      const nextIndex = cmdIndex + 1;
      if (nextIndex >= savedCommands.length) {
        setCmdIndex(-1);
        setInputVal('');
      } else {
        setCmdIndex(nextIndex);
        setInputVal(savedCommands[nextIndex] || '');
      }
    } else if (e.key === 'Tab') {
      e.preventDefault();
      const suggestions = [
        'help',
        'ping 127.0.0.1',
        'dns localhost',
        'port-check 127.0.0.1 8000',
        'headers http://127.0.0.1:8000',
        'audit-query',
        'test-ratelimit 15',
        'session-info',
        'rotate-token',
        'audit-log 10',
        'whoami',
        'clear',
      ];
      const match = suggestions.find((s) => s.startsWith(inputVal.toLowerCase().trim()));
      if (match) {
        setInputVal(match);
      }
    }
  };

  const copyTerminalOutput = () => {
    const text = history
      .map((h) => `sec-auditor@localhost:~$ ${h.command}\n${h.output.join('\n')}`)
      .join('\n\n');
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const quickCommands = [
    { label: 'ping 127.0.0.1', cmd: 'ping 127.0.0.1' },
    { label: 'port-check 8000', cmd: 'port-check 127.0.0.1 8000' },
    { label: 'dns localhost', cmd: 'dns localhost' },
    { label: 'headers audit', cmd: 'headers http://127.0.0.1:8000' },
    {
      label: 'audit SQLi query',
      cmd: "audit-query SELECT * FROM users WHERE username = 'admin' OR '1'='1'",
    },
    { label: 'ratelimit 15', cmd: 'test-ratelimit 15' },
    { label: 'session-info', cmd: 'session-info' },
  ];

  return (
    <div className={`space-y-4 ${isExpanded ? 'fixed inset-4 z-50 bg-slate-950 p-6 rounded-xl border border-slate-700 overflow-y-auto' : ''}`}>
      {/* Header Context Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
            <TerminalIcon className="w-5 h-5 text-cyan-400" />
            Security Diagnostic Web Terminal
          </h2>
          <div className="flex items-center gap-2 text-xs text-slate-400 mt-1">
            <span>Sandboxed Local Shell</span>
            <span aria-hidden="true">·</span>
            <span className="text-emerald-400 font-mono">127.0.0.1 (Authorized Only)</span>
            <span aria-hidden="true">·</span>
            <span>Zero Remote Exfiltration</span>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setIsExpanded(!isExpanded)}
            className="px-2.5 py-1.5 text-xs text-slate-400 hover:text-white border border-slate-800 hover:border-slate-700 bg-slate-900 rounded-md transition-colors flex items-center gap-1.5"
            title={isExpanded ? 'Collapse' : 'Expand full screen'}
          >
            {isExpanded ? <Minimize2 className="w-3.5 h-3.5" /> : <Maximize2 className="w-3.5 h-3.5" />}
            <span className="hidden sm:inline">{isExpanded ? 'Collapse' : 'Expand'}</span>
          </button>
          <button
            onClick={copyTerminalOutput}
            className="px-2.5 py-1.5 text-xs text-slate-400 hover:text-white border border-slate-800 hover:border-slate-700 bg-slate-900 rounded-md transition-colors flex items-center gap-1.5"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copied ? 'Copied' : 'Copy Session'}</span>
          </button>
          <button
            onClick={() => setHistory([])}
            className="px-2.5 py-1.5 text-xs text-slate-400 hover:text-white border border-slate-800 hover:border-slate-700 bg-slate-900 rounded-md transition-colors flex items-center gap-1.5"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span>Clear Buffer</span>
          </button>
        </div>
      </div>

      {/* Quick Launch Command Bar */}
      <div className="flex items-center gap-2 overflow-x-auto pb-1 text-xs">
        <span className="text-slate-400 whitespace-nowrap text-[11px] font-medium uppercase tracking-wider">
          Quick Diagnostic:
        </span>
        {quickCommands.map((qc) => (
          <button
            key={qc.label}
            onClick={() => runCommand(qc.cmd)}
            className="px-2.5 py-1 rounded bg-slate-900 hover:bg-slate-800 border border-slate-800 hover:border-cyan-500/40 text-slate-300 hover:text-cyan-300 font-mono text-[11px] transition-colors whitespace-nowrap"
          >
            {qc.label}
          </button>
        ))}
      </div>

      {/* Terminal Viewport */}
      <div
        className="rounded-lg border border-slate-800 bg-[#070b14] shadow-2xl flex flex-col font-mono text-xs overflow-hidden cursor-text"
        onClick={() => inputRef.current?.focus()}
        style={{ minHeight: isExpanded ? 'calc(100vh - 220px)' : '480px' }}
      >
        {/* Terminal Title Bar */}
        <div className="flex items-center justify-between px-4 py-2.5 bg-slate-900/90 border-b border-slate-800 text-slate-400 select-none">
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-rose-500/80 inline-block" />
            <span className="w-2.5 h-2.5 rounded-full bg-amber-500/80 inline-block" />
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-500/80 inline-block" />
            <span className="ml-2 font-mono text-[11px] text-slate-400">
              sec-auditor@localhost — bash [127.0.0.1:8000]
            </span>
          </div>
          <div className="flex items-center gap-3 text-[11px] text-slate-400">
            <span className="flex items-center gap-1">
              <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
              Strict Loopback
            </span>
          </div>
        </div>

        {/* Terminal Scroll Area */}
        <div className="p-4 space-y-4 flex-1 overflow-y-auto max-h-[560px]">
          {history.length === 0 ? (
            <div className="text-slate-400 text-center py-12">
              Terminal buffer cleared. Enter a command or click a quick diagnostic above.
            </div>
          ) : (
            history.map((item) => (
              <div key={item.id} className="space-y-1.5 leading-relaxed">
                {/* Command Line Prompt */}
                <div className="flex items-center gap-2 text-slate-300">
                  <span className="text-cyan-400 font-semibold">sec-auditor@localhost</span>
                  <span className="text-slate-500">:</span>
                  <span className="text-amber-400">~</span>
                  <span className="text-slate-500">$</span>
                  <span className="text-white font-medium">{item.command}</span>
                  <span className="ml-auto text-[10px] text-slate-400 tabular-nums">
                    {item.durationMs}ms · {item.timestamp}
                  </span>
                </div>

                {/* Output block */}
                <div
                  className={`pl-4 border-l-2 ${
                    item.success ? 'border-cyan-500/30 text-slate-300' : 'border-rose-500/40 text-rose-300'
                  } whitespace-pre-wrap leading-5`}
                >
                  {item.output.map((line, idx) => {
                    let lineClass = 'text-slate-300';
                    if (line.includes('✓') || line.includes('[PASS]') || line.includes('Nominal') || line.includes('success')) {
                      lineClass = 'text-emerald-400';
                    } else if (line.includes('✗') || line.includes('[FAIL]') || line.includes('Error') || line.includes('CRITICAL')) {
                      lineClass = 'text-rose-400 font-medium';
                    } else if (line.includes('!') || line.includes('[WARN]') || line.includes('WARNING')) {
                      lineClass = 'text-amber-400';
                    } else if (line.startsWith('---') || line.startsWith('===')) {
                      lineClass = 'text-slate-400';
                    } else if (line.startsWith(';')) {
                      lineClass = 'text-slate-400';
                    }
                    return (
                      <div key={idx} className={lineClass}>
                        {line}
                      </div>
                    );
                  })}
                </div>
              </div>
            ))
          )}

          {/* Active Input Line */}
          <form onSubmit={handleSubmit} className="flex items-center gap-2 pt-2">
            <span className="text-cyan-400 font-semibold select-none">sec-auditor@localhost</span>
            <span className="text-slate-500 select-none">:</span>
            <span className="text-amber-400 select-none">~</span>
            <span className="text-slate-500 select-none">$</span>
            <input
              ref={inputRef}
              type="text"
              value={inputVal}
              onChange={(e) => setInputVal(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="type diagnostic command (e.g., ping 127.0.0.1, help, dns localhost)..."
              className="flex-1 bg-transparent text-white focus:outline-none font-mono caret-cyan-400 text-xs placeholder:text-slate-600"
              autoFocus
              spellCheck={false}
              autoComplete="off"
            />
            <button
              type="submit"
              disabled={!inputVal.trim()}
              className="p-1 text-slate-400 hover:text-cyan-400 disabled:opacity-30 disabled:hover:text-slate-400"
              title="Run command"
            >
              <Play className="w-3.5 h-3.5" />
            </button>
          </form>
          <div ref={terminalEndRef} />
        </div>

        {/* Terminal Footer Bar */}
        <div className="px-4 py-2 bg-slate-900/60 border-t border-slate-800/80 flex items-center justify-between text-[11px] text-slate-400 select-none">
          <div className="flex items-center gap-4">
            <span>Press Tab for autocompletion</span>
            <span aria-hidden="true">·</span>
            <span>Up/Down arrows for history</span>
          </div>
          <div className="flex items-center gap-2 font-mono">
            <span className="w-2 h-2 rounded-full bg-emerald-400 inline-block" />
            <span>LOCAL_SOCKET_CONNECTED</span>
          </div>
        </div>
      </div>
    </div>
  );
};
