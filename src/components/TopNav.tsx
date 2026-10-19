import React from 'react';
import { Shield, Terminal, Lock, Download, Server, RefreshCw } from 'lucide-react';

interface TopNavProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  sessionToken: string;
  onRotateToken: () => void;
  onOpenPythonLab: () => void;
}

export const TopNav: React.FC<TopNavProps> = ({
  activeTab,
  setActiveTab,
  sessionToken,
  onRotateToken,
  onOpenPythonLab,
}) => {
  const navItems = [
    { id: 'terminal', label: 'CLI Terminal' },
    { id: 'headers', label: 'HTTP Headers' },
    { id: 'api_security', label: 'API & Inputs' },
    { id: 'database', label: 'Database Auditor' },
    { id: 'rate_limiting', label: 'Rate Limiting' },
    { id: 'session_audit', label: 'Session & Audit' },
    { id: 'python_sources', label: 'Python Lab' },
  ];

  return (
    <header className="sticky top-0 z-40 bg-slate-950/95 backdrop-blur-md border-b border-slate-800">
      <div className="max-w-7xl mx-auto flex items-center justify-between gap-8 px-6 py-3.5">
        {/* Zone 1: Single text element wordmark */}
        <div className="flex items-center gap-3 shrink-0">
          <div className="w-8 h-8 rounded-lg bg-cyan-950 border border-cyan-500/40 flex items-center justify-center text-cyan-400 shadow-sm">
            <Shield className="w-4 h-4" />
          </div>
          <span className="text-base font-bold tracking-tight text-white whitespace-nowrap">
            SecAudit Lab
          </span>
          <span className="text-xs text-slate-400 font-mono hidden sm:inline">
            127.0.0.1:8000
          </span>
        </div>

        {/* Zone 2: Clean single-line text navigation links */}
        <nav className="hidden lg:flex items-center gap-1">
          {navItems.map((item) => {
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setActiveTab(item.id)}
                className={`px-3 py-1.5 text-xs font-medium rounded-md whitespace-nowrap transition-colors ${
                  isActive
                    ? 'bg-slate-800 text-cyan-300 font-semibold border border-slate-700'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
                }`}
              >
                {item.label}
              </button>
            );
          })}
        </nav>

        {/* Zone 3: 1 primary action & session indicator */}
        <div className="flex items-center gap-3 shrink-0">
          <div className="hidden sm:flex items-center gap-2 text-xs text-slate-400 border border-slate-800 bg-slate-900/60 px-2.5 py-1.5 rounded-md">
            <Lock className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
            <span className="font-mono text-[11px] truncate max-w-[120px] text-slate-300" title={sessionToken}>
              {sessionToken.substring(0, 14)}...
            </span>
            <button
              onClick={onRotateToken}
              title="Rotate session token"
              className="text-slate-400 hover:text-cyan-300 transition-colors"
            >
              <RefreshCw className="w-3 h-3" />
            </button>
          </div>

          <button
            onClick={onOpenPythonLab}
            className="flex items-center gap-2 px-3.5 py-1.5 text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded-md transition-colors whitespace-nowrap shadow-sm"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Python Lab Package</span>
          </button>
        </div>
      </div>

      {/* Mobile navigation tab strip */}
      <div className="lg:hidden flex items-center gap-1 px-4 py-2 overflow-x-auto border-t border-slate-900 bg-slate-950">
        {navItems.map((item) => (
          <button
            key={item.id}
            onClick={() => setActiveTab(item.id)}
            className={`px-2.5 py-1 text-xs font-medium rounded whitespace-nowrap ${
              activeTab === item.id
                ? 'bg-slate-800 text-cyan-300 font-semibold'
                : 'text-slate-400'
            }`}
          >
            {item.label}
          </button>
        ))}
      </div>
    </header>
  );
};
