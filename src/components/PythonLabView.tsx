import React, { useState } from 'react';
import {
  FileCode,
  Download,
  Copy,
  Check,
  Terminal,
  Shield,
  Layers,
  CheckCircle2,
  BookOpen,
} from 'lucide-react';
import JSZip from 'jszip';
import { PYTHON_SOURCE_FILES, PythonSourceFile } from '../data/pythonSources';
import { auditLogger } from '../services/securityEngine';

export const PythonLabView: React.FC = () => {
  const [selectedFile, setSelectedFile] = useState<PythonSourceFile>(PYTHON_SOURCE_FILES[0]);
  const [copied, setCopied] = useState(false);
  const [isZipping, setIsZipping] = useState(false);
  const [zipSuccess, setZipSuccess] = useState(false);

  const handleCopyCode = () => {
    navigator.clipboard.writeText(selectedFile.content);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownloadZip = async () => {
    setIsZipping(true);
    try {
      const zip = new JSZip();

      // Add all source files to zip
      PYTHON_SOURCE_FILES.forEach((f) => {
        zip.file(f.path, f.content);
      });

      const content = await zip.generateAsync({ type: 'blob' });
      const url = URL.createObjectURL(content);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'SecAudit_Lab_Python_Engine.zip';
      a.click();
      URL.revokeObjectURL(url);

      setZipSuccess(true);
      setTimeout(() => setZipSuccess(false), 3000);
      auditLogger.record('PYTHON_LAB_ZIP_DOWNLOAD', 'system', 'nominal', 'Complete Python testing lab ZIP exported', 'session-active');
    } catch (err) {
      console.error('Failed to create zip:', err);
    } finally {
      setIsZipping(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header Context */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-3 border-b border-slate-800">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
            <FileCode className="w-5 h-5 text-cyan-400" />
            Production Python Backend Source Code & Ethical Lab Setup
          </h2>
          <div className="flex items-center gap-2 text-xs text-slate-400 mt-1">
            <span>FastAPI & Flask Backends</span>
            <span aria-hidden="true">·</span>
            <span>Pytest Security Suite</span>
            <span aria-hidden="true">·</span>
            <span>Localhost Dockerfile & Setup Guide</span>
          </div>
        </div>

        <button
          onClick={handleDownloadZip}
          disabled={isZipping}
          className="px-4 py-2 text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded-md transition-colors flex items-center gap-2 shadow-sm shrink-0 self-start sm:self-auto disabled:opacity-50"
        >
          {zipSuccess ? (
            <>
              <Check className="w-4 h-4 text-slate-950" />
              <span>Downloaded Lab ZIP!</span>
            </>
          ) : (
            <>
              <Download className="w-4 h-4" />
              <span>{isZipping ? 'Bundling ZIP...' : 'Download Full Python Lab (.zip)'}</span>
            </>
          )}
        </button>
      </div>

      {/* Main Two-Column Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: File Explorer (4 cols) */}
        <div className="lg:col-span-4 space-y-4">
          <div className="p-4 rounded-lg border border-slate-800 bg-slate-900/60 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs uppercase font-semibold text-slate-400 tracking-wider">
                Lab Repository Tree
              </span>
              <span className="text-[11px] font-mono text-cyan-400">
                {PYTHON_SOURCE_FILES.length} Files
              </span>
            </div>

            <div className="space-y-1.5">
              {PYTHON_SOURCE_FILES.map((file) => {
                const isSelected = selectedFile.name === file.name;
                return (
                  <button
                    key={file.name}
                    onClick={() => setSelectedFile(file)}
                    className={`w-full text-left p-2.5 rounded-md border text-xs transition-colors flex items-center justify-between ${
                      isSelected
                        ? 'bg-slate-850 border-cyan-500/50 text-white font-semibold shadow-sm'
                        : 'bg-slate-950/40 border-slate-800/80 text-slate-400 hover:text-slate-200 hover:bg-slate-900/60'
                    }`}
                  >
                    <div className="flex items-center gap-2 truncate">
                      <FileCode className={`w-4 h-4 shrink-0 ${isSelected ? 'text-cyan-400' : 'text-slate-500'}`} />
                      <span className="font-mono truncate">{file.path}</span>
                    </div>
                    <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-slate-900 text-slate-400 border border-slate-800 shrink-0">
                      {file.framework}
                    </span>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Quick Setup Instructions Card */}
          <div className="p-4 rounded-lg border border-slate-800 bg-slate-900/60 space-y-3 text-xs">
            <h3 className="font-semibold text-white flex items-center gap-1.5">
              <Terminal className="w-4 h-4 text-cyan-400" />
              Quick Local Setup Guide
            </h3>
            <ol className="list-decimal list-inside space-y-2 text-slate-300 font-mono text-[11px]">
              <li className="leading-relaxed">
                <span>Create Python Virtualenv:</span>
                <div className="p-1.5 mt-0.5 bg-slate-950 rounded border border-slate-800 text-cyan-300">
                  python3 -m venv venv && source venv/bin/activate
                </div>
              </li>
              <li className="leading-relaxed">
                <span>Install Dependencies:</span>
                <div className="p-1.5 mt-0.5 bg-slate-950 rounded border border-slate-800 text-cyan-300">
                  pip install -r requirements.txt
                </div>
              </li>
              <li className="leading-relaxed">
                <span>Run FastAPI on 127.0.0.1:</span>
                <div className="p-1.5 mt-0.5 bg-slate-950 rounded border border-slate-800 text-cyan-300">
                  python backend/app_fastapi.py
                </div>
              </li>
              <li className="leading-relaxed">
                <span>Run Automated Security Tests:</span>
                <div className="p-1.5 mt-0.5 bg-slate-950 rounded border border-slate-800 text-cyan-300">
                  pytest tests/test_security.py -v
                </div>
              </li>
            </ol>
          </div>
        </div>

        {/* Right Column: Code Viewer (8 cols) */}
        <div className="lg:col-span-8 space-y-3">
          <div className="p-4 rounded-lg border border-slate-800 bg-slate-900/60 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <div>
              <div className="text-xs font-mono text-cyan-400 uppercase tracking-wider">
                {selectedFile.path}
              </div>
              <p className="text-xs text-slate-300 mt-0.5">
                {selectedFile.description}
              </p>
            </div>
            <button
              onClick={handleCopyCode}
              className="px-3 py-1.5 text-xs text-slate-300 hover:text-white bg-slate-950 border border-slate-800 rounded-md transition-colors flex items-center gap-1.5 shrink-0 self-start sm:self-auto"
            >
              {copied ? (
                <>
                  <Check className="w-3.5 h-3.5 text-emerald-400" />
                  <span className="text-emerald-400">Copied</span>
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5" />
                  <span>Copy Code</span>
                </>
              )}
            </button>
          </div>

          {/* Syntax Code Container */}
          <div className="rounded-lg border border-slate-800 bg-[#070b14] overflow-hidden">
            <div className="px-4 py-2 bg-slate-900/80 border-b border-slate-800 flex items-center justify-between text-[11px] font-mono text-slate-400">
              <span>{selectedFile.name} — {selectedFile.content.split('\n').length} lines</span>
              <span>Python 3.11+ Compatible</span>
            </div>
            <pre className="p-4 font-mono text-xs text-slate-200 overflow-x-auto leading-relaxed max-h-[580px]">
              <code>{selectedFile.content}</code>
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
};
