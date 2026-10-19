import React, { useState } from 'react';
import {
  Activity,
  Play,
  RotateCcw,
  ShieldAlert,
  Clock,
  Gauge,
  CheckCircle2,
  XCircle,
  Copy,
  Check,
  Zap,
} from 'lucide-react';
import { runRateLimitSimulation } from '../services/securityEngine';
import { RateLimitResult } from '../types/security';

export const RateLimitView: React.FC = () => {
  const [totalRequests, setTotalRequests] = useState(30);
  const [concurrency, setConcurrency] = useState(5);
  const [rateLimitCap, setRateLimitCap] = useState(15);
  const [isRunning, setIsRunning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [copied, setCopied] = useState(false);

  const [result, setResult] = useState<RateLimitResult | null>(null);

  const handleStartSimulation = async () => {
    setIsRunning(true);
    setProgress(0);
    setResult(null);

    const simulationResult = await runRateLimitSimulation(
      totalRequests,
      concurrency,
      rateLimitCap,
      (completed) => setProgress(completed)
    );

    setResult(simulationResult);
    setIsRunning(false);
  };

  const copySnippet = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const pythonSlowapiSnippet = `# FastAPI Production Rate Limiter with Slowapi (Token Bucket)
from fastapi import FastAPI, Request
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

limiter = Limiter(key_func=get_remote_address, default_limits=["60/minute"])
app = FastAPI()
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Protect sensitive authentication endpoints against credential stuffing
@app.post("/api/auth/login")
@limiter.limit("5/minute")
def login(request: Request):
    # Enforces max 5 login attempts per minute per IP
    return {"status": "authenticated"}`;

  return (
    <div className="space-y-6">
      {/* Header Context */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-3 border-b border-slate-800">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
            <Activity className="w-5 h-5 text-cyan-400" />
            Rate-Limiting & Anti-Brute-Force Efficiency Evaluator
          </h2>
          <div className="flex items-center gap-2 text-xs text-slate-400 mt-1">
            <span>Token Bucket / Sliding Window Verification</span>
            <span aria-hidden="true">·</span>
            <span>HTTP 429 Too Many Requests Detection</span>
            <span aria-hidden="true">·</span>
            <span>DoS & Credential Stuffing Resilience</span>
          </div>
        </div>

        <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
          <span className="w-2 h-2 rounded-full bg-cyan-400" />
          <span>ALGORITHM: TOKEN_BUCKET</span>
        </div>
      </div>

      {/* Control Configuration Grid */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 p-5 rounded-lg border border-slate-800 bg-slate-900/60">
        {/* Total Requests Input */}
        <div>
          <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1.5">
            Total Request Burst:
          </label>
          <div className="flex items-center gap-2">
            <input
              type="range"
              min={10}
              max={60}
              step={5}
              value={totalRequests}
              disabled={isRunning}
              onChange={(e) => setTotalRequests(parseInt(e.target.value, 10))}
              className="flex-1 accent-cyan-400"
            />
            <span className="font-mono text-sm font-semibold text-white tabular-nums w-8">
              {totalRequests}
            </span>
          </div>
          <span className="text-[11px] text-slate-500 mt-1 block">Total client requests generated</span>
        </div>

        {/* Concurrency Level */}
        <div>
          <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1.5">
            Concurrency Workers:
          </label>
          <div className="flex items-center gap-2">
            <input
              type="range"
              min={1}
              max={15}
              step={1}
              value={concurrency}
              disabled={isRunning}
              onChange={(e) => setConcurrency(parseInt(e.target.value, 10))}
              className="flex-1 accent-cyan-400"
            />
            <span className="font-mono text-sm font-semibold text-white tabular-nums w-8">
              {concurrency}x
            </span>
          </div>
          <span className="text-[11px] text-slate-500 mt-1 block">Simulated simultaneous threads</span>
        </div>

        {/* Server Rate Cap */}
        <div>
          <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1.5">
            Configured Limit Cap:
          </label>
          <div className="flex items-center gap-2">
            <input
              type="range"
              min={5}
              max={30}
              step={5}
              value={rateLimitCap}
              disabled={isRunning}
              onChange={(e) => setRateLimitCap(parseInt(e.target.value, 10))}
              className="flex-1 accent-cyan-400"
            />
            <span className="font-mono text-sm font-semibold text-white tabular-nums w-8">
              {rateLimitCap}
            </span>
          </div>
          <span className="text-[11px] text-slate-500 mt-1 block">Allowed before HTTP 429 trigger</span>
        </div>

        {/* Start Action */}
        <div className="flex flex-col justify-end">
          <button
            onClick={handleStartSimulation}
            disabled={isRunning}
            className="w-full py-2.5 px-4 text-xs font-semibold rounded-md bg-cyan-400 hover:bg-cyan-300 text-slate-950 transition-colors flex items-center justify-center gap-2 shadow-sm disabled:opacity-50"
          >
            {isRunning ? (
              <>
                <Clock className="w-3.5 h-3.5 animate-spin" />
                <span>Simulating... ({progress}/{totalRequests})</span>
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5" />
                <span>Execute Burst Evaluation</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Progress Bar (when running) */}
      {isRunning && (
        <div className="space-y-1">
          <div className="flex justify-between text-xs text-slate-400 font-mono">
            <span>Burst probe in progress</span>
            <span>{Math.round((progress / totalRequests) * 100)}%</span>
          </div>
          <div className="h-2 bg-slate-900 rounded-full overflow-hidden border border-slate-800">
            <div
              className="h-full bg-cyan-400 transition-all duration-150"
              style={{ width: `${(progress / totalRequests) * 100}%` }}
            />
          </div>
        </div>
      )}

      {/* Results Overview Strip */}
      {result && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {/* Allowed Requests */}
            <div className="p-4 rounded-lg border border-slate-800 bg-slate-900/60">
              <span className="text-xs uppercase text-slate-400 font-semibold tracking-wider block">
                Allowed (200 OK)
              </span>
              <span className="text-2xl font-bold font-mono text-emerald-400 mt-1 block tabular-nums">
                {result.successfulRequests}
              </span>
              <span className="text-[11px] text-slate-500">Under rate threshold</span>
            </div>

            {/* Throttled Requests */}
            <div className="p-4 rounded-lg border border-slate-800 bg-slate-900/60">
              <span className="text-xs uppercase text-slate-400 font-semibold tracking-wider block">
                Throttled (429)
              </span>
              <span className="text-2xl font-bold font-mono text-rose-400 mt-1 block tabular-nums">
                {result.throttledRequests}
              </span>
              <span className="text-[11px] text-slate-500">Excess requests rejected</span>
            </div>

            {/* Threshold Point */}
            <div className="p-4 rounded-lg border border-slate-800 bg-slate-900/60">
              <span className="text-xs uppercase text-slate-400 font-semibold tracking-wider block">
                Triggered At Request
              </span>
              <span className="text-2xl font-bold font-mono text-amber-400 mt-1 block tabular-nums">
                {result.thresholdDetectedAt ? `#${result.thresholdDetectedAt}` : 'None'}
              </span>
              <span className="text-[11px] text-slate-500">Limit enforcement accuracy</span>
            </div>

            {/* Latency Average */}
            <div className="p-4 rounded-lg border border-slate-800 bg-slate-900/60">
              <span className="text-xs uppercase text-slate-400 font-semibold tracking-wider block">
                Average Latency
              </span>
              <span className="text-2xl font-bold font-mono text-cyan-300 mt-1 block tabular-nums">
                {result.avgLatencyMs} ms
              </span>
              <span className="text-[11px] text-slate-500">
                Min: {result.minLatencyMs}ms · Max: {result.maxLatencyMs}ms
              </span>
            </div>
          </div>

          {/* Observed Security Headers */}
          <div className="p-4 rounded-lg border border-slate-800 bg-slate-900/40 space-y-2">
            <span className="text-xs font-semibold text-white uppercase tracking-wider block">
              Observed Throttling Response Headers
            </span>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 font-mono text-xs">
              <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
                <span className="text-[10px] text-slate-500 block uppercase">X-RateLimit-Limit</span>
                <span className="text-cyan-300 font-semibold">{result.headersObserved.rateLimitLimit} req/window</span>
              </div>
              <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
                <span className="text-[10px] text-slate-500 block uppercase">X-RateLimit-Remaining</span>
                <span className="text-amber-300 font-semibold">{result.headersObserved.rateLimitRemaining}</span>
              </div>
              <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
                <span className="text-[10px] text-slate-500 block uppercase">Retry-After</span>
                <span className="text-rose-300 font-semibold">{result.headersObserved.retryAfter || 'N/A'}</span>
              </div>
            </div>
          </div>

          {/* Visual Sequence Timeline Grid */}
          <div className="p-4 rounded-lg border border-slate-800 bg-slate-900/60 space-y-3">
            <div className="flex items-center justify-between text-xs">
              <span className="font-semibold text-white">
                Burst Request Sequence & Status Matrix
              </span>
              <div className="flex items-center gap-3 text-[11px]">
                <span className="flex items-center gap-1.5">
                  <span className="w-2.5 h-2.5 rounded-sm bg-emerald-500" />
                  <span className="text-slate-400">200 OK</span>
                </span>
                <span className="flex items-center gap-1.5">
                  <span className="w-2.5 h-2.5 rounded-sm bg-rose-500" />
                  <span className="text-slate-400">429 Throttled</span>
                </span>
              </div>
            </div>

            {/* Matrix of request boxes */}
            <div className="grid grid-cols-6 sm:grid-cols-10 md:grid-cols-15 gap-1.5 pt-1">
              {result.requestTimeline.map((item) => (
                <div
                  key={item.seq}
                  className={`p-2 rounded text-center font-mono text-[10px] border transition-transform hover:scale-105 ${
                    item.throttled
                      ? 'bg-rose-950/60 border-rose-600/40 text-rose-300'
                      : 'bg-emerald-950/60 border-emerald-600/40 text-emerald-300'
                  }`}
                  title={`Request #${item.seq}: Status ${item.status} (${item.latencyMs}ms)`}
                >
                  <div className="font-bold">#{item.seq}</div>
                  <div className="text-[9px] opacity-80">{item.status}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Python Implementation Recipe */}
      <div className="p-4 rounded-lg border border-slate-800 bg-slate-900/60 space-y-3">
        <div className="flex items-center justify-between text-xs">
          <span className="font-semibold text-white flex items-center gap-1.5">
            <Zap className="w-4 h-4 text-cyan-400" />
            FastAPI Rate Limiting Code (Slowapi Token Bucket)
          </span>
          <button
            onClick={() => copySnippet(pythonSlowapiSnippet)}
            className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1 transition-colors text-[11px]"
          >
            {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
            <span>{copied ? 'Copied' : 'Copy Code'}</span>
          </button>
        </div>
        <pre className="p-3 bg-slate-950 rounded-md border border-slate-800 font-mono text-[11px] text-cyan-200 overflow-x-auto leading-relaxed">
          <code>{pythonSlowapiSnippet}</code>
        </pre>
      </div>
    </div>
  );
};
