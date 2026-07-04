"use client";
import { useEffect, useRef, useState } from "react";
import {
  Shield, Cpu, FileCode, Search, Brain,
  Globe, AlertTriangle, CheckCircle2, Loader2, Zap
} from "lucide-react";

export interface ProgressEvent {
  stage: string;
  pct: number;
  msg: string;
  analysis_id?: string;
  risk_level?: string;
  risk_score?: number;
}

interface Props {
  jobId: string;
  onComplete: (analysisId: string) => void;
  onError: (msg: string) => void;
}

const STAGE_META: Record<string, { label: string; icon: React.ElementType; color: string }> = {
  queued:      { label: "Queued",             icon: Loader2,       color: "text-slate-200" },
  hashing:     { label: "Hashing file",       icon: Cpu,           color: "text-blue-400" },
  manifest:    { label: "Manifest parser",    icon: FileCode,      color: "text-green-400" },
  strings:     { label: "String extractor",   icon: Search,        color: "text-yellow-400" },
  certificate: { label: "Certificate",        icon: Shield,        color: "text-purple-400" },
  yara:        { label: "YARA scanner",       icon: AlertTriangle, color: "text-orange-400" },
  obfuscation: { label: "Obfuscation check",  icon: Cpu,           color: "text-rose-400" },
  india_ioc:   { label: "India IOC check",    icon: Globe,         color: "text-amber-400" },
  threat_intel:{ label: "Threat intel",       icon: Globe,         color: "text-cyan-400" },
  risk_score:  { label: "Risk scoring",       icon: AlertTriangle, color: "text-rose-500" },
  mitre:       { label: "MITRE ATT&CK",       icon: Zap,           color: "text-violet-400" },
  ai:          { label: "AI narrative",       icon: Brain,         color: "text-indigo-400" },
  saving:      { label: "Saving to DB",       icon: Cpu,           color: "text-slate-200" },
  complete:    { label: "Complete!",          icon: CheckCircle2,  color: "text-green-400" },
  error:       { label: "Failed",             icon: AlertTriangle, color: "text-rose-500" },
};

const RISK_COLORS: Record<string, string> = {
  CRITICAL: "text-rose-400 border-rose-500/30 bg-rose-500/10",
  HIGH:     "text-orange-400 border-orange-500/30 bg-orange-500/10",
  MEDIUM:   "text-yellow-400 border-yellow-500/30 bg-yellow-500/10",
  LOW:      "text-green-400 border-green-500/30 bg-green-500/10",
  SAFE:     "text-emerald-400 border-emerald-500/30 bg-emerald-500/10",
};

export default function AnalysisProgress({ jobId, onComplete, onError }: Props) {
  const [events, setEvents] = useState<ProgressEvent[]>([]);
  const [current, setCurrent] = useState<ProgressEvent | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const logRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    let isCleaningUp = false;
    // Resolve backend API URL dynamically to avoid localhost/127.0.0.1/IP mismatch issues
    let wsUrl = "";
    const apiBase = process.env.NEXT_PUBLIC_API_URL;
    if (apiBase) {
      const wsBase = apiBase.replace(/^http/, "ws");
      wsUrl = `${wsBase}/api/ws/${jobId}`;
    } else {
      const host = typeof window !== "undefined" ? window.location.hostname : "localhost";
      wsUrl = `ws://${host}:8000/api/ws/${jobId}`;
    }
    
    const ws = new WebSocket(wsUrl);
    wsRef.current = ws;

    ws.onopen = () => {
      console.log("WS connected for job", jobId);
    };

    ws.onmessage = (e) => {
      try {
        const event: ProgressEvent = JSON.parse(e.data);
        if (event.stage === "ping") {
          return; // ignore keep-alive pings
        }
        
        setCurrent(event);
        setEvents((prev) => {
          // Don't duplicate stage events
          const filtered = prev.filter((p) => p.stage !== event.stage);
          return [...filtered, event].sort((a, b) => a.pct - b.pct);
        });

        if (event.stage === "complete" && event.analysis_id) {
          setTimeout(() => onComplete(event.analysis_id!), 600);
        }
        if (event.stage === "error") {
          onError(event.msg || "Analysis failed");
        }
      } catch {
        // ignore parse errors
      }
    };

    ws.onerror = () => {
      if (!isCleaningUp) {
        onError("Connection to analysis server lost");
      }
    };
    ws.onclose = () => console.log("WS closed");

    return () => {
      isCleaningUp = true;
      ws.close();
    };
  }, [jobId, onComplete, onError]);

  // Auto-scroll the log
  useEffect(() => {
    if (logRef.current) {
      logRef.current.scrollTop = logRef.current.scrollHeight;
    }
  }, [events]);

  const pct = current?.pct ?? 0;
  const stageMeta = current ? (STAGE_META[current.stage] ?? STAGE_META.queued) : STAGE_META.queued;
  const Icon = stageMeta.icon;

  return (
    <div className="w-full max-w-2xl mx-auto space-y-6">
      {/* Main progress card */}
      <div className="rounded-2xl border border-slate-700/40 bg-slate-900/80 p-8 space-y-6 backdrop-blur-sm">
        {/* Icon + Stage */}
        <div className="flex flex-col items-center gap-3">
          <div className="relative">
            <div className="w-20 h-20 rounded-full border-2 border-slate-700/50 flex items-center justify-center bg-slate-800/60">
              <Icon className={`w-8 h-8 ${stageMeta.color} ${pct < 100 && pct > 0 ? "animate-pulse" : ""}`} />
            </div>
            {/* Spinning ring */}
            {pct > 0 && pct < 100 && (
              <svg className="absolute inset-0 w-20 h-20 -rotate-90" viewBox="0 0 80 80">
                <circle cx="40" cy="40" r="36" fill="none" stroke="rgba(99,102,241,0.15)" strokeWidth="3" />
                <circle
                  cx="40" cy="40" r="36" fill="none"
                  stroke="rgb(99,102,241)" strokeWidth="3"
                  strokeLinecap="round"
                  strokeDasharray={`${2 * Math.PI * 36}`}
                  strokeDashoffset={`${2 * Math.PI * 36 * (1 - pct / 100)}`}
                  className="transition-all duration-700 ease-out"
                />
              </svg>
            )}
            {pct === 100 && (
              <div className="absolute inset-0 w-20 h-20 rounded-full border-2 border-green-400/60 animate-ping" />
            )}
          </div>

          <div className="text-center">
            <p className={`text-lg font-semibold ${stageMeta.color}`}>{stageMeta.label}</p>
            <p className="text-sm text-slate-200 mt-0.5">{current?.msg || "Connecting to analysis server..."}</p>
          </div>
        </div>

        {/* Progress bar */}
        <div className="space-y-2">
          <div className="flex justify-between text-xs text-slate-300">
            <span>Progress</span>
            <span className="font-mono text-slate-300">{pct}%</span>
          </div>
          <div className="h-2 bg-slate-800 rounded-full overflow-hidden">
            <div
              className="h-full rounded-full transition-all duration-700 ease-out"
              style={{
                width: `${pct}%`,
                background: pct === 100
                  ? "linear-gradient(90deg, #10b981, #34d399)"
                  : "linear-gradient(90deg, #4f46e5, #7c3aed, #6366f1)",
              }}
            />
          </div>
        </div>

        {/* Risk verdict on complete */}
        {current?.stage === "complete" && current.risk_level && (
          <div className={`rounded-xl border px-4 py-3 text-center ${RISK_COLORS[current.risk_level] ?? RISK_COLORS.SAFE}`}>
            <p className="text-xs font-medium uppercase tracking-widest mb-1">Verdict</p>
            <p className="text-2xl font-bold">{current.risk_level}</p>
            <p className="text-sm mt-0.5">Risk score: {current.risk_score}/100</p>
          </div>
        )}
      </div>

      {/* Stage log */}
      <div
        ref={logRef}
        className="rounded-xl border border-slate-700/30 bg-slate-950/60 p-4 space-y-1.5 max-h-48 overflow-y-auto scrollbar-thin scrollbar-track-transparent scrollbar-thumb-slate-700"
      >
        <p className="text-[10px] text-slate-200 font-mono uppercase tracking-widest mb-2">Analysis log</p>
        {events.map((ev, i) => {
          const m = STAGE_META[ev.stage] ?? STAGE_META.queued;
          const Ic = m.icon;
          return (
            <div key={i} className="flex items-start gap-2 text-xs">
              <span className={`flex-shrink-0 mt-0.5 ${m.color}`}>
                <Ic className="w-3 h-3" />
              </span>
              <span className="text-slate-300 font-mono w-8 flex-shrink-0">{ev.pct}%</span>
              <span className="text-slate-200">{ev.msg}</span>
            </div>
          );
        })}
        {events.length === 0 && (
          <p className="text-xs text-slate-200 text-center py-2">Waiting for analysis to start...</p>
        )}
      </div>
    </div>
  );
}
