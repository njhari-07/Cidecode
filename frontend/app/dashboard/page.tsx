"use client";

import { useEffect, useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { ChevronRight, RefreshCw, BarChart3, TrendingUp, Radio, Clock } from "lucide-react";
import { getStats, uploadApk } from "@/lib/api";
import type { DashboardStats } from "@/lib/types";
import DropZone from "@/components/DropZone";
import AnalysisProgress from "@/components/AnalysisProgress";

// ── Colour helpers ──────────────────────────────────────────────────────────
const RISK_COLORS: Record<string, string> = {
  CRITICAL: "text-danger",
  HIGH:     "text-[#f97316]",
  MEDIUM:   "text-[#fbbf24]",
  LOW:      "text-[#4ade80]",
  SAFE:     "text-[#22d3ee]",
};

const RISK_BG: Record<string, string> = {
  CRITICAL: "bg-[rgba(244,63,94,0.1)] border-danger",
  HIGH:     "bg-[rgba(249,115,22,0.1)] border-[#f97316]",
  MEDIUM:   "bg-[rgba(251,191,36,0.1)] border-[#fbbf24]",
  LOW:      "bg-[rgba(74,222,128,0.1)] border-[#4ade80]",
  SAFE:     "bg-[rgba(34,211,238,0.1)] border-[#22d3ee]",
};

const FAMILY_COLORS: Record<string, string> = {
  BankingTrojan:  "#f43f5e",
  Ransomware:     "#fb923c",
  Spyware:        "#a78bfa",
  RAT:            "#0052FF",
  Dropper:        "#f59e0b",
  Adware:         "#34d399",
  SMSMalware:     "#ec4899",
  Riskware:       "#94a3b8",
  Benign:         "#22d3ee",
  Unknown:        "#475569",
};

// ── Mini Donut Chart ────────────────────────────────────────────────────────
function DonutChart({ data }: { data: Record<string, number> }) {
  const entries = Object.entries(data).filter(([, v]) => v > 0);
  const total   = entries.reduce((s, [, v]) => s + v, 0);
  if (total === 0) return <p className="text-muted font-mono text-xs text-center py-6">[ NO DATA ]</p>;

  const R = 60, STROKE = 18, C = 2 * Math.PI * R;
  let offset = 0;

  return (
    <div className="flex flex-col items-center gap-4">
      <svg viewBox="0 0 160 160" className="w-40 h-40">
        <circle cx="80" cy="80" r={R} fill="none" stroke="#111" strokeWidth={STROKE} />
        {entries.map(([label, val]) => {
          const pct  = val / total;
          const dash = pct * C;
          const gap  = C - dash;
          const rot  = offset * 360 - 90;
          offset += pct;
          return (
            <circle
              key={label}
              cx="80" cy="80" r={R}
              fill="none"
              stroke={FAMILY_COLORS[label] ?? "#555"}
              strokeWidth={STROKE}
              strokeDasharray={`${dash} ${gap}`}
              strokeDashoffset={0}
              transform={`rotate(${rot} 80 80)`}
              className="transition-all duration-700"
            />
          );
        })}
        <text x="80" y="76" textAnchor="middle" className="fill-white font-mono" fontSize="20" fontWeight="bold">{total}</text>
        <text x="80" y="94" textAnchor="middle" className="fill-[#555] font-mono uppercase" fontSize="8" letterSpacing="2">TOTAL</text>
      </svg>

      <div className="grid grid-cols-2 gap-x-4 gap-y-2 w-full">
        {entries.map(([label, val]) => (
          <div key={label} className="flex items-center gap-2">
            <div className="w-1.5 h-1.5 rounded-none shrink-0" style={{ background: FAMILY_COLORS[label] ?? "#555" }} />
            <span className="text-[0.65rem] text-muted font-mono uppercase tracking-wider truncate">{label}</span>
            <span className="text-[0.65rem] text-secondary ml-auto font-mono">{val}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Risk Bar Chart ──────────────────────────────────────────────────────────
function RiskBars({ stats }: { stats: DashboardStats }) {
  const bars = [
    { label: "Critical", value: stats.critical_count ?? 0, color: "#f43f5e" },
    { label: "High",     value: stats.high_count    ?? 0, color: "#f97316" },
    { label: "Medium",   value: stats.medium_count  ?? 0, color: "#fbbf24" },
    { label: "Low",      value: stats.low_count     ?? 0, color: "#4ade80" },
    { label: "Safe",     value: stats.safe_count    ?? 0, color: "#22d3ee" },
  ];
  const max = Math.max(...bars.map(b => b.value), 1);

  return (
    <div className="space-y-4 pt-2">
      {bars.map(b => (
        <div key={b.label} className="flex items-center gap-3">
          <span className="text-[0.65rem] font-mono text-muted uppercase w-14 shrink-0">{b.label}</span>
          <div className="flex-1 h-1 bg-surface-raised overflow-hidden">
            <div
              className="h-full transition-all duration-1000 relative"
              style={{ width: `${(b.value / max) * 100}%`, background: b.color }}
            >
              <div className="absolute right-0 top-1/2 -translate-y-1/2 w-1 h-1 bg-white shadow-[0_0_5px_#fff]"></div>
            </div>
          </div>
          <span className="text-xs font-mono text-secondary w-6 text-right">{b.value}</span>
        </div>
      ))}
    </div>
  );
}

// ── Stat Card ───────────────────────────────────────────────────────────────
function StatCard({
  label, value, pulseColor,
}: {
  label: string; value: string | number; pulseColor?: string;
}) {
  return (
    <div className="bg-surface-raised border border-border p-4 corner-brackets group hover:bg-[#080808] transition-colors relative">
      <div className="flex justify-between items-center mb-2">
        <div className="text-[0.6rem] font-mono text-muted uppercase tracking-widest">{label}</div>
        {pulseColor && <span className={`w-1.5 h-1.5 rounded-full bg-[${pulseColor}] animate-pulse shadow-[0_0_8px_${pulseColor}]`} />}
      </div>
      <div className="text-xl lg:text-3xl font-mono text-secondary tracking-tight">{value}</div>
    </div>
  );
}

// ── Recent Scans Table ─────────────────────────────────────────────────────
interface RecentScan {
  id: string; filename: string; package_name: string;
  risk_score: number; risk_level: string; created_at: string;
}

function RecentScansTable({ scans }: { scans: RecentScan[] }) {
  if (!scans.length) {
    return <div className="text-center py-12 text-muted font-mono text-xs uppercase">[ NO SCANS RECORDED ]</div>;
  }

  return (
    <div className="overflow-x-auto mt-4">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-border">
            <th className="text-left py-2 px-2 text-muted font-mono text-[0.65rem] uppercase tracking-widest">APK / Package</th>
            <th className="text-center py-2 px-2 text-muted font-mono text-[0.65rem] uppercase tracking-widest">Score</th>
            <th className="text-center py-2 px-2 text-muted font-mono text-[0.65rem] uppercase tracking-widest">Risk</th>
            <th className="text-right py-2 px-2 text-muted font-mono text-[0.65rem] uppercase tracking-widest">Scanned</th>
            <th className="py-2 px-2" />
          </tr>
        </thead>
        <tbody className="font-mono text-xs">
          {scans.map((s) => (
            <tr key={s.id} className="border-b border-border hover:bg-[#080808] transition-colors group">
              <td className="py-3 px-2">
                <p className="text-[#DDD] truncate max-w-[200px]">{s.filename}</p>
                <p className="text-[0.65rem] text-muted truncate max-w-[200px]">{s.package_name}</p>
              </td>
              <td className="py-3 px-2 text-center">
                <span className={RISK_COLORS[s.risk_level] ?? "text-secondary"}>{s.risk_score}</span>
              </td>
              <td className="py-3 px-2 text-center">
                <span className={`text-[0.6rem] px-2 py-0.5 border ${RISK_BG[s.risk_level] ?? "border-border text-muted"}`}>
                  {s.risk_level}
                </span>
              </td>
              <td className="py-3 px-2 text-right text-muted whitespace-nowrap">
                {new Date(s.created_at).toLocaleString("en-IN", { dateStyle: "short", timeStyle: "short" })}
              </td>
              <td className="py-3 px-2 text-right">
                <Link
                  href={`/results/${s.id}`}
                  className="opacity-0 group-hover:opacity-100 transition-opacity text-primary hover:text-secondary flex items-center justify-end gap-1"
                >
                  [VIEW]
                </Link>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ── Threat Activity Feed ────────────────────────────────────────────────────
function ThreatFeed({ scans }: { scans: RecentScan[] }) {
  const critical = scans.filter(s => s.risk_level === "CRITICAL" || s.risk_level === "HIGH");
  if (!critical.length) {
    return <div className="text-center py-8 text-muted font-mono text-xs uppercase">[ NO CRITICAL THREATS ]</div>;
  }
  return (
    <div className="space-y-1 text-xs font-mono">
      {critical.slice(0, 6).map(s => (
        <Link key={s.id} href={`/results/${s.id}`}
          className="data-row p-2 border-l-2 flex justify-between transition-all duration-300 border-transparent hover:border-danger hover:bg-[rgba(204,34,0,0.1)] group"
        >
          <div className="flex gap-3">
            <span className="text-muted">[{new Date(s.created_at).toLocaleTimeString('en-IN', { hour12: false })}]</span>
            <span className="text-muted group-hover:text-secondary truncate max-w-[150px]">{s.filename}</span>
          </div>
          <span className={RISK_COLORS[s.risk_level]}>{s.risk_level}</span>
        </Link>
      ))}
    </div>
  );
}

type UploadState =
  | { phase: "idle" }
  | { phase: "uploading" }
  | { phase: "progress"; jobId: string }
  | { phase: "error"; msg: string };

// ── Main Dashboard ──────────────────────────────────────────────────────────
export default function DashboardPage() {
  const router = useRouter();
  const [stats, setStats]       = useState<DashboardStats | null>(null);
  const [loading, setLoading]   = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [uploadState, setUploadState] = useState<UploadState>({ phase: "idle" });

  const fetchStats = async (showRefresh = false) => {
    if (showRefresh) setRefreshing(true);
    try {
      const data = await getStats();
      setStats(data);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => { fetchStats(); }, []);

  const handleUpload = async (file: File) => {
    setUploadState({ phase: "uploading" });
    try {
      const res = await uploadApk(file);
      if (res.status === "complete" && res.result) {
        router.push(`/results/${res.result.id}`);
        return;
      }
      setUploadState({ phase: "progress", jobId: res.job_id });
    } catch (err: unknown) {
      setUploadState({ phase: "error", msg: err instanceof Error ? err.message : "Upload failed" });
    }
  };

  const handleComplete = useCallback((id: string) => {
    router.push(`/results/${id}`);
  }, [router]);

  const handleError = useCallback((msg: string) => {
    setUploadState({ phase: "error", msg });
  }, []);

  const isUploading = uploadState.phase === "uploading" || uploadState.phase === "progress";
  const recentScans: RecentScan[] = stats?.recent_analyses ?? [];
  const familyData  = stats?.family_breakdown ?? {};

  return (
    <div className="min-h-screen bg-background grid-bg relative p-6 md:p-12">
      <div className="absolute inset-0 bg-gradient-to-b from-transparent to-black pointer-events-none z-0"></div>

      <div className="max-w-[100rem] mx-auto relative z-10">
        {/* ── Header ── */}
        <div className="mb-10 flex flex-col md:flex-row justify-between items-end gap-8 border-b border-border pb-6">
          <div>
            <h1 className="text-3xl md:text-5xl font-bold tracking-tighter text-secondary uppercase mb-2">Command Terminal</h1>
            <p className="text-[0.65rem] text-muted font-mono tracking-widest uppercase">Global Threat Intelligence Overview</p>
          </div>
          <div className="flex items-center gap-4">
            <button
              onClick={() => fetchStats(true)}
              disabled={refreshing}
              className="text-muted hover:text-secondary transition-colors flex items-center gap-2 text-xs font-mono uppercase"
            >
              <RefreshCw className={`w-3 h-3 ${refreshing ? "animate-spin" : ""}`} />
              [ REFRESH ]
            </button>
            <Link href="/" className="btn-hex px-6 py-2 text-[0.65rem]">
              <span className="relative z-10 flex items-center gap-2">HOME <span></span></span>
            </Link>
          </div>
        </div>

        {loading ? (
          <div className="py-32 flex flex-col items-center justify-center font-mono text-muted text-xs uppercase animate-pulse">
            <span className="mb-4 w-4 h-4 border-2 border-primary border-t-transparent rounded-full animate-spin"></span>
            INITIALIZING TERMINAL...
          </div>
        ) : stats ? (
          <div className="space-y-8">
            {/* ── KPI Cards ── */}
            <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-6">
              <StatCard label="Total Scans" value={stats.total_analyzed ?? 0} />
              <StatCard label="Critical Threats" value={(stats.critical_count ?? 0) + (stats.high_count ?? 0)} pulseColor="#f43f5e" />
              <StatCard label="India Targeted" value={stats.india_targeted ?? 0} />
              <StatCard label="Safe Apps" value={stats.safe_count ?? 0} />
              <StatCard label="PCAP Scans" value={stats.pcap_scans ?? 0} />
              <StatCard label="YARA Rules" value={50} />
            </div>

            {/* ── Main Grid ── */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
              {/* Left: Upload Terminal */}
              <div className="lg:col-span-4 bg-surface-raised border border-border p-6 corner-brackets flex flex-col">
                <div className="text-[0.65rem] font-mono text-muted uppercase tracking-widest mb-4 pb-2 border-b border-border">
                  Ingress Node
                </div>
                <div className="flex-1">
                  {uploadState.phase === "progress" ? (
                    <AnalysisProgress
                      jobId={uploadState.jobId}
                      onComplete={handleComplete}
                      onError={handleError}
                    />
                  ) : (
                    <div className="h-full flex flex-col">
                      <DropZone onUpload={handleUpload} isLoading={isUploading} compact />
                      {uploadState.phase === "error" && (
                        <div className="mt-4 p-2 bg-[rgba(244,63,94,0.1)] border border-[rgba(244,63,94,0.3)] text-danger text-xs font-mono text-center">
                          ERR: {uploadState.msg}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              </div>

              {/* Middle: Family & Risk */}
              <div className="lg:col-span-4 flex flex-col gap-6">
                <div className="bg-surface-raised border border-border p-6 corner-brackets">
                  <div className="text-[0.65rem] font-mono text-muted uppercase tracking-widest mb-4 pb-2 border-b border-border">
                    Malware Families
                  </div>
                  <DonutChart data={familyData} />
                </div>
                
                <div className="bg-surface-raised border border-border p-6 corner-brackets flex-1">
                  <div className="text-[0.65rem] font-mono text-muted uppercase tracking-widest mb-4 pb-2 border-b border-border">
                    Risk Distribution
                  </div>
                  <RiskBars stats={stats} />
                </div>
              </div>

              {/* Right: Live Feed & Scans */}
              <div className="lg:col-span-4 flex flex-col gap-6">
                <div className="bg-surface-raised border border-border p-6 corner-brackets">
                  <div className="flex justify-between items-center text-[0.65rem] font-mono uppercase tracking-widest mb-4 pb-2 border-b border-border">
                    <span className="text-muted">Critical Feed</span>
                    <span className="w-1.5 h-1.5 bg-[#f43f5e] rounded-full animate-ping"></span>
                  </div>
                  <ThreatFeed scans={recentScans} />
                </div>

                <div className="bg-surface-raised border border-border p-6 corner-brackets flex-1">
                  <div className="text-[0.65rem] font-mono text-muted uppercase tracking-widest mb-2 pb-2 border-b border-border">
                    Recent Scans
                  </div>
                  <RecentScansTable scans={recentScans.slice(0, 5)} />
                </div>
              </div>
            </div>
          </div>
        ) : (
          <div className="text-center py-20 text-danger font-mono text-xs uppercase">
            [ ERROR: TERMINAL OFFLINE ]
          </div>
        )}
      </div>
    </div>
  );
}
