"use client";

import { useState } from "react";
import {
  Shield, AlertTriangle, Cpu, Lock, Eye, Terminal,
  Code2, Globe, Box, Zap, ChevronDown, ChevronUp,
} from "lucide-react";
import type { DynamicSandbox, MobSFResult } from "@/lib/types";

// ── Severity badge ─────────────────────────────────────────────────────────────
function SeverityBadge({ level }: { level: string }) {
  const colors: Record<string, string> = {
    CRITICAL: "bg-[rgba(204,34,0,0.12)] text-danger border-danger",
    HIGH:     "bg-[rgba(249,115,22,0.12)] text-[#f97316] border-[#f97316]",
    MEDIUM:   "bg-[rgba(251,191,36,0.12)] text-[#fbbf24] border-[#fbbf24]",
    LOW:      "bg-[rgba(74,222,128,0.12)] text-[#4ade80] border-[#4ade80]",
    SAFE:     "bg-[rgba(34,211,238,0.12)] text-[#22d3ee] border-[#22d3ee]",
    INFO:     "bg-[rgba(100,116,139,0.12)] text-[#64748b] border-[#64748b]",
  };
  return (
    <span className={`text-[0.6rem] font-bold px-2 py-0.5 border font-mono uppercase ${colors[level] ?? colors.INFO}`}>
      {level}
    </span>
  );
}

// ── Collapsible section ────────────────────────────────────────────────────────
function Section({
  title, icon: Icon, count, children, defaultOpen = true,
}: {
  title: string; icon: React.ElementType; count?: number; children: React.ReactNode; defaultOpen?: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="bg-surface-raised border border-border corner-brackets overflow-hidden">
      <button
        className="w-full flex items-center gap-3 px-5 py-4 text-left hover:bg-[#080808] transition-colors"
        onClick={() => setOpen(!open)}
      >
        <Icon className="w-4 h-4 text-primary" />
        <span className="text-[0.7rem] font-bold font-mono uppercase tracking-widest text-secondary">{title}</span>
        {count !== undefined && (
          <span className="ml-2 text-[0.6rem] font-mono text-muted bg-surface-raised px-2 py-0.5 border border-border">
            {count}
          </span>
        )}
        <span className="ml-auto text-muted">
          {open ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
        </span>
      </button>
      {open && <div className="px-5 pb-5 space-y-3 border-t border-border">{children}</div>}
    </div>
  );
}

// ── API hit row ────────────────────────────────────────────────────────────────
function ApiRow({ api, file, severity }: { api: string; file: string; severity: string }) {
  return (
    <div className="flex items-start gap-3 py-2 border-b border-border last:border-0">
      <SeverityBadge level={severity} />
      <div className="flex-1 min-w-0">
        <p className="text-[0.7rem] font-mono text-secondary font-bold truncate">{api}</p>
        <p className="text-[0.6rem] font-mono text-muted truncate">{file}</p>
      </div>
    </div>
  );
}

// ── Main component ─────────────────────────────────────────────────────────────

interface Props {
  analysisId: string;
  dynamic?: DynamicSandbox;
  mobsf?: MobSFResult;
}

export default function DynamicAnalysisPanel({ analysisId, dynamic, mobsf }: Props) {
  const [triggering, setTriggering] = useState(false);
  const [triggerMsg, setTriggerMsg] = useState<string | null>(null);

  const handleTrigger = async () => {
    setTriggering(true);
    setTriggerMsg(null);
    try {
      const res = await fetch(`/api/sandbox/${analysisId}/trigger`, { method: "POST" });
      const data = await res.json();
      if (res.ok) {
        setTriggerMsg("Sandbox triggered! Refresh results in ~60 seconds.");
      } else {
        setTriggerMsg(data.detail || "Failed to trigger sandbox.");
      }
    } catch (e) {
      setTriggerMsg("Network error — is the backend running?");
    } finally {
      setTriggering(false);
    }
  };

  // ── No sandbox run yet ──────────────────────────────────────────────────────
  if (!dynamic && !mobsf) {
    return (
      <div className="space-y-6">
        <div className="bg-surface-raised border border-border p-8 corner-brackets flex flex-col items-center gap-4 text-center">
          <Box className="w-12 h-12 text-[#222]" />
          <p className="text-[0.75rem] font-mono text-muted uppercase tracking-widest">
            Sandbox analysis not yet run for this APK
          </p>
          <p className="text-[0.65rem] font-mono text-[#333] max-w-md">
            The sandbox decompiles the APK with apktool, walks smali bytecode for behavioral intelligence,
            and queries MobSF for deep static analysis.
          </p>
          <button
            onClick={handleTrigger}
            disabled={triggering}
            className="btn-hex px-6 py-2 text-[0.65rem] mt-2 disabled:opacity-50"
          >
            <span className="relative z-10 flex items-center gap-2">
              {triggering ? "Triggering..." : "Run Sandbox Now"}
            </span>
          </button>
          {triggerMsg && (
            <p className="text-[0.65rem] font-mono text-[#22d3ee] mt-1">{triggerMsg}</p>
          )}
        </div>
      </div>
    );
  }

  // ── Sandbox unavailable (Docker not running) ────────────────────────────────
  const sandboxUnavailable = dynamic && !dynamic.sandbox_available;

  return (
    <div className="space-y-6">

      {/* ── Status Header ─────────────────────────────────────────────── */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">

        {/* Frida Sandbox Status */}
        <div className="bg-surface-raised border border-border p-5 corner-brackets">
          <p className="text-[0.6rem] font-mono text-muted uppercase tracking-widest mb-2">Frida Sandbox</p>
          {dynamic?.sandbox_available ? (
            <>
              <div className="flex items-center gap-2 mb-1">
                <span className="w-2 h-2 rounded-full bg-[#4ade80] animate-pulse" />
                <span className="text-[0.65rem] font-mono text-[#4ade80] uppercase font-bold">Complete</span>
              </div>
              <p className="text-[0.6rem] font-mono text-muted">
                {dynamic.smali_analysis?.smali_file_count ?? 0} smali files ·{" "}
                {dynamic.smali_analysis?.total_methods ?? 0} methods · {dynamic.analysis_time_sec}s
              </p>
            </>
          ) : (
            <>
              <div className="flex items-center gap-2 mb-1">
                <span className="w-2 h-2 rounded-full bg-[#f43f5e]" />
                <span className="text-[0.65rem] font-mono text-danger uppercase font-bold">Unavailable</span>
              </div>
              <p className="text-[0.6rem] font-mono text-muted truncate">{dynamic?.error ?? "Docker not running"}</p>
            </>
          )}
        </div>

        {/* Behavioral Score */}
        {dynamic?.behavioral_score && (
          <div className="bg-surface-raised border border-border p-5 corner-brackets">
            <p className="text-[0.6rem] font-mono text-muted uppercase tracking-widest mb-2">Behavioral Score</p>
            <div className="flex items-end gap-2">
              <span className="text-4xl font-black text-secondary font-mono">
                {dynamic.behavioral_score.score}
              </span>
              <span className="text-muted font-mono text-sm mb-1">/100</span>
              <SeverityBadge level={dynamic.behavioral_score.level} />
            </div>
            <div className="mt-2 w-full h-1 bg-surface-raised">
              <div
                className="h-full transition-all"
                style={{
                  width: `${dynamic.behavioral_score.score}%`,
                  background: dynamic.behavioral_score.score >= 75 ? "#f43f5e"
                    : dynamic.behavioral_score.score >= 55 ? "#f97316"
                    : dynamic.behavioral_score.score >= 30 ? "#fbbf24" : "#22d3ee",
                }}
              />
            </div>
          </div>
        )}

        {/* MobSF Status */}
        <div className="bg-surface-raised border border-border p-5 corner-brackets">
          <p className="text-[0.6rem] font-mono text-muted uppercase tracking-widest mb-2">MobSF Deep Scan</p>
          {mobsf?.available ? (
            <>
              <div className="flex items-center gap-2 mb-1">
                <span className="w-2 h-2 rounded-full bg-[#4ade80] animate-pulse" />
                <span className="text-[0.65rem] font-mono text-[#4ade80] uppercase font-bold">Complete</span>
              </div>
              <p className="text-[0.6rem] font-mono text-muted">
                Score: {mobsf.security_score ?? "N/A"} · {mobsf.findings?.length ?? 0} findings
              </p>
            </>
          ) : (
            <>
              <div className="flex items-center gap-2 mb-1">
                <span className="w-2 h-2 rounded-full bg-[#fbbf24]" />
                <span className="text-[0.65rem] font-mono text-[#fbbf24] uppercase font-bold">Not Connected</span>
              </div>
              <p className="text-[0.6rem] font-mono text-muted truncate">{mobsf?.error ?? "MobSF container not running"}</p>
            </>
          )}
        </div>
      </div>

      {/* ── Behavioral Flags ───────────────────────────────────────────── */}
      {dynamic?.behavioral_score?.flags && dynamic.behavioral_score.flags.length > 0 && (
        <Section title="Behavioral Flags" icon={AlertTriangle} count={dynamic.behavioral_score.flags.length}>
          <div className="mt-3 space-y-2">
            {dynamic.behavioral_score.flags.map((flag, i) => (
              <div key={i} className="flex items-start gap-2 text-[0.65rem] font-mono">
                <span className="text-danger mt-0.5 shrink-0">▶</span>
                <span className="text-[#ccc] uppercase">{flag}</span>
              </div>
            ))}
          </div>
        </Section>
      )}

      {/* ── API Call Analysis ──────────────────────────────────────────── */}
      {dynamic?.smali_analysis && (
        <Section
          title="Android API Calls Detected"
          icon={Cpu}
          count={(dynamic.smali_analysis.critical_apis?.length ?? 0) +
                 (dynamic.smali_analysis.high_apis?.length ?? 0) +
                 (dynamic.smali_analysis.medium_apis?.length ?? 0)}
        >
          <div className="mt-3 space-y-1">
            {[
              ...dynamic.smali_analysis.critical_apis.map(h => ({ ...h, severity: "CRITICAL" })),
              ...dynamic.smali_analysis.high_apis.map(h => ({ ...h, severity: "HIGH" })),
              ...dynamic.smali_analysis.medium_apis.map(h => ({ ...h, severity: "MEDIUM" })),
            ].map((hit, i) => (
              <ApiRow key={i} {...hit} />
            ))}
            {dynamic.smali_analysis.critical_apis.length === 0 &&
             dynamic.smali_analysis.high_apis.length === 0 && (
              <p className="text-[0.65rem] font-mono text-muted py-2">No dangerous API calls detected.</p>
            )}
          </div>
        </Section>
      )}

      {/* ── Crypto Usage ──────────────────────────────────────────────── */}
      {dynamic?.smali_analysis?.crypto_usage &&
       Object.keys(dynamic.smali_analysis.crypto_usage).length > 0 && (
        <Section title="Cryptography Usage" icon={Lock} count={Object.keys(dynamic.smali_analysis.crypto_usage).length}>
          <div className="mt-3 grid grid-cols-2 md:grid-cols-4 gap-3">
            {Object.entries(dynamic.smali_analysis.crypto_usage).map(([algo, files]) => (
              <div
                key={algo}
                className={`p-3 border text-center ${
                  ["DES", "XOR", "RC4", "MD5"].includes(algo)
                    ? "border-[#f97316]/40 bg-[rgba(249,115,22,0.05)]"
                    : "border-border"
                }`}
              >
                <p className="text-sm font-bold font-mono text-secondary">{algo}</p>
                <p className="text-[0.6rem] font-mono text-muted mt-1">{files.length} file(s)</p>
                {["DES", "XOR", "RC4"].includes(algo) && (
                  <p className="text-[0.55rem] font-mono text-[#f97316] mt-1 uppercase">Weak</p>
                )}
              </div>
            ))}
          </div>
        </Section>
      )}

      {/* ── Anti-Analysis ─────────────────────────────────────────────── */}
      {dynamic?.smali_analysis?.antianalysis &&
       Object.keys(dynamic.smali_analysis.antianalysis).length > 0 && (
        <Section title="Anti-Analysis Techniques" icon={Eye} count={Object.keys(dynamic.smali_analysis.antianalysis).length}>
          <div className="mt-3 space-y-3">
            {Object.entries(dynamic.smali_analysis.antianalysis).map(([technique, instances]) => (
              <div key={technique} className="border border-[#111] p-3">
                <div className="flex items-center gap-2 mb-2">
                  <span className="text-[0.65rem] font-bold font-mono text-danger uppercase">
                    {technique.replace(/_/g, " ")}
                  </span>
                  <span className="text-[0.6rem] font-mono text-muted">
                    {instances.length} instance(s)
                  </span>
                </div>
                {instances.slice(0, 2).map((inst, i) => (
                  <p key={i} className="text-[0.6rem] font-mono text-muted truncate">
                    {inst.file}: <span className="text-muted">{inst.match}</span>
                  </p>
                ))}
              </div>
            ))}
          </div>
        </Section>
      )}

      {/* ── Sensitive Data ────────────────────────────────────────────── */}
      {dynamic?.smali_analysis?.sensitive_data &&
       Object.keys(dynamic.smali_analysis.sensitive_data).length > 0 && (
        <Section title="Sensitive Data in Code" icon={Shield} count={Object.keys(dynamic.smali_analysis.sensitive_data).length} defaultOpen={false}>
          <div className="mt-3 space-y-3">
            {Object.entries(dynamic.smali_analysis.sensitive_data).map(([dtype, instances]) => (
              <div key={dtype} className="border border-danger/20 bg-[rgba(244,63,94,0.03)] p-3">
                <p className="text-[0.65rem] font-bold font-mono text-danger uppercase mb-2">
                  {dtype.replace(/_/g, " ")}
                </p>
                {instances.slice(0, 3).map((inst, i) => (
                  <div key={i} className="text-[0.6rem] font-mono text-muted mb-1">
                    <span className="text-muted">{inst.file}:</span>{" "}
                    <span className="text-danger/80 font-bold">{inst.snippet.slice(0, 80)}</span>
                  </div>
                ))}
              </div>
            ))}
          </div>
        </Section>
      )}

      {/* ── Dynamic Loading & Native Libs ─────────────────────────────── */}
      {dynamic?.smali_analysis && (
        dynamic.smali_analysis.dynamic_loading.length > 0 ||
        dynamic.smali_analysis.native_libs.length > 0
      ) && (
        <Section title="Dynamic Code Loading & Native Libraries" icon={Code2} defaultOpen={false}>
          <div className="mt-3 grid grid-cols-1 md:grid-cols-2 gap-4">
            {dynamic!.smali_analysis!.dynamic_loading.length > 0 && (
              <div>
                <p className="text-[0.6rem] font-mono text-[#f97316] uppercase mb-2">Dynamic DEX Loading ({dynamic!.smali_analysis!.dynamic_loading.length})</p>
                {dynamic!.smali_analysis!.dynamic_loading.slice(0, 5).map((f, i) => (
                  <p key={i} className="text-[0.6rem] font-mono text-muted truncate py-0.5">{f}</p>
                ))}
              </div>
            )}
            {dynamic!.smali_analysis!.native_libs.length > 0 && (
              <div>
                <p className="text-[0.6rem] font-mono text-[#f97316] uppercase mb-2">Native Libraries ({dynamic!.smali_analysis!.native_libs.length})</p>
                {dynamic!.smali_analysis!.native_libs.map((lib, i) => (
                  <p key={i} className="text-[0.65rem] font-mono text-secondary py-0.5">{lib}</p>
                ))}
              </div>
            )}
          </div>
        </Section>
      )}

      {/* ── Network Endpoints ─────────────────────────────────────────── */}
      {dynamic?.smali_analysis?.network_endpoints && dynamic.smali_analysis.network_endpoints.length > 0 && (
        <Section title="Hardcoded Network Endpoints" icon={Globe} count={dynamic.smali_analysis.network_endpoints.length} defaultOpen={false}>
          <div className="mt-3 space-y-1">
            {dynamic.smali_analysis.network_endpoints.slice(0, 20).map((url, i) => (
              <p key={i} className="text-[0.65rem] font-mono text-[#22d3ee] truncate py-0.5 border-b border-border">
                {url}
              </p>
            ))}
          </div>
        </Section>
      )}

      {/* ── MobSF Findings ────────────────────────────────────────────── */}
      {mobsf?.available && mobsf.findings && mobsf.findings.length > 0 && (
        <Section title="MobSF Security Findings" icon={Terminal} count={mobsf.findings.length} defaultOpen={false}>
          <div className="mt-3 space-y-2">
            {mobsf.findings.slice(0, 20).map((finding, i) => (
              <div key={i} className="border border-border p-3">
                <div className="flex items-start gap-2 mb-1">
                  <SeverityBadge level={finding.severity} />
                  <p className="text-[0.65rem] font-mono text-secondary font-bold uppercase">{finding.title}</p>
                </div>
                {finding.desc && (
                  <p className="text-[0.6rem] font-mono text-muted mt-1">{finding.desc}</p>
                )}
                {finding.files.length > 0 && (
                  <p className="text-[0.6rem] font-mono text-[#333] mt-1">
                    Files: {finding.files.join(", ")}
                  </p>
                )}
              </div>
            ))}
          </div>
        </Section>
      )}

      {/* ── Re-trigger button ─────────────────────────────────────────── */}
      <div className="flex justify-end pt-2">
        <button
          onClick={handleTrigger}
          disabled={triggering}
          className="btn-hex px-5 py-2 text-[0.6rem] disabled:opacity-50"
        >
          <span className="relative z-10 flex items-center gap-2">
            <Zap className="w-3 h-3" />
            {triggering ? "Triggering..." : "Re-run Sandbox"}
          </span>
        </button>
        {triggerMsg && (
          <p className="text-[0.65rem] font-mono text-[#22d3ee] ml-4 self-center">{triggerMsg}</p>
        )}
      </div>

    </div>
  );
}
