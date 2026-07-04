"use client";

import { GitCompareArrows, Link2, ShieldAlert, Unlink } from "lucide-react";
import type { ReactNode } from "react";
import type { CorrelationFinding, CorrelationResult } from "@/lib/types";

interface Props {
  correlation?: CorrelationResult | null;
}

const badgeClass = (severity: string) => {
  if (severity === "CRITICAL") return "text-[#f43f5e] border-[#f43f5e] bg-[rgba(244,63,94,0.1)]";
  if (severity === "HIGH") return "text-[#f97316] border-[#f97316] bg-[rgba(249,115,22,0.1)]";
  if (severity === "MEDIUM") return "text-[#eab308] border-[#eab308] bg-[rgba(234,179,8,0.1)]";
  return "text-[#22c55e] border-[#22c55e] bg-[rgba(34,197,94,0.1)]";
};

function FindingRow({ item, icon }: { item: CorrelationFinding; icon: ReactNode }) {
  return (
    <div className="border border-border bg-background/50 p-3">
      <div className="flex items-start gap-3">
        <span className="text-primary mt-0.5">{icon}</span>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <p className="text-xs text-secondary font-mono break-all">{item.value}</p>
            <span className={`text-[0.55rem] px-1.5 py-0.5 border font-mono uppercase ${badgeClass(item.severity)}`}>
              {item.severity}
            </span>
          </div>
          <p className="mt-1 text-[0.65rem] text-muted font-mono leading-relaxed">{item.explanation}</p>
        </div>
      </div>
    </div>
  );
}

export default function CorrelationPanel({ correlation }: Props) {
  if (!correlation?.available) {
    return (
      <div className="bg-surface-raised border border-border p-5 corner-brackets">
        <div className="flex items-center gap-2 text-secondary font-mono text-sm uppercase">
          <GitCompareArrows className="w-4 h-4 text-primary" />
          Static Dynamic Correlation
        </div>
        <p className="mt-3 text-[0.65rem] font-mono text-muted uppercase tracking-widest">
          Correlation will appear after analysis completes.
        </p>
      </div>
    );
  }

  return (
    <div className="bg-surface-raised border border-border p-5 corner-brackets space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border pb-3">
        <div className="flex items-center gap-2 text-secondary font-mono text-sm uppercase">
          <GitCompareArrows className="w-4 h-4 text-primary" />
          Static Dynamic Correlation
        </div>
        <span className={`text-[0.6rem] px-2 py-0.5 border font-mono uppercase ${badgeClass(correlation.severity)}`}>
          {correlation.severity} · {correlation.score}/100
        </span>
      </div>

      <p className="text-[0.7rem] text-muted font-mono uppercase leading-relaxed">{correlation.summary}</p>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div className="border border-border p-3 bg-background/50">
          <p className="text-[0.6rem] text-muted font-mono uppercase">Static Domains</p>
          <p className="text-xl text-secondary font-mono">{correlation.static_counts.domains}</p>
        </div>
        <div className="border border-border p-3 bg-background/50">
          <p className="text-[0.6rem] text-muted font-mono uppercase">Static IPs</p>
          <p className="text-xl text-secondary font-mono">{correlation.static_counts.ips}</p>
        </div>
        <div className="border border-border p-3 bg-background/50">
          <p className="text-[0.6rem] text-muted font-mono uppercase">Runtime Domains</p>
          <p className="text-xl text-secondary font-mono">{correlation.dynamic_counts.domains}</p>
        </div>
        <div className="border border-border p-3 bg-background/50">
          <p className="text-[0.6rem] text-muted font-mono uppercase">Runtime IPs</p>
          <p className="text-xl text-secondary font-mono">{correlation.dynamic_counts.ips}</p>
        </div>
      </div>

      {correlation.matches.length > 0 && (
        <div className="space-y-2">
          <p className="text-[0.65rem] font-mono text-primary uppercase tracking-widest">Confirmed Static Runtime Matches</p>
          {correlation.matches.slice(0, 6).map((item) => (
            <FindingRow key={`match-${item.value}`} item={item} icon={<Link2 className="w-4 h-4" />} />
          ))}
        </div>
      )}

      {correlation.hidden_runtime_indicators.length > 0 && (
        <div className="space-y-2">
          <p className="text-[0.65rem] font-mono text-[#eab308] uppercase tracking-widest">Runtime-Only Indicators</p>
          {correlation.hidden_runtime_indicators.slice(0, 6).map((item) => (
            <FindingRow key={`hidden-${item.value}`} item={item} icon={<Unlink className="w-4 h-4" />} />
          ))}
        </div>
      )}

      {correlation.threat_intel_overlaps.length > 0 && (
        <div className="space-y-2">
          <p className="text-[0.65rem] font-mono text-[#f97316] uppercase tracking-widest">Threat Intel Overlaps</p>
          {correlation.threat_intel_overlaps.slice(0, 6).map((item) => (
            <FindingRow key={`intel-${item.value}`} item={item} icon={<ShieldAlert className="w-4 h-4" />} />
          ))}
        </div>
      )}
    </div>
  );
}
