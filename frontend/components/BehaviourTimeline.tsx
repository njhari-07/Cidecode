"use client";

import { Activity, AlertTriangle, Clock, Globe, Radar, Shield } from "lucide-react";
import type { AnalysisResult, NetworkData } from "@/lib/types";

interface Props {
  result: AnalysisResult;
  network?: NetworkData | null;
}

const iconFor = (type: string) => {
  if (type === "beacon") return <Radar className="w-4 h-4" />;
  if (type === "dga") return <AlertTriangle className="w-4 h-4" />;
  if (type === "ioc") return <Shield className="w-4 h-4" />;
  if (type === "network") return <Globe className="w-4 h-4" />;
  return <Activity className="w-4 h-4" />;
};

export default function BehaviourTimeline({ result, network }: Props) {
  const dynamicFlags = result.dynamic?.behavioral_score?.flags ?? [];
  const items = [
    ...dynamicFlags.slice(0, 5).map((flag, index) => ({
      type: "sandbox",
      title: "Sandbox Behaviour",
      detail: flag,
      time: `T+${index + 1}`,
      severity: result.dynamic?.behavioral_score?.level ?? "MEDIUM",
    })),
    ...(network?.beaconing_alerts ?? []).slice(0, 4).map((alert, index) => ({
      type: "beacon",
      title: "Possible C2 Beacon",
      detail: `${alert.ip} contacted ${alert.contact_count} times every ~${alert.avg_interval_sec}s`,
      time: `N+${index + 1}`,
      severity: alert.confidence === "HIGH" ? "CRITICAL" : "HIGH",
    })),
    ...(network?.dga_suspects ?? []).slice(0, 4).map((domain, index) => ({
      type: "dga",
      title: "DGA-Like Domain",
      detail: `${domain.domain} entropy ${domain.entropy}`,
      time: `D+${index + 1}`,
      severity: "HIGH",
    })),
    ...(network?.india_ioc_hits ?? []).slice(0, 4).map((hit, index) => ({
      type: "ioc",
      title: "Threat Intel Hit",
      detail: `${hit.value} matched ${hit.reason}`,
      time: `I+${index + 1}`,
      severity: hit.severity,
    })),
  ];

  return (
    <div className="bg-surface-raised border border-border p-5 corner-brackets space-y-4">
      <div className="flex items-center gap-2 border-b border-border pb-3">
        <Clock className="w-4 h-4 text-primary" />
        <h3 className="font-bold text-secondary uppercase tracking-tight text-sm font-mono">Behaviour Timeline</h3>
      </div>

      {items.length === 0 ? (
        <p className="text-[0.65rem] font-mono text-muted uppercase tracking-widest">
          No dynamic behaviours recorded yet. Run sandbox analysis or attach PCAP traffic.
        </p>
      ) : (
        <div className="relative pl-5 space-y-4 before:absolute before:left-1.5 before:top-1 before:bottom-1 before:w-px before:bg-border">
          {items.map((item, index) => (
            <div key={`${item.type}-${index}`} className="relative">
              <div className={`absolute -left-5 top-1 w-3 h-3 border bg-black ${
                item.severity === "CRITICAL" ? "border-[#f43f5e]" :
                item.severity === "HIGH" ? "border-[#f97316]" :
                "border-[#22d3ee]"
              }`} />
              <div className="border border-border bg-background/50 p-3">
                <div className="flex items-center gap-2 text-[0.65rem] font-mono uppercase tracking-widest text-muted">
                  <span className="text-primary">{iconFor(item.type)}</span>
                  <span>{item.time}</span>
                  <span className="ml-auto">{item.severity}</span>
                </div>
                <p className="mt-1 text-xs font-bold text-secondary font-mono uppercase">{item.title}</p>
                <p className="mt-1 text-[0.7rem] text-muted font-mono leading-relaxed">{item.detail}</p>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
