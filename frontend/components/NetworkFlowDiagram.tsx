"use client";

import { GitBranch, Globe, Radio, Server, ShieldAlert } from "lucide-react";
import type { NetworkData } from "@/lib/types";

interface Props {
  network?: NetworkData | null;
}

const riskStroke = (risk?: string) => {
  if (risk === "CRITICAL") return "border-[#f43f5e] text-[#f43f5e]";
  if (risk === "HIGH") return "border-[#f97316] text-[#f97316]";
  if (risk === "MEDIUM") return "border-[#eab308] text-[#eab308]";
  return "border-[#22c55e] text-[#22c55e]";
};

export default function NetworkFlowDiagram({ network }: Props) {
  if (!network?.available) {
    return (
      <div className="bg-surface-raised border border-border p-5 corner-brackets">
        <div className="flex items-center gap-2 text-secondary font-mono text-sm uppercase">
          <GitBranch className="w-4 h-4 text-primary" />
          Network Flow Diagram
        </div>
        <p className="mt-3 text-[0.65rem] font-mono text-muted uppercase tracking-widest">
          Upload PCAP to render observed endpoint flow.
        </p>
      </div>
    );
  }

  const topIps = network.remote_ips.slice(0, 5);
  const topDomains = [
    ...network.dns_queries.map((d) => ({ label: d.domain, count: d.count, type: "DNS" })),
    ...network.http_hosts.map((h) => ({ label: h.host, count: h.count, type: "HTTP" })),
  ].slice(0, 6);
  const alerts = new Set(network.beaconing_alerts.map((a) => a.ip));

  return (
    <div className="bg-surface-raised border border-border p-5 corner-brackets space-y-5">
      <div className="flex items-center justify-between gap-3 border-b border-border pb-3">
        <div className="flex items-center gap-2 text-secondary font-mono text-sm uppercase">
          <GitBranch className="w-4 h-4 text-primary" />
          Network Flow Diagram
        </div>
        <span className={`text-[0.6rem] px-2 py-0.5 border font-mono uppercase ${riskStroke(network.pcap_risk)}`}>
          {network.pcap_risk}
        </span>
      </div>

      <div className="grid grid-cols-[1fr_auto_1fr] gap-3 items-center min-h-72">
        <div className="space-y-3">
          {topDomains.length ? topDomains.map((domain) => (
            <div key={`${domain.type}-${domain.label}`} className="border border-border bg-background/60 p-3">
              <div className="flex items-center gap-2 text-[0.65rem] font-mono text-[#22d3ee] uppercase">
                <Globe className="w-3.5 h-3.5" />
                {domain.type}
              </div>
              <p className="mt-1 text-xs text-secondary font-mono break-all">{domain.label}</p>
              <p className="mt-1 text-[0.6rem] text-muted font-mono uppercase">{domain.count} observations</p>
            </div>
          )) : (
            <div className="border border-border bg-background/60 p-3 text-[0.65rem] text-muted font-mono uppercase">
              No DNS/HTTP hosts observed
            </div>
          )}
        </div>

        <div className="flex flex-col items-center gap-3">
          <div className="w-20 h-20 border border-primary bg-black/50 grid place-items-center shadow-[0_0_24px_rgba(255,255,255,0.08)]">
            <Radio className="w-7 h-7 text-primary" />
          </div>
          <div className="h-44 w-px bg-gradient-to-b from-transparent via-border to-transparent" />
        </div>

        <div className="space-y-3">
          {topIps.length ? topIps.map((ip) => (
            <div
              key={ip.ip}
              className={`border bg-background/60 p-3 ${alerts.has(ip.ip) ? "border-[#f43f5e]" : "border-border"}`}
            >
              <div className={`flex items-center gap-2 text-[0.65rem] font-mono uppercase ${alerts.has(ip.ip) ? "text-[#f43f5e]" : "text-[#0ea5e9]"}`}>
                {alerts.has(ip.ip) ? <ShieldAlert className="w-3.5 h-3.5" /> : <Server className="w-3.5 h-3.5" />}
                Remote IP
              </div>
              <p className="mt-1 text-xs text-secondary font-mono">{ip.ip}</p>
              <div className="mt-2 flex flex-wrap gap-1">
                {ip.ports.slice(0, 4).map((port) => (
                  <span key={port} className="text-[0.55rem] border border-border px-1 py-0.5 text-muted font-mono">
                    {port}
                  </span>
                ))}
              </div>
            </div>
          )) : (
            <div className="border border-border bg-background/60 p-3 text-[0.65rem] text-muted font-mono uppercase">
              No remote IPs observed
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
