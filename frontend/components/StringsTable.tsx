import type { Strings } from "@/lib/types";
import { Link2, Globe, Code2 } from "lucide-react";

interface Props { strings: Strings }

const RISK_COLORS = {
  high:   "text-rose-400",
  medium: "text-yellow-400",
  low:    "text-slate-200",
};

export default function StringsTable({ strings }: Props) {
  const allUrls = strings.urls ?? [];
  const allIps  = strings.ips ?? [];
  const susp    = strings.suspicious_strings ?? [];

  return (
    <div className="card-surface p-6 rounded-2xl space-y-5">
      <div className="flex items-center gap-2">
        <Code2 className="w-5 h-5 text-cyan-400" />
        <h2 className="font-semibold text-slate-200">Extracted Strings</h2>
      </div>

      <div className="grid grid-cols-3 gap-3">
        {[
          { label: "URLs",        count: allUrls.length,  color: "text-indigo-400" },
          { label: "IP Addresses",count: allIps.length,   color: "text-cyan-400"   },
          { label: "Suspicious",  count: susp.length,     color: "text-rose-400"   },
        ].map(({ label, count, color }) => (
          <div key={label} className="rounded-lg p-3 bg-slate-800/60 text-center">
            <p className={`text-xl font-bold font-mono ${color}`}>{count}</p>
            <p className="text-xs text-slate-300 mt-0.5">{label}</p>
          </div>
        ))}
      </div>

      {allUrls.length > 0 && (
        <Section title="URLs" icon={<Link2 className="w-3.5 h-3.5 text-indigo-400" />}>
          {allUrls.slice(0, 15).map((u, i) => (
            <Row key={i} value={u.value} risk={u.risk} />
          ))}
          {allUrls.length > 15 && (
            <p className="text-xs text-slate-200 italic">+{allUrls.length - 15} more URLs…</p>
          )}
        </Section>
      )}

      {allIps.length > 0 && (
        <Section title="IP Addresses" icon={<Globe className="w-3.5 h-3.5 text-cyan-400" />}>
          {allIps.map((ip, i) => (
            <Row key={i} value={ip.value} risk={ip.risk} />
          ))}
        </Section>
      )}

      {susp.length > 0 && (
        <Section title="Suspicious Strings" icon={<Code2 className="w-3.5 h-3.5 text-rose-400" />}>
          {susp.slice(0, 10).map((s, i) => (
            <Row key={i} value={s.value} risk={s.risk ?? "high"} />
          ))}
        </Section>
      )}
    </div>
  );
}

function Section({
  title,
  icon,
  children,
}: {
  title: string;
  icon: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <div className="space-y-2">
      <p className="text-xs text-slate-300 flex items-center gap-1.5 uppercase tracking-wider font-medium">
        {icon} {title}
      </p>
      <div className="space-y-1">{children}</div>
    </div>
  );
}

function Row({ value, risk }: { value: string; risk?: string }) {
  const color = RISK_COLORS[(risk as keyof typeof RISK_COLORS) ?? "low"] ?? "text-slate-200";
  return (
    <div className="flex items-center gap-2 rounded px-2 py-1 hover:bg-white/[0.02] transition-colors">
      <span className={`font-mono text-xs break-all ${color}`}>{value}</span>
      {risk === "high" && (
        <span className="ml-auto shrink-0 text-xs px-1.5 rounded bg-rose-500/10 text-rose-400">High</span>
      )}
    </div>
  );
}
