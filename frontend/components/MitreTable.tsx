import type { MitreTactic } from "@/lib/types";
import { Target } from "lucide-react";

interface Props { tactics: MitreTactic[] }

const TACTIC_COLORS: Record<string, string> = {
  "Collection":           "bg-blue-500/10 text-blue-400 border-blue-500/20",
  "Persistence":          "bg-violet-500/10 text-violet-400 border-violet-500/20",
  "Privilege Escalation": "bg-rose-500/10 text-rose-400 border-rose-500/20",
  "Impact":               "bg-orange-500/10 text-orange-400 border-orange-500/20",
  "Command and Control":  "bg-red-500/10 text-red-400 border-red-500/20",
  "Defense Evasion":      "bg-yellow-500/10 text-yellow-400 border-yellow-500/20",
};

export default function MitreTable({ tactics }: Props) {
  if (!tactics || tactics.length === 0) {
    return (
      <div className="card-surface p-6 rounded-2xl">
        <div className="flex items-center gap-2 mb-3">
          <Target className="w-5 h-5 text-slate-300" />
          <h2 className="font-semibold text-slate-200">MITRE ATT&CK for Mobile</h2>
        </div>
        <p className="text-sm text-slate-300">No MITRE techniques mapped.</p>
      </div>
    );
  }

  return (
    <div className="card-surface p-6 rounded-2xl space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Target className="w-5 h-5 text-rose-400" />
          <h2 className="font-semibold text-slate-200">MITRE ATT&CK for Mobile</h2>
        </div>
        <span className="text-xs text-slate-300">{tactics.length} techniques</span>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-white/5">
              <th className="text-left py-2 text-xs text-slate-300 font-medium w-24">Technique</th>
              <th className="text-left py-2 text-xs text-slate-300 font-medium">Name</th>
              <th className="text-left py-2 text-xs text-slate-300 font-medium w-40">Tactic</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/5">
            {tactics.map((t, i) => (
              <tr key={i} className="hover:bg-white/[0.02] transition-colors group">
                <td className="py-2.5 pr-3">
                  <a
                    href={`https://attack.mitre.org/techniques/${t.technique_id.replace(".", "/")}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="font-mono text-xs text-indigo-400 hover:text-indigo-300 hover:underline"
                  >
                    {t.technique_id}
                  </a>
                </td>
                <td className="py-2.5 pr-3">
                  <p className="text-xs text-slate-200 font-medium">{t.name}</p>
                  <p className="text-xs text-slate-300 mt-0.5">{t.evidence}</p>
                </td>
                <td className="py-2.5">
                  <span
                    className={`text-xs px-2 py-0.5 rounded-full border ${
                      TACTIC_COLORS[t.tactic] ?? "bg-slate-700 text-slate-300 border-transparent"
                    }`}
                  >
                    {t.tactic}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
