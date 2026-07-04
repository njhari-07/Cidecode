import type { Permission, DangerousCombo } from "@/lib/types";
import { ShieldAlert, AlertTriangle } from "lucide-react";

interface Props {
  permissions: Permission[];
  dangerousCombos: DangerousCombo[];
}

export default function PermissionTable({ permissions, dangerousCombos }: Props) {
  const dangerous = permissions.filter((p) => p.is_dangerous);
  const normal = permissions.filter((p) => !p.is_dangerous);

  return (
    <div className="card-surface p-6 rounded-2xl space-y-5">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <ShieldAlert className="w-5 h-5 text-orange-400" />
          <h2 className="font-semibold text-slate-200">Permissions</h2>
        </div>
        <div className="flex gap-2 text-xs">
          <span className="px-2 py-0.5 rounded-full bg-rose-500/10 text-rose-400 border border-rose-500/20">
            {dangerous.length} dangerous
          </span>
          <span className="px-2 py-0.5 rounded-full bg-slate-700 text-slate-300">
            {normal.length} normal
          </span>
        </div>
      </div>

      {/* Dangerous combos */}
      {dangerousCombos.length > 0 && (
        <div className="space-y-2">
          <p className="text-xs font-semibold text-slate-200 uppercase tracking-wider flex items-center gap-1.5">
            <AlertTriangle className="w-3.5 h-3.5 text-yellow-400" />
            Dangerous Combinations
          </p>
          {dangerousCombos.map((combo, i) => (
            <div key={i} className="rounded-lg p-3 bg-yellow-500/5 border border-yellow-500/20">
              <p className="text-sm font-medium text-yellow-300">{combo.label}</p>
              <p className="text-xs text-slate-200 mt-1">{combo.permissions.join(" + ")}</p>
            </div>
          ))}
        </div>
      )}

      {/* Permission table */}
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-white/5">
              <th className="text-left py-2 text-xs text-slate-300 font-medium w-4/5">Permission</th>
              <th className="text-left py-2 text-xs text-slate-300 font-medium">Level</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/5">
            {[...dangerous, ...normal].map((perm, i) => (
              <tr key={i} className="hover:bg-white/[0.02] transition-colors">
                <td className="py-2 pr-4">
                  <span className={`font-mono text-xs ${perm.is_dangerous ? "text-rose-300" : "text-slate-200"}`}>
                    {perm.name.replace("android.permission.", "")}
                  </span>
                  {perm.description && (
                    <p className="text-xs text-slate-200 mt-0.5">{perm.description}</p>
                  )}
                </td>
                <td className="py-2">
                  {perm.is_dangerous ? (
                    <span className="text-xs px-1.5 py-0.5 rounded bg-rose-500/10 text-rose-400">
                      Dangerous
                    </span>
                  ) : (
                    <span className="text-xs text-slate-200">{perm.protection_level || "Normal"}</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
