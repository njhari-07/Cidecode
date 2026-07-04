import type { Certificate } from "@/lib/types";
import { Lock, AlertTriangle, CheckCircle2, Calendar } from "lucide-react";

interface Props { cert: Certificate }

export default function CertificateCard({ cert }: Props) {
  if (cert.error) {
    return (
      <div className="card-surface p-6 rounded-2xl">
        <div className="flex items-center gap-2 mb-3">
          <Lock className="w-5 h-5 text-slate-300" />
          <h2 className="font-semibold text-slate-200">Certificate</h2>
        </div>
        <p className="text-sm text-slate-300">{cert.error}</p>
      </div>
    );
  }

  const hasIssues = cert.is_expired || cert.is_self_signed || cert.warnings.length > 0;

  return (
    <div className="card-surface p-6 rounded-2xl space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Lock className={`w-5 h-5 ${hasIssues ? "text-yellow-400" : "text-green-400"}`} />
          <h2 className="font-semibold text-slate-200">Certificate</h2>
        </div>
        {hasIssues ? (
          <span className="text-xs px-2 py-0.5 rounded-full bg-yellow-500/10 text-yellow-400 border border-yellow-500/20 flex items-center gap-1">
            <AlertTriangle className="w-3 h-3" /> Issues Found
          </span>
        ) : (
          <span className="text-xs px-2 py-0.5 rounded-full bg-green-500/10 text-green-400 border border-green-500/20 flex items-center gap-1">
            <CheckCircle2 className="w-3 h-3" /> Valid
          </span>
        )}
      </div>

      <div className="grid grid-cols-1 gap-3 text-sm">
        <Field label="Subject"    value={cert.subject} />
        <Field label="Issuer"     value={cert.issuer} />
        <Field label="Serial"     value={cert.serial_number} mono />
        <Field
          label="Valid From"
          value={cert.not_before ? new Date(cert.not_before).toLocaleDateString() : "—"}
        />
        <Field
          label="Valid To"
          value={cert.not_after ? new Date(cert.not_after).toLocaleDateString() : "—"}
          highlight={cert.is_expired ? "rose" : undefined}
        />
      </div>

      {/* Flags */}
      <div className="flex flex-wrap gap-2">
        {cert.is_self_signed && (
          <Flag text="Self-Signed" color="yellow" />
        )}
        {cert.is_expired && (
          <Flag text="Expired" color="rose" />
        )}
        {cert.warnings.map((w, i) => (
          <Flag key={i} text={w} color="orange" />
        ))}
      </div>

      {cert.fingerprint_sha256 && (
        <div>
          <p className="text-xs text-slate-300 mb-1">SHA-256 Fingerprint</p>
          <p className="font-mono text-xs text-slate-200 break-all bg-slate-800/60 rounded p-2">
            {cert.fingerprint_sha256}
          </p>
        </div>
      )}
    </div>
  );
}

function Field({
  label,
  value,
  mono,
  highlight,
}: {
  label: string;
  value: string;
  mono?: boolean;
  highlight?: "rose" | "yellow";
}) {
  const color = highlight === "rose" ? "text-rose-400" : highlight === "yellow" ? "text-yellow-400" : "text-slate-300";
  return (
    <div className="flex gap-3">
      <span className="text-xs text-slate-300 w-24 shrink-0 pt-0.5">{label}</span>
      <span className={`text-xs break-all ${mono ? "font-mono" : ""} ${color}`}>{value || "—"}</span>
    </div>
  );
}

function Flag({ text, color }: { text: string; color: "rose" | "yellow" | "orange" }) {
  const styles = {
    rose:   "bg-rose-500/10 text-rose-400 border-rose-500/20",
    yellow: "bg-yellow-500/10 text-yellow-400 border-yellow-500/20",
    orange: "bg-orange-500/10 text-orange-400 border-orange-500/20",
  };
  return (
    <span className={`text-xs px-2 py-0.5 rounded-full border ${styles[color]}`}>{text}</span>
  );
}
