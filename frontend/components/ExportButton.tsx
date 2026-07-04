"use client";
import { useState } from "react";
import { Download, FileJson, FileText, Loader2, CheckCircle2 } from "lucide-react";

interface ExportButtonProps {
  analysisId: string;
  packageName?: string;
  sha256?: string;
}

type ExportState = "idle" | "loading" | "done" | "error";

export default function ExportButton({ analysisId, packageName = "Unknown", sha256 }: ExportButtonProps) {
  const [pdfState, setPdfState] = useState<ExportState>("idle");
  const [jsonState, setJsonState] = useState<ExportState>("idle");
  const [stixState, setStixState] = useState<ExportState>("idle");

  const downloadPDF = async () => {
    if (pdfState === "loading") return;
    setPdfState("loading");
    try {
      const identifier = sha256 || analysisId;
      const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"}/api/report/${identifier}`);
      if (!res.ok) throw new Error("Failed to generate report");
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `DroidRaksha_Report_${packageName.replace(/\./g, "_")}.pdf`;
      a.click();
      URL.revokeObjectURL(url);
      setPdfState("done");
      setTimeout(() => setPdfState("idle"), 3000);
    } catch {
      setPdfState("error");
      setTimeout(() => setPdfState("idle"), 3000);
    }
  };

  const downloadJSON = async () => {
    if (jsonState === "loading") return;
    setJsonState("loading");
    try {
      const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"}/api/analysis/${analysisId}`);
      if (!res.ok) throw new Error("Failed to fetch analysis data");
      const data = await res.json();
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `DroidRaksha_${packageName.replace(/\./g, "_")}_${analysisId.slice(0, 8)}.json`;
      a.click();
      URL.revokeObjectURL(url);
      setJsonState("done");
      setTimeout(() => setJsonState("idle"), 3000);
    } catch {
      setJsonState("error");
      setTimeout(() => setJsonState("idle"), 3000);
    }
  };

  const downloadSTIX = async () => {
    if (stixState === "loading") return;
    setStixState("loading");
    try {
      const identifier = sha256 || analysisId;
      const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"}/api/export/stix/${identifier}`);
      if (!res.ok) throw new Error("Failed to generate STIX bundle");
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `DroidRaksha_STIX_${packageName.replace(/\./g, "_")}.json`;
      a.click();
      URL.revokeObjectURL(url);
      setStixState("done");
      setTimeout(() => setStixState("idle"), 3000);
    } catch {
      setStixState("error");
      setTimeout(() => setStixState("idle"), 3000);
    }
  };

  const btnClass = (state: ExportState, color: string) => `
    flex items-center gap-2 px-4 py-2 text-[0.65rem] md:text-xs font-mono uppercase tracking-widest
    border transition-all duration-200 select-none cursor-pointer corner-brackets
    ${state === "loading" ? "opacity-60 cursor-not-allowed" : ""}
    ${state === "done" ? "border-green-500 bg-[rgba(34,197,94,0.1)] text-green-400" : ""}
    ${state === "error" ? "border-rose-500 bg-[rgba(244,63,94,0.1)] text-rose-400" : ""}
    ${state === "idle" && color === "rose" ? "border-danger bg-[rgba(204,34,0,0.1)] text-danger hover:bg-[rgba(244,63,94,0.15)]" : ""}
    ${state === "idle" && color === "indigo" ? "border-primary bg-[rgba(0,237,63,0.05)] text-primary hover:bg-[rgba(0,82,255,0.15)]" : ""}
    ${state === "idle" && color === "cyan" ? "border-cyan-500 bg-[rgba(6,182,212,0.1)] text-cyan-400 hover:bg-[rgba(6,182,212,0.2)]" : ""}
  `;

  return (
    <div className="flex items-center gap-4 flex-wrap">
      {/* PDF Export */}
      <button
        id="export-pdf-btn"
        onClick={downloadPDF}
        disabled={pdfState === "loading"}
        className={btnClass(pdfState, "rose")}
        title="Download forensic PDF report"
      >
        {pdfState === "loading" ? (
          <span className="w-3.5 h-3.5 border-2 border-current border-t-transparent rounded-full animate-spin"></span>
        ) : pdfState === "done" ? (
          <CheckCircle2 className="w-3.5 h-3.5" />
        ) : (
          <FileText className="w-3.5 h-3.5" />
        )}
        {pdfState === "loading" ? "[ GENERATING ]" : pdfState === "done" ? "[ DOWNLOADED ]" : pdfState === "error" ? "[ FAILED ]" : "[ EXPORT PDF ]"}
      </button>

      {/* JSON Export */}
      <button
        id="export-json-btn"
        onClick={downloadJSON}
        disabled={jsonState === "loading"}
        className={btnClass(jsonState, "indigo")}
        title="Download raw JSON analysis"
      >
        {jsonState === "loading" ? (
          <span className="w-3.5 h-3.5 border-2 border-current border-t-transparent rounded-full animate-spin"></span>
        ) : jsonState === "done" ? (
          <CheckCircle2 className="w-3.5 h-3.5" />
        ) : (
          <FileJson className="w-3.5 h-3.5" />
        )}
        {jsonState === "loading" ? "[ EXPORTING ]" : jsonState === "done" ? "[ DOWNLOADED ]" : jsonState === "error" ? "[ FAILED ]" : "[ EXPORT JSON ]"}
      </button>

      {/* STIX Export */}
      <button
        id="export-stix-btn"
        onClick={downloadSTIX}
        disabled={stixState === "loading"}
        className={btnClass(stixState, "cyan")}
        title="Download STIX 2.1 Threat Intel"
      >
        {stixState === "loading" ? (
          <span className="w-3.5 h-3.5 border-2 border-current border-t-transparent rounded-full animate-spin"></span>
        ) : stixState === "done" ? (
          <CheckCircle2 className="w-3.5 h-3.5" />
        ) : (
          <FileJson className="w-3.5 h-3.5" />
        )}
        {stixState === "loading" ? "[ GENERATING ]" : stixState === "done" ? "[ DOWNLOADED ]" : stixState === "error" ? "[ FAILED ]" : "[ EXPORT STIX ]"}
      </button>

      {/* Share link */}
      <button
        id="share-report-btn"
        onClick={() => {
          navigator.clipboard.writeText(`${window.location.origin}/report/${sha256 || analysisId}`);
        }}
        className="flex items-center gap-2 px-4 py-2 text-[0.65rem] md:text-xs font-mono uppercase tracking-widest border border-border bg-surface-raised text-muted hover:bg-surface-raised hover:text-secondary hover:border-border transition-all duration-200 corner-brackets"
        title="Copy shareable report link"
      >
        <Download className="w-3.5 h-3.5" />
        [ COPY LINK ]
      </button>
    </div>
  );
}
