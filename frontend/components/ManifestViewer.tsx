"use client";
import { useState, useEffect, useCallback } from "react";
import { FileCode, Copy, CheckCircle2, AlertTriangle, ChevronDown, ChevronUp } from "lucide-react";

interface ManifestData {
  xml_string: string | null;
  error?: string | null;
}

interface ManifestViewerProps {
  analysisId: string;
}

// Colorize tokens in the XML for syntax highlighting (pure CSS + regex)
function highlightXML(xml: string): string {
  return xml
    // Escape HTML first
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    // Strings (attribute values)
    .replace(/(&quot;[^&]*&quot;|"[^"]*")/g, '<span class="xml-string">$1</span>')
    // Attributes
    .replace(/\s([a-zA-Z_:][a-zA-Z0-9_:.-]*)=/g, ' <span class="xml-attr">$1</span>=')
    // Tags
    .replace(/&lt;\/?([a-zA-Z][a-zA-Z0-9_:-]*)/g, (m, tag) => {
      const dangerous = ["uses-permission", "service", "receiver", "provider", "activity"].includes(tag);
      const cls = dangerous ? "xml-tag-danger" : "xml-tag";
      return m.replace(tag, `<span class="${cls}">${tag}</span>`);
    })
    // Comments
    .replace(/(&lt;!--[\s\S]*?--&gt;)/g, '<span class="xml-comment">$1</span>');
}

const DANGEROUS_PERMS = [
  "READ_SMS", "RECEIVE_SMS", "SEND_SMS",
  "READ_CONTACTS", "WRITE_CONTACTS",
  "READ_CALL_LOG", "WRITE_CALL_LOG",
  "ACCESS_FINE_LOCATION", "ACCESS_BACKGROUND_LOCATION",
  "RECORD_AUDIO", "CAMERA",
  "SYSTEM_ALERT_WINDOW", "DRAW_OVER_OTHER_APPS",
  "BIND_ACCESSIBILITY_SERVICE",
  "BIND_DEVICE_ADMIN",
  "RECEIVE_BOOT_COMPLETED",
  "INSTALL_PACKAGES", "REQUEST_INSTALL_PACKAGES",
  "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE",
  "MANAGE_EXTERNAL_STORAGE",
];

function extractPermissions(xml: string): string[] {
  const matches = xml.match(/uses-permission[^>]+android:name="([^"]+)"/g) || [];
  return matches.map((m) => {
    const nm = m.match(/android:name="([^"]+)"/)?.[1] || "";
    return nm.replace("android.permission.", "");
  });
}

export default function ManifestViewer({ analysisId }: ManifestViewerProps) {
  const [data, setData] = useState<ManifestData | null>(null);
  const [loading, setLoading] = useState(true);
  const [copied, setCopied] = useState(false);
  const [collapsed, setCollapsed] = useState(false);

  const fetchManifest = useCallback(async () => {
    try {
      const res = await fetch(
        `${process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"}/api/analysis/${analysisId}/manifest`
      );
      if (res.ok) setData(await res.json());
      else setData({ xml_string: null, error: "Failed to load manifest" });
    } catch {
      setData({ xml_string: null, error: "Network error loading manifest" });
    } finally {
      setLoading(false);
    }
  }, [analysisId]);

  useEffect(() => { fetchManifest(); }, [fetchManifest]);

  const copyXML = async () => {
    if (!data?.xml_string) return;
    await navigator.clipboard.writeText(data.xml_string);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const permissions = data?.xml_string ? extractPermissions(data.xml_string) : [];
  const dangerousPerms = permissions.filter((p) => DANGEROUS_PERMS.includes(p));

  if (loading) {
    return (
      <div className="rounded-2xl border border-slate-700/40 bg-slate-900/60 p-6 animate-pulse">
        <div className="h-4 w-56 bg-slate-700/50 rounded mb-4" />
        <div className="space-y-1.5">
          {[...Array(12)].map((_, i) => (
            <div key={i} className="h-3 rounded bg-slate-800" style={{ width: `${40 + (i % 5) * 12}%` }} />
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="rounded-2xl border border-slate-700/40 bg-slate-900/60 overflow-hidden">
      {/* Styles for XML syntax highlighting */}
      <style>{`
        .xml-tag { color: #60a5fa; }
        .xml-tag-danger { color: #f87171; font-weight: 600; }
        .xml-attr { color: #a78bfa; }
        .xml-string { color: #34d399; }
        .xml-comment { color: #6b7280; font-style: italic; }
      `}</style>

      {/* Header */}
      <div className="border-b border-slate-700/40 px-5 py-4 flex items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <FileCode className="w-4 h-4 text-green-400" />
          <span className="font-semibold text-slate-100 text-sm">AndroidManifest.xml</span>
          {dangerousPerms.length > 0 && (
            <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-rose-500/15 text-rose-400 border border-rose-500/25">
              ⚠️ {dangerousPerms.length} dangerous permissions
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={copyXML}
            disabled={!data?.xml_string}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs text-slate-200 hover:text-slate-200 border border-slate-700/40 hover:border-slate-600 bg-slate-800/60 hover:bg-slate-700/60 transition-all disabled:opacity-40 disabled:cursor-not-allowed"
          >
            {copied ? <CheckCircle2 className="w-3 h-3 text-green-400" /> : <Copy className="w-3 h-3" />}
            {copied ? "Copied!" : "Copy XML"}
          </button>
          <button
            onClick={() => setCollapsed((c) => !c)}
            className="p-1.5 rounded-lg text-slate-300 hover:text-slate-300 hover:bg-slate-700/40 transition-all"
          >
            {collapsed ? <ChevronDown className="w-4 h-4" /> : <ChevronUp className="w-4 h-4" />}
          </button>
        </div>
      </div>

      {!collapsed && (
        <>
          {/* Dangerous permissions highlight bar */}
          {dangerousPerms.length > 0 && (
            <div className="mx-4 mt-4 rounded-lg border border-rose-500/20 bg-rose-500/5 p-3">
              <div className="flex items-center gap-2 text-rose-400 text-xs font-semibold mb-2">
                <AlertTriangle className="w-3.5 h-3.5" />
                Dangerous Permissions in Manifest
              </div>
              <div className="flex flex-wrap gap-1.5">
                {dangerousPerms.map((p) => (
                  <code key={p} className="text-[10px] bg-rose-500/10 text-rose-300 px-2 py-0.5 rounded-md font-mono border border-rose-500/15">
                    {p}
                  </code>
                ))}
              </div>
            </div>
          )}

          {/* Permission count */}
          {permissions.length > 0 && (
            <div className="px-4 pt-3 pb-0 flex gap-4 text-xs text-slate-300">
              <span><span className="text-slate-300 font-semibold">{permissions.length}</span> total permissions</span>
              <span className="text-slate-300">·</span>
              <span><span className="text-rose-400 font-semibold">{dangerousPerms.length}</span> dangerous</span>
            </div>
          )}

          {/* XML content */}
          <div className="p-4 max-h-[480px] overflow-auto scrollbar-thin scrollbar-track-transparent scrollbar-thumb-slate-700">
            {data?.xml_string ? (
              <pre
                className="text-xs font-mono leading-relaxed text-slate-300 whitespace-pre-wrap break-all"
                dangerouslySetInnerHTML={{ __html: highlightXML(data.xml_string) }}
              />
            ) : (
              <div className="text-center text-slate-300 py-10">
                <FileCode className="w-8 h-8 mx-auto mb-2 text-slate-300" />
                <p className="text-sm">{data?.error || "Manifest XML unavailable"}</p>
                <p className="text-xs mt-1 text-slate-200">
                  Install androguard for binary XML decoding: <code className="font-mono">pip install androguard</code>
                </p>
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}
