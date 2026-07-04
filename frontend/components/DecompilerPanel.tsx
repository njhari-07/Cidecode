"use client";
import { useState, useEffect, useCallback, useRef } from "react";
import {
  Code2, ChevronRight, ChevronDown, Copy, CheckCircle2,
  Search, Loader2, AlertTriangle, FolderOpen, Folder, FileCode,
  TerminalSquare, Zap,
} from "lucide-react";

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

// ── Types ──────────────────────────────────────────────────────────────────
interface TreeNode {
  name: string;
  path: string;
  type: "dir" | "file";
  children?: TreeNode[];
}

interface DecompileTreeResponse {
  available: boolean;
  tree: TreeNode[];
  total_classes?: number;
  cached?: boolean;
  error?: string | null;
}

interface ClassSourceResponse {
  available: boolean;
  class_path: string;
  source?: string | null;
  error?: string | null;
}

interface DecompilerPanelProps {
  analysisId: string;
}

// ── Suspicious Java API patterns (highlighted red in the viewer) ────────────
const SUSPICIOUS_PATTERNS = [
  "Runtime.exec", "ProcessBuilder", "Runtime.getRuntime",
  "Cipher", "SecretKey", "KeyGenerator", "MessageDigest",
  "TelephonyManager", "getDeviceId", "getSubscriberId", "getSimSerialNumber",
  "getLine1Number", "getImei",
  "SmsManager", "sendTextMessage", "sendMultipartTextMessage",
  "ContentResolver", "ContactsContract", "CallLog",
  "getSystemService", "DevicePolicyManager", "setPasswordQuality",
  "AccessibilityService", "onAccessibilityEvent",
  "DexClassLoader", "PathClassLoader", "loadClass",
  "Base64", "XOR", "AES", "RC4", "DES",
  "Socket", "HttpURLConnection", "OkHttpClient",
  "WebView", "loadUrl", "evaluateJavascript",
  "setWebContentsDebuggingEnabled",
  "getExternalStorageDirectory", "Environment.getExternalStorage",
  "PackageManager", "installPackage", "requestInstallPackages",
];

// ── Java Syntax Highlighter ────────────────────────────────────────────────
function highlightJava(source: string): string {
  const esc = (s: string) =>
    s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

  let out = esc(source);

  // Comments — must come first
  out = out.replace(/(\/\/[^\n]*)/g, '<span class="java-comment">$1</span>');
  out = out.replace(/(\/\*[\s\S]*?\*\/)/g, '<span class="java-comment">$1</span>');

  // String literals
  out = out.replace(/(&quot;[^&]*?&quot;|"[^"]*?")/g, '<span class="java-string">$1</span>');

  // Keywords
  const keywords = [
    "public", "private", "protected", "static", "final", "abstract",
    "class", "interface", "enum", "extends", "implements", "import",
    "package", "new", "return", "void", "null", "true", "false",
    "if", "else", "for", "while", "do", "switch", "case", "break",
    "continue", "try", "catch", "finally", "throw", "throws",
    "instanceof", "this", "super", "synchronized", "volatile",
    "int", "long", "float", "double", "boolean", "byte", "char", "short",
  ];
  const kwRe = new RegExp(`\\b(${keywords.join("|")})\\b`, "g");
  out = out.replace(kwRe, '<span class="java-keyword">$1</span>');

  // Annotations
  out = out.replace(/(@[A-Za-z][A-Za-z0-9_]*)/g, '<span class="java-annotation">$1</span>');

  // Numbers
  out = out.replace(/\b(\d+[LlFfDd]?)\b/g, '<span class="java-number">$1</span>');

  // Suspicious API calls — highlight after all other transforms
  SUSPICIOUS_PATTERNS.forEach((pat) => {
    const escaped = pat.replace(/\./g, "\\.").replace(/\(/g, "\\(");
    try {
      const re = new RegExp(`(${escaped})`, "g");
      out = out.replace(re, '<span class="java-suspicious" title="Suspicious API">$1</span>');
    } catch {}
  });

  // Types (CamelCase identifiers that are not keywords)
  out = out.replace(/\b([A-Z][A-Za-z0-9_]*)\b/g, (m) => {
    // Don't re-wrap already-wrapped spans
    return `<span class="java-type">${m}</span>`;
  });

  return out;
}

// ── Tree node component ────────────────────────────────────────────────────
function TreeItem({
  node,
  depth,
  selectedPath,
  onSelect,
  filter,
}: {
  node: TreeNode;
  depth: number;
  selectedPath: string | null;
  onSelect: (path: string, name: string) => void;
  filter: string;
}) {
  const [open, setOpen] = useState(depth < 2);
  const isDir = node.type === "dir";
  const isSelected = node.path === selectedPath;

  const matchesFilter = (n: TreeNode): boolean => {
    if (!filter) return true;
    if (n.name.toLowerCase().includes(filter.toLowerCase())) return true;
    if (n.children) return n.children.some(matchesFilter);
    return false;
  };

  if (!matchesFilter(node)) return null;

  const filteredChildren = node.children?.filter(matchesFilter) ?? [];

  return (
    <div>
      <button
        onClick={() => isDir ? setOpen((o) => !o) : onSelect(node.path, node.name)}
        style={{ paddingLeft: `${depth * 14 + 8}px` }}
        className={`w-full flex items-center gap-1.5 py-1 pr-3 text-left text-[0.65rem] font-mono transition-all group ${
          isSelected
            ? "bg-[rgba(0,237,63,0.08)] text-primary border-l border-primary"
            : "text-muted hover:text-secondary hover:bg-surface-raised border-l border-transparent"
        }`}
      >
        {isDir ? (
          open ? (
            <><ChevronDown className="w-3 h-3 shrink-0 text-muted" /><FolderOpen className="w-3 h-3 shrink-0 text-[#4466cc]" /></>
          ) : (
            <><ChevronRight className="w-3 h-3 shrink-0 text-muted" /><Folder className="w-3 h-3 shrink-0 text-[#4466cc]" /></>
          )
        ) : (
          <><span className="w-3 shrink-0" /><FileCode className="w-3 h-3 shrink-0 text-primary opacity-70" /></>
        )}
        <span className="truncate">{node.name}</span>
      </button>

      {isDir && open && filteredChildren.map((child) => (
        <TreeItem
          key={child.path}
          node={child}
          depth={depth + 1}
          selectedPath={selectedPath}
          onSelect={onSelect}
          filter={filter}
        />
      ))}
    </div>
  );
}

// ── Main Component ─────────────────────────────────────────────────────────
export default function DecompilerPanel({ analysisId }: DecompilerPanelProps) {
  const [treeData, setTreeData] = useState<DecompileTreeResponse | null>(null);
  const [treeLoading, setTreeLoading] = useState(true);
  const [selectedPath, setSelectedPath] = useState<string | null>(null);
  const [selectedName, setSelectedName] = useState<string | null>(null);
  const [sourceData, setSourceData] = useState<ClassSourceResponse | null>(null);
  const [sourceLoading, setSourceLoading] = useState(false);
  const [filter, setFilter] = useState("");
  const [copied, setCopied] = useState(false);
  const [suspiciousOnly, setSuspiciousOnly] = useState(false);
  const codeRef = useRef<HTMLPreElement>(null);

  // Fetch class tree on mount
  useEffect(() => {
    fetch(`${API_BASE}/api/analysis/${analysisId}/decompile`)
      .then((r) => r.json())
      .then((d: DecompileTreeResponse) => { setTreeData(d); setTreeLoading(false); })
      .catch(() => {
        setTreeData({ available: false, tree: [], error: "Network error loading class tree" });
        setTreeLoading(false);
      });
  }, [analysisId]);

  // Fetch source when a class is selected
  const handleSelect = useCallback(async (path: string, name: string) => {
    setSelectedPath(path);
    setSelectedName(name);
    setSourceData(null);
    setSourceLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/analysis/${analysisId}/decompile/${path}`);
      const data: ClassSourceResponse = await res.json();
      setSourceData(data);
    } catch {
      setSourceData({ available: false, class_path: path, source: null, error: "Failed to load source" });
    } finally {
      setSourceLoading(false);
    }
  }, [analysisId]);

  const copySource = async () => {
    if (!sourceData?.source) return;
    await navigator.clipboard.writeText(sourceData.source);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const suspiciousCount = sourceData?.source
    ? SUSPICIOUS_PATTERNS.filter((p) => sourceData.source!.includes(p)).length
    : 0;

  return (
    <div className="flex flex-col gap-4">
      {/* ── Header ── */}
      <div className="flex items-center gap-3">
        <TerminalSquare className="w-4 h-4 text-primary" />
        <p className="text-[0.65rem] font-mono text-muted uppercase tracking-widest border-l-2 border-primary pl-3">
          JADX decompiler — Java source from DEX bytecode
        </p>
        {treeData?.cached && (
          <span className="ml-auto text-[0.6rem] font-mono text-primary border border-border px-2 py-0.5">
            CACHED
          </span>
        )}
        {treeData?.total_classes != null && (
          <span className="text-[0.6rem] font-mono text-muted">
            {treeData.total_classes} classes
          </span>
        )}
      </div>

      {/* ── Main split panel ── */}
      <div className="flex gap-0 border border-border bg-surface h-[640px] overflow-hidden relative corner-brackets">

        {/* Left: Class Tree */}
        <div className="w-72 shrink-0 flex flex-col border-r border-border overflow-hidden">
          {/* Search */}
          <div className="p-2 border-b border-border">
            <div className="relative">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3 h-3 text-muted" />
              <input
                value={filter}
                onChange={(e) => setFilter(e.target.value)}
                placeholder="Filter classes..."
                className="w-full bg-background border border-border text-secondary text-[0.65rem] font-mono pl-7 pr-3 py-1.5 outline-none focus:border-primary transition-colors placeholder:text-muted"
              />
            </div>
          </div>

          {/* Tree content */}
          <div className="flex-1 overflow-y-auto custom-scrollbar">
            {treeLoading ? (
              <div className="flex flex-col items-center justify-center h-full gap-3 text-muted">
                <Loader2 className="w-5 h-5 animate-spin text-primary" />
                <p className="text-[0.6rem] font-mono uppercase tracking-widest animate-pulse">
                  Running JADX...
                </p>
                <p className="text-[0.55rem] font-mono text-muted/60 text-center px-4">
                  First run may take 30–60s.<br />Result is cached afterward.
                </p>
              </div>
            ) : !treeData?.available ? (
              <div className="p-4 text-center">
                <AlertTriangle className="w-6 h-6 text-warning mx-auto mb-2" />
                <p className="text-[0.6rem] font-mono text-warning uppercase">
                  {treeData?.error ?? "Decompilation unavailable"}
                </p>
                <p className="text-[0.55rem] font-mono text-muted mt-2">
                  Ensure JADX and Java are installed in the container.
                </p>
              </div>
            ) : treeData.tree.length === 0 ? (
              <div className="p-4 text-center text-muted">
                <p className="text-[0.6rem] font-mono uppercase">No classes found</p>
              </div>
            ) : (
              <div className="py-1">
                {treeData.tree.map((node) => (
                  <TreeItem
                    key={node.path}
                    node={node}
                    depth={0}
                    selectedPath={selectedPath}
                    onSelect={handleSelect}
                    filter={filter}
                  />
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Right: Source Viewer */}
        <div className="flex-1 flex flex-col overflow-hidden min-w-0">
          {/* Source header */}
          <div className="flex items-center gap-3 px-4 py-2 border-b border-border bg-surface-raised shrink-0">
            {selectedName ? (
              <>
                <FileCode className="w-3.5 h-3.5 text-primary shrink-0" />
                <span className="text-[0.65rem] font-mono text-secondary truncate flex-1">
                  {selectedPath}
                </span>
                {suspiciousCount > 0 && (
                  <span className="flex items-center gap-1 text-[0.6rem] font-mono text-danger border border-danger/30 bg-[rgba(204,34,0,0.08)] px-2 py-0.5 shrink-0">
                    <Zap className="w-2.5 h-2.5" />
                    {suspiciousCount} suspicious API{suspiciousCount > 1 ? "s" : ""}
                  </span>
                )}
                <button
                  onClick={copySource}
                  disabled={!sourceData?.source}
                  className="flex items-center gap-1 text-[0.6rem] font-mono text-muted hover:text-secondary border border-border px-2 py-0.5 transition-all hover:border-primary disabled:opacity-30 shrink-0"
                >
                  {copied ? <CheckCircle2 className="w-2.5 h-2.5 text-primary" /> : <Copy className="w-2.5 h-2.5" />}
                  {copied ? "Copied" : "Copy"}
                </button>
              </>
            ) : (
              <span className="text-[0.6rem] font-mono text-muted uppercase tracking-widest">
                ← Select a class to view source
              </span>
            )}
          </div>

          {/* Source content */}
          <div className="flex-1 overflow-auto custom-scrollbar relative">
            {/* Java syntax highlighting styles */}
            <style>{`
              .java-keyword   { color: #c084fc; font-weight: 600; }
              .java-string    { color: #4ade80; }
              .java-comment   { color: #4A4A40; font-style: italic; }
              .java-type      { color: #60a5fa; }
              .java-annotation{ color: #f97316; }
              .java-number    { color: #fbbf24; }
              .java-suspicious{
                color: #f43f5e;
                font-weight: 700;
                background: rgba(244,63,94,0.08);
                border-radius: 2px;
                padding: 0 2px;
                text-shadow: 0 0 8px rgba(244,63,94,0.4);
              }
              .custom-scrollbar::-webkit-scrollbar { width: 5px; height: 5px; }
              .custom-scrollbar::-webkit-scrollbar-track { background: transparent; }
              .custom-scrollbar::-webkit-scrollbar-thumb { background: #252525; border-radius: 0; }
            `}</style>

            {sourceLoading ? (
              <div className="flex flex-col items-center justify-center h-full gap-3 text-muted">
                <Loader2 className="w-5 h-5 animate-spin text-primary" />
                <p className="text-[0.6rem] font-mono uppercase tracking-widest animate-pulse">
                  Loading source...
                </p>
              </div>
            ) : !selectedPath ? (
              <div className="flex flex-col items-center justify-center h-full gap-4 text-muted">
                <Code2 className="w-10 h-10 text-border" />
                <div className="text-center">
                  <p className="text-[0.65rem] font-mono uppercase tracking-widest">
                    No class selected
                  </p>
                  <p className="text-[0.6rem] font-mono text-muted/60 mt-1">
                    Choose a .java file from the tree on the left
                  </p>
                </div>
              </div>
            ) : !sourceData?.available ? (
              <div className="flex flex-col items-center justify-center h-full gap-3">
                <AlertTriangle className="w-6 h-6 text-warning" />
                <p className="text-[0.6rem] font-mono text-warning uppercase">
                  {sourceData?.error ?? "Source unavailable"}
                </p>
              </div>
            ) : (
              /* Line-numbered source view */
              <div className="flex text-[0.65rem] font-mono leading-[1.65]">
                {/* Line numbers */}
                <div
                  className="select-none text-right pr-4 pl-4 py-4 text-muted border-r border-border bg-surface shrink-0"
                  aria-hidden="true"
                >
                  {sourceData.source!.split("\n").map((_, i) => (
                    <div key={i} className="leading-[1.65]">{i + 1}</div>
                  ))}
                </div>
                {/* Source code */}
                <pre
                  ref={codeRef}
                  className="flex-1 px-4 py-4 text-secondary whitespace-pre overflow-x-auto"
                  dangerouslySetInnerHTML={{ __html: highlightJava(sourceData.source!) }}
                />
              </div>
            )}
          </div>

          {/* Suspicious APIs legend — only shown when source loaded */}
          {sourceData?.available && suspiciousCount > 0 && (
            <div className="border-t border-border px-4 py-2 bg-[rgba(244,63,94,0.04)] flex items-center gap-2 shrink-0">
              <Zap className="w-3 h-3 text-danger shrink-0" />
              <p className="text-[0.6rem] font-mono text-danger/80 uppercase tracking-widest">
                Suspicious API calls are highlighted in red — potential malicious behaviour
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
