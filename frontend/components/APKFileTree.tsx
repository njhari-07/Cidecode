"use client";
import { useState, useEffect, useCallback } from "react";
import { ChevronRight, ChevronDown, Folder, FolderOpen, File, AlertTriangle, FileCode, Package } from "lucide-react";

interface TreeNode {
  name: string;
  path: string;
  type: "file" | "dir";
  size?: number;
  ext?: string;
  suspicious?: boolean;
  warning?: string;
  children?: TreeNode[];
}

interface FileTreeStats {
  total_files: number;
  total_size_bytes: number;
  dex_count: number;
  dex_files: string[];
  native_libs: number;
  suspicious_count: number;
  suspicious_files: string[];
}

interface FileTreeData {
  tree: TreeNode[];
  stats: FileTreeStats;
  error?: string | null;
}

const EXT_ICONS: Record<string, { icon: string; color: string }> = {
  ".dex": { icon: "⚙️", color: "text-blue-400" },
  ".so":  { icon: "🔧", color: "text-orange-400" },
  ".xml": { icon: "📋", color: "text-green-400" },
  ".png": { icon: "🖼️", color: "text-purple-400" },
  ".jpg": { icon: "🖼️", color: "text-purple-400" },
  ".json":{ icon: "📄", color: "text-yellow-400" },
  ".jar": { icon: "☕", color: "text-red-400" },
  ".bin": { icon: "💾", color: "text-rose-400" },
  ".enc": { icon: "🔒", color: "text-rose-500" },
  ".dat": { icon: "📦", color: "text-slate-200" },
};

function formatBytes(b: number) {
  if (b < 1024) return `${b} B`;
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`;
  return `${(b / 1024 / 1024).toFixed(2)} MB`;
}

function TreeNodeView({
  node,
  depth = 0,
}: {
  node: TreeNode;
  depth?: number;
}) {
  const [open, setOpen] = useState(depth < 2);
  const isDir = node.type === "dir";
  const extInfo = node.ext ? EXT_ICONS[node.ext] : null;

  return (
    <div className={`select-none ${depth > 0 ? "ml-4" : ""}`}>
      <div
        className={`
          flex items-center gap-1.5 py-[3px] px-2 rounded-md cursor-pointer group
          transition-colors text-sm
          ${node.suspicious
            ? "bg-rose-500/8 hover:bg-rose-500/15 text-rose-300"
            : "hover:bg-slate-700/40 text-slate-300"
          }
        `}
        onClick={() => isDir && setOpen((o) => !o)}
      >
        {/* Indent guides */}
        {depth > 0 && (
          <span className="text-slate-300 select-none" style={{ marginLeft: `${(depth - 1) * 12}px` }} />
        )}

        {/* Expand arrow */}
        {isDir ? (
          <span className="text-slate-300 w-3.5 flex-shrink-0">
            {open ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}
          </span>
        ) : (
          <span className="w-3.5 flex-shrink-0" />
        )}

        {/* Icon */}
        {isDir ? (
          open ? (
            <FolderOpen className="w-3.5 h-3.5 text-yellow-400 flex-shrink-0" />
          ) : (
            <Folder className="w-3.5 h-3.5 text-yellow-500 flex-shrink-0" />
          )
        ) : extInfo ? (
          <span className={`text-[11px] leading-none ${extInfo.color}`}>{extInfo.icon}</span>
        ) : (
          <File className="w-3 h-3 text-slate-300 flex-shrink-0" />
        )}

        {/* Name */}
        <span className={`truncate font-mono text-xs ${node.suspicious ? "text-rose-300 font-semibold" : ""}`}>
          {node.name}
        </span>

        {/* Size */}
        {node.size != null && (
          <span className="ml-auto text-[10px] text-slate-200 flex-shrink-0">
            {formatBytes(node.size)}
          </span>
        )}

        {/* Suspicious badge */}
        {node.suspicious && (
          <span className="ml-1 flex-shrink-0" title={node.warning}>
            <AlertTriangle className="w-3 h-3 text-rose-400" />
          </span>
        )}
      </div>

      {/* Warning tooltip */}
      {node.suspicious && node.warning && (
        <div className="ml-8 mb-1 text-[11px] text-rose-400/80 bg-rose-500/5 border border-rose-500/15 rounded px-2 py-1">
          ⚠️ {node.warning}
        </div>
      )}

      {/* Children */}
      {isDir && open && node.children && node.children.length > 0 && (
        <div>
          {node.children.map((child) => (
            <TreeNodeView key={child.path} node={child} depth={depth + 1} />
          ))}
        </div>
      )}
    </div>
  );
}

interface APKFileTreeProps {
  analysisId: string;
}

export default function APKFileTree({ analysisId }: APKFileTreeProps) {
  const [data, setData] = useState<FileTreeData | null>(null);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");

  const fetchTree = useCallback(async () => {
    try {
      const res = await fetch(
        `${process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"}/api/analysis/${analysisId}/filetree`
      );
      if (res.ok) setData(await res.json());
    } catch {
      setData({ tree: [], stats: {} as FileTreeStats, error: "Failed to load file tree" });
    } finally {
      setLoading(false);
    }
  }, [analysisId]);

  useEffect(() => { fetchTree(); }, [fetchTree]);

  if (loading) {
    return (
      <div className="rounded-2xl border border-slate-700/40 bg-slate-900/60 p-6 animate-pulse">
        <div className="h-4 w-48 bg-slate-700/50 rounded mb-4" />
        <div className="space-y-2">
          {[...Array(8)].map((_, i) => (
            <div key={i} className="h-3 rounded bg-slate-800" style={{ width: `${60 + i * 5}%` }} />
          ))}
        </div>
      </div>
    );
  }

  if (!data || data.error) {
    return (
      <div className="rounded-2xl border border-slate-700/40 bg-slate-900/60 p-6 text-center text-slate-300 text-sm">
        <Package className="w-8 h-8 mx-auto mb-2 text-slate-200" />
        {data?.error || "File tree unavailable"}
      </div>
    );
  }

  const stats = data.stats;

  return (
    <div className="rounded-2xl border border-slate-700/40 bg-slate-900/60 overflow-hidden">
      {/* Header */}
      <div className="border-b border-slate-700/40 px-5 py-4 flex items-center justify-between gap-3 flex-wrap">
        <div className="flex items-center gap-2">
          <Folder className="w-4 h-4 text-yellow-400" />
          <span className="font-semibold text-slate-100 text-sm">APK File Structure</span>
          {stats.suspicious_count > 0 && (
            <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-rose-500/15 text-rose-400 border border-rose-500/25">
              ⚠️ {stats.suspicious_count} suspicious
            </span>
          )}
        </div>
        <div className="flex items-center gap-3 text-xs text-slate-300">
          <span><span className="text-slate-300 font-semibold">{stats.total_files}</span> files</span>
          <span className="text-slate-300">·</span>
          <span><span className="text-blue-400 font-semibold">{stats.dex_count}</span> DEX</span>
          <span className="text-slate-300">·</span>
          <span><span className="text-orange-400 font-semibold">{stats.native_libs}</span> .so libs</span>
          <span className="text-slate-300">·</span>
          <span>{formatBytes(stats.total_size_bytes || 0)}</span>
        </div>
      </div>

      {/* Suspicious files summary */}
      {stats.suspicious_count > 0 && (
        <div className="mx-4 mt-4 rounded-lg border border-rose-500/20 bg-rose-500/5 p-3">
          <div className="flex items-center gap-2 text-rose-400 text-xs font-semibold mb-1.5">
            <AlertTriangle className="w-3.5 h-3.5" />
            Suspicious Entries Detected
          </div>
          <div className="flex flex-wrap gap-1.5">
            {stats.suspicious_files?.map((f) => (
              <code key={f} className="text-[10px] bg-rose-500/10 text-rose-300 px-2 py-0.5 rounded font-mono">
                {f}
              </code>
            ))}
          </div>
        </div>
      )}

      {/* Search */}
      <div className="px-4 pt-3 pb-2">
        <input
          type="text"
          placeholder="Filter files…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="w-full px-3 py-1.5 rounded-lg text-xs bg-slate-800/80 border border-slate-700/50 text-slate-300 placeholder-slate-600 outline-none focus:border-indigo-500/40"
        />
      </div>

      {/* Tree */}
      <div className="px-3 pb-4 max-h-96 overflow-y-auto scrollbar-thin scrollbar-track-transparent scrollbar-thumb-slate-700">
        {data.tree.length === 0 ? (
          <p className="text-center text-slate-200 text-xs py-8">No files found</p>
        ) : (
          data.tree.map((node) => (
            <TreeNodeView key={node.path} node={node} depth={0} />
          ))
        )}
      </div>
    </div>
  );
}
