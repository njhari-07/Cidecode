"use client";
import { useCallback, useState } from "react";
import { Shield, Upload, FileWarning, Loader2, Zap } from "lucide-react";

interface DropZoneProps {
  onUpload: (file: File) => void;
  isLoading: boolean;
  compact?: boolean;
}

export default function DropZone({ onUpload, isLoading, compact = false }: DropZoneProps) {
  const [isDragging, setIsDragging] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const validate = (file: File) => {
    if (!file.name.toLowerCase().endsWith(".apk")) {
      setError("Only .apk files are accepted");
      return false;
    }
    if (file.size > 700 * 1024 * 1024) {
      setError("File size must be under 700 MB");
      return false;
    }
    setError(null);
    return true;
  };

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setIsDragging(false);
      const file = e.dataTransfer.files[0];
      if (file && validate(file)) onUpload(file);
    },
    [onUpload]
  );

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file && validate(file)) onUpload(file);
  };

  return (
    <div className="w-full mx-auto">
      <label
        htmlFor="apk-upload"
        onDragEnter={() => setIsDragging(true)}
        onDragLeave={() => setIsDragging(false)}
        onDragOver={(e) => e.preventDefault()}
        onDrop={handleDrop}
        className={`
          relative flex flex-col items-center justify-center gap-4
          border border-dashed cursor-pointer
          transition-all duration-300 group select-none corner-brackets
          ${compact ? "p-5" : "p-12"}
          ${isLoading ? "pointer-events-none opacity-60" : ""}
          ${isDragging
            ? "border-primary bg-[rgba(0,237,63,0.05)]"
            : "border-border bg-surface-raised hover:border-primary hover:bg-[rgba(0,237,63,0.02)]"
          }
        `}
      >
        {isLoading ? (
          <>
            <div className="relative">
              <span className="w-8 h-8 border-2 border-primary border-t-transparent rounded-full animate-spin block mb-4"></span>
            </div>
            <p className="text-muted text-xs font-mono uppercase tracking-widest animate-pulse">
              [ SCANNING APK... ]
            </p>
          </>
        ) : (
          <>
            <div
              className={`w-12 h-12 flex items-center justify-center transition-all duration-300 border
                ${isDragging ? "border-primary bg-[rgba(0,237,63,0.1)]" : "border-border bg-background group-hover:border-primary"}`}
            >
              <Upload
                className={`w-5 h-5 transition-colors ${isDragging ? "text-secondary" : "text-muted group-hover:text-secondary"}`}
              />
            </div>

            <div className="text-center font-mono">
              <p className="text-secondary uppercase tracking-widest text-sm mb-1">
                {isDragging ? "[ RELEASE TO SCAN ]" : "[ DROP YOUR APK HERE ]"}
              </p>
              <p className="text-muted text-[0.65rem] uppercase tracking-widest">
                or{" "}
                <span className="text-primary hover:text-secondary transition-colors">
                  browse to upload
                </span>
                {" "}— max 700 MB
              </p>
            </div>

            {!compact && (
              <div className="flex flex-wrap justify-center items-center gap-4 text-[0.6rem] text-muted uppercase tracking-widest mt-2">
                <span className="flex items-center gap-1.5 border border-border px-2 py-0.5 bg-background">
                  AI Narrative
                </span>
                <span className="flex items-center gap-1.5 border border-border px-2 py-0.5 bg-background">
                  YARA Rules
                </span>
                <span className="flex items-center gap-1.5 border border-border px-2 py-0.5 bg-background">
                  MITRE ATT&CK
                </span>
              </div>
            )}
          </>
        )}

        <input
          id="apk-upload"
          type="file"
          accept=".apk"
          className="hidden"
          disabled={isLoading}
          onChange={handleChange}
        />
      </label>

      {error && (
        <p className="mt-4 p-2 bg-[rgba(244,63,94,0.1)] border border-[rgba(244,63,94,0.3)] text-danger text-xs font-mono uppercase tracking-widest text-center">
          [ ERR: {error} ]
        </p>
      )}
    </div>
  );
}
