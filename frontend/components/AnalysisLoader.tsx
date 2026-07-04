"use client";
import { Shield, Cpu, Globe, Zap, FileSearch, Lock } from "lucide-react";

const steps = [
  { icon: FileSearch, label: "Parsing Manifest", color: "text-cyan-400" },
  { icon: Shield,     label: "YARA Scanning",   color: "text-indigo-400" },
  { icon: Lock,       label: "Cert Analysis",   color: "text-violet-400" },
  { icon: Cpu,        label: "Obfuscation Check", color: "text-yellow-400" },
  { icon: Globe,      label: "Threat Intel",    color: "text-orange-400" },
  { icon: Zap,        label: "AI Narrative",    color: "text-green-400" },
];

export default function AnalysisLoader() {
  return (
    <div className="flex flex-col items-center justify-center gap-8 py-12">
      {/* Central shield spinner */}
      <div className="relative w-24 h-24">
        <div className="absolute inset-0 rounded-full border-2 border-indigo-500/20 animate-spin-slow border-t-indigo-500" />
        <div className="absolute inset-2 rounded-full border-2 border-cyan-500/20 animate-spin-slow border-b-cyan-500 [animation-direction:reverse] [animation-duration:2s]" />
        <div className="absolute inset-0 flex items-center justify-center">
          <Shield className="w-10 h-10 text-indigo-400 animate-pulse" />
        </div>
      </div>

      {/* Title */}
      <div className="text-center">
        <h3 className="text-xl font-bold text-slate-100">
          Analysing APK
        </h3>
        <p className="text-slate-200 text-sm mt-1">
          Running multi-engine threat analysis — this may take 15–30 seconds
        </p>
      </div>

      {/* Step indicators */}
      <div className="grid grid-cols-3 gap-3 max-w-lg w-full">
        {steps.map(({ icon: Icon, label, color }, i) => (
          <div
            key={label}
            className="card-surface flex flex-col items-center gap-2 p-3 rounded-xl"
            style={{ animationDelay: `${i * 0.2}s` }}
          >
            <Icon className={`w-5 h-5 ${color} animate-pulse`} style={{ animationDelay: `${i * 0.3}s` }} />
            <span className="text-xs text-slate-200 text-center">{label}</span>
          </div>
        ))}
      </div>

      {/* Scanning bar */}
      <div className="w-full max-w-md h-1 bg-slate-800 rounded-full overflow-hidden">
        <div
          className="h-full rounded-full bg-gradient-to-r from-indigo-500 via-cyan-400 to-indigo-500"
          style={{
            backgroundSize: "200% 100%",
            animation: "shimmer 1.5s linear infinite",
          }}
        />
      </div>
    </div>
  );
}
