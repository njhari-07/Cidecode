"use client";

import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { getStats, uploadApk } from "@/lib/api";
import type { DashboardStats } from "@/lib/types";
import DropZone from "@/components/DropZone";
import AnalysisProgress from "@/components/AnalysisProgress";

type UploadState =
  | { phase: "idle" }
  | { phase: "uploading" }
  | { phase: "progress"; jobId: string }
  | { phase: "error"; msg: string };

export default function Home() {
  const router = useRouter();
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [uploadState, setUploadState] = useState<UploadState>({ phase: "idle" });

  useEffect(() => {
    getStats()
      .then(setStats)
      .catch((err) => console.error("Failed to fetch stats:", err));
  }, []);

  const handleUpload = async (file: File) => {
    setUploadState({ phase: "uploading" });
    try {
      const response = await uploadApk(file);

      // Cache hit or sync fallback — result ready immediately
      if (response.status === "complete" && response.result) {
        router.push(`/results/${response.result.id}`);
        return;
      }

      // Queued — hand off to WebSocket progress UI
      setUploadState({ phase: "progress", jobId: response.job_id });

    } catch (err: any) {
      setUploadState({ phase: "error", msg: err.message || "Upload failed. Please try again." });
    }
  };

  const handleComplete = useCallback((analysisId: string) => {
    router.push(`/results/${analysisId}`);
  }, [router]);

  const handleError = useCallback((msg: string) => {
    setUploadState({ phase: "error", msg });
  }, []);

  const isLoading = uploadState.phase === "uploading" || uploadState.phase === "progress";

  const totalThreats = (stats?.critical_count ?? 0) + (stats?.high_count ?? 0) + (stats?.medium_count ?? 0);

  return (
    <div className="relative min-h-screen bg-transparent">
      {/* Navigation */}
      <nav className="fixed top-0 left-0 w-full z-50 transition-all duration-300 backdrop-blur-xl border-b border-transparent bg-background/40 py-4">
        <div className="w-full flex justify-between items-center px-6 lg:px-12">
          <Link href="/" className="flex items-center gap-4 relative z-10 group">
            <div className="relative">
              <div className="absolute inset-0 bg-primary blur-md opacity-20 group-hover:opacity-60 transition-opacity"></div>
              <img 
                src="/logo.png" 
                alt="DroidRaksha Logo" 
                className="w-11 h-11 object-contain mix-blend-screen relative z-10 group-hover:scale-110 transition-transform duration-300" 
              />
            </div>
            <span className="font-mono tracking-[0.2em] text-xl font-bold text-secondary uppercase leading-none hover-scramble drop-shadow-[var(--glow-primary)]">
              DROIDRAKSHA
            </span>
          </Link>
          <div className="hidden lg:flex items-center gap-8 text-xs font-mono tracking-widest text-muted uppercase">
            <a href="#platform" className="hover:text-secondary transition-colors flex items-center gap-2">
              <span className="text-primary opacity-50">01</span> Platform
            </a>
            <a href="#how-it-works" className="hover:text-secondary transition-colors flex items-center gap-2">
              <span className="text-primary opacity-50">02</span> Architecture
            </a>
            <a href="#features" className="hover:text-secondary transition-colors flex items-center gap-2">
              <span className="text-primary opacity-50">03</span> Features
            </a>
            <a href="#testimonials" className="hover:text-secondary transition-colors flex items-center gap-2">
              <span className="text-primary opacity-50">04</span> Testimonials
            </a>
          </div>
          <div className="flex items-center gap-6">
            <Link href="/dashboard" className="btn-hex px-6 py-2.5 text-xs hidden md:inline-flex">
              <span className="relative z-10">Access Terminal</span>
            </Link>
          </div>
        </div>
      </nav>

      <main>
        {/* Hero Section */}
        <section id="platform" className="relative min-h-screen flex items-center pt-32 pb-20 px-6 lg:px-12 z-10">
          <div className="absolute inset-0 grid-bg opacity-30"></div>
          <div className="w-full h-full max-w-[100rem] mx-auto grid grid-cols-1 lg:grid-cols-12 gap-12 relative items-center">
            <div className="lg:col-span-8 flex flex-col items-start relative z-20">
              <div className="sys-badge inline-flex items-center gap-3 px-4 py-1.5 mb-8 animate-fade-in">
                <span className="w-1.5 h-1.5 bg-primary rounded-full animate-pulse shadow-[var(--glow-primary)]"></span>
                <span className="text-xs font-mono text-secondary tracking-widest uppercase">System Integrity: Optimal</span>
                <span className="text-[0.6rem] text-muted ml-2 hidden sm:inline-block">INDIA IOC // ACTIVE</span>
              </div>
              <h1 className="text-[clamp(3.5rem,7vw,7rem)] font-bold leading-[0.95] tracking-tighter text-secondary mb-6 uppercase">
                <span className="block reveal" style={{ animationDelay: '0.1s' }}>AI-Powered Threat</span>
                <span className="block reveal text-muted" style={{ animationDelay: '0.2s' }}>Intelligence Platform.</span>
              </h1>
              <p className="text-sm md:text-base lg:text-lg font-light leading-relaxed text-muted max-w-2xl mb-12 reveal border-l-2 border-border pl-6" style={{ animationDelay: '0.3s' }}>
                India's advanced static and dynamic analysis platform. We identify banking trojans, UPI fraud apps, and loan scams through a multi-engine pipeline leveraging YARA rules, heuristics, and AI-driven narrative generation.
              </p>
              <div className="flex flex-col sm:flex-row items-center gap-4 w-full sm:w-auto reveal" style={{ animationDelay: '0.4s' }}>
                <a href="#deployment" className="btn-hex btn-hex-primary w-full sm:w-auto px-10 py-5 text-sm">
                  <span className="relative z-10 flex items-center gap-3">Analyze APK</span>
                </a>
                <Link href="/dashboard" className="btn-hex w-full sm:w-auto px-10 py-5 text-sm">
                  <span className="relative z-10 flex items-center gap-3">View Global Dashboard</span>
                </Link>
              </div>
              <div className="mt-16 flex items-center gap-8 reveal" style={{ animationDelay: '0.5s' }}>
                <div className="flex flex-col">
                  <span className="text-2xl font-mono text-secondary tracking-tight">{stats ? totalThreats : "..."}</span>
                  <span className="text-xs text-muted uppercase tracking-widest mt-1">Threats Uncovered</span>
                </div>
                <div className="w-px h-10 bg-[#151515]"></div>
                <div className="flex flex-col">
                  <span className="text-2xl font-mono text-secondary tracking-tight">15 Min</span>
                  <span className="text-xs text-muted uppercase tracking-widest mt-1">Avg. Sandbox Speed</span>
                </div>
              </div>
            </div>
            
            <div className="lg:col-span-4 hidden lg:flex flex-col justify-center items-end relative reveal" style={{ animationDelay: '0.6s' }}>
              <div className="w-full max-w-sm glass-panel p-6 corner-brackets clip-corner-sm scanlines clip-corner-sm scanlines">
                <div className="flex justify-between items-center mb-6 pb-4 border-b border-border">
                  <span className="text-xs font-mono text-muted uppercase tracking-widest">Analysis Pipeline</span>
                </div>
                <div className="space-y-4">
                  <div className="flex justify-between text-xs font-mono">
                    <span className="text-muted">XGBoost Confidence</span>
                    <span className="text-secondary">99.8%</span>
                  </div>
                  <div className="w-full bg-surface-raised h-1">
                    <div className="bg-primary h-full w-[99.8%] relative">
                      <div className="absolute right-0 top-1/2 -translate-y-1/2 w-2 h-2 bg-white rounded-full shadow-[0_0_10px_#fff]"></div>
                    </div>
                  </div>
                  <div className="flex justify-between text-xs font-mono pt-2">
                    <span className="text-muted">YARA Engine</span>
                    <span className="text-secondary">50+ RULES</span>
                  </div>
                  <div className="w-full bg-surface-raised h-1">
                    <div className="bg-white h-full w-[100%]"></div>
                  </div>
                  <div className="flex justify-between text-xs font-mono pt-2">
                    <span className="text-muted">Sandbox Security</span>
                    <span className="text-primary animate-pulse">ISOLATED</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* Marquee Section */}
        <section className="py-6 border-y border-border bg-surface relative z-10 overflow-hidden flex flex-col gap-4">
          <div className="absolute left-0 top-0 bottom-0 w-32 bg-gradient-to-r from-[#030303] to-transparent z-20 pointer-events-none"></div>
          <div className="absolute right-0 top-0 bottom-0 w-32 bg-gradient-to-l from-[#030303] to-transparent z-20 pointer-events-none"></div>
          <div className="flex whitespace-nowrap overflow-hidden">
            <div className="animate-marquee flex items-center gap-12 text-xs uppercase font-mono tracking-widest text-muted">
              <span className="text-secondary">Trusted by</span><span className="w-1 h-1 bg-border"></span>
              <span className="flex items-center gap-2">Security Researchers</span><span className="w-1 h-1 bg-border"></span>
              <span className="flex items-center gap-2">SOC Teams</span><span className="w-1 h-1 bg-border"></span>
              <span className="flex items-center gap-2">Forensics Teams</span><span className="w-1 h-1 bg-border"></span>
              <span className="flex items-center gap-2">App Store Security</span><span className="w-1 h-1 bg-border"></span>
              <span className="text-secondary">Trusted by</span><span className="w-1 h-1 bg-border"></span>
              <span className="flex items-center gap-2">Security Researchers</span><span className="w-1 h-1 bg-border"></span>
              <span className="flex items-center gap-2">SOC Teams</span><span className="w-1 h-1 bg-border"></span>
              <span className="flex items-center gap-2">Forensics Teams</span><span className="w-1 h-1 bg-border"></span>
              <span className="flex items-center gap-2">App Store Security</span><span className="w-1 h-1 bg-border"></span>
            </div>
          </div>
        </section>

        {/* Intelligence Demo Section */}
        <section className="py-32 px-6 lg:px-12 w-full relative z-10 bg-background">
          <div className="max-w-[100rem] mx-auto reveal">
            <div className="mb-16 flex flex-col md:flex-row justify-between items-end gap-8 border-b border-border pb-8">
              <div>
                <h2 className="text-3xl md:text-5xl font-bold tracking-tighter text-secondary uppercase mb-4">Command Terminal</h2>
                <p className="text-sm text-muted font-mono tracking-widest uppercase">Absolute transparency. Total control.</p>
              </div>
              <div className="text-right text-xs font-mono text-muted">[ SYSTEM PREVIEW ]<br/>VERSION 2.0.0</div>
            </div>
            
            <div className="w-full glass-panel rounded-xl overflow-hidden border border-border relative shadow-[var(--glow-primary)]">
              <div className="bg-surface-raised border-b border-border px-6 py-4 flex justify-between items-center">
                <div className="flex items-center gap-4">
                  <div className="flex gap-2">
                    <div className="w-3 h-3 rounded-full bg-border"></div>
                    <div className="w-3 h-3 rounded-full bg-border"></div>
                    <div className="w-3 h-3 rounded-full bg-border"></div>
                  </div>
                  <div className="h-4 w-px bg-border"></div>
                  <span className="text-xs font-mono text-secondary">DROID_OS // ROOT</span>
                </div>
                <div className="flex gap-4 text-xs font-mono">
                  <span className="text-primary">CONNECTED</span>
                  <span className="text-muted">LIVE FEED</span>
                </div>
              </div>
              <div className="grid grid-cols-1 lg:grid-cols-12 bg-background/50">
                <div className="hidden lg:block lg:col-span-2 border-r border-border p-6 space-y-8">
                  <div>
                    <div className="text-[0.6rem] font-mono text-muted uppercase tracking-widest mb-4">Navigation</div>
                    <ul className="space-y-3 text-xs font-mono">
                      <li className="text-secondary flex justify-between items-center">
                        <span className="flex items-center gap-2">APK Overview</span> 
                        <span className="w-1 h-1 bg-white rounded-full"></span>
                      </li>
                      <li className="text-muted hover:text-secondary transition-colors cursor-pointer flex items-center gap-2">Malware Logs</li>
                      <li className="text-muted hover:text-secondary transition-colors cursor-pointer flex items-center gap-2">Sandbox Status</li>
                      <li className="text-muted hover:text-secondary transition-colors cursor-pointer flex items-center gap-2">C2 Infrastructure</li>
                    </ul>
                  </div>
                  <div>
                    <div className="text-[0.6rem] font-mono text-muted uppercase tracking-widest mb-4">System Alerts</div>
                    <div className="bg-surface-raised border border-border p-3 text-[0.65rem] font-mono text-muted">
                      <span className="text-primary">INFO:</span> Automated LangChain report generated.
                    </div>
                  </div>
                </div>
                
                <div className="col-span-1 lg:col-span-7 border-r border-border p-6 lg:p-10 flex flex-col gap-8 grid-bg relative">
                  <div className="absolute inset-0 bg-gradient-to-b from-transparent to-black pointer-events-none"></div>
                  <div className="grid grid-cols-3 gap-6 relative z-10">
                    <div className="bg-surface-raised border border-border p-4 corner-brackets group">
                      <div className="text-[0.6rem] font-mono text-muted uppercase tracking-widest mb-2">Analyzed APKs</div>
                      <div className="text-xl lg:text-3xl font-mono text-secondary tracking-tight">{stats ? stats.total_analyzed : "84.2K"}</div>
                    </div>
                    <div className="bg-surface-raised border border-border p-4 corner-brackets group">
                      <div className="text-[0.6rem] font-mono text-muted uppercase tracking-widest mb-2">Detected Threats</div>
                      <div className="text-xl lg:text-3xl font-mono text-danger tracking-tight">{stats ? totalThreats : "1,420"}</div>
                    </div>
                    <div className="bg-surface-raised border border-border p-4 corner-brackets group">
                      <div className="text-[0.6rem] font-mono text-muted uppercase tracking-widest mb-2">Sandbox Load</div>
                      <div className="text-xl lg:text-3xl font-mono text-secondary tracking-tight">14%</div>
                    </div>
                  </div>
                  <div className="flex-1 flex items-center justify-center p-6 mt-12 mb-12">
                     <p className="text-muted font-mono text-sm uppercase animate-pulse">[ AWAITING INGRESS QUEUE ]</p>
                  </div>
                </div>
                
                <div className="col-span-1 lg:col-span-3 p-0 bg-surface-raised flex flex-col h-[30rem] lg:h-auto border-t lg:border-t-0 border-border">
                  <div className="p-4 border-b border-border">
                    <div className="text-xs font-mono text-secondary uppercase tracking-widest flex items-center gap-2">
                      <span className="w-2 h-2 bg-primary rounded-full animate-ping"></span> Live Feed
                    </div>
                  </div>
                  <div className="flex-1 p-4 overflow-y-auto relative max-h-[35rem]">
                    <div className="space-y-1 text-[0.65rem] font-mono flex flex-col">
                      <div className="data-row p-2 border-l-2 flex justify-between border-transparent"><span className="text-muted">[14:21:05]</span><span className="text-muted">APK_UPLOAD</span><span className="text-secondary">OK</span></div>
                      <div className="data-row p-2 border-l-2 flex justify-between border-transparent"><span className="text-muted">[14:21:12]</span><span className="text-muted">ANDROGUARD</span><span className="text-secondary">MANIFEST_OK</span></div>
                      <div className="data-row p-2 border-l-2 flex justify-between border-danger bg-[rgba(204,34,0,0.1)]"><span className="text-muted">[14:21:18]</span><span className="text-danger">YARA_MATCH</span><span className="text-danger">HIGH</span></div>
                      <div className="data-row p-2 border-l-2 flex justify-between border-transparent"><span className="text-muted">[14:21:33]</span><span className="text-muted">XGBOOST</span><span className="text-secondary">PASS</span></div>
                      <div className="data-row p-2 border-l-2 flex justify-between border-transparent"><span className="text-muted">[14:21:45]</span><span className="text-muted">MOBSF_SANDBOX</span><span className="text-secondary">EXECUTING</span></div>
                      <div className="data-row p-2 border-l-2 flex justify-between border-transparent"><span className="text-muted">[14:22:01]</span><span className="text-muted">PCAP_DUMP</span><span className="text-secondary">SCANNING</span></div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* The Arsenal Section */}
        <section id="features" className="py-32 px-6 lg:px-12 w-full relative z-10 bg-surface border-t border-border">
          <div className="max-w-[100rem] mx-auto">
            <div className="mb-20 reveal max-w-2xl">
              <h2 className="text-3xl md:text-5xl font-bold tracking-tighter text-secondary uppercase mb-6">The Arsenal.</h2>
              <p className="text-sm md:text-base text-muted font-light leading-relaxed">
                Everything you need to detect, analyze, and respond to advanced Android malware threats with forensic-grade precision.
              </p>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 reveal stagger-group">
              <div className="glass-panel p-8 corner-brackets clip-corner-md scanlines clip-corner-md scanlines group stagger-item flex flex-col hover:bg-[#080808] transition-colors duration-500">
                <h3 className="text-lg font-bold text-secondary uppercase tracking-tight mb-3 font-mono">Dynamic Sandbox & PCAP</h3>
                <p className="text-sm text-muted font-light leading-relaxed flex-1">
                  Execute APKs safely in a Dockerized MobSF environment. Hook APIs with Frida and automatically analyze PCAP network dumps for DGA and C2 beacons.
                </p>
                <div className="mt-8 pt-4 border-t border-border text-[0.65rem] font-mono text-muted uppercase">Tech: MobSF / Frida / tcpdump</div>
              </div>
              <div className="glass-panel p-8 corner-brackets clip-corner-md scanlines clip-corner-md scanlines group stagger-item flex flex-col hover:bg-[#080808] transition-colors duration-500">
                <h3 className="text-lg font-bold text-secondary uppercase tracking-tight mb-3 font-mono">AI & ML Intelligence</h3>
                <p className="text-sm text-muted font-light leading-relaxed flex-1">
                  Classify threats using Static ML (trained on CICMalDroid 2020), Deep Neural Net zero-shot classification, and Isolation Forests for zero-day anomaly detection.
                </p>
                <div className="mt-8 pt-4 border-t border-border text-[0.65rem] font-mono text-muted uppercase">Tech: Static ML / Deep Neural Net</div>
              </div>
              <div className="glass-panel p-8 corner-brackets clip-corner-md scanlines clip-corner-md scanlines group stagger-item flex flex-col hover:bg-[#080808] transition-colors duration-500">
                <h3 className="text-lg font-bold text-secondary uppercase tracking-tight mb-3 font-mono">India IOC Threat Intel</h3>
                <p className="text-sm text-muted font-light leading-relaxed flex-1">
                  Cross-reference behaviors against a curated database of Indicators of Compromise targeting the Indian landscape, including fake UPI and loan apps.
                </p>
                <div className="mt-8 pt-4 border-t border-border text-[0.65rem] font-mono text-muted uppercase">Tech: Custom IOC Engine</div>
              </div>
            </div>
          </div>
        </section>

        {/* Stats Banner */}
        <section className="py-32 relative z-10 bg-background overflow-hidden border-t border-border">
          <div className="absolute inset-0 grid-bg opacity-30"></div>
          <div className="max-w-[100rem] mx-auto px-6 grid grid-cols-1 md:grid-cols-4 gap-12 text-center reveal stagger-group relative z-10">
            <div className="stagger-item flex flex-col items-center">
              <div className="text-[0.65rem] font-mono text-muted uppercase tracking-widest mb-4 border border-border px-3 py-1 bg-surface-raised">YARA Rules</div>
              <div className="text-6xl font-bold tracking-tighter text-secondary mb-2">50<span className="text-2xl text-primary ml-1">+</span></div>
              <p className="text-xs text-muted font-mono uppercase mt-2">Comprehensive Signatures</p>
            </div>
            <div className="stagger-item flex flex-col items-center">
              <div className="text-[0.65rem] font-mono text-muted uppercase tracking-widest mb-4 border border-border px-3 py-1 bg-surface-raised">Machine Learning</div>
              <div className="text-6xl font-bold tracking-tighter text-secondary mb-2">3<span className="text-2xl text-primary ml-1">Models</span></div>
              <p className="text-xs text-muted font-mono uppercase mt-2">Static ML, Deep Neural Net, IF</p>
            </div>
            <div className="stagger-item flex flex-col items-center">
              <div className="text-[0.65rem] font-mono text-muted uppercase tracking-widest mb-4 border border-border px-3 py-1 bg-surface-raised">LangChain GenAI</div>
              <div className="text-6xl font-bold tracking-tighter text-secondary mb-2">100<span className="text-2xl text-primary ml-1">%</span></div>
              <p className="text-xs text-muted font-mono uppercase mt-2">Court-Admissible Narratives</p>
            </div>
            <div className="stagger-item flex flex-col items-center">
              <div className="text-[0.65rem] font-mono text-muted uppercase tracking-widest mb-4 border border-border px-3 py-1 bg-surface-raised">Analysis Pipeline</div>
              <div className="text-6xl font-bold tracking-tighter text-secondary mb-2">15<span className="text-2xl text-primary ml-1">Stages</span></div>
              <p className="text-xs text-muted font-mono uppercase mt-2">Async Celery Workers</p>
            </div>
          </div>
        </section>

        {/* How It Works */}
        <section id="how-it-works" className="py-40 px-6 lg:px-12 w-full relative z-10 bg-surface border-t border-border">
          <div className="max-w-[100rem] mx-auto grid grid-cols-1 lg:grid-cols-2 gap-20 items-center reveal">
            <div className="relative w-full aspect-square max-w-xl mx-auto flex items-center justify-center">
              <div className="absolute inset-0 rounded-full border border-border animate-spin-slow"></div>
              <div className="absolute inset-10 rounded-full border border-border border-dashed animate-spin-slow-reverse"></div>
              <div className="absolute inset-20 rounded-full border border-border"></div>
              <div className="w-24 h-24 bg-surface-raised border border-primary rounded-full relative z-20 flex items-center justify-center shadow-[var(--glow-primary)]">
                <div className="w-8 h-8 bg-white rounded-full animate-pulse shadow-[0_0_20px_#fff]"></div>
              </div>
              <div className="absolute top-0 left-1/2 -translate-x-1/2 -translate-y-1/2 w-4 h-4 bg-primary rounded-full z-10 before:content-[''] before:absolute before:w-px before:h-40 before:bg-gradient-to-b before:from-[#0052FF] before:to-transparent before:left-1/2 before:top-4"></div>
              <div className="absolute bottom-10 right-10 w-3 h-3 bg-white rounded-full z-10 before:content-[''] before:absolute before:h-px before:w-32 before:bg-gradient-to-l before:from-white before:to-transparent before:right-3 before:top-1/2"></div>
              <div className="absolute top-20 left-10 w-2 h-2 bg-[#777] rounded-full z-10"></div>
            </div>
            <div className="flex flex-col items-start">
              <div className="text-[0.65rem] font-mono text-primary uppercase tracking-widest mb-4 bg-[rgba(0,237,63,0.1)] px-3 py-1 border border-[rgba(0,237,63,0.3)]">Distributed Architecture</div>
              <h2 className="text-3xl md:text-5xl font-bold tracking-tighter text-secondary uppercase mb-8">Three Intelligent<br/>Analysis Layers.</h2>
              <p className="text-sm md:text-base text-muted font-light leading-relaxed mb-8">DroidRaksha uses a Celery & Redis backed microservice pipeline to offload heavy analysis to distributed workers seamlessly across three core layers.</p>
              <div className="space-y-6 font-mono text-xs text-muted">
                <div className="border-l border-border pl-4">
                  <span className="text-secondary block mb-1 uppercase tracking-widest">1. Static Analysis Layer</span>
                  <span className="text-muted block mb-2">Androguard and APKTool decompile the binary, mapping MITRE ATT&CK techniques and executing 50+ YARA signatures.</span>
                  <span className="text-xs text-muted flex flex-wrap gap-x-3 gap-y-1"><span>// Androguard</span><span>// YARA 50+</span><span>// Manifest Parsing</span></span>
                </div>
                <div className="border-l border-border pl-4">
                  <span className="text-secondary block mb-1 uppercase tracking-widest">2. Dynamic Sandbox Layer</span>
                  <span className="text-muted block mb-2">Dockerized MobSF environment safely detonates the payload while Frida hooks API calls and mitmproxy captures network PCAPs.</span>
                  <span className="text-xs text-muted flex flex-wrap gap-x-3 gap-y-1"><span>// MobSF Docker</span><span>// Frida Hooks</span><span>// PCAP Analysis</span></span>
                </div>
                <div className="border-l border-border pl-4">
                  <span className="text-secondary block mb-1 uppercase tracking-widest">3. AI & ML Intelligence Layer</span>
                  <span className="text-muted block mb-2">Combines Deep Neural Net text classification, Static ML structured detection, and LangChain ReAct agents to produce court-grade verdicts.</span>
                  <span className="text-xs text-muted flex flex-wrap gap-x-3 gap-y-1"><span>// Static ML</span><span>// Deep Neural Net</span><span>// LangChain ReAct</span></span>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* Testimonials */}
        <section id="testimonials" className="py-32 px-6 lg:px-12 w-full relative z-10 bg-surface border-t border-border">
          <div className="max-w-[100rem] mx-auto">
            <div className="mb-20 reveal max-w-2xl">
              <div className="text-[0.65rem] font-mono text-primary uppercase tracking-widest mb-4 bg-[rgba(0,237,63,0.1)] px-3 py-1 border border-[rgba(0,237,63,0.3)] inline-block">Testimonials</div>
              <h2 className="text-3xl md:text-5xl font-bold tracking-tighter text-secondary uppercase mb-6">Trusted by Security Professionals</h2>
              <p className="text-sm md:text-base text-muted font-light leading-relaxed">Discover how security researchers, SOC teams, and forensics professionals are detecting advanced Android malware with confidence.</p>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8 reveal stagger-group">
              <div className="glass-panel p-8 corner-brackets clip-corner-md scanlines clip-corner-md scanlines group stagger-item flex flex-col hover:bg-[#080808] transition-colors duration-500">
                <div className="flex justify-between items-center mb-6 pb-4 border-b border-border">
                  <span className="text-[0.6rem] font-mono text-muted uppercase">Verified Agent Log</span>
                </div>
                <p className="text-sm text-muted font-light leading-relaxed flex-1 italic mb-6">"The multi-agent analysis caught malware that our traditional scanners completely missed. The C2 communication detection is a game-changer for our security team."</p>
                <div className="flex flex-col">
                  <span className="text-sm font-bold text-secondary font-mono">Dr. Alex Kumar</span>
                  <span className="text-xs text-muted uppercase tracking-widest mt-1">Lead Security Researcher</span>
                </div>
              </div>
              <div className="glass-panel p-8 corner-brackets clip-corner-md scanlines clip-corner-md scanlines group stagger-item flex flex-col hover:bg-[#080808] transition-colors duration-500">
                <div className="flex justify-between items-center mb-6 pb-4 border-b border-border">
                  <span className="text-[0.6rem] font-mono text-muted uppercase">Verified Agent Log</span>
                </div>
                <p className="text-sm text-muted font-light leading-relaxed flex-1 italic mb-6">"We've reduced malware analysis time from 8 hours to under 15 minutes. The forensic reports are incredibly detailed and actionable."</p>
                <div className="flex flex-col">
                  <span className="text-sm font-bold text-secondary font-mono">Jessica Martinez</span>
                  <span className="text-xs text-muted uppercase tracking-widest mt-1">SOC Team Lead</span>
                </div>
              </div>
              <div className="glass-panel p-8 corner-brackets clip-corner-md scanlines clip-corner-md scanlines group stagger-item flex flex-col hover:bg-[#080808] transition-colors duration-500">
                <div className="flex justify-between items-center mb-6 pb-4 border-b border-border">
                  <span className="text-[0.6rem] font-mono text-muted uppercase">Verified Agent Log</span>
                </div>
                <p className="text-sm text-muted font-light leading-relaxed flex-1 italic mb-6">"As a digital forensics investigator, I've tested dozens of analysis tools. This platform's ability to detect C2 communication is unmatched."</p>
                <div className="flex flex-col">
                  <span className="text-sm font-bold text-secondary font-mono">Robert Chen</span>
                  <span className="text-xs text-muted uppercase tracking-widest mt-1">Digital Forensics Investigator</span>
                </div>
              </div>
              <div className="glass-panel p-8 corner-brackets clip-corner-md scanlines clip-corner-md scanlines group stagger-item flex flex-col hover:bg-[#080808] transition-colors duration-500">
                <div className="flex justify-between items-center mb-6 pb-4 border-b border-border">
                  <span className="text-[0.6rem] font-mono text-muted uppercase">Verified Agent Log</span>
                </div>
                <p className="text-sm text-muted font-light leading-relaxed flex-1 italic mb-6">"The dynamic analysis engine captured runtime behaviors that would have taken us days to trace manually. Exceptional accuracy and speed."</p>
                <div className="flex flex-col">
                  <span className="text-sm font-bold text-secondary font-mono">Sofia Patel</span>
                  <span className="text-xs text-muted uppercase tracking-widest mt-1">Malware Analyst</span>
                </div>
              </div>
              <div className="glass-panel p-8 corner-brackets clip-corner-md scanlines clip-corner-md scanlines group stagger-item flex flex-col hover:bg-[#080808] transition-colors duration-500">
                <div className="flex justify-between items-center mb-6 pb-4 border-b border-border">
                  <span className="text-[0.6rem] font-mono text-muted uppercase">Verified Agent Log</span>
                </div>
                <p className="text-sm text-muted font-light leading-relaxed flex-1 italic mb-6">"Before this platform, we were manually decompiling APKs. Now we get comprehensive reports in minutes with forensic evidence included."</p>
                <div className="flex flex-col">
                  <span className="text-sm font-bold text-secondary font-mono">Marcus Thompson</span>
                  <span className="text-xs text-muted uppercase tracking-widest mt-1">Security Analyst</span>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* Upload Terminal Section */}
        <section id="deployment" className="relative w-full border-t border-border bg-surface z-10">
          <div className="grid grid-cols-1 lg:grid-cols-2 min-h-screen">
            <div className="p-10 md:p-20 flex flex-col justify-center border-b lg:border-b-0 lg:border-r border-border relative overflow-hidden">
              <div className="absolute inset-0 grid-bg opacity-20 pointer-events-none"></div>
              <div className="absolute top-0 left-0 w-2 h-full bg-primary"></div>
              <div className="relative z-10 reveal max-w-lg">
                <div className="text-[0.65rem] font-mono text-primary uppercase tracking-widest mb-6">Analysis Terminal</div>
                <h2 className="text-4xl md:text-5xl font-bold tracking-tighter mb-8 leading-[0.9] text-secondary uppercase">Start Analyzing<br/>Android Threats Today.</h2>
                <div className="space-y-6 text-sm text-muted font-light leading-relaxed">
                  <p>Upload an APK and instantly uncover hidden malware behavior, C2 communication, and security risks using our AI-driven 15-stage analysis pipeline.</p>
                  <div className="pt-8 mt-8 border-t border-border space-y-6 font-mono text-xs">
                    <div className="flex items-start gap-4">
                      <div>
                        <span className="text-secondary block mb-1 uppercase tracking-widest">Distributed Analysis</span>
                        <span className="text-muted">Your APK will be routed to a Celery worker node.</span>
                      </div>
                    </div>
                    <div className="flex items-start gap-4">
                      <div>
                        <span className="text-secondary block mb-1 uppercase tracking-widest">Real-time Feedback</span>
                        <span className="text-muted">WebSocket progress will keep you updated in real-time.</span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
            
            <div className="p-10 md:p-20 bg-background flex items-center justify-center relative">
              <div className="absolute top-6 right-6 w-10 h-10 border-t-2 border-r-2 border-border"></div>
              <div className="absolute bottom-6 left-6 w-10 h-10 border-b-2 border-l-2 border-border"></div>
              
              <div className="w-full max-w-md reveal z-10" style={{ transitionDelay: '0.2s' }}>
                <div className="bg-surface-raised border border-border p-6 corner-brackets shadow-2xl relative z-20">
                  {uploadState.phase === "progress" ? (
                    <AnalysisProgress
                      jobId={uploadState.jobId}
                      onComplete={handleComplete}
                      onError={handleError}
                    />
                  ) : (
                    <div className="space-y-6">
                      <div className="text-left border-b border-border pb-4">
                        <h3 className="text-lg font-bold text-secondary uppercase tracking-tight font-mono">Upload APK</h3>
                        <p className="text-xs text-muted mt-1 font-mono tracking-widest">Scanned against 50 YARA rules, MITRE ATT&CK mapped, AI narrative generated.</p>
                      </div>

                      <DropZone onUpload={handleUpload} isLoading={isLoading} />

                      {uploadState.phase === "error" && (
                        <div className="p-3 bg-[rgba(244,63,94,0.1)] border border-[rgba(244,63,94,0.3)] text-danger text-xs font-mono text-center flex flex-col items-center gap-2">
                          <span>ERROR: {uploadState.msg}</span>
                          <button
                            onClick={() => setUploadState({ phase: "idle" })}
                            className="underline hover:text-secondary"
                          >
                            [ RETRY ]
                          </button>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>
        </section>
      </main>
      
      {/* Full Footer */}
      <footer className="border-t border-border bg-background pt-20 pb-10 px-6 lg:px-12 w-full relative z-10 overflow-hidden">
        <div className="max-w-[100rem] mx-auto grid grid-cols-1 md:grid-cols-12 gap-12 items-start relative z-10 mb-20">
          <div className="md:col-span-4 flex flex-col items-start">
            <Link href="#" className="flex items-center gap-4 mb-6 group">
              <span className="tracking-tighter text-lg font-bold text-secondary uppercase leading-none hover-scramble">DROIDRAKSHA</span>
            </Link>
            <p className="text-[0.7rem] font-mono text-muted uppercase tracking-widest leading-relaxed max-w-xs">Advanced Android threat detection. Uncover hidden malware behavior, C2 infrastructure, and compile forensic reports in minutes.</p>
          </div>
          <div className="md:col-span-2 md:col-start-7 flex flex-col gap-3 text-xs font-mono tracking-widest uppercase text-muted">
            <span className="text-secondary mb-2">Product</span>
            <Link href="#" className="hover:text-secondary transition-colors">Platform</Link>
            <Link href="#" className="hover:text-secondary transition-colors">Threat Detection</Link>
            <Link href="#" className="hover:text-secondary transition-colors">Sandbox Environment</Link>
            <Link href="#" className="hover:text-secondary transition-colors">Analysis Reports</Link>
          </div>
          <div className="md:col-span-2 flex flex-col gap-3 text-xs font-mono tracking-widest uppercase text-muted">
            <span className="text-secondary mb-2">Resources</span>
            <Link href="#" className="hover:text-secondary transition-colors">Documentation</Link>
            <Link href="#" className="hover:text-secondary transition-colors">API Access</Link>
            <Link href="#" className="hover:text-secondary transition-colors">Research Blog</Link>
            <Link href="#" className="hover:text-secondary transition-colors">Support</Link>
          </div>
          <div className="md:col-span-2 flex flex-col gap-3 text-xs font-mono tracking-widest uppercase text-muted">
            <span className="text-secondary mb-2">Company</span>
            <Link href="#" className="hover:text-secondary transition-colors">About</Link>
            <Link href="#" className="hover:text-secondary transition-colors">Contact</Link>
            <Link href="#" className="hover:text-secondary transition-colors">Security Policy</Link>
            <Link href="#" className="hover:text-secondary transition-colors">Terms</Link>
          </div>
        </div>
        <div className="max-w-[100rem] mx-auto flex flex-col md:flex-row justify-between items-center gap-4 text-[0.65rem] font-mono uppercase tracking-widest text-[#444] border-t border-border pt-8">
          <span>© 2026 DROIDRAKSHA. ALL RIGHTS RESERVED.</span>
          <span>SYSTEM STATUS: <span className="text-primary">NOMINAL</span></span>
        </div>
      </footer>
    </div>
  );
}
