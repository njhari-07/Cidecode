import type { Metadata } from "next";
import { IBM_Plex_Mono, Space_Mono } from "next/font/google";
import "./globals.css";

const ibm_plex_mono = IBM_Plex_Mono({
  weight: ['400', '500', '600', '700'],
  subsets: ["latin"],
  variable: "--font-mono",
  display: "swap",
});

const space_mono = Space_Mono({
  weight: ['400', '700'],
  subsets: ["latin"],
  variable: "--font-space-mono",
  display: "swap",
});

export const metadata: Metadata = {
  title: "DroidRaksha — India's APK Threat Intelligence Platform",
  description:
    "AI-powered Android APK security analysis platform for detecting malware, banking trojans, UPI fraud apps, and India-specific mobile threats.",
  keywords: [
    "APK analysis",
    "Android malware",
    "India cybersecurity",
    "UPI fraud",
    "mobile threat intelligence",
    "DroidRaksha",
  ],
  openGraph: {
    title: "DroidRaksha — APK Threat Intelligence",
    description: "Scan Android APKs for malware, banking trojans & India-specific mobile threats.",
    type: "website",
  },
};

import Aurora from "@/components/Aurora";

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className={`${ibm_plex_mono.variable} ${space_mono.variable} dark`}>
      <body className="min-h-screen bg-black text-secondary antialiased font-mono overflow-x-hidden">
        <div className="fixed inset-0 w-full h-full z-0">
          <Aurora colorStops={["#475569", "#64748b", "#475569"]} amplitude={1.2} blend={0.6} speed={0.8} />
        </div>
        <div className="relative z-10">
          {children}
        </div>
      </body>
    </html>
  );
}
