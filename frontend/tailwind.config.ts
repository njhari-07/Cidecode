import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        background: "var(--background)",
        foreground: "var(--text-secondary)",
        surface: "var(--surface)",
        "surface-raised": "var(--surface-raised)",
        border: "var(--border)",
        "border-active": "var(--border-active)",
        primary: "var(--text-primary)",
        secondary: "var(--text-secondary)",
        muted: "var(--text-muted)",
        warning: "var(--text-warning)",
        danger: "var(--text-danger)",
        "accent-primary": "var(--accent-primary)",
        "accent-secondary": "var(--accent-secondary)",
        "accent-warning": "var(--accent-warning)",
        cyber: {
          blue: "var(--accent-primary)",
          dark1: "var(--surface)",
          dark2: "var(--background)",
          dark3: "var(--surface-raised)",
          border: "var(--border)",
          border2: "var(--border-active)",
          textMuted: "var(--text-muted)",
          textLight: "var(--text-secondary)",
          textLighter: "var(--text-primary)",
        }
      },
      fontFamily: {
        sans: ["var(--font-mono)"],
        mono: ["var(--font-mono)"],
      },
      animation: {
        'marquee': 'marquee 30s linear infinite',
        'fade-in': 'fadeIn 1s ease-out forwards',
        'spin-slow': 'spin 30s linear infinite',
        'spin-slow-reverse': 'spin 30s linear infinite reverse',
        'flicker': 'flicker 8s infinite',
        'blink-cursor': 'blink-cursor 1s infinite',
        'glitch': 'glitch 0.3s ease-in-out',
        'scanline-move': 'scanline-move 8s linear infinite',
        'pulse-glow': 'pulse-glow 2s ease-in-out infinite',
        'data-scroll': 'data-scroll 20s linear infinite',
      },
      keyframes: {
        marquee: {
          '0%': { transform: 'translateX(0)' },
          '100%': { transform: 'translateX(-50%)' },
        },
        fadeIn: {
          '0%': { opacity: '0', transform: 'translateY(10px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        flicker: {
          '0%, 89%, 91%, 93%, 100%': { opacity: '1' },
          '90%': { opacity: '0.4' },
          '92%': { opacity: '0.8' },
          '94%': { opacity: '0.6' },
        },
        'blink-cursor': {
          '0%, 49%': { opacity: '1' },
          '50%, 100%': { opacity: '0' },
        },
        glitch: {
          '0%, 100%': { transform: 'translate(0)' },
          '10%': { transform: 'translate(-2px, 1px)' },
          '20%': { transform: 'translate(2px, -1px)' },
          '30%': { transform: 'translate(-1px, 2px)' },
          '40%': { transform: 'translate(1px, -1px)' },
          '50%': { transform: 'translate(0)' },
        },
        'scanline-move': {
          '0%': { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(100vh)' },
        },
        'pulse-glow': {
          '0%, 100%': { opacity: '0.6' },
          '50%': { opacity: '1' },
        },
        'data-scroll': {
          '0%': { transform: 'translateY(0)' },
          '100%': { transform: 'translateY(-50%)' },
        }
      }
    },
  },
  plugins: [],
};
export default config;
