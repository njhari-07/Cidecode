# 🛡️ DroidRaksha — Android APK Threat Intelligence Platform

> India's AI-powered APK static analysis & malware detection engine.  
> Built for security researchers, SOC teams, and hackathon glory. 🇮🇳

---

## 🚀 What is DroidRaksha?

**DroidRaksha** (Sanskrit: *Droid Guardian*) is a full-stack threat intelligence platform that:

- 📦 **Decompiles & analyzes** Android APKs in seconds
- 🧬 **Detects malware families** — BankingTrojans, Ransomware, Spyware, RATs, Droppers & more
- 🔎 **Runs YARA rules**, certificate checks, string extraction, and obfuscation detection
- 🌐 **Cross-checks threat intel** via VirusTotal, AbuseIPDB, OTX, and India IOC feeds
- 🤖 **ML-powered classification** using XGBoost, MalBERT, and anomaly detection
- 🗺️ **MITRE ATT&CK mapping** for tactical context
- 📊 **Beautiful dashboard** with real-time scan telemetry

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   Next.js 14 Frontend                   │
│  Landing · Dashboard · Results · Report Export          │
└───────────────────────┬─────────────────────────────────┘
                        │  REST / WebSocket
┌───────────────────────▼─────────────────────────────────┐
│               FastAPI Backend (Python 3.11)              │
│                                                         │
│  ┌────────────┐  ┌──────────────┐  ┌────────────────┐  │
│  │  Engines   │  │   Intel      │  │   AI / ML      │  │
│  │ ─ Manifest │  │ ─ VirusTotal │  │ ─ XGBoost      │  │
│  │ ─ YARA     │  │ ─ AbuseIPDB  │  │ ─ MalBERT      │  │
│  │ ─ Strings  │  │ ─ OTX        │  │ ─ LangChain    │  │
│  │ ─ Certs    │  │ ─ India IOC  │  │ ─ MITRE ATT&CK │  │
│  │ ─ Obfusc.  │  └──────────────┘  └────────────────┘  │
│  └────────────┘                                         │
│                                                         │
│  Database: PostgreSQL (Supabase) + Elasticsearch        │
└─────────────────────────────────────────────────────────┘
```

---

## ⚡ Quick Start

### Prerequisites

| Tool | Version |
|------|---------|
| Node.js | ≥ 18 |
| Python | ≥ 3.11 |
| Docker | ≥ 24 (optional) |

### 1. Clone

```bash
git clone https://github.com/njhari-07/Cidecode.git
cd Cidecode
```

### 2. Backend

```bash
# Create & activate virtualenv
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Copy env and fill in your keys
cp .env.example .env

# Run
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```

### 3. Frontend

```bash
cd frontend

# Copy env
cp .env.example .env.local

# Install & run
npm install
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) 🎉

### 4. Docker (Full Stack)

```bash
docker compose up --build
```

---

## 🔑 Environment Variables

### Backend (`.env`)

| Variable | Description | Required |
|----------|-------------|----------|
| `DATABASE_URL` | PostgreSQL connection string | ✅ |
| `VIRUSTOTAL_API_KEY` | VirusTotal API key | ✅ |
| `ABUSEIPDB_API_KEY` | AbuseIPDB API key | ✅ |
| `OTX_API_KEY` | AlienVault OTX key | ✅ |
| `OPENAI_API_KEY` | OpenAI for LangChain agent | ✅ |
| `MOBSF_API_KEY` | MobSF instance key | Optional |
| `ELASTICSEARCH_URL` | Bonsai/ES endpoint | Optional |
| `FRONTEND_URL` | Allowed CORS origin | ✅ |

### Frontend (`.env.local`)

| Variable | Description |
|----------|-------------|
| `NEXT_PUBLIC_API_URL` | Backend API base URL (default: `http://localhost:8000`) |

---

## 📁 Project Structure

```
Cidecode/
├── frontend/               # Next.js 14 App Router
│   ├── app/
│   │   ├── page.tsx        # Landing / Upload page
│   │   ├── dashboard/      # SOC dashboard
│   │   ├── results/[id]/   # Analysis report
│   │   └── report/[hash]/  # PDF report viewer
│   ├── components/         # Reusable UI components
│   └── lib/                # API client & types
│
├── backend/                # FastAPI application
│   ├── engines/            # Analysis engines
│   │   ├── static_analyzer.py   # Main orchestrator
│   │   ├── manifest_parser.py
│   │   ├── yara_scanner.py
│   │   ├── string_extractor.py
│   │   ├── cert_analyzer.py
│   │   └── obfuscation.py
│   ├── intel/              # Threat intel integrations
│   ├── ai/                 # ML classifiers & LangChain agent
│   ├── scoring/            # Risk scoring engine
│   ├── routes/             # FastAPI routers
│   ├── models/             # Pydantic schemas
│   └── db/                 # Database & Elasticsearch
│
├── requirements.txt
├── docker-compose.yml
└── README.md
```

---

## 🧪 API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/upload` | Upload APK for analysis |
| `GET` | `/api/analysis/{id}` | Get analysis result |
| `GET` | `/api/stats` | Dashboard statistics |
| `GET` | `/api/report/{id}` | Generate PDF report |
| `GET` | `/api/export/{id}` | Export as JSON/STIX |
| `GET` | `/api/search?q=` | Global search |
| `WS`  | `/api/ws/{job_id}` | Real-time progress |
| `GET` | `/health` | Health check |

Interactive docs: [http://localhost:8000/docs](http://localhost:8000/docs)

---

## 🎯 Detection Capabilities

| Engine | What it detects |
|--------|----------------|
| **Manifest Parser** | Dangerous permissions, exported components, debug flags |
| **YARA Scanner** | Malware signatures (50+ rules) |
| **String Extractor** | Hardcoded IPs, URLs, secrets, crypto keys |
| **Certificate Analyzer** | Self-signed certs, expired keys, weak algorithms |
| **Obfuscation Detector** | Class name entropy, string obfuscation ratio |
| **India IOC** | India-specific threat indicators |
| **XGBoost Classifier** | Malware family classification (9 families) |
| **MalBERT** | Transformer-based malicious code detection |
| **Anomaly Detector** | Isolation Forest for zero-day-like behavior |
| **LangChain Agent** | AI court-style forensic narrative |

---

## 🤝 Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for dev setup and guidelines.

---

## 📜 License

MIT © DroidRaksha Team — Built with ❤️ for India's cybersecurity ecosystem.
