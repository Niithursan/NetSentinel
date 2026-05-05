# 🛡️ NetSentinel

**Automated Network Vulnerability & Compliance Scanner**

NetSentinel is a full-stack security tool that combines custom packet crafting with AI-driven analysis to discover hosts, fingerprint services, and generate actionable remediation advisories.

## ✨ Features

- **ARP Host Discovery** — Layer 2 network scanning with Scapy
- **TCP SYN Port Scanning** — Half-open stealth scanning for open services
- **UDP Scanning** — Detect commonly open UDP services
- **Service Fingerprinting** — Banner grabbing and version detection
- **OS Fingerprinting** — TTL-based operating system identification
- **AI Vulnerability Analysis** — Gemini-powered threat identification
- **Rich AI Remediation Advisories** — Markdown-formatted, plain-English fix recommendations and specific commands
- **Golden Baseline Compliance** — Check against security configuration standards
- **Real-time Dashboard** — Visualize network topology and vulnerability status

## 🏗️ Tech Stack

| Layer | Technology |
|-------|-----------|
| **Backend** | Python, FastAPI, Scapy |
| **Database** | SQLite (async via SQLAlchemy) |
| **AI** | Google Gemini API |
| **Frontend** | React, TypeScript, Vite |
| **Charts** | Recharts |

## 🚀 Quick Start

### Prerequisites

- Python 3.11+
- Node.js 20+
- Administrator Privileges (required for Scapy network scanning)

### 1. Clone & Configure

```bash
git clone https://github.com/yourusername/NetSentinel.git
cd NetSentinel
cp .env.example .env
# Edit .env and add your GEMINI_API_KEY
```

### 2. Start Application (Windows)

We provide a convenient startup script for Windows users that handles dependencies and launches both the backend and frontend simultaneously.

```cmd
start.bat
```

> ⚠️ **Note:** The script will automatically install backend requirements, start the FastAPI server on port 8000, run npm install, and start the React frontend. Please ensure you run this from an Administrator terminal so Scapy can craft raw packets.

### 3. Start Application (Manual/Linux/macOS)

**Terminal 1 (Backend):**
```bash
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
# Must be run as root/admin for raw sockets
sudo uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

**Terminal 2 (Frontend):**
```bash
cd frontend
npm install
npm run dev
```

## 📡 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/scans` | Launch a new scan |
| `GET` | `/api/scans` | List all scans |
| `GET` | `/api/scans/{id}` | Get scan details with hosts/ports/vulns |
| `DELETE` | `/api/scans/{id}` | Delete a scan |
| `POST` | `/api/remediation` | Get AI remediation for findings |
| `GET` | `/api/baselines` | List compliance baselines |
| `POST` | `/api/baselines` | Create a new baseline |
| `POST` | `/api/compliance/check` | Check scan against baseline |
| `GET` | `/api/dashboard/stats` | Dashboard statistics |
| `GET` | `/health` | Health check |

## 📁 Project Structure

```
NetSentinel/
├── backend/
│   ├── app/
│   │   ├── api/routes.py        # FastAPI endpoints
│   │   ├── core/
│   │   │   ├── config.py        # Environment configuration
│   │   │   └── gemini.py        # AI integration
│   │   ├── models/
│   │   │   ├── database.py      # SQLAlchemy async setup
│   │   │   └── schemas.py       # ORM models & Pydantic schemas
│   │   ├── scanner/
│   │   │   └── engine.py        # Scapy scanning engine
│   │   └── main.py              # FastAPI app entry point
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── components/          # React components
│   │   ├── api.ts               # API client
│   │   ├── App.tsx              # Root component
│   │   └── index.css            # Design system
│   └── package.json
├── start.bat                    # Windows startup script
├── .env.example
└── README.md
```

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.
