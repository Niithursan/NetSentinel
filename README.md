# 🛡️ NetSentinel

**Automated Network Vulnerability & Compliance Scanner**

NetSentinel is a full-stack security tool that combines custom packet crafting with AI-driven analysis to discover hosts, fingerprint services, and generate actionable remediation advisories.

![Dashboard Preview](docs/dashboard-preview.png)

## ✨ Features

- **ARP Host Discovery** — Layer 2 network scanning with Scapy
- **TCP SYN Port Scanning** — Half-open stealth scanning for open services
- **UDP Scanning** — Detect commonly open UDP services
- **Service Fingerprinting** — Banner grabbing and version detection
- **OS Fingerprinting** — TTL-based operating system identification
- **AI Vulnerability Analysis** — Gemini-powered threat identification
- **AI Remediation Advisories** — Plain-English fix recommendations
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
| **Deployment** | Docker, Docker Compose |

## 🚀 Quick Start

### Prerequisites

- Python 3.11+
- Node.js 20+
- Docker (optional, recommended)

### 1. Clone & Configure

```bash
git clone https://github.com/yourusername/NetSentinel.git
cd NetSentinel
cp .env.example .env
# Edit .env and add your GEMINI_API_KEY
```

### 2. Backend Setup

```bash
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

### 3. Frontend Setup

```bash
cd frontend
npm install
npm run dev
```

### 4. Docker (Alternative)

```bash
docker compose up --build
```

> ⚠️ **Note:** Network scanning requires root/admin privileges. When using Docker, the container runs with `CAP_NET_RAW` for Scapy access.

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
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/
│   ├── src/
│   │   ├── components/          # React components
│   │   ├── api.ts               # API client
│   │   ├── App.tsx              # Root component
│   │   └── index.css            # Design system
│   ├── package.json
│   └── Dockerfile
├── docker-compose.yml
├── .env.example
└── README.md
```

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.
