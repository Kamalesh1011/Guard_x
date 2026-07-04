# GUARDIAN

**Offline Explainable Behavioral Threat Detection Using Isolation Forest and SHAP Attribution**

A Windows desktop security dashboard that runs as a background Python service + React UI. It watches your system continuously, detects threats using Isolation Forest (anomaly detection) + a rule engine, and explains every alert in plain English using SHAP feature contributions.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                   GUARDIAN Architecture               │
├─────────────────────────────────────────────────────┤
│                                                       │
│  Layer 1: DATA COLLECTION (Python watchers)          │
│  ├── Process Watcher (7 features)                    │
│  ├── Network Watcher (5 features)                    │
│  ├── Hardware Watcher (4 features)                   │
│  ├── Filesystem Watcher (4 features)                 │
│  └── Idle Watcher (4 features)                       │
│                                                       │
│  Layer 2: DETECTION ENGINE                           │
│  ├── Isolation Forest (per pillar)                   │
│  ├── Rule Engine (JSON rules)                        │
│  └── Threat Classifier                               │
│                                                       │
│  Layer 3: XAI ENGINE                                 │
│  ├── SHAP TreeExplainer                              │
│  └── Template Engine → English sentences             │
│                                                       │
│  Layer 4: API + UI                                   │
│  ├── FastAPI + WebSocket                             │
│  └── React Dashboard (5 pages)                       │
│                                                       │
└─────────────────────────────────────────────────────┘
```

## Features

- **5 Watchers**: Process, Network, Hardware (Camera/Mic), Filesystem, Idle state
- **24 Behavioral Features**: Comprehensive feature set for anomaly detection
- **Isolation Forest**: Unsupervised anomaly detection per watcher pillar
- **SHAP Explainability**: Every alert comes with feature contribution scores
- **Rule Engine**: Editable JSON rules for known threat patterns
- **Voice Alerts**: Jarvis-style TTS notifications (pyttsx3 + SAPI5)
- **Real-time Dashboard**: React UI with WebSocket live updates
- **System Tray**: Background monitoring with tray icon

## Quick Start

### Prerequisites

- Windows 10/11
- Python 3.11+
- Node.js 18+

### Backend Setup

```bash
cd guardian/agent
pip install -r requirements.txt
python main.py
```

### Frontend Setup

```bash
cd guardian/frontend
npm install
npm run dev
```

Dashboard opens at: `http://localhost:5173`

### Build Executable

```bash
cd guardian/scripts
build.bat
```

Output: `dist/Guardian.exe`

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | /api/status | System status + threat level |
| GET | /api/alerts | Paginated alert history |
| GET | /api/alerts/{id} | Single alert with SHAP breakdown |
| GET | /api/hardware | Camera/mic status |
| GET | /api/processes | Live process tree |
| GET | /api/network | Active connections |
| GET | /api/settings | Current configuration |
| POST | /api/settings | Update settings |
| POST | /api/actions/whitelist | Add to whitelist |
| POST | /api/actions/kill | Kill process |
| GET | /api/export/csv | Export alerts as CSV |
| WS | /ws/events | Real-time event stream |

## Configuration

All settings are stored in SQLite and configurable via the dashboard:

- **Poll Interval**: Seconds between system scans (default: 3)
- **Sensitivity**: Isolation Forest contamination threshold (default: 0.05)
- **Watcher Toggles**: Enable/disable individual watchers
- **Whitelist**: Trusted processes to ignore

## Database

SQLite with WAL mode for concurrent access:

- `alerts`: Alert history with SHAP values
- `whitelist`: Trusted process names
- `telemetry`: Historical feature vectors
- `baseline`: Serialized Isolation Forest models
- `settings`: Runtime configuration

## Research Contributions

1. **Offline SHAP-explained Isolation Forest** for live endpoint behavioral security monitoring
2. **Idle-state behavioral fingerprinting** using EWMA baseline
3. **Unified 5-pillar feature ontology** (24 features across process, network, hardware, filesystem, idle)

## License

MIT
