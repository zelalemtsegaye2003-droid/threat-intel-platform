# Threat Intelligence Platform

A modern, open-source threat intelligence platform inspired by MISP, implementing STIX 2.1 and TAXII 2.x standards with AI-powered analysis.

## Features

- **STIX 2.1 & TAXII 2.x**: Full compliance with industry standards
- **Multi-Database Architecture**: PostgreSQL (structured), Neo4j (graph), Qdrant (vectors)
- **AI-Powered Analysis**: Local LLM via Ollama for threat reports and IOC extraction
- **MITRE ATT&CK Mapping**: Automatic mapping of threats to ATT&CK framework
- **Real-time Enrichment**: VirusTotal, Shodan, AlienVault OTX integration
- **Graph Visualization**: Interactive relationship mapping with Cytoscape.js
- **Modern Frontend**: React + TypeScript + Tailwind CSS

## Quick Start

```bash
# 1. Clone/enter project
cd /home/zelalem/projects/threat-intel-platform

# 2. Copy environment file (optional - defaults work)
cp .env.example .env

# 3. Start all services
./start.sh

# 4. Access the platform
# Frontend: http://localhost:3000
# API Docs: http://localhost:8000/docs
```

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Frontend (React)                     │
│              React + TypeScript + Tailwind              │
└───────────────────────┬─────────────────────────────────┘
                        │
┌───────────────────────▼─────────────────────────────────┐
│              Backend API (FastAPI)                      │
│         STIX/TAXII + LLM + Enrichment                  │
└─────┬──────────┬──────────┬──────────┬─────────────────┘
      │          │          │          │
┌─────▼──┐ ┌────▼───┐ ┌───▼────┐ ┌──▼─────┐
│Postgres│ │ Neo4j  │ │ Qdrant │ │ Redis  │
│ (SQL)  │ │(Graph) │ │(Vector)│ │(Cache) │
└────────┘ └────────┘ └────────┘ └────────┘
      │          │          │          │
      └──────────┴──────────┴──────────┘
                    │
            ┌───────▼────────┐
            │  RabbitMQ      │
            │ (Celery Tasks) │
            └───────┬────────┘
                    │
            ┌───────▼────────┐
            │  Ollama (LLM)  │
            │ Llama 3.2/Phi-4│
            └────────────────┘
```

## Project Structure

```
threat-intel-platform/
├── backend/
│   ├── app/
│   │   ├── api/v1/endpoints/  # API routes (IOCs, Actors, Feeds, etc.)
│   │   ├── models/             # Pydantic/STIX models
│   │   ├── services/           # Business logic (enrichment, LLM, ATT&CK)
│   │   ├── workers/            # Celery background tasks
│   │   └── db/                 # Database connections
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── components/         # Reusable UI components
│   │   ├── pages/              # Dashboard, IOCs, Graph, Reports
│   │   └── services/           # API client
│   └── package.json
├── docker-compose.yml          # Full stack orchestration
├── start.sh                    # Quick start script
└── README.md
```

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `/api/v1/iocs` | Indicators of Compromise CRUD |
| `/api/v1/actors` | Threat Actor management |
| `/api/v1/malware` | Malware samples |
| `/api/v1/campaigns` | Campaign tracking |
| `/api/v1/feeds` | Threat feed management |
| `/api/v1/search` | Text & semantic search |
| `/api/v1/analysis` | LLM analysis & reports |
| `/api/v1/taxii/*` | TAXII 2.x server |
| `/api/v1/stix/*` | STIX 2.1 import/export |

## Services

| Service | Port | Purpose |
|---------|------|---------|
| Frontend | 3000 | React UI |
| API | 8000 | FastAPI backend |
| PostgreSQL | 5432 | Structured data |
| Neo4j | 7474/7687 | Graph relationships |
| Qdrant | 6333/6334 | Vector embeddings |
| Redis | 6379 | Caching |
| RabbitMQ | 5672/15672 | Task queue |
| Ollama | 11434 | Local LLM |

## Development

```bash
# Backend
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload

# Frontend
cd frontend
npm install
npm run dev

# Workers
cd backend
celery -A app.workers.celery_app worker --loglevel=info
```

## Testing

```bash
# Test all services
python scripts/test_services.py

# Test API
curl http://localhost:8000/health

# Test frontend
curl http://localhost:3000
```

## License

MIT License - Free for personal and commercial use.

## Acknowledgments

- MISP Project (inspiration)
- STIX/TAXII Working Groups
- MITRE ATT&CK Framework
- Ollama for local LLM hosting
