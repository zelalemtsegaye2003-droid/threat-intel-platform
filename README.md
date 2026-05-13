# Threat Intelligence Platform

A modern, open-source threat intelligence platform inspired by MISP, implementing STIX 2.1 and TAXII 2.x standards with AI-powered analysis.

## Features

- **STIX 2.1 & TAXII 2.x**: Full compliance with industry standards
- **Multi-Database Architecture**: PostgreSQL (structured), Neo4j (graph), Qdrant (vectors)
- **AI-Powered Analysis**: Google Gemini (express mode, Vertex AI, or Ollama for local LLMs) for threat reports and IOC extraction
- **MITRE ATT&CK Mapping**: Automatic mapping of threats to ATT&CK framework
- **Real-time Enrichment**: VirusTotal, Shodan, AlienVault OTX integration
- **Graph Visualization**: Interactive relationship mapping with Cytoscape.js
- **JWT Authentication**: Role-based access control (admin/analyst/viewer), audit logging, rate limiting
- **Enterprise Observability**: Prometheus metrics, Grafana dashboards, Loki log aggregation, Sentry error tracking, Celery Flower task monitoring, OpenTelemetry distributed tracing
- **TLS/HTTPS**: Nginx reverse proxy with TLS termination (Let's Encrypt or self-signed)
- **Database Migrations**: Alembic-managed schema versioning
- **Modern Frontend**: React + TypeScript + Tailwind CSS with auth UI (login/register)

## Quick Start

```bash
# 1. Clone/enter project
cd path/to/threat-intel-platform

# 2. Copy environment file (optional - defaults work)
cp .env.example .env

# 3. Generate self-signed TLS certificate (or configure Let's Encrypt)
chmod +x scripts/generate-self-signed-cert.sh
./scripts/generate-self-signed-cert.sh

# 4. Start all services
./start.sh

# 5. Run database migrations
python -m scripts.manage_db upgrade head

# 6. Access the platform
# Frontend:    https://localhost
# API Docs:    http://localhost:8000/docs
# Grafana:     http://localhost:3001  (admin/admin123)
# Prometheus:  http://localhost:9090
# Flower:      http://localhost:5555  (Celery task monitor)
# Loki logs:   http://localhost:3100
```

## Architecture

```
                        ┌─────────────────────────┐
                        │       Internet          │
                        └────────────┬────────────┘
                                     │
                        ┌────────────▼────────────┐
                        │      Nginx (TLS)        │
                        │  :80 → :443 redirect     │
                        │  Rate limiting, headers  │
                        └──────┬───────┬──────────┘
                               │       │
              ┌────────────────▼─┐  ┌──▼────────────────┐
              │   Frontend       │  │   API Gateway      │
              │   (React :3000)  │  │   (FastAPI :8000)  │
              │   via nginx      │  │   /api/v1/*        │
              └──────────────────┘  │                    │
                                    │  /metrics (Prom.)  │
                                    │  /health           │
                                    │  /health/deep      │
                                    └──┬────┬────┬───────┘
                                       │    │    │
               ┌───────────┐  ┌───────▼┐  ┌▼──────────┐  ┌───────┐
               │ PostgreSQL│  │ Neo4j  │  │  Qdrant   │  │ Redis │
               │   :5432   │  │ :7474  │  │   :6333   │  │ :6339 │
               └───────────┘  └────────┘  └───────────┘  └───────┘
                                       │
                               ┌───────▼───────┐
                               │   RabbitMQ     │
                               │   :5672        │
                               └───────┬───────┘
                                       │
                    ┌──────────────────▼──────────────────┐
                    │          Celery Workers              │
                    │  ┌─────────┐  ┌─────────┐  ┌──────┐│
                    │  │Ingestion│  │Enrichment│  │Metrics││
                    │  └─────────┘  └─────────┘  └──────┘│
                    └──────────────────┬──────────────────┘
                                       │
                               ┌───────▼───────┐
                               │    Ollama      │
                               │   :11434       │
                               └────────────────┘

  ┌─────────────┐  ┌──────────┐  ┌──────────┐  ┌─────────────┐
  │  Prometheus │  │ Grafana  │  │   Loki   │  │   Flower    │
  │    :9090    │  │   :3001  │  │  :3100   │  │    :5555    │
  └─────────────┘  └──────────┘  └──────────┘  └─────────────┘
       │                 │              │             │
       └─────────────────┴──────────────┴─────────────┘
                    Observability Stack
```

## Observability

| Service | Port | Purpose |
|---------|------|---------|
| Prometheus | 9090 | Metrics scraping & storage |
| Grafana | 3001 | Dashboards & visualization |
| Loki | 3100 | Log aggregation (JSON structured logs) |
| Flower | 5555 | Celery task monitoring |
| Promtail | (sidecar) | Log collection for Loki |

### Metrics Endpoints
- `GET /metrics` — Prometheus metrics (request count, latency, errors, LLM usage, IOC counts, feed ingestion, Celery tasks)
- `GET /health` — Quick health check
- `GET /health/deep` — Deep health check (Postgres, Neo4j, Qdrant, Redis, RabbitMQ)

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `GEMINI_API_KEY` | Google Gemini API key | — |
| `GEMINI_MODEL` | Gemini model | `gemini-2.5-flash` |
| `GOOGLE_CLOUD_PROJECT` | GCP project for Vertex AI | — |
| `USE_VERTEX_AI` | Use Vertex AI instead of express | `false` |
| `VIRUSTOTAL_API_KEY` | VirusTotal API key | — |
| `SHODAN_API_KEY` | Shodan API key | — |
| `OTX_API_KEY` | AlienVault OTX API key | — |
| `DB_PASSWORD` | PostgreSQL password | `secure_password` |
| `NEO4J_PASSWORD` | Neo4j password | `secure_password` |
| `RABBITMQ_PASSWORD` | RabbitMQ password | `secure_password` |
| `JWT_SECRET` | JWT signing key (min 32 chars) | `your_jwt_secret_here` |
| `SECRET_KEY` | App secret key | `your-secret-key` |
| `SENTRY_DSN` | Sentry error tracking DSN | — |
| `SENTRY_TRACES_SAMPLE_RATE` | Sentry trace sampling | `1.0` |
| `OTLP_EXPORT_ENDPOINT` | OpenTelemetry export endpoint | — |
| `ENVIRONMENT` | `development` / `production` | `development` |
| `TLS_TERMINATED_UPSTREAM` | Set `true` when behind TLS proxy | `false` |

## Project Structure

```
threat-intel-platform/
├── backend/
│   ├── app/
│   │   ├── api/v1/endpoints/  # API routes (IOCs, Actors, Feeds, etc.)
│   │   ├── models/             # Pydantic/STIX models
│   │   ├── services/           # Business logic (enrichment, LLM, ATT&CK)
│   │   ├── workers/            # Celery background tasks
│   │   ├── db/                 # Database connections (PG, Neo4j, Qdrant, Redis)
│   │   ├── auth.py             # JWT auth, RBAC, audit logging
│   │   ├── main.py             # FastAPI app with middleware & monitoring
│   │   ├── config.py           # Pydantic settings
│   │   ├── logging_config.py   # Structured JSON logging (structlog)
│   │   ├── metrics.py          # Prometheus metrics definitions
│   │   ├── sentry_config.py    # Sentry error tracking
│   │   ├── tracing.py          # OpenTelemetry distributed tracing
│   │   ├── health.py           # Deep health check endpoints
│   │   └── middleware.py       # Rate limiting, security headers
│   ├── alembic.ini             # Alembic config
│   ├── migrations/             # Database migration scripts
│   ├── scripts/
│   │   ├── manage_db.py        # Database migration CLI
│   │   └── test_services.sh    # Integration test script
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── context/            # Auth context provider
│   │   ├── components/         # Reusable UI components
│   │   ├── pages/              # Pages (incl. Login, Register)
│   │   └── services/           # API client (axios)
│   └── package.json
├── nginx/
│   ├── nginx.conf              # Production-ready nginx config
│   └── docker-compose-snippet.yml
├── prometheus/
│   ├── prometheus.yml          # Scrape configs
│   └── rules/
│       └── alerts.yml          # Alerting rules
├── grafana/
│   ├── provisioning/
│   │   ├── datasources.yml     # Prometheus/Loki datasources
│   │   └── dashboards/        # Dashboard provisioning
│   └── dashboards/
│       └── threat-intel-dashboard.json
├── promtail/
│   └── config.yml              # Loki log collection
├── scripts/
│   └── generate-self-signed-cert.sh
├── docker-compose.yml          # Full stack orchestration
├── start.sh                    # Quick start script
├── .env.example                # Environment variables template
├── SECURITY_HARDENING.md       # Security implementation details
└── README.md
```

## API Endpoints

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/` | GET | — | API info & endpoint list |
| `/health` | GET | — | Quick health check |
| `/health/deep` | GET | — | Deep health check (all databases) |
| `/metrics` | GET | — | Prometheus metrics |
| `/api/v1/login` | POST | — | Login → JWT token |
| `/api/v1/register` | POST | — | Register new user |
| `/api/v1/auth/me` | GET | ✓ | Current user info |
| `/api/v1/auth/users` | GET | admin | List all users |
| `/api/v1/auth/audit-logs` | GET | admin | Audit log history |
| `/api/v1/iocs` | GET | viewer | List IOCs (paginated) |
| `/api/v1/iocs` | POST | analyst | Create IOC |
| `/api/v1/iocs/{id}` | GET | viewer | Get IOC details |
| `/api/v1/iocs/{id}` | PUT | analyst | Update IOC |
| `/api/v1/iocs/{id}` | DELETE | analyst | Delete IOC |
| `/api/v1/iocs/bulk` | POST | analyst | Bulk create IOCs |
| `/api/v1/actors` | GET | viewer | List threat actors (paginated) |
| `/api/v1/malware` | GET | viewer | List malware (paginated) |
| `/api/v1/campaigns` | GET | viewer | List campaigns (paginated) |
| `/api/v1/feeds` | GET | viewer | Feed status |
| `/api/v1/feeds/register` | POST | analyst | Register feed |
| `/api/v1/feeds/ingest` | POST | analyst | Trigger feed ingestion |
| `/api/v1/search/text` | POST | analyst | Text search |
| `/api/v1/search/semantic` | POST | analyst | Vector semantic search |
| `/api/v1/analysis/analyze-text` | POST | analyst | LLM threat analysis |
| `/api/v1/analysis/map-attack` | POST | analyst | MITRE ATT&CK mapping |
| `/api/v1/stix/*` | GET/POST | analyst | STIX 2.1 import/export |
| `/api/v1/taxii/*` | GET/POST | analyst | TAXII 2.x server |

## Testing

```bash
# Bash integration tests (checks all endpoints)
chmod +x scripts/test_services.sh
./scripts/test_services.sh

# Or manually:
curl http://localhost:8000/health
curl http://localhost:8000/metrics | head -20
curl http://localhost:8000/health/deep | python -m json.tool
```

## Development

```bash
# Backend (with hot-reload)
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000

# Celery workers (separate terminal)
celery -A app.workers.celery_app worker --loglevel=info
celery -A app.workers.celery_app beat --loglevel=info

# Frontend (separate terminal)
cd frontend
npm install
npm run dev

# Database migrations
python -m scripts.manage_db upgrade head
python -m scripts.manage_db history
```

## License

MIT License - Free for personal and commercial use.

## Acknowledgments

- MISP Project (inspiration)
- STIX/TAXII Working Groups
- MITRE ATT&CK Framework
- Google Gemini / Ollama for LLM hosting
- Grafana, Prometheus, Loki for observability