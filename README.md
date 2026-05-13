# Threat Intelligence Platform

A modern, open-source threat intelligence platform inspired by MISP, implementing STIX 2.1 and TAXII 2.x standards with AI-powered analysis, multi-factor authentication, and enterprise observability.

---

## Features

- **STIX 2.1 & TAXII 2.x**: Full compliance with industry standards for threat intelligence sharing
- **Multi-Database Architecture**: PostgreSQL (structured data), Neo4j (graph relationships), Qdrant (vector similarity search)
- **AI-Powered Analysis**: Google Gemini (express mode, Vertex AI, or Ollama for local LLMs) for threat reports, IOC extraction, and MITRE ATT&CK mapping
- **Multi-Factor Authentication (MFA)**: TOTP-based 2FA with authenticator app support, recovery codes, and Google OAuth2 sign-in
- **Role-Based Access Control (RBAC)**: Admin / Analyst / Viewer roles enforced at every endpoint
- **Real-time Enrichment**: VirusTotal, Shodan, AlienVault OTX integration
- **Graph Visualization**: Interactive relationship mapping with Cytoscape.js
- **Audit Logging**: Every privileged action logged with username, action, resource, IP, and timestamp
- **Enterprise Observability**: Prometheus metrics, Grafana dashboards, Loki log aggregation, Sentry error tracking, Celery Flower task monitoring, OpenTelemetry distributed tracing
- **TLS/HTTPS**: Nginx reverse proxy with TLS termination (Let's Encrypt or self-signed)
- **Database Migrations**: Alembic-managed schema versioning with rollback capability
- **Modern Frontend**: React + TypeScript + Tailwind CSS with auth UI (login, register, MFA, settings)

---

## Table of Contents

- [Quick Start](#quick-start)
- [Architecture](#architecture)
- [Authentication & MFA](#authentication--mfa)
- [API Reference](#api-reference)
- [Observability](#observability)
- [Environment Variables](#environment-variables)
- [Project Structure](#project-structure)
- [Development](#development)
- [Database Migrations](#database-migrations)
- [Google OAuth2 Setup](#google-oauth2-setup)
- [Testing](#testing)
- [Security & Compliance](#security--compliance)
- [License](#license)

---

## Quick Start

```bash
# 1. Clone/enter project
cd path/to/threat-intel-platform

# 2. Create environment file
cp .env.example .env
# Edit .env — replace all placeholder passwords with real secrets!

# 3. Generate self-signed TLS certificate (or configure Let's Encrypt)
chmod +x scripts/generate-self-signed-cert.sh
./scripts/generate-self-signed-cert.sh

# 4. Start all services via Docker Compose
docker-compose up -d

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

**Create initial admin user** (after first migration):
```bash
# Register via API
curl -X POST https://localhost/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","email":"admin@example.com","password":"YourSecurePassword123","role":"admin"}' \
  --insecure

# Or register via the frontend at /register
```

---

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
                                     │  /metrics          │
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

---

## Authentication & MFA

### Login Flow

```
1. POST /auth/login {username, password}
   ├─ Success (no 2FA):     → 200 {access_token, token_type}
   └─ Success (2FA enabled): → 403 {detail: "Multi-factor authentication required"}
                              Header: WWW-Authenticate: Bearer pre_auth_token="<token>"

2. POST /auth/totp/verify {token: "123456"}
   Authorization: Bearer <pre_auth_token>
   ├─ Success: → 200 {access_token, token_type, mfa_verified: true}
   └─ Failure: → 401 {detail: "Invalid TOTP token"}

3. Use returned access_token for all subsequent API calls
   Authorization: Bearer <session_token>
```

### Sign in with Google

```
1. Frontend uses Google Identity Services to get a Google ID token
2. POST /auth/google {credential: "<google_id_token>"}
3. Backend verifies token, creates/finds user, returns JWT
   Note: Google-authenticated users bypass TOTP 2FA
```

### TOTP Enrollment (2FA Setup)

```
1. POST /auth/totp/enable {password: "current_password"}
   → 201 {secret, provisioning_uri, recovery_codes}

2. Display provisioning_uri as QR code (use any authenticator app)
   - Google Authenticator, Authy, Microsoft Authenticator, etc.

3. Save recovery codes securely (10 one-time codes provided)
```

### TOTP Management

| Endpoint | Method | Description |
|---|---|---|
| `/auth/totp/enable` | POST | Enable 2FA (requires current password) |
| `/auth/totp/disable` | POST | Disable 2FA (requires current password) |
| `/auth/totp/verify` | POST | Verify TOTP code after login |
| `/auth/totp/recovery` | POST | Use recovery code (bypass TOTP) |
| `/auth/totp/status` | GET | Check if 2FA is enabled |

### Google OAuth2 Management

| Endpoint | Method | Description |
|---|---|---|
| `/auth/google` | POST | Sign in/register with Google OAuth2 token |

---

## API Reference

### Authentication

| Endpoint | Method | Auth | Description |
|---|---|---|---|
| `/auth/login` | POST | — | Login with credentials (returns JWT or 403 if MFA needed) |
| `/auth/google` | POST | — | Sign in with Google OAuth2 |
| `/auth/register` | POST | — | Register new user (auto-login) |
| `/auth/me` | GET | ✓ | Current user info |
| `/auth/users` | GET | admin | List all users with MFA status |
| `/auth/audit-logs` | GET | admin | Audit log history |
| `/auth/totp/enable` | POST | ✓ | Enable TOTP 2FA |
| `/auth/totp/disable` | POST | ✓ | Disable TOTP 2FA |
| `/auth/totp/verify` | POST | — | Verify TOTP code (uses pre-auth token) |
| `/auth/totp/recovery` | POST | — | Use recovery code (uses pre-auth token) |
| `/auth/totp/status` | GET | ✓ | Check 2FA status |

### IOCs (Indicators of Compromise)

| Endpoint | Method | Auth | Description |
|---|---|---|---|
| `/iocs/` | GET | viewer | List IOCs (paginated, filterable) |
| `/iocs/` | POST | analyst | Create IOC |
| `/iocs/{id}` | GET | viewer | Get IOC details |
| `/iocs/{id}` | PUT | analyst | Update IOC |
| `/iocs/{id}` | DELETE | analyst | Delete IOC |
| `/iocs/bulk` | POST | analyst | Bulk create IOCs |
| `/iocs/{id}/enrich` | POST | analyst | Enrich IOC with external data |

### Threat Actors

| Endpoint | Method | Auth | Description |
|---|---|---|---|
| `/actors/` | GET | viewer | List threat actors |
| `/actors/` | POST | analyst | Create threat actor |
| `/actors/{id}` | GET | viewer | Get actor details |
| `/actors/{id}/graph` | GET | viewer | Get actor relationship graph |

### Malware

| Endpoint | Method | Auth | Description |
|---|---|---|---|
| `/malware/` | GET | viewer | List malware families |
| `/malware/` | POST | analyst | Create malware family |
| `/malware/{id}` | GET | viewer | Get malware details |

### Campaigns

| Endpoint | Method | Auth | Description |
|---|---|---|---|
| `/campaigns/` | GET | viewer | List campaigns |
| `/campaigns/` | POST | analyst | Create campaign |
| `/campaigns/{id}` | GET | viewer | Get campaign details |

### Feeds

| Endpoint | Method | Auth | Description |
|---|---|---|---|
| `/feeds/status` | GET | viewer | Feed status/health |
| `/feeds/register` | POST | analyst | Register new feed |
| `/feeds/ingest` | POST | analyst | Trigger feed ingestion |

### Analysis (AI-Powered)

| Endpoint | Method | Auth | Description |
|---|---|---|---|
| `/analysis/analyze-text` | POST | analyst | LLM threat report analysis (cached 1hr) |
| `/analysis/extract-iocs` | POST | analyst | Extract IOCs from text (cached 1hr) |
| `/analysis/generate-report` | POST | analyst | Generate threat brief from IOCs (cached 30min) |
| `/analysis/map-attack` | POST | analyst | MITRE ATT&CK mapping (cached 1hr) |
| `/analysis/upload-report` | POST | analyst | Upload & analyze document |

### Search

| Endpoint | Method | Auth | Description |
|---|---|---|---|
| `/search/text` | POST | analyst | Full-text search |
| `/search/semantic` | POST | analyst | Vector semantic search |

### STIX 2.1 & TAXII

| Endpoint | Method | Auth | Description |
|---|---|---|---|
| `/stix/import` | POST | analyst | Import STIX 2.1 bundle |
| `/stix/export` | GET | analyst | Export to STIX 2.1 (JSON) |
| `/stix/convert` | POST | analyst | Convert IOC to STIX pattern |
| `/taxii/collections` | GET | analyst | List TAXII collections |
| `/taxii/push` | POST | analyst | Push STIX bundle to collection |
| `/taxii/ingest` | POST | analyst | Ingest from TAXII server |

### Monitoring

| Endpoint | Method | Auth | Description |
|---|---|---|---|
| `/health` | GET | — | Quick health check |
| `/health/deep` | GET | — | Per-service health (Postgres, Neo4j, Qdrant, Redis, RabbitMQ) |
| `/metrics` | GET | — | Prometheus metrics |
| `/` | GET | — | API info & endpoint listing |
| `/docs` | GET | — | Swagger UI (disabled in production) |
| `/redoc` | GET | — | ReDoc documentation |

---

## Observability

| Service | Port | Credentials | Purpose |
|---|---|---|---|
| Prometheus | `:9090` | — | Metrics collection & querying |
| Grafana | `:3001` | `admin` / `admin123` | Dashboards & visualization |
| Loki | `:3100` | — | Log aggregation (JSON) |
| Promtail | (sidecar) | — | Log collection agent |
| Flower | `:5555` | — | Celery task monitoring |

### Grafana Pre-Built Dashboard

Import `grafana/dashboards/threat-intel-dashboard.json` for 12 panels:
- Request rate & latency (p50, p95, p99)
- Error rate tracking
- LLM API usage & latency
- IOC counts by type, threat level, and status
- Feed ingestion metrics
- Active user sessions
- Loki log viewer

### Alert Rules

8 pre-configured Prometheus alerting rules (`prometheus/rules/alerts.yml`):
- **HighErrorRate**: >5% error rate
- **HighLatency**: p99 latency >2s
- **ServiceDown**: Any monitored service unreachable
- **ExceptionSpike**: Application exceptions detected
- **RabbitMQQueueGrowth**: Consumer queue backing up
- **RedisHighMemory**: Redis approaching capacity
- **PostgresHighConnections**: Database connection pool exhaustion
- **HighRequestRate**: Anomalous traffic spike

---

## Environment Variables

### Required Configuration

| Variable | Description | Default |
|---|---|---|
| `DATABASE_URL` | PostgreSQL connection string | `postgresql://admin:secure_password@localhost:5432/threatintel` |
| `REDIS_URL` | Redis connection string | `redis://localhost:6379` |
| `RABBITMQ_URL` | RabbitMQ connection string | `amqp://admin:secure_password@localhost:5672` |
| `JWT_SECRET` | JWT signing key (min 32 chars) | `change_this_jwt_secret_in_production_min_32_chars` |
| `SECRET_KEY` | App secret key | `change_this_secret_key_in_production` |

### Optional Services

| Variable | Description | Default |
|---|---|---|
| `GEMINI_API_KEY` | Google Gemini API key | _(empty)_ |
| `GEMINI_MODEL` | Gemini model to use | `gemini-2.5-flash` |
| `GOOGLE_CLOUD_PROJECT` | Vertex AI project ID | _(empty)_ |
| `NEO4J_URI` | Neo4j connection URI | `bolt://localhost:7687` |
| `OTLP_EXPORT_ENDPOINT` | OpenTelemetry export URL | _(empty)_ |
| `SENTRY_DSN` | Sentry error tracking DSN | _(empty)_ |

### Google OAuth2

| Variable | Description | Default |
|---|---|---|
| `GOOGLE_CLIENT_ID` | OAuth2 Web Client ID from Google Cloud Console | _(empty — disables Google sign-in)_ |

### Security Settings

| Variable | Description | Default |
|---|---|---|
| `ENVIRONMENT` | `development` or `production` | `development` |
| `TLS_TERMINATED_UPSTREAM` | `true` when behind HTTPS proxy | `false` |
| `ENABLE_API_DOCS` | Enable Swagger UI | `true` _(production: disabled)_ |
| `DB_SCHEMA_MANAGEMENT` | `migrations` (recommended) or `autocreate` | `migrations` |

### Full Example (.env)

```bash
# Copy from template
cp .env.example .env

# Then edit with real values:
DATABASE_URL=postgresql://threatintel:Str0ngP@ss@db:5432/threatintel
REDIS_URL=redis://redis:6379
RABBITMQ_URL=amqp://admin:Str0ngP@ss@rabbitmq:5672
JWT_SECRET=your-64-character-secret-key-here-for-jwt-signing
SECRET_KEY=your-64-character-app-secret-key
GEMINI_API_KEY=your-google-gemini-api-key
GOOGLE_CLIENT_ID=123456789-abc123def456.apps.googleusercontent.com
TLS_TERMINATED_UPSTREAM=true
ENVIRONMENT=production
ENABLE_API_DOCS=
ENABLE_METRICS=true
METRICS_REQUIRE_AUTH=true
DB_SCHEMA_MANAGEMENT=migrations
RUN_DB_MIGRATIONS_ON_START=true
```

---

## Project Structure

```
threat-intel-platform/
├── backend/
│   ├── app/
│   │   ├── api/v1/
│   │   │   ├── endpoints/
│   │   │   │   ├── auth.py          # Auth + MFA + Google OAuth2
│   │   │   │   ├── iocs.py          # IOC CRUD
│   │   │   │   ├── actors.py        # Threat actors
│   │   │   │   ├── malware.py       # Malware families
│   │   │   │   ├── campaigns.py     # Campaigns
│   │   │   │   ├── feeds.py         # Feed management
│   │   │   │   ├── search.py        # Text & semantic search
│   │   │   │   ├── analysis.py      # AI analysis (cached)
│   │   │   │   ├── enrichment.py    # IOC enrichment
│   │   │   │   ├── stix.py          # STIX 2.1 import/export
│   │   │   │   └── taxii.py         # TAXII 2.x server
│   │   │   └── router.py            # Main API router
│   │   ├── auth.py                  # Auth logic, TOTP helpers, Google verify
│   │   ├── main.py                  # FastAPI app + middleware + lifespan
│   │   ├── config.py                # Pydantic settings
│   │   ├── db/
│   │   │   ├── postgres.py          # PostgreSQL connection + schema
│   │   │   └── redis_db.py          # Redis caching + sessions
│   │   ├── models/
│   │   │   ├── ioc.py               # Pydantic schemas
│   │   │   ├── response.py          # Response models
│   │   │   └── stix.py              # STIX 2.1 models
│   │   ├── services/                # Business logic (LLM, enrichment, etc.)
│   │   ├── workers/                 # Celery tasks
│   │   ├── health.py                # Health check endpoints
│   │   ├── metrics.py               # Prometheus metrics
│   │   ├── logging_config.py        # Structured logging (structlog)
│   │   ├── sentry_config.py         # Sentry error tracking
│   │   ├── tracing.py               # OpenTelemetry distributed tracing
│   │   └── middleware.py            # Rate limiting, security headers
│   ├── alembic.ini                  # Alembic configuration
│   ├── migrations/
│   │   ├── env.py                   # Alembic environment
│   │   └── versions/
│   │       ├── 001_initial.py        # Base tables (8 tables, 8 indexes)
│   │       ├── 002_totp_2fa.py       # TOTP 2FA support
│   │       └── 003_google_oauth2.py  # Google OAuth2 support
│   ├── scripts/
│   │   ├── manage_db.py             # Alembic CLI wrapper
│   │   ├── integration_test.py      # Integration tests (no Docker needed)
│   │   ├── connection_test.py       # Connectivity verification
│   │   └── test_services.sh         # Bash integration tests
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── context/
│   │   │   └── AuthContext.tsx       # React auth context + localStorage
│   │   ├── components/
│   │   │   └── Layout.tsx            # Layout with nav + stats
│   │   ├── pages/
│   │   │   ├── Login.tsx             # Login with 2FA support
│   │   │   ├── Register.tsx          # Registration
│   │   │   ├── Verify2FA.tsx         # TOTP verification page
│   │   │   ├── Dashboard.tsx
│   │   │   ├── Indicators.tsx
│   │   │   ├── GraphView.tsx
│   │   │   ├── Reports.tsx
│   │   │   └── Settings.tsx          # Security tab with MFA toggle
│   │   └── services/
│   │       └── api.ts                # API clients (all endpoints)
│   └── package.json
├── grafana/
│   ├── dashboards/
│   │   └── threat-intel-dashboard.json
│   └── provisioning/
│       ├── datasources.yml
│       └── dashboards/
├── prometheus/
│   ├── prometheus.yml
│   └── rules/
│       └── alerts.yml                # 8 alerting rules
├── promtail/
│   └── config.yml
├── nginx/
│   ├── nginx.conf                    # Production TLS config
│   └── docker-compose-snippet.yml
├── scripts/
│   └── generate-self-signed-cert.sh
├── docker-compose.yml                # Full stack orchestration
├── COMPLIANCE.md                     # SOC2/ISO 27001 compliance
├── SECURITY_HARDENING.md
├── .env.example
├── .github/
│   └── workflows/
│       └── ci.yml                   # CI pipeline (lint, test, build)
└── README.md
```

---

## Development

### Running the Backend (Standalone)

```bash
cd backend
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt

# Start the API server
uvicorn app.main:app --reload --port 8000

# Run Celery workers (separate terminal)
celery -A app.workers.celery_app worker --loglevel=info
celery -A app.workers.celery_app beat --loglevel=info
```

### Running the Frontend (Standalone)

```bash
cd frontend
npm install
npm run dev
```

### Database Migrations

```bash
# Upgrade to latest migration
python -m scripts.manage_db upgrade head

# Show current version
python -m scripts.manage_db current

# Downgrade one step
python -m scripts.manage_db downgrade -1

# View migration history
python -m scripts.manage_db history
```

### Integration Tests (no Docker required)

```bash
# Verifies all modules load, routes registered, middleware loads
python -m scripts.integration_test
```

---

## Google OAuth2 Setup

### Prerequisites

1. Open the [Google Cloud Console](https://console.cloud.google.com/)
2. Create or select a project
3. Navigate to **APIs & Services → Credentials**
4. Click **Create Credentials → OAuth client ID**
5. Choose **Web application**
6. Add an authorized redirect URI: `http://localhost:8000/api/v1/auth/google/callback` (if needed for server-side flow) or use the standard `postmessage` for frontend-only token verification
7. Copy the **Client ID**

### Configuration

Add to your `.env`:
```bash
GOOGLE_CLIENT_ID=123456789-abc123def456.apps.googleusercontent.com
```

### Frontend Integration

Add the Google Identity Services script to your `index.html`:
```html
<script src="https://accounts.google.com/gsi/client" async defer></script>
```

Use the Google Identity Services button or programmatic API to get an ID token, then send it to the backend:

```typescript
// Example using google.accounts.id
const { google } = window as any;
const client = google.accounts.id.initialize({
  client_id: import.meta.env.VITE_GOOGLE_CLIENT_ID,
  callback: (response: any) => {
    // response.credential is the JWT ID token
    api.post('/auth/google', { credential: response.credential })
      .then(res => {
        // Store token, redirect to dashboard
      });
  },
});
client.renderButton(document.getElementById('google-login-button'), { theme: 'outline', size: 'large' });
```

### How It Works

1. User clicks "Sign in with Google" on the frontend
2. Google Identity Services provides a JWT `credential` token
3. Frontend POSTs it to `/auth/google`
4. Backend verifies the token with Google using `google-auth`
5. If the user exists (matched by email or Google sub), they're logged in
6. If the user is new, they're auto-registered as a `viewer`
7. A JWT session token is returned (2FA is NOT required for Google sign-in)

---

## Testing

### CI Pipeline (GitHub Actions)

The `.github/workflows/ci.yml` pipeline runs automatically on push and PRs:

1. **Lint + Typecheck**: `ruff` for code style, `mypy` for type checking
2. **Tests**: Spin up Postgres 16 + Redis 7 in Docker, run Alembic migrations, execute pytest
3. **Build**: Validate Docker Compose configuration

### Manual Testing

```bash
# Start services
docker-compose up -d postgres redis

# Run migrations
python -m scripts.manage_db upgrade head

# Run integration tests
python -m scripts.integration_test

# Run bash service tests (all Docker services)
chmod +x scripts/test_services.sh
./scripts/test_services.sh
```

---

## Security & Compliance

See [**COMPLIANCE.md**](./COMPLIANCE.md) for full details.

### Summary

| Framework | Coverage |
|---|---|
| **SOC 2 Type I** | 15+ controls mapped (Security, Availability, Processing Integrity, Confidentiality) |
| **ISO 27001:2022** | 30+ Annex A controls mapped (Organizational, People, Physical, Technological) |

### Key Security Controls

- **Authentication**: JWT + bcrypt + TOTP 2FA + Google OAuth2
- **Authorization**: Role-based access control (RBAC) with viewer/analyst/admin hierarchy
- **Encryption**: TLS 1.2+ in transit, bcrypt for passwords, JWT-signed tokens
- **Auditing**: All privileged actions logged with full traceability
- **Rate Limiting**: 100 requests/minute per client
- **Security Headers**: HSTS, X-Frame-Options, CSP, CORS restrictions
- **Input Validation**: All inputs validated via Pydantic schemas
- **SQL Injection Prevention**: Parameterized queries via asyncpg
- **Dependency Scanning**: `pytest`, `ruff`, `mypy` in CI pipeline

### Known Limitations & Recommendations

| Priority | Action |
|---|---|
| **P0** | Enable HTTPS with Let's Encrypt in production |
| **P0** | Replace all `secure_password` defaults in `.env` |
| **P1** | Enable TOTP 2FA for all admin accounts |
| **P1** | Configure Prometheus alert notifications (Slack/PagerDuty) |
| **P1** | Enable `METRICS_REQUIRE_AUTH` in production |
| **P2** | Database encryption at rest (infrastructure level) |
| **P2** | WAF rules in Nginx |
| **P2** | IP allowlisting for admin endpoints |
| **P3** | SOC 2 Type II audit log retention (1 year min) |
| **P3** | Regular penetration testing schedule |

---

## License

MIT License — Free for personal and commercial use.

## Support

For issues, questions, or contributions, please open a GitHub issue or pull request.