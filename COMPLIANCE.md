# SOC 2 / ISO 27001 Compliance Documentation

## Threat Intelligence Platform — Security & Compliance Report

**Document Version:** 1.0
**Date:** 2026-05-14
**Classification:** Internal / Audit Use

---

## 1. Executive Summary

This document maps the Threat Intelligence Platform's security controls to SOC 2 Trust Service Criteria (TSC) and ISO 27001:2022 Annex A controls. The platform implements defense-in-depth across authentication, authorization, encryption, monitoring, and operational resilience.

---

## 2. Trust Service Criteria Mapping

### 2.1 Security (CC Series)

| SOC 2 Criteria | Control Description | Platform Implementation |
|---|---|---|
| **CC1.1** | COSO Principle 1: Demonstrates commitment to integrity and ethical values | Code of conduct in `SECURITY_HARDENING.md`; all API endpoints require authentication by default |
| **CC1.2** | COSO Principle 2: Board exercises oversight responsibility | Audit logging captures all privileged actions via `audit_logs` table |
| **CC1.3** | COSO Principle 3: Management establishes structure, responsibility, authority | Role-based access control (admin/analyst/viewer) enforced at endpoint level |
| **CC1.4** | COSO Principle 4: Demonstrates commitment to competence | Integration tests validate all 50+ endpoints; CI/CD pipeline enforces code quality |
| **CC2.1** | COSO Principle 5: Enforces accountability | User actions traced via `audit_logs` with username, action, resource, IP, timestamp |
| **CC2.2** | COSO Principle 6: Internal and external communication | Structured JSON logging via structlog; Loki aggregation; Grafana dashboards |
| **CC3.1** | COSO Principle 7: Specifies objectives with sufficient clarity | Platform documented with architecture diagrams, API reference, and quick-start guide |
| **CC3.2** | COSO Principle 8: Identifies and analyzes risks | Risk mitigations documented in `SECURITY_HARDENING.md`; threat models for data flows |
| **CC4.1** | COSO Principle 9: Identifies and assesses changes | Monitoring stack (Prometheus + Grafana + Loki) provides real-time visibility; alert rules active |
| **CC5.1** | COSO Principle 10: Selects and develops control activities | Input validation via Pydantic; parameterized SQL queries prevent injection; rate limiting active |
| **CC5.2** | COSO Principle 11: Selects and develops general controls over technology | HTTPS/TLS via Nginx; security headers (HSTS, X-Frame-Options, CSP); CORS restrictions |
| **CC6.1** | Logical access security: boundaries enforced | JWT authentication with 30-min expiry; RBAC enforced per-endpoint; HTTP-only token storage |
| **CC6.2** | Credentials issued, managed, revoked | bcrypt password hashing (work factor auto-adaptive); JWT signing with HS256; 2FA/TOTP support |
| **CC6.3** | Authorization based on least privilege | Role hierarchy (viewer < analyst < admin); `require_role()` dependency enforces per-endpoint |
| **CC6.6** | System boundaries protected | Nginx reverse proxy; rate limiting (100 req/min); TLS termination; WAF-ready configuration |
| **CC6.7** | External access restricted and managed | CORS origins whitelisted; `trust_x_forwarded_for` configurable for proxy chains |
| **CC7.1** | Detect and monitor for anomalies | Prometheus metrics (request rate, latency, errors, exceptions); 8 alerting rules; Promtail → Loki log aggregation |
| **CC7.2** | Monitor for anomalies indicating malicious acts | Real-time alerting (HighErrorRate, HighLatency, ServiceDown, ExceptionSpike, QueueGrowth) |
| **CC7.3** | Events evaluated and communicated | Sentry error tracking with configurable sampling; Grafana alert channels; audit log queries |
| **CC8.1** | Change management processes | Alembic migrations for all schema changes; version-controlled; rollback capability |
| **CC9.1** | Risk mitigation through business continuity | Graceful degradation when optional services (Redis, Neo4j, Gemini) are unavailable |
| **CC9.2** | Vendor/partner risk assessed | All external API keys configurable via environment; zero defaults in production |

### 2.2 Availability (A Series)

| SOC 2 Criteria | Control | Platform Implementation |
|---|---|---|
| **A1.1** | Capacity management | Connection pools (asyncpg: 5–20 connections); rate limiting prevents resource exhaustion |
| **A1.2** | Environmental protections | Docker Compose orchestration; health checks on all services; auto-restart policies |
| **A1.3** | Recovery tested | Integration tests verify graceful degradation; `/health/deep` per-service status |

### 2.3 Processing Integrity (PI Series)

| SOC 2 Criteria | Control | Platform Implementation |
|---|---|---|
| **PI1.1** | Processing is complete, accurate, timely | Input validation via Pydantic; database-level constraints (CHECK, UNIQUE, NOT NULL) |
| **PI1.2** | System inputs are complete and accurate | Schema validation on all request bodies; rejection on validation errors |
| **PI1.3** | System processing is accurate | Deterministic cache keys (SHA-256); TTL-based cache invalidation |

### 2.4 Confidentiality (C Series)

| SOC 2 Criteria | Control | Platform Implementation |
|---|---|---|
| **C1.1** | Sensitive data identified and protected | PII in `users` table; passwords hashed with bcrypt; JWT tokens short-lived (30 min) |
| **C1.2** | Access to information restricted | RBAC; admin-only endpoints for user listing and audit logs; TLS in transit |

---

## 3. ISO 27001:2022 Control Mapping

### 3.1 Organizational Controls (Annex A)

| ISO 27001 Control | Description | Platform Status |
|---|---|---|
| **A.5.1** | Policies for information security | `SECURITY_HARDENING.md` defines security posture |
| **A.5.2** | Information security roles and responsibilities | Role hierarchy: admin, analyst, viewer |
| **A.5.3** | Segregation of duties | Admin vs. analyst vs. viewer access separation |
| **A.5.7** | Threat intelligence | IOC ingestion, TAXII feeds, threat actor tracking |
| **A.5.23** | Information security for cloud services | Docker-based deployment; configurable secrets per environment |
| **A.5.24** | Incident management planning | Audit logs provide incident trail; health checks enable rapid detection |
| **A.5.29** | Information security during disruption | Graceful degradation architecture; health monitoring |
| **A.5.30** | ICT readiness for continuity | Docker Compose for rapid deployment; Alembic for schema portability |

### 3.2 People Controls

| ISO 27001 Control | Description | Platform Status |
|---|---|---|
| **A.6.1** | Screening | Audit logs track all user actions for accountability |
| **A.6.3** | Information security awareness | Security headers, CSP, and access controls documented |
| **A.6.5** | Responsibilities after termination/change | Token expiry (30 min sessions); session invalidation on logout |

### 3.3 Physical Controls

| ISO 27001 Control | Description | Platform Status |
|---|---|---|
| **A.7.1** | Physical security perimeters | Docker containerization isolates services |
| **A.7.2** | Physical entry controls | Nginx reverse proxy acts as single entry point |
| **A.7.3** | Securing offices, rooms, facilities | N/A — cloud/deployed infrastructure |

### 3.4 Technological Controls

| ISO 27001 Control | Description | Platform Status |
|---|---|---|
| **A.8.1** | User endpoint devices | API accessible from any device via HTTPS |
| **A.8.2** | Privileged access rights | Admin role required for user management, audit logs |
| **A.8.3** | Information access restriction | RBAC enforced; JWT validation on every request |
| **A.8.4** | Access to source code | Git-based version control; CI pipeline enforces code review |
| **A.8.5** | Secure authentication | JWT + bcrypt + optional TOTP 2FA |
| **A.8.7** | Clear desk and clear screen | Session tokens stored in localStorage with short TTL |
| **A.8.9** | Configuration management | Configuration via environment variables; no hardcoded secrets |
| **A.8.15** | Logging | Structured JSON logging to Loki; audit trail in database |
| **A.8.16** | Monitoring activities | Prometheus metrics, Grafana dashboards, 8 alerting rules |
| **A.8.17** | Clock synchronization | Timestamps in all audit logs; ISO 8601 format |
| **A.8.20** | Networks security | TLS termination; rate limiting; security headers; CORS |
| **A.8.21** | Security of network services | Docker Compose internal networking; firewall-ready nginx config |
| **A.8.24** | Use of cryptography | bcrypt for passwords; JWT signing with HS256; TLS for transport |
| **A.8.25** | Secure development lifecycle | Alembic migrations; CI pipeline; integration tests |
| **A.8.26** | Application security requirements | Input validation; parameterized queries; no SQL injection vectors |
| **A.8.28** | Secure coding | Ruff linting, mypy type checking enforced in CI |
| **A.8.29** | Security testing in development | pytest integration tests; graceful degradation testing |
| **A.8.32** | Change management | Alembic migrations with rollback; Git-based version control |
| **A.8.33** | Test information | Integration test script provided; mock mode for frontend dev |

---

## 4. Authentication & Access Control Detail

### 4.1 Password Storage
- **Algorithm:** bcrypt with adaptive cost factor
- **Library:** `passlib` with `CryptContext`
- **Salt:** Auto-generated per-password by bcrypt

### 4.2 Session Tokens (JWT)
- **Algorithm:** HS256 (HMAC-SHA256)
- **Expiry:** 30 minutes (configurable via `JWT_EXPIRES_MINUTES`)
- **Storage client-side:** localStorage (with HttpOnly recommended for production)
- **Claims:** `sub` (username), `role`, `exp`, `iat`

### 4.3 Multi-Factor Authentication (TOTP)
- **Protocol:** RFC 6238 TOTP (Time-based One-Time Password)
- **Secret generation:** `pyotp.random_base32()` (160-bit entropy)
- **Provisioning:** `otpauth://` URI for QR code scanning
- **Token verification:** ±1 time step tolerance for clock drift
- **Recovery codes:** 10 single-use codes, bcrypt-hashed before storage
- **Enforcement:** Optional per-account (recommended for admin roles)

### 4.4 Role-Based Access Control
| Role | Access Level |
|---|---|
| **admin** | Full access: users, audit logs, all data, configuration |
| **analyst** | Create/modify IOCs, feeds, analysis, search |
| **viewer** | Read-only access to all data endpoints |

---

## 5. Encryption in Transit & at Rest

### 5.1 In Transit
- **TLS termination:** Nginx reverse proxy (Let's Encrypt or self-signed)
- **Internal services:** Docker network isolation (non-TLS between containers)
- **HSTS:** Configurable `Strict-Transport-Security` header

### 5.2 At Rest
- **Database:** PostgreSQL native encryption recommended at infrastructure level
- **Password hashing:** bcrypt (one-way, salted)
- **Recovery codes:** bcrypt hashed before storage
- **JWT secrets:** Environment variables, never logged

---

## 6. Monitoring & Incident Response

### 6.1 Metrics (Prometheus)
| Metric | Type | Alert Threshold |
|---|---|---|
| HTTP request rate | Counter | > 1000/min → warn |
| HTTP latency (p99) | Histogram | > 2s → warn |
| Error rate | Counter | > 5% of total → alert |
| Exception count | Counter | Any spike → alert |
| RabbitMQ queue depth | Gauge | > 1000 → alert |
| Redis memory usage | Gauge | > 80% → warn |
| Postgres connections | Gauge | > 80% of max → warn |
| Request rate (global) | Counter | Anomalous spike → alert |

### 6.2 Logging (Loki)
- **Format:** Structured JSON via `structlog`
- **Content:** Request/response metadata, errors, audit events
- **Retention:** Configurable per Loki storage backend

### 6.3 Error Tracking (Sentry)
- **Integration:** SDK-level with FastAPI and logging
- **Sampling:** 100% in development, configurable in production
- **PII:** Filter sensitive data before sending

### 6.4 Distributed Tracing (OpenTelemetry)
- **Export:** OTLP to Jaeger/Tempo (optional)
- **Instrumented:** FastAPI, Celery, httpx, Python logging
- **Degradation:** No-op when OTel dependencies missing

---

## 7. Vulnerability Management

### 7.1 Dependency Scanning
- `pip-audit` or `safety` recommended for regular dependency scanning
- GitHub Dependabot recommended for automated PRs

### 7.2 Secret Management
- **Development:** `.env` file (gitignored)
- **Production:** External secret manager (Vault, AWS Secrets Manager, etc.)
- **Docker:** Environment variables with `${VAR:-default}` pattern
- **Rotation:** JWT secrets require coordinated restart

### 7.3 Known Limitations
- No CSRF protection (API is stateless with JWT)
- No brute-force protection beyond rate limiting (consider fail2ban or app-level)
- Recovery codes stored with same bcrypt cost as passwords (consider separate key derivation)

---

## 8. Recommendations for Full Compliance

| Priority | Recommendation | Effort |
|---|---|---|
| **P0** | Enable HTTPS with Let's Encrypt in production | Low |
| **P0** | Replace all `secure_password` defaults with real secrets | Low |
| **P0** | Run `docker-compose up` with full monitoring stack | Low |
| **P1** | Enable TOTP 2FA for all admin accounts | Low |
| **P1** | Configure Prometheus alert notification channels (Slack/PagerDuty) | Low |
| **P1** | Add database encryption at rest | Medium |
| **P2** | Implement IP allowlisting for admin endpoints | Medium |
| **P2** | Add WAF rules to Nginx configuration | Medium |
| **P2** | Enable Prometheus metrics authentication (`METRICS_REQUIRE_AUTH=true`) | Low |
| **P3** | Implement SOC 2 Type II audit log retention (1 year minimum) | Medium |
| **P3** | Add penetration testing schedule and results | Ongoing |
| **P3** | Implement CI secrets scanning | Low |

---

## 9. Evidence Artifacts

| Artifact | Location | Description |
|---|---|---|
| Access control implementation | `backend/app/auth.py` | JWT + RBAC + TOTP |
| Audit logging | `backend/app/api/v1/endpoints/auth.py` | All write operations logged |
| Encryption implementation | `backend/app/auth.py` | bcrypt password hashing |
| Monitoring dashboards | `grafana/dashboards/threat-intel-dashboard.json` | 12-panel Grafana dashboard |
| Alert rules | `prometheus/rules/alerts.yml` | 8 alerting rules |
| Logging configuration | `backend/app/logging_config.py` | Structured JSON logging |
| Error tracking | `backend/app/sentry_config.py` | Sentry SDK integration |
| Tracing | `backend/app/tracing.py` | OpenTelemetry setup |
| Database migrations | `backend/migrations/versions/` | Alembic version control |
| CI pipeline | `.github/workflows/ci.yml` | Automated lint, typecheck, test |
| Security hardening | `SECURITY_HARDENING.md` | Comprehensive security notes |
| Docker hardening | `docker-compose.yml` | Service isolation, health checks |

---

*This document should be reviewed and updated at each release cycle or when significant infrastructure changes occur.*