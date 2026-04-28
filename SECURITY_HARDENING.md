# Security Hardening Implementation

## Overview
Security hardening has been added to the Threat Intelligence Platform with the following features:

## 1. JWT Authentication (`backend/app/auth.py`)

### Features
- **Token-based auth** using JWT (HS256 algorithm)
- **Role-based access control** with three roles:
  - `admin`: Full access to all endpoints
  - `analyst`: Can create/update IOCs and run analysis
  - `viewer`: Read-only access

### Usage
```python
# Protect endpoint with role requirement
@router.get("/users")
async def list_users(current_user: dict = Depends(require_admin)):
    # Only admins can access
    ...

# Allow multiple roles
@router.get("/iocs")
async def list_iocs(current_user: dict = Depends(require_viewer)):
    # admin, analyst, and viewer can access
    ...
```

### Default Credentials
- Username: `admin`
- Password: `admin123`
- **Change in production!**

## 2. Role-Based Access Control

### Role Permissions
| Endpoint | Admin | Analyst | Viewer |
|----------|--------|---------|--------|
| List IOCs | ✓ | ✓ | ✓ |
| Create IOC | ✓ | ✓ | ✗ |
| Update IOC | ✓ | ✓ | ✗ |
| Delete IOC | ✓ | ✓ | ✗ |
| Manage Users | ✓ | ✗ | ✗ |
| View Audit Logs | ✓ | ✗ | ✗ |
| Enrichment | ✓ | ✓ | ✗ |

## 3. Rate Limiting (`backend/app/middleware.py`)

### Configuration
- **100 requests per 60 seconds** per IP address
- Applied to all endpoints except:
  - `/health`
  - `/docs`
  - `/redoc`
  - `/openapi.json`

### Response
- Status: `429 Too Many Requests`
- Body: `{"detail":"Rate limit exceeded. Please try again later."}`

### Production Note
The current implementation uses in-memory storage. For production with multiple workers, use Redis:
```python
# TODO: Replace in-memory storage with Redis
# from redis import Redis
# self.redis = Redis.from_url(settings.redis_url)
```

## 4. Audit Logging (`backend/app/auth.py`)

### Tracked Actions
- User login/logout
- IOC create/update/delete
- Bulk operations
- User management
- Feed ingestion

### Audit Log Schema
```sql
CREATE TABLE audit_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    username VARCHAR(50),
    action VARCHAR(50),      -- 'create', 'update', 'delete', 'login', etc.
    resource VARCHAR(50),    -- 'ioc', 'user', 'feed', etc.
    resource_id VARCHAR(100),
    details TEXT,
    ip_address VARCHAR(45),
    timestamp TIMESTAMP DEFAULT NOW()
);
```

### Access
- Admins can view logs: `GET /api/v1/auth/audit-logs?limit=100`
- Logs are automatically created on all protected operations

## 5. Input Validation (`backend/app/validation.py`)

### IOC Validation
Strict regex patterns for each IOC type:
- **IPv4**: Validates format (e.g., `192.168.1.1`)
- **IPv6**: Full IPv6 format validation
- **Domain**: Valid domain name format
- **URL**: Valid URL with protocol
- **Hashes**: MD5 (32 chars), SHA1 (40 chars), SHA256 (64 chars)
- **Email**: Valid email format

### STIX ID Validation
Validates STIX 2.1 ID format:
```
<type>--<uuid>
Example: indicator--a1b2c3d4-5e6f-7a8b-9c0d-1e2f3a4b5c6d
```

### Usage in Endpoints
```python
from app.validation import IOCValidator, validate_stix_id

# Validate IOC value
if not IOCValidator.validate_ioc_value(ioc.type, ioc.value):
    raise HTTPException(400, "Invalid IOC value for type")

# Sanitize input
value = IOCValidator.sanitize_value(raw_value)
```

## 6. Security Headers (`backend/app/middleware.py`)

Added to all responses:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Content-Security-Policy: default-src 'self'`

## 7. User Management Endpoints

### Endpoints
| Method | Endpoint | Description | Access |
|--------|-----------|-------------|--------|
| POST | `/api/v1/auth/register` | Register new user | Admin |
| POST | `/api/v1/auth/login` | Get JWT token | All |
| GET | `/api/v1/auth/me` | Get current user info | All |
| POST | `/api/v1/auth/logout` | Logout (client discards token) | All |
| GET | `/api/v1/auth/users` | List all users | Admin |
| GET | `/api/v1/auth/audit-logs` | View audit logs | Admin |

### Example Login
```bash
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}'

# Response
{
  "access_token": "eyJhbGciOi...",
  "token_type": "bearer"
}
```

### Using Token
```bash
curl http://localhost:8000/api/v1/iocs \
  -H "Authorization: Bearer eyJhbGciOi..."
```

## Database Changes

### New Tables
1. **users**: Stores user accounts with hashed passwords
2. **audit_logs**: Tracks all security-relevant actions

### Migration
Tables are created automatically on startup via `init_security_db()` in `postgres.py`.

## Production Checklist

- [ ] Change default admin password
- [ ] Set strong `SECRET_KEY` in environment
- [ ] Use HTTPS (configure reverse proxy)
- [ ] Replace in-memory rate limiter with Redis
- [ ] Set up centralized logging (ELK/Loki)
- [ ] Configure password complexity requirements
- [ ] Enable account lockout after failed attempts
- [ ] Add 2FA/TOTP support
- [ ] Use Vault or cloud secrets manager for API keys

## Files Modified/Created

- `backend/app/auth.py` - JWT auth, RBAC, audit logging
- `backend/app/validation.py` - IOC input validation
- `backend/app/middleware.py` - Rate limiting, security headers
- `backend/app/db/postgres.py` - Added users/audit_logs tables
- `backend/app/main.py` - Added security middleware and auth router
- `backend/app/api/v1/endpoints/auth.py` - Auth endpoints
- `backend/app/api/v1/endpoints/iocs.py` - Added auth to IOC endpoints
