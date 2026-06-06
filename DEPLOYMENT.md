# CyberWatch SIEM — Deployment Guide

## Quick Start (Demo Mode — no backend required)

The frontend runs entirely in the browser using simulated data. No server needed.

1. Open `index.html` directly in a browser, **or** serve with any static server:
   ```bash
   npx serve .
   # then open http://localhost:3000
   ```
2. On the login page, enter any username and password (demo mode accepts all credentials).
3. Use `admin` as the username to get the Administrator role.

---

## Full Stack Deployment (Docker)

### Prerequisites
- Docker Desktop installed and running
- Ports 80, 8000, 5432, 6379 available

### Steps

```bash
# 1. Clone the repo
git clone <repo-url>
cd cyberwatch-siem-main

# 2. Start all services
docker-compose up -d

# 3. Check services are healthy
docker-compose ps

# 4. Open the dashboard
#    Frontend: http://localhost
#    API docs: http://localhost:8000/docs
```

### Services

| Service  | Port | Description             |
|----------|------|-------------------------|
| Frontend | 80   | Nginx static files      |
| Backend  | 8000 | FastAPI REST + WebSocket|
| Postgres | 5432 | Primary database        |
| Redis    | 6379 | Cache / session store   |

---

## Environment Variables (backend)

| Variable       | Default                                          | Description              |
|----------------|--------------------------------------------------|--------------------------|
| DATABASE_URL   | postgresql://siem_user:siem_password@postgres/siem_db | Postgres connection  |
| API_HOST       | 0.0.0.0                                          | Bind address             |
| API_PORT       | 8000                                             | HTTP port                |
| SYSLOG_HOST    | 0.0.0.0                                          | Syslog listener address  |
| SYSLOG_PORT    | 514                                              | Syslog UDP port          |
| LOG_LEVEL      | INFO                                             | Logging verbosity        |

---

## Tear Down

```bash
docker-compose down          # stop containers
docker-compose down -v       # stop + delete volumes (data loss)
```

---

## Frontend-Only Notes

- `index.html` — full-featured SPA dashboard
- `dashboard-simple.html` — lightweight fallback (self-contained)
- `login.html` — authentication gate (demo: any credentials work)
- When the backend is unreachable, the dashboard automatically falls back to realistic simulated data and a WebSocket simulation.
