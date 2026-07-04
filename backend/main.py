import os
from fastapi import FastAPI, Depends, HTTPException, WebSocket, WebSocketDisconnect, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from sqlalchemy import func, desc
from datetime import datetime, timedelta
from typing import Optional, List
import asyncio, random

# Load .env file if python-dotenv is available (dev convenience).
# In production, set env vars through your process manager / container runtime.
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from database import get_db, init_db, SessionLocal, Event, Alert, Incident, User
from auth import (verify_password, hash_password, create_access_token, get_current_user)

# ---------------------------------------------------------------------------
# DEMO_MODE — when true, /api/auth/token accepts any non-empty credentials.
# Controlled by an explicit env flag so the behaviour is obviously intentional.
# Never enable in a real deployment.
# ---------------------------------------------------------------------------
DEMO_MODE: bool = os.environ.get("DEMO_MODE", "false").lower() == "true"

# ---------------------------------------------------------------------------
# CORS — restrict origins in production via the CORS_ORIGINS env var.
# Example: CORS_ORIGINS=https://siem.example.com,https://admin.example.com
# Falls back to "*" only when not set, which is fine for local dev/demo but
# should never be used alongside real credentials in production.
# ---------------------------------------------------------------------------
_raw_origins = os.environ.get("CORS_ORIGINS", "")
ALLOWED_ORIGINS: List[str] = [o.strip() for o in _raw_origins.split(",") if o.strip()] or ["*"]

# -- App --------------------------------------------------------------------
app = FastAPI(title="CyberWatch SIEM API", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
    # NOTE: allow_credentials=True must NOT be combined with allow_origins=["*"].
    # If you lock down CORS_ORIGINS to specific domains, you can enable this.
    allow_credentials=False,
)


@app.on_event("startup")
def startup():
    init_db()
    db = SessionLocal()
    try:
        if not db.query(User).filter(User.username == "admin").first():
            db.add(User(username="admin",   hashed_password=hash_password("admin123"),   role="Administrator"))
            db.add(User(username="analyst", hashed_password=hash_password("analyst123"), role="SOC Analyst"))
            db.commit()
    finally:
        db.close()


# -- Auth -------------------------------------------------------------------
@app.post("/api/auth/token")
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form.username).first()

    if user and verify_password(form.password, user.hashed_password):
        # Valid DB user — issue a real token.
        token = create_access_token({"sub": user.username, "role": user.role})
        return {"access_token": token, "token_type": "bearer", "role": user.role, "username": user.username}

    if DEMO_MODE:
        # Explicitly opt-in demo fallback: accept any non-empty credentials.
        role  = "Administrator" if form.username.lower() == "admin" else "SOC Analyst"
        token = create_access_token({"sub": form.username, "role": role})
        return {"access_token": token, "token_type": "bearer", "role": role, "username": form.username}

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Incorrect username or password",
        headers={"WWW-Authenticate": "Bearer"},
    )


# -- Events -----------------------------------------------------------------
@app.get("/api/events")
def get_events(
    hours: int = 24,
    severity: Optional[str] = None,
    limit: int = 200,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    since = datetime.utcnow() - timedelta(hours=hours)
    q = db.query(Event).filter(Event.timestamp >= since)
    if severity:
        q = q.filter(Event.severity == severity)
    return q.order_by(desc(Event.timestamp)).limit(limit).all()


@app.get("/api/events/stats")
def get_event_stats(
    hours: int = 24,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    since  = datetime.utcnow() - timedelta(hours=hours)
    events = db.query(Event).filter(Event.timestamp >= since)
    total    = events.count()
    critical = events.filter(Event.severity == "critical").count()
    high     = events.filter(Event.severity == "high").count()
    medium   = events.filter(Event.severity == "medium").count()
    low      = events.filter(Event.severity == "low").count()
    return {
        "total_events":    total,
        "critical_events": critical,
        "high_events":     high,
        "medium_events":   medium,
        "low_events":      low,
    }


# -- Alerts -----------------------------------------------------------------
@app.get("/api/alerts")
def get_alerts(
    status: str = "open",
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    return db.query(Alert).filter(Alert.status == status).order_by(desc(Alert.created_at)).limit(limit).all()


@app.patch("/api/alerts/{alert_id}")
def update_alert(
    alert_id: int,
    body: dict,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    if "status" in body:
        alert.status = body["status"]
    if "acknowledged_by" in body:
        alert.acknowledged_by = body["acknowledged_by"]
    db.commit()
    return {"success": True}


# -- Incidents --------------------------------------------------------------
@app.get("/api/incidents")
def get_incidents(
    status: str = "open",
    limit: int = 20,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    return db.query(Incident).filter(Incident.status == status).order_by(desc(Incident.created_at)).limit(limit).all()


# -- Dashboard Summary ------------------------------------------------------
@app.get("/api/dashboard/summary")
def get_dashboard_summary(
    hours: int = 24,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    since          = datetime.utcnow() - timedelta(hours=hours)
    events_q       = db.query(Event).filter(Event.timestamp >= since)
    total          = events_q.count()
    critical       = events_q.filter(Event.severity == "critical").count()
    open_alerts    = db.query(Alert).filter(Alert.status == "open").count()
    open_incidents = db.query(Incident).filter(Incident.status == "open").count()

    top_ips = (
        db.query(Event.source_ip, func.count(Event.id).label("count"))
        .filter(Event.timestamp >= since)
        .group_by(Event.source_ip)
        .order_by(desc("count"))
        .limit(6)
        .all()
    )

    return {
        "total_events":    total,
        "critical_events": critical,
        "critical_alerts": critical,
        "open_alerts":     open_alerts,
        "open_incidents":  open_incidents,
        "top_source_ips":  [{"ip": r[0], "count": r[1]} for r in top_ips],
    }


# -- WebSocket Live Feed ----------------------------------------------------
class ConnectionManager:
    def __init__(self):
        self.active: List[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)

    def disconnect(self, ws: WebSocket):
        if ws in self.active:
            self.active.remove(ws)

    async def broadcast(self, data: dict):
        for ws in list(self.active):
            try:
                await ws.send_json(data)
            except Exception:
                self.disconnect(ws)


manager = ConnectionManager()

_WS_EVENT_TYPES = ["SSH_Brute_Force", "SQL_Injection", "Port_Scan", "DDoS_Attack",
                   "Malware_Download", "Phishing_Attempt", "RCE_Exploit", "XSS_Attack"]
_WS_PROTOCOLS   = ["TCP", "UDP", "HTTP", "HTTPS", "SSH", "DNS"]
_WS_SOURCE_IPS  = ["192.168.1.100", "203.0.113.50", "198.51.100.25", "45.33.32.156", "185.220.101.45"]


def _random_severity():
    return random.choices(["critical", "high", "medium", "low"], weights=[0.08, 0.20, 0.42, 0.30])[0]


@app.websocket("/ws/events")
async def websocket_events(ws: WebSocket):
    """
    Each tick opens a fresh DB session and closes it immediately after the
    write is committed. This avoids holding a single long-lived session open
    for the lifetime of the WebSocket connection, which can exhaust the
    connection pool and cause stale-state issues under concurrent load.
    """
    await manager.connect(ws)
    try:
        while True:
            await asyncio.sleep(3)

            sev = _random_severity()
            src = random.choice(_WS_SOURCE_IPS)
            evt = random.choice(_WS_EVENT_TYPES)

            # Open a short-lived session just for this tick's writes.
            db = SessionLocal()
            try:
                event = Event(
                    severity         = sev,
                    source_ip        = src,
                    destination_ip   = f"10.0.0.{random.randint(1, 50)}",
                    event_type       = evt,
                    protocol         = random.choice(_WS_PROTOCOLS),
                    destination_port = random.choice([22, 80, 443, 3389, 8080]),
                    message          = f"{evt.replace('_', ' ')} from {src}",
                )
                db.add(event)
                db.commit()
                db.refresh(event)

                event_payload = {
                    "type":           "event",
                    "id":             event.id,
                    "timestamp":      event.timestamp.isoformat(),
                    "severity":       event.severity,
                    "source_ip":      event.source_ip,
                    "destination_ip": event.destination_ip,
                    "event_type":     event.event_type,
                    "protocol":       event.protocol,
                }

                # Randomly generate an alert on this tick.
                alert_triggered = False
                if random.random() < 0.08:
                    alert = Alert(
                        title       = f"{evt.replace('_', ' ')} Detected",
                        description = f"Automated detection: {evt.replace('_', ' ')} from {src}",
                        severity    = sev,
                        source_ip   = src,
                        status      = "open",
                    )
                    db.add(alert)
                    db.commit()
                    alert_triggered = True
            finally:
                db.close()

            await manager.broadcast(event_payload)
            if alert_triggered:
                await manager.broadcast({"type": "alert"})

    except WebSocketDisconnect:
        manager.disconnect(ws)


# -- User Management (Administrator only) ----------------------------------

def _require_admin(current_user: dict = Depends(get_current_user)):
    """Dependency that enforces Administrator role."""
    if current_user.get("role") != "Administrator":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrator role required",
        )
    return current_user


@app.get("/api/users")
def list_users(
    db: Session = Depends(get_db),
    current_user: dict = Depends(_require_admin),
):
    users = db.query(User).order_by(User.created_at).all()
    return [
        {
            "id":         u.id,
            "username":   u.username,
            "role":       u.role,
            "created_at": u.created_at.isoformat(),
        }
        for u in users
    ]


@app.post("/api/users", status_code=status.HTTP_201_CREATED)
def create_user(
    body: dict,
    db: Session = Depends(get_db),
    current_user: dict = Depends(_require_admin),
):
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""
    role     = body.get("role", "SOC Analyst")

    if not username:
        raise HTTPException(status_code=400, detail="username is required")
    if not password:
        raise HTTPException(status_code=400, detail="password is required")
    if role not in ("Administrator", "SOC Analyst"):
        raise HTTPException(status_code=400, detail="role must be Administrator or SOC Analyst")
    if db.query(User).filter(User.username == username).first():
        raise HTTPException(status_code=409, detail="Username already exists")

    user = User(username=username, hashed_password=hash_password(password), role=role)
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"id": user.id, "username": user.username, "role": user.role, "created_at": user.created_at.isoformat()}


@app.patch("/api/users/{user_id}")
def update_user(
    user_id: int,
    body: dict,
    db: Session = Depends(get_db),
    current_user: dict = Depends(_require_admin),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if "role" in body:
        if body["role"] not in ("Administrator", "SOC Analyst"):
            raise HTTPException(status_code=400, detail="role must be Administrator or SOC Analyst")
        user.role = body["role"]

    if body.get("password"):
        user.hashed_password = hash_password(body["password"])

    db.commit()
    return {"id": user.id, "username": user.username, "role": user.role}


@app.delete("/api/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(_require_admin),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    # Prevent deleting yourself
    if user.username == current_user.get("username"):
        raise HTTPException(status_code=400, detail="Cannot delete your own account")
    db.delete(user)
    db.commit()


# -- Health -----------------------------------------------------------------
@app.get("/api/health")
def health():
    return {"status": "ok", "version": "2.0.0", "demo_mode": DEMO_MODE}
