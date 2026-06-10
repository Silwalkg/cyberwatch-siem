from fastapi import FastAPI, Depends, HTTPException, WebSocket, WebSocketDisconnect, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from sqlalchemy import func, desc
from datetime import datetime, timedelta
from typing import Optional, List
import asyncio, random, json

from database import get_db, init_db, Event, Alert, Incident, User
from auth import (verify_password, hash_password, create_access_token,
                  get_current_user, SECRET_KEY, ALGORITHM)

# -- App -----------------------------------------------------
app = FastAPI(title="CyberWatch SIEM API", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def startup():
    init_db()
    # Create default admin user
    from database import SessionLocal
    db = SessionLocal()
    if not db.query(User).filter(User.username == "admin").first():
        db.add(User(username="admin",    hashed_password=hash_password("admin123"),    role="Administrator"))
        db.add(User(username="analyst",  hashed_password=hash_password("analyst123"),  role="SOC Analyst"))
        db.commit()
    db.close()

# -- Auth -----------------------------------------------------
@app.post("/api/auth/token")
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form.username).first()
    if not user or not verify_password(form.password, user.hashed_password):
        # Demo mode: accept any credentials
        role = "Administrator" if form.username.lower() == "admin" else "SOC Analyst"
        token = create_access_token({"sub": form.username, "role": role})
        return {"access_token": token, "token_type": "bearer", "role": role, "username": form.username}
    token = create_access_token({"sub": user.username, "role": user.role})
    return {"access_token": token, "token_type": "bearer", "role": user.role, "username": user.username}

# -- Events ---------------------------------------------------
@app.get("/api/events")
def get_events(
    hours: int = 24,
    severity: Optional[str] = None,
    limit: int = 200,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
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
    current_user: dict = Depends(get_current_user)
):
    since = datetime.utcnow() - timedelta(hours=hours)
    events = db.query(Event).filter(Event.timestamp >= since)
    total    = events.count()
    critical = events.filter(Event.severity == "critical").count()
    high     = events.filter(Event.severity == "high").count()
    medium   = events.filter(Event.severity == "medium").count()
    low      = events.filter(Event.severity == "low").count()
    return {
        "total_events": total,
        "critical_events": critical,
        "high_events": high,
        "medium_events": medium,
        "low_events": low,
    }

# -- Alerts ---------------------------------------------------
@app.get("/api/alerts")
def get_alerts(
    status: str = "open",
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    return db.query(Alert).filter(Alert.status == status).order_by(desc(Alert.created_at)).limit(limit).all()

@app.patch("/api/alerts/{alert_id}")
def update_alert(
    alert_id: int,
    body: dict,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
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

# -- Incidents ------------------------------------------------
@app.get("/api/incidents")
def get_incidents(
    status: str = "open",
    limit: int = 20,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    return db.query(Incident).filter(Incident.status == status).order_by(desc(Incident.created_at)).limit(limit).all()

# -- Dashboard Summary ----------------------------------------
@app.get("/api/dashboard/summary")
def get_dashboard_summary(
    hours: int = 24,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    since = datetime.utcnow() - timedelta(hours=hours)
    events    = db.query(Event).filter(Event.timestamp >= since)
    total     = events.count()
    critical  = events.filter(Event.severity == "critical").count()
    open_alerts    = db.query(Alert).filter(Alert.status == "open").count()
    open_incidents = db.query(Incident).filter(Incident.status == "open").count()

    # Top source IPs
    top_ips = (
        db.query(Event.source_ip, func.count(Event.id).label("count"))
        .filter(Event.timestamp >= since)
        .group_by(Event.source_ip)
        .order_by(desc("count"))
        .limit(6)
        .all()
    )

    return {
        "total_events":     total,
        "critical_events":  critical,
        "critical_alerts":  critical,
        "open_alerts":      open_alerts,
        "open_incidents":   open_incidents,
        "top_source_ips":   [{"ip": r[0], "count": r[1]} for r in top_ips],
    }

# -- WebSocket Live Feed ---------------------------------------
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

EVENT_TYPES = ["SSH_Brute_Force","SQL_Injection","Port_Scan","DDoS_Attack",
               "Malware_Download","Phishing_Attempt","RCE_Exploit","XSS_Attack"]
PROTOCOLS   = ["TCP","UDP","HTTP","HTTPS","SSH","DNS"]
SOURCE_IPS  = ["192.168.1.100","203.0.113.50","198.51.100.25","45.33.32.156","185.220.101.45"]

def random_severity():
    return random.choices(["critical","high","medium","low"], weights=[0.08,0.20,0.42,0.30])[0]

@app.websocket("/ws/events")
async def websocket_events(ws: WebSocket, db: Session = Depends(get_db)):
    await manager.connect(ws)
    try:
        while True:
            await asyncio.sleep(3)
            sev = random_severity()
            src = random.choice(SOURCE_IPS)
            evt = random.choice(EVENT_TYPES)

            # Save to DB
            event = Event(
                severity         = sev,
                source_ip        = src,
                destination_ip   = f"10.0.0.{random.randint(1,50)}",
                event_type       = evt,
                protocol         = random.choice(PROTOCOLS),
                destination_port = random.choice([22,80,443,3389,8080]),
                message          = f"{evt.replace('_',' ')} from {src}"
            )
            db.add(event)
            db.commit()
            db.refresh(event)

            await manager.broadcast({
                "type":           "event",
                "id":             event.id,
                "timestamp":      event.timestamp.isoformat(),
                "severity":       event.severity,
                "source_ip":      event.source_ip,
                "destination_ip": event.destination_ip,
                "event_type":     event.event_type,
                "protocol":       event.protocol,
            })

            # Randomly generate alert
            if random.random() < 0.08:
                alert = Alert(
                    title       = f"{evt.replace('_',' ')} Detected",
                    description = f"Automated detection: {evt.replace('_',' ')} from {src}",
                    severity    = sev,
                    source_ip   = src,
                    status      = "open"
                )
                db.add(alert)
                db.commit()
                await manager.broadcast({"type": "alert"})

    except WebSocketDisconnect:
        manager.disconnect(ws)

@app.get("/api/health")
def health():
    return {"status": "ok", "version": "2.0.0"}

