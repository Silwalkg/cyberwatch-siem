from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
import random

DATABASE_URL = "sqlite:///./cyberwatch.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# -- Models -------------------------------------------------
class Event(Base):
    __tablename__ = "events"
    id             = Column(Integer, primary_key=True, index=True)
    timestamp      = Column(DateTime, default=datetime.utcnow)
    severity       = Column(String, index=True)
    source_ip      = Column(String)
    destination_ip = Column(String)
    event_type     = Column(String)
    protocol       = Column(String)
    destination_port = Column(Integer)
    message        = Column(Text)

class Alert(Base):
    __tablename__ = "alerts"
    id             = Column(Integer, primary_key=True, index=True)
    title          = Column(String)
    description    = Column(Text)
    severity       = Column(String, index=True)
    status         = Column(String, default="open")
    source_ip      = Column(String, nullable=True)
    created_at     = Column(DateTime, default=datetime.utcnow)
    acknowledged_by = Column(String, nullable=True)

class Incident(Base):
    __tablename__ = "incidents"
    id          = Column(Integer, primary_key=True, index=True)
    title       = Column(String)
    description = Column(Text)
    severity    = Column(String)
    status      = Column(String, default="open")
    source_ip   = Column(String, nullable=True)
    created_at  = Column(DateTime, default=datetime.utcnow)

class User(Base):
    __tablename__ = "users"
    id            = Column(Integer, primary_key=True, index=True)
    username      = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    role          = Column(String, default="SOC Analyst")
    created_at    = Column(DateTime, default=datetime.utcnow)

# -- DB Dependency -------------------------------------------
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# -- Seed Data -----------------------------------------------
def seed_database(db):
    from datetime import timedelta
    import random

    severities  = ["critical","high","medium","low"]
    event_types = ["SSH_Brute_Force","SQL_Injection","Port_Scan","DDoS_Attack",
                   "Malware_Download","Phishing_Attempt","RCE_Exploit","XSS_Attack",
                   "Credential_Stuffing","DNS_Tunneling","Lateral_Movement","C2_Beacon"]
    protocols   = ["TCP","UDP","HTTP","HTTPS","SSH","DNS","ICMP"]
    countries_ips = ["192.168.1.100","203.0.113.50","198.51.100.25","45.33.32.156",
                     "185.220.101.45","91.108.4.0","77.88.55.70","103.224.182.0"]

    now = datetime.utcnow()

    # Seed events (last 24h)
    for i in range(200):
        sev_weights = [0.08, 0.20, 0.42, 0.30]
        sev = random.choices(severities, weights=sev_weights)[0]
        ts  = now - timedelta(minutes=random.randint(0, 1440))
        db.add(Event(
            timestamp        = ts,
            severity         = sev,
            source_ip        = random.choice(countries_ips),
            destination_ip   = f"10.0.0.{random.randint(1,50)}",
            event_type       = random.choice(event_types),
            protocol         = random.choice(protocols),
            destination_port = random.choice([22,80,443,3389,8080,3306,5432]),
            message          = f"Security event detected from {random.choice(countries_ips)}"
        ))

    # Seed alerts
    alert_data = [
        ("SSH Brute Force Attack Detected", "Multiple failed SSH login attempts from single IP exceeding threshold of 100 attempts/min", "critical", "192.168.1.100"),
        ("SQL Injection Pattern Matched",   "Web application firewall detected malicious SQL payload in POST request", "high", "203.0.113.50"),
        ("Port Scan Detected",              "Systematic port scanning detected across subnet range 10.0.0.0/24", "high", "198.51.100.25"),
        ("Malware C2 Beacon",               "Outbound connection to known C2 server detected", "critical", "45.33.32.156"),
        ("Suspicious DNS Queries",          "Unusually high volume of DNS TXT queries indicating possible DNS tunneling", "medium", "185.220.101.45"),
    ]
    for title, desc, sev, ip in alert_data:
        db.add(Alert(title=title, description=desc, severity=sev, source_ip=ip, status="open"))

    # Seed incidents
    incident_data = [
        ("Active Ransomware Campaign",    "Multiple endpoints showing signs of file encryption activity", "critical", "192.168.1.100"),
        ("Lateral Movement Detected",     "Attacker moving through internal network using compromised credentials", "high", "10.0.0.15"),
        ("Data Exfiltration Attempt",     "Large data transfer to external IP detected outside business hours", "high", "203.0.113.50"),
    ]
    for title, desc, sev, ip in incident_data:
        db.add(Incident(title=title, description=desc, severity=sev, source_ip=ip, status="open"))

    db.commit()

def init_db():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    if db.query(Event).count() == 0:
        seed_database(db)
    db.close()
