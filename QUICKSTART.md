# Quick Start Guide - CyberWatch Pro SIEM

Get up and running in 5 minutes!

## Option 1: Docker Compose (Easiest)

### 1. Prerequisites
- Docker Desktop installed
- 4GB RAM available
- Port 80, 8000, 514 available

### 2. Start the System

```bash
# Navigate to project directory
cd siem-dashboard

# Start all services
docker-compose up -d

# Wait for services to start (30 seconds)
sleep 30

# Check status
docker-compose ps
```

### 3. Access the Dashboard

- **Frontend**: http://localhost
- **API Docs**: http://localhost:8000/docs
- **Health Check**: http://localhost:8000/health

### 4. Send Test Events

```bash
# Send a test syslog message
echo "<34>Jan 15 10:30:45 firewall ALLOW TCP 192.168.1.100:54321 -> 8.8.8.8:53 (DNS)" | nc -u localhost 514

# Or send JSON event
curl -X POST http://localhost:8000/api/events \
  -H "Content-Type: application/json" \
  -d '{
    "timestamp": "2024-01-15T10:30:45Z",
    "source_ip": "192.168.1.100",
    "destination_ip": "8.8.8.8",
    "destination_port": 53,
    "protocol": "UDP",
    "event_type": "dns_query",
    "severity": "low",
    "message": "DNS query to 8.8.8.8",
    "source_system": "firewall"
  }'
```

### 5. View Events in Dashboard

1. Open http://localhost
2. Go to "Live Events" tab
3. You should see your test event

## Option 2: Local Development

### 1. Prerequisites
- Python 3.11+
- PostgreSQL 15+ (or SQLite for testing)
- Node.js (optional, for frontend development)

### 2. Install Backend

```bash
cd backend

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Create .env file
cp .env.example .env

# Initialize database
python -c "from database import init_db; init_db()"
```

### 3. Start Backend

```bash
# Terminal 1: Start API server
uvicorn main:app --reload

# Terminal 2: Start syslog receiver
python syslog_receiver.py
```

### 4. Open Frontend

```bash
# Open in browser
http://localhost:8000
```

## Testing the System

### Test 1: Brute Force Detection

```bash
# Send 5 failed SSH attempts from same IP
for i in {1..5}; do
  curl -X POST http://localhost:8000/api/events \
    -H "Content-Type: application/json" \
    -d "{
      \"timestamp\": \"2024-01-15T10:30:$(printf '%02d' $i)Z\",
      \"source_ip\": \"192.168.1.100\",
      \"destination_ip\": \"10.0.0.5\",
      \"destination_port\": 22,
      \"protocol\": \"TCP\",
      \"event_type\": \"ssh_brute_force\",
      \"severity\": \"high\",
      \"message\": \"Failed SSH login attempt\",
      \"source_system\": \"ssh_server\"
    }"
  sleep 1
done

# Check Alerts tab - should see "SSH Brute Force Attack Detected"
```

### Test 2: SQL Injection Detection

```bash
curl -X POST http://localhost:8000/api/events \
  -H "Content-Type: application/json" \
  -d '{
    "timestamp": "2024-01-15T10:30:45Z",
    "source_ip": "203.0.113.50",
    "destination_ip": "10.0.0.10",
    "destination_port": 443,
    "protocol": "TCP",
    "event_type": "sql_injection",
    "severity": "critical",
    "message": "SQL injection pattern detected: UNION SELECT",
    "source_system": "waf"
  }'

# Check Alerts tab - should see "SQL Injection Attack Detected"
```

### Test 3: Query Events

```bash
# Get all events
curl http://localhost:8000/api/events

# Get critical events only
curl http://localhost:8000/api/events?severity=critical

# Get events from last 24 hours
curl http://localhost:8000/api/events?hours=24

# Get events from specific IP
curl http://localhost:8000/api/events/source/192.168.1.100

# Get event statistics
curl http://localhost:8000/api/events/stats
```

### Test 4: Manage Alerts

```bash
# Get all alerts
curl http://localhost:8000/api/alerts

# Get alert details
curl http://localhost:8000/api/alerts/1

# Acknowledge an alert
curl -X PATCH http://localhost:8000/api/alerts/1 \
  -H "Content-Type: application/json" \
  -d '{
    "status": "acknowledged",
    "acknowledged_by": "analyst@example.com"
  }'

# Get alert statistics
curl http://localhost:8000/api/alerts/stats
```

## Dashboard Features

### Overview Tab
- **KPI Cards**: Total events, critical alerts, threats blocked, uptime
- **Event Timeline**: Events over last 30 minutes
- **Threat Gauge**: Current threat level (0-100)
- **Top Attackers**: Source IPs with most events

### Live Events Tab
- **Real-time Stream**: All incoming events
- **Filtering**: By severity, source IP, event type
- **Search**: Full-text search in messages
- **Auto-refresh**: Toggle to pause/resume

### Threat Intelligence Tab
- **World Map**: Attack origins with animated pulses
- **CVE Feed**: Latest vulnerabilities
- **Threat Categories**: Event distribution by type

### Network Monitor Tab
- **Traffic Chart**: Network traffic over time
- **Protocol Distribution**: Pie chart of protocols
- **Port Scans**: Detected port scan attempts
- **Network Health**: Status of security systems

### Alerts & Incidents Tab
- **Active Alerts**: Alert cards with details
- **Incident Timeline**: Chronological incident history
- **Acknowledgment**: Mark alerts as reviewed
- **Status Tracking**: Open, investigating, resolved

## Common Tasks

### Add a Correlation Rule

```bash
# Create a new rule via API
curl -X POST http://localhost:8000/api/rules \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Custom Rule",
    "description": "Detect custom pattern",
    "rule_type": "threshold",
    "conditions": "{\"event_type\": \"custom_event\"}",
    "time_window": 300,
    "threshold": 3,
    "alert_severity": "high",
    "alert_title": "Custom Alert",
    "alert_description": "Custom pattern detected"
  }'
```

### Export Events

```bash
# Export as JSON
curl http://localhost:8000/api/events?limit=1000 > events.json

# Export as CSV (requires custom endpoint)
# See DEPLOYMENT.md for implementation
```

### Monitor System Health

```bash
# Check API health
curl http://localhost:8000/health

# Check database
docker-compose exec backend python -c "from database import SessionLocal; db = SessionLocal(); print('DB OK')"

# View logs
docker-compose logs -f backend
```

## Troubleshooting

### Port Already in Use

```bash
# Find process using port 8000
lsof -i :8000

# Kill process
kill -9 <PID>

# Or change port in docker-compose.yml
```

### Database Connection Error

```bash
# Check PostgreSQL is running
docker-compose ps postgres

# Check connection string in .env
cat backend/.env | grep DATABASE_URL

# Restart database
docker-compose restart postgres
```

### No Events Appearing

```bash
# Check syslog receiver is running
docker-compose logs backend | grep -i syslog

# Test syslog connectivity
echo "test" | nc -u localhost 514

# Check firewall
sudo ufw status
```

### High Memory Usage

```bash
# Check container memory
docker stats

# Restart services
docker-compose restart

# Reduce log retention
# Edit correlation_engine.py to archive old events
```

## Next Steps

1. **Configure Real Log Sources**
   - Set up syslog forwarding from firewalls
   - Configure IDS/IPS to send alerts
   - Enable application logging

2. **Customize Correlation Rules**
   - Review default rules in database
   - Create rules for your environment
   - Test with sample events

3. **Set Up Alerting**
   - Configure email notifications
   - Set up Slack integration
   - Create incident response playbooks

4. **Deploy to Production**
   - Follow [DEPLOYMENT.md](./DEPLOYMENT.md)
   - Configure SSL/TLS
   - Set up backups and monitoring

5. **Learn More**
   - Read [README.md](./README.md) for full documentation
   - Check [API documentation](http://localhost:8000/docs)
   - Review correlation rules in database

## Support

- **API Docs**: http://localhost:8000/docs
- **GitHub Issues**: Report bugs and request features
- **Documentation**: See README.md and DEPLOYMENT.md

---

**Happy monitoring! 🛡️**
