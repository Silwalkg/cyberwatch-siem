# WebSocket API

Connect to: ws://localhost:8000/ws/events

## Message Types

### Event Message
```json
{
  "type": "event",
  "id": 12345,
  "timestamp": "2026-06-10T10:00:00",
  "severity": "high",
  "source_ip": "192.168.1.100",
  "destination_ip": "10.0.0.5",
  "event_type": "SSH_Brute_Force",
  "protocol": "TCP"
}
```n
### Alert Message
```json
{
  "type": "alert"
}
```
