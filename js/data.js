/* ============================================================
   data.js — SIEM_DATA, Auth, LiveFeed
   Provides mock/demo data + API fetch wrappers + auth helpers
   + WebSocket live feed stub with simulated fallback.
   ============================================================ */

/* ── Config ──────────────────────────────────────────────── */
// Detect whether we're being served through a reverse proxy (nginx on port 80/443)
// or hitting the backend directly (dev mode on port 8000).
// This means the same build works both locally and in Docker without changes.
const _isDev = window.location.port === '8000' || window.location.protocol === 'file:';
const API_BASE = _isDev
  ? 'http://localhost:8000/api'
  : `${window.location.protocol}//${window.location.host}/api`;
const WS_URL = _isDev
  ? 'ws://localhost:8000/ws/events'
  : `${window.location.protocol === 'https:' ? 'wss' : 'ws'}://${window.location.host}/ws/events`;

/* ============================================================
   AUTH
   Manages login token, username and role stored in localStorage.
   ============================================================ */
const Auth = (function () {
  const TOKEN_KEY    = 'cw_token';
  const USERNAME_KEY = 'cw_username';
  const ROLE_KEY     = 'cw_role';

  function getToken()    { return localStorage.getItem(TOKEN_KEY); }
  function getUsername() { return localStorage.getItem(USERNAME_KEY) || 'analyst'; }
  function getRole()     { return localStorage.getItem(ROLE_KEY)    || 'SOC Analyst'; }
  function isLoggedIn()  { return !!getToken(); }

  function login(username, password) {
    /* In demo mode, accept any non-empty credentials */
    if (!username || !password) return false;
    localStorage.setItem(TOKEN_KEY,    'demo_token_' + Date.now());
    localStorage.setItem(USERNAME_KEY, username);
    localStorage.setItem(ROLE_KEY,     username.toLowerCase() === 'admin' ? 'Administrator' : 'SOC Analyst');
    return true;
  }

  function logout() {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USERNAME_KEY);
    localStorage.removeItem(ROLE_KEY);
    window.location.href = 'login.html';
  }

  return { getToken, getUsername, getRole, isLoggedIn, login, logout };
})();


/* ============================================================
   LIVE FEED  (WebSocket with demo-simulation fallback)
   ============================================================ */
const LiveFeed = (function () {
  let _ws        = null;
  let _handlers  = [];
  let _simTimer  = null;

  function connect() {
    try {
      _ws = new WebSocket(WS_URL);
      _ws.onopen    = () => {};
      _ws.onmessage = (ev) => {
        try {
          const msg = JSON.parse(ev.data);
          _handlers.forEach(h => h(msg));
        } catch (_e) {}
      };
      _ws.onerror = () => _startSimulation();
      _ws.onclose = () => _startSimulation();
    } catch (_e) {
      _startSimulation();
    }
  }

  function _startSimulation() {
    if (_simTimer) return;
    _simTimer = setInterval(() => {
      const e = SIEM_DATA.generateEvent();
      const msg = {
        type:           'event',
        id:             Math.floor(Math.random() * 999999),
        timestamp:      new Date().toISOString(),
        severity:       e.severity,
        source_ip:      e.src,
        destination_ip: e.dst,
        event_type:     e.type.replace(/ /g, '_'),
        protocol:       e.protocol,
      };
      _handlers.forEach(h => h(msg));
      if (Math.random() < 0.08) {
        _handlers.forEach(h => h({ type: 'alert' }));
      }
    }, 3000);
  }

  function onMessage(handler) {
    if (typeof handler === 'function') _handlers.push(handler);
  }

  function disconnect() {
    if (_ws) { try { _ws.close(); } catch (_e) {} }
    if (_simTimer) { clearInterval(_simTimer); _simTimer = null; }
    _handlers = [];
  }

  return { connect, onMessage, disconnect };
})();


/* ============================================================
   SIEM_DATA  — static datasets + helpers + API fetch wrappers
   ============================================================ */
const SIEM_DATA = (function () {

  /* ── Internal KPI state ──────────────────────────────────── */
  let _kpi = {
    total:    12847,
    critical: 62,
    blocked:  3247,
    uptime:   99.7,
  };

  /* ── Utility helpers ─────────────────────────────────────── */
  function rand(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
  }

  function pick(arr) {
    return arr[Math.floor(Math.random() * arr.length)];
  }

  function randIp() {
    const r = Math.random();
    if (r < 0.33) return rand(1,254)+'.'+rand(0,255)+'.'+rand(0,255)+'.'+rand(1,254);
    if (r < 0.66) return '10.'+rand(0,255)+'.'+rand(0,255)+'.'+rand(1,254);
    return '192.168.'+rand(0,10)+'.'+rand(1,254);
  }

  function nowTimestamp() {
    const d = new Date(), p = n => String(n).padStart(2,'0');
    return p(d.getHours())+':'+p(d.getMinutes())+':'+p(d.getSeconds());
  }

  function randomSeverity() {
    const r = Math.random();
    if (r < 0.08) return 'critical';
    if (r < 0.28) return 'high';
    if (r < 0.62) return 'medium';
    return 'low';
  }

  /* ── Static datasets ─────────────────────────────────────── */
  const COUNTRIES = [
    { name:'Russia',        code:'RU', x:580, y: 90 },
    { name:'China',         code:'CN', x:720, y:130 },
    { name:'United States', code:'US', x:160, y:130 },
    { name:'Iran',          code:'IR', x:590, y:155 },
    { name:'North Korea',   code:'NK', x:755, y:130 },
    { name:'Brazil',        code:'BR', x:230, y:270 },
    { name:'Germany',       code:'DE', x:490, y: 90 },
    { name:'India',         code:'IN', x:650, y:175 },
    { name:'Ukraine',       code:'UA', x:545, y: 95 },
    { name:'Netherlands',   code:'NL', x:470, y: 82 },
    { name:'Romania',       code:'RO', x:528, y: 98 },
    { name:'Vietnam',       code:'VN', x:720, y:185 },
  ];

  const EVENT_TYPES = [
    'SSH Brute Force', 'SQL Injection', 'Port Scan', 'DDoS Attack',
    'Malware Download', 'Phishing Attempt', 'RCE Exploit', 'XSS Attack',
    'Credential Stuffing', 'DNS Tunneling', 'ARP Spoofing', 'MITM Attack',
    'Ransomware Activity', 'Data Exfiltration', 'Privilege Escalation',
    'Lateral Movement', 'C2 Beacon', 'Zero-Day Exploit',
  ];

  const PROTOCOLS = ['TCP','UDP','ICMP','HTTP','HTTPS','DNS','SSH','FTP','SMTP'];

  const PORTS = [22,80,443,3389,8080,8443,21,25,53,3306,5432,6379,27017,445,139];

  const CVE_FEED = [
    { id:'CVE-2024-3400',  score:'10.0', severity:'critical', desc:'PAN-OS: OS Command Injection in GlobalProtect Gateway' },
    { id:'CVE-2024-21762', score:'9.8',  severity:'critical', desc:'Fortinet FortiOS out-of-bounds write in SSL-VPN' },
    { id:'CVE-2024-1709',  score:'9.8',  severity:'critical', desc:'ConnectWise ScreenConnect authentication bypass' },
    { id:'CVE-2024-27198', score:'9.8',  severity:'critical', desc:'JetBrains TeamCity authentication bypass via alternate path' },
    { id:'CVE-2023-46805', score:'8.2',  severity:'high',     desc:'Ivanti Connect Secure authentication bypass in web component' },
    { id:'CVE-2024-20353', score:'8.6',  severity:'high',     desc:'Cisco ASA & FTD denial of service via crafted HTTP request' },
    { id:'CVE-2024-22024', score:'8.3',  severity:'high',     desc:'Ivanti Connect Secure XXE vulnerability in SAML component' },
    { id:'CVE-2024-6387',  score:'8.1',  severity:'high',     desc:'OpenSSH regreSSHion race condition in signal handler' },
    { id:'CVE-2024-38094', score:'7.2',  severity:'medium',   desc:'Microsoft SharePoint remote code execution' },
    { id:'CVE-2024-30051', score:'7.8',  severity:'medium',   desc:'Windows DWM Core Library privilege escalation' },
  ];

  const PORT_SCAN_TARGETS = [
    { target:'10.0.0.5',   service:'SSH / OpenSSH 8.9',       ports:'22, 2222, 22222' },
    { target:'10.0.0.10',  service:'HTTP / Apache 2.4',        ports:'80, 8080, 8000' },
    { target:'10.0.0.15',  service:'DB / PostgreSQL 15',       ports:'5432, 5433' },
    { target:'10.0.0.20',  service:'RDP / Windows Server',     ports:'3389, 3390' },
    { target:'10.0.0.25',  service:'SMTP / Postfix',           ports:'25, 465, 587' },
    { target:'10.0.0.30',  service:'DNS / BIND 9',             ports:'53' },
    { target:'10.0.0.50',  service:'SMB / Windows File Share', ports:'445, 139, 137' },
    { target:'10.0.0.100', service:'Redis / NoSQL Cache',      ports:'6379, 6380' },
  ];

  /* ── KPI helpers ─────────────────────────────────────────── */
  function updateKPI() {
    _kpi.total    += rand(-80, 200);
    _kpi.critical += rand(-3, 5);
    _kpi.blocked  += rand(0, 30);
    _kpi.uptime    = Math.max(98.5, Math.min(100, _kpi.uptime + (Math.random() - 0.5) * 0.05));
    if (_kpi.critical < 0) _kpi.critical = 0;
  }

  function getKPI() { return Object.assign({}, _kpi); }

  /* ── Event generation ────────────────────────────────────── */
  function generateEvent() {
    return {
      id:       rand(100000, 999999),
      time:     nowTimestamp(),
      severity: randomSeverity(),
      src:      randIp(),
      dst:      randIp(),
      type:     pick(EVENT_TYPES),
      protocol: pick(PROTOCOLS),
      port:     pick(PORTS),
    };
  }

  function seedEventHistory(count) {
    return Array.from({ length: count }, () => generateEvent());
  }

  /* ── Chart history ───────────────────────────────────────── */
  function generateChartHistory(points) {
    const now    = new Date();
    const labels = [];
    const data   = { critical:[], high:[], medium:[], low:[] };
    for (let i = points - 1; i >= 0; i--) {
      const t = new Date(now - i * 60000);
      const p = n => String(n).padStart(2,'0');
      labels.push(p(t.getHours())+':'+p(t.getMinutes()));
      data.critical.push(rand(1, 8));
      data.high.push(rand(5, 20));
      data.medium.push(rand(12, 40));
      data.low.push(rand(20, 60));
    }
    return { labels, data };
  }

  /* ── Traffic history ─────────────────────────────────────── */
  function generateTrafficHistory(points) {
    return Array.from({ length: points }, () => rand(120, 480));
  }

  function generateTrafficPoint() {
    return rand(80, 520);
  }

  /* ── API fetch wrappers (return null on failure = demo mode) */
  async function _apiFetch(path) {
    try {
      const token = Auth.getToken();
      const headers = token ? { 'Authorization': 'Bearer ' + token } : {};
      const res = await fetch(API_BASE + path, { headers: headers });
      if (!res.ok) return null;
      return await res.json();
    } catch (_e) {
      return null;
    }
  }

  async function fetchDashboard(hours) {
    return _apiFetch('/dashboard/summary?hours=' + (hours || 24));
  }

  async function fetchEventStats(hours) {
    return _apiFetch('/events/stats?hours=' + (hours || 24));
  }

  async function fetchEvents(hours, severity, limit) {
    let path = '/events?hours=' + (hours || 24) + '&limit=' + (limit || 200);
    if (severity) path += '&severity=' + severity;
    return _apiFetch(path);
  }

  async function fetchAlerts(status, limit) {
    return _apiFetch('/alerts?status=' + (status || 'open') + '&limit=' + (limit || 50));
  }

  async function fetchIncidents(status, limit) {
    return _apiFetch('/incidents?status=' + (status || 'open') + '&limit=' + (limit || 20));
  }

  async function updateAlertStatus(id, status, username) {
    try {
      const token = Auth.getToken();
      const headers = { 'Content-Type': 'application/json' };
      if (token) headers['Authorization'] = 'Bearer ' + token;
      await fetch(API_BASE + '/alerts/' + id, {
        method:  'PATCH',
        headers: headers,
        body:    JSON.stringify({ status: status, acknowledged_by: username || '' }),
      });
    } catch (_e) {}
    return true;  // always optimistic in demo mode
  }

  /* ── Public API ──────────────────────────────────────────── */
  return {
    rand,
    pick,
    randIp,
    nowTimestamp,
    randomSeverity,
    COUNTRIES,
    EVENT_TYPES,
    PROTOCOLS,
    CVE_FEED,
    PORT_SCAN_TARGETS,
    updateKPI,
    getKPI,
    generateEvent,
    seedEventHistory,
    generateChartHistory,
    generateTrafficHistory,
    generateTrafficPoint,
    fetchDashboard,
    fetchEventStats,
    fetchEvents,
    fetchAlerts,
    fetchIncidents,
    updateAlertStatus,
  };
})();

// CVE data sourced from NVD - National Vulnerability Database
