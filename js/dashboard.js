/* ============================================================
   dashboard.js � Core App Logic, Page Router, Charts, Live Feed
   Connects to real backend API with demo fallback.
   ============================================================ */

(function () {
  'use strict';

  // -- Auth guard � redirect to login if no token ------------
  if (!localStorage.getItem('cw_token') && !window.location.pathname.includes('login')) {
    window.location.href = 'login.html';
    return;
  }

  // -- State -------------------------------------------------
  let currentPage     = 'overview';
  let autoRefresh     = true;
  let alertBadgeCount = 0;
  let events          = SIEM_DATA.seedEventHistory(80);   // demo seed
  let trafficHistory  = SIEM_DATA.generateTrafficHistory(20);
  let chartHistory    = SIEM_DATA.generateChartHistory(30);
  let charts          = {};
  let filterState     = { search: '', severity: 'all' };
  let acknowledgedAlerts = new Set();
  let liveEventsFromAPI  = [];   // real events from backend
  let usingLiveData      = false;

  // -- Clock -------------------------------------------------
  function updateClock() {
    const d = new Date(), pad = n => String(n).padStart(2,'0');
    const el = document.getElementById('clock');
    if (el) el.textContent =
      `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}  ` +
      `${d.toLocaleDateString('en-US',{day:'2-digit',month:'short',year:'numeric'})}`;
  }

  // -- User info in header -----------------------------------
  function renderUserInfo() {
    const username = Auth.getUsername();
    const role     = Auth.getRole();
    const el = document.getElementById('user-info');
    if (el) el.innerHTML =
      `<span style="color:#c8daf0;font-size:11px;font-weight:600;margin-right:8px;">
         ${username} <span style="color:var(--neon-blue);font-weight:700;">[${role}]</span>
       </span>
       <button class="btn btn-ghost" style="font-size:11px;padding:4px 10px;color:#c8daf0;font-weight:600;" onclick="Auth.logout()">
         Sign Out
       </button>`;
  }

  // -- Navigation --------------------------------------------
  function navigateTo(pageId) {
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    const page = document.getElementById('page-' + pageId);
    const nav  = document.querySelector(`.nav-item[data-page="${pageId}"]`);
    if (page) page.classList.add('active');
    if (nav)  nav.classList.add('active');
    const titles = { overview:'Overview', events:'Live Events Feed', threats:'Threat Intelligence', network:'Network Monitor', alerts:'Alerts & Incidents' };
    const subs   = { overview:'Real-time security posture', events:'Live log stream with filtering', threats:'Global threat landscape', network:'Traffic & protocol analysis', alerts:'Active incidents & response' };
    document.getElementById('header-title').textContent    = titles[pageId] || pageId;
    document.getElementById('header-subtitle').textContent = subs[pageId]   || '';
    currentPage = pageId;
    if (pageId === 'overview') { initOverviewCharts(); refreshOverview(); }
    if (pageId === 'threats')  { initThreatCharts(); renderWorldMap(); }
    if (pageId === 'network')  initNetworkCharts();
    if (pageId === 'events')   { loadLiveEvents(); renderEventLog(); }
    if (pageId === 'alerts')   loadAlertsPage();
  }

  // -- Overview: fetch real KPIs -----------------------------
  async function refreshOverview() {
    const data = await SIEM_DATA.fetchDashboard(24);
    if (!data) { updateKPICards(); return; }
    usingLiveData = true;

    const set = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
    set('kpi-total',    data.total_events.toLocaleString());
    set('kpi-critical', data.critical_alerts.toLocaleString());
    set('kpi-blocked',  data.open_incidents.toLocaleString());
    set('kpi-uptime',   '99.9%');

    // Update alert badge
    alertBadgeCount = data.open_alerts;
    const badge = document.getElementById('alert-badge');
    if (badge) { badge.textContent = alertBadgeCount; badge.style.display = alertBadgeCount > 0 ? '' : 'none'; }

    // Top attackers from real data
    if (data.top_source_ips && data.top_source_ips.length) renderTopAttackersFromAPI(data.top_source_ips);
    else renderTopAttackers();

    // Update gauge based on critical ratio
    const ratio = data.total_events > 0 ? Math.round((data.critical_events / data.total_events) * 100) : 0;
    updateGauge(Math.min(100, Math.max(10, ratio * 10)));
  }

  // -- KPI Cards (demo fallback) -----------------------------
  function updateKPICards() {
    SIEM_DATA.updateKPI();
    const kpi = SIEM_DATA.getKPI();
    const set = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
    set('kpi-total',    kpi.total.toLocaleString());
    set('kpi-critical', kpi.critical.toLocaleString());
    set('kpi-blocked',  kpi.blocked.toLocaleString());
    set('kpi-uptime',   kpi.uptime.toFixed(1) + '%');
  }

  // -- Gauge -------------------------------------------------
  function updateGauge(value) {
    const gaugeArc   = document.getElementById('gauge-arc');
    const gaugeVal   = document.getElementById('gauge-value-text');
    const gaugeLevel = document.getElementById('gauge-level-text');
    if (!gaugeArc) return;
    const maxLen = 220, dashLen = (value / 100) * maxLen;
    gaugeArc.style.strokeDasharray = `${dashLen} ${maxLen}`;
    let color, level;
    if (value >= 80)      { color = '#ff3366'; level = 'CRITICAL'; }
    else if (value >= 60) { color = '#ff8c42'; level = 'HIGH'; }
    else if (value >= 40) { color = '#ffd60a'; level = 'MEDIUM'; }
    else                  { color = '#00d4ff'; level = 'LOW'; }
    gaugeArc.style.stroke = color;
    if (gaugeVal)   { gaugeVal.textContent = value; gaugeVal.style.color = color; }
    if (gaugeLevel) { gaugeLevel.textContent = level; gaugeLevel.style.color = color; }
  }

  // -- Overview Charts ---------------------------------------
  function initOverviewCharts() {
    if (charts.eventsLine) return;
    const lineCtx = document.getElementById('chart-events-line');
    if (lineCtx) {
      charts.eventsLine = new Chart(lineCtx, {
        type: 'line',
        data: {
          labels: chartHistory.labels,
          datasets: [
            { label:'Critical', data:chartHistory.data.critical, borderColor:'#ff3366', backgroundColor:'rgba(255,51,102,0.08)',  tension:0.4, borderWidth:2, pointRadius:0 },
            { label:'High',     data:chartHistory.data.high,     borderColor:'#ff8c42', backgroundColor:'rgba(255,140,66,0.08)', tension:0.4, borderWidth:2, pointRadius:0 },
            { label:'Medium',   data:chartHistory.data.medium,   borderColor:'#ffd60a', backgroundColor:'rgba(255,214,10,0.06)', tension:0.4, borderWidth:1.5, pointRadius:0 },
            { label:'Low',      data:chartHistory.data.low,      borderColor:'#00d4ff', backgroundColor:'rgba(0,212,255,0.05)',  tension:0.4, borderWidth:1.5, pointRadius:0 },
          ],
        },
        options: {
          responsive:true, maintainAspectRatio:false, animation:{duration:400},
          plugins:{ legend:{ labels:{ color:'#8899bb', font:{size:11}, boxWidth:12 } } },
          scales:{
            x:{ ticks:{color:'#4a5a7a',font:{size:10},maxTicksLimit:8}, grid:{color:'rgba(255,255,255,0.03)'} },
            y:{ ticks:{color:'#4a5a7a',font:{size:10}}, grid:{color:'rgba(255,255,255,0.04)'} },
          },
        },
      });
    }
    const donutCtx = document.getElementById('chart-severity-donut');
    if (donutCtx) {
      charts.severityDonut = new Chart(donutCtx, {
        type: 'doughnut',
        data: {
          labels: ['Critical','High','Medium','Low'],
          datasets:[{ data:[62,218,489,842], backgroundColor:['rgba(255,51,102,0.8)','rgba(255,140,66,0.8)','rgba(255,214,10,0.7)','rgba(0,212,255,0.7)'], borderColor:['#ff3366','#ff8c42','#ffd60a','#00d4ff'], borderWidth:1, hoverOffset:8 }],
        },
        options:{ responsive:true, maintainAspectRatio:false, cutout:'70%', plugins:{ legend:{ position:'right', labels:{color:'#8899bb',font:{size:11},boxWidth:12,padding:12} } }, animation:{animateRotate:true,duration:600} },
      });
    }
  }

  // Update donut chart with real severity counts
  async function refreshSeverityDonut() {
    const stats = await SIEM_DATA.fetchEventStats(24);
    if (!stats || !charts.severityDonut) return;
    charts.severityDonut.data.datasets[0].data = [
      stats.critical_events || 0,
      stats.high_events     || 0,
      stats.medium_events   || 0,
      stats.low_events      || 0,
    ];
    charts.severityDonut.update();
  }

  // -- Top Attackers -----------------------------------------
  function renderTopAttackersFromAPI(topIPs) {
    const tbody = document.getElementById('top-attackers-body');
    if (!tbody) return;
    tbody.innerHTML = topIPs.map((item, i) => `
      <tr>
        <td style="color:var(--text-muted);font-family:var(--font-mono);font-size:11px;">#${i+1}</td>
        <td class="ip-code">${item.ip || '�'}</td>
        <td style="font-size:12px;color:var(--text-secondary);">�</td>
        <td><span class="badge badge-high">high</span></td>
        <td style="font-size:12px;color:var(--text-secondary);">Multiple</td>
        <td class="count-num">${item.count.toLocaleString()}</td>
      </tr>
    `).join('');
  }

  function renderTopAttackers() {
    const tbody = document.getElementById('top-attackers-body');
    if (!tbody) return;
    const attackers = SIEM_DATA.COUNTRIES.slice(0,6).map(c => ({
      ip: SIEM_DATA.randIp(), country: c.name,
      count: SIEM_DATA.rand(120,2400), severity: SIEM_DATA.randomSeverity(),
      type: SIEM_DATA.pick(['Brute Force','SQL Injection','Port Scan','DDoS','Exploit']),
    })).sort((a,b) => b.count - a.count);
    tbody.innerHTML = attackers.map((a,i) => `
      <tr>
        <td style="color:var(--text-muted);font-family:var(--font-mono);font-size:11px;">#${i+1}</td>
        <td class="ip-code">${a.ip}</td>
        <td style="font-size:12px;color:var(--text-secondary);">${a.country}</td>
        <td><span class="badge badge-${a.severity}">${a.severity}</span></td>
        <td style="font-size:12px;color:var(--text-secondary);">${a.type}</td>
        <td class="count-num">${a.count.toLocaleString()}</td>
      </tr>
    `).join('');
  }

  // -- Live Events Page --------------------------------------
  async function loadLiveEvents() {
    const sev = filterState.severity !== 'all' ? filterState.severity : null;
    const apiEvents = await SIEM_DATA.fetchEvents(24, sev, 200);
    if (apiEvents && apiEvents.length > 0) {
      liveEventsFromAPI = apiEvents.map(e => ({
        id:       e.id,
        time:     new Date(e.timestamp).toLocaleTimeString('en-US',{hour12:false}),
        severity: e.severity,
        src:      e.source_ip,
        dst:      e.destination_ip || '�',
        type:     e.event_type.replace(/_/g,' '),
        protocol: e.protocol || '�',
        port:     e.destination_port || '�',
      }));
      usingLiveData = true;
    }
    renderEventLog();
  }

  function renderEventLog() {
    const container = document.getElementById('event-log-rows');
    if (!container) return;
    const source = (usingLiveData && liveEventsFromAPI.length) ? liveEventsFromAPI : [...events].reverse();
    let filtered = [...source];
    if (filterState.search) {
      const q = filterState.search.toLowerCase();
      filtered = filtered.filter(e =>
        String(e.src).includes(q) || String(e.dst).includes(q) ||
        String(e.type).toLowerCase().includes(q) ||
        String(e.protocol).toLowerCase().includes(q)
      );
    }
    if (filterState.severity !== 'all') filtered = filtered.filter(e => e.severity === filterState.severity);
    filtered = filtered.slice(0, 100);
    container.innerHTML = filtered.length ? filtered.map(e => `
      <div class="event-row ${e.severity}">
        <span class="event-time">${e.time}</span>
        <span class="badge badge-${e.severity}">${e.severity[0].toUpperCase()}</span>
        <span class="event-src">${e.src}</span>
        <span class="event-dst">${e.dst}</span>
        <span class="event-desc">${e.type}</span>
        <span class="event-type">${e.protocol}/${e.port}</span>
      </div>
    `).join('') : `<div class="empty-state">No events match the current filter</div>`;
  }

  function addNewEvent() {
    const e = SIEM_DATA.generateEvent();
    events.push(e);
    if (events.length > 500) events.shift();
    if (currentPage === 'events' && autoRefresh && !usingLiveData) renderEventLog();
    if (charts.eventsLine && currentPage === 'overview') {
      const ds = charts.eventsLine.data.datasets;
      charts.eventsLine.data.labels.push(SIEM_DATA.nowTimestamp());
      charts.eventsLine.data.labels.shift();
      const sev = e.severity;
      ds[0].data.push(sev==='critical'?1:0); ds[0].data.shift();
      ds[1].data.push(sev==='high'?1:0);     ds[1].data.shift();
      ds[2].data.push(sev==='medium'?1:0);   ds[2].data.shift();
      ds[3].data.push(sev==='low'?1:0);      ds[3].data.shift();
      charts.eventsLine.update('none');
    }
  }

  // -- Threat Intelligence Page ------------------------------
  function initThreatCharts() {
    if (charts.threatBar) return;
    const ctx = document.getElementById('chart-threat-categories');
    if (!ctx) return;
    charts.threatBar = new Chart(ctx, {
      type: 'bar',
      data: {
        labels: ['Brute Force','SQL Injection','Port Scan','Malware','Phishing','DDoS','RCE','XSS'],
        datasets:[{ label:'Events (Last 24h)', data:[842,614,589,421,318,256,198,147],
          backgroundColor:['rgba(255,51,102,0.7)','rgba(255,140,66,0.7)','rgba(255,214,10,0.6)','rgba(180,77,255,0.7)','rgba(0,212,255,0.6)','rgba(255,51,102,0.5)','rgba(255,140,66,0.5)','rgba(0,255,157,0.5)'],
          borderRadius:6, borderSkipped:false }],
      },
      options:{ responsive:true, maintainAspectRatio:false, animation:{duration:600},
        plugins:{legend:{display:false}},
        scales:{ x:{ticks:{color:'#8899bb',font:{size:11}},grid:{display:false}}, y:{ticks:{color:'#4a5a7a',font:{size:11}},grid:{color:'rgba(255,255,255,0.04)'}} } },
    });
  }

  function renderCVEFeed() {
    const el = document.getElementById('cve-feed');
    if (!el) return;
    el.innerHTML = SIEM_DATA.CVE_FEED.map(c => `
      <div class="cve-item">
        <div><div class="cve-score ${c.severity}">${c.score}</div></div>
        <div class="cve-body"><div class="cve-id">${c.id}</div><div class="cve-desc">${c.desc}</div></div>
        <span class="badge badge-${c.severity}">${c.severity}</span>
      </div>
    `).join('');
  }

  function renderWorldMap() {
    const container = document.getElementById('world-map-svg-container');
    if (!container || container.dataset.rendered) return;
    container.dataset.rendered = '1';
    const svg = document.getElementById('world-map-svg');
    if (!svg) return;
    const colors = { critical:'#ff3366', high:'#ff8c42', medium:'#ffd60a', low:'#00d4ff' };
    SIEM_DATA.COUNTRIES.forEach((c,i) => {
      const sev = SIEM_DATA.randomSeverity(), color = colors[sev], count = SIEM_DATA.rand(80,2400);
      const pulse = document.createElementNS('http://www.w3.org/2000/svg','circle');
      pulse.setAttribute('cx',c.x); pulse.setAttribute('cy',c.y); pulse.setAttribute('r',4);
      pulse.setAttribute('fill',color); pulse.setAttribute('opacity','0.6');
      pulse.style.animationDelay = `${(i*0.3)%2}s`; pulse.classList.add('attack-pulse');
      svg.appendChild(pulse);
      const dot = document.createElementNS('http://www.w3.org/2000/svg','circle');
      dot.setAttribute('cx',c.x); dot.setAttribute('cy',c.y); dot.setAttribute('r',4);
      dot.setAttribute('fill',color); dot.style.filter = `drop-shadow(0 0 4px ${color})`;
      svg.appendChild(dot);
      const text = document.createElementNS('http://www.w3.org/2000/svg','text');
      text.setAttribute('x',c.x+7); text.setAttribute('y',c.y+4); text.setAttribute('fill','#8899bb');
      text.setAttribute('font-size','9'); text.setAttribute('font-family','Inter,sans-serif');
      text.textContent = `${c.code} ${count}`; svg.appendChild(text);
    });
    const target = {x:180,y:180};
    SIEM_DATA.COUNTRIES.slice(0,5).forEach(c => {
      const line = document.createElementNS('http://www.w3.org/2000/svg','line');
      line.setAttribute('x1',c.x); line.setAttribute('y1',c.y);
      line.setAttribute('x2',target.x); line.setAttribute('y2',target.y);
      line.setAttribute('stroke','rgba(255,51,102,0.12)'); line.setAttribute('stroke-width','1');
      line.setAttribute('stroke-dasharray','4,4'); svg.insertBefore(line,svg.firstChild);
    });
  }

  // -- Network Monitor ---------------------------------------
  function initNetworkCharts() {
    if (charts.trafficLine) return;
    const lineCtx = document.getElementById('chart-traffic');
    if (lineCtx) {
      charts.trafficLine = new Chart(lineCtx, {
        type:'line',
        data:{ labels:Array.from({length:20},(_,i)=>`T-${20-i}`), datasets:[{ label:'Mbps', data:trafficHistory, borderColor:'#00d4ff', backgroundColor:'rgba(0,212,255,0.08)', tension:0.4, borderWidth:2, pointRadius:0, fill:true }] },
        options:{ responsive:true, maintainAspectRatio:false, animation:{duration:200}, plugins:{legend:{display:false}}, scales:{ x:{display:false}, y:{ticks:{color:'#4a5a7a',font:{size:10}},grid:{color:'rgba(255,255,255,0.04)'}} } },
      });
    }
    const pieCtx = document.getElementById('chart-protocols');
    if (pieCtx) {
      charts.protocolPie = new Chart(pieCtx, {
        type:'doughnut',
        data:{ labels:['HTTPS','HTTP','DNS','SSH','TCP','UDP','Other'], datasets:[{ data:[38,21,15,9,7,6,4], backgroundColor:['rgba(0,212,255,0.7)','rgba(0,255,157,0.7)','rgba(180,77,255,0.7)','rgba(255,140,66,0.7)','rgba(255,214,10,0.6)','rgba(255,51,102,0.6)','rgba(136,153,187,0.5)'], borderWidth:1, hoverOffset:6 }] },
        options:{ responsive:true, maintainAspectRatio:false, cutout:'65%', plugins:{legend:{position:'right',labels:{color:'#8899bb',font:{size:11},boxWidth:10,padding:10}}} },
      });
    }
  }

  function updateTrafficChart() {
    if (!charts.trafficLine) return;
    const point = SIEM_DATA.generateTrafficPoint();
    trafficHistory.push(point); trafficHistory.shift();
    charts.trafficLine.data.datasets[0].data = [...trafficHistory];
    charts.trafficLine.update('none');
    const el = document.getElementById('traffic-current');
    if (el) el.textContent = point;
  }

  function renderProtocolBars() {
    const container = document.getElementById('proto-bars');
    if (!container) return;
    const protos = [{name:'HTTPS',pct:38,color:'#00d4ff'},{name:'HTTP',pct:21,color:'#00ff9d'},{name:'DNS',pct:15,color:'#b44dff'},{name:'SSH',pct:9,color:'#ff8c42'},{name:'UDP',pct:6,color:'#ffd60a'},{name:'Other',pct:11,color:'#4a5a7a'}];
    container.innerHTML = protos.map(p => `
      <div class="proto-bar-wrap">
        <div class="proto-bar-label">
          <span style="color:var(--text-secondary);font-size:12px;">${p.name}</span>
          <span style="color:var(--text-muted);font-family:var(--font-mono);font-size:11px;">${p.pct}%</span>
        </div>
        <div class="proto-bar-track"><div class="proto-bar-fill" style="width:${p.pct}%;background:${p.color};box-shadow:0 0 6px ${p.color}40;"></div></div>
      </div>
    `).join('');
  }

  function renderPortScans() {
    const tbody = document.getElementById('port-scan-body');
    if (!tbody) return;
    tbody.innerHTML = SIEM_DATA.PORT_SCAN_TARGETS.map(p => `
      <tr>
        <td class="ip-code">${p.target}</td>
        <td style="font-size:12px;color:var(--text-secondary);">${p.service}</td>
        <td style="font-family:var(--font-mono);color:var(--neon-orange);font-size:12px;">${p.ports}</td>
        <td><span class="badge badge-${SIEM_DATA.randomSeverity()}">${SIEM_DATA.randomSeverity()}</span></td>
        <td style="font-size:11px;color:var(--text-muted);">${SIEM_DATA.nowTimestamp()}</td>
      </tr>
    `).join('');
  }

  // -- Alerts Page (live from API) ---------------------------
  async function loadAlertsPage() {
    const [apiAlerts, apiIncidents] = await Promise.all([
      SIEM_DATA.fetchAlerts('open', 50),
      SIEM_DATA.fetchIncidents('open', 20),
    ]);
    renderAlertsFromAPI(apiAlerts);
    renderTimelineFromAPI(apiIncidents);
  }

  function renderAlertsFromAPI(apiAlerts) {
    const container = document.getElementById('alerts-list');
    if (!container) return;
    if (!apiAlerts || apiAlerts.length === 0) {
      container.innerHTML = '<div class="empty-state" style="padding:24px;text-align:center;color:var(--text-muted);">No open alerts</div>';
      return;
    }
    container.innerHTML = apiAlerts.map(a => {
      const icons = { critical:'??', high:'??', medium:'??', low:'??', info:'?' };
      const icon  = icons[a.severity] || '?';
      const ackd  = a.status === 'acknowledged';
      return `
        <div class="alert-card ${a.severity} ${ackd ? 'acknowledged' : ''}" id="alert-card-${a.id}">
          <div class="alert-icon">${icon}</div>
          <div class="alert-body">
            <div class="alert-title">${a.title}</div>
            <div class="alert-desc">${a.description}</div>
            <div class="alert-meta">Alert #${a.id} &middot; ${new Date(a.created_at).toLocaleString()}</div>
            <div class="alert-actions">
              <button class="btn btn-success" onclick="acknowledgeAlert(${a.id})" id="ack-btn-${a.id}" ${ackd ? 'disabled' : ''}>
                ${ackd ? '? Acknowledged' : '? Acknowledge'}
              </button>
              <button class="btn btn-ghost" onclick="resolveAlert(${a.id})">? Resolve</button>
              <span class="badge badge-${a.severity}" style="margin-left:auto;">${a.severity}</span>
            </div>
          </div>
        </div>
      `;
    }).join('');
  }

  function renderTimelineFromAPI(apiIncidents) {
    const container = document.getElementById('incident-timeline');
    if (!container) return;
    if (!apiIncidents || apiIncidents.length === 0) {
      container.innerHTML = '<div style="padding:16px;color:var(--text-muted);font-size:12px;">No open incidents</div>';
      return;
    }
    container.innerHTML = apiIncidents.map(inc => `
      <div class="timeline-item">
        <div class="timeline-dot ${inc.severity}"></div>
        <div class="timeline-content">
          <div class="timeline-title">${inc.title}</div>
          <div class="timeline-time">${new Date(inc.created_at).toLocaleString()}</div>
          <div class="timeline-detail">${inc.description || ''} ${inc.source_ip ? '&mdash; Source: ' + inc.source_ip : ''}</div>
        </div>
      </div>
    `).join('');
  }

  window.acknowledgeAlert = async function(id) {
    const result = await SIEM_DATA.updateAlertStatus(id, 'acknowledged', Auth.getUsername());
    if (result) {
      const card = document.getElementById('alert-card-' + id);
      const btn  = document.getElementById('ack-btn-' + id);
      if (card) card.classList.add('acknowledged');
      if (btn)  { btn.textContent = '? Acknowledged'; btn.disabled = true; }
      if (alertBadgeCount > 0) alertBadgeCount--;
      const badge = document.getElementById('alert-badge');
      if (badge) { badge.textContent = alertBadgeCount; if (alertBadgeCount === 0) badge.style.display = 'none'; }
    }
  };

  window.resolveAlert = async function(id) {
    const result = await SIEM_DATA.updateAlertStatus(id, 'resolved');
    if (result) {
      const card = document.getElementById('alert-card-' + id);
      if (card) { card.style.transform = 'translateX(100%)'; card.style.opacity = '0'; card.style.transition = 'all 0.3s ease'; setTimeout(() => card.remove(), 300); }
      if (alertBadgeCount > 0) alertBadgeCount--;
      const badge = document.getElementById('alert-badge');
      if (badge) { badge.textContent = alertBadgeCount; if (alertBadgeCount === 0) badge.style.display = 'none'; }
    }
  };

  // -- WebSocket live push -----------------------------------
  function initWebSocket() {
    LiveFeed.connect();
    LiveFeed.onMessage(function(msg) {
      if (msg.type === 'event') {
        const e = {
          id: msg.id, time: new Date(msg.timestamp).toLocaleTimeString('en-US',{hour12:false}),
          severity: msg.severity, src: msg.source_ip, dst: msg.destination_ip || '-',
          type: (msg.event_type || '').replace(/_/g,' '), protocol: msg.protocol || '-', port: '-',
        };
        liveEventsFromAPI.unshift(e);
        if (liveEventsFromAPI.length > 500) liveEventsFromAPI.pop();
        usingLiveData = true;
        if (currentPage === 'events' && autoRefresh) renderEventLog();
      }
      if (msg.type === 'alert') {
        alertBadgeCount++;
        const badge = document.getElementById('alert-badge');
        if (badge) { badge.textContent = alertBadgeCount; badge.style.display = ''; }
        if (currentPage === 'alerts') loadAlertsPage();
      }
    });
  }

  // -- Auto-Refresh Toggle ----------------------------------
  window.toggleAutoRefresh = function() {
    autoRefresh = !autoRefresh;
    const btn = document.getElementById('auto-refresh-btn');
    if (btn) { btn.classList.toggle('active', autoRefresh); btn.textContent = autoRefresh ? '? Pause Feed' : '? Resume Feed'; }
  };

  // -- Filter Events ----------------------------------------
  window.applyFilter = function() {
    const search = document.getElementById('search-input');
    const sev    = document.getElementById('sev-filter');
    filterState.search   = search ? search.value : '';
    filterState.severity = sev    ? sev.value    : 'all';
    if (currentPage === 'events') loadLiveEvents();
  };

  // -- Main Tick --------------------------------------------
  function tick() {
    updateClock();
    if (currentPage === 'overview' && !usingLiveData) {
      updateKPICards();
      updateGauge(Math.min(100, SIEM_DATA.rand(62, 80)));
    }
    if (currentPage === 'network') updateTrafficChart();
    if (!usingLiveData) addNewEvent();
  }

  // -- Init -------------------------------------------------
  function init() {
    renderUserInfo();
    document.querySelectorAll('.nav-item').forEach(item => {
      item.addEventListener('click', () => { const page = item.dataset.page; if (page) navigateTo(page); });
    });
    navigateTo('overview');
    updateKPICards();
    updateGauge(72);
    renderTopAttackers();
    renderCVEFeed();
    renderProtocolBars();
    renderPortScans();
    initWebSocket();
    setInterval(tick, 2500);
    setInterval(() => { if (currentPage === 'overview') refreshOverview(); }, 30000);
    setInterval(() => { if (currentPage === 'overview') refreshSeverityDonut(); }, 60000);
  }

  document.addEventListener('DOMContentLoaded', init);

})();

// Dashboard v2.0 - Full stack with FastAPI backend
