/**
 * Chronicle Host Behaviour Analysis System — Client Engine & Mock ML Anomaly Detector
 * Supports standalone execution and pywebview bridge
 */

(function () {
  'use strict';

  // State
  const state = {
    events: [],
    alerts: [],
    profiles: {},
    isStreaming: false,
    streamTimer: null,
    activeTab: 'activityTab',
    filterText: '',
    filterEventType: 'ALL',
    filterRiskLevel: 'ALL',
    selectedEvent: null
  };

  // Process Baselines (Simulated Historical Profiles for Linux System)
  const BASELINE_DEFINITIONS = {
    'systemd': {
      comm: 'systemd',
      user: 'root',
      path: '/usr/lib/systemd/systemd',
      avgCpu: 0.2,
      stdCpu: 0.1,
      avgMem: 18.4,
      stdMem: 2.1,
      avgSyscalls: 42,
      typicalEvents: ['fork', 'execve'],
      sampleCount: 14200
    },
    'sshd': {
      comm: 'sshd',
      user: 'root',
      path: '/usr/sbin/sshd',
      avgCpu: 0.4,
      stdCpu: 0.2,
      avgMem: 7.2,
      stdMem: 1.0,
      avgSyscalls: 85,
      typicalEvents: ['socket_connect', 'fork'],
      sampleCount: 8900
    },
    'nginx': {
      comm: 'nginx',
      user: 'www-data',
      path: '/usr/sbin/nginx',
      avgCpu: 1.5,
      stdCpu: 0.8,
      avgMem: 42.0,
      stdMem: 5.5,
      avgSyscalls: 320,
      typicalEvents: ['socket_connect', 'file_modify'],
      sampleCount: 22400
    },
    'bash': {
      comm: 'bash',
      user: 'anurag',
      path: '/bin/bash',
      avgCpu: 0.3,
      stdCpu: 0.4,
      avgMem: 9.8,
      stdMem: 2.0,
      avgSyscalls: 110,
      typicalEvents: ['execve', 'fork'],
      sampleCount: 15600
    },
    'python3': {
      comm: 'python3',
      user: 'anurag',
      path: '/usr/bin/python3',
      avgCpu: 3.2,
      stdCpu: 2.1,
      avgMem: 65.0,
      stdMem: 15.0,
      avgSyscalls: 210,
      typicalEvents: ['execve', 'file_modify'],
      sampleCount: 11200
    },
    'dockerd': {
      comm: 'dockerd',
      user: 'root',
      path: '/usr/bin/dockerd',
      avgCpu: 2.1,
      stdCpu: 1.2,
      avgMem: 145.0,
      stdMem: 20.0,
      avgSyscalls: 450,
      typicalEvents: ['socket_connect', 'fork', 'execve'],
      sampleCount: 18700
    },
    'cron': {
      comm: 'cron',
      user: 'root',
      path: '/usr/sbin/cron',
      avgCpu: 0.1,
      stdCpu: 0.05,
      avgMem: 4.5,
      stdMem: 0.6,
      avgSyscalls: 25,
      typicalEvents: ['fork', 'execve'],
      sampleCount: 6500
    },
    'curl': {
      comm: 'curl',
      user: 'anurag',
      path: '/usr/bin/curl',
      avgCpu: 0.8,
      stdCpu: 0.5,
      avgMem: 12.0,
      stdMem: 3.0,
      avgSyscalls: 190,
      typicalEvents: ['socket_connect'],
      sampleCount: 3400
    }
  };

  // High-Risk Security Anomaly Scenarios
  const ANOMALY_SCENARIOS = [
    {
      comm: 'nginx',
      pid: 3812,
      ppid: 1120,
      user: 'www-data',
      eventType: 'fork',
      cpu: 4.8,
      mem: 54.0,
      syscalls: 890,
      riskScore: 94,
      anomalyType: 'Unauthorized Interactive Shell Spawned',
      mitre: 'T1059.004 (Unix Shell)',
      desc: 'Process "nginx" (web daemon) spawned interactive shell "/bin/bash -i". Historical deviation: nginx has 0 occurrences of spawning shells over 30 days.'
    },
    {
      comm: 'systemd-worker',
      pid: 6814,
      ppid: 1,
      user: 'root',
      eventType: 'execve',
      cpu: 98.6,
      mem: 380.0,
      syscalls: 2450,
      riskScore: 92,
      anomalyType: 'High-Intensity Crypto Mining Behavior',
      mitre: 'T1496 (Resource Hijacking)',
      desc: 'Unregistered binary mimicking systemd utilizing 98.6% CPU with outbound stratum+tcp connection to mining pool 185.193.125.1:3333.'
    },
    {
      comm: 'python3',
      pid: 5120,
      ppid: 4200,
      user: 'anurag',
      eventType: 'file_modify',
      cpu: 18.5,
      mem: 1850.0,
      syscalls: 6200,
      riskScore: 88,
      anomalyType: 'Mass Rapid File Traversal & Modification',
      mitre: 'T1486 (Data Encrypted for Impact)',
      desc: 'Abnormal burst: Python script modified 4,200 user documents in 15 seconds with entropy > 7.9. Current memory 1.8GB is 27.6x above 65MB baseline mean.'
    },
    {
      comm: 'cron',
      pid: 1042,
      ppid: 1,
      user: 'root',
      eventType: 'socket_connect',
      cpu: 0.6,
      mem: 6.2,
      syscalls: 140,
      riskScore: 85,
      anomalyType: 'Anomalous Outbound Reverse Shell Socket',
      mitre: 'T1071 (Application Layer Protocol)',
      desc: 'Cron daemon initiated unexpected TCP connection to external IP 198.51.100.42:4444. Cron has 0 historical outbound sockets in profile.'
    },
    {
      comm: 'sudo',
      pid: 7891,
      ppid: 3812,
      user: 'www-data',
      eventType: 'priv_escalate',
      cpu: 1.2,
      mem: 14.5,
      syscalls: 410,
      riskScore: 96,
      anomalyType: 'Unauthorized Privilege Escalation Attempt',
      mitre: 'T1068 (Exploitation for Privilege Escalation)',
      desc: 'Service user "www-data" executed sudo binary without TTY. Flagged as immediate privilege boundary breach.'
    }
  ];

  // Initialize Initial Telemetry
  function initSeedData() {
    state.profiles = JSON.parse(JSON.stringify(BASELINE_DEFINITIONS));
    state.events = [];
    state.alerts = [];

    const now = Date.now();
    const commKeys = Object.keys(BASELINE_DEFINITIONS);

    // Generate 16 normal events spaced over recent minutes
    for (let i = 0; i < 16; i++) {
      const comm = commKeys[i % commKeys.length];
      const base = BASELINE_DEFINITIONS[comm];
      const cpu = Math.max(0.1, +(base.avgCpu + (Math.random() - 0.5) * base.stdCpu * 1.5).toFixed(1));
      const mem = Math.max(2, +(base.avgMem + (Math.random() - 0.5) * base.stdMem * 1.5).toFixed(1));
      const syscalls = Math.max(10, Math.round(base.avgSyscalls + (Math.random() - 0.5) * 20));
      const evType = base.typicalEvents[Math.floor(Math.random() * base.typicalEvents.length)];

      state.events.unshift({
        id: 'evt-' + (1000 + i),
        timestamp: new Date(now - (16 - i) * 14000).toLocaleTimeString(),
        comm: comm,
        path: base.path,
        pid: 1000 + (i * 123) % 8000,
        ppid: 1,
        user: base.user,
        eventType: evType,
        cpu: cpu,
        mem: mem,
        syscalls: syscalls,
        riskScore: Math.floor(Math.random() * 22) + 5,
        status: 'NORMAL',
        anomalyDetails: null
      });
    }

    // Inject 2 initial anomalies to showcase threat detection
    injectAnomaly(ANOMALY_SCENARIOS[0], new Date(now - 120000));
    injectAnomaly(ANOMALY_SCENARIOS[1], new Date(now - 45000));
  }

  // Anomaly Evaluator (Simulated Scikit-learn Anomaly Model)
  function evaluateMLRisk(event) {
    const base = state.profiles[event.comm];
    if (!base) {
      // Unknown process = Novel binary anomaly
      return {
        riskScore: 78,
        status: 'SUSPICIOUS',
        anomalyType: 'Novel Unprofiled Binary Execution',
        desc: `Process "${event.comm}" has no prior historical profile on this Linux host.`
      };
    }

    const zCpu = Math.abs(event.cpu - base.avgCpu) / (base.stdCpu || 0.1);
    const zMem = Math.abs(event.mem - base.avgMem) / (base.stdMem || 1.0);
    const maxZ = Math.max(zCpu, zMem);

    if (maxZ > 4.5 || event.riskScore > 70) {
      return {
        riskScore: Math.min(99, Math.round(50 + maxZ * 8)),
        status: 'ANOMALOUS',
        anomalyType: zCpu > zMem ? 'Severe CPU Utilization Deviation' : 'Severe Memory Allocation Anomaly',
        desc: `Observed metrics deviate by Z=${maxZ.toFixed(1)} standard deviations from 30-day baseline mean.`
      };
    } else if (maxZ > 2.5 || event.riskScore > 40) {
      return {
        riskScore: Math.round(35 + maxZ * 6),
        status: 'SUSPICIOUS',
        anomalyType: 'Moderate Behavioral Drift',
        desc: `Moderate drift detected: resource consumption slightly exceeds typical profile envelope.`
      };
    }

    return {
      riskScore: Math.max(4, Math.round(maxZ * 8)),
      status: 'NORMAL',
      anomalyType: null,
      desc: null
    };
  }

  // Inject a single random normal event
  function injectRandomEvent() {
    const commKeys = Object.keys(state.profiles);
    const comm = commKeys[Math.floor(Math.random() * commKeys.length)];
    const base = state.profiles[comm];

    const cpu = Math.max(0.1, +(base.avgCpu + (Math.random() - 0.4) * base.stdCpu * 2.0).toFixed(1));
    const mem = Math.max(2, +(base.avgMem + (Math.random() - 0.4) * base.stdMem * 2.0).toFixed(1));
    const syscalls = Math.max(10, Math.round(base.avgSyscalls + (Math.random() - 0.5) * 35));
    const evType = base.typicalEvents[Math.floor(Math.random() * base.typicalEvents.length)];

    const rawEvent = {
      id: 'evt-' + Date.now().toString().slice(-5),
      timestamp: new Date().toLocaleTimeString(),
      comm: comm,
      path: base.path,
      pid: Math.floor(Math.random() * 8000) + 1000,
      ppid: Math.random() > 0.6 ? 1 : Math.floor(Math.random() * 900) + 100,
      user: base.user,
      eventType: evType,
      cpu: cpu,
      mem: mem,
      syscalls: syscalls,
      riskScore: 0
    };

    const evaluation = evaluateMLRisk(rawEvent);
    rawEvent.riskScore = evaluation.riskScore;
    rawEvent.status = evaluation.status;
    rawEvent.anomalyDetails = evaluation.desc;

    state.events.unshift(rawEvent);
    if (state.events.length > 200) state.events.pop();

    renderUI();
  }

  // Inject Anomaly Scenario
  function injectAnomaly(scenarioTemplate = null, customDate = null) {
    const scenario = scenarioTemplate || ANOMALY_SCENARIOS[Math.floor(Math.random() * ANOMALY_SCENARIOS.length)];
    const timestamp = (customDate || new Date()).toLocaleTimeString();

    const anomalousEvent = {
      id: 'evt-' + Date.now().toString().slice(-5),
      timestamp: timestamp,
      comm: scenario.comm,
      path: '/usr/bin/' + scenario.comm,
      pid: scenario.pid,
      ppid: scenario.ppid,
      user: scenario.user,
      eventType: scenario.eventType,
      cpu: scenario.cpu,
      mem: scenario.mem,
      syscalls: scenario.syscalls,
      riskScore: scenario.riskScore,
      status: 'ANOMALOUS',
      anomalyDetails: scenario.desc
    };

    state.events.unshift(anomalousEvent);

    // Create Alert entry
    const alertEntry = {
      id: 'alt-' + Date.now().toString().slice(-4),
      timestamp: timestamp,
      comm: scenario.comm,
      pid: scenario.pid,
      riskScore: scenario.riskScore,
      anomalyType: scenario.anomalyType,
      mitre: scenario.mitre,
      desc: scenario.desc,
      acknowledged: false
    };

    state.alerts.unshift(alertEntry);
    renderUI();
  }

  // Render Table & Metrics
  function renderUI() {
    renderKPIs();
    renderActivityTable();
    renderProfiles();
    renderAlerts();
  }

  function renderKPIs() {
    const totalEventsEl = document.getElementById('kpiTotalEvents');
    const activeProcEl = document.getElementById('kpiActiveProcesses');
    const alertCountEl = document.getElementById('kpiAlertCount');
    const unresAlertsEl = document.getElementById('kpiUnresolvedAlerts');
    const maxRiskEl = document.getElementById('kpiMaxRisk');
    const eventBadgeCount = document.getElementById('eventBadgeCount');
    const alertBadgeCount = document.getElementById('alertBadgeCount');

    const unackCount = state.alerts.filter(a => !a.acknowledged).length;
    const maxRisk = state.events.reduce((max, e) => Math.max(max, e.riskScore), 0);
    const uniqueProcesses = new Set(state.events.map(e => e.comm)).size;

    if (totalEventsEl) totalEventsEl.textContent = (1428 + state.events.length).toLocaleString();
    if (activeProcEl) activeProcEl.textContent = Math.max(38, uniqueProcesses);
    if (alertCountEl) alertCountEl.textContent = state.alerts.length;
    if (unresAlertsEl) unresAlertsEl.textContent = `${unackCount} requiring review`;
    if (maxRiskEl) maxRiskEl.innerHTML = `${maxRisk}<span class="kpi-unit">/100</span>`;
    if (eventBadgeCount) eventBadgeCount.textContent = state.events.length;
    if (alertBadgeCount) alertBadgeCount.textContent = unackCount;
  }

  function renderActivityTable() {
    const tbody = document.getElementById('eventsTableBody');
    const countEl = document.getElementById('visibleEventsCount');
    if (!tbody) return;

    const filtered = state.events.filter(e => {
      // Search
      const matchText = !state.filterText ||
        e.comm.toLowerCase().includes(state.filterText) ||
        e.user.toLowerCase().includes(state.filterText) ||
        e.pid.toString().includes(state.filterText) ||
        e.eventType.toLowerCase().includes(state.filterText);

      // Event Type
      const matchType = state.filterEventType === 'ALL' || e.eventType === state.filterEventType;

      // Risk
      const matchRisk = state.filterRiskLevel === 'ALL' || e.status === state.filterRiskLevel;

      return matchText && matchType && matchRisk;
    });

    if (countEl) countEl.textContent = filtered.length;

    if (filtered.length === 0) {
      tbody.innerHTML = `<tr><td colspan="11" style="text-align: center; color: var(--text-muted); padding: 24px;">No matching host events found. Try adjusting filters or click "Inject Random Event".</td></tr>`;
      return;
    }

    tbody.innerHTML = filtered.map(e => {
      const rowClass = e.status === 'ANOMALOUS' ? 'row-anomalous' : (e.status === 'SUSPICIOUS' ? 'row-suspicious' : '');
      const userClass = e.user === 'root' ? 'root' : '';
      const riskLevel = e.riskScore > 70 ? 'high' : (e.riskScore > 40 ? 'med' : 'low');

      return `
        <tr class="${rowClass}">
          <td class="mono text-muted">${e.timestamp}</td>
          <td>
            <div class="comm-cell">
              <span>${e.comm}</span>
            </div>
          </td>
          <td class="mono">${e.pid} <span class="text-muted">/ ${e.ppid}</span></td>
          <td><span class="user-badge ${userClass}">${e.user}</span></td>
          <td><span class="event-badge ${e.eventType}">${e.eventType}</span></td>
          <td class="mono ${e.cpu > 50 ? 'text-rose' : ''}">${e.cpu}%</td>
          <td class="mono ${e.mem > 500 ? 'text-rose' : ''}">${e.mem} MB</td>
          <td class="mono">${e.syscalls}/s</td>
          <td>
            <div class="risk-meter">
              <span class="mono font-bold ${riskLevel === 'high' ? 'text-rose' : (riskLevel === 'med' ? 'text-amber' : 'text-emerald')}">${e.riskScore}</span>
              <div class="risk-bar-bg">
                <div class="risk-bar-fill ${riskLevel}" style="width: ${e.riskScore}%"></div>
              </div>
            </div>
          </td>
          <td>
            <span class="status-tag ${e.status.toLowerCase()}">${e.status}</span>
          </td>
          <td>
            <button class="btn btn-secondary btn-inspect" style="padding: 3px 8px; font-size: 0.72rem;" data-id="${e.id}">Inspect</button>
          </td>
        </tr>
      `;
    }).join('');

    // Attach click listeners to inspect buttons
    tbody.querySelectorAll('.btn-inspect').forEach(btn => {
      btn.addEventListener('click', () => {
        const id = btn.getAttribute('data-id');
        openProcessModal(id);
      });
    });
  }

  function renderProfiles() {
    const grid = document.getElementById('profilesGrid');
    if (!grid) return;

    const cardsHtml = Object.keys(state.profiles).map(key => {
      const p = state.profiles[key];
      // Find current latest event for this process
      const latest = state.events.find(e => e.comm === key);
      const currentCpu = latest ? latest.cpu : p.avgCpu;
      const currentMem = latest ? latest.mem : p.avgMem;

      const cpuPct = Math.min(100, Math.round((currentCpu / (p.avgCpu * 3 || 10)) * 100));
      const memPct = Math.min(100, Math.round((currentMem / (p.avgMem * 3 || 100)) * 100));

      return `
        <div class="profile-card">
          <div class="profile-card-header">
            <div class="profile-title">
              🐧 ${p.comm}
            </div>
            <div class="profile-sample-count">${p.sampleCount.toLocaleString()} events profiled</div>
          </div>

          <div class="metric-row">
            <span class="metric-label">Execution Path</span>
            <span class="metric-values text-muted" style="font-size: 0.72rem;">${p.path}</span>
          </div>

          <div class="metric-row">
            <span class="metric-label">Default User</span>
            <span class="user-badge">${p.user}</span>
          </div>

          <div class="metric-bar-dual">
            <div class="metric-row" style="margin-bottom: 2px;">
              <span class="metric-label">CPU Usage: Current vs Baseline</span>
              <span class="metric-values">${currentCpu}% <span class="text-muted">(Avg ${p.avgCpu}%)</span></span>
            </div>
            <div class="dual-bar-track">
              <div class="dual-bar-baseline" style="width: ${Math.min(100, p.avgCpu * 15)}%;"></div>
              <div class="dual-bar-current" style="width: ${cpuPct}%;"></div>
            </div>
          </div>

          <div class="metric-bar-dual">
            <div class="metric-row" style="margin-bottom: 2px;">
              <span class="metric-label">Memory: Current vs Baseline</span>
              <span class="metric-values">${currentMem} MB <span class="text-muted">(Avg ${p.avgMem} MB)</span></span>
            </div>
            <div class="dual-bar-track">
              <div class="dual-bar-baseline" style="width: ${Math.min(100, (p.avgMem / 100) * 50)}%;"></div>
              <div class="dual-bar-current" style="width: ${memPct}%;"></div>
            </div>
          </div>

          <div class="metric-row" style="margin-top: 10px;">
            <span class="metric-label">Typical Syscalls</span>
            <span class="metric-values text-cyan" style="font-size: 0.75rem;">${p.typicalEvents.join(', ')}</span>
          </div>
        </div>
      `;
    }).join('');

    grid.innerHTML = cardsHtml;
  }

  function renderAlerts() {
    const container = document.getElementById('alertsContainer');
    if (!container) return;

    if (state.alerts.length === 0) {
      container.innerHTML = `
        <div style="background: var(--bg-card); padding: 32px; border-radius: var(--radius-md); text-align: center; border: 1px solid var(--border-subtle);">
          <h4 style="color: var(--accent-emerald);">All Clear</h4>
          <p class="text-muted mt-2">No active behavioral deviations detected on this host.</p>
        </div>
      `;
      return;
    }

    container.innerHTML = state.alerts.map(a => {
      const ackClass = a.acknowledged ? 'acknowledged' : '';

      return `
        <div class="alert-card ${ackClass}" id="alert-card-${a.id}">
          <div class="alert-main">
            <div class="alert-header-line">
              <span class="alert-title">${a.anomalyType}</span>
              <span class="alert-mitre">${a.mitre}</span>
            </div>
            <div class="alert-desc">${a.desc}</div>
            <div class="alert-meta">
              <span>Process: <strong>${a.comm}</strong> (PID ${a.pid})</span>
              <span>Time: ${a.timestamp}</span>
              <span>Status: ${a.acknowledged ? '<span class="text-muted">Acknowledged</span>' : '<span class="text-rose">Active Alert</span>'}</span>
            </div>
          </div>
          <div class="alert-right">
            <div class="alert-score-badge">
              Risk ${a.riskScore}/100
            </div>
            ${!a.acknowledged ? `<button class="btn btn-secondary btn-ack" data-id="${a.id}" style="padding: 4px 10px; font-size: 0.75rem;">Acknowledge</button>` : ''}
          </div>
        </div>
      `;
    }).join('');

    container.querySelectorAll('.btn-ack').forEach(btn => {
      btn.addEventListener('click', () => {
        const id = btn.getAttribute('data-id');
        acknowledgeAlert(id);
      });
    });
  }

  function acknowledgeAlert(alertId) {
    const alert = state.alerts.find(a => a.id === alertId);
    if (alert) {
      alert.acknowledged = true;
      renderUI();
    }
  }

  function openProcessModal(eventId) {
    const event = state.events.find(e => e.id === eventId);
    if (!event) return;

    const modal = document.getElementById('processModal');
    const titleEl = document.getElementById('modalProcessName');
    const riskBadge = document.getElementById('modalRiskBadge');
    const bodyEl = document.getElementById('modalBody');

    const base = state.profiles[event.comm] || {
      avgCpu: 'N/A', avgMem: 'N/A', sampleCount: 0, path: 'Unknown'
    };

    titleEl.textContent = `${event.comm} (PID ${event.pid})`;
    riskBadge.textContent = `Risk Score: ${event.riskScore}/100`;
    riskBadge.className = `badge ${event.riskScore > 70 ? 'text-rose' : 'text-emerald'}`;

    bodyEl.innerHTML = `
      <div class="modal-detail-row">
        <span class="modal-detail-label">Binary Path:</span>
        <span class="modal-detail-val">${event.path}</span>
      </div>
      <div class="modal-detail-row">
        <span class="modal-detail-label">User Context:</span>
        <span class="modal-detail-val">${event.user}</span>
      </div>
      <div class="modal-detail-row">
        <span class="modal-detail-label">Parent PID:</span>
        <span class="modal-detail-val">${event.ppid}</span>
      </div>
      <div class="modal-detail-row">
        <span class="modal-detail-label">Current Event:</span>
        <span class="modal-detail-val"><span class="event-badge ${event.eventType}">${event.eventType}</span></span>
      </div>
      <div class="modal-detail-row">
        <span class="modal-detail-label">Observed CPU Usage:</span>
        <span class="modal-detail-val">${event.cpu}% (Historical baseline: ${base.avgCpu}%)</span>
      </div>
      <div class="modal-detail-row">
        <span class="modal-detail-label">Observed Memory RSS:</span>
        <span class="modal-detail-val">${event.mem} MB (Historical baseline: ${base.avgMem} MB)</span>
      </div>
      <div class="modal-detail-row">
        <span class="modal-detail-label">Syscall Frequency:</span>
        <span class="modal-detail-val">${event.syscalls} events/sec</span>
      </div>
      <div style="background: rgba(0,0,0,0.3); padding: 12px; border-radius: 6px; border: 1px solid var(--border-subtle); margin-top: 6px;">
        <div style="font-weight: 600; color: var(--accent-cyan); margin-bottom: 4px;">Forensic Anomaly Analysis</div>
        <p style="color: var(--text-secondary); font-size: 0.82rem; line-height: 1.5;">
          ${event.anomalyDetails || 'Behavior is within normal statistical profile bounds (+/- 1.8 sigma). No suspicious system calls or unauthorized child process spawns observed.'}
        </p>
      </div>
    `;

    modal.classList.add('active');
  }

  // Toggle Live Streaming
  function toggleStream() {
    state.isStreaming = !state.isStreaming;
    const btnText = document.getElementById('streamBtnText');
    const icon = document.getElementById('streamIcon');

    if (state.isStreaming) {
      btnText.textContent = 'Pause Live Stream';
      icon.textContent = '⏸';
      state.streamTimer = setInterval(() => {
        // 90% normal, 10% chance of random anomaly
        if (Math.random() < 0.12) {
          injectAnomaly();
        } else {
          injectRandomEvent();
        }
      }, 1500);
    } else {
      btnText.textContent = 'Start Live Stream';
      icon.textContent = '▶';
      if (state.streamTimer) {
        clearInterval(state.streamTimer);
        state.streamTimer = null;
      }
    }
  }

  // System Clock
  function startClock() {
    const clockEl = document.getElementById('systemClock');
    setInterval(() => {
      if (clockEl) {
        const d = new Date();
        clockEl.textContent = d.toTimeString().split(' ')[0] + ' UTC';
      }
    }, 1000);
  }

  // Setup Event Listeners
  function setupEventListeners() {
    // Testing toolbar
    document.getElementById('btnRandomEvent')?.addEventListener('click', injectRandomEvent);
    document.getElementById('btnInjectAnomaly')?.addEventListener('click', () => injectAnomaly());
    document.getElementById('btnToggleStream')?.addEventListener('click', toggleStream);
    document.getElementById('btnResetData')?.addEventListener('click', initSeedData);
    document.getElementById('btnAcknowledgeAll')?.addEventListener('click', () => {
      state.alerts.forEach(a => a.acknowledged = true);
      renderUI();
    });

    // Navigation Tabs
    document.querySelectorAll('.nav-tab').forEach(tab => {
      tab.addEventListener('click', () => {
        const targetId = tab.getAttribute('data-tab');
        document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));

        tab.classList.add('active');
        document.getElementById(targetId)?.classList.add('active');
        state.activeTab = targetId;
      });
    });

    // Filtering
    document.getElementById('eventSearchInput')?.addEventListener('input', (e) => {
      state.filterText = e.target.value.toLowerCase().trim();
      renderActivityTable();
    });

    document.getElementById('eventTypeFilter')?.addEventListener('change', (e) => {
      state.filterEventType = e.target.value;
      renderActivityTable();
    });

    document.getElementById('riskLevelFilter')?.addEventListener('change', (e) => {
      state.filterRiskLevel = e.target.value;
      renderActivityTable();
    });

    // Modal close
    document.getElementById('closeModalBtn')?.addEventListener('click', () => {
      document.getElementById('processModal')?.classList.remove('active');
    });

    document.getElementById('processModal')?.addEventListener('click', (e) => {
      if (e.target.id === 'processModal') {
        document.getElementById('processModal')?.classList.remove('active');
      }
    });
  }

  // Bootstrap
  document.addEventListener('DOMContentLoaded', () => {
    initSeedData();
    renderUI();
    setupEventListeners();
    startClock();
  });

})();
