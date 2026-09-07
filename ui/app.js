/**
 * Chronicle Intelligent Host Behaviour & Activity Monitor
 * Client Engine & Machine Learning Anomaly Detection Simulation
 * Features:
 *  - Dual Themes (Light Mode & Dark Mode from Reference Screenshot 2)
 *  - Windows Task Manager (Heatmap Cell Tinting, Row Selection, End Task)
 *  - Apple Activity Monitor (Top Segmented Bar, Process Inspector, Real-time Metrics)
 *  - Interactive SVG Charts (Event Bursts, Z-Score Trend, Donut Breakdown)
 */

(function () {
  'use strict';

  // --- STATE ---
  const state = {
    events: [],
    alerts: [],
    profiles: {},
    isStreaming: false,
    streamTimer: null,
    activeTab: 'liveActivityView',
    activeSeg: 'all',
    filterText: '',
    filterCluster: null,
    selectedEventId: null,
    currentTheme: 'light'
  };

  // --- BASELINE DEFINITIONS (30-Day Historical Baselines) ---
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
      cluster: 'systemd',
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
      cluster: 'nginx',
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
      cluster: 'nginx',
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
      cluster: 'bash',
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
      cluster: 'bash',
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
      cluster: 'dockerd',
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
      cluster: 'systemd',
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
      cluster: 'bash',
      sampleCount: 3400
    }
  };

  // --- ANOMALY SCENARIO CATALOG ---
  const ANOMALY_SCENARIOS = {
    'webshell': {
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
      desc: 'Process "nginx" (web daemon) spawned interactive shell "/bin/bash -i". Historical baseline indicates 0 shell spawns over 30 days.'
    },
    'crypto': {
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
      desc: 'Unregistered binary mimicking systemd utilizing 98.6% CPU with outbound stratum+tcp socket to mining pool 185.193.125.1:3333.'
    },
    'ransomware': {
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
      desc: 'Abnormal burst: Python script modified 4,200 user documents in 15 seconds. Current memory 1.8GB is 27.6x above 65MB baseline mean.'
    },
    'reverseshell': {
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
    'privesc': {
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
  };

  // --- THEME ENGINE ---
  function initTheme() {
    const savedTheme = localStorage.getItem('chronicle_theme');
    if (savedTheme) {
      setTheme(savedTheme);
    } else if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
      setTheme('dark');
    } else {
      setTheme('light');
    }

    const toggleBtn = document.getElementById('themeToggleBtn');
    if (toggleBtn) {
      toggleBtn.addEventListener('click', () => {
        const newTheme = state.currentTheme === 'light' ? 'dark' : 'light';
        setTheme(newTheme);
      });
    }
  }

  function setTheme(theme) {
    state.currentTheme = theme;
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('chronicle_theme', theme);

    const themeLabel = document.getElementById('themeLabel');
    if (themeLabel) {
      themeLabel.textContent = theme === 'light' ? 'Classic' : 'Cyber CRT';
    }
  }

  // --- SEED DATA INITIALIZATION ---
  function initSeedData() {
    state.profiles = JSON.parse(JSON.stringify(BASELINE_DEFINITIONS));
    state.events = [];
    state.alerts = [];

    const now = Date.now();
    const commKeys = Object.keys(BASELINE_DEFINITIONS);

    // Generate 18 normal baseline events
    for (let i = 0; i < 18; i++) {
      const comm = commKeys[i % commKeys.length];
      const base = BASELINE_DEFINITIONS[comm];
      const cpu = Math.max(0.1, +(base.avgCpu + (Math.random() - 0.5) * base.stdCpu * 1.6).toFixed(1));
      const mem = Math.max(2, +(base.avgMem + (Math.random() - 0.5) * base.stdMem * 1.5).toFixed(1));
      const syscalls = Math.max(10, Math.round(base.avgSyscalls + (Math.random() - 0.5) * 20));
      const evType = base.typicalEvents[Math.floor(Math.random() * base.typicalEvents.length)];

      state.events.unshift({
        id: 'evt-' + (1000 + i),
        timestamp: new Date(now - (18 - i) * 12000).toLocaleTimeString(),
        comm: comm,
        path: base.path,
        pid: 1000 + (i * 127) % 8000,
        ppid: i % 3 === 0 ? 1 : Math.floor(Math.random() * 800) + 100,
        user: base.user,
        cluster: base.cluster,
        eventType: evType,
        cpu: cpu,
        mem: mem,
        syscalls: syscalls,
        riskScore: Math.floor(Math.random() * 18) + 4,
        status: 'NORMAL',
        anomalyDetails: null,
        terminated: false
      });
    }

    // Inject initial anomaly scenarios for security visibility
    injectAnomalyByKey('webshell', new Date(now - 90000));
    injectAnomalyByKey('crypto', new Date(now - 35000));

    // Select the first event by default (for Inspect & End Task)
    if (state.events.length > 0) {
      state.selectedEventId = state.events[0].id;
    }
  }

  // --- ML RISK EVALUATION ---
  function evaluateMLRisk(event) {
    const base = state.profiles[event.comm];
    if (!base) {
      return {
        riskScore: 78,
        status: 'SUSPICIOUS',
        desc: `Process "${event.comm}" is unprofiled on this Linux system.`
      };
    }

    const zCpu = Math.abs(event.cpu - base.avgCpu) / (base.stdCpu || 0.1);
    const zMem = Math.abs(event.mem - base.avgMem) / (base.stdMem || 1.0);
    const maxZ = Math.max(zCpu, zMem);

    if (maxZ > 4.5 || event.riskScore > 70) {
      return {
        riskScore: Math.min(99, Math.round(50 + maxZ * 8)),
        status: 'ANOMALOUS',
        desc: `Observed metrics deviate by Z=${maxZ.toFixed(1)}σ from 30-day baseline mean.`
      };
    } else if (maxZ > 2.5 || event.riskScore > 40) {
      return {
        riskScore: Math.round(35 + maxZ * 6),
        status: 'SUSPICIOUS',
        desc: `Moderate drift detected: resource consumption slightly exceeds typical baseline.`
      };
    }

    return {
      riskScore: Math.max(4, Math.round(maxZ * 7)),
      status: 'NORMAL',
      desc: null
    };
  }

  // --- INJECTION ENGINES ---
  function injectRandomEvent() {
    const commKeys = Object.keys(state.profiles);
    const comm = commKeys[Math.floor(Math.random() * commKeys.length)];
    const base = state.profiles[comm];

    const cpu = Math.max(0.1, +(base.avgCpu + (Math.random() - 0.3) * base.stdCpu * 2.2).toFixed(1));
    const mem = Math.max(2, +(base.avgMem + (Math.random() - 0.3) * base.stdMem * 2.0).toFixed(1));
    const syscalls = Math.max(10, Math.round(base.avgSyscalls + (Math.random() - 0.5) * 40));
    const evType = base.typicalEvents[Math.floor(Math.random() * base.typicalEvents.length)];

    const rawEvent = {
      id: 'evt-' + Date.now().toString().slice(-6),
      timestamp: new Date().toLocaleTimeString(),
      comm: comm,
      path: base.path,
      pid: Math.floor(Math.random() * 8500) + 1000,
      ppid: Math.random() > 0.6 ? 1 : Math.floor(Math.random() * 900) + 100,
      user: base.user,
      cluster: base.cluster,
      eventType: evType,
      cpu: cpu,
      mem: mem,
      syscalls: syscalls,
      riskScore: 0,
      terminated: false
    };

    const evaluation = evaluateMLRisk(rawEvent);
    rawEvent.riskScore = evaluation.riskScore;
    rawEvent.status = evaluation.status;
    rawEvent.anomalyDetails = evaluation.desc;

    state.events.unshift(rawEvent);
    if (state.events.length > 200) state.events.pop();

    renderUI();
  }

  function injectAnomalyByKey(key, customDate = null) {
    const scenario = ANOMALY_SCENARIOS[key] || ANOMALY_SCENARIOS['webshell'];
    const timestamp = (customDate || new Date()).toLocaleTimeString();

    const anomalousEvent = {
      id: 'evt-' + Date.now().toString().slice(-6),
      timestamp: timestamp,
      comm: scenario.comm,
      path: '/usr/bin/' + scenario.comm,
      pid: scenario.pid,
      ppid: scenario.ppid,
      user: scenario.user,
      cluster: BASELINE_DEFINITIONS[scenario.comm]?.cluster || 'systemd',
      eventType: scenario.eventType,
      cpu: scenario.cpu,
      mem: scenario.mem,
      syscalls: scenario.syscalls,
      riskScore: scenario.riskScore,
      status: 'ANOMALOUS',
      anomalyDetails: scenario.desc,
      terminated: false
    };

    state.events.unshift(anomalousEvent);

    const alertEntry = {
      id: 'alt-' + Date.now().toString().slice(-5),
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
    state.selectedEventId = anomalousEvent.id;

    renderUI();
  }

  // --- TERMINATE / END TASK SIMULATION (Windows Task Manager) ---
  function terminateProcess(eventId) {
    const ev = state.events.find(e => e.id === eventId);
    if (!ev) return;

    ev.terminated = true;
    ev.status = 'TERMINATED';
    ev.cpu = 0.0;
    ev.riskScore = 0;
    ev.anomalyDetails = 'Process terminated by user via SIGKILL (Task Manager)';

    // Mark corresponding alert as acknowledged if anomalous
    const alt = state.alerts.find(a => a.pid === ev.pid);
    if (alt) alt.acknowledged = true;

    renderUI();
    closeAllModals();
  }

  // --- UI RENDER SYSTEM ---
  function renderUI() {
    renderKPIs();
    renderActivityTable();
    renderProfiles();
    renderAlerts();
    renderGauge();
  }

  function renderKPIs() {
    const cpuEl = document.getElementById('cpuUtilization');
    const memEl = document.getElementById('memoryUsage');
    const syscallEl = document.getElementById('syscallRate');
    const normalcyEl = document.getElementById('hostNormalcyVal');
    const anomalyStatusText = document.getElementById('anomalyStatusText');
    const totalEventsBadge = document.getElementById('totalEventsBadge');
    const anomalySegBadge = document.getElementById('anomalySegBadge');
    const menuAlertBadge = document.getElementById('menuAlertBadge');

    const total = state.events.length;
    const anomCount = state.events.filter(e => e.status === 'ANOMALOUS' && !e.terminated).length;
    const unackCount = state.alerts.filter(a => !a.acknowledged).length;

    const avgCpu = total ? (state.events.reduce((acc, e) => acc + e.cpu, 0) / total).toFixed(1) : '0.0';
    const totalSyscalls = total ? state.events.slice(0, 10).reduce((acc, e) => acc + e.syscalls, 0) : 2840;

    if (cpuEl) cpuEl.textContent = `${avgCpu}%`;
    if (memEl) memEl.innerHTML = `3.2 GB <span class="kpi-denom">/ 16 GB</span>`;
    if (syscallEl) syscallEl.innerHTML = `${totalSyscalls.toLocaleString()} <span class="kpi-denom">calls/s</span>`;
    
    const normalcy = Math.max(25, 100 - (anomCount * 5.8)).toFixed(1);
    if (normalcyEl) normalcyEl.textContent = `${normalcy}%`;
    if (anomalyStatusText) anomalyStatusText.textContent = `${anomCount} Anomalies Active (>3σ)`;

    if (totalEventsBadge) totalEventsBadge.textContent = (1428 + state.events.length).toLocaleString();
    if (anomalySegBadge) anomalySegBadge.textContent = anomCount;
    if (menuAlertBadge) menuAlertBadge.textContent = unackCount;
  }

  function renderActivityTable() {
    const tbody = document.getElementById('eventsTableBody');
    if (!tbody) return;

    const filtered = state.events.filter(e => {
      // Search filter
      const matchText = !state.filterText ||
        e.comm.toLowerCase().includes(state.filterText) ||
        e.user.toLowerCase().includes(state.filterText) ||
        e.pid.toString().includes(state.filterText) ||
        e.eventType.toLowerCase().includes(state.filterText);

      // Cluster filter
      const matchCluster = !state.filterCluster || e.cluster === state.filterCluster || e.comm.includes(state.filterCluster);

      // Segment filter (Apple Activity Monitor style)
      let matchSeg = true;
      if (state.activeSeg === 'cpu') {
        matchSeg = e.cpu > 2.0;
      } else if (state.activeSeg === 'memory') {
        matchSeg = e.mem > 40.0;
      } else if (state.activeSeg === 'network') {
        matchSeg = e.eventType === 'socket_connect' || e.comm === 'nginx' || e.comm === 'sshd' || e.comm === 'curl';
      } else if (state.activeSeg === 'anomalies') {
        matchSeg = e.status === 'ANOMALOUS';
      }

      return matchText && matchCluster && matchSeg;
    });

    if (filtered.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="9" style="text-align: center; color: var(--text-muted); padding: 32px;">
            No matching process telemetry found for current filters.
          </td>
        </tr>
      `;
      return;
    }

    tbody.innerHTML = filtered.map(e => {
      const isSelected = state.selectedEventId === e.id;
      const selectedClass = isSelected ? 'row-selected' : '';

      // Windows Task Manager Heatmap cell classes
      const cpuHeatClass = e.cpu > 50 ? 'heat-cpu-high' : (e.cpu > 15 ? 'heat-cpu-med' : '');
      const memHeatClass = e.mem > 400 ? 'heat-mem-high' : '';

      // Risk Pill Class
      let riskPillClass = 'safe';
      if (e.terminated) riskPillClass = 'safe';
      else if (e.status === 'ANOMALOUS') riskPillClass = 'danger';
      else if (e.status === 'SUSPICIOUS') riskPillClass = 'warn';

      const procIcon = e.comm === 'nginx' ? '🌐' : (e.comm === 'dockerd' ? '🐳' : (e.comm === 'python3' ? '🐍' : '💻'));

      return `
        <tr class="${selectedClass}" data-id="${e.id}">
          <td>
            <div class="proc-cell">
              <span class="proc-icon">${procIcon}</span>
              <div class="proc-names">
                <span class="proc-comm">${e.comm}</span>
                <span class="proc-desc font-mono">${e.timestamp}</span>
              </div>
            </div>
          </td>
          <td class="font-mono">${e.pid}</td>
          <td><span class="font-mono">${e.user}</span></td>
          <td><span class="font-mono">${e.eventType}</span></td>
          <td class="font-mono ${cpuHeatClass}">${e.cpu}%</td>
          <td class="font-mono ${memHeatClass}">${e.mem} MB</td>
          <td class="font-mono">${e.syscalls}</td>
          <td>
            <span class="risk-pill ${riskPillClass}">
              ${e.status} • ${e.riskScore}
            </span>
          </td>
          <td style="text-align: right;">
            <button class="btn-row-action" data-action="inspect" data-id="${e.id}" title="Inspect Process (⌘I)">Inspect</button>
          </td>
        </tr>
      `;
    }).join('');

    // Row Click Listeners (Single-click selects, double-click inspects)
    tbody.querySelectorAll('tr').forEach(tr => {
      tr.addEventListener('click', (ev) => {
        const id = tr.getAttribute('data-id');
        if (!id) return;

        state.selectedEventId = id;
        tbody.querySelectorAll('tr').forEach(r => r.classList.remove('row-selected'));
        tr.classList.add('row-selected');

        // If inspect button directly clicked
        if (ev.target.closest('[data-action="inspect"]')) {
          openProcessModal(id);
        }
      });

      tr.addEventListener('dblclick', () => {
        const id = tr.getAttribute('data-id');
        if (id) openProcessModal(id);
      });
    });
  }

  function renderProfiles() {
    const grid = document.getElementById('profilesGrid');
    if (!grid) return;

    grid.innerHTML = Object.keys(state.profiles).map(key => {
      const p = state.profiles[key];
      const latest = state.events.find(e => e.comm === key);
      const currentCpu = latest ? latest.cpu : p.avgCpu;
      const currentMem = latest ? latest.mem : p.avgMem;

      return `
        <div class="profile-card">
          <div class="profile-header">
            <div class="profile-title">
              <span>🐧</span>
              <span>${p.comm}</span>
            </div>
            <span class="profile-category">${p.user}</span>
          </div>
          <div style="font-size: 0.74rem; color: var(--text-muted); font-family: var(--font-mono); margin-bottom: 12px;">
            ${p.path}
          </div>

          <div class="profile-metric-row">
            <div class="profile-metric-label">
              <span>CPU: ${currentCpu}%</span>
              <span>Baseline: ${p.avgCpu}% (±${p.stdCpu}%)</span>
            </div>
            <div class="baseline-bar-container">
              <div class="baseline-bar" style="width: ${Math.min(100, (currentCpu / (p.avgCpu * 2.5 || 5)) * 100)}%;"></div>
            </div>
          </div>

          <div class="profile-metric-row">
            <div class="profile-metric-label">
              <span>Memory RSS: ${currentMem} MB</span>
              <span>Baseline: ${p.avgMem} MB (±${p.stdMem} MB)</span>
            </div>
            <div class="baseline-bar-container">
              <div class="baseline-bar" style="background: var(--accent-blue); width: ${Math.min(100, (currentMem / (p.avgMem * 2.5 || 50)) * 100)}%;"></div>
            </div>
          </div>
        </div>
      `;
    }).join('');
  }

  function renderAlerts() {
    const container = document.getElementById('alertsContainer');
    if (!container) return;

    if (state.alerts.length === 0) {
      container.innerHTML = `
        <div style="background: var(--bg-surface); border: 1px solid var(--border-color); padding: 32px; border-radius: 16px; text-align: center;">
          <h4 style="color: var(--primary-emerald);">All Baselines Normal</h4>
          <p style="color: var(--text-muted); font-size: 0.85rem; margin-top: 4px;">No active behavioral deviations currently logged on this host.</p>
        </div>
      `;
      return;
    }

    container.innerHTML = state.alerts.map(a => `
      <div class="alert-item ${a.acknowledged ? 'acknowledged' : ''}">
        <div class="alert-main">
          <div class="alert-title-row">
            <span class="alert-name">${a.anomalyType}</span>
            <span class="alert-mitre font-mono">${a.mitre}</span>
          </div>
          <p class="alert-desc">${a.desc}</p>
          <div class="alert-meta-row font-mono">
            <span>Process: <strong>${a.comm}</strong> (PID ${a.pid})</span>
            <span>•</span>
            <span>${a.timestamp}</span>
            <span>•</span>
            <span>Confidence: 96.4%</span>
          </div>
        </div>
        <div style="display: flex; flex-direction: column; align-items: flex-end; gap: 8px;">
          <span class="risk-pill danger font-mono">Risk ${a.riskScore}/100</span>
          ${!a.acknowledged ? `<button class="btn-ack" data-id="${a.id}">Acknowledge</button>` : `<span style="font-size: 0.7rem; color: var(--text-muted);">Triaged</span>`}
        </div>
      </div>
    `).join('');

    container.querySelectorAll('.btn-ack').forEach(btn => {
      btn.addEventListener('click', (ev) => {
        ev.stopPropagation();
        const id = btn.getAttribute('data-id');
        const alert = state.alerts.find(a => a.id === id);
        if (alert) {
          alert.acknowledged = true;
          renderUI();
        }
      });
    });
  }

  function renderGauge() {
    const scoreEl = document.getElementById('gaugeHealthScore');
    const legSys = document.getElementById('legendSystemPct');
    const legUser = document.getElementById('legendUserPct');
    const legElev = document.getElementById('legendElevatedPct');
    const legAnom = document.getElementById('legendAnomalyPct');

    const total = state.events.length || 1;
    const anomCount = state.events.filter(e => e.status === 'ANOMALOUS' && !e.terminated).length;
    const suspCount = state.events.filter(e => e.status === 'SUSPICIOUS').length;
    const userCount = state.events.filter(e => e.user !== 'root').length;
    const sysCount = state.events.filter(e => e.user === 'root' && e.status === 'NORMAL').length;

    const anomPct = Math.round((anomCount / total) * 100);
    const suspPct = Math.round((suspCount / total) * 100);
    const userPct = Math.round((userCount / total) * 100);
    const sysPct = Math.max(0, 100 - anomPct - suspPct - userPct);

    const health = Math.max(15, 100 - (anomPct * 6 + suspPct * 2));

    if (scoreEl) scoreEl.textContent = `${health}%`;
    if (legSys) legSys.textContent = `${sysPct}%`;
    if (legUser) legUser.textContent = `${userPct}%`;
    if (legElev) legElev.textContent = `${suspPct}%`;
    if (legAnom) legAnom.textContent = `${anomPct}%`;
  }

  // --- PROCESS INSPECTOR MODAL (Apple Activity Monitor) ---
  function openProcessModal(eventId) {
    const ev = state.events.find(e => e.id === eventId) || state.events[0];
    if (!ev) return;

    state.selectedEventId = ev.id;
    const modal = document.getElementById('processModal');
    const nameEl = document.getElementById('modalProcessName');
    const subEl = document.getElementById('modalProcessSub');
    const riskBadge = document.getElementById('modalRiskBadge');
    const bodyEl = document.getElementById('modalBody');

    const base = state.profiles[ev.comm] || {
      avgCpu: 'N/A', avgMem: 'N/A', path: '/usr/bin/' + ev.comm
    };

    if (nameEl) nameEl.textContent = `${ev.comm} (PID ${ev.pid})`;
    if (subEl) subEl.textContent = `PPID: ${ev.ppid} • User: ${ev.user} • Architecture: x86_64`;
    if (riskBadge) {
      riskBadge.textContent = `Risk: ${ev.riskScore}/100`;
      riskBadge.className = `badge font-mono ${ev.status === 'ANOMALOUS' ? 'text-rose' : ''}`;
    }

    if (bodyEl) {
      bodyEl.innerHTML = `
        <div class="detail-grid">
          <div class="detail-item">
            <div class="detail-label">Executable Path</div>
            <div class="detail-value font-mono">${ev.path}</div>
          </div>
          <div class="detail-item">
            <div class="detail-label">Execution User</div>
            <div class="detail-value font-mono">${ev.user}</div>
          </div>
          <div class="detail-item">
            <div class="detail-label">Observed CPU Usage</div>
            <div class="detail-value font-mono">${ev.cpu}% (30d Mean: ${base.avgCpu}%)</div>
          </div>
          <div class="detail-item">
            <div class="detail-label">Resident Memory RSS</div>
            <div class="detail-value font-mono">${ev.mem} MB (30d Mean: ${base.avgMem} MB)</div>
          </div>
          <div class="detail-item">
            <div class="detail-label">Kernel Action</div>
            <div class="detail-value font-mono">${ev.eventType}</div>
          </div>
          <div class="detail-item">
            <div class="detail-label">Syscall Frequency</div>
            <div class="detail-value font-mono">${ev.syscalls} calls/s</div>
          </div>
        </div>

        <div style="background: var(--bg-subtle); padding: 14px; border-radius: 12px; border: 1px solid var(--border-color);">
          <div style="font-size: 0.72rem; font-weight: 800; color: var(--primary-emerald); text-transform: uppercase; margin-bottom: 4px;">
            ML Behavioral Analysis Rationale
          </div>
          <p style="font-size: 0.8rem; color: var(--text-secondary); line-height: 1.5;">
            ${ev.anomalyDetails || 'Kernel telemetry conforms to rolling 30-day historical baseline envelope (±1.6σ). No unauthorized privilege escalation or covert outbound sockets detected.'}
          </p>
        </div>
      `;
    }

    modal?.classList.add('active');
  }

  function closeAllModals() {
    document.querySelectorAll('.modal-overlay').forEach(m => m.classList.remove('active'));
  }

  // --- STREAM TOGGLE ---
  function toggleStream() {
    state.isStreaming = !state.isStreaming;

    const liveBtn = document.getElementById('btnToggleLiveFeed');
    const liveText = document.getElementById('liveFeedText');
    const sideIcon = document.getElementById('streamSideIcon');
    const sideText = document.getElementById('streamSideText');

    if (state.isStreaming) {
      if (liveText) liveText.textContent = 'Streaming...';
      if (liveBtn) liveBtn.classList.add('live-active');
      if (sideIcon) sideIcon.textContent = '⏸';
      if (sideText) sideText.textContent = 'Pause Stream';

      state.streamTimer = setInterval(() => {
        if (Math.random() < 0.14) {
          const keys = Object.keys(ANOMALY_SCENARIOS);
          const randKey = keys[Math.floor(Math.random() * keys.length)];
          injectAnomalyByKey(randKey);
        } else {
          injectRandomEvent();
        }
      }, 1500);
    } else {
      if (liveText) liveText.textContent = 'Live Stream';
      if (liveBtn) liveBtn.classList.remove('live-active');
      if (sideIcon) sideIcon.textContent = '▶';
      if (sideText) sideText.textContent = 'Live Stream';

      if (state.streamTimer) {
        clearInterval(state.streamTimer);
        state.streamTimer = null;
      }
    }
  }

  // --- VIEW SWITCHING ---
  function switchView(viewId) {
    document.querySelectorAll('.menu-item').forEach(m => m.classList.remove('active'));
    document.querySelectorAll('.content-view').forEach(v => v.classList.remove('active'));

    const activeMenu = document.querySelector(`.menu-item[data-tab="${viewId}"]`);
    if (activeMenu) activeMenu.classList.add('active');

    const targetView = document.getElementById(viewId);
    if (targetView) targetView.classList.add('active');

    state.activeTab = viewId;
  }

  // --- EVENT LISTENERS INITIALIZATION ---
  function setupEventListeners() {
    // 1. Theme Switcher
    initTheme();

    // 2. Navigation Tabs
    document.querySelectorAll('.menu-item[data-tab]').forEach(btn => {
      btn.addEventListener('click', () => {
        switchView(btn.getAttribute('data-tab'));
      });
    });

    // 3. Apple Activity Monitor Segmented Tabs
    document.querySelectorAll('.seg-tab').forEach(tab => {
      tab.addEventListener('click', () => {
        document.querySelectorAll('.seg-tab').forEach(t => t.classList.remove('active'));
        tab.classList.add('active');
        state.activeSeg = tab.getAttribute('data-seg');
        renderActivityTable();
      });
    });

    // 4. Action Buttons (Inspect & End Task)
    document.getElementById('btnInspectSelected')?.addEventListener('click', () => {
      if (state.selectedEventId) {
        openProcessModal(state.selectedEventId);
      } else if (state.events.length > 0) {
        openProcessModal(state.events[0].id);
      }
    });

    document.getElementById('btnEndTask')?.addEventListener('click', () => {
      if (state.selectedEventId) {
        terminateProcess(state.selectedEventId);
      }
    });

    document.getElementById('btnModalKill')?.addEventListener('click', () => {
      if (state.selectedEventId) {
        terminateProcess(state.selectedEventId);
      }
    });

    document.getElementById('btnModalClose')?.addEventListener('click', closeAllModals);
    document.getElementById('closeModalBtn')?.addEventListener('click', closeAllModals);

    // 5. Live Stream Toggles
    document.getElementById('btnToggleLiveFeed')?.addEventListener('click', toggleStream);
    document.getElementById('btnToggleStreamSide')?.addEventListener('click', toggleStream);

    // 6. Simulation Modals & Buttons
    document.getElementById('btnNewEvent')?.addEventListener('click', () => {
      document.getElementById('simulationModal')?.classList.add('active');
    });

    document.getElementById('btnInjectAnomalySide')?.addEventListener('click', () => {
      document.getElementById('simulationModal')?.classList.add('active');
    });

    document.getElementById('closeSimModalBtn')?.addEventListener('click', closeAllModals);

    // Simulation Scenario Buttons
    document.querySelectorAll('.scenario-card').forEach(card => {
      card.addEventListener('click', () => {
        const scenarioKey = card.getAttribute('data-scenario');
        if (scenarioKey) {
          injectAnomalyByKey(scenarioKey);
          closeAllModals();
        }
      });
    });

    // 7. Random Event
    document.getElementById('btnRandomEventSide')?.addEventListener('click', injectRandomEvent);

    // 8. Privacy Modals
    document.getElementById('btnPrivacyModal')?.addEventListener('click', () => {
      document.getElementById('privacyModal')?.classList.add('active');
    });

    document.getElementById('btnAuditPrivacy')?.addEventListener('click', () => {
      document.getElementById('privacyModal')?.classList.add('active');
    });

    document.getElementById('closePrivacyModalBtn')?.addEventListener('click', closeAllModals);

    // 9. Search Bar
    const searchInput = document.getElementById('eventSearchInput');
    searchInput?.addEventListener('input', (e) => {
      state.filterText = e.target.value.toLowerCase().trim();
      renderActivityTable();
    });

    // 10. Process Clusters Filter
    document.querySelectorAll('.cluster-card').forEach(card => {
      card.addEventListener('click', () => {
        const filterKey = card.getAttribute('data-filter');
        if (state.filterCluster === filterKey) {
          state.filterCluster = null;
          card.classList.remove('active-cluster');
        } else {
          document.querySelectorAll('.cluster-card').forEach(c => c.classList.remove('active-cluster'));
          card.classList.add('active-cluster');
          state.filterCluster = filterKey;
        }
        renderActivityTable();
      });
    });

    // Clear Filters
    document.getElementById('btnClearFilter')?.addEventListener('click', () => {
      state.filterText = '';
      state.filterCluster = null;
      state.activeSeg = 'all';
      if (searchInput) searchInput.value = '';
      document.querySelectorAll('.cluster-card').forEach(c => c.classList.remove('active-cluster'));
      document.querySelectorAll('.seg-tab').forEach(t => t.classList.remove('active'));
      document.querySelector('.seg-tab[data-seg="all"]')?.classList.add('active');
      renderActivityTable();
    });

    document.getElementById('btnViewProfilesLink')?.addEventListener('click', () => {
      switchView('profilesView');
    });

    document.getElementById('btnAckAllTop')?.addEventListener('click', () => {
      state.alerts.forEach(a => a.acknowledged = true);
      renderUI();
    });

    // Modal Background Click Closes
    document.querySelectorAll('.modal-overlay').forEach(modal => {
      modal.addEventListener('click', (e) => {
        if (e.target === modal) closeAllModals();
      });
    });

    // Keyboard Shortcuts (⌘K, ⌘I, Escape)
    window.addEventListener('keydown', (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        searchInput?.focus();
      } else if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'i') {
        e.preventDefault();
        if (state.selectedEventId) openProcessModal(state.selectedEventId);
      } else if (e.key === 'Escape') {
        closeAllModals();
      }
    });
  }

  // --- SYSTEM UPTIME CLOCK ---
  const startTime = Date.now();
  function startClock() {
    const uptimeEl = document.getElementById('systemUptime');
    setInterval(() => {
      if (uptimeEl) {
        const diffSec = Math.floor((Date.now() - startTime) / 1000) + 9912; // Start with realistic uptime
        const hrs = String(Math.floor(diffSec / 3600)).padStart(2, '0');
        const mins = String(Math.floor((diffSec % 3600) / 60)).padStart(2, '0');
        const secs = String(diffSec % 60).padStart(2, '0');
        uptimeEl.textContent = `Up: ${hrs}:${mins}:${secs}`;
      }
      const statusClock = document.getElementById('statusbarClock');
      if (statusClock) {
        const d = new Date();
        statusClock.textContent = d.toTimeString().split(' ')[0] + ' UTC';
      }
    }, 1000);
  }

  // --- INITIALIZATION ---
  document.addEventListener('DOMContentLoaded', () => {
    initSeedData();
    setupEventListeners();
    renderUI();
    startClock();
  });

})();
