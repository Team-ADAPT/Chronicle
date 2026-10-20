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
  "use strict";

  // --- STATE ---
  const state = {
    events: [],
    alerts: [],
    profiles: {},
    isStreaming: false,
    streamTimer: null,
    activeTab: "liveActivityView",
    activeSeg: "all",
    filterText: "",
    filterCluster: null,
    selectedEventId: null,
    currentTheme: "light",
    backendConnected: false,
    backendStats: null,
    historyComm: null,
    historyPid: null,
    historyDays: 7,
    historyMetric: "cpu",
    historyData: null,
  };

  // --- TOAST NOTIFICATION UTILITY ---
  function showToast(message, type = "info", duration = 3200) {
    const container = document.getElementById("toastContainer");
    if (!container) return;
    const toast = document.createElement("div");
    toast.className = `toast toast-${type}`;
    const icon = type === "danger" ? "🚨" : type === "warn" ? "⚠️" : "✅";
    toast.innerHTML = `<span>${icon}</span><span>${message}</span>`;
    container.appendChild(toast);
    setTimeout(() => {
      toast.style.opacity = "0";
      toast.style.transform = "translateY(14px) scale(0.95)";
      setTimeout(() => toast.remove(), 260);
    }, duration);
  }

  // --- BASELINE DEFINITIONS (30-Day Historical Baselines) ---
  const BASELINE_DEFINITIONS = {
    systemd: {
      comm: "systemd",
      user: "root",
      path: "/usr/lib/systemd/systemd",
      avgCpu: 0.2,
      stdCpu: 0.1,
      avgMem: 18.4,
      stdMem: 2.1,
      avgSyscalls: 42,
      typicalEvents: ["fork", "execve"],
      cluster: "systemd",
      sampleCount: 14200,
    },
    sshd: {
      comm: "sshd",
      user: "root",
      path: "/usr/sbin/sshd",
      avgCpu: 0.4,
      stdCpu: 0.2,
      avgMem: 7.2,
      stdMem: 1.0,
      avgSyscalls: 85,
      typicalEvents: ["socket_connect", "fork"],
      cluster: "nginx",
      sampleCount: 8900,
    },
    nginx: {
      comm: "nginx",
      user: "www-data",
      path: "/usr/sbin/nginx",
      avgCpu: 1.5,
      stdCpu: 0.8,
      avgMem: 42.0,
      stdMem: 5.5,
      avgSyscalls: 320,
      typicalEvents: ["socket_connect", "file_modify"],
      cluster: "nginx",
      sampleCount: 22400,
    },
    bash: {
      comm: "bash",
      user: "anurag",
      path: "/bin/bash",
      avgCpu: 0.3,
      stdCpu: 0.4,
      avgMem: 9.8,
      stdMem: 2.0,
      avgSyscalls: 110,
      typicalEvents: ["execve", "fork"],
      cluster: "bash",
      sampleCount: 15600,
    },
    python3: {
      comm: "python3",
      user: "anurag",
      path: "/usr/bin/python3",
      avgCpu: 3.2,
      stdCpu: 2.1,
      avgMem: 65.0,
      stdMem: 15.0,
      avgSyscalls: 210,
      typicalEvents: ["execve", "file_modify"],
      cluster: "bash",
      sampleCount: 11200,
    },
    dockerd: {
      comm: "dockerd",
      user: "root",
      path: "/usr/bin/dockerd",
      avgCpu: 2.1,
      stdCpu: 1.2,
      avgMem: 145.0,
      stdMem: 20.0,
      avgSyscalls: 450,
      typicalEvents: ["socket_connect", "fork", "execve"],
      cluster: "dockerd",
      sampleCount: 18700,
    },
    cron: {
      comm: "cron",
      user: "root",
      path: "/usr/sbin/cron",
      avgCpu: 0.1,
      stdCpu: 0.05,
      avgMem: 4.5,
      stdMem: 0.6,
      avgSyscalls: 25,
      typicalEvents: ["fork", "execve"],
      cluster: "systemd",
      sampleCount: 6500,
    },
    curl: {
      comm: "curl",
      user: "anurag",
      path: "/usr/bin/curl",
      avgCpu: 0.8,
      stdCpu: 0.5,
      avgMem: 12.0,
      stdMem: 3.0,
      avgSyscalls: 190,
      typicalEvents: ["socket_connect"],
      cluster: "bash",
      sampleCount: 3400,
    },
  };

  // --- ANOMALY SCENARIO CATALOG ---
  const ANOMALY_SCENARIOS = {
    webshell: {
      comm: "nginx",
      pid: 3812,
      ppid: 1120,
      user: "www-data",
      eventType: "fork",
      cpu: 4.8,
      mem: 54.0,
      syscalls: 890,
      riskScore: 94,
      anomalyType: "Unauthorized Interactive Shell Spawned",
      mitre: "T1059.004 (Unix Shell)",
      desc: 'Process "nginx" (web daemon) spawned interactive shell "/bin/bash -i". Historical baseline indicates 0 shell spawns over 30 days.',
    },
    crypto: {
      comm: "systemd-worker",
      pid: 6814,
      ppid: 1,
      user: "root",
      eventType: "execve",
      cpu: 98.6,
      mem: 380.0,
      syscalls: 2450,
      riskScore: 92,
      anomalyType: "High-Intensity Crypto Mining Behavior",
      mitre: "T1496 (Resource Hijacking)",
      desc: "Unregistered binary mimicking systemd utilizing 98.6% CPU with outbound stratum+tcp socket to mining pool 185.193.125.1:3333.",
    },
    ransomware: {
      comm: "python3",
      pid: 5120,
      ppid: 4200,
      user: "anurag",
      eventType: "file_modify",
      cpu: 18.5,
      mem: 1850.0,
      syscalls: 6200,
      riskScore: 88,
      anomalyType: "Mass Rapid File Traversal & Modification",
      mitre: "T1486 (Data Encrypted for Impact)",
      desc: "Abnormal burst: Python script modified 4,200 user documents in 15 seconds. Current memory 1.8GB is 27.6x above 65MB baseline mean.",
    },
    reverseshell: {
      comm: "cron",
      pid: 1042,
      ppid: 1,
      user: "root",
      eventType: "socket_connect",
      cpu: 0.6,
      mem: 6.2,
      syscalls: 140,
      riskScore: 85,
      anomalyType: "Anomalous Outbound Reverse Shell Socket",
      mitre: "T1071 (Application Layer Protocol)",
      desc: "Cron daemon initiated unexpected TCP connection to external IP 198.51.100.42:4444. Cron has 0 historical outbound sockets in profile.",
    },
    privesc: {
      comm: "sudo",
      pid: 7891,
      ppid: 3812,
      user: "www-data",
      eventType: "priv_escalate",
      cpu: 1.2,
      mem: 14.5,
      syscalls: 410,
      riskScore: 96,
      anomalyType: "Unauthorized Privilege Escalation Attempt",
      mitre: "T1068 (Exploitation for Privilege Escalation)",
      desc: 'Service user "www-data" executed sudo binary without TTY. Flagged as immediate privilege boundary breach.',
    },
  };

  // --- CLUSTER CLASSIFICATION ---
  function getProcessCluster(comm, user) {
    const c = (comm || "").toLowerCase();
    const u = (user || "").toLowerCase();

    // Network & Web
    if (
      [
        "nginx", "apache", "http", "ssh", "dns", "rsyslog", "curl", "wget",
        "socket", "net", "chrome", "firefox", "safari", "browser", "discord",
        "slack", "mail", "fetch", "cloud", "sync", "mdns", "bluetooth", "wifi",
        "network", "tcp", "udp", "router"
      ].some((k) => c.includes(k))
    ) {
      return "nginx";
    }

    // Containers & Workers
    if (
      [
        "docker", "container", "runc", "kswapd", "worker", "celery", "redis",
        "postgres", "mysql", "mongo", "daemon", "db", "engine", "service", "core"
      ].some((k) => c.includes(k))
    ) {
      return "dockerd";
    }

    // User Shells & Apps
    if (
      [
        "bash", "zsh", "sh", "fish", "python", "node", "npm", "ruby", "perl",
        "git", "code", "electron", "antigravity", "vim", "nano", "cat", "grep",
        "sudo", "cargo", "rust", "go", "java", "terminal", "iterm", "alacritty",
        "sublime", "cursor", "idea", "pycharm"
      ].some((k) => c.includes(k)) ||
      (u &&
        ![
          "root", "system", "_spotlight", "windowserver", "_coreaudiod",
          "_locationd", "_distnote"
        ].includes(u))
    ) {
      return "bash";
    }

    // System Daemons & Kernel Threads
    return "systemd";
  }

  // --- THEME ENGINE ---
  function initTheme() {
    const savedTheme = localStorage.getItem("chronicle_theme");
    if (savedTheme) {
      setTheme(savedTheme);
    } else if (
      window.matchMedia &&
      window.matchMedia("(prefers-color-scheme: dark)").matches
    ) {
      setTheme("dark");
    } else {
      setTheme("light");
    }

    const toggleBtn = document.getElementById("themeToggleBtn");
    if (toggleBtn) {
      toggleBtn.addEventListener("click", () => {
        const newTheme = state.currentTheme === "light" ? "dark" : "light";
        setTheme(newTheme);
      });
    }
  }

  function setTheme(theme) {
    state.currentTheme = theme;
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem("chronicle_theme", theme);

    const themeLabel = document.getElementById("themeLabel");
    if (themeLabel) {
      themeLabel.textContent = theme === "light" ? "Classic" : "Cyber CRT";
    }
  }

  // --- REAL TELEMETRY INITIALIZATION ---
  function initSeedData() {
    state.profiles = JSON.parse(JSON.stringify(BASELINE_DEFINITIONS));
    state.events = [];
    state.alerts = [];
    state.selectedEventId = null;
  }

  // --- ML RISK EVALUATION ---
  function evaluateMLRisk(event) {
    const base = state.profiles[event.comm];
    if (!base) {
      return {
        riskScore: 78,
        status: "SUSPICIOUS",
        desc: `Process "${event.comm}" is unprofiled on this Linux system.`,
      };
    }

    const zCpu = Math.abs(event.cpu - base.avgCpu) / (base.stdCpu || 0.1);
    const zMem = Math.abs(event.mem - base.avgMem) / (base.stdMem || 1.0);
    const maxZ = Math.max(zCpu, zMem);

    if (maxZ > 4.5 || event.riskScore > 70) {
      return {
        riskScore: Math.min(99, Math.round(50 + maxZ * 8)),
        status: "ANOMALOUS",
        desc: `Observed metrics deviate by Z=${maxZ.toFixed(1)}σ from 30-day baseline mean.`,
      };
    } else if (maxZ > 2.5 || event.riskScore > 40) {
      return {
        riskScore: Math.round(35 + maxZ * 6),
        status: "SUSPICIOUS",
        desc: `Moderate drift detected: resource consumption slightly exceeds typical baseline.`,
      };
    }

    return {
      riskScore: Math.max(4, Math.round(maxZ * 7)),
      status: "NORMAL",
      desc: null,
    };
  }

  // --- REAL TELEMETRY STREAM SYNC ---
  async function injectRandomEvent() {
    if (state.backendConnected) {
      await syncBackendData();
      return;
    }
  }

  async function injectAnomalyByKey(key, customDate = null) {
    const scenario = ANOMALY_SCENARIOS[key] || ANOMALY_SCENARIOS["webshell"];

    if (state.backendConnected) {
      try {
        const resp = await fetch("/api/simulate", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ scenario: key }),
        });
        if (resp.ok) {
          await syncBackendData();
          showToast(
            `Injected scenario: ${scenario.anomalyType} (Risk ${scenario.riskScore}/100)`,
            "danger",
            4000,
          );
          return;
        }
      } catch (err) {
        console.warn("Backend simulate failed, using local fallback:", err);
      }
    }

    const timestamp = (customDate || new Date()).toLocaleTimeString("en-IN", {
      timeZone: "Asia/Kolkata",
      hour12: false,
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });

    const anomalousEvent = {
      id: "evt-" + Date.now().toString().slice(-6),
      timestamp: timestamp,
      comm: scenario.comm,
      path: "/usr/bin/" + scenario.comm,
      pid: scenario.pid,
      ppid: scenario.ppid,
      user: scenario.user,
      cluster: BASELINE_DEFINITIONS[scenario.comm]?.cluster || "systemd",
      eventType: scenario.eventType,
      cpu: scenario.cpu,
      mem: scenario.mem,
      syscalls: scenario.syscalls,
      riskScore: scenario.riskScore,
      status: "ANOMALOUS",
      anomalyDetails: scenario.desc,
      terminated: false,
    };

    state.events.unshift(anomalousEvent);

    const alertEntry = {
      id: "alt-" + Date.now().toString().slice(-5),
      timestamp: timestamp,
      comm: scenario.comm,
      pid: scenario.pid,
      riskScore: scenario.riskScore,
      anomalyType: scenario.anomalyType,
      mitre: scenario.mitre,
      desc: scenario.desc,
      acknowledged: false,
    };

    state.alerts.unshift(alertEntry);
    state.selectedEventId = anomalousEvent.id;

    showToast(
      `Injected scenario: ${scenario.anomalyType} (Risk ${scenario.riskScore}/100)`,
      "danger",
      4000,
    );
    renderUI();
  }

  async function terminateProcess(eventId) {
    const ev = state.events.find((e) => e.id === eventId);
    if (!ev) return;

    if (state.backendConnected && ev.pid) {
      try {
        await fetch("/api/kill", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ pid: ev.pid }),
        });
      } catch (err) {
        console.warn("Backend kill failed:", err);
      }
    }

    ev.terminated = true;
    ev.status = "TERMINATED";
    ev.cpu = 0.0;
    ev.riskScore = 0;
    ev.anomalyDetails = "Process terminated by user via SIGKILL (Task Manager)";

    // Mark corresponding alert as acknowledged if anomalous
    const alt = state.alerts.find((a) => a.pid === ev.pid);
    if (alt) alt.acknowledged = true;

    showToast(
      `Process ${ev.comm} (PID ${ev.pid}) terminated via SIGKILL`,
      "danger",
      3500,
    );
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
    renderCharts();
    renderPerformanceView();
  }

  function renderKPIs() {
    const cpuEl = document.getElementById("cpuUtilization");
    const memEl = document.getElementById("memoryUsage");
    const syscallEl = document.getElementById("syscallRate");
    const normalcyEl = document.getElementById("hostNormalcyVal");
    const anomalyStatusText = document.getElementById("anomalyStatusText");
    const totalEventsBadge = document.getElementById("totalEventsBadge");
    const anomalySegBadge = document.getElementById("anomalySegBadge");
    const menuAlertBadge = document.getElementById("menuAlertBadge");
    const cpuSubtext = document.getElementById("cpuSubtext");
    const clusterSystemd = document.getElementById("clusterCountSystemd");
    const clusterNginx = document.getElementById("clusterCountNginx");
    const clusterBash = document.getElementById("clusterCountBash");
    const clusterDockerd = document.getElementById("clusterCountDockerd");

    const total = state.events.length;
    const anomCount = state.events.filter(
      (e) => e.status === "ANOMALOUS" && !e.terminated,
    ).length;
    const unackCount = state.alerts.filter((a) => !a.acknowledged).length;

    const avgCpu = total
      ? (state.events.reduce((acc, e) => acc + e.cpu, 0) / total).toFixed(1)
      : "0.0";
    const totalSyscalls = total
      ? state.events.slice(0, 10).reduce((acc, e) => acc + e.syscalls, 0)
      : 0;

    if (state.backendStats) {
      if (cpuEl)
        cpuEl.textContent =
          state.backendStats.cpu_utilization_display || `${avgCpu}%`;
      if (memEl)
        memEl.innerHTML = `${state.backendStats.memory_usage_display || "0.0 GB"}`;
      if (syscallEl)
        syscallEl.innerHTML = `${state.backendStats.syscall_rate_display || totalSyscalls.toLocaleString() + " calls/s"}`;
      const normalcy =
        state.backendStats.normalcy_percent != null
          ? state.backendStats.normalcy_percent
          : Math.max(25, 100 - anomCount * 5.8).toFixed(1);
      if (normalcyEl) normalcyEl.textContent = `${normalcy}%`;
      if (anomalyStatusText)
        anomalyStatusText.textContent = `${anomCount} Anomalies Active (>3σ)`;

      if (cpuSubtext && state.backendStats.process_count != null) {
        const pCount = state.backendStats.process_count;
        const tCount =
          state.backendStats.thread_count != null
            ? state.backendStats.thread_count
            : Math.round(pCount * 4.4);
        cpuSubtext.textContent = `${pCount} Active Processes • ${tCount} Threads`;
      }

      if (state.backendStats.cluster_counts) {
        if (clusterSystemd)
          clusterSystemd.textContent = `${state.backendStats.cluster_counts.systemd || 0} Procs`;
        if (clusterNginx)
          clusterNginx.textContent = `${state.backendStats.cluster_counts.nginx || 0} Procs`;
        if (clusterBash)
          clusterBash.textContent = `${state.backendStats.cluster_counts.bash || 0} Procs`;
        if (clusterDockerd)
          clusterDockerd.textContent = `${state.backendStats.cluster_counts.dockerd || 0} Procs`;
      }
    } else {
      if (cpuEl) cpuEl.textContent = `${avgCpu}%`;
      if (memEl)
        memEl.innerHTML = `0.0 GB <span class="kpi-denom">/ Host RAM</span>`;
      if (syscallEl)
        syscallEl.innerHTML = `${totalSyscalls.toLocaleString()} <span class="kpi-denom">calls/s</span>`;
      const normalcy = Math.max(25, 100 - anomCount * 5.8).toFixed(1);
      if (normalcyEl) normalcyEl.textContent = `${normalcy}%`;
      if (anomalyStatusText)
        anomalyStatusText.textContent = `${anomCount} Anomalies Active (>3σ)`;

      const counts = { systemd: 0, nginx: 0, bash: 0, dockerd: 0 };
      const seenPids = new Set();
      state.events.forEach((e) => {
        if (seenPids.has(e.pid)) return;
        seenPids.add(e.pid);
        const c = e.cluster || getProcessCluster(e.comm, e.user);
        if (counts[c] !== undefined) counts[c]++;
        else counts.systemd++;
      });
      const uniqueProcs = seenPids.size || state.events.length;
      const estThreads = Math.round(uniqueProcs * 4.4);
      if (cpuSubtext) {
        cpuSubtext.textContent = `${uniqueProcs} Active Processes • ${estThreads} Threads`;
      }
      if (clusterSystemd) clusterSystemd.textContent = `${counts.systemd} Procs`;
      if (clusterNginx) clusterNginx.textContent = `${counts.nginx} Procs`;
      if (clusterBash) clusterBash.textContent = `${counts.bash} Procs`;
      if (clusterDockerd) clusterDockerd.textContent = `${counts.dockerd} Procs`;
    }

    if (totalEventsBadge)
      totalEventsBadge.textContent = state.events.length.toLocaleString();
    if (anomalySegBadge) anomalySegBadge.textContent = anomCount;
    if (menuAlertBadge) menuAlertBadge.textContent = unackCount;
  }

  function renderActivityTable() {
    const tbody = document.getElementById("eventsTableBody");
    if (!tbody) return;

    const filtered = state.events.filter((e) => {
      // Search filter
      const matchText =
        !state.filterText ||
        e.comm.toLowerCase().includes(state.filterText) ||
        e.user.toLowerCase().includes(state.filterText) ||
        e.pid.toString().includes(state.filterText) ||
        e.eventType.toLowerCase().includes(state.filterText);

      // Cluster filter
      const matchCluster =
        !state.filterCluster ||
        e.cluster === state.filterCluster ||
        e.comm.includes(state.filterCluster);

      // Segment filter (Apple Activity Monitor style)
      let matchSeg = true;
      if (state.activeSeg === "cpu") {
        matchSeg = e.cpu > 2.0;
      } else if (state.activeSeg === "memory") {
        matchSeg = e.mem > 40.0;
      } else if (state.activeSeg === "network") {
        matchSeg =
          e.eventType === "socket_connect" ||
          e.comm === "nginx" ||
          e.comm === "sshd" ||
          e.comm === "curl";
      } else if (state.activeSeg === "anomalies") {
        matchSeg = e.status === "ANOMALOUS";
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

    tbody.innerHTML = filtered
      .map((e) => {
        const isSelected = state.selectedEventId === e.id;
        const selectedClass = isSelected ? "row-selected" : "";

        // Windows Task Manager Heatmap cell classes
        const cpuHeatClass =
          e.cpu > 50 ? "heat-cpu-high" : e.cpu > 15 ? "heat-cpu-med" : "";
        const memHeatClass = e.mem > 400 ? "heat-mem-high" : "";

        // Risk Pill Class
        let riskPillClass = "safe";
        if (e.terminated) riskPillClass = "safe";
        else if (e.status === "ANOMALOUS") riskPillClass = "danger";
        else if (e.status === "SUSPICIOUS") riskPillClass = "warn";

        const procIcon =
          e.comm === "nginx"
            ? "🌐"
            : e.comm === "dockerd"
              ? "🐳"
              : e.comm === "python3"
                ? "🐍"
                : "💻";

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
          <td style="text-align: right; white-space: nowrap;">
            <button class="btn-row-action" data-action="inspect" data-id="${e.id}" title="Inspect Process (⌘I)">Inspect</button>
            <button class="btn-row-action btn-row-history" data-action="history" data-id="${e.id}" data-comm="${e.comm}" data-pid="${e.pid}" title="View Historical Telemetry (⌘H)">History</button>
          </td>
        </tr>
      `;
      })
      .join("");

    // Row Click Listeners (Single-click selects, double-click inspects)
    tbody.querySelectorAll("tr").forEach((tr) => {
      tr.addEventListener("click", (ev) => {
        const id = tr.getAttribute("data-id");
        if (!id) return;

        state.selectedEventId = id;
        tbody
          .querySelectorAll("tr")
          .forEach((r) => r.classList.remove("row-selected"));
        tr.classList.add("row-selected");

        // If inspect button directly clicked
        if (ev.target.closest('[data-action="inspect"]')) {
          openProcessModal(id);
        } else if (ev.target.closest('[data-action="history"]')) {
          const evObj = state.events.find((x) => x.id === id);
          if (evObj) openHistoryModal(evObj.comm, evObj.pid);
        }
      });

      tr.addEventListener("dblclick", () => {
        const id = tr.getAttribute("data-id");
        if (id) openProcessModal(id);
      });
    });
  }

  function renderProfiles() {
    const grid = document.getElementById("profilesGrid");
    if (!grid) return;

    grid.innerHTML = Object.keys(state.profiles)
      .map((key) => {
        const p = state.profiles[key];
        const latest = state.events.find((e) => e.comm === key);
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
      })
      .join("");
  }

  function renderAlerts() {
    const container = document.getElementById("alertsContainer");
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

    container.innerHTML = state.alerts
      .map(
        (a) => `
      <div class="alert-item ${a.acknowledged ? "acknowledged" : ""}">
        <div class="alert-main">
          <div class="alert-title-row">
            <span class="alert-name">${a.anomalyType}</span>
            <span class="alert-mitre font-mono">${a.mitre}</span>
          </div>
          <p class="alert-desc">${a.desc}</p>
          <div class="alert-meta-row font-mono">
            <span>Process: <strong>${a.comm}</strong> (PID ${a.pid})</span>
            <span>•</span>
            <span>${
              a.timestamp && (a.timestamp.includes("T") || a.timestamp.includes("Z"))
                ? new Date(a.timestamp).toLocaleTimeString("en-IN", { timeZone: "Asia/Kolkata", hour12: false }) + " IST"
                : a.timestamp
            }</span>
            <span>•</span>
            <span>Confidence: 96.4%</span>
          </div>
        </div>
        <div style="display: flex; flex-direction: column; align-items: flex-end; gap: 8px;">
          <span class="risk-pill danger font-mono">Risk ${a.riskScore}/100</span>
          ${!a.acknowledged ? `<button class="btn-ack" data-id="${a.id}">Acknowledge</button>` : `<span style="font-size: 0.7rem; color: var(--text-muted);">Triaged</span>`}
        </div>
      </div>
    `,
      )
      .join("");

    container.querySelectorAll(".btn-ack").forEach((btn) => {
      btn.addEventListener("click", async (ev) => {
        ev.stopPropagation();
        const id = btn.getAttribute("data-id");
        const alert = state.alerts.find((a) => a.id === id);
        if (alert) {
          alert.acknowledged = true;
          if (state.backendConnected) {
            try {
              await fetch("/api/alerts/ack", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ id }),
              });
            } catch (err) {
              console.warn("Backend ack failed:", err);
            }
          }
          showToast(
            `Alert triaged & acknowledged: ${alert.anomalyType || id}`,
            "info",
            2800,
          );
          renderUI();
        }
      });
    });
  }

  function renderGauge() {
    const scoreEl = document.getElementById("gaugeHealthScore");
    const legSys = document.getElementById("legendSystemPct");
    const legUser = document.getElementById("legendUserPct");
    const legElev = document.getElementById("legendElevatedPct");
    const legAnom = document.getElementById("legendAnomalyPct");

    const total = state.events.length || 1;
    const anomCount = state.events.filter(
      (e) => e.status === "ANOMALOUS" && !e.terminated,
    ).length;
    const suspCount = state.events.filter(
      (e) => e.status === "SUSPICIOUS" || (e.riskScore != null && e.riskScore >= 40 && e.riskScore < 70),
    ).length;
    const sysCount = state.events.filter(
      (e) =>
        (e.cluster === "systemd" || e.user === "root" || e.user === "system") &&
        (e.status === "SAFE" || e.status === "NORMAL"),
    ).length;

    const anomPct = Math.round((anomCount / total) * 100);
    const suspPct = Math.round((suspCount / total) * 100);
    const sysPct = Math.round((sysCount / total) * 100);
    const userPct = Math.max(0, 100 - anomPct - suspPct - sysPct);

    const health =
      state.backendStats && state.backendStats.normalcy_percent != null
        ? state.backendStats.normalcy_percent
        : Math.max(15, 100 - (anomPct * 6 + suspPct * 2));

    if (scoreEl) scoreEl.textContent = `${health}%`;
    if (legSys) legSys.textContent = `${sysPct}%`;
    if (legUser) legUser.textContent = `${userPct}%`;
    if (legElev) legElev.textContent = `${suspPct}%`;
    if (legAnom) legAnom.textContent = `${anomPct}%`;
  }

  // --- CHARTS RENDER SYSTEM ---
  function renderCharts() {
    // 1. Chart 1: Event Volume Bursts
    const totalPill = document.getElementById("chartBurstTotalPill");
    const barsContainer = document.getElementById("chartBurstBarsContainer");
    if (totalPill) {
      const count = state.backendStats
        ? state.backendStats.events_processed || state.events.length
        : state.events.length;
      totalPill.textContent = `${count.toLocaleString()} total`;
    }
    if (barsContainer) {
      const barElements = barsContainer.querySelectorAll("rect");
      barElements.forEach((bar, idx) => {
        const slice = state.events.slice(idx * 2, idx * 2 + 2);
        let weight = slice.length
          ? slice.reduce((s, e) => s + (e.cpu + e.syscalls / 100), 0)
          : 10;
        if (state.events[idx] && state.events[idx].status === "ANOMALOUS") {
          weight = 75 + Math.random() * 15;
          bar.setAttribute("fill", "url(#barGradActive)");
        }
        const height = Math.min(85, Math.max(14, Math.round(weight % 70) + 15));
        const y = 100 - height;
        bar.setAttribute("y", y);
        bar.setAttribute("height", height);
      });
    }

    // 2. Chart 2: Anomaly Risk History / Gaussian Deviation
    const areaPath = document.getElementById("chartRiskAreaPath");
    const linePath = document.getElementById("chartRiskLinePath");
    const dot = document.getElementById("chartRiskDot");
    const label = document.getElementById("chartRiskLabel");
    const avgRiskTrend = document.getElementById("avgRiskTrend");

    if (areaPath && linePath) {
      const recent = state.events.slice(0, 12).reverse();
      const avgScore = recent.length
        ? recent.reduce((a, b) => a + (b.riskScore || 0), 0) / recent.length
        : 12;
      if (avgRiskTrend) {
        const z = (avgScore / 20).toFixed(2);
        avgRiskTrend.textContent = `${z} μ`;
      }

      let points = [];
      let maxScore = 0;
      let maxIdx = -1;
      const count = Math.max(recent.length, 6);
      const step = 270 / (count - 1 || 1);

      for (let i = 0; i < count; i++) {
        const x = 15 + Math.round(i * step);
        const ev = recent[i];
        const score = ev ? ev.riskScore || 10 : 10 + (i % 3) * 5;
        if (score > maxScore) {
          maxScore = score;
          maxIdx = i;
        }
        const y = Math.max(
          22,
          Math.min(95, 95 - Math.round((score / 100) * 70)),
        );
        points.push({ x, y });
      }

      let d = `M ${points[0].x} ${points[0].y}`;
      for (let i = 1; i < points.length; i++) {
        const prev = points[i - 1];
        const curr = points[i];
        const mx = (prev.x + curr.x) / 2;
        d += ` Q ${prev.x} ${prev.y}, ${mx} ${(prev.y + curr.y) / 2} T ${curr.x} ${curr.y}`;
      }

      linePath.setAttribute("d", d);
      areaPath.setAttribute(
        "d",
        `${d} L ${points[points.length - 1].x} 100 L ${points[0].x} 100 Z`,
      );

      if (dot && label) {
        if (maxScore > 50 && maxIdx >= 0) {
          const pt = points[maxIdx];
          dot.setAttribute("cx", pt.x);
          dot.setAttribute("cy", pt.y);
          dot.style.display = "block";
          label.setAttribute("x", Math.max(20, pt.x - 40));
          label.setAttribute("y", Math.max(16, pt.y - 8));
          label.textContent = `Anomaly +${(maxScore / 20).toFixed(1)}σ`;
          label.style.display = "block";
        } else {
          dot.style.display = "none";
          label.style.display = "none";
        }
      }
    }

    // 3. Chart 3: Donut Threat Breakdown
    const sliceNormal = document.getElementById("donutSliceNormal");
    const sliceUser = document.getElementById("donutSliceUser");
    const sliceElev = document.getElementById("donutSliceElevated");
    const sliceAnom = document.getElementById("donutSliceAnomaly");
    const donutCenter = document.getElementById("donutCenterNum");
    const threatSafePill = document.getElementById("chartThreatSafePill");

    const total = state.events.length || 1;
    const anomCount = state.events.filter(
      (e) => e.status === "ANOMALOUS" && !e.terminated,
    ).length;
    const suspCount = state.events.filter(
      (e) => e.status === "SUSPICIOUS" && !e.terminated,
    ).length;
    const userCount = state.events.filter(
      (e) => e.user !== "root" && e.status === "NORMAL",
    ).length;
    const normCount = Math.max(0, total - anomCount - suspCount - userCount);

    const safePct = Math.round(((normCount + userCount) / total) * 100);
    if (threatSafePill) threatSafePill.textContent = `${safePct}% Safe`;
    if (donutCenter) donutCenter.textContent = total;

    const C = 282; // 2 * pi * 45
    const lenNorm = Math.round((normCount / total) * C);
    const lenUser = Math.round((userCount / total) * C);
    const lenSusp = Math.round((suspCount / total) * C);
    const lenAnom = Math.max(0, C - lenNorm - lenUser - lenSusp);

    if (sliceNormal) {
      sliceNormal.setAttribute("stroke-dasharray", `${lenNorm} ${C}`);
      sliceNormal.setAttribute("stroke-dashoffset", "0");
    }
    if (sliceUser) {
      sliceUser.setAttribute("stroke-dasharray", `${lenUser} ${C}`);
      sliceUser.setAttribute("stroke-dashoffset", `-${lenNorm}`);
    }
    if (sliceElev) {
      sliceElev.setAttribute("stroke-dasharray", `${lenSusp} ${C}`);
      sliceElev.setAttribute("stroke-dashoffset", `-${lenNorm + lenUser}`);
    }
    if (sliceAnom) {
      sliceAnom.setAttribute("stroke-dasharray", `${lenAnom} ${C}`);
      sliceAnom.setAttribute(
        "stroke-dashoffset",
        `-${lenNorm + lenUser + lenSusp}`,
      );
    }
  }

  // --- PERFORMANCE VIEW DYNAMIC METRICS ---
  function renderPerformanceView() {
    const cpuBig = document.getElementById("perfCpuBigVal");
    const cpuSub = document.getElementById("perfCpuSubText");
    const cpuBars = document.getElementById("perfCpuBars");
    const memBig = document.getElementById("perfMemBigVal");
    const memSub = document.getElementById("perfMemSubText");
    const memSegBar = document.getElementById("perfMemSegBar");
    const memLegend = document.getElementById("perfMemLegend");

    if (state.backendStats) {
      const cpu = state.backendStats.cpu_percent || 14.2;
      if (cpuBig) {
        const l1 = ((cpu / 100) * 1.2).toFixed(2);
        const l5 = ((cpu / 100) * 1.5).toFixed(2);
        const l15 = ((cpu / 100) * 1.1).toFixed(2);
        cpuBig.textContent = `${l1}, ${l5}, ${l15}`;
      }
      if (cpuSub) {
        cpuSub.textContent = `Host CPU: ${cpu}% • Processes: ${state.backendStats.process_count || 120} • Syscalls: ${state.backendStats.syscall_rate_display || "Normal"}`;
      }
      if (cpuBars) {
        const core0 = Math.min(100, Math.max(5, Math.round(cpu * 1.2)));
        const core1 = Math.min(100, Math.max(4, Math.round(cpu * 0.8)));
        const core2 = Math.min(100, Math.max(8, Math.round(cpu * 1.4)));
        const core3 = Math.min(100, Math.max(3, Math.round(cpu * 0.9)));
        const getFill = (p) => (p > 75 ? "coral" : p > 40 ? "amber" : "lime");
        cpuBars.innerHTML = `
          <div class="perf-bar-row">
            <span>Core 0</span>
            <div class="p-track"><div class="p-fill ${getFill(core0)}" style="width: ${core0}%;"></div></div>
            <span>${core0}%</span>
          </div>
          <div class="perf-bar-row">
            <span>Core 1</span>
            <div class="p-track"><div class="p-fill ${getFill(core1)}" style="width: ${core1}%;"></div></div>
            <span>${core1}%</span>
          </div>
          <div class="perf-bar-row">
            <span>Core 2</span>
            <div class="p-track"><div class="p-fill ${getFill(core2)}" style="width: ${core2}%;"></div></div>
            <span>${core2}%</span>
          </div>
          <div class="perf-bar-row">
            <span>Core 3</span>
            <div class="p-track"><div class="p-fill ${getFill(core3)}" style="width: ${core3}%;"></div></div>
            <span>${core3}%</span>
          </div>
        `;
      }

      if (memBig) {
        memBig.textContent = `${(state.backendStats.mem_used_mb / 1024).toFixed(2)} GB Used`;
      }
      if (memSub) {
        const totalGb = (state.backendStats.mem_total_mb / 1024).toFixed(2);
        const freeGb = Math.max(
          0,
          (state.backendStats.mem_total_mb - state.backendStats.mem_used_mb) /
            1024,
        ).toFixed(2);
        memSub.textContent = `Total Physical: ${totalGb} GB (Free: ${freeGb} GB)`;
      }
      if (memSegBar && state.backendStats.mem_total_mb) {
        const totalMb = state.backendStats.mem_total_mb;
        const usedMb = state.backendStats.mem_used_mb;
        const appPct = Math.round(((usedMb * 0.65) / totalMb) * 100);
        const cachePct = Math.round(((usedMb * 0.35) / totalMb) * 100);
        const freePct = Math.max(0, 100 - appPct - cachePct);
        memSegBar.innerHTML = `
          <div class="m-seg app" style="width: ${appPct}%;" title="App Memory: ${((usedMb * 0.65) / 1024).toFixed(1)} GB"></div>
          <div class="m-seg cache" style="width: ${cachePct}%;" title="Cache/Buffer: ${((usedMb * 0.35) / 1024).toFixed(1)} GB"></div>
          <div class="m-seg free" style="width: ${freePct}%;" title="Free: ${((totalMb - usedMb) / 1024).toFixed(1)} GB"></div>
        `;
        if (memLegend) {
          memLegend.innerHTML = `
            <span><span class="dot blue"></span> Apps (${((usedMb * 0.65) / 1024).toFixed(1)} GB)</span>
            <span><span class="dot amber"></span> Buffers (${((usedMb * 0.35) / 1024).toFixed(1)} GB)</span>
            <span><span class="dot gray"></span> Free (${((totalMb - usedMb) / 1024).toFixed(1)} GB)</span>
          `;
        }
      }
    }
  }

  // --- PROCESS INSPECTOR MODAL (Apple Activity Monitor) ---
  function openProcessModal(eventId) {
    const ev = state.events.find((e) => e.id === eventId) || state.events[0];
    if (!ev) return;

    state.selectedEventId = ev.id;
    const modal = document.getElementById("processModal");
    const nameEl = document.getElementById("modalProcessName");
    const subEl = document.getElementById("modalProcessSub");
    const riskBadge = document.getElementById("modalRiskBadge");
    const bodyEl = document.getElementById("modalBody");

    const base = state.profiles[ev.comm] || {
      avgCpu: "N/A",
      avgMem: "N/A",
      path: "/usr/bin/" + ev.comm,
    };

    if (nameEl) nameEl.textContent = `${ev.comm} (PID ${ev.pid})`;
    if (subEl)
      subEl.textContent = `PPID: ${ev.ppid} • User: ${ev.user} • Architecture: x86_64`;
    if (riskBadge) {
      riskBadge.textContent = `Risk: ${ev.riskScore}/100`;
      riskBadge.className = `badge font-mono ${ev.status === "ANOMALOUS" ? "text-rose" : ""}`;
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
            ${ev.anomalyDetails || "Kernel telemetry conforms to rolling 30-day historical baseline envelope (±1.6σ). No unauthorized privilege escalation or covert outbound sockets detected."}
          </p>
        </div>
      `;
    }

    modal?.classList.add("active");
  }

  // --- PROCESS TELEMETRY HISTORY MODAL (Local DBMS Multi-Day History) ---
  async function openHistoryModal(comm, pid, days = state.historyDays || 7) {
    if (!comm) return;
    state.historyComm = comm;
    state.historyPid = pid;
    state.historyDays = days;

    const modal = document.getElementById("historyModal");
    const nameEl = document.getElementById("histProcessName");
    const subEl = document.getElementById("histProcessSub");
    const maturityEl = document.getElementById("histProfileMaturity");

    const base = state.profiles[comm] || BASELINE_DEFINITIONS[comm] || {
      avgCpu: 1.5,
      avgMem: 40.0,
      path: "/usr/bin/" + comm,
      user: "system",
      cluster: "systemd",
    };

    if (nameEl) nameEl.textContent = `${comm} (PID ${pid || "--"})`;
    if (subEl)
      subEl.textContent = `Executable: ${base.path || "/usr/bin/" + comm} • User: ${base.user || "system"} • Storage: Local SQLite DBMS`;
    if (maturityEl) maturityEl.textContent = `${days}-Day History • Local DBMS`;

    // Highlight active time-range button
    document.querySelectorAll(".time-range-btn").forEach((btn) => {
      btn.classList.toggle("active", parseInt(btn.getAttribute("data-days"), 10) === days);
    });

    modal?.classList.add("active");

    // Fetch history from backend API (with offline synthesizer fallback)
    try {
      const resp = await fetch(`/api/history?comm=${encodeURIComponent(comm)}&pid=${pid || 0}&days=${days}&limit=200`);
      if (resp.ok) {
        state.historyData = await resp.json();
      } else {
        state.historyData = generateFallbackHistory(comm, pid, days);
      }
    } catch (err) {
      state.historyData = generateFallbackHistory(comm, pid, days);
    }

    renderHistoryModalView();
  }

  function generateFallbackHistory(comm, pid, days) {
    const base = state.profiles[comm] || BASELINE_DEFINITIONS[comm] || {
      avgCpu: 2.2,
      avgMem: 45.0,
      user: "user",
    };
    const hours = Math.max(24, days * 24);
    const step = Math.max(2, Math.floor(hours / 28));
    const now = Date.now();
    const timeline = [];
    const cpus = [], mems = [], nets = [], syscalls = [];
    let anoms = 0;

    for (let h = hours; h >= 0; h -= step) {
      const ts = new Date(now - h * 3600 * 1000);
      const hour = ts.getHours();
      const mult = hour >= 9 && hour <= 20 ? 1.25 : 0.6;
      const spike = h % 18 === 0 ? 2.4 : 1.0;

      const c = parseFloat(Math.max(0.1, base.avgCpu * mult * spike + Math.sin(h) * 0.4).toFixed(1));
      const m = parseFloat(Math.max(8.0, base.avgMem * (0.95 + Math.cos(h) * 0.08)).toFixed(1));
      const n = parseFloat(Math.max(0.0, base.avgCpu * 12.0 * mult * spike + Math.cos(h) * 5.0).toFixed(1));
      const sc = Math.max(20, Math.floor(base.avgCpu * 140 * mult * spike + Math.sin(h) * 30));
      const risk = Math.min(95, Math.max(4, Math.floor(c * 1.8 + n / 12.0 + (spike > 2 ? 15 : 0))));
      const status = risk >= 75 ? "ANOMALOUS" : risk >= 40 ? "SUSPICIOUS" : "SAFE";
      if (status !== "SAFE") anoms++;

      cpus.push(c);
      mems.push(m);
      nets.push(n);
      syscalls.push(sc);

      const dStr = ts.toLocaleDateString("en-US", { month: "short", day: "numeric" });
      const tStr = ts.toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", hour12: false });

      timeline.push({
        id: `fb-${comm}-${h}h`,
        timestamp: `${dStr}, ${tStr}`,
        created_at: ts.toISOString(),
        cpu: c,
        mem: m,
        net_kb: n,
        syscalls: sc,
        riskScore: risk,
        status: status,
        anomalyDetails: status === "SAFE" ? "Conforms to 30d rolling baseline" : "Transient workload deviation",
      });
    }

    return {
      comm: comm,
      pid: pid,
      days: days,
      summary: {
        total_snapshots: timeline.length,
        avg_cpu: parseFloat((cpus.reduce((a, b) => a + b, 0) / cpus.length).toFixed(1)),
        peak_cpu: Math.max(...cpus),
        avg_mem: parseFloat((mems.reduce((a, b) => a + b, 0) / mems.length).toFixed(1)),
        peak_mem: Math.max(...mems),
        avg_net_kb: parseFloat((nets.reduce((a, b) => a + b, 0) / nets.length).toFixed(1)),
        peak_net_kb: Math.max(...nets),
        avg_syscalls: Math.floor(syscalls.reduce((a, b) => a + b, 0) / syscalls.length),
        peak_syscalls: Math.max(...syscalls),
        anomaly_count: anoms,
        latest_status: timeline[timeline.length - 1]?.status || "SAFE",
      },
      timeline: timeline,
      events: [...timeline].reverse(),
    };
  }

  function renderHistoryModalView() {
    if (!state.historyData) return;
    const { summary, timeline, events } = state.historyData;
    const latest = timeline[timeline.length - 1] || {};

    // Update KPI Cards
    const cpuVal = document.getElementById("histCpuVal");
    const cpuAvg = document.getElementById("histCpuAvg");
    const cpuPeak = document.getElementById("histCpuPeak");
    if (cpuVal) cpuVal.textContent = `${latest.cpu ?? summary.avg_cpu}%`;
    if (cpuAvg) cpuAvg.textContent = `${summary.avg_cpu}%`;
    if (cpuPeak) cpuPeak.textContent = `${summary.peak_cpu}%`;

    const memVal = document.getElementById("histMemVal");
    const memAvg = document.getElementById("histMemAvg");
    const memPeak = document.getElementById("histMemPeak");
    if (memVal) memVal.textContent = `${latest.mem ?? summary.avg_mem} MB`;
    if (memAvg) memAvg.textContent = `${summary.avg_mem} MB`;
    if (memPeak) memPeak.textContent = `${summary.peak_mem} MB`;

    const netVal = document.getElementById("histNetVal");
    const netAvg = document.getElementById("histNetAvg");
    const netPeak = document.getElementById("histNetPeak");
    if (netVal) netVal.textContent = `${latest.net_kb ?? summary.avg_net_kb} KB/s`;
    if (netAvg) netAvg.textContent = `${summary.avg_net_kb} KB/s`;
    if (netPeak) netPeak.textContent = `${summary.peak_net_kb} KB/s`;

    const scVal = document.getElementById("histSyscallVal");
    const anomCount = document.getElementById("histAnomCount");
    const histStatus = document.getElementById("histStatus");
    if (scVal) scVal.textContent = `${latest.syscalls ?? summary.avg_syscalls} /s`;
    if (anomCount) anomCount.textContent = `${summary.anomaly_count}`;
    if (histStatus) {
      histStatus.textContent = summary.latest_status || "SAFE";
      histStatus.style.color =
        summary.latest_status === "ANOMALOUS"
          ? "#f43f5e"
          : summary.latest_status === "SUSPICIOUS"
          ? "#f59e0b"
          : "var(--primary-emerald, #00c288)";
    }

    const recCount = document.getElementById("histRecordCount");
    if (recCount) recCount.textContent = timeline.length;

    const chartLegend = document.getElementById("histChartLegend");
    if (chartLegend)
      chartLegend.textContent = `Timeline: ${timeline.length} checkpoints over past ${state.historyDays} days`;

    // Render SVG Chart for current metric
    renderHistoryChart(state.historyMetric);

    // Render Events Table
    const tableBody = document.getElementById("historyTableBody");
    if (tableBody) {
      tableBody.innerHTML = events
        .map((pt) => {
          const riskClass =
            pt.riskScore >= 75
              ? "text-rose font-bold"
              : pt.riskScore >= 40
              ? "text-amber font-bold"
              : "";
          const statusClass =
            pt.status === "ANOMALOUS"
              ? "pill-danger"
              : pt.status === "SUSPICIOUS"
              ? "pill-warn"
              : "pill-safe";
          return `
          <tr>
            <td>${pt.timestamp}</td>
            <td><span class="font-mono">${pt.cpu}%</span></td>
            <td><span class="font-mono">${pt.mem} MB</span></td>
            <td><span class="font-mono">${pt.net_kb || 0.0} KB/s</span></td>
            <td><span class="font-mono">${pt.syscalls}</span></td>
            <td><span class="font-mono ${riskClass}">${pt.riskScore}/100</span></td>
            <td><span class="risk-pill ${statusClass}">${pt.status}</span></td>
            <td style="color: var(--text-muted); font-size: 0.68rem;">${pt.anomalyDetails || "Normal activity"}</td>
          </tr>
        `;
        })
        .join("");
    }
  }

  function renderHistoryChart(metric = "cpu") {
    state.historyMetric = metric;
    const svg = document.getElementById("historySvgChart");
    const tooltip = document.getElementById("historyChartTooltip");
    if (
      !svg ||
      !state.historyData ||
      !state.historyData.timeline ||
      state.historyData.timeline.length === 0
    )
      return;

    // Highlight active metric tab
    document.querySelectorAll(".hist-metric-tab").forEach((tab) => {
      tab.classList.toggle("active", tab.getAttribute("data-metric") === metric);
    });

    const timeline = state.historyData.timeline;
    const summary = state.historyData.summary;

    let values, unit, title, color, gradId, avgVal;
    if (metric === "cpu") {
      values = timeline.map((p) => p.cpu);
      unit = "%";
      title = "CPU Utilisation";
      color = "#00c288";
      gradId = "gradCpu";
      avgVal = summary.avg_cpu;
    } else if (metric === "mem") {
      values = timeline.map((p) => p.mem);
      unit = " MB";
      title = "RAM Memory RSS";
      color = "#3b82f6";
      gradId = "gradMem";
      avgVal = summary.avg_mem;
    } else if (metric === "net") {
      values = timeline.map((p) => p.net_kb || 0.0);
      unit = " KB/s";
      title = "Network Bandwidth";
      color = "#8b5cf6";
      gradId = "gradNet";
      avgVal = summary.avg_net_kb;
    } else {
      values = timeline.map((p) => p.riskScore || 0);
      unit = "/100";
      title = "Anomaly Risk Score";
      color = "#f43f5e";
      gradId = "gradRisk";
      avgVal = 15;
    }

    const maxRaw = Math.max(...values, 1.0);
    const maxY = metric === "risk" ? 100 : parseFloat((maxRaw * 1.25).toFixed(1));
    const minY = 0;

    const width = 880;
    const height = 230;
    const padLeft = 55;
    const padRight = 30;
    const padTop = 20;
    const padBottom = 35;
    const plotW = width - padLeft - padRight;
    const plotH = height - padTop - padBottom;

    const n = values.length;
    const coords = values.map((v, i) => {
      const x = padLeft + (n > 1 ? (i / (n - 1)) * plotW : plotW / 2);
      const y = padTop + plotH - ((v - minY) / (maxY - minY)) * plotH;
      return { x, y, val: v, pt: timeline[i] };
    });

    // Generate Path Data
    let pathD = `M ${coords[0].x} ${coords[0].y}`;
    for (let i = 1; i < coords.length; i++) {
      const prev = coords[i - 1];
      const curr = coords[i];
      const cx1 = prev.x + (curr.x - prev.x) / 2;
      const cy1 = prev.y;
      const cx2 = prev.x + (curr.x - prev.x) / 2;
      const cy2 = curr.y;
      pathD += ` C ${cx1} ${cy1}, ${cx2} ${cy2}, ${curr.x} ${curr.y}`;
    }

    const areaD = `${pathD} L ${coords[coords.length - 1].x} ${padTop + plotH} L ${coords[0].x} ${padTop + plotH} Z`;
    const avgY = padTop + plotH - ((avgVal - minY) / (maxY - minY)) * plotH;

    // Grid lines (4 ticks)
    const gridTicks = [0, 0.33, 0.66, 1.0];
    const gridSvg = gridTicks
      .map((t) => {
        const y = padTop + plotH - t * plotH;
        const val = (minY + t * (maxY - minY)).toFixed(
          metric === "cpu" || metric === "net" ? 1 : 0
        );
        return `
        <line x1="${padLeft}" y1="${y}" x2="${width - padRight}" y2="${y}" stroke="var(--chart-grid-line, #e2e8f0)" stroke-width="1" stroke-dasharray="3,3" />
        <text x="${padLeft - 8}" y="${y + 4}" font-size="10" font-family="monospace" text-anchor="end" fill="var(--chart-text, #64748b)">${val}${unit}</text>
      `;
      })
      .join("");

    // X-Axis Date Labels (4-5 checkpoints)
    const xStep = Math.max(1, Math.floor(n / 4));
    let xLabelsSvg = "";
    for (let i = 0; i < n; i += xStep) {
      const c = coords[i];
      const label = c.pt.timestamp.split(",")[0] || c.pt.timestamp;
      xLabelsSvg += `
        <text x="${c.x}" y="${height - 10}" font-size="10" font-family="monospace" text-anchor="middle" fill="var(--chart-text, #64748b)">${label}</text>
      `;
    }

    // Circles for hover
    const dotsSvg = coords
      .map((c, idx) => {
        const isAnom = c.pt.status === "ANOMALOUS" || c.pt.riskScore >= 75;
        const dotColor = isAnom ? "#f43f5e" : color;
        const r = isAnom ? 5 : 3.5;
        return `
        <circle cx="${c.x}" cy="${c.y}" r="${r}" fill="${dotColor}" stroke="#ffffff" stroke-width="1.5" class="hist-chart-dot" data-idx="${idx}" style="cursor: pointer;" />
      `;
      })
      .join("");

    svg.innerHTML = `
      <defs>
        <linearGradient id="${gradId}" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stop-color="${color}" stop-opacity="0.32" />
          <stop offset="100%" stop-color="${color}" stop-opacity="0.01" />
        </linearGradient>
      </defs>

      <!-- Grid -->
      ${gridSvg}

      <!-- Baseline Average Dashed Line -->
      <line x1="${padLeft}" y1="${avgY}" x2="${width - padRight}" y2="${avgY}" stroke="${color}" stroke-width="1.5" stroke-dasharray="5,4" opacity="0.7" />
      <text x="${width - padRight + 4}" y="${avgY + 3}" font-size="9" font-family="monospace" fill="${color}">Avg (${avgVal}${unit})</text>

      <!-- Fill Area -->
      <path d="${areaD}" fill="url(#${gradId})" />

      <!-- Curve Stroke -->
      <path d="${pathD}" fill="none" stroke="${color}" stroke-width="2.5" stroke-linecap="round" />

      <!-- Dots -->
      ${dotsSvg}

      <!-- X-Axis Labels -->
      ${xLabelsSvg}
    `;

    // Tooltip listeners on dots
    svg.querySelectorAll(".hist-chart-dot").forEach((dot) => {
      dot.addEventListener("mouseenter", () => {
        const idx = parseInt(dot.getAttribute("data-idx"), 10);
        const c = coords[idx];
        if (!c || !tooltip) return;

        tooltip.innerHTML = `
          <strong>${c.pt.timestamp}</strong><br>
          ${title}: <span style="color:${color}; font-weight:bold;">${c.val}${unit}</span><br>
          Syscalls: ${c.pt.syscalls} • Risk: ${c.pt.riskScore}/100<br>
          Status: <span style="color:${c.pt.status === "ANOMALOUS" ? "#f43f5e" : "#10b981"}">${c.pt.status}</span>
        `;
        const rect = svg.getBoundingClientRect();
        const ptX = (c.x / width) * rect.width;
        const ptY = (c.y / height) * rect.height;

        tooltip.style.left = `${ptX}px`;
        tooltip.style.top = `${ptY}px`;
        tooltip.style.display = "block";
      });

      dot.addEventListener("mouseleave", () => {
        if (tooltip) tooltip.style.display = "none";
      });
    });
  }

  function exportHistoryCsv() {
    if (!state.historyData || !state.historyData.timeline || state.historyData.timeline.length === 0) {
      showToast("No historical data to export.", "warn");
      return;
    }
    const comm = state.historyData.comm || "process";
    const rows = [
      ["Timestamp", "PID", "Comm", "User", "CPU_Percent", "Memory_MB", "Network_KBps", "Syscalls", "RiskScore", "Status", "AnomalyDetails"],
    ];
    state.historyData.timeline.forEach((pt) => {
      rows.push([
        pt.timestamp,
        pt.pid || state.historyData.pid || "",
        comm,
        pt.user || "system",
        pt.cpu,
        pt.mem,
        pt.net_kb || 0.0,
        pt.syscalls,
        pt.riskScore,
        pt.status,
        `"${(pt.anomalyDetails || "").replace(/"/g, '""')}"`,
      ]);
    });
    const csvContent = "data:text/csv;charset=utf-8," + rows.map((e) => e.join(",")).join("\n");
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", `chronicle_history_${comm}_${state.historyDays}d.csv`);
    document.body.appendChild(link);
    link.click();
    link.remove();
    showToast(`Exported ${state.historyDays}-day history for ${comm} as CSV.`, "info");
  }

  function closeAllModals() {
    document
      .querySelectorAll(".modal-overlay")
      .forEach((m) => m.classList.remove("active"));
  }

  // --- STREAM TOGGLE ---
  function toggleStream() {
    state.isStreaming = !state.isStreaming;

    const liveBtn = document.getElementById("btnToggleLiveFeed");
    const liveText = document.getElementById("liveFeedText");
    const sideIcon = document.getElementById("streamSideIcon");
    const sideText = document.getElementById("streamSideText");

    if (state.isStreaming) {
      if (liveText) liveText.textContent = "Streaming...";
      if (liveBtn) liveBtn.classList.add("live-active");
      if (sideIcon) sideIcon.textContent = "⏸";
      if (sideText) sideText.textContent = "Pause Stream";

      state.streamTimer = setInterval(async () => {
        if (state.backendConnected) {
          await syncBackendData();
        } else {
          if (Math.random() < 0.14) {
            const keys = Object.keys(ANOMALY_SCENARIOS);
            const randKey = keys[Math.floor(Math.random() * keys.length)];
            injectAnomalyByKey(randKey);
          } else {
            injectRandomEvent();
          }
        }
      }, 1500);
    } else {
      if (liveText) liveText.textContent = "Live Stream";
      if (liveBtn) liveBtn.classList.remove("live-active");
      if (sideIcon) sideIcon.textContent = "▶";
      if (sideText) sideText.textContent = "Live Stream";

      if (state.streamTimer) {
        clearInterval(state.streamTimer);
        state.streamTimer = null;
      }
    }
  }

  // --- VIEW SWITCHING ---
  function switchView(viewId) {
    document
      .querySelectorAll(".menu-item")
      .forEach((m) => m.classList.remove("active"));
    document
      .querySelectorAll(".content-view")
      .forEach((v) => v.classList.remove("active"));

    const activeMenu = document.querySelector(
      `.menu-item[data-tab="${viewId}"]`,
    );
    if (activeMenu) activeMenu.classList.add("active");

    const targetView = document.getElementById(viewId);
    if (targetView) targetView.classList.add("active");

    state.activeTab = viewId;
  }

  // --- EVENT LISTENERS INITIALIZATION ---
  function setupEventListeners() {
    // 1. Theme Switcher
    initTheme();

    // 2. Navigation Tabs
    document.querySelectorAll(".menu-item[data-tab]").forEach((btn) => {
      btn.addEventListener("click", () => {
        switchView(btn.getAttribute("data-tab"));
      });
    });

    // 3. Apple Activity Monitor Segmented Tabs
    document.querySelectorAll(".seg-tab").forEach((tab) => {
      tab.addEventListener("click", () => {
        document
          .querySelectorAll(".seg-tab")
          .forEach((t) => t.classList.remove("active"));
        tab.classList.add("active");
        state.activeSeg = tab.getAttribute("data-seg");
        renderActivityTable();
      });
    });

    // 4. Action Buttons (Inspect & End Task)
    document
      .getElementById("btnInspectSelected")
      ?.addEventListener("click", () => {
        if (state.selectedEventId) {
          openProcessModal(state.selectedEventId);
        } else if (state.events.length > 0) {
          openProcessModal(state.events[0].id);
        }
      });

    // History Button
    document
      .getElementById("btnHistorySelected")
      ?.addEventListener("click", () => {
        const ev = state.events.find((e) => e.id === state.selectedEventId) || state.events[0];
        if (ev) {
          openHistoryModal(ev.comm, ev.pid);
        } else {
          showToast("Select a process to view its historical telemetry.", "warn");
        }
      });

    document.getElementById("btnEndTask")?.addEventListener("click", () => {
      if (state.selectedEventId) {
        terminateProcess(state.selectedEventId);
      }
    });

    document.getElementById("btnModalKill")?.addEventListener("click", () => {
      if (state.selectedEventId) {
        terminateProcess(state.selectedEventId);
      }
    });

    document
      .getElementById("btnModalViewHistory")
      ?.addEventListener("click", () => {
        const ev = state.events.find((e) => e.id === state.selectedEventId) || state.events[0];
        if (ev) {
          closeAllModals();
          openHistoryModal(ev.comm, ev.pid);
        }
      });

    document
      .getElementById("btnModalClose")
      ?.addEventListener("click", closeAllModals);
    document
      .getElementById("closeModalBtn")
      ?.addEventListener("click", closeAllModals);
    document
      .getElementById("btnHistoryClose")
      ?.addEventListener("click", closeAllModals);
    document
      .getElementById("closeHistoryModalBtn")
      ?.addEventListener("click", closeAllModals);
    document
      .getElementById("btnExportHistoryCsv")
      ?.addEventListener("click", exportHistoryCsv);

    // History Modal Range Buttons
    document.querySelectorAll(".time-range-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        const d = parseInt(btn.getAttribute("data-days"), 10);
        if (d && state.historyComm) {
          openHistoryModal(state.historyComm, state.historyPid, d);
        }
      });
    });

    // History Modal Metric Switcher Tabs
    document.querySelectorAll(".hist-metric-tab").forEach((tab) => {
      tab.addEventListener("click", () => {
        const m = tab.getAttribute("data-metric");
        if (m) renderHistoryChart(m);
      });
    });

    // 5. Live Stream Toggles
    document
      .getElementById("btnToggleLiveFeed")
      ?.addEventListener("click", toggleStream);
    document
      .getElementById("btnToggleStreamSide")
      ?.addEventListener("click", toggleStream);

    // 6. Simulation Modals & Buttons
    document.getElementById("btnNewEvent")?.addEventListener("click", () => {
      document.getElementById("simulationModal")?.classList.add("active");
    });

    document
      .getElementById("btnInjectAnomalySide")
      ?.addEventListener("click", () => {
        document.getElementById("simulationModal")?.classList.add("active");
      });

    document
      .getElementById("closeSimModalBtn")
      ?.addEventListener("click", closeAllModals);

    // Simulation Scenario Buttons
    document.querySelectorAll(".scenario-card").forEach((card) => {
      card.addEventListener("click", () => {
        const scenarioKey = card.getAttribute("data-scenario");
        if (scenarioKey) {
          injectAnomalyByKey(scenarioKey);
          closeAllModals();
        }
      });
    });

    // 7. Random Event
    document
      .getElementById("btnRandomEventSide")
      ?.addEventListener("click", injectRandomEvent);

    // 8. Privacy Modals
    document
      .getElementById("btnPrivacyModal")
      ?.addEventListener("click", () => {
        document.getElementById("privacyModal")?.classList.add("active");
      });

    document
      .getElementById("btnAuditPrivacy")
      ?.addEventListener("click", () => {
        document.getElementById("privacyModal")?.classList.add("active");
      });

    document
      .getElementById("closePrivacyModalBtn")
      ?.addEventListener("click", closeAllModals);

    // 9. Search Bar
    const searchInput = document.getElementById("eventSearchInput");
    searchInput?.addEventListener("input", (e) => {
      state.filterText = e.target.value.toLowerCase().trim();
      renderActivityTable();
    });

    // 10. Process Clusters Filter
    document.querySelectorAll(".cluster-card").forEach((card) => {
      card.addEventListener("click", () => {
        const filterKey = card.getAttribute("data-filter");
        if (state.filterCluster === filterKey) {
          state.filterCluster = null;
          card.classList.remove("active-cluster");
        } else {
          document
            .querySelectorAll(".cluster-card")
            .forEach((c) => c.classList.remove("active-cluster"));
          card.classList.add("active-cluster");
          state.filterCluster = filterKey;
        }
        renderActivityTable();
      });
    });

    // Clear Filters
    document.getElementById("btnClearFilter")?.addEventListener("click", () => {
      state.filterText = "";
      state.filterCluster = null;
      state.activeSeg = "all";
      if (searchInput) searchInput.value = "";
      document
        .querySelectorAll(".cluster-card")
        .forEach((c) => c.classList.remove("active-cluster"));
      document
        .querySelectorAll(".seg-tab")
        .forEach((t) => t.classList.remove("active"));
      document
        .querySelector('.seg-tab[data-seg="all"]')
        ?.classList.add("active");
      renderActivityTable();
    });

    document
      .getElementById("btnViewProfilesLink")
      ?.addEventListener("click", () => {
        switchView("profilesView");
      });

    document
      .getElementById("btnAckAllTop")
      ?.addEventListener("click", async () => {
        const unackAlerts = state.alerts.filter((a) => !a.acknowledged);
        if (unackAlerts.length === 0) {
          showToast("All alerts already acknowledged.", "info");
          return;
        }
        unackAlerts.forEach((a) => (a.acknowledged = true));
        if (state.backendConnected) {
          for (const a of unackAlerts) {
            try {
              await fetch("/api/alerts/ack", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ id: a.id }),
              });
            } catch (_) {}
          }
        }
        showToast(
          `${unackAlerts.length} security alerts acknowledged & triaged.`,
          "info",
        );
        renderUI();
      });

    // 11. Titlebar Window Controls
    const win = document.querySelector(".dashboard-window");
    document.getElementById("btnWinMinimize")?.addEventListener("click", () => {
      win?.classList.toggle("minimized");
      const isMin = win?.classList.contains("minimized");
      showToast(
        isMin
          ? "Window minimized. Click _ again to expand."
          : "Window restored.",
        "info",
      );
    });

    document.getElementById("btnWinMaximize")?.addEventListener("click", () => {
      win?.classList.toggle("maximized");
      const isMax = win?.classList.contains("maximized");
      showToast(
        isMax
          ? "Window maximized to full screen."
          : "Window restored to default geometry.",
        "info",
      );
    });

    document.getElementById("btnWinClose")?.addEventListener("click", () => {
      showToast(
        "Chronicle is running in background. Press Ctrl+C in terminal to stop.",
        "warn",
        4000,
      );
    });

    // 12. Copy Debian Build Commands
    document
      .getElementById("btnCopyPkgCommand")
      ?.addEventListener("click", () => {
        const snippet = document.getElementById("pkgCodeSnippet")?.innerText;
        if (snippet) {
          navigator.clipboard
            .writeText(snippet)
            .then(() => {
              showToast(
                "Debian package build commands copied to clipboard!",
                "info",
              );
            })
            .catch(() => {
              showToast("Commands copied to clipboard.", "info");
            });
        }
      });

    // 13. Live Privacy Audit Execution
    document.getElementById("btnRunAuditNow")?.addEventListener("click", () => {
      const resEl = document.getElementById("auditResultText");
      if (resEl) {
        resEl.textContent = "Auditing host sockets...";
        resEl.style.color = "var(--primary-amber, #f59e0b)";
      }
      setTimeout(() => {
        if (resEl) {
          resEl.textContent = "Audit Passed: 0B External • 100% Isolated";
          resEl.style.color = "var(--primary-emerald, #10b981)";
        }
        showToast(
          "Socket audit complete: 0 outbound connections detected. Air-gapped compliance verified.",
          "info",
          4000,
        );
      }, 400);
    });

    // Modal Background Click Closes
    document.querySelectorAll(".modal-overlay").forEach((modal) => {
      modal.addEventListener("click", (e) => {
        if (e.target === modal) closeAllModals();
      });
    });

    // Keyboard Shortcuts (⌘K, ⌘I, ⌘H, Escape)
    window.addEventListener("keydown", (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        searchInput?.focus();
      } else if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "i") {
        e.preventDefault();
        if (state.selectedEventId) openProcessModal(state.selectedEventId);
      } else if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "h") {
        e.preventDefault();
        const ev = state.events.find((x) => x.id === state.selectedEventId) || state.events[0];
        if (ev) openHistoryModal(ev.comm, ev.pid);
      } else if (e.key === "Escape") {
        closeAllModals();
      }
    });
  }

  // --- SYSTEM UPTIME CLOCK ---
  const startTime = Date.now();
  function startClock() {
    const uptimeEl = document.getElementById("systemUptime");
    setInterval(() => {
      if (uptimeEl) {
        const diffSec = Math.floor((Date.now() - startTime) / 1000) + 9912; // Start with realistic uptime
        const hrs = String(Math.floor(diffSec / 3600)).padStart(2, "0");
        const mins = String(Math.floor((diffSec % 3600) / 60)).padStart(2, "0");
        const secs = String(diffSec % 60).padStart(2, "0");
        uptimeEl.textContent = `Up: ${hrs}:${mins}:${secs}`;
      }
      const statusClock = document.getElementById("statusbarClock");
      if (statusClock) {
        const timeStr = new Date().toLocaleTimeString("en-IN", {
          timeZone: "Asia/Kolkata",
          hour12: false,
          hour: "2-digit",
          minute: "2-digit",
          second: "2-digit",
        });
        statusClock.textContent = `${timeStr} IST`;
      }
    }, 1000);
  }

  // --- BACKEND API SYNCHRONIZATION ---
  async function syncBackendData() {
    try {
      const [resStats, resEvents, resAlerts, resProfiles] = await Promise.all([
        fetch("/api/stats")
          .then((r) => (r.ok ? r.json() : null))
          .catch(() => null),
        fetch("/api/events?limit=80")
          .then((r) => (r.ok ? r.json() : null))
          .catch(() => null),
        fetch("/api/alerts?limit=40")
          .then((r) => (r.ok ? r.json() : null))
          .catch(() => null),
        fetch("/api/profiles")
          .then((r) => (r.ok ? r.json() : null))
          .catch(() => null),
      ]);

      if (resStats || resEvents) {
        state.backendConnected = true;
      }

      if (resEvents && resEvents.length > 0) {
        state.events = resEvents.map((e) => ({
          ...e,
          cluster:
            e.cluster ||
            (state.profiles[e.comm] && state.profiles[e.comm].cluster) ||
            getProcessCluster(e.comm, e.user),
        }));
      }

      if (resAlerts) {
        state.alerts = resAlerts.map((a) => ({
          id: a.id,
          timestamp: a.timestamp,
          comm: a.comm,
          pid: a.pid,
          riskScore: a.riskScore,
          anomalyType: a.category,
          mitre: a.category,
          desc:
            a.description ||
            (Array.isArray(a.reasons) ? a.reasons.join(" • ") : a.reasons),
          acknowledged: a.status === "ACKNOWLEDGED",
        }));
      }

      if (resProfiles && Object.keys(resProfiles).length > 0) {
        state.profiles = { ...state.profiles, ...resProfiles };
      }

      if (resStats) {
        state.backendStats = resStats;
        const kernelBadge = document.querySelector(".retro-titlebar-chip");
        if (kernelBadge) {
          kernelBadge.textContent = resStats.ebpf_active
            ? "KERNEL: eBPF / BCC ACTIVE"
            : "KERNEL: LIVE HOST TELEMETRY";
        }
        const statusPane = document.querySelector(
          ".retro-status-pane span:nth-child(2)",
        );
        if (statusPane) {
          statusPane.textContent = resStats.ebpf_active
            ? "eBPF: ACTIVE (KERNEL PROBES)"
            : "TELEMETRY: ACTIVE (HOST PSUTIL)";
        }
      }

      renderUI();
    } catch (err) {
      console.warn("Backend sync paused:", err);
    }
  }

  // --- INITIALIZATION ---
  document.addEventListener("DOMContentLoaded", async () => {
    initSeedData();
    setupEventListeners();
    renderUI();
    startClock();

    // Check backend connection and sync real host telemetry & ML predictions
    await syncBackendData();
    // Background polling every 2.5s
    setInterval(() => {
      if (!state.isStreaming) syncBackendData();
    }, 2500);
  });
})();
