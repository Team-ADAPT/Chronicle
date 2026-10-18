# Chronicle — Task & Work-Done Ledger

**Team ID**: OSDBMS-V-2026-T-005  
**Project**: Chronicle — An Intelligent Historical Behaviour Analysis System  
**Department**: Computer Science & Engineering, Graphic Era (Deemed to be University)  
**Academic Session**: 2026–27  
**Design Paradigm**: Local-First Host Security Monitoring & Behavioural Anomaly Detection  

---

## 1. Project Overview & Architecture

Chronicle is a host behavioural analysis and threat detection system designed for Linux environments. Traditional host intrusion detection evaluates isolated system calls or short timeframes; Chronicle instead maintains persistent historical behavioral profiles for processes and evaluates live activity against established baselines using statistical and machine-learning anomaly detection.

### High-Level Architecture
```
                  Linux Host
                      │
                      ▼
               eBPF / Telemetry
                      │
                      ▼
           Normalization & Privacy Filter
                      │
                      ▼
            PostgreSQL / Local DB
                      │
                      ▼
          Historical Behaviour Profiles
                      │
                      ▼
             Feature Extraction
                      │
                      ▼
           Statistical & ML Detection
                      │
                      ▼
             Risk Scoring Engine
                      │
                      ▼
        Chronicle Desktop App (.deb)
```

---

## 2. Codebase Component Inventory

| Component | Files | Description / Purpose |
| :--- | :--- | :--- |
| **Desktop Application (UI)** | `ui/index.html`<br>`ui/style.css`<br>`ui/app.js`<br>`ui/assets/icon.png` | Native-feeling host monitoring dashboard. Features real-time activity stream, KPI telemetry cards, process detail drawer, 30-day baseline comparisons, and alert triage panel. |
| **Desktop Launcher** | `app.py` | Standalone Python executable. Automatically detects environment, starts zero-dependency threaded local server, launches native `pywebview` window if available, or falls back to browser. |
| **Debian Packaging** | `packaging/chronicle.desktop`<br>`packaging/DEBIAN/control`<br>`packaging/build_deb.sh`<br>`packaging/chronicle.png` | Scaffolding to build and install `chronicle_0.2.0-1_amd64.deb` into `/opt/chronicle` with desktop launcher integration in Ubuntu/Debian Applications menu. |
| **Backend API** | `src/chronicle/api.py`<br>`src/chronicle/config.py` | FastAPI backend exposing REST endpoints (`/events`, `/alerts`, `/stats`, `/health`, `/maintenance/cleanup`) with strict local-only privacy enforcement. |
| **Database Storage** | `src/chronicle/storage.py`<br>`docker-compose.yml`<br>`Dockerfile` | PostgreSQL schema and queries for `process_events`, `process_profiles`, and `alerts`. Containerized via Docker. |
| **Academic Documentation** | `Project.md`<br>`README.md`<br>`CONTRIBUTING.md`<br>`COMMIT_LOG.md` | Course documentation, conventional commits guidelines, architecture specs, and commit roadmap. |

---

## 3. Work Completed So Far

### ✅ Phase 1: Planning, Architecture & Packaging Scaffolding
- **Repository Setup & Governance**:
  - Initialized repository with `.gitignore`, `CONTRIBUTING.md` (Conventional Commits specification), and initial documentation (`commit 1cc9a07`).
  - Outlined detailed university research proposal and system specifications in `Project.md`.
- **Packaging & Desktop Scaffolding**:
  - Generated application branding icon (`packaging/chronicle.png`).
  - Created FreeDesktop `.desktop` entry (`packaging/chronicle.desktop`) targeting `/opt/chronicle/chronicle` for native application launcher access.
  - Formatted Debian control package definition (`packaging/DEBIAN/control`).
  - Wrote automated Debian package builder script (`packaging/build_deb.sh`) targeting `chronicle_0.2.0-1_amd64.deb` (`commit b040990`).
- **Privacy & Ignored Files Configuration**:
  - Configured `.gitignore` to maintain local-only tracking for `Project.md`, `COMMIT_LOG.md`, and `task.md` (`commit 7ab3c38`).
  - Updated `README.md` to reflect project roadmap and technology stack (`commit c74cee8`).

### ✅ Phase 2: Host Activity Monitoring Interface & Simulation Engine
- **Host Monitoring UI Layout (`ui/index.html`)**:
  - Built semantic dashboard layout with system health banner, Linux kernel badges, and KPI telemetry cards (`commit ec4a40a`).
  - Implemented real-time Process Activity Stream table with PID, PPID, User, Event Type, CPU %, RAM, and Syscalls.
  - Designed Process Profile Inspector and Alert Triage tabs.
- **Cybersecurity Dark Theme (`ui/style.css`)**:
  - Styled interface with obsidian/slate palette (`#080c14`, `#0d131f`), electric cyan (`#06b6d4`), and neon emerald accents.
  - Implemented glassmorphism cards, risk score meters, status badges, and responsive tables.
- **Activity Tracker & ML Anomaly Simulator (`ui/app.js`)**:
  - Configured 30-day rolling baseline statistical profiles for core Linux processes (`systemd`, `sshd`, `nginx`, `bash`, `python3`, `dockerd`, `cron`, `curl`).
  - Implemented Z-score deviation model ($Z = \frac{|x - \mu|}{\sigma}$) to compute composite risk scores (0–100).
  - Built real-world security anomaly simulation scenarios:
    - *Unauthorized Interactive Shell from Web Daemon* (`nginx` spawning `/bin/bash -i`)
    - *High-Intensity Crypto Mining Activity* (`systemd-worker` utilizing 98.6% CPU)
    - *Ransomware-like Mass File Traversal* (`python3` rapidly accessing 4,200 documents)
    - *Anomalous Outbound Reverse Shell Socket* (`cron` calling `socket_connect` to external IP)
    - *Unauthorized Privilege Escalation Attempt* (`www-data` attempting `sudo` execution)
  - Added interactive testing toolbar with one-click injection, live streaming toggle, and alert acknowledgement.
- **Desktop Application Launcher (`app.py`)**:
  - Built zero-dependency Python entry point with threaded local web server and automatic browser launching.
  - Added native `pywebview` window integration for borderless Linux desktop window execution.

### ✅ Phase 2.5: UI Redesign — Modern 3-Column Mint SaaS Dashboard
- **Visual Design Overhaul (`ui/style.css`, `ui/index.html`)**:
  - Transitioned from terminal dark mode to a modern, high-aesthetic SaaS dashboard inspired by the reference layout.
  - Soft pale mint background (`#eaf6f0`), crisp white cards with floating shadows, and vibrant emerald accents (`#00c288`).
  - Implemented 3-column architecture: Left Navigation Sidebar, Center Main Workspace, and Right Analytics & Threat Gauge Sidebar.
- **Dynamic Half-Donut Threat & Normalcy Gauge**:
  - Built multi-segmented SVG half-donut arc gauge dynamically rendering overall host normalcy (94%) with risk level breakdown.
- **Process Cluster & Activity Architecture (`ui/app.js`)**:
  - Categorized host processes into visual Process Clusters (System Daemons, Network Services, Web & DB Servers, User Workspaces) with interactive click-to-filter.
  - Quick-access KPI cards with an emerald gradient highlight card.
  - Clean Telemetry Events table with risk tags, resource meters, and row-click forensic inspection drawer.
  - Emerald "+ Simulate Event" action button with interactive modal to test real-world attack scenarios on demand.

### ✅ Phase 2.6: Dual Themes, Windows Task Manager & Apple Activity Monitor Integration
- **Dual-Theme System (Light & Dark Mode)**:
  - Added full Light Mode (clean off-white `#f1f5f9` with pastel cards) and Dark Mode (deep midnight slate `#0b0f19` / `#172033` with glowing neon accents) matching the dual preview in Reference Screenshot 2.
  - Theme toggle button in header with persistent `localStorage` memory and automatic OS preference detection.
- **Windows 11 Task Manager Utility Features**:
  - Dynamic cell heatmap tinting on high-usage CPU (>50% rose tint, >15% amber tint) and RAM (>400MB blue tint) to instantly flag rogue/miner processes.
  - Row selection state (`.row-selected`) with active outline.
  - Interactive "End Task" command with simulated `SIGKILL` termination.
- **Apple Activity Monitor Controls**:
  - Top segmented control bar (`All Telemetry`, `CPU & Threads`, `Memory Footprint`, `Network Sockets`, `High-Risk Anomalies`).
  - "Inspect" process tool (`⌘I`) opening forensic drawer with 30-day baseline comparisons ($Z$-score) and Mitre ATT&CK taxonomy.
- **Reference Screenshot Bottom Analytics Charts**:
  - SVG Event Volume Bursts bar chart.
  - SVG Z-score Anomaly Risk History area curve with anomaly callout.
  - SVG Threat & Category Breakdown donut chart with interactive legends.

### ✅ Phase 2.7: Old School Retro Workstation Transformation (Branch: `ui`)
- **Authentic 3D Beveled Architecture (`ui/style.css`, `ui/index.html`)**:
  - Built 3D raised and inset bevel system (`border-color: #fff #404040 #404040 #fff`).
  - Added classic retro window titlebar with square minimize/maximize/close buttons (`[ _ ]`, `[ 口 ]`, `[ ✕ ]`) and navy gradient banner.
  - Added multi-pane retro status bar with blinking green diode (`eBPF: ACTIVE`) and real-time UTC clock.
- **Tactile Mechanical Buttons & Property Tabs**:
  - Push-buttons with authentic mechanical click feel (depressing on `:active` with `translate(1px, 1px)`).
  - Raised property sheet tabs for process filtering (`All Telemetry`, `CPU`, `Memory`, `Network`, `Anomalies`).
- **Retro Modular Instrument Racks & Data Grid**:
  - Inset CRT readout panels with glowing phosphor digits and discrete segmented LED bar meters.
  - High-density monospace data grid with sortable mechanical column headers and inverted solid video row selection (classic Win95 Task Manager / Norton Commander style).
  - High-contrast retro warning blocks for high CPU/RAM and alert pills.
- **Oscilloscope Waveforms & Dual Retro Themes**:
  - Vintage oscilloscope dotted grid backgrounds with vector traces.
  - ☀️ **Classic Workstation (Light)**: Gray chassis (`#d4d0c8`), retro desktop teal (`#008080`), navy titlebars, and white inset wells.
  - 🌙 **Cyber CRT Terminal (Dark)**: Matte carbon chassis (`#1c222a`), vacuum tube CRT glass (`#05080c`), glowing phosphor green, amber, and cyan.

### ✅ Phase 2.7: Soft Pastel Palette Aesthetics (`commit 71780a1`)
- Replaced harsh saturated tones with soft, elegant pastel palette:
  - Sage/mint desktop (`#d6e8e0`) with retro dot-matrix pattern.
  - Warm vintage ecru/bone chassis (`#eae6dd`).
  - Dusty slate-periwinkle titlebars (`linear-gradient(90deg, #5b7a99, #7b9ab8)`).
  - Pastel tokens: Mint (`#a7e8bd`), Coral/Peach (`#ffc4a8`), Sky Blue (`#b3d9ff`), Lilac (`#d9c5f8`), Rose (`#ffb8c6`), Butter (`#ffe699`).

### ✅ Phase 2.8: Layout De-Congestion & Illuminated Graphs in Light Mode
- **Layout De-Congestion**:
  - Main workspace padding expanded from 14px to 24px/28px for generous breathing room.
  - Process table rows de-congested: cell padding increased from 6px to 12px/16px with improved line-height.
  - Process cluster cards and KPI telemetry grid spacing enlarged (gaps 14px-18px, cards padding 14px-18px).
  - Top toolbar, segmented tabstrip, sidebars, and dialog modals given comfortable margins and paddings.
- **Illuminated Graphs in Light Mode**:
  - Resolved dark graph containers in Light Mode: replaced pitch-black CRT insets (`#141920`) with clean crisp surfaces (`--chart-bg: #ffffff`).
  - Dotted grid lines set to subtle pastel slate (`--chart-grid-line: #e2e8f0`).
  - Radial donut and half-gauge tracks rendered in light slate (`--chart-track: #e2e8f0`).
  - Text, indicators, and labels updated for high contrast and readability on light surfaces (`--chart-text: #475569`, `--chart-center-num: #0f172a`).
### ✅ Phase 2.9: Pull Requests
- **PR #1**: `retro-ui` -> `main` (Closed)
- **PR #2**: `ui` -> `main` (Open)
  - PR Title: `feat(ui): retro pastel theme with spacious layout and illuminated graphs`
  - URL: [Team-ADAPT/Chronicle#2](https://github.com/Team-ADAPT/Chronicle/pull/2)
  - Conventional Scope: Follows `CONTRIBUTING.md` standards.

---

## 4. Pending & Upcoming Tasks

### 🔲 Milestone 1: Client UI & Runner Commits (Staged Progression)
- [ ] **Commit UI Stylesheet**: Commit `ui/style.css` following conventional commit format (`feat(ui): implement dark cybersecurity theme and responsive styles`).
- [ ] **Commit Client Engine**: Commit `ui/app.js` and `ui/assets/icon.png` (`feat(simulator): add process activity tracker and anomaly simulation`).
- [ ] **Commit Desktop Runner**: Commit `app.py` (`feat(app): add desktop launcher and zero-dependency dev server`).

### 🔲 Milestone 2: Backend Dual-Engine Storage (SQLite + PostgreSQL)
- [ ] **SQLite Fallback**: Update `src/chronicle/storage.py` to auto-detect whether PostgreSQL is running; if not, automatically fall back to local `chronicle.db` using Python's built-in `sqlite3`.
- [ ] **API Endpoint Unification**: Connect the frontend activity feed to FastAPI `/events` and `/alerts` endpoints while maintaining offline demo simulation mode.

### 🔲 Milestone 3: Machine Learning Model Training & Evaluation
- [ ] **Dataset Preparation**: Extract realistic host trace CSVs containing normal baseline activity and injected synthetic attacks.
- [ ] **Model Implementation**: Train an Isolation Forest / One-Class SVM model using Scikit-learn (`model(detection): add historical baseline isolation forest`).
- [ ] **Model Serialization**: Export model weights to an in-process serialized format for zero-overhead inference in the desktop app.

### 🔲 Milestone 4: eBPF Linux Kernel Telemetry
- [ ] **BCC/libbpf Kernel Probes**: Write C eBPF probes hooking `sys_enter_execve`, `sys_enter_clone`, `sys_enter_connect`, and `sys_enter_openat`.
- [ ] **Ring Buffer Collector**: Implement Python collector reading eBPF perf buffer events and streaming them to the storage layer.

### 🔲 Milestone 5: Production Debian Package Compilation
- [ ] **PyInstaller Binary**: Compile `app.py` into a standalone ELF binary to hide source code and model weights inside `/opt/chronicle/chronicle`.
- [ ] **Package Assembly**: Execute `./packaging/build_deb.sh` on an Ubuntu 22.04/24.04 system to produce `chronicle_0.2.0-1_amd64.deb`.
- [ ] **Installation Testing**: Verify package installation via `sudo dpkg -i chronicle_0.2.0-1_amd64.deb` and confirm desktop launcher appears in GNOME / KDE Application menu.

---

## 5. Quick Reference: How to Run & Test

### Run Desktop App Locally
```bash
python3 app.py
```
*Opens `http://127.0.0.1:8000` automatically in your browser.*

### Run as Native Desktop Window (Linux with pywebview)
```bash
python3 app.py --window
```

### Build Debian (.deb) Package (on Linux)
```bash
chmod +x packaging/build_deb.sh
./packaging/build_deb.sh
sudo dpkg -i chronicle_0.2.0-1_amd64.deb
```
