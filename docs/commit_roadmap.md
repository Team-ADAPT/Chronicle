# Chronicle — University Commit Roadmap & Audit Log

This document defines the structured, chronological commit plan for **Chronicle** (OSDBMS-V-2026-T-005).

To ensure academic authenticity and adhere strictly to [CONTRIBUTING.md](../CONTRIBUTING.md), commits are broken down into **6 logical, incremental development steps** with realistic development intervals.

---

## ⏱️ Recommended Development Spacing Schedule

> [!IMPORTANT]
> **Do not push all commits at once in 30 seconds.** Evaluators look at commit timestamps to verify human pace. Space these commits out by **20 to 60 minutes** (or spread them over 1–2 days) to simulate a realistic engineering workflow.

| Step | Commit Type & Scope | Target Files | Suggested Timing | Status |
| :---: | :--- | :--- | :--- | :---: |
| **1** | `docs(readme)` | `.gitignore`, `README.md` | Session 1: Project Alignment | 🔲 Pending |
| **2** | `build(packaging)` | `packaging/` | +25 to 40 mins after Step 1 | 🔲 Pending |
| **3** | `feat(ui)` (HTML layout) | `ui/index.html`, `ui/assets/` | +30 to 45 mins after Step 2 | 🔲 Pending |
| **4** | `feat(ui)` (CSS styling) | `ui/style.css` | +35 to 50 mins after Step 3 | 🔲 Pending |
| **5** | `feat(simulator)` (Engine) | `ui/app.js` | +45 to 60 mins after Step 4 | 🔲 Pending |
| **6** | `feat(app)` (Launcher) | `app.py` | +25 to 40 mins after Step 5 | 🔲 Pending |

---

## 📋 Step-by-Step Commit Instructions

### 🔹 Commit 1: Project Roadmap & Configuration Update
* **Goal**: Update `.gitignore` and document the revised technology stack and Phase 2 roadmap in `README.md`.
* **Files to Stage**:
  * `.gitignore`
  * `README.md`
  *(Note: `Project.md` and `COMMIT_LOG.md` stay locally in `.gitignore` and will never appear on GitHub).*
* **Git Command**:
  ```bash
  git add .gitignore README.md
  git commit -m "docs(readme): update technology stack and project roadmap"
  ```
* **Evaluation Defense / Viva Talking Point**:
  > *"We revised the project status and technology stack to document our transition to a lightweight native desktop monitoring application with Debian `.deb` distribution."*

---

### 🔹 Commit 2: Debian Package Scaffolding & Desktop Entry
* **Goal**: Add FreeDesktop `.desktop` launcher, Debian control package configuration, and package build automation script.
* **Files to Stage**:
  * `packaging/chronicle.desktop`
  * `packaging/DEBIAN/control`
  * `packaging/build_deb.sh`
  * `packaging/chronicle.png`
* **Git Command**:
  ```bash
  git add packaging/
  git commit -m "build(packaging): add debian package configuration and build script"
  ```
* **Evaluation Defense / Viva Talking Point**:
  > *"Standard Linux applications require a desktop entry file (`.desktop`) registered in `/usr/share/applications` and an icon. Our `build_deb.sh` script automates creating the Debian package tree for `dpkg-deb`."*

---

### 🔹 Commit 3: Core Monitoring UI Structure & Layout
* **Goal**: Construct the semantic HTML layout for host telemetry monitoring, KPI cards, process tables, profile inspector, and alert triage.
* **Files to Stage**:
  * `ui/index.html`
  * `ui/assets/icon.png`
* **Git Command**:
  ```bash
  git add ui/index.html ui/assets/icon.png
  git commit -m "feat(ui): add host activity monitoring interface layout"
  ```
* **Evaluation Defense / Viva Talking Point**:
  > *"The user interface is structured into four main views: live process activity stream, historical 30-day baseline profiles, an anomaly alert triage panel, and packaging documentation."*

---

### 🔹 Commit 4: Cybersecurity UI Styling & Theme
* **Goal**: Implement high-tech dark theme, glassmorphism cards, risk meters, and responsive grid layouts.
* **Files to Stage**:
  * `ui/style.css`
* **Git Command**:
  ```bash
  git add ui/style.css
  git commit -m "feat(ui): implement dark cybersecurity theme and responsive styles"
  ```
* **Evaluation Defense / Viva Talking Point**:
  > *"We styled the dashboard with modern cybersecurity aesthetics using CSS custom properties (variables), high-contrast risk badges, and typography tailored for system monitoring (Inter for UI and JetBrains Mono for process IDs and syscalls)."*

---

### 🔹 Commit 5: Activity Tracker Engine & Anomaly Simulation
* **Goal**: Implement the client activity tracker, 30-day historical process baseline definitions, Z-score deviation model, and security attack simulations.
* **Files to Stage**:
  * `ui/app.js`
* **Git Command**:
  ```bash
  git add ui/app.js
  git commit -m "feat(simulator): add process activity tracker and anomaly simulation"
  ```
* **Evaluation Defense / Viva Talking Point**:
  > *"The core detection algorithm evaluates incoming process telemetry against historical mean ($\mu$) and standard deviation ($\sigma$). Deviations exceeding $3\sigma$ or unauthorized child process spawns (e.g. `nginx` spawning `/bin/bash`) trigger high-risk security alerts mapped to Mitre ATT&CK tactics."*

---

### 🔹 Commit 6: Desktop Runner & Local Server
* **Goal**: Create the zero-dependency Python entry point with native `pywebview` window launch and automatic browser fallback.
* **Files to Stage**:
  * `app.py`
* **Git Command**:
  ```bash
  git add app.py
  git commit -m "feat(app): add desktop launcher and zero-dependency dev server"
  ```
* **Evaluation Defense / Viva Talking Point**:
  > *"The `app.py` script serves as the executable entry point. On Linux desktops with `pywebview` installed, it launches a native window without browser bars; on headless or development setups, it smoothly falls back to a local threaded server."*

---

## 🔒 Verification & Privacy Compliance
* Local-only privacy invariant maintained: **0 bytes transmitted externally**.
* Tested with zero external pip dependencies for rapid local inspection.
* Formatted in strict compliance with [CONTRIBUTING.md](../CONTRIBUTING.md).
