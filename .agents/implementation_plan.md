# FinGuard Detailed Implementation Plan (C++ Core & Hybrid UI)

## Phase 1: Windows Process Scanner & Core C++ Telemetry

### Objective
Build the native C++20 process enumeration and anomaly detection engine with CMake, creating a high-performance scanner that identifies running processes, maps lineage, and flags impostor system binaries.

### Deliverables & Tasks
- [ ] **1.1 CMake Build Architecture & Core Types (`core/`)**
  - Create root `CMakeLists.txt` and `core/CMakeLists.txt` supporting C++20.
  - Define `finguard/types.hpp` (`ProcessInfo`, `ModuleInfo`, `ProcessTree`, `PrivilegeInfo`).
  - Define `finguard/hal/platform_collector.hpp` (Pure virtual C++ base class).
- [ ] **1.2 Native Win32 Collector (`core/src/hal/win32_collector.cpp`)**
  - Implement using Win32 API:
    - `CreateToolhelp32Snapshot`, `Process32FirstW`, `Process32NextW`.
    - `QueryFullProcessImageNameW` for authentic disk paths.
    - `WTSEnumerateProcessesW` fast fallback.
    - `OpenProcessToken` and `GetTokenInformation` for elevation status.
- [ ] **1.3 Linux Mock / Synthetic Collector (`core/src/hal/mock_collector.cpp`)**
  - Provide synthetic process trees for Linux host development and testing:
    - Baseline system processes (`explorer.exe`, `svchost.exe`).
    - Impostor processes (e.g. `svchost.exe` running outside System32).
    - Suspicious parent-child lineages (e.g. `word.exe` spawning `powershell.exe`).
- [ ] **1.4 Process Anomaly Engine (`core/src/monitors/process_monitor.cpp`)**
  - Path spoofing detector (verifies known Windows binaries against authentic system directories).
  - Suspicious command-line argument detector (`-enc`, `-w hidden`, `downloadstring`).
  - PPID anomaly checks.
- [ ] **1.5 Phase 1 Tests**
  - CTest / unit tests verifying process scanning performance (< 50ms) and anomaly detection.

---

## Phase 2: Static PE File & Digital Signature Analyzer (C++)

### Objective
Build a native C++ static PE32/PE32+ binary parser capable of reading executable headers, calculating section entropy, profiling dangerous API imports (IAT), and verifying Authenticode signatures.

### Deliverables & Tasks
- [ ] **2.1 Portable PE Structure Engine (`core/include/finguard/pe/pe_structures.hpp`)**
  - Provide portable definitions of `IMAGE_DOS_HEADER`, `IMAGE_NT_HEADERS32`, `IMAGE_NT_HEADERS64`, `IMAGE_SECTION_HEADER`, `IMAGE_DATA_DIRECTORY`, `IMAGE_IMPORT_DESCRIPTOR` that compile identically on Linux (GCC/Clang) and Windows (MSVC).
- [ ] **2.2 PE Parsing Implementation (`core/src/pe/pe_analyzer.cpp`)**
  - Parse DOS header, verify `MZ` magic (`0x5A4D`).
  - Locate and verify PE signature `PE\0\0` (`0x00004550`).
  - Read File Header (architecture, section count, timestamp).
  - Read Optional Header (entry point, image base, subsystem, data directories).
  - Parse Section Table (names, virtual size, raw size, memory characteristics like RWX).
- [ ] **2.3 Fast Shannon Entropy Calculator (`core/src/pe/entropy.cpp`)**
  - Implement streaming byte frequency histogram calculation across 256 byte values.
  - Compute Shannon entropy per section:
    $$H(X) = -\sum_{i=0}^{255} P(i) \log_2 P(i)$$
  - Flag sections with entropy > 7.1 or known packer section names (`UPX0`, `UPX1`, `.vmp`, `.themida`).
- [ ] **2.4 Import Address Table (IAT) Danger Profiler (`core/src/pe/pe_analyzer.cpp`)**
  - Parse the Import Directory Table and resolve imported DLL names and function names.
  - Catalog dangerous APIs:
    - **Injection:** `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`, `QueueUserAPC`.
    - **Keylogging:** `SetWindowsHookExA/W`, `GetAsyncKeyState`, `GetKeyState`, `RegisterRawInputDevices`.
    - **Screen Capture:** `BitBlt`, `GetDC`, `PrintWindow`.
- [ ] **2.5 Authenticode Signature Verification (`core/src/pe/signature_verifier.cpp`)**
  - Extract the Security Directory (`IMAGE_DIRECTORY_ENTRY_SECURITY`).
  - Windows: Call CryptoAPI `WinVerifyTrust`.
  - Linux / Cross-Platform: Validate presence and structure of `WIN_CERTIFICATE` / PKCS#7 block.
- [ ] **2.6 Phase 2 Tests**
  - Unit tests verifying PE parsing, entropy calculation, and IAT cataloging using sample binaries.

---

## Phase 3: Permission Analyzer & Multi-Factor Risk Engine (C++)

### Objective
Implement token privilege evaluation and a multi-factor deterministic risk scoring engine that computes an explainable 0–100 risk score in C++.

### Deliverables & Tasks
- [ ] **3.1 Permission & Privilege Monitor (`core/src/monitors/permission_monitor.cpp`)**
  - Windows token inspection: Query `TokenPrivileges` for `SeDebugPrivilege`, `SeImpersonatePrivilege`, `SeTcbPrivilege`.
  - Integrity level checks: Low, Medium, High (Elevated), System.
  - Persistence audit: Check registry `Run` / `RunOnce` keys.
- [ ] **3.2 Risk Scoring Engine (`core/src/engine/risk_engine.cpp`)**
  - Implement mathematical weighted scoring model:
    $$\text{RiskScore}(P) = \min\left(100, \sum w_i \cdot \text{Indicator}_i\right) \times \text{DampeningFactor}$$
  - Calibrate weights:
    - Impostor System Path: $+40$
    - High Entropy Section (> 7.1) / Packed: $+25$
    - Keylogging APIs in IAT: $+35$
    - Injection APIs in IAT: $+35$
    - Screen Capture APIs in IAT: $+20$
    - Unsigned / Invalid Certificate: $+25$
    - `SeDebugPrivilege` held by non-system app: $+35$
    - Verified Trusted Vendor Signature: $\times 0.2$ (Dampening)
- [ ] **3.3 Diagnostic Report Generation**
  - Format structured C++ diagnostic reports with categorized threat tags and clear human-readable explanations.
- [ ] **3.4 Phase 3 Tests**
  - Verify scoring accuracy across clean baselines and simulated multi-vector threats.

---

## Phase 4: Real-Time Behavior Monitor (C++)

### Objective
Observe real-time behavioral vectors including foreign network connections, remote desktop co-presence, and global input hooks.

### Deliverables & Tasks
- [ ] **4.1 Network Socket Monitor (`core/src/monitors/behavior_monitor.cpp`)**
  - Correlate active TCP/UDP connections to process PIDs using `GetExtendedTcpTable`.
  - Flag connections to suspicious ports or unverified remote endpoints.
- [ ] **4.2 Remote Desktop & Spyware Co-Presence**
  - Detect running remote access software (AnyDesk, TeamViewer, RustDesk, UltraViewer).
  - Evaluate risk of unauthorized remote interaction during financial sessions.
- [ ] **4.3 Global Hook Detection**
  - Identify processes installing global message hooks (`WH_KEYBOARD`, `WH_MOUSE`).

---

## Phase 5: Financial Application Protection (Pre-Flight Shield) & UI

### Objective
Build the C-ABI export layer, Python orchestration bridge, financial app pre-flight gatekeeper, and the modern dark-mode security UI.

### Deliverables & Tasks
- [ ] **5.1 C-ABI Export Layer (`core/src/core_api.cpp` & `core_api.h`)**
  - Export clean C functions: `finguard_scan_process()`, `finguard_analyze_pe()`, `finguard_evaluate_system_risk()`, `finguard_free_report()`.
  - Provide JSON serialization for straightforward IPC.
- [ ] **5.2 Python Orchestrator & C++ Bridge (`ui/backend/core_bridge.py`)**
  - Load `libfinguard.so` / `finguard.dll` via Python `ctypes`.
  - Provide high-level Python wrappers.
- [ ] **5.3 Financial Target Registry & Pre-Flight Gatekeeper (`ui/backend/gatekeeper.py`)**
  - Target configurations: CBE Mobile/Web (`cbe.com.et`), Telebirr (`telebirr.et`), Bank of Abyssinia, Dashen Bank.
  - Intercepts target launch, triggers C++ pre-flight scan (< 500ms), and gates execution.
- [ ] **5.4 Modern Security Dashboard UI (`ui/static/`)**
  - Modern cybersecurity dark-mode UI with live system risk meter, process inspector, and PE file drag-and-drop dropzone.

---

## Phase 6: Android Version & Mobile Extension

### Objective
Extend FinGuard's financial protection paradigms to the Android ecosystem via an ADB-based security auditor.

### Deliverables & Tasks
- [ ] **6.1 Android Threat Model Specification**
  - Focus on dangerous Accessibility Services (`BIND_ACCESSIBILITY_SERVICE`) and overlay permissions (`SYSTEM_ALERT_WINDOW`).
- [ ] **6.2 ADB Remote Scanner Module (`finguard_android/`)**
  - Connect via ADB, query installed packages, audit permissions, and flag sideloaded financial trojans.
