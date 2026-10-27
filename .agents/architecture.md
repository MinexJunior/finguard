# FinGuard System Architecture (C++ Core & Hybrid UI)

## 1. Executive Overview

**FinGuard** is a proactive financial application security shield designed to protect users during sensitive banking and digital wallet operations (e.g., Commercial Bank of Ethiopia (CBE), Telebirr, and international financial portals). 

FinGuard implements a **high-performance hybrid architecture**:
1. **Performance-Critical Core (Modern C++20):** Direct, low-latency execution for process enumeration, PE binary parsing, section entropy calculation, Windows token privilege auditing, and deterministic risk scoring.
2. **Presentation & Gating Layer (Python & Modern Web UI):** Handles application pre-flight interception, user-facing alert modals, animated cybersecurity dashboard telemetry, and target configuration.
3. **Bridge Interface:** Clean C-ABI (`extern "C"`) and structured JSON-RPC, enabling zero-copy library loading or decoupled IPC.

---

## 2. High-Level Architecture Diagram

```mermaid
graph TD
    subgraph UI_Layer [Presentation & Interaction Layer (Python / Web)]
        UI[FinGuard Dashboard & Shield UI]
        Gatekeeper[Financial App Launcher & Gatekeeper]
        PyBridge[C-ABI Bridge / ctypes / IPC]
    end

    subgraph C_Core [Native C++20 Core Engine (libfinguard)]
        CAPI[Core C-ABI Interface - core_api.h]
        Orchestrator[C++ Scan Orchestrator]
        RiskEngine[Multi-Factor Risk Engine]
        
        subgraph Analysis_Engines [Analysis Subsystems]
            ProcMon[Process & Lineage Monitor]
            PEAnalyzer[PE Parser, IAT & Entropy Engine]
            PermAnalyzer[Token Privilege & UAC Auditor]
            BehavMon[Behavior & Socket Monitor]
        end
        
        subgraph HAL_Layer [Hardware & OS Abstraction Layer]
            WinHAL[Windows Native Collector - Win32 API]
            MockHAL[Linux / Dev Synthetic Mock Collector]
        end
    end

    Gatekeeper -->|Banking App Triggered| PyBridge
    PyBridge -->|Call C-ABI| CAPI
    CAPI --> Orchestrator
    Orchestrator --> ProcMon
    Orchestrator --> PEAnalyzer
    Orchestrator --> PermAnalyzer
    Orchestrator --> BehavMon

    ProcMon --> HAL_Layer
    PermAnalyzer --> HAL_Layer
    BehavMon --> HAL_Layer
    PEAnalyzer -->|Direct File Stream| PEAnalyzer

    ProcMon -->|Telemetry| RiskEngine
    PEAnalyzer -->|Binary Metrics| RiskEngine
    PermAnalyzer -->|Privilege Data| RiskEngine
    BehavMon -->|Behavior Flags| RiskEngine

    RiskEngine -->|Diagnostic Risk Report| CAPI
    CAPI -->|JSON / Struct Data| PyBridge
    PyBridge --> UI
    Gatekeeper -->|Allow / Block Decision| UI
```

---

## 3. C++ Core Components Breakdown

### 3.1. Process Monitor (`finguard::monitors::ProcessMonitor`)
- **Language:** C++20.
- **Functionality:**
  - Fast Win32 enumeration using `CreateToolhelp32Snapshot` / `EnumProcesses`.
  - Process path normalization and spoofing detection (e.g., verifying `svchost.exe` path against `%SystemRoot%\System32`).
  - PPID lineage validation (detecting orphaned or spoofed parent processes).
  - Identification of suspicious command lines and LOLBins.

### 3.2. PE & Binary Analyzer (`finguard::pe::PeAnalyzer`)
- **Language:** C++20.
- **Functionality:**
  - Header parsing: DOS Header (`e_magic`), PE Signature (`IMAGE_NT_SIGNATURE`), File Header, Optional Header (`Magic`, `Subsystem`, `DataDirectory`).
  - Section Analysis: Virtual size vs. raw size ratio, section characteristics (`IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE`).
  - **Shannon Entropy Calculator:** Fast sliding-window byte entropy:
    $$H(X) = -\sum_{i=0}^{255} P(i) \log_2 P(i)$$
    Detects packed, crypted, or compressed payloads (UPX, Themida, VMProtect).
  - **IAT Danger Profiler:** Scans the Import Address Table for dangerous Windows API patterns:
    - Injection: `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`, `QueueUserAPC`.
    - Keylogging: `SetWindowsHookExA/W`, `GetAsyncKeyState`, `GetKeyboardState`.
    - Screen capture: `BitBlt`, `GetDC`, `PrintWindow`.
  - **Authenticode Verification:** Parses `IMAGE_DIRECTORY_ENTRY_SECURITY` certificate structures.

### 3.3. Permission & Privilege Analyzer (`finguard::monitors::PermissionMonitor`)
- **Language:** C++20.
- **Functionality:**
  - Token inspection via `OpenProcessToken` and `GetTokenInformation`.
  - Checks for dangerous non-system privileges: `SeDebugPrivilege`, `SeImpersonatePrivilege`, `SeTcbPrivilege`.
  - UAC elevation token query: `TokenElevation`, `TokenIntegrityLevel`.
  - Windows registry autorun audit (`HKLM`/`HKCU` `Run` and `RunOnce` keys).

### 3.4. Behavior & Telemetry Monitor (`finguard::monitors::BehaviorMonitor`)
- **Language:** C++20.
- **Functionality:**
  - Network connection enumeration via `GetExtendedTcpTable` (correlating foreign IPs to PID).
  - Detection of active remote desktop tools (AnyDesk, TeamViewer, RustDesk, UltraViewer).
  - Detection of installed global input hooks.

### 3.5. Risk Engine (`finguard::engine::RiskEngine`)
- **Language:** C++20.
- **Functionality:**
  - Multi-factor deterministic risk calculation in sub-millisecond execution time.
  - Generates structured diagnostic reports (risk score 0-100, risk tier, indicator list, remediation steps).

---

## 4. UI & Orchestration Layer (Python / Modern Web UI)

- **Language:** Python 3.12+ / Modern Web UI (HTML5, Vanilla CSS, JS).
- **Functionality:**
  - **Pre-Flight Gatekeeper:** Monitors for launches of designated financial applications (CBE, Telebirr, web banking portals).
  - **Pre-Flight Modal:** Presents an interactive scan modal in < 1.5 seconds.
  - **Interactive Cybersecurity Dashboard:** Real-time system risk meter, process inspector table, and drag-and-drop PE file analyzer.
  - **Bridge:** Loads `libfinguard.so` / `finguard.dll` via `ctypes` or executes `finguard-core --scan-json`.
