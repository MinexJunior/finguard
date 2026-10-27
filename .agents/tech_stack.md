# FinGuard Technology Stack & Development Environment (Hybrid C++ & UI Architecture)

## 1. High-Performance Hybrid Architecture

To maximize execution speed, low-level OS introspection fidelity, and UI flexibility, FinGuard adopts a **Modern C++20 Core + Python/Web UI Hybrid Architecture**:

```
+---------------------------------------------------------------------------------------+
|                                    PRESENTATION LAYER                                 |
|               Python / Modern Web UI (FastAPI, WebSockets, Dark-Mode Dashboard)       |
|               - Financial App Launch Interceptor & Pre-Flight Gatekeeper              |
|               - Real-Time Alerts, Visual Telemetry & User Remediation Modals          |
+-------------------------------------------+-------------------------------------------+
                                            |
                            [ C ABI / JSON-RPC / IPC Layer ]
                                            |
+-------------------------------------------v-------------------------------------------+
|                                   NATIVE C++20 CORE                                   |
|                                (libfinguard / finguard-core)                          |
|                                                                                       |
|  [ Process Monitor ]        [ PE & Binary Analyzer ]       [ Risk Scoring Engine ]     |
|  - Win32 Toolhelp32         - Portable PE32/PE32+ parser   - Multi-factor weights     |
|  - Process tree & PPID      - Shannon entropy calculator   - Diagnostic explainability|
|  - Path spoofing detector   - IAT danger profiler          - Sub-millisecond compute  |
|                             - Authenticode validator                                  |
|                                                                                       |
|  [ Permission Analyzer ]    [ Behavior & Socket Engine ]   [ Platform HAL ]           |
|  - Token privileges (SeDebug)- TCP/UDP socket tracking     - Win32 native backend     |
|  - UAC Integrity level      - Remote desktop detection     - Linux test mock backend  |
|  - Startup autorun keys     - Global hook detection                                   |
+---------------------------------------------------------------------------------------+
```

---

## 2. Technology Selection Matrix

| Subsystem | Technology | Rationale |
|---|---|---|
| **Core Security Engine** | **Modern C++ (C++20)** | Unmatched execution speed, direct Win32 API memory structures (`IMAGE_DOS_HEADER`, `IMAGE_NT_HEADERS`), zero garbage collection pauses, low memory footprint, and native OS access. |
| **Build System** | **CMake (>= 3.25)** | Industry-standard cross-platform build generator. Natively supports Linux GCC/Clang and Windows MSVC/MinGW. |
| **PE Parser & Entropy** | **Native C++ Header-only Engine** | High-speed binary parsing of PE32/PE32+ files without heavy external dependencies. Portable across Linux and Windows. |
| **Cryptography & Signatures**| C++ Windows CryptoAPI (`wintrust.dll`, `crypt32.dll`) + OpenSSL/Embedded ASN.1 for cross-platform | Authenticode signature chain validation and SHA-256 / MD5 hashing. |
| **Inter-Process / Binding** | **C-ABI Export (`extern "C"`) + JSON-RPC** | Allows the C++ engine to be loaded as a dynamic library (`.so`/`.dll`) or executed as a fast CLI daemon communicating with the UI via structured JSON. |
| **UI & Orchestrator** | **Python 3.12+ / Modern Web UI (FastAPI + HTML5/CSS3/JS)** | Rapid development of modern, animated cybersecurity dashboards, pre-flight popups, and financial application launch hooks. |
| **Test Framework** | **GoogleTest / CTest** (C++) & **pytest** (Integration) | Comprehensive unit tests for C++ PE parser and end-to-end integration tests. |

---

## 3. Directory Structure

```
finguard/
├── CMakeLists.txt                # Root CMake build configuration
├── .agents/                      # Architectural blueprints & documentation
│   ├── architecture.md
│   ├── tech_stack.md
│   ├── implementation_plan.md
│   ├── progress_track.md
│   └── security_model.md
├── core/                         # Native C++20 Core Library & Executable
│   ├── CMakeLists.txt
│   ├── include/
│   │   ├── finguard/
│   │   │   ├── core_api.h        # Clean C-ABI export interface for UI/bindings
│   │   │   ├── types.hpp         # Core data structs (ProcessInfo, PeReport, RiskScore)
│   │   │   ├── hal/
│   │   │   │   ├── platform_collector.hpp # Abstract OS telemetry interface
│   │   │   │   ├── win32_collector.hpp    # Windows native (Toolhelp32, Tokens)
│   │   │   │   └── mock_collector.hpp     # Linux mock/synthetic provider
│   │   │   ├── pe/
│   │   │   │   ├── pe_structures.hpp      # Portable PE structures (Win32 compatible)
│   │   │   │   ├── pe_analyzer.hpp        # PE Header, Section, & IAT parser
│   │   │   │   ├── entropy.hpp            # Shannon entropy calculator
│   │   │   │   └── signature_verifier.hpp # Authenticode & Certificate verifier
│   │   │   ├── monitors/
│   │   │   │   ├── process_monitor.hpp    # Path spoofing, PPID, LOLBins
│   │   │   │   ├── permission_monitor.hpp # SeDebugPrivilege, UAC integrity
│   │   │   │   └── behavior_monitor.hpp   # Sockets, Remote desktop, Hooks
│   │   │   └── engine/
│   │   │       ├── risk_engine.hpp        # Multi-factor mathematical scoring
│   │   │       └── rules.hpp              # Threat indicators & weights
│   └── src/
│       ├── core_api.cpp          # C-ABI and JSON serialization endpoints
│       ├── main.cpp              # Standalone C++ daemon / CLI runner
│       ├── hal/
│       │   ├── win32_collector.cpp
│       │   └── mock_collector.cpp
│       ├── pe/
│       │   ├── pe_analyzer.cpp
│       │   ├── entropy.cpp
│       │   └── signature_verifier.cpp
│       ├── monitors/
│       │   ├── process_monitor.cpp
│       │   ├── permission_monitor.cpp
│       │   └── behavior_monitor.cpp
│       └── engine/
│           └── risk_engine.cpp
├── ui/                           # UI & Orchestration Layer (Python / Web)
│   ├── app.py                    # Pre-flight interceptor & UI launcher
│   ├── backend/
│   │   ├── core_bridge.py        # ctypes / JSON IPC bridge to C++ core
│   │   ├── gatekeeper.py         # Financial app detection & pre-flight gating
│   │   └── server.py             # FastAPI local server & WebSocket manager
│   └── static/                   # Modern dark-mode cybersecurity UI
│       ├── index.html
│       ├── styles.css
│       └── app.js
├── tests/
│   ├── cpp/                      # C++ unit tests (GoogleTest / CTest)
│   │   ├── test_entropy.cpp
│   │   ├── test_pe_analyzer.cpp
│   │   └── test_risk_engine.cpp
│   ├── integration/              # End-to-end Python-C++ integration tests
│   └── samples/                  # Safe sample PE binaries for validation
```

---

## 4. Development Workflow on Linux Host

1. **C++ Core Development on Linux:**
   - Compiled using `g++ -std=c++20` or `clang++` via `cmake -B build && cmake --build build`.
   - `pe_analyzer.cpp` and `entropy.cpp` parse real Windows executables directly on Linux using portable PE structures.
   - `mock_collector.cpp` provides synthetic Windows processes with simulated malicious behaviors to test the full pipeline.
2. **C-ABI / Python Integration:**
   - The compiled `libfinguard.so` (Linux) / `finguard.dll` (Windows) exposes simple, robust C functions (`finguard_scan_process`, `finguard_analyze_pe`, `finguard_evaluate_system_risk`).
   - Python accesses these functions via `ctypes` or high-speed JSON IPC, ensuring the UI remains ultra-fast and decoupled.
3. **Target Windows Build:**
   - Windows build via MSVC (`cl.exe`) or MinGW cross-compiler generates native Windows 64-bit binaries.
