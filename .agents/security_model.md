# FinGuard Security & Threat Model

## 1. Threat Landscape & Financial Target Context

FinGuard is engineered specifically to defend users who interact with digital financial assets. In the target operating environments—including Ethiopian banking ecosystems such as **Commercial Bank of Ethiopia (CBE)**, **Telebirr**, **Bank of Abyssinia**, **Dashen Bank (Amole)**, and international web banking portals—the primary adversaries are not simple file-encrypting ransomware, but stealthy **Financial Infostealers, Keyloggers, Remote Access Trojans (RATs), and Session Hijackers**.

---

## 2. Primary Attack Vectors Addressed

### Vector 1: Background Keyloggers & Input Snooping
- **Threat:** Malicious background utilities capture keystrokes when the user types banking credentials, passwords, or transaction PINs.
- **Mechanism:** Hooking the Windows message loop (`SetWindowsHookEx` with `WH_KEYBOARD` or `WH_KEYBOARD_LL`), polling `GetAsyncKeyState`, or reading raw inputs (`RegisterRawInputDevices`).
- **FinGuard Defense:**
  - Import Address Table (IAT) inspection for keylogging APIs.
  - Runtime detection of unverified processes registering global hooks.
  - Pre-flight warning blocking financial input if an active hook is detected.

### Vector 2: Screen Scraping & Overlay Clickjacking
- **Threat:** Malware takes periodic screenshots or records the screen while the user views account balances or enters SMS OTPs (One-Time Passwords).
- **Mechanism:** Calling GDI screen-capture APIs (`BitBlt`, `GetDC`, `PrintWindow`, `CreateCompatibleDC`) or Direct3D capture.
- **FinGuard Defense:**
  - Static IAT profiling for screen capture imports combined with missing digital signatures.
  - Active detection of background processes opening desktop device contexts.

### Vector 3: Memory Inspection & Process Injection
- **Threat:** Advanced trojans inject malicious DLLs or shellcode directly into trusted processes (e.g. `explorer.exe`, `chrome.exe`) to alter transaction recipient accounts or steal session cookies.
- **Mechanism:** `OpenProcess` with `PROCESS_VM_WRITE | PROCESS_VM_OPERATION`, followed by `VirtualAllocEx`, `WriteProcessMemory`, and `CreateRemoteThread` or `QueueUserAPC`.
- **FinGuard Defense:**
  - Token privilege auditing: Flags any non-system process holding `SeDebugPrivilege`.
  - Process memory auditing: Detects unbacked executable memory regions (RWX pages) and suspicious remote thread calls.

### Vector 4: Remote Access Trojan (RAT) & Piggybacking Attacks
- **Threat:** An attacker connects to the victim's PC via remote access software (AnyDesk, TeamViewer, RustDesk, UltraViewer, VNC) or social engineering ("IT support scam"), waiting for the user to authenticate with their bank to initiate unauthorized transfers.
- **Mechanism:** Active remote desktop sessions and TCP sockets connected to remote administration relays.
- **FinGuard Defense:**
  - Behavior monitor identifies running remote desktop utilities during banking sessions.
  - Financial Pre-Flight Shield explicitly halts execution if an active remote desktop connection is detected.

### Vector 5: Digital Signature Spoofing & Packed Binaries
- **Threat:** Sophisticated malware uses runtime packers (UPX, Themida, VMProtect) and invalid, expired, or self-signed digital certificates to evade traditional signature matching.
- **Mechanism:** High entropy executable sections ($H > 7.2$), fake PE headers, and invalid PKCS#7 certificate structures.
- **FinGuard Defense:**
  - Shannon entropy calculation across every PE section.
  - Authenticode digital signature validation against verified Root Certificate Authorities (CAs).

---

## 3. Financial Permission & Risk Assessment Matrix

FinGuard evaluates every running process across four core dimensions:

```
+-----------------------------------------------------------------------------------+
|                              PROCESS RISK MATRIX                                  |
+-----------------------------------------------------------------------------------+
| 1. Binary Integrity     | Authenticode Signed? Trusted Vendor? High Entropy?       |
| 2. Import Capabilities  | Keylogger APIs? Injection APIs? Screen Capture APIs?     |
| 3. OS Privileges        | SeDebugPrivilege? Elevated Admin? Autorun Persistence?   |
| 4. Runtime Behavior     | Suspicious Foreign Socket? Active Remote Desktop? Hooks? |
+-----------------------------------------------------------------------------------+
```

### Risk Tier Definitions

| Score Range | Category | Color | Pre-Flight Action |
|---|---|---|---|
| **0 – 24** | **Clean / Safe** | 🟢 Emerald Green | **Allow:** Target financial application launches seamlessly. |
| **25 – 49** | **Guarded / Warning** | 🟡 Amber Yellow | **Warn:** Non-critical unknown process present. Prompt user with explanation. |
| **50 – 74** | **Elevated Risk** | 🟠 Orange | **High Risk:** Potentially dangerous tool or unsigned high-privilege app running. User review required. |
| **75 – 100** | **Critical Threat** | 🔴 Crimson Red | **Block:** Active keylogger, injection vector, or remote session detected. Target application access locked until threat is terminated. |

---

## 4. Protected Financial Target Registry

FinGuard maintains a curated database of target applications and web portals, which can be extended by the user:

```yaml
protected_targets:
  - name: "Commercial Bank of Ethiopia (CBE) Web Banking"
    type: "web"
    domains: ["*.cbe.com.et", "cbe.com.et", "cbebirr.cbe.com.et"]
    strict_mode: true

  - name: "Telebirr Web Portal & App"
    type: "web_or_app"
    domains: ["*.telebirr.et", "telebirr.et"]
    process_names: ["telebirr.exe"]
    strict_mode: true

  - name: "Bank of Abyssinia (BOA)"
    type: "web"
    domains: ["*.bankofabyssinia.com"]
    strict_mode: true

  - name: "Dashen Bank (Amole)"
    type: "web"
    domains: ["*.dashenbanksc.com"]
    strict_mode: true

  - name: "Awash Bank"
    type: "web"
    domains: ["*.awashbank.com"]
    strict_mode: true

  - name: "Generic Banking & Crypto Wallets"
    type: "process"
    process_names: ["exodus.exe", "electrum.exe", "metamask.exe"]
    strict_mode: true
```
