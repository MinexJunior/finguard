#include "finguard/monitors/permission_monitor.hpp"
#include <algorithm>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

namespace finguard::monitors {

namespace {

std::string to_lower_str(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return std::tolower(c); });
    return s;
}

bool is_core_system_process(const std::string& proc_name) {
    auto p = to_lower_str(proc_name);
    return (p == "system" || p == "lsass.exe" || p == "services.exe" || 
            p == "csrss.exe" || p == "smss.exe" || p == "wininit.exe");
}

} // namespace

PermissionMonitor::PermissionMonitor(std::shared_ptr<hal::PlatformCollector> collector)
    : collector_(std::move(collector)) {}

bool PermissionMonitor::is_dangerous_userland_privilege(const std::string& priv_name) {
    auto p = to_lower_str(priv_name);
    return (p == "sedebugprivilege" || 
            p == "seimpersonateprivilege" || 
            p == "setcbprivilege" || 
            p == "seloaddriverprivilege" || 
            p == "sebackupprivilege" || 
            p == "serestoreprivilege" ||
            p == "setakeownershipprivilege");
}

std::vector<PermissionAuditFinding> PermissionMonitor::audit_process_privileges(const ProcessInfo& proc) {
    std::vector<PermissionAuditFinding> findings;
    bool is_system = is_core_system_process(proc.name);

    for (const auto& priv : proc.privileges) {
        if (!priv.is_enabled) continue;

        auto p = to_lower_str(priv.name);

        if (p == "sedebugprivilege" && !is_system) {
            PermissionAuditFinding f;
            f.pid = proc.pid;
            f.process_name = proc.name;
            f.privilege_name = priv.name;
            f.severity = Severity::Critical;
            f.risk_weight = 40;
            f.description = "Process holds SeDebugPrivilege. Capable of reading and injecting memory into financial applications.";
            findings.push_back(std::move(f));
        } else if (p == "seimpersonateprivilege" && !is_system) {
            PermissionAuditFinding f;
            f.pid = proc.pid;
            f.process_name = proc.name;
            f.privilege_name = priv.name;
            f.severity = Severity::High;
            f.risk_weight = 30;
            f.description = "Process holds SeImpersonatePrivilege. Vulnerable to token abuse and privilege escalation.";
            findings.push_back(std::move(f));
        } else if ((p == "setcbprivilege" || p == "seloaddriverprivilege") && !is_system) {
            PermissionAuditFinding f;
            f.pid = proc.pid;
            f.process_name = proc.name;
            f.privilege_name = priv.name;
            f.severity = Severity::Critical;
            f.risk_weight = 45;
            f.description = "Process holds kernel-level OS privileges (" + priv.name + "). High rootkit/tampering risk.";
            findings.push_back(std::move(f));
        }
    }

    return findings;
}

std::vector<StartupEntry> PermissionMonitor::audit_startup_entries() {
    std::vector<StartupEntry> entries;

#ifdef _WIN32
    auto scan_reg_key = [&](HKEY root, const wchar_t* subkey, const std::string& location_name) {
        HKEY hKey = nullptr;
        if (RegOpenKeyExW(root, subkey, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            DWORD index = 0;
            wchar_t val_name[256];
            DWORD val_name_len = 256;
            DWORD val_type = 0;
            BYTE data[1024];
            DWORD data_len = sizeof(data);

            while (RegEnumValueW(hKey, index, val_name, &val_name_len, nullptr, &val_type, data, &data_len) == ERROR_SUCCESS) {
                if (val_type == REG_SZ || val_type == REG_EXPAND_SZ) {
                    StartupEntry entry;
                    entry.location = location_name;
                    
                    // Convert wide to utf8
                    std::wstring wname(val_name, val_name_len);
                    std::wstring wpath(reinterpret_cast<wchar_t*>(data), data_len / sizeof(wchar_t));
                    
                    entry.value_name = std::string(wname.begin(), wname.end());
                    entry.executable_path = std::string(wpath.begin(), wpath.end());
                    entries.push_back(std::move(entry));
                }
                index++;
                val_name_len = 256;
                data_len = sizeof(data);
            }
            RegCloseKey(hKey);
        }
    };

    scan_reg_key(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", "HKCU\\Run");
    scan_reg_key(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", "HKLM\\Run");
#else
    // Synthetic mock startup entries for development/testing
    StartupEntry e1;
    e1.location = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    e1.value_name = "OneDrive";
    e1.executable_path = "C:\\Users\\Victim\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe /background";
    e1.is_verified = true;
    entries.push_back(e1);
#endif

    return entries;
}

PermissionReport PermissionMonitor::audit_permissions() {
    PermissionReport report;
    auto procs = collector_->enumerate_processes();

    for (const auto& proc : procs) {
        auto findings = audit_process_privileges(proc);
        for (auto& f : findings) {
            report.privilege_findings.push_back(std::move(f));
        }
    }

    report.startup_entries = audit_startup_entries();
    return report;
}

} // namespace finguard::monitors
