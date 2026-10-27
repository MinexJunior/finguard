#pragma once

#include "finguard/hal/platform_collector.hpp"
#include "finguard/types.hpp"
#include <string>
#include <vector>
#include <memory>

namespace finguard::monitors {

struct StartupEntry {
    std::string location;       // e.g. "HKCU\\...\\Run", "HKLM\\...\\Run"
    std::string value_name;     // Name of startup program
    std::string executable_path;// Target executable
    bool is_verified{false};
};

struct PermissionAuditFinding {
    uint32_t pid{0};
    std::string process_name;
    std::string privilege_name;
    Severity severity{Severity::High};
    std::string description;
    uint32_t risk_weight{30};
};

struct PermissionReport {
    std::vector<PermissionAuditFinding> privilege_findings;
    std::vector<StartupEntry> startup_entries;
    std::vector<std::string> warnings;
};

class PermissionMonitor {
public:
    explicit PermissionMonitor(std::shared_ptr<hal::PlatformCollector> collector);
    ~PermissionMonitor() = default;

    // Run full permission audit across running processes and persistence entries
    PermissionReport audit_permissions();

    // Audit privileges of a single process
    std::vector<PermissionAuditFinding> audit_process_privileges(const ProcessInfo& proc);

    // Audit Windows startup persistence entries
    std::vector<StartupEntry> audit_startup_entries();

    // Check if privilege is inherently dangerous for userland software
    static bool is_dangerous_userland_privilege(const std::string& priv_name);

private:
    std::shared_ptr<hal::PlatformCollector> collector_;
};

} // namespace finguard::monitors
