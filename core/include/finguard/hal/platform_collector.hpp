#pragma once

#include "finguard/types.hpp"
#include <vector>
#include <optional>
#include <memory>
#include <string>

namespace finguard::hal {

class PlatformCollector {
public:
    virtual ~PlatformCollector() = default;

    // Enumerate all active processes with base metadata
    virtual std::vector<ProcessInfo> enumerate_processes() = 0;

    // Fetch deep information for a specific process
    virtual std::optional<ProcessInfo> get_process_by_pid(uint32_t pid) = 0;

    // Get loaded modules/DLLs for a given process
    virtual std::vector<ModuleInfo> get_loaded_modules(uint32_t pid) = 0;

    // Query token privileges (e.g. SeDebugPrivilege) for a process
    virtual std::vector<PrivilegeInfo> get_process_privileges(uint32_t pid) = 0;

    // Identify underlying provider name (e.g., "Win32Native", "LinuxSyntheticMock", "LinuxProcFS")
    virtual std::string get_platform_name() const = 0;
};

// Factory function to obtain the appropriate collector for the active runtime
std::unique_ptr<PlatformCollector> create_default_collector();

} // namespace finguard::hal
