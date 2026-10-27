#pragma once

#include "finguard/hal/platform_collector.hpp"
#include <unordered_map>
#include <mutex>

namespace finguard::hal {

class MockCollector : public PlatformCollector {
public:
    MockCollector();
    ~MockCollector() override = default;

    std::vector<ProcessInfo> enumerate_processes() override;
    std::optional<ProcessInfo> get_process_by_pid(uint32_t pid) override;
    std::vector<ModuleInfo> get_loaded_modules(uint32_t pid) override;
    std::vector<PrivilegeInfo> get_process_privileges(uint32_t pid) override;
    std::string get_platform_name() const override { return "MockSyntheticCollector"; }

    // Test manipulation methods
    void load_default_threat_scenario();
    void add_process(ProcessInfo process);
    void clear_processes();
    void set_modules(uint32_t pid, std::vector<ModuleInfo> modules);
    void set_privileges(uint32_t pid, std::vector<PrivilegeInfo> privs);

    // Optional: read real processes from local Linux /proc filesystem
    void populate_from_linux_procfs();

private:
    std::mutex mutex_;
    std::unordered_map<uint32_t, ProcessInfo> processes_;
};

} // namespace finguard::hal
