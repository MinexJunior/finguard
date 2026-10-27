#pragma once

#include "finguard/hal/platform_collector.hpp"

namespace finguard::hal {

class Win32Collector : public PlatformCollector {
public:
    Win32Collector();
    ~Win32Collector() override;

    std::vector<ProcessInfo> enumerate_processes() override;
    std::optional<ProcessInfo> get_process_by_pid(uint32_t pid) override;
    std::vector<ModuleInfo> get_loaded_modules(uint32_t pid) override;
    std::vector<PrivilegeInfo> get_process_privileges(uint32_t pid) override;
    std::string get_platform_name() const override { return "Win32Native"; }

private:
#ifdef _WIN32
    void query_token_info(void* process_handle, ProcessInfo& info);
#endif
};

} // namespace finguard::hal
