#pragma once

#include "finguard/hal/platform_collector.hpp"
#include "finguard/types.hpp"
#include <vector>
#include <memory>
#include <unordered_map>
#include <string>

namespace finguard::monitors {

struct ScanReport {
    size_t total_processes_scanned{0};
    std::vector<ProcessAnomaly> anomalies;
    std::vector<ProcessInfo> processes;
    std::chrono::microseconds scan_duration_us{0};
};

class ProcessMonitor {
public:
    explicit ProcessMonitor(std::shared_ptr<hal::PlatformCollector> collector);
    ~ProcessMonitor() = default;

    // Run complete process snapshot and anomaly analysis
    ScanReport scan_and_analyze();

    // Isolated inspection methods for focused testing
    std::vector<ProcessAnomaly> inspect_process(const ProcessInfo& proc, 
                                               const std::unordered_map<uint32_t, ProcessInfo>& all_procs);

    // Helpers to classify known threats
    static bool is_path_spoofing(const std::string& proc_name, const std::string& full_path);
    static bool is_suspicious_parent(const std::string& parent_name, const std::string& child_name);
    static bool has_suspicious_command_line(const std::string& proc_name, const std::string& cmd_line);

private:
    std::shared_ptr<hal::PlatformCollector> collector_;

    void check_path_spoofing(const ProcessInfo& proc, std::vector<ProcessAnomaly>& out);
    void check_parent_child_lineage(const ProcessInfo& proc, 
                                   const std::unordered_map<uint32_t, ProcessInfo>& all_procs, 
                                   std::vector<ProcessAnomaly>& out);
    void check_command_line_anomalies(const ProcessInfo& proc, std::vector<ProcessAnomaly>& out);
    void check_privilege_anomalies(const ProcessInfo& proc, std::vector<ProcessAnomaly>& out);
};

} // namespace finguard::monitors
