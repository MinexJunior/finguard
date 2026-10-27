#include "finguard/monitors/process_monitor.hpp"
#include <algorithm>
#include <cctype>
#include <chrono>

namespace finguard::monitors {

namespace {

std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return std::tolower(c); });
    return s;
}

bool contains_ci(const std::string& haystack, const std::string& needle) {
    auto h = to_lower(haystack);
    auto n = to_lower(needle);
    return h.find(n) != std::string::npos;
}


// Canonical Windows system paths
const std::unordered_map<std::string, std::vector<std::string>> CANONICAL_WINDOWS_PATHS = {
    {"svchost.exe", {"c:\\windows\\system32\\svchost.exe", "c:\\windows\\syswow64\\svchost.exe"}},
    {"lsass.exe", {"c:\\windows\\system32\\lsass.exe"}},
    {"services.exe", {"c:\\windows\\system32\\services.exe"}},
    {"csrss.exe", {"c:\\windows\\system32\\csrss.exe"}},
    {"smss.exe", {"c:\\windows\\system32\\smss.exe"}},
    {"wininit.exe", {"c:\\windows\\system32\\wininit.exe"}},
    {"winlogon.exe", {"c:\\windows\\system32\\winlogon.exe"}},
    {"explorer.exe", {"c:\\windows\\explorer.exe"}},
    {"taskhostw.exe", {"c:\\windows\\system32\\taskhostw.exe", "c:\\windows\\syswow64\\taskhostw.exe"}},
    {"spoolsv.exe", {"c:\\windows\\system32\\spoolsv.exe"}}
};

} // namespace

ProcessMonitor::ProcessMonitor(std::shared_ptr<hal::PlatformCollector> collector)
    : collector_(std::move(collector)) {}

bool ProcessMonitor::is_path_spoofing(const std::string& proc_name, const std::string& full_path) {
    if (full_path.empty()) return false;
    std::string lower_name = to_lower(proc_name);
    std::string lower_path = to_lower(full_path);

    auto it = CANONICAL_WINDOWS_PATHS.find(lower_name);
    if (it != CANONICAL_WINDOWS_PATHS.end()) {
        const auto& valid_paths = it->second;
        bool match = false;
        for (const auto& valid : valid_paths) {
            if (lower_path == valid) {
                match = true;
                break;
            }
        }
        return !match; // Path does NOT match authentic system location!
    }
    return false;
}

bool ProcessMonitor::is_suspicious_parent(const std::string& parent_name, const std::string& child_name) {
    std::string p = to_lower(parent_name);
    std::string c = to_lower(child_name);

    // Office applications spawning shells or script engines
    const std::vector<std::string> office_apps = {
        "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe"
    };

    const std::vector<std::string> risky_children = {
        "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
        "mshta.exe", "certutil.exe", "bitsadmin.exe", "rundll32.exe", "regsvr32.exe"
    };

    for (const auto& off : office_apps) {
        if (p == off) {
            for (const auto& r : risky_children) {
                if (c == r) return true;
            }
        }
    }

    // Browsers spawning command shells directly
    const std::vector<std::string> browsers = {
        "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe"
    };
    for (const auto& b : browsers) {
        if (p == b && (c == "cmd.exe" || c == "powershell.exe" || c == "cscript.exe")) {
            return true;
        }
    }

    // svchost.exe should normally be spawned by services.exe
    if (c == "svchost.exe" && !p.empty() && p != "services.exe") {
        return true;
    }

    return false;
}

bool ProcessMonitor::has_suspicious_command_line(const std::string& proc_name, const std::string& cmd_line) {
    if (cmd_line.empty()) return false;
    std::string p = to_lower(proc_name);

    // PowerShell suspicious flags
    if (p == "powershell.exe" || p == "pwsh.exe") {
        if (contains_ci(cmd_line, "-enc") ||
            contains_ci(cmd_line, "-encodedcommand") ||
            contains_ci(cmd_line, "downloadstring") ||
            contains_ci(cmd_line, "downloadfile") ||
            contains_ci(cmd_line, "net.webclient") ||
            contains_ci(cmd_line, "invoke-expression") ||
            contains_ci(cmd_line, "iex") ||
            (contains_ci(cmd_line, "-w hidden") || contains_ci(cmd_line, "-windowstyle hidden"))) {
            return true;
        }
    }

    // Certutil URL cache download abuse
    if (p == "certutil.exe") {
        if (contains_ci(cmd_line, "-urlcache") || contains_ci(cmd_line, "-split")) {
            return true;
        }
    }

    // Mshta remote payload execution
    if (p == "mshta.exe") {
        if (contains_ci(cmd_line, "http://") || contains_ci(cmd_line, "https://") || contains_ci(cmd_line, "vbscript:")) {
            return true;
        }
    }

    // Vssadmin shadow copy deletion (ransomware indicator)
    if (p == "vssadmin.exe") {
        if (contains_ci(cmd_line, "delete") && contains_ci(cmd_line, "shadows")) {
            return true;
        }
    }

    return false;
}

void ProcessMonitor::check_path_spoofing(const ProcessInfo& proc, std::vector<ProcessAnomaly>& out) {
    if (is_path_spoofing(proc.name, proc.executable_path)) {
        ProcessAnomaly a;
        a.pid = proc.pid;
        a.process_name = proc.name;
        a.category = AnomalyCategory::PathSpoofing;
        a.severity = Severity::Critical;
        a.title = "Critical Impostor Process Detected (Path Spoofing)";
        a.description = "System binary '" + proc.name + "' is executing from an illegitimate directory!";
        a.observed_context = proc.executable_path;
        a.expected_context = "C:\\Windows\\System32\\" + proc.name;
        a.risk_weight = 45;
        out.push_back(std::move(a));
    }
}

void ProcessMonitor::check_parent_child_lineage(const ProcessInfo& proc, 
                                               const std::unordered_map<uint32_t, ProcessInfo>& all_procs, 
                                               std::vector<ProcessAnomaly>& out) {
    if (proc.ppid == 0) return;
    auto it = all_procs.find(proc.ppid);
    if (it != all_procs.end()) {
        const auto& parent = it->second;
        if (is_suspicious_parent(parent.name, proc.name)) {
            ProcessAnomaly a;
            a.pid = proc.pid;
            a.process_name = proc.name;
            a.category = AnomalyCategory::SuspiciousParentChild;
            a.severity = Severity::High;
            a.title = "Suspicious Process Lineage Detected";
            a.description = "Process '" + proc.name + "' was spawned by unexpected parent '" + parent.name + "'. Possible macro/exploit chain.";
            a.expected_context = "Legitimate administrative shell or system service";
            a.observed_context = "Parent: " + parent.name + " (PID " + std::to_string(parent.pid) + ")";
            a.risk_weight = 35;
            out.push_back(std::move(a));
        }
    }
}

void ProcessMonitor::check_command_line_anomalies(const ProcessInfo& proc, std::vector<ProcessAnomaly>& out) {
    if (has_suspicious_command_line(proc.name, proc.command_line)) {
        ProcessAnomaly a;
        a.pid = proc.pid;
        a.process_name = proc.name;
        a.category = AnomalyCategory::SuspiciousCommandLine;
        a.severity = Severity::High;
        a.title = "Suspicious Command Line Parameters (LOLBin Evasion / Download)";
        a.description = "Command line contains evasive flags (e.g. hidden window, encoded script, or remote download).";
        a.observed_context = proc.command_line;
        a.expected_context = "Standard interactive or service flags";
        a.risk_weight = 30;
        out.push_back(std::move(a));
    }
}

void ProcessMonitor::check_privilege_anomalies(const ProcessInfo& proc, std::vector<ProcessAnomaly>& out) {
    std::string lower_name = to_lower(proc.name);
    // Standard system processes that legitimately require SeDebugPrivilege
    bool is_legit_debug = (lower_name == "lsass.exe" || lower_name == "system" || lower_name == "services.exe");

    for (const auto& priv : proc.privileges) {
        if (priv.name == "SeDebugPrivilege" && priv.is_enabled && !is_legit_debug) {
            ProcessAnomaly a;
            a.pid = proc.pid;
            a.process_name = proc.name;
            a.category = AnomalyCategory::PrivilegeAbuse;
            a.severity = Severity::Critical;
            a.title = "Excessive Privilege Hazard: SeDebugPrivilege Active";
            a.description = "Non-system process holds enabled SeDebugPrivilege. This allows arbitrary memory reading and injection into banking applications.";
            a.observed_context = "SeDebugPrivilege=ENABLED in process " + proc.name + " (" + proc.executable_path + ")";
            a.expected_context = "Restricted user or standard integrity token";
            a.risk_weight = 40;
            out.push_back(std::move(a));
            break;
        }
    }
}

std::vector<ProcessAnomaly> ProcessMonitor::inspect_process(
    const ProcessInfo& proc,
    const std::unordered_map<uint32_t, ProcessInfo>& all_procs) {
    std::vector<ProcessAnomaly> anomalies;
    check_path_spoofing(proc, anomalies);
    check_parent_child_lineage(proc, all_procs, anomalies);
    check_command_line_anomalies(proc, anomalies);
    check_privilege_anomalies(proc, anomalies);
    return anomalies;
}

ScanReport ProcessMonitor::scan_and_analyze() {
    auto start_time = std::chrono::high_resolution_clock::now();

    ScanReport report;
    report.processes = collector_->enumerate_processes();
    report.total_processes_scanned = report.processes.size();

    std::unordered_map<uint32_t, ProcessInfo> proc_map;
    proc_map.reserve(report.processes.size());
    for (const auto& p : report.processes) {
        proc_map[p.pid] = p;
    }

    for (const auto& p : report.processes) {
        auto findings = inspect_process(p, proc_map);
        for (auto& f : findings) {
            report.anomalies.push_back(std::move(f));
        }
    }

    auto end_time = std::chrono::high_resolution_clock::now();
    report.scan_duration_us = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);

    return report;
}

} // namespace finguard::monitors
