#include "finguard/hal/mock_collector.hpp"
#include "finguard/monitors/process_monitor.hpp"
#include "finguard/monitors/permission_monitor.hpp"
#include "finguard/monitors/behavior_monitor.hpp"
#include "finguard/engine/risk_engine.hpp"
#include <iostream>
#include <cassert>

#define TEST_ASSERT(cond, msg) \
    do { \
        if (!(cond)) { \
            std::cerr << "\033[1;31m[FAILED]\033[0m " << msg << " (" << __FILE__ << ":" << __LINE__ << ")\n"; \
            return 1; \
        } \
    } while (0)

int test_remote_desktop_classification() {
    using namespace finguard::monitors;

    TEST_ASSERT(BehaviorMonitor::is_known_remote_desktop_tool("AnyDesk.exe"), "AnyDesk must be detected");
    TEST_ASSERT(BehaviorMonitor::is_known_remote_desktop_tool("teamviewer.exe"), "TeamViewer must be detected");
    TEST_ASSERT(BehaviorMonitor::is_known_remote_desktop_tool("rustdesk.exe"), "RustDesk must be detected");
    TEST_ASSERT(BehaviorMonitor::is_known_remote_desktop_tool("ultraviewer.exe"), "UltraViewer must be detected");
    TEST_ASSERT(BehaviorMonitor::is_known_remote_desktop_tool("winvnc.exe"), "VNC must be detected");
    TEST_ASSERT(!BehaviorMonitor::is_known_remote_desktop_tool("chrome.exe"), "Chrome must not be classified as remote desktop");
    TEST_ASSERT(!BehaviorMonitor::is_known_remote_desktop_tool("telebirr.exe"), "Telebirr must not be remote desktop");

    std::cout << "\033[1;32m[PASSED]\033[0m test_remote_desktop_classification\n";
    return 0;
}

int test_suspicious_socket_inspection() {
    using namespace finguard::monitors;

    TEST_ASSERT(BehaviorMonitor::is_suspicious_socket_binary("powershell.exe"), "PowerShell socket must be suspicious");
    TEST_ASSERT(BehaviorMonitor::is_suspicious_socket_binary("cmd.exe"), "cmd.exe socket must be suspicious");
    TEST_ASSERT(!BehaviorMonitor::is_suspicious_socket_binary("chrome.exe"), "Browser socket is expected");

    TEST_ASSERT(BehaviorMonitor::is_suspicious_remote_port(4444), "Port 4444 must be suspicious");
    TEST_ASSERT(BehaviorMonitor::is_suspicious_remote_port(1337), "Port 1337 must be suspicious");
    TEST_ASSERT(BehaviorMonitor::is_suspicious_remote_port(6667), "Port 6667 (IRC) must be suspicious");
    TEST_ASSERT(!BehaviorMonitor::is_suspicious_remote_port(443), "Port 443 (HTTPS) must be normal");
    TEST_ASSERT(!BehaviorMonitor::is_suspicious_remote_port(80), "Port 80 (HTTP) must be normal");

    std::cout << "\033[1;32m[PASSED]\033[0m test_suspicious_socket_inspection\n";
    return 0;
}

int test_remote_desktop_presence_detection() {
    using namespace finguard;
    using namespace finguard::hal;
    using namespace finguard::monitors;

    auto collector = std::make_shared<MockCollector>();

    // Inject an active AnyDesk session
    ProcessInfo anydesk;
    anydesk.pid = 7788;
    anydesk.ppid = 1024;
    anydesk.name = "AnyDesk.exe";
    anydesk.executable_path = "C:\\Program Files (x86)\\AnyDesk\\AnyDesk.exe";
    collector->add_process(anydesk);

    BehaviorMonitor monitor(collector);
    auto report = monitor.audit_behavior();

    TEST_ASSERT(report.has_active_remote_desktop, "Must flag has_active_remote_desktop = true");
    TEST_ASSERT(!report.active_remote_desktop_tools.empty(), "Active tools list must not be empty");

    bool found_anydesk_finding = false;
    for (const auto& f : report.findings) {
        if (f.pid == 7788 && f.category == "RemoteDesktopCoPresence") {
            found_anydesk_finding = true;
            TEST_ASSERT(f.severity == Severity::Critical, "Remote desktop presence must be Critical");
        }
    }
    TEST_ASSERT(found_anydesk_finding, "Must generate RemoteDesktopCoPresence finding for AnyDesk");

    std::cout << "\033[1;32m[PASSED]\033[0m test_remote_desktop_presence_detection\n";
    return 0;
}

int test_behavioral_risk_engine_integration() {
    using namespace finguard;
    using namespace finguard::hal;
    using namespace finguard::monitors;
    using namespace finguard::engine;

    auto collector = std::make_shared<MockCollector>();

    // Inject active TeamViewer session
    ProcessInfo tv;
    tv.pid = 8899;
    tv.ppid = 1024;
    tv.name = "TeamViewer.exe";
    tv.executable_path = "C:\\Program Files\\TeamViewer\\TeamViewer.exe";
    collector->add_process(tv);

    ProcessMonitor proc_mon(collector);
    PermissionMonitor perm_mon(collector);
    BehaviorMonitor behav_mon(collector);

    auto scan_rep = proc_mon.scan_and_analyze();
    auto perm_rep = perm_mon.audit_permissions();
    auto behav_rep = behav_mon.audit_behavior();

    auto sys_risk = RiskEngine::evaluate_system(scan_rep, perm_rep, behav_rep);

    TEST_ASSERT(sys_risk.overall_tier == RiskTier::Critical, 
                "System with active Remote Desktop must be elevated to Critical tier");
    TEST_ASSERT(sys_risk.preflight_decision == PreFlightAction::BlockLaunch,
                "Financial pre-flight must block launch while TeamViewer is active");

    bool found_tv_remediation = false;
    for (const auto& step : sys_risk.remediation_steps) {
        if (step.find("TeamViewer.exe") != std::string::npos) {
            found_tv_remediation = true;
        }
    }
    TEST_ASSERT(found_tv_remediation, "Must instruct user to close TeamViewer before banking");

    std::cout << "\033[1;32m[PASSED]\033[0m test_behavioral_risk_engine_integration (overall score: " 
              << sys_risk.overall_risk_score << "/100)\n";
    return 0;
}

int test_behavior_audit_performance() {
    using namespace finguard::hal;
    using namespace finguard::monitors;

    auto collector = std::make_shared<MockCollector>();
    BehaviorMonitor monitor(collector);

    auto report = monitor.audit_behavior();
    TEST_ASSERT(!report.active_sockets.empty(), "Active sockets should be populated");

    std::cout << "\033[1;32m[PASSED]\033[0m test_behavior_audit_performance (found " 
              << report.active_sockets.size() << " sockets, "
              << report.findings.size() << " behavioral findings)\n";
    return 0;
}

int main() {
    std::cout << "\n=== Running FinGuard Behavior Monitor Test Suite ===\n";
    int failed = 0;
    failed += test_remote_desktop_classification();
    failed += test_suspicious_socket_inspection();
    failed += test_remote_desktop_presence_detection();
    failed += test_behavioral_risk_engine_integration();
    failed += test_behavior_audit_performance();

    if (failed == 0) {
        std::cout << "\033[1;32m=== ALL 5 BEHAVIOR MONITOR TESTS PASSED SUCCESSFULLY! ===\033[0m\n\n";
        return 0;
    } else {
        std::cerr << "\033[1;31m=== " << failed << " TESTS FAILED! ===\033[0m\n\n";
        return 1;
    }
}
