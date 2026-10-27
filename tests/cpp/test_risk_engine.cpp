#include "finguard/hal/mock_collector.hpp"
#include "finguard/monitors/process_monitor.hpp"
#include "finguard/monitors/permission_monitor.hpp"
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

int test_score_to_tier_mapping() {
    using namespace finguard::engine;

    // Technical Report Section 4.3 & 7.4 Ranges:
    // Low: 0 - 29
    // Medium: 30 - 59
    // High: 60 - 99
    // Critical: 100+
    TEST_ASSERT(RiskEngine::score_to_tier(0) == RiskTier::Clean, "0 must map to Clean (Low)");
    TEST_ASSERT(RiskEngine::score_to_tier(29) == RiskTier::Clean, "29 must map to Clean (Low)");
    TEST_ASSERT(RiskEngine::score_to_tier(30) == RiskTier::Guarded, "30 must map to Guarded (Medium)");
    TEST_ASSERT(RiskEngine::score_to_tier(59) == RiskTier::Guarded, "59 must map to Guarded (Medium)");
    TEST_ASSERT(RiskEngine::score_to_tier(60) == RiskTier::Elevated, "60 must map to Elevated (High)");
    TEST_ASSERT(RiskEngine::score_to_tier(99) == RiskTier::Elevated, "99 must map to Elevated (High)");
    TEST_ASSERT(RiskEngine::score_to_tier(100) == RiskTier::Critical, "100 must map to Critical");
    TEST_ASSERT(RiskEngine::score_to_tier(150) == RiskTier::Critical, "150 must map to Critical");

    TEST_ASSERT(RiskEngine::tier_to_action(RiskTier::Clean) == PreFlightAction::AllowLaunch, "Clean must allow launch");
    TEST_ASSERT(RiskEngine::tier_to_action(RiskTier::Guarded) == PreFlightAction::WarnUser, "Guarded must warn user");
    TEST_ASSERT(RiskEngine::tier_to_action(RiskTier::Elevated) == PreFlightAction::RequireUserReview, "Elevated must require review/close app");
    TEST_ASSERT(RiskEngine::tier_to_action(RiskTier::Critical) == PreFlightAction::BlockLaunch, "Critical must block launch");

    std::cout << "\033[1;32m[PASSED]\033[0m test_score_to_tier_mapping\n";
    return 0;
}

int test_permission_privilege_audit() {
    using namespace finguard;
    using namespace finguard::monitors;

    auto collector = std::make_shared<hal::MockCollector>();
    PermissionMonitor perm_monitor(collector);

    auto perm_report = perm_monitor.audit_permissions();

    // Verify untrusted_injector.exe (PID 6200) holding SeDebugPrivilege was flagged
    bool found_injector_debug = false;
    bool legit_lsass_flagged = false;

    for (const auto& f : perm_report.privilege_findings) {
        if (f.pid == 6200 && f.privilege_name == "SeDebugPrivilege") {
            found_injector_debug = true;
            TEST_ASSERT(f.severity == Severity::Critical, "SeDebugPrivilege must have Critical severity");
        }
        if (f.process_name == "lsass.exe") {
            legit_lsass_flagged = true;
        }
    }

    TEST_ASSERT(found_injector_debug, "Non-system untrusted_injector.exe must be flagged for SeDebugPrivilege");
    TEST_ASSERT(!legit_lsass_flagged, "System lsass.exe holding SeDebugPrivilege must not be flagged");

    std::cout << "\033[1;32m[PASSED]\033[0m test_permission_privilege_audit\n";
    return 0;
}

int test_clean_baseline_scoring() {
    using namespace finguard;
    using namespace finguard::engine;

    ProcessInfo clean_proc;
    clean_proc.pid = 880;
    clean_proc.ppid = 612;
    clean_proc.name = "svchost.exe";
    clean_proc.executable_path = "C:\\Windows\\System32\\svchost.exe";

    auto risk = RiskEngine::evaluate_process(clean_proc, {}, std::nullopt, {});

    TEST_ASSERT(risk.final_score < 15, "Authentic System32 svchost must score < 15");
    TEST_ASSERT(risk.tier == RiskTier::Clean, "Clean process must be in Clean tier");
    TEST_ASSERT(risk.action == PreFlightAction::AllowLaunch, "Clean process must have AllowLaunch decision");

    std::cout << "\033[1;32m[PASSED]\033[0m test_clean_baseline_scoring (score: " 
              << risk.final_score << "/100)\n";
    return 0;
}

int test_composite_malware_scoring() {
    using namespace finguard;
    using namespace finguard::engine;

    // Simulate an aggressive financial trojan:
    // Unsigned, AppData path, holds SeDebugPrivilege, imports Keylogger & Injection APIs
    ProcessInfo trojan_proc;
    trojan_proc.pid = 9999;
    trojan_proc.ppid = 1024;
    trojan_proc.name = "telebirr_update_helper.exe";
    trojan_proc.executable_path = "C:\\Users\\Victim\\AppData\\Local\\Temp\\telebirr_update_helper.exe";

    std::vector<ProcessAnomaly> anomalies;
    ProcessAnomaly anom;
    anom.pid = trojan_proc.pid;
    anom.category = AnomalyCategory::PathSpoofing;
    anom.risk_weight = 40;
    anom.title = "Impostor executable location";
    anomalies.push_back(anom);

    std::vector<monitors::PermissionAuditFinding> priv_findings;
    monitors::PermissionAuditFinding priv;
    priv.pid = trojan_proc.pid;
    priv.privilege_name = "SeDebugPrivilege";
    priv.risk_weight = 40;
    priv_findings.push_back(priv);

    pe::PeReport pe_rep;
    pe_rep.is_valid_pe = true;
    pe_rep.is_packed = true;
    pe_rep.signature.is_signed = false;

    pe::DangerousApiFinding d1;
    d1.api_name = "SetWindowsHookExW";
    d1.category = "Keylogging";
    d1.risk_weight = 40;
    pe_rep.dangerous_apis.push_back(d1);

    pe::DangerousApiFinding d2;
    d2.api_name = "VirtualAllocEx";
    d2.category = "ProcessInjection";
    d2.risk_weight = 40;
    pe_rep.dangerous_apis.push_back(d2);

    auto risk = RiskEngine::evaluate_process(trojan_proc, anomalies, pe_rep, priv_findings);

    TEST_ASSERT(risk.raw_score >= 150, "Raw score must accumulate all threat factors");
    TEST_ASSERT(risk.final_score == 100, "Final score must be clamped at 100/100");
    TEST_ASSERT(risk.tier == RiskTier::Critical, "Composite trojan must be in Critical tier");
    TEST_ASSERT(risk.action == PreFlightAction::BlockLaunch, "Pre-flight action must be BLOCK_LAUNCH");
    TEST_ASSERT(risk.factors.size() >= 4, "Must list all triggered risk factors");

    std::cout << "\033[1;32m[PASSED]\033[0m test_composite_malware_scoring (score: " 
              << risk.final_score << "/100 [" << to_string(risk.tier) << "])\n";
    return 0;
}

int test_system_wide_risk_evaluation() {
    using namespace finguard;
    using namespace finguard::hal;
    using namespace finguard::monitors;
    using namespace finguard::engine;

    auto collector = std::make_shared<MockCollector>();
    ProcessMonitor proc_mon(collector);
    PermissionMonitor perm_mon(collector);

    auto scan_report = proc_mon.scan_and_analyze();
    auto perm_report = perm_mon.audit_permissions();

    auto sys_risk = RiskEngine::evaluate_system(scan_report, perm_report);

    TEST_ASSERT(sys_risk.total_processes_scanned >= 10, "Must scan all processes");
    TEST_ASSERT(sys_risk.overall_tier == RiskTier::Elevated || sys_risk.overall_tier == RiskTier::Critical, 
                "System containing impostor svchost and injector must trigger Elevated or Critical tier");
    TEST_ASSERT(sys_risk.preflight_decision != PreFlightAction::AllowLaunch,
                "Pre-flight decision must intercept launching financial apps until threats are cleared");
    TEST_ASSERT(!sys_risk.top_threats.empty(), "Must produce list of top threats");
    TEST_ASSERT(sys_risk.evaluation_duration_us.count() < 10000, 
                "System risk evaluation must execute in under 10ms (< 10,000 us)");

    std::cout << "\033[1;32m[PASSED]\033[0m test_system_wide_risk_evaluation (duration: " 
              << sys_risk.evaluation_duration_us.count() << " us / "
              << (sys_risk.evaluation_duration_us.count() / 1000.0) << " ms, overall risk: "
              << sys_risk.overall_risk_score << "/100)\n";
    return 0;
}

int test_technical_report_scenario_b() {
    using namespace finguard;
    using namespace finguard::hal;
    using namespace finguard::monitors;
    using namespace finguard::engine;

    auto collector = std::make_shared<MockCollector>();
    ProcessMonitor proc_mon(collector);
    PermissionMonitor perm_mon(collector);
    BehaviorMonitor behav_mon(collector);

    auto scan_report = proc_mon.scan_and_analyze();
    auto perm_report = perm_mon.audit_permissions();
    auto behav_report = behav_mon.audit_behavior();
    auto sys_risk = RiskEngine::evaluate_system(scan_report, perm_report, behav_report);

    // Locate UnknownApp.exe (PID 5500)
    const ProcessRiskReport* unknown_app = nullptr;
    for (const auto& t : sys_risk.top_threats) {
        if (t.process_name == "UnknownApp.exe" || t.pid == 5500) {
            unknown_app = &t;
            break;
        }
    }

    TEST_ASSERT(unknown_app != nullptr, "UnknownApp.exe must be evaluated in top threats");
    TEST_ASSERT(unknown_app->final_score == 85, "Scenario B: UnknownApp.exe score must be exactly 85 (20+15+20+30)");
    TEST_ASSERT(unknown_app->tier == RiskTier::Elevated, "Scenario B: UnknownApp.exe level must be HIGH (Elevated)");
    TEST_ASSERT(unknown_app->action == PreFlightAction::RequireUserReview, "Action must recommend reviewing/closing application");

    std::cout << "\033[1;32m[PASSED]\033[0m test_technical_report_scenario_b (UnknownApp.exe score: " 
              << unknown_app->final_score << " level: " << tier_to_report_level(unknown_app->tier) << ")\n";
    return 0;
}

int main() {
    std::cout << "\n=== Running FinGuard Permission & Risk Engine Test Suite ===\n";
    int failed = 0;
    failed += test_score_to_tier_mapping();
    failed += test_permission_privilege_audit();
    failed += test_clean_baseline_scoring();
    failed += test_composite_malware_scoring();
    failed += test_system_wide_risk_evaluation();
    failed += test_technical_report_scenario_b();

    if (failed == 0) {
        std::cout << "\033[1;32m=== ALL 6 RISK ENGINE TESTS PASSED SUCCESSFULLY! ===\033[0m\n\n";
        return 0;
    } else {
        std::cerr << "\033[1;31m=== " << failed << " TESTS FAILED! ===\033[0m\n\n";
        return 1;
    }
}
