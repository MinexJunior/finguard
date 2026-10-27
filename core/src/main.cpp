#include "finguard/hal/mock_collector.hpp"
#include "finguard/monitors/process_monitor.hpp"
#include <iostream>
#include <iomanip>
#include <string_view>

void print_banner() {
    std::cout << "\033[1;36m"
              << "========================================================\n"
              << "       FinGuard Native Process Security Scanner         \n"
              << "       Financial Pre-Flight Endpoint Integrity Guard   \n"
              << "========================================================\n"
              << "\033[0m";
}

#include "finguard/monitors/permission_monitor.hpp"
#include "finguard/engine/risk_engine.hpp"

void print_json(const finguard::engine::SystemRiskReport& sys_risk, const finguard::monitors::ScanReport& report) {
    std::cout << "{\n";
    std::cout << "  \"overall_risk_score\": " << sys_risk.overall_risk_score << ",\n";
    std::cout << "  \"risk_tier\": \"" << finguard::engine::to_string(sys_risk.overall_tier) << "\",\n";
    std::cout << "  \"preflight_decision\": \"" << finguard::engine::to_string(sys_risk.preflight_decision) << "\",\n";
    std::cout << "  \"total_processes\": " << report.total_processes_scanned << ",\n";
    std::cout << "  \"anomalous_process_count\": " << sys_risk.anomalous_process_count << ",\n";
    std::cout << "  \"scan_duration_us\": " << report.scan_duration_us.count() << ",\n";
    std::cout << "  \"top_threats\": [\n";

    for (size_t i = 0; i < sys_risk.top_threats.size(); ++i) {
        const auto& t = sys_risk.top_threats[i];
        std::cout << "    {\n";
        std::cout << "      \"pid\": " << t.pid << ",\n";
        std::cout << "      \"process_name\": \"" << t.process_name << "\",\n";
        std::cout << "      \"final_score\": " << t.final_score << ",\n";
        std::cout << "      \"tier\": \"" << finguard::engine::to_string(t.tier) << "\",\n";
        std::cout << "      \"action\": \"" << finguard::engine::to_string(t.action) << "\",\n";
        std::cout << "      \"factor_count\": " << t.factors.size() << "\n";
        std::cout << "    }" << (i + 1 < sys_risk.top_threats.size() ? "," : "") << "\n";
    }
    std::cout << "  ],\n";
    std::cout << "  \"remediation_steps\": [\n";
    for (size_t i = 0; i < sys_risk.remediation_steps.size(); ++i) {
        std::cout << "    \"" << sys_risk.remediation_steps[i] << "\"" 
                  << (i + 1 < sys_risk.remediation_steps.size() ? "," : "") << "\n";
    }
    std::cout << "  ]\n";
    std::cout << "}\n";
}

void print_human_report(const finguard::engine::SystemRiskReport& sys_risk, const finguard::monitors::ScanReport& report) {
    print_banner();

    std::cout << "\n[+] Endpoint Security & Pre-Flight Analysis\n";
    std::cout << "    Processes Scanned: " << report.total_processes_scanned << "\n";
    std::cout << "    Scan Duration:     " << report.scan_duration_us.count() << " us ("
              << std::fixed << std::setprecision(3) << (report.scan_duration_us.count() / 1000.0) << " ms)\n";

    // Color-coded Risk Score Banner
    std::string tier_color = "\033[1;32m"; // Green
    if (sys_risk.overall_tier == finguard::engine::RiskTier::Guarded) tier_color = "\033[1;33m"; // Amber
    else if (sys_risk.overall_tier == finguard::engine::RiskTier::Elevated) tier_color = "\033[1;35m"; // Magenta
    else if (sys_risk.overall_tier == finguard::engine::RiskTier::Critical) tier_color = "\033[1;31m"; // Red

    std::cout << "\n" << tier_color
              << "========================================================\n"
              << "  RISK SCORE: " << sys_risk.overall_risk_score << "/100  [" 
              << finguard::engine::to_string(sys_risk.overall_tier) << "]\n"
              << "  PRE-FLIGHT DECISION: " << finguard::engine::to_string(sys_risk.preflight_decision) << "\n"
              << "========================================================\033[0m\n";

    if (sys_risk.preflight_decision == finguard::engine::PreFlightAction::AllowLaunch) {
        std::cout << "\n\033[1;32m[✓] PRE-FLIGHT CHECK PASSED: Safe to launch CBE, Telebirr, and web banking apps.\033[0m\n";
        return;
    }

    std::cout << "\n\033[1;31m[!] CRITICAL BLOCKERS FOR FINANCIAL APPLICATIONS (" 
              << sys_risk.top_threats.size() << " Threats):\033[0m\n";
    std::cout << std::string(75, '-') << "\n";

    for (const auto& t : sys_risk.top_threats) {
        std::string col = (t.tier == finguard::engine::RiskTier::Critical) ? "\033[1;31m" : "\033[1;33m";
        std::cout << col << "[" << finguard::engine::to_string(t.tier) << "] " 
                  << t.process_name << " (PID " << t.pid << ") - Risk: " << t.final_score << "/100\033[0m\n";
        std::cout << "  Path: " << t.executable_path << "\n";
        for (const auto& f : t.factors) {
            std::cout << "    * " << f.name << " (+" << f.points << " pts) - " << f.description << "\n";
        }
        std::cout << std::string(75, '-') << "\n";
    }

    if (!sys_risk.remediation_steps.empty()) {
        std::cout << "\n\033[1;36m[+] Required Remediation Steps Before Proceeding:\033[0m\n";
        for (const auto& step : sys_risk.remediation_steps) {
            std::cout << "    -> " << step << "\n";
        }
    }
}

#include "finguard/pe/pe_analyzer.hpp"

void print_pe_report(const finguard::pe::PeReport& rep, bool json_mode) {
    if (json_mode) {
        std::cout << "{\n";
        std::cout << "  \"valid_pe\": " << (rep.is_valid_pe ? "true" : "false") << ",\n";
        std::cout << "  \"file_path\": \"" << rep.file_path << "\",\n";
        std::cout << "  \"architecture\": \"" << rep.architecture << "\",\n";
        std::cout << "  \"global_entropy\": " << rep.global_entropy << ",\n";
        std::cout << "  \"is_packed\": " << (rep.is_packed ? "true" : "false") << ",\n";
        std::cout << "  \"is_signed\": " << (rep.signature.is_signed ? "true" : "false") << ",\n";
        std::cout << "  \"dangerous_api_count\": " << rep.dangerous_apis.size() << ",\n";
        std::cout << "  \"dangerous_apis\": [\n";
        for (size_t i = 0; i < rep.dangerous_apis.size(); ++i) {
            const auto& d = rep.dangerous_apis[i];
            std::cout << "    {\"api\": \"" << d.api_name << "\", \"category\": \"" << d.category 
                      << "\", \"severity\": \"" << finguard::to_string(d.severity) << "\"}" 
                      << (i + 1 < rep.dangerous_apis.size() ? "," : "") << "\n";
        }
        std::cout << "  ]\n";
        std::cout << "}\n";
        return;
    }

    print_banner();
    std::cout << "\n\033[1;36m[+] PE Binary Static Analysis Report\033[0m\n";
    std::cout << "    Target File:    " << rep.file_path << "\n";
    std::cout << "    SHA-256:        " << rep.sha256_hash << "\n";
    std::cout << "    Valid PE:       " << (rep.is_valid_pe ? "\033[1;32mYES\033[0m" : "\033[1;31mNO\033[0m") << "\n";
    std::cout << "    Architecture:   " << rep.architecture << "\n";
    std::cout << "    Global Entropy: " << std::fixed << std::setprecision(3) << rep.global_entropy 
              << " bits/byte " << (rep.is_packed ? "\033[1;31m[PACKED/ENCRYPTED]\033[0m" : "\033[1;32m[NORMAL]\033[0m") << "\n";
    std::cout << "    Digital Sig:    " << (rep.signature.is_signed ? "\033[1;32mSIGNED (" + rep.signature.status_message + ")\033[0m" : "\033[1;33mUNSIGNED\033[0m") << "\n";

    std::cout << "\n[+] Sections (" << rep.sections.size() << "):\n";
    for (const auto& sec : rep.sections) {
        std::cout << "    " << std::left << std::setw(10) << sec.name 
                  << " Entropy: " << std::fixed << std::setprecision(2) << sec.entropy
                  << (sec.is_packed ? " \033[1;31m(PACKED)\033[0m" : "")
                  << (sec.is_rwx ? " \033[1;31m(RWX - INJECTION RISK!)\033[0m" : "")
                  << "\n";
    }

    if (!rep.dangerous_apis.empty()) {
        std::cout << "\n\033[1;31m[!] Dangerous Financial-Risk APIs Detected (" << rep.dangerous_apis.size() << "):\033[0m\n";
        for (const auto& d : rep.dangerous_apis) {
            std::cout << "    [" << finguard::to_string(d.severity) << "] " << d.api_name 
                      << " (" << d.dll_name << ") - Category: " << d.category << "\n";
        }
    } else {
        std::cout << "\n\033[1;32m[✓] No dangerous injection, keylogging, or screen capture APIs found in IAT.\033[0m\n";
    }

    if (!rep.anomalies.empty()) {
        std::cout << "\n\033[1;33m[!] Heuristic Warnings:\033[0m\n";
        for (const auto& a : rep.anomalies) {
            std::cout << "    * " << a << "\n";
        }
    }
}

int main(int argc, char* argv[]) {
    bool json_mode = false;
    bool real_procfs = false;
    bool benchmark = false;
    std::string pe_target;

    for (int i = 1; i < argc; ++i) {
        std::string_view arg = argv[i];
        if (arg == "--json") json_mode = true;
        else if (arg == "--real-procfs") real_procfs = true;
        else if (arg == "--benchmark") benchmark = true;
        else if (arg == "--analyze-pe" && i + 1 < argc) {
            pe_target = argv[++i];
        }
        else if (arg == "--help" || arg == "-h") {
            std::cout << "Usage: finguard-core [options]\n"
                      << "  --scan                   Perform process snapshot scan and output audit table (default)\n"
                      << "  --analyze-pe <filepath>  Statically inspect a Windows PE (.exe/.dll) binary\n"
                      << "  --json                   Output JSON format for UI and IPC\n"
                      << "  --real-procfs            Scan actual host Linux /proc instead of synthetic scenario\n"
                      << "  --benchmark              Run 100 consecutive scans and compute latency metrics\n"
                      << "  --help                   Show this help message\n";
            return 0;
        }
    }

    if (!pe_target.empty()) {
        auto rep = finguard::pe::PeAnalyzer::analyze_file(pe_target);
        print_pe_report(rep, json_mode);
        return 0;
    }

    auto mock_collector = std::make_shared<finguard::hal::MockCollector>();
    if (real_procfs) {
        mock_collector->populate_from_linux_procfs();
    }

    finguard::monitors::ProcessMonitor monitor(mock_collector);

    if (benchmark) {
        print_banner();
        std::cout << "[*] Running 100 scan iterations to measure execution latency...\n";
        int64_t total_us = 0;
        for (int i = 0; i < 100; ++i) {
            auto rep = monitor.scan_and_analyze();
            total_us += rep.scan_duration_us.count();
        }
        std::cout << "[✓] 100 Iterations Complete.\n";
        std::cout << "    Average Scan Duration: " << (total_us / 100.0) << " us ("
                  << (total_us / 100000.0) << " ms)\n";
        return 0;
    }

    finguard::monitors::PermissionMonitor perm_monitor(mock_collector);
    finguard::monitors::BehaviorMonitor behav_monitor(mock_collector);

    auto scan_report = monitor.scan_and_analyze();
    auto perm_report = perm_monitor.audit_permissions();
    auto behav_report = behav_monitor.audit_behavior();
    auto sys_risk = finguard::engine::RiskEngine::evaluate_system(scan_report, perm_report, behav_report);

    if (json_mode) {
        print_json(sys_risk, scan_report);
    } else {
        print_human_report(sys_risk, scan_report);
    }

    return 0;
}
