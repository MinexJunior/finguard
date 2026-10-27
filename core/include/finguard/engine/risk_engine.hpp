#pragma once

#include "finguard/types.hpp"
#include "finguard/pe/pe_analyzer.hpp"
#include "finguard/monitors/process_monitor.hpp"
#include "finguard/monitors/permission_monitor.hpp"
#include <string>
#include <vector>
#include <memory>
#include <chrono>

#include "finguard/monitors/behavior_monitor.hpp"

namespace finguard::engine {

enum class RiskTier {
    Clean = 0,      // Low (0 - 29): Clean / Emerald Green (Safe to open financial apps)
    Guarded = 1,    // Medium (30 - 59): Notice / Amber (Minor anomalies, warn user)
    Elevated = 2,   // High (60 - 99): Warning / Orange (High risk, recommend closing app)
    Critical = 3    // Critical (100+): Crimson Red (Critical threat, BLOCK launch)
};

inline std::string to_string(RiskTier tier) {
    switch (tier) {
        case RiskTier::Clean: return "CLEAN";
        case RiskTier::Guarded: return "GUARDED";
        case RiskTier::Elevated: return "ELEVATED";
        case RiskTier::Critical: return "CRITICAL";
        default: return "UNKNOWN";
    }
}

inline std::string tier_to_report_level(RiskTier tier) {
    switch (tier) {
        case RiskTier::Clean: return "LOW";
        case RiskTier::Guarded: return "MEDIUM";
        case RiskTier::Elevated: return "HIGH";
        case RiskTier::Critical: return "CRITICAL";
        default: return "UNKNOWN";
    }
}

enum class PreFlightAction {
    AllowLaunch = 0,
    WarnUser = 1,
    RequireUserReview = 2,
    BlockLaunch = 3
};

inline std::string to_string(PreFlightAction action) {
    switch (action) {
        case PreFlightAction::AllowLaunch: return "ALLOW_LAUNCH";
        case PreFlightAction::WarnUser: return "WARN_USER";
        case PreFlightAction::RequireUserReview: return "REQUIRE_USER_REVIEW";
        case PreFlightAction::BlockLaunch: return "BLOCK_LAUNCH";
        default: return "UNKNOWN";
    }
}

struct RiskFactor {
    std::string name;
    std::string category;
    uint32_t points{0};
    Severity severity{Severity::Medium};
    std::string description;
};

struct ProcessRiskReport {
    uint32_t pid{0};
    std::string process_name;
    std::string executable_path;
    uint32_t raw_score{0};
    uint32_t final_score{0}; // 0 - 100
    RiskTier tier{RiskTier::Clean};
    PreFlightAction action{PreFlightAction::AllowLaunch};
    double dampening_factor{1.0};
    std::vector<RiskFactor> factors;
    std::string diagnostic_summary;
};

struct SystemRiskReport {
    uint32_t overall_risk_score{0};
    RiskTier overall_tier{RiskTier::Clean};
    PreFlightAction preflight_decision{PreFlightAction::AllowLaunch};
    size_t total_processes_scanned{0};
    size_t anomalous_process_count{0};
    std::vector<ProcessRiskReport> top_threats;
    std::vector<std::string> critical_blockers;
    std::vector<std::string> remediation_steps;
    std::chrono::microseconds evaluation_duration_us{0};
};

class RiskEngine {
public:
    RiskEngine() = default;

    // Evaluate risk of a single process based on process anomalies, PE report, permissions, and behavior
    static ProcessRiskReport evaluate_process(const ProcessInfo& proc,
                                             const std::vector<ProcessAnomaly>& anomalies,
                                             const std::optional<pe::PeReport>& pe_report,
                                             const std::vector<monitors::PermissionAuditFinding>& priv_findings,
                                             const std::vector<monitors::BehaviorFinding>& behavior_findings = {});

    // Evaluate end-to-end endpoint risk before launching financial apps
    static SystemRiskReport evaluate_system(const monitors::ScanReport& scan_report,
                                           const monitors::PermissionReport& perm_report,
                                           const std::optional<monitors::BehaviorReport>& behavior_report = std::nullopt);

    // Map numerical score to RiskTier
    static RiskTier score_to_tier(uint32_t score);

    // Map RiskTier to PreFlightAction
    static PreFlightAction tier_to_action(RiskTier tier);

    // Write structured audit log matching Technical Report Section 6.1 & 7.6
    static void write_audit_log(const SystemRiskReport& report, 
                                const std::string& target_app = "Financial App",
                                const std::string& log_file_path = "logs/finguard_scan.log");
};

} // namespace finguard::engine
