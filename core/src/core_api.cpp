#include "finguard/core_api.h"
#include "finguard/hal/mock_collector.hpp"
#include "finguard/monitors/process_monitor.hpp"
#include "finguard/monitors/permission_monitor.hpp"
#include "finguard/monitors/behavior_monitor.hpp"
#include "finguard/pe/pe_analyzer.hpp"
#include "finguard/engine/risk_engine.hpp"

#include <string>
#include <sstream>
#include <cstdlib>
#include <cstring>

namespace {

char* duplicate_string(const std::string& str) {
    char* copy = static_cast<char*>(std::malloc(str.size() + 1));
    if (copy) {
        std::memcpy(copy, str.c_str(), str.size() + 1);
    }
    return copy;
}

std::string escape_json(const std::string& s) {
    std::ostringstream o;
    for (char c : s) {
        switch (c) {
            case '"': o << "\\\""; break;
            case '\\': o << "\\\\"; break;
            case '\b': o << "\\b"; break;
            case '\f': o << "\\f"; break;
            case '\n': o << "\\n"; break;
            case '\r': o << "\\r"; break;
            case '\t': o << "\\t"; break;
            default:
                if ('\x00' <= c && c <= '\x1f') {
                    // Control character
                } else {
                    o << c;
                }
        }
    }
    return o.str();
}

} // namespace

extern "C" {

char* finguard_scan_system_json(bool real_procfs) {
    auto collector = std::make_shared<finguard::hal::MockCollector>();
    if (real_procfs) {
        collector->populate_from_linux_procfs();
    }

    finguard::monitors::ProcessMonitor proc_mon(collector);
    finguard::monitors::PermissionMonitor perm_mon(collector);
    finguard::monitors::BehaviorMonitor behav_mon(collector);

    auto scan_rep = proc_mon.scan_and_analyze();
    auto perm_rep = perm_mon.audit_permissions();
    auto behav_rep = behav_mon.audit_behavior();
    auto sys_risk = finguard::engine::RiskEngine::evaluate_system(scan_rep, perm_rep, behav_rep);

    std::ostringstream json;
    json << "{\n";
    json << "  \"overall_risk_score\": " << sys_risk.overall_risk_score << ",\n";
    json << "  \"risk_tier\": \"" << finguard::engine::to_string(sys_risk.overall_tier) << "\",\n";
    json << "  \"preflight_decision\": \"" << finguard::engine::to_string(sys_risk.preflight_decision) << "\",\n";
    json << "  \"total_processes\": " << scan_rep.total_processes_scanned << ",\n";
    json << "  \"anomalous_process_count\": " << sys_risk.anomalous_process_count << ",\n";
    json << "  \"scan_duration_us\": " << scan_rep.scan_duration_us.count() << ",\n";

    // Top threats
    json << "  \"top_threats\": [\n";
    for (size_t i = 0; i < sys_risk.top_threats.size(); ++i) {
        const auto& t = sys_risk.top_threats[i];
        json << "    {\n";
        json << "      \"pid\": " << t.pid << ",\n";
        json << "      \"process_name\": \"" << escape_json(t.process_name) << "\",\n";
        json << "      \"executable_path\": \"" << escape_json(t.executable_path) << "\",\n";
        json << "      \"final_score\": " << t.final_score << ",\n";
        json << "      \"tier\": \"" << finguard::engine::to_string(t.tier) << "\",\n";
        json << "      \"action\": \"" << finguard::engine::to_string(t.action) << "\",\n";
        json << "      \"diagnostic_summary\": \"" << escape_json(t.diagnostic_summary) << "\",\n";
        json << "      \"factors\": [\n";
        for (size_t j = 0; j < t.factors.size(); ++j) {
            const auto& f = t.factors[j];
            json << "        {\n";
            json << "          \"name\": \"" << escape_json(f.name) << "\",\n";
            json << "          \"category\": \"" << escape_json(f.category) << "\",\n";
            json << "          \"points\": " << f.points << ",\n";
            json << "          \"severity\": \"" << finguard::to_string(f.severity) << "\",\n";
            json << "          \"description\": \"" << escape_json(f.description) << "\"\n";
            json << "        }" << (j + 1 < t.factors.size() ? "," : "") << "\n";
        }
        json << "      ]\n";
        json << "    }" << (i + 1 < sys_risk.top_threats.size() ? "," : "") << "\n";
    }
    json << "  ],\n";

    // Critical blockers
    json << "  \"critical_blockers\": [\n";
    for (size_t i = 0; i < sys_risk.critical_blockers.size(); ++i) {
        json << "    \"" << escape_json(sys_risk.critical_blockers[i]) << "\""
             << (i + 1 < sys_risk.critical_blockers.size() ? "," : "") << "\n";
    }
    json << "  ],\n";

    // Remediation steps
    json << "  \"remediation_steps\": [\n";
    for (size_t i = 0; i < sys_risk.remediation_steps.size(); ++i) {
        json << "    \"" << escape_json(sys_risk.remediation_steps[i]) << "\""
             << (i + 1 < sys_risk.remediation_steps.size() ? "," : "") << "\n";
    }
    json << "  ],\n";

    // Process table sample for UI
    json << "  \"processes\": [\n";
    for (size_t i = 0; i < scan_rep.processes.size(); ++i) {
        const auto& p = scan_rep.processes[i];
        json << "    {\n";
        json << "      \"pid\": " << p.pid << ",\n";
        json << "      \"ppid\": " << p.ppid << ",\n";
        json << "      \"name\": \"" << escape_json(p.name) << "\",\n";
        json << "      \"path\": \"" << escape_json(p.executable_path) << "\",\n";
        json << "      \"integrity\": \"" << finguard::to_string(p.integrity_level) << "\",\n";
        json << "      \"is_elevated\": " << (p.is_elevated ? "true" : "false") << "\n";
        json << "    }" << (i + 1 < scan_rep.processes.size() ? "," : "") << "\n";
    }
    json << "  ]\n";
    json << "}\n";

    return duplicate_string(json.str());
}

char* finguard_analyze_pe_json(const char* filepath) {
    if (!filepath) return nullptr;

    auto rep = finguard::pe::PeAnalyzer::analyze_file(filepath);

    std::ostringstream json;
    json << "{\n";
    json << "  \"valid_pe\": " << (rep.is_valid_pe ? "true" : "false") << ",\n";
    json << "  \"file_path\": \"" << escape_json(rep.file_path) << "\",\n";
    json << "  \"file_size\": " << rep.file_size << ",\n";
    json << "  \"sha256\": \"" << rep.sha256_hash << "\",\n";
    json << "  \"architecture\": \"" << escape_json(rep.architecture) << "\",\n";
    json << "  \"global_entropy\": " << rep.global_entropy << ",\n";
    json << "  \"is_packed\": " << (rep.is_packed ? "true" : "false") << ",\n";
    json << "  \"subsystem\": " << rep.subsystem << ",\n";
    json << "  \"entry_point_rva\": " << rep.entry_point_rva << ",\n";
    json << "  \"image_base\": " << rep.image_base << ",\n";
    json << "  \"is_signed\": " << (rep.signature.is_signed ? "true" : "false") << ",\n";
    json << "  \"signature_status\": \"" << escape_json(rep.signature.status_message) << "\",\n";
    json << "  \"is_trusted_ca\": " << (rep.signature.is_trusted_ca ? "true" : "false") << ",\n";

    // Sections
    json << "  \"sections\": [\n";
    for (size_t i = 0; i < rep.sections.size(); ++i) {
        const auto& s = rep.sections[i];
        json << "    {\n";
        json << "      \"name\": \"" << escape_json(s.name) << "\",\n";
        json << "      \"virtual_address\": " << s.virtual_address << ",\n";
        json << "      \"virtual_size\": " << s.virtual_size << ",\n";
        json << "      \"raw_size\": " << s.raw_data_size << ",\n";
        json << "      \"entropy\": " << s.entropy << ",\n";
        json << "      \"is_executable\": " << (s.is_executable ? "true" : "false") << ",\n";
        json << "      \"is_writable\": " << (s.is_writable ? "true" : "false") << ",\n";
        json << "      \"is_rwx\": " << (s.is_rwx ? "true" : "false") << ",\n";
        json << "      \"is_packed\": " << (s.is_packed ? "true" : "false") << "\n";
        json << "    }" << (i + 1 < rep.sections.size() ? "," : "") << "\n";
    }
    json << "  ],\n";

    // Dangerous APIs
    json << "  \"dangerous_apis\": [\n";
    for (size_t i = 0; i < rep.dangerous_apis.size(); ++i) {
        const auto& d = rep.dangerous_apis[i];
        json << "    {\n";
        json << "      \"api_name\": \"" << escape_json(d.api_name) << "\",\n";
        json << "      \"dll_name\": \"" << escape_json(d.dll_name) << "\",\n";
        json << "      \"category\": \"" << escape_json(d.category) << "\",\n";
        json << "      \"severity\": \"" << finguard::to_string(d.severity) << "\",\n";
        json << "      \"risk_weight\": " << d.risk_weight << ",\n";
        json << "      \"description\": \"" << escape_json(d.description) << "\"\n";
        json << "    }" << (i + 1 < rep.dangerous_apis.size() ? "," : "") << "\n";
    }
    json << "  ],\n";

    // Anomalies
    json << "  \"anomalies\": [\n";
    for (size_t i = 0; i < rep.anomalies.size(); ++i) {
        json << "    \"" << escape_json(rep.anomalies[i]) << "\""
             << (i + 1 < rep.anomalies.size() ? "," : "") << "\n";
    }
    json << "  ]\n";
    json << "}\n";

    return duplicate_string(json.str());
}

int finguard_get_preflight_decision(bool real_procfs) {
    auto collector = std::make_shared<finguard::hal::MockCollector>();
    if (real_procfs) {
        collector->populate_from_linux_procfs();
    }
    finguard::monitors::ProcessMonitor proc_mon(collector);
    finguard::monitors::PermissionMonitor perm_mon(collector);
    finguard::monitors::BehaviorMonitor behav_mon(collector);

    auto scan_rep = proc_mon.scan_and_analyze();
    auto perm_rep = perm_mon.audit_permissions();
    auto behav_rep = behav_mon.audit_behavior();
    auto sys_risk = finguard::engine::RiskEngine::evaluate_system(scan_rep, perm_rep, behav_rep);

    return static_cast<int>(sys_risk.preflight_decision);
}

uint32_t finguard_get_system_risk_score(bool real_procfs) {
    auto collector = std::make_shared<finguard::hal::MockCollector>();
    if (real_procfs) {
        collector->populate_from_linux_procfs();
    }
    finguard::monitors::ProcessMonitor proc_mon(collector);
    finguard::monitors::PermissionMonitor perm_mon(collector);
    finguard::monitors::BehaviorMonitor behav_mon(collector);

    auto scan_rep = proc_mon.scan_and_analyze();
    auto perm_rep = perm_mon.audit_permissions();
    auto behav_rep = behav_mon.audit_behavior();
    auto sys_risk = finguard::engine::RiskEngine::evaluate_system(scan_rep, perm_rep, behav_rep);

    return sys_risk.overall_risk_score;
}

void finguard_free_string(char* ptr) {
    if (ptr) {
        std::free(ptr);
    }
}

} // extern "C"
