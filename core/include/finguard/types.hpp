#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <optional>
#include <chrono>

namespace finguard {

enum class Severity {
    None = 0,
    Informational = 1,
    Low = 2,
    Medium = 3,
    High = 4,
    Critical = 5
};

inline std::string to_string(Severity s) {
    switch (s) {
        case Severity::Informational: return "INFORMATIONAL";
        case Severity::Low: return "LOW";
        case Severity::Medium: return "MEDIUM";
        case Severity::High: return "HIGH";
        case Severity::Critical: return "CRITICAL";
        default: return "NONE";
    }
}

enum class IntegrityLevel {
    Unknown = 0,
    Untrusted = 1,
    Low = 2,
    Medium = 3,
    High = 4,
    System = 5,
    ProtectedProcess = 6
};

inline std::string to_string(IntegrityLevel level) {
    switch (level) {
        case IntegrityLevel::Untrusted: return "Untrusted";
        case IntegrityLevel::Low: return "Low";
        case IntegrityLevel::Medium: return "Medium";
        case IntegrityLevel::High: return "High";
        case IntegrityLevel::System: return "System";
        case IntegrityLevel::ProtectedProcess: return "ProtectedProcess";
        default: return "Unknown";
    }
}

struct PrivilegeInfo {
    std::string name;
    bool is_enabled{false};
    std::string description;
};

struct ModuleInfo {
    std::string name;
    std::string path;
    uint64_t base_address{0};
    uint32_t module_size{0};
};

struct ProcessInfo {
    uint32_t pid{0};
    uint32_t ppid{0};
    std::string name;
    std::string executable_path;
    std::string command_line;
    std::string user_account;
    IntegrityLevel integrity_level{IntegrityLevel::Unknown};
    bool is_elevated{false};
    uint64_t memory_rss_bytes{0};
    std::chrono::system_clock::time_point start_time{};
    std::vector<PrivilegeInfo> privileges;
    std::vector<ModuleInfo> loaded_modules;
};

enum class AnomalyCategory {
    PathSpoofing,
    SuspiciousParentChild,
    SuspiciousCommandLine,
    UnsignedSystemProcess,
    LOLBinAbuse,
    PrivilegeAbuse,
    MemoryInjectionRisk
};

inline std::string to_string(AnomalyCategory cat) {
    switch (cat) {
        case AnomalyCategory::PathSpoofing: return "PathSpoofing";
        case AnomalyCategory::SuspiciousParentChild: return "SuspiciousParentChild";
        case AnomalyCategory::SuspiciousCommandLine: return "SuspiciousCommandLine";
        case AnomalyCategory::UnsignedSystemProcess: return "UnsignedSystemProcess";
        case AnomalyCategory::LOLBinAbuse: return "LOLBinAbuse";
        case AnomalyCategory::PrivilegeAbuse: return "PrivilegeAbuse";
        case AnomalyCategory::MemoryInjectionRisk: return "MemoryInjectionRisk";
        default: return "Unknown";
    }
}

struct ProcessAnomaly {
    uint32_t pid{0};
    std::string process_name;
    AnomalyCategory category{AnomalyCategory::PathSpoofing};
    Severity severity{Severity::Medium};
    std::string title;
    std::string description;
    std::string expected_context;
    std::string observed_context;
    uint32_t risk_weight{20};
};

} // namespace finguard
