#pragma once

#include "finguard/pe/pe_structures.hpp"
#include "finguard/pe/entropy.hpp"
#include "finguard/pe/signature_verifier.hpp"
#include "finguard/types.hpp"
#include <string>
#include <vector>
#include <optional>
#include <cstdint>

namespace finguard::pe {

struct PeSectionInfo {
    std::string name;
    uint32_t virtual_address{0};
    uint32_t virtual_size{0};
    uint32_t raw_data_size{0};
    uint32_t raw_data_offset{0};
    uint32_t characteristics{0};
    double entropy{0.0};
    bool is_executable{false};
    bool is_writable{false};
    bool is_rwx{false}; // Writable AND Executable simultaneously (malware shellcode indicator)
    bool is_packed{false};
};

struct ImportedModule {
    std::string dll_name;
    std::vector<std::string> functions;
};

struct DangerousApiFinding {
    std::string api_name;
    std::string dll_name;
    std::string category;
    Severity severity{Severity::Medium};
    uint32_t risk_weight{25};
    std::string description;
};

struct PeReport {
    bool is_valid_pe{false};
    std::string file_path;
    size_t file_size{0};
    std::string architecture; // "x86", "x64", "ARM64", etc.
    uint32_t entry_point_rva{0};
    uint64_t image_base{0};
    uint32_t size_of_image{0};
    uint16_t subsystem{0}; // GUI vs Console
    double global_entropy{0.0};
    bool is_packed{false};
    std::string sha256_hash;

    std::vector<PeSectionInfo> sections;
    std::vector<ImportedModule> imports;
    std::vector<DangerousApiFinding> dangerous_apis;
    SignatureReport signature;
    std::vector<std::string> anomalies;
};

class PeAnalyzer {
public:
    PeAnalyzer() = default;

    // Analyze PE directly from disk file
    static PeReport analyze_file(const std::string& filepath);

    // Analyze PE from memory buffer
    static PeReport analyze_memory(const uint8_t* data, size_t size, const std::string& origin = "memory_buffer");

    // RVA to File Offset translation helper
    static uint32_t rva_to_offset(uint32_t rva, const std::vector<ImageSectionHeader>& sections);

private:
    static void parse_imports(const uint8_t* data, 
                              size_t size, 
                              const ImageDataDirectory& import_dir,
                              const std::vector<ImageSectionHeader>& sections,
                              bool is_64bit,
                              PeReport& report);

    static void evaluate_dangerous_api(const std::string& dll, 
                                       const std::string& func, 
                                       PeReport& report);
};

} // namespace finguard::pe
