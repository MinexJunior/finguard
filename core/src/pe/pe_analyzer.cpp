#include "finguard/pe/pe_analyzer.hpp"
#include "finguard/pe/sha256.hpp"
#include <fstream>
#include <cstring>
#include <algorithm>

namespace finguard::pe {

namespace {

std::string clean_section_name(const uint8_t name[8]) {
    char buf[9] = {0};
    std::memcpy(buf, name, 8);
    return std::string(buf);
}

std::string to_lower_str(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return std::tolower(c); });
    return s;
}

} // namespace

uint32_t PeAnalyzer::rva_to_offset(uint32_t rva, const std::vector<ImageSectionHeader>& sections) {
    for (const auto& sec : sections) {
        uint32_t sec_vaddr = sec.VirtualAddress;
        uint32_t sec_vsize = sec.Misc.VirtualSize ? sec.Misc.VirtualSize : sec.SizeOfRawData;

        if (rva >= sec_vaddr && rva < sec_vaddr + sec_vsize) {
            return (rva - sec_vaddr) + sec.PointerToRawData;
        }
    }
    return 0;
}

PeReport PeAnalyzer::analyze_file(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        PeReport rep;
        rep.file_path = filepath;
        rep.anomalies.push_back("Failed to open file on disk: " + filepath);
        return rep;
    }

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<uint8_t> buffer(size);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        PeReport rep;
        rep.file_path = filepath;
        rep.anomalies.push_back("Failed to read file contents into memory");
        return rep;
    }

    auto report = analyze_memory(buffer.data(), buffer.size(), filepath);
    report.file_path = filepath;

    // Optional platform live signature validation on Windows
    if (report.signature.is_signed) {
        auto live_sig = SignatureVerifier::verify_file(filepath);
        if (live_sig.is_trusted_ca) {
            report.signature.is_trusted_ca = true;
            report.signature.status_message = live_sig.status_message;
        }
    }

    return report;
}

PeReport PeAnalyzer::analyze_memory(const uint8_t* data, size_t size, const std::string& origin) {
    PeReport rep;
    rep.file_path = origin;
    rep.file_size = size;

    if (!data || size == 0) {
        rep.anomalies.push_back("Empty data buffer provided for analysis");
        return rep;
    }

    // Compute SHA-256 hash of binary
    rep.sha256_hash = Sha256::hash_bytes(data, size);

    if (size < sizeof(ImageDosHeader)) {
        rep.anomalies.push_back("Buffer smaller than minimum DOS header size");
        return rep;
    }

    // 1. Validate DOS Header
    const auto* dos = reinterpret_cast<const ImageDosHeader*>(data);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        rep.anomalies.push_back("Invalid DOS signature (Expected 'MZ')");
        return rep;
    }

    // 2. Validate PE Signature offset
    if (dos->e_lfanew <= 0 || static_cast<size_t>(dos->e_lfanew) + 4 > size) {
        rep.anomalies.push_back("Corrupted e_lfanew offset to PE signature");
        return rep;
    }

    const uint32_t pe_sig = *reinterpret_cast<const uint32_t*>(data + dos->e_lfanew);
    if (pe_sig != IMAGE_NT_SIGNATURE) {
        rep.anomalies.push_back("Invalid PE signature (Expected 'PE\\0\\0')");
        return rep;
    }

    rep.is_valid_pe = true;

    // 3. COFF File Header
    size_t file_header_offset = dos->e_lfanew + 4;
    if (file_header_offset + sizeof(ImageFileHeader) > size) {
        rep.anomalies.push_back("Truncated COFF file header");
        return rep;
    }

    const auto* file_header = reinterpret_cast<const ImageFileHeader*>(data + file_header_offset);

    if (file_header->Machine == IMAGE_FILE_MACHINE_AMD64) {
        rep.architecture = "x64";
    } else if (file_header->Machine == IMAGE_FILE_MACHINE_I386) {
        rep.architecture = "x86";
    } else if (file_header->Machine == IMAGE_FILE_MACHINE_ARM64) {
        rep.architecture = "ARM64";
    } else {
        rep.architecture = "Unknown (0x" + std::to_string(file_header->Machine) + ")";
    }

    // 4. Optional Header & Data Directories
    size_t opt_header_offset = file_header_offset + sizeof(ImageFileHeader);
    if (opt_header_offset + 2 > size) {
        rep.anomalies.push_back("Missing Optional Header");
        return rep;
    }

    uint16_t opt_magic = *reinterpret_cast<const uint16_t*>(data + opt_header_offset);
    bool is_64bit = (opt_magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);

    ImageDataDirectory import_dir{};
    ImageDataDirectory security_dir{};

    if (is_64bit) {
        if (opt_header_offset + sizeof(ImageOptionalHeader64) > size) {
            rep.anomalies.push_back("Truncated 64-bit Optional Header");
            return rep;
        }
        const auto* opt64 = reinterpret_cast<const ImageOptionalHeader64*>(data + opt_header_offset);
        rep.entry_point_rva = opt64->AddressOfEntryPoint;
        rep.image_base = opt64->ImageBase;
        rep.size_of_image = opt64->SizeOfImage;
        rep.subsystem = opt64->Subsystem;

        import_dir = opt64->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        security_dir = opt64->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
    } else if (opt_magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        if (opt_header_offset + sizeof(ImageOptionalHeader32) > size) {
            rep.anomalies.push_back("Truncated 32-bit Optional Header");
            return rep;
        }
        const auto* opt32 = reinterpret_cast<const ImageOptionalHeader32*>(data + opt_header_offset);
        rep.entry_point_rva = opt32->AddressOfEntryPoint;
        rep.image_base = opt32->ImageBase;
        rep.size_of_image = opt32->SizeOfImage;
        rep.subsystem = opt32->Subsystem;

        import_dir = opt32->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        security_dir = opt32->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
    } else {
        rep.anomalies.push_back("Unknown Optional Header magic (0x" + std::to_string(opt_magic) + ")");
    }

    // 5. Global Shannon Entropy
    rep.global_entropy = EntropyCalculator::calculate(data, size);
    rep.is_packed = EntropyCalculator::is_suspiciously_packed(rep.global_entropy);
    if (rep.is_packed) {
        rep.anomalies.push_back("Extremely high global entropy (" + std::to_string(rep.global_entropy) + " bits/byte) indicates packed or crypted payload");
    }

    // 6. Section Table
    size_t section_table_offset = opt_header_offset + file_header->SizeOfOptionalHeader;
    size_t total_sections_size = file_header->NumberOfSections * sizeof(ImageSectionHeader);

    std::vector<ImageSectionHeader> raw_sections;
    if (section_table_offset + total_sections_size <= size) {
        raw_sections.resize(file_header->NumberOfSections);
        std::memcpy(raw_sections.data(), data + section_table_offset, total_sections_size);

        for (const auto& sec : raw_sections) {
            PeSectionInfo info;
            info.name = clean_section_name(sec.Name);
            info.virtual_address = sec.VirtualAddress;
            info.virtual_size = sec.Misc.VirtualSize;
            info.raw_data_size = sec.SizeOfRawData;
            info.raw_data_offset = sec.PointerToRawData;
            info.characteristics = sec.Characteristics;

            info.is_executable = (sec.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
            info.is_writable = (sec.Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
            info.is_rwx = info.is_executable && info.is_writable;

            if (info.is_rwx) {
                rep.anomalies.push_back("Section '" + info.name + "' is simultaneously Writable and Executable (RWX). Shellcode injection risk!");
            }

            // Section entropy
            if (sec.PointerToRawData + sec.SizeOfRawData <= size && sec.SizeOfRawData > 0) {
                info.entropy = EntropyCalculator::calculate(data + sec.PointerToRawData, sec.SizeOfRawData);
                info.is_packed = EntropyCalculator::is_suspiciously_packed(info.entropy);

                if (info.is_packed) {
                    rep.anomalies.push_back("Section '" + info.name + "' has packed entropy: " + std::to_string(info.entropy));
                }
            }

            // Known packer section name checks
            std::string lower_sec = to_lower_str(info.name);
            if (lower_sec.find("upx") != std::string::npos ||
                lower_sec.find("vmp") != std::string::npos ||
                lower_sec.find("themida") != std::string::npos ||
                lower_sec.find("aspack") != std::string::npos) {
                info.is_packed = true;
                rep.anomalies.push_back("Section '" + info.name + "' is a known malware packer signature name");
            }

            rep.sections.push_back(std::move(info));
        }
    }

    // 7. Parse Import Address Table (IAT)
    parse_imports(data, size, import_dir, raw_sections, is_64bit, rep);

    // 8. Authenticode Digital Signature Verification
    rep.signature = SignatureVerifier::verify_from_pe(data, size, security_dir);

    return rep;
}

void PeAnalyzer::parse_imports(const uint8_t* data, 
                              size_t size, 
                              const ImageDataDirectory& import_dir,
                              const std::vector<ImageSectionHeader>& sections,
                              bool is_64bit,
                              PeReport& report) {
    if (import_dir.VirtualAddress == 0 || import_dir.Size == 0) {
        return;
    }

    uint32_t import_offset = rva_to_offset(import_dir.VirtualAddress, sections);
    if (import_offset == 0 || import_offset >= size) {
        return;
    }

    const auto* desc = reinterpret_cast<const ImageImportDescriptor*>(data + import_offset);

    while (desc->Name != 0 && (reinterpret_cast<const uint8_t*>(desc) + sizeof(ImageImportDescriptor) <= data + size)) {
        uint32_t name_offset = rva_to_offset(desc->Name, sections);
        if (name_offset != 0 && name_offset < size) {
            std::string dll_name = reinterpret_cast<const char*>(data + name_offset);
            ImportedModule mod;
            mod.dll_name = dll_name;

            // Traversal of OriginalFirstThunk (ILT) or FirstThunk (IAT)
            uint32_t thunk_rva = desc->DUMMYUNIONNAME.OriginalFirstThunk ? desc->DUMMYUNIONNAME.OriginalFirstThunk : desc->FirstThunk;
            uint32_t thunk_offset = rva_to_offset(thunk_rva, sections);

            if (thunk_offset != 0 && thunk_offset < size) {
                if (is_64bit) {
                    const auto* thunk64 = reinterpret_cast<const uint64_t*>(data + thunk_offset);
                    while (*thunk64 != 0 && reinterpret_cast<const uint8_t*>(thunk64) + 8 <= data + size) {
                        uint64_t val = *thunk64;
                        if ((val & (1ULL << 63)) == 0) { // Import by name, not ordinal
                            uint32_t hint_name_offset = rva_to_offset(static_cast<uint32_t>(val), sections);
                            if (hint_name_offset != 0 && hint_name_offset + 2 < size) {
                                const char* func_name = reinterpret_cast<const char*>(data + hint_name_offset + 2);
                                mod.functions.emplace_back(func_name);
                                evaluate_dangerous_api(dll_name, func_name, report);
                            }
                        }
                        thunk64++;
                    }
                } else {
                    const auto* thunk32 = reinterpret_cast<const uint32_t*>(data + thunk_offset);
                    while (*thunk32 != 0 && reinterpret_cast<const uint8_t*>(thunk32) + 4 <= data + size) {
                        uint32_t val = *thunk32;
                        if ((val & 0x80000000) == 0) {
                            uint32_t hint_name_offset = rva_to_offset(val, sections);
                            if (hint_name_offset != 0 && hint_name_offset + 2 < size) {
                                const char* func_name = reinterpret_cast<const char*>(data + hint_name_offset + 2);
                                mod.functions.emplace_back(func_name);
                                evaluate_dangerous_api(dll_name, func_name, report);
                            }
                        }
                        thunk32++;
                    }
                }
            }

            report.imports.push_back(std::move(mod));
        }
        desc++;
    }
}

void PeAnalyzer::evaluate_dangerous_api(const std::string& dll, 
                                       const std::string& func, 
                                       PeReport& report) {
    auto f = to_lower_str(func);

    // 1. Process Injection & Memory Tampering
    if (f == "virtualallocex" || f == "writeprocessmemory" || f == "createremotethread" ||
        f == "queueuserapc" || f == "ntqueueapcthread" || f == "setthreadcontext" || f == "ntmapviewofsection") {
        DangerousApiFinding d;
        d.api_name = func;
        d.dll_name = dll;
        d.category = "ProcessInjection";
        d.severity = Severity::Critical;
        d.risk_weight = 40;
        d.description = "API capable of modifying foreign process memory or executing remote code threads";
        report.dangerous_apis.push_back(std::move(d));
    }
    // 2. Keylogging & Input Snooping
    else if (f == "setwindowshookexa" || f == "setwindowshookexw" || f == "getasynckeystate" ||
             f == "getkeyboardstate" || f == "registerrawinputdevices") {
        DangerousApiFinding d;
        d.api_name = func;
        d.dll_name = dll;
        d.category = "Keylogging";
        d.severity = Severity::Critical;
        d.risk_weight = 40;
        d.description = "API commonly used by infostealers and keyloggers to record credentials";
        report.dangerous_apis.push_back(std::move(d));
    }
    // 3. Screen Scraping & Spyware
    else if (f == "bitblt" || f == "printwindow" || f == "getdc" || f == "createcompatibledc") {
        DangerousApiFinding d;
        d.api_name = func;
        d.dll_name = dll;
        d.category = "ScreenCapture";
        d.severity = Severity::High;
        d.risk_weight = 25;
        d.description = "API capable of capturing desktop displays and sensitive financial OTPs";
        report.dangerous_apis.push_back(std::move(d));
    }
    // 4. Memory Dumping & Credential Extraction
    else if (f == "minidumpwritedump" || f == "lsaenumeratelogonsessions") {
        DangerousApiFinding d;
        d.api_name = func;
        d.dll_name = dll;
        d.category = "CredentialTheft";
        d.severity = Severity::Critical;
        d.risk_weight = 45;
        d.description = "API used to dump LSASS or process memory to extract plain text credentials";
        report.dangerous_apis.push_back(std::move(d));
    }
    // 5. Anti-Analysis & Debugger Evasion
    else if (f == "isdebuggerpresent" || f == "checkremotedebuggerpresent" || f == "ntqueryinformationprocess") {
        DangerousApiFinding d;
        d.api_name = func;
        d.dll_name = dll;
        d.category = "AntiAnalysis";
        d.severity = Severity::Medium;
        d.risk_weight = 15;
        d.description = "API used to evade detection in analysis environments or sandbox virtual machines";
        report.dangerous_apis.push_back(std::move(d));
    }
}

} // namespace finguard::pe
