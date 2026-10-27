#include "finguard/pe/entropy.hpp"
#include "finguard/pe/pe_analyzer.hpp"
#include "finguard/pe/signature_verifier.hpp"
#include <iostream>
#include <cassert>
#include <vector>
#include <cstring>
#include <cmath>

#define TEST_ASSERT(cond, msg) \
    do { \
        if (!(cond)) { \
            std::cerr << "\033[1;31m[FAILED]\033[0m " << msg << " (" << __FILE__ << ":" << __LINE__ << ")\n"; \
            return 1; \
        } \
    } while (0)

int test_entropy_calculation() {
    using namespace finguard::pe;

    // 1. Single byte distribution (Zero entropy)
    std::vector<uint8_t> zeroes(1024, 0x00);
    double h_zero = EntropyCalculator::calculate(zeroes);
    TEST_ASSERT(std::abs(h_zero - 0.0) < 0.0001, "All-zero buffer must have 0.0 entropy");

    // 2. Uniform 256-byte distribution (Maximum possible entropy: 8.0 bits/byte)
    std::vector<uint8_t> max_dist(256 * 10);
    for (size_t i = 0; i < max_dist.size(); ++i) {
        max_dist[i] = static_cast<uint8_t>(i % 256);
    }
    double h_max = EntropyCalculator::calculate(max_dist);
    TEST_ASSERT(std::abs(h_max - 8.0) < 0.0001, "Uniform 256-byte distribution must have exactly 8.0 entropy");

    // 3. Packed threshold test
    TEST_ASSERT(EntropyCalculator::is_suspiciously_packed(7.5), "7.5 entropy must be flagged as packed");
    TEST_ASSERT(!EntropyCalculator::is_suspiciously_packed(5.8), "5.8 normal code entropy must not be flagged");

    std::cout << "\033[1;32m[PASSED]\033[0m test_entropy_calculation\n";
    return 0;
}

// Helper to assemble a valid in-memory PE64 binary with synthetic sections and imports
std::vector<uint8_t> build_synthetic_pe64(bool add_rwx_section, bool add_packed_section, bool add_signature) {
    using namespace finguard::pe;

    size_t pe_size = 0x2000;
    std::vector<uint8_t> buf(pe_size, 0);

    // 1. DOS Header
    auto* dos = reinterpret_cast<ImageDosHeader*>(buf.data());
    dos->e_magic = IMAGE_DOS_SIGNATURE; // "MZ"
    dos->e_lfanew = 0x80; // Offset to PE header

    // 2. PE Signature
    *reinterpret_cast<uint32_t*>(buf.data() + dos->e_lfanew) = IMAGE_NT_SIGNATURE; // "PE\0\0"

    // 3. COFF File Header
    auto* file_hdr = reinterpret_cast<ImageFileHeader*>(buf.data() + dos->e_lfanew + 4);
    file_hdr->Machine = IMAGE_FILE_MACHINE_AMD64;
    file_hdr->NumberOfSections = 2;
    file_hdr->SizeOfOptionalHeader = sizeof(ImageOptionalHeader64);
    file_hdr->Characteristics = 0x0022; // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE

    // 4. Optional Header 64
    size_t opt_offset = dos->e_lfanew + 4 + sizeof(ImageFileHeader);
    auto* opt = reinterpret_cast<ImageOptionalHeader64*>(buf.data() + opt_offset);
    opt->Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    opt->AddressOfEntryPoint = 0x1000;
    opt->ImageBase = 0x140000000;
    opt->SectionAlignment = 0x1000;
    opt->FileAlignment = 0x200;
    opt->SizeOfImage = 0x4000;
    opt->Subsystem = IMAGE_SUBSYSTEM_WINDOWS_GUI;

    // 5. Sections
    size_t sec_table_offset = opt_offset + sizeof(ImageOptionalHeader64);
    auto* sec1 = reinterpret_cast<ImageSectionHeader*>(buf.data() + sec_table_offset);
    std::memcpy(sec1->Name, ".text\0\0\0", 8);
    sec1->VirtualAddress = 0x1000;
    sec1->Misc.VirtualSize = 0x800;
    sec1->PointerToRawData = 0x400;
    sec1->SizeOfRawData = 0x400;
    sec1->Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;

    // Fill .text with normal instruction bytes (moderate entropy)
    for (size_t i = 0x400; i < 0x800; ++i) {
        buf[i] = static_cast<uint8_t>((i * 7 + 3) % 120);
    }

    auto* sec2 = reinterpret_cast<ImageSectionHeader*>(buf.data() + sec_table_offset + sizeof(ImageSectionHeader));
    if (add_rwx_section) {
        std::memcpy(sec2->Name, ".injected", 8);
        sec2->VirtualAddress = 0x2000;
        sec2->Misc.VirtualSize = 0x600;
        sec2->PointerToRawData = 0x800;
        sec2->SizeOfRawData = 0x400;
        sec2->Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_READ; // RWX!
    } else {
        std::memcpy(sec2->Name, ".rdata\0\0", 8);
        sec2->VirtualAddress = 0x2000;
        sec2->Misc.VirtualSize = 0x600;
        sec2->PointerToRawData = 0x800;
        sec2->SizeOfRawData = 0x400;
        sec2->Characteristics = IMAGE_SCN_MEM_READ;
    }

    if (add_packed_section) {
        // Fill sec2 with high-entropy bytes (random distribution)
        for (size_t i = 0x800; i < 0xC00; ++i) {
            buf[i] = static_cast<uint8_t>((i * 1103515245 + 12345) % 256);
        }
    }

    // 6. Optional Authenticode Signature Table
    if (add_signature) {
        uint32_t cert_offset = 0x1000;
        uint32_t cert_size = sizeof(WinCertificate) + 128;
        opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress = cert_offset;
        opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size = cert_size;

        auto* cert = reinterpret_cast<WinCertificate*>(buf.data() + cert_offset);
        cert->dwLength = cert_size;
        cert->wRevision = 0x0200; // WIN_CERT_REVISION_2_0
        cert->wCertificateType = WIN_CERT_TYPE_PKCS_SIGNED_DATA;
    }

    return buf;
}

int test_pe_parsing_headers() {
    auto pe_buf = build_synthetic_pe64(false, false, false);
    auto report = finguard::pe::PeAnalyzer::analyze_memory(pe_buf.data(), pe_buf.size(), "test_pe64.exe");

    TEST_ASSERT(report.is_valid_pe, "Synthesized PE must be parsed as valid PE");
    TEST_ASSERT(report.architecture == "x64", "Machine must be detected as x64");
    TEST_ASSERT(report.entry_point_rva == 0x1000, "Entry point RVA must be 0x1000");
    TEST_ASSERT(report.image_base == 0x140000000, "Image base must match");
    TEST_ASSERT(report.sections.size() == 2, "Must identify exactly 2 sections");
    TEST_ASSERT(report.sections[0].name == ".text", "First section must be .text");
    TEST_ASSERT(report.sections[0].is_executable, ".text must be executable");
    TEST_ASSERT(!report.sections[0].is_rwx, ".text must not be RWX");

    std::cout << "\033[1;32m[PASSED]\033[0m test_pe_parsing_headers\n";
    return 0;
}

int test_rwx_section_detection() {
    auto pe_buf = build_synthetic_pe64(true, false, false); // add RWX section
    auto report = finguard::pe::PeAnalyzer::analyze_memory(pe_buf.data(), pe_buf.size(), "test_rwx.exe");

    bool found_rwx = false;
    for (const auto& sec : report.sections) {
        if (sec.is_rwx) found_rwx = true;
    }
    TEST_ASSERT(found_rwx, "Must detect RWX section flag");

    bool found_rwx_anomaly = false;
    for (const auto& a : report.anomalies) {
        if (a.find("RWX") != std::string::npos) {
            found_rwx_anomaly = true;
        }
    }
    TEST_ASSERT(found_rwx_anomaly, "Anomaly list must contain RWX shellcode warning");

    std::cout << "\033[1;32m[PASSED]\033[0m test_rwx_section_detection\n";
    return 0;
}

int test_packed_entropy_detection() {
    auto pe_buf = build_synthetic_pe64(false, true, false); // add high-entropy packed section
    auto report = finguard::pe::PeAnalyzer::analyze_memory(pe_buf.data(), pe_buf.size(), "test_packed.exe");

    TEST_ASSERT(report.sections[1].entropy > 7.15, "Section 2 must have entropy > 7.15");
    TEST_ASSERT(report.sections[1].is_packed, "Section 2 must be flagged as packed");

    std::cout << "\033[1;32m[PASSED]\033[0m test_packed_entropy_detection (entropy: " 
              << report.sections[1].entropy << " bits/byte)\n";
    return 0;
}

int test_authenticode_signature_verification() {
    // 1. Unsigned binary
    auto unsigned_pe = build_synthetic_pe64(false, false, false);
    auto report_unsigned = finguard::pe::PeAnalyzer::analyze_memory(unsigned_pe.data(), unsigned_pe.size(), "unsigned.exe");
    TEST_ASSERT(!report_unsigned.signature.is_signed, "Unsigned PE must report is_signed == false");

    // 2. Signed binary
    auto signed_pe = build_synthetic_pe64(false, false, true);
    auto report_signed = finguard::pe::PeAnalyzer::analyze_memory(signed_pe.data(), signed_pe.size(), "signed.exe");
    TEST_ASSERT(report_signed.signature.is_signed, "Signed PE must report is_signed == true");
    TEST_ASSERT(report_signed.signature.is_valid_format, "Authenticode format must be valid");
    TEST_ASSERT(report_signed.signature.certificate_size > 0, "Certificate size must be > 0");

    // 3. Trusted vendor check
    TEST_ASSERT(finguard::pe::SignatureVerifier::is_known_trusted_vendor("Commercial Bank of Ethiopia"),
                "CBE must be recognized as trusted financial vendor");
    TEST_ASSERT(finguard::pe::SignatureVerifier::is_known_trusted_vendor("Ethio Telecom"),
                "Ethio Telecom must be recognized as trusted vendor");
    TEST_ASSERT(!finguard::pe::SignatureVerifier::is_known_trusted_vendor("Unknown Hacker LLC"),
                "Unknown vendor must not be trusted");

    std::cout << "\033[1;32m[PASSED]\033[0m test_authenticode_signature_verification\n";
    return 0;
}

// Test IAT parsing and dangerous API detection
int test_iat_dangerous_api_detection() {
    using namespace finguard::pe;

    // Build PE with mock imports
    auto pe_buf = build_synthetic_pe64(false, false, false);

    // Place an Import Directory in Section 1 (RVA 0x1100 -> Offset 0x500)
    size_t opt_offset = 0x80 + 4 + sizeof(ImageFileHeader);
    auto* opt = reinterpret_cast<ImageOptionalHeader64*>(pe_buf.data() + opt_offset);
    opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = 0x1100;
    opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = sizeof(ImageImportDescriptor) * 3;

    // Descriptors in file offset 0x500
    size_t desc_offset = 0x500;
    auto* desc1 = reinterpret_cast<ImageImportDescriptor*>(pe_buf.data() + desc_offset);
    desc1->Name = 0x1200; // DLL name at RVA 0x1200 -> Offset 0x600
    desc1->DUMMYUNIONNAME.OriginalFirstThunk = 0x1250; // ILT at RVA 0x1250 -> Offset 0x650

    auto* desc2 = reinterpret_cast<ImageImportDescriptor*>(pe_buf.data() + desc_offset + sizeof(ImageImportDescriptor));
    desc2->Name = 0x1300; // DLL name at RVA 0x1300 -> Offset 0x700
    desc2->DUMMYUNIONNAME.OriginalFirstThunk = 0x1350; // ILT at RVA 0x1350 -> Offset 0x750

    // DLL 1: USER32.dll
    const char* dll1 = "USER32.dll";
    std::memcpy(pe_buf.data() + 0x600, dll1, std::strlen(dll1) + 1);

    // ILT 1 -> points to RVA 0x1260 (Offset 0x660) containing hint + "SetWindowsHookExW"
    *reinterpret_cast<uint64_t*>(pe_buf.data() + 0x650) = 0x1260;
    const char* fn1 = "SetWindowsHookExW";
    std::memcpy(pe_buf.data() + 0x660 + 2, fn1, std::strlen(fn1) + 1);

    // DLL 2: KERNEL32.dll
    const char* dll2 = "KERNEL32.dll";
    std::memcpy(pe_buf.data() + 0x700, dll2, std::strlen(dll2) + 1);

    // ILT 2 -> points to RVA 0x1360 (Offset 0x760) containing hint + "VirtualAllocEx"
    *reinterpret_cast<uint64_t*>(pe_buf.data() + 0x750) = 0x1360;
    const char* fn2 = "VirtualAllocEx";
    std::memcpy(pe_buf.data() + 0x760 + 2, fn2, std::strlen(fn2) + 1);

    auto report = PeAnalyzer::analyze_memory(pe_buf.data(), pe_buf.size(), "imports_test.exe");

    TEST_ASSERT(report.imports.size() >= 2, "Must extract at least 2 imported DLLs");

    bool found_keylogger_api = false;
    bool found_injection_api = false;

    for (const auto& d : report.dangerous_apis) {
        if (d.category == "Keylogging" && d.api_name == "SetWindowsHookExW") {
            found_keylogger_api = true;
        }
        if (d.category == "ProcessInjection" && d.api_name == "VirtualAllocEx") {
            found_injection_api = true;
        }
    }

    TEST_ASSERT(found_keylogger_api, "Must identify SetWindowsHookExW as Keylogging API");
    TEST_ASSERT(found_injection_api, "Must identify VirtualAllocEx as ProcessInjection API");

    std::cout << "\033[1;32m[PASSED]\033[0m test_iat_dangerous_api_detection\n";
    return 0;
}

int main() {
    std::cout << "\n=== Running FinGuard PE File & Signature Analyzer Test Suite ===\n";
    int failed = 0;
    failed += test_entropy_calculation();
    failed += test_pe_parsing_headers();
    failed += test_rwx_section_detection();
    failed += test_packed_entropy_detection();
    failed += test_authenticode_signature_verification();
    failed += test_iat_dangerous_api_detection();

    if (failed == 0) {
        std::cout << "\033[1;32m=== ALL 6 PE ANALYZER TESTS PASSED SUCCESSFULLY! ===\033[0m\n\n";
        return 0;
    } else {
        std::cerr << "\033[1;31m=== " << failed << " TESTS FAILED! ===\033[0m\n\n";
        return 1;
    }
}
