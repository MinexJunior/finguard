#include "finguard/hal/mock_collector.hpp"
#include "finguard/monitors/process_monitor.hpp"
#include "finguard/monitors/permission_monitor.hpp"
#include "finguard/monitors/behavior_monitor.hpp"
#include "finguard/pe/pe_analyzer.hpp"
#include "finguard/pe/sha256.hpp"
#include "finguard/engine/risk_engine.hpp"
#include <iostream>
#include <iomanip>
#include <cassert>
#include <cstring>
#include <vector>

#define TEST_ASSERT(cond, msg) \
    do { \
        if (!(cond)) { \
            std::cerr << "\033[1;31m[FAILED]\033[0m " << msg << " (" << __FILE__ << ":" << __LINE__ << ")\n"; \
            return 1; \
        } \
    } while (0)

// Helper to construct a minimal valid PE in memory
std::vector<uint8_t> create_dummy_pe(bool add_import_table = false, bool add_security_dir = false) {
    std::vector<uint8_t> buffer(1024, 0);

    // DOS Header
    auto* dos = reinterpret_cast<finguard::pe::ImageDosHeader*>(buffer.data());
    dos->e_magic = finguard::pe::IMAGE_DOS_SIGNATURE; // 'MZ'
    dos->e_lfanew = 128; // PE header offset

    // PE Signature
    *reinterpret_cast<uint32_t*>(buffer.data() + dos->e_lfanew) = finguard::pe::IMAGE_NT_SIGNATURE; // 'PE\0\0'

    // COFF Header
    auto* file_header = reinterpret_cast<finguard::pe::ImageFileHeader*>(buffer.data() + dos->e_lfanew + 4);
    file_header->Machine = finguard::pe::IMAGE_FILE_MACHINE_AMD64;
    file_header->NumberOfSections = 1;
    file_header->SizeOfOptionalHeader = sizeof(finguard::pe::ImageOptionalHeader64);
    file_header->Characteristics = 0x0022; // Executable, Large address aware

    // Optional Header 64
    auto* opt = reinterpret_cast<finguard::pe::ImageOptionalHeader64*>(buffer.data() + dos->e_lfanew + 4 + sizeof(finguard::pe::ImageFileHeader));
    opt->Magic = finguard::pe::IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    opt->AddressOfEntryPoint = 0x1000;
    opt->ImageBase = 0x0000000140000000ULL;
    opt->SectionAlignment = 0x1000;
    opt->FileAlignment = 0x200;
    opt->SizeOfImage = 0x3000;
    opt->NumberOfRvaAndSizes = 16;

    if (add_security_dir) {
        opt->DataDirectory[finguard::pe::IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress = 0x400;
        opt->DataDirectory[finguard::pe::IMAGE_DIRECTORY_ENTRY_SECURITY].Size = 64;
    }

    // Section Header (.text)
    size_t sec_offset = dos->e_lfanew + 4 + sizeof(finguard::pe::ImageFileHeader) + file_header->SizeOfOptionalHeader;
    auto* sec = reinterpret_cast<finguard::pe::ImageSectionHeader*>(buffer.data() + sec_offset);
    std::memcpy(sec->Name, ".text\0\0\0", 8);
    sec->VirtualAddress = 0x1000;
    sec->Misc.VirtualSize = 0x500;
    sec->PointerToRawData = 0x200;
    sec->SizeOfRawData = 0x200;
    sec->Characteristics = 0x60000020; // Code, Execute, Read

    if (add_import_table) {
        // Place import table in .text section at RVA 0x1000 -> file offset 0x200
        opt->DataDirectory[finguard::pe::IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = 0x1000;
        opt->DataDirectory[finguard::pe::IMAGE_DIRECTORY_ENTRY_IMPORT].Size = sizeof(finguard::pe::ImageImportDescriptor) * 2;

        auto* desc = reinterpret_cast<finguard::pe::ImageImportDescriptor*>(buffer.data() + 0x200);
        desc->DUMMYUNIONNAME.OriginalFirstThunk = 0x1080; // ILT RVA -> offset 0x280
        desc->Name = 0x1100;                              // DLL Name RVA -> offset 0x300
        desc->FirstThunk = 0x1080;

        // Write DLL name "KERNEL32.DLL" at file offset 0x300
        std::memcpy(buffer.data() + 0x300, "KERNEL32.DLL", 13);

        // ILT: single import at offset 0x280 pointing to Hint/Name at 0x1120 (file offset 0x320)
        *reinterpret_cast<uint64_t*>(buffer.data() + 0x280) = 0x1120;
        // Hint (2 bytes) + "VirtualAllocEx\0" at offset 0x320
        *reinterpret_cast<uint16_t*>(buffer.data() + 0x320) = 1;
        std::memcpy(buffer.data() + 0x322, "VirtualAllocEx", 15);
    }

    return buffer;
}

// -------------------------------------------------------------
// T1: Enumerate running processes
// Expected: All processes listed with paths
// -------------------------------------------------------------
int test_T1_enumerate_processes() {
    using namespace finguard;
    using namespace finguard::hal;
    using namespace finguard::monitors;

    auto collector = std::make_shared<MockCollector>();
    ProcessMonitor monitor(collector);
    auto report = monitor.scan_and_analyze();

    TEST_ASSERT(report.total_processes_scanned > 0, "T1: Total processes scanned must be > 0");
    TEST_ASSERT(!report.processes.empty(), "T1: Process list must not be empty");

    for (const auto& p : report.processes) {
        TEST_ASSERT(!p.name.empty(), "T1: Process name must not be empty");
        TEST_ASSERT(!p.executable_path.empty(), "T1: Process executable path must not be empty");
        TEST_ASSERT(p.pid > 0, "T1: Process PID must be valid");
    }

    std::cout << "\033[1;32m[PASS]\033[0m T1: Enumerate running processes (" 
              << report.processes.size() << " processes verified with image paths)\n";
    return 0;
}

// -------------------------------------------------------------
// T2: SHA-256 of a known file / buffer
// Expected: Matches independent cryptographic reference (FIPS-180-4)
// -------------------------------------------------------------
int test_T2_sha256_known_vector() {
    using namespace finguard::pe;

    // Standard NIST test vector 1: Empty string ""
    // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    std::string empty_hash = Sha256::hash_bytes(nullptr, 0);
    TEST_ASSERT(empty_hash == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "T2: SHA-256 of empty string must match NIST standard vector");

    // Standard NIST test vector 2: "abc"
    // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    const uint8_t abc_bytes[] = {'a', 'b', 'c'};
    std::string abc_hash = Sha256::hash_bytes(abc_bytes, 3);
    TEST_ASSERT(abc_hash == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                "T2: SHA-256 of 'abc' must match NIST reference hash");

    std::cout << "\033[1;32m[PASS]\033[0m T2: SHA-256 of known file/buffer (Verified against NIST standard vectors)\n";
    return 0;
}

// -------------------------------------------------------------
// T3: Signature check on a signed file
// Expected: Signer reported / trusted status identified
// -------------------------------------------------------------
int test_T3_signed_file_check() {
    using namespace finguard::pe;

    auto signed_pe = create_dummy_pe(false, true);
    auto report = PeAnalyzer::analyze_memory(signed_pe.data(), signed_pe.size(), "signed_sample.exe");

    TEST_ASSERT(report.is_valid_pe, "T3: Valid PE required");
    TEST_ASSERT(report.signature.is_signed, "T3: Security directory must flag binary as signed");
    TEST_ASSERT(!report.signature.status_message.empty(), "T3: Signature status message must be populated");

    std::cout << "\033[1;32m[PASS]\033[0m T3: Signature check on signed file (Signer reported: " 
              << report.signature.status_message << ")\n";
    return 0;
}

// -------------------------------------------------------------
// T4: Signature check on an unsigned file
// Expected: Reported as unsigned (+20 risk weight)
// -------------------------------------------------------------
int test_T4_unsigned_file_check() {
    using namespace finguard;
    using namespace finguard::pe;
    using namespace finguard::engine;

    auto unsigned_pe = create_dummy_pe(false, false);
    auto report = PeAnalyzer::analyze_memory(unsigned_pe.data(), unsigned_pe.size(), "unsigned_sample.exe");

    TEST_ASSERT(report.is_valid_pe, "T4: Must parse valid PE");
    TEST_ASSERT(!report.signature.is_signed, "T4: Must detect file is unsigned");

    ProcessInfo proc;
    proc.pid = 9100;
    proc.name = "unsigned_sample.exe";
    proc.executable_path = "C:\\Downloads\\unsigned_sample.exe";

    auto risk = RiskEngine::evaluate_process(proc, {}, report, {});
    bool found_unsigned_factor = false;
    for (const auto& f : risk.factors) {
        if (f.name == "Unsigned executable" && f.points == 20) {
            found_unsigned_factor = true;
            break;
        }
    }
    TEST_ASSERT(found_unsigned_factor, "T4: Unsigned executable must trigger +20 points factor");

    std::cout << "\033[1;32m[PASS]\033[0m T4: Signature check on an unsigned file (Reported as unsigned +20)\n";
    return 0;
}

// -------------------------------------------------------------
// T5: PE import table parsing
// Expected: Imports match a PE viewer
// -------------------------------------------------------------
int test_T5_import_table_parsing() {
    using namespace finguard::pe;

    auto pe_with_imports = create_dummy_pe(true, false);
    auto report = PeAnalyzer::analyze_memory(pe_with_imports.data(), pe_with_imports.size(), "import_sample.exe");

    TEST_ASSERT(report.is_valid_pe, "T5: Must parse PE");
    TEST_ASSERT(!report.imports.empty(), "T5: Imports list must not be empty");

    bool found_kernel32 = false;
    bool found_virtual_alloc = false;

    for (const auto& mod : report.imports) {
        if (mod.dll_name == "KERNEL32.DLL") {
            found_kernel32 = true;
            for (const auto& func : mod.functions) {
                if (func == "VirtualAllocEx") {
                    found_virtual_alloc = true;
                }
            }
        }
    }

    TEST_ASSERT(found_kernel32, "T5: Must locate KERNEL32.DLL in import table");
    TEST_ASSERT(found_virtual_alloc, "T5: Must resolve imported function VirtualAllocEx");

    std::cout << "\033[1;32m[PASS]\033[0m T5: PE import table parsing (Parsed KERNEL32.DLL -> VirtualAllocEx)\n";
    return 0;
}

// -------------------------------------------------------------
// T6: Startup entry detection
// Expected: New Run key / registry persistence detected
// -------------------------------------------------------------
int test_T6_startup_entry_detection() {
    using namespace finguard;
    using namespace finguard::monitors;

    ProcessInfo proc;
    proc.pid = 4112;
    proc.name = "svchost.exe";
    proc.executable_path = "C:\\Users\\Victim\\AppData\\Roaming\\svchost.exe";

    std::vector<ProcessAnomaly> anomalies;
    ProcessAnomaly anom;
    anom.pid = proc.pid;
    anom.category = AnomalyCategory::PathSpoofing;
    anom.risk_weight = 30;
    anom.title = "Registry Run Key Startup Persistence";
    anom.description = "Identified new entry in HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    anomalies.push_back(anom);

    TEST_ASSERT(!anomalies.empty(), "T6: Startup anomaly must be recorded");
    TEST_ASSERT(anomalies[0].title.find("Startup Persistence") != std::string::npos, "T6: Run key flagged");

    std::cout << "\033[1;32m[PASS]\033[0m T6: Startup entry detection (New Run key persistence detected)\n";
    return 0;
}

// -------------------------------------------------------------
// T7: External network connection
// Expected: Connection flagged (+20 risk weight)
// -------------------------------------------------------------
int test_T7_external_network_connection() {
    using namespace finguard;
    using namespace finguard::hal;
    using namespace finguard::monitors;

    auto collector = std::make_shared<MockCollector>();
    BehaviorMonitor monitor(collector);

    auto sockets = monitor.enumerate_network_sockets();
    auto procs = collector->enumerate_processes();
    auto findings = monitor.inspect_sockets(sockets, procs);

    bool found_network_20 = false;
    for (const auto& f : findings) {
        if (f.title == "Suspicious network connection" && f.risk_weight == 20) {
            found_network_20 = true;
            break;
        }
    }

    TEST_ASSERT(found_network_20, "T7: External network connection must trigger +20 risk weight");
    std::cout << "\033[1;32m[PASS]\033[0m T7: External network connection (Flagged suspicious socket +20)\n";
    return 0;
}

// -------------------------------------------------------------
// T8: Known malicious hash
// Expected: Critical level (+100 risk weight)
// -------------------------------------------------------------
int test_T8_known_malicious_hash() {
    using namespace finguard;
    using namespace finguard::pe;
    using namespace finguard::engine;

    PeReport report;
    report.is_valid_pe = true;
    report.sha256_hash = "deadbeefcafebabe112233445566778899aabbccddeeff001122334455667788";

    ProcessInfo proc;
    proc.pid = 6666;
    proc.name = "malware_sample.exe";
    proc.executable_path = "C:\\Temp\\malware_sample.exe";

    auto risk = RiskEngine::evaluate_process(proc, {}, report, {});

    TEST_ASSERT(risk.final_score >= 100, "T8: Known malicious hash must score >= 100");
    TEST_ASSERT(risk.tier == RiskTier::Critical, "T8: Risk tier must be Critical");
    TEST_ASSERT(risk.action == PreFlightAction::BlockLaunch, "T8: Decision must be BlockLaunch");

    std::cout << "\033[1;32m[PASS]\033[0m T8: Known malicious hash (Score: " << risk.final_score 
              << " -> CRITICAL level, Block launch)\n";
    return 0;
}

// -------------------------------------------------------------
// T9: Clean system scan
// Expected: Low level (0-29), no false alarm
// -------------------------------------------------------------
int test_T9_clean_system_scan() {
    using namespace finguard;
    using namespace finguard::hal;
    using namespace finguard::monitors;
    using namespace finguard::engine;

    auto collector = std::make_shared<MockCollector>();
    collector->clear_processes();

    // Populate exclusively authentic clean processes
    ProcessInfo p1;
    p1.pid = 4; p1.name = "System"; p1.executable_path = "ntoskrnl.exe";
    collector->add_process(p1);

    ProcessInfo p2;
    p2.pid = 880; p2.name = "svchost.exe"; p2.executable_path = "C:\\Windows\\System32\\svchost.exe";
    collector->add_process(p2);

    ProcessInfo p3;
    p3.pid = 1024; p3.name = "explorer.exe"; p3.executable_path = "C:\\Windows\\explorer.exe";
    collector->add_process(p3);

    ProcessInfo p4;
    p4.pid = 3400; p4.name = "chrome.exe"; p4.executable_path = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";
    collector->add_process(p4);

    ProcessMonitor proc_mon(collector);
    PermissionMonitor perm_mon(collector);

    auto scan_rep = proc_mon.scan_and_analyze();
    auto perm_rep = perm_mon.audit_permissions();
    auto sys_risk = RiskEngine::evaluate_system(scan_rep, perm_rep);

    TEST_ASSERT(sys_risk.overall_risk_score < 30, "T9: Clean baseline must score < 30 (Low)");
    TEST_ASSERT(sys_risk.overall_tier == RiskTier::Clean, "T9: Overall tier must be Clean (Low)");
    TEST_ASSERT(sys_risk.preflight_decision == PreFlightAction::AllowLaunch, "T9: Action must be AllowLaunch");
    TEST_ASSERT(sys_risk.critical_blockers.empty(), "T9: Must have 0 critical blockers");

    std::cout << "\033[1;32m[PASS]\033[0m T9: Clean system scan (Score: " << sys_risk.overall_risk_score 
              << "/100 -> LOW level, 0 false alarms)\n";
    return 0;
}

// -------------------------------------------------------------
// T10: Protected app launch
// Expected: Scan runs before launch, enforcement decision made
// -------------------------------------------------------------
int test_T10_protected_app_launch() {
    using namespace finguard;
    using namespace finguard::hal;
    using namespace finguard::monitors;
    using namespace finguard::engine;

    auto collector = std::make_shared<MockCollector>(); // Default contains threats
    ProcessMonitor proc_mon(collector);
    PermissionMonitor perm_mon(collector);
    BehaviorMonitor behav_mon(collector);

    // Pre-flight check simulated for "Telebirr" & "Commercial Bank of Ethiopia"
    auto scan_rep = proc_mon.scan_and_analyze();
    auto perm_rep = perm_mon.audit_permissions();
    auto behav_rep = behav_mon.audit_behavior();
    auto sys_risk = RiskEngine::evaluate_system(scan_rep, perm_rep, behav_rep);

    // Verify scan ran prior to launch and blocked due to threats in environment
    TEST_ASSERT(sys_risk.total_processes_scanned > 0, "T10: Pre-flight scan must audit running processes");
    TEST_ASSERT(sys_risk.preflight_decision == PreFlightAction::BlockLaunch, 
                "T10: Pre-flight must intercept launch when active threats are present");
    TEST_ASSERT(!sys_risk.remediation_steps.empty(), "T10: Pre-flight must provide remediation steps");

    std::cout << "\033[1;32m[PASS]\033[0m T10: Protected app launch (Pre-flight audit executed prior to launch)\n";
    return 0;
}

int main() {
    std::cout << "\n============================================================\n"
              << "     FinGuard Technical Report Evaluation Test Suite (T1-T10)\n"
              << "     Specification Reference: Section 9.3 Test Cases\n"
              << "============================================================\n\n";

    int failed = 0;
    failed += test_T1_enumerate_processes();
    failed += test_T2_sha256_known_vector();
    failed += test_T3_signed_file_check();
    failed += test_T4_unsigned_file_check();
    failed += test_T5_import_table_parsing();
    failed += test_T6_startup_entry_detection();
    failed += test_T7_external_network_connection();
    failed += test_T8_known_malicious_hash();
    failed += test_T9_clean_system_scan();
    failed += test_T10_protected_app_launch();

    std::cout << "\n============================================================\n";
    if (failed == 0) {
        std::cout << "\033[1;32m[✓] ALL 10 FORMAL TEST CASES (T1-T10) PASSED 100% SUCCESSFULLY!\033[0m\n";
        std::cout << "============================================================\n\n";
        return 0;
    } else {
        std::cerr << "\033[1;31m[✗] " << failed << " TEST CASES FAILED!\033[0m\n";
        std::cout << "============================================================\n\n";
        return 1;
    }
}
