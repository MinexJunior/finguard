#pragma once

#include <cstdint>
#include <array>
#include <string>

namespace finguard::pe {

#pragma pack(push, 1)

// DOS MZ Header (64 bytes)
struct ImageDosHeader {
    uint16_t e_magic;    // Magic number: 0x5A4D ("MZ")
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    int32_t  e_lfanew;   // File address of new exe header (offset to PE header)
};

// COFF File Header (20 bytes)
struct ImageFileHeader {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
};

// Data Directory entry (8 bytes)
struct ImageDataDirectory {
    uint32_t VirtualAddress;
    uint32_t Size;
};

constexpr size_t IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16;
constexpr size_t IMAGE_DIRECTORY_ENTRY_EXPORT    = 0;
constexpr size_t IMAGE_DIRECTORY_ENTRY_IMPORT    = 1;
constexpr size_t IMAGE_DIRECTORY_ENTRY_RESOURCE  = 2;
constexpr size_t IMAGE_DIRECTORY_ENTRY_EXCEPTION = 3;
constexpr size_t IMAGE_DIRECTORY_ENTRY_SECURITY  = 4; // Authenticode Certificate Table
constexpr size_t IMAGE_DIRECTORY_ENTRY_BASERELOC = 5;
constexpr size_t IMAGE_DIRECTORY_ENTRY_DEBUG     = 6;
constexpr size_t IMAGE_DIRECTORY_ENTRY_TLS       = 9;
constexpr size_t IMAGE_DIRECTORY_ENTRY_IAT       = 12;

// Optional Header for PE32 (32-bit)
struct ImageOptionalHeader32 {
    uint16_t Magic; // 0x10b
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint32_t BaseOfData;
    uint32_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint32_t SizeOfStackReserve;
    uint32_t SizeOfStackCommit;
    uint32_t SizeOfHeapReserve;
    uint32_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    ImageDataDirectory DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
};

// Optional Header for PE32+ (64-bit)
struct ImageOptionalHeader64 {
    uint16_t Magic; // 0x20b
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    ImageDataDirectory DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
};

// Section Header (40 bytes)
struct ImageSectionHeader {
    uint8_t  Name[8];
    union {
        uint32_t PhysicalAddress;
        uint32_t VirtualSize;
    } Misc;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
};

// Import Directory Descriptor (20 bytes)
struct ImageImportDescriptor {
    union {
        uint32_t Characteristics;
        uint32_t OriginalFirstThunk; // RVA to Original INT (Import Name Table)
    } DUMMYUNIONNAME;
    uint32_t TimeDateStamp;
    uint32_t ForwarderChain;
    uint32_t Name;             // RVA to DLL name string
    uint32_t FirstThunk;        // RVA to IAT (Import Address Table)
};

// Authenticode WIN_CERTIFICATE structure (in Security Directory)
struct WinCertificate {
    uint32_t dwLength;
    uint16_t wRevision;
    uint16_t wCertificateType;
    // Followed by bCertificate bytes (PKCS#7 signed data)
};

#pragma pack(pop)

// Constants
constexpr uint16_t IMAGE_DOS_SIGNATURE = 0x5A4D; // "MZ"
constexpr uint32_t IMAGE_NT_SIGNATURE  = 0x00004550; // "PE\0\0"
constexpr uint16_t IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b;
constexpr uint16_t IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b;

// Machine Architectures
constexpr uint16_t IMAGE_FILE_MACHINE_I386  = 0x014c;
constexpr uint16_t IMAGE_FILE_MACHINE_AMD64 = 0x8664;
constexpr uint16_t IMAGE_FILE_MACHINE_ARM64 = 0xaa64;

// Section Characteristics
constexpr uint32_t IMAGE_SCN_MEM_EXECUTE = 0x20000000;
constexpr uint32_t IMAGE_SCN_MEM_READ    = 0x40000000;
constexpr uint32_t IMAGE_SCN_MEM_WRITE   = 0x80000000;
constexpr uint32_t IMAGE_SCN_CNT_CODE    = 0x00000020;

// Subsystems
constexpr uint16_t IMAGE_SUBSYSTEM_WINDOWS_GUI = 2;
constexpr uint16_t IMAGE_SUBSYSTEM_WINDOWS_CUI = 3;

// Certificate Types
constexpr uint16_t WIN_CERT_TYPE_X509             = 0x0001;
constexpr uint16_t WIN_CERT_TYPE_PKCS_SIGNED_DATA = 0x0002;

} // namespace finguard::pe
