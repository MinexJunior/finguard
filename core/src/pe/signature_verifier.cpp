#include "finguard/pe/signature_verifier.hpp"
#include <cstring>
#include <algorithm>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")
#endif

namespace finguard::pe {

namespace {

const std::vector<std::string> TRUSTED_VENDORS = {
    "Microsoft Corporation",
    "Microsoft Windows",
    "Google LLC",
    "Commercial Bank of Ethiopia",
    "Ethio Telecom",
    "Bank of Abyssinia",
    "Dashen Bank"
};

} // namespace

bool SignatureVerifier::is_known_trusted_vendor(const std::string& vendor_name) {
    if (vendor_name.empty()) return false;
    for (const auto& v : TRUSTED_VENDORS) {
        if (vendor_name.find(v) != std::string::npos) {
            return true;
        }
    }
    return false;
}

SignatureReport SignatureVerifier::verify_from_pe(const uint8_t* file_data, 
                                                 size_t file_size, 
                                                 const ImageDataDirectory& sec_dir) {
    SignatureReport report;

    // Security Directory VirtualAddress is a direct file offset, NOT an RVA!
    uint32_t cert_offset = sec_dir.VirtualAddress;
    uint32_t cert_size = sec_dir.Size;

    if (cert_offset == 0 || cert_size == 0) {
        report.is_signed = false;
        report.status_message = "Binary is not signed (no Authenticode certificate table)";
        return report;
    }

    if (cert_offset + sizeof(WinCertificate) > file_size || cert_offset + cert_size > file_size) {
        report.is_signed = true;
        report.is_valid_format = false;
        report.status_message = "Corrupt security directory offset or truncated certificate table";
        return report;
    }

    const auto* cert = reinterpret_cast<const WinCertificate*>(file_data + cert_offset);
    report.is_signed = true;
    report.certificate_size = cert->dwLength;

    if (cert->wCertificateType == WIN_CERT_TYPE_PKCS_SIGNED_DATA) {
        report.is_valid_format = true;
        report.status_message = "Authenticode PKCS#7 signature present";
    } else if (cert->wCertificateType == WIN_CERT_TYPE_X509) {
        report.is_valid_format = true;
        report.status_message = "X.509 raw certificate present";
    } else {
        report.is_valid_format = false;
        report.status_message = "Unknown certificate type: " + std::to_string(cert->wCertificateType);
    }

    return report;
}

SignatureReport SignatureVerifier::verify_file(const std::string& filepath) {
    SignatureReport report;

#ifdef _WIN32
    std::wstring wpath(filepath.begin(), filepath.end());

    WINTRUST_FILE_INFO file_info{};
    file_info.cbStruct = sizeof(WINTRUST_FILE_INFO);
    file_info.pcwszFilePath = wpath.c_str();

    GUID action_guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WINTRUST_DATA trust_data{};
    trust_data.cbStruct = sizeof(WINTRUST_DATA);
    trust_data.dwUIChoice = WTD_UI_NONE;
    trust_data.fdwRevocationChecks = WTD_REVOKE_NONE;
    trust_data.dwUnionChoice = WTD_CHOICE_FILE;
    trust_data.pFile = &file_info;
    trust_data.dwStateAction = WTD_STATEACTION_VERIFY;

    LONG status = WinVerifyTrust(nullptr, &action_guid, &trust_data);

    trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &action_guid, &trust_data);

    if (status == ERROR_SUCCESS) {
        report.is_signed = true;
        report.is_valid_format = true;
        report.is_trusted_ca = true;
        report.status_message = "Signature verified and trusted by Windows CryptoAPI";
    } else if (status == TRUST_E_NOSIGNATURE) {
        report.is_signed = false;
        report.status_message = "No digital signature found";
    } else if (status == TRUST_E_BAD_DIGEST) {
        report.is_signed = true;
        report.is_valid_format = false;
        report.status_message = "Signature digest mismatch (executable modified or corrupted)";
    } else {
        report.is_signed = true;
        report.is_valid_format = false;
        report.status_message = "Signature untrusted or revoked (code " + std::to_string(status) + ")";
    }
#else
    report.is_signed = false;
    report.status_message = "Platform verification requires Windows CryptoAPI; using PE static parser";
#endif

    return report;
}

} // namespace finguard::pe
