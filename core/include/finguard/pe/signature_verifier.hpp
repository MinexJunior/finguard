#pragma once

#include "finguard/pe/pe_structures.hpp"
#include <string>
#include <vector>
#include <cstdint>

namespace finguard::pe {

struct SignatureReport {
    bool is_signed{false};
    bool is_valid_format{false};
    bool is_trusted_ca{false};
    std::string signer_name;
    std::string issuer_name;
    std::string status_message{"Unsigned executable"};
    uint32_t certificate_size{0};
};

class SignatureVerifier {
public:
    SignatureVerifier() = default;

    // Verify digital signature from raw PE file buffer
    static SignatureReport verify_from_pe(const uint8_t* file_data, 
                                         size_t file_size, 
                                         const ImageDataDirectory& sec_dir);

    // Platform-specific verification for a file path (e.g. WinVerifyTrust on Windows)
    static SignatureReport verify_file(const std::string& filepath);

    // Known trusted vendors relevant to financial software & OS baselines
    static bool is_known_trusted_vendor(const std::string& vendor_name);
};

} // namespace finguard::pe
