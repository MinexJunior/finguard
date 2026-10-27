#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <cstddef>

namespace finguard::pe {

class Sha256 {
public:
    static std::string hash_bytes(const uint8_t* data, size_t len);
    static std::string hash_bytes(const std::vector<uint8_t>& data);
    static std::string hash_file(const std::string& filepath);
};

} // namespace finguard::pe
