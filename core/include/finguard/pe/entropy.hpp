#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>
#include <array>

namespace finguard::pe {

class EntropyCalculator {
public:
    // Calculates Shannon entropy (0.0 to 8.0 bits per byte)
    static double calculate(const uint8_t* data, size_t size);
    static double calculate(const std::vector<uint8_t>& data);

    // Byte distribution frequency histogram
    static std::array<size_t, 256> byte_distribution(const uint8_t* data, size_t size);

    // Heuristic thresholds
    static constexpr double PACKED_THRESHOLD = 7.15; // Above this is strongly indicative of packing/encryption
    static constexpr double COMPRESSED_THRESHOLD = 6.80;

    static bool is_suspiciously_packed(double entropy) {
        return entropy >= PACKED_THRESHOLD;
    }
};

} // namespace finguard::pe
