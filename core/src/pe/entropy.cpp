#include "finguard/pe/entropy.hpp"
#include <cmath>

namespace finguard::pe {

std::array<size_t, 256> EntropyCalculator::byte_distribution(const uint8_t* data, size_t size) {
    std::array<size_t, 256> counts{};
    for (size_t i = 0; i < size; ++i) {
        counts[data[i]]++;
    }
    return counts;
}

double EntropyCalculator::calculate(const uint8_t* data, size_t size) {
    if (!data || size == 0) {
        return 0.0;
    }

    auto counts = byte_distribution(data, size);
    double entropy = 0.0;
    const double total = static_cast<double>(size);

    for (size_t count : counts) {
        if (count > 0) {
            double p = static_cast<double>(count) / total;
            entropy -= p * std::log2(p);
        }
    }

    return entropy;
}

double EntropyCalculator::calculate(const std::vector<uint8_t>& data) {
    return calculate(data.data(), data.size());
}

} // namespace finguard::pe
