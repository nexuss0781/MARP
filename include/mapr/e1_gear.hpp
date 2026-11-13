#pragma once
#include "e1_types.hpp"
#include <array>
#include <cstddef>
#include <string_view>

namespace mapr {

// Gear hash: h = seed·2^n + Σ G[b_j]·2^{n-1-j} (mod 2^64)
// G[x] = (x * 0x9E3779B97F4A7C15) ^ (x * 0xC2B2AE3D27D4EB4F)  (Math-SPECS §15.1)
static constexpr uint64_t GEAR_SEED_DEFAULT = 0;

// Precomputed table (compile-time)
const std::array<uint64_t, 256>& gear_table() noexcept;

// One-shot
uint64_t gear_hash(std::string_view data, uint64_t seed = GEAR_SEED_DEFAULT) noexcept;

// Streaming (identical to one-shot, for API symmetry)
class GearHash {
public:
    explicit GearHash(uint64_t seed = GEAR_SEED_DEFAULT) noexcept;
    void reset(uint64_t seed = GEAR_SEED_DEFAULT) noexcept;
    void update(std::string_view data) noexcept;
    uint64_t finish() noexcept;
private:
    uint64_t state_;
    size_t total_bytes_;
};

} // namespace mapr