#include "mapr/e1_gear.hpp"
#include <array>
#include <string_view>

namespace mapr {

// ============================================================================
// Gear table (compile-time)
// ============================================================================

static constexpr uint64_t GEAR_CONST1 = 0x9E3779B97F4A7C15ull;
static constexpr uint64_t GEAR_CONST2 = 0xC2B2AE3D27D4EB4Full;

static constexpr std::array<uint64_t, 256> build_gear_table() noexcept {
    std::array<uint64_t, 256> table{};
    for (int i = 0; i < 256; ++i) {
        table[i] = (static_cast<uint64_t>(i) * GEAR_CONST1) ^ (static_cast<uint64_t>(i) * GEAR_CONST2);
    }
    return table;
}

const std::array<uint64_t, 256>& gear_table() noexcept {
    static const auto table = build_gear_table();
    return table;
}

// ============================================================================
// Gear hash implementation
// ============================================================================

GearHash::GearHash(uint64_t seed) noexcept {
    reset(seed);
}

void GearHash::reset(uint64_t seed) noexcept {
    state_ = seed;
    total_bytes_ = 0;
}

void GearHash::update(std::string_view data) noexcept {
    const uint8_t* bytes = reinterpret_cast<const uint8_t*>(data.data());
    const auto& G = gear_table();
    for (size_t i = 0; i < data.size(); ++i) {
        state_ = (state_ << 1) + G[bytes[i]];
    }
    total_bytes_ += data.size();
}

uint64_t GearHash::finish() noexcept {
    uint64_t result = state_;
    // State persists for further updates (not consumed)
    return result;
}

uint64_t gear_hash(std::string_view data, uint64_t seed) noexcept {
    GearHash gh(seed);
    gh.update(data);
    return gh.finish();
}

} // namespace mapr