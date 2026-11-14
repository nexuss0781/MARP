#include "mapr/e1_crc32.hpp"
#include <array>
#include <cstddef>
#include <string_view>
#include <string>

namespace mapr {

// ============================================================================
// Compile-time table generation
// ============================================================================

static constexpr uint32_t step_zero_bit(uint32_t crc) noexcept {
    if (crc & 1) return (crc >> 1) ^ CRC32_POLY;
    return crc >> 1;
}

static constexpr uint32_t step_zero_byte(uint32_t crc) noexcept {
    for (int i = 0; i < 8; ++i) crc = step_zero_bit(crc);
    return crc;
}

static constexpr std::array<uint32_t, 256> build_crc32_table() noexcept {
    std::array<uint32_t, 256> table{};
    for (uint32_t i = 0; i < 256; ++i) {
        uint32_t crc = i;
        for (int j = 0; j < 8; ++j) {
            if (crc & 1) crc = (crc >> 1) ^ CRC32_POLY;
            else crc >>= 1;
        }
        table[i] = crc;
    }
    return table;
}

const std::array<uint32_t, 256>& crc32_table() noexcept {
    static const auto table = build_crc32_table();
    return table;
}

// ============================================================================
// Combine matrix (Math-SPECS C8)
// ============================================================================

// One zero-byte step = 8 zero bits in internal state space (linear)
static constexpr std::array<uint32_t, 32> build_zero_byte_matrix() noexcept {
    std::array<uint32_t, 32> mat{};
    for (int i = 0; i < 32; ++i) {
        mat[i] = step_zero_byte(1u << i);
    }
    return mat;
}

static constexpr uint32_t mat_times(const std::array<uint32_t, 32>& mat, uint32_t vec) noexcept {
    uint32_t res = 0;
    for (int i = 0; i < 32; ++i) {
        if (vec & 1) res ^= mat[i];
        vec >>= 1;
    }
    return res;
}

static constexpr std::array<uint32_t, 32> mat_square(const std::array<uint32_t, 32>& mat) noexcept {
    std::array<uint32_t, 32> res{};
    for (int i = 0; i < 32; ++i) {
        res[i] = mat_times(mat, mat[i]);
    }
    return res;
}

static constexpr std::array<std::array<uint32_t, 32>, 32> build_combine_matrix() noexcept {
    std::array<std::array<uint32_t, 32>, 32> powers{};
    powers[0] = build_zero_byte_matrix(); // M^1
    for (int i = 1; i < 32; ++i) {
        powers[i] = mat_square(powers[i-1]); // M^{2^i}
    }
    return powers;
}

const std::array<std::array<uint32_t, 32>, 32>& crc32_combine_matrix() noexcept {
    static const auto matrix = build_combine_matrix();
    return matrix;
}

// ============================================================================
// Core CRC functions
// ============================================================================

uint32_t crc32(std::string_view data) noexcept {
    // Standard CRC-32 (ISO 3309): init=0xFFFFFFFF, xorout=0xFFFFFFFF
    uint32_t crc = CRC32_INIT;
    const uint8_t* bytes = reinterpret_cast<const uint8_t*>(data.data());
    for (size_t i = 0; i < data.size(); ++i) {
        crc = crc32_table()[(crc ^ bytes[i]) & 0xFF] ^ (crc >> 8);
    }
    return crc ^ CRC32_XOROUT;
}

uint32_t crc32_incremental(std::string_view data, uint32_t crc) noexcept {
    // zlib-compatible: init=0, no final XOR
    const uint8_t* bytes = reinterpret_cast<const uint8_t*>(data.data());
    for (size_t i = 0; i < data.size(); ++i) {
        crc = crc32_table()[(crc ^ bytes[i]) & 0xFF] ^ (crc >> 8);
    }
    return crc;
}

uint32_t crc32_combine(uint32_t crc_a, uint32_t crc_b, size_t len_b) noexcept {
    // Both CRCs are standard finalized values (xorout=0xFFFFFFFF)
    // Formula: c_AB = Z^{8*len_b}(c_A) ⊕ c_B
    // Internal state: s = crc ^ CRC32_INIT
    // Shift internal state, then xorout

    uint32_t internal_a = crc_a ^ CRC32_INIT;
    uint32_t internal_b = crc_b ^ CRC32_INIT;

    // Apply M^len_b to internal_a
    const auto& powers = crc32_combine_matrix();
    size_t e = len_b;
    int p = 0;
    while (e) {
        if (e & 1) internal_a = mat_times(powers[p], internal_a);
        e >>= 1;
        ++p;
    }

    uint32_t combined_internal = internal_a ^ internal_b;
    return combined_internal ^ CRC32_INIT;
}

uint32_t crc32_zeroed(std::string_view data, size_t offset) noexcept {
    if (offset + 4 > data.size()) return crc32(data); // out of bounds, just return normal
    uint32_t crc = CRC32_INIT;
    const uint8_t* bytes = reinterpret_cast<const uint8_t*>(data.data());

    // Process bytes before offset
    for (size_t i = 0; i < offset; ++i) {
        crc = crc32_table()[(crc ^ bytes[i]) & 0xFF] ^ (crc >> 8);
    }
    // Process 4 zero bytes
    for (int i = 0; i < 4; ++i) {
        crc = crc32_table()[(crc ^ 0) & 0xFF] ^ (crc >> 8);
    }
    // Process bytes after offset+4
    for (size_t i = offset + 4; i < data.size(); ++i) {
        crc = crc32_table()[(crc ^ bytes[i]) & 0xFF] ^ (crc >> 8);
    }
    return crc ^ CRC32_XOROUT;
}

bool crc32_zeroed_invariant(std::string_view data, size_t offset) noexcept {
    if (offset + 4 > data.size()) return true;
    uint32_t z1 = crc32_zeroed(data, offset);
    // Create modified copy with random bytes at offset
    std::string modified(data);
    modified[offset] ^= static_cast<char>(0xFF);
    modified[offset+1] ^= static_cast<char>(0xAA);
    modified[offset+2] ^= static_cast<char>(0x55);
    modified[offset+3] ^= static_cast<char>(0x33);
    uint32_t z2 = crc32_zeroed(modified, offset);
    return z1 == z2;
}

} // namespace mapr