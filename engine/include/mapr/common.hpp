#pragma once

#include <array>
#include <bit>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>



namespace mapr {

enum class V4Op : uint8_t {
    ID = 0,
    NOT = 1,
    REV = 2,
    REV_NOT = 3
};

inline constexpr V4Op compose_v4(V4Op a, V4Op b) noexcept {
    return static_cast<V4Op>(static_cast<uint8_t>(a) ^ static_cast<uint8_t>(b));
}

enum class AtomBasis : uint8_t {
    POS = 0,
    ZHEG = 1
};

struct StreamConfig {
    uint32_t w_sync = 64;
    uint32_t l_min = 262144;    // 2^18 bits = 32 KiB
    uint32_t l_target = 1048576;// 2^20 bits = 128 KiB
    uint32_t l_max = 4194304;   // 2^22 bits = 512 KiB
    uint32_t w_hist = 64;       // 64 superchunks

    bool valid() const noexcept {
        return w_sync == 64 &&
               l_min >= 64 &&
               l_min < l_target &&
               l_target <= l_max &&
               l_max <= (1u << 28) &&
               w_hist <= 4096;
    }
};

// Safe 64-bit low mask for 0 <= b <= 64 (never triggers shift UB at b == 64)
inline constexpr uint64_t low_mask(int b) noexcept {
    if (b <= 0) return 0ULL;
    if (b >= 64) return ~0ULL;
    return (1ULL << b) - 1ULL;
}

inline constexpr bool is_dyadic_atom_len(int b) noexcept {
    return b == 1 || b == 2 || b == 4 || b == 8 || b == 16 || b == 32 || b == 64;
}

inline constexpr uint64_t splitmix64(uint64_t x) noexcept {
    x += 0x9E3779B97F4A7C15ULL;
    x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ULL;
    x = (x ^ (x >> 27)) * 0x94D049BB133111EBULL;
    return x ^ (x >> 31);
}

inline constexpr uint64_t bitrev64(uint64_t x) noexcept {
    x = ((x & 0x5555555555555555ULL) << 1) | ((x >> 1) & 0x5555555555555555ULL);
    x = ((x & 0x3333333333333333ULL) << 2) | ((x >> 2) & 0x3333333333333333ULL);
    x = ((x & 0x0F0F0F0F0F0F0F0FULL) << 4) | ((x >> 4) & 0x0F0F0F0F0F0F0F0FULL);
    x = ((x & 0x00FF00FF00FF00FFULL) << 8) | ((x >> 8) & 0x00FF00FF00FF00FFULL);
    x = ((x & 0x0000FFFF0000FFFFULL) << 16) | ((x >> 16) & 0x0000FFFF0000FFFFULL);
    return (x << 32) | (x >> 32);
}

// Reverse bits within each individual byte of a 64-bit word (implements beta_MSB <-> little-endian u64)
inline constexpr uint64_t bitrev_bytes64(uint64_t x) noexcept {
    x = ((x & 0x5555555555555555ULL) << 1) | ((x >> 1) & 0x5555555555555555ULL);
    x = ((x & 0x3333333333333333ULL) << 2) | ((x >> 2) & 0x3333333333333333ULL);
    x = ((x & 0x0F0F0F0F0F0F0F0FULL) << 4) | ((x >> 4) & 0x0F0F0F0F0F0F0F0FULL);
    return x;
}

inline constexpr uint8_t bitrev8(uint8_t b) noexcept {
    b = static_cast<uint8_t>(((b & 0x55u) << 1) | ((b >> 1) & 0x55u));
    b = static_cast<uint8_t>(((b & 0x33u) << 2) | ((b >> 2) & 0x33u));
    b = static_cast<uint8_t>(((b & 0x0Fu) << 4) | ((b >> 4) & 0x0Fu));
    return b;
}

// Little-endian explicit byte serialization helpers
inline void write_le16(uint8_t* dst, uint16_t v) noexcept {
    dst[0] = static_cast<uint8_t>(v & 0xFFu);
    dst[1] = static_cast<uint8_t>((v >> 8) & 0xFFu);
}
inline void write_le32(uint8_t* dst, uint32_t v) noexcept {
    dst[0] = static_cast<uint8_t>(v & 0xFFu);
    dst[1] = static_cast<uint8_t>((v >> 8) & 0xFFu);
    dst[2] = static_cast<uint8_t>((v >> 16) & 0xFFu);
    dst[3] = static_cast<uint8_t>((v >> 24) & 0xFFu);
}
inline void write_le64(uint8_t* dst, uint64_t v) noexcept {
    for (int i = 0; i < 8; ++i) dst[i] = static_cast<uint8_t>((v >> (8 * i)) & 0xFFu);
}
inline void write_be64(uint8_t* dst, uint64_t v) noexcept {
    for (int i = 0; i < 8; ++i) dst[i] = static_cast<uint8_t>((v >> (56 - 8 * i)) & 0xFFu);
}

inline uint16_t read_le16(const uint8_t* src) noexcept {
    return static_cast<uint16_t>(src[0]) | (static_cast<uint16_t>(src[1]) << 8);
}
inline uint32_t read_le32(const uint8_t* src) noexcept {
    return static_cast<uint32_t>(src[0]) |
           (static_cast<uint32_t>(src[1]) << 8) |
           (static_cast<uint32_t>(src[2]) << 16) |
           (static_cast<uint32_t>(src[3]) << 24);
}
inline uint64_t read_le64(const uint8_t* src) noexcept {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= static_cast<uint64_t>(src[i]) << (8 * i);
    return v;
}
inline uint64_t read_be64(const uint8_t* src) noexcept {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = (v << 8) | static_cast<uint64_t>(src[i]);
    return v;
}

} // namespace mapr
