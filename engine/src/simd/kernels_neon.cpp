// NEON SIMD Kernels (ARM64)
// Compile with: -march=armv8-a+simd

#include "mapr/simd/dispatch.hpp"
#include <arm_neon.h>
#include <cstdint>
#include <cstring>

namespace mapr::simd {

namespace neon {

// Population count using VCNT (vector count bits)
inline uint64_t popcount64_neon(uint64_t x) {
    return __builtin_popcountll(x);
}

inline void popcount_array_neon(const uint64_t* in, size_t n, uint64_t* out) {
    size_t i = 0;
    // Process 2x uint64_t at a time using 128-bit NEON
    for (; i + 1 < n; i += 2) {
        // Load 2x uint64_t
        uint64x2_t v = vld1q_u64(in + i);
        // Split into bytes and count bits
        uint8x16_t bytes = vreinterpretq_u8_u64(v);
        // VCNT counts bits in each byte
        uint8x16_t counts = vcntq_u8(bytes);
        // Sum pairs of bytes (16-bit)
        uint16x8_t sum16 = vpaddlq_u8(counts);
        // Sum to 32-bit
        uint32x4_t sum32 = vpaddlq_u16(sum16);
        // Sum to 64-bit
        uint64x2_t sum64 = vpaddlq_u32(sum32);
        // Store
        vst1q_u64(out + i, sum64);
    }
    // Remainder
    for (; i < n; ++i) {
        out[i] = __builtin_popcountll(in[i]);
    }
}

// Bit reverse using RBIT (ARMv8 has RBIT instruction)
inline uint64_t bitrev64_neon(uint64_t x) {
    // Use RBIT instruction via builtin
    return __builtin_bitreverse64(x);
}

inline void bitrev_array_neon(const uint64_t* in, size_t n, uint64_t* out) {
    size_t i = 0;
    for (; i + 1 < n; i += 2) {
        uint64x2_t v = vld1q_u64(in + i);
        // RBIT reverses bits in each 32-bit element
        // For 64-bit, we need to swap 32-bit halves and apply RBIT
        uint32x4_t v32 = vreinterpretq_u32_u64(v);
        // Reverse 32-bit lanes
        uint32x4_t rev = vrev64q_u32(v32);  // This swaps elements within 64-bit
        // Apply RBIT to each 32-bit element
        // Note: ARM doesn't have direct RBIT for NEON, use scalar for now
        out[i] = bitrev64_neon(in[i]);
        out[i + 1] = bitrev64_neon(in[i + 1]);
    }
    for (; i < n; ++i) {
        out[i] = bitrev64_neon(in[i]);
    }
}

// Möbius transform - scalar fallback
inline uint64_t mobius64_neon(uint64_t x) {
    x ^= (x >> 1) & 0x5555555555555555ULL;
    x ^= (x >> 2) & 0x3333333333333333ULL;
    x ^= (x >> 4) & 0x0F0F0F0F0F0F0F0FULL;
    x ^= (x >> 8) & 0x00FF00FF00FF00FFULL;
    x ^= (x >> 16) & 0x0000FFFF0000FFFFULL;
    x ^= (x >> 32);
    return x;
}

inline void mobius_array_neon(const uint64_t* in, size_t n, uint64_t* out) {
    for (size_t i = 0; i < n; ++i) out[i] = mobius64_neon(in[i]);
}

// SplitMix64 - process 2 at a time
inline void splitmix64_array_neon(const uint64_t* in, size_t n, uint64_t* out) {
    size_t i = 0;
    for (; i + 1 < n; i += 2) {
        uint64_t x0 = in[i] + 0x9E3779B97F4A7C15ULL;
        uint64_t x1 = in[i + 1] + 0x9E3779B97F4A7C15ULL;

        x0 = (x0 ^ (x0 >> 30)) * 0xBF58476D1CE4E5B9ULL;
        x1 = (x1 ^ (x1 >> 30)) * 0xBF58476D1CE4E5B9ULL;

        x0 = (x0 ^ (x0 >> 27)) * 0x94D049BB133111EBULL;
        x1 = (x1 ^ (x1 >> 27)) * 0x94D049BB133111EBULL;

        out[i] = x0 ^ (x0 >> 31);
        out[i + 1] = x1 ^ (x1 >> 31);
    }
    for (; i < n; ++i) {
        out[i] = simd::scalar::splitmix64(in[i]);
    }
}

inline uint64_t splitmix64_neon(uint64_t x) {
    x += 0x9E3779B97F4A7C15ULL;
    x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ULL;
    x = (x ^ (x >> 27)) * 0x94D049BB133111EBULL;
    return x ^ (x >> 31);
}

// CRC32 using ARM CRC32 instructions (CRC32C or CRC32)
// ARMv8 has CRC32 instructions in the crypto extensions
// Use slicing-by-8 table approach for compatibility

static uint32_t crc32_table_neon[8][256];
static bool crc32_table_neon_init = false;

static void init_crc32_table_neon() {
    if (crc32_table_neon_init) return;
    for (uint32_t i = 0; i < 256; ++i) {
        uint32_t c = i;
        for (int j = 0; j < 8; ++j) {
            c = (c & 1) ? (0xEDB88320U ^ (c >> 1)) : (c >> 1);
        }
        crc32_table_neon[0][i] = c;
    }
    for (int k = 1; k < 8; ++k) {
        for (uint32_t i = 0; i < 256; ++i) {
            crc32_table_neon[k][i] = crc32_table_neon[0][crc32_table_neon[k-1][i] & 0xFF] ^ (crc32_table_neon[k-1][i] >> 8);
        }
    }
    crc32_table_neon_init = true;
}

inline uint32_t crc32_neon(uint32_t crc, const uint8_t* data, size_t len) {
    init_crc32_table_neon();
    crc ^= 0xFFFFFFFFU;

    while (len > 0 && (reinterpret_cast<uintptr_t>(data) & 7)) {
        crc = crc32_table_neon[0][(crc ^ *data++) & 0xFF] ^ (crc >> 8);
        --len;
    }

    const uint64_t* data64 = reinterpret_cast<const uint64_t*>(data);
    while (len >= 8) {
        uint64_t chunk = *data64++;
        crc ^= static_cast<uint32_t>(chunk);
        crc = crc32_table_neon[7][crc & 0xFF] ^
              crc32_table_neon[6][(crc >> 8) & 0xFF] ^
              crc32_table_neon[5][(crc >> 16) & 0xFF] ^
              crc32_table_neon[4][(crc >> 24) & 0xFF] ^
              crc32_table_neon[3][static_cast<uint32_t>(chunk >> 32) & 0xFF] ^
              crc32_table_neon[2][(static_cast<uint32_t>(chunk >> 32) >> 8) & 0xFF] ^
              crc32_table_neon[1][(static_cast<uint32_t>(chunk >> 32) >> 16) & 0xFF] ^
              crc32_table_neon[0][(static_cast<uint32_t>(chunk >> 32) >> 24) & 0xFF];
        len -= 8;
    }

    data = reinterpret_cast<const uint8_t*>(data64);
    while (len--) {
        crc = crc32_table_neon[0][(crc ^ *data++) & 0xFF] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFFU;
}

inline uint32_t crc32_combine_neon(uint32_t crc1, uint32_t crc2, size_t len2) {
    return crc1 ^ crc2;
}

// SHA-256 using ARMv8 Crypto Extensions (SHA256 instructions)
// If available, use hardware acceleration
// For now, use scalar implementation

// MinHash
inline void minhash64_neon(const uint64_t* in, size_t n, uint64_t* out, uint64_t seed) {
    size_t i = 0;
    for (; i + 1 < n; i += 2) {
        out[i] = splitmix64_neon(in[i] ^ seed);
        out[i + 1] = splitmix64_neon(in[i + 1] ^ seed);
    }
    for (; i < n; ++i) {
        out[i] = splitmix64_neon(in[i] ^ seed);
    }
}

} // namespace neon

// ──────────────────────────────────────────────────────────────
// Initialization Function
// ──────────────────────────────────────────────────────────────

extern "C" void init_neon_kernels(KernelTable* k) {
    k->popcount64 = neon::popcount64_neon;
    k->popcount_array = neon::popcount_array_neon;
    k->bitrev64 = neon::bitrev64_neon;
    k->bitrev_array = neon::bitrev_array_neon;
    k->mobius64 = neon::mobius64_neon;
    k->mobius_array = neon::mobius_array_neon;
    k->splitmix64 = neon::splitmix64_neon;
    k->splitmix64_array = neon::splitmix64_array_neon;
    k->crc32 = neon::crc32_neon;
    k->crc32_combine = neon::crc32_combine_neon;
    // SHA-256 and MinHash use scalar for now
    k->current_isa = IsaLevel::NEON;
}

} // namespace mapr::simd