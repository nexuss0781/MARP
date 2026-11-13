// AVX-512 SIMD Kernels
// Compile with: -mavx512f -mavx512vl -mavx512bw -mavx512dq -mavx512vbmi

#include "mapr/simd/dispatch.hpp"
#include <immintrin.h>
#include <cstdint>
#include <cstring>

namespace mapr::simd {

namespace avx512 {

// Population count using VPOPCNTDQ (AVX-512 VPOPCNTDQ)
// Processes 8x uint64_t at once
inline void popcount_array_avx512(const uint64_t* in, size_t n, uint64_t* out) {
    size_t i = 0;
    for (; i + 7 < n; i += 8) {
        // Load 8x uint64_t (512 bits)
        __m512i v = _mm512_loadu_si512(reinterpret_cast<const __m512i*>(in + i));
        // VPOPCNTDQ - population count of doublewords (64-bit)
        __m512i counts = _mm512_popcnt_epi64(v);
        _mm512_storeu_si512(reinterpret_cast<__m512i*>(out + i), counts);
    }
    for (; i < n; ++i) {
        out[i] = __builtin_popcountll(in[i]);
    }
}

inline uint64_t popcount64_avx512(uint64_t x) {
    return __builtin_popcountll(x);
}

// Bit reverse using AVX-512 permutations
inline uint64_t bitrev64_avx512(uint64_t x) {
    x = ((x >> 1) & 0x5555555555555555ULL) | ((x & 0x5555555555555555ULL) << 1);
    x = ((x >> 2) & 0x3333333333333333ULL) | ((x & 0x3333333333333333ULL) << 2);
    x = ((x >> 4) & 0x0F0F0F0F0F0F0F0FULL) | ((x & 0x0F0F0F0F0F0F0F0FULL) << 4);
    x = ((x >> 8) & 0x00FF00FF00FF00FFULL) | ((x & 0x00FF00FF00FF00FFULL) << 8);
    x = ((x >> 16) & 0x0000FFFF0000FFFFULL) | ((x & 0x0000FFFF0000FFFFULL) << 16);
    x = (x >> 32) | (x << 32);
    return x;
}

inline void bitrev_array_avx512(const uint64_t* in, size_t n, uint64_t* out) {
    size_t i = 0;
    for (; i + 7 < n; i += 8) {
        // Load 8x uint64_t
        __m512i v = _mm512_loadu_si512(reinterpret_cast<const __m512i*>(in + i));
        // Byte swap within each 64-bit word
        // _mm512_shuffle_epi8 with appropriate mask
        __m512i swapped = _mm512_shuffle_epi8(v, _mm512_set_epi8(
            7,6,5,4,3,2,1,0, 15,14,13,12,11,10,9,8,
            7,6,5,4,3,2,1,0, 15,14,13,12,11,10,9,8,
            7,6,5,4,3,2,1,0, 15,14,13,12,11,10,9,8,
            7,6,5,4,3,2,1,0, 15,14,13,12,11,10,9,8
        ));
        // For full bit reverse, we'd need more steps
        // Simplified: scalar for now
        for (int j = 0; j < 8; ++j) {
            out[i + j] = bitrev64_avx512(in[i + j]);
        }
    }
    for (; i < n; ++i) {
        out[i] = bitrev64_avx512(in[i]);
    }
}

// Möbius transform
inline uint64_t mobius64_avx512(uint64_t x) {
    x ^= (x >> 1) & 0x5555555555555555ULL;
    x ^= (x >> 2) & 0x3333333333333333ULL;
    x ^= (x >> 4) & 0x0F0F0F0F0F0F0F0FULL;
    x ^= (x >> 8) & 0x00FF00FF00FF00FFULL;
    x ^= (x >> 16) & 0x0000FFFF0000FFFFULL;
    x ^= (x >> 32);
    return x;
}

inline void mobius_array_avx512(const uint64_t* in, size_t n, uint64_t* out) {
    for (size_t i = 0; i < n; ++i) out[i] = mobius64_avx512(in[i]);
}

// SplitMix64 - process 8 at a time
inline void splitmix64_array_avx512(const uint64_t* in, size_t n, uint64_t* out) {
    size_t i = 0;
    // Constants
    __m512i c1 = _mm512_set1_epi64(0x9E3779B97F4A7C15LL);
    __m512i c2 = _mm512_set1_epi64(0xBF58476D1CE4E5B9LL);
    __m512i c3 = _mm512_set1_epi64(0x94D049BB133111EBLL);

    for (; i + 7 < n; i += 8) {
        __m512i v = _mm512_loadu_si512(reinterpret_cast<const __m512i*>(in + i));
        v = _mm512_add_epi64(v, c1);

        // v ^ (v >> 30)
        __m512i v_shr = _mm512_srli_epi64(v, 30);
        v = _mm512_xor_si512(v, v_shr);
        v = _mm512_mullo_epi64(v, c2);

        // v ^ (v >> 27)
        v_shr = _mm512_srli_epi64(v, 27);
        v = _mm512_xor_si512(v, v_shr);
        v = _mm512_mullo_epi64(v, c3);

        // v ^ (v >> 31)
        v_shr = _mm512_srli_epi64(v, 31);
        v = _mm512_xor_si512(v, v_shr);

        _mm512_storeu_si512(reinterpret_cast<__m512i*>(out + i), v);
    }
    for (; i < n; ++i) {
        out[i] = simd::scalar::splitmix64(in[i]);
    }
}

inline uint64_t splitmix64_avx512(uint64_t x) {
    x += 0x9E3779B97F4A7C15ULL;
    x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ULL;
    x = (x ^ (x >> 27)) * 0x94D049BB133111EBULL;
    return x ^ (x >> 31);
}

// CRC32 using VPCLMULQDQ (carry-less multiply)
// This is the most efficient way for AVX-512
// We'll use the Intel whitepaper approach

// For now, use slicing-by-8 which works well
static uint32_t crc32_table_avx512[8][256];
static bool crc32_table_avx512_init = false;

static void init_crc32_table_avx512() {
    if (crc32_table_avx512_init) return;
    for (uint32_t i = 0; i < 256; ++i) {
        uint32_t c = i;
        for (int j = 0; j < 8; ++j) {
            c = (c & 1) ? (0xEDB88320U ^ (c >> 1)) : (c >> 1);
        }
        crc32_table_avx512[0][i] = c;
    }
    for (int k = 1; k < 8; ++k) {
        for (uint32_t i = 0; i < 256; ++i) {
            crc32_table_avx512[k][i] = crc32_table_avx512[0][crc32_table_avx512[k-1][i] & 0xFF] ^ (crc32_table_avx512[k-1][i] >> 8);
        }
    }
    crc32_table_avx512_init = true;
}

inline uint32_t crc32_avx512(uint32_t crc, const uint8_t* data, size_t len) {
    init_crc32_table_avx512();
    crc ^= 0xFFFFFFFFU;

    while (len > 0 && (reinterpret_cast<uintptr_t>(data) & 7)) {
        crc = crc32_table_avx512[0][(crc ^ *data++) & 0xFF] ^ (crc >> 8);
        --len;
    }

    const uint64_t* data64 = reinterpret_cast<const uint64_t*>(data);
    while (len >= 8) {
        uint64_t chunk = *data64++;
        crc ^= static_cast<uint32_t>(chunk);
        crc = crc32_table_avx512[7][crc & 0xFF] ^
              crc32_table_avx512[6][(crc >> 8) & 0xFF] ^
              crc32_table_avx512[5][(crc >> 16) & 0xFF] ^
              crc32_table_avx512[4][(crc >> 24) & 0xFF] ^
              crc32_table_avx512[3][static_cast<uint32_t>(chunk >> 32) & 0xFF] ^
              crc32_table_avx512[2][(static_cast<uint32_t>(chunk >> 32) >> 8) & 0xFF] ^
              crc32_table_avx512[1][(static_cast<uint32_t>(chunk >> 32) >> 16) & 0xFF] ^
              crc32_table_avx512[0][(static_cast<uint32_t>(chunk >> 32) >> 24) & 0xFF];
        len -= 8;
    }

    data = reinterpret_cast<const uint8_t*>(data64);
    while (len--) {
        crc = crc32_table_avx512[0][(crc ^ *data++) & 0xFF] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFFU;
}

inline uint32_t crc32_combine_avx512(uint32_t crc1, uint32_t crc2, size_t len2) {
    return crc1 ^ crc2;
}

// SHA-256 using AVX-512 (no dedicated SHA instructions in AVX-512)
// Use Intel SHA extensions if available (separate CPUID bit)
// For now, scalar

// MinHash
inline void minhash64_avx512(const uint64_t* in, size_t n, uint64_t* out, uint64_t seed) {
    __m512i seed_v = _mm512_set1_epi64(seed);
    size_t i = 0;
    for (; i + 7 < n; i += 8) {
        __m512i v = _mm512_loadu_si512(reinterpret_cast<const __m512i*>(in + i));
        v = _mm512_xor_si512(v, seed_v);

        // Apply splitmix64 to each element
        __m512i c1 = _mm512_set1_epi64(0x9E3779B97F4A7C15LL);
        __m512i c2 = _mm512_set1_epi64(0xBF58476D1CE4E5B9LL);
        __m512i c3 = _mm512_set1_epi64(0x94D049BB133111EBLL);

        __m512i x = _mm512_add_epi64(v, c1);
        __m512i x_shr = _mm512_srli_epi64(x, 30);
        x = _mm512_xor_si512(x, x_shr);
        x = _mm512_mullo_epi64(x, c2);

        x_shr = _mm512_srli_epi64(x, 27);
        x = _mm512_xor_si512(x, x_shr);
        x = _mm512_mullo_epi64(x, c3);

        x_shr = _mm512_srli_epi64(x, 31);
        x = _mm512_xor_si512(x, x_shr);

        _mm512_storeu_si512(reinterpret_cast<__m512i*>(out + i), x);
    }
    for (; i < n; ++i) {
        out[i] = simd::scalar::splitmix64(in[i] ^ seed);
    }
}

} // namespace avx512

// ──────────────────────────────────────────────────────────────
// Initialization Function
// ──────────────────────────────────────────────────────────────

extern "C" void init_avx512_kernels(KernelTable* k) {
    k->popcount64 = avx512::popcount64_avx512;
    k->popcount_array = avx512::popcount_array_avx512;
    k->bitrev64 = avx512::bitrev64_avx512;
    k->bitrev_array = avx512::bitrev_array_avx512;
    k->mobius64 = avx512::mobius64_avx512;
    k->mobius_array = avx512::mobius_array_avx512;
    k->splitmix64 = avx512::splitmix64_avx512;
    k->splitmix64_array = avx512::splitmix64_array_avx512;
    k->crc32 = avx512::crc32_avx512;
    k->crc32_combine = avx512::crc32_combine_avx512;
    // SHA-256 and MinHash use scalar for now
    k->current_isa = IsaLevel::AVX512;
}

} // namespace mapr::simd