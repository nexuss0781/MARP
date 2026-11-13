#pragma once

#include "mapr/simd/dispatch.hpp"
#include <cstdint>

namespace mapr::simd {

// ──────────────────────────────────────────────────────────────
// Inline wrappers for encoder hot paths
// ──────────────────────────────────────────────────────────────

// splitmix64 hash - used extensively in encoder for hashing
inline uint64_t splitmix64(uint64_t x) {
    const KernelTable* k = get_kernels();
    return k->splitmix64(x);
}

// splitmix64 array - for batch hashing
inline void splitmix64_array(const uint64_t* in, size_t n, uint64_t* out) {
    const KernelTable* k = get_kernels();
    k->splitmix64_array(in, n, out);
}

// Population count - used for Hamming weight
inline uint64_t popcount64(uint64_t x) {
    const KernelTable* k = get_kernels();
    return k->popcount64(x);
}

inline void popcount_array(const uint64_t* in, size_t n, uint64_t* out) {
    const KernelTable* k = get_kernels();
    k->popcount_array(in, n, out);
}

// Möbius transform
inline uint64_t mobius64(uint64_t x) {
    const KernelTable* k = get_kernels();
    return k->mobius64(x);
}

inline void mobius_array(const uint64_t* in, size_t n, uint64_t* out) {
    const KernelTable* k = get_kernels();
    k->mobius_array(in, n, out);
}

// Bit reverse
inline uint64_t bitrev64(uint64_t x) {
    const KernelTable* k = get_kernels();
    return k->bitrev64(x);
}

inline void bitrev_array(const uint64_t* in, size_t n, uint64_t* out) {
    const KernelTable* k = get_kernels();
    k->bitrev_array(in, n, out);
}

// CRC32
inline uint32_t crc32(uint32_t crc, const uint8_t* data, size_t len) {
    const KernelTable* k = get_kernels();
    return k->crc32(crc, data, len);
}

inline uint32_t crc32_combine(uint32_t crc1, uint32_t crc2, size_t len2) {
    const KernelTable* k = get_kernels();
    return k->crc32_combine(crc1, crc2, len2);
}

// SHA-256
inline void sha256_init(void* ctx) {
    const KernelTable* k = get_kernels();
    k->sha256_init(ctx);
}

inline void sha256_update(void* ctx, const uint8_t* data, size_t len) {
    const KernelTable* k = get_kernels();
    k->sha256_update(ctx, data, len);
}

inline void sha256_final(void* ctx, uint8_t out[32]) {
    const KernelTable* k = get_kernels();
    k->sha256_final(ctx, out);
}

inline void sha256_hash(const uint8_t* data, size_t len, uint8_t out[32]) {
    const KernelTable* k = get_kernels();
    k->sha256_hash(data, len, out);
}

// MinHash (for minimizers)
inline void minhash64(const uint64_t* in, size_t n, uint64_t* out, uint64_t seed) {
    const KernelTable* k = get_kernels();
    k->minhash64(in, n, out, seed);
}

// ──────────────────────────────────────────────────────────────
// Convenience: ensure SIMD is initialized
// ──────────────────────────────────────────────────────────────

inline void ensure_simd_initialized() {
    (void)get_kernels(); // triggers init_simd() if not already done
}

} // namespace mapr::simd