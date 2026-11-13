#include "mapr/simd/dispatch.hpp"
#include "mapr/hwprobe.hpp"

#include <atomic>
#include <cstdint>
#include <cstring>

namespace mapr::simd {

// ──────────────────────────────────────────────────────────────
// Global Kernel Table
// ──────────────────────────────────────────────────────────────

static KernelTable g_kernels{};
static std::atomic<bool> g_initialized{false};
static IsaLevel g_current_isa = IsaLevel::SCALAR;

// Forward declarations for ISA-specific implementations (C linkage)
extern "C" void init_avx2_kernels(KernelTable*);
extern "C" void init_avx512_kernels(KernelTable*);
// NEON only on ARM
#if defined(__aarch64__) || defined(__arm64__) || defined(__arm__)
extern "C" void init_neon_kernels(KernelTable*);
#endif

// ──────────────────────────────────────────────────────────────
// Initialization
// ──────────────────────────────────────────────────────────────

void init_simd(IsaLevel forced_isa) {
    if (g_initialized.exchange(true)) return;

    // Start with scalar fallbacks (now defined in dispatch.hpp as inline)
    g_kernels.popcount64 = scalar::popcount64;
    g_kernels.popcount_array = scalar::popcount_array;
    g_kernels.bitrev64 = scalar::bitrev64;
    g_kernels.bitrev_array = scalar::bitrev_array;
    g_kernels.mobius64 = scalar::mobius64;
    g_kernels.mobius_array = scalar::mobius_array;
    g_kernels.splitmix64 = scalar::splitmix64;
    g_kernels.splitmix64_array = scalar::splitmix64_array;
    g_kernels.crc32 = scalar::crc32;
    g_kernels.crc32_combine = scalar::crc32_combine;
    g_kernels.sha256_init = scalar::sha256_init;
    g_kernels.sha256_update = scalar::sha256_update;
    g_kernels.sha256_final = scalar::sha256_final;
    g_kernels.sha256_hash = scalar::sha256_hash;
    g_kernels.minhash64 = scalar::minhash64;
    g_kernels.current_isa = IsaLevel::SCALAR;

    // Detect hardware capabilities
    IsaLevel best_isa = IsaLevel::SCALAR;
    HardwareCaps caps = probe_hardware();

    // Priority: AVX-512 > AVX2 > NEON > SVE > Scalar
    if (forced_isa != IsaLevel::SCALAR) {
        best_isa = forced_isa;
    } else if (caps.has_avx512f && caps.has_avx512vl && caps.has_avx512bw && caps.has_avx512dq && caps.has_avx512vbmi) {
        best_isa = IsaLevel::AVX512;
    } else if (caps.has_avx2) {
        best_isa = IsaLevel::AVX2;
    } else if (caps.has_neon) {
        best_isa = IsaLevel::NEON;
    } else if (caps.has_sve) {
        best_isa = IsaLevel::SVE;
    }

    // Override with ISA-specific implementations
    switch (best_isa) {
        case IsaLevel::AVX512:
            init_avx512_kernels(&g_kernels);
            break;
        case IsaLevel::AVX2:
            init_avx2_kernels(&g_kernels);
            break;
        case IsaLevel::NEON:
#if defined(__aarch64__) || defined(__arm64__) || defined(__arm__)
            init_neon_kernels(&g_kernels);
#endif
            break;
        default:
            break;
    }

    g_kernels.current_isa = best_isa;
    g_current_isa = best_isa;
}

const KernelTable* get_kernels() {
    if (!g_initialized.load()) {
        init_simd(IsaLevel::SCALAR);
    }
    return &g_kernels;
}

IsaLevel get_current_isa() {
    if (!g_initialized.load()) {
        init_simd(IsaLevel::SCALAR);
    }
    return g_current_isa;
}

bool has_isa(IsaLevel isa) {
    HardwareCaps caps = probe_hardware();
    switch (isa) {
        case IsaLevel::AVX512:
            return caps.has_avx512f && caps.has_avx512vl && caps.has_avx512bw && caps.has_avx512dq && caps.has_avx512vbmi;
        case IsaLevel::AVX2:
            return caps.has_avx2;
        case IsaLevel::NEON:
            return caps.has_neon;
        case IsaLevel::SVE:
            return caps.has_sve;
        default:
            return true;
    }
}

} // namespace mapr::simd