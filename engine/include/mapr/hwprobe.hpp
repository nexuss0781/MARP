#pragma once

#include "mapr/common.hpp"
#include <cstdint>

namespace mapr {

struct HardwareCaps {
    int physical_cores = 0;
    int logical_cores = 0;
    size_t l1_cache_kb = 0;
    size_t l2_cache_kb = 0;
    size_t l3_cache_kb = 0;
    bool has_avx2 = false;
    bool has_avx512f = false;
    bool has_avx512vl = false;
    bool has_avx512bw = false;
    bool has_avx512dq = false;
    bool has_avx512vbmi = false;
    bool has_neon = false;
    bool has_sve = false;
    bool has_bmi2 = false;
    bool has_popcnt = false;
    bool has_lzcnt = false;
    bool has_crc32 = false;
    bool has_sha_ext = false;
    size_t total_ram_mb = 0;
    size_t available_ram_mb = 0;
    float thermal_headroom = 1.0f; // 0.0-1.0
};

HardwareCaps probe_hardware();

} // namespace mapr