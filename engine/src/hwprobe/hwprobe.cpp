#include "mapr/hwprobe.hpp"
#include "mapr/mapr.h"
#include "mapr/mapr_internal.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#if defined(_WIN32)
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#  include <intrin.h>
#  include <psapi.h>
#  pragma comment(lib, "psapi.lib")
#elif defined(__APPLE__)
#  include <sys/sysctl.h>
#  include <sys/types.h>
#  include <mach/mach.h>
#  include <mach/mach_host.h>
#  include <mach/host_info.h>
#else
#  include <unistd.h>
#  include <sys/utsname.h>
#  include <sys/sysinfo.h>
#  include <fstream>
#  include <cpuid.h>
#endif

namespace mapr {

namespace {

// ──────────────────────────────────────────────────────────────
// CPUID Helpers
// ──────────────────────────────────────────────────────────────

struct CpuIdResult {
    uint32_t eax, ebx, ecx, edx;
};

inline CpuIdResult cpuid(uint32_t leaf, uint32_t subleaf = 0) {
    CpuIdResult r{0, 0, 0, 0};
#if defined(_WIN32)
    int regs[4];
    __cpuidex(regs, static_cast<int>(leaf), static_cast<int>(subleaf));
    r.eax = static_cast<uint32_t>(regs[0]);
    r.ebx = static_cast<uint32_t>(regs[1]);
    r.ecx = static_cast<uint32_t>(regs[2]);
    r.edx = static_cast<uint32_t>(regs[3]);
#elif defined(__GNUC__) || defined(__clang__)
    __cpuid_count(leaf, subleaf, r.eax, r.ebx, r.ecx, r.edx);
#endif
    return r;
}

inline bool has_cpuid() {
#if defined(_WIN32)
    return true;
#elif defined(__GNUC__) || defined(__clang__)
    unsigned int eax, ebx, ecx, edx;
    return __get_cpuid_max(0, nullptr) >= 1;
#else
    return false;
#endif
}

// ──────────────────────────────────────────────────────────────
// Cache Info Parsing
// ──────────────────────────────────────────────────────────────

struct CacheInfo {
    size_t l1_kb = 0, l2_kb = 0, l3_kb = 0;
};

CacheInfo parse_cache_info() {
    CacheInfo info{};
    if (!has_cpuid()) return info;

    // Leaf 4: Deterministic Cache Parameters
    for (uint32_t i = 0; i < 32; ++i) {
        CpuIdResult r = cpuid(4, i);
        uint32_t cache_type = r.eax & 0x1F;
        if (cache_type == 0) break;

        uint32_t level = (r.eax >> 5) & 0x7;
        uint32_t ways = ((r.ebx >> 22) & 0x3FF) + 1;
        uint32_t partitions = ((r.ebx >> 12) & 0x3FF) + 1;
        uint32_t line_size = (r.ebx & 0xFFF) + 1;
        uint32_t sets = r.ecx + 1;

        size_t size_kb = (static_cast<size_t>(ways) * partitions * line_size * sets) / 1024;

        if (level == 1) info.l1_kb += size_kb;
        else if (level == 2) info.l2_kb += size_kb;
        else if (level == 3) info.l3_kb += size_kb;
    }

    // Fallback for older CPUs: Leaf 2 (Intel) / Leaf 0x80000005/6 (AMD)
    if (info.l1_kb == 0 && info.l2_kb == 0 && info.l3_kb == 0) {
        CpuIdResult r = cpuid(2);
        // Intel cache descriptor parsing would go here
        // For now, skip - leaf 4 is standard on modern CPUs
    }

    return info;
}

// ──────────────────────────────────────────────────────────────
// Feature Detection
// ──────────────────────────────────────────────────────────────

struct Features {
    bool avx2 = false, avx512f = false, avx512vl = false, avx512bw = false;
    bool avx512dq = false, avx512vbmi = false;
    bool neon = false, sve = false;
    bool bmi2 = false, popcnt = false, lzcnt = false;
    bool crc32 = false, sha_ext = false;
};

Features detect_features() {
    Features f{};
    if (!has_cpuid()) return f;

    // Leaf 1: Basic feature flags
    CpuIdResult r1 = cpuid(1);
    f.popcnt  = (r1.ecx >> 23) & 1;
    f.crc32   = (r1.ecx >> 20) & 1; // SSE4.2
    // Note: AVX, AVX2, BMI2 are in leaf 7

    // Leaf 7: Extended features
    CpuIdResult r7 = cpuid(7, 0);
    f.avx2      = (r7.ebx >> 5) & 1;
    f.bmi2      = (r7.ebx >> 8) & 1;
    f.avx512f   = (r7.ebx >> 16) & 1;
    f.avx512vl  = (r7.ebx >> 31) & 1;
    f.avx512bw  = (r7.ebx >> 30) & 1;
    f.avx512dq  = (r7.ecx >> 1) & 1;
    f.avx512vbmi = (r7.ecx >> 6) & 1;
    f.sha_ext   = (r7.ecx >> 29) & 1; // SHA extensions

    // Leaf 7, subleaf 1: More AVX-512
    CpuIdResult r7_1 = cpuid(7, 1);
    // Additional AVX-512 features here if needed

    // LZCNT: AMD feature, check via leaf 0x80000001
    CpuIdResult r8001 = cpuid(0x80000001);
    f.lzcnt = (r8001.ecx >> 27) & 1; // LZCNT (AMD) / BMI1 (Intel)

    // ARM64 features: detect via HWCAP (Linux) or sysctl (macOS)
#if defined(__aarch64__) || defined(__arm64__)
#  if defined(__linux__)
    unsigned long hwcap = 0;
    std::ifstream proc_cpuinfo("/proc/cpuinfo");
    std::string line;
    while (std::getline(proc_cpuinfo, line)) {
        if (line.rfind("Features", 0) == 0) {
            // Parse features from /proc/cpuinfo
            if (line.find("asimd") != std::string::npos) f.neon = true;
            if (line.find("sve") != std::string::npos) f.sve = true;
            if (line.find("crc32") != std::string::npos) f.crc32 = true;
            if (line.find("sha2") != std::string::npos) f.sha_ext = true;
            break;
        }
    }
#  elif defined(__APPLE__)
    // On Apple Silicon, NEON and CRC32 are always present
    f.neon = true;
    f.crc32 = true;
    f.sha_ext = true;
    // SVE not on Apple Silicon
#  endif
#endif

    return f;
}

// ──────────────────────────────────────────────────────────────
// CPU Topology
// ──────────────────────────────────────────────────────────────

struct Topology {
    int physical_cores = 0;
    int logical_cores = 0;
};

Topology detect_topology() {
    Topology t{};
#if defined(_WIN32)
    SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX* buffer = nullptr;
    DWORD length = 0;
    GetLogicalProcessorInformationEx(RelationProcessorCore, nullptr, &length);
    buffer = (SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX*)malloc(length);
    if (GetLogicalProcessorInformationEx(RelationProcessorCore, buffer, &length)) {
        BYTE* ptr = (BYTE*)buffer;
        BYTE* end = ptr + length;
        while (ptr < end) {
            auto* info = (SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX*)ptr;
            if (info->Relationship == RelationProcessorCore) {
                t.physical_cores++;
                // Count logical processors in this core
                DWORD mask = info->Processor.GroupMask[0].Mask;
                t.logical_cores += __popcnt(mask);
            }
            ptr += info->Size;
        }
    }
    free(buffer);
#elif defined(__APPLE__)
    int mib[2] = {CTL_HW, HW_PHYSICALCPU};
    size_t len = sizeof(t.physical_cores);
    sysctl(mib, 2, &t.physical_cores, &len, nullptr, 0);
    mib[1] = HW_LOGICALCPU;
    len = sizeof(t.logical_cores);
    sysctl(mib, 2, &t.logical_cores, &len, nullptr, 0);
#else
    // Linux: parse /proc/cpuinfo
    std::ifstream cpuinfo("/proc/cpuinfo");
    std::string line;
    std::vector<int> core_ids;
    int physical_id = -1, core_id = -1;
    int logical = 0;

    while (std::getline(cpuinfo, line)) {
        if (line.rfind("processor", 0) == 0) logical++;
        else if (line.rfind("physical id", 0) == 0) {
            physical_id = std::stoi(line.substr(line.find(':') + 1));
        }
        else if (line.rfind("core id", 0) == 0) {
            core_id = std::stoi(line.substr(line.find(':') + 1));
            if (physical_id >= 0) {
                int combined = (physical_id << 16) | core_id;
                if (std::find(core_ids.begin(), core_ids.end(), combined) == core_ids.end()) {
                    core_ids.push_back(combined);
                }
            }
        }
    }
    t.physical_cores = static_cast<int>(core_ids.size());
    t.logical_cores = logical;
    if (t.physical_cores == 0) t.physical_cores = t.logical_cores;
#endif
    return t;
}

// ──────────────────────────────────────────────────────────────
// Memory Info
// ──────────────────────────────────────────────────────────────

struct MemoryInfo {
    size_t total_mb = 0;
    size_t available_mb = 0;
};

MemoryInfo detect_memory() {
    MemoryInfo m{};
#if defined(_WIN32)
    MEMORYSTATUSEX mem{};
    mem.dwLength = sizeof(mem);
    if (GlobalMemoryStatusEx(&mem)) {
        m.total_mb = static_cast<size_t>(mem.ullTotalPhys / (1024 * 1024));
        m.available_mb = static_cast<size_t>(mem.ullAvailPhys / (1024 * 1024));
    }
#elif defined(__APPLE__)
    int mib[2] = {CTL_HW, HW_MEMSIZE};
    uint64_t total = 0;
    size_t len = sizeof(total);
    sysctl(mib, 2, &total, &len, nullptr, 0);
    m.total_mb = static_cast<size_t>(total / (1024 * 1024));

    // Available memory via mach
    mach_msg_type_number_t count = HOST_VM_INFO_COUNT;
    vm_statistics_data_t vmstat;
    if (host_statistics(mach_host_self(), HOST_VM_INFO, (host_info_t)&vmstat, &count) == KERN_SUCCESS) {
        m.available_mb = static_cast<size_t>(vmstat.free_count * 4096 / (1024 * 1024));
    } else {
        m.available_mb = m.total_mb;
    }
#else
    struct sysinfo si;
    if (sysinfo(&si) == 0) {
        m.total_mb = static_cast<size_t>(si.totalram * si.mem_unit / (1024 * 1024));
        m.available_mb = static_cast<size_t>(si.freeram * si.mem_unit / (1024 * 1024));
    }
#endif
    return m;
}

// ──────────────────────────────────────────────────────────────
// Thermal Headroom (Mobile)
// ──────────────────────────────────────────────────────────────

float detect_thermal_headroom() {
    // Default: 1.0 = unknown/desktop (no throttling expected)
    float headroom = 1.0f;

#if defined(__linux__)
    // Try Android thermal API first
    std::ifstream thermal("/sys/class/thermal/thermal_zone0/temp");
    if (thermal) {
        long temp_millicelsius = 0;
        thermal >> temp_millicelsius;
        float temp_c = temp_millicelsius / 1000.0f;
        // Assume throttle at 80°C, critical at 90°C
        if (temp_c >= 80.0f) headroom = 0.0f;
        else if (temp_c >= 60.0f) headroom = (80.0f - temp_c) / 20.0f;
    }
    // Also check for trip points
    for (int i = 0; i < 10; ++i) {
        std::string path = "/sys/class/thermal/thermal_zone" + std::to_string(i) + "/trip_point_0_temp";
        std::ifstream trip(path);
        if (trip) {
            long trip_temp = 0;
            trip >> trip_temp;
            if (trip_temp > 0) {
                // Found a trip point, use it
                break;
            }
        }
    }
#elif defined(__APPLE__)
    // iOS/macOS: use IOKit or thermal state (requires linking)
    // For now, assume desktop = 1.0
    // On iOS, would use NSProcessInfo.thermalState
#endif

    return headroom;
}

} // anonymous namespace

// ──────────────────────────────────────────────────────────────
// Public API
// ──────────────────────────────────────────────────────────────

HardwareCaps probe_hardware() {
    HardwareCaps caps{};

    // CPU topology
    Topology topo = detect_topology();
    caps.physical_cores = topo.physical_cores;
    caps.logical_cores = topo.logical_cores;

    // Cache hierarchy
    CacheInfo cache = parse_cache_info();
    caps.l1_cache_kb = cache.l1_kb;
    caps.l2_cache_kb = cache.l2_kb;
    caps.l3_cache_kb = cache.l3_kb;

    // ISA features
    Features feat = detect_features();
    caps.has_avx2 = feat.avx2;
    caps.has_avx512f = feat.avx512f;
    caps.has_avx512vl = feat.avx512vl;
    caps.has_avx512bw = feat.avx512bw;
    caps.has_avx512dq = feat.avx512dq;
    caps.has_avx512vbmi = feat.avx512vbmi;
    caps.has_neon = feat.neon;
    caps.has_sve = feat.sve;
    caps.has_bmi2 = feat.bmi2;
    caps.has_popcnt = feat.popcnt;
    caps.has_lzcnt = feat.lzcnt;
    caps.has_crc32 = feat.crc32;
    caps.has_sha_ext = feat.sha_ext;

    // Memory
    MemoryInfo mem = detect_memory();
    caps.total_ram_mb = mem.total_mb;
    caps.available_ram_mb = mem.available_mb;

    // Thermal
    caps.thermal_headroom = detect_thermal_headroom();

    return caps;
}

// C API wrapper
extern "C" {

mapr_result_t mapr_probe_hardware(mapr_hw_caps_handle_t* out_caps) {
    if (!out_caps) return MAPR_ERR_INVALID_ARG;

    mapr::HardwareCaps caps = probe_hardware();

    // Allocate the handle
    *out_caps = new mapr_hw_caps_s();
    (*out_caps)->caps.physical_cores = caps.physical_cores;
    (*out_caps)->caps.logical_cores = caps.logical_cores;
    (*out_caps)->caps.l1_cache_kb = caps.l1_cache_kb;
    (*out_caps)->caps.l2_cache_kb = caps.l2_cache_kb;
    (*out_caps)->caps.l3_cache_kb = caps.l3_cache_kb;
    (*out_caps)->caps.has_avx2 = caps.has_avx2;
    (*out_caps)->caps.has_avx512f = caps.has_avx512f;
    (*out_caps)->caps.has_avx512vl = caps.has_avx512vl;
    (*out_caps)->caps.has_avx512bw = caps.has_avx512bw;
    (*out_caps)->caps.has_avx512dq = caps.has_avx512dq;
    (*out_caps)->caps.has_avx512vbmi = caps.has_avx512vbmi;
    (*out_caps)->caps.has_neon = caps.has_neon;
    (*out_caps)->caps.has_sve = caps.has_sve;
    (*out_caps)->caps.has_bmi2 = caps.has_bmi2;
    (*out_caps)->caps.has_popcnt = caps.has_popcnt;
    (*out_caps)->caps.has_lzcnt = caps.has_lzcnt;
    (*out_caps)->caps.has_crc32 = caps.has_crc32;
    (*out_caps)->caps.has_sha_ext = caps.has_sha_ext;
    (*out_caps)->caps.total_ram_mb = caps.total_ram_mb;
    (*out_caps)->caps.available_ram_mb = caps.available_ram_mb;
    (*out_caps)->caps.thermal_headroom = caps.thermal_headroom;

    return MAPR_OK;
}

mapr_result_t mapr_free_hw_caps(mapr_hw_caps_handle_t caps) {
    if (!caps) return MAPR_OK;
    delete caps;
    return MAPR_OK;
}

} // extern "C"

} // namespace mapr