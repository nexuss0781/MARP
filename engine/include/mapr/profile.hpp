#pragma once

#include "mapr/hwprobe.hpp"
#include "mapr/common.hpp"
#include <cstdint>

namespace mapr {

enum class Profile : uint8_t {
    FAST      = 0,
    BALANCED  = 1,
    THOROUGH  = 2,
    MAX       = 3,
};

struct EncodeConfig {
    // Core algorithm toggles
    bool enable_lfsr_detection = true;
    bool enable_interleave = true;
    bool enable_xor_diff = true;
    bool enable_morphic_lifting = true;
    int  morphic_lift_rounds = 8;

    // History & anchoring
    size_t max_history_window = 64;
    size_t minimizer_radius = 64;

    // Periodicity detection
    bool enable_periodicity = true;
    size_t max_period = 16384;

    // Resource limits
    int threads = 0;              // 0 = auto
    size_t max_memory_mb = 0;     // 0 = auto
    double time_budget_sec = 0;   // 0 = no limit

    // Input mode
    bool raw_bytes_mode = false;
    bool compute_sha256 = true;
};

EncodeConfig select_config(Profile profile, const HardwareCaps& hw,
                           uint64_t file_bits = 0, double time_budget_sec = 0);

EncodeConfig make_fast_config(const HardwareCaps& hw, int threads);
EncodeConfig make_balanced_config(const HardwareCaps& hw, int threads);
EncodeConfig make_thorough_config(const HardwareCaps& hw, int threads);
EncodeConfig make_max_config(const HardwareCaps& hw, int threads);

void apply_resource_limits(EncodeConfig& cfg, const HardwareCaps& hw);

} // namespace mapr