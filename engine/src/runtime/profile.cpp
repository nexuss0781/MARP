#include "mapr/profile.hpp"

#include <algorithm>
#include <cmath>

namespace mapr {

EncodeConfig select_config(Profile profile, const HardwareCaps& hw,
                           uint64_t file_bits, double time_budget_sec) {
    EncodeConfig cfg;

    switch (profile) {
        case Profile::FAST:
            cfg = make_fast_config(hw, 0);
            break;
        case Profile::BALANCED:
            cfg = make_balanced_config(hw, 0);
            break;
        case Profile::THOROUGH:
            cfg = make_thorough_config(hw, 0);
            break;
        case Profile::MAX:
            cfg = make_max_config(hw, 0);
            break;
    }

    // Apply user overrides
    if (time_budget_sec > 0) cfg.time_budget_sec = time_budget_sec;

    // Apply resource limits (threads, memory)
    apply_resource_limits(cfg, hw);

    return cfg;
}

EncodeConfig make_fast_config(const HardwareCaps& hw, int threads) {
    EncodeConfig cfg;
    cfg.enable_lfsr_detection = false;
    cfg.enable_interleave = false;
    cfg.enable_xor_diff = false;
    cfg.enable_morphic_lifting = false;
    cfg.morphic_lift_rounds = 0;
    cfg.max_history_window = 16;
    cfg.minimizer_radius = 32;
    cfg.enable_periodicity = true;
    cfg.max_period = 4096;
    cfg.threads = threads;
    cfg.max_memory_mb = 0;
    return cfg;
}

EncodeConfig make_balanced_config(const HardwareCaps& hw, int threads) {
    EncodeConfig cfg;
    cfg.enable_lfsr_detection = true;
    cfg.enable_interleave = true;
    cfg.enable_xor_diff = true;
    cfg.enable_morphic_lifting = true;
    cfg.morphic_lift_rounds = 4;
    cfg.max_history_window = 32;
    cfg.minimizer_radius = 48;
    cfg.enable_periodicity = true;
    cfg.max_period = 16384;
    cfg.threads = threads;
    cfg.max_memory_mb = 0;
    return cfg;
}

EncodeConfig make_thorough_config(const HardwareCaps& hw, int threads) {
    EncodeConfig cfg;
    cfg.enable_lfsr_detection = true;
    cfg.enable_interleave = true;
    cfg.enable_xor_diff = true;
    cfg.enable_morphic_lifting = true;
    cfg.morphic_lift_rounds = 8;
    cfg.max_history_window = 64;
    cfg.minimizer_radius = 64;
    cfg.enable_periodicity = true;
    cfg.max_period = 16384;
    cfg.threads = threads;
    cfg.max_memory_mb = 0;
    return cfg;
}

EncodeConfig make_max_config(const HardwareCaps& hw, int threads) {
    EncodeConfig cfg;
    cfg.enable_lfsr_detection = true;
    cfg.enable_interleave = true;
    cfg.enable_xor_diff = true;
    cfg.enable_morphic_lifting = true;
    cfg.morphic_lift_rounds = 24;
    cfg.max_history_window = 64;
    cfg.minimizer_radius = 128;
    cfg.enable_periodicity = true;
    cfg.max_period = 65536;
    cfg.threads = threads;
    cfg.max_memory_mb = 0;
    return cfg;
}

void apply_resource_limits(EncodeConfig& cfg, const HardwareCaps& hw) {
    // Thread count: use physical cores by default
    if (cfg.threads <= 0) {
        cfg.threads = std::max(1, hw.physical_cores);
    }

    // Cap threads to logical cores
    cfg.threads = std::min(cfg.threads, hw.logical_cores);

    // Memory budget: 25% of available RAM, capped at 256 MB
    if (cfg.max_memory_mb == 0) {
        cfg.max_memory_mb = std::min<size_t>(hw.available_ram_mb / 4, 256);
        cfg.max_memory_mb = std::max<size_t>(cfg.max_memory_mb, 8); // minimum 8 MB
    }

    // Time budget: if set, adjust profile downward if needed
    if (cfg.time_budget_sec > 0) {
        // Estimate time per GB based on profile
        double est_sec_per_gb = 0;
        if (cfg.enable_lfsr_detection && cfg.enable_interleave && cfg.enable_xor_diff && cfg.morphic_lift_rounds >= 8) {
            est_sec_per_gb = 30.0; // THOROUGH/MAX
        } else if (cfg.enable_lfsr_detection || cfg.enable_interleave || cfg.enable_xor_diff) {
            est_sec_per_gb = 15.0; // BALANCED
        } else {
            est_sec_per_gb = 5.0;  // FAST
        }

        // Estimate file size in GB
        double file_gb = 1.0; // default assumption
        // In practice, we'd pass file size here

        if (est_sec_per_gb * file_gb > cfg.time_budget_sec * 0.8) {
            // Downgrade profile
            if (cfg.morphic_lift_rounds > 4) {
                cfg.morphic_lift_rounds = 4;
                cfg.enable_xor_diff = false;
            }
            if (cfg.morphic_lift_rounds > 0 && est_sec_per_gb * file_gb > cfg.time_budget_sec * 0.8) {
                cfg.enable_interleave = false;
                cfg.morphic_lift_rounds = 0;
            }
            if (cfg.enable_lfsr_detection && est_sec_per_gb * file_gb > cfg.time_budget_sec * 0.8) {
                cfg.enable_lfsr_detection = false;
            }
        }
    }

    // Thermal throttling: reduce intensity on mobile
    if (hw.thermal_headroom < 0.5f) {
        cfg.morphic_lift_rounds = std::min(cfg.morphic_lift_rounds, 2);
        cfg.max_history_window = std::min(cfg.max_history_window, static_cast<size_t>(16));
        cfg.threads = std::max(1, cfg.threads / 2);
    }
}

} // namespace mapr