#pragma once

// Internal header for MAPR implementation - not for public use
#include "mapr/encoder.hpp"
#include "mapr/decoder.hpp"
#include "mapr/container.hpp"
#include "mapr/hwprobe.hpp"
#include "mapr/profile.hpp"
#include "mapr/thread_pool.hpp"
#include "mapr/bitseq.hpp"
#include "mapr/crypto.hpp"
#include "mapr/simd/dispatch.hpp"
#include "mapr/pipeline.hpp"

#include <memory>
#include <string>
#include <vector>

// ──────────────────────────────────────────────────────────────
// Helper: Convert EncodeConfig to StreamConfig
// ──────────────────────────────────────────────────────────────

inline mapr::StreamConfig to_stream_config(const mapr::EncodeConfig& cfg) {
    mapr::StreamConfig sc;
    sc.w_sync = 64;
    sc.l_min = 262144;
    sc.l_target = 1048576;
    sc.l_max = 4194304;
    sc.w_hist = static_cast<uint32_t>(cfg.max_history_window);
    return sc;
}

// ──────────────────────────────────────────────────────────────
// Opaque Handle Implementations (global namespace for C API)
// ──────────────────────────────────────────────────────────────

struct mapr_encoder_s {
    mapr::EncodeConfig config;
    mapr::ThreadPool pool;
    mapr_encoder_s(const mapr::EncodeConfig& cfg) : config(cfg), pool(static_cast<size_t>(cfg.threads)) {}
};

struct mapr_decoder_s {
    struct DecodeConfig {
        int threads = 1;
        bool verify_sha256 = true;
    } config;
    mapr::ThreadPool pool;
    mapr_decoder_s(int threads, bool verify_sha256)
        : config{threads, verify_sha256}, pool(static_cast<size_t>(threads)) {}
};

struct mapr_stream_encoder_s {
    mapr::EncodeConfig config;
    mapr::StreamConfig stream_config;
    std::unique_ptr<std::vector<uint8_t>> output_buffer;
    std::unique_ptr<mapr::ContainerWriter> writer;
    std::unique_ptr<mapr::BoundedChunkPipeline> pipeline;
    mapr::Sha256 sha;
    std::vector<uint64_t> wbuf;
    uint64_t buf_bit_start = 0;
    uint64_t buf_bit_len = 0;
    uint64_t total_input_bits = 0;
    uint64_t sync_mask = 0;
    bool finished = false;

    mapr_stream_encoder_s(const mapr::EncodeConfig& cfg)
        : config(cfg), stream_config(to_stream_config(cfg)) {}
};

struct mapr_stream_decoder_s {
    // Not implemented yet
};

struct mapr_hw_caps_s {
    mapr::HardwareCaps caps;
};

namespace mapr {

// Re-export for internal use
using ::mapr_encoder_s;
using ::mapr_decoder_s;
using ::mapr_stream_encoder_s;
using ::mapr_stream_decoder_s;
using ::mapr_hw_caps_s;

} // namespace mapr