#pragma once

#include "mapr/bitseq.hpp"
#include "mapr/common.hpp"
#include "mapr/container.hpp"
#include "mapr/dag.hpp"
#include <cstdint>
#include <string>

namespace mapr {

struct EncodeStats {
    uint64_t input_bits = 0;
    uint64_t output_bytes = 0;
    uint64_t chunk_count = 0;
    uint64_t chunk_ref_count = 0;
    double wall_seconds = 0.0;
    double peak_rss_mb = 0.0;
    std::string stream_sha256_hex;
};

// Pure stateless Meso/Micro chunk DAG synthesizer (thread-safe, deterministic)
ExplicitChunkDAG encode_chunk_dag(const BitSeq& seq, bool allow_interleave = true);

// Partition an in-memory BitSeq into deterministic synchronizing superchunks
std::vector<std::pair<uint64_t, uint64_t>> synchronize_partition(
    const BitSeq& seq, const StreamConfig& cfg = StreamConfig{});

// Encode an arbitrary in-memory BitSeq to a `.mapr` v1.0 file
EncodeStats encode_bitseq_to_file(
    const BitSeq& seq,
    const std::string& out_mapr_path,
    bool raw_bytes_mode = false,
    unsigned num_threads = 1,
    const StreamConfig& cfg = StreamConfig{});

// True bounded-RAM single-pass streaming encoder for arbitrarily large raw byte files (e.g. multi-GB .zip)
EncodeStats encode_raw_file_streaming(
    const std::string& in_raw_path,
    const std::string& out_mapr_path,
    unsigned num_threads = 2,
    const StreamConfig& cfg = StreamConfig{});

} // namespace mapr
