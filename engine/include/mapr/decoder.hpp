#pragma once

#include "mapr/bitseq.hpp"
#include "mapr/container.hpp"
#include "mapr/dag.hpp"
#include <cstdint>
#include <string>

namespace mapr {

struct DecodeStats {
    uint64_t output_bits = 0;
    uint64_t output_bytes = 0;
    uint64_t chunk_count = 0;
    double wall_seconds = 0.0;
    double peak_rss_mb = 0.0;
    std::string stream_sha256_hex;
    bool sha256_verified = false;
};

// Decode `.mapr` v1.0 file into an in-memory BitSeq (verifying all CRCs, DAGs, and SHA-256)
std::pair<BitSeq, DecodeStats> decode_mapr_to_bitseq(
    const std::string& in_mapr_path, unsigned num_threads = 1);

// Bounded-RAM streaming decode of `.mapr` v1.0 file directly to raw byte output file (e.g. .zip)
DecodeStats decode_mapr_to_raw_file(
    const std::string& in_mapr_path,
    const std::string& out_raw_path,
    unsigned num_threads = 2);

// Full multi-layer structural inspection & 100% bit-accountability audit
struct FullInspectReport {
    ContainerMetadata meta;
    uint64_t file_size = 0;
    InspectionSummary summary;
};

FullInspectReport inspect_mapr_container(const std::string& in_mapr_path);

} // namespace mapr
