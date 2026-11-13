#pragma once

#include "mapr/common.hpp"
#include "mapr/crypto.hpp"
#include "mapr/dag.hpp"
#include <array>
#include <cstdint>
#include <fstream>
#include <string>
#include <vector>

namespace mapr {

inline constexpr uint8_t MAPR_MAGIC[8] = {0x89u, 'M', 'A', 'P', 'R', 0x0Du, 0x0Au, 0x1Au};
inline constexpr uint32_t FLAG_RAW_BYTES_MSB   = 0x00000001u;
inline constexpr uint32_t FLAG_HAS_INDEX       = 0x00000002u;
inline constexpr uint32_t FLAG_STREAMED_HEADER = 0x00000004u;

inline constexpr uint8_t KIND_CHUNK_REF    = 0x00u;
inline constexpr uint8_t KIND_EXPLICIT_DAG = 0x01u;

struct IndexEntry {
    uint64_t file_offset = 0;
    uint64_t bit_offset = 0;
    uint32_t bit_len = 0;
    uint32_t frame_bytes = 0;
    uint32_t ref_target = 0;
    uint8_t chunk_kind = 0;
    uint8_t v4_op = 0;
};

struct ContainerMetadata {
    uint16_t version_major = 1;
    uint16_t version_minor = 0;
    uint32_t flags = 0;
    uint64_t total_bits = 0;
    uint64_t chunk_count = 0;
    StreamConfig config{};
    uint64_t index_offset = 0;
    std::array<uint8_t, 32> stream_sha256{};
    std::vector<IndexEntry> index;
};

// Single-pass streaming writer for `.mapr` v1.0
class ContainerWriter {
public:
    // File output constructor
    ContainerWriter(const std::string& path, const StreamConfig& cfg, bool raw_bytes_mode);

    // Memory buffer output constructor
    ContainerWriter(std::vector<uint8_t>& out_buffer, const StreamConfig& cfg, bool raw_bytes_mode);

    void write_chunk_ref(uint32_t chunk_idx, uint64_t bit_offset, uint32_t bit_len,
                         uint32_t ref_target, V4Op mu);

    void write_explicit_dag(uint32_t chunk_idx, uint64_t bit_offset, uint32_t bit_len,
                            const std::vector<uint8_t>& serialized_dag_payload);

    uint64_t finish(uint64_t total_bits, const std::array<uint8_t, 32>& stream_sha256);

private:
    void write_header_block(uint64_t total_bits, uint64_t chunk_count,
                            uint64_t index_offset, bool streamed_flag);
    void write_bytes(const void* data, size_t size);

    std::ofstream out_file_;
    std::vector<uint8_t>* out_buffer_ = nullptr;
    StreamConfig cfg_;
    uint32_t base_flags_ = 0;
    uint64_t cur_offset_ = 0;
    std::vector<IndexEntry> index_;
};

// Independent multi-layer container reader & verifier
class ContainerReader {
public:
    explicit ContainerReader(const std::string& path);

    const ContainerMetadata& meta() const noexcept { return meta_; }
    uint64_t file_size() const noexcept { return file_size_; }

    struct ChunkFrame {
        uint32_t chunk_index = 0;
        uint64_t bit_offset = 0;
        uint32_t bit_len = 0;
        uint8_t chunk_kind = 0;
        V4Op v4_op = V4Op::ID;
        uint32_t ref_target = 0;
        ExplicitChunkDAG dag;
    };

    ChunkFrame read_chunk(uint64_t chunk_idx);

private:
    void parse_and_verify_structure();

    std::ifstream in_;
    uint64_t file_size_ = 0;
    ContainerMetadata meta_;
};

} // namespace mapr
