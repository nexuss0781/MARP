// =====================================================================
//  MARP  ::  Stage 2  ::  Global Dedup Index  ::  dedup_index.hpp
//
//  Cross-file / cross-chunk content-addressed deduplication.
//  Key: (bit_length, sha256). Near-duplicate via XOR_DIFF over aligned windows.
// =====================================================================

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <optional>
#include "mapr/bitseq.hpp"
#include "mapr/dag.hpp"

namespace mapr {

struct DedupEntry {
    uint64_t bit_length = 0;
    std::array<uint8_t, 32> sha256;
    uint32_t dag_node_id = 0;
    ExplicitChunkDAG dag;
};

class GlobalDedupIndex {
public:
    GlobalDedupIndex() = default;

    std::optional<DedupEntry> lookup(uint64_t bit_length, const std::array<uint8_t, 32>& sha256) const;

    std::vector<std::pair<DedupEntry, double>> lookup_near_duplicates(
        const BitSeq& seq, double max_diff_ratio = 0.05) const;

    void insert(uint64_t bit_length, const std::array<uint8_t, 32>& sha256,
                uint32_t dag_node_id, const ExplicitChunkDAG& dag);

    std::string serialise() const;
    static GlobalDedupIndex deserialise(const std::string& data);

    size_t size() const { return index_.size(); }

private:
    struct Key {
        uint64_t length;
        std::array<uint8_t, 32> sha256;
        bool operator==(const Key& o) const noexcept {
            return length == o.length && sha256 == o.sha256;
        }
    };

    struct KeyHash {
        size_t operator()(const Key& k) const noexcept {
            size_t h = k.length;
            for (uint8_t b : k.sha256) h = h * 31 + b;
            return h;
        }
    };

    std::unordered_map<Key, DedupEntry, KeyHash> index_;
    std::unordered_map<uint64_t, std::vector<DedupEntry>> length_buckets_;
};

} // namespace mapr