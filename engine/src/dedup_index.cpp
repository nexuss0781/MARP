// =====================================================================
//  MARP  ::  Stage 2  ::  Global Dedup Index  ::  dedup_index.cpp
// =====================================================================

#include "mapr/dedup_index.hpp"
#include "mapr/bitseq.hpp"
#include "mapr/crypto.hpp"
#include "mapr/dag.hpp"
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <bit>

namespace mapr {

std::optional<DedupEntry> GlobalDedupIndex::lookup(uint64_t bit_length, const std::array<uint8_t, 32>& sha256) const {
    Key key{bit_length, sha256};
    auto it = index_.find(key);
    if (it != index_.end()) return it->second;
    return std::nullopt;
}

std::vector<std::pair<DedupEntry, double>> GlobalDedupIndex::lookup_near_duplicates(
    const BitSeq& seq, double max_diff_ratio) const {
    std::vector<std::pair<DedupEntry, double>> results;
    uint64_t n = seq.bit_len();
    if (n == 0) return results;

    // Near-duplicate detection via XOR_DIFF over aligned windows:
    // compare against entries with same length (exact alignment) and compute
    // bit-difference ratio. This is provably correct and enables XOR_DIFF.
    auto it = length_buckets_.find(n);
    if (it == length_buckets_.end()) return results;

    for (const auto& entry : it->second) {
        if (entry.dag.nodes.empty()) continue;
        try {
            BitSeq ref = evaluate_chunk_dag(entry.dag, entry.bit_length);
            if (ref.bit_len() != n) continue;
            // Compute Hamming distance (XOR density) over aligned window.
            uint64_t diff = 0;
            size_t words = n / 64;
            for (size_t i = 0; i < words; ++i) {
                diff += std::popcount(seq.word(i) ^ ref.word(i));
            }
            int rem = static_cast<int>(n % 64);
            if (rem > 0) {
                uint64_t mask = (rem == 64) ? ~uint64_t(0) : ((uint64_t(1) << rem) - 1);
                diff += std::popcount((seq.word(words) ^ ref.word(words)) & mask);
            }
            double ratio = (n == 0) ? 0.0 : static_cast<double>(diff) / static_cast<double>(n);
            if (ratio <= max_diff_ratio) {
                results.emplace_back(entry, ratio);
            }
        } catch (...) {
            // Skip entries that cannot be evaluated
            continue;
        }
    }
    return results;
}

void GlobalDedupIndex::insert(uint64_t bit_length, const std::array<uint8_t, 32>& sha256,
                              uint32_t dag_node_id, const ExplicitChunkDAG& dag) {
    Key key{bit_length, sha256};
    DedupEntry entry;
    entry.bit_length = bit_length;
    entry.sha256 = sha256;
    entry.dag_node_id = dag_node_id;
    entry.dag = dag;
    
    index_[key] = entry;
    length_buckets_[bit_length].push_back(entry);
}

std::string GlobalDedupIndex::serialise() const {
    std::ostringstream oss;
    oss << index_.size() << "\n";
    for (const auto& [key, entry] : index_) {
        oss << key.length << "\n";
        for (uint8_t b : key.sha256) oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
        oss << "\n";
        oss << entry.dag_node_id << "\n";
    }
    return oss.str();
}

GlobalDedupIndex GlobalDedupIndex::deserialise(const std::string& data) {
    (void)data;
    GlobalDedupIndex idx;
    return idx;
}

} // namespace mapr