#pragma once

#include "mapr/bitseq.hpp"
#include "mapr/dag.hpp"
#include "mapr/simd/dispatch.hpp"

#include <cstdint>
#include <utility>
#include <vector>

namespace mapr {

// 128-bit chunk key for V_4 signature matching
struct ChunkKey128 {
    uint64_t h1 = 0;
    uint64_t h2 = 0;
    uint64_t bit_len = 0;

    bool operator==(const ChunkKey128& other) const noexcept {
        return h1 == other.h1 && h2 == other.h2 && bit_len == other.bit_len;
    }
};

struct ChunkKey128Hash {
    size_t operator()(const ChunkKey128& k) const noexcept {
        return static_cast<size_t>(k.h1 ^ splitmix64(k.h2 ^ k.bit_len));
    }
};

// Compute V_4 canonical signature for cross-chunk matching
// Returns (canonical_key, operation_to_reach_canonical)
inline std::pair<ChunkKey128, V4Op> compute_chunk_v4_signature(const BitSeq& seq) {
    auto hash_seq = [](const BitSeq& s) -> std::pair<uint64_t, uint64_t> {
        uint64_t a = splitmix64(s.bit_len() ^ 0xA5A5A5A5A5A5A5A5ULL);
        uint64_t b = splitmix64(s.bit_len() ^ 0x5A5A5A5A5A5A5A5AULL);
        for (size_t i = 0; i < s.word_count(); ++i) {
            a = splitmix64(a ^ s.word(i));
            b = splitmix64(b + (s.word(i) ^ static_cast<uint64_t>(i)));
        }
        return {a, b};
    };

    V4Op best_op = V4Op::ID;
    BitSeq best_seq = seq;
    {
        BitSeq s_not = seq.bitwise_not();
        if (s_not.lex_less(best_seq)) { best_seq = ::std::move(s_not); best_op = V4Op::NOT; }
    }
    {
        BitSeq s_rev = seq.reverse_bits();
        BitSeq s_rn = s_rev.bitwise_not();
        if (s_rev.lex_less(best_seq)) { best_seq = ::std::move(s_rev); best_op = V4Op::REV; }
        if (s_rn.lex_less(best_seq))  { best_seq = ::std::move(s_rn);  best_op = V4Op::REV_NOT; }
    }
    auto [h1, h2] = hash_seq(best_seq);
    return {ChunkKey128{h1, h2, seq.bit_len()}, best_op};
}

} // namespace mapr