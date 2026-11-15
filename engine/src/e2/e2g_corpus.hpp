// MARP v2 — E2-G integrated ALGEBRA gate — deterministic corpus generation.
//
// Implements E2 §12.3 with the counts the spec pins:
//   T-KAT      128   pinned terms; every kind, every morph id with valid k,
//                    every predictor id with param edges, pinned LFSR vectors,
//                    empty term, one-byte atom, atom exactly ATOM_MAX,
//                    Interleave strides 1/2/3/7
//   T-GEN    5 000   seeded well-formed terms, depth 1..8, expansion <= 4 MiB,
//                    every kind at least 100 times
//   T-BIG       64   virtual terms; lengths above 2^40, never materialised
//   T-BAD       64   one term per violation
//   T-NONCANON 200   one term per rewrite redex (rules 1..13)
//   T-CRIT   1 000   pairs where two rules overlap, enumerated from local
//                    patterns of depth <= 4
//   M-KAT       96   pinned morph/predictor bytes
//   L-KAT       48   pinned LFSR vectors (8 (conn,init) pairs x 6 lengths)
//
// Every generator is a pure function of a recorded seed.  `corpus.tsv` records
// id, kind, length, seed and the SHA-256 of the canonical description.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "e2g_terms.hpp"

namespace e2g {

// Recorded generator seeds (§12.3 requires seeds in `corpus.tsv`).
struct CorpusSeeds {
    static constexpr u64 kGen = 0xE2A1'5EED'0001ull;
    static constexpr u64 kGenAtoms = 0xE2A1'5EED'0002ull;
    static constexpr u64 kBig = 0xE2A1'5EED'0003ull;
    static constexpr u64 kNonCanon = 0xE2A1'5EED'0004ull;
    static constexpr u64 kCrit = 0xE2A1'5EED'0005ull;
    static constexpr u64 kRange = 0xE2A1'5EED'0006ull;
    static constexpr u64 kOrder = 0xE2A1'5EED'0007ull;
};

// Seeded deterministic generator (xorshift64); the seed is recorded per corpus.
class Rng {
public:
    explicit Rng(u64 seed) : state_(seed == 0 ? 0x9E3779B97F4A7C15ull : seed), seed_(seed) {}

    u64 next() {
        u64 x = state_;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        state_ = x;
        return x;
    }

    u64 below(u64 bound) { return bound == 0 ? 0 : next() % bound; }
    u8 byte() { return static_cast<u8>(next() & 0xFFu); }
    bool coin() { return (next() & 1u) != 0u; }
    u64 seed() const { return seed_; }

private:
    u64 state_ = 0;
    u64 seed_ = 0;
};

// One corpus entry.
struct CorpusTerm {
    std::string id;
    std::string corpus;
    TermDesc desc;
    u64 seed = 0;
    // T-BAD only: the expected first-failure constraint identifier and code.
    const char* expected_constraint = "";
    Code expected_code = Code::Invalid;
    // T-NONCANON only: the rule (1..13) this term is a redex for.
    int redex_rule = 0;
    // T-CRIT only: the two overlapping rules.
    int crit_rule_a = 0;
    int crit_rule_b = 0;
    // T-CRIT only: the second member of the pair (empty for other corpora).
    TermDesc alt;
    std::string alt_root;
};

struct MorphKat {
    std::string id;
    u8 morph = 0;
    u8 k = 0;
    std::vector<u8> input;
    std::vector<u8> expected;
    bool involution = false;          // declared m(m(x)) == x
    bool rotation_composition = false;  // part of a rotation-composition triple
};

struct PredictorKat {
    std::string id;
    u8 pid = 0;
    u32 param = 0;
    std::vector<u8> residual;
    std::vector<u8> expected;
    bool param_edge = false;
};

struct LfsrKat {
    std::string id;
    u64 conn = 0;
    u64 init = 0;
    std::size_t length = 0;
    std::vector<u8> expected;
};

// The corpus bundle plus the pinned KAT tables.
struct Corpus {
    std::vector<CorpusTerm> terms;
    std::vector<MorphKat> morph_kats;
    std::vector<PredictorKat> predictor_kats;
    std::vector<LfsrKat> lfsr_kats;
};

Corpus build_corpus();

// Exact §4.4 length of a bound `Ir` node, recomputed from structure with the
// gate's own arithmetic path (used by the generator to enforce the 4 MiB cap).
BigInt ir_length(const Ir& ir, u32 node);

}  // namespace e2g
