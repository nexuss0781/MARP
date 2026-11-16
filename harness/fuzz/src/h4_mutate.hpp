// MARP v2 — H4 FUZZ — mutation planning (internal).
//
// One mutant is a pure function of (seed bytes, seed index, mutation class,
// global mutant index, campaign seed).  Nothing is drawn from a clock, the
// environment, the locale, or the order in which workers happen to run: the
// same (campaign seed, index) plans byte-identical mutations in every worker
// count, which is what makes a worker-count comparison a real determinism
// check rather than a scheduling coincidence.
//
// A mutation is expressed as a bounded byte-level edit of the seed:
//   * `changes` — final byte values at absolute offsets (last write wins);
//   * `size` — the mutant's length, smaller than the seed's for truncation;
//   * `repair_outer_crcs` — recompute the header file CRC and the trailer CRC
//     over the *mutated* bytes, so the mutant is not rejected by stage 4/5 for
//     the wrong reason.  Half of the mutants keep the stale CRCs, so both
//     families are exercised.
//
// Large seeds are never fully rewritten by an in-place mutation: their
// mutations target the header, the trailer and the index region only, exactly
// as §12.8 allows ("header/index mutations of large containers ... bounded
// handling suffices").
#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <utility>
#include <vector>

#include "marp/harness/h4_fuzz.hpp"

namespace marp::harness::h4 {

using u8 = std::uint8_t;

// splitmix64: a fixed, platform-independent bit generator (no <random>).
class SplitMix64 {
public:
    explicit SplitMix64(u64 state) : state_(state) {}

    u64 next() noexcept {
        state_ += 0x9E3779B97F4A7C15ull;
        u64 z = state_;
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
        return z ^ (z >> 31);
    }

    // Uniform-enough bounded draw; `bound > 0` is a precondition.
    std::size_t below(std::size_t bound) noexcept {
        return static_cast<std::size_t>(next() % static_cast<u64>(bound));
    }

private:
    u64 state_;
};

// Byte layout of a seed container, derived from its own header (E3 §4.2).
struct SeedLayout {
    std::size_t size = 0;
    std::size_t trailer_offset = 0;  // size - TRAILER_BYTES for a valid seed
    std::size_t index_offset = 0;    // 0 when the index is absent
    bool index_present = false;
};

SeedLayout layout_of(const SeedInfo& seed);

struct Mutation {
    MutationClass cls = MutationClass::BitFlip;
    std::size_t seed_index = 0;
    std::size_t size = 0;                 // mutant length
    std::map<std::size_t, u8> changes;    // absolute offset -> final byte
    bool repair_outer_crcs = false;
    bool touched_header = false;
    bool touched_index = false;
    bool touched_trailer = false;
    bool touched_body = false;

    bool changed() const noexcept { return !changes.empty(); }
};

// Plans one mutation.  `index` is the global mutant index; it selects bytes
// inside the seed but never changes the class or the seed, which the caller
// derives from the same index.
Mutation plan_mutation(const SeedInfo& seed, std::size_t seed_index, MutationClass cls,
                       u64 index, u64 campaign_seed);

// Applies `changes` to a copy of `base`, resizes to `mutation.size`, and (when
// requested and the result is large enough) repairs the two outer CRCs.
std::vector<u8> materialize(const std::vector<u8>& base, const Mutation& mutation);

}  // namespace marp::harness::h4
