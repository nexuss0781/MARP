// MARP v2 — E0 HARNESS — H4 `FUZZ`
//
// Mutation campaign over valid v2 containers (SPECS/SPECS-V2.md §12.8,
// SPECS/COMPONENTS-V2.md H4).
//
// H4 is a *measurement instrument*: it produces mutants of valid canonical v2
// containers, feeds every mutant to C07's two acceptance surfaces — `validate`
// (the verify path) and `decode` (the decode path) — and counts what escapes.
// It never changes E1–E7 semantics, never normalises a wire, and never narrows
// the mutation classes to make a count look better.
//
// Normative targets (§12.8): over 100,000 mutants,
//     accepted_invalid = 0, crashes = 0, timeouts = 0.
//
// The `marp::harness::fuzz` signature is the one SPECS/COMPONENTS-V2.md H4
// pins.  The richer `run_fuzz` surface exists because a campaign that is
// evidence, not an anecdote, must also record the seed identities, the class
// mix, the rejection stages, the per-mutant resource bounds and the
// determinism check — none of which fit in a five-field struct.
//
// Seeds are *E3 outputs*: each seed wire is produced by C07's `encode` from an
// E2 canonical term of the E3-G corpus and is admitted only when its SHA-256
// and byte count equal the identity E3-G committed in
// `specs_and_reports/v2/corpus/E3/corpus.tsv`.  A seed that does not reproduce
// its committed digest is a hard failure, never a silently skipped seed.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace marp::harness {

using u64 = std::uint64_t;

// §12.8's counts.  `total` is the campaign size; `valid` counts mutants that
// both surfaces accepted *and* whose decoded `Ir` re-encodes to the mutant
// byte-for-byte (a genuinely canonical container).  Every mutant falls in
// exactly one of `valid`, `accepted_invalid`, `crashes`, `timeouts` — the
// remaining mutants are rejections and are reported as `rejected` in the
// detailed surface so `valid + rejected + crashes + timeouts == total`.
struct FuzzCounts {
    u64 total = 0;
    u64 accepted_invalid = 0;
    u64 crashes = 0;
    u64 timeouts = 0;
    u64 valid = 0;
};

// The four mutation classes §12.8 names.  No other classification is used and
// no class is optional: every class must appear in the campaign.
enum class MutationClass : std::uint8_t {
    BitFlip = 0,           // bit flips
    Truncation = 1,        // truncation
    FieldSwap = 2,         // field swaps
    LengthCorruption = 3,  // length / count / offset corruption
};

const char* mutation_class_name(MutationClass cls) noexcept;

// One seed wire.  `e3_item` is the E3-G corpus id it reproduces (empty when the
// seed is an H4-derived canonical container, which the campaign does not use);
// `sha256` is the lowercase hex digest of `wire`.
struct SeedInfo {
    std::string id;
    std::string e3_item;
    std::string source;   // "E3-G:W-CANON" / "E3-G:W-CANON-EDGE"
    std::vector<std::uint8_t> wire;
    std::string sha256;
    bool index_present = false;
    bool large = false;   // header/index/trailer-targeted mutation only
};

// Campaign configuration.  Every field is recorded in the evidence so a run is
// reproducible from its own TSV.
struct FuzzConfig {
    u64 mutants = 100'000;
    u64 seed = 0x4834'4655'5A5Aull;              // campaign PRNG seed
    unsigned workers = 1;                        // shard processes
    unsigned long per_mutant_timeout_ms = 5'000; // §12.8 bounded run
    u64 alloc_budget_bytes = 64ull << 20;        // O7.10-style per-mutant budget
    bool fork_workers = false;                   // child-process isolation
    bool verify_fixpoint = true;                 // canonical re-encode of accepts
    unsigned long total_timeout_ms = 600'000;    // whole-campaign safety bound
};

// Detailed tally.  Arrays are indexed by `MutationClass` cast to size_t and by
// C07 `Stage` (0 = None, 1..11 per E3 §5.1, 12 = beyond).
struct FuzzTally {
    std::array<u64, 4> by_class{};
    std::vector<u64> by_seed;
    std::array<u64, 13> validate_stage{};
    std::array<u64, 13> decode_stage{};
    u64 region_header = 0;
    u64 region_index = 0;
    u64 region_trailer = 0;
    u64 region_body = 0;
    u64 rejected = 0;
    u64 verified = 0;            // validate() accepted
    u64 decode_accepted = 0;     // decode() accepted
    u64 fixpoint_checked = 0;
    u64 fixpoint_mismatch = 0;
    u64 processed = 0;           // mutants that reached a verdict
    u64 alloc_violations = 0;
    u64 peak_alloc_bytes = 0;
    u64 slowest_us = 0;          // measurement, never committed as evidence
    u64 first_failure_index = 0;
    std::string first_failure;   // empty when the campaign is clean
    std::string first_failure_kind;

    bool clean() const noexcept;
};

struct FuzzReport {
    FuzzCounts counts;
    FuzzTally tally;
    bool completed = false;   // every mutant reached a verdict
    bool prng_ok = true;
    std::string failure;      // non-empty when the campaign could not complete

    bool targets_met() const noexcept;
};

// SPECS/COMPONENTS-V2.md H4 surface: `fuzz(seeds, mutants, seed)`.
//
// `seeds` is a directory of seed wires named `<id>.wire`; the directory is
// produced by the H4 seed builder (and its identity is committed), never
// assembled by hand.  The call runs a single-process campaign with the
// documented default bounds and returns §12.8's counts.
FuzzCounts fuzz(const std::filesystem::path& seeds, u64 mutants, u64 seed);

// Reads every `*.wire` in `dir` in name order.  `manifest.tsv`, when present,
// supplies the E3 identity columns; it is informational and never overrides a
// digest computed from the bytes.
std::vector<SeedInfo> load_seeds(const std::filesystem::path& dir);

// Runs a campaign over `seeds`.  `config.mutants` must be > 0.  With
// `fork_workers` the index space is split into `workers` contiguous shards,
// each processed by a child process; a child that dies abnormally is a crash,
// and a shard whose progress stops advancing for
// `per_mutant_timeout_ms` is a timeout.  Without it the campaign runs
// in-process (the sanitizer and self-test path).
FuzzReport run_fuzz(const std::vector<SeedInfo>& seeds, const FuzzConfig& config);

// True when §12.8's three hard targets hold and every mutant is accounted for.
bool targets_met(const FuzzCounts& counts) noexcept;

}  // namespace marp::harness
