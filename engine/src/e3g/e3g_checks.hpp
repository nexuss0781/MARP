// MARP v2 — E3 WIRE — E3-G integrated gate — wire-side checks (§13.4 steps 2–7, 9–11).
//
// This translation unit includes `mapr/e3/e3_wire.hpp` (C07) and nothing from
// C08.  The legacy half lives in `e3g_legacy_side.cpp`, which includes C08 and
// nothing from C07; the two are joined only through the plain-old-data interface
// in `e3g_legacy_side.hpp`.  The split is not cosmetic: `e3_wire.hpp` and
// `e3_legacy.hpp` are mutually exclusive in one translation unit (each defines
// the shared wire types under `MAPR_E3_WIRE_TYPES_DEFINED`, with different
// layouts for `WireCode`), and both define `HeapArena::store`, so one binary
// cannot link C07 and C08 objects as emitted.
#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include "e3g_corpus.hpp"
#include "e3g_oracle.hpp"
#include "e3g_support.hpp"

namespace e3g {

// Gate-wide settings.  Every value is recorded in the evidence, so a run is
// reproducible from its own TSV.
struct Settings {
    std::string root = ".";                       // repository root
    std::string oracle_path = "bin/mapr_oracle";  // H3 clean-room decoder
    std::string legacy_binary;                    // bin/e3g_legacy_half (C08 process)
    std::size_t fuzz_iterations = 100000;         // §13.4 step 7
    std::size_t fuzz_threads = 4;                 // recorded, not required
    unsigned fuzz_timeout_seconds = 10;           // §13.4 step 7
    std::size_t fuzz_alloc_budget_bytes = 64u << 20;  // O7.10 per-mutant budget
    std::vector<unsigned> thread_counts = {1, 4};  // §13.4 step 9
    bool write_evidence = false;                   // rewrite the committed files
    bool full_oracle = true;                       // cross-check every W-CANON term
    std::size_t oracle_sample = 0;                 // 0 == all
};

// Coverage counters of §13.4 step 10.  A zero is a gate failure.
struct Coverage {
    std::array<std::size_t, 12> kind{};
    std::array<std::size_t, 10> morph{};      // ids 1..9
    std::array<std::size_t, 5> predictor{};   // pids 0..4
    std::array<std::size_t, 3> bigint_tag{};  // tags 0, 1, 2
    std::size_t total_length_u64 = 0;
    std::size_t total_length_big = 0;
    std::size_t index_present = 0;
    std::size_t index_absent = 0;
    std::size_t atom_at_max = 0;
    std::size_t atom_max_plus_one_split = 0;
    std::size_t klass_values = 0;
    std::size_t stage_exercised[12] = {};  // rejection stages actually reached

    void observe_ir(const Ir& ir);
    void add(const Coverage& other);
    void observe_wire(std::span<const u8> wire);
    bool every_counter_nonzero(std::string& why) const;
    std::string to_text() const;
};

// One aggregate of the fuzz campaign (§13.4 step 7).
struct FuzzResult {
    std::size_t iterations = 0;
    std::size_t accepted_invalid = 0;
    std::size_t accepted_valid = 0;
    std::size_t rejected = 0;
    std::size_t crashes = 0;
    std::size_t timeouts = 0;
    std::size_t alloc_violations = 0;
    std::size_t peak_alloc_bytes = 0;
    std::size_t slowest_us = 0;     // worst per-mutant wall time (§13.4 step 7)
    std::string first_failure;  // kind + identity of the first failing mutant
    std::string tally;          // "stage:count" pairs, sorted
    bool clean() const {
        return accepted_invalid == 0 && crashes == 0 && timeouts == 0 && alloc_violations == 0&&
               iterations > 0 && accepted_valid + rejected == iterations;
    }
};

// Deterministic mutant stream (§13.3 `W-FUZZ`).  A splitmix64 core seeded from a
// fixed constant: no <random>, no environment, identical on every platform.
class Mutator {
public:
    explicit Mutator(u64 seed) : state_(seed) {}
    u64 next();
    std::size_t below(std::size_t bound) { return static_cast<std::size_t>(next() % bound); }

    // Applies exactly one mutation of one of the classes E3 §13.3 names.  Returns
    // false when the seed is too small to mutate usefully.
    bool mutate(std::vector<u8>& wire, const std::vector<u8>& seed, u64 index);

private:
    u64 state_;
};

// Runs the whole wire-side half of §13.4 into `collector`, returning the coverage
// census and the fuzz aggregate.  `settings.thread_counts` drives step 9: every
// check runs at each count and the per-check wire bytes and verdicts must match.
struct WireResultSummary {
    Coverage coverage;
    FuzzResult fuzz;
    std::size_t canon_items = 0;
    std::size_t canon_encoded = 0;
    std::size_t canon_failed = 0;
    std::size_t measured_canon_items = 0;
    std::size_t noncanon_items = 0;
    std::size_t noncanon_rejected = 0;
    std::size_t seed_items = 0;
    std::size_t seed_roundtripped = 0;
    std::size_t determinism_mismatches = 0;
    std::size_t oracle_agreements = 0;
    std::size_t oracle_disagreements = 0;
    std::string first_disagreement;
    std::size_t encode_limit_items = 0;
    std::size_t encode_limit_observed = 0;
    std::vector<std::string> corpus_tsv;   // rows of corpus/E3/corpus.tsv
    std::vector<std::string> count_tsv;    // rows of corpus/E3/fuzz_counts.tsv
    bool ok = true;
};

WireResultSummary run_wire_checks(const Corpus& corpus, const Settings& settings,
                                  Collector& collector);

// §13.4 step 8's v2 half: rebuild a term the legacy process decoded, encode it as a
// v2 container, decode that container again, and require the term to survive
// unchanged.  `structure_text` is a `structural_key` rendering and `payload_hex`
// holds the atom payloads; `record_row` reports every obligation once.
//
// This lives on the wire side because the v2 encode path may not be reachable from
// anything that links C08 (E3 §13.1 and the process boundary documented in
// `e3g_legacy_side.hpp`).
void reencode_legacy_term(const std::string& item_id, const std::string& structure_text,
                          const std::vector<std::string>& payload_hex, const std::string& expected_digest,
                          const Settings& settings, Collector& collector, std::size_t& failures);

// §13.4 step 9's cross-thread identity check, exposed so the gate can report it
// separately from the per-check rows.
bool determinism_identical(const Corpus& corpus, const Settings& settings, std::string& why);

}  // namespace e3g
