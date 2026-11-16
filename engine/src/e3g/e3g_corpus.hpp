// MARP v2 — E3 WIRE — E3-G integrated gate — corpus construction (§13.3).
//
//   W-CANON    E2's `T-KAT`/`T-GEN` terms (canonicalised where E2's own
//              canonical form requires it) plus the §13.3 edge cases: empty,
//              one byte, an atom exactly `ATOM_MAX`, `ATOM_MAX + 1` split,
//              totals 2^32 / 2^64-1 / 2^64 / 2^64+1 / 2^128, `Zero(2^40)`,
//              `Lfsr(2^40)`, index-present terms >= 3 MiB, index-absent terms.
//   W-SEED     every W-CANON wire, plus hand-assembled canonical wires produced
//              by this harness's own byte writer (never by C07's `encode`), so
//              `enc(dec(w)) = w` is checked against an independent writer.
//   W-NONCANON one container per violation of §4.10 / §5.1, with the expected
//              stage and code taken from §5.1's order and §5.2's table.
//   W-V1       the pinned v1.0.1/v1.1 fixture corpus, when it is present.
//   W-FUZZ     small valid seeds plus the header/trailer/index fields of large
//              virtual containers.
//
// No corpus item is hand-serialised into the *evidence*: every wire in the
// W-CANON and W-SEED sets is produced by C07's `encode` (or by the harness's
// independent writer for the hand-built subset) at gate-run time, and the
// `corpus.tsv` identities are computed from the terms.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "e3g_support.hpp"
#include "mapr/e2/e2_term.hpp"
#include "mapr/e3/e3_wire.hpp"

namespace e3g {

// One canonical term of W-CANON.
struct CanonItem {
    std::string id;
    std::string group;   // W-CANON | W-CANON-EDGE | W-BIG
    std::string origin;  // T-KAT / T-GEN / edge
    Ir ir;
    // The term's declared length exceeds the §8.3 output cap, so E2 refuses it
    // through `Dag::finish`; such a term is built directly and certified with
    // `Limits::enforce_output_cap = false` (the Region A.1 wire form).
    bool above_output_cap = false;
    // The shape has no canonical v2 wire at all: a declared length above 2^64
    // whose denotation needs more stride boundaries than `entry_count` (u32)
    // can express.  Every writer entry point must report `Limit` at stage 10;
    // the item is carried so the limitation is measured, not silently dropped.
    bool expect_encode_limit = false;
    // The item's declared length exceeds the default §8.3 output cap, so `encode`
    // and `validate` are driven with a `WireLimits` whose output cap is lifted
    // (the wire itself is small; only the *denotation* is huge).  Such an item is
    // still a fully canonical §4 wire and its `enc`/`dec` roundtrip is exact;
    // stage 11 cannot evaluate the denotation under the default work bound, so
    // the gate drives `validate` with `max_eval_bytes` lifted for these items and
    // records the default-limits outcome (`Limit` at stage 6 or 11) as its own
    // row — the §5.2 table's "declared limit exceeded => Limit" case.
    // Set automatically for every term whose declared length exceeds either C07
    // limit that can stop steps 2–4 (`max_output_bytes` = 2^63, `max_eval_bytes` =
    // 1 GiB).  Both are policy bounds, not wire-format limits, so such a term is
    // still a canonical wire and is round-tripped with the bound lifted; the
    // default-limits `Limit` is recorded separately and never suppressed.
    bool needs_limit_lift = false;
    std::string note;
    // E2 canonicalisation was required to reach canonical form (T-GEN terms
    // whose `Dag` emission is not canonical by E2's own §4.7 rules).
    bool canonicalised = false;
    std::string canonical_report;  // constraint identifier, when canonicalised
};

// One W-NONCANON container and the rejection §5.1 assigns it.
struct NonCanonItem {
    std::string id;
    std::string violation;  // the §4.10 rule or §5.1 stage the case violates
    std::vector<u8> wire;
    Stage stage;
    WireCode code;
    std::string note;
};

// One W-SEED wire.
struct SeedWire {
    std::string id;
    std::string origin;  // the W-CANON item id, or "hand-built:<shape>"
    std::vector<u8> wire;
};

// One W-V1 fixture.
struct V1Fixture {
    std::string name;
    std::vector<u8> bytes;
    std::string recorded_sha256;   // from W-V1/manifest.tsv, empty when absent
    std::string expected_sha256;   // recorded expected output digest, empty when absent
    std::string sha256_actual;     // computed by the harness
    bool hash_matches = false;     // recorded == actual
};

struct Corpus {
    std::vector<CanonItem> canon;
    std::vector<NonCanonItem> noncanon;
    std::vector<SeedWire> hand_built;   // hand-assembled canonical wires
    std::vector<V1Fixture> v1;
    std::vector<std::vector<u8>> fuzz_seeds;
    std::vector<std::string> fuzz_seed_ids;
    // Recorded generator identity.
    std::string e2_seed_note;
    std::size_t t_kat_bound = 0;
    std::size_t t_gen_bound = 0;
};

// Builds the whole corpus.  Deterministic: the same run produces the same items
// in the same order from the same E2 seeds.
Corpus build_corpus(const std::string& root);

// Deterministic byte pattern for atom payloads (no <random>, no environment).
std::vector<u8> payload(std::size_t size, u8 seed);

// ---------------------------------------------------------------------------
// The harness's own canonical container writer (W-SEED hand-built wires)
// ---------------------------------------------------------------------------
//
// Deliberately independent of C07's `plan`/`encode_to`: it assembles the bytes
// described by E3 §4 directly, so a byte comparison against C07's output is a
// real cross-check rather than a tautology.  It supports only the simple shapes
// the hand-built seeds need, and it refuses anything else rather than
// approximating.
struct HandNode {
    u8 kind = 0;
    std::vector<u32> args;
    std::string param_a;   // decimal text
    std::string param_b;   // decimal text
    u8 morph = 0;
    u8 morph_k = 0;
    u32 stride = 0;
    u64 lfsr_conn = 0;
    u64 lfsr_init = 0;
    u8 affine_start = 0;
    u8 affine_step = 0;
    u8 predictor_id = 0;
    u32 predictor_param = 0;
    std::string length;    // decimal text
    // Raw byte overrides, used verbatim instead of the canonical encoding of the
    // corresponding decimal field.  They exist so the W-NONCANON cases can express
    // a deliberately non-canonical integer (§4.9) at an exact byte position
    // without post-hoc splicing.
    std::vector<u8> raw_param_a;
    std::vector<u8> raw_param_b;
    std::vector<u8> raw_length;
};

struct HandAtom {
    u8 klass = 0;
    std::vector<u8> payload_bytes;
};

struct HandContainer {
    std::string total_length;  // decimal text
    std::vector<HandAtom> atoms;
    std::vector<HandNode> nodes;
};

std::vector<u8> assemble_container(const HandContainer& container, std::string& why);

}  // namespace e3g
