// MARP v2 — C07 WIRE — corpus construction for the gate harness.
//
// The corpus is built only through the frozen E2 `Dag` builder and, for the two
// cases E2 deliberately refuses (a declared total length above the §8.3 output
// cap, which is the Region A.1 wire form), through a direct `Ir` construction
// that is then checked with E2's own well-formedness predicate using
// `Limits::enforce_output_cap = false`.
//
// No corpus item is hand-serialised here: every wire in the evidence set is
// produced by C07's `encode`.  Hand-built wires exist only in `c07_checks.*`,
// as `W-NONCANON` tampering cases, and they are always derived from a canonical
// wire by a documented mutation.
#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "mapr/e2/e2_term.hpp"
#include "mapr/e3/e3_wire.hpp"

namespace c07 {

using marp::v2::Atom;
using marp::v2::BigInt;
using marp::v2::Ir;
using marp::v2::Kind;
using marp::v2::Node;
using marp::v2::u32;
using marp::v2::u64;
using marp::v2::u8;

// One corpus item: a canonical `Ir`, its stable id, and the limits it needs.
struct CorpusItem {
    std::string id;
    std::string group;      // W-CANON / W-SEED / W-EDGE / W-BIG
    Ir ir;
    bool above_output_cap = false;  // needs Limits::enforce_output_cap = false
    // True for the shapes whose canonical index cannot exist within the format's
    // own `entry_count = u32` bound (E3 §4.7): a declared total length above 2^64
    // whose denotation has more than 2^32-1 stride boundaries.  `encode` must
    // report `Limit` at stage Index for these, and no wire may be produced.
    bool expect_encode_limit = false;
    // Non-empty when the item is expected to be covered by an extra check.
    std::string note;
};

// Builds the whole corpus.  Deterministic: the same run always produces the
// same items in the same order.
std::vector<CorpusItem> build_corpus();

// Small deterministic payload generator (no <random>, no environment).
std::vector<u8> payload(std::size_t size, u8 seed);

// A canonical `Ir` for `Zero(n)` with an arbitrary precision `n`, built directly
// so that lengths above the §8.3 cap can be exercised on the wire.
Ir direct_zero(const BigInt& n);

// A canonical `Ir` for `Lfsr(conn, init, n)` built directly, same rationale.
Ir direct_lfsr(u64 conn, u64 init, const BigInt& n);

// A canonical `Ir` for `Repeat(child, q, r)` built directly from a single Atom.
Ir direct_repeat_atom(std::size_t atom_bytes, u8 seed, const BigInt& q, const BigInt& r);

}  // namespace c07
