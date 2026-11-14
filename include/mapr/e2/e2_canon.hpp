// MARP v2 — E2 ALGEBRA — C04 CANON
//
// Canonicalisation to a fixed point: `canon` applies the §3.8 rewrite rules
// 1–13 in the fixed strategy of E2 §5.2 until no rule fires and returns the
// unique canonical representative of the term's rewrite class.  This header
// also declares `is_canonical` / `check_canonical` (E2 §4.7 conditions) and
// `canonical_key` (E2 §5.7).
//
// Normative sources:
//   SPECS/SPECS-V2.md            §3.8, §2.2, §4.1, §7.4
//   SPECS/COMPONENTS/e2-algebra/SPECS.md   §4.7–4.8, §5.1–5.2, §5.6–5.7, §8, §9,
//                                          §6 (E2-I4…I7, I11, I12), §7 (O4.1…O4.5)
//   SPECS/COMPONENTS-V2.md       §4 C04
//   SPECS-V2 parent §3.1, §3.2, §3.7, §4.1
//
// Scope discipline (E2 §10, C04 prompt §3.7–3.8):
//   * canonicalisation only — no wire encode/decode (E3), no discovery or
//     selection (E4–E6), no CLI/MAU/certificate (E7), no DAG interning
//     service (C06);
//   * no file, path, environment, thread, or global mutable state access;
//   * C++20 only; E1 `BigInt` is the only arithmetic provider;
//   * `Interleave` child order is semantic and is never sorted or reordered.
//
// Error model (E2 §9): every fallible operation returns `Result<T>`.
// `canon` requires `WF(ir)`: a non-well-formed input yields `Invalid` and no
// output term; exhausting the rewrite budget yields `Limit` (O4.1).  Nothing
// throws past the API boundary and nothing terminates the process.
//
// Determinism (E2-I5, E2-I7): results depend only on the input term, never on
// effort, wall clock, thread count, address values, hash-map iteration, or
// construction order beyond the input term itself.  `hash` is used for
// hash-consing only; every table is probed, never iterated.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "mapr/e2/e2_term.hpp"

namespace marp::v2 {

// ---------------------------------------------------------------------------
// Canonical-shape constraint identifiers (E2 §4.7, checked in the fixed order
// of the table after the WF constraints of §5.1).
//
// The first failing canonical condition is reported with one of these
// identifiers; these are disjoint from the `kC_*` well-formedness identifiers
// of `e2_term.hpp`.
// ---------------------------------------------------------------------------
constexpr const char* kCanon1 = "C1.concat-child-concat";
constexpr const char* kCanon2 = "C2.empty-or-concat-argc";
constexpr const char* kCanon3 = "C3.atom-length";
constexpr const char* kCanon4 = "C4.adjacent-zero";
constexpr const char* kCanon5 = "C5.repeat-normal-form";
constexpr const char* kCanon6 = "C6.slice-fold";
constexpr const char* kCanon7 = "C7.morph-fold";
constexpr const char* kCanon8 = "C8.xor-fold";
constexpr const char* kCanon9 = "C9.interleave-argc";
constexpr const char* kCanon10 = "C10.affine-step-zero";
constexpr const char* kCanon11 = "C11.repeat-slice-zero-child";
constexpr const char* kCanon12 = "C12.not-hash-consed";
constexpr const char* kCanon13 = "C13.identity-shape";

// ---------------------------------------------------------------------------
// Validation (E2 §5.1, §4.7)
// ---------------------------------------------------------------------------

// `Ok` iff `WF(ir)` holds and no §4.7 canonical-shape condition is violated;
// the first failure is reported in the fixed order: WF constraints (§5.1
// order), then canonical rules 1, 2, …, 13.
WfReport check_canonical(const Ir& ir);
WfReport check_canonical(const Ir& ir, const Limits& limits);

// Boolean form; consistent with `check_canonical`.
bool is_canonical(const Ir& ir);
bool is_canonical(const Ir& ir, const Limits& limits);

// ---------------------------------------------------------------------------
// canonicalisation (E2 §5.2, parent §3.8)
// ---------------------------------------------------------------------------

// Instrumentation for O4.1/O4.5.  `rule_fires[i]` counts the firings of
// §3.8 rule `i + 1`; `rewrites` is the total.  A rule whose tabulated redex
// is unreachable from `WF` input (see REPORT/E2/C04-CANON-REPORT.md §5)
// fires zero times.
struct CanonReport {
    u64 rewrites = 0;
    std::array<u64, 13> rule_fires{};
    u64 nodes_in = 0;
    u64 atoms_in = 0;
    u64 nodes_out = 0;
    u64 atoms_out = 0;
    bool budget_exhausted = false;
};

// `canon(ir)` requires `WF(ir)`.  On non-well-formed input it returns
// `Invalid` (with no output); on rewrite-budget exhaustion it returns `Limit`.
// The returned `Ir` is well-formed, canonical, has the same denotation, and
// uses post-order first-use ids with root last (E2 §4.8).
Result<Ir> canon(const Ir& ir);
Result<Ir> canon(const Ir& ir, CanonReport& report);

// Rewrite budget implementing O4.1: canonicalisation of a well-formed term
// with `n` nodes terminates within `64 * (n + 1)` rule firings.  The budget is
// derived from the *input* node count; on exhaustion `Limit` is returned and
// `CanonReport::budget_exhausted` is set.  The `max_rewrites` argument is an
// additive testability hook (mirroring `Limits` for C03); `canon(ir)` always
// uses `64 * (ir.nodes.size() + 1)`.
Result<Ir> canon_with_budget(const Ir& ir, u64 max_rewrites, CanonReport* report);

// ---------------------------------------------------------------------------
// Canonical key (E2 §5.7)
// ---------------------------------------------------------------------------

// Deterministic byte string that is equal for structurally equal subterms and
// distinct otherwise.  Independent of node ids outside the subterm (atoms are
// identified by `(length, sha256)`, never by atom index).  The encoding is a
// pre-order, length-prefixed, self-delimiting binary form; the exact bytes
// are not normative, only its equality and ordering behaviour.  `node >=
// ir.nodes.size()` yields an empty string.  Never throws; total on any `Ir`.
std::string canonical_key(const Ir& ir, u32 node);

// ---------------------------------------------------------------------------
// Structural equality helper (diagnostics and tests)
// ---------------------------------------------------------------------------

// True iff the subtrees at `a` and `b` are structurally identical
// (kind, params, atom payloads, child structure).  Used for idempotence
// checks and diagnostics; not part of the normative canonicality predicate.
bool structurally_equal(const Ir& ir, u32 a, u32 b);

}  // namespace marp::v2
