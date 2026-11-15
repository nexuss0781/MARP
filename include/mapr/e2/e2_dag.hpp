// MARP v2 — E2 ALGEBRA — C06 DAG
//
// Ownership of *identity* inside a term: the `Dag` builder records construction
// events in caller order, and `Dag::finish(root)` resolves them into the
// canonical `Ir` — post-order first-use node ids, dense topological node table,
// root last, interned structurally identical subterms, and one atom record per
// payload.
//
// Normative sources:
//   SPECS/SPECS-V2.md            §2.2 (canonicality invariants), §4.1 (IR
//                                invariants), §7.3 (serialised hash-consing)
//   SPECS/COMPONENTS/e2-algebra/SPECS.md   §4.2 (IR), §4.8 (canonical traversal
//                                and ids), §5.6 (DAG construction), §5.7
//                                (canonical key), §6 (E2-I3, I4, I6, I7, I11,
//                                I12), §7 (O6.1–O6.4 context), §8, §9, §11, §12
//   SPECS/COMPONENTS-V2.md       §4 C06
//
// Scope discipline (E2 §10, C06 prompt §1):
//   * identity only — no rewriting or normalisation beyond the canonical
//     traversal required for emission (C04 owns rewrite/fixed point), no
//     denotation work (C03), no evaluation (C05);
//   * no wire encode/decode (E3), no discovery/selection (E4–E6), no
//     CLI/MAU/certificate (E7);
//   * no file, path, media-type, environment, thread, or global mutable state
//     access.  `finish` is serial (SPECS-V2 §7.3);
//   * C++20 only; E1 `BigInt` is the only length arithmetic.
//
// Determinism (E2-I7):
//   Id assignment is a pure function of the logical term reachable from `root`.
//   Nothing in the emitted `Ir` depends on construction order, pointer values,
//   hash-map iteration, or thread completion order.  Internal hash tables are
//   probed only; emission order comes from the traversal.
//
// Error model (E2 §9): every fallible operation returns `Result<T>`;
// `Invalid` is a contract violation (empty payload, unknown kind, child id not
// already present, non-well-formed term), `Limit` is a resource bound
// (W1 counts, W7 depth, §8.3 output cap).  Nothing throws past the API
// boundary and nothing terminates the process.
#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
#include <span>
#include <vector>

#include "mapr/e2/e2_term.hpp"

namespace marp::v2 {

// ---------------------------------------------------------------------------
// Dag builder (E2 §5.6, SPECS-V2 §2.2)
// ---------------------------------------------------------------------------
//
// Two id spaces, both builder-local:
//   * atom ids   — returned by `add_atom`, consumed by an `Atom` node's `a`
//                  field;
//   * node ids   — returned by `add_node`, consumed by another node's `args`.
// Neither id space is the output id space.  `finish` re-numbers everything in
// canonical post-order, so the caller may construct in any order that respects
// the builder-local dependency (`add_node` args must already exist).
//
// `Node::length` supplied by the caller is *ignored*: it is recomputed from
// structure (E2 §4.4) during `finish`, exactly as E1/E2 require.  Fields that a
// kind does not use are normalised to zero at `add_node`, so they can never
// split an intern key.
class Dag {
public:
    // `Limits` carries the W1 counts and the W7 depth bound; the §8.3 output
    // cap is enforced by the well-formedness pass at `finish`.
    Dag();
    explicit Dag(const Limits& limits);
    ~Dag();

    Dag(Dag&&) noexcept;
    Dag& operator=(Dag&&) noexcept;
    Dag(const Dag&) = delete;
    Dag& operator=(const Dag&) = delete;

    // Records an atom payload.  The bytes are copied (the caller's span need
    // not outlive the call); the emitted `Ir` keeps them alive through
    // `Atom::owner`.  `klass` is advisory: it never affects denotation and is
    // never used for control flow (E2-I11); it is part of the *record*, not of
    // the payload identity, so two payloads are one record regardless of
    // `klass` — the emitted record carries the `klass` of the first `Atom`
    // node met by the canonical traversal (see REPORT/E2/C06-DAG-REPORT.md §5).
    //
    // Returns `Invalid` for an empty payload (a zero-length `Atom` is not a
    // well-formed term, E2 §4.5), `Limit` when `max_atoms` is exhausted.
    Result<u32> add_atom(std::span<const u8> payload, u8 klass = 0);

    // Records a node.  `node.args` must already be ids returned by this builder
    // (`Invalid` otherwise); an `Atom` node's `a` must be an atom id returned by
    // `add_atom` of this builder.  Kind domain, `flags == 0`, W1 counts and W7
    // depth are validated here; the remaining W3/W5/W6/W8 constraints are
    // validated at `finish`, so an ill-formed term is reported there.
    Result<u32> add_node(Node node);

    // Canonical emission (E2 §4.8): post-order traversal from `root`, atoms
    // appended on first encounter, structurally identical subterms interned to a
    // single node, equal payloads to a single atom record.  The result has dense
    // topological ids (`arg < id`), `root == nodes.size()-1`, no unused nodes or
    // atoms, atoms in first-use order, exact `BigInt` lengths, and
    // `total_length == nodes[root].length`.
    //
    // `finish` is rvalue-qualified: it consumes the builder (a `Dag` is used
    // once).  `Invalid` for an out-of-range `root`, a dangling builder id, or a
    // term that fails `WF`; `Limit` for the §8.3 output cap.
    Result<Ir> finish(u32 root) &&;

    // Builder-local counts (construction events recorded so far), not output
    // counts.  Use `Ir::nodes.size()` / `Ir::atoms.size()` for the emitted term.
    u32 node_count() const noexcept;
    u32 atom_count() const noexcept;

    const Limits& limits() const noexcept;

    // Read-only access to the recorded construction events (diagnostics and
    // evidence only; the values are builder-local).
    const Node& builder_node(u32 id) const;
    std::span<const u8> builder_atom_payload(u32 id) const;
    u8 builder_atom_klass(u32 id) const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace marp::v2
