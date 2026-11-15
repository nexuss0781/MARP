// MARP v2 — E2-G integrated ALGEBRA gate — term description, arena, binding.
//
// Evidence-support code for the E2-G harness only.  It is never linked into
// `e2_term.o`, `e2_canon.o`, `e2_eval.o`, or `e2_dag.o`, and no E3–E7 symbol is
// referenced here.
//
// Two responsibilities:
//   1. `Desc` / `DescArena` — a *description* of a logical term.  A description
//      is a pre-order constructor tree with explicit node ids and an explicit
//      atom table; it records construction events in the exact order the file
//      gives them, so it can describe malformed terms (child ids that are not
//      smaller, unused records, wrong stored lengths) as well as well-formed
//      ones.  It is the corpus-generation input and the `corpus.tsv` digest
//      source.
//   2. `bind` — turns a description into an `Ir` with *recomputed* lengths
//      (E2 §4.4) unless the description pins a stored length on purpose
//      (`T-BAD` stored-length cases), and `replay_dag` — turns a description
//      into a `Dag` construction in a caller-chosen order (O6.1).
//
// Nothing here reimplements a denotation: lengths use the C03 builder's third
// independent implementation of the §4.4 formulas, denotations come from the
// engine (C03/C05) and the H3 oracle.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <initializer_list>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "c03_build.hpp"
#include "mapr/e1_bigint.hpp"
#include "mapr/e1_sha256.hpp"
#include "mapr/e2/e2_dag.hpp"
#include "mapr/e2/e2_term.hpp"

namespace e2g {

using namespace marp::v2;  // NOLINT
using c03::pattern;

// ---------------------------------------------------------------------------
// Stable text encoding (used for corpus digests and for `expected` columns).
// ---------------------------------------------------------------------------

inline std::string hex_bytes(std::span<const u8> bytes) {
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2u);
    for (const u8 byte : bytes) {
        out.push_back(kHex[(byte >> 4) & 0x0Fu]);
        out.push_back(kHex[byte & 0x0Fu]);
    }
    return out;
}

inline std::string hex_array(const std::array<u8, 32>& digest) {
    return hex_bytes(std::span<const u8>(digest.data(), digest.size()));
}

inline std::string sha_text(const std::string& text) {
    auto digest = mapr::Sha256::hash(std::string_view(text.data(), text.size()));
    return digest.ok() ? hex_array(digest.value()) : std::string(64, '0');
}

inline std::string sha_of_bytes(std::span<const u8> bytes) {
    auto digest = mapr::Sha256::hash(
        std::string_view(reinterpret_cast<const char*>(bytes.data()), bytes.size()));
    return digest.ok() ? hex_array(digest.value()) : std::string(64, '0');
}

// A `BigInt` equality/comparison helper pair that keeps the call sites short.
inline bool bi_eq(const BigInt& a, const BigInt& b) { return a.compare(b) == 0; }

// ---------------------------------------------------------------------------
// Description of a logical term (pre-order constructor tree, explicit ids)
// ---------------------------------------------------------------------------

struct DescAtom {
    std::string id;
    std::vector<u8> payload;
    u8 klass = 0;
    u8 flags = 0;
    // Declared payload length when it deliberately disagrees with `payload`
    // (W6.atom-payload-length case); `nullopt` = use `payload.size()`.
    std::optional<BigInt> declared_length;
};

struct DescNode {
    std::string id;
    // Description-local child references, in semantic order.  A well-formed
    // description lists every child before the parent; an ill-formed one may
    // list anything the spec wants to reject.
    std::vector<std::string> kids;
    Kind kind = Kind::Empty;
    u8 flags = 0;
    BigInt a, b;
    u8 morph = 0;
    u8 morph_k = 0;
    u64 lfsr_conn = 0;
    u64 lfsr_init = 0;
    u8 affine_start = 0;
    u8 affine_step = 0;
    u8 predictor_id = 0;
    u32 predictor_param = 0;
    // Stored length contract: `std::nullopt` = recompute from structure;
    // a value pins the stored `Node::length` (used by `T-BAD` length cases).
    std::optional<BigInt> stored_length;
    // Atom reference by description atom id (Kind::Atom only).
    std::string atom;
    std::string note;  // free-form label, part of the digest
};

class DescArena {
public:
    DescArena() = default;

    std::string atom(std::string id, std::vector<u8> payload, u8 klass = 0) {
        DescAtom a;
        a.id = std::move(id);
        a.payload = std::move(payload);
        a.klass = klass;
        atoms_.push_back(std::move(a));
        return atoms_.back().id;
    }

    std::string atom_bytes(const std::string& id, std::size_t n, u8 seed, u8 klass = 0) {
        return atom(id, pattern(n, seed), klass);
    }

    // Generic node factory; the typed helpers below cover the corpus shapes.
    std::string node(DescNode node) {
        node.id = "n" + std::to_string(nodes_.size());
        nodes_.push_back(std::move(node));
        return nodes_.back().id;
    }

    std::string empty() {
        DescNode n;
        n.kind = Kind::Empty;
        return node(std::move(n));
    }

    std::string atom_node(const std::string& atom_id) {
        DescNode n;
        n.kind = Kind::Atom;
        n.atom = atom_id;
        return node(std::move(n));
    }

    std::string zero(const BigInt& len) {
        DescNode n;
        n.kind = Kind::Zero;
        n.a = len;
        return node(std::move(n));
    }
    std::string zero(u64 len) { return zero(BigInt(len)); }

    std::string concat(std::vector<std::string> kids) {
        DescNode n;
        n.kind = Kind::Concat;
        n.kids = std::move(kids);
        return node(std::move(n));
    }

    std::string repeat(const std::string& kid, const BigInt& q, const BigInt& r) {
        DescNode n;
        n.kind = Kind::Repeat;
        n.kids = {kid};
        n.a = q;
        n.b = r;
        return node(std::move(n));
    }
    std::string repeat(const std::string& kid, u64 q, u64 r) {
        return repeat(kid, BigInt(q), BigInt(r));
    }

    std::string slice(const std::string& kid, const BigInt& start, const BigInt& len) {
        DescNode n;
        n.kind = Kind::Slice;
        n.kids = {kid};
        n.a = start;
        n.b = len;
        return node(std::move(n));
    }
    std::string slice(const std::string& kid, u64 start, u64 len) {
        return slice(kid, BigInt(start), BigInt(len));
    }

    std::string morph(const std::string& kid, u8 id, u8 k) {
        DescNode n;
        n.kind = Kind::Morph;
        n.kids = {kid};
        n.morph = id;
        n.morph_k = k;
        return node(std::move(n));
    }

    std::string xor_node(const std::string& x, const std::string& y) {
        DescNode n;
        n.kind = Kind::Xor;
        n.kids = {x, y};
        return node(std::move(n));
    }

    std::string interleave(std::vector<std::string> kids, const BigInt& stride) {
        DescNode n;
        n.kind = Kind::Interleave;
        n.kids = std::move(kids);
        n.a = stride;
        return node(std::move(n));
    }
    std::string interleave(std::vector<std::string> kids, u64 stride) {
        return interleave(std::move(kids), BigInt(stride));
    }

    std::string lfsr(u64 conn, u64 init, const BigInt& len) {
        DescNode n;
        n.kind = Kind::Lfsr;
        n.lfsr_conn = conn;
        n.lfsr_init = init;
        n.a = len;
        return node(std::move(n));
    }
    std::string lfsr(u64 conn, u64 init, u64 len) { return lfsr(conn, init, BigInt(len)); }

    std::string affine(u8 start, u8 step, const BigInt& len) {
        DescNode n;
        n.kind = Kind::Affine;
        n.affine_start = start;
        n.affine_step = step;
        n.a = len;
        return node(std::move(n));
    }
    std::string affine(u8 start, u8 step, u64 len) { return affine(start, step, BigInt(len)); }

    std::string predictor(u8 pid, u32 param, const std::string& residual) {
        DescNode n;
        n.kind = Kind::Predictor;
        n.kids = {residual};
        n.predictor_id = pid;
        n.predictor_param = param;
        return node(std::move(n));
    }

    // Pins the stored length of an already-created node (`T-BAD`).
    void pin_length(const std::string& node_id, const BigInt& stored) {
        node_mut(node_id).stored_length = stored;
    }
    void set_flags(const std::string& node_id, u8 flags) { node_mut(node_id).flags = flags; }
    void set_atom_flags(const std::string& atom_id, u8 flags) { atom_mut(atom_id).flags = flags; }
    // Declares a stored atom length that disagrees with the payload bytes
    // (W6.atom-payload-length case).
    void set_atom_declared_length(const std::string& atom_id, const BigInt& declared) {
        atom_mut(atom_id).declared_length = declared;
    }
    void set_atom_payload(const std::string& atom_id, std::vector<u8> payload) {
        atom_mut(atom_id).payload = std::move(payload);
    }
    void set_note(const std::string& node_id, std::string note) {
        node_mut(node_id).note = std::move(note);
    }
    void set_kind_raw(const std::string& node_id, u8 raw);
    void add_extra_child(const std::string& node_id, const std::string& kid) {
        node_mut(node_id).kids.push_back(kid);
    }
    void set_atom_ref(const std::string& node_id, const std::string& atom_id) {
        node_mut(node_id).atom = atom_id;
    }

    const std::vector<DescAtom>& atoms() const { return atoms_; }
    const std::vector<DescNode>& nodes() const { return nodes_; }
    std::size_t atom_count() const { return atoms_.size(); }
    std::size_t node_count() const { return nodes_.size(); }

    const DescNode& node_at(const std::string& id) const {
        return nodes_[index_of(id)];
    }

    // Public lookup helpers (used by the generator's pruner).
    std::size_t index_of_public(const std::string& id) const { return index_of(id); }
    std::size_t atom_index_public(const std::string& id) const { return atom_index(id); }

    // Exact §4.4 length of a description node, recomputed from structure.
    // Returns `std::nullopt` when the subterm is incomplete (unknown child or
    // atom, or a cycle).
    std::optional<BigInt> length_of(const std::string& id) const;
    const DescAtom& atom_at(const std::string& id) const { return atoms_[atom_index(id)]; }

private:
    DescNode& node_mut(const std::string& id) { return nodes_[index_of(id)]; }
    DescAtom& atom_mut(const std::string& id) { return atoms_[atom_index(id)]; }

    std::size_t index_of(const std::string& id) const {
        for (std::size_t i = 0; i < nodes_.size(); ++i) {
            if (nodes_[i].id == id) return i;
        }
        return nodes_.size();
    }
    std::size_t atom_index(const std::string& id) const {
        for (std::size_t i = 0; i < atoms_.size(); ++i) {
            if (atoms_[i].id == id) return i;
        }
        return atoms_.size();
    }

    std::vector<DescAtom> atoms_;
    std::vector<DescNode> nodes_;
};

// A description plus its root reference.
struct TermDesc {
    std::string id;
    std::string corpus;
    std::string note;
    DescArena arena;
    std::string root;
    // `virtual_term == true`: never materialise the denotation (T-BIG).
    bool virtual_term = false;
    // Pinned description digest (`corpus.tsv` column) when set.
    std::string pinned_digest;
};

// Canonical, id-independent text encoding of a description.  Recomputed node
// lengths are encoded with it, so the digest covers the term the file *means*,
// not an artefact of the ordering used to write it down.
std::string describe_desc(const TermDesc& desc);

// Binding outcome.  `ir` is only meaningful when `ok == false` for malformed
// descriptions is still produced whenever possible (the T-BAD cases need an Ir
// to hand to `check_well_formed`).
struct BindResult {
    Ir ir;
    bool ok = false;          // every reference resolved and no cycle
    std::string error;        // why binding failed (empty when ok)
    std::vector<BigInt> recomputed;  // §4.4 lengths by description node order
    std::vector<char> known;         // recomputed[i] is meaningful
};

// Binds by description node order.  This is the *file* order, which for T-BAD
// cases may violate `arg < self`; binding never enforces that (C03 does).
BindResult bind(const TermDesc& desc);

// As `bind`, but with an explicit root override and an explicit
// `Ir::total_length` (used only by the `T-BAD` root / total-length cases).
BindResult bind_with(const TermDesc& desc, const std::string& root_override,
                     const std::optional<BigInt>& total_override);

// Minimal deterministic generator for the replay order (kept local so
// `e2g_terms` does not depend on the corpus generator).
class RngLike {
public:
    explicit RngLike(u64 seed) : state_(seed == 0 ? 0x9E3779B97F4A7C15ull : seed) {}
    u64 next() {
        u64 x = state_;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        state_ = x;
        return x;
    }

private:
    u64 state_ = 0;
};

// Replays a description into a `Dag` in a caller-seeded construction order and
// returns `Dag::finish(root)`.  Nodes are emitted in a random topological order
// (a node only after its children, atoms interned on first use), so the result
// must be identical for every seed (E2 §5.6, O6.1).
struct DagReplay {
    Ir ir;
    bool ok = false;
    std::string error;
};

DagReplay replay_dag(const TermDesc& desc, u64 seed);

// Structural denotation-free equality of two `Ir`s (ids, lengths, atoms,
// payload hashes, params).  `klass` is compared because it is part of the
// record; `Atom::owner` is not.
bool ir_structurally_equal(const Ir& a, const Ir& b);

// Description of an existing `Ir` (post-order first use), used to check that
// `canon` and `Dag::finish` produce the same logical term.
std::string describe_ir(const Ir& ir);

}  // namespace e2g
