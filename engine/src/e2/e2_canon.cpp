// MARP v2 — E2 ALGEBRA — C04 CANON implementation.
//
// Every obligation in this file is traceable to:
//   SPECS/COMPONENTS/e2-algebra/SPECS.md §4.7–4.8 (canonical shape, traversal),
//   §5.1–5.2 (validation order, fixed rewrite strategy), §5.7 (canonical key),
//   §6 (invariants E2-I4…I7, I11, I12), §7 (O4.1–O4.5), §9 (errors);
//   SPECS/SPECS-V2.md §3.8 (rules 1–13), §2.2 (canonicality invariants),
//   §4.1 (IR invariants);
//   SPECS/COMPONENTS-V2.md §4 C04.
//
// Design:
//   canon requires WF(ir) (checked first).  A hash-consed work arena
//   ("smart constructors") rewrites bottom-up: the input is topologically
//   ordered (WF ⇒ args < own id), so each input node is reduced exactly once
//   after its children.  Each §3.8 rule fires inside the corresponding
//   smart constructor; rule 12 (structural dedup) fires on every hash-cons
//   hit; rules 1–11 may only fire on the values the constructors produce, and
//   they re-enter the constructors, so the arena always reaches a fixpoint.
//   Rule 13 (prune, first-use id assignment) is applied by the emission pass,
//   which walks the hash-consed result from the root and emits post-order
//   first-use ids; unused records are simply never emitted.
//
// No file, environment, thread, time, or global mutable state is touched.
// No E3–E7 symbol is referenced.  Atom digests are recomputed from payload at
// emission time, so output records are self-consistent; input `sha256` fields
// are used only for input-side bookkeeping and are never trusted for merging
// decisions (atoms are deduplicated by payload bytes, which is exact and is
// strictly stronger than the (length, sha256) key — a collision never grants
// permission to merge).
//
// The rewrite budget implementing O4.1 is 64 * (input_nodes + 1) rule firings.
// Exhaustion returns `Limit`, never a loop.

#include "mapr/e2/e2_canon.hpp"

#include <algorithm>
#include <cstring>
#include <deque>
#include <limits>
#include <optional>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "mapr/e1_sha256.hpp"

namespace marp::v2 {
namespace {

// --- exact arithmetic helpers (E1 BigInt only) ------------------------------

Result<BigInt> bi_add(const BigInt& x, const BigInt& y) {
    auto r = x.add(y);
    if (!r.ok()) return Code::Limit;
    return std::move(r.value());
}

Result<BigInt> bi_mul(const BigInt& x, const BigInt& y) {
    auto r = x.mul(y);
    if (!r.ok()) return Code::Limit;
    return std::move(r.value());
}

// Floor quotient and remainder of value / divisor (divisor != 0).  For value
// >= 0 and divisor > 0 this is the exact Euclidean split.
Result<std::pair<BigInt, BigInt>> bi_divmod(const BigInt& value, const BigInt& divisor) {
    if (divisor.is_zero()) return Code::Invalid;
    auto r = value.divmod(divisor);
    if (!r.ok()) return Code::Limit;
    return std::move(r.value());
}

// --- encoding primitives (self-delimiting, length-prefixed) -----------------

void enc_uvarint(std::string& out, u64 value) {
    while (value >= 0x80u) {
        out += static_cast<char>(static_cast<u8>(value) | 0x80u);
        value >>= 7;
    }
    out += static_cast<char>(static_cast<u8>(value));
}

void enc_bigint(std::string& out, const BigInt& value) {
    const std::vector<u8> bytes = value.to_le_bytes();  // trimmed trailing zeros
    out += '\xBB';
    enc_uvarint(out, static_cast<u64>(bytes.size()));
    if (!bytes.empty()) out.append(reinterpret_cast<const char*>(bytes.data()), bytes.size());
}

// Descriptor cap for canonical/work keys.  Keys concatenated past this many
// bytes are truncated deterministically; equality/ordering stay total and
// deterministic both ways (a truncated key simply compares equal to another
// key with the same prefix, which never affects a fixed-strategy rewrite).
constexpr std::size_t kKeyCap = 1u << 20;  // 1 MiB of descriptor bytes per key

// Append `child_key` to `key`, writing its full length prefix and truncating
// deterministically at kKeyCap bytes total.
void append_child_capped(std::string& key, const std::string& child_key) {
    if (key.size() >= kKeyCap) return;
    std::string lenbuf;
    enc_uvarint(lenbuf, static_cast<u64>(child_key.size()));
    const std::size_t room = kKeyCap - key.size();
    if (lenbuf.size() >= room) {
        key.append(lenbuf, 0, room);
        return;
    }
    key += lenbuf;
    const std::size_t room2 = kKeyCap - key.size();
    key.append(child_key.data(), std::min(child_key.size(), room2));
}

void enc_u64_fixed(std::string& out, u64 value) {
    for (unsigned i = 0; i < 8; ++i) {
        out += static_cast<char>(static_cast<u8>((value >> (i * 8u)) & 0xFFu));
    }
}

constexpr char kKeyTag[12] = {'\x00', '\x01', '\x02', '\x03', '\x04', '\x05',
                              '\x06', '\x07', '\x08', '\x09', '\x0A', '\x0B'};

char tag_of(Kind kind) { return kKeyTag[static_cast<u8>(kind) & 0x0Fu]; }

// Encode the tag and parameter fields of a node (everything except children).
void enc_node_params(std::string& key, Kind kind, const BigInt& a, const BigInt& b, u8 morph,
                     u8 morph_k, u64 lfsr_conn, u64 lfsr_init, u8 affine_start,
                     u8 affine_step, u8 predictor_id, u32 predictor_param,
                     std::size_t argc) {
    key += tag_of(kind);
    switch (kind) {
        case Kind::Empty:
            break;
        case Kind::Zero:
            enc_bigint(key, a);
            break;
        case Kind::Concat:
            enc_uvarint(key, static_cast<u64>(argc));
            break;
        case Kind::Xor:
            enc_uvarint(key, static_cast<u64>(argc));
            break;
        case Kind::Interleave:
            enc_bigint(key, a);
            enc_uvarint(key, static_cast<u64>(argc));
            break;
        case Kind::Repeat:
        case Kind::Slice:
            enc_bigint(key, a);
            enc_bigint(key, b);
            break;
        case Kind::Morph:
            key += static_cast<char>(morph);
            key += static_cast<char>(morph_k);
            break;
        case Kind::Lfsr:
            enc_u64_fixed(key, lfsr_conn);
            enc_u64_fixed(key, lfsr_init);
            enc_bigint(key, a);
            break;
        case Kind::Affine:
            key += static_cast<char>(affine_start);
            key += static_cast<char>(affine_step);
            enc_bigint(key, a);
            break;
        case Kind::Predictor:
            key += static_cast<char>(predictor_id);
            enc_u64_fixed(key, predictor_param);
            break;
        case Kind::Atom:
            break;  // handled by the caller (needs atom record access)
    }
}


}  // namespace

// ---------------------------------------------------------------------------
// canonical_key (E2 §5.7) — iterative, memoized bottom-up, id independent
// ---------------------------------------------------------------------------

std::string canonical_key(const Ir& ir, u32 node) {
    if (node >= ir.nodes.size()) return {};
    // Single left-to-right pass computes keys in node-id order.  WF terms and
    // canonical terms are topologically ordered (args < self); a child id >=
    // self id is tolerated by falling back to a deterministic marker, keeping
    // the function total and deterministic instead of recursing unboundedly.
    const u32 count = static_cast<u32>(ir.nodes.size());
    std::vector<std::optional<std::string>> keys(count);
    constexpr std::size_t kCap = kKeyCap;

    for (u32 id = 0; id < count; ++id) {
        if (keys[id].has_value()) continue;
        const Node& n = ir.nodes[id];
        std::string key;
        if (n.kind == Kind::Atom) {
            key += tag_of(n.kind);
            auto atom_id = n.a.to_u64_checked();
            if (atom_id.has_value() && *atom_id < static_cast<u64>(ir.atoms.size())) {
                const Atom& atom = ir.atoms[static_cast<std::size_t>(*atom_id)];
                enc_bigint(key, atom.length);
                key.append(reinterpret_cast<const char*>(atom.sha256.data()),
                           atom.sha256.size());
            } else {
                key += "\xFE";
            }
        } else {
            enc_node_params(key, n.kind, n.a, n.b, n.morph, n.morph_k, n.lfsr_conn,
                            n.lfsr_init, n.affine_start, n.affine_step, n.predictor_id,
                            n.predictor_param, n.args.size());
        }
        for (const u32 child : n.args) {
            if (key.size() >= kCap) break;
            std::string marker;
            const std::string* child_ptr = &marker;
            if (child < id && keys[child].has_value()) {
                child_ptr = &*keys[child];
            } else {
                marker = "\xFF?";
                child_ptr = &marker;
            }
            append_child_capped(key, *child_ptr);
        }
        keys[id] = std::move(key);
    }

    if (!keys[node].has_value()) return {};
    return *keys[node];
}

// ---------------------------------------------------------------------------
// Structural equality (iterative; subgraph memo on (a, b))
// ---------------------------------------------------------------------------

bool structurally_equal(const Ir& ir, u32 a, u32 b) {
    if (a >= ir.nodes.size() || b >= ir.nodes.size()) return false;
    // Memo of resolved-unequal pairs keeps this from exploring the same
    // shared subgraph pair repeatedly.  Pairs are (min_id << 32 | max_id).
    std::unordered_set<u64> known_unequal;
    struct Frame {
        u32 a;
        u32 b;
    };
    std::vector<Frame> stack;
    stack.push_back({a, b});
    auto note_unequal = [&known_unequal](u32 x, u32 y) {
        const u32 lo = std::min(x, y);
        const u32 hi = std::max(x, y);
        known_unequal.insert((static_cast<u64>(lo) << 32u) | hi);
    };
    while (!stack.empty()) {
        const Frame frame = stack.back();
        stack.pop_back();
        const u32 x = frame.a;
        const u32 y = frame.b;
        if (x == y) continue;
        const u32 lo = x < y ? x : y;
        const u32 hi = x < y ? y : x;
        if (known_unequal.find((static_cast<u64>(lo) << 32u) | hi) != known_unequal.end()) {
            return false;
        }
        const Node& nx = ir.nodes[x];
        const Node& ny = ir.nodes[y];
        bool same = nx.kind == ny.kind && nx.a == ny.a && nx.b == ny.b &&
                    nx.morph == ny.morph && nx.morph_k == ny.morph_k &&
                    nx.lfsr_conn == ny.lfsr_conn && nx.lfsr_init == ny.lfsr_init &&
                    nx.affine_start == ny.affine_start &&
                    nx.affine_step == ny.affine_step &&
                    nx.predictor_id == ny.predictor_id &&
                    nx.predictor_param == ny.predictor_param &&
                    nx.args.size() == ny.args.size();
        if (!same) {
            note_unequal(x, y);
            return false;
        }
        if (nx.kind == Kind::Atom) {
            auto ax = nx.a.to_u64_checked();
            auto by = ny.a.to_u64_checked();
            if (!ax.has_value() || !by.has_value() || *ax >= ir.atoms.size() ||
                *by >= ir.atoms.size()) {
                return false;
            }
            const Atom& atom_a = ir.atoms[static_cast<std::size_t>(*ax)];
            const Atom& atom_b = ir.atoms[static_cast<std::size_t>(*by)];
            same = atom_a.length == atom_b.length &&
                   atom_a.payload.size() == atom_b.payload.size() &&
                   std::memcmp(atom_a.payload.data(), atom_b.payload.data(),
                               atom_a.payload.size()) == 0;
            if (!same) {
                note_unequal(x, y);
                return false;
            }
            continue;
        }
        for (std::size_t i = 0; i < nx.args.size(); ++i) {
            stack.push_back({nx.args[i], ny.args[i]});
        }
    }
    return true;
}

}  // namespace marp::v2

namespace marp::v2 {
namespace {

// ===========================================================================
// Work arena with hash-consing (rule 12) and atom payload dedup
// =========================================================================

struct WorkAtom {
    std::vector<u8> payload;  // length <= ATOM_MAX (splits happen before intern)
    BigInt length;            // == payload.size()
    u8 klass = 0;             // advisory only; first-encountered record wins
};

struct WorkNode {
    Kind kind = Kind::Empty;
    std::vector<u32> args;    // arena indices, topologically ordered by construction
    BigInt a, b, length;
    u8 morph = 0;
    u8 morph_k = 0;
    u64 lfsr_conn = 0;
    u64 lfsr_init = 0;
    u8 affine_start = 0;
    u8 affine_step = 0;
    u8 predictor_id = 0;
    u32 predictor_param = 0;
};

struct WorkArena {
    u64 max_rewrites = 0;
    std::deque<WorkAtom> atoms;
    std::vector<WorkNode> nodes;
    std::unordered_map<std::string, u32> atom_map;    // payload bytes -> atom record id
    std::unordered_map<std::string, u32> node_map;    // work key -> node id (never iterated)
    u64 rewrites = 0;
    std::array<u64, 13> rule_fires{};
    bool over_budget = false;
    std::vector<std::optional<std::array<u8, 32>>> sha_memo;   // per atom record
    std::vector<std::optional<std::string>> key_memo;          // per node id
};

// Sig-based helper for diagnostics only (128-bit FNV-1a).  Never used to make
// identity decisions; hash-consing uses exact keys.
std::string work_key(const WorkNode& node) {
    std::string key;
    key += tag_of(node.kind);
    const auto feed_bigint = [&key](const BigInt& value) { enc_bigint(key, value); };
    switch (node.kind) {
        case Kind::Empty:
            break;
        case Kind::Atom:
            feed_bigint(node.a);  // atom record id (dense, deterministic)
            break;
        case Kind::Zero:
            feed_bigint(node.a);
            break;
        case Kind::Concat:
            enc_uvarint(key, static_cast<u64>(node.args.size()));
            break;
        case Kind::Xor:
            enc_uvarint(key, static_cast<u64>(node.args.size()));
            break;
        case Kind::Interleave:
            feed_bigint(node.a);
            enc_uvarint(key, static_cast<u64>(node.args.size()));
            break;
        case Kind::Repeat:
        case Kind::Slice:
            feed_bigint(node.a);
            feed_bigint(node.b);
            break;
        case Kind::Morph:
            key += static_cast<char>(node.morph);
            key += static_cast<char>(node.morph_k);
            break;
        case Kind::Lfsr:
            enc_u64_fixed(key, node.lfsr_conn);
            enc_u64_fixed(key, node.lfsr_init);
            feed_bigint(node.a);
            break;
        case Kind::Affine:
            key += static_cast<char>(node.affine_start);
            key += static_cast<char>(node.affine_step);
            feed_bigint(node.a);
            break;
        case Kind::Predictor:
            key += static_cast<char>(node.predictor_id);
            enc_u64_fixed(key, node.predictor_param);
            break;
    }
    for (const u32 child : node.args) enc_uvarint(key, child);
    return key;
}

void fire(WorkArena& arena, u64 rule_index /* 0..12, rule_index+1 == rule number */) {
    ++arena.rule_fires[rule_index];
    ++arena.rewrites;
    if (arena.rewrites > arena.max_rewrites) arena.over_budget = true;
}

u32 intern(WorkArena& arena, WorkNode node) {
    const std::string key = work_key(node);
    const auto it = arena.node_map.find(key);
    if (it != arena.node_map.end()) {
        // Rule 12 (structural hash-consing hit).
        ++arena.rule_fires[11];
        ++arena.rewrites;
        if (arena.rewrites > arena.max_rewrites) arena.over_budget = true;
        return it->second;
    }
    const u32 id = static_cast<u32>(arena.nodes.size());
    arena.nodes.push_back(std::move(node));
    arena.node_map.emplace(key, id);
    return id;
}

const BigInt& node_len(const WorkArena& arena, u32 id) { return arena.nodes[id].length; }

Result<u32> mk_concat(WorkArena& arena, std::vector<u32> children);
Result<u32> mk_slice(WorkArena& arena, u32 child, const BigInt& start, const BigInt& length);

// Intern an atom record (dedup by payload bytes — exact, collision-free).
u32 intern_atom_record(WorkArena& arena, std::vector<u8> payload, u8 klass) {
    const std::string key(reinterpret_cast<const char*>(payload.data()), payload.size());
    const auto it = arena.atom_map.find(key);
    if (it != arena.atom_map.end()) {
        return it->second;  // identical payload: one record (rule 13 atom dedup)
    }
    WorkAtom atom;
    atom.length = BigInt(static_cast<u64>(payload.size()));
    atom.payload = std::move(payload);
    atom.klass = klass;
    const u32 id = static_cast<u32>(arena.atoms.size());
    arena.atoms.push_back(std::move(atom));
    arena.atom_map.emplace(key, id);
    return id;
}

u32 intern_atom_node(WorkArena& arena, u32 atom_record) {
    WorkNode node;
    node.kind = Kind::Atom;
    node.a = BigInt(static_cast<u64>(atom_record));
    node.length = arena.atoms[atom_record].length;
    return intern(arena, std::move(node));
}

Result<u32> mk_zero(WorkArena& arena, const BigInt& n) {
    if (arena.over_budget) return Code::Limit;
    WorkNode node;
    node.kind = Kind::Zero;
    node.a = n;
    node.length = n;
    return intern(arena, std::move(node));
}

Result<u32> mk_empty(WorkArena& arena) {
    if (arena.over_budget) return Code::Limit;
    WorkNode node;
    node.kind = Kind::Empty;
    node.length = BigInt::zero();
    return intern(arena, std::move(node));
}

Result<u32> mk_atom_piece(WorkArena& arena, std::vector<u8> payload, u8 klass) {
    if (arena.over_budget) return Code::Limit;
    const u32 record = intern_atom_record(arena, std::move(payload), klass);
    return intern_atom_node(arena, record);
}

// Rule 3 (split): an atom above ATOM_MAX becomes a Concat of ATOM_MAX pieces.
Result<u32> mk_atom(WorkArena& arena, std::span<const u8> payload, u8 klass) {
    if (arena.over_budget) return Code::Limit;
    if (payload.size() <= static_cast<std::size_t>(kAtomMax)) {
        return mk_atom_piece(arena,
                             std::vector<u8>(payload.begin(), payload.end()), klass);
    }
    fire(arena, 2 /* rule 3 */);
    if (arena.over_budget) return Code::Limit;
    std::vector<u32> pieces;
    std::size_t offset = 0;
    while (offset < payload.size()) {
        const std::size_t take =
            std::min(static_cast<std::size_t>(kAtomMax), payload.size() - offset);
        auto id = mk_atom_piece(arena,
                                std::vector<u8>(
                                    payload.begin() + static_cast<std::ptrdiff_t>(offset),
                                    payload.begin() + static_cast<std::ptrdiff_t>(offset + take)),
                                klass);
        if (!id.ok()) return id.code();
        pieces.push_back(id.value());
        offset += take;
    }
    if (pieces.size() == 1) return pieces.front();  // unreachable (split needs >= 2 pieces)
    return mk_concat(arena, std::move(pieces));
}

// Rule 1 (flatten) + rule 2 (drop Empty, collapse) + rule 3 (merge adjacent
// atoms with sum <= ATOM_MAX) + rule 4 (merge adjacent Zeros).
Result<u32> mk_concat(WorkArena& arena, std::vector<u32> children) {
    if (arena.over_budget) return Code::Limit;
    // Rule 1: flatten nested Concat children.
    std::vector<u32> flat;
    flat.reserve(children.size());
    for (const u32 child : children) {
        if (arena.nodes[child].kind == Kind::Concat) {
            fire(arena, 0 /* rule 1 */);
            if (arena.over_budget) return Code::Limit;
            for (const u32 grandchild : arena.nodes[child].args) flat.push_back(grandchild);
        } else {
            flat.push_back(child);
        }
    }
    // Rule 2: drop Empty children.
    std::vector<u32> no_empty;
    no_empty.reserve(flat.size());
    for (const u32 id : flat) {
        if (arena.nodes[id].kind == Kind::Empty) {
            fire(arena, 1 /* rule 2 */);
            continue;
        }
        no_empty.push_back(id);
    }
    // Rules 3/4: merge adjacent atoms / Zeros, left to right with a trailing
    // fixup loop (a freshly merged record may itself merge left again).
    std::vector<u32> merged;
    merged.reserve(no_empty.size());
    for (const u32 id : no_empty) {
        merged.push_back(id);
        for (;;) {
            const std::size_t n = merged.size();
            if (n < 2) break;
            const u32 back = merged[n - 1];
            const u32 prev = merged[n - 2];
            const WorkNode& bn = arena.nodes[back];
            const WorkNode& pn = arena.nodes[prev];
            if (pn.kind == Kind::Atom && bn.kind == Kind::Atom) {
                auto sum = bi_add(pn.length, bn.length);
                if (!sum.ok()) return sum.code();
                if (sum.value().compare(BigInt(kAtomMax)) <= 0) {
                    fire(arena, 2 /* rule 3 */);
                    if (arena.over_budget) return Code::Limit;
                    const u32 rec_a = static_cast<u32>(pn.a.to_u64_checked().value());
                    const u32 rec_b = static_cast<u32>(bn.a.to_u64_checked().value());
                    std::vector<u8> payload = arena.atoms[rec_a].payload;
                    payload.insert(payload.end(), arena.atoms[rec_b].payload.begin(),
                                   arena.atoms[rec_b].payload.end());
                    const u8 klass = arena.atoms[rec_a].klass;  // advisory; keep left
                    auto merged_atom = mk_atom_piece(arena, std::move(payload), klass);
                    if (!merged_atom.ok()) return merged_atom.code();
                    merged.pop_back();
                    merged.pop_back();
                    merged.push_back(merged_atom.value());
                    continue;
                }
            } else if (pn.kind == Kind::Zero && bn.kind == Kind::Zero) {
                fire(arena, 3 /* rule 4 */);
                if (arena.over_budget) return Code::Limit;
                auto sum = bi_add(pn.a, bn.a);
                if (!sum.ok()) return sum.code();
                merged.pop_back();
                merged.pop_back();
                auto zero_node = mk_zero(arena, sum.value());
                if (!zero_node.ok()) return zero_node.code();
                merged.push_back(zero_node.value());
                continue;
            }
            break;
        }
    }
    // Rule 2: empty / unary collapse.
    if (merged.empty()) {
        fire(arena, 1 /* rule 2 */);
        return mk_empty(arena);
    }
    if (merged.size() == 1) {
        fire(arena, 1 /* rule 2 */);
        return merged.front();
    }
    WorkNode node;
    node.kind = Kind::Concat;
    node.args = std::move(merged);
    BigInt total = BigInt::zero();
    for (const u32 child : node.args) {
        auto sum = bi_add(total, node_len(arena, child));
        if (!sum.ok()) return sum.code();
        total = std::move(sum.value());
    }
    node.length = std::move(total);
    return intern(arena, std::move(node));
}

}  // namespace
}  // namespace marp::v2
namespace marp::v2 {
namespace {

// ---------------------------------------------------------------------------
// Work-arena keys: encoding identical to `canonical_key` (E2 §5.7) applied to
// the work subgraph, memoized.  Used only for Xor operand ordering; the
// arena and the output Ir produce identical bytes for identical subtrees.
// ---------------------------------------------------------------------------

std::array<u8, 32> atom_sha256(WorkArena& arena, u32 atom_record) {
    while (arena.sha_memo.size() <= atom_record) arena.sha_memo.push_back(std::nullopt);
    auto& slot = arena.sha_memo[atom_record];
    if (slot.has_value()) return *slot;
    const WorkAtom& atom = arena.atoms[atom_record];
    const std::string_view view(reinterpret_cast<const char*>(atom.payload.data()),
                                atom.payload.size());
    auto digest = mapr::Sha256::hash(view);
    std::array<u8, 32> sha{};
    if (digest.ok()) {
        sha = digest.value();
    } else {
        sha.fill(0xA5);  // unreachable for in-memory payloads; deterministic
    }
    slot = sha;
    return sha;
}

void emit_work_key(WorkArena& arena, u32 id, std::vector<std::optional<std::string>>& memo) {
    if (memo[id].has_value()) return;
    // Iterative post-order over the dependency subgraph with explicit phases.
    struct Frame {
        u32 id;
        u8 phase;
    };
    std::vector<Frame> stack;
    stack.push_back({id, 0});
    while (!stack.empty()) {
        Frame& frame = stack.back();
        const u32 cur = frame.id;
        if (memo[cur].has_value()) {
            stack.pop_back();
            continue;
        }
        if (frame.phase == 0) {
            frame.phase = 1;
            for (const u32 child : arena.nodes[cur].args) {
                if (!memo[child].has_value()) stack.push_back({child, 0});
            }
            continue;
        }
        const WorkNode& n = arena.nodes[cur];
        std::string key;
        if (n.kind == Kind::Atom) {
            key += tag_of(n.kind);
            const u32 record = static_cast<u32>(n.a.to_u64_checked().value_or(0));
            const WorkAtom& atom = arena.atoms[record];
            enc_bigint(key, atom.length);
            const std::array<u8, 32> sha = atom_sha256(arena, record);
            key.append(reinterpret_cast<const char*>(sha.data()), sha.size());
        } else {
            enc_node_params(key, n.kind, n.a, n.b, n.morph, n.morph_k, n.lfsr_conn,
                            n.lfsr_init, n.affine_start, n.affine_step, n.predictor_id,
                            n.predictor_param, n.args.size());
        }
        for (const u32 child : n.args) {
            if (key.size() >= kKeyCap) break;
            append_child_capped(key, *memo[child]);
        }
        memo[cur] = std::move(key);
        stack.pop_back();
    }
}

std::string arena_key(WorkArena& arena, u32 id) {
    if (arena.key_memo.size() < arena.nodes.size()) arena.key_memo.resize(arena.nodes.size());
    emit_work_key(arena, id, arena.key_memo);
    return *arena.key_memo[id];   // copy: memo may reallocate on the next call
}

bool key_less(const std::string& a, const std::string& b) {
    const std::size_t n = std::min(a.size(), b.size());
    for (std::size_t i = 0; i < n; ++i) {
        const u8 x = static_cast<u8>(a[i]);
        const u8 y = static_cast<u8>(b[i]);
        if (x != y) return x < y;
    }
    return a.size() < b.size();
}

// ---------------------------------------------------------------------------
// Remaining smart constructors
// ---------------------------------------------------------------------------

Result<u32> mk_slice(WorkArena& arena, u32 child, const BigInt& start, const BigInt& length) {
    if (arena.over_budget) return Code::Limit;
    // Rule 6: zero-length slice folds to Empty.
    if (length.is_zero()) {
        fire(arena, 5 /* rule 6 */);
        return mk_empty(arena);
    }
    const Kind child_kind = arena.nodes[child].kind;
    // Rule 6: nested slices compose.
    if (child_kind == Kind::Slice) {
        const WorkNode& cn = arena.nodes[child];
        auto new_start = bi_add(cn.a, start);
        if (!new_start.ok()) return new_start.code();
        fire(arena, 5 /* rule 6 */);
        if (arena.over_budget) return Code::Limit;
        return mk_slice(arena, cn.args[0], new_start.value(), length);
    }
    // Rule 6: full-cover slice folds to the child.
    if (start.is_zero() && length.compare(node_len(arena, child)) == 0) {
        fire(arena, 5 /* rule 6 */);
        return child;
    }
    // Rule 11: slice of Zero is Zero(l).
    if (child_kind == Kind::Zero) {
        fire(arena, 10 /* rule 11 */);
        return mk_zero(arena, length);
    }
    // Defensive: slice of Empty is empty (only reachable for l == 0, handled).
    if (child_kind == Kind::Empty) return mk_empty(arena);
    WorkNode node;
    node.kind = Kind::Slice;
    node.args = {child};
    node.a = start;
    node.b = length;
    node.length = length;
    return intern(arena, std::move(node));
}

Result<u32> mk_repeat(WorkArena& arena, u32 child, const BigInt& q, const BigInt& r) {
    if (arena.over_budget) return Code::Limit;
    const Kind child_kind = arena.nodes[child].kind;
    const BigInt child_len = arena.nodes[child].length;
    const bool child_is_zero = child_kind == Kind::Zero;
    // Rule 5: fold r >= len(child) into q (needs len(child) > 0; the ℓ(child) = 0
    // case can only have r = 0 in WF input and is handled by the q == 0 arm).
    BigInt q2 = q;
    BigInt r2 = r;
    if (!child_len.is_zero() && r.compare(child_len) >= 0) {
        auto qr = bi_divmod(r, child_len);
        if (!qr.ok()) return qr.code();
        auto qsum = bi_add(q, qr.value().first);
        if (!qsum.ok()) return qsum.code();
        q2 = std::move(qsum.value());
        r2 = std::move(qr.value().second);
        fire(arena, 4 /* rule 5 */);
        if (arena.over_budget) return Code::Limit;
    }
    const bool r2_zero = r2.is_zero();
    const int q_cmp_1 = q2.compare(BigInt(1));
    // Rule 5: q = 0.
    if (q2.is_zero()) {
        if (r2_zero) {
            fire(arena, 4 /* rule 5 */);
            return mk_empty(arena);
        }
        fire(arena, 4 /* rule 5 */);
        return mk_slice(arena, child, BigInt::zero(), r2);
    }
    // Rule 5: q = 1.
    if (q_cmp_1 == 0) {
        if (r2_zero) {
            fire(arena, 4 /* rule 5 */);
            return child;
        }
        auto slice = mk_slice(arena, child, BigInt::zero(), r2);
        if (!slice.ok()) return slice.code();
        fire(arena, 4 /* rule 5 */);
        return mk_concat(arena, {child, slice.value()});
    }
    // q >= 2: rule 11 folds Repeat of Zero to Zero(q*len + r).
    if (child_is_zero) {
        fire(arena, 10 /* rule 11 */);
        auto qn = bi_mul(q2, child_len);
        if (!qn.ok()) return qn.code();
        auto total = bi_add(qn.value(), r2);
        if (!total.ok()) return total.code();
        return mk_zero(arena, total.value());
    }
    // Defensive: a zero-length non-Zero child can only be Empty; q copies of
    // nothing plus nothing is Zero(q*0 + r2) = Zero(r2).
    if (child_len.is_zero()) {
        return mk_zero(arena, r2);
    }
    WorkNode node;
    node.kind = Kind::Repeat;
    node.args = {child};
    node.a = std::move(q2);
    node.b = std::move(r2);
    auto qn = bi_mul(node.a, child_len);
    if (!qn.ok()) return qn.code();
    auto total = bi_add(qn.value(), node.b);
    if (!total.ok()) return total.code();
    node.length = std::move(total.value());
    return intern(arena, std::move(node));
}

Result<u32> mk_morph(WorkArena& arena, u32 child, u8 morph, u8 morph_k) {
    if (arena.over_budget) return Code::Limit;
    const WorkNode& cn = arena.nodes[child];
    // Rule 7: adjacent morph folds (only when the child is itself a Morph).
    if (cn.kind == Kind::Morph) {
        const u8 inner = cn.morph;
        const u8 inner_k = cn.morph_k;
        // Identical involutions cancel (all k == 0 catalogue morphs are
        // self-inverse: 1, 2, 3, 4, 5, 8, 9).
        if (morph == inner && morph_k == 0 && inner_k == 0) {
            fire(arena, 6 /* rule 7 */);
            return arena.nodes[child].args[0];
        }
        const bool outer_rot = (morph == 6 || morph == 7);
        const bool inner_rot = (inner == 6 || inner == 7);
        if (outer_rot && inner_rot) {
            const auto disp = [](u8 m, u8 k) {
                const int v = static_cast<int>(k);
                return m == 6 ? v : -v;
            };
            int d = disp(morph, morph_k) + disp(inner, inner_k);
            int s = ((d % 8) + 8) % 8;
            fire(arena, 6 /* rule 7 */);
            if (arena.over_budget) return Code::Limit;
            if (s == 0) return arena.nodes[child].args[0];
            return mk_morph(arena, arena.nodes[child].args[0], 6 /* ROTL8 */,
                            static_cast<u8>(s));
        }
    }
    WorkNode node;
    node.kind = Kind::Morph;
    node.args = {child};
    node.morph = morph;
    node.morph_k = morph_k;
    node.length = cn.length;
    return intern(arena, std::move(node));
}

Result<u32> mk_xor(WorkArena& arena, u32 a, u32 b) {
    if (arena.over_budget) return Code::Limit;
    // Rule 8: x xor x -> Zero(len(x)).  (Hash-consing makes structurally
    // identical operands share one work id.)
    if (a == b) {
        fire(arena, 7 /* rule 8 */);
        return mk_zero(arena, arena.nodes[a].length);
    }
    const WorkNode& an = arena.nodes[a];
    const WorkNode& bn = arena.nodes[b];
    // Rule 8: Xor with a Zero operand (length-compatible; WF guarantees the
    // lengths match, so the remaining operand has ℓ == len(Zero)).
    if (an.kind == Kind::Zero) {
        fire(arena, 7 /* rule 8 */);
        return b;
    }
    if (bn.kind == Kind::Zero) {
        fire(arena, 7 /* rule 8 */);
        return a;
    }
    // Rule 8: operands ordered by canonical_key ascending (bytes, unsigned).
    const std::string ka = arena_key(arena, a);
    const std::string kb = arena_key(arena, b);
    if (key_less(kb, ka)) {
        fire(arena, 7 /* rule 8 */);
        std::swap(a, b);
    }
    if (arena.over_budget) return Code::Limit;
    WorkNode node;
    node.kind = Kind::Xor;
    node.args = {a, b};
    node.length = arena.nodes[a].length;
    return intern(arena, std::move(node));
}

Result<u32> mk_interleave(WorkArena& arena, std::vector<u32> children, const BigInt& stride) {
    if (arena.over_budget) return Code::Limit;
    // Rule 9: a single child folds to the child (order is never reordered).
    if (children.size() == 1) {
        fire(arena, 8 /* rule 9 */);
        return children.front();
    }
    WorkNode node;
    node.kind = Kind::Interleave;
    node.args = std::move(children);
    node.a = stride;
    // ℓ = argc * ℓ(child) with all children equal-length (WF).
    auto k = bi_mul(BigInt(static_cast<u64>(node.args.size())), node_len(arena, node.args.front()));
    if (!k.ok()) return k.code();
    node.length = std::move(k.value());
    return intern(arena, std::move(node));
}

Result<u32> mk_affine(WorkArena& arena, u8 start_byte, u8 step, const BigInt& n) {
    if (arena.over_budget) return Code::Limit;
    // Rule 10: step == 0 folds; denotation is the constant byte `start` (or
    // zeros when start == 0).
    if (step == 0) {
        fire(arena, 9 /* rule 10 */);
        if (start_byte == 0) return mk_zero(arena, n);
        auto atom = mk_atom_piece(arena, std::vector<u8>{start_byte}, 0);
        if (!atom.ok()) return atom.code();
        return mk_repeat(arena, atom.value(), n, BigInt::zero());
    }
    WorkNode node;
    node.kind = Kind::Affine;
    node.affine_start = start_byte;
    node.affine_step = step;
    node.a = n;
    node.length = n;
    return intern(arena, std::move(node));
}

}  // namespace
}  // namespace marp::v2
namespace marp::v2 {
namespace {

// ---------------------------------------------------------------------------
// Input translation: WF ir (topologically ordered) -> work arena
// ---------------------------------------------------------------------------

Result<u32> build_node(WorkArena& arena, const Ir& ir, u32 id, std::vector<u32>& env) {
    const Node& n = ir.nodes[id];
    std::vector<u32> children;
    children.reserve(n.args.size());
    for (const u32 child : n.args) children.push_back(env[child]);
    switch (n.kind) {
        case Kind::Empty:
            return mk_empty(arena);
        case Kind::Atom: {
            auto atom_id = n.a.to_u64_checked();
            if (!atom_id.has_value() || *atom_id >= ir.atoms.size()) return Code::Invalid;
            const Atom& atom = ir.atoms[static_cast<std::size_t>(*atom_id)];
            return mk_atom(arena, atom.payload, atom.klass);
        }
        case Kind::Zero:
            return mk_zero(arena, n.a);
        case Kind::Concat:
            return mk_concat(arena, std::move(children));
        case Kind::Repeat:
            return mk_repeat(arena, children[0], n.a, n.b);
        case Kind::Slice:
            return mk_slice(arena, children[0], n.a, n.b);
        case Kind::Morph:
            return mk_morph(arena, children[0], n.morph, n.morph_k);
        case Kind::Xor:
            return mk_xor(arena, children[0], children[1]);
        case Kind::Interleave:
            return mk_interleave(arena, std::move(children), n.a);
        case Kind::Lfsr: {
            WorkNode node;
            node.kind = Kind::Lfsr;
            node.a = n.a;
            node.lfsr_conn = n.lfsr_conn;
            node.lfsr_init = n.lfsr_init;
            node.length = n.a;
            return intern(arena, std::move(node));
        }
        case Kind::Affine:
            return mk_affine(arena, n.affine_start, n.affine_step, n.a);
        case Kind::Predictor: {
            WorkNode node;
            node.kind = Kind::Predictor;
            node.args = {children[0]};
            node.predictor_id = n.predictor_id;
            node.predictor_param = n.predictor_param;
            node.length = node_len(arena, children[0]);
            return intern(arena, std::move(node));
        }
        default:
            return Code::Invalid;
    }
}

// ---------------------------------------------------------------------------
// Emission: post-order first-use ids, dedup (exact), pruning, atom dedup
// ---------------------------------------------------------------------------

struct EmitOutcome {
    Ir ir;
    u64 pruned_nodes = 0;
    u64 pruned_atoms = 0;
};

Result<EmitOutcome> emit_canonical(WorkArena& arena, u32 work_root) {
    if (arena.over_budget) return Code::Limit;
    EmitOutcome out;
    Ir& ir = out.ir;
    const u32 n_work = static_cast<u32>(arena.nodes.size());
    constexpr u32 kUnset = ~0u;
    std::vector<u32> node_map(n_work, kUnset);
    std::vector<u32> atom_map(arena.atoms.size(), kUnset);
    ir.atoms.reserve(arena.atoms.size());
    ir.nodes.reserve(n_work);
    const auto store = std::make_shared<std::deque<std::vector<u8>>>();

    struct Frame {
        u32 id;
        std::size_t next_child;
    };
    std::vector<Frame> stack;
    stack.push_back({work_root, 0});

    while (!stack.empty()) {
        Frame& top = stack.back();
        const WorkNode& wn = arena.nodes[top.id];
        if (top.next_child < wn.args.size()) {
            const u32 child = wn.args[top.next_child];
            ++top.next_child;
            if (node_map[child] == kUnset) stack.push_back({child, 0});
            continue;
        }
        if (node_map[top.id] != kUnset) {
            stack.pop_back();  // shared subterm already emitted (rule 12)
            continue;
        }
        // -- leave: build the output node -----------------------------------
        Node node;
        node.kind = wn.kind;
        node.flags = 0;
        node.a = wn.a;
        node.b = wn.b;
        node.morph = wn.morph;
        node.morph_k = wn.morph_k;
        node.lfsr_conn = wn.lfsr_conn;
        node.lfsr_init = wn.lfsr_init;
        node.affine_start = wn.affine_start;
        node.affine_step = wn.affine_step;
        node.predictor_id = wn.predictor_id;
        node.predictor_param = wn.predictor_param;
        switch (wn.kind) {
            case Kind::Atom: {
                const u32 record = u32(wn.a.to_u64_checked().value_or(0));
                if (atom_map[record] == kUnset) {
                    WorkAtom& wa = arena.atoms[record];
                    store->push_back(std::move(wa.payload));
                    const std::vector<u8>& bytes = store->back();
                    Atom atom;
                    atom.klass = wa.klass;
                    atom.flags = 0;
                    atom.length = BigInt(static_cast<u64>(bytes.size()));
                    const std::string_view view(reinterpret_cast<const char*>(bytes.data()),
                                                bytes.size());
                    auto digest = mapr::Sha256::hash(view);
                    if (!digest.ok()) return Code::Limit;
                    atom.sha256 = digest.value();
                    atom.payload = std::span<const u8>(bytes.data(), bytes.size());
                    atom.owner = store;
                    ir.atoms.push_back(std::move(atom));
                    atom_map[record] = static_cast<u32>(ir.atoms.size() - 1);
                }
                node.args = {};
                node.a = BigInt(static_cast<u64>(atom_map[record]));
                node.b = BigInt::zero();
                node.length = ir.atoms[atom_map[record]].length;
                break;
            }
            case Kind::Zero:
                node.args = {};
                node.length = wn.a;
                break;
            case Kind::Empty:
                node.args = {};
                node.a = BigInt::zero();
                node.b = BigInt::zero();
                node.length = BigInt::zero();
                break;
            case Kind::Concat: {
                BigInt total = BigInt::zero();
                for (const u32 child : wn.args) {
                    const u32 out_id = node_map[child];
                    node.args.push_back(out_id);
                    auto sum = bi_add(total, ir.nodes[out_id].length);
                    if (!sum.ok()) return sum.code();
                    total = std::move(sum.value());
                }
                node.length = std::move(total);
                break;
            }
            case Kind::Repeat: {
                const u32 child = wn.args[0];
                node.args.push_back(node_map[child]);
                auto qn = bi_mul(wn.a, ir.nodes[node.args[0]].length);
                if (!qn.ok()) return qn.code();
                auto total = bi_add(qn.value(), wn.b);
                if (!total.ok()) return total.code();
                node.length = std::move(total.value());
                break;
            }
            case Kind::Slice:
                node.args.push_back(node_map[wn.args[0]]);
                node.length = wn.b;
                break;
            case Kind::Morph:
                node.args.push_back(node_map[wn.args[0]]);
                node.length = ir.nodes[node.args[0]].length;
                break;
            case Kind::Xor: {
                for (const u32 child : wn.args) node.args.push_back(node_map[child]);
                node.length = ir.nodes[node.args[0]].length;
                break;
            }
            case Kind::Interleave: {
                BigInt first;
                for (const u32 child : wn.args) {
                    node.args.push_back(node_map[child]);
                }
                first = ir.nodes[node.args.front()].length;
                auto k = bi_mul(BigInt(static_cast<u64>(node.args.size())), first);
                if (!k.ok()) return k.code();
                node.length = std::move(k.value());
                break;
            }
            case Kind::Lfsr:
                node.args = {};
                node.length = wn.a;
                break;
            case Kind::Affine:
                node.args = {};
                node.length = wn.a;
                break;
            case Kind::Predictor:
                node.args.push_back(node_map[wn.args[0]]);
                node.length = ir.nodes[node.args[0]].length;
                break;
        }
        ir.nodes.push_back(std::move(node));
        node_map[top.id] = static_cast<u32>(ir.nodes.size() - 1);
        stack.pop_back();
    }

    u64 pruned_nodes = 0;
    for (const u32 mapped : node_map) pruned_nodes += (mapped == kUnset) ? 1 : 0;
    u64 pruned_atoms = 0;
    for (const u32 mapped : atom_map) pruned_atoms += (mapped == kUnset) ? 1 : 0;
    out.pruned_nodes = pruned_nodes;
    out.pruned_atoms = pruned_atoms;
    ir.root = static_cast<u32>(ir.nodes.size() - 1);
    ir.total_length = ir.nodes.back().length;
    return out;
}

}  // namespace
}  // namespace marp::v2
namespace marp::v2 {
namespace {

// ---------------------------------------------------------------------------
// canon driver
// ---------------------------------------------------------------------------

Result<Ir> canon_impl(const Ir& ir, u64 max_rewrites, CanonReport* report) {
    CanonReport local;
    if (report == nullptr) report = &local;
    report->nodes_in = static_cast<u64>(ir.nodes.size());
    report->atoms_in = static_cast<u64>(ir.atoms.size());
    report->rewrites = 0;
    report->rule_fires = {};
    report->budget_exhausted = false;

    const WfReport wf = check_well_formed_report(ir);
    if (!wf.ok()) return wf.code;

    WorkArena arena;
    arena.max_rewrites = max_rewrites;
    std::vector<u32> env(ir.nodes.size(), ~0u);
    for (u32 i = 0; i < static_cast<u32>(ir.nodes.size()); ++i) {
        auto result = build_node(arena, ir, i, env);
        if (!result.ok()) {
            report->rewrites = arena.rewrites;
            report->rule_fires = arena.rule_fires;
            report->budget_exhausted = arena.over_budget;
            return result.code();
        }
        if (arena.over_budget) {
            report->rewrites = arena.rewrites;
            report->rule_fires = arena.rule_fires;
            report->budget_exhausted = true;
            return Code::Limit;
        }
        env[i] = result.value();
    }

    auto outcome = emit_canonical(arena, env[ir.root]);
    if (!outcome.ok()) {
        report->rewrites = arena.rewrites;
        report->rule_fires = arena.rule_fires;
        report->budget_exhausted = arena.over_budget;
        return outcome.code();
    }
    const u64 pruned = outcome.value().pruned_nodes + outcome.value().pruned_atoms;
    report->rule_fires = arena.rule_fires;
    report->rule_fires[12] += pruned;   // rule 13: records pruned at emission
    report->rewrites = arena.rewrites + pruned;
    report->budget_exhausted = false;
    report->nodes_out = static_cast<u64>(outcome.value().ir.nodes.size());
    report->atoms_out = static_cast<u64>(outcome.value().ir.atoms.size());
    return std::move(outcome.value().ir);
}

WfReport canon_fail(u32 node, const char* constraint, std::string message) {
    WfReport report;
    report.code = Code::Invalid;
    report.node = node;
    report.constraint = constraint;
    report.message = std::move(message);
    return report;
}

// ===========================================================================
// Canonical-shape checks (E2 §4.7) in the fixed rule order, after WF
// =========================================================================

std::optional<WfReport> find_c1(const Ir& ir) {
    for (u32 i = 0; i < ir.nodes.size(); ++i) {
        const Node& n = ir.nodes[i];
        if (n.kind != Kind::Concat) continue;
        for (const u32 child : n.args) {
            if (ir.nodes[child].kind == Kind::Concat) {
                return canon_fail(i, kCanon1,
                                  "Concat child is a Concat (node " + std::to_string(child) + ")");
            }
        }
    }
    return std::nullopt;
}

std::optional<WfReport> find_c2(const Ir& ir) {
    const bool only_empty = ir.nodes.size() == 1 && ir.nodes[0].kind == Kind::Empty;
    for (u32 i = 0; i < ir.nodes.size(); ++i) {
        const Node& n = ir.nodes[i];
        if (n.kind == Kind::Empty && !only_empty) {
            return canon_fail(i, kCanon2, "Empty node in canonical term");
        }
        if (n.kind == Kind::Concat && n.args.size() < 2) {
            return canon_fail(i, kCanon2, "Concat with argc < 2");
        }
    }
    return std::nullopt;
}

std::optional<WfReport> find_c3(const Ir& ir) {
    for (std::size_t i = 0; i < ir.atoms.size(); ++i) {
        if (ir.atoms[i].length.compare(BigInt(kAtomMax)) > 0) {
            u32 witness = ~0u;
            for (u32 j = 0; j < static_cast<u32>(ir.nodes.size()); ++j) {
                const Node& n = ir.nodes[j];
                if (n.kind == Kind::Atom && n.a == BigInt(static_cast<u64>(i))) {
                    witness = j;
                    break;
                }
            }
            const u32 witness_node =
                (witness == ~0u) ? static_cast<u32>(i) : witness;
            return canon_fail(witness_node, kCanon3,
                              "atom length exceeds ATOM_MAX");
        }
    }
    for (u32 i = 0; i < ir.nodes.size(); ++i) {
        const Node& n = ir.nodes[i];
        if (n.kind != Kind::Concat) continue;
        for (std::size_t k = 0; k + 1 < n.args.size(); ++k) {
            const Node& x = ir.nodes[n.args[k]];
            const Node& y = ir.nodes[n.args[k + 1]];
            if (x.kind != Kind::Atom || y.kind != Kind::Atom) continue;
            auto sum = x.length.add(y.length);
            if (sum.ok() && sum.value().compare(BigInt(kAtomMax)) <= 0) {
                return canon_fail(i, kCanon3,
                                  "adjacent atoms merge under ATOM_MAX (sum " +
                                      sum.value().to_decimal() + ")");
            }
        }
    }
    return std::nullopt;
}

std::optional<WfReport> find_c4(const Ir& ir) {
    for (u32 i = 0; i < ir.nodes.size(); ++i) {
        const Node& n = ir.nodes[i];
        if (n.kind != Kind::Concat) continue;
        for (std::size_t k = 0; k + 1 < n.args.size(); ++k) {
            if (ir.nodes[n.args[k]].kind == Kind::Zero &&
                ir.nodes[n.args[k + 1]].kind == Kind::Zero) {
                return canon_fail(i, kCanon4, "adjacent Zero children in Concat");
            }
        }
    }
    return std::nullopt;
}

std::optional<WfReport> find_c5(const Ir& ir) {
    const BigInt two(2);
    for (u32 i = 0; i < ir.nodes.size(); ++i) {
        const Node& n = ir.nodes[i];
        if (n.kind != Kind::Repeat) continue;
        const BigInt child_len = ir.nodes[n.args[0]].length;
        if (n.a.compare(two) < 0) {
            return canon_fail(i, kCanon5, "Repeat with q < 2");
        }
        if (n.b.compare(BigInt::zero()) < 0 || n.b.compare(child_len) >= 0) {
            return canon_fail(i, kCanon5, "Repeat with r outside [0, len(child))");
        }
    }
    return std::nullopt;
}

std::optional<WfReport> find_c6(const Ir& ir) {
    for (u32 i = 0; i < ir.nodes.size(); ++i) {
        const Node& n = ir.nodes[i];
        if (n.kind != Kind::Slice) continue;
        const Node& child = ir.nodes[n.args[0]];
        if (child.kind == Kind::Slice) {
            return canon_fail(i, kCanon6, "Slice child is a Slice");
        }
        if (n.b.is_zero()) {
            return canon_fail(i, kCanon6, "Slice with length 0");
        }
        if (n.a.is_zero() && n.b.compare(child.length) == 0) {
            return canon_fail(i, kCanon6, "full-cover Slice (start = 0, len = len(child))");
        }
    }
    return std::nullopt;
}

std::optional<WfReport> find_c7(const Ir& ir) {
    for (u32 i = 0; i < ir.nodes.size(); ++i) {
        const Node& n = ir.nodes[i];
        if (n.kind != Kind::Morph) continue;
        const Node& child = ir.nodes[n.args[0]];
        if (child.kind != Kind::Morph) continue;
        // A Morph whose child is a Morph is reportable exactly when one of the
        // rule 7 folds would fire (see REPORT/E2/C04-CANON-REPORT.md §5).
        if (n.morph == child.morph && n.morph_k == 0 && child.morph_k == 0) {
            return canon_fail(i, kCanon7, "identical adjacent involutions");
        }
        const bool outer_rot = (n.morph == 6 || n.morph == 7);
        const bool inner_rot = (child.morph == 6 || child.morph == 7);
        if (outer_rot && inner_rot) {
            return canon_fail(i, kCanon7, "adjacent rotations compose");
        }
    }
    return std::nullopt;
}

std::optional<WfReport> find_c8(const Ir& ir) {
    for (u32 i = 0; i < ir.nodes.size(); ++i) {
        const Node& n = ir.nodes[i];
        if (n.kind != Kind::Xor) continue;
        const u32 a = n.args[0];
        const u32 b = n.args[1];
        if (ir.nodes[a].kind == Kind::Zero || ir.nodes[b].kind == Kind::Zero) {
            return canon_fail(i, kCanon8, "Xor with a Zero operand");
        }
        if (structurally_equal(ir, a, b)) {
            return canon_fail(i, kCanon8, "Xor of structurally identical operands");
        }
        const std::string ka = canonical_key(ir, a);
        const std::string kb = canonical_key(ir, b);
        if (key_less(kb, ka)) {
            return canon_fail(i, kCanon8, "Xor operands not ordered by canonical_key");
        }
    }
    return std::nullopt;
}

std::optional<WfReport> find_c9(const Ir& ir) {
    for (u32 i = 0; i < ir.nodes.size(); ++i) {
        const Node& n = ir.nodes[i];
        if (n.kind == Kind::Interleave && n.args.size() < 2) {
            return canon_fail(i, kCanon9, "Interleave with argc < 2");
        }
    }
    return std::nullopt;
}

std::optional<WfReport> find_c10(const Ir& ir) {
    for (u32 i = 0; i < ir.nodes.size(); ++i) {
        const Node& n = ir.nodes[i];
        if (n.kind == Kind::Affine && n.affine_step == 0) {
            return canon_fail(i, kCanon10, "Affine with step = 0");
        }
    }
    return std::nullopt;
}

std::optional<WfReport> find_c11(const Ir& ir) {
    for (u32 i = 0; i < ir.nodes.size(); ++i) {
        const Node& n = ir.nodes[i];
        if ((n.kind == Kind::Repeat || n.kind == Kind::Slice) &&
            ir.nodes[n.args[0]].kind == Kind::Zero) {
            return canon_fail(i, kCanon11,
                              n.kind == Kind::Repeat ? "Repeat with Zero child"
                                                      : "Slice with Zero child");
        }
    }
    return std::nullopt;
}

}  // namespace
}  // namespace marp::v2
namespace marp::v2 {
namespace {

// ===========================================================================
// Rule 12 check: structural duplicates via 128-bit signatures + confirmation
// =========================================================================

// 128-bit FNV-1a accumulator; used only to group nodes for the exact
// structural-equality confirmation (rule 12 check).
struct Sig128 {
    u64 lo = 0xcbf29ce484222325ull;
    u64 hi = 0x9e3779b97f4a7c15ull;
    void feed(u8 byte) {
        lo ^= byte;
        lo *= 0x100000001b3ull;
        hi ^= static_cast<u64>(byte) + 0x9Eu;
        hi *= 0x100000001b3ull;
        hi ^= hi >> 13;
    }
    void feed_bytes(const u8* data, std::size_t size) {
        for (std::size_t i = 0; i < size; ++i) feed(data[i]);
    }
};

struct SigPair {
    u64 lo = 0;
    u64 hi = 0;
    bool operator==(const SigPair& other) const noexcept {
        return lo == other.lo && hi == other.hi;
    }
};

struct SigPairHash {
    std::size_t operator()(const SigPair& pair) const noexcept {
        return static_cast<std::size_t>(pair.lo ^
                                        (pair.hi + 0x9e3779b97f4a7c15ull + (pair.lo << 6) +
                                         (pair.lo >> 2)));
    }
};

void sig_feed_u64(Sig128& sig, u64 value) {
    for (unsigned i = 0; i < 8; ++i) {
        sig.feed(static_cast<u8>((value >> (i * 8u)) & 0xFFu));
    }
}

std::vector<SigPair> compute_sigs(const Ir& ir) {
    const std::size_t n = ir.nodes.size();
    std::vector<SigPair> sigs(n);
    for (std::size_t i = 0; i < n; ++i) {
        const Node& node = ir.nodes[i];
        Sig128 acc;
        std::string params;
        if (node.kind == Kind::Atom) {
            params += tag_of(node.kind);
            auto atom_id = node.a.to_u64_checked();
            if (atom_id.has_value() && *atom_id < static_cast<u64>(ir.atoms.size())) {
                const Atom& atom = ir.atoms[static_cast<std::size_t>(*atom_id)];
                enc_bigint(params, atom.length);
                params.append(reinterpret_cast<const char*>(atom.sha256.data()),
                              atom.sha256.size());
            }
        } else {
            enc_node_params(params, node.kind, node.a, node.b, node.morph, node.morph_k,
                            node.lfsr_conn, node.lfsr_init, node.affine_start,
                            node.affine_step, node.predictor_id, node.predictor_param,
                            node.args.size());
        }
        acc.feed_bytes(reinterpret_cast<const u8*>(params.data()), params.size());
        for (const u32 child : node.args) {
            sig_feed_u64(acc, sigs[child].lo);
            sig_feed_u64(acc, sigs[child].hi);
        }
        sigs[i] = SigPair{acc.lo, acc.hi};
    }
    return sigs;
}

std::optional<WfReport> find_c12(const Ir& ir) {
    const std::vector<SigPair> sigs = compute_sigs(ir);
    std::unordered_map<SigPair, u32, SigPairHash> first_seen;
    first_seen.reserve(ir.nodes.size() * 2 + 1);
    for (u32 i = 0; i < ir.nodes.size(); ++i) {
        const auto it = first_seen.find(sigs[i]);
        if (it != first_seen.end()) {
            const u32 j = it->second;
            if (structurally_equal(ir, i, j)) {
                return canon_fail(i, kCanon12,
                                  "structurally identical subterm already emitted at node " +
                                      std::to_string(j));
            }
            // Signature collision on distinct structures: keep the earlier one.
            continue;
        }
        first_seen.emplace(sigs[i], i);
    }
    return std::nullopt;
}

// ===========================================================================
// Rule 13 check: reachability, post-order identity, atom first-use, payload
// =========================================================================

std::optional<WfReport> find_c13(const Ir& ir) {
    const u32 n = static_cast<u32>(ir.nodes.size());
    // Post-order visit from the root.
    struct Frame {
        u32 id;
        std::size_t next_child;
    };
    std::vector<u32> order;
    order.reserve(n);
    std::vector<char> visited(n, 0);
    std::vector<Frame> stack;
    stack.push_back({ir.root, 0});
    while (!stack.empty()) {
        Frame& top = stack.back();
        const Node& node = ir.nodes[top.id];
        if (top.next_child < node.args.size()) {
            const u32 child = node.args[top.next_child];
            ++top.next_child;
            if (visited[child] == 0) stack.push_back({child, 0});
            continue;
        }
        if (visited[top.id] == 0) {
            visited[top.id] = 1;
            order.push_back(top.id);
        }
        stack.pop_back();
    }
    if (order.size() != n) {
        return canon_fail(ir.root, kCanon13, "unreachable nodes present");
    }
    for (u32 i = 0; i < n; ++i) {
        if (order[i] != i) {
            return canon_fail(order[i], kCanon13,
                              "ids are not post-order first-use (position " +
                                  std::to_string(i) + " holds node " +
                                  std::to_string(order[i]) + ")");
        }
    }
    // Atom payload uniqueness (rule 13: no two atom records share a payload).
    {
        std::unordered_map<std::string, u32> seen;
        seen.reserve(ir.atoms.size() * 2 + 1);
        for (u32 i = 0; i < ir.atoms.size(); ++i) {
            const Atom& atom = ir.atoms[i];
            const std::string key(reinterpret_cast<const char*>(atom.payload.data()),
                                  atom.payload.size());
            const auto it = seen.find(key);
            if (it != seen.end()) {
                return canon_fail(i, kCanon13,
                                  "atom records share a payload (duplicates of atom " +
                                      std::to_string(it->second) + ")");
            }
            seen.emplace(key, i);
        }
    }
    // Atom first-use order: atom ids must be assigned in order of first use.
    {
        std::vector<u32> seq;
        for (const u32 id : order) {
            const Node& node = ir.nodes[id];
            if (node.kind != Kind::Atom) continue;
            auto atom_id = node.a.to_u64_checked();
            if (!atom_id.has_value() || *atom_id >= ir.atoms.size()) continue;  // WF-enforced
            seq.push_back(static_cast<u32>(*atom_id));
        }
        if (seq.size() != ir.atoms.size()) {
            return canon_fail(ir.root, kCanon13, "atoms emitted out of first-use order");
        }
        for (u32 i = 0; i < seq.size(); ++i) {
            if (seq[i] != i) {
                return canon_fail(seq[i], kCanon13,
                                  "atoms not in first-use order (position " +
                                      std::to_string(i) + " holds atom " +
                                      std::to_string(seq[i]) + ")");
            }
        }
    }
    if (ir.root != n - 1) {
        return canon_fail(ir.root, kCanon13, "root is not the last node");
    }
    return std::nullopt;
}

}  // namespace

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

Result<Ir> canon(const Ir& ir) {
    return canon_impl(ir, 64ull * (static_cast<u64>(ir.nodes.size()) + 1ull), nullptr);
}

Result<Ir> canon(const Ir& ir, CanonReport& report) {
    return canon_impl(ir, 64ull * (static_cast<u64>(ir.nodes.size()) + 1ull), &report);
}

Result<Ir> canon_with_budget(const Ir& ir, u64 max_rewrites, CanonReport* report) {
    return canon_impl(ir, max_rewrites, report);
}

WfReport check_canonical(const Ir& ir) {
    return check_canonical(ir, Limits{});
}

WfReport check_canonical(const Ir& ir, const Limits& limits) {
    const WfReport wf = check_well_formed_report(ir, limits);
    if (!wf.ok()) return wf;
    if (auto report = find_c1(ir)) return *report;
    if (auto report = find_c2(ir)) return *report;
    if (auto report = find_c3(ir)) return *report;
    if (auto report = find_c4(ir)) return *report;
    if (auto report = find_c5(ir)) return *report;
    if (auto report = find_c6(ir)) return *report;
    if (auto report = find_c7(ir)) return *report;
    if (auto report = find_c8(ir)) return *report;
    if (auto report = find_c9(ir)) return *report;
    if (auto report = find_c10(ir)) return *report;
    if (auto report = find_c11(ir)) return *report;
    if (auto report = find_c12(ir)) return *report;
    if (auto report = find_c13(ir)) return *report;
    WfReport report;
    report.code = Code::Ok;
    report.node = ir.root;
    report.constraint = "";
    report.message = "canonical";
    return report;
}

bool is_canonical(const Ir& ir) {
    return check_canonical(ir).ok();
}

bool is_canonical(const Ir& ir, const Limits& limits) {
    return check_canonical(ir, limits).ok();
}

}  // namespace marp::v2
