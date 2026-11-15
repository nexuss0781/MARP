// MARP v2 — E2 ALGEBRA — C06 DAG implementation.
//
// `Dag` records construction events in caller order and resolves them into a
// canonical `Ir` at `finish`: one serial post-order traversal from `root`,
// atoms appended on first encounter, structurally identical subterms and equal
// atom payloads interned to single records.
//
// Determinism argument (E2-I7, O6.1).  The intern key of an emitted node is a
// function of (kind, normalised parameters, output child ids, atom record id of
// its payload).  Output child ids and atom record ids are themselves produced by
// the same traversal, which is a pure function of the logical term reachable
// from `root`.  The hash maps below are probed only — iteration order never
// reaches the output — and no pointer value, address, or construction index is
// ever encoded into a key.  Construction order therefore cannot influence the
// emitted ids.
//
// Atom dedup (E2 §4.8, C06 O6.3).  The dedup key is the exact payload bytes, a
// refinement of the normative `(length, SHA-256)` key: equal bytes always agree
// in `(length, SHA-256)`, and a SHA-256 collision between different payloads can
// never merge two records (it would be `Mismatch` at E3, never a merge permit).

#include "mapr/e2/e2_dag.hpp"

#include <cstddef>
#include <cstring>
#include <deque>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include "mapr/e1_sha256.hpp"

namespace marp::v2 {
namespace {

constexpr u32 kUnset = ~0u;

// --- key encoding -----------------------------------------------------------
// Self-delimiting, pre-order, id-free apart from the output ids themselves.
void enc_uvarint(std::string& out, u64 value) {
    while (value >= 0x80u) {
        out.push_back(static_cast<char>((value & 0x7Fu) | 0x80u));
        value >>= 7u;
    }
    out.push_back(static_cast<char>(value & 0x7Fu));
}

void enc_bigint(std::string& out, const BigInt& value) {
    const std::string decimal = value.to_decimal();
    enc_uvarint(out, static_cast<u64>(decimal.size()));
    out += decimal;
}

void enc_u64_fixed(std::string& out, u64 value) {
    for (unsigned shift = 0; shift < 64u; shift += 8u) {
        out.push_back(static_cast<char>((value >> shift) & 0xFFu));
    }
}

// The intern key of an *emitted* node: kind, the parameters the kind owns, and
// the already-canonical output ids of its children.  Because child ids are
// themselves output ids, the key is construction-order free (E2-I7).
std::string emit_key(const Node& node) {
    std::string key;
    key.push_back(static_cast<char>(static_cast<u8>(node.kind)));
    switch (node.kind) {
        case Kind::Empty:
            break;
        case Kind::Atom:
            enc_bigint(key, node.a);  // output atom record id
            break;
        case Kind::Zero:
            enc_bigint(key, node.a);
            break;
        case Kind::Concat:
        case Kind::Xor:
            break;
        case Kind::Interleave:
            enc_bigint(key, node.a);
            break;
        case Kind::Repeat:
        case Kind::Slice:
            enc_bigint(key, node.a);
            enc_bigint(key, node.b);
            break;
        case Kind::Morph:
            key.push_back(static_cast<char>(node.morph));
            key.push_back(static_cast<char>(node.morph_k));
            break;
        case Kind::Lfsr:
            enc_u64_fixed(key, node.lfsr_conn);
            enc_u64_fixed(key, node.lfsr_init);
            enc_bigint(key, node.a);
            break;
        case Kind::Affine:
            key.push_back(static_cast<char>(node.affine_start));
            key.push_back(static_cast<char>(node.affine_step));
            enc_bigint(key, node.a);
            break;
        case Kind::Predictor:
            key.push_back(static_cast<char>(node.predictor_id));
            enc_u64_fixed(key, node.predictor_param);
            break;
    }
    enc_uvarint(key, static_cast<u64>(node.args.size()));
    for (const u32 child : node.args) enc_uvarint(key, child);
    return key;
}

// Normalises a caller-supplied node so that only the fields the kind owns
// survive; `length` is dropped (recomputed from structure at `finish`).
Node normalise(const Node& in) {
    Node node;
    node.kind = in.kind;
    node.flags = 0;
    node.args = in.args;
    switch (in.kind) {
        case Kind::Atom:
            node.a = in.a;
            break;
        case Kind::Zero:
            node.a = in.a;
            break;
        case Kind::Repeat:
            node.a = in.a;
            node.b = in.b;
            break;
        case Kind::Slice:
            node.a = in.a;
            node.b = in.b;
            break;
        case Kind::Morph:
            node.morph = in.morph;
            node.morph_k = in.morph_k;
            break;
        case Kind::Interleave:
            node.a = in.a;
            break;
        case Kind::Lfsr:
            node.a = in.a;
            node.lfsr_conn = in.lfsr_conn;
            node.lfsr_init = in.lfsr_init;
            break;
        case Kind::Affine:
            node.a = in.a;
            node.affine_start = in.affine_start;
            node.affine_step = in.affine_step;
            break;
        case Kind::Predictor:
            node.predictor_id = in.predictor_id;
            node.predictor_param = in.predictor_param;
            break;
        case Kind::Empty:
        case Kind::Concat:
        case Kind::Xor:
            break;
    }
    return node;
}

bool kind_in_domain(Kind kind) {
    return static_cast<u8>(kind) < kKindCount;
}

Result<BigInt> bi_add(const BigInt& x, const BigInt& y) {
    auto sum = x.add(y);
    if (!sum.ok()) return Code::Limit;
    return sum.value();
}

Result<BigInt> bi_mul(const BigInt& x, const BigInt& y) {
    auto product = x.mul(y);
    if (!product.ok()) return Code::Limit;
    return product.value();
}

}  // namespace

// ---------------------------------------------------------------------------
// Builder state
// ---------------------------------------------------------------------------

struct Dag::Impl {
    struct AtomRecord {
        std::vector<u8> payload;
        u8 klass = 0;
    };

    Limits limits{};
    std::vector<AtomRecord> atoms;
    std::vector<Node> nodes;   // normalised, length unset
    std::vector<u32> depth;    // W7 depth per builder node (Empty == 0)
};

Dag::Dag() : impl_(std::make_unique<Impl>()) {}

Dag::Dag(const Limits& limits) : impl_(std::make_unique<Impl>()) { impl_->limits = limits; }

Dag::~Dag() = default;

Dag::Dag(Dag&&) noexcept = default;
Dag& Dag::operator=(Dag&&) noexcept = default;

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

Result<u32> Dag::add_atom(std::span<const u8> payload, u8 klass) {
    // A zero-length atom is not a well-formed term (E2 §4.5, W8.atom-length).
    if (payload.empty()) return Code::Invalid;
    if (impl_->atoms.size() >= static_cast<std::size_t>(impl_->limits.max_atoms)) {
        return Code::Limit;
    }
    Impl::AtomRecord record;
    record.payload.assign(payload.begin(), payload.end());
    record.klass = klass;
    impl_->atoms.push_back(std::move(record));
    return static_cast<u32>(impl_->atoms.size() - 1);
}

Result<u32> Dag::add_node(Node node) {
    if (!kind_in_domain(node.kind)) return Code::Invalid;
    if (node.flags != 0) return Code::Invalid;
    if (impl_->nodes.size() >= static_cast<std::size_t>(impl_->limits.max_nodes)) {
        return Code::Limit;
    }

    // Builder-local references: a child id must already exist in this Dag.
    u32 deepest = 0;  // Empty has depth 0, so an argument-less leaf gets depth 1
    for (const u32 child : node.args) {
        if (child >= impl_->nodes.size()) return Code::Invalid;
        if (impl_->depth[child] > deepest) deepest = impl_->depth[child];
    }
    if (node.kind == Kind::Atom) {
        if (!node.args.empty()) return Code::Invalid;  // Atom argc 0 (E2 §4.5)
        const auto atom_id = node.a.to_u64_checked();
        if (!atom_id.has_value() || *atom_id >= impl_->atoms.size()) return Code::Invalid;
    }

    // W7: depth = 1 + max(child depth), Empty = 0; the bound is inclusive.
    if (node.kind != Kind::Empty && deepest >= impl_->limits.max_depth) return Code::Limit;
    const u32 depth = (node.kind == Kind::Empty) ? 0u : deepest + 1u;

    impl_->nodes.push_back(normalise(node));
    impl_->depth.push_back(depth);
    return static_cast<u32>(impl_->nodes.size() - 1);
}

u32 Dag::node_count() const noexcept { return static_cast<u32>(impl_->nodes.size()); }

u32 Dag::atom_count() const noexcept { return static_cast<u32>(impl_->atoms.size()); }

const Limits& Dag::limits() const noexcept { return impl_->limits; }

const Node& Dag::builder_node(u32 id) const {
    static const Node kEmpty{};
    return id < impl_->nodes.size() ? impl_->nodes[id] : kEmpty;
}

std::span<const u8> Dag::builder_atom_payload(u32 id) const {
    if (id >= impl_->atoms.size()) return std::span<const u8>();
    const std::vector<u8>& payload = impl_->atoms[id].payload;
    return std::span<const u8>(payload.data(), payload.size());
}

u8 Dag::builder_atom_klass(u32 id) const {
    return id < impl_->atoms.size() ? impl_->atoms[id].klass : u8{0};
}

// ---------------------------------------------------------------------------
// finish (E2 §4.8 / §5.6)
// ---------------------------------------------------------------------------

Result<Ir> Dag::finish(u32 root) && {
    Impl& self = *impl_;
    if (root >= self.nodes.size()) return Code::Invalid;

    Ir ir;
    ir.atoms.reserve(self.atoms.size());
    ir.nodes.reserve(self.nodes.size());

    // Payload storage shared by every emitted atom (keeps `Atom::payload` valid
    // for the lifetime of the returned Ir, the C04 `owner` convention).
    auto store = std::make_shared<std::deque<std::vector<u8>>>();

    std::vector<u32> node_map(self.nodes.size(), kUnset);
    std::unordered_map<std::string, u32> node_intern;  // emit key -> output id
    std::unordered_map<std::string, u32> atom_intern;  // exact payload -> atom id

    struct Frame {
        u32 id;
        std::size_t next_child;
    };
    std::vector<Frame> stack;
    stack.push_back(Frame{root, 0});

    while (!stack.empty()) {
        Frame& top = stack.back();
        const Node& source = self.nodes[top.id];

        // -- enter: children in argument order ------------------------------
        if (top.next_child < source.args.size()) {
            const u32 child = source.args[top.next_child];
            ++top.next_child;
            if (node_map[child] == kUnset) stack.push_back(Frame{child, 0});
            continue;
        }

        // -- leave: a shared subterm was already interned --------------------
        if (node_map[top.id] != kUnset) {
            stack.pop_back();
            continue;
        }

        Node out;
        out.kind = source.kind;
        out.flags = 0;
        switch (source.kind) {
            case Kind::Atom: {
                const u32 record = static_cast<u32>(source.a.to_u64_checked().value_or(0));
                if (record >= self.atoms.size()) return Code::Invalid;
                const std::vector<u8>& payload = self.atoms[record].payload;
                const std::string payload_key(reinterpret_cast<const char*>(payload.data()),
                                              payload.size());
                const auto it = atom_intern.find(payload_key);
                u32 atom_id = 0;
                if (it != atom_intern.end()) {
                    atom_id = it->second;
                } else {
                    store->emplace_back(payload.begin(), payload.end());
                    const std::vector<u8>& stored = store->back();
                    const std::string_view view(reinterpret_cast<const char*>(stored.data()),
                                                stored.size());
                    auto digest = mapr::Sha256::hash(view);
                    if (!digest.ok()) return Code::Limit;
                    Atom atom;
                    atom.klass = self.atoms[record].klass;
                    atom.flags = 0;
                    atom.length = BigInt(static_cast<u64>(stored.size()));
                    atom.sha256 = digest.value();
                    atom.payload = std::span<const u8>(stored.data(), stored.size());
                    atom.owner = store;
                    ir.atoms.push_back(std::move(atom));
                    atom_id = static_cast<u32>(ir.atoms.size() - 1);
                    atom_intern.emplace(payload_key, atom_id);
                }
                out.args.clear();
                out.a = BigInt(atom_id);
                out.b = BigInt::zero();
                out.length = ir.atoms[atom_id].length;
                break;
            }
            case Kind::Empty:
                out.args.clear();
                out.length = BigInt::zero();
                break;
            case Kind::Zero:
                out.args.clear();
                out.a = source.a;
                out.length = source.a;
                break;
            case Kind::Concat: {
                BigInt total = BigInt::zero();
                out.args.reserve(source.args.size());
                for (const u32 child : source.args) {
                    const u32 out_id = node_map[child];
                    out.args.push_back(out_id);
                    auto sum = bi_add(total, ir.nodes[out_id].length);
                    if (!sum.ok()) return sum.code();
                    total = std::move(sum.value());
                }
                out.length = std::move(total);
                break;
            }
            case Kind::Repeat: {
                const u32 child = node_map[source.args[0]];
                out.args.push_back(child);
                out.a = source.a;
                out.b = source.b;
                auto product = bi_mul(source.a, ir.nodes[child].length);
                if (!product.ok()) return product.code();
                auto total = bi_add(product.value(), source.b);
                if (!total.ok()) return total.code();
                out.length = std::move(total.value());
                break;
            }
            case Kind::Slice: {
                const u32 child = node_map[source.args[0]];
                out.args.push_back(child);
                out.a = source.a;
                out.b = source.b;
                out.length = source.b;
                break;
            }
            case Kind::Morph: {
                const u32 child = node_map[source.args[0]];
                out.args.push_back(child);
                out.morph = source.morph;
                out.morph_k = source.morph_k;
                out.length = ir.nodes[child].length;
                break;
            }
            case Kind::Xor: {
                const u32 first = node_map[source.args[0]];
                const u32 second = node_map[source.args[1]];
                out.args.push_back(first);
                out.args.push_back(second);
                out.length = ir.nodes[first].length;
                break;
            }
            case Kind::Interleave: {
                out.args.reserve(source.args.size());
                for (const u32 child : source.args) out.args.push_back(node_map[child]);
                out.a = source.a;
                auto total = bi_mul(BigInt(static_cast<u64>(out.args.size())),
                                    ir.nodes[out.args.front()].length);
                if (!total.ok()) return total.code();
                out.length = std::move(total.value());
                break;
            }
            case Kind::Lfsr:
                out.args.clear();
                out.a = source.a;
                out.lfsr_conn = source.lfsr_conn;
                out.lfsr_init = source.lfsr_init;
                out.length = source.a;
                break;
            case Kind::Affine:
                out.args.clear();
                out.a = source.a;
                out.affine_start = source.affine_start;
                out.affine_step = source.affine_step;
                out.length = source.a;
                break;
            case Kind::Predictor: {
                const u32 child = node_map[source.args[0]];
                out.args.push_back(child);
                out.predictor_id = source.predictor_id;
                out.predictor_param = source.predictor_param;
                out.length = ir.nodes[child].length;
                break;
            }
            default:
                return Code::Invalid;
        }

        // -- intern (O6.1): identical subterms share one node ---------------
        const std::string key = emit_key(out);
        const auto it = node_intern.find(key);
        if (it != node_intern.end()) {
            node_map[top.id] = it->second;
            stack.pop_back();
            continue;
        }
        const u32 out_id = static_cast<u32>(ir.nodes.size());
        ir.nodes.push_back(std::move(out));
        node_intern.emplace(key, out_id);
        node_map[top.id] = out_id;
        stack.pop_back();
    }

    if (ir.nodes.empty()) return Code::Invalid;

    // Root is the last emitted node by construction; assert the contract.
    ir.root = static_cast<u32>(ir.nodes.size() - 1);
    ir.total_length = ir.nodes[ir.root].length;

    // The emitted term must be well-formed (W1–W8, §8.3 cap).  Kind-specific
    // constraints that a caller can violate (argc, r >= len(child), Xor length
    // mismatch, ...) are rejected here with the normative code.
    const Status wf = check_well_formed(ir, self.limits);
    if (!wf.ok()) return wf.code();

    return ir;
}

}  // namespace marp::v2
