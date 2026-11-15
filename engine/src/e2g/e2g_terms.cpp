// MARP v2 — E2-G integrated ALGEBRA gate — term description implementation.

#include "e2g_terms.hpp"

#include <algorithm>
#include <cstring>

namespace e2g {
namespace {

constexpr std::size_t kUnresolved = std::numeric_limits<std::size_t>::max();

std::string kind_tag(Kind kind) {
    return std::string(kind_name(kind));
}

}  // namespace

void DescArena::set_kind_raw(const std::string& node_id, u8 raw) {
    node_mut(node_id).kind = static_cast<Kind>(raw);
}

std::optional<BigInt> DescArena::length_of(const std::string& id) const {
    // Local recursive recomputation with a visiting set for cycles.  This is a
    // third independent transcription of the §4.4 formulas (the gate's binder
    // and the C03 reference are the other two); it only ever measures the
    // description the corpus generator just built.
    struct Solver {
        const DescArena& arena;
        std::vector<BigInt> memo;
        std::vector<char> state;  // 0 = new, 1 = visiting, 2 = done
        explicit Solver(const DescArena& a) : arena(a), memo(a.node_count()), state(a.node_count(), 0) {}

        std::size_t idx(const std::string& node_id) const {
            const auto& nodes = arena.nodes();
            for (std::size_t i = 0; i < nodes.size(); ++i) {
                if (nodes[i].id == node_id) return i;
            }
            return nodes.size();
        }
        std::size_t aidx(const std::string& atom_id) const {
            const auto& atoms = arena.atoms();
            for (std::size_t i = 0; i < atoms.size(); ++i) {
                if (atoms[i].id == atom_id) return i;
            }
            return atoms.size();
        }

        std::optional<BigInt> solve(std::size_t i) {
            if (i >= state.size()) return std::nullopt;
            if (state[i] == 2) return memo[i];
            if (state[i] == 1) return std::nullopt;
            state[i] = 1;
            const DescNode& n = arena.nodes()[i];
            std::vector<BigInt> kids;
            bool ok = true;
            for (const std::string& kid : n.kids) {
                auto sub = solve(idx(kid));
                if (!sub.has_value()) {
                    ok = false;
                    kids.emplace_back();
                    continue;
                }
                kids.push_back(sub.value());
            }
            BigInt out;
            switch (n.kind) {
                case Kind::Empty: out = BigInt::zero(); break;
                case Kind::Atom: {
                    const std::size_t a = aidx(n.atom);
                    if (a >= arena.atoms().size()) { ok = false; }
                    else out = BigInt(static_cast<u64>(arena.atoms()[a].payload.size()));
                    break;
                }
                case Kind::Zero: out = n.a; break;
                case Kind::Concat:
                    out = BigInt::zero();
                    for (const BigInt& k : kids) out = out.add(k).value();
                    break;
                case Kind::Repeat:
                    if (!ok || kids.empty()) { ok = false; out = BigInt::zero(); }
                    else out = n.a.mul(kids[0]).value().add(n.b).value();
                    break;
                case Kind::Slice: out = n.b; break;
                case Kind::Morph:
                case Kind::Xor:
                    if (!ok || kids.empty()) { ok = false; out = BigInt::zero(); }
                    else out = kids[0];
                    break;
                case Kind::Interleave:
                    if (!ok || kids.empty()) { ok = false; out = BigInt::zero(); }
                    else out = BigInt(static_cast<u64>(kids.size())).mul(kids[0]).value();
                    break;
                case Kind::Lfsr:
                case Kind::Affine: out = n.a; break;
                case Kind::Predictor:
                    if (!ok || kids.empty()) { ok = false; out = BigInt::zero(); }
                    else out = kids[0];
                    break;
                default: ok = false; break;
            }
            state[i] = 2;
            memo[i] = out;
            if (!ok) return std::nullopt;
            return out;
        }
    };
    Solver solver(*this);
    const std::size_t i = index_of(id);
    if (i >= nodes_.size()) return std::nullopt;
    return solver.solve(i);
}

// ---------------------------------------------------------------------------
// Structural length (E2 §4.4) over a description: dependency order, not file
// order, so ill-ordered but acyclic descriptions still yield exact lengths.
// ---------------------------------------------------------------------------

namespace {

struct LengthSolver {
    const TermDesc& desc;
    std::vector<BigInt> lengths;
    std::vector<char> known;
    std::vector<char> visiting;

    explicit LengthSolver(const TermDesc& d)
        : desc(d), lengths(d.arena.node_count()), known(d.arena.node_count(), 0),
          visiting(d.arena.node_count(), 0) {}

    std::size_t index_of(const std::string& id) const {
        const auto& nodes = desc.arena.nodes();
        for (std::size_t i = 0; i < nodes.size(); ++i) {
            if (nodes[i].id == id) return i;
        }
        return kUnresolved;
    }

    std::size_t atom_index_of(const std::string& id) const {
        const auto& atoms = desc.arena.atoms();
        for (std::size_t i = 0; i < atoms.size(); ++i) {
            if (atoms[i].id == id) return i;
        }
        return kUnresolved;
    }

    // Returns true when the length of node `i` is known.
    bool solve(std::size_t i) {
        if (known[i] != 0) return true;
        if (visiting[i] != 0) return false;  // cycle
        visiting[i] = 1;
        const auto& nodes = desc.arena.nodes();
        const DescNode& n = nodes[i];
        bool ok = true;
        std::vector<BigInt> kid_len;
        kid_len.reserve(n.kids.size());
        for (const std::string& kid : n.kids) {
            const std::size_t k = index_of(kid);
            if (k == kUnresolved || !solve(k)) {
                ok = false;
                kid_len.emplace_back();
                continue;
            }
            kid_len.push_back(lengths[k]);
        }
        BigInt out;
        switch (n.kind) {
            case Kind::Empty:
                out = BigInt::zero();
                break;
            case Kind::Atom: {
                const std::size_t a = atom_index_of(n.atom);
                if (a == kUnresolved) {
                    ok = false;
                } else {
                    out = BigInt(static_cast<u64>(desc.arena.atoms()[a].payload.size()));
                }
                break;
            }
            case Kind::Zero:
                out = n.a;
                break;
            case Kind::Concat: {
                out = BigInt::zero();
                for (const BigInt& kl : kid_len) out = out.add(kl).value();
                break;
            }
            case Kind::Repeat: {
                if (!ok) {
                    out = BigInt::zero();
                } else {
                    out = n.a.mul(kid_len[0]).value().add(n.b).value();
                }
                break;
            }
            case Kind::Slice:
                out = n.b;
                break;
            case Kind::Morph: {
                if (!ok) out = BigInt::zero();
                else out = kid_len[0];
                break;
            }
            case Kind::Xor: {
                if (!ok) out = BigInt::zero();
                else out = kid_len[0];
                break;
            }
            case Kind::Interleave: {
                if (!ok || kid_len.empty()) {
                    out = BigInt::zero();
                    if (kid_len.empty()) ok = false;
                } else {
                    out = BigInt(static_cast<u64>(n.kids.size())).mul(kid_len[0]).value();
                }
                break;
            }
            case Kind::Lfsr:
            case Kind::Affine:
                out = n.a;
                break;
            case Kind::Predictor: {
                if (!ok) out = BigInt::zero();
                else out = kid_len[0];
                break;
            }
            default:
                ok = false;
                break;
        }
        visiting[i] = 0;
        if (!ok) return false;
        lengths[i] = out;
        known[i] = 1;
        return true;
    }
};

}  // namespace

BindResult bind_with(const TermDesc& desc, const std::string& root_override,
                     const std::optional<BigInt>& total_override) {
    BindResult result;
    const auto& desc_atoms = desc.arena.atoms();
    const auto& desc_nodes = desc.arena.nodes();

    if (desc_nodes.empty()) {
        result.error = "empty description";
        return result;
    }

    // Atom table: payload storage is owned by the result's `payload_store`
    // through `Atom::owner`, so the returned `Ir` is self-contained.
    auto payload_store = std::make_shared<std::deque<std::vector<u8>>>();
    for (const DescAtom& da : desc_atoms) {
        Atom atom;
        atom.klass = da.klass;
        atom.flags = da.flags;
        atom.length = da.declared_length.has_value()
                          ? da.declared_length.value()
                          : BigInt(static_cast<u64>(da.payload.size()));
        payload_store->push_back(da.payload);
        const std::vector<u8>& stored = payload_store->back();
        auto digest = mapr::Sha256::hash(std::string_view(
            reinterpret_cast<const char*>(stored.data()), stored.size()));
        if (digest.ok()) atom.sha256 = digest.value();
        atom.payload = std::span<const u8>(stored.data(), stored.size());
        atom.owner = payload_store;
        result.ir.atoms.push_back(atom);
    }

    std::vector<std::size_t> index_of(desc_nodes.size(), kUnresolved);
    for (std::size_t i = 0; i < desc_nodes.size(); ++i) index_of[i] = i;

    // Length pass.
    LengthSolver solver(desc);
    for (std::size_t i = 0; i < desc_nodes.size(); ++i) (void)solver.solve(i);
    result.recomputed = solver.lengths;
    result.known = solver.known;

    auto node_index = [&](const std::string& id) -> std::size_t {
        for (std::size_t i = 0; i < desc_nodes.size(); ++i) {
            if (desc_nodes[i].id == id) return i;
        }
        return kUnresolved;
    };
    auto atom_index = [&](const std::string& id) -> std::size_t {
        for (std::size_t i = 0; i < desc_atoms.size(); ++i) {
            if (desc_atoms[i].id == id) return i;
        }
        return kUnresolved;
    };

    bool ok = true;
    for (const DescNode& dn : desc_nodes) {
        Node node;
        node.kind = dn.kind;
        node.flags = dn.flags;
        for (const std::string& kid : dn.kids) {
            const std::size_t k = node_index(kid);
            if (k == kUnresolved) {
                ok = false;
                result.error = "unknown child reference '" + kid + "' in node '" + dn.id + "'";
                node.args.push_back(0);
            } else {
                node.args.push_back(static_cast<u32>(k));
            }
        }
        node.a = dn.a;
        node.b = dn.b;
        node.morph = dn.morph;
        node.morph_k = dn.morph_k;
        node.lfsr_conn = dn.lfsr_conn;
        node.lfsr_init = dn.lfsr_init;
        node.affine_start = dn.affine_start;
        node.affine_step = dn.affine_step;
        node.predictor_id = dn.predictor_id;
        node.predictor_param = dn.predictor_param;
        if (dn.kind == Kind::Atom) {
            const std::size_t a = atom_index(dn.atom);
            if (a == kUnresolved) {
                ok = false;
                result.error = "unknown atom reference '" + dn.atom + "'";
                node.a = BigInt(0);
            } else {
                node.a = BigInt(static_cast<u64>(a));
            }
        }
        const std::size_t i = static_cast<std::size_t>(result.ir.nodes.size());
        if (dn.stored_length.has_value()) {
            node.length = dn.stored_length.value();
        } else if (solver.known[i] != 0) {
            node.length = solver.lengths[i];
        } else {
            node.length = BigInt(0);
        }
        result.ir.nodes.push_back(std::move(node));
    }

    const std::string effective_root =
        root_override.empty() ? desc.root : root_override;
    const std::size_t root_index = node_index(effective_root);
    if (root_index == kUnresolved) {
        ok = false;
        result.error = "unknown root reference '" + effective_root + "'";
        result.ir.root = 0;
        result.ir.total_length = result.ir.nodes.front().length;
        // An out-of-range root is preserved so the WF report identifies W2.root.
        result.ir.root = static_cast<u32>(desc_nodes.size());
    } else {
        result.ir.root = static_cast<u32>(root_index);
        result.ir.total_length = result.ir.nodes[root_index].length;
    }
    if (total_override.has_value()) result.ir.total_length = total_override.value();
    result.ok = ok;
    return result;
}

BindResult bind(const TermDesc& desc) {
    return bind_with(desc, std::string(), std::optional<BigInt>());
}

// ---------------------------------------------------------------------------
// Structural equality
// ---------------------------------------------------------------------------

bool ir_structurally_equal(const Ir& a, const Ir& b) {
    if (a.nodes.size() != b.nodes.size()) return false;
    if (a.atoms.size() != b.atoms.size()) return false;
    if (a.root != b.root) return false;
    if (!bi_eq(a.total_length, b.total_length)) return false;
    for (std::size_t i = 0; i < a.atoms.size(); ++i) {
        const Atom& x = a.atoms[i];
        const Atom& y = b.atoms[i];
        if (x.klass != y.klass || x.flags != y.flags) return false;
        if (!bi_eq(x.length, y.length)) return false;
        if (x.sha256 != y.sha256) return false;
        if (x.payload.size() != y.payload.size()) return false;
        if (!x.payload.empty() && std::memcmp(x.payload.data(), y.payload.data(),
                                              x.payload.size()) != 0) {
            return false;
        }
    }
    for (std::size_t i = 0; i < a.nodes.size(); ++i) {
        const Node& x = a.nodes[i];
        const Node& y = b.nodes[i];
        if (x.kind != y.kind || x.flags != y.flags) return false;
        if (x.args != y.args) return false;
        if (!bi_eq(x.a, y.a) || !bi_eq(x.b, y.b)) return false;
        if (x.morph != y.morph || x.morph_k != y.morph_k) return false;
        if (x.lfsr_conn != y.lfsr_conn || x.lfsr_init != y.lfsr_init) return false;
        if (x.affine_start != y.affine_start || x.affine_step != y.affine_step) return false;
        if (x.predictor_id != y.predictor_id || x.predictor_param != y.predictor_param) return false;
        if (!bi_eq(x.length, y.length)) return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Canonical description text (id-independent, length-exact)
// ---------------------------------------------------------------------------

std::string describe_desc(const TermDesc& desc) {
    const auto& nodes = desc.arena.nodes();
    const auto& atoms = desc.arena.atoms();
    LengthSolver solver(desc);
    for (std::size_t i = 0; i < nodes.size(); ++i) (void)solver.solve(i);

    std::string text = "term|" + desc.id + "|" + desc.corpus;
    text += "|root=" + desc.root;
    text += "|nodes=" + std::to_string(nodes.size());
    text += "|atoms=" + std::to_string(atoms.size());
    for (std::size_t i = 0; i < atoms.size(); ++i) {
        text += "|A" + std::to_string(i) + ":" + std::to_string(atoms[i].payload.size()) + ":" +
                sha_of_bytes(atoms[i].payload) + ":" +
                std::to_string(static_cast<unsigned>(atoms[i].klass));
    }
    for (std::size_t i = 0; i < nodes.size(); ++i) {
        const DescNode& n = nodes[i];
        text += "|N" + std::to_string(i) + ":" + kind_tag(n.kind);
        for (const std::string& kid : n.kids) text += "," + kid;
        text += ";a=" + n.a.to_decimal() + ";b=" + n.b.to_decimal();
        text += ";m=" + std::to_string(static_cast<unsigned>(n.morph)) + "/" +
                std::to_string(static_cast<unsigned>(n.morph_k));
        text += ";l=" + std::to_string(n.lfsr_conn) + "/" + std::to_string(n.lfsr_init);
        text += ";f=" + std::to_string(static_cast<unsigned>(n.affine_start)) + "/" +
                std::to_string(static_cast<unsigned>(n.affine_step));
        text += ";p=" + std::to_string(static_cast<unsigned>(n.predictor_id)) + "/" +
                std::to_string(n.predictor_param);
        text += ";k=" + n.atom;
        text += ";L=" + (solver.known[i] != 0 ? solver.lengths[i].to_decimal() : std::string("?"));
        if (n.stored_length.has_value()) text += ";S=" + n.stored_length.value().to_decimal();
        text += ";id=" + n.id;
        if (!n.note.empty()) text += ";note=" + n.note;
    }
    return text;
}

std::string describe_ir(const Ir& ir) {
    if (ir.nodes.empty()) return "empty-ir";
    std::string text = "ir|root=" + std::to_string(ir.root);
    text += "|len=" + ir.total_length.to_decimal();
    text += "|nodes=" + std::to_string(ir.nodes.size());
    text += "|atoms=" + std::to_string(ir.atoms.size());
    for (std::size_t i = 0; i < ir.atoms.size(); ++i) {
        const Atom& a = ir.atoms[i];
        text += "|A" + std::to_string(i) + ":" + a.length.to_decimal() + ":" + hex_array(a.sha256) +
                ":" + std::to_string(static_cast<unsigned>(a.klass));
    }
    for (std::size_t i = 0; i < ir.nodes.size(); ++i) {
        const Node& n = ir.nodes[i];
        text += "|N" + std::to_string(i) + ":" + kind_tag(n.kind) + ":";
        for (std::size_t k = 0; k < n.args.size(); ++k) {
            if (k != 0) text += ",";
            text += std::to_string(n.args[k]);
        }
        text += ";a=" + n.a.to_decimal() + ";b=" + n.b.to_decimal();
        text += ";m=" + std::to_string(static_cast<unsigned>(n.morph)) + "/" +
                std::to_string(static_cast<unsigned>(n.morph_k));
        text += ";l=" + std::to_string(n.lfsr_conn) + "/" + std::to_string(n.lfsr_init);
        text += ";f=" + std::to_string(static_cast<unsigned>(n.affine_start)) + "/" +
                std::to_string(static_cast<unsigned>(n.affine_step));
        text += ";p=" + std::to_string(static_cast<unsigned>(n.predictor_id)) + "/" +
                std::to_string(n.predictor_param);
        text += ";L=" + n.length.to_decimal();
    }
    return text;
}


// ---------------------------------------------------------------------------
// Dag replay in a caller-seeded construction order (E2 §5.6, O6.1/O6.2)
// ---------------------------------------------------------------------------

DagReplay replay_dag(const TermDesc& desc, u64 seed) {
    DagReplay out;
    const auto& desc_nodes = desc.arena.nodes();
    const auto& desc_atoms = desc.arena.atoms();
    if (desc_nodes.empty()) {
        out.error = "empty description";
        return out;
    }

    // Description node ids are creation-ordered and children are already
    // resolved by `bind`, so replay uses the bound graph for its dependency
    // edges and rebuilds each node through `Dag::add_node` in a random order
    // that still visits every child first.
    const BindResult bound = bind(desc);
    if (!bound.ok) {
        out.error = bound.error;
        return out;
    }
    const Ir& ir = bound.ir;

    std::vector<std::vector<u32>> kids(ir.nodes.size());
    for (std::size_t i = 0; i < ir.nodes.size(); ++i) {
        kids[i] = ir.nodes[i].args;
    }

    // Random topological order: repeatedly pick a random node whose children are
    // already emitted.  Deterministic for a given seed.
    RngLike rng(seed);
    std::vector<u32> order;
    order.reserve(ir.nodes.size());
    std::vector<char> emitted(ir.nodes.size(), 0);
    std::vector<u32> ready;
    auto scan_ready = [&]() {
        ready.clear();
        for (std::size_t i = 0; i < ir.nodes.size(); ++i) {
            if (emitted[i] != 0) continue;
            bool ok = true;
            for (const u32 k : kids[i]) {
                if (k >= ir.nodes.size() || emitted[k] == 0) { ok = false; break; }
            }
            if (ok) ready.push_back(static_cast<u32>(i));
        }
    };
    scan_ready();
    while (order.size() < ir.nodes.size()) {
        if (ready.empty()) {
            out.error = "cyclic description";
            return out;
        }
        const u64 pick = rng.next() % ready.size();
        const u32 chosen = ready[static_cast<std::size_t>(pick)];
        order.push_back(chosen);
        emitted[chosen] = 1;
        scan_ready();
    }

    Dag dag;
    std::vector<u32> builder_id(ir.nodes.size(), 0);
    std::vector<char> have_builder(ir.nodes.size(), 0);
    for (const u32 id : order) {
        const Node& n = ir.nodes[id];
        Node out_node = n;
        out_node.args.clear();
        for (const u32 kid : n.args) {
            if (have_builder[kid] == 0) {
                out.error = "child emitted after parent";
                return out;
            }
            out_node.args.push_back(builder_id[kid]);
        }
        if (n.kind == Kind::Atom) {
            const u64 a = n.a.to_u64_checked().value_or(ir.atoms.size());
            if (a >= ir.atoms.size()) {
                out.error = "atom reference out of range";
                return out;
            }
            auto atom_id = dag.add_atom(ir.atoms[static_cast<std::size_t>(a)].payload,
                                        ir.atoms[static_cast<std::size_t>(a)].klass);
            if (!atom_id.ok()) {
                out.error = std::string("add_atom: ") + code_name(atom_id.code());
                return out;
            }
            out_node.a = BigInt(static_cast<u64>(atom_id.value()));
        }
        auto node_id = dag.add_node(std::move(out_node));
        if (!node_id.ok()) {
            out.error = std::string("add_node: ") + code_name(node_id.code());
            return out;
        }
        builder_id[id] = node_id.value();
        have_builder[id] = 1;
    }
    if (have_builder[ir.root] == 0) {
        out.error = "root not emitted";
        return out;
    }
    auto finished = std::move(dag).finish(builder_id[ir.root]);
    if (!finished.ok()) {
        out.error = std::string("finish: ") + code_name(finished.code());
        return out;
    }
    out.ir = std::move(finished.value());
    out.ok = true;
    (void)desc_atoms;
    return out;
}

}  // namespace e2g
