// MARP v2 — E2 ALGEBRA — C06 DAG evidence harness.
//
// Produces, with `--root <repo> --write-evidence`:
//   specs_and_reports/v2/gates/C06-DAG.tsv
//   specs_and_reports/v2/logs/C06-DAG.log
//   specs_and_reports/v2/evidence/C06/SHA256SUMS
//
// Never asserts: every obligation is evaluated and recorded as a TSV row with
// exact expected/actual values and a PASS/FAIL verdict.
//
// Coverage (C06 prompt §6):
//   O6.1  construction-order independence (8 shuffled topological construction
//         orders per corpus term, reversed atom registration order, 4 threads,
//         repeated runs) — every emitted `Ir` field compared, not just a digest;
//   O6.2  canonical shape: root == nodes.size()-1, topological ids, no unused
//         nodes or atoms, reachable-from-root consistency, maximal interning;
//   O6.3  atom payload dedup, independent of insertion order;
//   errors/limits; C03/C04/C05 integration; source-level isolation; coverage.

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <optional>
#include <random>
#include <set>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include "c03_build.hpp"
#include "c03_reference.hpp"
#include "mapr/e1_sha256.hpp"
#include "mapr/e2/e2_canon.hpp"
#include "mapr/e2/e2_dag.hpp"
#include "mapr/e2/e2_eval.hpp"
#include "mapr/e2/e2_term.hpp"

namespace c06 {

using namespace marp::v2;  // NOLINT
using c03::Builder;
using c03::pattern;

// ---------------------------------------------------------------------------
// small utilities
// ---------------------------------------------------------------------------

std::string hex_bytes(std::span<const u8> bytes) {
    std::string out;
    out.reserve(bytes.size() * 2u);
    for (const u8 byte : bytes) {
        char buf[3];
        std::snprintf(buf, sizeof(buf), "%02x", static_cast<unsigned>(byte));
        out += buf;
    }
    return out;
}

std::string hex_array(const std::array<u8, 32>& digest) {
    return hex_bytes(std::span<const u8>(digest.data(), digest.size()));
}

std::string sha_text(const std::string& text) {
    auto digest = mapr::Sha256::hash(std::string_view(text.data(), text.size()));
    return digest.ok() ? hex_array(digest.value()) : std::string(64, '0');
}

std::string code_str(Code code) { return std::string(code_name(code)); }

// Deterministic, id-aware description of a whole `Ir` (used for digests and for
// the byte-level equality checks below).
std::string ir_digest_input(const Ir& ir) {
    std::string text;
    text += "root=" + std::to_string(ir.root);
    text += "|len=" + ir.total_length.to_decimal();
    text += "|nodes=" + std::to_string(ir.nodes.size());
    text += "|atoms=" + std::to_string(ir.atoms.size());
    for (const Atom& atom : ir.atoms) {
        text += "|A" + atom.length.to_decimal() + ":" + hex_array(atom.sha256) + ":" +
                std::to_string(static_cast<unsigned>(atom.klass));
    }
    for (std::size_t i = 0; i < ir.nodes.size(); ++i) {
        const Node& n = ir.nodes[i];
        text += "|N" + std::to_string(i) + ":" + kind_name(n.kind);
        for (const u32 arg : n.args) text += "," + std::to_string(arg);
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

std::string describe(const Ir& ir) {
    if (ir.nodes.empty()) return "empty-ir";
    std::string text = structural_key(ir, ir.root);
    text += "|len=" + ir.total_length.to_decimal();
    text += "|nodes=" + std::to_string(ir.nodes.size());
    text += "|atoms=" + std::to_string(ir.atoms.size());
    for (const Atom& atom : ir.atoms) text += ":" + hex_array(atom.sha256);
    return text;
}

// Exact, field-by-field equality of two emitted IR values.
bool ir_equal(const Ir& a, const Ir& b) {
    if (a.nodes.size() != b.nodes.size()) return false;
    if (a.atoms.size() != b.atoms.size()) return false;
    if (a.root != b.root) return false;
    if (a.total_length != b.total_length) return false;
    for (std::size_t i = 0; i < a.atoms.size(); ++i) {
        if (a.atoms[i].klass != b.atoms[i].klass) return false;
        if (a.atoms[i].length != b.atoms[i].length) return false;
        if (a.atoms[i].sha256 != b.atoms[i].sha256) return false;
        if (a.atoms[i].payload.size() != b.atoms[i].payload.size()) return false;
        if (!a.atoms[i].payload.empty() &&
            std::memcmp(a.atoms[i].payload.data(), b.atoms[i].payload.data(),
                        a.atoms[i].payload.size()) != 0) {
            return false;
        }
    }
    for (std::size_t i = 0; i < a.nodes.size(); ++i) {
        const Node& x = a.nodes[i];
        const Node& y = b.nodes[i];
        if (x.kind != y.kind || x.flags != y.flags) return false;
        if (x.args != y.args) return false;
        if (x.a != y.a || x.b != y.b) return false;
        if (x.morph != y.morph || x.morph_k != y.morph_k) return false;
        if (x.lfsr_conn != y.lfsr_conn || x.lfsr_init != y.lfsr_init) return false;
        if (x.affine_start != y.affine_start || x.affine_step != y.affine_step) return false;
        if (x.predictor_id != y.predictor_id || x.predictor_param != y.predictor_param) {
            return false;
        }
        if (x.length != y.length) return false;
    }
    return true;
}


// Small node constructors (avoid aggregate-init warnings under -Werror).
Node mk_zero(const BigInt& n) {
    Node node;
    node.kind = Kind::Zero;
    node.a = n;
    return node;
}

Node mk_atom(u32 atom) {
    Node node;
    node.kind = Kind::Atom;
    node.a = BigInt(atom);
    return node;
}

Node mk_morph(u32 child, u8 morph, u8 k) {
    Node node;
    node.kind = Kind::Morph;
    node.args = {child};
    node.morph = morph;
    node.morph_k = k;
    return node;
}

Node mk_xor(u32 a, u32 b) {
    Node node;
    node.kind = Kind::Xor;
    node.args = {a, b};
    return node;
}

Node mk_concat(std::vector<u32> children) {
    Node node;
    node.kind = Kind::Concat;
    node.args = std::move(children);
    return node;
}

// ---------------------------------------------------------------------------
// shape / sharing analysis (O6.2, O6.3)
// ---------------------------------------------------------------------------

struct ShapeReport {
    bool root_last = false;         // root == nodes.size()-1
    bool topological = false;       // every child id < parent id
    bool no_unused_nodes = false;   // every node reachable from root
    bool no_unused_atoms = false;   // every atom referenced by a reachable Atom node
    bool total_length_ok = false;
    bool interned = false;          // distinct canonical keys == node count
    bool atoms_unique = false;      // no two atom records share a payload
    std::size_t distinct_node_keys = 0;
    std::size_t distinct_atom_payloads = 0;
    bool well_formed = false;
};

ShapeReport analyse_shape(const Ir& ir) {
    ShapeReport report;
    if (ir.nodes.empty()) return report;
    report.root_last = ir.root == ir.nodes.size() - 1;
    report.total_length_ok = ir.total_length == ir.nodes[ir.root].length;

    report.topological = true;
    for (std::size_t i = 0; i < ir.nodes.size(); ++i) {
        for (const u32 arg : ir.nodes[i].args) {
            if (arg >= i) report.topological = false;
        }
    }

    std::vector<char> reachable(ir.nodes.size(), 0);
    std::vector<u32> stack{ir.root};
    reachable[ir.root] = 1;
    while (!stack.empty()) {
        const u32 id = stack.back();
        stack.pop_back();
        for (const u32 arg : ir.nodes[id].args) {
            if (!reachable[arg]) {
                reachable[arg] = 1;
                stack.push_back(arg);
            }
        }
    }
    report.no_unused_nodes = std::all_of(reachable.begin(), reachable.end(),
                                        [](char flag) { return flag != 0; });

    std::vector<char> atom_used(ir.atoms.size(), 0);
    for (const Node& node : ir.nodes) {
        if (node.kind != Kind::Atom) continue;
        const auto id = node.a.to_u64_checked();
        if (id.has_value() && *id < atom_used.size()) {
            atom_used[static_cast<std::size_t>(*id)] = 1;
        }
    }
    report.no_unused_atoms =
        std::all_of(atom_used.begin(), atom_used.end(), [](char flag) { return flag != 0; });

    // Maximal interning: `canonical_key` is equal exactly for structurally equal
    // subterms, so a fully interned DAG has one distinct key per node.
    std::set<std::string> node_keys;
    for (u32 i = 0; i < static_cast<u32>(ir.nodes.size()); ++i) {
        node_keys.insert(canonical_key(ir, i));
    }
    report.distinct_node_keys = node_keys.size();
    report.interned = node_keys.size() == ir.nodes.size();

    std::set<std::string> payloads;
    for (const Atom& atom : ir.atoms) {
        payloads.insert(std::string(reinterpret_cast<const char*>(atom.payload.data()),
                                    atom.payload.size()));
    }
    report.distinct_atom_payloads = payloads.size();
    report.atoms_unique = payloads.size() == ir.atoms.size();

    report.well_formed = check_well_formed(ir).ok();
    return report;
}

std::string shape_text(const ShapeReport& report) {
    std::string text;
    text += report.root_last ? "root-last" : "root-not-last";
    text += report.topological ? "+topological" : "+non-topological";
    text += report.no_unused_nodes ? "+no-unused-nodes" : "+unused-nodes";
    text += report.no_unused_atoms ? "+no-unused-atoms" : "+unused-atoms";
    text += report.total_length_ok ? "+total-length" : "+bad-total-length";
    text += report.well_formed ? "+wf" : "+not-wf";
    return text;
}

// ---------------------------------------------------------------------------
// corpus: logical terms described by a reference `Ir` built with C03's Builder
// ---------------------------------------------------------------------------

struct CorpusItem {
    std::string id;
    std::string group;
    Ir ir;  // reference construction (owns payload storage through its Builder)
};

// Replays the abstract construction events of `ref` into a `Dag`.
//
// `order` is a permutation of the reference node ids in a topological order
// (children before parents); `reverse_atoms` registers atom payloads last-first.
Result<Ir> replay(const Ir& ref, const std::vector<u32>& order, bool reverse_atoms) {
    Dag dag;
    std::vector<u32> atom_ids(ref.atoms.size(), 0);
    if (reverse_atoms) {
        for (std::size_t i = ref.atoms.size(); i-- > 0;) {
            auto id = dag.add_atom(ref.atoms[i].payload, ref.atoms[i].klass);
            if (!id.ok()) return id.code();
            atom_ids[i] = id.value();
        }
    } else {
        for (std::size_t i = 0; i < ref.atoms.size(); ++i) {
            auto id = dag.add_atom(ref.atoms[i].payload, ref.atoms[i].klass);
            if (!id.ok()) return id.code();
            atom_ids[i] = id.value();
        }
    }

    std::vector<u32> ids(ref.nodes.size(), ~0u);
    for (const u32 index : order) {
        const Node& source = ref.nodes[index];
        Node node;
        node.kind = source.kind;
        node.a = source.a;
        node.b = source.b;
        node.morph = source.morph;
        node.morph_k = source.morph_k;
        node.lfsr_conn = source.lfsr_conn;
        node.lfsr_init = source.lfsr_init;
        node.affine_start = source.affine_start;
        node.affine_step = source.affine_step;
        node.predictor_id = source.predictor_id;
        node.predictor_param = source.predictor_param;
        if (source.kind == Kind::Atom) {
            const auto atom_id = source.a.to_u64_checked();
            if (!atom_id.has_value() || *atom_id >= atom_ids.size()) return Code::Invalid;
            node.a = BigInt(atom_ids[static_cast<std::size_t>(*atom_id)]);
        }
        for (const u32 child : source.args) {
            if (child >= ids.size() || ids[child] == ~0u) return Code::Invalid;
            node.args.push_back(ids[child]);
        }
        auto id = dag.add_node(std::move(node));
        if (!id.ok()) return id.code();
        ids[index] = id.value();
    }
    return std::move(dag).finish(ids[ref.root]);
}

std::vector<u32> natural_order(std::size_t count) {
    std::vector<u32> order(count);
    for (std::size_t i = 0; i < count; ++i) order[i] = static_cast<u32>(i);
    return order;
}

// Deterministic random linear extensions of the reference DAG (randomised
// Kahn), so every returned order lists children strictly before parents.
// `orders[0]` is always the natural order.
std::vector<std::vector<u32>> shuffled_orders(const Ir& ref, std::size_t count, u32 seed) {
    const std::size_t n = ref.nodes.size();
    std::vector<std::vector<u32>> orders;
    orders.push_back(natural_order(n));
    if (n == 0) return orders;

    std::vector<std::vector<u32>> successors(n);
    std::vector<std::size_t> indegree(n, 0);
    for (std::size_t i = 0; i < n; ++i) {
        for (const u32 child : ref.nodes[i].args) {
            if (child >= n) continue;
            successors[child].push_back(static_cast<u32>(i));
            ++indegree[i];
        }
    }
    std::mt19937 rng(seed);
    for (std::size_t attempt = 0; attempt < count; ++attempt) {
        std::vector<std::size_t> remaining = indegree;
        std::vector<u32> ready;
        for (std::size_t i = 0; i < n; ++i) {
            if (remaining[i] == 0) ready.push_back(static_cast<u32>(i));
        }
        std::vector<u32> order;
        order.reserve(n);
        while (!ready.empty()) {
            std::uniform_int_distribution<std::size_t> pick(0, ready.size() - 1);
            const std::size_t slot = pick(rng);
            const u32 id = ready[slot];
            ready[slot] = ready.back();
            ready.pop_back();
            order.push_back(id);
            for (const u32 next : successors[id]) {
                if (--remaining[next] == 0) ready.push_back(next);
            }
        }
        if (order.size() == n) orders.push_back(std::move(order));
    }
    return orders;
}

// ---------------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------------

struct Row {
    std::string check;
    std::string corpus;
    std::string item_id;
    std::string input_sha256;
    std::string expected;
    std::string actual;
    std::string verdict;
    std::string log;
};

class Gate {
public:
    explicit Gate(std::string root) : root_(std::move(root)) {}

    int run();
    bool write_evidence();
    void set_environment(const std::string& env) { environment_ = env; }

private:
    std::string root_;
    std::string environment_;
    std::vector<CorpusItem> corpus_;
    std::vector<std::unique_ptr<Builder>> builders_;
    std::vector<Row> rows_;
    std::vector<std::string> log_lines_;
    std::size_t passes_ = 0;
    std::size_t failures_ = 0;
    std::array<std::size_t, kKindCount> kind_hits_{};
    std::array<std::size_t, kMorphCount + 1u> morph_hits_{};
    std::array<std::size_t, kPredictorCount> predictor_hits_{};

    void log(const std::string& line) { log_lines_.push_back(line); }

    void section(const std::string& name) {
        log("[" + name + "] cumulative pass=" + std::to_string(passes_) +
            " fail=" + std::to_string(failures_));
    }

    void row(std::string check, std::string corpus, std::string item_id,
             std::string input_sha, std::string expected, std::string actual, bool pass,
             std::string note) {
        if (pass) {
            ++passes_;
        } else {
            ++failures_;
            log("FAIL " + check + " " + item_id + " expected=" + expected + " actual=" + actual);
        }
        rows_.push_back(Row{std::move(check), std::move(corpus), std::move(item_id),
                            std::move(input_sha), std::move(expected), std::move(actual),
                            pass ? "PASS" : "FAIL", std::move(note)});
    }

    Builder& new_builder() {
        builders_.push_back(std::make_unique<Builder>());
        return *builders_.back();
    }

    void add_item(const std::string& id, const std::string& group, Ir ir) {
        for (const Node& node : ir.nodes) {
            const auto kind = static_cast<std::size_t>(node.kind);
            if (kind < kKindCount) ++kind_hits_[kind];
            if (node.kind == Kind::Morph && node.morph >= 1 && node.morph <= kMorphCount) {
                ++morph_hits_[node.morph];
            }
            if (node.kind == Kind::Predictor && node.predictor_id < kPredictorCount) {
                ++predictor_hits_[node.predictor_id];
            }
        }
        corpus_.push_back(CorpusItem{id, group, std::move(ir)});
    }

    void build_corpus();
    void run_order_independence();
    void run_shape_and_sharing();
    void run_atom_dedup();
    void run_threaded_and_repeat();
    void run_denotation_and_integration();
    void run_errors_and_limits();
    void run_source_independence();
    void run_coverage();
};

void Gate::build_corpus() {
    {
        Builder& b = new_builder();
        add_item("e-empty", "C06-SHAPE", b.finish(b.empty()));
    }
    {
        Builder& b = new_builder();
        add_item("e-zero-0", "C06-SHAPE", b.finish(b.zero(BigInt::zero())));
    }
    {
        Builder& b = new_builder();
        add_item("e-zero-29", "C06-SHAPE", b.finish(b.zero(BigInt(29))));
    }
    {
        Builder& b = new_builder();
        const BigInt huge = BigInt(1).shl(40).value();
        add_item("e-zero-2pow40", "C06-SHAPE", b.finish(b.zero(huge)));
    }
    {
        Builder& b = new_builder();
        add_item("e-atom-1", "C06-SHAPE", b.finish(b.atom_node(b.add_atom({0x7Bu}))));
    }
    {
        Builder& b = new_builder();
        add_item("e-atom-37", "C06-SHAPE",
                 b.finish(b.atom_node(b.add_atom(pattern(37, 13)))));
    }
    {
        // Two distinct atom records with the *same* payload: O6.3 must merge.
        Builder& b = new_builder();
        const std::vector<u8> bytes = pattern(9, 41);
        const u32 a0 = b.add_atom(bytes);
        const u32 a1 = b.add_atom(bytes);
        const u32 n0 = b.atom_node(a0);
        const u32 n1 = b.atom_node(a1);
        add_item("e-atom-dup", "C06-DEDUP", b.finish(b.concat({n0, n1})));
    }
    {
        // Same payload, different advisory klass: one record (payload identity).
        Builder& b = new_builder();
        const std::vector<u8> bytes = pattern(5, 42);
        const u32 a0 = b.add_atom(bytes, 1);
        const u32 a1 = b.add_atom(bytes, 2);
        add_item("e-atom-dup-klass", "C06-DEDUP",
                 b.finish(b.concat({b.atom_node(a0), b.zero(3), b.atom_node(a1)})));
    }
    {
        Builder& b = new_builder();
        const u32 a = b.atom_node(b.add_atom(pattern(11, 3)));
        const u32 z = b.zero(7);
        const u32 c = b.affine(9, 23, 15);
        add_item("e-concat-3", "C06-SHAPE", b.finish(b.concat({a, z, c})));
    }
    {
        // Diamond: the same subterm reached twice through different parents.
        Builder& b = new_builder();
        const u32 base = b.atom_node(b.add_atom(pattern(12, 44)));
        const u32 m = b.morph(base, 2, 0);
        add_item("e-diamond", "C06-SHARE", b.finish(b.concat({m, m})));
    }
    {
        // A nested diamond built through *distinct* builder nodes with equal shapes.
        Builder& b = new_builder();
        const u32 base = b.atom_node(b.add_atom(pattern(12, 45)));
        const u32 m1 = b.morph(base, 6, 3);
        const u32 m2 = b.morph(base, 6, 3);
        add_item("e-diamond-dupnode", "C06-SHARE",
                 b.finish(b.concat({m1, m2, b.zero(4)})));
    }
    {
        Builder& b = new_builder();
        const u32 base = b.zero(48);
        const u32 m1 = b.morph(base, 4, 0);
        const u32 m2 = b.morph(base, 4, 0);
        const u32 x = b.xor_node(m1, m2);
        add_item("e-shared-xor", "C06-SHARE", b.finish(x));
    }
    {
        Builder& b = new_builder();
        const u32 c = b.atom_node(b.add_atom(pattern(9, 7)));
        add_item("e-repeat-3-6", "C06-SHAPE",
                 b.finish(b.repeat(c, BigInt(3), BigInt(6))));
    }
    {
        Builder& b = new_builder();
        const u32 base = b.lfsr(0x80200003ull, 0x12345678ull, 64);
        const u32 s1 = b.slice(base, BigInt(7), BigInt(45));
        const u32 s2 = b.slice(s1, BigInt(5), BigInt(29));
        add_item("e-slice-nested", "C06-SHAPE", b.finish(s2));
    }
    for (u8 morph : {u8{1}, u8{2}, u8{3}, u8{4}, u8{5}, u8{6}, u8{7}, u8{8}, u8{9}}) {
        Builder& b = new_builder();
        const std::size_t n = (morph >= 3 && morph <= 5) ? 32u : 29u;
        const u8 k = (morph == 6 || morph == 7) ? 3u : 0u;
        const u32 child =
            b.atom_node(b.add_atom(pattern(n, static_cast<u8>(morph * 31u + 5u))));
        add_item("e-morph-" + std::to_string(morph), "C06-KIND",
                 b.finish(b.morph(child, morph, k)));
    }
    {
        Builder& b = new_builder();
        const u32 x = b.lfsr(0xD0080004ull, 0xCAFEBABEull, 35);
        const u32 y = b.affine(17, 59, 35);
        add_item("e-xor", "C06-KIND", b.finish(b.xor_node(x, y)));
    }
    for (u32 stride : {1u, 2u, 3u, 7u}) {
        Builder& b = new_builder();
        const u32 len = stride * 4u;
        const u32 c0 = b.atom_node(b.add_atom(pattern(len, static_cast<u8>(stride + 60u))));
        const u32 c1 = b.affine(3, 41, len);
        const u32 c2 = b.lfsr(0x80200003ull, 7ull, len);
        add_item("e-interleave-s" + std::to_string(stride), "C06-KIND",
                 b.finish(b.interleave({c0, c1, c2}, stride)));
    }
    {
        Builder& b = new_builder();
        add_item("e-lfsr-37", "C06-KIND",
                 b.finish(b.lfsr(0x800000000000000Dull, 0x0102030405060708ull, 37)));
    }
    {
        Builder& b = new_builder();
        add_item("e-affine-41", "C06-KIND", b.finish(b.affine(250, 13, 41)));
    }
    for (u8 pid : {u8{0}, u8{1}, u8{2}, u8{3}, u8{4}}) {
        Builder& b = new_builder();
        const u32 param = (pid >= 3) ? 7u : 0u;
        const u32 residual =
            b.atom_node(b.add_atom(pattern(33, static_cast<u8>(pid * 13u + 21u))));
        add_item("e-pred-" + std::to_string(pid), "C06-KIND",
                 b.finish(b.predictor(pid, param, residual)));
    }
    {
        Builder& b = new_builder();
        const u32 lf = b.lfsr(0x80200003ull, 0x778899AAull, 24);
        const u32 p2 = b.predictor(2, 0, lf);
        const u32 sw = b.morph(p2, 5, 0);
        const u32 rv = b.morph(sw, 9, 0);
        const u32 af = b.affine(11, 29, 24);
        const u32 il = b.interleave({rv, af}, 4u);
        const u32 rp = b.repeat(il, BigInt(1), BigInt(16));
        const u32 sl = b.slice(rp, BigInt(5), BigInt(48));
        add_item("e-composite-all", "C06-DEEP", b.finish(sl));
    }
    {
        // Deep chain: finishes the whole thing post-order, no recursion.
        Builder& b = new_builder();
        u32 cur = b.atom_node(b.add_atom(pattern(32, 99)));
        for (u32 i = 0; i < 10; ++i) {
            const u32 rot = b.morph(cur, 6, static_cast<u8>((i % 7u) + 1u));
            cur = b.xor_node(cur, rot);
        }
        add_item("e-deep-xor-chain", "C06-DEEP", b.finish(cur));
    }
    {
        // Deep unary chain (depth 300) to exercise the explicit traversal stack.
        Builder& b = new_builder();
        u32 cur = b.zero(64);
        for (u32 i = 0; i < 300; ++i) cur = b.morph(cur, 2, 0);
        add_item("e-deep-morph-chain", "C06-DEEP", b.finish(cur));
    }
    {
        // Wide Concat with repeated children.
        Builder& b = new_builder();
        std::vector<u32> kids;
        const u32 a = b.atom_node(b.add_atom(pattern(4, 71)));
        const u32 z = b.zero(4);
        for (u32 i = 0; i < 24; ++i) kids.push_back((i % 2u == 0) ? a : z);
        add_item("e-concat-wide-shared", "C06-SHARE", b.finish(b.concat(kids)));
    }
}

// ---------------------------------------------------------------------------
// O6.1 — construction-order independence
// ---------------------------------------------------------------------------

void Gate::run_order_independence() {
    std::size_t index = 0;
    for (const CorpusItem& item : corpus_) {
        const std::string in_sha = sha_text(describe(item.ir));
        const auto orders = shuffled_orders(item.ir, 8, static_cast<u32>(0xC0600u + index));
        ++index;

        auto baseline = replay(item.ir, orders.front(), false);
        if (!baseline.ok() || baseline.value().nodes.empty()) {
            row("o6.1.order_independence", item.group, item.id, in_sha,
                "identical Ir in 8/8 orders",
                "replay failed: " + code_str(baseline.code()), false, item.id);
            continue;
        }
        const std::string baseline_sha = sha_text(ir_digest_input(baseline.value()));
        std::size_t identical = 0;
        std::string first_mismatch;
        for (std::size_t i = 0; i < orders.size(); ++i) {
            auto candidate = replay(item.ir, orders[i], i % 2 == 1);
            if (!candidate.ok()) {
                if (first_mismatch.empty()) {
                    first_mismatch = "order#" + std::to_string(i) + ":" + code_str(candidate.code());
                }
                continue;
            }
            if (ir_equal(baseline.value(), candidate.value())) {
                ++identical;
            } else if (first_mismatch.empty()) {
                first_mismatch = "order#" + std::to_string(i);
            }
        }
        const bool pass = identical == orders.size();
        row("o6.1.order_independence", item.group, item.id, in_sha, "identical Ir in 8/8 orders",
            std::to_string(identical) + "/" + std::to_string(orders.size()) +
                (pass ? " orders byte-identical" : " mismatch at " + first_mismatch),
            pass, item.id + ":sha=" + baseline_sha);
    }
    section("o6.1_order_independence");
}

// ---------------------------------------------------------------------------
// O6.2 — shape, interning, and reachability
// ---------------------------------------------------------------------------

void Gate::run_shape_and_sharing() {
    for (const CorpusItem& item : corpus_) {
        const std::string in_sha = sha_text(describe(item.ir));
        auto ir = replay(item.ir, natural_order(item.ir.nodes.size()), false);
        if (!ir.ok()) {
            row("o6.2.shape", item.group, item.id, in_sha, "canonical shape",
                "finish failed: " + code_str(ir.code()), false, item.id);
            continue;
        }
        const ShapeReport report = analyse_shape(ir.value());
        const bool pass = report.root_last && report.topological && report.no_unused_nodes &&
                          report.no_unused_atoms && report.total_length_ok &&
                          report.well_formed;
        row("o6.2.shape", item.group, item.id, in_sha, "canonical shape",
            shape_text(report), pass, item.id);

        // Interning: identical subterms share a node (O6.1/O6.2), and no two atom
        // records share a payload (O6.3) — canonical_key is id-free.
        const bool interned = report.interned && report.atoms_unique;
        row("o6.2.interned", item.group, item.id, in_sha, "distinct-subterms==nodes",
            "nodes=" + std::to_string(ir.value().nodes.size()) + " distinct=" +
                std::to_string(report.distinct_node_keys) +
                " atoms=" + std::to_string(ir.value().atoms.size()) +
                " payloads=" + std::to_string(report.distinct_atom_payloads),
            interned, item.id);
    }
    section("o6.2_shape");
}

// ---------------------------------------------------------------------------
// O6.3 — atom payload dedup
// ---------------------------------------------------------------------------

void Gate::run_atom_dedup() {
    // 1. Corpus-wide: no emitted IR has two records with the same payload.
    for (const CorpusItem& item : corpus_) {
        const std::string in_sha = sha_text(describe(item.ir));
        auto ir = replay(item.ir, natural_order(item.ir.nodes.size()), false);
        if (!ir.ok()) {
            row("o6.3.atom_dedup", item.group, item.id, in_sha, "unique payloads",
                "finish failed: " + code_str(ir.code()), false, item.id);
            continue;
        }
        const ShapeReport report = analyse_shape(ir.value());
        row("o6.3.atom_dedup", item.group, item.id, in_sha, "unique payloads",
            std::to_string(report.distinct_atom_payloads) + "/" +
                std::to_string(ir.value().atoms.size()) + " distinct payloads",
            report.atoms_unique, item.id);
    }

    // 2. Insertion order: the same logical term with payloads registered in
    //    reverse order dedups to the same records in the same first-use order.
    {
        Dag forward;
        Dag backward;
        const std::vector<std::vector<u8>> payloads{pattern(4, 1), pattern(4, 2), pattern(4, 3)};
        std::array<u32, 3> fwd_ids{};
        std::array<u32, 3> bwd_ids{};
        for (std::size_t i = 0; i < payloads.size(); ++i) {
            fwd_ids[i] = forward.add_atom(payloads[i]).value();
        }
        for (std::size_t i = payloads.size(); i-- > 0;) {
            bwd_ids[i] = backward.add_atom(payloads[i]).value();
        }
        std::array<u32, 3> fwd_nodes{};
        std::array<u32, 3> bwd_nodes{};
        for (std::size_t i = 0; i < 3; ++i) {
            Node f;
            f.kind = Kind::Atom;
            f.a = BigInt(fwd_ids[i]);
            fwd_nodes[i] = forward.add_node(f).value();
            Node b = f;
            b.a = BigInt(bwd_ids[i]);
            bwd_nodes[i] = backward.add_node(b).value();
        }
        Node fc;
        fc.kind = Kind::Concat;
        fc.args = {fwd_nodes[0], fwd_nodes[1], fwd_nodes[2]};
        Node bc;
        bc.kind = Kind::Concat;
        bc.args = {bwd_nodes[0], bwd_nodes[1], bwd_nodes[2]};
        const u32 froot = forward.add_node(fc).value();
        const u32 broot = backward.add_node(bc).value();
        auto fir = std::move(forward).finish(froot);
        auto bir = std::move(backward).finish(broot);
        const bool pass = fir.ok() && bir.ok() && ir_equal(fir.value(), bir.value());
        row("o6.3.atom_insertion_order", "C06-DEDUP", "reverse-registration",
            sha_text(describe(fir.ok() ? fir.value() : Ir{})), "identical Ir",
            pass ? "identical Ir" : "mismatch",
            pass, "atoms=3");
    }

    // 3. Duplicate payload registered twice but referenced once: one record.
    {
        Dag dag;
        const std::vector<u8> payload = pattern(8, 77);
        const u32 a = dag.add_atom(payload).value();
        const u32 b = dag.add_atom(payload).value();
        const u32 n = dag.add_node(mk_atom(a)).value();
        auto ir = std::move(dag).finish(n);
        const bool pass = ir.ok() && ir.value().atoms.size() == 1;
        row("o6.3.atom_reuse_single_record", "C06-DEDUP", "duplicate-registration",
            sha_text("duplicate-registration"), "1 atom record",
            ir.ok() ? std::to_string(ir.value().atoms.size()) + " atom record(s)" : "error",
            pass, "ids=" + std::to_string(a) + "," + std::to_string(b));
    }
    section("o6.3_atom_dedup");
}

// ---------------------------------------------------------------------------
// thread-completion order and repeat determinism (E2-I7, SPECS-V2 §7.3)
// ---------------------------------------------------------------------------

void Gate::run_threaded_and_repeat() {
    // Pick the deepest item: 4 threads each build it from a different order.
    const CorpusItem* target = nullptr;
    for (const CorpusItem& item : corpus_) {
        if (item.id == "e-composite-all") target = &item;
    }
    if (target != nullptr) {
        const std::string in_sha = sha_text(describe(target->ir));
        const std::size_t orders_count = target->ir.nodes.size() + 1;
        std::vector<std::vector<u32>> orders =
            shuffled_orders(target->ir, 8, 0xC06F00u);
        while (orders.size() < orders_count) orders.push_back(orders.back());

        std::array<Result<Ir>, 4> results{Result<Ir>(Code::Invalid), Result<Ir>(Code::Invalid),
                                          Result<Ir>(Code::Invalid), Result<Ir>(Code::Invalid)};
        std::vector<std::thread> pool;
        pool.reserve(4);
        for (std::size_t t = 0; t < 4; ++t) {
            pool.emplace_back([&, t]() { results[t] = replay(target->ir, orders[t], t % 2 == 1); });
        }
        for (std::thread& thread : pool) thread.join();

        bool all_ok = true;
        for (const auto& result : results) all_ok = all_ok && result.ok();
        bool identical = all_ok;
        for (std::size_t t = 1; t < 4; ++t) {
            if (!results[t].ok() || !results[0].ok()) {
                identical = false;
                continue;
            }
            if (!ir_equal(results[0].value(), results[t].value())) identical = false;
        }
        row("o6.1.threaded_fragments", "C06-THREAD", target->id, in_sha,
            "4/4 threads identical Ir", identical ? "4/4 threads identical Ir" : "mismatch",
            identical, "completion-order-independent");
    } else {
        row("o6.1.threaded_fragments", "C06-THREAD", "missing", sha_text("missing"),
            "4/4 threads identical Ir", "corpus item absent", false, "missing");
    }

    // Repeat determinism: 4 sequential rebuilds of every corpus item.
    {
        std::size_t total = 0;
        std::size_t identical = 0;
        std::string in_sha = sha_text("repeat-determinism");
        for (const CorpusItem& item : corpus_) {
            const std::vector<u32> order = natural_order(item.ir.nodes.size());
            auto first = replay(item.ir, order, false);
            if (!first.ok()) continue;
            for (int run = 0; run < 3; ++run) {
                ++total;
                auto other = replay(item.ir, order, run % 2 == 1);
                if (other.ok() && ir_equal(first.value(), other.value())) ++identical;
            }
        }
        row("o6.1.repeat_determinism", "C06", "all-corpus-items", in_sha,
            std::to_string(total) + "/" + std::to_string(total) + " identical",
            std::to_string(identical) + "/" + std::to_string(total) + " identical",
            total != 0 && identical == total, "repeat-determinism");
    }
    section("o6.1_threaded_and_repeat");
}

// ---------------------------------------------------------------------------
// denotation and C03/C04/C05 integration
// ---------------------------------------------------------------------------

void Gate::run_denotation_and_integration() {
    for (const CorpusItem& item : corpus_) {
        const std::string in_sha = sha_text(describe(item.ir));
        auto ir = replay(item.ir, natural_order(item.ir.nodes.size()), false);
        if (!ir.ok()) {
            row("o6.denotation", item.group, item.id, in_sha, "denotation preserved",
                "finish failed", false, item.id);
            continue;
        }
        const Ir& dag_ir = ir.value();

        // Terms whose declared length exceeds the materialisation cap are not
        // evaluated here (C05 owns virtual/bounded evaluation, §8.3); the row
        // instead pins that the C03 surface returns `Limit` rather than
        // approximating, and the remaining checks still run.
        constexpr u64 kMaterialCap = 1u << 22;
        const auto declared = dag_ir.total_length.to_u64_checked();
        if (!declared.has_value() || *declared > kMaterialCap) {
            const auto capped_result = denote_root(dag_ir, kMaterialCap);
            const Code capped = capped_result.ok() ? Code::Ok : capped_result.code();
            const bool exact_cap = capped == Code::Limit;
            row("o6.denotation", item.group, item.id, in_sha,
                "Limit above " + std::to_string(kMaterialCap) + " B",
                exact_cap ? "Limit" : code_str(capped), exact_cap,
                "len=" + dag_ir.total_length.to_decimal());
            row("o6.canon_consistency", item.group, item.id, in_sha, "canon(dag) Ok",
                canon(dag_ir).ok() ? "Ok" : "error", canon(dag_ir).ok(), item.id);
            continue;
        }

        // C03 reference denotation of the Dag output.
        std::vector<u8> ref_dag;
        const bool ref_ok = c03ref::ref_denote(dag_ir, dag_ir.root, ref_dag, kMaterialCap);
        // C05 streaming evaluation of the same term.
        std::vector<u8> streamed;
        {
            struct VecSink final : Sink {
                std::vector<u8> bytes;
                Status write(std::span<const u8> chunk) override {
                    bytes.insert(bytes.end(), chunk.begin(), chunk.end());
                    return Status{};
                }
            } sink;
            if (eval_stream(dag_ir, sink).ok()) streamed = std::move(sink.bytes);
        }
        // C03 reference denotation of the *input* construction.
        std::vector<u8> ref_input;
        const bool ref_in_ok = c03ref::ref_denote(item.ir, item.ir.root, ref_input, kMaterialCap);

        const bool pass = ref_ok && ref_in_ok && ref_dag == ref_input && streamed == ref_input;
        row("o6.denotation", item.group, item.id, in_sha, "denotation preserved",
            pass ? "identical bytes" : "mismatch", pass,
            "bytes=" + std::to_string(ref_input.size()));

        // C04: `canon` of a canonical Dag output reproduces it exactly; for a
        // non-canonical logical term the Dag output is (correctly) not rewritten,
        // and `canon` must still be denotation-preserving.
        auto canon_out = canon(dag_ir);
        bool canon_pass = canon_out.ok();
        if (canon_pass) {
            std::vector<u8> canon_bytes;
            canon_pass = c03ref::ref_denote(canon_out.value(), canon_out.value().root,
                                            canon_bytes, kMaterialCap) &&
                         canon_bytes == ref_dag;
            if (is_canonical(dag_ir)) {
                canon_pass = canon_pass && ir_equal(dag_ir, canon_out.value());
            }
        }
        row("o6.canon_consistency", item.group, item.id, in_sha,
            is_canonical(dag_ir) ? "canon(dag)==dag" : "canon(dag) preserves denotation",
            canon_pass ? (is_canonical(dag_ir) ? "canon(dag)==dag" : "denotation preserved")
                       : "mismatch",
            canon_pass, item.id);
    }
    section("o6_denotation");
}

// ---------------------------------------------------------------------------
// errors and limits
// ---------------------------------------------------------------------------

void Gate::run_errors_and_limits() {
    auto report = [this](const std::string& id, const std::string& expected, Code actual,
                         const char* note) {
        const bool pass = code_str(actual) == expected;
        row("errors", "C06-ERR", id, sha_text(id + expected), expected, code_str(actual), pass,
            note);
    };

    {
        Dag dag;
        report("empty-payload", "Invalid", dag.add_atom(std::span<const u8>()).code(),
               "W8.atom-length: zero-length atom");
    }
    {
        Dag dag;
        (void)dag.add_node(Node{});
        Node node;
        node.kind = Kind::Concat;
        node.args = {1};
        report("missing-child", "Invalid", dag.add_node(node).code(), "args must be existing ids");
    }
    {
        Dag dag;
        Node node;
        node.kind = Kind::Atom;
        node.a = BigInt(0);
        report("unknown-atom", "Invalid", dag.add_node(node).code(), "atom id not registered");
    }
    {
        Dag dag;
        Node node;
        node.kind = static_cast<Kind>(99);
        report("kind-domain", "Invalid", dag.add_node(node).code(), "kind outside 0..11");
    }
    {
        Dag dag;
        Node node;
        node.kind = Kind::Zero;
        node.flags = 1;
        report("flags-nonzero", "Invalid", dag.add_node(node).code(), "W4 flags must be 0");
    }
    {
        Dag dag;
        (void)dag.add_node(Node{});
        report("unknown-root", "Invalid", std::move(dag).finish(3).code(), "root out of range");
    }
    {
        // Concat with a single child: well-formedness (W8.argc) is reported at
        // finish, since the builder accepts it as a recorded event.
        Dag dag;
        const u32 atom = dag.add_atom(pattern(4, 1)).value();
        const u32 a = dag.add_node(mk_atom(atom)).value();
        const u32 root = dag.add_node(mk_concat({a})).value();
        report("ill-formed-finish", "Invalid", std::move(dag).finish(root).code(),
               "W8.argc: Concat argc < 2");
    }
    {
        // Xor of unequal lengths.
        Dag dag;
        const u32 a = dag.add_node(mk_zero(BigInt(4))).value();
        const u32 b = dag.add_node(mk_zero(BigInt(5))).value();
        const u32 root = dag.add_node(mk_xor(a, b)).value();
        report("xor-length-mismatch", "Invalid", std::move(dag).finish(root).code(),
               "W8.xor: operand lengths differ");
    }
    {
        Limits limits;
        limits.max_nodes = 2;
        Dag dag(limits);
        (void)dag.add_node(Node{});
        (void)dag.add_node(mk_zero(BigInt(1)));
        report("node-count-limit", "Limit", dag.add_node(mk_zero(BigInt(2))).code(),
               "W1 counts");
    }
    {
        Limits limits;
        limits.max_atoms = 1;
        Dag dag(limits);
        (void)dag.add_atom(pattern(2, 1));
        report("atom-count-limit", "Limit", dag.add_atom(pattern(2, 2)).code(), "W1 counts");
    }
    {
        Limits limits;
        limits.max_depth = 3;
        Dag dag(limits);
        const u32 leaf = dag.add_node(mk_zero(BigInt(8))).value();
        const u32 d1 = dag.add_node(mk_morph(leaf, 2, 0)).value();
        const u32 d2 = dag.add_node(mk_morph(d1, 2, 0)).value();
        report("depth-limit-ok", "Ok",
               static_cast<Code>(dag.add_node(mk_morph(d1, 2, 0)).code()),
               "W7: depth 3 == max_depth is allowed");
        report("depth-limit-exceeded", "Limit",
               static_cast<Code>(dag.add_node(mk_morph(d2, 2, 0)).code()),
               "W7: depth 4 > max_depth");
    }
    {
        // §8.3 output cap: a single Zero(2^63+1) node.
        Dag dag;
        const BigInt over = BigInt(1).shl(63).value().add(BigInt(1)).value();
        const u32 root = dag.add_node(mk_zero(over)).value();
        report("output-cap", "Limit", std::move(dag).finish(root).code(), "§8.3 2^63 cap");
    }
    section("errors");
}

// ---------------------------------------------------------------------------
// isolation + coverage
// ---------------------------------------------------------------------------

void Gate::run_source_independence() {
    namespace fs = std::filesystem;
    const std::vector<std::string> dirs = {root_ + "/include/mapr/e2", root_ + "/engine/src/e2"};
    const std::vector<std::string> forbidden = {"wire",    "container", "harness", "cli",
                                                "mau",     "certificate", "discovery",
                                                "rewrite", "selection", "e3", "e4", "e5", "e6",
                                                "e7"};
    std::vector<std::string> files;
    for (const std::string& dir : dirs) {
        std::error_code ec;
        for (auto it = fs::recursive_directory_iterator(dir, ec);
             !ec && it != fs::recursive_directory_iterator(); ++it) {
            if (!it->is_regular_file()) continue;
            const std::string ext = it->path().extension().string();
            if (ext == ".hpp" || ext == ".h" || ext == ".cpp") files.push_back(it->path().string());
        }
    }
    std::sort(files.begin(), files.end());

    std::size_t bad = 0;
    std::string digest_acc;
    for (const std::string& file : files) {
        std::ifstream in(file);
        std::string line;
        while (std::getline(in, line)) {
            digest_acc += line;
            digest_acc.push_back('\n');
            if (line.find("#include") == std::string::npos) continue;
            for (const std::string& token : forbidden) {
                if (line.find(token) != std::string::npos) {
                    ++bad;
                    log("forbidden include in " + file + ": " + line);
                }
            }
        }
    }
    row("independence", "C06", "source-scan", sha_text(digest_acc), "0 forbidden includes",
        std::to_string(bad) + " forbidden includes across " + std::to_string(files.size()) +
            " files",
        bad == 0 && !files.empty(), "source-scan");
    section("independence");
}

void Gate::run_coverage() {
    std::size_t kinds = 0;
    for (std::size_t i = 0; i < kKindCount; ++i) {
        if (kind_hits_[i] > 0) ++kinds;
    }
    row("coverage.kind", "C06", "all-12-kinds", sha_text("kinds"), "12/12",
        std::to_string(kinds) + "/12", kinds == kKindCount, "all-12-kinds");

    std::size_t morphs = 0;
    for (std::size_t i = 1; i <= kMorphCount; ++i) {
        if (morph_hits_[i] > 0) ++morphs;
    }
    row("coverage.morph", "C06", "all-9-morphs", sha_text("morphs"), "9/9",
        std::to_string(morphs) + "/9", morphs == kMorphCount, "all-9-morphs");

    std::size_t predictors = 0;
    for (std::size_t i = 0; i < kPredictorCount; ++i) {
        if (predictor_hits_[i] > 0) ++predictors;
    }
    row("coverage.predictor", "C06", "all-5-predictors", sha_text("predictors"), "5/5",
        std::to_string(predictors) + "/5", predictors == kPredictorCount, "all-5-predictors");
    section("coverage");
}

// ---------------------------------------------------------------------------
// driver
// ---------------------------------------------------------------------------

int Gate::run() {
    build_corpus();
    run_order_independence();
    run_shape_and_sharing();
    run_atom_dedup();
    run_threaded_and_repeat();
    run_denotation_and_integration();
    run_errors_and_limits();
    run_source_independence();
    run_coverage();

    const std::size_t checks = passes_ + failures_;
    log("totals: checks=" + std::to_string(checks) + " pass=" + std::to_string(passes_) +
        " fail=" + std::to_string(failures_));
    log(failures_ == 0 ? std::string("RESULT: PASS (C06 DAG)")
                       : std::string("RESULT: FAIL (C06 DAG)"));
    row("c06.summary", "C06", "all-checks", sha_text("summary"),
        std::to_string(checks + 1) + " checks all PASS",
        "pass=" + std::to_string(passes_) + " fail=" + std::to_string(failures_),
        failures_ == 0, "summary");
    return failures_ == 0 ? 0 : 1;
}

bool Gate::write_evidence() {
    namespace fs = std::filesystem;
    const std::string gate_dir = root_ + "/specs_and_reports/v2/gates";
    const std::string log_dir = root_ + "/specs_and_reports/v2/logs";
    const std::string evidence_dir = root_ + "/specs_and_reports/v2/evidence/C06";
    std::error_code ec;
    fs::create_directories(gate_dir, ec);
    fs::create_directories(log_dir, ec);
    fs::create_directories(evidence_dir, ec);

    std::string tsv = "check\tcorpus\titem_id\tinput_sha256\texpected\tactual\tverdict\tlog\n";
    for (const Row& r : rows_) {
        tsv += r.check + "\t" + r.corpus + "\t" + r.item_id + "\t" + r.input_sha256 + "\t" +
               r.expected + "\t" + r.actual + "\t" + r.verdict + "\t" + r.log + "\n";
    }
    {
        std::ofstream out(gate_dir + "/C06-DAG.tsv", std::ios::binary | std::ios::trunc);
        if (!out) return false;
        out.write(tsv.data(), static_cast<std::streamsize>(tsv.size()));
    }

    std::string log_text = environment_;
    for (const std::string& line : log_lines_) log_text += line + "\n";
    {
        std::ofstream out(log_dir + "/C06-DAG.log", std::ios::binary | std::ios::trunc);
        if (!out) return false;
        out.write(log_text.data(), static_cast<std::streamsize>(log_text.size()));
    }

    const std::string tsv_sha =
        sha_text(tsv);
    const std::string log_sha = sha_text(log_text);
    std::string sums;
    sums += tsv_sha + "  specs_and_reports/v2/gates/C06-DAG.tsv\n";
    sums += log_sha + "  specs_and_reports/v2/logs/C06-DAG.log\n";
    {
        std::ofstream out(evidence_dir + "/SHA256SUMS", std::ios::binary | std::ios::trunc);
        if (!out) return false;
        out.write(sums.data(), static_cast<std::streamsize>(sums.size()));
    }
    return true;
}

std::string environment_record(const std::string& root, const char* command_line) {
    std::string text;
    text += "tool: C06-DAG evidence harness\n";
    text += "root: " + root + "\n";
    text += "command_line: " + std::string(command_line) + "\n";
    // Deliberately compiler-version free: the log is covered by
    // evidence/C06/SHA256SUMS, so it must be reproducible on any conforming
    // C++20 toolchain.  The toolchain used for the authoritative run is recorded
    // in REPORT/E2/C06-DAG-REPORT.md §1 and printed by the CI workflow.
    text += "std: c++20 (build flags in engine/Makefile.c06)\n";
    text += "build: -O2 -pedantic -Wall -Wextra -Werror -Wconversion -Wshadow "
            "-Wnull-dereference -Wdouble-promotion -Wformat=2\n";
    return text;
}

int run_main(int argc, char** argv) {
    std::string root = ".";
    bool write_evidence = false;
    std::string command_line;
    for (int i = 0; i < argc; ++i) {
        if (i != 0) command_line.push_back(' ');
        command_line.append(argv[i]);
    }
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--root" && i + 1 < argc) {
            root = argv[++i];
        } else if (arg == "--write-evidence") {
            write_evidence = true;
        } else if (arg == "--help") {
            std::printf("usage: e2_c06_gate [--root PATH] [--write-evidence]\n");
            return 0;
        } else {
            std::fprintf(stderr, "unknown argument: %s\n", arg.c_str());
            return 2;
        }
    }
    Gate gate(root);
    gate.set_environment(environment_record(root, command_line.c_str()));
    const int rc = gate.run();
    if (!write_evidence) return rc;
    if (!gate.write_evidence()) {
        std::fprintf(stderr, "failed to write evidence\n");
        return 1;
    }
    return rc;
}

}  // namespace c06

int main(int argc, char** argv) { return c06::run_main(argc, argv); }
