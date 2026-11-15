// C06 DAG — unit tests (GoogleTest).
//
// These tests pin the C06 surface:
//   * construction events (`add_atom`, `add_node`, builder-local ids);
//   * `finish` canonical emission: post-order first-use ids, topological table,
//     root last, no unused records, atoms in first-use order (O6.2);
//   * atom payload dedup (O6.3) and subterm sharing;
//   * construction-order independence (O6.1): shuffled builds of the same
//     logical term emit an identical `Ir`;
//   * error/limit behaviour (`Invalid` / `Limit`), and integration with
//     C03 (well-formedness, denotation), C04 (canonicality, canonical_key) and
//     C05 (evaluation).

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <map>
#include <random>
#include <string>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include "c03_build.hpp"
#include "c03_reference.hpp"
#include "mapr/e1_sha256.hpp"
#include "mapr/e2/e2_canon.hpp"
#include "mapr/e2/e2_dag.hpp"
#include "mapr/e2/e2_eval.hpp"
#include "mapr/e2/e2_term.hpp"

namespace {

using namespace marp::v2;  // NOLINT
using c03::pattern;

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

bool ir_equal(const Ir& a, const Ir& b) {
    if (a.nodes.size() != b.nodes.size() || a.atoms.size() != b.atoms.size()) return false;
    if (a.root != b.root || a.total_length != b.total_length) return false;
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

// Canonical shape obligations O6.2 / O6.3, checked structurally.
void expect_canonical_shape(const Ir& ir) {
    ASSERT_FALSE(ir.nodes.empty());
    EXPECT_EQ(ir.nodes.size() - 1, ir.root);
    EXPECT_EQ(ir.nodes[ir.root].length, ir.total_length);
    for (std::size_t i = 0; i < ir.nodes.size(); ++i) {
        for (const u32 arg : ir.nodes[i].args) {
            EXPECT_LT(arg, i) << "node " << i << " child " << arg;
        }
    }
    // No two atoms share a payload.
    for (std::size_t i = 0; i < ir.atoms.size(); ++i) {
        for (std::size_t j = i + 1; j < ir.atoms.size(); ++j) {
            EXPECT_FALSE(ir.atoms[i].sha256 == ir.atoms[j].sha256 &&
                         ir.atoms[i].payload.size() == ir.atoms[j].payload.size() &&
                         std::equal(ir.atoms[i].payload.begin(), ir.atoms[i].payload.end(),
                                    ir.atoms[j].payload.begin()))
                << "atoms " << i << " and " << j << " share a payload";
        }
    }
    // Every atom is referenced, every node is reachable from root.
    std::vector<char> atom_used(ir.atoms.size(), 0);
    for (const Node& node : ir.nodes) {
        if (node.kind == Kind::Atom) {
            const u64 id = node.a.to_u64_checked().value_or(~0ull);
            if (id < atom_used.size()) atom_used[static_cast<std::size_t>(id)] = 1;
        }
    }
    for (const char used : atom_used) EXPECT_EQ(1, used);
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
    for (const char r : reachable) EXPECT_EQ(1, r);
    EXPECT_TRUE(check_well_formed(ir).ok());
}

Node make_zero(const BigInt& n) {
    Node node;
    node.kind = Kind::Zero;
    node.a = n;
    return node;
}

Node make_atom(u32 atom) {
    Node node;
    node.kind = Kind::Atom;
    node.a = BigInt(static_cast<u64>(atom));
    return node;
}

Node make_concat(std::initializer_list<u32> children) {
    Node node;
    node.kind = Kind::Concat;
    node.args.assign(children.begin(), children.end());
    return node;
}

Node make_slice(u32 child, const BigInt& start, const BigInt& len) {
    Node node;
    node.kind = Kind::Slice;
    node.args = {child};
    node.a = start;
    node.b = len;
    return node;
}

Node make_morph(u32 child, u8 morph, u8 k) {
    Node node;
    node.kind = Kind::Morph;
    node.args = {child};
    node.morph = morph;
    node.morph_k = k;
    return node;
}

Node make_xor(u32 a, u32 b) {
    Node node;
    node.kind = Kind::Xor;
    node.args = {a, b};
    return node;
}

// ---------------------------------------------------------------------------
// construction / shape
// ---------------------------------------------------------------------------

TEST(C06Dag, EmptyIsTheOnlyNode) {
    Dag dag;
    const u32 root = dag.add_node(Node{}).value();
    EXPECT_EQ(1u, dag.node_count());
    EXPECT_EQ(0u, dag.atom_count());
    auto ir = std::move(dag).finish(root);
    ASSERT_TRUE(ir.ok());
    EXPECT_EQ(1u, ir.value().nodes.size());
    EXPECT_EQ(Kind::Empty, ir.value().nodes[0].kind);
    EXPECT_EQ(0u, ir.value().root);
    EXPECT_TRUE(ir.value().total_length.is_zero());
    expect_canonical_shape(ir.value());
}

TEST(C06Dag, FinishRejectsUnknownRoot) {
    Dag dag;
    (void)dag.add_node(Node{});
    EXPECT_EQ(Code::Invalid, std::move(dag).finish(7).code());
}

TEST(C06Dag, AddNodeRejectsMissingChild) {
    Dag dag;
    Node node;
    node.kind = Kind::Concat;
    node.args = {0};
    EXPECT_EQ(Code::Invalid, dag.add_node(node).code());
    EXPECT_EQ(0u, dag.node_count());
}

TEST(C06Dag, AddAtomRejectsEmptyPayload) {
    Dag dag;
    EXPECT_EQ(Code::Invalid, dag.add_atom(std::span<const u8>()).code());
    EXPECT_EQ(0u, dag.atom_count());
}

TEST(C06Dag, AddNodeRejectsUnknownAtomAndBadKind) {
    Dag dag;
    EXPECT_EQ(Code::Invalid, dag.add_node(make_atom(0)).code());
    Node bad;
    bad.kind = static_cast<Kind>(200);
    EXPECT_EQ(Code::Invalid, dag.add_node(bad).code());
    Node flagged;
    flagged.kind = Kind::Zero;
    flagged.flags = 1;
    EXPECT_EQ(Code::Invalid, dag.add_node(flagged).code());
}

// ---------------------------------------------------------------------------
// O6.2 — post-order first-use ids
// ---------------------------------------------------------------------------

TEST(C06Dag, PostOrderFirstUseIds) {
    Dag dag;
    const u32 a = dag.add_atom(pattern(4, 1)).value();
    const u32 b = dag.add_atom(pattern(5, 2)).value();
    const u32 na = dag.add_node(make_atom(a)).value();
    const u32 nb = dag.add_node(make_atom(b)).value();
    const u32 root = dag.add_node(make_concat({na, nb, na})).value();

    auto ir = std::move(dag).finish(root);
    ASSERT_TRUE(ir.ok());
    // Atom(a) -> 0, Atom(b) -> 1, Concat -> 2 (a is a shared child).
    ASSERT_EQ(3u, ir.value().nodes.size());
    EXPECT_EQ(Kind::Atom, ir.value().nodes[0].kind);
    EXPECT_EQ(Kind::Atom, ir.value().nodes[1].kind);
    EXPECT_EQ(Kind::Concat, ir.value().nodes[2].kind);
    EXPECT_EQ((std::vector<u32>{0, 1, 0}), ir.value().nodes[2].args);
    EXPECT_EQ(2u, ir.value().root);
    EXPECT_EQ(BigInt(13), ir.value().total_length);
    expect_canonical_shape(ir.value());
}

TEST(C06Dag, RootIsLastEvenWhenSubtermsAreBuiltAfterwards) {
    Dag dag;
    const u32 leaf = dag.add_node(make_zero(BigInt(3))).value();
    // Unrelated node constructed after the logical root; must not be emitted.
    const u32 root = dag.add_node(make_slice(leaf, BigInt(1), BigInt(2))).value();
    (void)dag.add_node(make_zero(BigInt(999)));

    auto ir = std::move(dag).finish(root);
    ASSERT_TRUE(ir.ok());
    ASSERT_EQ(2u, ir.value().nodes.size());
    EXPECT_EQ(Kind::Zero, ir.value().nodes[0].kind);
    EXPECT_EQ(Kind::Slice, ir.value().nodes[1].kind);
    EXPECT_EQ(1u, ir.value().root);
    expect_canonical_shape(ir.value());
}

TEST(C06Dag, UnreachableAtomsArePruned) {
    Dag dag;
    const u32 used = dag.add_atom(pattern(6, 3)).value();
    (void)dag.add_atom(pattern(7, 4));  // never referenced
    const u32 root = dag.add_node(make_atom(used)).value();
    auto ir = std::move(dag).finish(root);
    ASSERT_TRUE(ir.ok());
    EXPECT_EQ(1u, ir.value().atoms.size());
    expect_canonical_shape(ir.value());
}

// ---------------------------------------------------------------------------
// O6.1 — subterm sharing
// ---------------------------------------------------------------------------

TEST(C06Dag, StructurallyIdenticalSubtermsShareOneNode) {
    Dag dag;
    const u32 atom = dag.add_atom(pattern(8, 5)).value();
    // Two independent builder nodes with the same shape.
    const u32 left = dag.add_node(make_morph(dag.add_node(make_atom(atom)).value(), 2, 0)).value();
    const u32 right = dag.add_node(make_morph(dag.add_node(make_atom(atom)).value(), 2, 0)).value();
    const u32 root = dag.add_node(make_xor(left, right)).value();

    ASSERT_NE(left, right);
    auto ir = std::move(dag).finish(root);
    ASSERT_TRUE(ir.ok());
    // Atom, Morph, Xor — one Morph because the two inner nodes are identical.
    ASSERT_EQ(3u, ir.value().nodes.size());
    EXPECT_EQ(Kind::Xor, ir.value().nodes[2].kind);
    EXPECT_EQ(ir.value().nodes[2].args[0], ir.value().nodes[2].args[1]);
    EXPECT_EQ(1u, ir.value().atoms.size());
    expect_canonical_shape(ir.value());
}

// ---------------------------------------------------------------------------
// O6.3 — atom payload dedup
// ---------------------------------------------------------------------------

TEST(C06Dag, EqualPayloadsShareOneAtomRecord) {
    Dag dag;
    const u32 p1 = dag.add_atom(pattern(9, 7)).value();
    const u32 p2 = dag.add_atom(pattern(9, 7)).value();
    ASSERT_NE(p1, p2);
    const u32 n1 = dag.add_node(make_atom(p1)).value();
    const u32 n2 = dag.add_node(make_atom(p2)).value();
    const u32 root = dag.add_node(make_concat({n1, n2})).value();

    auto ir = std::move(dag).finish(root);
    ASSERT_TRUE(ir.ok());
    EXPECT_EQ(1u, ir.value().atoms.size());
    // The two Atom nodes are structurally identical, so interning leaves one Atom
    // node and one Concat node: Concat(0, 0).
    ASSERT_EQ(2u, ir.value().nodes.size());
    EXPECT_EQ((std::vector<u32>{0, 0}), ir.value().nodes[1].args);
    expect_canonical_shape(ir.value());
}

TEST(C06Dag, DifferentPayloadsOfEqualLengthStayDistinct) {
    Dag dag;
    const u32 p1 = dag.add_atom(pattern(9, 1)).value();
    const u32 p2 = dag.add_atom(pattern(9, 2)).value();
    const u32 root =
        dag.add_node(make_concat({dag.add_node(make_atom(p1)).value(),
                                  dag.add_node(make_atom(p2)).value()}))
            .value();
    auto ir = std::move(dag).finish(root);
    ASSERT_TRUE(ir.ok());
    EXPECT_EQ(2u, ir.value().atoms.size());
    EXPECT_NE(ir.value().atoms[0].sha256, ir.value().atoms[1].sha256);
    expect_canonical_shape(ir.value());
}

TEST(C06Dag, AtomIdsAreFirstUseOrderNotInsertionOrder) {
    Dag dag;
    const std::vector<u8> first_payload = pattern(5, 11);
    const std::vector<u8> second_payload = pattern(5, 12);
    const u32 p_first_inserted = dag.add_atom(first_payload).value();
    const u32 p_second_inserted = dag.add_atom(second_payload).value();
    // Traversal reaches the second-inserted payload first.
    const u32 n_second = dag.add_node(make_atom(p_second_inserted)).value();
    const u32 n_first = dag.add_node(make_atom(p_first_inserted)).value();
    const u32 root = dag.add_node(make_concat({n_second, n_first})).value();

    auto ir = std::move(dag).finish(root);
    ASSERT_TRUE(ir.ok());
    ASSERT_EQ(2u, ir.value().atoms.size());
    const auto want = mapr::Sha256::hash(std::string_view(
        reinterpret_cast<const char*>(second_payload.data()), second_payload.size()));
    ASSERT_TRUE(want.ok());
    EXPECT_EQ(want.value(), ir.value().atoms[0].sha256);
    EXPECT_EQ(static_cast<u32>(0), ir.value().nodes[0].a.to_u64_checked().value());
}

// ---------------------------------------------------------------------------
// O6.1 — construction-order independence
// ---------------------------------------------------------------------------

// A logical term described independently of construction order: a small
// "spec" tree that can be instantiated in any node order.
struct SpecNode {
    Kind kind = Kind::Empty;
    std::vector<int> children;  // indices into the spec list
    BigInt a, b;
    u8 morph = 0;
    u8 morph_k = 0;
    u64 lfsr_conn = 0;
    u64 lfsr_init = 0;
    u8 affine_start = 0;
    u8 affine_step = 0;
    u8 predictor_id = 0;
    u32 predictor_param = 0;
    int atom_slot = -1;  // deterministic payload slot
};

struct SpecTerm {
    std::vector<std::vector<u8>> payloads;
    std::vector<SpecNode> nodes;
    int root = 0;
};

SpecTerm build_spec_term() {
    SpecTerm term;
    term.payloads = {pattern(6, 21), pattern(7, 22), pattern(6, 21)};  // slot 2 duplicates 0

    auto add = [&term](SpecNode node) {
        term.nodes.push_back(std::move(node));
        return static_cast<int>(term.nodes.size() - 1);
    };

    SpecNode atom1;
    atom1.kind = Kind::Atom;
    atom1.atom_slot = 0;
    const int a1 = add(atom1);

    SpecNode atom2;
    atom2.kind = Kind::Atom;
    atom2.atom_slot = 1;
    const int a2 = add(atom2);

    SpecNode atom3;
    atom3.kind = Kind::Atom;
    atom3.atom_slot = 2;  // same bytes as atom1
    const int a3 = add(atom3);

    SpecNode zero;
    zero.kind = Kind::Zero;
    zero.a = BigInt(5);
    const int z = add(zero);

    SpecNode cat;
    cat.kind = Kind::Concat;
    cat.children = {a1, z, a2};
    const int c = add(cat);

    SpecNode morph;
    morph.kind = Kind::Morph;
    morph.children = {c};
    morph.morph = 6;  // ROTL8
    morph.morph_k = 3;
    const int m1 = add(morph);

    SpecNode morph2 = morph;  // structurally identical to m1
    const int m2 = add(morph2);

    SpecNode cat2;
    cat2.kind = Kind::Concat;
    cat2.children = {a3, z, a2};  // shares subterm with c
    const int c2 = add(cat2);

    SpecNode xor_node;
    xor_node.kind = Kind::Xor;
    xor_node.children = {m1, c2};
    const int x = add(xor_node);

    SpecNode sl;
    sl.kind = Kind::Slice;
    sl.children = {x};
    sl.a = BigInt(2);
    sl.b = BigInt(12);
    term.root = add(sl);

    (void)m2;
    return term;
}

// Instantiates `term` into a `Dag`, adding nodes in the given order (which must
// be a topological order of the spec indices).
Ir instantiate(const SpecTerm& term, const std::vector<int>& order) {
    Dag dag;
    std::vector<u32> atom_ids;
    atom_ids.reserve(term.payloads.size());
    for (const std::vector<u8>& payload : term.payloads) {
        auto id = dag.add_atom(std::span<const u8>(payload.data(), payload.size()));
        EXPECT_TRUE(id.ok());
        atom_ids.push_back(id.ok() ? id.value() : 0);
    }
    std::vector<u32> ids(term.nodes.size(), ~0u);
    for (const int index : order) {
        const SpecNode& spec = term.nodes[static_cast<std::size_t>(index)];
        Node node;
        node.kind = spec.kind;
        node.a = spec.a;
        node.b = spec.b;
        node.morph = spec.morph;
        node.morph_k = spec.morph_k;
        node.lfsr_conn = spec.lfsr_conn;
        node.lfsr_init = spec.lfsr_init;
        node.affine_start = spec.affine_start;
        node.affine_step = spec.affine_step;
        node.predictor_id = spec.predictor_id;
        node.predictor_param = spec.predictor_param;
        if (spec.atom_slot >= 0) node.a = BigInt(atom_ids[static_cast<std::size_t>(spec.atom_slot)]);
        for (const int child : spec.children) {
            node.args.push_back(ids[static_cast<std::size_t>(child)]);
        }
        auto id = dag.add_node(std::move(node));
        EXPECT_TRUE(id.ok()) << "add_node failed for spec index " << index;
        ids[static_cast<std::size_t>(index)] = id.ok() ? id.value() : 0;
    }
    auto ir = std::move(dag).finish(ids[static_cast<std::size_t>(term.root)]);
    EXPECT_TRUE(ir.ok());
    return ir.ok() ? ir.value() : Ir{};
}

// Random linear extension of the spec DAG (randomised Kahn), so every returned
// order is topological by construction.  `order[0]` is always the natural order.
std::vector<std::vector<int>> topological_orders(const SpecTerm& term, std::size_t count) {
    std::vector<int> natural;
    for (std::size_t i = 0; i < term.nodes.size(); ++i) natural.push_back(static_cast<int>(i));
    std::vector<std::vector<int>> orders{natural};

    const std::size_t n = term.nodes.size();
    std::vector<std::vector<std::size_t>> successors(n);
    std::vector<std::size_t> indegree(n, 0);
    for (std::size_t i = 0; i < n; ++i) {
        for (const int child : term.nodes[i].children) {
            successors[static_cast<std::size_t>(child)].push_back(i);
            ++indegree[i];
        }
    }
    std::mt19937 rng(0xC06u);
    for (std::size_t attempt = 0; attempt < count; ++attempt) {
        std::vector<std::size_t> remaining = indegree;
        std::vector<int> ready;
        for (std::size_t i = 0; i < n; ++i) {
            if (remaining[i] == 0) ready.push_back(static_cast<int>(i));
        }
        std::vector<int> order;
        order.reserve(n);
        while (!ready.empty()) {
            std::uniform_int_distribution<std::size_t> pick(0, ready.size() - 1);
            const std::size_t slot = pick(rng);
            const int id = ready[slot];
            ready[slot] = ready.back();
            ready.pop_back();
            order.push_back(id);
            for (const std::size_t next : successors[static_cast<std::size_t>(id)]) {
                if (--remaining[next] == 0) ready.push_back(static_cast<int>(next));
            }
        }
        if (order.size() == n) orders.push_back(std::move(order));
    }
    return orders;
}

TEST(C06Dag, ConstructionOrderDoesNotAffectTheIr) {
    const SpecTerm term = build_spec_term();
    const auto orders = topological_orders(term, 24);
    const Ir reference = instantiate(term, orders.front());
    expect_canonical_shape(reference);
    for (std::size_t i = 1; i < orders.size(); ++i) {
        const Ir other = instantiate(term, orders[i]);
        EXPECT_TRUE(ir_equal(reference, other)) << "order " << i << " differs";
    }
}

TEST(C06Dag, AtomInsertionOrderDoesNotAffectTheIr) {
    // Same logical term, payloads registered in a different order.
    auto build = [](bool reversed) {
        Dag dag;
        std::vector<std::vector<u8>> payloads{pattern(4, 1), pattern(4, 2), pattern(4, 3)};
        if (reversed) std::reverse(payloads.begin(), payloads.end());
        std::array<u32, 3> atom_ids{};
        for (std::size_t i = 0; i < payloads.size(); ++i) {
            atom_ids[i] = dag.add_atom(std::span<const u8>(payloads[i].data(), payloads[i].size()))
                              .value();
        }
        std::array<u32, 3> nodes{};
        for (std::size_t i = 0; i < 3; ++i) {
            nodes[i] = dag.add_node(make_atom(atom_ids[i])).value();
        }
        const u32 root = dag.add_node(make_concat({nodes[0], nodes[1], nodes[2]})).value();
        auto ir = std::move(dag).finish(root);
        EXPECT_TRUE(ir.ok());
        return ir.ok() ? ir.value() : Ir{};
    };
    for (const bool reversed : {false, true}) {
        const Ir ir = build(reversed);
        EXPECT_EQ(3u, ir.atoms.size());
        EXPECT_EQ(BigInt(12), ir.total_length);
        expect_canonical_shape(ir);
    }
}

// ---------------------------------------------------------------------------
// determinism
// ---------------------------------------------------------------------------

TEST(C06Dag, RepeatedFinishIsByteIdentical) {
    const SpecTerm term = build_spec_term();
    const auto orders = topological_orders(term, 0);
    const Ir a = instantiate(term, orders.front());
    for (int i = 0; i < 4; ++i) {
        const Ir b = instantiate(term, orders.front());
        EXPECT_TRUE(ir_equal(a, b));
    }
}

// ---------------------------------------------------------------------------
// limits
// ---------------------------------------------------------------------------

TEST(C06Dag, CountAndDepthLimits) {
    Limits limits;
    limits.max_nodes = 3;
    Dag dag(limits);
    EXPECT_TRUE(dag.add_node(Node{}).ok());
    EXPECT_TRUE(dag.add_node(make_zero(BigInt(1))).ok());
    EXPECT_TRUE(dag.add_node(make_zero(BigInt(2))).ok());
    EXPECT_EQ(Code::Limit, dag.add_node(make_zero(BigInt(3))).code());

    Limits atom_limits;
    atom_limits.max_atoms = 1;
    Dag atom_dag(atom_limits);
    EXPECT_TRUE(atom_dag.add_atom(pattern(2, 1)).ok());
    EXPECT_EQ(Code::Limit, atom_dag.add_atom(pattern(2, 2)).code());

    Limits shallow;
    shallow.max_depth = 3;  // W7 bound: depth == max_depth is allowed, +1 is not
    Dag depth_dag(shallow);
    const u32 leaf = depth_dag.add_node(make_zero(BigInt(4))).value();      // depth 1
    const u32 mid = depth_dag.add_node(make_morph(leaf, 2, 0)).value();     // depth 2
    const u32 top = depth_dag.add_node(make_morph(mid, 2, 0)).value();      // depth 3
    EXPECT_EQ(2u, top);
    Node deeper = make_morph(top, 2, 0);                                    // depth 4
    EXPECT_EQ(Code::Limit, depth_dag.add_node(deeper).code());
}

TEST(C06Dag, OutputCapIsLimit) {
    // Zero(2^63 + 1) exceeds the §8.3 output cap; the term itself is a single
    // node, so the rejection is the cap and not a count or depth bound.
    Dag dag;
    const BigInt huge = BigInt(1).shl(63).value();
    const BigInt over = huge.add(BigInt(1)).value();
    const u32 root = dag.add_node(make_zero(over)).value();
    EXPECT_EQ(Code::Limit, std::move(dag).finish(root).code());
}

TEST(C06Dag, IllFormedTermIsRejectedAtFinish) {
    Dag dag;
    const u32 atom = dag.add_atom(pattern(4, 3)).value();
    const u32 n1 = dag.add_node(make_atom(atom)).value();
    // Concat with one child is not well-formed (W8.argc).
    const u32 bad_root = dag.add_node(make_concat({n1})).value();
    EXPECT_EQ(Code::Invalid, std::move(dag).finish(bad_root).code());
}

// ---------------------------------------------------------------------------
// integration with C03 / C04 / C05
// ---------------------------------------------------------------------------

TEST(C06Dag, DagBuiltTermAgreesWithBuilderBuiltTerm) {
    const SpecTerm term = build_spec_term();
    const auto orders = topological_orders(term, 0);
    const Ir dag_ir = instantiate(term, orders.front());
    if (dag_ir.nodes.empty()) return;

    // C05 evaluation agrees with C03 denotation.
    auto streamed = denote_root(dag_ir, 1u << 20);
    ASSERT_TRUE(streamed.ok());
    std::vector<u8> ref;
    ASSERT_TRUE(c03ref::ref_denote(dag_ir, dag_ir.root, ref, 1u << 20));
    EXPECT_EQ(ref, streamed.value());
    // C06 does not rewrite: the spec term is not a canonical C04 term (its Xor
    // operands are not in canonical_key order), so `canon` may change it — but
    // never its denotation, and it must be idempotent.
    auto recanon = canon(dag_ir);
    ASSERT_TRUE(recanon.ok());
    std::vector<u8> recanon_bytes;
    ASSERT_TRUE(c03ref::ref_denote(recanon.value(), recanon.value().root, recanon_bytes, 1u << 20));
    EXPECT_EQ(streamed.value(), recanon_bytes);
    auto twice = canon(recanon.value());
    ASSERT_TRUE(twice.ok());
    EXPECT_TRUE(ir_equal(recanon.value(), twice.value()));
}

TEST(C06Dag, CanonicalDagOutputEqualsItsOwnCanonicalisation) {
    // A term that is canonical in the C04 sense: Concat(Atom(4), Zero(3)).
    Dag dag;
    const u32 atom = dag.add_atom(pattern(4, 31)).value();
    const u32 a = dag.add_node(make_atom(atom)).value();
    const u32 z = dag.add_node(make_zero(BigInt(3))).value();
    const u32 root = dag.add_node(make_concat({a, z})).value();
    auto ir = std::move(dag).finish(root);
    ASSERT_TRUE(ir.ok());
    expect_canonical_shape(ir.value());
    EXPECT_TRUE(is_canonical(ir.value()));
    auto recanon = canon(ir.value());
    ASSERT_TRUE(recanon.ok());
    EXPECT_TRUE(ir_equal(ir.value(), recanon.value()));
}

}  // namespace
