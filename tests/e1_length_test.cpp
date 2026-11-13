#include "mapr/e1_length.hpp"
#include <gtest/gtest.h>
#include <vector>

using namespace mapr;

// Minimal TermView implementation for testing
class TestTermView : public TermView {
public:
    struct Node {
        NodeKind kind = NodeKind::Empty;
        size_t atom_size = 0;
        BigInt zero_count;
        std::vector<NodeId> concat_children;
        NodeId repeat_child = 0;
        BigInt repeat_q, repeat_r;
        NodeId slice_child = 0;
        BigInt slice_start, slice_len;
        NodeId morph_child = 0;
        NodeId xor_a = 0, xor_b = 0;
        std::vector<NodeId> interleave_children;
        uint32_t interleave_stride = 0;
        BigInt fixed_n;
        NodeId predictor_residual = 0;
    };

    std::vector<Node> nodes;

    size_t node_count() const noexcept override { return nodes.size(); }
    NodeKind node_kind(NodeId id) const noexcept override { return nodes[id].kind; }

    size_t atom_size(NodeId id) const noexcept override { return nodes[id].atom_size; }
    BigInt zero_count(NodeId id) const noexcept override { return nodes[id].zero_count; }
    std::vector<NodeId> concat_children(NodeId id) const noexcept override { return nodes[id].concat_children; }
    NodeId repeat_child(NodeId id) const noexcept override { return nodes[id].repeat_child; }
    const BigInt& repeat_q(NodeId id) const noexcept override { return nodes[id].repeat_q; }
    const BigInt& repeat_r(NodeId id) const noexcept override { return nodes[id].repeat_r; }
    NodeId slice_child(NodeId id) const noexcept override { return nodes[id].slice_child; }
    const BigInt& slice_start(NodeId id) const noexcept override { return nodes[id].slice_start; }
    const BigInt& slice_len(NodeId id) const noexcept override { return nodes[id].slice_len; }
    NodeId morph_child(NodeId id) const noexcept override { return nodes[id].morph_child; }
    NodeId xor_a(NodeId id) const noexcept override { return nodes[id].xor_a; }
    NodeId xor_b(NodeId id) const noexcept override { return nodes[id].xor_b; }
    std::vector<NodeId> interleave_children(NodeId id) const noexcept override { return nodes[id].interleave_children; }
    uint32_t interleave_stride(NodeId id) const noexcept override { return nodes[id].interleave_stride; }
    BigInt lfsr_n(NodeId id) const noexcept override { return nodes[id].fixed_n; }
    BigInt affine_n(NodeId id) const noexcept override { return nodes[id].fixed_n; }
    NodeId predictor_residual(NodeId id) const noexcept override { return nodes[id].predictor_residual; }
};

static TestTermView::Node make_empty() {
    TestTermView::Node n;
    n.kind = NodeKind::Empty;
    return n;
}

static TestTermView::Node make_atom(size_t size) {
    TestTermView::Node n;
    n.kind = NodeKind::Atom;
    n.atom_size = size;
    return n;
}

static TestTermView::Node make_zero(const BigInt& count) {
    TestTermView::Node n;
    n.kind = NodeKind::Zero;
    n.zero_count = count;
    return n;
}

static TestTermView::Node make_concat(const std::vector<NodeId>& children) {
    TestTermView::Node n;
    n.kind = NodeKind::Concat;
    n.concat_children = children;
    return n;
}

static TestTermView::Node make_repeat(NodeId child, const BigInt& q, const BigInt& r) {
    TestTermView::Node n;
    n.kind = NodeKind::Repeat;
    n.repeat_child = child;
    n.repeat_q = q;
    n.repeat_r = r;
    return n;
}

static TestTermView::Node make_slice(NodeId child, const BigInt& start, const BigInt& len) {
    TestTermView::Node n;
    n.kind = NodeKind::Slice;
    n.slice_child = child;
    n.slice_start = start;
    n.slice_len = len;
    return n;
}

static TestTermView::Node make_morph(NodeId child) {
    TestTermView::Node n;
    n.kind = NodeKind::Morph;
    n.morph_child = child;
    return n;
}

static TestTermView::Node make_xor(NodeId a, NodeId b) {
    TestTermView::Node n;
    n.kind = NodeKind::Xor;
    n.xor_a = a;
    n.xor_b = b;
    return n;
}

static TestTermView::Node make_interleave(const std::vector<NodeId>& children, uint32_t stride) {
    TestTermView::Node n;
    n.kind = NodeKind::Interleave;
    n.interleave_children = children;
    n.interleave_stride = stride;
    return n;
}

static TestTermView::Node make_lfsr(const BigInt& n_bytes) {
    TestTermView::Node n;
    n.kind = NodeKind::Lfsr;
    n.fixed_n = n_bytes;
    return n;
}

static TestTermView::Node make_affine(const BigInt& n_bytes) {
    TestTermView::Node n;
    n.kind = NodeKind::Affine;
    n.fixed_n = n_bytes;
    return n;
}

static TestTermView::Node make_predictor(NodeId residual) {
    TestTermView::Node n;
    n.kind = NodeKind::Predictor;
    n.predictor_residual = residual;
    return n;
}

TEST(E1Length, Empty) {
    TestTermView term;
    term.nodes.push_back(make_empty());
    auto r = length_of(term);
    ASSERT_TRUE(r.ok());
    EXPECT_TRUE(r.value().length.is_zero());
}

TEST(E1Length, Atom) {
    TestTermView term;
    term.nodes.push_back(make_atom(10));
    auto r = length_of(term);
    ASSERT_TRUE(r.ok());
    EXPECT_EQ(r.value().length, BigInt(10));
}

TEST(E1Length, Zero) {
    TestTermView term;
    term.nodes.push_back(make_zero(BigInt(100)));
    auto r = length_of(term);
    ASSERT_TRUE(r.ok());
    EXPECT_EQ(r.value().length, BigInt(100));
}

TEST(E1Length, Concat) {
    TestTermView term;
    term.nodes.push_back(make_atom(4));
    term.nodes.push_back(make_atom(6));
    term.nodes.push_back(make_concat({0, 1}));

    auto r = length_of(term);
    ASSERT_TRUE(r.ok());
    EXPECT_EQ(r.value().length, BigInt(10));
    EXPECT_EQ(r.value().memo[0], BigInt(4));
    EXPECT_EQ(r.value().memo[1], BigInt(6));
    EXPECT_EQ(r.value().memo[2], BigInt(10));
}

TEST(E1Length, Repeat) {
    TestTermView term;
    term.nodes.push_back(make_atom(4));
    term.nodes.push_back(make_repeat(0, BigInt(3), BigInt(2)));

    auto r = length_of(term);
    ASSERT_TRUE(r.ok());
    EXPECT_EQ(r.value().length, BigInt(14));
}

TEST(E1Length, RepeatInvalid) {
    // r >= L when q >= 1
    TestTermView term;
    term.nodes.push_back(make_atom(4));
    term.nodes.push_back(make_repeat(0, BigInt(1), BigInt(4)));
    auto r = length_of(term);
    EXPECT_FALSE(r.ok());
    EXPECT_EQ(r.error(), ErrCode::Invalid);

    // q = 0, r > 0
    TestTermView term2;
    term2.nodes.push_back(make_atom(4));
    term2.nodes.push_back(make_repeat(0, BigInt(0), BigInt(1)));
    auto r2 = length_of(term2);
    EXPECT_FALSE(r2.ok());
}

TEST(E1Length, Slice) {
    TestTermView term;
    term.nodes.push_back(make_atom(100));
    term.nodes.push_back(make_slice(0, BigInt(10), BigInt(20)));

    auto r = length_of(term);
    ASSERT_TRUE(r.ok());
    EXPECT_EQ(r.value().length, BigInt(20));
}

TEST(E1Length, SliceInvalid) {
    // start > L
    TestTermView term;
    term.nodes.push_back(make_atom(10));
    term.nodes.push_back(make_slice(0, BigInt(15), BigInt(5)));
    auto r = length_of(term);
    EXPECT_FALSE(r.ok());

    // start + len > L
    TestTermView term2;
    term2.nodes.push_back(make_atom(10));
    term2.nodes.push_back(make_slice(0, BigInt(8), BigInt(5)));
    auto r2 = length_of(term2);
    EXPECT_FALSE(r2.ok());
}

TEST(E1Length, Morph) {
    TestTermView term;
    term.nodes.push_back(make_atom(42));
    term.nodes.push_back(make_morph(0));
    auto r = length_of(term);
    ASSERT_TRUE(r.ok());
    EXPECT_EQ(r.value().length, BigInt(42));
}

TEST(E1Length, Xor) {
    TestTermView term;
    term.nodes.push_back(make_atom(10));
    term.nodes.push_back(make_atom(10));
    term.nodes.push_back(make_xor(0, 1));
    auto r = length_of(term);
    ASSERT_TRUE(r.ok());
    EXPECT_EQ(r.value().length, BigInt(10));
}

TEST(E1Length, XorInvalid) {
    TestTermView term;
    term.nodes.push_back(make_atom(10));
    term.nodes.push_back(make_atom(5));
    term.nodes.push_back(make_xor(0, 1));
    auto r = length_of(term);
    EXPECT_FALSE(r.ok());
    EXPECT_EQ(r.error(), ErrCode::Invalid);
}

TEST(E1Length, Interleave) {
    TestTermView term;
    term.nodes.push_back(make_atom(12));
    term.nodes.push_back(make_atom(12));
    term.nodes.push_back(make_atom(12));
    term.nodes.push_back(make_interleave({0, 1, 2}, 4));
    auto r = length_of(term);
    ASSERT_TRUE(r.ok());
    EXPECT_EQ(r.value().length, BigInt(36));
}

TEST(E1Length, InterleaveInvalid) {
    // Unequal lengths
    TestTermView term;
    term.nodes.push_back(make_atom(12));
    term.nodes.push_back(make_atom(10));
    term.nodes.push_back(make_interleave({0, 1}, 4));
    auto r = length_of(term);
    EXPECT_FALSE(r.ok());

    // Stride doesn't divide
    TestTermView term2;
    term2.nodes.push_back(make_atom(10));
    term2.nodes.push_back(make_atom(10));
    term2.nodes.push_back(make_interleave({0, 1}, 4));
    auto r2 = length_of(term2);
    EXPECT_FALSE(r2.ok());
}

TEST(E1Length, Lfsr) {
    TestTermView term;
    term.nodes.push_back(make_lfsr(BigInt(64)));
    auto r = length_of(term);
    ASSERT_TRUE(r.ok());
    EXPECT_EQ(r.value().length, BigInt(64));
}

TEST(E1Length, Affine) {
    TestTermView term;
    term.nodes.push_back(make_affine(BigInt(256)));
    auto r = length_of(term);
    ASSERT_TRUE(r.ok());
    EXPECT_EQ(r.value().length, BigInt(256));
}

TEST(E1Length, Predictor) {
    TestTermView term;
    term.nodes.push_back(make_atom(50));
    term.nodes.push_back(make_predictor(0));
    auto r = length_of(term);
    ASSERT_TRUE(r.ok());
    EXPECT_EQ(r.value().length, BigInt(50));
}

TEST(E1Length, StructuralIdentities_O1_5) {
    // I1: concat
    auto c = length_identity::concat({BigInt(3), BigInt(5), BigInt(7)});
    EXPECT_EQ(c, BigInt(15));

    // I2: repeat
    auto r = length_identity::repeat(BigInt(4), BigInt(3), BigInt(2));
    EXPECT_EQ(r, BigInt(14));

    // I3: slice
    auto s = length_identity::slice(BigInt(100), BigInt(10), BigInt(20));
    EXPECT_EQ(s, BigInt(20));

    // I4: interleave
    auto i = length_identity::interleave({BigInt(10), BigInt(10), BigInt(10)}, 2);
    EXPECT_EQ(i, BigInt(30));

    // I5: morph
    auto m = length_identity::morph(BigInt(42));
    EXPECT_EQ(m, BigInt(42));

    // I6: xor
    auto x = length_identity::xor_len(BigInt(10), BigInt(10));
    EXPECT_EQ(x, BigInt(10));

    // I7: predictor
    auto p = length_identity::predictor(BigInt(99));
    EXPECT_EQ(p, BigInt(99));

    // I8: fixed
    auto f = length_identity::fixed(BigInt(123));
    EXPECT_EQ(f, BigInt(123));
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}