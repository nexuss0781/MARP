// C04 CANON — unit tests (GoogleTest).
//
// These tests pin the C04 surface: canonicalisation to a fixed point, the
// canonical-shape predicates (`check_canonical` / `is_canonical`), the
// canonical key, and the O4.1 rewrite budget.  Denotation preservation is
// checked with the C03 reference denotation (`denote_root`), and idempotence
// is checked by structural comparison of the whole Ir.

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "c03_build.hpp"
#include "mapr/e1_sha256.hpp"
#include "mapr/e2/e2_canon.hpp"
#include "mapr/e2/e2_term.hpp"

namespace {

using namespace marp::v2;  // NOLINT
using c03::Builder;
using c03::pattern;

// Structural comparison of two Ir values: kinds, params, child ids, atom
// records (including payload bytes), root and total length.
bool ir_equal(const Ir& a, const Ir& b) {
    if (a.nodes.size() != b.nodes.size() || a.atoms.size() != b.atoms.size()) return false;
    if (a.root != b.root || a.total_length != b.total_length) return false;
    for (std::size_t i = 0; i < a.atoms.size(); ++i) {
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
        if (x.kind != y.kind) return false;
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

std::vector<u8> denote(const Ir& ir) {
    auto out = denote_root(ir, static_cast<u64>(8) * 1024 * 1024);
    EXPECT_TRUE(out.ok());
    return out.ok() ? out.value() : std::vector<u8>{};
}

TEST(C04Canon, EmptyTermIsCanonicalAndIdempotent) {
    Builder b;
    const u32 root = b.empty();
    Ir ir = b.finish(root);
    EXPECT_TRUE(is_canonical(ir));
    auto out = canon(ir);
    ASSERT_TRUE(out.ok());
    EXPECT_EQ(1u, out.value().nodes.size());
    EXPECT_EQ(Kind::Empty, out.value().nodes[0].kind);
}

TEST(C04Canon, ZeroZeroIsCanonical) {
    // Zero(0) is a legitimate terminal form (no enumerated rule folds it).
    Builder b;
    const u32 root = b.zero(0);
    Ir ir = b.finish(root);
    EXPECT_TRUE(is_canonical(ir));
    auto out = canon(ir);
    ASSERT_TRUE(out.ok());
    EXPECT_EQ(1u, out.value().nodes.size());
}

TEST(C04Canon, ConcatNestedChildFlattens) {
    Builder b;
    const u32 atom = b.atom_node(b.add_atom({0x11}));
    const u32 inner = b.concat({atom, b.zero(5)});   // Concat stays (atom, zero)
    const u32 root = b.concat({inner, b.zero(7)});
    Ir ir = b.finish(root);
    EXPECT_FALSE(is_canonical(ir));
    CanonReport report;
    auto out = canon(ir, report);
    ASSERT_TRUE(out.ok());
    // Flatten brings (atom, zero(5), zero(7)) together; the adjacent zeros merge.
    ASSERT_EQ(3u, out.value().nodes.size());
    EXPECT_EQ(Kind::Concat, out.value().nodes.back().kind);
    ASSERT_EQ(2u, out.value().nodes.back().args.size());
    EXPECT_GE(report.rule_fires[0], 1u);  // rule 1
    EXPECT_GE(report.rule_fires[3], 1u);  // rule 4
    EXPECT_TRUE(is_canonical(out.value()));
    EXPECT_EQ(denote(ir), denote(out.value()));
}

TEST(C04Canon, ConcatEmptyChildCollapsesToChild) {
    Builder b;
    const u32 atom = b.atom_node(b.add_atom({0xA5}));
    const u32 e = b.empty();
    const u32 root = b.concat({e, atom});
    Ir ir = b.finish(root);
    EXPECT_FALSE(is_canonical(ir));
    CanonReport report;
    auto out = canon(ir, report);
    ASSERT_TRUE(out.ok());
    ASSERT_EQ(1u, out.value().nodes.size());
    EXPECT_EQ(Kind::Atom, out.value().nodes[0].kind);
    EXPECT_GE(report.rule_fires[1], 1u);   // rule 2
    EXPECT_GE(report.rule_fires[12], 1u);  // rule 13 (Empty record pruned)
}

TEST(C04Canon, ConcatOfAllEmptiesBecomesEmpty) {
    Builder b;
    const u32 e1 = b.empty();
    const u32 e2 = b.empty();
    const u32 root = b.concat({e1, e2});
    Ir ir = b.finish(root);
    auto out = canon(ir);
    ASSERT_TRUE(out.ok());
    ASSERT_EQ(1u, out.value().nodes.size());
    EXPECT_EQ(Kind::Empty, out.value().nodes[0].kind);
    EXPECT_TRUE(is_canonical(out.value()));
}

TEST(C04Canon, AdjacentAtomsMergeWhenSumFits) {
    Builder b;
    const u32 a1 = b.atom_node(b.add_atom(std::vector<u8>(500000, 0x11)));
    const u32 a2 = b.atom_node(b.add_atom(std::vector<u8>(500000, 0x22)));
    const u32 root = b.concat({a1, a2});
    Ir ir = b.finish(root);
    EXPECT_FALSE(is_canonical(ir));
    CanonReport report;
    auto out = canon(ir, report);
    ASSERT_TRUE(out.ok());
    ASSERT_EQ(1u, out.value().atoms.size());
    EXPECT_EQ(1000000u, out.value().atoms[0].length.to_u64_checked().value());
    EXPECT_GE(report.rule_fires[2], 1u);  // rule 3
    EXPECT_TRUE(is_canonical(out.value()));
}

TEST(C04Canon, AdjacentAtomsAboveAtomMaxStaySplit) {
    Builder b;
    const u32 a1 = b.atom_node(b.add_atom(std::vector<u8>(700000, 0x11)));
    const u32 a2 = b.atom_node(b.add_atom(std::vector<u8>(400000, 0x22)));
    const u32 root = b.concat({a1, a2});
    Ir ir = b.finish(root);
    auto out = canon(ir);
    ASSERT_TRUE(out.ok());
    ASSERT_EQ(2u, out.value().atoms.size());  // 700k + 400k > ATOM_MAX: no merge
}

TEST(C04Canon, OversizedAtomSplitsIntoAtomMaxPieces) {
    std::vector<u8> payload(static_cast<std::size_t>(kAtomMax) + 7, 0x5A);
    Builder b;
    const u32 atom = b.atom_node(b.add_atom(payload));
    Ir ir = b.finish(atom);
    EXPECT_FALSE(is_canonical(ir));
    CanonReport report;
    auto out = canon(ir, report);
    ASSERT_TRUE(out.ok());
    ASSERT_EQ(2u, out.value().atoms.size());
    EXPECT_EQ(kAtomMax, out.value().atoms[0].length.to_u64_checked().value());
    EXPECT_EQ(7u, out.value().atoms[1].length.to_u64_checked().value());
    EXPECT_EQ(Kind::Concat, out.value().nodes.back().kind);
    EXPECT_GE(report.rule_fires[2], 1u);  // rule 3 split
    EXPECT_TRUE(is_canonical(out.value()));
    EXPECT_EQ(static_cast<u64>(payload.size()),
              out.value().total_length.to_u64_checked().value());
}

TEST(C04Canon, AdjacentZerosMerge) {
    Builder b;
    const u32 root = b.concat({b.zero(2), b.zero(3)});
    Ir ir = b.finish(root);
    CanonReport report;
    auto out = canon(ir, report);
    ASSERT_TRUE(out.ok());
    ASSERT_EQ(1u, out.value().nodes.size());
    EXPECT_EQ(Kind::Zero, out.value().nodes[0].kind);
    EXPECT_EQ(5u, out.value().nodes[0].a.to_u64_checked().value());
    EXPECT_GE(report.rule_fires[3], 1u);  // rule 4
}

TEST(C04Canon, RepeatFoldsToEmptyChildOrConcat) {
    // q = 0, r = 0 -> Empty
    {
        Builder b;
        const u32 atom = b.atom_node(b.add_atom(pattern(4, 3)));
        const u32 root = b.repeat(atom, 0, 0);
        Ir ir = b.finish(root);
        CanonReport report;
        auto out = canon(ir, report);
        ASSERT_TRUE(out.ok());
        ASSERT_EQ(1u, out.value().nodes.size());
        EXPECT_EQ(Kind::Empty, out.value().nodes[0].kind);
        EXPECT_GE(report.rule_fires[4], 1u);  // rule 5
    }
    // q = 1, r = 0 -> child
    {
        Builder b;
        const u32 atom = b.atom_node(b.add_atom(pattern(4, 3)));
        const u32 root = b.repeat(atom, 1, 0);
        Ir ir = b.finish(root);
        CanonReport report;
        auto out = canon(ir, report);
        ASSERT_TRUE(out.ok());
        ASSERT_EQ(1u, out.value().nodes.size());
        EXPECT_EQ(Kind::Atom, out.value().nodes[0].kind);
        EXPECT_GE(report.rule_fires[4], 1u);  // rule 5
    }
    // q = 1, r > 0 -> Concat(child, Slice(child, 0, r)), denotation preserved
    {
        Builder b;
        const u32 atom = b.atom_node(b.add_atom(pattern(8, 4)));
        const u32 root = b.repeat(atom, 1, 3);
        Ir ir = b.finish(root);
        CanonReport report;
        auto out = canon(ir, report);
        ASSERT_TRUE(out.ok());
        ASSERT_EQ(Kind::Concat, out.value().nodes.back().kind);
        EXPECT_EQ(2u, out.value().nodes.back().args.size());
        EXPECT_GE(report.rule_fires[4], 1u);  // rule 5
        EXPECT_EQ(denote(ir), denote(out.value()));
        EXPECT_TRUE(is_canonical(out.value()));
    }
}

TEST(C04Canon, RepeatNormalFormStays) {
    Builder b;
    const u32 atom = b.atom_node(b.add_atom(pattern(16, 9)));
    const u32 root = b.repeat(atom, 3, 5);
    Ir ir = b.finish(root);
    EXPECT_TRUE(is_canonical(ir));
    CanonReport report;
    auto out = canon(ir, report);
    ASSERT_TRUE(out.ok());
    EXPECT_TRUE(ir_equal(ir, out.value()));
}

TEST(C04Canon, SliceNestedComposes) {
    Builder b;
    const u32 atom = b.atom_node(b.add_atom(pattern(32, 2)));
    const u32 inner = b.slice(atom, 1, 8);
    const u32 root = b.slice(inner, 2, 3);
    Ir ir = b.finish(root);
    EXPECT_FALSE(is_canonical(ir));
    CanonReport report;
    auto out = canon(ir, report);
    ASSERT_TRUE(out.ok());
    ASSERT_EQ(2u, out.value().nodes.size());
    ASSERT_EQ(Kind::Slice, out.value().nodes.back().kind);
    EXPECT_EQ(3u, out.value().nodes.back().a.to_u64_checked().value());
    EXPECT_EQ(3u, out.value().nodes.back().b.to_u64_checked().value());
    EXPECT_GE(report.rule_fires[5], 1u);  // rule 6
    EXPECT_EQ(denote(ir), denote(out.value()));
}

TEST(C04Canon, SliceFullCoverFoldsToChild) {
    Builder b;
    const u32 atom = b.atom_node(b.add_atom(pattern(16, 5)));
    const u32 root = b.slice(atom, 0, 16);
    Ir ir = b.finish(root);
    CanonReport report;
    auto out = canon(ir, report);
    ASSERT_TRUE(out.ok());
    ASSERT_EQ(1u, out.value().nodes.size());
    EXPECT_EQ(Kind::Atom, out.value().nodes[0].kind);
    EXPECT_GE(report.rule_fires[5], 1u);  // rule 6
}

TEST(C04Canon, SliceZeroLengthFoldsToEmpty) {
    Builder b;
    const u32 atom = b.atom_node(b.add_atom(pattern(16, 6)));
    const u32 slice = b.slice(atom, 2, 0);
    const u32 other = b.atom_node(b.add_atom(pattern(3, 7)));
    const u32 root = b.concat({slice, other});
    Ir ir = b.finish(root);
    CanonReport report;
    auto out = canon(ir, report);
    ASSERT_TRUE(out.ok());
    ASSERT_EQ(1u, out.value().nodes.size());
    EXPECT_EQ(Kind::Atom, out.value().nodes[0].kind);
    ASSERT_EQ(1u, out.value().atoms.size());
    EXPECT_EQ(3u, out.value().atoms[0].length.to_u64_checked().value());
    EXPECT_GE(report.rule_fires[5], 1u);   // rule 6
    EXPECT_GE(report.rule_fires[1], 1u);   // rule 2 (Empty child dropped)
}

TEST(C04Canon, MorphIdenticalInvolutionsCancel) {
    Builder b;
    const u32 atom = b.atom_node(b.add_atom(pattern(16, 8)));
    const u32 m1 = b.morph(atom, 8 /* REVERSE_BYTES */, 0);
    const u32 root = b.morph(m1, 8 /* REVERSE_BYTES */, 0);
    Ir ir = b.finish(root);
    CanonReport report;
    auto out = canon(ir, report);
    ASSERT_TRUE(out.ok());
    ASSERT_EQ(1u, out.value().nodes.size());
    EXPECT_EQ(Kind::Atom, out.value().nodes[0].kind);
    EXPECT_GE(report.rule_fires[6], 1u);  // rule 7
    EXPECT_EQ(denote(ir), denote(out.value()));
}

TEST(C04Canon, MorphRotationsComposeToIdentity) {
    Builder b;
    const u32 atom = b.atom_node(b.add_atom(pattern(16, 8)));
    const u32 m1 = b.morph(atom, 6 /* ROTL8 */, 3);
    const u32 root = b.morph(m1, 6 /* ROTL8 */, 5);  // 3 + 5 = 8 -> identity
    Ir ir = b.finish(root);
    CanonReport report;
    auto out = canon(ir, report);
    ASSERT_TRUE(out.ok());
    ASSERT_EQ(1u, out.value().nodes.size());
    EXPECT_EQ(Kind::Atom, out.value().nodes[0].kind);
    EXPECT_GE(report.rule_fires[6], 1u);  // rule 7
}

TEST(C04Canon, MorphRotationsCompose) {
    Builder b;
    const u32 atom = b.atom_node(b.add_atom(pattern(16, 8)));
    const u32 m1 = b.morph(atom, 7 /* ROTR8 */, 1);
    const u32 root = b.morph(m1, 6 /* ROTL8 */, 3);  // net ROTL8(2)
    Ir ir = b.finish(root);
    CanonReport report;
    auto out = canon(ir, report);
    ASSERT_TRUE(out.ok());
    ASSERT_EQ(2u, out.value().nodes.size());
    ASSERT_EQ(Kind::Morph, out.value().nodes.back().kind);
    EXPECT_EQ(6u, out.value().nodes.back().morph);
    EXPECT_EQ(2u, out.value().nodes.back().morph_k);
    EXPECT_GE(report.rule_fires[6], 1u);  // rule 7
    EXPECT_EQ(denote(ir), denote(out.value()));
}

TEST(C04Canon, XorSelfFoldsToZero) {
    Builder b;
    const u32 a = b.lfsr(0x80200003, 1, 16);
    const u32 b2 = b.lfsr(0x80200003, 1, 16);
    const u32 root = b.xor_node(a, b2);
    Ir ir = b.finish(root);
    EXPECT_FALSE(is_canonical(ir));
    CanonReport report;
    auto out = canon(ir, report);
    ASSERT_TRUE(out.ok());
    ASSERT_EQ(1u, out.value().nodes.size());
    EXPECT_EQ(Kind::Zero, out.value().nodes[0].kind);
    EXPECT_EQ(16u, out.value().nodes[0].a.to_u64_checked().value());
    EXPECT_GE(report.rule_fires[7], 1u);  // rule 8
}

TEST(C04Canon, XorZeroOperandFolds) {
    Builder b;
    const u32 atom = b.atom_node(b.add_atom(pattern(16, 10)));
    const u32 z = b.zero(16);
    const u32 root = b.xor_node(atom, z);
    Ir ir = b.finish(root);
    CanonReport report;
    auto out = canon(ir, report);
    ASSERT_TRUE(out.ok());
    ASSERT_EQ(1u, out.value().nodes.size());
    EXPECT_EQ(Kind::Atom, out.value().nodes[0].kind);
    EXPECT_GE(report.rule_fires[7], 1u);  // rule 8
}

TEST(C04Canon, XorAtomLeafSortedOnCanonicalKey) {
    Builder b;
    const u32 atom = b.atom_node(b.add_atom(pattern(16, 11)));
    const u32 z = b.zero(16);
    // Force an order that needs a swap: operands are emitted in input order,
    // canon orders by canonical_key ascending.
    const u32 root = b.xor_node(atom, z);  // Atom key vs Zero key ordering is fixed by the encoding
    Ir ir = b.finish(root);
    auto out = canon(ir);
    ASSERT_TRUE(out.ok());
    // Zero operand folded above, so this case folds instead of ordering.
    ASSERT_EQ(1u, out.value().nodes.size());
    EXPECT_EQ(Kind::Atom, out.value().nodes[0].kind);
}

TEST(C04Canon, XorOperandOrderMatchesCanonicalKey) {
    // Lfsr vs Atom: whatever the input order, the output must be key-ascending.
    Builder b1;
    const u32 atom1 = b1.atom_node(b1.add_atom(pattern(16, 12)));
    const u32 lfsr1 = b1.lfsr(0x80200003, 1, 16);
    Ir x = b1.finish(b1.xor_node(atom1, lfsr1));
    Builder b2;
    const u32 lfsr2 = b2.lfsr(0x80200003, 1, 16);
    const u32 atom2 = b2.atom_node(b2.add_atom(pattern(16, 12)));
    Ir y = b2.finish(b2.xor_node(lfsr2, atom2));
    auto ox = canon(x);
    auto oy = canon(y);
    ASSERT_TRUE(ox.ok());
    ASSERT_TRUE(oy.ok());
    ASSERT_EQ(2u, ox.value().nodes.back().args.size());
    const u32 xa = ox.value().nodes.back().args[0];
    const u32 xb = ox.value().nodes.back().args[1];
    EXPECT_LE(canonical_key(ox.value(), xa), canonical_key(ox.value(), xb));
    EXPECT_TRUE(ir_equal(ox.value(), oy.value()));  // construction order independent
}

TEST(C04Canon, InterleaveSingleChildFolds) {
    Builder b;
    const u32 atom = b.atom_node(b.add_atom(pattern(8, 13)));
    const u32 root = b.interleave({atom}, 1);
    Ir ir = b.finish(root);
    CanonReport report;
    auto out = canon(ir, report);
    ASSERT_TRUE(out.ok());
    ASSERT_EQ(1u, out.value().nodes.size());
    EXPECT_EQ(Kind::Atom, out.value().nodes[0].kind);
    EXPECT_GE(report.rule_fires[8], 1u);  // rule 9
}

TEST(C04Canon, InterleaveOrderIsNeverSorted) {
    Builder b;
    const u32 a1 = b.atom_node(b.add_atom(pattern(4, 21)));
    const u32 a2 = b.atom_node(b.add_atom(pattern(4, 22)));
    const u32 root = b.interleave({a1, a2}, 1);
    Ir ir = b.finish(root);
    auto out = canon(ir);
    ASSERT_TRUE(out.ok());
    ASSERT_EQ(2u, out.value().nodes.back().args.size());
    const u32 c0 = out.value().nodes.back().args[0];
    const u32 c1 = out.value().nodes.back().args[1];
    EXPECT_EQ(out.value().nodes[c0].kind, Kind::Atom);
    EXPECT_EQ(out.value().nodes[c1].kind, Kind::Atom);
    // Child order is semantic: payload order must match the input order.
    EXPECT_EQ(denote(ir), denote(out.value()));
}

TEST(C04Canon, AffineStepZeroStartZeroFoldsToZero) {
    Builder b;
    const u32 root = b.affine(0x00, 0, 10);
    Ir ir = b.finish(root);
    CanonReport report;
    auto out = canon(ir, report);
    ASSERT_TRUE(out.ok());
    ASSERT_EQ(1u, out.value().nodes.size());
    EXPECT_EQ(Kind::Zero, out.value().nodes[0].kind);
    EXPECT_EQ(10u, out.value().nodes[0].a.to_u64_checked().value());
    EXPECT_GE(report.rule_fires[9], 1u);  // rule 10
}

TEST(C04Canon, AffineStepZeroNonZeroStartFoldsToRepeatAtom) {
    Builder b;
    const u32 root = b.affine(0x07, 0, 5);
    Ir ir = b.finish(root);
    CanonReport report;
    auto out = canon(ir, report);
    ASSERT_TRUE(out.ok());
    ASSERT_EQ(Kind::Repeat, out.value().nodes.back().kind);
    EXPECT_GE(report.rule_fires[9], 1u);  // rule 10
    EXPECT_EQ(denote(ir), denote(out.value()));
}

TEST(C04Canon, RepeatOfZeroFoldsToZero) {
    Builder b;
    const u32 z = b.zero(2);
    const u32 root = b.repeat(z, 3, 1);  // ℓ = 2*3 + 1 = 7 zeros
    Ir ir = b.finish(root);
    CanonReport report;
    auto out = canon(ir, report);
    ASSERT_TRUE(out.ok());
    ASSERT_EQ(1u, out.value().nodes.size());
    EXPECT_EQ(Kind::Zero, out.value().nodes[0].kind);
    EXPECT_EQ(7u, out.value().nodes[0].a.to_u64_checked().value());
    EXPECT_GE(report.rule_fires[10], 1u);  // rule 11
}

TEST(C04Canon, SliceOfZeroFoldsToZero) {
    Builder b;
    const u32 z = b.zero(9);
    const u32 root = b.slice(z, 2, 4);
    Ir ir = b.finish(root);
    CanonReport report;
    auto out = canon(ir, report);
    ASSERT_TRUE(out.ok());
    ASSERT_EQ(1u, out.value().nodes.size());
    EXPECT_EQ(Kind::Zero, out.value().nodes[0].kind);
    EXPECT_EQ(4u, out.value().nodes[0].a.to_u64_checked().value());
    EXPECT_GE(report.rule_fires[10], 1u);  // rule 11
}

TEST(C04Canon, StructurallyIdenticalSubtermsShareOneNode) {
    Builder b;
    const u32 atom1 = b.atom_node(b.add_atom(pattern(4, 211)));
    const u32 atom2 = b.atom_node(b.add_atom(pattern(4, 211)));
    const u32 first = b.xor_node(b.lfsr(0x80200003, 1, 4), atom1);
    const u32 second = b.xor_node(b.lfsr(0x80200003, 1, 4), atom2);
    const u32 root = b.concat({first, second});
    Ir ir = b.finish(root);
    EXPECT_FALSE(is_canonical(ir));
    CanonReport report;
    auto out = canon(ir, report);
    ASSERT_TRUE(out.ok());
    // Concat(x, x) with shared x: nodes = x's nodes + concat = 4
    ASSERT_EQ(4u, out.value().nodes.size());
    const u32 c0 = out.value().nodes.back().args[0];
    const u32 c1 = out.value().nodes.back().args[1];
    EXPECT_EQ(c0, c1);
    EXPECT_GE(report.rule_fires[11], 1u);  // rule 12 (hash-cons hit)
    EXPECT_TRUE(is_canonical(out.value()));
}

TEST(C04Canon, UnusedRecordsArePrunedAndIdsReassigned) {
    Builder b;
    const u32 z = b.zero(5);    // id 0
    const u32 atom = b.atom_node(b.add_atom(pattern(3, 31)));  // id 1
    const u32 root = b.concat({atom, z});  // id 2
    Ir ir = b.finish(root);
    // Visit order is atom (id 1) then zero (id 0): emitted ids must be
    // reassigned so the first-visited child gets 0.
    auto out = canon(ir);
    ASSERT_TRUE(out.ok());
    ASSERT_EQ(3u, out.value().nodes.size());
    EXPECT_EQ(Kind::Atom, out.value().nodes[0].kind);
    EXPECT_EQ(Kind::Zero, out.value().nodes[1].kind);
    EXPECT_EQ(Kind::Concat, out.value().nodes[2].kind);
    EXPECT_EQ(2u, out.value().root);
    EXPECT_TRUE(is_canonical(out.value()));
}

TEST(C04Canon, CanonRequiresWellFormedInput) {
    Builder b;
    const u32 atom = b.atom_node(b.add_atom(pattern(4, 41)));
    Node& n = b.node(atom);  // corrupt a stored length
    n.length = BigInt(99);
    Ir ir = b.finish(atom);
    auto out = canon(ir);
    EXPECT_FALSE(out.ok());
    EXPECT_EQ(Code::Invalid, out.code());
}

TEST(C04Canon, RewriteBudgetExhaustionReturnsLimit) {
    Builder b;
    const u32 root = b.concat({b.zero(2), b.zero(3), b.zero(4)});  // needs 2 rule-4 fires
    Ir ir = b.finish(root);
    CanonReport report;
    auto out = canon_with_budget(ir, 0, &report);
    EXPECT_FALSE(out.ok());
    EXPECT_EQ(Code::Limit, out.code());
    EXPECT_TRUE(report.budget_exhausted);
    auto out2 = canon_with_budget(ir, 64ull * (static_cast<u64>(ir.nodes.size()) + 1ull), nullptr);
    ASSERT_TRUE(out2.ok());
    EXPECT_TRUE(is_canonical(out2.value()));
}

TEST(C04Canon, BudgetMatchesNodeCount) {
    Builder b;
    const u32 root = b.concat({b.zero(2), b.zero(3), b.zero(4)});
    Ir ir = b.finish(root);
    CanonReport report;
    auto out = canon(ir, report);
    ASSERT_TRUE(out.ok());
    EXPECT_LE(report.rewrites, 64ull * (static_cast<u64>(ir.nodes.size()) + 1ull));
}

TEST(C04Canon, XorKeyOrderingAcceptsDuplicates) {
    // Critical pair sanity: canon(canon(t)) == canon(t) for xor-heavy terms.
    Builder b;
    const u32 atom = b.atom_node(b.add_atom(pattern(8, 51)));
    const u32 l1 = b.lfsr(0x80200003, 1, 8);
    const u32 x1 = b.xor_node(atom, l1);
    const u32 x2 = b.xor_node(l1, atom);  // same subtree, reversed input order
    const u32 root = b.concat({x1, x2});
    Ir ir = b.finish(root);
    auto once = canon(ir);
    ASSERT_TRUE(once.ok());
    auto twice = canon(once.value());
    ASSERT_TRUE(twice.ok());
    EXPECT_TRUE(ir_equal(once.value(), twice.value()));
}

TEST(C04Canon, IdempotenceOnC03StyleCorpus) {
    auto run = [](Builder& b, u32 root) {
        Ir ir = b.finish(root);
        auto once = canon(ir);
        ASSERT_TRUE(once.ok());
        auto twice = canon(once.value());
        ASSERT_TRUE(twice.ok());
        EXPECT_TRUE(ir_equal(once.value(), twice.value()));
        EXPECT_TRUE(is_canonical(once.value()));
        EXPECT_EQ(denote(ir), denote(once.value()));
    };
    {
        Builder b;
        const u32 atom = b.atom_node(b.add_atom(pattern(16, 61)));
        const u32 inner = b.repeat(atom, 3, 2);
        const u32 root = b.xor_node(inner, b.zero(50));
        run(b, root);
    }
    {
        Builder b;
        const u32 atom = b.atom_node(b.add_atom(pattern(32, 62)));
        const u32 morph = b.morph(atom, 9 /* REVERSE_BITS */, 0);
        const u32 root = b.slice(morph, 1, 20);
        run(b, root);
    }
    {
        Builder b;
        const u32 root = b.interleave(
            {b.atom_node(b.add_atom(pattern(4, 63))),
             b.atom_node(b.add_atom(pattern(4, 64)))},
            2);
        run(b, root);
    }
    {
        Builder b;
        const u32 atom = b.atom_node(b.add_atom(pattern(8, 65)));
        const u32 rep = b.repeat(atom, 2, 3);
        const u32 morph = b.morph(rep, 2 /* INVERT8 */, 0);
        const u32 root = b.concat({morph, b.zero(7)});
        run(b, root);
    }
}

TEST(C04Canon, CanonicalKeyIsIdIndependentAndTotal) {
    Builder b;
    const u32 a = b.atom_node(b.add_atom(pattern(12, 71)));
    const u32 lfsr = b.lfsr(0x80200003, 1, 12);
    const u32 x = b.xor_node(a, lfsr);
    const u32 c1 = b.slice(x, 0, 12);
    const u32 root = b.concat({c1, b.zero(3)});
    Ir ir = b.finish(root);
    auto out = canon(ir);
    ASSERT_TRUE(out.ok());
    // Every subtree of a canonical term must equal its own reconstruction key.
    for (u32 i = 0; i < out.value().nodes.size(); ++i) {
        EXPECT_FALSE(canonical_key(out.value(), i).empty()) << "node " << i;
    }
    EXPECT_EQ("", canonical_key(out.value(), static_cast<u32>(out.value().nodes.size())));
}

TEST(C04Canon, CanonicalKeysDifferForDifferentSubterms) {
    Builder b;
    const u32 atom = b.atom_node(b.add_atom(pattern(8, 81)));
    const u32 z3 = b.zero(3);
    const u32 z5 = b.zero(5);
    const u32 root = b.concat({atom, z3, z5});
    Ir ir = b.finish(root);
    const std::string k_zero3 = canonical_key(ir, 1);
    const std::string k_zero5 = canonical_key(ir, 2);
    EXPECT_NE(k_zero3, k_zero5);
    EXPECT_NE(k_zero3, canonical_key(ir, 0));
}

TEST(C04Canon, CheckCanonicalReportsFirstFailureInRuleOrder) {
    Builder b;
    // Concat(Concat(Zero(1), Zero(2)), Empty) has both a C1 and a C2 redex;
    // C1 must win (lower rule number).
    const u32 inner = b.concat({b.zero(1), b.zero(2)});
    const u32 root = b.concat({inner, b.empty()});
    Ir ir = b.finish(root);
    const WfReport report = check_canonical(ir);
    EXPECT_EQ(Code::Invalid, report.code);
    EXPECT_STREQ(kCanon1, report.constraint);
}

TEST(C04Canon, CheckCanonicalOnNonWellFormedInput) {
    Builder b;
    const u32 atom = b.atom_node(b.add_atom(pattern(4, 91)));
    b.node(atom).length = BigInt(7);  // corrupt stored length
    Ir ir = b.finish(atom);
    const WfReport report = check_canonical(ir);
    EXPECT_EQ(Code::Invalid, report.code);
    EXPECT_NE(nullptr, std::strstr(report.constraint, "W"));
}

TEST(C04Canon, AtomDigestsMatchPayloadAfterMergeAndSplit) {
    // Merged atoms carry the digest of the merged payload.
    Builder b;
    const u32 a1 = b.atom_node(b.add_atom(std::vector<u8>(500000, 0x33)));
    const u32 a2 = b.atom_node(b.add_atom(std::vector<u8>(500000, 0x44)));
    const u32 root = b.concat({a1, a2});
    Ir ir = b.finish(root);
    auto out = canon(ir);
    ASSERT_TRUE(out.ok());
    ASSERT_EQ(1u, out.value().atoms.size());
    EXPECT_TRUE(verify_atom_digests(out.value()).ok());
}

TEST(C04Canon, DeterminismRepeatedRuns) {
    Builder b;
    const u32 atom = b.atom_node(b.add_atom(pattern(16, 101)));
    const u32 root = b.concat({b.repeat(atom, 2, 4), b.zero(3)});
    Ir ir = b.finish(root);
    auto first = canon(ir);
    auto second = canon(ir);
    auto third = canon(ir);
    ASSERT_TRUE(first.ok());
    ASSERT_TRUE(second.ok());
    ASSERT_TRUE(third.ok());
    EXPECT_TRUE(ir_equal(first.value(), second.value()));
    EXPECT_TRUE(ir_equal(second.value(), third.value()));
    EXPECT_EQ(canonical_key(first.value(), first.value().root),
              canonical_key(third.value(), third.value().root));
}

}  // namespace
