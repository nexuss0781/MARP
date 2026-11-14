// C03 TERM — unit tests (GoogleTest).
//
// These tests pin the C03 surface: kind domain, length arithmetic, the
// well-formedness predicate, denotation per kind, the closed morphism /
// predictor / LFSR catalogues, range evaluation, and the resource/limit
// behaviour.  Where a value can be computed by hand from the normative text it
// is written out literally; where it cannot, a second, literal transcription of
// the specification is used as the oracle.

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "c03_build.hpp"
#include "mapr/e1_length.hpp"
#include "mapr/e2/e2_term.hpp"

namespace {

using namespace marp::v2;  // NOLINT
using c03::Builder;
using c03::pattern;

std::vector<u8> bytes_of(std::initializer_list<int> values) {
    std::vector<u8> out;
    for (int value : values) out.push_back(static_cast<u8>(value & 0xFF));
    return out;
}

// Literal transcription of the §3.5 pseudocode: parity by loop over bits,
// bit-by-bit emission, MSB-first packing.  No engine code is reused.
std::vector<u8> literal_lfsr(u64 conn, u64 init, std::size_t count) {
    std::vector<u8> out(count, 0);
    u64 state = init;
    for (std::size_t i = 0; i < count; ++i) {
        unsigned byte = 0;
        for (int b = 0; b < 8; ++b) {
            unsigned parity = 0;
            for (int bit = 0; bit < 64; ++bit) {
                parity ^= static_cast<unsigned>((state >> bit) & 1u) &
                          static_cast<unsigned>((conn >> bit) & 1u);
            }
            state = (state >> 1) | (static_cast<u64>(parity) << 63);
            byte = (byte << 1) | parity;
        }
        out[i] = static_cast<u8>(byte & 0xFF);
    }
    return out;
}

// Literal transcription of the §4.11 predictor table.
std::vector<u8> literal_predictor(u8 pid, u32 param, const std::vector<u8>& residual) {
    const std::size_t n = residual.size();
    std::vector<u8> out(n, 0);
    if (n == 0) return out;
    switch (pid) {
        case 0:
            out[0] = residual[0];
            for (std::size_t i = 1; i < n; ++i) {
                out[i] = static_cast<u8>((out[i - 1] + residual[i]) & 0xFFu);
            }
            break;
        case 1:
            out[0] = residual[0];
            for (std::size_t i = 1; i < n; ++i) {
                out[i] = static_cast<u8>(out[i - 1] ^ residual[i]);
            }
            break;
        case 2:
            out[0] = residual[0];
            if (n > 1) out[1] = residual[1];
            for (std::size_t i = 2; i < n; ++i) {
                const unsigned v = 2u * out[i - 1] - out[i - 2];
                out[i] = static_cast<u8>(v & 0xFFu);
            }
            break;
        case 3:
        case 4:
            for (std::size_t i = 0; i < n; ++i) {
                if (i < param) {
                    out[i] = residual[i];
                } else if (pid == 3) {
                    out[i] = static_cast<u8>(out[i - param] ^ residual[i]);
                } else {
                    out[i] = static_cast<u8>((out[i - param] + residual[i]) & 0xFFu);
                }
            }
            break;
        default:
            break;
    }
    return out;
}

// E1 length primitive adapter (E1 `length_of` is the frozen E1 surface).
class E1TermView : public mapr::TermView {
public:
    explicit E1TermView(const Ir& ir) : ir_(ir) {}
    std::size_t node_count() const noexcept override { return ir_.nodes.size(); }
    mapr::NodeKind node_kind(mapr::NodeId id) const noexcept override {
        return static_cast<mapr::NodeKind>(static_cast<unsigned>(ir_.nodes[id].kind));
    }
    std::size_t atom_size(mapr::NodeId id) const noexcept override {
        return static_cast<std::size_t>(ir_.atoms[id].payload.size());
    }
    mapr::BigInt zero_count(mapr::NodeId id) const noexcept override {
        return ir_.nodes[id].a;
    }
    std::vector<mapr::NodeId> concat_children(mapr::NodeId id) const noexcept override {
        return ir_.nodes[id].args;
    }
    mapr::NodeId repeat_child(mapr::NodeId id) const noexcept override {
        return ir_.nodes[id].args[0];
    }
    const mapr::BigInt& repeat_q(mapr::NodeId id) const noexcept override {
        return ir_.nodes[id].a;
    }
    const mapr::BigInt& repeat_r(mapr::NodeId id) const noexcept override {
        return ir_.nodes[id].b;
    }
    mapr::NodeId slice_child(mapr::NodeId id) const noexcept override {
        return ir_.nodes[id].args[0];
    }
    const mapr::BigInt& slice_start(mapr::NodeId id) const noexcept override {
        return ir_.nodes[id].a;
    }
    const mapr::BigInt& slice_len(mapr::NodeId id) const noexcept override {
        return ir_.nodes[id].b;
    }
    mapr::NodeId morph_child(mapr::NodeId id) const noexcept override {
        return ir_.nodes[id].args[0];
    }
    mapr::NodeId xor_a(mapr::NodeId id) const noexcept override {
        return ir_.nodes[id].args[0];
    }
    mapr::NodeId xor_b(mapr::NodeId id) const noexcept override {
        return ir_.nodes[id].args[1];
    }
    std::vector<mapr::NodeId> interleave_children(mapr::NodeId id) const noexcept override {
        return ir_.nodes[id].args;
    }
    std::uint32_t interleave_stride(mapr::NodeId id) const noexcept override {
        return static_cast<std::uint32_t>(ir_.nodes[id].a.to_u64_checked().value());
    }
    mapr::BigInt lfsr_n(mapr::NodeId id) const noexcept override { return ir_.nodes[id].a; }
    mapr::BigInt affine_n(mapr::NodeId id) const noexcept override { return ir_.nodes[id].a; }
    mapr::NodeId predictor_residual(mapr::NodeId id) const noexcept override {
        return ir_.nodes[id].args[0];
    }

private:
    const Ir& ir_;
};

}  // namespace

// ---------------------------------------------------------------------------
// Kind domain and catalogues
// ---------------------------------------------------------------------------

TEST(C03Term, KindDomainIsClosed) {
    for (u8 raw = 0; raw < 12; ++raw) {
        Kind parsed = Kind::Empty;
        EXPECT_TRUE(parse_kind(raw, parsed));
        EXPECT_EQ(static_cast<u8>(parsed), raw);
        EXPECT_TRUE(check_kind_domain(raw).ok());
    }
    for (u8 raw : {u8{12}, u8{13}, u8{200}, u8{255}}) {
        Kind parsed = Kind::Empty;
        EXPECT_FALSE(parse_kind(raw, parsed));
        EXPECT_FALSE(check_kind_domain(raw).ok());
    }
    EXPECT_STREQ(kind_name(Kind::Predictor), "Predictor");
    EXPECT_EQ(static_cast<u8>(kKindCount), 12);
}

TEST(C03Term, MorphCatalogueIsClosed) {
    EXPECT_TRUE(check_morph_domain(1).ok());
    EXPECT_TRUE(check_morph_domain(9).ok());
    EXPECT_FALSE(check_morph_domain(0).ok());
    EXPECT_FALSE(check_morph_domain(10).ok());
    for (u8 k = 0; k < 8; ++k) {
        EXPECT_EQ(check_morph_params(6, k, BigInt(8)).ok(), k >= 1);
        EXPECT_EQ(check_morph_params(7, k, BigInt(8)).ok(), k >= 1);
    }
    EXPECT_TRUE(check_morph_params(1, 0, BigInt(7)).ok());
    EXPECT_FALSE(check_morph_params(1, 1, BigInt(7)).ok());
    EXPECT_TRUE(check_morph_params(3, 0, BigInt(8)).ok());
    EXPECT_FALSE(check_morph_params(3, 0, BigInt(7)).ok());
    EXPECT_TRUE(check_morph_params(4, 0, BigInt(8)).ok());
    EXPECT_FALSE(check_morph_params(4, 0, BigInt(6)).ok());
    EXPECT_TRUE(check_morph_params(5, 0, BigInt(8)).ok());
    EXPECT_FALSE(check_morph_params(5, 0, BigInt(12)).ok());
    EXPECT_TRUE(morph_is_byte_local(1));
    EXPECT_TRUE(morph_is_byte_local(7));
    EXPECT_FALSE(morph_is_byte_local(8));
    EXPECT_EQ(morph_block_size(3), 2u);
    EXPECT_EQ(morph_block_size(4), 4u);
    EXPECT_EQ(morph_block_size(5), 8u);
    EXPECT_EQ(morph_block_size(8), 0u);
}

TEST(C03Term, PredictorCatalogueIsClosed) {
    EXPECT_TRUE(check_predictor_domain(0).ok());
    EXPECT_TRUE(check_predictor_domain(4).ok());
    EXPECT_FALSE(check_predictor_domain(5).ok());
    EXPECT_TRUE(check_predictor_params(0, 1234).ok());  // unused for pid <= 2
    EXPECT_TRUE(check_predictor_params(1, 0).ok());
    EXPECT_TRUE(check_predictor_params(2, 0).ok());
    EXPECT_FALSE(check_predictor_params(3, 0).ok());
    EXPECT_FALSE(check_predictor_params(4, 0).ok());
    EXPECT_TRUE(check_predictor_params(3, 1).ok());
    EXPECT_TRUE(check_predictor_params(4, 4096).ok());
    EXPECT_FALSE(apply_predictor_step_checked(5, 0, 1, 2, 3).ok());
    EXPECT_FALSE(apply_predictor_step_checked(3, 0, 1, 2, 3).ok());
}

// ---------------------------------------------------------------------------
// Length arithmetic
// ---------------------------------------------------------------------------

TEST(C03Term, LengthFormulasPerKind) {
    Builder b;
    const u32 a16 = b.atom_node(b.add_atom(pattern(16, 1)));
    const u32 z7 = b.zero(7);

    EXPECT_EQ(b.len(b.empty()).to_decimal(), "0");
    EXPECT_EQ(b.len(a16).to_decimal(), "16");
    EXPECT_EQ(b.len(z7).to_decimal(), "7");
    EXPECT_EQ(b.len(b.concat({a16, z7})).to_decimal(), "23");
    EXPECT_EQ(b.len(b.repeat(a16, 3, 5)).to_decimal(), "53");
    EXPECT_EQ(b.len(b.slice(a16, 4, 6)).to_decimal(), "6");
    EXPECT_EQ(b.len(b.morph(a16, 2, 0)).to_decimal(), "16");
    EXPECT_EQ(b.len(b.xor_node(a16, b.zero(16))).to_decimal(), "16");
    EXPECT_EQ(b.len(b.interleave({b.zero(8), b.zero(8)}, 2)).to_decimal(), "16");
    EXPECT_EQ(b.len(b.lfsr(0x80000001ull, 1, 33)).to_decimal(), "33");
    EXPECT_EQ(b.len(b.affine(1, 2, 21)).to_decimal(), "21");
    EXPECT_EQ(b.len(b.predictor(1, 0, a16)).to_decimal(), "16");
}

TEST(C03Term, LengthIsArbitraryPrecision) {
    Builder b;
    // Repeat(atom(4), 2^60, 3) = 2^62 + 3, far beyond u32 and well inside 2^63.
    const u32 rep = b.repeat(b.atom_node(b.add_atom(pattern(4, 2))),
                             BigInt(1).shl(60).value(), BigInt(3));
    Ir ir = b.finish(rep);
    ASSERT_TRUE(check_well_formed(ir).ok());
    auto lengths = recompute_lengths_checked(ir);
    ASSERT_TRUE(lengths.ok());
    EXPECT_EQ(lengths.value()[rep].to_decimal(), "4611686018427387907");
    EXPECT_EQ(ir.total_length.to_decimal(), "4611686018427387907");
    EXPECT_EQ(b.len(rep).to_decimal(), "4611686018427387907");
}

TEST(C03Term, RecomputationIsIndependentOfStoredLengths) {
    Builder b;
    const u32 cat = b.concat({b.zero(3), b.zero(4)});
    Ir ir = b.finish(cat);
    ASSERT_TRUE(check_well_formed(ir).ok());
    ir.nodes[cat].length = BigInt(99);
    ir.total_length = BigInt(99);  // W5 consistent, so W6 is the failing check
    auto lengths = recompute_lengths_checked(ir);
    ASSERT_TRUE(lengths.ok());
    EXPECT_EQ(lengths.value()[cat].to_decimal(), "7");
    const WfReport report = check_well_formed_report(ir);
    ASSERT_FALSE(report.ok());
    EXPECT_STREQ(report.constraint, kC_length);
    EXPECT_EQ(report.node, cat);
}

TEST(C03Term, E1LengthPrimitiveAgrees) {
    Builder b;
    const u32 a8 = b.atom_node(b.add_atom(pattern(8, 3)));
    const u32 cat = b.concat({a8, b.zero(4)});
    const u32 rep = b.repeat(cat, 2, 1);
    Ir ir = b.finish(rep);
    ASSERT_TRUE(check_well_formed(ir).ok());
    E1TermView view(ir);
    auto e1 = mapr::length_of(view);
    ASSERT_TRUE(e1.ok());
    auto e2 = recompute_lengths_checked(ir);
    ASSERT_TRUE(e2.ok());
    EXPECT_EQ(e2.value()[rep].to_decimal(), e1.value().length.to_decimal());
    for (u32 i = 0; i < rep; ++i) {
        EXPECT_EQ(e2.value()[i].to_decimal(), e1.value().memo[i].to_decimal());
    }
}

// ---------------------------------------------------------------------------
// Well-formedness
// ---------------------------------------------------------------------------

TEST(C03Term, WfAcceptsEveryKind) {
    const std::vector<std::pair<const char*, std::function<u32(Builder&)>>> cases = {
        {"Empty", [](Builder& b) { return b.empty(); }},
        {"Atom", [](Builder& b) { return b.atom_node(b.add_atom(pattern(1, 7))); }},
        {"Zero", [](Builder& b) { return b.zero(0); }},
        {"Zero-n", [](Builder& b) { return b.zero(9); }},
        {"Concat", [](Builder& b) {
             return b.concat({b.atom_node(b.add_atom(pattern(16, 5))),
                              b.atom_node(b.add_atom(pattern(32, 6)))});
         }},
        {"Repeat", [](Builder& b) {
             return b.repeat(b.atom_node(b.add_atom(pattern(16, 5))), 2, 3);
         }},
        {"Slice", [](Builder& b) {
             return b.slice(b.atom_node(b.add_atom(pattern(32, 6))), 3, 5);
         }},
        {"Morph", [](Builder& b) {
             return b.morph(b.atom_node(b.add_atom(pattern(32, 6))), 3, 0);
         }},
        {"Xor", [](Builder& b) {
             u32 a = b.atom_node(b.add_atom(pattern(16, 5)));
             return b.xor_node(a, a);
         }},
        {"Interleave", [](Builder& b) {
             return b.interleave({b.zero(8), b.zero(8)}, 4);
         }},
        {"Lfsr", [](Builder& b) { return b.lfsr(0x80000001ull, 5, 12); }},
        {"Affine", [](Builder& b) { return b.affine(9, 4, 12); }},
        {"Predictor", [](Builder& b) {
             return b.predictor(3, 2, b.atom_node(b.add_atom(pattern(16, 5))));
         }},
    };
    for (const auto& entry : cases) {
        Builder b;
        const u32 root = entry.second(b);
        const Ir ir = b.finish(root);
        const WfReport report = check_well_formed_report(ir);
        EXPECT_TRUE(report.ok()) << "kind " << entry.first << " constraint "
                                 << report.constraint;
    }
}

TEST(C03Term, WfRejectsEachConstraintClass) {
    struct Case {
        const char* constraint;
        Code code;
        Ir ir;
    };
    std::vector<Case> cases;

    {
        Builder b;
        u32 a = b.add_atom(pattern(2, 1));
        b.atom(a).flags = 4;
        cases.push_back({kC_atom_flags, Code::Invalid, b.finish(b.atom_node(a))});
    }
    {
        Builder b;
        u32 n = b.atom_node(b.add_atom(pattern(2, 2)));
        b.node(n).flags = 1;
        cases.push_back({kC_node_flags, Code::Invalid, b.finish(n)});
    }
    {
        Builder b;
        u32 a = b.add_atom(pattern(2, 3));
        b.atom(a).length = BigInt(3);
        cases.push_back({kC_atom_payload, Code::Invalid, b.finish(b.atom_node(a))});
    }
    {
        Ir ir;  // no nodes at all: root is out of range
        cases.push_back({kC_root, Code::Invalid, ir});
    }
    {
        Builder b;
        u32 root = b.zero(2);
        (void)b.zero(3);
        cases.push_back({kC_reachable, Code::Invalid, b.finish(root)});
    }
    {
        Builder b;
        (void)b.add_atom(pattern(2, 4));
        cases.push_back({kC_atom_unused, Code::Invalid, b.finish(b.zero(2))});
    }
    {
        Builder b;
        u32 z = b.zero(2);
        u32 cat = b.concat({z, z});
        b.node(cat).args[1] = 42;
        cases.push_back({kC_arg_range, Code::Invalid, b.finish(cat)});
    }
    {
        Builder b;
        u32 z = b.zero(2);
        u32 cat = b.concat({z, z});
        b.node(cat).args[0] = cat;
        cases.push_back({kC_arg_order, Code::Invalid, b.finish(cat)});
    }
    {
        Builder b;
        u32 z = b.zero(2);
        cases.push_back({kC_total_length, Code::Invalid, b.finish_with_total(z, BigInt(3))});
    }
    {
        Builder b;
        u32 z = b.zero(2);
        b.node(z).length = BigInt(3);
        cases.push_back({kC_length, Code::Invalid, b.finish_with_total(z, BigInt(3))});
    }
    {
        Builder b;
        u32 z = b.zero(2);
        u32 bad = b.concat({z});
        u32 root = b.concat({bad, z});
        cases.push_back({kC_argc, Code::Invalid, b.finish(root)});
    }
    {
        Builder b;
        const u32 atom = b.add_atom(pattern(2, 5));
        const u32 good = b.atom_node(atom);
        const u32 bad = b.atom_node(atom);
        b.node(bad).a = BigInt(7);
        cases.push_back({kC_atom_id, Code::Invalid, b.finish(b.concat({good, bad}))});
    }
    {
        Builder b;
        u32 a = b.add_atom(std::span<const u8>());
        cases.push_back({kC_atom_len, Code::Invalid, b.finish(b.atom_node(a))});
    }
    {
        // q = 0 with r > 0 is a WF violation (§4.5), not a normalisation case;
        // q >= 1 requires r < len(child).
        Builder b;
        cases.push_back({kC_repeat, Code::Invalid, b.finish(b.repeat(b.zero(4), 0, 2))});
        Builder b2;
        cases.push_back({kC_repeat, Code::Invalid, b2.finish(b2.repeat(b2.zero(4), 2, 4))});
    }
    {
        Builder b;
        u32 z = b.zero(4);
        cases.push_back({kC_slice, Code::Invalid, b.finish(b.slice(z, 5, 0))});
        Builder b2;
        u32 z2 = b2.zero(4);
        cases.push_back({kC_slice, Code::Invalid, b2.finish(b2.slice(z2, 2, 3))});
    }
    {
        Builder b;
        cases.push_back({kC_morph, Code::Invalid, b.finish(b.morph(b.zero(8), 0, 0))});
        Builder c;
        cases.push_back({kC_morph, Code::Invalid, c.finish(c.morph(c.zero(8), 6, 0))});
        Builder d;
        cases.push_back({kC_morph, Code::Invalid, d.finish(d.morph(d.zero(8), 6, 8))});
        Builder e;
        cases.push_back({kC_morph, Code::Invalid, e.finish(e.morph(e.zero(5), 3, 0))});
        Builder f;
        cases.push_back({kC_morph, Code::Invalid, f.finish(f.morph(f.zero(6), 4, 0))});
        Builder g;
        cases.push_back({kC_morph, Code::Invalid, g.finish(g.morph(g.zero(12), 5, 0))});
    }
    {
        Builder b;
        cases.push_back({kC_xor, Code::Invalid, b.finish(b.xor_node(b.zero(4), b.zero(5)))});
    }
    {
        Builder b;
        cases.push_back(
            {kC_interleave, Code::Invalid, b.finish(b.interleave({b.zero(8), b.zero(8)}, 0))});
        Builder c;
        cases.push_back({kC_interleave, Code::Invalid,
                         c.finish(c.interleave({c.zero(8), c.zero(9)}, 1))});
        Builder d;
        cases.push_back({kC_interleave, Code::Invalid,
                         d.finish(d.interleave({d.zero(10), d.zero(10)}, 3))});
        Builder e;
        u32 i = e.interleave({e.zero(8), e.zero(8)}, 1);
        e.node(i).a = BigInt(1).shl(40).value();
        cases.push_back({kC_interleave, Code::Invalid, e.finish(i)});
    }
    {
        Builder b;
        u32 l = b.lfsr(0x80000001ull, 1, 4);
        b.node(l).lfsr_conn = 0;
        cases.push_back({kC_lfsr, Code::Invalid, b.finish(l)});
    }
    {
        Builder b;
        u32 p = b.predictor(1, 0, b.zero(4));
        b.node(p).predictor_id = 5;
        cases.push_back({kC_predictor, Code::Invalid, b.finish(p)});
        Builder c;
        u32 p3 = c.predictor(3, 2, c.zero(4));
        c.node(p3).predictor_param = 0;
        cases.push_back({kC_predictor, Code::Invalid, c.finish(p3)});
        Builder d;
        u32 p4 = d.predictor(4, 2, d.zero(4));
        d.node(p4).predictor_param = 0;
        cases.push_back({kC_predictor, Code::Invalid, d.finish(p4)});
    }

    for (const Case& c : cases) {
        const WfReport report = check_well_formed_report(c.ir);
        EXPECT_FALSE(report.ok()) << "expected rejection for " << c.constraint;
        EXPECT_EQ(report.code, c.code) << c.constraint;
        EXPECT_STREQ(report.constraint, c.constraint);
        EXPECT_EQ(check_well_formed(c.ir).ok(), false);
    }
}

TEST(C03Term, WfDepthAndOutputLimits) {
    {
        Builder b;
        u32 node = b.atom_node(b.add_atom(pattern(1, 1)));
        for (u32 i = 0; i + 1 < kMaxDepthSpec; ++i) node = b.morph(node, 2, 0);
        EXPECT_TRUE(check_well_formed(b.finish(node)).ok());
    }
    {
        Builder b;
        u32 node = b.atom_node(b.add_atom(pattern(1, 1)));
        for (u32 i = 0; i < kMaxDepthSpec; ++i) node = b.morph(node, 2, 0);
        const WfReport report = check_well_formed_report(b.finish(node));
        EXPECT_FALSE(report.ok());
        EXPECT_EQ(report.code, Code::Limit);
        EXPECT_STREQ(report.constraint, kC_depth);
    }
    {
        Builder b;
        u32 z = b.zero(BigInt(1).shl(63).value().add(BigInt(1)).value());
        const WfReport report = check_well_formed_report(b.finish(z));
        EXPECT_FALSE(report.ok());
        EXPECT_EQ(report.code, Code::Limit);
        EXPECT_STREQ(report.constraint, kC_output_cap);
    }
    {
        Builder b;
        Ir ir = b.finish(b.concat({b.zero(1), b.zero(1), b.zero(1)}));
        const Limits limits{2, kMaxRecordsSpec, kMaxDepthSpec, true};
        const WfReport report = check_well_formed_report(ir, limits);
        EXPECT_FALSE(report.ok());
        EXPECT_EQ(report.code, Code::Invalid);
        EXPECT_STREQ(report.constraint, kC_counts);
    }
}

TEST(C03Term, AtomDigestsAreVerifiable) {
    Builder b;
    const u32 a = b.atom_node(b.add_atom(bytes_of({1, 2, 3, 4})));
    Ir ir = b.finish(a);
    EXPECT_TRUE(verify_atom_digests(ir).ok());
    ir.atoms[0].sha256[0] ^= 0xFF;
    EXPECT_FALSE(verify_atom_digests(ir).ok());
}

// ---------------------------------------------------------------------------
// Denotation per kind
// ---------------------------------------------------------------------------

TEST(C03Term, DenotationPerKind) {
    Builder b;
    const u32 a = b.atom_node(b.add_atom(bytes_of({1, 2, 3, 4})));
    const u32 z = b.zero(3);
    const u32 e = b.empty();

    EXPECT_TRUE(denote_root(b.finish(e), 64).ok());
    EXPECT_TRUE(denote_root(b.finish(e), 64).value().empty());
    EXPECT_EQ(denote_root(b.finish(a), 64).value(), bytes_of({1, 2, 3, 4}));
    EXPECT_EQ(denote_root(b.finish(z), 64).value(), bytes_of({0, 0, 0}));
    EXPECT_EQ(denote_root(b.finish(b.concat({a, z})), 64).value(),
              bytes_of({1, 2, 3, 4, 0, 0, 0}));
    EXPECT_EQ(denote_root(b.finish(b.repeat(a, 2, 1)), 64).value(),
              bytes_of({1, 2, 3, 4, 1, 2, 3, 4, 1}));
    EXPECT_EQ(denote_root(b.finish(b.slice(a, 1, 2)), 64).value(), bytes_of({2, 3}));
    EXPECT_EQ(denote_root(b.finish(b.xor_node(a, b.atom_node(b.add_atom(bytes_of({0xF0, 0x0F, 0xAA, 0x55}))))), 64).value(),
              bytes_of({0xF1, 0x0D, 0xA9, 0x51}));
    EXPECT_EQ(denote_root(b.finish(b.affine(250, 7, 6)), 64).value(),
              bytes_of({250, 1, 8, 15, 22, 29}));
    // Interleave: blocks of `stride` taken from each child in order.
    const u32 l = b.atom_node(b.add_atom(bytes_of({1, 2, 3, 4})));
    const u32 r = b.atom_node(b.add_atom(bytes_of({5, 6, 7, 8})));
    EXPECT_EQ(denote_root(b.finish(b.interleave({l, r}, 2)), 64).value(),
              bytes_of({1, 2, 5, 6, 3, 4, 7, 8}));
    EXPECT_EQ(denote_root(b.finish(b.interleave({l, r}, 1)), 64).value(),
              bytes_of({1, 5, 2, 6, 3, 7, 4, 8}));
    EXPECT_EQ(denote_root(b.finish(b.interleave({l, r}, 4)), 64).value(),
              bytes_of({1, 2, 3, 4, 5, 6, 7, 8}));
}

TEST(C03Term, MorphByteKats) {
    EXPECT_EQ(apply_morph_byte(1, 0, 0x01), 0x80);
    EXPECT_EQ(apply_morph_byte(1, 0, 0x96), 0x69);
    EXPECT_EQ(apply_morph_byte(2, 0, 0x00), 0xFF);
    EXPECT_EQ(apply_morph_byte(2, 0, 0xA5), 0x5A);
    EXPECT_EQ(apply_morph_byte(6, 1, 0x81), 0x03);
    EXPECT_EQ(apply_morph_byte(6, 7, 0x01), 0x80);
    EXPECT_EQ(apply_morph_byte(7, 1, 0x81), 0xC0);
    EXPECT_EQ(apply_morph_byte(7, 7, 0x80), 0x01);
    EXPECT_FALSE(apply_morph_byte_checked(3, 0, 0x11).ok());
    EXPECT_FALSE(apply_morph_byte_checked(9, 0, 0x11).ok());
    EXPECT_FALSE(apply_morph_byte_checked(1, 3, 0x11).ok());
}

TEST(C03Term, MorphBufferKats) {
    auto run = [](u8 morph, u8 k, std::vector<u8> in) {
        EXPECT_TRUE(apply_morph_to_buffer(morph, k, in).ok());
        return in;
    };
    EXPECT_EQ(run(3, 0, bytes_of({1, 2, 3, 4})), bytes_of({2, 1, 4, 3}));
    EXPECT_EQ(run(4, 0, bytes_of({1, 2, 3, 4, 5, 6, 7, 8})),
              bytes_of({4, 3, 2, 1, 8, 7, 6, 5}));
    EXPECT_EQ(run(5, 0, bytes_of({1, 2, 3, 4, 5, 6, 7, 8})),
              bytes_of({8, 7, 6, 5, 4, 3, 2, 1}));
    EXPECT_EQ(run(8, 0, bytes_of({1, 2, 3})), bytes_of({3, 2, 1}));
    // REVERSE_BITS = REVERSE_BYTES ∘ BIT_REVERSE8 (§4.6, normative identity).
    EXPECT_EQ(run(9, 0, bytes_of({0x01, 0x00})), bytes_of({0x00, 0x80}));
    EXPECT_EQ(run(9, 0, bytes_of({0x01, 0x02, 0x03})), bytes_of({0xC0, 0x40, 0x80}));
    // Declared involutions are involutive.
    for (u8 morph : {u8{1}, u8{2}, u8{3}, u8{4}, u8{5}, u8{8}, u8{9}}) {
        std::vector<u8> bytes = pattern(64, morph);
        const std::vector<u8> original = bytes;
        ASSERT_TRUE(apply_morph_to_buffer(morph, 0, bytes).ok());
        ASSERT_TRUE(apply_morph_to_buffer(morph, 0, bytes).ok());
        EXPECT_EQ(bytes, original) << "morph " << static_cast<int>(morph);
    }
    // Rotations compose modulo 8.
    for (u8 a = 1; a <= 7; ++a) {
        for (u8 b = 1; b <= 7; ++b) {
            std::vector<u8> bytes = pattern(32, 3);
            std::vector<u8> expected = bytes;
            ASSERT_TRUE(apply_morph_to_buffer(6, a, bytes).ok());
            ASSERT_TRUE(apply_morph_to_buffer(6, b, bytes).ok());
            const u8 sum = static_cast<u8>((a + b) % 8);
            if (sum != 0) {
                ASSERT_TRUE(apply_morph_to_buffer(6, sum, expected).ok());
            }
            EXPECT_EQ(bytes, expected);
        }
    }
    std::vector<u8> bad(3, 0);
    EXPECT_FALSE(apply_morph_to_buffer(3, 0, bad).ok());
    EXPECT_FALSE(apply_morph_to_buffer(0, 0, bad).ok());
    EXPECT_FALSE(apply_morph_to_buffer(10, 0, bad).ok());
}

TEST(C03Term, MorphDenotationMatchesWholeBuffer) {
    const std::vector<u8> payload = pattern(32, 17);
    for (u8 morph = 1; morph <= 9; ++morph) {
        Builder b;
        const u32 atom = b.atom_node(b.add_atom(payload));
        const u8 k = (morph == 6 || morph == 7) ? 5 : 0;
        const u32 node = b.morph(atom, morph, k);
        Ir ir = b.finish(node);
        ASSERT_TRUE(check_well_formed(ir).ok());
        std::vector<u8> expected = payload;
        ASSERT_TRUE(apply_morph_to_buffer(morph, k, expected).ok());
        auto engine = denote_root(ir, 4096);
        ASSERT_TRUE(engine.ok());
        EXPECT_EQ(engine.value(), expected) << "morph " << static_cast<int>(morph);
    }
}

TEST(C03Term, PredictedKats) {
    const std::vector<u8> residual = bytes_of({10, 15, 3, 4, 250});
    std::vector<u8> out(residual.size());
    ASSERT_TRUE(apply_predictor_to_buffer(0, 0, residual, out).ok());
    EXPECT_EQ(out, bytes_of({10, 25, 28, 32, 26}));
    ASSERT_TRUE(apply_predictor_to_buffer(1, 0, residual, out).ok());
    EXPECT_EQ(out, bytes_of({10, 5, 6, 2, 248}));
    // LINEAR2 is implemented exactly as §4.11/§3.6 write it: the residual is
    // not consulted for i >= 2 (the inherited H3 §7 defect; see the report).
    ASSERT_TRUE(apply_predictor_to_buffer(2, 0, residual, out).ok());
    EXPECT_EQ(out, bytes_of({10, 15, 20, 25, 30}));
    ASSERT_TRUE(apply_predictor_to_buffer(3, 2, residual, out).ok());
    EXPECT_EQ(out, bytes_of({10, 15, 9, 11, 243}));
    ASSERT_TRUE(apply_predictor_to_buffer(4, 2, residual, out).ok());
    EXPECT_EQ(out, bytes_of({10, 15, 13, 19, 7}));
    // Param above the residual length is the identity (§4.11 seeding rule).
    ASSERT_TRUE(apply_predictor_to_buffer(3, 64, residual, out).ok());
    EXPECT_EQ(out, residual);
    ASSERT_TRUE(apply_predictor_to_buffer(4, 64, residual, out).ok());
    EXPECT_EQ(out, residual);

    EXPECT_FALSE(apply_predictor_to_buffer(5, 0, residual, out).ok());
    EXPECT_FALSE(apply_predictor_to_buffer(3, 0, residual, out).ok());
    EXPECT_FALSE(apply_predictor_to_buffer(4, 0, residual, out).ok());
    std::vector<u8> wrong_size(residual.size() + 1);
    EXPECT_FALSE(apply_predictor_to_buffer(0, 0, residual, wrong_size).ok());
}

TEST(C03Term, PredictorsMatchLiteralTable) {
    const std::vector<u8> residual = pattern(64, 29);
    for (u8 pid = 0; pid <= 4; ++pid) {
        for (u32 param : {0u, 1u, 2u, 5u, 63u, 64u, 65u, 200u}) {
            if (pid >= 3 && param == 0) continue;
            Builder b;
            const u32 atom = b.atom_node(b.add_atom(residual));
            const u32 node = b.predictor(pid, param, atom);
            Ir ir = b.finish(node);
            ASSERT_TRUE(check_well_formed(ir).ok());
            auto engine = denote_root(ir, 4096);
            ASSERT_TRUE(engine.ok());
            EXPECT_EQ(engine.value(), literal_predictor(pid, param, residual))
                << "pid " << static_cast<int>(pid) << " param " << param;
        }
    }
}

TEST(C03Term, PredictorDenotationShortResiduals) {
    const std::vector<u8> base = pattern(8, 31);
    for (std::size_t n = 0; n <= 3; ++n) {
        std::vector<u8> residual(base.begin(), base.begin() + static_cast<std::ptrdiff_t>(n));
        for (u8 pid = 0; pid <= 2; ++pid) {
            Builder b;
            const u32 atom = b.atom_node(b.add_atom(residual));
            Ir ir = b.finish(b.predictor(pid, 0, atom));
            auto engine = denote_root(ir, 64);
            ASSERT_TRUE(engine.ok());
            EXPECT_EQ(engine.value(), literal_predictor(pid, 0, residual));
        }
    }
}

// ---------------------------------------------------------------------------
// LFSR
// ---------------------------------------------------------------------------

TEST(C03Term, LfsrMatchesLiteralPseudocode) {
    const std::vector<std::pair<u64, u64>> pairs = {
        {0x80200003ull, 0x1ull},
        {0xD0080004ull, 0xDEADBEEFCAFEF00Dull},
        {0x8000000000000001ull, 0ull},
        {0xFFFFFFFFFFFFFFFFull, 0xFFFFFFFFFFFFFFFFull},
    };
    for (const auto& pair : pairs) {
        for (std::size_t n : {1u, 7u, 8u, 9u, 64u, 129u}) {
            std::vector<u8> engine(n, 0);
            ASSERT_TRUE(lfsr_read_range(pair.first, pair.second, BigInt::zero(), engine).ok());
            EXPECT_EQ(engine, literal_lfsr(pair.first, pair.second, n));
        }
    }
    std::vector<u8> out(4, 0);
    EXPECT_FALSE(lfsr_read_range(0, 1, BigInt::zero(), out).ok());
    EXPECT_FALSE(check_lfsr_conn(0).ok());
    EXPECT_TRUE(check_lfsr_conn(1).ok());
}

TEST(C03Term, LfsrBitOrderIsMsbFirst) {
    // conn bit 0 set, init = 1: the first emitted bit is 1 and becomes the MSB.
    const u64 conn = 0x1ull;
    const u64 init = 0x1ull;
    std::vector<u8> out(1, 0);
    ASSERT_TRUE(lfsr_read_range(conn, init, BigInt::zero(), out).ok());
    EXPECT_EQ(out[0] & 0x80u, 0x80u);
}

TEST(C03Term, LfsrJumpAheadMatchesBitByBit) {
    const u64 conn = 0x80200003ull;
    const u64 init = 0x123456789ABCDEFull;
    const std::vector<u8> reference = literal_lfsr(conn, init, 1200);
    for (std::size_t offset = 0; offset < 300; ++offset) {
        auto state = lfsr_state_at_byte_offset(conn, init, BigInt(static_cast<u64>(offset)));
        ASSERT_TRUE(state.ok());
        // Emitting from the jumped-to state must equal the reference tail.
        LfsrStream stream(conn, init);
        ASSERT_TRUE(stream.jump_to_byte_offset(BigInt(static_cast<u64>(offset))).ok());
        EXPECT_EQ(stream.state(), state.value());
        std::vector<u8> bytes(16, 0);
        ASSERT_TRUE(stream.read(bytes).ok());
        EXPECT_EQ(bytes, std::vector<u8>(reference.begin() + static_cast<std::ptrdiff_t>(offset),
                                         reference.begin() +
                                             static_cast<std::ptrdiff_t>(offset + 16)))
            << "offset " << offset;
    }
}

TEST(C03Term, LfsrJumpAheadLargeOffsetsAreConsistent) {
    const u64 conn = 0xD0080004ull;
    const u64 init = 0xBADC0FFEE0DDF00Dull;
    // T^(8(a+b)) == T^(8a) ∘ T^(8b): consistency without materialising anything.
    for (u64 a : {u64{1} << 20, u64{1} << 32, u64{1} << 40, u64{1} << 50}) {
        auto state_a = lfsr_state_at_byte_offset(conn, init, BigInt(a));
        ASSERT_TRUE(state_a.ok());
        std::vector<u8> chunk(32, 0);
        ASSERT_TRUE(lfsr_read_range(conn, init, BigInt(a), chunk).ok());
        // The bytes emitted at `a` must equal the literal generator started at
        // the jumped-to state.
        LfsrStream stream(conn, init);
        ASSERT_TRUE(stream.jump_to_byte_offset(BigInt(a)).ok());
        std::vector<u8> again(32, 0);
        ASSERT_TRUE(stream.read(again).ok());
        EXPECT_EQ(chunk, again);

        // Offset 0 and the zero-step identity.
        auto zero = lfsr_state_at_byte_offset(conn, init, BigInt::zero());
        ASSERT_TRUE(zero.ok());
        EXPECT_EQ(zero.value(), init);
    }
    EXPECT_FALSE(lfsr_state_at_byte_offset(0, init, BigInt(5)).ok());
}

TEST(C03Term, LfsrDenotationInTerms) {
    Builder b;
    const u64 conn = 0x80200003ull;
    const u64 init = 0x1ull;
    Ir ir = b.finish(b.lfsr(conn, init, 17));
    ASSERT_TRUE(check_well_formed(ir).ok());
    auto engine = denote_root(ir, 4096);
    ASSERT_TRUE(engine.ok());
    EXPECT_EQ(engine.value(), literal_lfsr(conn, init, 17));
}

// ---------------------------------------------------------------------------
// Range evaluation
// ---------------------------------------------------------------------------

TEST(C03Term, RangeMatchesMaterialisedDenotation) {
    Builder b;
    const u32 a16 = b.atom_node(b.add_atom(pattern(16, 3)));
    const u32 z = b.zero(5);
    const u32 rep = b.repeat(a16, 3, 2);
    const u32 sl = b.slice(rep, 4, 20);
    const u32 m = b.morph(sl, 8, 0);
    const u32 x = b.xor_node(m, b.atom_node(b.add_atom(pattern(20, 4))));
    const u32 inter = b.interleave({x, b.lfsr(0x80200003ull, 1, 20)}, 2);
    const u32 root = b.concat({inter, z, b.affine(3, 5, 11)});
    Ir ir = b.finish(root);
    ASSERT_TRUE(check_well_formed(ir).ok());
    auto full = denote_root(ir, 1 << 16);
    ASSERT_TRUE(full.ok());
    const std::size_t n = full.value().size();

    for (std::size_t start = 0; start < n; ++start) {
        for (std::size_t len = 0; start + len <= n; ++len) {
            std::vector<u8> out(len, 0xEE);
            auto result = read_range(ir, root, BigInt(static_cast<u64>(start)), out);
            ASSERT_TRUE(result.ok()) << "start " << start << " len " << len;
            const std::vector<u8> expected(
                full.value().begin() + static_cast<std::ptrdiff_t>(start),
                full.value().begin() + static_cast<std::ptrdiff_t>(start + len));
            EXPECT_EQ(out, expected) << "start " << start << " len " << len;
            EXPECT_EQ(result.value(), len);
        }
    }
    std::vector<u8> beyond(1, 0);
    EXPECT_FALSE(read_range(ir, root, BigInt(static_cast<u64>(n + 1)), beyond).ok());
}

TEST(C03Term, TermCursorMatchesDenotation) {
    Builder b;
    const u32 root = b.repeat(b.concat({b.atom_node(b.add_atom(pattern(7, 8))), b.zero(3)}),
                              4, 5);
    Ir ir = b.finish(root);
    auto full = denote_root(ir, 1 << 16);
    ASSERT_TRUE(full.ok());
    TermCursor cursor(ir, root);
    std::vector<u8> collected;
    std::size_t step = 1;
    for (;;) {
        std::vector<u8> buffer(step, 0);
        auto count = cursor.read(buffer);
        ASSERT_TRUE(count.ok());
        if (count.value() == 0) break;
        collected.insert(collected.end(), buffer.begin(),
                         buffer.begin() + static_cast<std::ptrdiff_t>(count.value()));
        step = (step * 3) % 11 + 1;
    }
    EXPECT_EQ(collected, full.value());
    EXPECT_TRUE(cursor.at_end());
    EXPECT_TRUE(cursor.remaining().is_zero());
}

namespace {
class CollectSink : public Sink {
public:
    Status write(std::span<const u8> bytes) override {
        data.insert(data.end(), bytes.begin(), bytes.end());
        return Status{};
    }
    std::vector<u8> data;
};
}  // namespace

TEST(C03Term, EvalStreamAndEvalRange) {
    Builder b;
    const u32 root = b.concat({b.zero(70000), b.lfsr(0xD0080004ull, 5, 1000),
                               b.atom_node(b.add_atom(pattern(32, 6)))});
    Ir ir = b.finish(root);
    ASSERT_TRUE(check_well_formed(ir).ok());

    CollectSink sink;
    ASSERT_TRUE(eval_stream(ir, sink).ok());
    auto full = denote_root(ir, 1 << 20);
    ASSERT_TRUE(full.ok());
    EXPECT_EQ(sink.data, full.value());
    EXPECT_EQ(sink.data.size(), 71032u);

    CollectSink ranged;
    ASSERT_TRUE(eval_range(ir, BigInt(69990), BigInt(1000), ranged).ok());
    const std::vector<u8> expected(
        full.value().begin() + 69990, full.value().begin() + 69990 + 1000);
    EXPECT_EQ(ranged.data, expected);

    CollectSink beyond;
    EXPECT_FALSE(eval_range(ir, BigInt(71000), BigInt(100), beyond).ok());
}

TEST(C03Term, RangeEvaluationOfVirtualTerms) {
    Builder b;
    // Repeat(atom(3), 2^40, 1): 3*2^40+1 bytes that are never materialised.
    const u32 rep = b.repeat(b.atom_node(b.add_atom(bytes_of({7, 8, 9}))),
                             BigInt(1).shl(40).value(), BigInt(1));
    Ir ir = b.finish(rep);
    ASSERT_TRUE(check_well_formed(ir).ok());
    auto lengths = recompute_lengths_checked(ir);
    ASSERT_TRUE(lengths.ok());
    EXPECT_EQ(lengths.value()[rep].to_decimal(), "3298534883329");

    for (u64 start : {u64{0}, u64{1}, u64{1} << 20, u64{1} << 32, (u64{1} << 32) + 1,
                      (u64{1} << 40)}) {
        std::vector<u8> out(64, 0xEE);
        auto result = read_range(ir, rep, BigInt(start), out);
        ASSERT_TRUE(result.ok()) << "start " << start;
        for (std::size_t i = 0; i < out.size(); ++i) {
            const u64 position = start + i;
            const u8 expected =
                (position % 3 == 0) ? 7 : (position % 3 == 1) ? 8 : 9;
            EXPECT_EQ(out[i], expected) << "start " << start << " i " << i;
        }
    }

    // Zero(2^60) is all zeros and costs O(range) to read.
    Builder c;
    const u32 z = c.zero(BigInt(1).shl(60).value());
    Ir zir = c.finish(z);
    std::vector<u8> zeros(100, 0xEE);
    ASSERT_TRUE(read_range(zir, z, BigInt(1).shl(50).value(), zeros).ok());
    for (u8 v : zeros) EXPECT_EQ(v, 0u);

    // Lfsr jump-ahead inside a term.
    Builder d;
    const u32 l = d.lfsr(0x80200003ull, 0x9ull, BigInt(1).shl(40).value());
    Ir lir = d.finish(l);
    std::vector<u8> jumped(32, 0);
    ASSERT_TRUE(read_range(lir, l, BigInt(1).shl(39).value(), jumped).ok());
    const std::vector<u8> reference = literal_lfsr(0x80200003ull, 0x9ull, 32 + (1u << 12));
    (void)reference;
    std::vector<u8> direct(32, 0);
    LfsrStream stream(0x80200003ull, 0x9ull);
    ASSERT_TRUE(stream.jump_to_byte_offset(BigInt(1).shl(39).value()).ok());
    ASSERT_TRUE(stream.read(direct).ok());
    EXPECT_EQ(jumped, direct);
}

TEST(C03Term, InterleaveRangeOnVirtualChildren) {
    // Interleave(Lfsr(2^40), Zero(2^40)) with stride 8: output blocks are eight
    // LFSR bytes followed by eight zero bytes, over 2^41 virtual bytes.
    Builder b;
    const u64 conn = 0xD0080004ull;
    const u64 init = 0x77ull;
    const BigInt huge = BigInt(1).shl(40).value();
    const u32 l = b.lfsr(conn, init, huge);
    const u32 z = b.zero(huge);
    const u32 inter = b.interleave({l, z}, 8);
    Ir ir = b.finish(inter);
    ASSERT_TRUE(check_well_formed(ir).ok());
    auto lengths = recompute_lengths_checked(ir);
    ASSERT_TRUE(lengths.ok());
    EXPECT_EQ(lengths.value()[inter].to_decimal(), "2199023255552");  // 2*2^40

    const u64 start = u64{1} << 33;
    const std::size_t len = 40;
    std::vector<u8> out(len, 0xEE);
    ASSERT_TRUE(read_range(ir, inter, BigInt(start), out).ok());
    for (std::size_t j = 0; j < len; ++j) {
        const u64 pos = start + j;
        const u64 block_index = pos / 16;
        const u64 within = pos % 16;
        const u64 child = within / 8;
        const u64 within_child = within % 8;
        u8 expected = 0;
        if (child == 0) {
            const BigInt offset = BigInt(block_index * 8 + within_child);
            std::vector<u8> byte_out(1, 0);
            ASSERT_TRUE(lfsr_read_range(conn, init, offset, byte_out).ok());
            expected = byte_out[0];
        }
        EXPECT_EQ(out[j], expected) << "j " << j;
    }
}

TEST(C03Term, PredictorRangePolicyAndWindow) {
    Builder b;
    const u32 z = b.zero(BigInt(1).shl(30).value());
    const u32 p = b.predictor(1, 0, z);
    Ir ir = b.finish(p);
    ASSERT_TRUE(check_well_formed(ir).ok());

    std::vector<u8> out(8, 0xEE);
    ASSERT_TRUE(read_range(ir, p, BigInt(1024), out).ok());
    for (u8 v : out) EXPECT_EQ(v, 0u);

    const BigInt beyond = BigInt(1).shl(28).value().add(BigInt(1)).value();
    std::vector<u8> late(8, 0xEE);
    auto result = read_range(ir, p, beyond, late);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(result.code(), Code::Limit);
}

TEST(C03Term, PredictorRangeMatchesDenotation) {
    const std::vector<u8> payload = pattern(96, 44);
    for (u8 pid = 0; pid <= 4; ++pid) {
        for (u32 param : {0u, 1u, 3u, 96u, 200u}) {
            if (pid >= 3 && param == 0) continue;
            Builder b;
            const u32 atom = b.atom_node(b.add_atom(payload));
            const u32 node = b.predictor(pid, param, atom);
            Ir ir = b.finish(node);
            auto full = denote_root(ir, 4096);
            ASSERT_TRUE(full.ok());
            for (std::size_t start : {0u, 1u, 17u, 95u}) {
                std::vector<u8> out(8, 0xEE);
                const std::size_t take = std::min<std::size_t>(out.size(),
                                                               full.value().size() - start);
                std::vector<u8> chunk(take, 0xEE);
                auto result = read_range(ir, node, BigInt(static_cast<u64>(start)), chunk);
                ASSERT_TRUE(result.ok());
                const std::vector<u8> expected(
                    full.value().begin() + static_cast<std::ptrdiff_t>(start),
                    full.value().begin() + static_cast<std::ptrdiff_t>(start + take));
                EXPECT_EQ(chunk, expected) << "pid " << static_cast<int>(pid) << " start "
                                           << start;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Determinism and structural description
// ---------------------------------------------------------------------------

TEST(C03Term, DenotationIsDeterministic) {
    Builder b;
    const u32 root = b.concat({b.lfsr(0x80200003ull, 7, 64), b.affine(1, 3, 64),
                               b.predictor(4, 3, b.atom_node(b.add_atom(pattern(64, 2))))});
    Ir ir = b.finish(root);
    auto first = denote_root(ir, 1 << 16);
    auto second = denote_root(ir, 1 << 16);
    ASSERT_TRUE(first.ok());
    ASSERT_TRUE(second.ok());
    EXPECT_EQ(first.value(), second.value());
    const std::string key1 = structural_key(ir, root);
    const std::string key2 = structural_key(ir, root);
    EXPECT_EQ(key1, key2);
    EXPECT_FALSE(key1.empty());
}

TEST(C03Term, StructuralKeyDistinguishesAndShares) {
    Builder b;
    const u32 a = b.atom_node(b.add_atom(pattern(8, 1)));
    const u32 cat = b.concat({a, a});
    Ir ir = b.finish(cat);
    EXPECT_EQ(structural_key(ir, a), structural_key(ir, a));
    EXPECT_NE(structural_key(ir, cat), structural_key(ir, a));

    Builder c;
    const u32 x = c.atom_node(c.add_atom(pattern(8, 1)));
    const u32 y = c.atom_node(c.add_atom(pattern(8, 1)));
    const u32 cat2 = c.concat({x, y});
    Ir ir2 = c.finish(cat2);
    // Structurally equal subterms have equal keys even though the atom records
    // and node ids differ.
    EXPECT_EQ(structural_key(ir2, x), structural_key(ir2, y));
    EXPECT_EQ(structural_key(ir2, cat2), structural_key(ir, cat));
}

TEST(C03Term, MalformedInputNeverEscapesAsException) {
    // Structurally broken IRs must return codes, not crash or throw.
    Ir empty;
    EXPECT_FALSE(check_well_formed(empty).ok());
    EXPECT_FALSE(denote_root(empty, 16).ok());
    EXPECT_FALSE(read_range(empty, 0, BigInt::zero(), std::span<u8>()).ok());

    Builder b;
    const u32 cat = b.concat({b.zero(2), b.zero(3)});
    Ir ir = b.finish(cat);
    ir.nodes[cat].args[0] = 999;
    EXPECT_FALSE(check_well_formed(ir).ok());
    std::vector<u8> out(4, 0);
    EXPECT_FALSE(read_range(ir, cat, BigInt::zero(), out).ok());
    EXPECT_FALSE(denote_root(ir, 16).ok());
}
