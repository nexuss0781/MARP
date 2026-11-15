// MARP v2 — E2 ALGEBRA — C05 EVAL unit & property tests.
//
// Exercises obligations O5.1 (full/range equivalence across all 12 kinds, 9
// morphisms, 5 predictors), O5.2 (LFSR jump-ahead, Concat skipping, Predictor
// prefix limit & checkpoints), O5.3 (bounded memory / incremental SHA-256),
// WF enforcement, W7 max-depth (65,536) explicit-stack execution, BigInt
// offsets > 2^64, C04 canon coherence (E2-I4), and multi-threaded reentrancy
// (E2-I12).

#include "mapr/e2/e2_eval.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <random>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include "c03_build.hpp"
#include "c03_reference.hpp"
#include "mapr/e1_sha256.hpp"
#include "mapr/e2/e2_canon.hpp"
#include "mapr/e2/e2_term.hpp"

namespace marp::v2 {
namespace {

using c03::Builder;
using c03::pattern;

struct VecSink final : Sink {
    std::vector<u8> bytes;
    std::size_t calls = 0;
    std::size_t max_chunk = 0;
    Code fail_on_call_code = Code::Ok;
    std::size_t fail_on_call = 0;

    Status write(std::span<const u8> chunk) override {
        ++calls;
        if (chunk.size() > max_chunk) max_chunk = chunk.size();
        if (fail_on_call != 0 && calls == fail_on_call) {
            return fail_on_call_code;
        }
        bytes.insert(bytes.end(), chunk.begin(), chunk.end());
        return Status{};
    }
};

std::array<u8, 32> sha256_of(std::span<const u8> data) {
    auto res = mapr::Sha256::hash(
        std::string_view(reinterpret_cast<const char*>(data.data()), data.size()));
    EXPECT_TRUE(res.ok());
    return res.value();
}

BigInt pow2(u32 k) {
    auto r = BigInt(1).shl(k);
    EXPECT_TRUE(r.ok());
    return r.value();
}

std::size_t read_rss_kib() {
    std::ifstream in("/proc/self/status");
    std::string line;
    while (std::getline(in, line)) {
        if (line.rfind("VmRSS:", 0) == 0) {
            unsigned long kib = 0;
            if (std::sscanf(line.c_str() + 6, "%lu", &kib) == 1) {
                return static_cast<std::size_t>(kib);
            }
        }
    }
    return 0;
}

void verify_all_subranges_against_full(const Ir& ir, std::size_t max_step = 1) {
    ASSERT_TRUE(check_well_formed(ir).ok());
    VecSink full_sink;
    ASSERT_TRUE(eval_stream(ir, full_sink).ok());
    const std::vector<u8>& expected = full_sink.bytes;

    std::vector<u8> ref;
    ASSERT_TRUE(c03ref::ref_denote(ir, ir.root, ref, expected.size() + 64u));
    ASSERT_EQ(ref, expected);

    const std::size_t n = expected.size();
    const std::size_t step = std::max<std::size_t>(1u, max_step);
    for (std::size_t s = 0; s <= n; s += step) {
        for (std::size_t len = 0; s + len <= n; len += step) {
            std::vector<u8> buf(len, 0xA5u);
            auto r = read_range(ir, ir.root, BigInt(static_cast<u64>(s)), buf);
            ASSERT_TRUE(r.ok()) << "s=" << s << " len=" << len;
            ASSERT_EQ(r.value(), len);
            EXPECT_TRUE(std::equal(buf.begin(), buf.end(),
                                   expected.begin() + static_cast<std::ptrdiff_t>(s)))
                << "s=" << s << " len=" << len;
        }
    }

    // Out-of-bounds checks at the right edge.
    {
        std::array<u8, 1> one{};
        EXPECT_EQ(read_range(ir, ir.root, BigInt(static_cast<u64>(n)), one).code(),
                  Code::Invalid);
        EXPECT_EQ(read_range(ir, ir.root, BigInt(static_cast<u64>(n + 1)), {}).code(),
                  Code::Invalid);
        VecSink sink;
        EXPECT_EQ(eval_range(ir, BigInt(static_cast<u64>(n)), BigInt(1), sink).code(),
                  Code::Invalid);
    }
}

// ---------------------------------------------------------------------------
// 1. Preconditions: WF(ir) enforced across all C05 entry points
// ---------------------------------------------------------------------------

TEST(C05Eval, FullWfEnforcedAcrossAllEntryPoints) {
    auto expect_all_fail = [](const Ir& bad, Code expected) {
        VecSink sink;
        EXPECT_EQ(eval_stream(bad, sink).code(), expected);
        EXPECT_EQ(eval_range(bad, BigInt::zero(), BigInt::zero(), sink).code(), expected);
        std::array<u8, 1> buf{};
        EXPECT_EQ(read_range(bad, bad.root, BigInt::zero(), {}).code(), expected);
        EXPECT_EQ(read_range_ex(bad, bad.root, BigInt::zero(), {}).code(), expected);
        EXPECT_EQ(eval_stream_digest(bad).code(), expected);
        EXPECT_EQ(eval_range_digest(bad, BigInt::zero(), BigInt::zero()).code(), expected);
        EXPECT_EQ(PreparedEval::prepare(bad).code(), expected);
        TermCursor cur(bad, bad.root);
        EXPECT_EQ(cur.read(buf).code(), expected);
    };

    // W2: unreachable sibling node.
    {
        Builder b;
        (void)b.atom_node(b.add_atom(pattern(4, 1)));  // unreachable node 0 & atom 0
        const u32 root = b.atom_node(b.add_atom(pattern(4, 2)));
        expect_all_fail(b.finish(root), Code::Invalid);
    }

    // W2: unreferenced atom record.
    {
        Builder b;
        (void)b.add_atom(pattern(3, 9));  // unused atom 0
        expect_all_fail(b.finish(b.zero(BigInt(8))), Code::Invalid);
    }

    // W3: self-edge / forward reference.
    {
        Builder b;
        Ir ir = b.finish(b.morph(b.atom_node(b.add_atom(pattern(4, 3))), 1, 0));
        ir.nodes[1].args[0] = 1;  // cycle
        expect_all_fail(ir, Code::Invalid);
    }

    // W4: nonzero node flags.
    {
        Builder b;
        Ir ir = b.finish(b.zero(BigInt(16)));
        ir.nodes[0].flags = 1;
        expect_all_fail(ir, Code::Invalid);
    }

    // W5: zero-length atom.
    {
        Builder b;
        Ir ir = b.finish(b.atom_node(b.add_atom({})));
        expect_all_fail(ir, Code::Invalid);
    }

    // W6: tampered stored node length.
    {
        Builder b;
        Ir ir = b.finish(b.zero(BigInt(16)));
        ir.nodes[0].length = BigInt(15);
        expect_all_fail(ir, Code::Invalid);
    }

    // S1.output-cap: root length > 2^63 -> Code::Limit.
    {
        Builder b;
        auto over = pow2(63).add(BigInt(1));
        ASSERT_TRUE(over.ok());
        Ir ir = b.finish(b.zero(over.value()));
        expect_all_fail(ir, Code::Limit);
    }
}

// ---------------------------------------------------------------------------
// 2. Explicit stack up to W7 = 65,536 (no C++ call-stack recursion)
// ---------------------------------------------------------------------------

TEST(C05Eval, MaxDepth65536EvaluatesOnExplicitStackWithoutOverflow) {
    // 1 Atom (depth 1) + 65,535 unary INVERT8 Morphs => root depth == 65,536 == W7!
    Builder b;
    const std::vector<u8> payload = {0x12u, 0x34u, 0x56u, 0x78u, 0x9Au, 0xBCu, 0xDEu, 0xF0u};
    u32 cur = b.atom_node(b.add_atom(payload));
    for (u32 i = 1; i < kMaxDepthSpec; ++i) {
        cur = b.morph(cur, 2, 0);  // INVERT8 involution
    }
    const Ir ir = b.finish(cur);
    ASSERT_TRUE(check_well_formed(ir).ok());

    // 65,535 applications of INVERT8 (odd count) flips every bit once.
    std::vector<u8> expected(payload.size());
    for (std::size_t i = 0; i < payload.size(); ++i) {
        expected[i] = static_cast<u8>(~payload[i]);
    }

    EvalStats stats{};
    VecSink sink;
    ASSERT_TRUE(eval_stream_ex(ir, sink, EvalLimits{}, &stats).ok());
    EXPECT_EQ(sink.bytes, expected);
    EXPECT_EQ(stats.peak_stack_depth, kMaxDepthSpec);
    EXPECT_EQ(stats.peak_scratch_bytes, 0u);

    // Subrange read on the 65,536-deep DAG also works with zero stack recursion.
    std::array<u8, 4> sub{};
    EvalStats rstats{};
    auto rr = read_range_ex(ir, ir.root, BigInt(2), sub, EvalLimits{}, {}, &rstats);
    ASSERT_TRUE(rr.ok());
    EXPECT_EQ(rr.value(), 4u);
    EXPECT_TRUE(std::equal(sub.begin(), sub.end(), expected.begin() + 2));
    EXPECT_EQ(rstats.peak_stack_depth, kMaxDepthSpec);

    // Adding one more unary layer (depth 65,537 > W7) returns Code::Limit.
    {
        Builder b2;
        u32 n = b2.atom_node(b2.add_atom(payload));
        for (u32 i = 1; i <= kMaxDepthSpec; ++i) {
            n = b2.morph(n, 1, 0);
        }
        const Ir too_deep = b2.finish(n);
        VecSink s2;
        EXPECT_EQ(eval_stream(too_deep, s2).code(), Code::Limit);
        EXPECT_EQ(read_range(too_deep, too_deep.root, BigInt::zero(), sub).code(), Code::Limit);
    }
}

// ---------------------------------------------------------------------------
// 3. Empty, Atom, Zero
// ---------------------------------------------------------------------------

TEST(C05Eval, EmptyAtomAndZeroSemantics) {
    // Empty root
    {
        Builder b;
        const Ir ir = b.finish(b.empty());
        verify_all_subranges_against_full(ir);

        auto dig = eval_stream_digest(ir);
        ASSERT_TRUE(dig.ok());
        EXPECT_TRUE(dig.value().bytes.is_zero());
        EXPECT_EQ(dig.value().sha256, sha256_of({}));

        TermCursor cur(ir, ir.root);
        EXPECT_TRUE(cur.at_end());
        EXPECT_TRUE(cur.remaining().is_zero());
        std::array<u8, 8> tmp{};
        auto r = cur.read(tmp);
        ASSERT_TRUE(r.ok());
        EXPECT_EQ(r.value(), 0u);
    }

    // Atom (non-aligned payload)
    {
        Builder b;
        const Ir ir = b.finish(b.atom_node(b.add_atom(pattern(37, 19))));
        verify_all_subranges_against_full(ir);
    }

    // Virtual Zero(2^62) at astronomical offsets
    {
        Builder b;
        const BigInt len = pow2(62);
        const Ir ir = b.finish(b.zero(len));
        std::vector<u8> buf(4096, 0xFFu);
        auto off = len.sub(BigInt(4096));
        ASSERT_TRUE(off.ok());
        EvalStats stats{};
        auto r = read_range_ex(ir, ir.root, off.value(), buf, EvalLimits{}, {}, &stats);
        ASSERT_TRUE(r.ok());
        EXPECT_EQ(r.value(), 4096u);
        EXPECT_TRUE(std::all_of(buf.begin(), buf.end(), [](u8 x) { return x == 0u; }));
        EXPECT_EQ(stats.peak_scratch_bytes, 0u);
    }
}

// ---------------------------------------------------------------------------
// 4. Concat: cumulative-offset binary search & untouched sibling skipping
// ---------------------------------------------------------------------------

TEST(C05Eval, ConcatSkipsDisjointChildrenViaBinarySearch) {
    Builder b;
    std::vector<u32> kids;
    std::vector<u8> full_expected;
    constexpr std::size_t kChildren = 256;
    for (std::size_t i = 0; i < kChildren; ++i) {
        const std::size_t clen = 7u + (i % 13u);
        auto bytes = pattern(clen, static_cast<u8>(i * 37u + 5u));
        full_expected.insert(full_expected.end(), bytes.begin(), bytes.end());
        kids.push_back(b.atom_node(b.add_atom(bytes)));
    }
    const Ir ir = b.finish(b.concat(kids));

    auto prep = PreparedEval::prepare(ir);
    ASSERT_TRUE(prep.ok());

    // Read a 20-byte window near the middle (touches at most 3 children out of 256).
    const std::size_t start = full_expected.size() / 2u + 3u;
    std::array<u8, 20> got{};
    EvalStats stats{};
    auto r = prep.value().read_range(ir.root, BigInt(static_cast<u64>(start)), got, {}, &stats);
    ASSERT_TRUE(r.ok());
    EXPECT_TRUE(std::equal(got.begin(), got.end(),
                           full_expected.begin() + static_cast<std::ptrdiff_t>(start)));
    EXPECT_LE(stats.subterms_touched, 4u);
    EXPECT_GE(stats.concat_children_skipped, kChildren - 4u);

    // Also test a Concat containing Empty children (zero-length children inside cumulative table).
    {
        Builder b2;
        const u32 a0 = b2.atom_node(b2.add_atom(pattern(11, 1)));
        const u32 e = b2.empty();
        const u32 a1 = b2.atom_node(b2.add_atom(pattern(13, 2)));
        const u32 a2 = b2.atom_node(b2.add_atom(pattern(9, 3)));
        std::vector<u32> args = {e, a0, e, e, a1, e, a2, e, a0, e};
        const Ir ir2 = b2.finish(b2.concat(args));
        verify_all_subranges_against_full(ir2, 3);
    }
}

// ---------------------------------------------------------------------------
// 5. Repeat: modulo boundaries, remainder r, and virtual q
// ---------------------------------------------------------------------------

TEST(C05Eval, RepeatModuloBoundariesAndVirtualCopies) {
    {
        Builder b;
        const u32 c = b.atom_node(b.add_atom(pattern(11, 41)));
        const Ir ir = b.finish(b.repeat(c, BigInt(4), BigInt(7)));  // 4*11 + 7 = 51 bytes
        verify_all_subranges_against_full(ir);
    }
    {
        // Repeat(q=0, r=0) == Empty
        Builder b;
        const u32 c = b.atom_node(b.add_atom(pattern(9, 3)));
        const Ir ir = b.finish(b.repeat(c, BigInt::zero(), BigInt::zero()));
        verify_all_subranges_against_full(ir);
    }
    {
        // Virtual Repeat: ℓ(c) = 13, q = 2^55, r = 9 => ℓ = 13 * 2^55 + 9 < 2^63.
        Builder b;
        const auto payload = pattern(13, 77);
        const u32 c = b.atom_node(b.add_atom(payload));
        const BigInt q = pow2(55);
        const Ir ir = b.finish(b.repeat(c, q, BigInt(9)));

        // Read across the boundary from copy (q-1) into the trailing prefix [0, 9).
        auto boundary = q.mul(BigInt(13));
        ASSERT_TRUE(boundary.ok());
        auto start = boundary.value().sub(BigInt(5));
        ASSERT_TRUE(start.ok());
        std::array<u8, 14> out{};  // last 5 bytes of copy (q-1) + all 9 bytes of prefix
        ASSERT_TRUE(read_range(ir, ir.root, start.value(), out).ok());
        for (std::size_t i = 0; i < 5; ++i) EXPECT_EQ(out[i], payload[8 + i]);
        for (std::size_t i = 0; i < 9; ++i) EXPECT_EQ(out[5 + i], payload[i]);
    }
}

// ---------------------------------------------------------------------------
// 6. Slice: nested composition and exact BigInt offsets > 2^64 (M2-I2)
// ---------------------------------------------------------------------------

TEST(C05Eval, SliceCompositionAndChildOffsetsAbove2Pow64) {
    {
        Builder b;
        const u32 base = b.affine(19, 37, BigInt(90));
        const u32 s1 = b.slice(base, BigInt(11), BigInt(61));
        const u32 s2 = b.slice(s1, BigInt(7), BigInt(35));
        const Ir ir = b.finish(s2);
        verify_all_subranges_against_full(ir);
    }

    // Child is Lfsr of length 2^70 (> 2^64!), while root is Slice(..., 2^65 + 137, 64)
    // so ℓ(root) = 64 <= 2^63 satisfies S1.output-cap!
    {
        Builder b;
        constexpr u64 kConn = 0x800000000000001Bull;
        constexpr u64 kInit = 0x0123456789ABCDEFull;
        const BigInt child_len = pow2(70);
        auto slice_off = pow2(65).add(BigInt(137));
        ASSERT_TRUE(slice_off.ok());
        const u32 lf = b.lfsr(kConn, kInit, child_len);
        const u32 sl = b.slice(lf, slice_off.value(), BigInt(64));
        const Ir ir = b.finish(sl);
        ASSERT_TRUE(check_well_formed(ir).ok());

        // Subrange [13, 45) inside the Slice corresponds to child offset 2^65 + 150.
        std::array<u8, 32> got{};
        ASSERT_TRUE(read_range(ir, ir.root, BigInt(13), got).ok());

        auto direct_off = slice_off.value().add(BigInt(13));
        ASSERT_TRUE(direct_off.ok());
        std::array<u8, 32> expected{};
        ASSERT_TRUE(lfsr_read_range(kConn, kInit, direct_off.value(), expected).ok());
        EXPECT_EQ(got, expected);

        // Also verify full stream matches direct LFSR at slice_off.
        VecSink sink;
        ASSERT_TRUE(eval_stream(ir, sink).ok());
        std::vector<u8> exp_full(64);
        ASSERT_TRUE(lfsr_read_range(kConn, kInit, slice_off.value(), exp_full).ok());
        EXPECT_EQ(sink.bytes, exp_full);
    }
}

// ---------------------------------------------------------------------------
// 7. Morphisms: byte-local (1,2,6,7), block (3,4,5), mirrored (8,9)
// ---------------------------------------------------------------------------

TEST(C05Eval, MorphAllCatalogueEntriesAndZeroScratchBlockAndMirrored) {
    // Byte-local: 1, 2, 6(k=1..7), 7(k=1..7)
    for (u8 m : {u8{1}, u8{2}}) {
        Builder b;
        const Ir ir = b.finish(
            b.morph(b.atom_node(b.add_atom(pattern(29, static_cast<u8>(m + 10u)))), m, 0));
        verify_all_subranges_against_full(ir);
    }
    for (u8 m : {u8{6}, u8{7}}) {
        for (u8 k = 1; k <= 7; ++k) {
            Builder b;
            const Ir ir = b.finish(
                b.morph(b.atom_node(b.add_atom(pattern(23, static_cast<u8>(k * 11u)))), m, k));
            verify_all_subranges_against_full(ir, 2);
        }
    }

    // Block morphs 3 (SWAP16), 4 (SWAP32), 5 (SWAP64): every subrange + zero heap scratch!
    for (u8 m : {u8{3}, u8{4}, u8{5}}) {
        const std::size_t blen = 32u;  // divisible by 2, 4, and 8
        Builder b;
        const Ir ir = b.finish(
            b.morph(b.atom_node(b.add_atom(pattern(blen, static_cast<u8>(m * 17u)))), m, 0));
        verify_all_subranges_against_full(ir);

        // Verify unaligned subrange uses 0 heap scratch bytes.
        std::array<u8, 13> unaligned{};
        EvalStats stats{};
        ASSERT_TRUE(
            read_range_ex(ir, ir.root, BigInt(3), unaligned, EvalLimits{}, {}, &stats).ok());
        EXPECT_EQ(stats.peak_scratch_bytes, 0u);
    }

    // Mirrored morphs 8 (REVERSE_BYTES) and 9 (REVERSE_BITS = REVERSE_BYTES o BIT_REVERSE8)
    for (u8 m : {u8{8}, u8{9}}) {
        Builder b;
        const Ir ir = b.finish(
            b.morph(b.atom_node(b.add_atom(pattern(31, static_cast<u8>(m * 29u)))), m, 0));
        verify_all_subranges_against_full(ir);
    }

    // Virtual REVERSE_BITS on a 2^40-byte LFSR child: out[j] = bit_reverse8(in[N - 1 - j]).
    {
        Builder b;
        constexpr u64 kConn = 0xD008000000000005ull;
        constexpr u64 kInit = 0xCAFEBABE12345678ull;
        const BigInt n = pow2(40);
        const Ir ir = b.finish(b.morph(b.lfsr(kConn, kInit, n), 9, 0));

        const BigInt start = pow2(39);
        std::array<u8, 25> got{};
        EvalStats stats{};
        ASSERT_TRUE(read_range_ex(ir, ir.root, start, got, EvalLimits{}, {}, &stats).ok());
        EXPECT_EQ(stats.peak_scratch_bytes, 0u);

        // Child range is [n - start - 25, n - start).
        auto child_from = n.sub(start).value().sub(BigInt(25));
        ASSERT_TRUE(child_from.ok());
        std::array<u8, 25> raw{};
        ASSERT_TRUE(lfsr_read_range(kConn, kInit, child_from.value(), raw).ok());
        std::reverse(raw.begin(), raw.end());
        for (u8& byte : raw) byte = bit_reverse8(byte);
        EXPECT_EQ(got, raw);
    }
}

// ---------------------------------------------------------------------------
// 8. Xor & DAG sharing without exponential blowup
// ---------------------------------------------------------------------------

TEST(C05Eval, XorSubrangesAndDeepSharedDag) {
    {
        Builder b;
        const u32 left = b.lfsr(0x80200003ull, 0x1122334455667788ull, BigInt(43));
        const u32 right = b.affine(7, 53, BigInt(43));
        const Ir ir = b.finish(b.xor_node(left, right));
        verify_all_subranges_against_full(ir, 2);
    }

    // 14-level shared Xor+Morph DAG (tree unfolding has 2^14 = 16,384 leaves, DAG has 29 nodes).
    {
        Builder b;
        u32 cur = b.atom_node(b.add_atom(pattern(64, 101)));
        for (u32 i = 0; i < 14; ++i) {
            const u32 rot = b.morph(cur, 6, static_cast<u8>((i % 7u) + 1u));
            cur = b.xor_node(cur, rot);
        }
        const Ir ir = b.finish(cur);
        verify_all_subranges_against_full(ir, 7);
    }
}

// ---------------------------------------------------------------------------
// 9. Interleave: unaligned strides, multiple children, virtual children
// ---------------------------------------------------------------------------

TEST(C05Eval, InterleaveUnalignedStridesAndVirtualChildren) {
    for (u32 stride : {u32{1}, u32{3}, u32{8}}) {
        Builder b;
        const std::size_t child_len = static_cast<std::size_t>(stride * 5u);
        const u32 c0 = b.atom_node(b.add_atom(pattern(child_len, 11)));
        const u32 c1 = b.atom_node(b.add_atom(pattern(child_len, 22)));
        const u32 c2 = b.atom_node(b.add_atom(pattern(child_len, 33)));
        const Ir ir = b.finish(b.interleave({c0, c1, c2}, stride));
        verify_all_subranges_against_full(ir, 2);
    }

    // Virtual 3-way Interleave of length 3 * (17 * 2^45)
    {
        Builder b;
        constexpr u32 kStride = 17;
        const BigInt blocks = pow2(45);
        const BigInt child_len = blocks.mul(BigInt(kStride)).value();
        const u32 c0 = b.lfsr(0x80000057ull, 0xABCull, child_len);
        const u32 c1 = b.affine(9, 13, child_len);
        const u32 c2 = b.zero(child_len);
        const Ir ir = b.finish(b.interleave({c0, c1, c2}, kStride));

        // Read 60 bytes starting mid-stride at block index 2^40 + 7, child 1, offset 5.
        const BigInt blk_idx = pow2(40).add(BigInt(7)).value();
        const BigInt block_bytes(3u * kStride);
        const BigInt start =
            blk_idx.mul(block_bytes).value().add(BigInt(kStride + 5u)).value();
        std::array<u8, 60> got{};
        ASSERT_TRUE(read_range(ir, ir.root, start, got).ok());

        // Reconstruct expected byte-by-byte from the three virtual children.
        std::array<u8, 60> expected{};
        for (std::size_t i = 0; i < got.size(); ++i) {
            const BigInt pos = start.add(BigInt(static_cast<u64>(i))).value();
            auto dm = pos.divmod(block_bytes).value();
            const u64 within = dm.second.to_u64_checked().value();
            const u64 cid = within / kStride;
            const u64 wchild = within % kStride;
            const BigInt coff = dm.first.mul(BigInt(kStride)).value().add(BigInt(wchild)).value();
            u32 node_id = (cid == 0) ? c0 : (cid == 1 ? c1 : c2);
            std::array<u8, 1> one{};
            ASSERT_TRUE(read_range(ir, node_id, coff, one).ok());
            expected[i] = one[0];
        }
        EXPECT_EQ(got, expected);
    }
}

// ---------------------------------------------------------------------------
// 10. Lfsr: O(log offset) GF(2) jump-ahead & O(1) streaming continuity
// ---------------------------------------------------------------------------

TEST(C05Eval, LfsrLogarithmicJumpAheadAndZeroJumpStreaming) {
    Builder b;
    constexpr u64 kConn = 0xD80000000000000Dull;
    constexpr u64 kInit = 0xFEDCBA9876543210ull;
    const BigInt total = pow2(62);
    const Ir ir = b.finish(b.lfsr(kConn, kInit, total));

    // Jump to 2^60 + 999999: must take O(log offset) <= 130 GF(2) matrix multiplications.
    const BigInt far = pow2(60).add(BigInt(999999)).value();
    std::array<u8, 128> span128{};
    EvalStats stats_far{};
    ASSERT_TRUE(read_range_ex(ir, ir.root, far, span128, EvalLimits{}, {}, &stats_far).ok());
    EXPECT_EQ(stats_far.lfsr_jumps, 1u);
    EXPECT_LE(stats_far.lfsr_gf2_mul_ops, 130u);

    // Adjacent 64-byte halves must concatenate to the 128-byte span.
    std::array<u8, 64> lo{}, hi{};
    ASSERT_TRUE(read_range(ir, ir.root, far, lo).ok());
    ASSERT_TRUE(read_range(ir, ir.root, far.add(BigInt(64)).value(), hi).ok());
    EXPECT_TRUE(std::equal(lo.begin(), lo.end(), span128.begin()));
    EXPECT_TRUE(std::equal(hi.begin(), hi.end(), span128.begin() + 64));

    // Streaming a 200 KiB LFSR from offset 0 must perform ZERO jump-aheads across chunks!
    {
        Builder b2;
        const Ir ir2 = b2.finish(b2.lfsr(kConn, kInit, BigInt(200 * 1024)));
        EvalLimits lim;
        lim.block_bytes = 4096;
        EvalStats sstats{};
        auto dig = eval_stream_digest(ir2, lim, &sstats);
        ASSERT_TRUE(dig.ok());
        EXPECT_EQ(sstats.lfsr_jumps, 0u);
        EXPECT_EQ(sstats.lfsr_gf2_mul_ops, 0u);
        EXPECT_EQ(sstats.lfsr_byte_steps, 200u * 1024u);
    }
}

// ---------------------------------------------------------------------------
// 11.Predictors: all 5 IDs, 2^28 prefix limit, checkpoints, streaming cache
// ---------------------------------------------------------------------------

TEST(C05Eval, PredictorAllFiveIdsSubrangeEquivalence) {
    struct Spec {
        u8 pid;
        u32 param;
    };
    const std::vector<Spec> specs = {
        {0, 0}, {1, 0}, {2, 0}, {3, 1}, {3, 4}, {3, 17}, {4, 1}, {4, 5}, {4, 19},
    };
    for (const Spec& sp : specs) {
        for (std::size_t len : {std::size_t{1}, std::size_t{2}, std::size_t{3}, std::size_t{35}}) {
            Builder b;
            const u32 res = b.atom_node(
                b.add_atom(pattern(len, static_cast<u8>(sp.pid * 23u + sp.param + 3u))));
            const Ir ir = b.finish(b.predictor(sp.pid, sp.param, res));
            verify_all_subranges_against_full(ir, 2);
        }
    }
}

TEST(C05Eval, PredictorPrefixLimitAndStrideWindowPolicy) {
    // Default 2^28 prefix limit on a 2^30 virtual Predictor:
    //   - start = 2^28 + 1 -> Code::Limit (checked before any prefix scan!)
    //   - start = 2^30 + 1 -> Code::Invalid (out-of-bounds takes precedence!)
    {
        Builder b;
        const BigInt len = pow2(30);
        const Ir ir = b.finish(b.predictor(0, 0, b.zero(len)));
        std::array<u8, 8> out{};

        const BigInt over_prefix = predictor_prefix_limit().add(BigInt(1)).value();
        EXPECT_EQ(read_range(ir, ir.root, over_prefix, out).code(), Code::Limit);

        const BigInt out_of_bounds = len.add(BigInt(1)).value();
        EXPECT_EQ(read_range(ir, ir.root, out_of_bounds, {}).code(), Code::Invalid);
        EXPECT_EQ(read_range(ir, ir.root, len, out).code(), Code::Invalid);
    }

    // Custom predictor_prefix_max = 1024: start = 1024 succeeds, start = 1025 returns Limit.
    {
        Builder b;
        const Ir ir = b.finish(b.predictor(2, 0, b.affine(5, 17, BigInt(4096))));
        EvalLimits lim;
        lim.predictor_prefix_max = BigInt(1024);

        std::array<u8, 16> ok_buf{};
        ASSERT_TRUE(read_range_ex(ir, ir.root, BigInt(1024), ok_buf, lim).ok());
        EXPECT_EQ(read_range_ex(ir, ir.root, BigInt(1025), ok_buf, lim).code(), Code::Limit);
    }

    // Stride window > 16 MiB:
    //   - reading beyond `param` requires the full ring -> Code::Limit
    //   - reading strictly inside `[0, param]` needs zero ring -> succeeds!
    {
        Builder b;
        constexpr u32 kHugeStride = (16u << 20) + 64u;
        const BigInt len(static_cast<u64>(kHugeStride) + 1024ull);
        const Ir ir = b.finish(b.predictor(3, kHugeStride, b.affine(3, 7, len)));

        std::array<u8, 16> inside{};
        EvalStats stats{};
        ASSERT_TRUE(read_range_ex(ir, ir.root, BigInt(100), inside, EvalLimits{}, {}, &stats).ok());
        // Pass-1 uses a 100-byte chunk buffer for [0, 100), and ZERO 16 MiB stride ring!
        EXPECT_EQ(stats.peak_scratch_bytes, 100u);

        std::array<u8, 16> past_stride{};
        EXPECT_EQ(read_range(ir, ir.root, BigInt(kHugeStride), past_stride).code(), Code::Limit);
    }
}

TEST(C05Eval, PredictorCheckpointsCaptureValidateChainAndRandomAccess) {
    struct Spec {
        u8 pid;
        u32 param;
    };
    const std::vector<Spec> specs = {{0, 0}, {1, 0}, {2, 0}, {3, 13}, {4, 19}};

    for (const Spec& sp : specs) {
        Builder b;
        const u32 res = b.lfsr(0x80200003ull, 0x13579BDF2468ACE0ull + sp.pid, BigInt(5000));
        const u32 pred = b.predictor(sp.pid, sp.param, res);
        const Ir ir = b.finish(pred);

        VecSink full;
        ASSERT_TRUE(eval_stream(ir, full).ok());

        EvalLimits lim;
        lim.predictor_prefix_max = BigInt(1000);
        lim.block_bytes = 257;

        // Without checkpoint, offset 3400 > 1000 returns Code::Limit.
        std::array<u8, 73> got{};
        EXPECT_EQ(read_range_ex(ir, pred, BigInt(3400), got, lim).code(), Code::Limit);

        // Chain checkpoints 0 -> 1000 -> 2000 -> 3000 within the 1000-byte budget!
        auto cp0 = capture_predictor_checkpoint(ir, pred, BigInt::zero(), nullptr, lim);
        ASSERT_TRUE(cp0.ok());
        ASSERT_TRUE(validate_predictor_checkpoint(ir, cp0.value(), lim).ok());

        auto cp1 = capture_predictor_checkpoint(ir, pred, BigInt(1000), &cp0.value(), lim);
        ASSERT_TRUE(cp1.ok());
        auto cp2 = capture_predictor_checkpoint(ir, pred, BigInt(2000), &cp1.value(), lim);
        ASSERT_TRUE(cp2.ok());
        auto cp3 = capture_predictor_checkpoint(ir, pred, BigInt(3000), &cp2.value(), lim);
        ASSERT_TRUE(cp3.ok());

        const std::array<PredictorCheckpoint, 3> cps = {cp1.value(), cp2.value(), cp3.value()};
        EvalStats stats{};
        ASSERT_TRUE(read_range_ex(ir, pred, BigInt(3400), got, lim, cps, &stats).ok());
        EXPECT_EQ(stats.predictor_prefix_bytes, 400u);  // jumped from cp3 @ 3000, not 0!
        EXPECT_TRUE(std::equal(got.begin(), got.end(), full.bytes.begin() + 3400));

        // Also test checkpoint at offset == 1 (critical LINEAR2 half-seeded boundary).
        auto cp_one = capture_predictor_checkpoint(ir, pred, BigInt(1), nullptr, lim);
        ASSERT_TRUE(cp_one.ok());
        ASSERT_TRUE(validate_predictor_checkpoint(ir, cp_one.value(), lim).ok());
        const std::array<PredictorCheckpoint, 1> one_arr = {cp_one.value()};
        std::array<u8, 32> from_one{};
        ASSERT_TRUE(read_range_ex(ir, pred, BigInt(1), from_one, lim, one_arr).ok());
        EXPECT_TRUE(std::equal(from_one.begin(), from_one.end(), full.bytes.begin() + 1));
    }

    // Invalid checkpoints must be rejected cleanly with Code::Invalid.
    {
        Builder b;
        const u32 res = b.affine(1, 3, BigInt(200));
        const u32 p2 = b.predictor(2, 0, res);
        const Ir ir = b.finish(p2);

        PredictorCheckpoint bad;
        bad.node = 99;  // invalid node id
        EXPECT_EQ(validate_predictor_checkpoint(ir, bad).code(), Code::Invalid);

        bad = PredictorCheckpoint{0, BigInt(10), 0, 0, {}};  // node 0 is Affine, not Predictor
        EXPECT_EQ(validate_predictor_checkpoint(ir, bad).code(), Code::Invalid);

        bad = PredictorCheckpoint{p2, BigInt(201), 0, 0, {}};  // offset > len
        EXPECT_EQ(validate_predictor_checkpoint(ir, bad).code(), Code::Invalid);

        bad = PredictorCheckpoint{p2, BigInt::zero(), 1, 0, {}};  // nonzero prev1 at offset 0
        EXPECT_EQ(validate_predictor_checkpoint(ir, bad).code(), Code::Invalid);

        bad = PredictorCheckpoint{p2, BigInt(1), 5, 7, {}};  // nonzero prev2 at offset 1
        EXPECT_EQ(validate_predictor_checkpoint(ir, bad).code(), Code::Invalid);

        bad = PredictorCheckpoint{p2, BigInt(10), 5, 7, {1, 2}};  // window forbidden for pid=2
        EXPECT_EQ(validate_predictor_checkpoint(ir, bad).code(), Code::Invalid);
    }

    // Checkpoint beyond 2^28 (at 2^32 on a virtual Zero predictor) enables direct high-offset read!
    {
        Builder b;
        const BigInt len = pow2(34);
        const u32 pred = b.predictor(0, 0, b.zero(len));
        const Ir ir = b.finish(pred);

        // On Zero residual, DELTA8 output is identically 0, so state at 2^32 has prev1 == 0.
        PredictorCheckpoint high_cp;
        high_cp.node = pred;
        high_cp.offset = pow2(32);
        high_cp.prev1 = 0;
        ASSERT_TRUE(validate_predictor_checkpoint(ir, high_cp).ok());

        const std::array<PredictorCheckpoint, 1> cps = {high_cp};
        std::array<u8, 64> out{};
        out.fill(0xEEu);
        const BigInt target = pow2(32).add(BigInt(512)).value();
        // Without checkpoint -> Limit; with checkpoint -> Ok!
        EXPECT_EQ(read_range(ir, pred, target, out).code(), Code::Limit);
        ASSERT_TRUE(read_range_ex(ir, pred, target, out, EvalLimits{}, cps).ok());
        EXPECT_TRUE(std::all_of(out.begin(), out.end(), [](u8 x) { return x == 0u; }));
    }
}

TEST(C05Eval, PredictorSequentialStreamAndDagSharingCrossPrefixLimitInLinearTime) {
    // Stream a 12,000-byte predictor with block_bytes = 199 and predictor_prefix_max = 600:
    // rolling session state keeps gap == 0 across all ~61 chunks, so predictor_prefix_bytes == 0!
    Builder b;
    const u32 res = b.lfsr(0x80200003ull, 0xCAFE1234ull, BigInt(12000));
    const u32 p_stride = b.predictor(3, 37, res);
    // DAG-shared predictor used twice in Xor(p, INVERT8(p)) and Concat!
    const u32 inv = b.morph(p_stride, 2, 0);
    const u32 x = b.xor_node(p_stride, inv);  // identically 0xFF!
    const u32 cat = b.concat({p_stride, x});
    const Ir ir = b.finish(cat);

    EvalLimits lim;
    lim.block_bytes = 199;
    lim.predictor_prefix_max = BigInt(600);

    VecSink sink;
    EvalStats stats{};
    ASSERT_TRUE(eval_stream_ex(ir, sink, lim, &stats).ok());
    ASSERT_EQ(sink.bytes.size(), 24000u);
    EXPECT_EQ(stats.predictor_prefix_bytes, 0u);  // Zero quadratic re-scan!

    // Second half `Xor(p, NOT8(p))` must be all 0xFF bytes.
    for (std::size_t i = 12000; i < 24000; ++i) {
        ASSERT_EQ(sink.bytes[i], 0xFFu) << "i=" << i;
    }

    // Verify TermCursor with irregular chunk sizes matches byte-for-byte.
    TermCursor cur(ir, ir.root);
    std::vector<u8> cursor_bytes;
    std::size_t step = 1;
    while (!cur.at_end()) {
        std::vector<u8> tmp(step);
        auto n = cur.read(tmp);
        ASSERT_TRUE(n.ok());
        ASSERT_GT(n.value(), 0u);
        cursor_bytes.insert(cursor_bytes.end(), tmp.begin(),
                            tmp.begin() + static_cast<std::ptrdiff_t>(n.value()));
        step = (step * 7u + 13u) % 521u + 1u;
    }
    EXPECT_EQ(cursor_bytes, sink.bytes);
}

// ---------------------------------------------------------------------------
// 12. Sink error propagation & block-buffer invariance (E2-I8)
// ---------------------------------------------------------------------------

TEST(C05Eval, SinkPropagationAndBlockSizeInvariance) {
    Builder b;
    const u32 a = b.lfsr(0x80200003ull, 0x42ull, BigInt(10000));
    const u32 p = b.predictor(2, 0, a);
    const u32 m = b.morph(p, 4, 0);  // SWAP32
    const Ir ir = b.finish(m);

    // Block size 0 is invalid.
    {
        EvalLimits bad;
        bad.block_bytes = 0;
        EXPECT_EQ(eval_stream_digest(ir, bad).code(), Code::Invalid);
    }

    // Digest must be identical across wildly varying block sizes (E2-I8).
    const auto baseline = eval_stream_digest(ir);
    ASSERT_TRUE(baseline.ok());
    for (std::size_t blk :
         {std::size_t{1}, std::size_t{7}, std::size_t{64}, std::size_t{513},
          std::size_t{4096}, std::size_t{65536}, std::size_t{131072}}) {
        EvalLimits lim;
        lim.block_bytes = blk;
        VecSink s;
        ASSERT_TRUE(eval_stream_ex(ir, s, lim).ok());
        EXPECT_LE(s.max_chunk, blk);
        EXPECT_EQ(sha256_of(s.bytes), baseline.value().sha256) << "blk=" << blk;
    }

    // Sink failure aborts immediately and returns exact error code.
    {
        EvalLimits lim;
        lim.block_bytes = 256;
        VecSink fail_sink;
        fail_sink.fail_on_call = 4;
        fail_sink.fail_on_call_code = Code::Limit;
        EXPECT_EQ(eval_stream_ex(ir, fail_sink, lim).code(), Code::Limit);
        EXPECT_EQ(fail_sink.calls, 4u);
    }
}

// ---------------------------------------------------------------------------
// 13. Bounded memory & incremental SHA-256 on 64 MiB stream (O5.3, E2-I9)
// ---------------------------------------------------------------------------

TEST(C05Eval, LargeStreamIncrementalDigestUsesBoundedMemory) {
    // 64 MiB structured term combining Concat, Repeat, Interleave, Xor, Morph, Lfsr,
    // Affine, and Stride Predictor.
    Builder b;
    constexpr u64 kHalf = 32ull << 20;  // 32 MiB
    const u32 lf = b.lfsr(0x800000000000000Dull, 0xA5A5A5A55A5A5A5Aull, BigInt(kHalf));
    const u32 af = b.affine(17, 29, BigInt(kHalf));
    const u32 xr = b.xor_node(lf, af);
    const u32 sw = b.morph(xr, 5, 0);               // SWAP64 (32 MiB)
    const u32 pr = b.predictor(3, 64, af);          // STRIDE_DELTA s=64 (32 MiB)
    const Ir ir = b.finish(b.concat({sw, pr}));     // 64 MiB total

    const std::size_t rss_before = read_rss_kib();
    EvalStats stats{};
    auto dig = eval_stream_digest(ir, EvalLimits{}, &stats);
    const std::size_t rss_after = read_rss_kib();

    ASSERT_TRUE(dig.ok());
    EXPECT_EQ(dig.value().bytes, BigInt(64ull << 20));
    // Scratch is strictly bounded by one 64 KiB Xor buffer + 64-byte ring (<< 64 MiB!).
    EXPECT_LE(stats.peak_scratch_bytes, 128u * 1024u);
    if (rss_before != 0 && rss_after >= rss_before) {
        EXPECT_LE(rss_after - rss_before, 16u * 1024u);  // <= 16 MiB RSS delta for 64 MiB stream
    }
}

// ---------------------------------------------------------------------------
// 14. C04 CANON + C05 EVAL coherence (E2-I4)
// ---------------------------------------------------------------------------

TEST(C05Eval, CanonicalisationPreservesFullAndRangeEvaluation) {
    Builder b;
    // Construct a redex-heavy term exercising atom merge, zero merge, nested concat,
    // nested slice, involution cancel, rotation compose, self-xor, affine step=0,
    // single-child interleave, and common subexpression sharing.
    const u32 a1 = b.atom_node(b.add_atom(pattern(16, 5)));
    const u32 a2 = b.atom_node(b.add_atom(pattern(16, 9)));
    const u32 merged_atoms = b.concat({a1, b.empty(), a2});
    const u32 rot = b.morph(b.morph(merged_atoms, 6, 5), 6, 3);  // ROTL(8) -> identity
    const u32 rev2 = b.morph(b.morph(rot, 9, 0), 9, 0);          // double REVERSE_BITS -> id
    const u32 self_xor = b.xor_node(a1, a1);                     // -> Zero(16)
    const u32 aff_const = b.affine(0x5Au, 0u, BigInt(16));       // -> Repeat(Atom(0x5A), 16, 0)
    const u32 il1 = b.interleave({aff_const}, 4u);               // -> aff_const
    const u32 cat = b.concat({rev2, self_xor, b.zero(BigInt(8)), il1});
    const u32 sl = b.slice(b.slice(cat, BigInt(4), BigInt(60)), BigInt(3), BigInt(48));
    const Ir raw = b.finish(sl);

    auto can = canon(raw);
    ASSERT_TRUE(can.ok());
    ASSERT_TRUE(is_canonical(can.value()));

    const auto d_raw = eval_stream_digest(raw);
    const auto d_can = eval_stream_digest(can.value());
    ASSERT_TRUE(d_raw.ok());
    ASSERT_TRUE(d_can.ok());
    EXPECT_EQ(d_raw.value().sha256, d_can.value().sha256);
    EXPECT_EQ(d_raw.value().bytes, d_can.value().bytes);

    for (u64 s = 0; s <= 48; s += 5) {
        for (u64 l = 0; s + l <= 48; l += 7) {
            std::vector<u8> r_buf(static_cast<std::size_t>(l));
            std::vector<u8> c_buf(static_cast<std::size_t>(l));
            ASSERT_TRUE(read_range(raw, raw.root, BigInt(s), r_buf).ok());
            ASSERT_TRUE(read_range(can.value(), can.value().root, BigInt(s), c_buf).ok());
            EXPECT_EQ(r_buf, c_buf);
        }
    }
}

// ---------------------------------------------------------------------------
// 15. Reentrancy & multi-threaded determinism (E2-I2, E2-I12)
// ---------------------------------------------------------------------------

TEST(C05Eval, PreparedEvalIsThreadSafeAndDeterministic) {
    Builder b;
    const u32 lf = b.lfsr(0x80200003ull, 0x9988776655443322ull, BigInt(4096));
    const u32 pr = b.predictor(4, 23, lf);
    const u32 sw = b.morph(pr, 5, 0);
    const u32 rp = b.repeat(sw, BigInt(3), BigInt(128));  // 12,416 bytes
    const Ir ir = b.finish(rp);

    auto prep = PreparedEval::prepare(ir);
    ASSERT_TRUE(prep.ok());

    VecSink ref_sink;
    ASSERT_TRUE(prep.value().eval_stream(ref_sink).ok());
    const std::vector<u8>& truth = ref_sink.bytes;
    const auto truth_sha = sha256_of(truth);

    constexpr std::size_t kThreads = 8;
    std::vector<std::thread> pool;
    std::array<bool, kThreads> thread_ok{};
    thread_ok.fill(true);

    for (std::size_t tid = 0; tid < kThreads; ++tid) {
        pool.emplace_back([&, tid]() {
            std::mt19937_64 rng(0xC05E2A1ull + tid * 977ull);
            for (int iter = 0; iter < 40; ++iter) {
                const std::size_t s = rng() % truth.size();
                const std::size_t max_l = std::min<std::size_t>(truth.size() - s, 777u);
                const std::size_t l = rng() % (max_l + 1u);
                std::vector<u8> buf(l);
                auto r = prep.value().read_range(ir.root, BigInt(static_cast<u64>(s)), buf);
                if (!r.ok() || r.value() != l ||
                    !std::equal(buf.begin(), buf.end(),
                                truth.begin() + static_cast<std::ptrdiff_t>(s))) {
                    thread_ok[tid] = false;
                    return;
                }
            }
            HashingSink hs;
            if (!prep.value().eval_stream(hs).ok()) {
                thread_ok[tid] = false;
                return;
            }
            auto d = hs.finish();
            if (!d.ok() || d.value().sha256 != truth_sha) {
                thread_ok[tid] = false;
            }
        });
    }
    for (std::thread& t : pool) t.join();
    for (std::size_t tid = 0; tid < kThreads; ++tid) {
        EXPECT_TRUE(thread_ok[tid]) << "tid=" << tid;
    }
}

// ---------------------------------------------------------------------------
// 16. Resource budgets: max_scratch_bytes and max_work_bytes
// ---------------------------------------------------------------------------

TEST(C05Eval, ScratchAndWorkBudgetsReturnLimitCleanly) {
    Builder b;
    const u32 lf = b.lfsr(0x80200003ull, 1ull, BigInt(4096));
    const u32 pr = b.predictor(3, 512, lf);  // needs 512-byte ring
    const Ir ir = b.finish(pr);

    // Scratch budget smaller than stride window -> Code::Limit.
    {
        EvalLimits tight_scratch;
        tight_scratch.max_scratch_bytes = 128;
        EXPECT_EQ(eval_stream_digest(ir, tight_scratch).code(), Code::Limit);
    }

    // Work budget smaller than 4096 bytes -> Code::Limit.
    {
        EvalLimits tight_work;
        tight_work.max_work_bytes = 1024;
        EXPECT_EQ(eval_stream_digest(ir, tight_work).code(), Code::Limit);
    }
}

}  // namespace
}  // namespace marp::v2
