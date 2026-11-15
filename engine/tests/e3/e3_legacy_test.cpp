#include <mapr/e3/e3_legacy.hpp>

#include <mapr/e1_bigint.hpp>
#include <mapr/e1_crc32.hpp>
#include <mapr/e1_sha256.hpp>
#include <mapr/e2/e2_canon.hpp>
#include <mapr/e2/e2_eval.hpp>
#include <mapr/e2/e2_term.hpp>

#include "v1_test_vectors.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <random>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace marp::v2 {
namespace {

using test_v1::TestBitPacker;
using test_v1::TestChunkSpec;
using test_v1::TestContainerOptions;
using test_v1::assemble_v1_container;
using test_v1::make_raw_v1_container;
using test_v1::refresh_header_crc;
using test_v1::refresh_trailer_crc;
using test_v1::write_le16_at;
using test_v1::write_le32_at;

static_assert(noexcept(looks_like_v1(std::declval<Source&>())));
static_assert(noexcept(looks_like_v1(std::declval<std::span<const u8>>())));

[[nodiscard]] constexpr u8 bitrev8_ref(u8 x) noexcept {
    unsigned v = static_cast<unsigned>(x);
    v = ((v & 0x55u) << 1) | ((v & 0xAAu) >> 1);
    v = ((v & 0x33u) << 2) | ((v & 0xCCu) >> 2);
    v = ((v & 0x0Fu) << 4) | ((v & 0xF0u) >> 4);
    return static_cast<u8>(v & 0xFFu);
}

// Packs LSB-ordered bit vector (each entry 0 or 1) into MSB-first bytes.
[[nodiscard]] std::vector<u8> pack_bits_msb(const std::vector<u8>& bits) {
    const std::size_t n_bytes = (bits.size() + 7u) / 8u;
    std::vector<u8> out(n_bytes, 0u);
    for (std::size_t i = 0; i < bits.size(); ++i) {
        if (bits[i] != 0u) {
            out[i / 8u] |= static_cast<u8>(1u << (7u - (i % 8u)));
        }
    }
    return out;
}

[[nodiscard]] std::vector<u8> unpack_bytes_msb(std::span<const u8> bytes) {
    std::vector<u8> bits;
    bits.reserve(bytes.size() * 8u);
    for (u8 b : bytes) {
        for (int i = 7; i >= 0; --i) {
            bits.push_back(static_cast<u8>((b >> i) & 1u));
        }
    }
    return bits;
}

// Encodes an arbitrary <= 64-bit MSB bit vector as a POS-basis DualBasisAtom.
void emit_pos_atom_from_bits(TestBitPacker& bp, std::span<const u8> bits, bool include_b_prefix = true) {
    const int b = static_cast<int>(bits.size());
    u64 word = 0ULL;
    int w = 0;
    for (int i = 0; i < b; ++i) {
        if (bits[static_cast<std::size_t>(i)] != 0u) {
            word |= (1ULL << i);
            ++w;
        }
    }
    // Compute colex rank rho = sum_{j=1}^w C(p_j, j) via exact Pascal table (no u64 overflow).
    static constexpr auto kPascal = []() {
        std::array<std::array<u64, 65>, 65> c{};
        for (std::size_t n = 0; n <= 64; ++n) {
            c[n][0] = 1ULL;
            c[n][n] = 1ULL;
            for (std::size_t k = 1; k < n; ++k) {
                c[n][k] = c[n - 1][k - 1] + c[n - 1][k];
            }
        }
        return c;
    }();
    auto binom = [](int n, int k) -> u64 {
        if (k < 0 || n < 0 || n > 64 || k > n) return 0ULL;
        return kPascal[static_cast<std::size_t>(n)][static_cast<std::size_t>(k)];
    };
    u64 rho = 0ULL;
    int j = 1;
    for (int p = 0; p < b; ++p) {
        if (((word >> p) & 1ULL) != 0ULL) {
            rho += binom(p, j);
            ++j;
        }
    }
    const u64 comb = binom(b, w);
    if (include_b_prefix) {
        bp.atom(b, /*zheg=*/false, w, comb, rho);
    } else {
        bp.atom_fixed_b(b, /*zheg=*/false, w, comb, rho);
    }
}

void verify_ir_matches_bytes(const Ir& ir, std::span<const u8> expected) {
    EXPECT_TRUE(check_well_formed(ir).ok());
    EXPECT_TRUE(check_canonical(ir).ok());
    EXPECT_TRUE(is_canonical(ir));
    EXPECT_TRUE(verify_atom_digests(ir).ok());
    EXPECT_EQ(ir.total_length, mapr::BigInt(static_cast<u64>(expected.size())));

    auto denoted = denote_root(ir, static_cast<u64>(expected.size()) + 16ULL);
    ASSERT_TRUE(denoted.ok());
    EXPECT_EQ(denoted.value(), std::vector<u8>(expected.begin(), expected.end()));

    auto sha = eval_stream_digest(ir);
    ASSERT_TRUE(sha.ok());
    EXPECT_EQ(sha.value().sha256, test_v1::sha256_span(expected));
    EXPECT_EQ(sha.value().bytes, mapr::BigInt(static_cast<u64>(expected.size())));
}

// Spy Source proving looks_like_v1 inspects only the 8-byte prefix and never decodes.
class ProbeSpySource final : public Source {
public:
    ProbeSpySource(std::vector<u8> prefix, u64 reported_size, bool fail_beyond_8 = true)
        : prefix_(std::move(prefix)),
          reported_size_(reported_size),
          fail_beyond_8_(fail_beyond_8) {}

    u64 size() const noexcept override { return reported_size_; }

    WireCode read(u64 offset, std::span<u8> dst) override {
        ++read_calls;
        bytes_read += dst.size();
        if (fail_beyond_8_ && (offset + dst.size() > 8ULL)) {
            return WireCode::Io;
        }
        if (offset + dst.size() > prefix_.size()) {
            return WireCode::Invalid;
        }
        std::memcpy(dst.data(),
                    prefix_.data() + static_cast<std::size_t>(offset),
                    dst.size());
        return WireCode::Ok;
    }

    std::size_t read_calls = 0;
    std::size_t bytes_read = 0;

private:
    std::vector<u8> prefix_;
    u64 reported_size_;
    bool fail_beyond_8_;
};

class ThrowingSource final : public Source {
public:
    u64 size() const noexcept override { return 256ULL; }
    WireCode read(u64, std::span<u8>) override {
        throw std::runtime_error("simulated I/O exception");
    }
};

class FailingAtOffsetSource final : public Source {
public:
    FailingAtOffsetSource(std::span<const u8> data, u64 fail_at)
        : data_(data), fail_at_(fail_at) {}

    u64 size() const noexcept override { return static_cast<u64>(data_.size()); }

    WireCode read(u64 offset, std::span<u8> dst) override {
        if (offset + dst.size() > data_.size()) return WireCode::Invalid;
        if (offset <= fail_at_ && fail_at_ < offset + dst.size()) {
            return WireCode::Io;
        }
        std::memcpy(dst.data(), data_.data() + static_cast<std::size_t>(offset), dst.size());
        return WireCode::Ok;
    }

private:
    std::span<const u8> data_;
    u64 fail_at_;
};

// ============================================================================
// 1. looks_like_v1 probe tests
// ============================================================================

TEST(C08LegacyProbe, DistinguishesV1MagicFromV2AndOtherFormatsWithoutDecoding) {
    const std::array<u8, 8> v1_magic = {0x89u, 0x4Du, 0x41u, 0x50u, 0x52u, 0x0Du, 0x0Au, 0x1Au};
    const std::array<u8, 8> v2_magic = {0x89u, 0x4Du, 0x41u, 0x50u, 0x52u, 0x32u, 0x0Du, 0x0Au};
    const std::array<u8, 8> png_magic = {0x89u, 0x50u, 0x4Eu, 0x47u, 0x0Du, 0x0Au, 0x1Au, 0x0Au};
    const std::array<u8, 8> zip_magic = {0x50u, 0x4Bu, 0x03u, 0x04u, 0x14u, 0x00u, 0x00u, 0x00u};

    EXPECT_TRUE(looks_like_v1(v1_magic));
    EXPECT_FALSE(looks_like_v1(v2_magic));
    EXPECT_FALSE(looks_like_v1(png_magic));
    EXPECT_FALSE(looks_like_v1(zip_magic));
    EXPECT_FALSE(looks_like_v1(std::span<const u8>{}));

    for (std::size_t len = 0; len < 8u; ++len) {
        EXPECT_FALSE(looks_like_v1(std::span<const u8>(v1_magic.data(), len)));
    }

    for (std::size_t byte_i = 0; byte_i < 8u; ++byte_i) {
        for (int bit = 0; bit < 8; ++bit) {
            auto mutated = v1_magic;
            mutated[byte_i] ^= static_cast<u8>(1u << bit);
            EXPECT_FALSE(looks_like_v1(mutated));
        }
    }

    // Probe spy: virtual 1 GiB source where reading past byte 8 fails with Io.
    ProbeSpySource spy(
        std::vector<u8>(v1_magic.begin(), v1_magic.end()),
        1ULL << 30,
        /*fail_beyond_8=*/true);
    EXPECT_TRUE(looks_like_v1(spy));
    EXPECT_EQ(spy.read_calls, 1u);
    EXPECT_EQ(spy.bytes_read, 8u);

    ThrowingSource throwing_src;
    EXPECT_FALSE(looks_like_v1(throwing_src));
}

// ============================================================================
// 2. v1.0.1 core operators (opcodes 0..9, CHUNK_REF, streamed header, bitseq)
// ============================================================================

TEST(C08LegacyDecodeV1_0_1, EmptyZeroByteContainer) {
    const auto wire = make_raw_v1_container({}, /*version_minor=*/0u);
    EXPECT_TRUE(looks_like_v1(wire));

    HeapArena arena;
    auto res = decode_v1(wire, arena);
    ASSERT_TRUE(res.ok()) << res.error().what;
    verify_ir_matches_bytes(res.value(), {});
    ASSERT_EQ(res.value().nodes.size(), 1u);
    EXPECT_EQ(res.value().nodes[0].kind, Kind::Empty);
}

TEST(C08LegacyDecodeV1_0_1, DualBasisAtomPosAndZheg) {
    // Node 0: 8-bit POS atom for byte 0xA5 -> bits [1,0,1,0,0,1,0,1] -> word = 0xA5 (bitrev8(0xA5) = 0xA5).
    // Node 1: 8-bit ZHEG atom with ANF coefficients word = 0x0F; mobius_word64(0x0F, 8):
    //   step1 (b>=2): 0x0F ^ ((0x0F & 0x55) << 1) = 0x0F ^ 0x0A = 0x05
    //   step2 (b>=4): 0x05 ^ ((0x05 & 0x33) << 2) = 0x05 ^ 0x04 = 0x01
    //   step3 (b>=8): 0x01 ^ ((0x01 & 0x0F) << 4) = 0x11 -> MSB byte = bitrev8(0x11) = 0x88.
    // Node 2: CONCAT(0, 1) -> 16 bits = {0xA5, 0x88}.
    TestBitPacker bp;
    bp.varint(3ULL); // m = 3
    bp.varint(2ULL); // root = 2

    // Node 0: ATOM POS b=8
    bp.bits(1ULL, 4);
    const std::array<u8, 8> b0_bits = {1, 0, 1, 0, 0, 1, 0, 1};
    emit_pos_atom_from_bits(bp, b0_bits, true);

    // Node 1: ATOM ZHEG b=8, word=0x0F (positions 0,1,2,3 -> w=4, rho = C(0,1)+C(1,2)+C(2,3)+C(3,4) = 0)
    bp.bits(1ULL, 4);
    bp.atom(8, /*zheg=*/true, /*w=*/4, /*C(8,4)=*/70ULL, /*rho=*/0ULL);

    // Node 2: CONCAT d=2 (0, 1)
    bp.bits(3ULL, 4);
    bp.varint(0ULL); // raw_d = 0 -> d = 2
    bp.child_ref(2u, 0u);
    bp.child_ref(2u, 1u);

    const std::array<u8, 2> expected = {0xA5u, 0x88u};
    const auto wire = assemble_v1_container(
        {TestChunkSpec{16u, 1u, 0u, 0u, bp.finish()}}, expected, 16ULL);

    auto res = decode_v1(wire);
    ASSERT_TRUE(res.ok()) << res.error().what;
    verify_ir_matches_bytes(res.value(), expected);
}

TEST(C08LegacyDecodeV1_0_1, AtomSpanHomogeneousAndHeterogeneous) {
    // Build 11 bytes = 88 bits via homog ATOM_SPAN (64-bit body + 24-bit tail)
    // concatenated with 4 bytes = 32 bits via heterog ATOM_SPAN (3 + 5 + 11 + 13 = 32 bits).
    std::vector<u8> expected(15u);
    for (std::size_t i = 0; i < expected.size(); ++i) {
        expected[i] = static_cast<u8>(0x37u + i * 29u);
    }
    const auto all_bits = unpack_bytes_msb(expected);

    TestBitPacker bp;
    bp.varint(3ULL);
    bp.varint(2ULL);

    // Node 0: homog ATOM_SPAN cnt=2 (64 + 24 = 88 bits)
    bp.bits(2ULL, 4);
    bp.varint(2ULL);
    bp.bits(1ULL, 1);         // homog = 1
    bp.bits(24ULL - 1ULL, 6); // tail_b = 24
    emit_pos_atom_from_bits(bp, std::span<const u8>(all_bits.data(), 64u), false);
    emit_pos_atom_from_bits(bp, std::span<const u8>(all_bits.data() + 64u, 24u), false);

    // Node 1: heterog ATOM_SPAN cnt=4 (3 + 5 + 11 + 13 = 32 bits)
    bp.bits(2ULL, 4);
    bp.varint(4ULL);
    bp.bits(0ULL, 1); // homog = 0
    emit_pos_atom_from_bits(bp, std::span<const u8>(all_bits.data() + 88u, 3u), true);
    emit_pos_atom_from_bits(bp, std::span<const u8>(all_bits.data() + 91u, 5u), true);
    emit_pos_atom_from_bits(bp, std::span<const u8>(all_bits.data() + 96u, 11u), true);
    emit_pos_atom_from_bits(bp, std::span<const u8>(all_bits.data() + 107u, 13u), true);

    // Node 2: CONCAT(0, 1) -> 120 bits = 15 bytes
    bp.bits(3ULL, 4);
    bp.varint(0ULL);
    bp.child_ref(2u, 0u);
    bp.child_ref(2u, 1u);

    const auto wire = assemble_v1_container(
        {TestChunkSpec{120u, 1u, 0u, 0u, bp.finish()}}, expected, 120ULL);

    HeapArena arena;
    auto res = decode_v1(wire, arena);
    ASSERT_TRUE(res.ok()) << res.error().what;
    verify_ir_matches_bytes(res.value(), expected);
}

TEST(C08LegacyDecodeV1_0_1, RepeatOneMiBZerosAndSubByteMotifs) {
    // Case A: 1 MiB of zeros encoded as 1-bit 0 repeated 8,388,608 times (like SPECS.md §3 299B fixture).
    {
        TestBitPacker bp;
        bp.varint(2ULL);
        bp.varint(1ULL);
        // Node 0: 1-bit zero atom
        bp.bits(1ULL, 4);
        bp.atom(1, false, 0, 1ULL, 0ULL);
        // Node 1: REPEAT(child=0, q=8388608, r=0)
        bp.bits(4ULL, 4);
        bp.child_ref(1u, 0u);
        bp.varint(8'388'608ULL - 1ULL);
        bp.varint(0ULL);

        std::vector<u8> zeros(1'048'576u, 0u);
        TestContainerOptions opt{};
        opt.l_max = 8'388'608u;
        const auto wire = assemble_v1_container(
            {TestChunkSpec{8'388'608u, 1u, 0u, 0u, bp.finish()}}, zeros, 8'388'608ULL, opt);
        EXPECT_LE(wire.size(), 320u);

        auto res = decode_v1(wire);
        ASSERT_TRUE(res.ok()) << res.error().what;
        ASSERT_EQ(res.value().nodes.size(), 1u);
        EXPECT_EQ(res.value().nodes[0].kind, Kind::Zero);
        EXPECT_TRUE(res.value().atoms.empty());
        verify_ir_matches_bytes(res.value(), zeros);
    }

    // Case B: 5-bit motif [1, 0, 1, 1, 0] repeated q=6, r=2 -> 32 bits = 4 bytes!
    {
        const std::array<u8, 5> motif = {1, 0, 1, 1, 0};
        std::vector<u8> full_bits;
        for (int q = 0; q < 6; ++q) {
            full_bits.insert(full_bits.end(), motif.begin(), motif.end());
        }
        full_bits.push_back(motif[0]);
        full_bits.push_back(motif[1]);
        const auto expected = pack_bits_msb(full_bits);

        TestBitPacker bp;
        bp.varint(2ULL);
        bp.varint(1ULL);
        bp.bits(1ULL, 4);
        emit_pos_atom_from_bits(bp, motif, true);
        bp.bits(4ULL, 4);
        bp.child_ref(1u, 0u);
        bp.varint(6ULL - 1ULL);
        bp.varint(2ULL);

        const auto wire = assemble_v1_container(
            {TestChunkSpec{32u, 1u, 0u, 0u, bp.finish()}}, expected, 32ULL);
        auto res = decode_v1(wire);
        ASSERT_TRUE(res.ok()) << res.error().what;
        verify_ir_matches_bytes(res.value(), expected);
    }

    // Case C: 3-bit motif [1, 0, 1] repeated q=80, r=0 -> 240 bits = 30 bytes (lifts to Repeat of 3B tile).
    {
        const std::array<u8, 3> motif = {1, 0, 1};
        std::vector<u8> full_bits;
        for (int q = 0; q < 80; ++q) {
            full_bits.insert(full_bits.end(), motif.begin(), motif.end());
        }
        const auto expected = pack_bits_msb(full_bits);

        TestBitPacker bp;
        bp.varint(2ULL);
        bp.varint(1ULL);
        bp.bits(1ULL, 4);
        emit_pos_atom_from_bits(bp, motif, true);
        bp.bits(4ULL, 4);
        bp.child_ref(1u, 0u);
        bp.varint(80ULL - 1ULL);
        bp.varint(0ULL);

        const auto wire = assemble_v1_container(
            {TestChunkSpec{240u, 1u, 0u, 0u, bp.finish()}}, expected, 240ULL);
        auto res = decode_v1(wire);
        ASSERT_TRUE(res.ok()) << res.error().what;
        EXPECT_EQ(res.value().nodes.back().kind, Kind::Repeat);
        verify_ir_matches_bytes(res.value(), expected);
    }
}

TEST(C08LegacyDecodeV1_0_1, SliceMorphAndXorDiffAllPaths) {
    // Base 8 bytes = 64 bits
    const std::array<u8, 8> base_bytes = {0x12u, 0x34u, 0xABu, 0xCDu, 0xEFu, 0x01u, 0x80u, 0x7Fu};
    const std::array<u8, 8> delta_bytes = {0x00u, 0xFFu, 0x00u, 0x55u, 0xAAu, 0x01u, 0x80u, 0x00u};
    const auto base_bits = unpack_bytes_msb(base_bytes);
    const auto delta_bits = unpack_bytes_msb(delta_bytes);

    // Expected pieces:
    // - aligned slice [16..48) -> bytes [2..6) = {0xAB, 0xCD, 0xEF, 0x01}
    // - unaligned slice [3..27) -> 24 bits = 3 bytes
    // - MORPH ID, NOT, REV, REV_NOT on base_bytes (4 * 8 = 32 bytes)
    // - XOR_DIFF(base, delta) (8 bytes)
    std::vector<u8> expected;
    expected.insert(expected.end(), base_bytes.begin() + 2, base_bytes.begin() + 6);
    {
        std::vector<u8> unaligned(base_bits.begin() + 3, base_bits.begin() + 27);
        const auto ub = pack_bits_msb(unaligned);
        expected.insert(expected.end(), ub.begin(), ub.end());
    }
    // ID
    expected.insert(expected.end(), base_bytes.begin(), base_bytes.end());
    // NOT
    for (u8 b : base_bytes) expected.push_back(static_cast<u8>(~b));
    // REV (reverse bytes + bitrev8 each)
    for (std::size_t i = 0; i < 8u; ++i) {
        expected.push_back(bitrev8_ref(base_bytes[7u - i]));
    }
    // REV_NOT
    for (std::size_t i = 0; i < 8u; ++i) {
        expected.push_back(static_cast<u8>(~bitrev8_ref(base_bytes[7u - i])));
    }
    // XOR
    for (std::size_t i = 0; i < 8u; ++i) {
        expected.push_back(static_cast<u8>(base_bytes[i] ^ delta_bytes[i]));
    }

    TestBitPacker bp;
    bp.varint(10ULL); // m = 10
    bp.varint(9ULL);  // root = 9

    // 0: base atom (64 bits)
    bp.bits(1ULL, 4);
    emit_pos_atom_from_bits(bp, base_bits, true);
    // 1: delta atom (64 bits)
    bp.bits(1ULL, 4);
    emit_pos_atom_from_bits(bp, delta_bits, true);
    // 2: aligned SLICE(0, 16, 32)
    bp.bits(5ULL, 4);
    bp.child_ref(2u, 0u);
    bp.varint(16ULL);
    bp.varint(32ULL - 1ULL);
    // 3: unaligned SLICE(0, 3, 24)
    bp.bits(5ULL, 4);
    bp.child_ref(3u, 0u);
    bp.varint(3ULL);
    bp.varint(24ULL - 1ULL);
    // 4..7: MORPH(0, mu=0..3)
    for (u32 mu = 0u; mu < 4u; ++mu) {
        bp.bits(6ULL, 4);
        bp.child_ref(4u + mu, 0u);
        bp.bits(mu, 2);
    }
    // 8: XOR_DIFF(0, 1)
    bp.bits(7ULL, 4);
    bp.child_ref(8u, 0u);
    bp.child_ref(8u, 1u);
    // 9: CONCAT(2, 3, 4, 5, 6, 7, 8) -> d = 7
    bp.bits(3ULL, 4);
    bp.varint(7ULL - 2ULL);
    for (u32 u = 2u; u <= 8u; ++u) {
        bp.child_ref(9u, u);
    }

    const u32 total_bits = static_cast<u32>(expected.size() * 8u);
    const auto wire = assemble_v1_container(
        {TestChunkSpec{total_bits, 1u, 0u, 0u, bp.finish()}}, expected, total_bits);

    auto res = decode_v1(wire);
    ASSERT_TRUE(res.ok()) << res.error().what;
    verify_ir_matches_bytes(res.value(), expected);
}

TEST(C08LegacyDecodeV1_0_1, InterleaveAllStridesAndLfsrLifting) {
    // Test INTERLEAVE across all 4 strides {8, 16, 32, 64}.
    for (int sc = 0; sc < 4; ++sc) {
        const std::size_t stride = static_cast<std::size_t>(8u << sc);
        const std::size_t lane_len = 5u;
        std::vector<std::vector<u8>> lanes(stride, std::vector<u8>(lane_len, 0u));
        std::vector<u8> interleaved_bits(stride * lane_len, 0u);
        for (std::size_t j = 0; j < stride; ++j) {
            for (std::size_t k = 0; k < lane_len; ++k) {
                const u8 bit = static_cast<u8>(((j * 7u + k * 3u + 1u) % 3u == 0u) ? 1u : 0u);
                lanes[j][k] = bit;
                interleaved_bits[k * stride + j] = bit;
            }
        }
        const auto expected = pack_bits_msb(interleaved_bits);

        TestBitPacker bp;
        const u64 m = static_cast<u64>(stride + 1u);
        bp.varint(m);
        bp.varint(m - 1ULL);
        for (std::size_t j = 0; j < stride; ++j) {
            bp.bits(1ULL, 4);
            emit_pos_atom_from_bits(bp, lanes[j], true);
        }
        bp.bits(8ULL, 4); // INTERLEAVE
        bp.bits(static_cast<u64>(sc), 2);
        for (std::size_t j = 0; j < stride; ++j) {
            bp.child_ref(static_cast<u32>(stride), static_cast<u32>(j));
        }

        const u32 total_bits = static_cast<u32>(interleaved_bits.size());
        const auto wire = assemble_v1_container(
            {TestChunkSpec{total_bits, 1u, 0u, 0u, bp.finish()}}, expected, total_bits);
        auto res = decode_v1(wire);
        ASSERT_TRUE(res.ok()) << "sc=" << sc << ": " << res.error().what;
        verify_ir_matches_bytes(res.value(), expected);
    }

    // Test LFSR degree 17 with highest tap active (c_L = 1 -> lifts to native v2 Kind::Lfsr)
    // and degree 9 with highest tap 0 (falls back cleanly to exact Atom bytes).
    for (bool top_tap_active : {true, false}) {
        const int deg = top_tap_active ? 17 : 9;
        const u64 conn = top_tap_active ? ((1ULL << 16) | (1ULL << 2) | 1ULL) : 0x05ULL;
        const u64 init = top_tap_active ? 0x15A3BULL : 0x137ULL;
        const u64 bit_len = 512ULL;

        // Reference v1 LFSR evaluation
        const u64 mask = (1ULL << deg) - 1ULL;
        std::vector<u8> bits(static_cast<std::size_t>(bit_len), 0u);
        u64 state = 0ULL;
        for (int i = 0; i < deg; ++i) {
            const u8 b = static_cast<u8>((init >> i) & 1ULL);
            bits[static_cast<std::size_t>(i)] = b;
            state = ((state << 1) | b) & mask;
        }
        for (u64 t = static_cast<u64>(deg); t < bit_len; ++t) {
            const u64 fb = static_cast<u64>(std::popcount(state & conn) & 1);
            bits[static_cast<std::size_t>(t)] = static_cast<u8>(fb);
            state = ((state << 1) | fb) & mask;
        }
        const auto expected = pack_bits_msb(bits);

        TestBitPacker bp;
        bp.varint(1ULL);
        bp.varint(0ULL);
        bp.bits(9ULL, 4); // LFSR
        bp.bits(static_cast<u64>(deg - 1), 6);
        bp.bits(conn, deg);
        bp.bits(init, deg);
        bp.varint(bit_len);

        const auto wire = assemble_v1_container(
            {TestChunkSpec{static_cast<u32>(bit_len), 1u, 0u, 0u, bp.finish()}},
            expected,
            bit_len);
        auto res = decode_v1(wire);
        ASSERT_TRUE(res.ok()) << res.error().what;
        if (top_tap_active) {
            EXPECT_EQ(res.value().nodes.back().kind, Kind::Lfsr);
        }
        verify_ir_matches_bytes(res.value(), expected);
    }
}

TEST(C08LegacyDecodeV1_0_1, MultiChunkUnalignedCutsChunkRefsStreamedHeaderAndBitseqAligned) {
    // 6 superchunks:
    //   chunk 0: 19 bits (unaligned cut!)
    //   chunk 1: 45 bits (19 + 45 = 64 bits = 8 bytes aligned!)
    //   chunk 2: 64 bits EXPLICIT_DAG
    //   chunk 3: 64 bits CHUNK_REF(target=2, V4=NOT)
    //   chunk 4: 64 bits CHUNK_REF(target=2, V4=REV)
    //   chunk 5: 64 bits CHUNK_REF(target=2, V4=REV_NOT)
    std::mt19937_64 rng(0xC081E6ACULL);
    auto rand_bits = [&](std::size_t n) {
        std::vector<u8> b(n);
        for (std::size_t i = 0; i < n; ++i) b[i] = static_cast<u8>(rng() & 1ULL);
        return b;
    };

    const auto c0_bits = rand_bits(19u);
    const auto c1_bits = rand_bits(45u);
    const auto c2_bits = rand_bits(64u);

    auto make_atom_dag = [](std::span<const u8> bits) {
        TestBitPacker bp;
        bp.varint(1ULL);
        bp.varint(0ULL);
        bp.bits(1ULL, 4);
        emit_pos_atom_from_bits(bp, bits, true);
        return bp.finish();
    };

    std::vector<u8> all_bits;
    all_bits.insert(all_bits.end(), c0_bits.begin(), c0_bits.end());
    all_bits.insert(all_bits.end(), c1_bits.begin(), c1_bits.end());
    all_bits.insert(all_bits.end(), c2_bits.begin(), c2_bits.end());
    // NOT(c2)
    for (u8 b : c2_bits) all_bits.push_back(static_cast<u8>(b ^ 1u));
    // REV(c2)
    for (std::size_t i = 0; i < c2_bits.size(); ++i) {
        all_bits.push_back(c2_bits[c2_bits.size() - 1u - i]);
    }
    // REV_NOT(c2)
    for (std::size_t i = 0; i < c2_bits.size(); ++i) {
        all_bits.push_back(static_cast<u8>(c2_bits[c2_bits.size() - 1u - i] ^ 1u));
    }

    const auto expected = pack_bits_msb(all_bits);
    const std::vector<TestChunkSpec> chunks = {
        TestChunkSpec{19u, 1u, 0u, 0u, make_atom_dag(c0_bits)},
        TestChunkSpec{45u, 1u, 0u, 0u, make_atom_dag(c1_bits)},
        TestChunkSpec{64u, 1u, 0u, 0u, make_atom_dag(c2_bits)},
        TestChunkSpec{64u, 0u, 1u, 2u, {}},
        TestChunkSpec{64u, 0u, 2u, 2u, {}},
        TestChunkSpec{64u, 0u, 3u, 2u, {}},
    };

    // Test 1: FLAG_STREAMED_HEADER = true, FLAG_RAW_BYTES_MSB = true
    {
        TestContainerOptions opt{};
        opt.streamed_header = true;
        opt.raw_bytes_msb = true;
        const auto wire = assemble_v1_container(chunks, expected, 320ULL, opt);
        HeapArena arena;
        auto res = decode_v1(wire, arena);
        ASSERT_TRUE(res.ok()) << res.error().what;
        verify_ir_matches_bytes(res.value(), expected);
    }

    // Test 2: FLAG_RAW_BYTES_MSB = false (byte-aligned --bitseq mode)
    {
        TestContainerOptions opt{};
        opt.streamed_header = false;
        opt.raw_bytes_msb = false;
        const auto wire = assemble_v1_container(chunks, expected, 320ULL, opt);
        auto res = decode_v1(wire);
        ASSERT_TRUE(res.ok()) << res.error().what;
        verify_ir_matches_bytes(res.value(), expected);
    }
}

// ============================================================================
// 3. v1.1 additive features & Unsupported legacy feature/version paths
// ============================================================================

TEST(C08LegacyDecodeV1_1, RawNodeSupportedInV1_1AndStage2V1_0IncludingSubByteConcat) {
    std::vector<u8> payload(257u);
    for (std::size_t i = 0; i < payload.size(); ++i) {
        payload[i] = static_cast<u8>((i * 131u + 17u) & 0xFFu);
    }

    // Strict v1.1 (version 1.1)
    {
        const auto wire = make_raw_v1_container(payload, /*version_minor=*/1u);
        auto res = decode_v1(wire);
        ASSERT_TRUE(res.ok()) << res.error().what;
        verify_ir_matches_bytes(res.value(), payload);
    }

    // Stage 2 compatibility (version 1.0 + opcode 10 RAW)
    {
        const auto wire = make_raw_v1_container(payload, /*version_minor=*/0u);
        auto res = decode_v1(wire);
        ASSERT_TRUE(res.ok()) << res.error().what;
        verify_ir_matches_bytes(res.value(), payload);
    }

    // Sub-byte RAW nodes (5 bits + 11 bits = 16 bits) joined by CONCAT in v1.1
    {
        // RAW0: byte 0xB0, bit_len 5 -> bits [1, 0, 1, 1, 0]
        // RAW1: bytes {0xD4, 0x80}, bit_len 11 -> bits [1,1,0,1,0,1,0,0, 1,0,0]
        const std::vector<u8> expected_bits = {
            1, 0, 1, 1, 0,
            1, 1, 0, 1, 0, 1, 0, 0, 1, 0, 0};
        const auto expected = pack_bits_msb(expected_bits);

        TestBitPacker bp;
        bp.varint(3ULL);
        bp.varint(2ULL);
        // Node 0: RAW 1 byte, 5 bits
        bp.bits(10ULL, 4);
        bp.varint(1ULL);
        bp.bits(0xB0u, 8);
        bp.varint(5ULL);
        // Node 1: RAW 2 bytes, 11 bits
        bp.bits(10ULL, 4);
        bp.varint(2ULL);
        bp.bits(0xD4u, 8);
        bp.bits(0x80u, 8);
        bp.varint(11ULL);
        // Node 2: CONCAT(0, 1)
        bp.bits(3ULL, 4);
        bp.varint(0ULL);
        bp.child_ref(2u, 0u);
        bp.child_ref(2u, 1u);

        TestContainerOptions opt{};
        opt.version_minor = 1u;
        const auto wire = assemble_v1_container(
            {TestChunkSpec{16u, 1u, 0u, 0u, bp.finish()}}, expected, 16ULL, opt);
        auto res = decode_v1(wire);
        ASSERT_TRUE(res.ok()) << res.error().what;
        verify_ir_matches_bytes(res.value(), expected);
    }
}

TEST(C08LegacyUnsupported, RejectsUnsupportedVersionsAndFeaturesWithoutApproximation) {
    const std::array<u8, 4> sample = {0xDEu, 0xADu, 0xBEu, 0xEFu};

    // 1. Future / unsupported legacy versions with valid v1 magic & CRC -> Unsupported
    for (const auto& [maj, min] : std::array<std::pair<u16, u16>, 4>{{
             {1u, 2u}, {1u, 99u}, {2u, 0u}, {3u, 1u}}}) {
        auto wire = make_raw_v1_container(sample, /*version_minor=*/1u);
        write_le16_at(wire.data() + 8, maj);
        write_le16_at(wire.data() + 10, min);
        refresh_header_crc(wire);
        EXPECT_TRUE(looks_like_v1(wire));
        auto res = decode_v1(wire);
        EXPECT_FALSE(res.ok());
        EXPECT_EQ(res.code(), WireCode::Unsupported)
            << "version " << maj << "." << min << " got " << wire_code_name(res.code());
    }

    // Version 0.x -> Invalid (never existed)
    {
        auto wire = make_raw_v1_container(sample, 0u);
        write_le16_at(wire.data() + 8, 0u);
        write_le16_at(wire.data() + 10, 1u);
        refresh_header_crc(wire);
        EXPECT_EQ(decode_v1(wire).code(), WireCode::Invalid);
    }

    // 2. Opcode 11 (DEDUP_REF) in valid v1.1 container -> Unsupported
    {
        TestBitPacker bp;
        bp.varint(1ULL);
        bp.varint(0ULL);
        bp.bits(11ULL, 4); // DEDUP_REF
        bp.varint(42ULL);  // ref_id = 42
        TestContainerOptions opt{};
        opt.version_minor = 1u;
        const auto wire = assemble_v1_container(
            {TestChunkSpec{32u, 1u, 0u, 0u, bp.finish()}}, sample, 32ULL, opt);
        auto res = decode_v1(wire);
        EXPECT_FALSE(res.ok());
        EXPECT_EQ(res.code(), WireCode::Unsupported);
    }

    // 3. Opcode 12 (DEFLATE_HINT) in valid v1.1 container -> Unsupported
    {
        TestBitPacker bp;
        bp.varint(1ULL);
        bp.varint(0ULL);
        bp.bits(12ULL, 4); // DEFLATE_HINT
        bp.bits(0x08u, 8);
        bp.bits(0x00u, 8);
        bp.bits(0x5678ULL, 16);
        bp.bits(0x02u, 8);
        bp.bits(0x03u, 8);
        TestContainerOptions opt{};
        opt.version_minor = 1u;
        const auto wire = assemble_v1_container(
            {TestChunkSpec{32u, 1u, 0u, 0u, bp.finish()}}, sample, 32ULL, opt);
        auto res = decode_v1(wire);
        EXPECT_FALSE(res.ok());
        EXPECT_EQ(res.code(), WireCode::Unsupported);
    }

    // 4. Non-byte-aligned v1 bitseq container (FLAG_RAW_BYTES_MSB=0, total_bits=19) -> Unsupported
    {
        const std::vector<u8> bits19 = {
            1, 0, 1, 1, 0, 0, 1, 0,
            1, 1, 1, 0, 0, 1, 0, 1,
            1, 0, 1};
        const auto padded = pack_bits_msb(bits19);
        TestBitPacker bp;
        bp.varint(1ULL);
        bp.varint(0ULL);
        bp.bits(1ULL, 4);
        emit_pos_atom_from_bits(bp, bits19, true);

        TestContainerOptions opt{};
        opt.raw_bytes_msb = false;
        const auto wire = assemble_v1_container(
            {TestChunkSpec{19u, 1u, 0u, 0u, bp.finish()}}, padded, 19ULL, opt);
        auto res = decode_v1(wire);
        EXPECT_FALSE(res.ok());
        EXPECT_EQ(res.code(), WireCode::Unsupported);

        // If trailer SHA-256 of that sub-byte bitseq container is corrupt, Mismatch wins first!
        auto bad_sha_wire = wire;
        bad_sha_wire[bad_sha_wire.size() - 72u + 32u] ^= 0x01u;
        refresh_trailer_crc(bad_sha_wire);
        EXPECT_EQ(decode_v1(bad_sha_wire).code(), WireCode::Mismatch);
    }
}

// ============================================================================
// 4. Malformed, truncated, CRC/digest mismatch, and 1,000-mutation fuzz suite
// ============================================================================

TEST(C08LegacyMalformed, RejectsTruncationsCrcsNonCanonicalBitstreamsAndBadConfigs) {
    const std::array<u8, 8> payload = {1, 2, 3, 4, 5, 6, 7, 8};
    const auto valid_wire = make_raw_v1_container(payload, 1u);

    // v2 wire magic rejected by decode_v1 with Invalid
    {
        std::vector<u8> fake_v2(256u, 0u);
        const std::array<u8, 8> v2m = {0x89u, 0x4Du, 0x41u, 0x50u, 0x52u, 0x32u, 0x0Du, 0x0Au};
        std::memcpy(fake_v2.data(), v2m.data(), 8u);
        EXPECT_EQ(decode_v1(fake_v2).code(), WireCode::Invalid);
    }

    // Every truncation prefix returns Invalid (never Limit)
    for (std::size_t cut : {std::size_t{0}, std::size_t{1}, std::size_t{7},
                            std::size_t{8}, std::size_t{63}, std::size_t{64},
                            std::size_t{191}, std::size_t{192},
                            valid_wire.size() - 73u, valid_wire.size() - 1u}) {
        const auto res = decode_v1(std::span<const u8>(valid_wire.data(), cut));
        EXPECT_EQ(res.code(), WireCode::Invalid) << "cut=" << cut;
    }

    // Corrupt header CRC, MCHK CRC, INDX CRC, TRLR CRC -> Invalid
    {
        auto w = valid_wire;
        w[60] ^= 0xFFu;
        EXPECT_EQ(decode_v1(w).code(), WireCode::Invalid);
    }
    {
        auto w = valid_wire;
        w[64 + 28] ^= 0xFFu;
        EXPECT_EQ(decode_v1(w).code(), WireCode::Invalid);
    }
    {
        auto w = valid_wire;
        w[w.size() - 72u - 1u] ^= 0xFFu;
        EXPECT_EQ(decode_v1(w).code(), WireCode::Invalid);
    }
    {
        auto w = valid_wire;
        w[w.size() - 1u] ^= 0xFFu;
        EXPECT_EQ(decode_v1(w).code(), WireCode::Invalid);
    }

    // Tampered trailer SHA-256 with recomputed trailer CRC -> Mismatch
    {
        auto w = valid_wire;
        w[w.size() - 72u + 35u] ^= 0x80u;
        refresh_trailer_crc(w);
        EXPECT_EQ(decode_v1(w).code(), WireCode::Mismatch);
    }

    // Bad StreamConfig bounds -> Invalid
    {
        TestContainerOptions bad = {};
        bad.w_sync = 32u;
        EXPECT_EQ(decode_v1(assemble_v1_container(
                                {TestChunkSpec{64u, 1u, 0u, 0u, {1, 0}}}, payload, 64ULL, bad))
                      .code(),
                  WireCode::Invalid);
    }
    {
        TestContainerOptions bad = {};
        bad.l_max = 16'777'217u; // > normative 16,777,216
        EXPECT_EQ(decode_v1(assemble_v1_container(
                                {TestChunkSpec{64u, 1u, 0u, 0u, {1, 0}}}, payload, 64ULL, bad))
                      .code(),
                  WireCode::Invalid);
    }

    // Unknown DAG opcodes 13, 14, 15 -> Invalid
    for (u64 op : {13ULL, 14ULL, 15ULL}) {
        TestBitPacker bp;
        bp.varint(1ULL);
        bp.varint(0ULL);
        bp.bits(op, 4);
        const auto w = assemble_v1_container(
            {TestChunkSpec{64u, 1u, 0u, 0u, bp.finish()}}, payload, 64ULL);
        EXPECT_EQ(decode_v1(w).code(), WireCode::Invalid) << "op=" << op;
    }

    // Non-canonical overlong ULEB128 for m (0x81, 0x00) -> Invalid
    {
        const std::vector<u8> overlong_dag = {0x81u, 0x00u, 0x00u, 0x00u};
        const auto w = assemble_v1_container(
            {TestChunkSpec{0u, 1u, 0u, 0u, overlong_dag}}, {}, 0ULL);
        EXPECT_EQ(decode_v1(w).code(), WireCode::Invalid);
    }

    // Extra trailing zero byte in MCHK payload -> Invalid
    {
        TestBitPacker bp;
        bp.varint(1ULL);
        bp.varint(0ULL);
        bp.bits(0ULL, 4);
        auto dag_bytes = bp.finish();
        dag_bytes.push_back(0x00u);
        const auto w = assemble_v1_container(
            {TestChunkSpec{0u, 1u, 0u, 0u, dag_bytes}}, {}, 0ULL);
        EXPECT_EQ(decode_v1(w).code(), WireCode::Invalid);
    }

    // Non-canonical b=64 atom prefix (is64=0 followed by b-1=63 instead of is64=1) -> Invalid
    {
        TestBitPacker bp;
        bp.varint(1ULL);
        bp.varint(0ULL);
        bp.bits(1ULL, 4);  // ATOM
        bp.bits(0ULL, 1);  // is64 = 0 (non-canonical for b=64)
        bp.bits(63ULL, 6); // b - 1 = 63
        bp.bits(0ULL, 1);  // POS basis
        bp.trunc_bin(0ULL, 65ULL); // w = 0
        const std::array<u8, 8> zero8{};
        const auto w = assemble_v1_container(
            {TestChunkSpec{64u, 1u, 0u, 0u, bp.finish()}}, zero8, 64ULL);
        EXPECT_EQ(decode_v1(w).code(), WireCode::Invalid);
    }
}

TEST(C08LegacyMalformed, DeterministicOneThousandAdversarialMutationsRejected) {
    std::vector<u8> p0(64u), p1(64u);
    for (std::size_t i = 0; i < 64u; ++i) {
        p0[i] = static_cast<u8>(i * 3u + 1u);
        p1[i] = static_cast<u8>(~(i * 3u + 1u));
    }
    TestBitPacker bp;
    bp.varint(1ULL);
    bp.varint(0ULL);
    bp.bits(10ULL, 4);
    bp.varint(64ULL);
    for (u8 b : p0) bp.bits(b, 8);
    bp.varint(512ULL);

    std::vector<u8> full;
    full.insert(full.end(), p0.begin(), p0.end());
    full.insert(full.end(), p1.begin(), p1.end());

    TestContainerOptions opt{};
    opt.version_minor = 1u;
    const auto base = assemble_v1_container(
        {TestChunkSpec{512u, 1u, 0u, 0u, bp.finish()},
         TestChunkSpec{512u, 0u, 1u, 0u, {}}},
        full,
        1024ULL,
        opt);
    ASSERT_TRUE(decode_v1(base).ok());

    std::mt19937_64 rng(0xF022C08ULL);
    int rejected = 0;
    for (int iter = 0; iter < 1000; ++iter) {
        std::vector<u8> mut = base;
        const int mode = iter % 4;
        if (mode == 0) {
            // Single bit flip anywhere in container (every bit of header, MCHK, INDX, TRLR is covered!)
            const std::size_t pos = static_cast<std::size_t>(rng() % mut.size());
            const u8 bit = static_cast<u8>(1u << (rng() % 8u));
            mut[pos] ^= bit;
        } else if (mode == 1) {
            // Random truncation
            const std::size_t cut = static_cast<std::size_t>(rng() % mut.size());
            mut.resize(cut);
        } else if (mode == 2) {
            // Multi-byte overwrite
            const std::size_t pos = static_cast<std::size_t>(rng() % mut.size());
            for (std::size_t k = 0; k < 4u && pos + k < mut.size(); ++k) {
                mut[pos + k] ^= static_cast<u8>((rng() & 0xFEULL) | 1ULL);
            }
        } else {
            // Append trailing garbage
            mut.push_back(static_cast<u8>(rng() & 0xFFULL));
        }

        auto res = decode_v1(mut);
        if (!res.ok()) {
            ++rejected;
        }
    }
    EXPECT_EQ(rejected, 1000);
}

// ============================================================================
// 5. Arena ownership, LegacyLimits, Source I/O errors, and deep iterative DAGs
// ============================================================================

TEST(C08LegacyLimitsAndArena, EnforcesArenaCapLegacyLimitsIoErrorsAndDeepChain) {
    std::vector<u8> payload(128u);
    for (std::size_t i = 0; i < payload.size(); ++i) {
        payload[i] = static_cast<u8>(i ^ 0x5Au);
    }
    const auto wire = make_raw_v1_container(payload, 1u);

    // Arena stores atom payload with zero Atom::owner heap vector
    {
        HeapArena arena(1024u);
        auto res = decode_v1(wire, arena);
        ASSERT_TRUE(res.ok());
        ASSERT_EQ(res.value().atoms.size(), 1u);
        EXPECT_EQ(res.value().atoms[0].owner, nullptr);
        EXPECT_EQ(arena.used_bytes(), 128u);
        verify_ir_matches_bytes(res.value(), payload);
    }

    // Tight Arena cap -> Limit
    {
        HeapArena tiny_arena(64u);
        auto res = decode_v1(wire, tiny_arena);
        EXPECT_EQ(res.code(), WireCode::Limit);
    }

    // LegacyLimits::max_output_bytes -> Limit
    {
        LegacyLimits lim{};
        lim.max_output_bytes = 64ULL;
        EXPECT_EQ(decode_v1(wire, lim).code(), WireCode::Limit);
    }

    // LegacyLimits::max_chunks -> Limit
    {
        LegacyLimits lim{};
        lim.max_chunks = 0ULL;
        EXPECT_EQ(decode_v1(wire, lim).code(), WireCode::Limit);
    }

    // LegacyLimits::max_chunk_payload_bytes -> Limit
    {
        LegacyLimits lim{};
        lim.max_chunk_payload_bytes = 4ULL;
        EXPECT_EQ(decode_v1(wire, lim).code(), WireCode::Limit);
    }

    // Source I/O failures at header, MCHK, INDX, and TRLR offsets -> Io
    for (u64 fail_off : {u64{0}, u64{70}, u64{wire.size() - 80u}, u64{wire.size() - 10u}}) {
        FailingAtOffsetSource io_src(wire, fail_off);
        EXPECT_EQ(decode_v1(io_src).code(), WireCode::Io) << "fail_off=" << fail_off;
    }

    // Deep 512-node linear MORPH chain evaluates iteratively without stack overflow
    {
        std::vector<u8> seed(32u);
        for (std::size_t i = 0; i < seed.size(); ++i) {
            seed[i] = static_cast<u8>(0x10u + i * 7u);
        }
        TestBitPacker bp;
        const u64 m = 513ULL; // 1 RAW(256b) + 512 MORPH(NOT) <= 2*256 + 16 = 528
        bp.varint(m);
        bp.varint(m - 1ULL);
        bp.bits(10ULL, 4); // RAW
        bp.varint(32ULL);
        for (u8 b : seed) bp.bits(b, 8);
        bp.varint(256ULL);
        for (u32 v = 1u; v < static_cast<u32>(m); ++v) {
            bp.bits(6ULL, 4);
            bp.child_ref(v, v - 1u);
            bp.bits(1ULL, 2); // NOT
        }
        TestContainerOptions opt{};
        opt.version_minor = 1u;
        const auto deep_wire = assemble_v1_container(
            {TestChunkSpec{256u, 1u, 0u, 0u, bp.finish()}}, seed, 256ULL, opt);
        auto res = decode_v1(deep_wire);
        ASSERT_TRUE(res.ok()) << res.error().what;
        verify_ir_matches_bytes(res.value(), seed);
    }
}

} // namespace
} // namespace marp::v2
