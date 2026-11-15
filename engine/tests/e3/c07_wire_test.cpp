// MARP v2 — C07 WIRE — unit tests (GoogleTest).
//
// These tests are the *component* test surface: they drive the public
// `mapr/e3/e3_wire.hpp` API directly, with no harness code, no evidence writer,
// and no oracle.  The gate harness (`bin/c07_wire_gate`) is the separate,
// corpus-driven evidence producer; a PASS here plus a PASS there is what §13.4
// asks for.
//
// Coverage map (E3 §13.4 / SPECS-V2 §15):
//   Header*        §4.2 header fields, version policy, flags minimality
//   LengthForm*    §4.3/§4.4 u64 vs Region A.1
//   Codec*         §4.5 canonical uvarint and tagged bigint
//   AtomTable*     §4.6 first-use order, dedup, SHA-256, ATOM_MAX
//   NodeTable*     §4.7 kind/argc/params, post-order, root last, reachability
//   Index*         §4.8 policy, magic, entries, CRCs
//   Trailer*       §4.9 fields and CRC chaining
//   Stage*         §5.1 order, first-failure, code class
//   Totality*      no throw/abort/partial decode on any input
//   Determinism*   byte-identical output under repetition
//   Size*          O7.1 `encoded_size` == emitted bytes
//   Bijection*     O7.2/O7.3 round trips
//   Limits*        §6 limit codes

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

#include "mapr/e1_crc32.hpp"
#include "mapr/e1_sha256.hpp"
#include "mapr/e2/e2_canon.hpp"
#include "mapr/e2/e2_dag.hpp"
#include "mapr/e2/e2_eval.hpp"
#include "mapr/e3/e3_wire.hpp"

namespace {

using namespace marp::v2;



// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

std::array<u8, 32> payload_sha(std::span<const u8> bytes) {
    auto digest = mapr::Sha256::hash(std::string_view(
        reinterpret_cast<const char*>(bytes.data()), bytes.size()));
    std::array<u8, 32> out{};
    if (digest.ok()) std::memcpy(out.data(), digest.value().data(), out.size());
    return out;
}

std::shared_ptr<std::vector<std::vector<u8>>> owner_of(std::vector<u8> bytes) {
    auto owner = std::make_shared<std::vector<std::vector<u8>>>();
    owner->push_back(std::move(bytes));
    return owner;
}

// A single-Atom term with the given payload and `klass`.
Ir atom_term(const std::vector<u8>& bytes, u8 klass) {
    auto owner = owner_of(bytes);
    Ir ir;
    Atom atom;
    atom.klass = klass;
    atom.length = BigInt(static_cast<u64>(bytes.size()));
    atom.payload = std::span<const u8>(owner->back().data(), owner->back().size());
    atom.owner = owner;
    atom.sha256 = payload_sha(atom.payload);
    ir.atoms.push_back(std::move(atom));

    Node node;
    node.kind = Kind::Atom;
    node.a = BigInt(0);
    node.length = BigInt(static_cast<u64>(bytes.size()));
    ir.nodes.push_back(std::move(node));
    ir.root = 0;
    ir.total_length = ir.nodes[0].length;
    return ir;
}

Ir empty_term() {
    Ir ir;
    ir.nodes.push_back(Node{});
    ir.root = 0;
    ir.total_length = BigInt{};
    return ir;
}

Ir zero_term(u64 n) {
    Ir ir;
    Node node;
    node.kind = Kind::Zero;
    node.a = BigInt(n);
    node.length = BigInt(n);
    ir.nodes.push_back(std::move(node));
    ir.root = 0;
    ir.total_length = BigInt(n);
    return ir;
}

std::vector<u8> patterns(std::size_t n, u8 seed) {
    std::vector<u8> out(n);
    u8 state = seed;
    for (std::size_t i = 0; i < n; ++i) {
        state = static_cast<u8>(state * 131u + 7u);
        out[i] = state;
    }
    return out;
}

template <typename T>
std::string hex(const T& bytes) {
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string out;
    for (const auto b : bytes) {
        out.push_back(kDigits[(b >> 4) & 0x0Fu]);
        out.push_back(kDigits[b & 0x0Fu]);
    }
    return out;
}

u16 load16(const std::vector<u8>& wire, std::size_t at) {
    return static_cast<u16>(static_cast<u16>(wire[at]) |
                            (static_cast<u16>(wire[at + 1]) << 8));
}
u32 load32(const std::vector<u8>& wire, std::size_t at) {
    return static_cast<u32>(wire[at]) | (static_cast<u32>(wire[at + 1]) << 8) |
           (static_cast<u32>(wire[at + 2]) << 16) | (static_cast<u32>(wire[at + 3]) << 24);
}
u64 load64(const std::vector<u8>& wire, std::size_t at) {
    return static_cast<u64>(load32(wire, at)) | (static_cast<u64>(load32(wire, at + 4)) << 32);
}
void store16(std::vector<u8>& wire, std::size_t at, u16 v) {
    wire[at] = static_cast<u8>(v & 0xFFu);
    wire[at + 1] = static_cast<u8>((v >> 8) & 0xFFu);
}
void store32(std::vector<u8>& wire, std::size_t at, u32 v) {
    wire[at + 0] = static_cast<u8>(v & 0xFFu);
    wire[at + 1] = static_cast<u8>((v >> 8) & 0xFFu);
    wire[at + 2] = static_cast<u8>((v >> 16) & 0xFFu);
    wire[at + 3] = static_cast<u8>((v >> 24) & 0xFFu);
}

// Recomputes the two outer CRCs so a mutated byte is reported by the stage that
// owns the mutated field rather than by stage 4 or 5.
void fix_crcs(std::vector<u8>& wire) {
    const std::size_t trailer_offset = wire.size() - 32u;
    store32(wire, kHdrOffFileCrc32, 0u);
    const u32 file_crc = mapr::crc32(std::string_view(
        reinterpret_cast<const char*>(wire.data()), trailer_offset));
    store32(wire, kHdrOffFileCrc32, file_crc);

    std::array<u8, 32> buffer{};
    std::memcpy(buffer.data(), wire.data() + trailer_offset, 28);
    buffer[28] = static_cast<u8>(file_crc & 0xFFu);
    buffer[29] = static_cast<u8>((file_crc >> 8) & 0xFFu);
    buffer[30] = static_cast<u8>((file_crc >> 16) & 0xFFu);
    buffer[31] = static_cast<u8>((file_crc >> 24) & 0xFFu);
    const u32 trailer_crc = mapr::crc32(std::string_view(
        reinterpret_cast<const char*>(buffer.data()), buffer.size()));
    store32(wire, trailer_offset + kTrlOffTrailerCrc32, trailer_crc);
}

struct DecodedWire {
    WirePlan plan;
    std::vector<u8> bytes;
};

// Encodes `ir`, checking O7.1 on the way, and returns the wire plus its plan.
bool encode_ok(const Ir& ir, DecodedWire& out, const WireLimits& limits = WireLimits{}) {
    auto planned = plan(ir, limits);
    auto size = encoded_size(ir, limits);
    auto encoded = encode(ir, limits);
    if (!planned.ok() || !size.ok() || !encoded.ok()) return false;
    if (size.value() != planned.value().file_bytes) return false;
    if (size.value() != static_cast<u64>(encoded.value().size())) return false;
    out.plan = planned.value();
    out.bytes = std::move(encoded.value());
    return true;
}

// ==== Header ===============================================================

TEST(Header, LayoutIsExactly64Bytes) {
    DecodedWire wire;
    ASSERT_TRUE(encode_ok(empty_term(), wire));
    // 64 header + 1 atom_count + 1 node_count + 4 (_Empty_) + 1 (bigint 0) + 32
    EXPECT_EQ(wire.bytes.size(), 103u);
    const std::array<u8, 8> magic = {0x89u, 0x4Du, 0x41u, 0x50u,
                                     0x52u, 0x32u, 0x0Du, 0x0Au};
    EXPECT_EQ(std::memcmp(wire.bytes.data(), magic.data(), magic.size()), 0);
    EXPECT_EQ(load16(wire.bytes, kHdrOffVersionMajor), 2u);
    EXPECT_EQ(load16(wire.bytes, kHdrOffVersionMinor), 0u);
    EXPECT_EQ(load16(wire.bytes, kHdrOffHeaderBytes), 64u);
    EXPECT_EQ(load64(wire.bytes, kHdrOffTotalLengthU64), 0u);
    EXPECT_EQ(load16(wire.bytes, kHdrOffTotalLengthBigLen), 0u);
    EXPECT_EQ(load64(wire.bytes, kHdrOffAtomOffset), 64u);
    EXPECT_EQ(load64(wire.bytes, kHdrOffNodeOffset), 65u);  // 64 + atom_count uvarint
    EXPECT_EQ(load64(wire.bytes, kHdrOffIndexOffset), 0u);
    EXPECT_EQ(load64(wire.bytes, kHdrOffTrailerOffset), 71u);  // 65 + node_count + Empty
    EXPECT_EQ(wire.bytes.size(), 103u);
}

TEST(Header, RecenteredConstantValuesMatchTheSpec) {
    EXPECT_EQ(kWireHeaderBytes, 64u);
    EXPECT_EQ(kWireTrailerBytes, 32u);
    EXPECT_EQ(kWireMinContainerBytes, 96u);
    EXPECT_EQ(kWireAtomMax, 1u << 20);
    EXPECT_EQ(kWireAtomMax, 1048576u);
    EXPECT_EQ(kWireIndexStride, 1ull << 20);
    EXPECT_EQ(kMaxDepthSpec, 1u << 16);
    EXPECT_EQ(kMaxRecordsSpec, 1u << 24);
    EXPECT_EQ(WireLimits{}.max_container_bytes, 1ull << 63);
    EXPECT_EQ(WireLimits{}.max_nodes, 1u << 24);
    EXPECT_EQ(WireLimits{}.max_atoms, 1u << 24);
    EXPECT_EQ(WireLimits{}.max_depth, 1u << 16);
}

TEST(Header, FlagsAreMinimal) {
    DecodedWire wire;
    ASSERT_TRUE(encode_ok(empty_term(), wire));
    const u32 flags = load32(wire.bytes, kHdrOffFlags);
    EXPECT_EQ(flags, static_cast<u32>(kWireFlagCanonical | kWireFlagByteAligned |
                                      kWireFlagU64Lengths));
    EXPECT_EQ(flags & ~static_cast<u32>(kWireKnownFlagsMask), 0u);
}

TEST(Header, FileCrc32CoversEverythingBeforeTheTrailer) {
    DecodedWire wire;
    ASSERT_TRUE(encode_ok(atom_term(patterns(37, 3), 42), wire));
    const std::size_t trailer_offset = wire.bytes.size() - 32u;
    std::vector<u8> copy = wire.bytes;
    store32(copy, kHdrOffFileCrc32, 0u);
    const u32 expected = mapr::crc32(std::string_view(
        reinterpret_cast<const char*>(copy.data()), trailer_offset));
    EXPECT_EQ(load32(wire.bytes, kHdrOffFileCrc32), expected);
}

TEST(Header, TrailerCrc32IsChainedOverTheFileCrc) {
    DecodedWire wire;
    ASSERT_TRUE(encode_ok(atom_term(patterns(11, 9), 7), wire));
    const std::size_t trailer_offset = wire.bytes.size() - 32u;
    std::array<u8, 32> buffer{};
    std::memcpy(buffer.data(), wire.bytes.data() + trailer_offset, 28);
    const u32 file_crc = load32(wire.bytes, kHdrOffFileCrc32);
    buffer[28] = static_cast<u8>(file_crc & 0xFFu);
    buffer[29] = static_cast<u8>((file_crc >> 8) & 0xFFu);
    buffer[30] = static_cast<u8>((file_crc >> 16) & 0xFFu);
    buffer[31] = static_cast<u8>((file_crc >> 24) & 0xFFu);
    const u32 expected = mapr::crc32(std::string_view(
        reinterpret_cast<const char*>(buffer.data()), buffer.size()));
    EXPECT_EQ(load32(wire.bytes, trailer_offset + kTrlOffTrailerCrc32), expected);
}

TEST(Header, TrailerFieldsMatchThePlan) {
    DecodedWire wire;
    ASSERT_TRUE(encode_ok(atom_term(patterns(23, 5), 200), wire));
    const std::size_t trailer_offset = wire.bytes.size() - 32u;
    EXPECT_EQ(load64(wire.bytes, trailer_offset + kTrlOffFileBytes), wire.bytes.size());
    EXPECT_EQ(load32(wire.bytes, trailer_offset + kTrlOffRootId), 0u);
    EXPECT_EQ(load32(wire.bytes, trailer_offset + kTrlOffAtomCount), 1u);
    EXPECT_EQ(load32(wire.bytes, trailer_offset + kTrlOffNodeCount), 1u);
}

TEST(Header, TrailerMagicIsExact) {
    DecodedWire wire;
    ASSERT_TRUE(encode_ok(empty_term(), wire));
    const std::size_t trailer_offset = wire.bytes.size() - 32u;
    const std::array<u8, 8> magic = {0x54u, 0x52u, 0x4Cu, 0x52u,
                                     0x32u, 0x0Du, 0x0Au, 0x1Au};
    EXPECT_EQ(std::memcmp(wire.bytes.data() + trailer_offset, magic.data(), magic.size()), 0);
}

// ==== Length forms =========================================================

TEST(LengthForm, SmallLengthsUseTheU64Form) {
    for (const u64 n : {0ull, 1ull, 255ull, 65536ull, (1ull << 32)}) {
        DecodedWire wire;
        ASSERT_TRUE(encode_ok(zero_term(n), wire)) << n;
        EXPECT_EQ(load16(wire.bytes, kHdrOffTotalLengthBigLen), 0u) << n;
        EXPECT_EQ(load64(wire.bytes, kHdrOffTotalLengthU64), n) << n;
        EXPECT_EQ(load64(wire.bytes, kHdrOffAtomOffset), 64u) << n;
        EXPECT_NE(load32(wire.bytes, kHdrOffFlags) & kWireFlagU64Lengths, 0u) << n;
    }
}

TEST(LengthForm, TwoPow64UsesTheBigForm) {
    Ir ir = zero_term(0);
    ir.nodes[0].a = BigInt(1).shl(64).value();
    ir.nodes[0].length = ir.nodes[0].a;
    ir.total_length = ir.nodes[0].length;
    WireLimits limits;
    limits.enforce_output_cap = false;
    limits.verify_denotation = false;
    DecodedWire wire;
    ASSERT_TRUE(encode_ok(ir, wire, limits));
    const u16 big_len = load16(wire.bytes, kHdrOffTotalLengthBigLen);
    EXPECT_EQ(big_len, 9u);
    EXPECT_EQ(load64(wire.bytes, kHdrOffAtomOffset), 64u + 9u);
    EXPECT_EQ(load32(wire.bytes, kHdrOffFlags) & kWireFlagU64Lengths, 0u);
    // Region A.1 is the raw little-endian magnitude with no tag and no leading
    // zero byte (§4.4).  2^64 is 0x01 followed by eight zero bytes in big-endian,
    // so the little-endian region is eight zero bytes followed by 0x01.
    for (std::size_t i = 64u; i < 64u + 8u; ++i) EXPECT_EQ(wire.bytes[i], 0x00u) << i;
    EXPECT_EQ(wire.bytes[64u + 8u], 0x01u);
}

TEST(LengthForm, TwoPow64MinusOneStillUsesU64) {
    Ir ir = zero_term(0);
    ir.nodes[0].a = BigInt(1).shl(64).value().sub(BigInt(1)).value();
    ir.nodes[0].length = ir.nodes[0].a;
    ir.total_length = ir.nodes[0].length;
    WireLimits limits;
    limits.enforce_output_cap = false;
    DecodedWire wire;
    ASSERT_TRUE(encode_ok(ir, wire, limits));
    EXPECT_EQ(load16(wire.bytes, kHdrOffTotalLengthBigLen), 0u);
    EXPECT_EQ(load64(wire.bytes, kHdrOffTotalLengthU64), ~0ull);
}

// ==== Codecs ===============================================================

TEST(Codec, UvarintIsShortestForm) {
    struct Case {
        u64 value;
        std::vector<u8> bytes;
    };
    const Case cases[] = {
        {0, {0x00}},
        {1, {0x01}},
        {127, {0x7F}},
        {128, {0x80, 0x01}},
        {300, {0xAC, 0x02}},
        {16383, {0xFF, 0x7F}},
        {16384, {0x80, 0x80, 0x01}},
        {0xFFFFFFFFull, {0xFF, 0xFF, 0xFF, 0xFF, 0x0F}},
        {0xFFFFFFFFFFFFFFFFull,
         {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01}},
    };
    for (const Case& c : cases) {
        struct Collector final : public Sink {
            std::vector<u8> bytes;
            Status write(std::span<const u8> data) override {
                bytes.insert(bytes.end(), data.begin(), data.end());
                return Status{};
            }
        } sink;
        ASSERT_TRUE(write_uvarint(sink, c.value).ok()) << c.value;
        EXPECT_EQ(sink.bytes, c.bytes) << c.value;
        EXPECT_EQ(uvarint_size(c.value), c.bytes.size()) << c.value;

        SpanSource source(std::span<const u8>(sink.bytes.data(), sink.bytes.size()));
        Reader reader(source, 0, sink.bytes.size());
        auto back = reader.read_uvarint();
        ASSERT_TRUE(back.ok()) << c.value;
        EXPECT_EQ(back.value(), c.value);
        EXPECT_EQ(reader.remaining(), 0u);
    }
}

TEST(Codec, OverlongUvarintsAreRejected) {
    const std::vector<std::vector<u8>> bad = {
        {0x80, 0x00},          // two bytes encoding 0
        {0x80, 0x80, 0x00},    // three bytes encoding 0
        {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x02},  // > u64
        {0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01},  // 11 bytes
        {0x80},                // truncated
    };
    for (const std::vector<u8>& bytes : bad) {
        SpanSource source(std::span<const u8>(bytes.data(), bytes.size()));
        Reader reader(source, 0, bytes.size());
        EXPECT_FALSE(reader.read_uvarint().ok()) << hex(bytes);
    }
}

TEST(Codec, BigintTagsAreCanonical) {
    // Tag 0x00 is zero and nothing else.
    {
        const std::vector<u8> bytes = {0x00};
        SpanSource source(std::span<const u8>(bytes.data(), bytes.size()));
        Reader reader(source, 0, bytes.size());
        auto value = reader.read_bigint();
        ASSERT_TRUE(value.ok());
        EXPECT_TRUE(value.value().is_zero());
    }
    // Tag 0x01 with a zero uvarint is overlong: zero must use 0x00.
    {
        const std::vector<u8> bytes = {0x01, 0x00};
        SpanSource source(std::span<const u8>(bytes.data(), bytes.size()));
        Reader reader(source, 0, bytes.size());
        EXPECT_FALSE(reader.read_bigint().ok());
    }
    // Tag 0x02 with a length below 9 is overlong: small values use 0x01.
    {
        const std::vector<u8> bytes = {0x02, 0x08, 0, 0, 0, 0, 0, 0, 0, 0};
        SpanSource source(std::span<const u8>(bytes.data(), bytes.size()));
        Reader reader(source, 0, bytes.size());
        EXPECT_FALSE(reader.read_bigint().ok());
    }
    // Tag 0x02 with a leading zero magnitude byte is overlong.
    {
        const std::vector<u8> bytes = {0x02, 0x09, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        SpanSource source(std::span<const u8>(bytes.data(), bytes.size()));
        Reader reader(source, 0, bytes.size());
        EXPECT_FALSE(reader.read_bigint().ok());
    }
    // An unknown tag is invalid.
    {
        const std::vector<u8> bytes = {0x03};
        SpanSource source(std::span<const u8>(bytes.data(), bytes.size()));
        Reader reader(source, 0, bytes.size());
        EXPECT_FALSE(reader.read_bigint().ok());
    }
}

TEST(Codec, BigintRoundTrips) {
    for (const char* text : {"0", "1", "255", "256", "4294967295", "4294967296",
                             "18446744073709551615", "18446744073709551616",
                             "340282366920938463463374607431768211456"}) {
        auto parsed = BigInt::from_decimal(text);
        ASSERT_TRUE(parsed.ok()) << text;
        struct Collector final : public Sink {
            std::vector<u8> bytes;
            Status write(std::span<const u8> data) override {
                bytes.insert(bytes.end(), data.begin(), data.end());
                return Status{};
            }
        } sink;
        ASSERT_TRUE(write_bigint(sink, parsed.value()).ok()) << text;
        SpanSource source(std::span<const u8>(sink.bytes.data(), sink.bytes.size()));
        Reader reader(source, 0, sink.bytes.size());
        auto back = reader.read_bigint();
        ASSERT_TRUE(back.ok()) << text;
        EXPECT_EQ(back.value(), parsed.value()) << text;
        EXPECT_EQ(reader.remaining(), 0u) << text;
    }
}

// ==== Atom table ===========================================================

TEST(AtomTable, KlassIsPreservedExactly) {
    for (const u8 klass : {u8{0}, u8{1}, u8{127}, u8{128}, u8{254}, u8{255}}) {
        const std::vector<u8> bytes = patterns(9, klass);
        DecodedWire wire;
        ASSERT_TRUE(encode_ok(atom_term(bytes, klass), wire)) << unsigned{klass};
        // klass is the first byte of the first atom record.
        const std::size_t atom_offset = static_cast<std::size_t>(
            load64(wire.bytes, kHdrOffAtomOffset));
        EXPECT_EQ(wire.bytes[atom_offset + 1u], klass) << unsigned{klass};  // +1: count uvarint

        auto decoded = decode(std::span<const u8>(wire.bytes.data(), wire.bytes.size()));
        ASSERT_TRUE(decoded.ok());
        ASSERT_EQ(decoded.value().atoms.size(), 1u);
        EXPECT_EQ(decoded.value().atoms[0].klass, klass);
        EXPECT_EQ(decoded.value().atoms[0].payload.size(), bytes.size());
        EXPECT_EQ(std::memcmp(decoded.value().atoms[0].payload.data(), bytes.data(),
                              bytes.size()),
                  0);
    }
}

TEST(AtomTable, Sha256FieldIsTheHashOfThePayload) {
    const std::vector<u8> bytes = patterns(1000, 0x5C);
    DecodedWire wire;
    ASSERT_TRUE(encode_ok(atom_term(bytes, 3), wire));
    auto expected = mapr::Sha256::hash(std::string_view(
        reinterpret_cast<const char*>(bytes.data()), bytes.size()));
    ASSERT_TRUE(expected.ok());
    auto decoded = decode(std::span<const u8>(wire.bytes.data(), wire.bytes.size()));
    ASSERT_TRUE(decoded.ok());
    EXPECT_EQ(decoded.value().atoms[0].sha256, expected.value());
}

TEST(AtomTable, FirstUseOrderAndDedup) {
    // Atom 0 is used twice (Repeat over a Concat child would be non-canonical), so
    // build Concat(Atom(x), Atom(y)) and check the table order is first-use.
    Dag dag;
    // Two adjacent Atom children of a Concat must not be mergeable under
    // ATOM_MAX (E2 C3), so each is 700 KiB.
    const std::vector<u8> x = patterns(700u * 1024u, 1);
    const std::vector<u8> y = patterns(700u * 1024u, 2);
    auto xi = dag.add_atom(std::span<const u8>(x.data(), x.size()), 1);
    auto yi = dag.add_atom(std::span<const u8>(y.data(), y.size()), 2);
    Node a;
    a.kind = Kind::Atom;
    a.a = BigInt(xi.value());
    auto ai = dag.add_node(std::move(a));
    Node b;
    b.kind = Kind::Atom;
    b.a = BigInt(yi.value());
    auto bi = dag.add_node(std::move(b));
    Node concat;
    concat.kind = Kind::Concat;
    concat.args = std::vector<u32>{ai.value(), bi.value()};
    auto root = dag.add_node(std::move(concat));
    auto finished = std::move(dag).finish(root.value());
    ASSERT_TRUE(finished.ok());
    DecodedWire wire;
    ASSERT_TRUE(encode_ok(finished.value(), wire));
    auto decoded = decode(std::span<const u8>(wire.bytes.data(), wire.bytes.size()));
    ASSERT_TRUE(decoded.ok());
    ASSERT_EQ(decoded.value().atoms.size(), 2u);
    EXPECT_EQ(decoded.value().atoms[0].klass, 1u);
    EXPECT_EQ(decoded.value().atoms[1].klass, 2u);
    EXPECT_EQ(decoded.value().atoms[0].payload.size(), x.size());
}

TEST(AtomTable, PayloadsAreStoredVerbatim) {
    for (const std::size_t size : {std::size_t{1}, std::size_t{2}, std::size_t{255},
                                   std::size_t{256}, std::size_t{4096}}) {
        const std::vector<u8> bytes = patterns(size, static_cast<u8>(size));
        DecodedWire wire;
        ASSERT_TRUE(encode_ok(atom_term(bytes, 0), wire)) << size;
        auto decoded = decode(std::span<const u8>(wire.bytes.data(), wire.bytes.size()));
        ASSERT_TRUE(decoded.ok()) << size;
        ASSERT_EQ(decoded.value().atoms.size(), 1u) << size;
        ASSERT_EQ(decoded.value().atoms[0].payload.size(), size) << size;
        EXPECT_EQ(std::memcmp(decoded.value().atoms[0].payload.data(), bytes.data(), size), 0)
            << size;
    }
}

// ==== Node table ===========================================================

TEST(NodeTable, EveryKindRoundTrips) {
    // Empty
    {
        DecodedWire wire;
        ASSERT_TRUE(encode_ok(empty_term(), wire));
        auto decoded = decode(std::span<const u8>(wire.bytes.data(), wire.bytes.size()));
        ASSERT_TRUE(decoded.ok());
        ASSERT_EQ(decoded.value().nodes.size(), 1u);
        EXPECT_EQ(decoded.value().nodes[0].kind, Kind::Empty);
    }
    // Zero
    {
        DecodedWire wire;
        ASSERT_TRUE(encode_ok(zero_term(4096), wire));
        auto decoded = decode(std::span<const u8>(wire.bytes.data(), wire.bytes.size()));
        ASSERT_TRUE(decoded.ok());
        EXPECT_EQ(decoded.value().nodes[0].kind, Kind::Zero);
        EXPECT_EQ(decoded.value().nodes[0].a, BigInt(4096u));
    }
    // Lfsr
    {
        Dag dag;
        Node node;
        node.kind = Kind::Lfsr;
        node.lfsr_conn = 0x8000000000000001ull;
        node.lfsr_init = 0xCAFEBABEull;
        node.a = BigInt(1024u);
        auto id = dag.add_node(std::move(node));
        auto finished = std::move(dag).finish(id.value());
        ASSERT_TRUE(finished.ok());
        DecodedWire wire;
        ASSERT_TRUE(encode_ok(finished.value(), wire));
        auto decoded = decode(std::span<const u8>(wire.bytes.data(), wire.bytes.size()));
        ASSERT_TRUE(decoded.ok());
        EXPECT_EQ(decoded.value().nodes[0].lfsr_conn, 0x8000000000000001ull);
        EXPECT_EQ(decoded.value().nodes[0].lfsr_init, 0xCAFEBABEull);
        EXPECT_EQ(decoded.value().nodes[0].a, BigInt(1024u));
    }
    // Affine
    {
        Dag dag;
        Node node;
        node.kind = Kind::Affine;
        node.affine_start = 3;
        node.affine_step = 7;
        node.a = BigInt(65536u);
        auto id = dag.add_node(std::move(node));
        auto finished = std::move(dag).finish(id.value());
        ASSERT_TRUE(finished.ok());
        DecodedWire wire;
        ASSERT_TRUE(encode_ok(finished.value(), wire));
        auto decoded = decode(std::span<const u8>(wire.bytes.data(), wire.bytes.size()));
        ASSERT_TRUE(decoded.ok());
        EXPECT_EQ(decoded.value().nodes[0].affine_start, 3u);
        EXPECT_EQ(decoded.value().nodes[0].affine_step, 7u);
    }
    // Concat / Repeat / Slice / Xor / Interleave / Morph / Predictor
    {
        auto build = [](Kind kind) {
            Dag dag;
            const std::vector<u8> a_bytes = patterns(700u * 1024u, 11);
            const std::vector<u8> b_bytes = patterns(700u * 1024u, 22);
            auto a_id = dag.add_atom(std::span<const u8>(a_bytes.data(), a_bytes.size()), 1);
            auto b_id = dag.add_atom(std::span<const u8>(b_bytes.data(), b_bytes.size()), 2);
            Node a;
            a.kind = Kind::Atom;
            a.a = BigInt(a_id.value());
            auto ai = dag.add_node(std::move(a));
            Node b;
            b.kind = Kind::Atom;
            b.a = BigInt(b_id.value());
            auto bi = dag.add_node(std::move(b));
            Node node;
            node.kind = kind;
            switch (kind) {
                case Kind::Concat:
                    node.args = std::vector<u32>{ai.value(), bi.value()};
                    break;
                case Kind::Repeat:
                    node.args = {ai.value()};
                    node.a = BigInt(3u);
                    node.b = BigInt(5u);
                    break;
                case Kind::Slice:
                    node.args = {ai.value()};
                    node.a = BigInt(4u);
                    node.b = BigInt(20u);
                    break;
                case Kind::Xor:
                    // E2 C8 orders the operands by `canonical_key`, which is a
                    // structural key over the whole subterm (payload hashes
                    // included) — not something the test should re-derive.  Both
                    // orders are built and E2's `canon` picks the canonical one.
                    node.args = std::vector<u32>{ai.value(), bi.value()};
                    break;
                case Kind::Interleave:
                    node.args = std::vector<u32>{ai.value(), bi.value()};
                    node.a = BigInt(8u);
                    break;
                case Kind::Morph:
                    node.args = {ai.value()};
                    node.morph = 6;
                    node.morph_k = 3;
                    break;
                case Kind::Predictor:
                    node.args = {ai.value()};
                    node.predictor_id = 3;
                    node.predictor_param = 3;
                    break;
                default:
                    break;
            }
            auto id = dag.add_node(std::move(node));
            auto finished = std::move(dag).finish(id.value());
            if (!finished.ok()) return finished;
            // Canonicalise through E2's own authority.  `canon` only repairs an
            // already well-formed term, so this cannot invent a shape the corpus
            // could not otherwise produce.
            return canon(finished.value());
        };
        for (const Kind kind : {Kind::Concat, Kind::Repeat, Kind::Slice, Kind::Xor,
                                Kind::Interleave, Kind::Morph, Kind::Predictor}) {
            auto finished = build(kind);
            ASSERT_TRUE(finished.ok()) << static_cast<int>(kind);
            DecodedWire wire;
            ASSERT_TRUE(encode_ok(finished.value(), wire)) << static_cast<int>(kind);
            auto decoded = decode(std::span<const u8>(wire.bytes.data(), wire.bytes.size()));
            ASSERT_TRUE(decoded.ok()) << static_cast<int>(kind);
            EXPECT_EQ(decoded.value().nodes.back().kind, kind) << static_cast<int>(kind);
        }
    }
}

TEST(NodeTable, PostOrderRootLastAndReachability) {
    // Repeat(Concat(Atom, Atom), 2, 0) has a 4-node post-order table.
    Dag dag;
    const std::vector<u8> x = patterns(700u * 1024u, 1);
    const std::vector<u8> y = patterns(700u * 1024u, 2);
    auto xi = dag.add_atom(std::span<const u8>(x.data(), x.size()), 0);
    auto yi = dag.add_atom(std::span<const u8>(y.data(), y.size()), 0);
    Node a;
    a.kind = Kind::Atom;
    a.a = BigInt(xi.value());
    auto ai = dag.add_node(std::move(a));
    Node b;
    b.kind = Kind::Atom;
    b.a = BigInt(yi.value());
    auto bi = dag.add_node(std::move(b));
    Node concat;
    concat.kind = Kind::Concat;
    concat.args = std::vector<u32>{ai.value(), bi.value()};
    auto ci = dag.add_node(std::move(concat));
    Node repeat;
    repeat.kind = Kind::Repeat;
    repeat.args = {ci.value()};
    repeat.a = BigInt(2u);
    repeat.b = BigInt(0u);
    auto root = dag.add_node(std::move(repeat));
    auto finished = std::move(dag).finish(root.value());
    ASSERT_TRUE(finished.ok());
    DecodedWire wire;
    ASSERT_TRUE(encode_ok(finished.value(), wire));
    auto decoded = decode(std::span<const u8>(wire.bytes.data(), wire.bytes.size()));
    ASSERT_TRUE(decoded.ok());
    ASSERT_EQ(decoded.value().nodes.size(), 4u);
    EXPECT_EQ(decoded.value().root, 3u);
    EXPECT_EQ(decoded.value().nodes[3].kind, Kind::Repeat);
    for (std::size_t i = 0; i < decoded.value().nodes.size(); ++i) {
        for (const u32 arg : decoded.value().nodes[i].args) {
            EXPECT_LT(arg, i) << "node " << i << " arg " << arg;
        }
    }
}

// ==== Index ================================================================

TEST(Index, AbsentBelowTheStride) {
    DecodedWire wire;
    ASSERT_TRUE(encode_ok(zero_term((1ull << 20) - 1), wire));
    EXPECT_FALSE(wire.plan.index_present);
    EXPECT_EQ(wire.plan.index_offset, 0u);
    EXPECT_EQ(wire.plan.index_region_bytes, 0u);
    EXPECT_EQ(load64(wire.bytes, kHdrOffIndexOffset), 0u);
    EXPECT_EQ(load32(wire.bytes, kHdrOffFlags) & kWireFlagIndexPresent, 0u);
}

TEST(Index, PresentAboveTheStrideWithCanonicalOffsets) {
    // Concat of two 1 MiB atoms: one entry at 1 MiB.
    Dag dag;
    std::vector<u32> args;
    for (u32 i = 0; i < 2; ++i) {
        const std::vector<u8> bytes = patterns(1u << 20, static_cast<u8>(i + 1));
        auto atom_id = dag.add_atom(std::span<const u8>(bytes.data(), bytes.size()),
                                    static_cast<u8>(i));
        Node node;
        node.kind = Kind::Atom;
        node.a = BigInt(atom_id.value());
        args.push_back(dag.add_node(std::move(node)).value());
    }
    Node concat;
    concat.kind = Kind::Concat;
    concat.args = args;
    auto root = dag.add_node(std::move(concat));
    auto finished = std::move(dag).finish(root.value());
    ASSERT_TRUE(finished.ok());
    DecodedWire wire;
    ASSERT_TRUE(encode_ok(finished.value(), wire));
    ASSERT_TRUE(wire.plan.index_present);
    EXPECT_EQ(wire.plan.index_entries, 1u);
    // magic(8) + entry_count(4) + one entry + index_crc32(4); the entry is
    // bigint(2^20) = tag 0x01 + a 3-byte uvarint = 4, node_id uvarint = 1, crc = 4.
    EXPECT_EQ(wire.plan.index_region_bytes, 8u + 4u + (4u + 1u + 4u) + 4u);
    EXPECT_NE(load32(wire.bytes, kHdrOffFlags) & kWireFlagIndexPresent, 0u);

    const std::size_t index_offset = static_cast<std::size_t>(wire.plan.index_offset);
    const std::array<u8, 8> magic = {0x49u, 0x4Eu, 0x44u, 0x58u,
                                     0x32u, 0x0Du, 0x0Au, 0x1Au};
    EXPECT_EQ(std::memcmp(wire.bytes.data() + index_offset, magic.data(), magic.size()), 0);

    auto validated = validate(std::span<const u8>(wire.bytes.data(), wire.bytes.size()));
    ASSERT_TRUE(validated.ok());
    EXPECT_TRUE(validated.value().index_present);
    EXPECT_EQ(validated.value().index_entries, 1u);
}

TEST(Index, PrefixCrcsMatchTheDenotation) {
    Dag dag;
    std::vector<u32> args;
    for (u32 i = 0; i < 3; ++i) {
        const std::vector<u8> bytes = patterns(1u << 20, static_cast<u8>(0x30 + i));
        auto atom_id = dag.add_atom(std::span<const u8>(bytes.data(), bytes.size()), 0);
        Node node;
        node.kind = Kind::Atom;
        node.a = BigInt(atom_id.value());
        args.push_back(dag.add_node(std::move(node)).value());
    }
    Node concat;
    concat.kind = Kind::Concat;
    concat.args = args;
    auto root = dag.add_node(std::move(concat));
    auto finished = std::move(dag).finish(root.value());
    ASSERT_TRUE(finished.ok());
    DecodedWire wire;
    ASSERT_TRUE(encode_ok(finished.value(), wire));
    ASSERT_TRUE(wire.plan.index_present);
    ASSERT_EQ(wire.plan.index_entries, 2u);

    auto validated = validate(std::span<const u8>(wire.bytes.data(), wire.bytes.size()));
    ASSERT_TRUE(validated.ok());
    EXPECT_TRUE(validated.value().index_present);
    EXPECT_EQ(validated.value().index_entries, 2u);
}

// ==== Stages ===============================================================

TEST(Stage, EmptySourceIsRejectedAtStageSize) {
    auto verdict = validate(std::span<const u8>());
    ASSERT_FALSE(verdict.ok());
    EXPECT_EQ(verdict.error().stage, Stage::Size);
    EXPECT_EQ(verdict.error().code, WireCode::Invalid);
}

TEST(Stage, OverlongContainerIsRejectedAtStageSize) {
    WireLimits limits;
    limits.max_container_bytes = 8;
    std::vector<u8> bytes(9, 0u);
    auto verdict = validate(std::span<const u8>(bytes.data(), bytes.size()), limits);
    ASSERT_FALSE(verdict.ok());
    EXPECT_EQ(verdict.error().stage, Stage::Size);
}

TEST(Stage, BadMagicIsRejectedAtStageHeader) {
    DecodedWire wire;
    ASSERT_TRUE(encode_ok(empty_term(), wire));
    wire.bytes[0] ^= 0xFFu;
    fix_crcs(wire.bytes);
    auto verdict = validate(std::span<const u8>(wire.bytes.data(), wire.bytes.size()));
    ASSERT_FALSE(verdict.ok());
    EXPECT_EQ(verdict.error().stage, Stage::Header);
    EXPECT_EQ(verdict.error().code, WireCode::Invalid);
}

TEST(Stage, WrongMajorVersionIsUnsupported) {
    DecodedWire wire;
    ASSERT_TRUE(encode_ok(empty_term(), wire));
    store16(wire.bytes, kHdrOffVersionMajor, 3);
    fix_crcs(wire.bytes);
    auto verdict = validate(std::span<const u8>(wire.bytes.data(), wire.bytes.size()));
    ASSERT_FALSE(verdict.ok());
    EXPECT_EQ(verdict.error().stage, Stage::Header);
    EXPECT_EQ(verdict.error().code, WireCode::Unsupported);
}

TEST(Stage, V1DeviceIsInvalidNotUnsupported) {
    DecodedWire wire;
    ASSERT_TRUE(encode_ok(empty_term(), wire));
    store16(wire.bytes, kHdrOffVersionMajor, 1);
    fix_crcs(wire.bytes);
    auto verdict = validate(std::span<const u8>(wire.bytes.data(), wire.bytes.size()));
    ASSERT_FALSE(verdict.ok());
    EXPECT_EQ(verdict.error().stage, Stage::Header);
    EXPECT_EQ(verdict.error().code, WireCode::Invalid);
}

TEST(Stage, ReservedFlagBitIsRejected) {
    DecodedWire wire;
    ASSERT_TRUE(encode_ok(empty_term(), wire));
    wire.bytes[kHdrOffFlags] |= 0x10u;
    fix_crcs(wire.bytes);
    auto verdict = validate(std::span<const u8>(wire.bytes.data(), wire.bytes.size()));
    ASSERT_FALSE(verdict.ok());
    EXPECT_EQ(verdict.error().stage, Stage::Header);
}

TEST(Stage, BadFileCrcIsRejectedAtStageHeaderCrc) {
    DecodedWire wire;
    ASSERT_TRUE(encode_ok(empty_term(), wire));
    wire.bytes[kHdrOffFileCrc32] ^= 0x01u;
    auto verdict = validate(std::span<const u8>(wire.bytes.data(), wire.bytes.size()));
    ASSERT_FALSE(verdict.ok());
    EXPECT_EQ(verdict.error().stage, Stage::HeaderCrc);
}

TEST(Stage, BadTrailerIsRejectedAtStageTrailer) {
    DecodedWire wire;
    ASSERT_TRUE(encode_ok(empty_term(), wire));
    wire.bytes[wire.bytes.size() - 32u] ^= 0xFFu;
    fix_crcs(wire.bytes);
    auto verdict = validate(std::span<const u8>(wire.bytes.data(), wire.bytes.size()));
    ASSERT_FALSE(verdict.ok());
    EXPECT_EQ(verdict.error().stage, Stage::Trailer);
}

TEST(Stage, TrailingByteIsRejected) {
    DecodedWire wire;
    ASSERT_TRUE(encode_ok(empty_term(), wire));
    std::vector<u8> longer = wire.bytes;
    longer.push_back(0u);
    auto verdict = validate(std::span<const u8>(longer.data(), longer.size()));
    ASSERT_FALSE(verdict.ok());
    EXPECT_EQ(verdict.error().stage, Stage::Bounds);
}

TEST(Stage, TruncationNeverPartiallyAccepts) {
    DecodedWire wire;
    ASSERT_TRUE(encode_ok(atom_term(patterns(64, 4), 7), wire));
    for (std::size_t length = 0; length + 1 < wire.bytes.size(); ++length) {
        auto verdict = validate(std::span<const u8>(wire.bytes.data(), length));
        EXPECT_FALSE(verdict.ok()) << "prefix of length " << length << " was accepted";
        EXPECT_EQ(verdict.error().code, WireCode::Invalid) << length;
    }
}

TEST(Stage, AtomPayloadMutationIsRejectedAtStageAtoms) {
    DecodedWire wire;
    ASSERT_TRUE(encode_ok(atom_term(patterns(128, 6), 4), wire));
    const std::size_t atom_offset = static_cast<std::size_t>(load64(wire.bytes, kHdrOffAtomOffset));
    wire.bytes[atom_offset + 1u + 1u + 1u + 2u + 1u + 32u] ^= 0x01u;
    fix_crcs(wire.bytes);
    auto verdict = validate(std::span<const u8>(wire.bytes.data(), wire.bytes.size()));
    ASSERT_FALSE(verdict.ok());
    EXPECT_EQ(verdict.error().stage, Stage::Atoms);
}

TEST(Stage, UnknownNodeKindIsRejectedAtStageNodes) {
    DecodedWire wire;
    ASSERT_TRUE(encode_ok(zero_term(16), wire));
    const std::size_t node_offset = static_cast<std::size_t>(load64(wire.bytes, kHdrOffNodeOffset));
    wire.bytes[node_offset + 1u] = 99u;
    fix_crcs(wire.bytes);
    auto verdict = validate(std::span<const u8>(wire.bytes.data(), wire.bytes.size()));
    ASSERT_FALSE(verdict.ok());
    EXPECT_EQ(verdict.error().stage, Stage::Nodes);
}

TEST(Stage, NodeFlagsMustBeZero) {
    DecodedWire wire;
    ASSERT_TRUE(encode_ok(zero_term(16), wire));
    const std::size_t node_offset = static_cast<std::size_t>(load64(wire.bytes, kHdrOffNodeOffset));
    wire.bytes[node_offset + 2u] = 1u;
    fix_crcs(wire.bytes);
    auto verdict = validate(std::span<const u8>(wire.bytes.data(), wire.bytes.size()));
    ASSERT_FALSE(verdict.ok());
    EXPECT_EQ(verdict.error().stage, Stage::Nodes);
}

// ==== Totality =============================================================

TEST(Totality, ArbitraryBytesAreRejectedNotFatal) {
    // Deterministic pseudo-random bytes with a fixed seed; every call must return
    // a `Validation` or `Ir` without throwing or aborting.
    u64 state = 0x123456789ABCDEFull;
    auto next = [&state]() {
        state = state * 6364136223846793005ull + 1442695040888963407ull;
        return static_cast<u32>(state >> 33);
    };
    for (std::size_t iteration = 0; iteration < 2000; ++iteration) {
        std::vector<u8> bytes(next() % 200u);
        for (u8& byte : bytes) byte = static_cast<u8>(next() & 0xFFu);
        auto verdict = validate(std::span<const u8>(bytes.data(), bytes.size()));
        if (!verdict.ok()) {
            EXPECT_NE(verdict.error().code, WireCode::Ok) << iteration;
            EXPECT_NE(stage_name(verdict.error().stage), nullptr) << iteration;
        }
        auto decoded = decode(std::span<const u8>(bytes.data(), bytes.size()));
        if (decoded.ok()) {
            // Anything the decoder accepts must re-encode to the same bytes.
            auto re = encode(decoded.value());
            ASSERT_TRUE(re.ok()) << iteration;
            EXPECT_EQ(re.value(), bytes) << iteration;
        }
    }
}

TEST(Totality, DecodeDoesNotThrowOnHugeDeclaredCounts) {
    // A header claiming an enormous atom count must be rejected from the trailer
    // or the table, not by attempting the allocation.
    DecodedWire wire;
    ASSERT_TRUE(encode_ok(empty_term(), wire));
    const std::size_t atom_offset = static_cast<std::size_t>(load64(wire.bytes, kHdrOffAtomOffset));
    wire.bytes[atom_offset] = 0xFFu;  // count uvarint claims a huge value
    fix_crcs(wire.bytes);
    auto verdict = validate(std::span<const u8>(wire.bytes.data(), wire.bytes.size()));
    ASSERT_FALSE(verdict.ok());
    EXPECT_TRUE(verdict.error().stage == Stage::Atoms || verdict.error().stage == Stage::Trailer);
}

// ==== Determinism ==========================================================

TEST(Determinism, RepeatedEncodeIsByteIdentical) {
    const Ir ir = atom_term(patterns(3000, 77), 9);
    std::vector<u8> first;
    for (int i = 0; i < 32; ++i) {
        auto encoded = encode(ir);
        ASSERT_TRUE(encoded.ok());
        if (i == 0) {
            first = encoded.value();
        } else {
            EXPECT_EQ(encoded.value(), first) << i;
        }
    }
}

TEST(Determinism, EncodeFromDecodedIsStable) {
    DecodedWire wire;
    ASSERT_TRUE(encode_ok(atom_term(patterns(500, 33), 200), wire));
    auto first = decode(std::span<const u8>(wire.bytes.data(), wire.bytes.size()));
    ASSERT_TRUE(first.ok());
    auto a = encode(first.value());
    ASSERT_TRUE(a.ok());
    auto second = decode(std::span<const u8>(a.value().data(), a.value().size()));
    ASSERT_TRUE(second.ok());
    auto b = encode(second.value());
    ASSERT_TRUE(b.ok());
    EXPECT_EQ(a.value(), b.value());
    EXPECT_EQ(a.value(), wire.bytes);
}

// ==== Size (O7.1) ==========================================================

TEST(Size, EncodedSizeEqualsBytesForEveryKind) {
    std::vector<Ir> terms;
    terms.push_back(empty_term());
    terms.push_back(zero_term(0));
    terms.push_back(zero_term(1));
    terms.push_back(zero_term(1ull << 20));
    terms.push_back(atom_term(patterns(1, 1), 0));
    terms.push_back(atom_term(patterns(255, 2), 255));
    terms.push_back(atom_term(patterns(1u << 16, 3), 128));
    for (const Ir& ir : terms) {
        auto size = encoded_size(ir);
        auto encoded = encode(ir);
        ASSERT_TRUE(size.ok());
        ASSERT_TRUE(encoded.ok());
        EXPECT_EQ(size.value(), static_cast<u64>(encoded.value().size()));
    }
}

TEST(Size, PlanRegionsPartitionTheFile) {
    DecodedWire wire;
    ASSERT_TRUE(encode_ok(atom_term(patterns(77, 3), 4), wire));
    const WirePlan& p = wire.plan;
    EXPECT_EQ(p.atom_offset, static_cast<u64>(kWireHeaderBytes) + p.total_length_big_len);
    EXPECT_EQ(p.node_offset, p.atom_offset + p.atom_region_bytes);
    EXPECT_EQ(p.trailer_offset, p.node_offset + p.node_region_bytes + p.index_region_bytes);
    EXPECT_EQ(p.file_bytes, p.trailer_offset + static_cast<u64>(kWireTrailerBytes));
    EXPECT_EQ(p.file_bytes, static_cast<u64>(wire.bytes.size()));
}

// ==== Bijection ============================================================

TEST(Bijection, DecodeThenEncodeReproducesTheWire) {
    std::vector<Ir> terms = {empty_term(), zero_term(0), zero_term(1000),
                             atom_term(patterns(1, 1), 1),
                             atom_term(patterns(1024, 2), 200)};
    for (const Ir& ir : terms) {
        auto encoded = encode(ir);
        ASSERT_TRUE(encoded.ok());
        auto decoded = decode(
            std::span<const u8>(encoded.value().data(), encoded.value().size()));
        ASSERT_TRUE(decoded.ok());
        auto re = encode(decoded.value());
        ASSERT_TRUE(re.ok());
        EXPECT_EQ(re.value(), encoded.value());
    }
}

TEST(Bijection, KlassSurvivesTheRoundTrip) {
    for (const u8 klass : {u8{0}, u8{1}, u8{255}}) {
        const Ir ir = atom_term(patterns(32, klass), klass);
        auto encoded = encode(ir);
        ASSERT_TRUE(encoded.ok());
        auto decoded = decode(
            std::span<const u8>(encoded.value().data(), encoded.value().size()));
        ASSERT_TRUE(decoded.ok());
        ASSERT_EQ(decoded.value().atoms.size(), 1u);
        EXPECT_EQ(decoded.value().atoms[0].klass, klass);
    }
}

// ==== Limits ===============================================================

TEST(Limits, DepthLimitReportsLimit) {
    // Concat(Atom, Atom) is depth 2: the root plus the Atom children.
    Dag dag;
    const std::vector<u8> x = patterns(700u * 1024u, 1);
    const std::vector<u8> y = patterns(700u * 1024u, 2);
    auto xi = dag.add_atom(std::span<const u8>(x.data(), x.size()), 1);
    auto yi = dag.add_atom(std::span<const u8>(y.data(), y.size()), 2);
    Node a;
    a.kind = Kind::Atom;
    a.a = BigInt(xi.value());
    auto ai = dag.add_node(std::move(a));
    Node b;
    b.kind = Kind::Atom;
    b.a = BigInt(yi.value());
    auto bi = dag.add_node(std::move(b));
    Node concat;
    concat.kind = Kind::Concat;
    concat.args = std::vector<u32>{ai.value(), bi.value()};
    auto root = dag.add_node(std::move(concat));
    auto finished = std::move(dag).finish(root.value());
    ASSERT_TRUE(finished.ok());

    WireLimits limits;
    limits.max_depth = 2;
    EXPECT_TRUE(encode(finished.value(), limits).ok());
    limits.max_depth = 1;
    auto encoded = encode(finished.value(), limits);
    ASSERT_FALSE(encoded.ok());
    EXPECT_EQ(encoded.error().code, WireCode::Limit);
}

TEST(Limits, AtomCountLimitReportsLimit) {
    Dag dag;
    std::vector<u32> args;
    for (u32 i = 0; i < 3; ++i) {
        const std::vector<u8> bytes = patterns(700u * 1024u, static_cast<u8>(i));
        auto atom_id = dag.add_atom(std::span<const u8>(bytes.data(), bytes.size()), 0);
        Node node;
        node.kind = Kind::Atom;
        node.a = BigInt(atom_id.value());
        args.push_back(dag.add_node(std::move(node)).value());
    }
    Node concat;
    concat.kind = Kind::Concat;
    concat.args = args;
    auto root = dag.add_node(std::move(concat));
    auto finished = std::move(dag).finish(root.value());
    ASSERT_TRUE(finished.ok());
    WireLimits limits;
    limits.max_atoms = 2;
    EXPECT_FALSE(encode(finished.value(), limits).ok());
    limits.max_atoms = 3;
    EXPECT_TRUE(encode(finished.value(), limits).ok());
}

TEST(Limits, NodeCountLimitReportsLimit) {
    WireLimits limits;
    limits.max_nodes = 0;
    auto encoded = encode(empty_term(), limits);
    ASSERT_FALSE(encoded.ok());
    EXPECT_EQ(encoded.error().code, WireCode::Limit);
}

TEST(Limits, OutputCapCanBeDisabled) {
    Ir ir = zero_term(0);
    ir.nodes[0].a = BigInt(1).shl(64).value();
    ir.nodes[0].length = ir.nodes[0].a;
    ir.total_length = ir.nodes[0].length;
    WireLimits limits;
    EXPECT_FALSE(encode(ir, limits).ok());  // default: output cap enforced
    limits.enforce_output_cap = false;
    EXPECT_TRUE(encode(ir, limits).ok());
}

}  // namespace
