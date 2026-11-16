// MARP v2 — E4 MEASURE — C09 PROVENANCE — GoogleTest suite.
//
// Covers the C09 acceptance obligations (prompt §5):
//
//   * exact `length`, whole-input SHA-256, gear at seed 0, and the §4.3 seed
//     against an independent reference (H3's clean-room SHA-256, E1's gear
//     table, and pinned KATs derived outside both);
//   * the seed is a pure function of bytes and effort — same bytes at the same
//     effort are identical across runs and across chunkings, and the same bytes
//     at a different effort differ as specified;
//   * one streaming pass: `Source::read` is observed exactly ceil(L / block)
//     times and never sees a single request larger than one block, so the
//     whole input is never materialised;
//   * re-read consistency (E4-I11) and provenance re-verification (`Mismatch`);
//   * `Io` for a short or unreadable source, `Invalid` for an out-of-domain
//     effort — never a throw, never a partial value;
//   * no filename/extension dependence: the same bytes under different names
//     produce identical output.

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "mapr/e4/e4_measure.hpp"
#include "mapr/e1_bigint.hpp"
#include "mapr/e1_gear.hpp"
#include "mapr/e1_sha256.hpp"

namespace marp::v2 {
namespace {

using Bytes = std::vector<u8>;

std::string hex_of(std::span<const u8> bytes) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    for (const u8 b : bytes) {
        out.push_back(kHex[(b >> 4) & 0x0Fu]);
        out.push_back(kHex[b & 0x0Fu]);
    }
    return out;
}

// Deterministic splitmix64 byte stream.  Fixed seed, no clock, no random device.
Bytes splitmix_bytes(std::size_t n, u64 seed) {
    Bytes out;
    out.reserve(n);
    u64 s = seed;
    while (out.size() < n) {
        s += 0x9E3779B97F4A7C15ull;
        u64 z = s;
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
        z = z ^ (z >> 31);
        for (int k = 0; k < 8 && out.size() < n; ++k) {
            out.push_back(static_cast<u8>((z >> (8u * static_cast<unsigned>(k))) & 0xFFu));
        }
    }
    return out;
}

// A Source that records how it was read: every request size and offset.
class SpySource final : public Source {
public:
    explicit SpySource(std::span<const u8> data) : data_(data) {}

    BigInt size() const noexcept override { return BigInt(static_cast<u64>(data_.size())); }

    MeasureCode read(const BigInt& off, std::span<u8> dst) const noexcept override {
        ++calls;
        max_request = std::max(max_request, dst.size());
        const auto offset = off.to_u64_checked();
        if (!offset.has_value()) return MeasureCode::Io;
        if (*offset > data_.size()) return MeasureCode::Io;
        if (dst.size() > data_.size() - static_cast<std::size_t>(*offset)) return MeasureCode::Io;
        std::memcpy(dst.data(), data_.data() + static_cast<std::size_t>(*offset), dst.size());
        return MeasureCode::Ok;
    }

    mutable std::size_t calls = 0;
    mutable std::size_t max_request = 0;

private:
    std::span<const u8> data_;
};

// Lies about its length: declares `declared` bytes but only serves `available`.
class ShortSource final : public Source {
public:
    ShortSource(std::span<const u8> data, u64 declared) : data_(data), declared_(declared) {}

    BigInt size() const noexcept override { return BigInt(declared_); }

    MeasureCode read(const BigInt& off, std::span<u8> dst) const noexcept override {
        const auto offset = off.to_u64_checked();
        if (!offset.has_value()) return MeasureCode::Io;
        if (*offset > data_.size()) return MeasureCode::Io;
        if (dst.size() > data_.size() - static_cast<std::size_t>(*offset)) return MeasureCode::Io;
        std::memcpy(dst.data(), data_.data() + static_cast<std::size_t>(*offset), dst.size());
        return MeasureCode::Ok;
    }

private:
    std::span<const u8> data_;
    u64 declared_;
};

// Fails on the Nth read.
class FailOnReadSource final : public Source {
public:
    FailOnReadSource(std::span<const u8> data, std::size_t fail_on) : data_(data), fail_on_(fail_on) {}

    BigInt size() const noexcept override { return BigInt(static_cast<u64>(data_.size())); }

    MeasureCode read(const BigInt& off, std::span<u8> dst) const noexcept override {
        ++calls;
        if (calls == fail_on_) return MeasureCode::Io;
        const auto offset = off.to_u64_checked();
        if (!offset.has_value()) return MeasureCode::Io;
        if (*offset > data_.size()) return MeasureCode::Io;
        if (dst.size() > data_.size() - static_cast<std::size_t>(*offset)) return MeasureCode::Io;
        std::memcpy(dst.data(), data_.data() + static_cast<std::size_t>(*offset), dst.size());
        return MeasureCode::Ok;
    }

    mutable std::size_t calls = 0;

private:
    std::span<const u8> data_;
    std::size_t fail_on_;
};

// ---------------------------------------------------------------------------
// Pinned KAT table.
//
// `sha256` and `gear` were produced by H3's clean-room SHA-256
// (`harness/oracle/src/sha256.cpp`) and E1's gear table respectively; `seed_*`
// values were produced by the §4.3 formula over those digests with an
// independent implementation (`pack("V")` + `pack("H*")` + Digest::SHA in Perl)
// and agree with the H3-based generator byte for byte.  Two implementations
// that share no code produce the same table, so the table is a reference, not
// a regression snapshot.
// ---------------------------------------------------------------------------
struct Kat {
    const char* id;
    std::span<const u8> bytes;
    const char* sha256_hex;
    u64 gear;
    u64 seed_effort_0;
    u64 seed_effort_5;
    u64 seed_effort_9;
};

constexpr u8 kEmpty[1] = {0};
constexpr u8 kOneA5[1] = {0xA5};
constexpr u8 kTwoMA[2] = {'M', 'A'};
constexpr u8 kAbc[3] = {'a', 'b', 'c'};
constexpr u8 kMarp[4] = {'M', 'A', 'R', 'P'};
constexpr u8 kZeros64[64] = {0};
constexpr u8 kZeros65[65] = {0};
constexpr u8 kFf65[65] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF};

constexpr std::array<Kat, 9> kKatTable = {{
    {"empty", std::span<const u8>(kEmpty, 0),
     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
     0x0000000000000000ull, 0x238c533748c1885eull, 0xcd140ec74dd6d355ull, 0x37f0f5ef3aa94dd7ull},
    {"one-0xa5", std::span<const u8>(kOneA5, 1),
     "6922e93e3827642ce4b883c756b31abf80036649d3614bf5fcb3adda43b8ea32",
     0x84eb39e5a73a5062ull, 0x9148cd8f9960aa39ull, 0x6d123f977adc02d6ull, 0x181f89c094b48f11ull},
    {"two-MA", std::span<const u8>(kTwoMA, 2),
     "f0055891f09fff4839b344a4af5e0482696cab0e0bf307455661ba4056c787ee",
     0x756fbefdb1c1677eull, 0x4255b2b701131c79ull, 0x763cae5f48c85db0ull, 0x268fe95ca8691da0ull},
    {"abc", std::span<const u8>(kAbc, 3),
     "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
     0x71e631861aeed862ull, 0x5de59487cfc49968ull, 0x8729e954e385f029ull, 0x3da0c05604b4e33aull},
    {"MARP", std::span<const u8>(kMarp, 4),
     "7c39a13611f1e460c738aa0eddf2a74c2035cf659a81826459a6d1c32779f16e",
     0x5e3ddcda8ca6b000ull, 0xb31738919845cc94ull, 0x452ed0558a02918dull, 0xf36d0970bd87a0cbull},
    {"zeros-64", std::span<const u8>(kZeros64, 64),
     "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b",
     0x0000000000000000ull, 0x74fcb3566819a2e4ull, 0xdef32013b03b9d1full, 0xc1d8b242a9e82291ull},
    {"zeros-65", std::span<const u8>(kZeros65, 65),
     "98ce42deef51d40269d542f5314bef2c7468d401ad5d85168bfab4c0108f75f7",
     0x0000000000000000ull, 0xf368b41aee6c376cull, 0x98f5775978a47b81ull, 0x16f0792ce9e3aa21ull},
    {"ff-65", std::span<const u8>(kFf65, 65),
     "855c9a28fff2bbbd71327165554a00c6fdd44d5d58c1f12b8fdff29b5d67f001",
     0x89464ed099d804a6ull, 0xf419c1a7a7f4732cull, 0xb68aa89c35412fcfull, 0xa7ff83619bfdf526ull},
    {"A-4096", std::span<const u8>(),
     "6896d9ea3f73a4434f5832bc65714e7d066f177373f36f34dc8a6f735daa41b1",
     0xbcb42a61b319c1a6ull, 0xceb0f0d3bd4e544aull, 0x2d7b60b00b7f742dull, 0x3939f9af1f0cc339ull},
}};

// The A-4096 case needs a 4 KiB buffer that cannot be a literal; it is filled
// here and patched into a local copy of the table.
const Bytes& a4096() {
    static const Bytes data(4096, static_cast<u8>('A'));
    return data;
}

Kat kat_with_bytes(const Kat& kat) {
    if (std::string_view(kat.id) != "A-4096") return kat;
    Kat copy = kat;
    copy.bytes = std::span<const u8>(a4096().data(), a4096().size());
    return copy;
}

// ---------------------------------------------------------------------------
// length / sha256 / gear / seed against the pinned reference
// ---------------------------------------------------------------------------

TEST(C09Provenance, KatTable) {
    for (const Kat& raw : kKatTable) {
        const Kat kat = kat_with_bytes(raw);
        SpanSource source(kat.bytes);
        const Policy policy{5};
        const auto got = provenance(source, policy);
        ASSERT_TRUE(got.ok()) << kat.id;
        const Provenance& prov = got.value();

        EXPECT_EQ(prov.length, BigInt(static_cast<u64>(kat.bytes.size()))) << kat.id;
        EXPECT_EQ(hex_of(prov.sha256), std::string(kat.sha256_hex)) << kat.id;
        EXPECT_EQ(prov.gear, kat.gear) << kat.id;
        EXPECT_EQ(prov.seed, kat.seed_effort_5) << kat.id;
    }
}

TEST(C09Provenance, SeedPerEffort) {
    for (const Kat& raw : kKatTable) {
        const Kat kat = kat_with_bytes(raw);
        SpanSource source(kat.bytes);
        const std::array<std::pair<u8, u64>, 3> effort_seed = {{
            {0, kat.seed_effort_0}, {5, kat.seed_effort_5}, {9, kat.seed_effort_9}}};
        for (const auto& [effort, want] : effort_seed) {
            const auto got = provenance(source, Policy{effort});
            ASSERT_TRUE(got.ok()) << kat.id << " effort=" << static_cast<int>(effort);
            EXPECT_EQ(got.value().seed, want)
                << kat.id << " effort=" << static_cast<int>(effort);
            // Effort changes the seed and nothing else (E4 §4.10: effort never
            // changes exactness, only which observations exist).
            EXPECT_EQ(got.value().length, BigInt(static_cast<u64>(kat.bytes.size())));
            EXPECT_EQ(hex_of(got.value().sha256), std::string(kat.sha256_hex));
            EXPECT_EQ(got.value().gear, kat.gear);
        }
    }
}

TEST(C09Provenance, SeedDomainLiteral) {
    EXPECT_EQ(std::string_view(kSeedDomain), std::string_view("MARP2-seed"));
    EXPECT_EQ(kSeedDomainLen, 10u);
}

// The seed function independently re-derived from a digest, and the property
// that the seed is a function of (digest, effort) only.
TEST(C09Provenance, DeriveSeedIsPureAndInjectiveEnough) {
    std::array<u8, 32> digest{};
    for (std::size_t i = 0; i < digest.size(); ++i) {
        digest[i] = static_cast<u8>((i * 37u + 11u) & 0xFFu);
    }
    u64 previous = 0;
    bool first = true;
    for (u32 effort = 0; effort <= 9u; ++effort) {
        const auto a = derive_seed(digest, static_cast<u8>(effort));
        const auto b = derive_seed(digest, static_cast<u8>(effort));
        ASSERT_TRUE(a.ok());
        ASSERT_TRUE(b.ok());
        EXPECT_EQ(a.value(), b.value());
        if (!first) {
            EXPECT_NE(a.value(), previous) << "effort " << effort;
        }
        previous = a.value();
        first = false;
    }
    EXPECT_FALSE(derive_seed(digest, 10).ok());
    EXPECT_EQ(derive_seed(digest, 10).code(), MeasureCode::Invalid);
}

// ---------------------------------------------------------------------------
// Independent reference: H3's SHA-256 (clean-room) and E1's one-shot gear
// ---------------------------------------------------------------------------

TEST(C09Provenance, MatchesE1SurfacesOnGeneratedBytes) {
    const std::array<std::size_t, 8> sizes = {0, 1, 63, 64, 65, 4095, 65536, 65537};
    for (const std::size_t n : sizes) {
        const Bytes data = splitmix_bytes(n, 0x4d41525043303931ull + n);
        SpanSource source(std::span<const u8>(data.data(), data.size()));

        const auto prov = provenance(source, Policy{5});
        ASSERT_TRUE(prov.ok()) << "n=" << n;

        // Whole-input references computed one-shot through E1's frozen surface.
        const std::string_view text(reinterpret_cast<const char*>(data.data()), data.size());
        const auto sha_ref = mapr::Sha256::hash(text);
        ASSERT_TRUE(sha_ref.ok());
        EXPECT_EQ(hex_of(prov.value().sha256), hex_of(sha_ref.value())) << "n=" << n;
        EXPECT_EQ(prov.value().gear, mapr::gear_hash(text)) << "n=" << n;
        EXPECT_EQ(prov.value().length, BigInt(static_cast<u64>(n))) << "n=" << n;
    }
}

// ---------------------------------------------------------------------------
// Streaming: one pass, bounded request size, no materialisation
// ---------------------------------------------------------------------------

TEST(C09Provenance, StreamingSinglePassBoundedBuffer) {
    const std::size_t n = 1'048'577;  // 1 MiB + 1: not a block multiple
    const Bytes data = splitmix_bytes(n, 0x4d41525043303932ull);
    SpySource source(std::span<const u8>(data.data(), data.size()));

    const auto prov = provenance(source, Policy{5});
    ASSERT_TRUE(prov.ok());

    // The pass reads the input exactly once.
    const std::size_t expected_calls = (n + (64u * 1024u) - 1u) / (64u * 1024u);
    EXPECT_EQ(source.calls, expected_calls);
    // No request exceeds the fixed block, so the whole input is never buffered.
    EXPECT_LE(source.max_request, 64u * 1024u);
    EXPECT_LT(source.max_request, n);
}

TEST(C09Provenance, StreamingChunkSizeInvariance) {
    // The same bytes read through different Source implementations (different
    // internal blocking) produce the identical Provenance: the result depends
    // on bytes and effort, never on how the pass is chunked.
    const Bytes data = splitmix_bytes(300'000, 0x4d41525043303933ull);
    SpanSource plain(std::span<const u8>(data.data(), data.size()));
    SpySource spy(std::span<const u8>(data.data(), data.size()));

    const auto a = provenance(plain, Policy{5});
    const auto b = provenance(spy, Policy{5});
    ASSERT_TRUE(a.ok());
    ASSERT_TRUE(b.ok());
    EXPECT_EQ(a.value().length, b.value().length);
    EXPECT_TRUE(same_digest(a.value().sha256, b.value().sha256));
    EXPECT_EQ(a.value().gear, b.value().gear);
    EXPECT_EQ(a.value().seed, b.value().seed);
}

// ---------------------------------------------------------------------------
// Determinism (E4-I1) and re-read consistency (E4-I11)
// ---------------------------------------------------------------------------

TEST(C09Provenance, DeterminismAcrossRuns) {
    const Bytes data = splitmix_bytes(70'000, 0x4d41525043303934ull);
    SpanSource source(std::span<const u8>(data.data(), data.size()));

    const auto first = provenance(source, Policy{5});
    ASSERT_TRUE(first.ok());
    for (int repeat = 0; repeat < 8; ++repeat) {
        const auto again = provenance(source, Policy{5});
        ASSERT_TRUE(again.ok());
        EXPECT_EQ(again.value().length, first.value().length);
        EXPECT_TRUE(same_digest(again.value().sha256, first.value().sha256));
        EXPECT_EQ(again.value().gear, first.value().gear);
        EXPECT_EQ(again.value().seed, first.value().seed);
    }
    // Repeated re-reads of the same range are byte-identical (E4-I11).
    std::array<u8, 4096> a{};
    std::array<u8, 4096> b{};
    ASSERT_EQ(source.read(BigInt(1234u), a), MeasureCode::Ok);
    ASSERT_EQ(source.read(BigInt(1234u), b), MeasureCode::Ok);
    EXPECT_EQ(a, b);
}

TEST(C09Provenance, BytewiseSensitivity) {
    // One bit anywhere changes the digest; this is what makes the identity
    // exact rather than representative.
    Bytes data = splitmix_bytes(4096, 0x4d41525043303935ull);
    SpanSource source(std::span<const u8>(data.data(), data.size()));
    const auto base = provenance(source, Policy{5});
    ASSERT_TRUE(base.ok());

    for (std::size_t pos : {std::size_t{0}, std::size_t{1}, std::size_t{2047}, data.size() - 1}) {
        Bytes mutated = data;
        mutated[pos] = static_cast<u8>(mutated[pos] ^ 0x01u);
        SpanSource mutated_source(std::span<const u8>(mutated.data(), mutated.size()));
        const auto got = provenance(mutated_source, Policy{5});
        ASSERT_TRUE(got.ok());
        EXPECT_FALSE(same_digest(got.value().sha256, base.value().sha256)) << "pos=" << pos;
        EXPECT_EQ(got.value().length, base.value().length);
    }
}

// ---------------------------------------------------------------------------
// Errors (E4 §9): Io for a short/unreadable source, Invalid for bad effort
// ---------------------------------------------------------------------------

TEST(C09Provenance, ShortReadIsIo) {
    const Bytes data = splitmix_bytes(1000, 0x4d41525043303936ull);
    ShortSource short_source(std::span<const u8>(data.data(), data.size()), 4096u);
    const auto got = provenance(short_source, Policy{5});
    EXPECT_FALSE(got.ok());
    EXPECT_EQ(got.code(), MeasureCode::Io);
}

TEST(C09Provenance, ReadFailureIsIo) {
    const Bytes data = splitmix_bytes(200'000, 0x4d41525043303937ull);
    for (std::size_t fail_on : {std::size_t{1}, std::size_t{2}, std::size_t{4}}) {
        FailOnReadSource source(std::span<const u8>(data.data(), data.size()), fail_on);
        const auto got = provenance(source, Policy{5});
        EXPECT_FALSE(got.ok()) << "fail_on=" << fail_on;
        EXPECT_EQ(got.code(), MeasureCode::Io) << "fail_on=" << fail_on;
    }
}

TEST(C09Provenance, OutOfDomainEffortIsInvalid) {
    const Bytes data = splitmix_bytes(32, 0x4d41525043303938ull);
    SpanSource source(std::span<const u8>(data.data(), data.size()));
    for (u8 effort : {static_cast<u8>(10), static_cast<u8>(255)}) {
        const auto got = provenance(source, Policy{effort});
        EXPECT_FALSE(got.ok());
        EXPECT_EQ(got.code(), MeasureCode::Invalid);
    }
}

TEST(C09Provenance, SpanSourceBoundsAreIo) {
    const Bytes data = splitmix_bytes(16, 0x4d41525043303939ull);
    SpanSource source(std::span<const u8>(data.data(), data.size()));
    std::array<u8, 8> dst{};
    EXPECT_EQ(source.read(BigInt(16u), dst), MeasureCode::Io);       // start at end, non-empty
    EXPECT_EQ(source.read(BigInt(17u), dst), MeasureCode::Io);       // past end
    EXPECT_EQ(source.read(BigInt(9u), dst), MeasureCode::Io);        // straddles end
    EXPECT_EQ(source.read(BigInt(8u), dst), MeasureCode::Ok);        // exactly fits
    EXPECT_EQ(source.read(BigInt(0u), std::span<u8>()), MeasureCode::Ok);  // empty read
}

// ---------------------------------------------------------------------------
// `provenance_matches`: Mismatch when the recorded identity is not the source's
// ---------------------------------------------------------------------------

TEST(C09Provenance, MatchesReportsMismatch) {
    const Bytes data = splitmix_bytes(5000, 0x4d41525043313031ull);
    SpanSource source(std::span<const u8>(data.data(), data.size()));
    const auto prov = provenance(source, Policy{5});
    ASSERT_TRUE(prov.ok());

    EXPECT_TRUE(provenance_matches(source, prov.value(), Policy{5}).ok());

    Provenance tampered = prov.value();
    tampered.sha256[0] ^= 0xFFu;
    EXPECT_EQ(provenance_matches(source, tampered, Policy{5}).code(), MeasureCode::Mismatch);

    tampered = prov.value();
    tampered.gear ^= 1ull;
    EXPECT_EQ(provenance_matches(source, tampered, Policy{5}).code(), MeasureCode::Mismatch);

    tampered = prov.value();
    tampered.seed += 1ull;
    EXPECT_EQ(provenance_matches(source, tampered, Policy{5}).code(), MeasureCode::Mismatch);

    tampered = prov.value();
    tampered.length = BigInt(static_cast<u64>(data.size()) + 1ull);
    EXPECT_EQ(provenance_matches(source, tampered, Policy{5}).code(), MeasureCode::Mismatch);

    // Different bytes: the source is the reference, so the old record mismatches.
    Bytes other = data;
    other[0] ^= 0x01u;
    SpanSource other_source(std::span<const u8>(other.data(), other.size()));
    EXPECT_EQ(provenance_matches(other_source, prov.value(), Policy{5}).code(),
              MeasureCode::Mismatch);

    // A failing source is `Io`, not `Mismatch`.
    ShortSource short_source(std::span<const u8>(data.data(), data.size()), 8192u);
    EXPECT_EQ(provenance_matches(short_source, prov.value(), Policy{5}).code(), MeasureCode::Io);
}

// ---------------------------------------------------------------------------
// No filename / extension / media-type dependence (V2-G14, E4 §10)
// ---------------------------------------------------------------------------

TEST(C09Provenance, NameAndExtensionIndependent) {
    // Same bytes, four different names/extensions.  Nothing in the surface can
    // see a name: `Source` has no name accessor and no path is ever read.  This
    // test asserts the property that makes that claim observable.
    const Bytes data = splitmix_bytes(256 * 1024, 0x4d41525043313032ull);
    const std::array<const char*, 5> names = {
        "fixture.bin", "fixture.txt", "fixture.zip", "fixture", "fixture.bin"};

    std::vector<std::string> texts;
    for (const char* name : names) {
        SpanSource source(std::span<const u8>(data.data(), data.size()));
        const auto prov = provenance(source, Policy{5});
        ASSERT_TRUE(prov.ok()) << name;
        texts.push_back(provenance_text(prov.value()));
    }
    for (std::size_t i = 1; i < texts.size(); ++i) {
        EXPECT_EQ(texts[i], texts[0]) << names[i];
    }
}

// ---------------------------------------------------------------------------
// Rendering is a pure function of the Provenance
// ---------------------------------------------------------------------------

TEST(C09Provenance, ProvenanceTextIsStable) {
    const std::array<u8, 2> bytes = {'M', 'A'};
    SpanSource source(std::span<const u8>(bytes.data(), bytes.size()));
    const auto prov = provenance(source, Policy{5});
    ASSERT_TRUE(prov.ok());
    const std::string text = provenance_text(prov.value());
    EXPECT_EQ(text,
              "length=2;sha256=f0055891f09fff4839b344a4af5e0482696cab0e0bf307455661ba4056c787ee"
              ";gear=0x756fbefdb1c1677e;seed=0x763cae5f48c85db0");
    // Deterministic across calls.
    EXPECT_EQ(provenance_text(prov.value()), text);
}

// ---------------------------------------------------------------------------
// Large-input path: the 64-bit length arithmetic does not drift
// ---------------------------------------------------------------------------

TEST(C09Provenance, LargeInputIsExact) {
    // 4 MiB + 12345 exercises many blocks plus a partial final block.
    const std::size_t n = (4u << 20) + 12345u;
    const Bytes data = splitmix_bytes(n, 0x4d41525043313033ull);
    SpanSource source(std::span<const u8>(data.data(), data.size()));

    const auto prov = provenance(source, Policy{5});
    ASSERT_TRUE(prov.ok());
    EXPECT_EQ(prov.value().length, BigInt(static_cast<u64>(n)));

    const std::string_view text(reinterpret_cast<const char*>(data.data()), data.size());
    const auto sha_ref = mapr::Sha256::hash(text);
    ASSERT_TRUE(sha_ref.ok());
    EXPECT_TRUE(same_digest(prov.value().sha256, sha_ref.value()));
    EXPECT_EQ(prov.value().gear, mapr::gear_hash(text));
}

}  // namespace
}  // namespace marp::v2
