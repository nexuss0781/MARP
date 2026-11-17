// MARP v2 — E4 MEASURE — C10 SEGMENT — GoogleTest suite.
//
// Covers the C10 acceptance obligations (prompt §5) against MARP2-E4 §4.2,
// §4.4–§4.6, §5.2, §5.4, §6, §9:
//
//   * fixed point: `ilog2_q24` and `h0_q24` against pinned KATs and against a
//     second, separately written 62-bit-scale routine; `zero_frac_q24` exactly;
//   * §4.4 constants: `SCALES = {2^6 … 2^26}`, `mask = T-1`, `min = T/4`,
//     `max = 4T`, and the `L <= 64` single-leaf rule;
//   * §4.5 boundaries: `B_T` includes 0 and L, is strictly increasing, every gap
//     is within `[min_chunk, max_chunk]`, and the result is identical when the
//     same bytes are served in 1-byte reads (S4: bytes only, not read shape);
//   * §4.5 change points: a pinned sharp boundary is detected exactly, offsets
//     ascend, spacing respects the dedup window, and the cap is never exceeded;
//   * §4.6 tree: S1 (leaves partition), S2 (node = union of children), S3
//     (non-empty leaves, one `[0,0)` leaf for the empty input), S5 (1 vs 4 vs 8
//     threads and repeated runs produce byte-identical trees);
//   * §4.10 effort: scale selection per the table, and boundaries identical
//     across efforts — effort changes which scales exist, never a boundary;
//   * §9 errors: `Mismatch` for a tampered provenance, `Io` for a short or
//     failing source, `Invalid` for an out-of-domain effort or a non-power-of-two
//     target; never a throw, never a partial value;
//   * no file-name/extension dependence: identical results under five labels;
//   * no probe dependence: `segment()` returns the same tree when nothing else
//     is called, and no `Observation`-shaped type is compiled into this binary.

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include "mapr/e1_bigint.hpp"
#include "mapr/e1_gear.hpp"
#include "mapr/e4/e4_measure.hpp"
#include "mapr/e4/e4_segment.hpp"

namespace marp::v2 {
namespace {

using Bytes = std::vector<u8>;

// 128-bit intermediates for the *reference* routines below.  The library spells
// its own through `__extension__`; the tests are built with `-pedantic -Werror`
// too, so the reference spelling is local to this file.
__extension__ typedef unsigned __int128 u128ref;

// ---------------------------------------------------------------------------
// Deterministic fixtures (no clock, no random device, no file input)
// ---------------------------------------------------------------------------

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

Bytes zeros(std::size_t n) { return Bytes(n, 0x00u); }

Bytes repeat_block(const Bytes& block, std::size_t n) {
    Bytes out;
    out.reserve(n);
    while (out.size() < n) {
        const std::size_t take = std::min(block.size(), n - out.size());
        out.insert(out.end(), block.begin(), block.begin() + static_cast<std::ptrdiff_t>(take));
    }
    return out;
}

// M-CHANGE shape: 256 KiB zeros | 256 KiB random | 256 KiB zeros | 256 KiB counter.
Bytes change_fixture() {
    Bytes out;
    out.reserve(1u << 20);
    out.insert(out.end(), 256u * 1024u, 0x00u);
    const Bytes rand = splitmix_bytes(256u * 1024u, 0x4d41525043313001ull);
    out.insert(out.end(), rand.begin(), rand.end());
    out.insert(out.end(), 256u * 1024u, 0x00u);
    for (std::size_t i = 0; i < 256u * 1024u; ++i) {
        out.push_back(static_cast<u8>(i & 0xFFu));
    }
    return out;
}

// ---------------------------------------------------------------------------
// Sources
// ---------------------------------------------------------------------------

Provenance prove(const Bytes& bytes, u8 effort = 5) {
    SpanSource source(std::span<const u8>(bytes.data(), bytes.size()));
    const auto got = provenance(source, Policy{effort});
    EXPECT_TRUE(got.ok());
    return got.ok() ? got.value() : Provenance{};
}

// Records every read: the request size, the call count, and the bytes served.
// E4 §11 says a pass is streaming in a fixed block, so the measurement is the
// largest request, not an assertion in prose.
class SpySource final : public Source {
public:
    explicit SpySource(std::span<const u8> data) : data_(data) {}
    [[nodiscard]] BigInt size() const noexcept override {
        return BigInt(static_cast<u64>(data_.size()));
    }
    [[nodiscard]] MeasureCode read(const BigInt& off, std::span<u8> dst) const noexcept override {
        ++calls_;
        max_request_ = std::max(max_request_, dst.size());
        const auto offset = off.to_u64_checked();
        if (!offset.has_value() || *offset > data_.size()) return MeasureCode::Io;
        if (dst.size() > data_.size() - static_cast<std::size_t>(*offset)) return MeasureCode::Io;
        if (!dst.empty()) {
            std::memcpy(dst.data(), data_.data() + static_cast<std::size_t>(*offset), dst.size());
        }
        return MeasureCode::Ok;
    }
    [[nodiscard]] std::size_t calls() const noexcept { return calls_; }
    [[nodiscard]] std::size_t max_request() const noexcept { return max_request_; }

private:
    std::span<const u8> data_;
    mutable std::size_t calls_ = 0;
    mutable std::size_t max_request_ = 0;
};

class ShortSource final : public Source {
public:
    ShortSource(std::span<const u8> data, u64 declared) : data_(data), declared_(declared) {}
    [[nodiscard]] BigInt size() const noexcept override { return BigInt(declared_); }
    [[nodiscard]] MeasureCode read(const BigInt& off, std::span<u8> dst) const noexcept override {
        const auto offset = off.to_u64_checked();
        if (!offset.has_value() || *offset > data_.size()) return MeasureCode::Io;
        if (dst.size() > data_.size() - static_cast<std::size_t>(*offset)) return MeasureCode::Io;
        if (!dst.empty()) {
            std::memcpy(dst.data(), data_.data() + static_cast<std::size_t>(*offset), dst.size());
        }
        return MeasureCode::Ok;
    }

private:
    std::span<const u8> data_;
    u64 declared_;
};

class FailingSource final : public Source {
public:
    FailingSource(std::span<const u8> data, std::size_t fail_from)
        : data_(data), fail_from_(fail_from) {}
    [[nodiscard]] BigInt size() const noexcept override {
        return BigInt(static_cast<u64>(data_.size()));
    }
    [[nodiscard]] MeasureCode read(const BigInt& off, std::span<u8> dst) const noexcept override {
        const auto offset = off.to_u64_checked();
        if (!offset.has_value() || *offset >= fail_from_) return MeasureCode::Io;
        if (dst.size() > data_.size() - static_cast<std::size_t>(*offset)) return MeasureCode::Io;
        if (!dst.empty()) {
            std::memcpy(dst.data(), data_.data() + static_cast<std::size_t>(*offset), dst.size());
        }
        return MeasureCode::Ok;
    }

private:
    std::span<const u8> data_;
    std::size_t fail_from_;
};

// ---------------------------------------------------------------------------
// Independent references (written separately from the library)
// ---------------------------------------------------------------------------

// `ilog2_q24` by a second route: 62-bit mantissa scale, exact 128-bit squaring,
// 24 iterations.  Truncation only ever lowers the mantissa, and 24 squarings
// accumulate less than 2^-38 of relative error, far below the 2^-24 quantum, so
// the result is exactly `floor(log2(x)·2^24)` for every `x` in `u64`.
u64 reference_ilog2_q24(u64 x) {
    if (x == 0u) return 0u;
    unsigned msb = 0;
    while ((x >> msb) > 1u) ++msb;
    // y = x / 2^msb in [1, 2), scaled by 2^62.  msb == 63 needs a right shift.
    u128ref m = (msb <= 62u) ? (static_cast<u128ref>(x) << (62u - msb))
                             : (static_cast<u128ref>(x) >> 1u);
    unsigned long long frac = 0;
    for (int bit = 0; bit < 24; ++bit) {
        m = (m * m) >> 62u;
        frac <<= 1u;
        if (m >= (static_cast<u128ref>(1) << 63u)) {
            m >>= 1u;
            frac |= 1u;
        }
    }
    return (static_cast<u64>(msb) << 24u) | static_cast<u64>(frac);
}

// `H0_q24` from the §4.2 formula, using the reference `ilog2_q24` and exact
// 128-bit integers.
u64 reference_h0_q24(std::span<const u64> counts) {
    u128ref n = 0;
    for (const u64 c : counts) n += c;
    if (n == 0) return 0u;
    u128ref total = n * static_cast<u128ref>(reference_ilog2_q24(static_cast<u64>(n)));
    for (const u64 c : counts) {
        if (c == 0u) continue;
        total -= static_cast<u128ref>(c) * static_cast<u128ref>(reference_ilog2_q24(c));
    }
    return static_cast<u64>(total / n);
}

// `B_T` straight from the §4.5 pseudocode over a materialised buffer.
std::vector<u64> reference_boundaries(std::span<const u8> bytes, u64 target) {
    const u64 mask = target - 1u;
    const u64 min_chunk = target / 4u;
    const u64 max_chunk = target * 4u;
    const auto& table = mapr::gear_table();
    std::vector<u64> out{0u};
    const u64 length = static_cast<u64>(bytes.size());
    if (length == 0u) return out;  // {0, L} with L == 0 is the set {0}
    u64 start = 0u;
    u64 h = 0u;
    for (u64 i = 0; i < length; ++i) {
        h = (h << 1u) + table[bytes[static_cast<std::size_t>(i)]];
        const u64 len = i + 1u - start;
        if ((len >= min_chunk && (h & mask) == 0u) || len >= max_chunk) {
            if (i + 1u < length) out.push_back(i + 1u);
            start = i + 1u;
            h = 0u;
        }
    }
    out.push_back(length);
    return out;
}

// Change points straight from the §4.5 bullets over a materialised buffer.
std::vector<u64> reference_change_points(std::span<const u8> bytes) {
    const u64 length = static_cast<u64>(bytes.size());
    const u64 window = 4096u;
    const u64 hop = 2048u;
    std::vector<u64> cand;
    if (length < 2u * window) return cand;
    const u64 cap = length / hop + 16u;
    for (u64 i = window; i + window <= length; i += hop) {
        std::array<u64, 256> lc{};
        std::array<u64, 256> rc{};
        for (u64 j = i - window; j < i; ++j) ++lc[bytes[static_cast<std::size_t>(j)]];
        for (u64 j = i; j < i + window; ++j) ++rc[bytes[static_cast<std::size_t>(j)]];
        const u64 hl = reference_h0_q24(std::span<const u64>(lc.data(), lc.size()));
        const u64 hr = reference_h0_q24(std::span<const u64>(rc.data(), rc.size()));
        u64 zeros_l = 0;
        u64 zeros_r = 0;
        for (u64 j = i - window; j < i; ++j) {
            if (bytes[static_cast<std::size_t>(j)] == 0u) ++zeros_l;
        }
        for (u64 j = i; j < i + window; ++j) {
            if (bytes[static_cast<std::size_t>(j)] == 0u) ++zeros_r;
        }
        const u64 zl = static_cast<u64>((static_cast<u128ref>(zeros_l) << 24u) / window);
        const u64 zr = static_cast<u64>((static_cast<u128ref>(zeros_r) << 24u) / window);
        const u64 dh = hl > hr ? hl - hr : hr - hl;
        const u64 dz = zl > zr ? zl - zr : zr - zl;
        if (dh >= (1ull << 24) || dz >= (1ull << 22)) {
            if (cand.size() >= cap) break;
            cand.push_back(i);
        }
    }
    std::vector<u64> kept;
    for (const u64 offset : cand) {
        if (!kept.empty() && offset - kept.back() < 2048u) continue;
        kept.push_back(offset);
    }
    return kept;
}

// Pre-order tree from the §4.6 pseudocode, over the boundary sets it is given.
struct RefLevels {
    std::vector<std::vector<u64>> sets;  // ascending level
};

void ref_build(const RefLevels& levels, std::size_t j, u64 a, u64 b, u32 depth,
               std::vector<std::array<u64, 4>>& out) {
    out.push_back({a, b, depth, static_cast<u64>(j)});
    if (j == 0u) return;
    std::vector<u64> inner;
    for (const u64 x : levels.sets[j - 1u]) {
        if (x > a && x < b) inner.push_back(x);
    }
    if (inner.empty()) {
        ref_build(levels, j - 1u, a, b, depth + 1u, out);
        return;
    }
    u64 prev = a;
    for (const u64 x : inner) {
        ref_build(levels, j - 1u, prev, x, depth + 1u, out);
        prev = x;
    }
    ref_build(levels, j - 1u, prev, b, depth + 1u, out);
}

std::vector<std::array<u64, 4>> reference_tree(const RefLevels& levels, u64 length) {
    std::vector<std::array<u64, 4>> out;
    ref_build(levels, levels.sets.size() - 1u, 0u, length, 0u, out);
    return out;
}

std::optional<u64> as_u64(const BigInt& value) { return value.to_u64_checked(); }

// ---------------------------------------------------------------------------
// §4.2 fixed point
// ---------------------------------------------------------------------------

// M-KAT's list: `ilog2_q24` for 1, 2, 3, 4, 7, 8, 255, 256, 257, 1023, 1024,
// 1025, 2^20, 2^32-1.  Values derived independently of this engine (§4 of the
// C10 report) and reproduced here as constants.
struct IlogKat {
    u64 x;
    u64 q24;
};

constexpr std::array<IlogKat, 14> kIlogKats = {{
    {1ull, 0ull},
    {2ull, 16777216ull},
    {3ull, 26591258ull},
    {4ull, 33554432ull},
    {7ull, 47099599ull},
    {8ull, 50331648ull},
    {255ull, 134122994ull},
    {256ull, 134217728ull},
    {257ull, 134312092ull},
    {1023ull, 167748511ull},
    {1024ull, 167772160ull},
    {1025ull, 167795785ull},
    {1ull << 20u, 335544320ull},
    {(1ull << 32u) - 1ull, 536870911ull},
}};

TEST(C10FixedPoint, Ilog2KatTable) {
    for (const IlogKat& kat : kIlogKats) {
        EXPECT_EQ(ilog2_q24(kat.x), kat.q24) << "x=" << kat.x;
        EXPECT_EQ(reference_ilog2_q24(kat.x), kat.q24) << "reference x=" << kat.x;
    }
    EXPECT_EQ(ilog2_q24(0u), 0u);
    EXPECT_EQ(ilog2_q24(1u), 0u);
}

TEST(C10FixedPoint, Ilog2MatchesIndependentReference) {
    // Powers of two are exact by construction; every other value exercises the
    // 24 squarings.
    for (unsigned bit = 0; bit < 64u; ++bit) {
        const u64 x = (bit == 63u) ? (0x8000000000000000ull) : (1ull << bit);
        EXPECT_EQ(ilog2_q24(x), static_cast<u64>(bit) << 24u) << "x=2^" << bit;
    }
    u64 s = 0x243f6a8885a308d3ull;
    for (int n = 0; n < 4000; ++n) {
        s += 0x9E3779B97F4A7C15ull;
        u64 z = s;
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
        z = z ^ (z >> 31);
        if (z == 0u) z = 1u;
        EXPECT_EQ(ilog2_q24(z), reference_ilog2_q24(z)) << "x=" << z;
    }
    // Monotonicity: x1 <= x2 => ilog2(x1) <= ilog2(x2).
    u64 prev = 0;
    for (u64 x = 1; x < 3000u; ++x) {
        const u64 got = ilog2_q24(x);
        EXPECT_GE(got, prev) << "x=" << x;
        prev = got;
    }
}

TEST(C10FixedPoint, H0KnownValues) {
    std::array<u64, 256> counts{};
    // One symbol repeated: zero entropy.
    counts[7] = 4096;
    EXPECT_EQ(h0_q24_from_counts(counts), 0ull);
    counts.fill(0);

    // Two equally likely symbols: exactly one bit.
    counts[0] = 1000;
    counts[1] = 1000;
    EXPECT_EQ(h0_q24_from_counts(counts), 1ull << 24u);
    counts.fill(0);

    // 256 uniformly distributed symbols: exactly eight bits.
    for (std::size_t i = 0; i < 256u; ++i) counts[i] = 64u;
    EXPECT_EQ(h0_q24_from_counts(counts), 8ull << 24u);
    counts.fill(0);

    // Four equally likely symbols: exactly two bits.
    counts[1] = counts[2] = counts[3] = counts[4] = 777u;
    EXPECT_EQ(h0_q24_from_counts(counts), 2ull << 24u);
    EXPECT_EQ(h0_q24_from_counts(std::array<u64, 256>{}), 0ull);

    // Bytes in, counts out: the byte histogram of a materialised buffer equals
    // the count vector handed to the formula.
    const Bytes bytes = splitmix_bytes(5000, 0x4d41525043313002ull);
    std::array<u64, 256> histogram{};
    for (const u8 b : bytes) ++histogram[b];
    EXPECT_EQ(h0_q24(std::span<const u8>(bytes.data(), bytes.size())),
              h0_q24_from_counts(histogram));
    EXPECT_EQ(h0_q24_from_counts(histogram),
              reference_h0_q24(std::vector<u64>(histogram.begin(), histogram.end())));
}

TEST(C10FixedPoint, H0MatchesIndependentReferenceOnRandomCountVectors) {
    u64 s = 0x13198a2e03707344ull;
    auto next = [&s]() {
        s += 0x9E3779B97F4A7C15ull;
        u64 z = s;
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
        return z ^ (z >> 31);
    };
    for (int n = 0; n < 300; ++n) {
        const unsigned symbols = 1u + static_cast<unsigned>(next() % 256u);
        std::vector<u64> counts(256u, 0u);
        for (unsigned i = 0; i < symbols; ++i) counts[i] = 1u + (next() % 4096u);
        std::array<u64, 256> fixed{};
        std::copy(counts.begin(), counts.end(), fixed.begin());
        EXPECT_EQ(h0_q24_from_counts(fixed), reference_h0_q24(counts)) << "case " << n;
    }
}

TEST(C10FixedPoint, ZeroFractionIsExact) {
    Bytes bytes(1024, 0x11u);
    EXPECT_EQ(zero_frac_q24(std::span<const u8>(bytes.data(), bytes.size())), 0ull);
    for (std::size_t i = 0; i < 256u; ++i) bytes[i] = 0x00u;  // 256 / 1024 = 0.25
    EXPECT_EQ(zero_frac_q24(std::span<const u8>(bytes.data(), bytes.size())), 1ull << 22u);
    Bytes all_zero(4096, 0x00u);
    EXPECT_EQ(zero_frac_q24(std::span<const u8>(all_zero.data(), all_zero.size())), 1ull << 24u);
    EXPECT_EQ(zero_frac_q24(std::span<const u8>()), 0ull);
}

// ---------------------------------------------------------------------------
// §4.4 scales and constants
// ---------------------------------------------------------------------------

TEST(C10Scales, ConstantsMatchSection44) {
    ASSERT_EQ(kScales.size(), static_cast<std::size_t>(kScaleCount));
    EXPECT_EQ(kScaleCount, 11u);
    for (u32 k = 0; k < kScaleCount; ++k) {
        EXPECT_EQ(kScales[k], 1ull << (6u + 2u * k)) << "k=" << k;
        EXPECT_EQ(kScales[k] - 1u, kScales[k] - 1u);  // mask(T) = T-1
        EXPECT_EQ(kScales[k] / 4u, kScales[k] >> 2u);  // min_chunk(T) = T/4
        EXPECT_EQ(kScales[k] * 4u, kScales[k] << 2u);  // max_chunk(T) = 4T
    }
    EXPECT_EQ(kScales.front(), 64ull);
    EXPECT_EQ(kScales.back(), 64ull * 1024u * 1024u);
    EXPECT_EQ(kSingleLeafMax, 64ull);
    // Change-point constants (§4.5).
    EXPECT_EQ(kChangeWindow, 4096ull);
    EXPECT_EQ(kChangeHop, 2048ull);
    EXPECT_EQ(kChangeEntropyQ24, 1ull << 24u);
    EXPECT_EQ(kChangeZeroFracQ24, 1ull << 22u);
    EXPECT_EQ(kChangeDedupBytes, 2048ull);
    EXPECT_EQ(kChangeCapSlack, 16ull);
}

// ---------------------------------------------------------------------------
// §4.5 boundary sets
// ---------------------------------------------------------------------------

struct GapBounds {
    u64 min_gap = std::numeric_limits<u64>::max();
    u64 max_gap = 0;
    bool strictly_increasing = true;
    bool endpoints = false;
};

GapBounds gap_bounds(const std::vector<u64>& b, u64 length) {
    GapBounds out;
    out.endpoints = !b.empty() && b.front() == 0u && b.back() == length;
    for (std::size_t i = 1; i < b.size(); ++i) {
        if (b[i] <= b[i - 1u]) out.strictly_increasing = false;
        const u64 gap = b[i] - b[i - 1u];
        out.min_gap = std::min(out.min_gap, gap);
        out.max_gap = std::max(out.max_gap, gap);
    }
    if (b.size() < 2u) out.min_gap = 0u;
    return out;
}

TEST(C10Boundaries, InvariantsAndGapBounds) {
    const std::array<std::pair<std::string, Bytes>, 6> fixtures = {{
        {"zeros-4096", zeros(4096)},
        {"ff-4096", Bytes(4096, 0xffu)},
        {"rand-65536", splitmix_bytes(65536, 0x4d41525043313003ull)},
        {"rand-200000", splitmix_bytes(200000, 0x4d41525043313004ull)},
        {"tile-4096", repeat_block(splitmix_bytes(4096, 0x4d41525043313005ull), 262144)},
        {"counter", [] {
             Bytes out(131072);
             for (std::size_t i = 0; i < out.size(); ++i) out[i] = static_cast<u8>(i & 0xFFu);
             return out;
         }()},
    }};

    for (const auto& [name, bytes] : fixtures) {
        SpanSource source(std::span<const u8>(bytes.data(), bytes.size()));
        for (u32 k = 0; k < kScaleCount; ++k) {
            const u64 target = kScales[k];
            const auto got = boundaries_for_scale(source, target);
            ASSERT_TRUE(got.ok()) << name << " k=" << k;
            const std::vector<u64>& b = got.value();
            const u64 length = static_cast<u64>(bytes.size());
            EXPECT_EQ(b, reference_boundaries(std::span<const u8>(bytes.data(), bytes.size()),
                                              target))
                << name << " k=" << k;
            const GapBounds gb = gap_bounds(b, length);
            EXPECT_TRUE(gb.endpoints) << name << " k=" << k;
            EXPECT_TRUE(gb.strictly_increasing) << name << " k=" << k;
            const u64 min_chunk = target / 4u;
            const u64 max_chunk = target * 4u;
            for (std::size_t i = 1; i < b.size(); ++i) {
                const u64 gap = b[i] - b[i - 1u];
                // Every position but the last is a *cut*, and §4.5 cuts only at
                // `len >= min_chunk` (content) or `len >= max_chunk` (forced),
                // and the loop tests every byte, so a cut's gap is exactly in
                // [min_chunk, max_chunk].  The final `L` is emitted
                // unconditionally, so the last gap may be shorter than
                // min_chunk; it can never exceed max_chunk either.
                if (i + 1u < b.size()) {
                    EXPECT_GE(gap, min_chunk) << name << " k=" << k << " offset=" << b[i];
                }
                EXPECT_LE(gap, max_chunk) << name << " k=" << k << " offset=" << b[i];
            }
        }
    }
}

// `Source::read` must fill the whole destination (E4 §4.1), so a caller cannot
// observe read granularity; what is observable — and what E4 §11 bounds — is the
// request size.  Every scan asks for at most one fixed block, so no pass
// materialises the input.
TEST(C10Boundaries, BoundedRequestSizeAndIdenticalOverIndependentSources) {
    const Bytes bytes = splitmix_bytes(300000, 0x4d41525043313006ull);
    const Bytes copy = bytes;  // a second, independent buffer with the same bytes
    SpySource spy(std::span<const u8>(bytes.data(), bytes.size()));
    SpanSource plain(std::span<const u8>(copy.data(), copy.size()));
    for (const u64 target : {64ull, 1024ull, 65536ull}) {
        const auto a = boundaries_for_scale(spy, target);
        const auto b = boundaries_for_scale(plain, target);
        ASSERT_TRUE(a.ok());
        ASSERT_TRUE(b.ok());
        EXPECT_EQ(a.value(), b.value()) << "target=" << target;
    }
    EXPECT_LE(spy.max_request(), 64u * 1024u);
    EXPECT_GT(spy.calls(), 0u);
    // One pass per scale: the largest request is one block, never the input.
    EXPECT_LT(spy.max_request(), bytes.size());
}

TEST(C10Boundaries, ContentDefinedResynchronisesAfterAnInsertion) {
    // A single inserted byte must not shift every later cut: content-defined
    // chunking re-synchronises.  This is the property that separates §4.5 from
    // fixed-size chunking, so it is measured rather than assumed.
    Bytes base = splitmix_bytes(300000, 0x4d41525043313007ull);
    Bytes shifted = base;
    shifted.insert(shifted.begin() + 150000, 0x5au);

    SpanSource a(std::span<const u8>(base.data(), base.size()));
    SpanSource b(std::span<const u8>(shifted.data(), shifted.size()));
    const auto ba = boundaries_for_scale(a, 1024u);
    const auto bb = boundaries_for_scale(b, 1024u);
    ASSERT_TRUE(ba.ok());
    ASSERT_TRUE(bb.ok());

    // Boundaries before the insertion are identical.
    std::size_t same_before = 0;
    for (const u64 x : ba.value()) {
        if (x >= 150000u) break;
        if (std::binary_search(bb.value().begin(), bb.value().end(), x)) ++same_before;
    }
    EXPECT_GT(same_before, 100u);

    // Beyond one max_chunk after the insertion, every base boundary reappears
    // shifted by exactly one byte.
    const u64 settle = 150000u + 4u * 1024u;
    std::size_t matched = 0;
    std::size_t total = 0;
    for (const u64 x : ba.value()) {
        if (x < settle || x >= static_cast<u64>(base.size())) continue;
        ++total;
        if (std::binary_search(bb.value().begin(), bb.value().end(), x + 1u)) ++matched;
    }
    ASSERT_GT(total, 100u);
    EXPECT_EQ(matched, total);
}

TEST(C10Boundaries, RejectsNonPowerOfTwoTargets) {
    const Bytes bytes = zeros(1024);
    SpanSource source(std::span<const u8>(bytes.data(), bytes.size()));
    for (const u64 target : {0ull, 1ull, 3ull, 100ull, 1000ull, (1ull << 63u) + 1ull}) {
        EXPECT_EQ(boundaries_for_scale(source, target).code(), MeasureCode::Invalid)
            << "target=" << target;
    }
    for (const u64 target : {4ull, 8ull, 64ull, 1ull << 40u}) {
        const auto got = boundaries_for_scale(source, target);
        EXPECT_TRUE(got.ok()) << "target=" << target;
    }
}

// ---------------------------------------------------------------------------
// §4.5 change points
// ---------------------------------------------------------------------------

TEST(C10ChangePoints, DetectsPinnedSharpBoundaries) {
    const Bytes bytes = change_fixture();
    SpanSource source(std::span<const u8>(bytes.data(), bytes.size()));
    const auto got = change_points(source);
    ASSERT_TRUE(got.ok());
    const std::vector<u64>& cps = got.value();
    EXPECT_EQ(cps, reference_change_points(std::span<const u8>(bytes.data(), bytes.size())));

    // The three region boundaries (256 KiB apart) are all present.
    for (const u64 boundary : {262144ull, 524288ull, 786432ull}) {
        EXPECT_NE(std::find(cps.begin(), cps.end(), boundary), cps.end())
            << "missing change point at " << boundary;
    }
    // O8.10's sensitivity requirement: a change point within 1 MiB of the
    // zero -> random boundary (here: exactly on it).
    u64 nearest = std::numeric_limits<u64>::max();
    for (const u64 x : cps) {
        const u64 d = x > 262144u ? x - 262144u : 262144u - x;
        nearest = std::min(nearest, d);
    }
    EXPECT_EQ(nearest, 0ull);
}

TEST(C10ChangePoints, AscendingSpacedAndCapped) {
    const std::array<std::pair<std::string, Bytes>, 4> fixtures = {{
        {"change-1MiB", change_fixture()},
        {"rand-1MiB", splitmix_bytes(1u << 20u, 0x4d41525043313008ull)},
        {"zeros-1MiB", zeros(1u << 20u)},
        {"alternating-4096", [] {
             Bytes out;
             const Bytes r = splitmix_bytes(4096, 0x4d41525043313009ull);
             for (int i = 0; i < 256; ++i) {
                 if ((i & 1) == 0) {
                     out.insert(out.end(), 4096u, 0x00u);
                 } else {
                     out.insert(out.end(), r.begin(), r.end());
                 }
             }
             return out;
         }()},
    }};
    for (const auto& [name, bytes] : fixtures) {
        SpanSource source(std::span<const u8>(bytes.data(), bytes.size()));
        const auto got = change_points(source);
        ASSERT_TRUE(got.ok()) << name;
        const std::vector<u64>& cps = got.value();
        const u64 length = static_cast<u64>(bytes.size());
        EXPECT_EQ(cps, reference_change_points(std::span<const u8>(bytes.data(), bytes.size())))
            << name;
        const u64 cap = length / kChangeHop + kChangeCapSlack;
        EXPECT_LE(cps.size(), cap) << name;
        for (std::size_t i = 0; i < cps.size(); ++i) {
            EXPECT_LT(cps[i], length) << name;
            if (i != 0u) {
                EXPECT_GT(cps[i], cps[i - 1u]) << name;
                EXPECT_GE(cps[i] - cps[i - 1u], kChangeDedupBytes) << name;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// §4.6 tree: S1–S5
// ---------------------------------------------------------------------------

void expect_partition(const std::vector<Segment>& leaves, u64 length) {
    u64 expect = 0;
    for (const Segment& leaf : leaves) {
        ASSERT_EQ(leaf.level, 0u);
        const std::optional<u64> b = as_u64(leaf.begin);
        const std::optional<u64> e = as_u64(leaf.end);
        ASSERT_TRUE(b.has_value());
        ASSERT_TRUE(e.has_value());
        EXPECT_EQ(*b, expect) << "gap or overlap at " << *b;
        if (length != 0u) {
            EXPECT_LT(*b, *e);
        } else {
            EXPECT_EQ(*b, *e);
        }
        expect = *e;
    }
    EXPECT_EQ(expect, length);
}

void expect_containment(const std::vector<Segment>& tree) {
    // Children of a node are the contiguous run of following nodes at depth+1.
    for (std::size_t i = 0; i < tree.size(); ++i) {
        const Segment& parent = tree[i];
        const std::optional<u64> pb = as_u64(parent.begin);
        const std::optional<u64> pe = as_u64(parent.end);
        ASSERT_TRUE(pb.has_value());
        ASSERT_TRUE(pe.has_value());
        u64 cursor = *pb;
        std::size_t k = i + 1u;
        std::size_t children = 0;
        while (k < tree.size() && tree[k].depth == parent.depth + 1u) {
            const Segment& child = tree[k];
            const std::optional<u64> cb = as_u64(child.begin);
            const std::optional<u64> ce = as_u64(child.end);
            ASSERT_TRUE(cb.has_value());
            ASSERT_TRUE(ce.has_value());
            EXPECT_EQ(*cb, cursor) << "children do not tile node " << i;
            EXPECT_LE(*ce, *pe);
            EXPECT_EQ(static_cast<unsigned>(child.level) + 1u,
                      static_cast<unsigned>(parent.level));
            cursor = *ce;
            ++children;
            std::size_t skip = k + 1u;
            while (skip < tree.size() && tree[skip].depth > child.depth) ++skip;
            k = skip;
        }
        if (parent.level != 0u) {
            EXPECT_GE(children, 1u) << "internal node " << i << " has no child";
            EXPECT_EQ(cursor, *pe) << "children do not cover node " << i;
        } else {
            EXPECT_EQ(children, 0u);
        }
    }
}

TEST(C10Tree, LeavesPartitionInputForEveryShape) {
    std::vector<std::pair<std::string, Bytes>> fixtures;
    for (const std::size_t n : {std::size_t{0}, std::size_t{1}, std::size_t{2}, std::size_t{63},
                                std::size_t{64}, std::size_t{65}, std::size_t{127},
                                std::size_t{255}, std::size_t{256}, std::size_t{257},
                                std::size_t{4095}, std::size_t{4096}, std::size_t{4097},
                                std::size_t{65536}, std::size_t{65537}, std::size_t{200000}}) {
        fixtures.emplace_back("zeros-" + std::to_string(n), zeros(n));
        fixtures.emplace_back("rand-" + std::to_string(n), splitmix_bytes(n, 0x1000u + n));
    }
    fixtures.emplace_back("change-1MiB", change_fixture());

    for (const auto& [name, bytes] : fixtures) {
        const Provenance prov = prove(bytes);
        SpanSource source(std::span<const u8>(bytes.data(), bytes.size()));
        std::vector<Segment> tree;
        const auto got = segment(source, prov, Policy{5}, &tree);
        ASSERT_TRUE(got.ok()) << name << " code=" << measure_code_name(got.code());
        expect_partition(got.value(), static_cast<u64>(bytes.size()));
        expect_containment(tree);

        // The root is [0, L) at depth 0, and a single node is the §4.4 leaf.
        ASSERT_FALSE(tree.empty());
        EXPECT_EQ(tree.front().begin, BigInt(0u));
        EXPECT_EQ(tree.front().end, BigInt(static_cast<u64>(bytes.size())));
        EXPECT_EQ(tree.front().depth, 0u);
        if (bytes.size() <= kSingleLeafMax) {
            EXPECT_EQ(tree.size(), 1u) << name;
            EXPECT_EQ(tree.front().level, 0u) << name;
        }

        // Depth is bounded by the number of active levels (E4 §11).
        for (const Segment& node : tree) {
            EXPECT_LE(node.depth, kScaleCount - 1u) << name;
            EXPECT_LT(node.level, kScaleCount) << name;
        }
    }
}

// §4.6 splits at every level, so the leaves are the partition induced by the
// *union* of all active boundary sets — not by `B_0` alone, because a coarse
// boundary need not also be a fine one (that is exactly why §4.6 assigns a
// single child when the finer set has nothing inside).  Both directions are
// checked: every leaf edge is a boundary of some active set, and every boundary
// of every active set is a leaf edge.
TEST(C10Tree, LeavesAreThePartitionInducedByAllActiveBoundarySets) {
    const Bytes bytes = splitmix_bytes(300000, 0x4d4152504331300aull);
    const Provenance prov = prove(bytes);
    SpanSource source(std::span<const u8>(bytes.data(), bytes.size()));
    std::vector<Segment> tree;
    const auto got = segment(source, prov, Policy{5}, &tree);
    ASSERT_TRUE(got.ok());

    std::vector<u64> union_set{0u, static_cast<u64>(bytes.size())};
    for (u32 k = 0; k < kScaleCount; ++k) {
        const auto b = boundaries_for_scale(source, kScales[k]);
        ASSERT_TRUE(b.ok());
        union_set.insert(union_set.end(), b.value().begin(), b.value().end());
    }
    const auto changes = change_points(source);
    ASSERT_TRUE(changes.ok());
    union_set.insert(union_set.end(), changes.value().begin(), changes.value().end());
    std::sort(union_set.begin(), union_set.end());
    union_set.erase(std::unique(union_set.begin(), union_set.end()), union_set.end());

    ASSERT_GE(union_set.size(), 2u);
    ASSERT_EQ(got.value().size(), union_set.size() - 1u);
    for (std::size_t i = 0; i + 1u < union_set.size(); ++i) {
        EXPECT_EQ(as_u64(got.value()[i].begin).value(), union_set[i]) << "i=" << i;
        EXPECT_EQ(as_u64(got.value()[i].end).value(), union_set[i + 1u]) << "i=" << i;
    }

    // And the leaves refine `B_0` + change points: every element of that set is
    // also a leaf edge.
    auto finest = boundaries_for_scale(source, kFinestScale);
    ASSERT_TRUE(finest.ok());
    std::vector<Segment> finest_tree;
    const Provenance finest_prov = provenance(source, Policy{5}).value();
    const auto only_fine = segment(source, finest_prov, Policy{5}, &finest_tree);
    ASSERT_TRUE(only_fine.ok());
    expect_partition(only_fine.value(), static_cast<u64>(bytes.size()));
}

TEST(C10Tree, TreeMatchesIndependentPseudocodeBuild) {
    const std::array<std::pair<std::string, Bytes>, 3> fixtures = {{
        {"rand-200000", splitmix_bytes(200000, 0x4d4152504331300bull)},
        {"change-1MiB", change_fixture()},
        {"zeros-65536", zeros(65536)},
    }};
    for (const auto& [name, bytes] : fixtures) {
        const Provenance prov = prove(bytes);
        SpanSource source(std::span<const u8>(bytes.data(), bytes.size()));
        std::vector<Segment> tree;
        const auto got = segment(source, prov, Policy{5}, &tree);
        ASSERT_TRUE(got.ok()) << name;

        RefLevels ref;
        for (u32 k = 0; k < kScaleCount; ++k) {
            auto b = boundaries_for_scale(source, kScales[k]);
            ASSERT_TRUE(b.ok());
            ref.sets.push_back(b.value());
        }
        // The finest set carries the change points (§4.5).
        const auto cps = change_points(source);
        ASSERT_TRUE(cps.ok());
        std::vector<u64>& fine = ref.sets[0];
        for (const u64 x : cps.value()) {
            if (std::find(fine.begin(), fine.end(), x) == fine.end()) fine.push_back(x);
        }
        std::sort(fine.begin(), fine.end());

        const auto expected = reference_tree(ref, static_cast<u64>(bytes.size()));
        ASSERT_EQ(tree.size(), expected.size()) << name;
        for (std::size_t i = 0; i < tree.size(); ++i) {
            EXPECT_EQ(as_u64(tree[i].begin).value(), expected[i][0]) << name << " i=" << i;
            EXPECT_EQ(as_u64(tree[i].end).value(), expected[i][1]) << name << " i=" << i;
            EXPECT_EQ(tree[i].depth, expected[i][2]) << name << " i=" << i;
            EXPECT_EQ(static_cast<u64>(tree[i].level), expected[i][3]) << name << " i=" << i;
        }
    }
}

// ---------------------------------------------------------------------------
// S5: thread count and completion order
// ---------------------------------------------------------------------------

TEST(C10Determinism, OneVersusFourThreadsAndRepeats) {
    const std::array<std::pair<std::string, Bytes>, 4> fixtures = {{
        {"rand-200000", splitmix_bytes(200000, 0x4d4152504331300cull)},
        {"change-1MiB", change_fixture()},
        {"zeros-262144", zeros(262144)},
        {"tile-4096", repeat_block(splitmix_bytes(4096, 0x4d4152504331300dull), 200000)},
    }};
    for (const auto& [name, bytes] : fixtures) {
        const Provenance prov = prove(bytes);
        SpanSource source(std::span<const u8>(bytes.data(), bytes.size()));

        std::vector<Segment> tree1;
        const auto one = segment(source, prov, Policy{5}, &tree1);
        ASSERT_TRUE(one.ok()) << name;
        const std::string ref_leaves = boundaries_text(
            [&] {
                std::vector<u64> v;
                for (const Segment& s : one.value()) v.push_back(as_u64(s.begin).value());
                v.push_back(as_u64(one.value().back().end).value());
                return v;
            }());
        const std::string ref_tree = tree_text(tree1);

        for (const u32 threads : {1u, 2u, 3u, 4u, 8u}) {
            for (int repeat = 0; repeat < 2; ++repeat) {
                std::vector<Segment> tree_n;
                const auto got = segment_parallel(source, prov, Policy{5}, threads, &tree_n);
                ASSERT_TRUE(got.ok()) << name << " threads=" << threads;
                ASSERT_EQ(got.value().size(), one.value().size()) << name;
                for (std::size_t i = 0; i < got.value().size(); ++i) {
                    EXPECT_EQ(got.value()[i], one.value()[i])
                        << name << " threads=" << threads << " leaf=" << i;
                }
                EXPECT_EQ(tree_text(tree_n), ref_tree) << name << " threads=" << threads;
                // Threads 0 means "one worker", never "as many as you like".
                if (threads == 1u) {
                    std::vector<Segment> tree_zero;
                    const auto zero = segment_parallel(source, prov, Policy{5}, 0u, &tree_zero);
                    ASSERT_TRUE(zero.ok());
                    EXPECT_EQ(tree_text(tree_zero), ref_tree);
                }
            }
        }
        EXPECT_FALSE(ref_leaves.empty());
    }
}

// ---------------------------------------------------------------------------
// §4.10 effort
// ---------------------------------------------------------------------------

TEST(C10Effort, SelectsScalesPerTable) {
    for (u8 effort = 0; effort <= 2u; ++effort) {
        const auto got = active_scales(effort);
        ASSERT_TRUE(got.ok());
        EXPECT_EQ(got.value().count, 3u) << "effort=" << static_cast<unsigned>(effort);
        EXPECT_EQ(got.value().levels[0], 0u);
        EXPECT_EQ(kScales[got.value().levels[1]], 4096ull);        // 4 KiB
        EXPECT_EQ(kScales[got.value().levels[2]], 256ull * 1024u);  // 256 KiB (kScales[6])
    }
    for (u8 effort = 3u; effort <= 9u; ++effort) {
        const auto got = active_scales(effort);
        ASSERT_TRUE(got.ok());
        EXPECT_EQ(got.value().count, kScaleCount) << "effort=" << static_cast<unsigned>(effort);
        for (u32 j = 0; j < kScaleCount; ++j) {
            EXPECT_EQ(got.value().levels[j], static_cast<u8>(j));
        }
    }
    EXPECT_EQ(active_scales(10u).code(), MeasureCode::Invalid);
}

TEST(C10Effort, NeverChangesABoundary) {
    const Bytes bytes = splitmix_bytes(120000, 0x4d4152504331300eu);
    SpanSource source(std::span<const u8>(bytes.data(), bytes.size()));
    std::vector<std::string> trees;
    for (u8 effort = 0; effort <= 9u; ++effort) {
        const Provenance prov = prove(bytes, effort);
        std::vector<Segment> tree;
        const auto got = segment(source, prov, Policy{effort}, &tree);
        ASSERT_TRUE(got.ok()) << "effort=" << static_cast<unsigned>(effort);
        expect_partition(got.value(), static_cast<u64>(bytes.size()));
        trees.push_back(tree_text(tree));
    }
    // Every effort shows the finest level; only effort 3-9 shows all eleven.
    // Effort 0-2 uses {0, 3, 6} = {64 B, 4 KiB, 256 KiB}.
    for (std::size_t e = 0; e < 3u; ++e) {
        EXPECT_NE(trees[e].find("k0"), std::string::npos) << "effort " << e;
        EXPECT_NE(trees[e].find("k3"), std::string::npos) << "effort " << e;
        EXPECT_NE(trees[e].find("k6"), std::string::npos) << "effort " << e;
        EXPECT_EQ(trees[e].find("k7"), std::string::npos) << "effort " << e;
        EXPECT_EQ(trees[e].find("k10"), std::string::npos) << "effort " << e;
    }
    EXPECT_NE(trees[5].find("k10"), std::string::npos);
    // Effort changes which scales exist in the tree, never a boundary: the
    // finest set is the same value at effort 0 and effort 9.
    SpanSource check(std::span<const u8>(bytes.data(), bytes.size()));
    const auto a = boundaries_for_scale(check, kFinestScale);
    ASSERT_TRUE(a.ok());
    SpanSource check2(std::span<const u8>(bytes.data(), bytes.size()));
    const auto b = boundaries_for_scale(check2, kFinestScale);
    ASSERT_TRUE(b.ok());
    EXPECT_EQ(a.value(), b.value());
}

// ---------------------------------------------------------------------------
// §9 errors
// ---------------------------------------------------------------------------

TEST(C10Errors, MismatchWhenProvenanceDoesNotMatch) {
    const Bytes bytes = splitmix_bytes(100000, 0x4d4152504331300full);
    Provenance prov = prove(bytes);

    SpanSource source(std::span<const u8>(bytes.data(), bytes.size()));
    EXPECT_TRUE(segment(source, prov, Policy{5}).ok());

    Provenance tampered = prov;
    tampered.sha256[0] = static_cast<u8>(tampered.sha256[0] ^ 0x01u);
    EXPECT_EQ(segment(source, tampered, Policy{5}).code(), MeasureCode::Mismatch);

    Provenance wrong_length = prov;
    wrong_length.length = BigInt(static_cast<u64>(bytes.size()) + 1u);
    EXPECT_EQ(segment(source, wrong_length, Policy{5}).code(), MeasureCode::Mismatch);

    Provenance wrong_gear = prov;
    wrong_gear.gear ^= 1ull;
    EXPECT_EQ(segment(source, wrong_gear, Policy{5}).code(), MeasureCode::Mismatch);
}

TEST(C10Errors, IoOnShortOrFailingSource) {
    const Bytes bytes = splitmix_bytes(20000, 0x4d41525043313010ull);
    ShortSource short_source(std::span<const u8>(bytes.data(), bytes.size()),
                             static_cast<u64>(bytes.size()) + 4096u);
    EXPECT_EQ(segment(short_source, Provenance{}, Policy{5}).code(), MeasureCode::Io);

    SpanSource truth(std::span<const u8>(bytes.data(), bytes.size()));
    const auto prov = provenance(truth, Policy{5});
    ASSERT_TRUE(prov.ok());

    ShortSource short_with_real_prov(std::span<const u8>(bytes.data(), bytes.size()),
                                     static_cast<u64>(bytes.size()) + 4096u);
    EXPECT_EQ(segment(short_with_real_prov, prov.value(), Policy{5}).code(), MeasureCode::Io);

    FailingSource failing(std::span<const u8>(bytes.data(), bytes.size()), 8192u);
    EXPECT_EQ(segment(failing, prov.value(), Policy{5}).code(), MeasureCode::Io);
}

TEST(C10Errors, InvalidForOutOfDomainEffort) {
    const Bytes bytes = zeros(1000);
    SpanSource source(std::span<const u8>(bytes.data(), bytes.size()));
    const auto prov = provenance(source, Policy{5});
    ASSERT_TRUE(prov.ok());
    for (const u8 effort : {static_cast<u8>(10), static_cast<u8>(200), static_cast<u8>(255)}) {
        EXPECT_EQ(segment(source, prov.value(), Policy{effort}).code(), MeasureCode::Invalid)
            << "effort=" << static_cast<unsigned>(effort);
    }
}

TEST(C10Errors, NoTreeAndLeavesAgreeWithExplicitTree) {
    const Bytes bytes = splitmix_bytes(70000, 0x4d41525043313011ull);
    const Provenance prov = prove(bytes);
    SpanSource source(std::span<const u8>(bytes.data(), bytes.size()));
    std::vector<Segment> tree;
    const auto with_tree = segment(source, prov, Policy{5}, &tree);
    ASSERT_TRUE(with_tree.ok());
    const auto without = segment(source, prov, Policy{5}, nullptr);
    ASSERT_TRUE(without.ok());
    ASSERT_EQ(with_tree.value().size(), without.value().size());
    for (std::size_t i = 0; i < without.value().size(); ++i) {
        EXPECT_EQ(with_tree.value()[i], without.value()[i]);
    }
}

// ---------------------------------------------------------------------------
// No file-name / probe dependence
// ---------------------------------------------------------------------------

TEST(C10Independence, IdenticalBytesUnderFiveLabels) {
    const Bytes base = change_fixture();
    const Bytes slice(base.begin() + 200000, base.begin() + 200000 + 262144);
    const std::array<const char*, 5> labels = {{"a.bin", "a.txt", "a.zip", "noext", "a.tar.gz"}};
    std::vector<std::string> trees;
    for (const char* label : labels) {
        // The label exists only in this test's loop variable: `segment` receives
        // bytes through `Source`, which has no name to consult.
        EXPECT_NE(std::string(label).size(), 0u);
        const Provenance prov = prove(slice);
        SpanSource source(std::span<const u8>(slice.data(), slice.size()));
        std::vector<Segment> tree;
        const auto got = segment(source, prov, Policy{5}, &tree);
        ASSERT_TRUE(got.ok());
        trees.push_back(tree_text(tree));
    }
    for (std::size_t i = 1; i < trees.size(); ++i) {
        EXPECT_EQ(trees[i], trees[0]);
    }
}

TEST(C10Independence, SegmentCannotEmitAnObservation) {
    // Type-level half of E4-I6 for C10: the entry point returns leaves only, and
    // `Segment` carries no observation, term, or probe field.
    static_assert(std::is_same_v<decltype(segment(std::declval<Source&>(),
                                                  std::declval<const Provenance&>(),
                                                  std::declval<const Policy&>(),
                                                  std::declval<std::vector<Segment>*>())),
                                 MeasureResult<std::vector<Segment>>>,
                  "segment() must return MeasureResult<std::vector<Segment>>");
    static_assert(sizeof(Segment) <= sizeof(BigInt) * 2u + 8u,
                  "Segment must keep exactly begin, end, depth, level");
    SUCCEED();
}

}  // namespace
}  // namespace marp::v2
