// MARP v2 — E4 MEASURE — C11 PROBE — GoogleTest suite.
//
// Covers the C11 acceptance obligations (prompt §5) against MARP2-E4 §4.2,
// §4.7–§4.10, §5.3, §5.4, §6, §9:
//
//   * fixed point: `ilog2_q24` and the entropy formulas against pinned KATs and
//     against separately written reference routines;
//   * §4.7 field discipline: every field present, unused fields zero, no
//     floating point type in the record (`static_assert`);
//   * §4.8 probes: exact values on constructed fixtures — known periods (p=1,
//     p=tile, p=N, p=0), affine and quadratic fits with their witnesses, runs,
//     skew planes, Berlekamp–Massey linear complexity and connection-polynomial
//     digests, Repeat16 planted matches, stride winners and ties, change
//     points on a pinned boundary;
//   * §4.8 period rule: a reported period always passes the full byte check and
//     is minimal; `verify_period` accepts only reportable claims;
//   * §4.9 sampling: the 2 MiB threshold, the 16×64 KiB windows, the recorded
//     offsets, and the sampled flag discipline;
//   * §4.10 effort: budget selects which observations exist, never their
//     values;
//   * §5.4 merge: shuffled parallel results merge to the serial order;
//   * E4-I2 locality: bytes outside `where` cannot reach an observation;
//   * reproducibility: re-running a probe on the recorded `where` reproduces
//     every field;
//   * §9 errors: `Invalid`, `Io`, never a throw.

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include "mapr/e1_bigint.hpp"
#include "mapr/e1_sha256.hpp"
#include "mapr/e4/e4_measure.hpp"
#include "mapr/e4/e4_probe.hpp"
#include "mapr/e4/e4_segment.hpp"

namespace marp::v2 {
namespace {

using Bytes = std::vector<u8>;

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

Bytes repeat_block(const Bytes& block, std::size_t n) {
    Bytes out;
    out.reserve(n);
    while (out.size() < n) {
        const std::size_t take = std::min(block.size(), n - out.size());
        out.insert(out.end(), block.begin(), block.begin() + static_cast<std::ptrdiff_t>(take));
    }
    return out;
}

Segment whole(const Bytes& data) {
    return Segment{BigInt(0), BigInt(data.size()), 0, 0};
}

const Observation* find(const std::vector<Observation>& rows, ProbeKind kind, u32 param) {
    for (const Observation& obs : rows) {
        if (obs.kind == kind && obs.param == param) return &obs;
    }
    return nullptr;
}

// First observation of a kind, whatever its parameter (for kinds like
// `Repeat16` or `Stride` whose parameter is part of the measurement).
const Observation* find_kind(const std::vector<Observation>& rows, ProbeKind kind) {
    for (const Observation& obs : rows) {
        if (obs.kind == kind) return &obs;
    }
    return nullptr;
}

// ---------------------------------------------------------------------------
// Separately written reference routines (from the text of §4.2 and §4.8)
// ---------------------------------------------------------------------------

u64 ref_conditional(u64 sum_ctx, u64 sum_joint, u64 samples) {
    if (samples == 0u) return 0u;
    return sum_joint > sum_ctx ? 0u : (sum_ctx - sum_joint) / samples;
}

u64 ref_h1(const Bytes& b) {
    if (b.size() < 2u) return 0u;
    std::array<u64, 256> ctx{};
    std::map<u32, u64> joint;
    for (std::size_t i = 1; i < b.size(); ++i) {
        ++ctx[b[i - 1u]];
        ++joint[(static_cast<u32>(b[i - 1u]) << 8) | b[i]];
    }
    u64 sum_ctx = 0;
    for (const u64 c : ctx) {
        if (c != 0u) sum_ctx += c * ilog2_q24(c);
    }
    u64 sum_joint = 0;
    for (const auto& [k, c] : joint) {
        (void)k;
        sum_joint += c * ilog2_q24(c);
    }
    return ref_conditional(sum_ctx, sum_joint, static_cast<u64>(b.size() - 1u));
}

// The reference deliberately differs in mechanism (128-bit sums replaced by
// exact u64 sums bounded by the fixture sizes) to keep it a check, not a copy.
u64 ref_runs_count(const Bytes& b) {
    u64 runs = 0;
    for (std::size_t i = 0; i < b.size(); ++i) {
        if (i == 0u || b[i] != b[i - 1u]) ++runs;
    }
    return runs;
}

u64 ref_runs_max(const Bytes& b) {
    u64 best = 0;
    u64 current = 0;
    for (std::size_t i = 0; i < b.size(); ++i) {
        if (i != 0u && b[i] == b[i - 1u]) {
            ++current;
        } else {
            current = 1u;
        }
        best = std::max(best, current);
    }
    return best;
}

bool ref_period_holds(const Bytes& b, u64 p) {
    for (u64 i = p; i < b.size(); ++i) {
        if (b[static_cast<std::size_t>(i)] != b[static_cast<std::size_t>(i - p)]) return false;
    }
    return true;
}

u64 ref_minimal_period(const Bytes& b) {
    if (b.empty()) return 0u;
    for (u64 p = 1; p <= b.size(); ++p) {
        if (ref_period_holds(b, p)) return p;
    }
    return b.size();  // unreachable: p = N always holds
}

// ===========================================================================
// §4.7 — the record itself
// ===========================================================================

TEST(C11Observation, TypeDiscipline) {
    static_assert(sizeof(ProbeKind) == 1, "ProbeKind is u8 (§4.7)");
    static_assert(!std::is_floating_point_v<decltype(Observation::value)>, "no float fields");
    static_assert(!std::is_floating_point_v<decltype(Observation::aux)>, "no float fields");
    static_assert(std::is_same_v<decltype(probe(std::declval<Source&>(),
                                               std::declval<const Segment&>(),
                                               std::declval<const Policy&>())),
                                 MeasureResult<std::vector<Observation>>>,
                  "probe() returns MeasureResult<vector<Observation>> (§8)");
    static_assert(std::is_same_v<decltype(verify_period(std::declval<Source&>(),
                                                        std::declval<const Observation&>())),
                                 MeasureResult<bool>>,
                  "verify_period() returns MeasureResult<bool> (§8)");
    // §4.7: every field is present and the default record is zero everywhere.
    Observation zero;
    EXPECT_EQ(zero.value, 0u);
    EXPECT_EQ(zero.aux, 0u);
    EXPECT_TRUE(zero.period.is_zero());
    for (const u8 b : zero.digest) EXPECT_EQ(b, 0u);
    EXPECT_FALSE(zero.verified);
    EXPECT_FALSE(zero.sampled);
    EXPECT_EQ(zero.sample_count, 0u);
    EXPECT_EQ(zero.param, 0u);
}

TEST(C11Observation, ValidateFieldDiscipline) {
    Observation obs;
    obs.where = Segment{BigInt(0), BigInt(10), 0, 0};
    obs.kind = ProbeKind::H0;
    obs.value = 123;
    obs.aux = 10;
    EXPECT_TRUE(validate_observation(obs, 10).ok());

    // period present with verified = false -> Invalid (§9)
    obs.period = BigInt(3);
    EXPECT_FALSE(validate_observation(obs, 10).ok());

    obs.period = BigInt(0);
    obs.verified = true;  // non-Period kind with verified = true -> Invalid
    EXPECT_FALSE(validate_observation(obs, 10).ok());

    obs.verified = false;
    obs.sample_count = 16;  // not sampled but sample_count != 0 -> Invalid
    EXPECT_FALSE(validate_observation(obs, 10).ok());

    obs.sample_count = 0;
    obs.param = 7;  // H0 has no parameter -> Invalid
    EXPECT_FALSE(validate_observation(obs, 10).ok());

    obs.param = 0;
    obs.where = Segment{BigInt(0), BigInt(11), 0, 0};  // outside source -> Invalid
    EXPECT_FALSE(validate_observation(obs, 10).ok());

    // Period discipline
    Observation per;
    per.where = Segment{BigInt(0), BigInt(10), 0, 0};
    per.kind = ProbeKind::Period;
    per.period = BigInt(3);
    per.verified = true;
    EXPECT_TRUE(validate_observation(per, 10).ok());
    per.verified = false;
    EXPECT_FALSE(validate_observation(per, 10).ok());
    per.verified = true;
    per.period = BigInt(11);  // p > N
    EXPECT_FALSE(validate_observation(per, 10).ok());
    per.period = BigInt(0);  // p = 0 on non-empty range
    EXPECT_FALSE(validate_observation(per, 10).ok());
}

// ===========================================================================
// §4.2 — fixed point
// ===========================================================================

TEST(C11FixedPoint, Ilog2Kats) {
    EXPECT_EQ(ilog2_q24(1), 0u);
    EXPECT_EQ(ilog2_q24(2), 1ull << 24);
    EXPECT_EQ(ilog2_q24(4), 2ull << 24);
    EXPECT_EQ(ilog2_q24(8), 3ull << 24);
    EXPECT_EQ(ilog2_q24(256), 8ull << 24);
    EXPECT_EQ(ilog2_q24(1024), 10ull << 24);
    EXPECT_EQ(ilog2_q24(1ull << 20), 20ull << 24);
    EXPECT_EQ(ilog2_q24(1ull << 32), 32ull << 24);
    EXPECT_EQ(ilog2_q24(0), 0u);  // out-of-domain value pinned (decision D9)
    // floor(log2(3) * 2^24) = 26591258
    EXPECT_EQ(ilog2_q24(3), 26591258u);
}

TEST(C11FixedPoint, EntropyKats) {
    // H0 of two equiprobable symbols is exactly 1 bit.
    std::array<u64, 256> counts{};
    counts[0] = 1;
    counts[255] = 1;
    EXPECT_EQ(h0_q24_from_counts(std::span<const u64, 256>(counts)), 1ull << 24);
    // H0 of one symbol is 0.
    counts.fill(0);
    counts[7] = 9;
    EXPECT_EQ(h0_q24_from_counts(std::span<const u64, 256>(counts)), 0u);
    // H1 of one pair is 0 (single sample).
    const Bytes pair = {0x00, 0xFF};
    EXPECT_EQ(ref_h1(pair), 0u);
    SpanSource src(pair);
    auto rows = probe(src, whole(pair), Policy{});
    ASSERT_TRUE(rows.ok());
    const Observation* h1 = find_kind(rows.value(), ProbeKind::H1);
    ASSERT_NE(h1, nullptr);
    EXPECT_EQ(h1->value, 0u);
    EXPECT_EQ(h1->aux, 1u);  // one pair
}

// ===========================================================================
// §4.8 — each probe kind on constructed fixtures
// ===========================================================================

TEST(C11Probe, EntropiesMatchReference) {
    const Bytes fixtures[] = {
        Bytes{},
        Bytes{0x00},
        Bytes{0x00, 0xFF},
        Bytes(16, 0x5A),
        splitmix_bytes(4096, 0x11),
        splitmix_bytes(1000, 0x22),
    };
    for (const Bytes& data : fixtures) {
        SpanSource src(data);
        auto rows = probe(src, whole(data), Policy{});
        ASSERT_TRUE(rows.ok());
        const Observation* h0 = find_kind(rows.value(), ProbeKind::H0);
        const Observation* h1 = find_kind(rows.value(), ProbeKind::H1);
        const Observation* h2 = find_kind(rows.value(), ProbeKind::H2);
        ASSERT_NE(h0, nullptr);
        ASSERT_NE(h1, nullptr);
        ASSERT_NE(h2, nullptr);
        EXPECT_EQ(h0->value, h0_q24(data));
        EXPECT_EQ(h0->aux, data.size());
        EXPECT_EQ(h1->value, ref_h1(data));
        EXPECT_EQ(h1->aux, data.size() >= 2u ? data.size() - 1u : 0u);
        EXPECT_EQ(h2->aux, data.size() >= 3u ? data.size() - 2u : 0u);
    }
}

TEST(C11Probe, PeriodPinned) {
    // zeros -> p = 1; tile -> p = tile length; distinct -> p = N; empty -> p = 0.
    const Bytes zeros(500, 0x00);
    {
        SpanSource src(zeros);
        auto rows = probe(src, whole(zeros), Policy{});
        ASSERT_TRUE(rows.ok());
        const Observation* per = find_kind(rows.value(), ProbeKind::Period);
        ASSERT_NE(per, nullptr);
        EXPECT_TRUE(per->verified);
        EXPECT_EQ(per->period, BigInt(1));
        EXPECT_EQ(per->value, 0u);
        EXPECT_EQ(per->aux, 0u);
    }
    {
        const Bytes tile = splitmix_bytes(96, 0x33);
        const Bytes data = repeat_block(tile, 384);
        SpanSource src(data);
        auto rows = probe(src, whole(data), Policy{});
        ASSERT_TRUE(rows.ok());
        const Observation* per = find_kind(rows.value(), ProbeKind::Period);
        ASSERT_NE(per, nullptr);
        EXPECT_EQ(per->period, BigInt(96));
    }
    {
        const Bytes distinct = {9, 7, 3, 5, 2, 8, 1, 4, 6, 0};
        SpanSource src(distinct);
        auto rows = probe(src, whole(distinct), Policy{});
        ASSERT_TRUE(rows.ok());
        const Observation* per = find_kind(rows.value(), ProbeKind::Period);
        ASSERT_NE(per, nullptr);
        EXPECT_EQ(per->period, BigInt(10));  // p = N: no nontrivial period
    }
    {
        Bytes empty;
        SpanSource src(empty);
        auto rows = probe(src, whole(empty), Policy{});
        ASSERT_TRUE(rows.ok());
        const Observation* per = find_kind(rows.value(), ProbeKind::Period);
        ASSERT_NE(per, nullptr);
        EXPECT_EQ(per->period, BigInt(0));  // p = N = 0
        EXPECT_TRUE(per->verified);
    }
}

TEST(C11Probe, PeriodAlwaysVerifiedAndMinimal) {
    const Bytes fixtures[] = {
        Bytes(300, 0x00),
        repeat_block(splitmix_bytes(12, 0x44), 96),
        splitmix_bytes(512, 0x55),
        Bytes{1, 1, 2, 1, 1, 2, 1, 1, 2, 1, 1},
    };
    for (const Bytes& data : fixtures) {
        SpanSource src(data);
        auto rows = probe(src, whole(data), Policy{});
        ASSERT_TRUE(rows.ok());
        const Observation* per = find_kind(rows.value(), ProbeKind::Period);
        ASSERT_NE(per, nullptr);
        EXPECT_TRUE(per->verified);  // §4.8: reported only when verified
        const std::optional<u64> p = per->period.to_u64_checked();
        ASSERT_TRUE(p.has_value());
        EXPECT_TRUE(ref_period_holds(data, *p));   // full byte check
        EXPECT_EQ(ref_minimal_period(data), *p);   // smallest p, by naive scan
    }
}

TEST(C11Probe, RunsExact) {
    Bytes data;
    for (int run = 1; run <= 20; ++run) {
        for (int i = 0; i < run; ++i) data.push_back(static_cast<u8>(run));
    }
    SpanSource src(data);
    auto rows = probe(src, whole(data), Policy{});
    ASSERT_TRUE(rows.ok());
    const Observation* runs = find_kind(rows.value(), ProbeKind::Runs);
    ASSERT_NE(runs, nullptr);
    EXPECT_EQ(runs->value, 20u);   // run_count
    EXPECT_EQ(runs->aux, 20u);     // max_run
    EXPECT_EQ(runs->value, ref_runs_count(data));
    EXPECT_EQ(runs->aux, ref_runs_max(data));
}

TEST(C11Probe, SkewPlanes) {
    const Bytes data(128, 0x0F);  // planes 0..3 all ones, 4..7 all zeros
    SpanSource src(data);
    auto rows = probe(src, whole(data), Policy{});
    ASSERT_TRUE(rows.ok());
    for (u32 plane = 0; plane < 8; ++plane) {
        const Observation* skew = find(rows.value(), ProbeKind::Skew, plane);
        ASSERT_NE(skew, nullptr) << "plane " << plane;
        EXPECT_EQ(skew->aux, 128u);
        EXPECT_EQ(skew->value, plane < 4u ? (1ull << 24) : 0u) << "plane " << plane;
    }
}

TEST(C11Probe, AffineAndQuadraticFits) {
    // b[i] = (7 + 3i) mod 256: exact affine, and quadratic with d2 = 0.
    Bytes aff;
    for (u64 i = 0; i < 64; ++i) aff.push_back(static_cast<u8>((7 + 3u * i) & 0xFFu));
    {
        SpanSource src(aff);
        auto rows = probe(src, whole(aff), Policy{});
        ASSERT_TRUE(rows.ok());
        const Observation* fit = find_kind(rows.value(), ProbeKind::AffineFit);
        ASSERT_NE(fit, nullptr);
        EXPECT_EQ(fit->value, 1u);
        EXPECT_EQ(fit->aux, 7ull | (3ull << 8));
        const Observation* quad = find_kind(rows.value(), ProbeKind::QuadraticFit);
        ASSERT_NE(quad, nullptr);
        EXPECT_EQ(quad->value, 1u);   // affine implies constant second difference
        EXPECT_EQ(quad->aux, 0u);
    }
    // b[i] = C(i,2) mod 256: quadratic with d2 = 1, not affine.
    Bytes quad;
    for (u64 i = 0; i < 64; ++i) quad.push_back(static_cast<u8>((i * (i - 1u) / 2u) & 0xFFu));
    {
        SpanSource src(quad);
        auto rows = probe(src, whole(quad), Policy{});
        ASSERT_TRUE(rows.ok());
        const Observation* fit = find_kind(rows.value(), ProbeKind::AffineFit);
        ASSERT_NE(fit, nullptr);
        EXPECT_EQ(fit->value, 0u);
        EXPECT_EQ(fit->aux, 0u);  // no fit: no witness
        const Observation* qfit = find_kind(rows.value(), ProbeKind::QuadraticFit);
        ASSERT_NE(qfit, nullptr);
        EXPECT_EQ(qfit->value, 1u);
        EXPECT_EQ(qfit->aux, 1u);
    }
    // Underdetermined ranges report no fit (decision D5).
    {
        const Bytes one = {42};
        SpanSource src(one);
        auto rows = probe(src, whole(one), Policy{});
        ASSERT_TRUE(rows.ok());
        EXPECT_EQ(find_kind(rows.value(), ProbeKind::AffineFit)->value, 0u);
        EXPECT_EQ(find_kind(rows.value(), ProbeKind::QuadraticFit)->value, 0u);
    }
}

TEST(C11Probe, BitComplexityPinned) {
    // One byte 0x01: plane 0 is [1] -> L=1, C=[1,1]; planes 1..7 are [0] -> L=0.
    const Bytes one = {0x01};
    SpanSource src(one);
    auto rows = probe(src, whole(one), Policy{});
    ASSERT_TRUE(rows.ok());
    for (u32 plane = 0; plane < 8; ++plane) {
        const Observation* bm = find(rows.value(), ProbeKind::BitComplexity, plane);
        ASSERT_NE(bm, nullptr);
        EXPECT_EQ(bm->aux, 0u);
        const auto expect = mapr::Sha256::hash(
            std::string_view(plane == 0u ? "\xC0" : "\x80", 1));
        ASSERT_TRUE(expect.ok());
        EXPECT_TRUE(same_digest(bm->digest, expect.value())) << "plane " << plane;
        EXPECT_EQ(bm->value, plane == 0u ? 1u : 0u) << "plane " << plane;
    }
    // [0, 0, 0, 1]: L = 4, C = 1 + x^4 -> packed [1,0,0,0,1] = 0x88.
    const Bytes four = {0x00, 0x00, 0x00, 0x01};
    SpanSource src4(four);
    auto rows4 = probe(src4, whole(four), Policy{});
    ASSERT_TRUE(rows4.ok());
    const Observation* bm0 = find(rows4.value(), ProbeKind::BitComplexity, 0);
    ASSERT_NE(bm0, nullptr);
    EXPECT_EQ(bm0->value, 4u);
    const auto expect4 = mapr::Sha256::hash(std::string_view("\x88", 1));
    ASSERT_TRUE(expect4.ok());
    EXPECT_TRUE(same_digest(bm0->digest, expect4.value()));
}

TEST(C11Probe, Repeat16Exact) {
    // 64 bytes of distinct 16-grams, then one planted duplicate window.
    Bytes data = splitmix_bytes(64, 0x66);
    for (u64 i = 0; i < 16; ++i) data[32 + i] = data[i];
    SpanSource src(data);
    auto rows = probe(src, whole(data), Policy{});
    ASSERT_TRUE(rows.ok());
    const Observation* rep = find_kind(rows.value(), ProbeKind::Repeat16);
    ASSERT_NE(rep, nullptr);
    EXPECT_EQ(rep->aux, 1u);          // only position 32 repeats position 0
    EXPECT_EQ(rep->param, 16u);
    EXPECT_FALSE(rep->sampled);
    EXPECT_EQ(rep->sample_count, 0u);
    // density = 1 / 49 positions
    EXPECT_EQ(rep->value, (1ull << 24) / 49u);

    // Short ranges: no positions at all.
    const Bytes short_data(15, 0x77);
    SpanSource src2(short_data);
    auto rows2 = probe(src2, whole(short_data), Policy{});
    ASSERT_TRUE(rows2.ok());
    const Observation* rep2 = find_kind(rows2.value(), ProbeKind::Repeat16);
    ASSERT_NE(rep2, nullptr);
    EXPECT_EQ(rep2->aux, 0u);
    EXPECT_EQ(rep2->value, 0u);
}

TEST(C11Probe, StrideWinnersAndTies) {
    // Period-2 tile: stride 2 wins with H = 0.
    Bytes two;
    for (u64 i = 0; i < 64; ++i) two.push_back(i % 2u == 0u ? 0x12u : 0x34u);
    {
        SpanSource src(two);
        auto rows = probe(src, whole(two), Policy{});
        ASSERT_TRUE(rows.ok());
        const Observation* st = find_kind(rows.value(), ProbeKind::Stride);
        ASSERT_NE(st, nullptr);
        EXPECT_EQ(st->aux, 2u);
        EXPECT_EQ(st->param, 2u);
        EXPECT_EQ(st->value, 0u);
    }
    // Period-4 tile: 4 and 8 (and larger multiples) tie at H = 0 -> smallest.
    Bytes four;
    for (u64 i = 0; i < 64; ++i) four.push_back(static_cast<u8>(0x40 + (i % 4u) * 3u));
    {
        SpanSource src(four);
        auto rows = probe(src, whole(four), Policy{});
        ASSERT_TRUE(rows.ok());
        const Observation* st = find_kind(rows.value(), ProbeKind::Stride);
        ASSERT_NE(st, nullptr);
        EXPECT_EQ(st->aux, 4u);
    }
    // Period-3 tile: only 3 divides a stride in the set -> unique winner.
    Bytes three;
    for (u64 i = 0; i < 66; ++i) three.push_back(static_cast<u8>(1 + (i % 3u) * 5u));
    {
        SpanSource src(three);
        auto rows = probe(src, whole(three), Policy{});
        ASSERT_TRUE(rows.ok());
        const Observation* st = find_kind(rows.value(), ProbeKind::Stride);
        ASSERT_NE(st, nullptr);
        EXPECT_EQ(st->aux, 3u);
    }
    // Near-constant data: H0 below 0.5 bit -> no stride reported.
    const Bytes flat(512, 0x5A);
    {
        SpanSource src(flat);
        auto rows = probe(src, whole(flat), Policy{});
        ASSERT_TRUE(rows.ok());
        EXPECT_EQ(find_kind(rows.value(), ProbeKind::Stride), nullptr);
    }
}

TEST(C11Probe, ChangePointPinned) {
    // 32 KiB zeros | 32 KiB random: the sharp boundary at 32768 is on the scan
    // grid and must be detected exactly (O8.10 shape).
    Bytes data(65536, 0x00);
    const Bytes noise = splitmix_bytes(32768, 0x77);
    for (std::size_t i = 0; i < noise.size(); ++i) data[32768 + i] = noise[i];
    SpanSource src(data);
    auto rows = probe(src, whole(data), Policy{});
    ASSERT_TRUE(rows.ok());
    bool at_boundary = false;
    std::vector<u64> offsets;
    for (const Observation& obs : rows.value()) {
        if (obs.kind != ProbeKind::ChangePoint) continue;
        EXPECT_EQ(obs.value, 1u);
        EXPECT_EQ(obs.param, static_cast<u32>(kChangeWindow));
        offsets.push_back(obs.aux);
        if (obs.aux == 32768u) at_boundary = true;
    }
    EXPECT_TRUE(at_boundary);
    EXPECT_TRUE(std::is_sorted(offsets.begin(), offsets.end()));
    // Every kept point is a window boundary the rule fires on, within one
    // window of the sharp edge.
    for (const u64 off : offsets) {
        EXPECT_GE(off, 32768u - kChangeWindow);
        EXPECT_LE(off, 32768u + kChangeWindow);
    }
    // A segment below 2W has no interior window boundary -> no rows.
    const Bytes small(4096, 0x00);
    SpanSource src2(small);
    auto rows2 = probe(src2, whole(small), Policy{});
    ASSERT_TRUE(rows2.ok());
    EXPECT_EQ(find_kind(rows2.value(), ProbeKind::ChangePoint), nullptr);
}

// ===========================================================================
// §4.9 — sampling
// ===========================================================================

TEST(C11Sampling, ThresholdAndWindows) {
    // N = 2 MiB exactly: full-range path.
    const Bytes exact(2u << 20, 0x33);
    {
        SpanSource src(exact);
        auto rows = probe(src, whole(exact), Policy{});
        ASSERT_TRUE(rows.ok());
        const Observation* h2 = find_kind(rows.value(), ProbeKind::H2);
        const Observation* rep = find_kind(rows.value(), ProbeKind::Repeat16);
        ASSERT_NE(h2, nullptr);
        ASSERT_NE(rep, nullptr);
        EXPECT_FALSE(h2->sampled);
        EXPECT_EQ(h2->sample_count, 0u);
        EXPECT_FALSE(rep->sampled);
        EXPECT_EQ(rep->sample_count, 0u);
        EXPECT_EQ(h2->aux, exact.size() - 2u);
    }
    // N = 2 MiB + 1: sample path, 16 windows of 64 KiB at the §4.9 offsets.
    Bytes sampled_data((2u << 20) + 1u, 0x33);
    const Bytes noise = splitmix_bytes(256, 0x88);
    for (std::size_t i = 0; i < noise.size(); ++i) sampled_data[(2u << 20) - 256u + i] = noise[i];
    {
        SpanSource src(sampled_data);
        auto rows = probe(src, whole(sampled_data), Policy{});
        ASSERT_TRUE(rows.ok());
        const Observation* h2 = find_kind(rows.value(), ProbeKind::H2);
        const Observation* rep = find_kind(rows.value(), ProbeKind::Repeat16);
        ASSERT_NE(h2, nullptr);
        ASSERT_NE(rep, nullptr);
        EXPECT_TRUE(h2->sampled);
        EXPECT_EQ(h2->sample_count, 16u);
        EXPECT_EQ(h2->aux, 16ull * 65534ull);
        EXPECT_TRUE(rep->sampled);
        EXPECT_EQ(rep->sample_count, 16u);
        EXPECT_TRUE(validate_observation(*h2, sampled_data.size()).ok());
        EXPECT_TRUE(validate_observation(*rep, sampled_data.size()).ok());
    }
    // The offsets are floor(j·(N - 65536)/15) and stay inside the range.
    auto offsets = sample_window_offsets((2u << 20) + 1u);
    ASSERT_TRUE(offsets.ok());
    for (u64 j = 0; j < 16; ++j) {
        const u64 expect = (j * (((2ull << 20) + 1u) - 65536u)) / 15u;
        EXPECT_EQ(offsets.value()[static_cast<std::size_t>(j)], expect);
        EXPECT_LE(expect + 65536u, (2ull << 20) + 1u);
    }
    EXPECT_FALSE(sample_window_offsets(2u << 20).ok());  // at threshold: Invalid
}

// ===========================================================================
// §4.10 — effort
// ===========================================================================

TEST(C11Effort, BudgetSelectsExistenceNotValues) {
    const Bytes data = splitmix_bytes(300, 0x99);
    SpanSource src(data);
    std::map<std::string, std::string> by_effort[10];
    for (const u8 effort : {u8{0}, u8{2}, u8{3}, u8{5}, u8{9}}) {
        Policy pol;
        pol.effort = effort;
        auto rows = probe(src, whole(data), pol);
        ASSERT_TRUE(rows.ok()) << "effort " << static_cast<unsigned>(effort);
        const bool full = effort >= 3u;
        EXPECT_EQ(find_kind(rows.value(), ProbeKind::H2) != nullptr, full);
        EXPECT_EQ(find_kind(rows.value(), ProbeKind::Repeat16) != nullptr, full);
        u32 bm_planes = 0;
        for (const Observation& obs : rows.value()) {
            if (obs.kind == ProbeKind::BitComplexity) ++bm_planes;
        }
        EXPECT_EQ(bm_planes, full ? 8u : 2u);
        for (const Observation& obs : rows.value()) {
            if (obs.kind == ProbeKind::Stride) {
                if (full) {
                    EXPECT_NE(std::find(kStrideSet.begin(), kStrideSet.end(), obs.aux),
                              kStrideSet.end());
                } else {
                    EXPECT_NE(std::find(kStrideSetReduced.begin(), kStrideSetReduced.end(),
                                        obs.aux),
                              kStrideSetReduced.end());
                }
            }
        }
        for (const Observation& obs : rows.value()) {
            const std::string key =
                std::string(probe_kind_name(obs.kind)) + ":" + std::to_string(obs.param);
            by_effort[effort][key] = observation_text(obs);
        }
    }
    // Values of the shared observations are identical at every effort.  A
    // `Stride` row is keyed by its chosen stride: the candidate set itself is
    // an effort budget (§4.10), so two efforts may legitimately pick different
    // winners; any row present at both efforts must still agree.
    for (const u8 effort : {u8{0}, u8{2}, u8{3}, u8{9}}) {
        for (const auto& [key, text] : by_effort[effort]) {
            const auto it = by_effort[5].find(key);
            if (it == by_effort[5].end()) {
                EXPECT_EQ(key.rfind("Stride:", 0), 0u)
                    << "effort " << static_cast<unsigned>(effort)
                    << " row vanished at effort 5: " << key;
                continue;
            }
            EXPECT_EQ(it->second, text) << "effort " << static_cast<unsigned>(effort) << " "
                                        << key;
        }
    }
    Policy bad;
    bad.effort = 10;
    EXPECT_FALSE(probe(src, whole(data), bad).ok());  // out of domain: Invalid
}

// ===========================================================================
// §5.4 — merge order, reproducibility, locality (E4-I2)
// ===========================================================================

TEST(C11Determinism, MergeOrder) {
    // Per-segment probe results arrive out of order; the merge is canonical.
    const Bytes a = splitmix_bytes(64, 0xA1);
    const Bytes b = splitmix_bytes(64, 0xB2);
    SpanSource src_a(a);
    SpanSource src_b(b);
    const Segment seg_a{BigInt(0), BigInt(64), 0, 0};
    const Segment seg_b{BigInt(64), BigInt(128), 1, 0};
    Bytes joined = a;
    joined.insert(joined.end(), b.begin(), b.end());
    SpanSource src_all(joined);

    auto rows_a = probe(src_all, seg_a, Policy{});
    auto rows_b = probe(src_all, seg_b, Policy{});
    ASSERT_TRUE(rows_a.ok());
    ASSERT_TRUE(rows_b.ok());

    std::vector<Observation> serial = rows_a.value();
    const std::vector<Observation> copy_b = rows_b.value();
    serial.insert(serial.end(), copy_b.begin(), copy_b.end());

    std::vector<Observation> shuffled = rows_b.value();
    const std::vector<Observation> copy_a = rows_a.value();
    shuffled.insert(shuffled.end(), copy_a.begin(), copy_a.end());
    std::reverse(shuffled.begin(), shuffled.end());
    merge_observations(shuffled);
    ASSERT_EQ(serial.size(), shuffled.size());
    for (std::size_t i = 0; i < serial.size(); ++i) {
        EXPECT_EQ(observation_text(serial[i]), observation_text(shuffled[i])) << "row " << i;
    }
}

TEST(C11Determinism, ReproducibleFromWhere) {
    const Bytes data = splitmix_bytes(2048, 0xC3);
    Bytes source_bytes = data;
    for (int pad = 0; pad < 32; ++pad) source_bytes.insert(source_bytes.begin(), 0xEE);
    source_bytes.insert(source_bytes.end(), 32, 0xFF);
    SpanSource src(source_bytes);
    const Segment seg{BigInt(32), BigInt(32 + 2048), 0, 0};
    auto first = probe(src, seg, Policy{});
    auto second = probe(src, seg, Policy{});
    ASSERT_TRUE(first.ok());
    ASSERT_TRUE(second.ok());
    ASSERT_EQ(first.value().size(), second.value().size());
    for (std::size_t i = 0; i < first.value().size(); ++i) {
        EXPECT_EQ(observation_text(first.value()[i]), observation_text(second.value()[i]))
            << "row " << i;
    }
}

TEST(C11Determinism, LocalityMutationOutsideWhere) {
    Bytes source_bytes = splitmix_bytes(1024, 0xD4);
    source_bytes.insert(source_bytes.end(), 1024, 0x11);
    SpanSource src(source_bytes);
    const Segment seg{BigInt(0), BigInt(512), 0, 0};
    auto before = probe(src, seg, Policy{});
    ASSERT_TRUE(before.ok());
    // Mutate a byte outside `where` in the underlying memory.
    source_bytes[900] ^= 0xFF;
    SpanSource src2(source_bytes);
    auto after = probe(src2, seg, Policy{});
    ASSERT_TRUE(after.ok());
    ASSERT_EQ(before.value().size(), after.value().size());
    for (std::size_t i = 0; i < before.value().size(); ++i) {
        EXPECT_EQ(observation_text(before.value()[i]), observation_text(after.value()[i]))
            << "row " << i;
    }
}

// ===========================================================================
// §5.3 — verify_period
// ===========================================================================

TEST(C11VerifyPeriod, Api) {
    Bytes data = {1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4};
    SpanSource src(data);
    Observation obs;
    obs.where = whole(data);
    obs.kind = ProbeKind::Period;
    obs.period = BigInt(4);
    obs.verified = true;
    auto ok = verify_period(src, obs);
    ASSERT_TRUE(ok.ok());
    EXPECT_TRUE(ok.value());

    obs.period = BigInt(3);
    auto bad = verify_period(src, obs);
    ASSERT_TRUE(bad.ok());
    EXPECT_FALSE(bad.value());  // claim does not hold: Ok(false), not an error

    obs.period = BigInt(4);
    obs.verified = false;
    EXPECT_FALSE(verify_period(src, obs).ok());  // unverified claim: Invalid

    obs.verified = true;
    obs.kind = ProbeKind::H2;
    EXPECT_FALSE(verify_period(src, obs).ok());  // wrong kind: Invalid

    obs.kind = ProbeKind::Period;
    obs.period = BigInt(13);
    EXPECT_FALSE(verify_period(src, obs).ok());  // p > N: Invalid

    obs.period = BigInt(0);
    EXPECT_FALSE(verify_period(src, obs).ok());  // p = 0 on non-empty: Invalid

    obs.where = Segment{BigInt(0), BigInt(20), 0, 0};
    obs.period = BigInt(1);
    EXPECT_FALSE(verify_period(src, obs).ok());  // where outside source: Invalid

    // Every period reported by probe() verifies.
    auto rows = probe(src, whole(data), Policy{});
    ASSERT_TRUE(rows.ok());
    for (const Observation& row : rows.value()) {
        if (row.kind != ProbeKind::Period) continue;
        auto v = verify_period(src, row);
        ASSERT_TRUE(v.ok());
        EXPECT_TRUE(v.value());
    }
}

// ===========================================================================
// §9 — errors
// ===========================================================================

TEST(C11Errors, InvalidAndIo) {
    const Bytes data(64, 0x22);
    SpanSource src(data);
    // Segment outside the input.
    EXPECT_FALSE(probe(src, Segment{BigInt(0), BigInt(65), 0, 0}, Policy{}).ok());
    EXPECT_FALSE(probe(src, Segment{BigInt(10), BigInt(5), 0, 0}, Policy{}).ok());
    // Out-of-domain effort.
    Policy bad;
    bad.effort = 200;
    EXPECT_FALSE(probe(src, Segment{BigInt(0), BigInt(64), 0, 0}, bad).ok());

    class FailingSource final : public Source {
    public:
        [[nodiscard]] BigInt size() const noexcept override { return BigInt(64); }
        [[nodiscard]] MeasureCode read(const BigInt&, std::span<u8>) const noexcept override {
            return MeasureCode::Io;
        }
    };
    FailingSource failing;
    auto r = probe(failing, Segment{BigInt(0), BigInt(64), 0, 0}, Policy{});
    ASSERT_FALSE(r.ok());
    EXPECT_EQ(r.code(), MeasureCode::Io);
}

TEST(C11Errors, SegmentFromLargerSource) {
    // A mid-source segment measures only its own bytes (E4-I7).
    Bytes data = splitmix_bytes(256, 0xE5);
    SpanSource src(data);
    const Segment seg{BigInt(64), BigInt(192), 0, 0};
    auto rows = probe(src, seg, Policy{});
    ASSERT_TRUE(rows.ok());
    for (const Observation& obs : rows.value()) {
        EXPECT_EQ(obs.where.begin, BigInt(64));
        EXPECT_EQ(obs.where.end, BigInt(192));
        EXPECT_TRUE(validate_observation(obs, 256).ok());
    }
}

}  // namespace
}  // namespace marp::v2
