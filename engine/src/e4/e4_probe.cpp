// MARP v2 — E4 MEASURE — C11 PROBE (implementation).
//
// Every probe is computed from the bytes of the segment's own range and the
// constants of the specification, and nothing else (E4-I2, E4-I12):
//
//   1. `probe()` materialises `[begin, end)` once through `Source::read`, then
//      runs the §4.8 definitions over that buffer.  The buffer is an
//      implementation detail; every value is a pure function of the bytes.
//   2. `verify_period()` re-reads the recorded range and performs the §4.8 full
//      byte check against the claim in the observation.
//   3. `merge_observations()` is the §5.4 serial merge: stable sort by segment
//      begin offset, then `ProbeKind` ordinal, then `param`.
//
// Fixed point (E4 §4.2): all entropy and fraction values are Q24.24 exact
// integers built from `ilog2_q24` (C10) in 128-bit intermediates with a single
// final floor.  There is no floating point anywhere in this translation unit.
//
// Locality (E4-I2, E4-I10): the `H2`/`Repeat16` sample path takes 16 windows
// of 64 KiB at `floor(j·(N - 65536) / 15)`, entirely inside `where`, and the
// result is marked `sampled = true`, `sample_count = 16` — it never claims
// full-range observation.  Change points are detected by the §4.5 rule applied
// to the segment's own bytes on a grid anchored at the segment start, so no
// byte outside `where` can reach a `ChangePoint` value.
//
// Determinism (E4-I3): count maps are only ever *accumulated* into exact
// 128-bit sums (integer addition is commutative and associative, so iteration
// order cannot change a value), `Repeat16` counts a position by existence of an
// earlier equal key regardless of map order, and no result iterates an
// unordered container.

#include "mapr/e4/e4_probe.hpp"

#include <algorithm>
#include <cstring>
#include <limits>
#include <map>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "mapr/e1_sha256.hpp"

namespace marp::v2 {

namespace {

// E4 §4.2 requires a 128-bit intermediate; spelled through `__extension__`
// because the project builds with `-pedantic -Werror`.
#if !defined(__SIZEOF_INT128__)
#error "C11 PROBE requires a 128-bit unsigned intermediate (MARP2-E4 §4.2)"
#endif
__extension__ typedef unsigned __int128 u128;

constexpr std::size_t kBlockBytes = 64u * 1024u;

// ---------------------------------------------------------------------------
// Source access
// ---------------------------------------------------------------------------

// Reads `[off, off + count)` into `out` in fixed blocks.  A short or failed
// read is `Io`; nothing is silently zero-filled.
[[nodiscard]] MeasureCode read_range(Source& source, u64 off, u64 count, std::vector<u8>& out) {
    out.assign(static_cast<std::size_t>(count), 0u);
    if (count == 0u) return MeasureCode::Ok;
    u64 pos = off;
    u64 left = count;
    while (left > 0u) {
        const std::size_t want = static_cast<std::size_t>(std::min<u64>(left, kBlockBytes));
        const MeasureCode rc = source.read(BigInt(pos),
                                           std::span<u8>(out.data() + (pos - off), want));
        if (rc != MeasureCode::Ok) return MeasureCode::Io;
        pos += static_cast<u64>(want);
        left -= static_cast<u64>(want);
    }
    return MeasureCode::Ok;
}

[[nodiscard]] MeasureResult<u64> source_length(Source& source) {
    const std::optional<u64> length = source.size().to_u64_checked();
    if (!length.has_value()) return MeasureCode::Invalid;
    return *length;
}

// ---------------------------------------------------------------------------
// Fixed-point helpers (E4 §4.2)
// ---------------------------------------------------------------------------

// `floor((Σ n_c·ilog2(n_c) − Σ n_{c,b}·ilog2(n_{c,b})) / N)` — the §4.2
// order-1 / order-2 formula in one place.  Both sums are exact 128-bit
// integers; the single division is the final floor.  The mathematically
// non-negative numerator is saturated to 0 on the (unreachable for integer
// counts) rounding edge where floored `ilog2` terms could subtract past zero,
// so a `u128` can never wrap.
[[nodiscard]] u64 conditional_entropy_q24(u128 sum_context, u128 sum_joint, u64 samples) {
    if (samples == 0u) return 0u;
    if (sum_joint > sum_context) return 0u;
    return static_cast<u64>((sum_context - sum_joint) / static_cast<u128>(samples));
}

[[nodiscard]] u128 sum_ilog(std::span<const u64> counts) {
    u128 total = 0u;
    for (const u64 c : counts) {
        if (c == 0u) continue;
        total += static_cast<u128>(c) * static_cast<u128>(ilog2_q24(c));
    }
    return total;
}

[[nodiscard]] u128 sum_ilog_map(const std::map<u32, u64>& counts) {
    u128 total = 0u;
    for (const auto& [key, count] : counts) {
        (void)key;
        total += static_cast<u128>(count) * static_cast<u128>(ilog2_q24(count));
    }
    return total;
}

// Order-1 entropy of consecutive byte pairs `(b[i-1], b[i])`, i in [1, N):
// contexts are first bytes, joints are the pairs, samples = pair count (the
// `N = Σ n_i` of §4.2).
[[nodiscard]] u64 h1_pairs_q24(std::span<const u8> bytes) {
    if (bytes.size() < 2u) return 0u;
    std::array<u64, 256> context{};
    std::map<u32, u64> joint;
    for (std::size_t i = 1; i < bytes.size(); ++i) {
        const u32 key = (static_cast<u32>(bytes[i - 1u]) << 8) | static_cast<u32>(bytes[i]);
        ++context[bytes[i - 1u]];
        ++joint[key];
    }
    const u64 samples = static_cast<u64>(bytes.size() - 1u);
    return conditional_entropy_q24(sum_ilog(std::span<const u64>(context.data(), 256)),
                                   sum_ilog_map(joint), samples);
}

// Order-2 entropy of consecutive trigrams `(b[i-2], b[i-1], b[i])`, i in
// [2, N): contexts are the leading pairs, joints are the trigrams, samples =
// trigram count.
[[nodiscard]] u64 h2_trigrams_q24(std::span<const u8> bytes) {
    if (bytes.size() < 3u) return 0u;
    std::map<u32, u64> joint;    // trigram counts
    std::map<u32, u64> context;  // leading-pair counts
    for (std::size_t i = 2; i < bytes.size(); ++i) {
        const u32 tri = (static_cast<u32>(bytes[i - 2u]) << 16) |
                        (static_cast<u32>(bytes[i - 1u]) << 8) | static_cast<u32>(bytes[i]);
        ++joint[tri];
        ++context[tri >> 8];
    }
    const u64 samples = static_cast<u64>(bytes.size() - 2u);
    return conditional_entropy_q24(sum_ilog_map(context), sum_ilog_map(joint), samples);
}

// H2 aggregated over the §4.9 sample windows: the caller accumulates trigram
// counts across windows; the formula runs once over the aggregate.  `samples`
// is the aggregated trigram count (16·(65536−2) on the full sample path).
[[nodiscard]] u64 h2_aggregate_q24(const std::map<u32, u64>& trigrams) {
    std::map<u32, u64> context;
    u64 samples = 0u;
    for (const auto& [tri, count] : trigrams) {
        context[tri >> 8] += count;
        samples += count;
    }
    return conditional_entropy_q24(sum_ilog_map(context), sum_ilog_map(trigrams), samples);
}

// The §4.8 stride statistic: "the aggregate order-1 entropy under `i mod s`",
// i.e. `H1` with the position class as context.  Positions are the samples.
[[nodiscard]] u64 stride_entropy_q24(std::span<const u8> bytes, u64 stride) {
    if (bytes.empty() || stride == 0u) return 0u;
    std::vector<u64> context(static_cast<std::size_t>(stride), 0u);
    std::map<u32, u64> joint;
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        const u64 cls = static_cast<u64>(i) % stride;
        ++context[static_cast<std::size_t>(cls)];
        const u32 key = (static_cast<u32>(cls) << 8) | static_cast<u32>(bytes[i]);
        ++joint[key];
    }
    return conditional_entropy_q24(sum_ilog(std::span<const u64>(context.data(), context.size())),
                                   sum_ilog_map(joint), static_cast<u64>(bytes.size()));
}

// ---------------------------------------------------------------------------
// Runs (§4.8)
// ---------------------------------------------------------------------------

struct RunStats {
    u64 run_count = 0;
    u64 max_run = 0;
};

[[nodiscard]] RunStats run_stats(std::span<const u8> bytes) {
    RunStats out;
    if (bytes.empty()) return out;
    u64 current = 1u;
    out.run_count = 1u;
    for (std::size_t i = 1; i < bytes.size(); ++i) {
        if (bytes[i] == bytes[i - 1u]) {
            ++current;
        } else {
            out.max_run = std::max(out.max_run, current);
            current = 1u;
            ++out.run_count;
        }
    }
    out.max_run = std::max(out.max_run, current);
    return out;
}

// ---------------------------------------------------------------------------
// Period (§4.8)
// ---------------------------------------------------------------------------

// The smallest `p` with `b[i] == b[i - p]` for all `i >= p`, via the KMP prefix
// function: `p = N − π(N−1)`.  The empty range reports `p = 0` (= `N`).  For
// `N >= 1` the result is in `[1, N]`, and `p = N` is the vacuous "no nontrivial
// period" case.
[[nodiscard]] u64 minimal_period(std::span<const u8> bytes) {
    const u64 n = static_cast<u64>(bytes.size());
    if (n == 0u) return 0u;
    std::vector<u64> pi(static_cast<std::size_t>(n), 0u);
    for (u64 i = 1; i < n; ++i) {
        u64 j = pi[static_cast<std::size_t>(i - 1u)];
        while (j > 0u && bytes[static_cast<std::size_t>(i)] != bytes[static_cast<std::size_t>(j)]) {
            j = pi[static_cast<std::size_t>(j - 1u)];
        }
        if (bytes[static_cast<std::size_t>(i)] == bytes[static_cast<std::size_t>(j)]) ++j;
        pi[static_cast<std::size_t>(i)] = j;
    }
    return n - pi[static_cast<std::size_t>(n - 1u)];
}

// ---------------------------------------------------------------------------
// Repeat16 (§4.8)
// ---------------------------------------------------------------------------

// Positions `p` in `[0, N - 16]` whose 16-byte window equals the window of some
// earlier position `q < p` **inside the same range**.  Hash buckets with exact
// key comparison: a hash collision can never count a position, only an exact
// 16-byte equality can.  Returns the match count; `positions_out` receives the
// number of candidate positions (`N - 15` for `N >= 16`).
[[nodiscard]] u64 repeat16_matches(std::span<const u8> bytes, u64& positions_out) {
    positions_out = 0u;
    if (bytes.size() < kRepeat16Window) return 0u;
    const u64 n = static_cast<u64>(bytes.size());
    const u64 window = static_cast<u64>(kRepeat16Window);
    positions_out = n - window + 1u;

    auto key_at = [&](u64 pos) -> std::span<const u8> {
        return bytes.subspan(static_cast<std::size_t>(pos), kRepeat16Window);
    };
    auto hash_of = [&](std::span<const u8> key) -> u64 {
        u64 h = 0xcbf29ce484222325ull;  // FNV-1a 64, fixed constants
        for (const u8 b : key) {
            h ^= static_cast<u64>(b);
            h *= 0x100000001b3ull;
        }
        return h;
    };

    std::unordered_map<u64, std::vector<u64>> seen;
    seen.reserve(static_cast<std::size_t>(positions_out));
    u64 matches = 0u;
    for (u64 p = 0u; p + window <= n; ++p) {
        const std::span<const u8> key = key_at(p);
        const u64 h = hash_of(key);
        bool matched = false;
        const auto it = seen.find(h);
        if (it != seen.end()) {
            for (const u64 q : it->second) {
                if (std::memcmp(key.data(), key_at(q).data(), kRepeat16Window) == 0) {
                    matched = true;
                    break;
                }
            }
        }
        if (matched) ++matches;
        seen[h].push_back(p);
    }
    return matches;
}

// ---------------------------------------------------------------------------
// Berlekamp–Massey (§4.8 `BitComplexity`)
// ---------------------------------------------------------------------------

struct BmResult {
    u64 length = 0;          // L, the linear complexity
    std::vector<u8> coeffs;  // c_0 .. c_L of the connection polynomial (c_0 = 1)
};

// Binary Berlekamp–Massey over GF(2): `C(x) = 1 + c_1·x + ... + c_L·x^L` is the
// connection polynomial of the shortest LFSR with
// `s_n = Σ_{i=1..L} c_i·s_{n-i}` for all `n >= L`.  Coefficients live in `u64`
// words so one step costs O(L/64) word operations:
//
//   d  = s_n xor Σ_{i=1..L} c_i·s_{n-i}          (parity of (C>>1) & S)
//   if d == 0: m++
//   else: T = C; C += x^m·B; if 2L <= n: L = n+1-L; B = T; m = 1; else m++
//
// `S` is a shift register with bit `j = s_{n-1-j}`, rebuilt from the input for
// the bits a growth of `L` exposes, so the register never needs more than
// `L/64 + 1` words.  The gate's reference is written independently from the
// same definition.
[[nodiscard]] BmResult berlekamp_massey(std::span<const u8> bits) {
    BmResult out;
    const u64 n = static_cast<u64>(bits.size());
    if (n == 0u) {
        out.coeffs.assign(1u, 1u);  // C(x) = 1 for the empty sequence
        return out;
    }
    const u64 word_cap = n / 64u + 2u;
    std::vector<u64> c(word_cap, 0u);
    std::vector<u64> b(word_cap, 0u);
    std::vector<u64> sreg(word_cap, 0u);
    std::vector<u64> scratch(word_cap, 0u);
    c[0] = 1u;
    b[0] = 1u;
    u64 l = 0u;        // linear complexity so far
    u64 m = 1u;        // age of the last discrepancy update
    u64 cover = 1u;    // words of C/S that can matter (bits 0 .. 64*cover-1)
    u64 b_words = 1u;  // meaningful words of B (stale words are cleared)

    for (u64 idx = 0; idx < n; ++idx) {
        // d = s[idx] xor Σ_{i=1..L} c_i·s[idx-i]; bit j of S is s[idx-1-j].
        u8 d = bits[static_cast<std::size_t>(idx)];
        for (u64 w = 0; w < cover; ++w) {
            const u64 cw = (c[w] >> 1) | ((w + 1u < word_cap ? c[w + 1u] : 0u) << 63);
            if ((static_cast<u64>(__builtin_popcountll(cw & sreg[w])) & 1u) != 0u) d ^= 1u;
        }

        // Shift the register and insert s[idx] at bit 0.
        u64 carry = static_cast<u64>(bits[static_cast<std::size_t>(idx)]);
        for (u64 w = 0; w < cover; ++w) {
            const u64 next = (sreg[w] << 1) | carry;
            carry = sreg[w] >> 63;
            sreg[w] = next;
        }

        if (d == 0u) {
            ++m;
            continue;
        }

        // T = C (pre-update), C += x^m·B.
        std::copy(c.begin(), c.begin() + static_cast<std::ptrdiff_t>(cover), scratch.begin());
        const u64 shift_words = m / 64u;
        const unsigned shift_bits = static_cast<unsigned>(m % 64u);
        u64 reach = cover;  // words of C that the xor can touch
        const u64 blim = std::min(cover, b_words);
        for (u64 w = 0; w < blim; ++w) {
            if (b[w] == 0u) continue;
            const u64 wj = w + shift_words;
            if (wj >= word_cap) break;
            c[wj] ^= b[w] << shift_bits;
            if (shift_bits != 0u && wj + 1u < word_cap) c[wj + 1u] ^= b[w] >> (64u - shift_bits);
            reach = std::max(reach, wj + 2u);
        }
        reach = std::min(reach, word_cap);

        if (2u * l <= idx) {
            l = idx + 1u - l;
            // B <- T: the pre-update C.  Clear B's stale words past `cover`
            // first (scratch beyond `cover` is never written and must not leak
            // an older T into B).
            for (u64 w = cover; w < b_words; ++w) b[w] = 0u;
            std::copy(scratch.begin(), scratch.begin() + static_cast<std::ptrdiff_t>(cover),
                      b.begin());
            b_words = cover;
            m = 1u;
        } else {
            ++m;
        }

        // Grow the covered window to the new L (and to the extent of the
        // update), rebuilding the register bits a growth exposes straight from
        // the input: after step `idx`, bit j of S must be s[idx - j].
        u64 need = std::min<u64>(word_cap, (l + 63u) / 64u + 1u);
        need = std::max(need, reach);
        for (u64 w = cover; w < need; ++w) {
            u64 word = 0u;
            for (unsigned t = 0; t < 64u; ++t) {
                const u64 j = 64u * w + t;
                if (j < idx + 1u) {
                    word |= static_cast<u64>(bits[static_cast<std::size_t>(idx - j)]) << t;
                }
            }
            sreg[w] = word;
        }
        cover = std::max(cover, need);
    }

    out.length = l;
    out.coeffs.assign(static_cast<std::size_t>(l) + 1u, 0u);
    for (u64 i = 0; i <= l; ++i) {
        out.coeffs[static_cast<std::size_t>(i)] =
            static_cast<u8>((c[i / 64u] >> (i % 64u)) & 1u);
    }
    return out;
}

// SHA-256 of the packed connection polynomial: `c_0 .. c_L` as `L + 1` bits,
// packed MSB-first (`c_0` in bit 7 of byte 0), zero-padded to whole bytes.
[[nodiscard]] std::array<u8, 32> poly_digest(const std::vector<u8>& coeffs) {
    std::vector<u8> packed((coeffs.size() + 7u) / 8u, 0u);
    for (std::size_t i = 0; i < coeffs.size(); ++i) {
        if (coeffs[i] != 0u) {
            packed[i / 8u] = static_cast<u8>(packed[i / 8u] | (0x80u >> (i % 8u)));
        }
    }
    const auto digest = mapr::Sha256::hash(
        std::string_view(reinterpret_cast<const char*>(packed.data()), packed.size()));
    std::array<u8, 32> out{};
    if (digest.ok()) {
        for (std::size_t i = 0; i < 32u; ++i) out[i] = digest.value()[i];
    }
    return out;
}

// ---------------------------------------------------------------------------
// Change points (§4.5) over one span
// ---------------------------------------------------------------------------

// The §4.5 window rule applied to the segment's own bytes, with the scan grid
// anchored at the segment start: interior window boundaries `i` (relative) with
// `W` bytes on both sides, stepping by the hop, kept when `dH0 >= 2^24` or
// `dZ >= 2^22`, capped at `N/2048 + 16`, deduplicated within 2048 bytes
// keeping the smaller offset.  Relative offsets ascend.
[[nodiscard]] std::vector<u64> span_change_points(std::span<const u8> bytes) {
    std::vector<u64> candidates;
    const u64 n = static_cast<u64>(bytes.size());
    const u64 window = kChangeWindow;
    const u64 hop = kChangeHop;
    if (n < 2u * window) return candidates;
    const u64 cap = n / kChangeHop + kChangeCapSlack;
    candidates.reserve(static_cast<std::size_t>(std::min<u64>(cap, kMaxProbeObservations)));

    std::array<u64, 256> left_counts{};
    std::array<u64, 256> right_counts{};
    for (u64 i = window; i + window <= n; i += hop) {
        left_counts.fill(0u);
        right_counts.fill(0u);
        u64 zeros_left = 0u;
        u64 zeros_right = 0u;
        for (u64 j = i - window; j < i; ++j) {
            const u8 v = bytes[static_cast<std::size_t>(j)];
            ++left_counts[v];
            if (v == 0u) ++zeros_left;
        }
        for (u64 j = i; j < i + window; ++j) {
            const u8 v = bytes[static_cast<std::size_t>(j)];
            ++right_counts[v];
            if (v == 0u) ++zeros_right;
        }
        const u64 h_left = h0_q24_from_counts(std::span<const u64, 256>(left_counts));
        const u64 h_right = h0_q24_from_counts(std::span<const u64, 256>(right_counts));
        const u64 z_left = static_cast<u64>((static_cast<u128>(zeros_left) << 24u) / window);
        const u64 z_right = static_cast<u64>((static_cast<u128>(zeros_right) << 24u) / window);
        const u64 d_h0 = h_left > h_right ? h_left - h_right : h_right - h_left;
        const u64 d_z = z_left > z_right ? z_left - z_right : z_right - z_left;
        if (d_h0 >= kChangeEntropyQ24 || d_z >= kChangeZeroFracQ24) {
            if (candidates.size() >= cap) break;  // §4.5 cap: keep the first ones
            candidates.push_back(i);
        }
    }
    // Dedup within 2048 bytes, keeping the smaller offset (candidates ascend).
    std::vector<u64> kept;
    kept.reserve(candidates.size());
    for (const u64 offset : candidates) {
        if (!kept.empty() && offset - kept.back() < kChangeDedupBytes) continue;
        kept.push_back(offset);
    }
    return kept;
}

// ---------------------------------------------------------------------------
// Rendering helpers
// ---------------------------------------------------------------------------

std::string digest_hex(const std::array<u8, 32>& digest) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(64u);
    for (const u8 b : digest) {
        out.push_back(kHex[(b >> 4) & 0x0Fu]);
        out.push_back(kHex[b & 0x0Fu]);
    }
    return out;
}

[[nodiscard]] bool digest_is_zero(const std::array<u8, 32>& digest) noexcept {
    for (const u8 b : digest) {
        if (b != 0u) return false;
    }
    return true;
}

}  // namespace

// ---------------------------------------------------------------------------
// Parameters and effort budget (E4 §4.9, §4.10)
// ---------------------------------------------------------------------------

MeasureResult<std::array<u64, kSampleWindowCount>> sample_window_offsets(u64 length) noexcept {
    if (length <= kSampleThreshold) return MeasureCode::Invalid;
    std::array<u64, kSampleWindowCount> out{};
    const u64 span = length - kSampleWindowBytes;
    for (u64 j = 0; j < kSampleWindowCount; ++j) {
        // floor(j · span / 15) — exact in u64 for every length this
        // implementation accepts (kMaxProbeBytes = 2^32).
        out[static_cast<std::size_t>(j)] = (j * span) / (kSampleWindowCount - 1u);
    }
    return out;
}

MeasureResult<StrideSet> stride_set_for_effort(u8 effort) noexcept {
    if (!effort_in_domain(static_cast<u32>(effort))) return MeasureCode::Invalid;
    StrideSet out{};
    if (effort <= 2u) {
        for (u32 i = 0; i < kStrideSetReduced.size(); ++i) {
            out.strides[i] = kStrideSetReduced[i];
        }
        out.count = static_cast<u32>(kStrideSetReduced.size());
        return out;
    }
    for (u32 i = 0; i < kStrideSet.size(); ++i) {
        out.strides[i] = kStrideSet[i];
    }
    out.count = static_cast<u32>(kStrideSet.size());
    return out;
}

MeasureResult<u32> bit_complexity_planes(u8 effort) noexcept {
    if (!effort_in_domain(static_cast<u32>(effort))) return MeasureCode::Invalid;
    return effort <= 2u ? 2u : kBitPlanes;
}

// ---------------------------------------------------------------------------
// probe (E4 §5.3, §8)
// ---------------------------------------------------------------------------

MeasureResult<std::vector<Observation>> probe(Source& source, const Segment& segment,
                                              const Policy& policy) {
    if (!effort_in_domain(static_cast<u32>(policy.effort))) return MeasureCode::Invalid;

    const std::optional<u64> begin = segment.begin.to_u64_checked();
    const std::optional<u64> end = segment.end.to_u64_checked();
    if (!begin.has_value() || !end.has_value()) return MeasureCode::Invalid;
    if (*begin > *end) return MeasureCode::Invalid;  // segment outside input
    const MeasureResult<u64> length_r = source_length(source);
    if (!length_r.ok()) return length_r.code();
    if (*end > length_r.value()) return MeasureCode::Invalid;  // segment outside input
    const u64 range_len = *end - *begin;
    if (range_len > kMaxProbeBytes) return MeasureCode::Limit;  // range cap

    std::vector<u8> data;
    const MeasureCode rc = read_range(source, *begin, range_len, data);
    if (rc != MeasureCode::Ok) return MeasureCode::Io;
    const std::span<const u8> bytes(data.data(), data.size());

    std::vector<Observation> out;
    out.reserve(2u * kProbeKindCount);
    auto emit = [&](ProbeKind kind, u64 value, u64 aux, u32 param) {
        Observation obs;
        obs.where = segment;
        obs.kind = kind;
        obs.value = value;
        obs.aux = aux;
        obs.param = param;
        out.push_back(std::move(obs));
    };

    const u64 n = range_len;
    const bool budget_h2 = policy.effort >= 3u;
    const bool budget_repeat = policy.effort >= 3u;

    // --- H0 (§4.8) ---
    {
        std::array<u64, 256> counts{};
        for (const u8 v : bytes) ++counts[v];
        emit(ProbeKind::H0, h0_q24_from_counts(std::span<const u64, 256>(counts)), n, 0u);
    }

    // --- H1 (§4.8) ---
    emit(ProbeKind::H1, h1_pairs_q24(bytes), n >= 2u ? n - 1u : 0u, 0u);

    // --- H2 (§4.8, §4.9) — exact at or below 2 MiB, sampled above ---
    if (budget_h2) {
        if (n <= kSampleThreshold) {
            emit(ProbeKind::H2, h2_trigrams_q24(bytes), n >= 3u ? n - 2u : 0u, 0u);
        } else {
            const MeasureResult<std::array<u64, kSampleWindowCount>> offsets =
                sample_window_offsets(n);
            if (!offsets.ok()) return offsets.code();
            std::map<u32, u64> trigrams;
            for (const u64 off : offsets.value()) {
                if (off + kSampleWindowBytes > n) return MeasureCode::Invalid;
                const std::span<const u8> win = bytes.subspan(
                    static_cast<std::size_t>(off), static_cast<std::size_t>(kSampleWindowBytes));
                for (std::size_t i = 2; i < win.size(); ++i) {
                    const u32 tri = (static_cast<u32>(win[i - 2u]) << 16) |
                                    (static_cast<u32>(win[i - 1u]) << 8) | static_cast<u32>(win[i]);
                    ++trigrams[tri];
                }
            }
            const u64 samples = static_cast<u64>(kSampleWindowCount) * (kSampleWindowBytes - 2u);
            Observation obs;
            obs.where = segment;
            obs.kind = ProbeKind::H2;
            obs.value = h2_aggregate_q24(trigrams);
            obs.aux = samples;
            obs.sampled = true;
            obs.sample_count = kSampleWindowCount;
            out.push_back(std::move(obs));
        }
    }

    // --- Runs (§4.8) ---
    {
        const RunStats runs = run_stats(bytes);
        emit(ProbeKind::Runs, runs.run_count, runs.max_run, 0u);
    }

    // --- Period (§4.8) — reported only with verified = true ---
    {
        Observation obs;
        obs.where = segment;
        obs.kind = ProbeKind::Period;
        obs.period = BigInt(minimal_period(bytes));
        obs.verified = true;  // the full check over these exact bytes passes
        out.push_back(std::move(obs));
    }

    // --- Repeat16 (§4.8, §4.9) ---
    if (budget_repeat) {
        u64 matches = 0u;
        u64 density_den = 0u;
        bool sampled = false;
        if (n <= kSampleThreshold) {
            u64 positions = 0u;
            matches = repeat16_matches(bytes, positions);
            density_den = positions;
        } else {
            const MeasureResult<std::array<u64, kSampleWindowCount>> offsets =
                sample_window_offsets(n);
            if (!offsets.ok()) return offsets.code();
            sampled = true;
            for (const u64 off : offsets.value()) {
                if (off + kSampleWindowBytes > n) return MeasureCode::Invalid;
                const std::span<const u8> win = bytes.subspan(
                    static_cast<std::size_t>(off), static_cast<std::size_t>(kSampleWindowBytes));
                u64 win_positions = 0u;
                matches += repeat16_matches(win, win_positions);
                density_den += win_positions;
            }
        }
        Observation obs;
        obs.where = segment;
        obs.kind = ProbeKind::Repeat16;
        obs.value = density_den == 0u
                        ? 0u
                        : static_cast<u64>((static_cast<u128>(matches) << 24u) /
                                           static_cast<u128>(density_den));
        obs.aux = matches;
        obs.sampled = sampled;
        obs.sample_count = sampled ? kSampleWindowCount : 0u;
        obs.param = kRepeat16Window;
        out.push_back(std::move(obs));
    }

    // --- Skew (§4.8): planes 0..7 at every effort ---
    for (u32 plane = 0; plane < kBitPlanes; ++plane) {
        u64 ones = 0u;
        for (const u8 v : bytes) {
            if (((v >> plane) & 1u) != 0u) ++ones;
        }
        const u64 ones_q24 =
            n == 0u ? 0u
                    : static_cast<u64>((static_cast<u128>(ones) << 24u) / static_cast<u128>(n));
        emit(ProbeKind::Skew, ones_q24, n, plane);
    }

    // --- BitComplexity (§4.8): Berlekamp–Massey per plane ---
    {
        const MeasureResult<u32> planes_r = bit_complexity_planes(policy.effort);
        if (!planes_r.ok()) return planes_r.code();
        std::vector<u8> bits(n, 0u);
        for (u32 plane = 0; plane < planes_r.value(); ++plane) {
            for (u64 i = 0; i < n; ++i) {
                bits[static_cast<std::size_t>(i)] =
                    static_cast<u8>((data[static_cast<std::size_t>(i)] >> plane) & 1u);
            }
            const BmResult bm = berlekamp_massey(bits);
            Observation obs;
            obs.where = segment;
            obs.kind = ProbeKind::BitComplexity;
            obs.value = bm.length;
            obs.digest = poly_digest(bm.coeffs);
            obs.param = plane;
            out.push_back(std::move(obs));
        }
    }

    // --- AffineFit (§4.8): exact predicate b[i] = (a + i·s) mod 256 ---
    {
        u64 value = 0u;
        u64 aux = 0u;
        if (n >= 2u) {
            const u64 a = bytes[0];
            const u64 s = (static_cast<u64>(bytes[1]) + 256u - bytes[0]) & 0xFFu;
            bool fits = true;
            for (u64 i = 0; i < n && fits; ++i) {
                const u64 expect = (a + ((i & 0xFFu) * s)) & 0xFFu;
                if (bytes[static_cast<std::size_t>(i)] != expect) fits = false;
            }
            if (fits) {
                value = 1u;
                aux = a | (s << 8);
            }
        }
        emit(ProbeKind::AffineFit, value, aux, 0u);
    }

    // --- QuadraticFit (§4.8): exact predicate, constant second difference ---
    {
        u64 value = 0u;
        u64 aux = 0u;
        if (n >= 3u) {
            const u64 d0 = (static_cast<u64>(bytes[1]) + 256u - bytes[0]) & 0xFFu;
            const u64 d1 = (static_cast<u64>(bytes[2]) + 256u - bytes[1]) & 0xFFu;
            const u64 d2 = (d1 + 256u - d0) & 0xFFu;
            bool fits = true;
            for (u64 i = 1; i + 2u < n && fits; ++i) {
                const u64 di = (static_cast<u64>(bytes[i + 1u]) + 256u - bytes[i]) & 0xFFu;
                const u64 dj = (static_cast<u64>(bytes[i + 2u]) + 256u - bytes[i + 1u]) & 0xFFu;
                if (((dj + 256u - di) & 0xFFu) != d2) fits = false;
            }
            if (fits) {
                value = 1u;
                aux = d2;
            }
        }
        emit(ProbeKind::QuadraticFit, value, aux, 0u);
    }

    // --- Stride (§4.8): best of the effort's set, reported only at >= 0.5 bit ---
    {
        const MeasureResult<StrideSet> set_r = stride_set_for_effort(policy.effort);
        if (!set_r.ok()) return set_r.code();
        std::array<u64, 256> counts{};
        for (const u8 v : bytes) ++counts[v];
        const u64 h0 = h0_q24_from_counts(std::span<const u64, 256>(counts));
        bool have = false;
        u64 best_h = 0u;
        u64 best_stride = 0u;
        for (u32 i = 0; i < set_r.value().count; ++i) {
            const u64 s = set_r.value().strides[i];
            const u64 h_s = stride_entropy_q24(bytes, s);
            const u64 improvement = h0 - h_s;  // floors are monotone: h_s <= h0
            if (improvement < kStrideMinImprovementQ24) continue;
            if (!have || h_s < best_h) {  // strict: ascending set keeps ties smallest
                have = true;
                best_h = h_s;
                best_stride = s;
            }
        }
        if (have) {
            Observation obs;
            obs.where = segment;
            obs.kind = ProbeKind::Stride;
            obs.value = best_h;
            obs.aux = best_stride;
            obs.param = static_cast<u32>(best_stride);
            out.push_back(std::move(obs));
        }
    }

    // --- ChangePoint (§4.8): the §4.5 rule over the segment's own bytes ---
    {
        const std::vector<u64> points = span_change_points(bytes);
        for (const u64 rel : points) {
            Observation obs;
            obs.where = segment;
            obs.kind = ProbeKind::ChangePoint;
            obs.value = 1u;
            obs.aux = *begin + rel;
            obs.param = static_cast<u32>(kChangeWindow);
            out.push_back(std::move(obs));
        }
    }

    if (out.size() > kMaxProbeObservations) return MeasureCode::Limit;  // count cap

    // Canonise to §5.4 order (kind ordinal, then param, ChangePoint ascending
    // in aux): the rows are already almost sorted, and the sort is stable so
    // the ascending change-point order survives.
    std::stable_sort(out.begin(), out.end(), [](const Observation& x, const Observation& y) {
        const u8 kx = probe_kind_ordinal(x.kind);
        const u8 ky = probe_kind_ordinal(y.kind);
        if (kx != ky) return kx < ky;
        if (x.param != y.param) return x.param < y.param;
        return x.aux < y.aux;
    });
    return out;
}

// ---------------------------------------------------------------------------
// verify_period (E4 §5.3)
// ---------------------------------------------------------------------------

MeasureResult<bool> verify_period(Source& source, const Observation& obs) {
    if (obs.kind != ProbeKind::Period) return MeasureCode::Invalid;
    if (!obs.verified) return MeasureCode::Invalid;  // period present, verified = false
    const std::optional<u64> begin = obs.where.begin.to_u64_checked();
    const std::optional<u64> end = obs.where.end.to_u64_checked();
    if (!begin.has_value() || !end.has_value()) return MeasureCode::Invalid;
    if (*begin > *end) return MeasureCode::Invalid;
    const MeasureResult<u64> length_r = source_length(source);
    if (!length_r.ok()) return length_r.code();
    if (*end > length_r.value()) return MeasureCode::Invalid;  // range outside input
    const u64 n = *end - *begin;
    const std::optional<u64> p = obs.period.to_u64_checked();
    if (!p.has_value()) return MeasureCode::Invalid;
    if (*p > n) return MeasureCode::Invalid;
    if (*p == 0u && n != 0u) return MeasureCode::Invalid;

    std::vector<u8> data;
    const MeasureCode rc = read_range(source, *begin, n, data);
    if (rc != MeasureCode::Ok) return MeasureCode::Io;
    for (u64 i = *p; i < n; ++i) {
        if (data[static_cast<std::size_t>(i)] != data[static_cast<std::size_t>(i - *p)]) {
            return false;
        }
    }
    return true;
}

// ---------------------------------------------------------------------------
// Contract validation and rendering (E4 §4.7)
// ---------------------------------------------------------------------------

MeasureStatus validate_observation(const Observation& obs, u64 source_length) noexcept {
    const std::optional<u64> begin = obs.where.begin.to_u64_checked();
    const std::optional<u64> end = obs.where.end.to_u64_checked();
    if (!begin.has_value() || !end.has_value()) return MeasureCode::Invalid;
    if (*begin > *end || *end > source_length) return MeasureCode::Invalid;
    const u64 n = *end - *begin;

    if (obs.sampled) {
        if (obs.kind != ProbeKind::H2 && obs.kind != ProbeKind::Repeat16) {
            return MeasureCode::Invalid;
        }
        if (obs.sample_count != kSampleWindowCount) return MeasureCode::Invalid;
        if (n <= kSampleThreshold) return MeasureCode::Invalid;
    } else if (obs.sample_count != 0u) {
        return MeasureCode::Invalid;
    }

    if (obs.kind == ProbeKind::Period) {
        if (!obs.verified) return MeasureCode::Invalid;
        if (obs.value != 0u || obs.aux != 0u) return MeasureCode::Invalid;
        if (!digest_is_zero(obs.digest)) return MeasureCode::Invalid;
        const std::optional<u64> p = obs.period.to_u64_checked();
        if (!p.has_value() || *p > n) return MeasureCode::Invalid;
        if (*p == 0u && n != 0u) return MeasureCode::Invalid;
    } else {
        if (obs.verified) return MeasureCode::Invalid;
        if (!obs.period.is_zero()) return MeasureCode::Invalid;
        if (obs.kind != ProbeKind::BitComplexity && !digest_is_zero(obs.digest)) {
            return MeasureCode::Invalid;
        }
    }

    switch (obs.kind) {
        case ProbeKind::Skew:
        case ProbeKind::BitComplexity:
            if (obs.param >= kBitPlanes) return MeasureCode::Invalid;
            break;
        case ProbeKind::Repeat16:
            if (obs.param != kRepeat16Window) return MeasureCode::Invalid;
            break;
        case ProbeKind::Stride:
            if (obs.param != static_cast<u32>(obs.aux)) return MeasureCode::Invalid;
            break;
        case ProbeKind::ChangePoint:
            if (obs.param != static_cast<u32>(kChangeWindow)) return MeasureCode::Invalid;
            break;
        default:
            if (obs.param != 0u) return MeasureCode::Invalid;
            break;
    }
    return MeasureStatus{};
}

std::string observation_text(const Observation& obs) {
    std::string out;
    out += probe_kind_name(obs.kind);
    out += '@';
    out += obs.where.begin.to_decimal();
    out += '-';
    out += obs.where.end.to_decimal();
    out += " v=";
    out += std::to_string(obs.value);
    out += " a=";
    out += std::to_string(obs.aux);
    out += " p=";
    out += obs.period.to_decimal();
    out += " d=";
    out += digest_hex(obs.digest);
    out += " ver=";
    out += obs.verified ? '1' : '0';
    out += " sam=";
    out += obs.sampled ? '1' : '0';
    out += " sc=";
    out += std::to_string(obs.sample_count);
    out += " par=";
    out += std::to_string(obs.param);
    return out;
}

void merge_observations(std::vector<Observation>& rows) {
    std::stable_sort(rows.begin(), rows.end(), [](const Observation& x, const Observation& y) {
        if (!(x.where.begin == y.where.begin)) return x.where.begin < y.where.begin;
        const u8 kx = probe_kind_ordinal(x.kind);
        const u8 ky = probe_kind_ordinal(y.kind);
        if (kx != ky) return kx < ky;
        return x.param < y.param;
    });
}

}  // namespace marp::v2
