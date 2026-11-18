// MARP v2 — E4 MEASURE — C11 PROBE — GoogleTest suite.
//
// Covers the C11 acceptance obligations (prompt §5) against MARP2-E4 §4.2,
// §4.7–§4.10, §5.3–§5.4, §6, §8, §9:
//
//   * fixed point: `ilog2_q24`/H0 KATs (pinned), H1/H2 against independently
//     written §4.2 references on random byte strings;
//   * every probe kind on constructed fixtures with exact expected fields
//     (value, aux, period, digest, verified, sampled, sample_count, param),
//     including hand-derived Berlekamp–Massey KATs and all 8 bit planes;
//   * period discipline: every reported period passes the full byte check via
//     `verify_period`; forged periods fail it; contract violations are
//     `Invalid` (§9), and no unverified period is ever reported;
//   * locality (E4-I2): mutating a byte outside `where` leaves every
//     measurement observation identical; the documented ChangePoint scope is
//     checked against its detection window;
//   * reproducibility (O8.5): re-running probe on the recorded range and
//     parameters reproduces every field, from independent Source objects;
//   * merge (§5.4): a deliberately shuffled completion order merges to the
//     same list as the serial order;
//   * sampling (§4.9): exact and sampled paths, recorded flags, and the
//     sampled values recomputed independently from the pinned window offsets;
//   * effort (§4.10): the budget table, and effort never changes a value;
//   * errors (§9): `Io` and `Invalid` — never a throw, never a partial value;
//   * empty-input leaf observations; observation field discipline (no FP
//     field exists; unused fields are zero); no term-shaped type exists.
//
// The reference implementations below are written from the text of the
// specification and share no code with the C11 library: a linear-algebra
// (Gaussian elimination over GF(2)) linear complexity instead of
// Berlekamp–Massey, an ordered std::set Repeat16 instead of an open-addressing
// table, brute-force Period and Repeat16, and transcribed §4.5 change-point
// pseudocode.  Agreement is evidence that C11 implements the specification,
// not that it agrees with itself.

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <map>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <tuple>
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
        out.insert(out.end(), block.begin(),
                   block.begin() + static_cast<std::ptrdiff_t>(take));
    }
    return out;
}

Segment seg(u64 begin, u64 end) { return Segment{BigInt(begin), BigInt(end), 0u, 0u}; }

// ---------------------------------------------------------------------------
// Independent references, written from the text of the specification
// ---------------------------------------------------------------------------

u64 ref_ilog2_q24(u64 x) {
    if (x == 0u) return 0u;
    u64 msb = 0u;
    while ((x >> msb) > 1u) ++msb;
    u128ref m = (msb <= 62u) ? (static_cast<u128ref>(x) << (62u - msb))
                             : (static_cast<u128ref>(x) >> 1u);
    u64 frac = 0u;
    for (int bit = 0; bit < 24; ++bit) {
        m = (m * m) >> 62u;
        frac <<= 1u;
        if (m >= (static_cast<u128ref>(1) << 63u)) {
            m >>= 1u;
            frac |= 1u;
        }
    }
    return (msb << 24u) + frac;
}

u128ref ref_term(u64 n) {
    if (n == 0u) return 0u;
    return static_cast<u128ref>(n) * static_cast<u128ref>(ref_ilog2_q24(n));
}

// §4.2 order-0 over a count vector.
u64 ref_h0_counts(std::span<const u64> counts) {
    u128ref n = 0u;
    for (const u64 c : counts) n += c;
    if (n == 0u) return 0u;
    u128ref total = n * static_cast<u128ref>(ref_ilog2_q24(static_cast<u64>(n)));
    for (const u64 c : counts) {
        if (c == 0u) continue;
        total -= ref_term(c);
    }
    return static_cast<u64>(total / n);
}

u64 ref_h0(std::span<const u8> bytes) {
    std::array<u64, 256> counts{};
    for (const u8 b : bytes) ++counts[b];
    return ref_h0_counts(std::span<const u64>(counts.data(), counts.size()));
}

// §4.2 order-1: contexts are the previous byte; N is the bigram count.
u64 ref_h1(std::span<const u8> bytes) {
    const u64 n = static_cast<u64>(bytes.size());
    if (n < 2u) return 0u;
    std::array<u64, 256> ctx{};
    std::vector<u64> joint(65536u, 0u);
    for (u64 i = 1u; i < n; ++i) {
        const u8 prev = bytes[static_cast<std::size_t>(i - 1u)];
        const u8 cur = bytes[static_cast<std::size_t>(i)];
        ++ctx[prev];
        ++joint[(static_cast<u32>(prev) << 8u) | static_cast<u32>(cur)];
    }
    u128ref ctx_sum = 0u;
    for (const u64 c : ctx) ctx_sum += ref_term(c);
    u128ref joint_sum = 0u;
    for (const u64 c : joint) joint_sum += ref_term(c);
    if (joint_sum >= ctx_sum) return 0u;
    return static_cast<u64>((ctx_sum - joint_sum) / (n - 1u));
}

// §4.2 order-2: contexts are the two previous bytes; N is the trigram count.
u64 ref_h2(std::span<const u8> bytes) {
    const u64 n = static_cast<u64>(bytes.size());
    if (n < 3u) return 0u;
    std::vector<u64> bigram(65536u, 0u);
    std::map<u32, u64> tri;
    for (u64 i = 2u; i < n; ++i) {
        const u8 b0 = bytes[static_cast<std::size_t>(i - 2u)];
        const u8 b1 = bytes[static_cast<std::size_t>(i - 1u)];
        const u8 b2 = bytes[static_cast<std::size_t>(i)];
        ++bigram[(static_cast<u32>(b0) << 8u) | static_cast<u32>(b1)];
        ++tri[(static_cast<u32>(b0) << 16u) | (static_cast<u32>(b1) << 8u) |
              static_cast<u32>(b2)];
    }
    u128ref ctx_sum = 0u;
    for (const u64 c : bigram) ctx_sum += ref_term(c);
    u128ref joint_sum = 0u;
    for (const auto& entry : tri) joint_sum += ref_term(entry.second);
    if (joint_sum >= ctx_sum) return 0u;
    return static_cast<u64>((ctx_sum - joint_sum) / (n - 2u));
}

// §4.8 Runs.
std::pair<u64, u64> ref_runs(std::span<const u8> bytes) {
    u64 run_count = 0u;
    u64 max_run = 0u;
    u64 i = 0u;
    const u64 n = static_cast<u64>(bytes.size());
    while (i < n) {
        const u8 symbol = bytes[static_cast<std::size_t>(i)];
        u64 j = i + 1u;
        while (j < n && bytes[static_cast<std::size_t>(j)] == symbol) ++j;
        ++run_count;
        if (j - i > max_run) max_run = j - i;
        i = j;
    }
    return {run_count, max_run};
}

// §4.8 Period: brute force over p = 1..N.
u64 ref_period(std::span<const u8> bytes) {
    const u64 n = static_cast<u64>(bytes.size());
    for (u64 p = 1u; p <= n; ++p) {
        bool ok = true;
        for (u64 i = p; i < n; ++i) {
            if (bytes[static_cast<std::size_t>(i)] != bytes[static_cast<std::size_t>(i - p)]) {
                ok = false;
                break;
            }
        }
        if (ok) return p;
    }
    return n;
}

// §4.8 Repeat16: exact 16-byte keys in an ordered set (no hashing at all).
std::pair<u64, u64> ref_repeat16(std::span<const u8> bytes) {
    const u64 n = static_cast<u64>(bytes.size());
    if (n < 16u) return {0u, 0u};
    std::set<std::array<u8, 16>> seen;
    u64 matches = 0u;
    const u64 positions = n - 15u;
    for (u64 i = 0u; i < positions; ++i) {
        std::array<u8, 16> key{};
        for (std::size_t k = 0; k < 16u; ++k) {
            key[k] = bytes[static_cast<std::size_t>(i) + k];
        }
        if (seen.find(key) != seen.end()) {
            ++matches;
        } else {
            seen.insert(key);
        }
    }
    const u128ref density = (static_cast<u128ref>(matches) << 24u) / positions;
    return {static_cast<u64>(density), matches};
}

// §4.8 Skew for one plane.
u64 ref_skew(std::span<const u8> bytes, u32 plane) {
    const u64 n = static_cast<u64>(bytes.size());
    u64 ones = 0u;
    for (const u8 b : bytes) ones += static_cast<u64>((b >> plane) & 1u);
    if (n == 0u) return 0u;
    return static_cast<u64>((static_cast<u128ref>(ones) << 24u) / n);
}

// §4.8 BitComplexity: minimal LFSR length by Gaussian elimination over GF(2)
// (a linear-algebra route, deliberately not Berlekamp–Massey).  The sequence
// has complexity L iff the system  Σ_{i=1..L} c_i·s[t−i] = s[t]  (t = L..N−1)
// is consistent; L = 0 means every bit is zero.
bool ref_lfsr_consistent(std::span<const u8> bits, u32 l) {
    const u64 n = static_cast<u64>(bits.size());
    if (l == 0u) {
        for (const u8 b : bits) {
            if (b != 0u) return false;
        }
        return true;
    }
    if (static_cast<u64>(l) > n) return false;
    const std::size_t words = (static_cast<std::size_t>(l) + 1u + 63u) / 64u;
    std::vector<std::vector<u64>> rows;
    rows.reserve(static_cast<std::size_t>(n - l));
    for (u64 t = static_cast<u64>(l); t < n; ++t) {
        std::vector<u64> row(words, 0u);
        for (u32 i = 1u; i <= l; ++i) {
            if (bits[static_cast<std::size_t>(t - i)] != 0u) {
                const std::size_t col = static_cast<std::size_t>(i) - 1u;
                row[col / 64u] |= (1ull << (static_cast<u64>(col) % 64u));
            }
        }
        if (bits[static_cast<std::size_t>(t)] != 0u) {
            const std::size_t col = static_cast<std::size_t>(l);  // rhs column
            row[col / 64u] |= (1ull << (static_cast<u64>(col) % 64u));
        }
        rows.push_back(std::move(row));
    }
    // Forward elimination with first-set pivoting per column.
    std::size_t rank_row = 0u;
    for (u32 col = 0u; col < l && rank_row < rows.size(); ++col) {
        const std::size_t word = static_cast<std::size_t>(col) / 64u;
        const u64 bit = 1ull << (static_cast<u64>(col) % 64u);
        std::size_t pivot = rank_row;
        while (pivot < rows.size() && (rows[pivot][word] & bit) == 0u) ++pivot;
        if (pivot == rows.size()) continue;  // free variable
        std::swap(rows[rank_row], rows[pivot]);
        for (std::size_t r = 0u; r < rows.size(); ++r) {
            if (r == rank_row) continue;
            if ((rows[r][word] & bit) != 0u) {
                for (std::size_t w = 0u; w < words; ++w) rows[r][w] ^= rows[rank_row][w];
            }
        }
        ++rank_row;
    }
    for (const std::vector<u64>& row : rows) {
        bool any_coeff = false;
        for (u32 cbit = 0u; cbit < l; ++cbit) {
            const std::size_t w = static_cast<std::size_t>(cbit) / 64u;
            if ((row[w] & (1ull << (static_cast<u64>(cbit) % 64u))) != 0u) {
                any_coeff = true;
                break;
            }
        }
        const std::size_t rw = static_cast<std::size_t>(l) / 64u;
        const bool rhs = (row[rw] & (1ull << (static_cast<u64>(l) % 64u))) != 0u;
        if (!any_coeff && rhs) return false;
    }
    return true;
}

u32 ref_linear_complexity(std::span<const u8> bits) {
    const u32 n = static_cast<u32>(bits.size());
    for (u32 l = 0u; l <= n; ++l) {
        if (ref_lfsr_consistent(bits, l)) return l;
    }
    return n;
}

// Independent Berlekamp–Massey transcription returning (L, c_1..c_L) of
// C(x) = 1 + c_1·x + … + c_L·x^L.  Used to check the probe's digest and that
// the connection polynomial generates the plane.
std::pair<u32, std::vector<u8>> ref_bm(std::span<const u8> bits) {
    const u32 n = static_cast<u32>(bits.size());
    std::vector<u8> c(static_cast<std::size_t>(n) + 2u, 0u);
    std::vector<u8> b(static_cast<std::size_t>(n) + 2u, 0u);
    c[0] = 1u;
    b[0] = 1u;
    u32 l = 0u;
    u64 m = 1u;
    for (u32 t = 0u; t < n; ++t) {
        u8 d = bits[static_cast<std::size_t>(t)];
        const u32 max_i = std::min(l, t);
        for (u32 i = 1u; i <= max_i; ++i) {
            d = static_cast<u8>(d ^ (c[static_cast<std::size_t>(i)] &
                                     bits[static_cast<std::size_t>(t - i)]));
        }
        if (d == 0u) {
            ++m;
            continue;
        }
        if (2u * static_cast<u64>(l) <= static_cast<u64>(t)) {
            std::vector<u8> saved = c;
            for (u32 i = 0u; i + m <= static_cast<u64>(t) + 1u; ++i) {
                if (b[static_cast<std::size_t>(i)] != 0u) {
                    c[static_cast<std::size_t>(i + m)] ^= 1u;
                }
            }
            l = static_cast<u32>(static_cast<u64>(t) + 1u - static_cast<u64>(l));
            b = saved;
            m = 1u;
        } else {
            for (u32 i = 0u; i + m <= static_cast<u64>(t) + 1u; ++i) {
                if (b[static_cast<std::size_t>(i)] != 0u) {
                    c[static_cast<std::size_t>(i + m)] ^= 1u;
                }
            }
            ++m;
        }
    }
    std::vector<u8> coeffs(static_cast<std::size_t>(l), 0u);
    for (u32 i = 1u; i <= l; ++i) {
        coeffs[static_cast<std::size_t>(i) - 1u] = c[static_cast<std::size_t>(i)];
    }
    return {l, coeffs};
}

// §4.8 digest serialisation: SHA-256(LE64(L) || packed c_1..c_L), LSB-first.
std::array<u8, 32> ref_bm_digest(u32 l, const std::vector<u8>& coeffs) {
    std::string payload;
    const u64 l64 = static_cast<u64>(l);
    for (unsigned k = 0u; k < 8u; ++k) {
        payload.push_back(static_cast<char>((l64 >> (8u * k)) & 0xFFu));
    }
    const std::size_t packed = (coeffs.size() + 7u) / 8u;
    for (std::size_t byte_index = 0u; byte_index < packed; ++byte_index) {
        u8 byte = 0u;
        for (unsigned p = 0u; p < 8u; ++p) {
            const std::size_t idx = byte_index * 8u + static_cast<std::size_t>(p);
            if (idx < coeffs.size() && coeffs[idx] != 0u) {
                byte = static_cast<u8>(byte | (1u << p));
            }
        }
        payload.push_back(static_cast<char>(byte));
    }
    const auto digest = mapr::Sha256::hash(payload);
    std::array<u8, 32> out{};
    if (digest.ok()) std::copy(digest.value().begin(), digest.value().end(), out.begin());
    return out;
}

// §4.8 AffineFit: exact predicate, witness a | (s << 8) on a fit.
std::pair<u64, u64> ref_affine_fit(std::span<const u8> bytes) {
    const u64 n = static_cast<u64>(bytes.size());
    if (n == 0u) return {0u, 0u};
    const u64 a = bytes[0u];
    const u64 s = (n >= 2u) ? ((static_cast<u64>(bytes[1u]) + 256u - bytes[0u]) & 0xFFu) : 0u;
    for (u64 i = 0u; i < n; ++i) {
        if (bytes[static_cast<std::size_t>(i)] !=
            static_cast<u8>((a + i * s) & 0xFFu)) {
            return {0u, 0u};
        }
    }
    return {1u, a | (s << 8u)};
}

// §4.8 QuadraticFit: constant second difference mod 256.
std::pair<u64, u64> ref_quadratic_fit(std::span<const u8> bytes) {
    const u64 n = static_cast<u64>(bytes.size());
    if (n == 0u) return {0u, 0u};
    if (n <= 2u) return {1u, 0u};
    const auto d2_at = [&](u64 i) {
        const int b0 = static_cast<int>(bytes[static_cast<std::size_t>(i)]);
        const int b1 = static_cast<int>(bytes[static_cast<std::size_t>(i + 1u)]);
        const int b2 = static_cast<int>(bytes[static_cast<std::size_t>(i + 2u)]);
        return ((b2 - 2 * b1 + b0) % 256 + 256) % 256;
    };
    const int d2 = d2_at(0u);
    for (u64 i = 0u; i + 2u < n; ++i) {
        if (d2_at(i) != d2) return {0u, 0u};
    }
    return {1u, static_cast<u64>(d2)};
}

// §4.8 Stride: best stride of `set` by H0 − H(b | i mod s), >= 2^23, smallest
// tie.  Returns (found, stride, conditional entropy).
std::tuple<bool, u64, u64> ref_stride(std::span<const u8> bytes, std::span<const u64> set) {
    const u64 n = static_cast<u64>(bytes.size());
    if (n == 0u) return {false, 0u, 0u};
    const u64 h0 = ref_h0(bytes);
    u64 best_stride = 0u;
    u64 best_h = 0u;
    u64 best_improvement = 0u;
    for (const u64 s : set) {
        // Same §4.8 reading as the implementation: a stride needs at least two
        // samples per residue class to be non-degenerate.
        if (s > n / 2u) continue;
        std::vector<u64> joint(static_cast<std::size_t>(s) * 256u, 0u);
        for (u64 i = 0u; i < n; ++i) {
            ++joint[static_cast<std::size_t>(
                (i % s) * 256u + static_cast<u64>(bytes[static_cast<std::size_t>(i)]))];
        }
        u128ref ctx_sum = 0u;
        for (u64 cls = 0u; cls < s; ++cls) {
            u64 row = 0u;
            for (u32 sym = 0u; sym < 256u; ++sym) {
                row += joint[static_cast<std::size_t>(cls * 256u + sym)];
            }
            ctx_sum += ref_term(row);
        }
        u128ref joint_sum = 0u;
        for (const u64 c : joint) joint_sum += ref_term(c);
        u64 h_s = 0u;
        if (joint_sum < ctx_sum) {
            h_s = static_cast<u64>((ctx_sum - joint_sum) / n);
        }
        const u64 improvement = (h0 > h_s) ? h0 - h_s : 0u;
        if (improvement > best_improvement) {
            best_improvement = improvement;
            best_stride = s;
            best_h = h_s;
        }
    }
    if (best_improvement < (1ull << 23)) return {false, 0u, 0u};
    return {true, best_stride, best_h};
}

// §4.5 change points, transcribed over a materialised buffer (same semantics
// as the C10 gate's reference: cap on pre-dedup candidates, dedup keeping the
// smaller offset).
std::vector<u64> ref_change_points(std::span<const u8> bytes) {
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
        u64 zeros_l = 0u;
        u64 zeros_r = 0u;
        for (u64 j = i - window; j < i; ++j) {
            if (bytes[static_cast<std::size_t>(j)] == 0u) ++zeros_l;
        }
        for (u64 j = i; j < i + window; ++j) {
            if (bytes[static_cast<std::size_t>(j)] == 0u) ++zeros_r;
        }
        const u64 hl = ref_h0_counts(std::span<const u64>(lc.data(), lc.size()));
        const u64 hr = ref_h0_counts(std::span<const u64>(rc.data(), rc.size()));
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

// ---------------------------------------------------------------------------
// Observation helpers
// ---------------------------------------------------------------------------

const Observation* find_obs(const std::vector<Observation>& obs, ProbeKind kind, u32 param = 0u) {
    for (const Observation& o : obs) {
        if (o.kind == kind && o.param == param) return &o;
    }
    return nullptr;
}

bool has_obs(const std::vector<Observation>& obs, ProbeKind kind, u32 param = 0u) {
    return find_obs(obs, kind, param) != nullptr;
}

// Stride's `param` is the stride value (never 0), so look it up by kind only.
const Observation* find_stride(const std::vector<Observation>& obs) {
    for (const Observation& o : obs) {
        if (o.kind == ProbeKind::Stride) return &o;
    }
    return nullptr;
}

// Sampled H2/Repeat16 carry param = window size (65536), so look them up by
// kind only.
template <ProbeKind K> const Observation* find_kind(const std::vector<Observation>& obs) {
    for (const Observation& o : obs) {
        if (o.kind == K) return &o;
    }
    return nullptr;
}

std::vector<Observation> probe_bytes(const Bytes& bytes, const Segment& where, u8 effort) {
    SpanSource source(std::span<const u8>(bytes.data(), bytes.size()));
    const auto got = probe(source, where, Policy{effort});
    if (!got.ok()) {
        ADD_FAILURE() << "probe failed: " << measure_code_name(got.code());
        return {};
    }
    return got.value();
}

std::array<u64, 3> probe_entropies(const Bytes& bytes, u64 begin, u64 end) {
    const std::vector<Observation> obs = probe_bytes(bytes, seg(begin, end), 5u);
    const Observation* h0 = find_obs(obs, ProbeKind::H0);
    const Observation* h1 = find_obs(obs, ProbeKind::H1);
    const Observation* h2 = find_obs(obs, ProbeKind::H2);
    EXPECT_NE(h0, nullptr);
    EXPECT_NE(h1, nullptr);
    EXPECT_NE(h2, nullptr);
    if (h0 == nullptr || h1 == nullptr || h2 == nullptr) return {0u, 0u, 0u};
    return {h0->value, h1->value, h2->value};
}

// Field discipline (§4.7): a field a kind does not use is zero, and only
// Period carries `verified`/a non-zero `period`, only BitComplexity a digest,
// only the §4.9 kinds `sampled`/`sample_count`.
void expect_field_discipline(const Observation& o) {
    const bool is_period = o.kind == ProbeKind::Period;
    const bool is_bm = o.kind == ProbeKind::BitComplexity;
    const bool sampled_kind = (o.kind == ProbeKind::H2 || o.kind == ProbeKind::Repeat16);
    if (is_period) {
        EXPECT_TRUE(o.verified) << "Period must be verified";
        EXPECT_GT(o.period, BigInt(0u)) << "Period must carry p >= 1";
    } else {
        EXPECT_FALSE(o.verified) << probe_kind_name(o.kind);
        EXPECT_EQ(o.period, BigInt(0u)) << probe_kind_name(o.kind);
    }
    if (!is_bm) {
        EXPECT_EQ(o.digest, (std::array<u8, 32>{})) << probe_kind_name(o.kind);
    }
    if (!sampled_kind || !o.sampled) {
        EXPECT_EQ(o.sample_count, 0u) << probe_kind_name(o.kind);
        EXPECT_FALSE(o.sampled) << probe_kind_name(o.kind);
    }
    if (sampled_kind && o.sampled) {
        EXPECT_EQ(o.sample_count, 16u) << probe_kind_name(o.kind);
        EXPECT_EQ(o.param, 65536u) << probe_kind_name(o.kind);
    }
    if (o.kind != ProbeKind::Skew && o.kind != ProbeKind::BitComplexity &&
        o.kind != ProbeKind::Stride && !(sampled_kind && o.sampled)) {
        EXPECT_EQ(o.param, 0u) << probe_kind_name(o.kind);
    }
}

// ---------------------------------------------------------------------------
// Fixed point
// ---------------------------------------------------------------------------

TEST(C11FixedPoint, Ilog2KatTable) {
    constexpr std::array<std::pair<u64, u64>, 14> kats = {{
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
    for (const auto& kat : kats) {
        EXPECT_EQ(ilog2_q24(kat.first), kat.second) << "x=" << kat.first;
        EXPECT_EQ(ilog2_q24(kat.first), ref_ilog2_q24(kat.first)) << "x=" << kat.first;
    }
}

TEST(C11FixedPoint, H0KnownValues) {
    {
        std::array<u64, 256> one{};
        one[7] = 4096u;
        EXPECT_EQ(h0_q24_from_counts(one), 0u);
    }
    {
        std::array<u64, 256> two{};
        two[0] = 1000u;
        two[1] = 1000u;
        EXPECT_EQ(h0_q24_from_counts(two), 1ull << 24u);
    }
    {
        std::array<u64, 256> uniform{};
        for (std::size_t i = 0; i < 256u; ++i) uniform[i] = 64u;
        EXPECT_EQ(h0_q24_from_counts(uniform), 8ull << 24u);
    }
    EXPECT_EQ(h0_q24_from_counts(std::array<u64, 256>{}), 0u);
}

TEST(C11FixedPoint, H0MatchesReferenceOnRandomInputs) {
    u64 s = 0x4d41525043313131ull;
    auto next = [&s]() {
        s += 0x9E3779B97F4A7C15ull;
        u64 z = s;
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
        return z ^ (z >> 31);
    };
    for (int iter = 0; iter < 64; ++iter) {
        const std::size_t n = 1u + static_cast<std::size_t>(next() % 512u);
        const Bytes bytes = splitmix_bytes(n, next());
        const std::span<const u8> view(bytes.data(), bytes.size());
        EXPECT_EQ(h0_q24(view), ref_h0(view)) << "iter=" << iter;
    }
}

TEST(C11FixedPoint, H1H2MatchReferencesOnRandomRanges) {
    u64 s = 0x4d41525043313132ull;
    auto next = [&s]() {
        s += 0x9E3779B97F4A7C15ull;
        u64 z = s;
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
        return z ^ (z >> 31);
    };
    for (int iter = 0; iter < 48; ++iter) {
        const std::size_t n = 3u + static_cast<std::size_t>(next() % 400u);
        const Bytes bytes = splitmix_bytes(n, next());
        const std::span<const u8> view(bytes.data(), bytes.size());
        const std::array<u64, 3> got = probe_entropies(bytes, 0u, static_cast<u64>(n));
        EXPECT_EQ(got[0u], ref_h0(view)) << "iter=" << iter;
        EXPECT_EQ(got[1u], ref_h1(view)) << "iter=" << iter;
        EXPECT_EQ(got[2u], ref_h2(view)) << "iter=" << iter;
    }
}

TEST(C11FixedPoint, EntropyKatAlternatingBytes) {
    // "ab" alternating: H0 = 1 bit; every conditional entropy is exactly 0
    // because the context determines the next byte completely.
    const Bytes bytes = repeat_block(Bytes{'a', 'b'}, 128u);
    const std::array<u64, 3> got = probe_entropies(bytes, 0u, 128u);
    EXPECT_EQ(got[0u], 1ull << 24u);
    EXPECT_EQ(got[1u], 0u);
    EXPECT_EQ(got[2u], 0u);
}

// ---------------------------------------------------------------------------
// Probe kinds — pinned fixtures with exact expected fields
// ---------------------------------------------------------------------------

TEST(C11ProbeKinds, H0AndAuxCarryRangeLength) {
    const Bytes bytes = splitmix_bytes(300u, 0x4d41525043313141ull);
    const std::vector<Observation> obs = probe_bytes(bytes, seg(0u, 300u), 5u);
    const Observation* h0 = find_obs(obs, ProbeKind::H0);
    ASSERT_NE(h0, nullptr);
    EXPECT_EQ(h0->value, ref_h0(std::span<const u8>(bytes.data(), bytes.size())));
    EXPECT_EQ(h0->aux, 300u);
    EXPECT_EQ(h0->where, seg(0u, 300u));
    EXPECT_EQ(h0->verified, false);
    EXPECT_EQ(h0->sampled, false);
    EXPECT_EQ(h0->sample_count, 0u);
    EXPECT_EQ(h0->param, 0u);
}

TEST(C11ProbeKinds, H1ZeroWhenContextDeterminesByte) {
    const Bytes bytes = repeat_block(Bytes{'a', 'b'}, 128u);
    const std::vector<Observation> obs = probe_bytes(bytes, seg(0u, 128u), 5u);
    const Observation* h1 = find_obs(obs, ProbeKind::H1);
    ASSERT_NE(h1, nullptr);
    EXPECT_EQ(h1->value, 0u);
    EXPECT_EQ(h1->aux, 127u);  // the bigram count N-1
}

TEST(C11ProbeKinds, H2KatUniformByteIsZero) {
    const Bytes bytes = zeros(1000u);
    const std::vector<Observation> obs = probe_bytes(bytes, seg(0u, 1000u), 5u);
    const Observation* h2 = find_obs(obs, ProbeKind::H2);
    ASSERT_NE(h2, nullptr);
    EXPECT_EQ(h2->value, 0u);
    EXPECT_EQ(h2->aux, 998u);
    EXPECT_FALSE(h2->sampled);
}

TEST(C11ProbeKinds, RunsKat) {
    Bytes bytes;
    bytes.insert(bytes.end(), 5u, 0x00u);
    bytes.insert(bytes.end(), 3u, 0xFFu);
    bytes.push_back(0x07u);
    const std::span<const u8> view(bytes.data(), bytes.size());
    const std::vector<Observation> obs = probe_bytes(bytes, seg(0u, 9u), 5u);
    const Observation* runs = find_obs(obs, ProbeKind::Runs);
    ASSERT_NE(runs, nullptr);
    EXPECT_EQ(runs->value, 3u);
    EXPECT_EQ(runs->aux, 5u);
    EXPECT_EQ(runs->value, ref_runs(view).first);
    EXPECT_EQ(runs->aux, ref_runs(view).second);
}

TEST(C11ProbeKinds, PeriodKat) {
    // "abab..." has p = 2; zeros have p = 1; random bytes have p = N.
    {
        const Bytes bytes = repeat_block(Bytes{'a', 'b'}, 128u);
        const std::vector<Observation> obs = probe_bytes(bytes, seg(0u, 128u), 5u);
        const Observation* period = find_obs(obs, ProbeKind::Period);
        ASSERT_NE(period, nullptr);
        EXPECT_EQ(period->period, BigInt(2u));
        EXPECT_TRUE(period->verified);
        EXPECT_EQ(period->value, 0u);
        EXPECT_EQ(period->aux, 0u);
    }
    {
        const Bytes bytes = zeros(40u);
        const std::vector<Observation> obs = probe_bytes(bytes, seg(0u, 40u), 5u);
        const Observation* period = find_obs(obs, ProbeKind::Period);
        ASSERT_NE(period, nullptr);
        EXPECT_EQ(period->period, BigInt(1u));
        EXPECT_TRUE(period->verified);
    }
    {
        const Bytes bytes = splitmix_bytes(50u, 0x4d41525043313142ull);
        const std::vector<Observation> obs = probe_bytes(bytes, seg(0u, 50u), 5u);
        const Observation* period = find_obs(obs, ProbeKind::Period);
        ASSERT_NE(period, nullptr);
        EXPECT_EQ(period->period, BigInt(50u));
        EXPECT_TRUE(period->verified);
    }
}

TEST(C11ProbeKinds, Repeat16KatDuplicateBlock) {
    // 16 bytes followed by the same 16 bytes: exactly one later position (16)
    // sees an earlier window; positions 0..15 are all first occurrences, and
    // position 16 repeats position 0.  17 positions total.
    Bytes pattern;
    for (std::size_t i = 0; i < 16u; ++i) {
        pattern.push_back(static_cast<u8>((i * 17u + 3u) & 0xFFu));
    }
    Bytes bytes = pattern;
    bytes.insert(bytes.end(), pattern.begin(), pattern.end());
    ASSERT_EQ(bytes.size(), 32u);
    const std::span<const u8> view(bytes.data(), bytes.size());
    const std::vector<Observation> obs = probe_bytes(bytes, seg(0u, 32u), 5u);
    const Observation* rep = find_obs(obs, ProbeKind::Repeat16);
    ASSERT_NE(rep, nullptr);
    const std::pair<u64, u64> want = ref_repeat16(view);
    EXPECT_EQ(want.second, 1u);
    EXPECT_EQ(rep->aux, want.second);
    EXPECT_EQ(rep->value, want.first);
    EXPECT_FALSE(rep->sampled);
    EXPECT_EQ(rep->sample_count, 0u);
    EXPECT_EQ(rep->param, 0u);
}

TEST(C11ProbeKinds, Repeat16ExactMatchesSetReference) {
    const Bytes bytes = splitmix_bytes(700u, 0x4d41525043313143ull);
    const std::span<const u8> view(bytes.data(), bytes.size());
    const std::vector<Observation> obs = probe_bytes(bytes, seg(0u, 700u), 5u);
    const Observation* rep = find_obs(obs, ProbeKind::Repeat16);
    ASSERT_NE(rep, nullptr);
    const std::pair<u64, u64> want = ref_repeat16(view);
    EXPECT_EQ(rep->aux, want.second);
    EXPECT_EQ(rep->value, want.first);
}

TEST(C11ProbeKinds, SkewAllEightPlanesKat) {
    // 0x0F has planes 0-3 all ones and planes 4-7 all zeros.
    const Bytes bytes(200u, 0x0Fu);
    const std::span<const u8> view(bytes.data(), bytes.size());
    const std::vector<Observation> obs = probe_bytes(bytes, seg(0u, 200u), 5u);
    for (u32 plane = 0u; plane < 8u; ++plane) {
        const Observation* skew = find_obs(obs, ProbeKind::Skew, plane);
        ASSERT_NE(skew, nullptr) << "plane=" << plane;
        EXPECT_EQ(skew->param, plane);
        EXPECT_EQ(skew->aux, 200u);
        EXPECT_EQ(skew->value, plane < 4u ? (1ull << 24u) : 0u) << "plane=" << plane;
        EXPECT_EQ(skew->value, ref_skew(view, plane)) << "plane=" << plane;
    }
}

TEST(C11ProbeKinds, SkewAlternatingPlanesOnAbab) {
    const Bytes bytes = repeat_block(Bytes{'a', 'b'}, 128u);
    const std::span<const u8> view(bytes.data(), bytes.size());
    const std::vector<Observation> obs = probe_bytes(bytes, seg(0u, 128u), 5u);
    for (u32 plane = 0u; plane < 8u; ++plane) {
        const Observation* skew = find_obs(obs, ProbeKind::Skew, plane);
        ASSERT_NE(skew, nullptr) << "plane=" << plane;
        EXPECT_EQ(skew->value, ref_skew(view, plane)) << "plane=" << plane;
    }
}

TEST(C11ProbeKinds, BitComplexityHandDerivedKats) {
    // Plane 0 of {0x01, 0x00, 0x01, 0x00} is 1,0,1,0 -> L = 2, C = 1 + x^2;
    // planes 1..7 are all-zero -> L = 0.
    const Bytes bytes = {0x01, 0x00, 0x01, 0x00};
    const std::vector<Observation> obs = probe_bytes(bytes, seg(0u, 4u), 5u);
    const Observation* bm0 = find_obs(obs, ProbeKind::BitComplexity, 0u);
    ASSERT_NE(bm0, nullptr);
    EXPECT_EQ(bm0->value, 2u);
    EXPECT_EQ(bm0->aux, 0u);
    EXPECT_EQ(bm0->param, 0u);
    EXPECT_EQ(bm0->digest, ref_bm_digest(2u, {0u, 1u}));

    const Observation* bm1 = find_obs(obs, ProbeKind::BitComplexity, 1u);
    ASSERT_NE(bm1, nullptr);
    EXPECT_EQ(bm1->value, 0u);
    EXPECT_EQ(bm1->digest, ref_bm_digest(0u, {}));

    // Plane 1 of {0x02, 0x00, 0x02, 0x00} is also 1,0,1,0.
    const Bytes bytes2 = {0x02, 0x00, 0x02, 0x00};
    const std::vector<Observation> obs2 = probe_bytes(bytes2, seg(0u, 4u), 5u);
    const Observation* bm2 = find_obs(obs2, ProbeKind::BitComplexity, 1u);
    ASSERT_NE(bm2, nullptr);
    EXPECT_EQ(bm2->value, 2u);
    EXPECT_EQ(bm2->digest, ref_bm_digest(2u, {0u, 1u}));
}

TEST(C11ProbeKinds, BitComplexitySingleOneKat) {
    // Bits [1,0]: L = 1 with C = 1 (c_1 = 0) because s_1 = 0.
    const Bytes bytes = {0x01, 0x00};
    const std::vector<Observation> obs = probe_bytes(bytes, seg(0u, 2u), 5u);
    const Observation* bm0 = find_obs(obs, ProbeKind::BitComplexity, 0u);
    ASSERT_NE(bm0, nullptr);
    EXPECT_EQ(bm0->value, 1u);
    EXPECT_EQ(bm0->digest, ref_bm_digest(1u, {0u}));
}

TEST(C11ProbeKinds, BitComplexityAllOnesKat) {
    // Bits [1,1,1,1]: L = 1, C = 1 + x (c_1 = 1).
    const Bytes bytes(4u, 0x01u);
    const std::vector<Observation> obs = probe_bytes(bytes, seg(0u, 4u), 5u);
    const Observation* bm0 = find_obs(obs, ProbeKind::BitComplexity, 0u);
    ASSERT_NE(bm0, nullptr);
    EXPECT_EQ(bm0->value, 1u);
    EXPECT_EQ(bm0->digest, ref_bm_digest(1u, {1u}));
}

TEST(C11ProbeKinds, BitComplexityMatchesGaussianReferenceOnRandom) {
    u64 s = 0x4d41525043313144ull;
    auto next = [&s]() {
        s += 0x9E3779B97F4A7C15ull;
        u64 z = s;
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
        return z ^ (z >> 31);
    };
    for (int iter = 0; iter < 12; ++iter) {
        const std::size_t n = 1u + static_cast<std::size_t>(next() % 96u);
        const Bytes bytes = splitmix_bytes(n, next());
        const std::vector<Observation> obs =
            probe_bytes(bytes, seg(0u, static_cast<u64>(n)), 5u);
        for (u32 plane = 0u; plane < 8u; ++plane) {
            const Observation* bm = find_obs(obs, ProbeKind::BitComplexity, plane);
            ASSERT_NE(bm, nullptr) << "iter=" << iter << " plane=" << plane;
            std::vector<u8> bits(bytes.size(), 0u);
            for (std::size_t t = 0; t < bytes.size(); ++t) {
                bits[t] = static_cast<u8>((bytes[t] >> plane) & 1u);
            }
            const auto ref = ref_bm(bits);
            EXPECT_EQ(bm->value, static_cast<u64>(ref_linear_complexity(bits)))
                << "iter=" << iter << " plane=" << plane;
            // The digest must match the independent serialisation, and the
            // connection polynomial must generate the whole plane from its
            // first L bits.
            const std::vector<u8>& coeffs = ref.second;
            EXPECT_EQ(bm->digest, ref_bm_digest(ref.first, coeffs))
                << "iter=" << iter << " plane=" << plane;
            for (u64 t = static_cast<u64>(ref.first);
                 t < static_cast<u64>(bits.size()); ++t) {
                u8 gen = 0u;
                for (u32 i = 1u; i <= ref.first; ++i) {
                    gen = static_cast<u8>(gen ^ (coeffs[static_cast<std::size_t>(i) - 1u] &
                                                 bits[static_cast<std::size_t>(t - i)]));
                }
                ASSERT_EQ(gen, bits[static_cast<std::size_t>(t)])
                    << "iter=" << iter << " plane=" << plane << " t=" << t;
            }
        }
    }
}

TEST(C11ProbeKinds, AffineFitKat) {
    // b[i] = (5 + i) mod 256 over 300 bytes fits with a = 5, s = 1.
    Bytes bytes(300u, 0u);
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        bytes[i] = static_cast<u8>((i + 5u) & 0xFFu);
    }
    const std::span<const u8> view(bytes.data(), bytes.size());
    const std::vector<Observation> obs = probe_bytes(bytes, seg(0u, 300u), 5u);
    const Observation* fit = find_obs(obs, ProbeKind::AffineFit);
    ASSERT_NE(fit, nullptr);
    EXPECT_EQ(fit->value, 1u);
    EXPECT_EQ(fit->aux, (5u | (1u << 8u)));
    EXPECT_EQ(fit->value, ref_affine_fit(view).first);
    EXPECT_EQ(fit->aux, ref_affine_fit(view).second);
}

TEST(C11ProbeKinds, AffineFitIsRangeLocal) {
    // The same bytes, probed from offset 5: the witness is relative to `where`.
    Bytes bytes(300u, 0u);
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        bytes[i] = static_cast<u8>((i + 5u) & 0xFFu);
    }
    const std::span<const u8> view(bytes.data() + 5u, bytes.size() - 5u);
    const std::vector<Observation> obs = probe_bytes(bytes, seg(5u, 300u), 5u);
    const Observation* fit = find_obs(obs, ProbeKind::AffineFit);
    ASSERT_NE(fit, nullptr);
    EXPECT_EQ(fit->value, 1u);
    EXPECT_EQ(fit->aux, (10u | (1u << 8u)));
    EXPECT_EQ(fit->aux, ref_affine_fit(view).second);
}

TEST(C11ProbeKinds, AffineFitRejectsNonAffine) {
    const Bytes bytes = repeat_block(Bytes{'a', 'b'}, 128u);
    const std::span<const u8> view(bytes.data(), bytes.size());
    const std::vector<Observation> obs = probe_bytes(bytes, seg(0u, 128u), 5u);
    const Observation* fit = find_obs(obs, ProbeKind::AffineFit);
    ASSERT_NE(fit, nullptr);
    EXPECT_EQ(fit->value, 0u);
    EXPECT_EQ(fit->aux, 0u);
    EXPECT_EQ(ref_affine_fit(view).first, 0u);
}

TEST(C11ProbeKinds, QuadraticFitKat) {
    // b[i] = i*i has constant second difference 2 mod 256.
    Bytes bytes(300u, 0u);
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        bytes[i] = static_cast<u8>((i * i) & 0xFFu);
    }
    const std::span<const u8> view(bytes.data(), bytes.size());
    const std::vector<Observation> obs = probe_bytes(bytes, seg(0u, 300u), 5u);
    const Observation* fit = find_obs(obs, ProbeKind::QuadraticFit);
    ASSERT_NE(fit, nullptr);
    EXPECT_EQ(fit->value, 1u);
    EXPECT_EQ(fit->aux, 2u);
    EXPECT_EQ(fit->value, ref_quadratic_fit(view).first);
    EXPECT_EQ(fit->aux, ref_quadratic_fit(view).second);
    const Observation* affine = find_obs(obs, ProbeKind::AffineFit);
    ASSERT_NE(affine, nullptr);
    EXPECT_EQ(affine->value, 0u);  // second difference 2 is not affine
}

TEST(C11ProbeKinds, QuadraticFitCoversAffine) {
    // An affine sequence has second difference 0, so it also fits quadratically.
    Bytes bytes(300u, 0u);
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        bytes[i] = static_cast<u8>((i + 5u) & 0xFFu);
    }
    const std::vector<Observation> obs = probe_bytes(bytes, seg(0u, 300u), 5u);
    const Observation* fit = find_obs(obs, ProbeKind::QuadraticFit);
    ASSERT_NE(fit, nullptr);
    EXPECT_EQ(fit->value, 1u);
    EXPECT_EQ(fit->aux, 0u);
}

TEST(C11ProbeKinds, StrideKatPeriodTwoTiesChooseSmallest) {
    // "ab" repeated: stride 2 makes the byte deterministic (H = 0); strides
    // 4, 8, ... do too, and the tie rule chooses the smallest: 2.
    const Bytes bytes = repeat_block(Bytes{'a', 'b'}, 128u);
    const std::vector<Observation> obs = probe_bytes(bytes, seg(0u, 128u), 5u);
    const Observation* stride = find_stride(obs);
    ASSERT_NE(stride, nullptr);
    EXPECT_EQ(stride->aux, 2u);
    EXPECT_EQ(stride->param, 2u);
    EXPECT_EQ(stride->value, 0u);  // the conditional entropy under i mod 2
    const auto want = ref_stride(std::span<const u8>(bytes.data(), bytes.size()),
                                 std::span<const u64>(kStrideSetAll.data(),
                                                      kStrideSetAll.size()));
    EXPECT_TRUE(std::get<0>(want));
    EXPECT_EQ(std::get<1>(want), 2u);
    EXPECT_EQ(std::get<2>(want), 0u);
}

TEST(C11ProbeKinds, StrideKatAllNineStridesWin) {
    // A tile of length s repeated: stride s makes every class deterministic,
    // so the improvement is the full H0 and s wins (larger strides that also
    // reach H = 0 lose the smallest-tie rule).  The tile is random with two
    // pinned distinct bytes, so no smaller period can make another stride
    // deterministic.
    for (const u64 s : kStrideSetAll) {
        SCOPED_TRACE(::testing::Message() << "stride=" << s);
        Bytes tile = splitmix_bytes(static_cast<std::size_t>(s), 0x4d41525043313171ull + s);
        tile[0u] = 0x00u;
        tile[static_cast<std::size_t>(s) - 1u] = 0xFFu;
        const std::size_t n = 2u * static_cast<std::size_t>(s);
        const Bytes bytes = repeat_block(tile, n);
        const std::span<const u8> view(bytes.data(), bytes.size());
        const std::vector<Observation> obs =
            probe_bytes(bytes, seg(0u, static_cast<u64>(n)), 5u);
        const Observation* stride = find_stride(obs);
        ASSERT_NE(stride, nullptr) << "stride=" << s;
        const auto want = ref_stride(view, std::span<const u64>(kStrideSetAll.data(),
                                                                kStrideSetAll.size()));
        ASSERT_TRUE(std::get<0>(want)) << "stride=" << s;
        EXPECT_EQ(std::get<1>(want), s) << "stride=" << s;
        EXPECT_EQ(stride->aux, s) << "stride=" << s;
        EXPECT_EQ(stride->param, s);
        EXPECT_EQ(stride->value, std::get<2>(want)) << "stride=" << s;
    }
}

TEST(C11ProbeKinds, StrideAbsentWhenImprovementZero) {
    // Constant bytes: H0 = 0, so every stride's H_s is 0 and the improvement
    // is 0 < 2^23; no Stride observation is reported.
    const Bytes bytes = zeros(512u);
    const std::vector<Observation> obs = probe_bytes(bytes, seg(0u, 512u), 5u);
    EXPECT_FALSE(has_obs(obs, ProbeKind::Stride));
    const auto want = ref_stride(std::span<const u8>(bytes.data(), bytes.size()),
                                 std::span<const u64>(kStrideSetAll.data(),
                                                      kStrideSetAll.size()));
    EXPECT_FALSE(std::get<0>(want));
}

TEST(C11ProbeKinds, StrideMatchesReferenceOnRandom) {
    // The probe's stride decision must match the independent reference sweep on
    // random data (both apply the same §4.8 class-size reading).
    const Bytes bytes = splitmix_bytes(512u, 0x4d41525043313146ull);
    const std::span<const u8> view(bytes.data(), bytes.size());
    const std::vector<Observation> obs = probe_bytes(bytes, seg(0u, 512u), 5u);
    const Observation* stride = find_stride(obs);
    const auto want = ref_stride(view, std::span<const u64>(kStrideSetAll.data(),
                                                            kStrideSetAll.size()));
    if (std::get<0>(want)) {
        ASSERT_NE(stride, nullptr);
        EXPECT_EQ(stride->aux, std::get<1>(want));
        EXPECT_EQ(stride->param, static_cast<u32>(std::get<1>(want)));
        EXPECT_EQ(stride->value, std::get<2>(want));
    } else {
        EXPECT_EQ(stride, nullptr);
    }
}

TEST(C11ProbeKinds, ChangePointEmittedExactlyAtDetectedBoundaries) {
    // 32 KiB zeros then 96 KiB random: a sharp zero -> random boundary.
    Bytes bytes;
    bytes.insert(bytes.end(), 32u * 1024u, 0x00u);
    const Bytes rand = splitmix_bytes(96u * 1024u, 0x4d41525043313147ull);
    bytes.insert(bytes.end(), rand.begin(), rand.end());
    const std::span<const u8> view(bytes.data(), bytes.size());

    const std::vector<u64> cps = ref_change_points(view);
    ASSERT_FALSE(cps.empty());
    // O8.10-flavoured sensitivity: the zero -> random boundary at 32768 is
    // found within one window of it.
    bool near_boundary = false;
    for (const u64 cp : cps) {
        if (cp + 4096u >= 32768u && cp <= 32768u + 4096u) near_boundary = true;
    }
    EXPECT_TRUE(near_boundary);

    // Every change point is reported by probe() on a segment starting there.
    for (const u64 cp : cps) {
        const std::vector<Observation> obs =
            probe_bytes(bytes, seg(cp, static_cast<u64>(bytes.size())), 5u);
        const Observation* change = find_obs(obs, ProbeKind::ChangePoint);
        ASSERT_NE(change, nullptr) << "cp=" << cp;
        EXPECT_EQ(change->value, 1u);
        EXPECT_EQ(change->aux, cp);
        EXPECT_EQ(change->where, seg(cp, static_cast<u64>(bytes.size())));
        EXPECT_FALSE(change->verified);
    }
    // Non-change-point begins report none: an off-grid offset, and an on-grid
    // offset that the reference does not list.
    {
        const std::vector<Observation> obs =
            probe_bytes(bytes, seg(12345u, static_cast<u64>(bytes.size())), 5u);
        EXPECT_FALSE(has_obs(obs, ProbeKind::ChangePoint));
    }
    {
        u64 non_cp = 6144u;
        while (std::find(cps.begin(), cps.end(), non_cp) != cps.end()) non_cp += 2048u;
        const std::vector<Observation> obs =
            probe_bytes(bytes, seg(non_cp, static_cast<u64>(bytes.size())), 5u);
        EXPECT_FALSE(has_obs(obs, ProbeKind::ChangePoint)) << "non_cp=" << non_cp;
    }
}

// ---------------------------------------------------------------------------
// Observation discipline, ordering, empty segments
// ---------------------------------------------------------------------------

TEST(C11Observations, FieldDisciplineHoldsAcrossKinds) {
    const Bytes bytes = splitmix_bytes(600u, 0x4d41525043313148ull);
    const std::vector<Observation> obs = probe_bytes(bytes, seg(0u, 600u), 5u);
    ASSERT_FALSE(obs.empty());
    for (const Observation& o : obs) expect_field_discipline(o);
    // Ordered by kind ordinal then param.
    for (std::size_t i = 1; i < obs.size(); ++i) {
        EXPECT_FALSE(observation_precedes(obs[i], obs[i - 1u]))
            << "index " << i << ": " << observation_text(obs[i - 1u]) << " then "
            << observation_text(obs[i]);
    }
}

TEST(C11Observations, EmptySegmentYieldsWellDefinedZeros) {
    const std::vector<Observation> obs = probe_bytes(Bytes{}, seg(0u, 0u), 5u);
    ASSERT_TRUE(has_obs(obs, ProbeKind::H0));
    ASSERT_TRUE(has_obs(obs, ProbeKind::H1));
    ASSERT_TRUE(has_obs(obs, ProbeKind::H2));
    ASSERT_TRUE(has_obs(obs, ProbeKind::Runs));
    for (u32 plane = 0u; plane < 8u; ++plane) {
        ASSERT_TRUE(has_obs(obs, ProbeKind::Skew, plane));
        ASSERT_TRUE(has_obs(obs, ProbeKind::BitComplexity, plane));
    }
    EXPECT_FALSE(has_obs(obs, ProbeKind::Period));
    EXPECT_FALSE(has_obs(obs, ProbeKind::Repeat16));
    EXPECT_FALSE(has_obs(obs, ProbeKind::AffineFit));
    EXPECT_FALSE(has_obs(obs, ProbeKind::QuadraticFit));
    EXPECT_FALSE(has_obs(obs, ProbeKind::Stride));
    EXPECT_FALSE(has_obs(obs, ProbeKind::ChangePoint));
    for (const Observation& o : obs) {
        EXPECT_EQ(o.value, 0u) << probe_kind_name(o.kind);
        EXPECT_EQ(o.aux, 0u) << probe_kind_name(o.kind);
        expect_field_discipline(o);
    }
}

TEST(C11Observations, ObservationCountIsBounded) {
    const Bytes bytes = splitmix_bytes(4096u, 0x4d41525043313149ull);
    const std::vector<Observation> obs = probe_bytes(bytes, seg(0u, 4096u), 5u);
    // Random bytes: begin = 0 is no change point, but the plug-in stride
    // estimator reports a win at s=256 (16 samples/class), so the structural
    // maximum that actually appears is 25 of the 26 possible.
    EXPECT_EQ(obs.size(), 25u);
    EXPECT_LE(obs.size(), static_cast<std::size_t>(kMaxObservationsPerProbe));
    EXPECT_TRUE(has_obs(obs, ProbeKind::H0));
    EXPECT_TRUE(has_obs(obs, ProbeKind::H1));
    EXPECT_TRUE(has_obs(obs, ProbeKind::H2));
    EXPECT_TRUE(has_obs(obs, ProbeKind::Runs));
    EXPECT_TRUE(has_obs(obs, ProbeKind::Period));
    EXPECT_TRUE(has_obs(obs, ProbeKind::Repeat16));
    EXPECT_TRUE(has_obs(obs, ProbeKind::AffineFit));
    EXPECT_TRUE(has_obs(obs, ProbeKind::QuadraticFit));
    for (u32 plane = 0u; plane < 8u; ++plane) {
        EXPECT_TRUE(has_obs(obs, ProbeKind::Skew, plane));
        EXPECT_TRUE(has_obs(obs, ProbeKind::BitComplexity, plane));
    }
}

TEST(C11Observations, NoFloatingPointFieldExists) {
    static_assert(std::is_same_v<decltype(Observation::value), u64>);
    static_assert(std::is_same_v<decltype(Observation::aux), u64>);
    static_assert(std::is_same_v<decltype(Observation::period), BigInt>);
    static_assert(std::is_same_v<decltype(Observation::digest), std::array<u8, 32>>);
    static_assert(!std::is_floating_point_v<u64>);
    static_assert(!std::is_floating_point_v<u32>);
    static_assert(!std::is_floating_point_v<BigInt>);
    SUCCEED();
}

TEST(C11Observations, EqualityAndTextAreFieldExact) {
    const Bytes bytes = repeat_block(Bytes{'a', 'b'}, 128u);
    const std::vector<Observation> a = probe_bytes(bytes, seg(0u, 128u), 5u);
    const std::vector<Observation> b = probe_bytes(bytes, seg(0u, 128u), 5u);
    ASSERT_EQ(a.size(), b.size());
    for (std::size_t i = 0; i < a.size(); ++i) {
        EXPECT_TRUE(observations_equal(a[i], b[i]));
        EXPECT_EQ(observation_text(a[i]), observation_text(b[i]));
    }
    Observation mutated = a[0u];
    mutated.aux = mutated.aux + 1u;
    EXPECT_FALSE(observations_equal(mutated, a[0u]));
}

// ---------------------------------------------------------------------------
// Locality (E4-I2, O8.7)
// ---------------------------------------------------------------------------

TEST(C11Locality, MutatingOutsideWhereLeavesObservationsIdentical) {
    const Bytes base = splitmix_bytes(8192u, 0x4d41525043313150ull);
    const Segment where = seg(1000u, 2000u);
    const std::vector<Observation> expected = probe_bytes(base, where, 5u);
    ASSERT_FALSE(expected.empty());
    EXPECT_FALSE(has_obs(expected, ProbeKind::ChangePoint));  // off-grid begin

    // Mutate bytes outside [1000, 2000), one at a time; measurement
    // observations must not move.
    for (const u64 at : {u64{0u}, u64{500u}, u64{999u}, u64{2000u}, u64{4000u}, u64{8191u}}) {
        Bytes mutated = base;
        mutated[static_cast<std::size_t>(at)] =
            static_cast<u8>(mutated[static_cast<std::size_t>(at)] ^ 0xA5u);
        const std::vector<Observation> got = probe_bytes(mutated, where, 5u);
        ASSERT_EQ(got.size(), expected.size()) << "at=" << at;
        for (std::size_t i = 0; i < got.size(); ++i) {
            EXPECT_TRUE(observations_equal(got[i], expected[i]))
                << "at=" << at << " obs=" << probe_kind_name(expected[i].kind);
        }
    }
}

TEST(C11Locality, MutatingInsideWhereChangesTheObservation) {
    // Sanity: the probe does read the range.  A constant run with one byte
    // flipped changes H0, Runs and Skew deterministically.
    const Bytes base(500u, 0x33u);
    const Segment where = seg(0u, 500u);
    const std::vector<Observation> expected = probe_bytes(base, where, 5u);
    Bytes mutated = base;
    mutated[250u] = 0x44u;
    const std::vector<Observation> got = probe_bytes(mutated, where, 5u);
    const Observation* h0a = find_obs(expected, ProbeKind::H0);
    const Observation* h0b = find_obs(got, ProbeKind::H0);
    ASSERT_NE(h0a, nullptr);
    ASSERT_NE(h0b, nullptr);
    EXPECT_NE(h0a->value, h0b->value);
    const Observation* runs_a = find_obs(expected, ProbeKind::Runs);
    const Observation* runs_b = find_obs(got, ProbeKind::Runs);
    ASSERT_NE(runs_a, nullptr);
    ASSERT_NE(runs_b, nullptr);
    EXPECT_NE(runs_a->value, runs_b->value);
}

TEST(C11Locality, ChangePointScopeIsItsDetectionWindow) {
    // ChangePoint records a boundary classification made by the §4.5 detector,
    // whose decision window straddles `where.begin` (documented C11 decision).
    // Mutating outside the classification inputs must not move it.
    Bytes base;
    base.insert(base.end(), 32u * 1024u, 0x00u);
    const Bytes rand = splitmix_bytes(96u * 1024u, 0x4d41525043313151ull);
    base.insert(base.end(), rand.begin(), rand.end());
    const std::span<const u8> view(base.data(), base.size());
    const std::vector<u64> cps = ref_change_points(view);
    ASSERT_FALSE(cps.empty());
    const u64 cp = cps.front();
    const Segment where = seg(cp, cp + 4096u);
    const std::vector<Observation> expected = probe_bytes(base, where, 5u);
    const Observation* change = find_obs(expected, ProbeKind::ChangePoint);
    ASSERT_NE(change, nullptr);
    EXPECT_EQ(change->aux, cp);

    // Mutate far outside the detection window [cp-4096, cp+4096) and outside
    // `where`: every observation, ChangePoint included, is identical.
    const u64 length = static_cast<u64>(base.size());
    for (const u64 at : {u64{0u}, u64{100u}, u64{cp + 8192u}, u64{length - 1u}}) {
        if (at >= (cp >= 4096u ? cp - 4096u : 0u) && at < cp + 4096u) continue;
        if (at >= cp && at < cp + 4096u) continue;  // inside `where`
        Bytes mutated = base;
        mutated[static_cast<std::size_t>(at)] =
            static_cast<u8>(mutated[static_cast<std::size_t>(at)] ^ 0x5Au);
        const std::vector<Observation> got = probe_bytes(mutated, where, 5u);
        ASSERT_EQ(got.size(), expected.size()) << "at=" << at;
        for (std::size_t i = 0; i < got.size(); ++i) {
            EXPECT_TRUE(observations_equal(got[i], expected[i]))
                << "at=" << at << " obs=" << probe_kind_name(expected[i].kind);
        }
    }
}

// ---------------------------------------------------------------------------
// Reproducibility (O8.5) and merge (§5.4)
// ---------------------------------------------------------------------------

TEST(C11Reproducibility, ReRunReproducesEveryField) {
    const Bytes base = splitmix_bytes(4096u, 0x4d41525043313152ull);
    const std::vector<Segment> ranges = {seg(0u, 4096u), seg(100u, 1100u), seg(4000u, 4096u)};
    for (const Segment& where : ranges) {
        const std::vector<Observation> first = probe_bytes(base, where, 5u);
        const std::vector<Observation> second = probe_bytes(base, where, 5u);
        ASSERT_EQ(first.size(), second.size());
        for (std::size_t i = 0; i < first.size(); ++i) {
            EXPECT_TRUE(observations_equal(first[i], second[i]))
                << probe_kind_name(first[i].kind);
        }
    }
}

TEST(C11Reproducibility, IndependentSourcesGiveIdenticalObservations) {
    const Bytes base = splitmix_bytes(2048u, 0x4d41525043313153ull);
    const Segment where = seg(0u, 2048u);
    std::vector<Observation> first;
    std::vector<Observation> second;
    {
        SpanSource a(std::span<const u8>(base.data(), base.size()));
        const auto got = probe(a, where, Policy{5u});
        ASSERT_TRUE(got.ok());
        first = got.value();
    }
    {
        // A second Source object over the same bytes, constructed separately.
        Bytes copy = base;
        SpanSource b(std::span<const u8>(copy.data(), copy.size()));
        const auto got = probe(b, where, Policy{5u});
        ASSERT_TRUE(got.ok());
        second = got.value();
    }
    ASSERT_EQ(first.size(), second.size());
    for (std::size_t i = 0; i < first.size(); ++i) {
        EXPECT_TRUE(observations_equal(first[i], second[i]));
    }
}

TEST(C11Merge, ShuffledCompletionOrderMergesToTheSerialList) {
    const Bytes base = splitmix_bytes(4096u, 0x4d41525043313154ull);
    std::vector<Segment> leaves;
    for (u64 begin = 0u; begin < 4096u; begin += 256u) {
        leaves.push_back(seg(begin, std::min<u64>(begin + 256u, 4096u)));
    }
    std::vector<std::vector<Observation>> parts;
    for (const Segment& leaf : leaves) {
        parts.push_back(probe_bytes(base, leaf, 5u));
    }
    const std::vector<Observation> serial =
        merge_observations(std::vector<std::vector<Observation>>(parts));

    // Deterministic completion orders: reversed, rotated, interleaved.
    std::vector<std::vector<Observation>> shuffled = parts;
    std::reverse(shuffled.begin(), shuffled.end());
    const std::vector<Observation> merged_reversed = merge_observations(std::move(shuffled));
    ASSERT_EQ(merged_reversed.size(), serial.size());
    for (std::size_t i = 0; i < serial.size(); ++i) {
        EXPECT_TRUE(observations_equal(merged_reversed[i], serial[i]));
    }

    std::vector<std::vector<Observation>> rotated = parts;
    std::rotate(rotated.begin(), rotated.begin() + 3u, rotated.end());
    const std::vector<Observation> merged_rotated = merge_observations(std::move(rotated));
    ASSERT_EQ(merged_rotated.size(), serial.size());
    for (std::size_t i = 0; i < serial.size(); ++i) {
        EXPECT_TRUE(observations_equal(merged_rotated[i], serial[i]));
    }

    std::vector<std::vector<Observation>> interleaved(parts.size());
    for (std::size_t i = 0; i < parts.size(); ++i) {
        interleaved[(i * 7u) % parts.size()] = parts[i];  // 16 parts, 7 coprime
    }
    const std::vector<Observation> merged_interleaved = merge_observations(std::move(interleaved));
    ASSERT_EQ(merged_interleaved.size(), serial.size());
    for (std::size_t i = 0; i < serial.size(); ++i) {
        EXPECT_TRUE(observations_equal(merged_interleaved[i], serial[i]));
    }

    // Sorted by (begin, kind, param).
    for (std::size_t i = 1; i < serial.size(); ++i) {
        EXPECT_FALSE(observation_precedes(serial[i], serial[i - 1u]));
    }
}

// ---------------------------------------------------------------------------
// Sampling (§4.9)
// ---------------------------------------------------------------------------

TEST(C11Sampling, ExactAtTwoMiBSampledAbove) {
    const Bytes exact = splitmix_bytes(2u * 1024u * 1024u, 0x4d41525043313155ull);
    {
        const u64 n = 2u * 1024u * 1024u;
        const std::vector<Observation> obs = probe_bytes(exact, seg(0u, n), 5u);
        const Observation* h2 = find_kind<ProbeKind::H2>(obs);
        ASSERT_NE(h2, nullptr);
        EXPECT_FALSE(h2->sampled);
        EXPECT_EQ(h2->sample_count, 0u);
        EXPECT_EQ(h2->param, 0u);
        EXPECT_EQ(h2->aux, n - 2u);
        const Observation* rep = find_kind<ProbeKind::Repeat16>(obs);
        ASSERT_NE(rep, nullptr);
        EXPECT_FALSE(rep->sampled);
        EXPECT_EQ(rep->sample_count, 0u);
        EXPECT_EQ(rep->param, 0u);
    }
    const Bytes sampled = splitmix_bytes((2u * 1024u * 1024u) + 1u, 0x4d41525043313156ull);
    {
        const u64 n = (2u * 1024u * 1024u) + 1u;
        const std::vector<Observation> obs = probe_bytes(sampled, seg(0u, n), 5u);
        const Observation* h2 = find_kind<ProbeKind::H2>(obs);
        ASSERT_NE(h2, nullptr);
        EXPECT_TRUE(h2->sampled);
        EXPECT_EQ(h2->sample_count, 16u);
        EXPECT_EQ(h2->param, 65536u);
        EXPECT_EQ(h2->aux, 16u * (65536u - 2u));
        const Observation* rep = find_kind<ProbeKind::Repeat16>(obs);
        ASSERT_NE(rep, nullptr);
        EXPECT_TRUE(rep->sampled);
        EXPECT_EQ(rep->sample_count, 16u);
        EXPECT_EQ(rep->param, 65536u);
    }
}

TEST(C11Sampling, SampledH2ReproducesFromPinnedWindowOffsets) {
    const Bytes bytes = splitmix_bytes((2u * 1024u * 1024u) + 1u, 0x4d41525043313157ull);
    const u64 n = static_cast<u64>(bytes.size());
    const std::vector<Observation> obs = probe_bytes(bytes, seg(0u, n), 5u);
    const Observation* h2 = find_kind<ProbeKind::H2>(obs);
    ASSERT_NE(h2, nullptr);
    ASSERT_TRUE(h2->sampled);

    // Independent recomputation: 16 windows of 64 KiB at floor(j*(N-65536)/15),
    // counts aggregated across windows (std::map, not the library's table).
    std::vector<u64> bigram(65536u, 0u);
    std::map<u32, u64> tri;
    for (u32 j = 0u; j < 16u; ++j) {
        const u64 off = static_cast<u64>(j) * (n - 65536u) / 15u;
        ASSERT_LE(off + 65536u, n) << "window j=" << j;
        for (u64 i = 2u; i < 65536u; ++i) {
            const u8 b0 = bytes[static_cast<std::size_t>(off + i - 2u)];
            const u8 b1 = bytes[static_cast<std::size_t>(off + i - 1u)];
            const u8 b2 = bytes[static_cast<std::size_t>(off + i)];
            ++bigram[(static_cast<u32>(b0) << 8u) | static_cast<u32>(b1)];
            ++tri[(static_cast<u32>(b0) << 16u) | (static_cast<u32>(b1) << 8u) |
                  static_cast<u32>(b2)];
        }
    }
    u128ref ctx_sum = 0u;
    for (const u64 c : bigram) ctx_sum += ref_term(c);
    u128ref joint_sum = 0u;
    for (const auto& entry : tri) joint_sum += ref_term(entry.second);
    const u64 total = 16u * (65536u - 2u);
    const u64 want = static_cast<u64>((ctx_sum - joint_sum) / total);
    EXPECT_EQ(h2->value, want);
    EXPECT_EQ(h2->aux, total);
}

TEST(C11Sampling, SampledRepeat16ReproducesFromPinnedWindowOffsets) {
    const Bytes bytes = splitmix_bytes((2u * 1024u * 1024u) + 1u, 0x4d41525043313158ull);
    const u64 n = static_cast<u64>(bytes.size());
    const std::vector<Observation> obs = probe_bytes(bytes, seg(0u, n), 5u);
    const Observation* rep = find_kind<ProbeKind::Repeat16>(obs);
    ASSERT_NE(rep, nullptr);
    ASSERT_TRUE(rep->sampled);

    // Independent recomputation with an ordered set (no hashing), one shared
    // seen-set across windows in ascending offset order.
    std::set<std::array<u8, 16>> seen;
    u64 matches = 0u;
    for (u32 j = 0u; j < 16u; ++j) {
        const u64 off = static_cast<u64>(j) * (n - 65536u) / 15u;
        for (u64 i = 0u; i + 16u <= 65536u; ++i) {
            std::array<u8, 16> key{};
            for (std::size_t k = 0; k < 16u; ++k) {
                key[k] = bytes[static_cast<std::size_t>(off + i + k)];
            }
            if (seen.find(key) != seen.end()) {
                ++matches;
            } else {
                seen.insert(key);
            }
        }
    }
    const u64 positions = 16u * (65536u - 15u);
    const u64 density = static_cast<u64>((static_cast<u128ref>(matches) << 24u) / positions);
    EXPECT_EQ(rep->aux, matches);
    EXPECT_EQ(rep->value, density);
}

TEST(C11Sampling, SampledNeverClaimsFullRange) {
    const Bytes bytes = splitmix_bytes((2u * 1024u * 1024u) + 9999u, 0x4d41525043313159ull);
    const u64 n = static_cast<u64>(bytes.size());
    const std::vector<Observation> obs = probe_bytes(bytes, seg(0u, n), 5u);
    for (const Observation& o : obs) {
        if (o.kind == ProbeKind::H2) {
            EXPECT_TRUE(o.sampled) << probe_kind_name(o.kind);
            EXPECT_EQ(o.aux, 16u * (65536u - 2u));
        } else if (o.kind == ProbeKind::Repeat16) {
            EXPECT_TRUE(o.sampled) << probe_kind_name(o.kind);
            EXPECT_LE(o.aux, 16u * (65536u - 15u));
        } else {
            EXPECT_FALSE(o.sampled) << probe_kind_name(o.kind);
        }
    }
}

// ---------------------------------------------------------------------------
// Effort (§4.10)
// ---------------------------------------------------------------------------

TEST(C11Effort, BudgetTableSelectsKinds) {
    const Bytes bytes = repeat_block(Bytes{'a', 'b'}, 128u);  // 128 bytes
    for (const u8 effort : {u8{0u}, u8{1u}, u8{2u}}) {
        const std::vector<Observation> obs = probe_bytes(bytes, seg(0u, 128u), effort);
        EXPECT_FALSE(has_obs(obs, ProbeKind::H2)) << "effort=" << static_cast<unsigned>(effort);
        EXPECT_FALSE(has_obs(obs, ProbeKind::Repeat16))
            << "effort=" << static_cast<unsigned>(effort);
        for (u32 plane = 2u; plane < 8u; ++plane) {
            EXPECT_FALSE(has_obs(obs, ProbeKind::BitComplexity, plane))
                << "effort=" << static_cast<unsigned>(effort);
        }
        for (u32 plane = 0u; plane < 2u; ++plane) {
            EXPECT_TRUE(has_obs(obs, ProbeKind::BitComplexity, plane))
                << "effort=" << static_cast<unsigned>(effort);
        }
        // Stride set {2,4,8}: the tie rule still picks 2.
        const Observation* stride = find_stride(obs);
        ASSERT_NE(stride, nullptr) << "effort=" << static_cast<unsigned>(effort);
        EXPECT_EQ(stride->aux, 2u);
    }
    for (const u8 effort : {u8{3u}, u8{5u}, u8{9u}}) {
        const std::vector<Observation> obs = probe_bytes(bytes, seg(0u, 128u), effort);
        EXPECT_TRUE(has_obs(obs, ProbeKind::H2)) << "effort=" << static_cast<unsigned>(effort);
        EXPECT_TRUE(has_obs(obs, ProbeKind::Repeat16))
            << "effort=" << static_cast<unsigned>(effort);
        for (u32 plane = 0u; plane < 8u; ++plane) {
            EXPECT_TRUE(has_obs(obs, ProbeKind::BitComplexity, plane))
                << "effort=" << static_cast<unsigned>(effort);
        }
        EXPECT_NE(find_stride(obs), nullptr) << "effort=" << static_cast<unsigned>(effort);
    }
}

TEST(C11Effort, NeverChangesAValue) {
    // "ab" repeated: every kind that exists at any effort exists at effort 5,
    // and every value matches — including Stride, which picks 2 from both
    // stride sets.
    const Bytes bytes = repeat_block(Bytes{'a', 'b'}, 128u);
    std::vector<std::vector<Observation>> per_effort;
    for (u8 effort = 0u; effort <= 9u; ++effort) {
        per_effort.push_back(probe_bytes(bytes, seg(0u, 128u), effort));
    }
    const std::vector<Observation>& full = per_effort[5u];
    for (u8 effort = 0u; effort <= 9u; ++effort) {
        ASSERT_FALSE(per_effort[static_cast<std::size_t>(effort)].empty());
        for (const Observation& o : per_effort[static_cast<std::size_t>(effort)]) {
            const Observation* twin = find_obs(full, o.kind, o.param);
            ASSERT_NE(twin, nullptr)
                << "effort=" << static_cast<unsigned>(effort)
                << " kind=" << probe_kind_name(o.kind);
            EXPECT_TRUE(observations_equal(o, *twin))
                << "effort=" << static_cast<unsigned>(effort)
                << " kind=" << probe_kind_name(o.kind);
        }
    }
}

TEST(C11Effort, EffortHelpersMatchTheTable) {
    {
        const auto set = stride_set_for_effort(0u);
        ASSERT_TRUE(set.ok());
        EXPECT_EQ(set.value().size(), 3u);
        EXPECT_EQ(set.value()[0u], 2u);
        EXPECT_EQ(set.value()[2u], 8u);
    }
    {
        const auto set = stride_set_for_effort(5u);
        ASSERT_TRUE(set.ok());
        EXPECT_EQ(set.value().size(), 9u);
        EXPECT_EQ(set.value()[8u], 4096u);
    }
    EXPECT_FALSE(stride_set_for_effort(10u).ok());
    {
        const auto planes = bit_complexity_plane_count(2u);
        ASSERT_TRUE(planes.ok());
        EXPECT_EQ(planes.value(), 2u);
    }
    {
        const auto planes = bit_complexity_plane_count(7u);
        ASSERT_TRUE(planes.ok());
        EXPECT_EQ(planes.value(), 8u);
    }
    EXPECT_FALSE(bit_complexity_plane_count(11u).ok());
}

// ---------------------------------------------------------------------------
// verify_period and errors (§5.3, §9)
// ---------------------------------------------------------------------------

TEST(C11VerifyPeriod, EveryReportedPeriodPassesTheFullCheck) {
    u64 seed = 0x4d41525043313161ull;
    for (const std::size_t n : {std::size_t{1u}, std::size_t{16u}, std::size_t{255u},
                                std::size_t{1024u}}) {
        seed += 0x9E3779B97F4A7C15ull;
        const Bytes bytes = splitmix_bytes(n, seed);
        const std::vector<Observation> obs =
            probe_bytes(bytes, seg(0u, static_cast<u64>(n)), 5u);
        const Observation* period = find_obs(obs, ProbeKind::Period);
        ASSERT_NE(period, nullptr) << "n=" << n;
        EXPECT_EQ(period->period,
                  BigInt(ref_period(std::span<const u8>(bytes.data(), n))));
        SpanSource source(std::span<const u8>(bytes.data(), bytes.size()));
        const auto verdict = verify_period(source, *period);
        ASSERT_TRUE(verdict.ok()) << "n=" << n;
        EXPECT_TRUE(verdict.value()) << "n=" << n;
    }
}

TEST(C11VerifyPeriod, ForgedPeriodFailsTheCheck) {
    const Bytes bytes = repeat_block(Bytes{'a', 'b'}, 128u);
    const std::vector<Observation> obs = probe_bytes(bytes, seg(0u, 128u), 5u);
    const Observation* period = find_obs(obs, ProbeKind::Period);
    ASSERT_NE(period, nullptr);
    ASSERT_EQ(period->period, BigInt(2u));

    SpanSource source(std::span<const u8>(bytes.data(), bytes.size()));
    {
        Observation forged = *period;
        forged.period = BigInt(3u);  // "abab" does not have period 3
        const auto verdict = verify_period(source, forged);
        ASSERT_TRUE(verdict.ok());
        EXPECT_FALSE(verdict.value());
    }
    {
        Observation forged = *period;
        forged.period = BigInt(1u);  // not constant
        const auto verdict = verify_period(source, forged);
        ASSERT_TRUE(verdict.ok());
        EXPECT_FALSE(verdict.value());
    }
}

TEST(C11VerifyPeriod, ContractViolationsAreInvalid) {
    const Bytes bytes = repeat_block(Bytes{'a', 'b'}, 128u);
    const std::vector<Observation> obs = probe_bytes(bytes, seg(0u, 128u), 5u);
    const Observation* period = find_obs(obs, ProbeKind::Period);
    ASSERT_NE(period, nullptr);
    SpanSource source(std::span<const u8>(bytes.data(), bytes.size()));

    {
        Observation wrong_kind = *period;
        wrong_kind.kind = ProbeKind::H0;
        EXPECT_EQ(verify_period(source, wrong_kind).code(), MeasureCode::Invalid);
    }
    {
        Observation zero_period = *period;
        zero_period.period = BigInt(0u);
        EXPECT_EQ(verify_period(source, zero_period).code(), MeasureCode::Invalid);
    }
    {
        Observation too_large = *period;
        too_large.period = BigInt(129u);  // > N = 128
        EXPECT_EQ(verify_period(source, too_large).code(), MeasureCode::Invalid);
    }
    {
        Observation unverified = *period;
        unverified.verified = false;  // §9: period present with verified = false
        EXPECT_EQ(verify_period(source, unverified).code(), MeasureCode::Invalid);
    }
    {
        Observation outside = *period;
        outside.where = seg(0u, 4096u);  // range outside the input
        EXPECT_EQ(verify_period(source, outside).code(), MeasureCode::Invalid);
    }
    {
        Observation empty = *period;
        empty.where = seg(0u, 0u);
        EXPECT_EQ(verify_period(source, empty).code(), MeasureCode::Invalid);
    }
}

TEST(C11Errors, InvalidForSegmentOutsideInputOrReversed) {
    const Bytes bytes = splitmix_bytes(100u, 0x4d41525043313162ull);
    SpanSource source(std::span<const u8>(bytes.data(), bytes.size()));
    EXPECT_EQ(probe(source, seg(0u, 101u), Policy{5u}).code(), MeasureCode::Invalid);
    EXPECT_EQ(probe(source, seg(101u, 200u), Policy{5u}).code(), MeasureCode::Invalid);
    EXPECT_EQ(probe(source, seg(5u, 2u), Policy{5u}).code(), MeasureCode::Invalid);
    EXPECT_EQ(probe(source, seg(0u, 100u), Policy{10u}).code(), MeasureCode::Invalid);
    EXPECT_EQ(probe(source, seg(0u, 100u), Policy{255u}).code(), MeasureCode::Invalid);
}

TEST(C11Errors, IoOnFailingOrShortSource) {
    class BigReadFailingSource final : public Source {
    public:
        explicit BigReadFailingSource(std::span<const u8> data) : data_(data) {}
        [[nodiscard]] BigInt size() const noexcept override {
            return BigInt(static_cast<u64>(data_.size()));
        }
        [[nodiscard]] MeasureCode read(const BigInt& off,
                                       std::span<u8> dst) const noexcept override {
            const auto at = off.to_u64_checked();
            if (!at.has_value()) return MeasureCode::Io;
            if (*at + static_cast<u64>(dst.size()) > 64u) return MeasureCode::Io;
            if (dst.size() > data_.size() - static_cast<std::size_t>(*at)) {
                return MeasureCode::Io;
            }
            if (!dst.empty()) {
                std::memcpy(dst.data(), data_.data() + static_cast<std::size_t>(*at),
                            dst.size());
            }
            return MeasureCode::Ok;
        }

    private:
        std::span<const u8> data_;
    };
    const Bytes bytes = splitmix_bytes(100u, 0x4d41525043313163ull);
    BigReadFailingSource failing(std::span<const u8>(bytes.data(), bytes.size()));
    EXPECT_EQ(probe(failing, seg(0u, 100u), Policy{5u}).code(), MeasureCode::Io);

    class TruncatingSource final : public Source {
    public:
        TruncatingSource(std::span<const u8> data, u64 declared)
            : data_(data), declared_(declared) {}
        [[nodiscard]] BigInt size() const noexcept override { return BigInt(declared_); }
        [[nodiscard]] MeasureCode read(const BigInt& off,
                                       std::span<u8> dst) const noexcept override {
            const auto at = off.to_u64_checked();
            if (!at.has_value() || *at > data_.size()) return MeasureCode::Io;
            if (dst.size() > data_.size() - static_cast<std::size_t>(*at)) {
                return MeasureCode::Io;
            }
            if (!dst.empty()) {
                std::memcpy(dst.data(), data_.data() + static_cast<std::size_t>(*at),
                            dst.size());
            }
            return MeasureCode::Ok;
        }

    private:
        std::span<const u8> data_;
        u64 declared_;
    };
    TruncatingSource short_source(std::span<const u8>(bytes.data(), bytes.size()), 10000u);
    EXPECT_EQ(probe(short_source, seg(0u, 10000u), Policy{5u}).code(), MeasureCode::Io);
}

TEST(C11Errors, NamesNeverReachTheProbe) {
    // The same bytes probed five times under five would-be labels — the label
    // is a log column only; `probe` receives bytes, never a path.
    const Bytes base = splitmix_bytes(1024u, 0x4d41525043313164ull);
    const Segment where = seg(0u, 1024u);
    const std::vector<Observation> first = probe_bytes(base, where, 5u);
    for (int i = 0; i < 4; ++i) {
        const std::vector<Observation> again = probe_bytes(base, where, 5u);
        ASSERT_EQ(again.size(), first.size());
        for (std::size_t k = 0; k < first.size(); ++k) {
            EXPECT_TRUE(observations_equal(again[k], first[k]));
        }
    }
}

}  // namespace
}  // namespace marp::v2
