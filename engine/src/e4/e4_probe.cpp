// MARP v2 — E4 MEASURE — C11 PROBE (implementation).
//
// One `probe()` call reads its segment's byte range once (bounded by
// `kProbeRangeCapBytes`, §9 `Limit`) and computes every §4.8 probe from that
// buffer with exact integer / Q24.24 fixed-point arithmetic over 128-bit
// intermediates.  Nothing here reads the clock, the environment, a file name,
// or global mutable state; nothing iterates a hash table to produce a value;
// no result depends on anything but the bytes of `where` and the recorded
// parameters (E4-I2, E4-I3, E4-I12).
//
// Probe notes:
//   * H0 reuses C10's `h0_q24`; H1/H2 and the Stride conditional entropies
//     accumulate the §4.2 sums exactly in `unsigned __int128` and perform the
//     single final floor division.  `N` in each formula is the total of the
//     count vector the formula sums (§4.2 defines N that way), so H1 divides
//     by the bigram count, H2 by the trigram count (exact: N-2; sampled:
//     16·(65536-2)), and Stride by the full byte count (every position has a
//     `i mod s` class).  See the C11 report §5 for the reading.
//   * Period scans p = 1..N and verifies the full byte check before
//     reporting; only a verified period is ever emitted (E4-I4).
//   * Repeat16 uses exact 16-byte keys in an open-addressing table with
//     byte-exact comparison (collision-checked, E4 §4.8); the table is never
//     iterated to produce a value — matches are counted in one left-to-right
//     scan.
//   * BitComplexity runs Berlekamp–Massey over GF(2) per bit plane and digests
//     the connection polynomial as SHA-256(LE64(L) || packed c_1..c_L),
//     coefficients LSB-first, a documented C11 serialisation.
//   * ChangePoint re-derives the §4.5 detector's decision for `segment.begin`
//     with the same cap and dedup semantics as C10, scanning from the input
//     start with an early exit as soon as the decision is reached.
//
// Memory: H1/H2/Stride use dense count arrays bounded by the range cap;
// the H2 trigram map and the Repeat16 key set are open-addressing tables with
// power-of-two capacity (O(observed trigrams) / O(positions), §11).  No
// recursion, no exceptions, no floating point.

#include "mapr/e4/e4_probe.hpp"

#include <algorithm>
#include <cstring>
#include <limits>
#include <string>
#include <utility>
#include <vector>

#include "mapr/e1_sha256.hpp"

namespace marp::v2 {

namespace {

#if !defined(__SIZEOF_INT128__)
#error "C11 PROBE requires a 128-bit unsigned intermediate (MARP2-E4 §4.2)"
#endif
__extension__ typedef unsigned __int128 u128;

constexpr std::size_t kBlockBytes = 64u * 1024u;

// ---------------------------------------------------------------------------
// Block reader
// ---------------------------------------------------------------------------

// Streams `[off, off + count)` in fixed blocks.  A failed or short read is
// `Io`; nothing is ever silently zero-filled.
template <typename Fn>
[[nodiscard]] MeasureCode for_each_block(Source& source, u64 off, u64 count, Fn&& fn) {
    std::array<u8, kBlockBytes> block{};
    u64 pos = off;
    u64 left = count;
    while (left > 0u) {
        const std::size_t want = static_cast<std::size_t>(std::min<u64>(left, kBlockBytes));
        const std::span<u8> dst(block.data(), want);
        const MeasureCode rc = source.read(BigInt(pos), dst);
        if (rc != MeasureCode::Ok) return MeasureCode::Io;
        if (!fn(std::span<const u8>(block.data(), want), pos)) return MeasureCode::Ok;
        pos += static_cast<u64>(want);
        left -= static_cast<u64>(want);
    }
    return MeasureCode::Ok;
}

// Reads `[off, off + count)` into `out` (one pass, deterministic re-reads are
// the `Source` contract, E4-I11).
[[nodiscard]] MeasureCode read_range(Source& source, u64 off, u64 count, std::vector<u8>& out) {
    out.assign(static_cast<std::size_t>(count), 0u);
    if (count == 0u) return MeasureCode::Ok;
    return for_each_block(source, off, count,
                          [&](std::span<const u8> bytes, u64 base) {
                              const std::size_t at = static_cast<std::size_t>(base - off);
                              std::memcpy(out.data() + at, bytes.data(), bytes.size());
                              return true;
                          });
}

// ---------------------------------------------------------------------------
// Fixed-point entropy helpers (E4 §4.2)
// ---------------------------------------------------------------------------

// n · ilog2_q24(n) as an exact 128-bit term; 0 for n = 0.
[[nodiscard]] inline u128 entropy_term(u64 n) noexcept {
    if (n == 0u) return 0u;
    return static_cast<u128>(n) * static_cast<u128>(ilog2_q24(n));
}

// floor((ctx_sum − joint_sum) / n).  Floor(log) is monotone, so with
// Σ_joint n_j = n_ctx = n the difference is provably non-negative even with
// every log pre-floored; the guard keeps the division well-defined regardless.
[[nodiscard]] inline u64 conditional_entropy_q24(u128 ctx_sum, u128 joint_sum, u64 n) noexcept {
    if (n == 0u) return 0u;
    if (joint_sum >= ctx_sum) return 0u;
    return static_cast<u64>((ctx_sum - joint_sum) / static_cast<u128>(n));
}

// floor(v · 2^24 / n) — the Q24.24 density of v in n.
[[nodiscard]] inline u64 density_q24(u64 v, u64 n) noexcept {
    if (n == 0u) return 0u;
    return static_cast<u64>((static_cast<u128>(v) << 24u) / static_cast<u128>(n));
}

// H1 over a materialised range: contexts are the previous byte, positions
// 1..N-1.  aux/N is the bigram count N-1 (§4.2's N is the count total).
[[nodiscard]] u64 h1_q24_of(std::span<const u8> bytes) {
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
    u128 ctx_sum = 0u;
    for (const u64 c : ctx) ctx_sum += entropy_term(c);
    u128 joint_sum = 0u;
    for (const u64 c : joint) joint_sum += entropy_term(c);
    return conditional_entropy_q24(ctx_sum, joint_sum, n - 1u);
}

// ---------------------------------------------------------------------------
// Sparse H2 trigram counts
// ---------------------------------------------------------------------------

// Open-addressing table over 24-bit trigram keys with u32 counts.  The table
// is never iterated to produce an *ordered* result: `joint_sum()` sums exact
// 128-bit terms, which is order-independent, so the value cannot depend on
// slot order or growth history (E4-I3).
class TrigramCounts {
public:
    TrigramCounts() { reset(); }

    void reset() {
        if (slots_.empty()) {
            slots_.assign(kInitialSlots, kEmptySlot);
            counts_.assign(kInitialSlots, 0u);
        } else {
            std::fill(slots_.begin(), slots_.end(), kEmptySlot);
        }
        mask_ = slots_.size() - 1u;
        entries_ = 0u;
    }

    void add(u32 key) {
        if ((entries_ + 1u) * 2u > slots_.size()) grow();
        std::size_t idx = static_cast<std::size_t>(mix(key)) & mask_;
        for (;;) {
            if (slots_[idx] == kEmptySlot) {
                slots_[idx] = key;
                counts_[idx] = 1u;
                ++entries_;
                return;
            }
            if (slots_[idx] == key) {
                ++counts_[idx];  // bounded by the range cap, far below 2^32
                return;
            }
            idx = (idx + 1u) & mask_;
        }
    }

    // Σ n_{c,b,d} · ilog2_q24(n_{c,b,d}) over all observed trigrams.
    [[nodiscard]] u128 joint_sum() const noexcept {
        u128 sum = 0u;
        for (std::size_t i = 0; i < slots_.size(); ++i) {
            if (slots_[i] != kEmptySlot) sum += entropy_term(counts_[i]);
        }
        return sum;
    }

private:
    static constexpr u32 kEmptySlot = 0xFFFFFFFFu;  // trigram keys are < 2^24
    static constexpr std::size_t kInitialSlots = 1u << 16;

    static u32 mix(u32 key) noexcept {
        u64 z = key;
        z = (z + 0x9E3779B97F4A7C15ull) & 0xFFFFFFFFull;
        z = (z ^ (z >> 16)) * 0x21F0AA19ull;
        z = (z ^ (z >> 15)) * 0x735A2D97ull;
        return static_cast<u32>((z ^ (z >> 15)) & 0xFFFFFFFFull);
    }

    void grow() {
        const std::vector<u32> old_slots = slots_;
        const std::vector<u32> old_counts = counts_;
        slots_.assign(old_slots.size() * 2u, kEmptySlot);
        counts_.assign(old_counts.size() * 2u, 0u);
        mask_ = slots_.size() - 1u;
        entries_ = 0u;
        for (std::size_t i = 0; i < old_slots.size(); ++i) {
            if (old_slots[i] == kEmptySlot) continue;
            const u32 key = old_slots[i];
            const u32 count = old_counts[i];
            std::size_t idx = static_cast<std::size_t>(mix(key)) & mask_;
            while (slots_[idx] != kEmptySlot) idx = (idx + 1u) & mask_;
            slots_[idx] = key;
            counts_[idx] = count;
            ++entries_;
        }
    }

    std::vector<u32> slots_;
    std::vector<u32> counts_;
    std::size_t mask_ = 0u;
    std::size_t entries_ = 0u;
};

// H2 over one contiguous byte span (exact path): contexts are the two previous
// bytes; the trigram count total is n − 2.
struct H2Counts {
    std::vector<u64> bigram = std::vector<u64>(65536u, 0u);  // context counts
    TrigramCounts tri{};

    void reset() {
        std::fill(bigram.begin(), bigram.end(), 0u);
        tri.reset();
    }
};

// Accumulates one contiguous span into `counts` (window-local for the sampled
// path; shared across windows by calling it per window, which aggregates).
void h2_accumulate(std::span<const u8> bytes, H2Counts& counts) {
    const u64 n = static_cast<u64>(bytes.size());
    for (u64 i = 2u; i < n; ++i) {
        const u8 b0 = bytes[static_cast<std::size_t>(i - 2u)];
        const u8 b1 = bytes[static_cast<std::size_t>(i - 1u)];
        const u8 b2 = bytes[static_cast<std::size_t>(i)];
        ++counts.bigram[(static_cast<u32>(b0) << 8u) | static_cast<u32>(b1)];
        counts.tri.add((static_cast<u32>(b0) << 16u) | (static_cast<u32>(b1) << 8u) |
                       static_cast<u32>(b2));
    }
}

// H2 value from accumulated counts over `total` trigrams.
[[nodiscard]] u64 h2_value_of(const H2Counts& counts, u64 total) {
    u128 ctx_sum = 0u;
    for (const u64 c : counts.bigram) ctx_sum += entropy_term(c);
    return conditional_entropy_q24(ctx_sum, counts.tri.joint_sum(), total);
}

// ---------------------------------------------------------------------------
// Repeat16 — exact 16-byte keys, collision-checked (E4 §4.8)
// ---------------------------------------------------------------------------

// Open-addressing set of 16-byte keys with byte-exact comparison.  Lookup and
// insertion never read beyond the key; the table is never iterated.
class Seen16 {
public:
    Seen16() {
        keys_.assign(kInitialSlots, Key{});
        used_.assign(kInitialSlots, 0u);
        mask_ = kInitialSlots - 1u;
    }

    // Returns true when the key was already present; otherwise inserts it.
    [[nodiscard]] bool seen_or_insert(const u8* key) {
        if ((entries_ + 1u) * 2u > keys_.size()) grow();
        std::size_t idx = static_cast<std::size_t>(hash16(key)) & mask_;
        for (;;) {
            if (used_[idx] == 0u) {
                std::memcpy(keys_[idx].data(), key, 16u);
                used_[idx] = 1u;
                ++entries_;
                return false;
            }
            if (std::memcmp(keys_[idx].data(), key, 16u) == 0) return true;
            idx = (idx + 1u) & mask_;
        }
    }

private:
    using Key = std::array<u8, 16>;
    static constexpr std::size_t kInitialSlots = 1u << 10;

    static u64 load_be(const u8* p) noexcept {
        u64 v = 0u;
        for (int i = 0; i < 8; ++i) v = (v << 8u) | static_cast<u64>(p[i]);
        return v;
    }

    static u64 mix64(u64 z) noexcept {
        z += 0x9E3779B97F4A7C15ull;
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
        return z ^ (z >> 31);
    }

    static u64 hash16(const u8* key) noexcept {
        const u64 a = load_be(key);
        const u64 b = load_be(key + 8u);
        return mix64(a) ^ mix64(b + 0x9E3779B97F4A7C15ull);
    }

    void grow() {
        const std::size_t old_slots = keys_.size();
        std::vector<Key> old_keys = keys_;
        std::vector<u8> old_used = used_;
        keys_.assign(old_slots * 2u, Key{});
        used_.assign(old_slots * 2u, 0u);
        mask_ = keys_.size() - 1u;
        entries_ = 0u;
        for (std::size_t i = 0; i < old_slots; ++i) {
            if (old_used[i] == 0u) continue;
            (void)seen_or_insert(old_keys[i].data());
        }
    }

    std::vector<Key> keys_;
    std::vector<u8> used_;
    std::size_t mask_ = 0u;
    std::size_t entries_ = 0u;
};

// ---------------------------------------------------------------------------
// Berlekamp–Massey over GF(2) (E4 §4.8 BitComplexity)
// ---------------------------------------------------------------------------

struct BmResult {
    u32 l = 0u;                 // linear complexity
    std::vector<u8> coeffs;     // c_1..c_L of C(x) = 1 + c_1·x + … + c_L·x^L
};

// Massey's iterative algorithm on the bit sequence `bits` (0/1 per position).
// `c` and `b` hold the connection polynomial coefficients indexed by degree
// (c[0] = 1 always); `m` counts the steps since `b` was set.  All arrays are
// sized n+2, which dominates deg(x^m·B) ≤ t+1 (Massey's invariant).
[[nodiscard]] BmResult berlekamp_massey(std::span<const u8> bits) {
    const u64 n = static_cast<u64>(bits.size());
    BmResult out;
    if (n == 0u) return out;  // empty range: the zero polynomial, L = 0

    // C(x) and B(x) as coefficient vectors indexed by degree; c[0] = 1 always.
    // GCC 15's path-based -Wnull-dereference cannot see through the
    // runtime-sized value-initialising constructors below and falsely reports
    // the index-0 stores as potential null dereferences (the vectors are
    // provably non-empty: n >= 1 after the early return).  Writing through
    // explicitly checked data pointers documents that invariant to the analyzer.
    std::vector<u8> c(static_cast<std::size_t>(n) + 2u, 0u);
    std::vector<u8> b(static_cast<std::size_t>(n) + 2u, 0u);
    if (u8* pc = c.data()) {
        pc[0] = 1u;
    }
    if (u8* pb = b.data()) {
        pb[0] = 1u;
    }
    u32 l = 0u;
    u64 m = 1u;

    for (u64 t = 0u; t < n; ++t) {
        u8 d = bits[static_cast<std::size_t>(t)];
        const u64 max_i = std::min<u64>(static_cast<u64>(l), t);
        for (u64 i = 1u; i <= max_i; ++i) {
            d = static_cast<u8>(d ^ (c[static_cast<std::size_t>(i)] &
                                     bits[static_cast<std::size_t>(t - i)]));
        }
        if (d == 0u) {
            ++m;
            continue;
        }
        if (2ull * static_cast<u64>(l) <= t) {
            const std::vector<u8> saved = c;  // T = C
            for (u64 i = 0u; i + m <= t + 1u; ++i) {
                if (b[static_cast<std::size_t>(i)] != 0u) {
                    c[static_cast<std::size_t>(i + m)] ^= 1u;
                }
            }
            l = static_cast<u32>(t + 1u - static_cast<u64>(l));
            b = saved;  // B = T
            m = 1u;
        } else {
            for (u64 i = 0u; i + m <= t + 1u; ++i) {
                if (b[static_cast<std::size_t>(i)] != 0u) {
                    c[static_cast<std::size_t>(i + m)] ^= 1u;
                }
            }
            ++m;
        }
    }

    out.l = l;
    out.coeffs.assign(static_cast<std::size_t>(l), 0u);
    for (u32 i = 1u; i <= l; ++i) {
        out.coeffs[static_cast<std::size_t>(i) - 1u] = c[static_cast<std::size_t>(i)];
    }
    return out;
}

// SHA-256( LE64(L) || packed c_1..c_L ), coefficients LSB-first within each
// byte: bit p of byte k is c_{8k+p+1}.  Documented C11 serialisation.
[[nodiscard]] std::array<u8, 32> bm_digest(u32 l, std::span<const u8> coeffs) {
    std::string payload;
    payload.reserve(8u + coeffs.size() / 8u + 1u);
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
    if (digest.ok()) {
        std::copy(digest.value().begin(), digest.value().end(), out.begin());
    }
    return out;
}

// ---------------------------------------------------------------------------
// §4.5 change-point membership for one offset (ChangePoint probe)
// ---------------------------------------------------------------------------

// Decides whether `begin` is a boundary inserted by the §4.5 change-point
// detector, with exactly C10's semantics: candidates are the interior window
// boundaries `i` (W bytes on both sides, stepping by the hop) with
// `dH0 >= 2^24` or `dZ >= 2^22`, inserted in increasing order up to the cap
// `L/2048 + 16` (the scan stops at the cap), then deduplicated within 2048
// bytes keeping the smaller offset.  `begin` is therefore a change point iff
// it passes the thresholds, the scan reached it before the cap was hit, and
// no *kept* candidate lies within 2048 bytes before it.  The scan stops as
// soon as the decision is reached; later candidates cannot change it.
[[nodiscard]] bool begin_is_change_point(Source& source, u64 length, u64 begin) {
    const u64 window = kChangeWindow;
    const u64 hop = kChangeHop;
    if (begin < window || begin % hop != 0u) return false;
    if (length < 2u * window || begin + window > length) return false;

    const u64 cap = length / hop + kChangeCapSlack;
    std::vector<u8> buf(static_cast<std::size_t>(2u * window));
    u64 buf_start = 0u;
    u64 buf_len = 0u;  // valid bytes at buf[0, buf_len) starting at buf_start

    std::array<u64, 256> left_counts{};
    std::array<u64, 256> right_counts{};
    u64 candidates = 0u;
    u64 last_kept = 0u;
    bool have_kept = false;

    for (u64 i = window; i + window <= length; i += hop) {
        // Slide the 2W window: keep the overlap, read only what entered.
        const u64 want = i - window;
        const u64 need_end = want + 2u * window;
        if (buf_len != 0u && want >= buf_start && want < buf_start + buf_len) {
            const u64 shift = want - buf_start;
            std::memmove(buf.data(), buf.data() + static_cast<std::size_t>(shift),
                         static_cast<std::size_t>(buf_len - shift));
            buf_len -= shift;
            buf_start = want;
        } else {
            buf_len = 0u;
            buf_start = want;
        }
        if (buf_start + buf_len < need_end) {
            const u64 tail_start = buf_start + buf_len;
            const MeasureCode rc =
                for_each_block(source, tail_start, need_end - tail_start,
                               [&](std::span<const u8> bytes, u64 base) {
                                   const std::size_t at =
                                       static_cast<std::size_t>(base - buf_start);
                                   std::memcpy(buf.data() + at, bytes.data(), bytes.size());
                                   return true;
                               });
            if (rc != MeasureCode::Ok) return false;  // unreadable: not provable, not reported
            buf_len = need_end - buf_start;
        }

        left_counts.fill(0u);
        right_counts.fill(0u);
        const std::span<const u8> left(buf.data(), static_cast<std::size_t>(window));
        const std::span<const u8> right(buf.data() + window, static_cast<std::size_t>(window));
        for (const u8 byte : left) ++left_counts[byte];
        for (const u8 byte : right) ++right_counts[byte];

        const u64 h0_left = h0_q24_from_counts(left_counts);
        const u64 h0_right = h0_q24_from_counts(right_counts);
        const u64 z_left = zero_frac_q24(left);
        const u64 z_right = zero_frac_q24(right);
        const u64 d_h0 = h0_left > h0_right ? h0_left - h0_right : h0_right - h0_left;
        const u64 d_z = z_left > z_right ? z_left - z_right : z_right - z_left;

        if (d_h0 >= kChangeEntropyQ24 || d_z >= kChangeZeroFracQ24) {
            if (candidates >= cap) return false;  // the detector's scan stops at the cap
            if (i == begin) {
                return !have_kept || (begin - last_kept >= kChangeDedupBytes);
            }
            ++candidates;
            if (!have_kept || i - last_kept >= kChangeDedupBytes) {
                last_kept = i;
                have_kept = true;
            }
        }
        if (i == begin) return false;  // decided: begin is not a candidate
    }
    return false;
}

// ---------------------------------------------------------------------------
// Observation construction
// ---------------------------------------------------------------------------

[[nodiscard]] Observation base_observation(const Segment& where, ProbeKind kind) {
    Observation o{};
    o.where = where;
    o.kind = kind;
    return o;
}

}  // namespace

// ---------------------------------------------------------------------------
// Public surface
// ---------------------------------------------------------------------------

bool observations_equal(const Observation& a, const Observation& b) noexcept {
    return a.where == b.where && a.kind == b.kind && a.value == b.value && a.aux == b.aux &&
           a.period == b.period && a.digest == b.digest && a.verified == b.verified &&
           a.sampled == b.sampled && a.sample_count == b.sample_count && a.param == b.param;
}

bool observation_precedes(const Observation& a, const Observation& b) noexcept {
    if (a.where.begin != b.where.begin) return a.where.begin < b.where.begin;
    if (a.kind != b.kind) return static_cast<u8>(a.kind) < static_cast<u8>(b.kind);
    return a.param < b.param;
}

std::string observation_text(const Observation& obs) {
    std::string out;
    out += probe_kind_name(obs.kind);
    out += ' ';
    out += obs.where.begin.to_decimal();
    out += '-';
    out += obs.where.end.to_decimal();
    out += "@d";
    out += std::to_string(obs.where.depth);
    out += 'k';
    out += std::to_string(static_cast<unsigned>(obs.where.level));
    out += " value=";
    out += std::to_string(obs.value);
    out += " aux=";
    out += std::to_string(obs.aux);
    out += " period=";
    out += obs.period.to_decimal();
    out += " digest=";
    static constexpr char kHex[] = "0123456789abcdef";
    for (const u8 byte : obs.digest) {
        out.push_back(kHex[(byte >> 4u) & 0x0Fu]);
        out.push_back(kHex[byte & 0x0Fu]);
    }
    out += " verified=";
    out += obs.verified ? "1" : "0";
    out += " sampled=";
    out += obs.sampled ? "1" : "0";
    out += " sample_count=";
    out += std::to_string(obs.sample_count);
    out += " param=";
    out += std::to_string(obs.param);
    return out;
}

MeasureResult<std::span<const u64>> stride_set_for_effort(u8 effort) noexcept {
    if (!effort_in_domain(static_cast<u32>(effort))) return MeasureCode::Invalid;
    if (effort <= 2u) return std::span<const u64>(kStrideSetLow.data(), kStrideSetLow.size());
    return std::span<const u64>(kStrideSetAll.data(), kStrideSetAll.size());
}

MeasureResult<u32> bit_complexity_plane_count(u8 effort) noexcept {
    if (!effort_in_domain(static_cast<u32>(effort))) return MeasureCode::Invalid;
    return (effort <= 2u) ? 2u : 8u;
}

MeasureResult<std::vector<Observation>> probe(Source& source, const Segment& segment,
                                              const Policy& policy) {
    if (!effort_in_domain(static_cast<u32>(policy.effort))) return MeasureCode::Invalid;

    const auto length_opt = source.size().to_u64_checked();
    if (!length_opt.has_value()) return MeasureCode::Invalid;
    const u64 length = *length_opt;

    const auto begin_opt = segment.begin.to_u64_checked();
    const auto end_opt = segment.end.to_u64_checked();
    if (!begin_opt.has_value() || !end_opt.has_value()) return MeasureCode::Invalid;
    if (*begin_opt > *end_opt || *end_opt > length) return MeasureCode::Invalid;
    const u64 begin = *begin_opt;
    const u64 n = *end_opt - begin;

    if (n > kProbeRangeCapBytes) return MeasureCode::Limit;

    const MeasureResult<std::span<const u64>> strides = stride_set_for_effort(policy.effort);
    if (!strides.ok()) return strides.code();
    const MeasureResult<u32> planes = bit_complexity_plane_count(policy.effort);
    if (!planes.ok()) return planes.code();

    // One read of the evidence range; every probe below works off this buffer.
    std::vector<u8> buf;
    {
        const MeasureCode rc = read_range(source, begin, n, buf);
        if (rc != MeasureCode::Ok) return MeasureCode::Io;
    }
    const std::span<const u8> bytes(buf.data(), buf.size());
    const u64 h0 = h0_q24(bytes);

    std::vector<Observation> out;
    out.reserve(32u);

    // --- H0 (always) ---------------------------------------------------------
    {
        Observation o = base_observation(segment, ProbeKind::H0);
        o.value = h0;
        o.aux = n;
        out.push_back(std::move(o));
    }

    // --- H1 (always) ---------------------------------------------------------
    {
        Observation o = base_observation(segment, ProbeKind::H1);
        o.value = h1_q24_of(bytes);
        o.aux = (n >= 2u) ? n - 1u : 0u;
        out.push_back(std::move(o));
    }

    // --- H2 (effort >= 3; §4.9 sampling above 2 MiB) --------------------------
    if (policy.effort >= 3u) {
        Observation o = base_observation(segment, ProbeKind::H2);
        if (n >= 3u) {
            H2Counts counts;
            if (n <= kSampleExactMaxBytes) {
                h2_accumulate(bytes, counts);
                o.value = h2_value_of(counts, n - 2u);
                o.aux = n - 2u;
            } else {
                // 16 windows of 64 KiB at floor(j·(N−65536)/15), aggregated.
                for (u32 j = 0u; j < kSampleWindowCount; ++j) {
                    const u64 off = static_cast<u64>(j) * (n - kSampleWindowBytes) /
                                    static_cast<u64>(kSampleWindowCount - 1u);
                    const std::span<const u8> window(
                        bytes.data() + static_cast<std::size_t>(off),
                        static_cast<std::size_t>(kSampleWindowBytes));
                    h2_accumulate(window, counts);
                }
                const u64 total = static_cast<u64>(kSampleWindowCount) *
                                  (kSampleWindowBytes - 2u);
                o.value = h2_value_of(counts, total);
                o.aux = total;
                o.sampled = true;
                o.sample_count = kSampleWindowCount;
                o.param = static_cast<u32>(kSampleWindowBytes);
            }
        }
        out.push_back(std::move(o));
    }

    // --- Runs (always) --------------------------------------------------------
    {
        Observation o = base_observation(segment, ProbeKind::Runs);
        u64 run_count = 0u;
        u64 max_run = 0u;
        u64 i = 0u;
        while (i < n) {
            const u8 symbol = bytes[static_cast<std::size_t>(i)];
            u64 j = i + 1u;
            while (j < n && bytes[static_cast<std::size_t>(j)] == symbol) ++j;
            ++run_count;
            if (j - i > max_run) max_run = j - i;
            i = j;
        }
        o.value = run_count;
        o.aux = max_run;
        out.push_back(std::move(o));
    }

    // --- Period (non-empty; reported only when fully verified, E4-I4) ---------
    if (n > 0u) {
        u64 found = n;  // p = N is the trivial period (the check passes vacuously)
        for (u64 p = 1u; p <= n; ++p) {
            bool ok = true;
            for (u64 i = p; i < n; ++i) {
                if (bytes[static_cast<std::size_t>(i)] !=
                    bytes[static_cast<std::size_t>(i - p)]) {
                    ok = false;
                    break;
                }
            }
            if (ok) {
                found = p;
                break;
            }
        }
        Observation o = base_observation(segment, ProbeKind::Period);
        o.period = BigInt(found);
        o.verified = true;
        out.push_back(std::move(o));
    }

    // --- Repeat16 (effort >= 3; at least one full 16-byte window; §4.9) -------
    if (policy.effort >= 3u && n >= 16u) {
        Observation o = base_observation(segment, ProbeKind::Repeat16);
        Seen16 seen;
        u64 matches = 0u;
        u64 positions = 0u;
        if (n <= kSampleExactMaxBytes) {
            positions = n - 15u;
            for (u64 i = 0u; i < positions; ++i) {
                if (seen.seen_or_insert(bytes.data() + static_cast<std::size_t>(i))) ++matches;
            }
        } else {
            for (u32 j = 0u; j < kSampleWindowCount; ++j) {
                const u64 off = static_cast<u64>(j) * (n - kSampleWindowBytes) /
                                static_cast<u64>(kSampleWindowCount - 1u);
                const std::span<const u8> window(
                    bytes.data() + static_cast<std::size_t>(off),
                    static_cast<std::size_t>(kSampleWindowBytes));
                for (u64 i = 0u; i + 16u <= kSampleWindowBytes; ++i) {
                    if (seen.seen_or_insert(window.data() + static_cast<std::size_t>(i))) {
                        ++matches;
                    }
                }
            }
            positions = static_cast<u64>(kSampleWindowCount) * (kSampleWindowBytes - 15u);
            o.sampled = true;
            o.sample_count = kSampleWindowCount;
            o.param = static_cast<u32>(kSampleWindowBytes);
        }
        o.value = density_q24(matches, positions);
        o.aux = matches;
        out.push_back(std::move(o));
    }

    // --- Skew (always, planes 0..7) -------------------------------------------
    {
        std::array<u64, 8> ones{};
        for (const u8 byte : bytes) {
            for (u32 plane = 0u; plane < 8u; ++plane) {
                ones[plane] += static_cast<u64>((byte >> plane) & 1u);
            }
        }
        for (u32 plane = 0u; plane < 8u; ++plane) {
            Observation o = base_observation(segment, ProbeKind::Skew);
            o.value = density_q24(ones[plane], n);
            o.aux = n;
            o.param = plane;
            out.push_back(std::move(o));
        }
    }

    // --- BitComplexity (effort-selected planes; documented range cap) ---------
    if (n <= kBitComplexityMaxBytes) {
        std::vector<u8> bits(static_cast<std::size_t>(n), 0u);
        for (u32 plane = 0u; plane < planes.value(); ++plane) {
            for (u64 t = 0u; t < n; ++t) {
                bits[static_cast<std::size_t>(t)] =
                    static_cast<u8>((bytes[static_cast<std::size_t>(t)] >> plane) & 1u);
            }
            const BmResult bm = berlekamp_massey(std::span<const u8>(bits));
            Observation o = base_observation(segment, ProbeKind::BitComplexity);
            o.value = static_cast<u64>(bm.l);
            o.aux = 0u;
            o.digest = bm_digest(bm.l, std::span<const u8>(bm.coeffs));
            o.param = plane;
            out.push_back(std::move(o));
        }
    }

    // --- AffineFit (non-empty; exact predicate over the full range) -----------
    if (n > 0u) {
        const u8 a = bytes[0u];
        const u8 s = (n >= 2u)
                         ? static_cast<u8>((static_cast<u32>(bytes[1u]) - bytes[0u]) & 0xFFu)
                         : 0u;
        bool fit = true;
        for (u64 i = 0u; i < n; ++i) {
            const u8 want = static_cast<u8>((static_cast<u64>(a) + i * static_cast<u64>(s)) & 0xFFu);
            if (bytes[static_cast<std::size_t>(i)] != want) {
                fit = false;
                break;
            }
        }
        Observation o = base_observation(segment, ProbeKind::AffineFit);
        o.value = fit ? 1u : 0u;
        o.aux = fit ? (static_cast<u64>(a) | (static_cast<u64>(s) << 8u)) : 0u;
        out.push_back(std::move(o));
    }

    // --- QuadraticFit (non-empty; constant second difference mod 256) ---------
    if (n > 0u) {
        Observation o = base_observation(segment, ProbeKind::QuadraticFit);
        if (n <= 2u) {
            o.value = 1u;  // fewer than three points: vacuously constant, d2 = 0
            o.aux = 0u;
        } else {
            const auto second_diff = [&](u64 i) -> int {
                const int b0 = static_cast<int>(bytes[static_cast<std::size_t>(i)]);
                const int b1 = static_cast<int>(bytes[static_cast<std::size_t>(i + 1u)]);
                const int b2 = static_cast<int>(bytes[static_cast<std::size_t>(i + 2u)]);
                return b2 - 2 * b1 + b0;  // in [−511, 511]
            };
            const int d2 = ((second_diff(0u) % 256) + 256) % 256;
            bool fit = true;
            for (u64 i = 0u; i + 2u < n; ++i) {
                const int d = ((second_diff(i) % 256) + 256) % 256;
                if (d != d2) {
                    fit = false;
                    break;
                }
            }
            o.value = fit ? 1u : 0u;
            o.aux = fit ? static_cast<u64>(d2) : 0u;
        }
        out.push_back(std::move(o));
    }

    // --- Stride (best of the effort's set, improvement >= 2^23, smallest tie) -
    if (n > 0u) {
        u64 best_stride = 0u;
        u64 best_h = 0u;
        u64 best_improvement = 0u;
        std::vector<u64> joint;  // s × 256, reused per stride
        for (const u64 s : strides.value()) {
            // §4.8 reading: the aggregate order-1 entropy under `i mod s` is
            // only non-degenerate when every residue class holds at least two
            // samples.  With s > n/2 some classes hold 0 or 1 sample and the
            // floored-log plug-in estimator returns H_s = 0 trivially, which
            // would make any large stride "win" on random data.  Exclude such
            // strides; the smallest admissible stride still wins ties.
            if (s > n / 2u) continue;
            joint.assign(static_cast<std::size_t>(s) * 256u, 0u);
            for (u64 i = 0u; i < n; ++i) {
                const u64 cls = i % s;
                ++joint[static_cast<std::size_t>(cls * 256u +
                                                static_cast<u64>(bytes[static_cast<std::size_t>(i)]))];
            }
            u128 ctx_sum = 0u;
            for (u64 cls = 0u; cls < s; ++cls) {
                u64 row = 0u;
                for (u32 sym = 0u; sym < 256u; ++sym) {
                    row += joint[static_cast<std::size_t>(cls * 256u + sym)];
                }
                ctx_sum += entropy_term(row);
            }
            u128 joint_sum = 0u;
            for (const u64 c : joint) joint_sum += entropy_term(c);
            const u64 h_s = conditional_entropy_q24(ctx_sum, joint_sum, n);
            const u64 improvement = (h0 > h_s) ? h0 - h_s : 0u;
            if (improvement > best_improvement) {
                best_improvement = improvement;
                best_stride = s;
                best_h = h_s;
            }
        }
        if (best_improvement >= kStrideImprovementQ24) {
            Observation o = base_observation(segment, ProbeKind::Stride);
            o.value = best_h;
            o.aux = best_stride;
            o.param = static_cast<u32>(best_stride);
            out.push_back(std::move(o));
        }
    }

    // --- ChangePoint (exactly when segment.begin is a §4.5 change point) ------
    if (n > 0u && begin > 0u && begin_is_change_point(source, length, begin)) {
        Observation o = base_observation(segment, ProbeKind::ChangePoint);
        o.value = 1u;
        o.aux = begin;
        out.push_back(std::move(o));
    }

    if (out.size() > static_cast<std::size_t>(kMaxObservationsPerProbe)) {
        return MeasureCode::Limit;
    }
    return out;
}

MeasureResult<bool> verify_period(Source& source, const Observation& obs) {
    if (obs.kind != ProbeKind::Period) return MeasureCode::Invalid;

    const auto length_opt = source.size().to_u64_checked();
    if (!length_opt.has_value()) return MeasureCode::Invalid;
    const u64 length = *length_opt;

    const auto begin_opt = obs.where.begin.to_u64_checked();
    const auto end_opt = obs.where.end.to_u64_checked();
    if (!begin_opt.has_value() || !end_opt.has_value()) return MeasureCode::Invalid;
    if (*begin_opt > *end_opt || *end_opt > length) return MeasureCode::Invalid;
    const u64 begin = *begin_opt;
    const u64 n = *end_opt - begin;
    if (n == 0u) return MeasureCode::Invalid;  // a Period observation needs a non-empty range

    const auto period_opt = obs.period.to_u64_checked();
    if (!period_opt.has_value() || *period_opt == 0u || *period_opt > n) {
        return MeasureCode::Invalid;
    }
    if (!obs.verified) return MeasureCode::Invalid;  // §9: period present with verified = false
    const u64 p = *period_opt;

    if (n > kProbeRangeCapBytes) return MeasureCode::Limit;
    std::vector<u8> buf;
    {
        const MeasureCode rc = read_range(source, begin, n, buf);
        if (rc != MeasureCode::Ok) return MeasureCode::Io;
    }
    for (u64 i = p; i < n; ++i) {
        if (buf[static_cast<std::size_t>(i)] != buf[static_cast<std::size_t>(i - p)]) {
            return false;
        }
    }
    return true;
}

std::vector<Observation> merge_observations(std::vector<std::vector<Observation>>&& parts) {
    std::vector<Observation> out;
    std::size_t total = 0u;
    for (const std::vector<Observation>& part : parts) total += part.size();
    out.reserve(total);
    for (std::vector<Observation>& part : parts) {
        for (Observation& obs : part) out.push_back(std::move(obs));
    }
    std::stable_sort(out.begin(), out.end(), observation_precedes);
    return out;
}

}  // namespace marp::v2
