// MARP v2 — E4 MEASURE — C11 PROBE gate (`engine/bin/c11_gate`).
//
// Produces exactly three artefacts, all written by this binary and never by
// hand (C11 prompt §3, §5):
//
//   specs_and_reports/v2/gates/C11-PROBE.tsv
//   specs_and_reports/v2/logs/C11-PROBE.log
//   specs_and_reports/v2/evidence/C11/SHA256SUMS
//
// Every obligation is one row with the exact expected and actual values and a
// PASS/FAIL verdict.  Any FAIL makes the process exit non-zero.  The log is a
// fixed banner plus the rows in sorted order, so two runs on any host produce
// byte-identical files: the committed evidence is the evidence CI regenerates,
// not a snapshot of one machine.
//
// What this gate deliberately does NOT do:
//   * it does not claim the integrated E4-G gate (M-* corpus, 1-vs-4-thread
//     segmentation, rename independence at gate scale, oracle comparisons);
//   * it does not build a term, candidate, node, or atom, and it does not move
//     a boundary: every observation is checked against its own recorded `where`
//     and parameters only (E4-I2, E4-I8, O8.5, O8.7);
//   * it never reads a fixture from a file.  Every fixture is a pure function
//     of a pinned constant seed, so no name, extension, or path can reach a
//     value.
//
// Independence: the reference implementations in this file are written from the
// text of §4.2 and §4.7–§4.10 and share no code with the C11 library — a
// separate 62-bit-mantissa `ilog2_q24`, direct transcriptions of the entropy
// formulas over `std::map` counts, a naive minimal-period scan, a sort-based
// exact-key `Repeat16`, a bit-vector Berlekamp–Massey with the textbook
// T = pre-update-C swap, and the §4.5 window scan over materialised spans.
// Agreement is evidence that C11 implements the specification, not that it
// agrees with itself.

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <limits>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include "mapr/e1_bigint.hpp"
#include "mapr/e1_sha256.hpp"
#include "mapr/e4/e4_measure.hpp"
#include "mapr/e4/e4_probe.hpp"
#include "mapr/e4/e4_segment.hpp"

namespace fs = std::filesystem;

namespace {

using marp::v2::BigInt;
using marp::v2::bit_complexity_planes;
using marp::v2::h0_q24_from_counts;
using marp::v2::ilog2_q24;
using marp::v2::kBitPlanes;
using marp::v2::kChangeHop;
using marp::v2::kChangeWindow;
using marp::v2::kMaxProbeBytes;
using marp::v2::kMaxProbeObservations;
using marp::v2::kProbeKindCount;
using marp::v2::kRepeat16Window;
using marp::v2::kSampleThreshold;
using marp::v2::kSampleWindowBytes;
using marp::v2::kSampleWindowCount;
using marp::v2::kStrideMinImprovementQ24;
using marp::v2::kStrideSet;
using marp::v2::kStrideSetReduced;
using marp::v2::MeasureCode;
using marp::v2::Observation;
using marp::v2::observation_text;
using marp::v2::Policy;
using marp::v2::probe;
using marp::v2::probe_kind_name;
using marp::v2::probe_kind_ordinal;
using marp::v2::ProbeKind;
using marp::v2::sample_window_offsets;
using marp::v2::same_digest;
using marp::v2::Segment;
using marp::v2::Source;
using marp::v2::SpanSource;
using marp::v2::stride_set_for_effort;
using marp::v2::u32;
using marp::v2::u64;
using marp::v2::u8;
using marp::v2::validate_observation;
using marp::v2::verify_period;

__extension__ typedef unsigned __int128 u128;

// ---------------------------------------------------------------------------
// Evidence collector (eight columns, same as every other v2 gate)
// ---------------------------------------------------------------------------

struct Row {
    std::string check;
    std::string corpus;
    std::string item_id;
    std::string input_sha256;
    std::string expected;
    std::string actual;
    std::string verdict;
    std::string log;
};

class Evidence {
public:
    void add(Row row) {
        if (row.verdict == "PASS") {
            ++pass_;
        } else if (row.verdict == "BLOCKED") {
            ++blocked_;
        } else {
            ++fail_;
        }
        rows_.push_back(std::move(row));
    }

    void pass(const std::string& check, const std::string& corpus, const std::string& item,
              const std::string& input_sha, const std::string& expected,
              const std::string& actual) {
        add(Row{check, corpus, item, input_sha, expected, actual, "PASS", ref(check, item)});
    }

    void fail(const std::string& check, const std::string& corpus, const std::string& item,
              const std::string& input_sha, const std::string& expected,
              const std::string& actual) {
        add(Row{check, corpus, item, input_sha, expected, actual, "FAIL", ref(check, item)});
    }

    void either(bool ok, const std::string& check, const std::string& corpus,
                const std::string& item, const std::string& input_sha,
                const std::string& expected, const std::string& actual) {
        if (ok) {
            pass(check, corpus, item, input_sha, expected, actual);
        } else {
            fail(check, corpus, item, input_sha, expected, actual);
        }
    }

    static std::string ref(const std::string& check, const std::string& item) {
        return "logs/C11-PROBE.log#" + check + ":" + item;
    }

    [[nodiscard]] const std::vector<Row>& rows() const { return rows_; }
    [[nodiscard]] std::size_t passes() const { return pass_; }
    [[nodiscard]] std::size_t fails() const { return fail_; }
    [[nodiscard]] std::size_t blocked() const { return blocked_; }

private:
    std::vector<Row> rows_;
    std::size_t pass_ = 0;
    std::size_t fail_ = 0;
    std::size_t blocked_ = 0;
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

std::string hex_of(std::span<const u8> bytes) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2u);
    for (const u8 b : bytes) {
        out.push_back(kHex[(b >> 4) & 0x0Fu]);
        out.push_back(kHex[b & 0x0Fu]);
    }
    return out;
}

std::string u64_dec(u64 v) { return std::to_string(v); }

std::string digest_hex(const std::array<u8, 32>& digest) {
    return hex_of(std::span<const u8>(digest.data(), digest.size()));
}

std::string sha256_text_hex(std::string_view text) {
    const auto digest = mapr::Sha256::hash(text);
    if (!digest.ok()) return "err";
    return digest_hex(digest.value());
}

std::string hex_digest_of_bytes(std::span<const u8> bytes) {
    const auto digest = mapr::Sha256::hash(
        std::string_view(reinterpret_cast<const char*>(bytes.data()), bytes.size()));
    if (!digest.ok()) return "err";
    return digest_hex(digest.value());
}

// Deterministic splitmix64 bytes.  Fixed constant seeds; no clock, no random
// device, no file.
std::vector<u8> splitmix_bytes(std::size_t n, u64 seed) {
    std::vector<u8> out;
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

std::vector<u8> zeros(std::size_t n) { return std::vector<u8>(n, 0x00u); }

std::vector<u8> repeat_block(const std::vector<u8>& block, std::size_t n) {
    std::vector<u8> out;
    out.reserve(n);
    while (out.size() < n) {
        const std::size_t take = std::min(block.size(), n - out.size());
        out.insert(out.end(), block.begin(),
                   block.begin() + static_cast<std::ptrdiff_t>(take));
    }
    return out;
}

std::string list_text(const std::vector<u64>& values) {
    std::string out;
    for (std::size_t i = 0; i < values.size(); ++i) {
        if (i != 0u) out += ',';
        out += std::to_string(values[i]);
    }
    return out;
}

// ---------------------------------------------------------------------------
// Sources that misbehave on purpose
// ---------------------------------------------------------------------------

class FailingSource final : public Source {
public:
    explicit FailingSource(std::size_t fail_from) : fail_from_(fail_from) {}
    [[nodiscard]] BigInt size() const noexcept override { return BigInt(64); }
    [[nodiscard]] MeasureCode read(const BigInt& off, std::span<u8> dst) const noexcept override {
        const auto offset = off.to_u64_checked();
        if (!offset.has_value() || *offset >= fail_from_) return MeasureCode::Io;
        if (dst.size() > 64u - static_cast<std::size_t>(*offset)) return MeasureCode::Io;
        return MeasureCode::Ok;
    }

private:
    std::size_t fail_from_;
};

// ---------------------------------------------------------------------------
// Independent references, written from the text of the specification
// ---------------------------------------------------------------------------

// §4.2: `floor(log2(x)·2^24)` by 24 exact squarings of a 62-bit mantissa.
u64 reference_ilog2_q24(u64 x) {
    if (x == 0u) return 0u;
    unsigned msb = 0;
    while ((x >> msb) > 1u) ++msb;
    u128 m = (msb <= 62u) ? (static_cast<u128>(x) << (62u - msb))
                          : (static_cast<u128>(x) >> 1u);
    u64 frac = 0;
    for (int bit = 0; bit < 24; ++bit) {
        m = (m * m) >> 62u;
        frac <<= 1u;
        if (m >= (static_cast<u128>(1) << 63u)) {
            m >>= 1u;
            frac |= 1u;
        }
    }
    return (static_cast<u64>(msb) << 24u) | frac;
}

u64 reference_h0_q24(std::span<const u64> counts) {
    u128 n = 0;
    for (const u64 c : counts) n += c;
    if (n == 0) return 0u;
    u128 total = n * static_cast<u128>(reference_ilog2_q24(static_cast<u64>(n)));
    for (const u64 c : counts) {
        if (c == 0u) continue;
        total -= static_cast<u128>(c) * static_cast<u128>(reference_ilog2_q24(c));
    }
    return static_cast<u64>(total / n);
}

// §4.2 order-1 formula over byte pairs.
u64 reference_h1_q24(std::span<const u8> bytes) {
    if (bytes.size() < 2u) return 0u;
    std::unordered_map<u32, u64> joint;
    std::array<u64, 256> ctx{};
    for (std::size_t i = 1; i < bytes.size(); ++i) {
        ++joint[(static_cast<u32>(bytes[i - 1u]) << 8) | bytes[i]];
        ++ctx[bytes[i - 1u]];
    }
    const u64 samples = static_cast<u64>(bytes.size() - 1u);
    u128 sum_ctx = 0;
    for (const u64 c : ctx) {
        if (c != 0u) sum_ctx += static_cast<u128>(c) * reference_ilog2_q24(c);
    }
    u128 sum_joint = 0;
    for (const auto& [k, c] : joint) {
        (void)k;
        sum_joint += static_cast<u128>(c) * reference_ilog2_q24(c);
    }
    if (sum_joint > sum_ctx) return 0u;
    return static_cast<u64>((sum_ctx - sum_joint) / samples);
}

// §4.2 order-2 formula over trigrams, optionally aggregated over windows.
u64 reference_h2_q24_from(const std::unordered_map<u32, u64>& trigrams) {
    std::unordered_map<u32, u64> ctx;
    u64 samples = 0;
    for (const auto& [tri, c] : trigrams) {
        ctx[tri >> 8] += c;
        samples += c;
    }
    if (samples == 0u) return 0u;
    u128 sum_ctx = 0;
    for (const auto& [k, c] : ctx) {
        (void)k;
        sum_ctx += static_cast<u128>(c) * reference_ilog2_q24(c);
    }
    u128 sum_joint = 0;
    for (const auto& [k, c] : trigrams) {
        (void)k;
        sum_joint += static_cast<u128>(c) * reference_ilog2_q24(c);
    }
    if (sum_joint > sum_ctx) return 0u;
    return static_cast<u64>((sum_ctx - sum_joint) / samples);
}

u64 reference_h2_q24(std::span<const u8> bytes) {
    if (bytes.size() < 3u) return 0u;
    std::unordered_map<u32, u64> trigrams;
    for (std::size_t i = 2; i < bytes.size(); ++i) {
        ++trigrams[(static_cast<u32>(bytes[i - 2u]) << 16) |
                   (static_cast<u32>(bytes[i - 1u]) << 8) | bytes[i]];
    }
    return reference_h2_q24_from(trigrams);
}

// §4.8 Runs: direct scan.
u64 reference_run_count(std::span<const u8> bytes) {
    u64 runs = 0;
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        if (i == 0u || bytes[i] != bytes[i - 1u]) ++runs;
    }
    return runs;
}

u64 reference_max_run(std::span<const u8> bytes) {
    u64 best = 0;
    u64 current = 0;
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        current = (i != 0u && bytes[i] == bytes[i - 1u]) ? current + 1u : 1u;
        best = std::max(best, current);
    }
    return best;
}

// §4.8 Period: the definition itself — smallest p with b[i] == b[i-p] for all
// i >= p — searched naively.
bool reference_period_holds(std::span<const u8> bytes, u64 p) {
    for (u64 i = p; i < static_cast<u64>(bytes.size()); ++i) {
        if (bytes[static_cast<std::size_t>(i)] != bytes[static_cast<std::size_t>(i - p)]) {
            return false;
        }
    }
    return true;
}

u64 reference_minimal_period(std::span<const u8> bytes) {
    const u64 n = static_cast<u64>(bytes.size());
    if (n == 0u) return 0u;
    for (u64 p = 1; p <= n; ++p) {
        if (reference_period_holds(bytes, p)) return p;
    }
    return n;
}

// §4.8 Repeat16: exact 16-byte keys, grouped by sorting.  A position counts
// iff its key has an earlier occurrence, so the match count is
// `positions - distinct_keys` — computed here without any hashing at all.
u64 reference_repeat16_matches(std::span<const u8> bytes, u64& positions_out) {
    positions_out = 0u;
    if (bytes.size() < kRepeat16Window) return 0u;
    const u64 n = static_cast<u64>(bytes.size());
    const u64 positions = n - kRepeat16Window + 1u;
    positions_out = positions;
    std::vector<std::array<u8, kRepeat16Window>> keys;
    keys.reserve(static_cast<std::size_t>(positions));
    for (u64 p = 0; p < positions; ++p) {
        std::array<u8, kRepeat16Window> key{};
        std::memcpy(key.data(), bytes.data() + p, kRepeat16Window);
        keys.push_back(key);
    }
    std::sort(keys.begin(), keys.end());
    const u64 distinct = static_cast<u64>(
        std::unique(keys.begin(), keys.end()) - keys.begin());
    return positions - distinct;
}

// §4.8 BitComplexity: bit-vector Berlekamp–Massey, textbook form.  T is the
// pre-update C; the connection polynomial is 1 + c_1 x + ... + c_L x^L.
struct RefBm {
    u64 length = 0;
    std::vector<u8> coeffs;  // c_0 .. c_L
};

RefBm reference_bm(std::span<const u8> bits) {
    RefBm out;
    const u64 n = static_cast<u64>(bits.size());
    if (n == 0u) {
        out.coeffs.assign(1u, 1u);
        return out;
    }
    std::vector<u8> c(static_cast<std::size_t>(n) + 2u, 0u);
    std::vector<u8> b(static_cast<std::size_t>(n) + 2u, 0u);
    c[0] = 1u;
    b[0] = 1u;
    u64 l = 0;
    u64 m = 1;
    for (u64 idx = 0; idx < n; ++idx) {
        u8 d = bits[static_cast<std::size_t>(idx)];
        for (u64 i = 1; i <= l; ++i) {
            if (c[static_cast<std::size_t>(i)] != 0u &&
                bits[static_cast<std::size_t>(idx - i)] != 0u) {
                d ^= 1u;
            }
        }
        if (d == 0u) {
            ++m;
            continue;
        }
        const std::vector<u8> t = c;  // pre-update copy
        for (u64 j = 0; j + m <= n + 1u; ++j) {
            if (b[static_cast<std::size_t>(j)] != 0u) {
                c[static_cast<std::size_t>(j + m)] ^= 1u;
            }
        }
        if (2u * l <= idx) {
            l = idx + 1u - l;
            b = t;
            m = 1;
        } else {
            ++m;
        }
    }
    out.length = l;
    out.coeffs.assign(static_cast<std::size_t>(l) + 1u, 0u);
    for (u64 i = 0; i <= l; ++i) {
        out.coeffs[static_cast<std::size_t>(i)] = c[static_cast<std::size_t>(i)];
    }
    return out;
}

// The documented packing: c_0..c_L as L+1 bits, MSB-first, zero-padded.
std::array<u8, 32> reference_poly_digest(const std::vector<u8>& coeffs) {
    std::vector<u8> packed((coeffs.size() + 7u) / 8u, 0u);
    for (std::size_t i = 0; i < coeffs.size(); ++i) {
        if (coeffs[i] != 0u) packed[i / 8u] |= static_cast<u8>(0x80u >> (i % 8u));
    }
    std::array<u8, 32> out{};
    const auto digest = mapr::Sha256::hash(std::string_view(
        reinterpret_cast<const char*>(packed.data()), packed.size()));
    if (digest.ok()) out = digest.value();
    return out;
}

// §4.8 Skew: direct bit counts.
u64 reference_ones_q24(std::span<const u8> bytes, u32 plane) {
    if (bytes.empty()) return 0u;
    u64 ones = 0;
    for (const u8 v : bytes) {
        if (((v >> plane) & 1u) != 0u) ++ones;
    }
    return static_cast<u64>((static_cast<u128>(ones) << 24u) / bytes.size());
}

// §4.8 AffineFit / QuadraticFit: exact predicates.
u64 reference_affine(std::span<const u8> bytes, u64& aux) {
    aux = 0;
    const u64 n = static_cast<u64>(bytes.size());
    if (n < 2u) return 0u;
    const u64 a = bytes[0];
    const u64 s = (static_cast<u64>(bytes[1]) + 256u - bytes[0]) & 0xFFu;
    for (u64 i = 0; i < n; ++i) {
        if (bytes[static_cast<std::size_t>(i)] != ((a + (i % 256u) * s) & 0xFFu)) return 0u;
    }
    aux = a | (s << 8);
    return 1u;
}

u64 reference_quadratic(std::span<const u8> bytes, u64& aux) {
    aux = 0;
    const u64 n = static_cast<u64>(bytes.size());
    if (n < 3u) return 0u;
    const u64 d2 = (((static_cast<u64>(bytes[2]) + 256u - bytes[1]) & 0xFFu) + 256u -
                    ((static_cast<u64>(bytes[1]) + 256u - bytes[0]) & 0xFFu)) &
                   0xFFu;
    for (u64 i = 0; i + 2u < n; ++i) {
        const u64 di = (static_cast<u64>(bytes[i + 1u]) + 256u - bytes[i]) & 0xFFu;
        const u64 dj = (static_cast<u64>(bytes[i + 2u]) + 256u - bytes[i + 1u]) & 0xFFu;
        if (((dj + 256u - di) & 0xFFu) != d2) return 0u;
    }
    aux = d2;
    return 1u;
}

// §4.8 Stride: H1 with the position class as context, per candidate.
u64 reference_stride_entropy(std::span<const u8> bytes, u64 stride) {
    const u64 n = static_cast<u64>(bytes.size());
    if (n == 0u || stride == 0u) return 0u;
    std::vector<u64> ctx(static_cast<std::size_t>(stride), 0u);
    std::unordered_map<u32, u64> joint;
    for (u64 i = 0; i < n; ++i) {
        const u64 cls = i % stride;
        ++ctx[static_cast<std::size_t>(cls)];
        ++joint[(static_cast<u32>(cls) << 8) | bytes[static_cast<std::size_t>(i)]];
    }
    u128 sum_ctx = 0;
    for (const u64 c : ctx) {
        if (c != 0u) sum_ctx += static_cast<u128>(c) * reference_ilog2_q24(c);
    }
    u128 sum_joint = 0;
    for (const auto& [k, c] : joint) {
        (void)k;
        sum_joint += static_cast<u128>(c) * reference_ilog2_q24(c);
    }
    if (sum_joint > sum_ctx) return 0u;
    return static_cast<u64>((sum_ctx - sum_joint) / n);
}

struct RefStride {
    bool reported = false;
    u64 h = 0;
    u64 stride = 0;
};

RefStride reference_stride(std::span<const u8> bytes, const std::vector<u64>& candidates) {
    RefStride out;
    std::array<u64, 256> counts{};
    for (const u8 v : bytes) ++counts[v];
    const u64 h0 = reference_h0_q24(std::span<const u64>(counts.data(), counts.size()));
    for (const u64 s : candidates) {
        const u64 h_s = reference_stride_entropy(bytes, s);
        const u64 improvement = h0 - h_s;
        if (improvement < kStrideMinImprovementQ24) continue;
        if (!out.reported || h_s < out.h) {
            out.reported = true;
            out.h = h_s;
            out.stride = s;
        }
    }
    return out;
}

// §4.5 change-point rule over a materialised span, grid anchored at 0.
std::vector<u64> reference_change_points(std::span<const u8> bytes) {
    const u64 length = static_cast<u64>(bytes.size());
    const u64 window = kChangeWindow;
    const u64 hop = kChangeHop;
    std::vector<u64> cand;
    if (length < 2u * window) return cand;
    const u64 cap = length / hop + 16u;
    for (u64 i = window; i + window <= length; i += hop) {
        std::array<u64, 256> lc{};
        std::array<u64, 256> rc{};
        u64 zeros_l = 0;
        u64 zeros_r = 0;
        for (u64 j = i - window; j < i; ++j) {
            const u8 v = bytes[static_cast<std::size_t>(j)];
            ++lc[v];
            if (v == 0u) ++zeros_l;
        }
        for (u64 j = i; j < i + window; ++j) {
            const u8 v = bytes[static_cast<std::size_t>(j)];
            ++rc[v];
            if (v == 0u) ++zeros_r;
        }
        const u64 hl = reference_h0_q24(std::span<const u64>(lc.data(), lc.size()));
        const u64 hr = reference_h0_q24(std::span<const u64>(rc.data(), rc.size()));
        const u64 zl = static_cast<u64>((static_cast<u128>(zeros_l) << 24u) / window);
        const u64 zr = static_cast<u64>((static_cast<u128>(zeros_r) << 24u) / window);
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

// §4.9 sample offsets: floor(j·(N - 65536) / 15).
std::array<u64, 16> reference_sample_offsets(u64 length) {
    std::array<u64, 16> out{};
    for (u64 j = 0; j < 16; ++j) {
        out[static_cast<std::size_t>(j)] = (j * (length - 65536u)) / 15u;
    }
    return out;
}

// ---------------------------------------------------------------------------
// Fixtures — every one a pure function of a pinned seed
// ---------------------------------------------------------------------------

struct Fixture {
    std::string name;
    std::string corpus;
    std::vector<u8> bytes;
    bool bm_reference = true;  // naive BM affordable for this fixture
};

std::vector<Fixture> build_fixtures() {
    std::vector<Fixture> out;
    auto add = [&](std::string name, std::string corpus, std::vector<u8> bytes,
                   bool bm_reference = true) {
        out.push_back(Fixture{std::move(name), std::move(corpus), std::move(bytes), bm_reference});
    };

    // C11-CORE
    add("empty", "C11-CORE", {});
    add("one-0x00", "C11-CORE", {0x00});
    add("one-0xff", "C11-CORE", {0xFF});
    add("two-bytes", "C11-CORE", {0x00, 0xFF});
    add("zeros-4096", "C11-CORE", zeros(4096));
    add("zeros-64KiB", "C11-CORE", zeros(65536), false);
    add("rand-512", "C11-CORE", splitmix_bytes(512, 0x4331110000000001ull));
    add("rand-4096", "C11-CORE", splitmix_bytes(4096, 0x4331110000000002ull));
    add("rand-8KiB", "C11-CORE", splitmix_bytes(8192, 0x4331110000000003ull));
    add("rand-64KiB", "C11-CORE", splitmix_bytes(65536, 0x4331110000000004ull), false);

    // C11-TILE — one fixture per stride in the fixed set, for stride coverage
    add("tile2-64", "C11-TILE",
        repeat_block(std::vector<u8>{0x12, 0x34}, 64));
    add("tile3-66", "C11-TILE",
        repeat_block(std::vector<u8>{0x11, 0x22, 0x33}, 66));
    add("tile4-64", "C11-TILE",
        repeat_block(std::vector<u8>{0x40, 0x43, 0x46, 0x49}, 64));
    add("tile8-128", "C11-TILE", repeat_block(splitmix_bytes(8, 0x5449000000000008ull), 128));
    add("tile16-256", "C11-TILE", repeat_block(splitmix_bytes(16, 0x5449000000000010ull), 256));
    add("tile32-256", "C11-TILE", repeat_block(splitmix_bytes(32, 0x5449000000000020ull), 256));
    add("tile64-512", "C11-TILE", repeat_block(splitmix_bytes(64, 0x5449000000000040ull), 512));
    add("tile256-4096", "C11-TILE",
        repeat_block(splitmix_bytes(256, 0x5449000000000100ull), 4096));
    add("tile256-64KiB", "C11-TILE",
        repeat_block(splitmix_bytes(256, 0x5449000000000100ull), 65536));
    add("tile4096-12288", "C11-TILE",
        repeat_block(splitmix_bytes(4096, 0x5449000000001000ull), 12288));

    // C11-PAT — fits, runs, skew planes
    {
        std::vector<u8> aff;
        for (u64 i = 0; i < 256; ++i) aff.push_back(static_cast<u8>((7 + 3u * i) & 0xFFu));
        add("affine-a7-s3", "C11-PAT", aff);
    }
    {
        std::vector<u8> counter;
        for (u64 i = 0; i < 1024; ++i) counter.push_back(static_cast<u8>(i & 0xFFu));
        add("affine-a0-s1", "C11-PAT", counter);
    }
    {
        std::vector<u8> aff;
        for (u64 i = 0; i < 128; ++i) aff.push_back(static_cast<u8>((255 + 255u * i) & 0xFFu));
        add("affine-a255-s255", "C11-PAT", aff);
    }
    {
        std::vector<u8> quad;
        for (u64 i = 0; i < 256; ++i) {
            quad.push_back(static_cast<u8>((i * (i - 1u) / 2u) & 0xFFu));
        }
        add("quad-d2-1", "C11-PAT", quad);
    }
    {
        std::vector<u8> quad;
        for (u64 i = 0; i < 256; ++i) {
            quad.push_back(static_cast<u8>((5 + 9u * i + 7u * (i * (i - 1u) / 2u)) & 0xFFu));
        }
        add("quad-d2-7", "C11-PAT", quad);
    }
    {
        std::vector<u8> runs;
        for (u64 run = 1; run <= 20; ++run) {
            for (u64 i = 0; i < run; ++i) runs.push_back(static_cast<u8>(run));
        }
        add("runs-ladder", "C11-PAT", runs);
    }
    add("runs-flat", "C11-PAT", std::vector<u8>(100, 0x5A));
    add("nibble-0F", "C11-PAT", std::vector<u8>(100, 0x0F));
    add("bitplane-55", "C11-PAT", std::vector<u8>(100, 0x55));
    {
        // Distinct per-plane densities: bit p set when (i % (p + 2)) == 0.
        std::vector<u8> mixed;
        for (u64 i = 0; i < 512; ++i) {
            u8 v = 0;
            for (u32 p = 0; p < 8; ++p) {
                if (i % (p + 2u) == 0u) v = static_cast<u8>(v | (1u << p));
            }
            mixed.push_back(v);
        }
        add("mixed-planes", "C11-PAT", mixed);
    }

    // C11-BM
    add("bm-single1", "C11-BM", {0x01});
    add("bm-alt", "C11-BM", std::vector<u8>(64, 0x55));
    {
        // Pinned 15-bit LFSR stream (taps 15, 14) packed one bit per byte in
        // the low bit of each entry, 128 steps.
        std::vector<u8> lfsr;
        std::uint16_t state = 0xACE1u;
        for (int i = 0; i < 128; ++i) {
            lfsr.push_back(static_cast<u8>(state & 1u));
            const std::uint16_t bit = static_cast<std::uint16_t>(((state >> 0) ^ (state >> 1)) & 1u);
            state = static_cast<std::uint16_t>((state >> 1) | (bit << 14));
        }
        add("bm-lfsr", "C11-BM", lfsr);
    }

    // C11-REP
    {
        std::vector<u8> rep = splitmix_bytes(64, 0x5245000000000001ull);
        for (u64 i = 0; i < 16; ++i) rep[32 + i] = rep[i];
        add("rep16-planted", "C11-REP", rep);
    }
    {
        std::vector<u8> rep = splitmix_bytes(1024, 0x5245000000000002ull);
        for (u64 plant = 0; plant < 8; ++plant) {
            const u64 src = static_cast<u64>(plant) * 64u;
            const u64 dst = 512u + static_cast<u64>(plant) * 64u;
            for (u64 i = 0; i < 16; ++i) rep[dst + i] = rep[src + i];
        }
        add("rep16-mix", "C11-REP", rep);
    }

    // C11-CHANGE
    {
        std::vector<u8> change = zeros(32768);
        const std::vector<u8> noise = splitmix_bytes(32768, 0x4348000000000001ull);
        change.insert(change.end(), noise.begin(), noise.end());
        add("chg-64k", "C11-CHANGE", change, false);
    }
    {
        std::vector<u8> change = zeros(16384);
        const std::vector<u8> noise = splitmix_bytes(16384, 0x4348000000000002ull);
        change.insert(change.end(), noise.begin(), noise.end());
        change.insert(change.end(), 16384, 0x00u);
        for (u64 i = 0; i < 16384; ++i) change.push_back(static_cast<u8>(i & 0xFFu));
        add("chg-multi", "C11-CHANGE", change, false);
    }

    // C11-SAMPLE — the §4.9 threshold and sample path
    add("sample-2MiB", "C11-SAMPLE",
        repeat_block(splitmix_bytes(256, 0x5449000000000100ull), 2u << 20), false);
    add("sample-big", "C11-SAMPLE",
        repeat_block(splitmix_bytes(256, 0x5449000000000100ull), (2u << 20) + 65536u), false);
    return out;
}

// ---------------------------------------------------------------------------
// File helpers
// ---------------------------------------------------------------------------

std::string sha256_file_hex(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return {};
    mapr::Sha256 ctx;
    std::array<char, 64u * 1024u> buffer{};
    while (in) {
        in.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        const std::streamsize got = in.gcount();
        if (got > 0) {
            if (ctx.update(std::string_view(buffer.data(), static_cast<std::size_t>(got))) !=
                mapr::ErrCode::Ok) {
                return {};
            }
        }
    }
    const auto digest = ctx.finish();
    if (!digest.ok()) return {};
    return digest_hex(digest.value());
}

bool write_tsv(const fs::path& path, std::vector<Row> rows) {
    std::stable_sort(rows.begin(), rows.end(), [](const Row& a, const Row& b) {
        if (a.check != b.check) return a.check < b.check;
        if (a.corpus != b.corpus) return a.corpus < b.corpus;
        return a.item_id < b.item_id;
    });

    std::error_code ec;
    fs::create_directories(path.parent_path(), ec);
    fs::path temp = path;
    temp += ".tmp";
    {
        std::ofstream out(temp, std::ios::trunc);
        if (!out) return false;
        out << "check\tcorpus\titem_id\tinput_sha256\texpected\tactual\tverdict\tlog\n";
        for (const Row& row : rows) {
            for (const std::string* f : {&row.check, &row.corpus, &row.item_id,
                                         &row.input_sha256, &row.expected, &row.actual,
                                         &row.verdict, &row.log}) {
                if (f->find('\t') != std::string::npos ||
                    f->find('\n') != std::string::npos ||
                    f->find('\r') != std::string::npos) {
                    return false;
                }
            }
            out << row.check << '\t' << row.corpus << '\t' << row.item_id << '\t'
                << row.input_sha256 << '\t' << row.expected << '\t' << row.actual << '\t'
                << row.verdict << '\t' << row.log << '\n';
        }
        out.flush();
        if (!out) return false;
    }
    fs::rename(temp, path, ec);
    if (ec) {
        fs::remove(temp, ec);
        return false;
    }
    return true;
}

int verify_manifest(const fs::path& manifest) {
    std::ifstream in(manifest);
    if (!in) return 1;
    fs::path root = manifest;
    for (int i = 0; i < 6; ++i) {
        root = root.parent_path();
        if (fs::exists(root / "include" / "mapr")) break;
    }
    std::string line;
    bool saw = false;
    while (std::getline(in, line)) {
        if (line.empty()) continue;
        const std::size_t sep = line.find("  ");
        if (sep == std::string::npos) return 1;
        const std::string want = line.substr(0, sep);
        const std::string rel = line.substr(sep + 2);
        const std::string got = sha256_file_hex(root / rel);
        if (got.empty() || got != want) {
            std::fprintf(stderr, "verify: mismatch for %s\n", rel.c_str());
            return 1;
        }
        saw = true;
    }
    return saw ? 0 : 1;
}

// ---------------------------------------------------------------------------
// Per-fixture observation comparison
// ---------------------------------------------------------------------------

const Observation* find_obs(const std::vector<Observation>& rows, ProbeKind kind, u32 param) {
    for (const Observation& obs : rows) {
        if (obs.kind == kind && obs.param == param) return &obs;
    }
    return nullptr;
}

int run_gate(const fs::path& repo_root, const fs::path& out_root) {
    Evidence ev;
    std::vector<std::string> log_lines;
    auto note = [&](const std::string& line) { log_lines.push_back(line); };

    const std::vector<Fixture> fixtures = build_fixtures();

    // =======================================================================
    // c11.constants — the §4.7–§4.10 constants, pinned
    // =======================================================================
    {
        const std::string sha = "pinned";
        ev.either(kProbeKindCount == 12u, "c11.constants.section47", "SPEC", "kind_count", sha,
                  "12", u64_dec(kProbeKindCount));
        bool names_ok = true;
        std::string got_names;
        for (u32 k = 0; k < kProbeKindCount; ++k) {
            if (probe_kind_ordinal(static_cast<ProbeKind>(k)) != k) names_ok = false;
            if (k != 0u) got_names += ',';
            got_names += probe_kind_name(static_cast<ProbeKind>(k));
        }
        ev.either(names_ok, "c11.constants.section47", "SPEC", "kind_ordinals", sha,
                  "0..11 in declaration order", got_names);
        ev.either(got_names == "H0,H1,H2,Runs,Period,Repeat16,Skew,BitComplexity,AffineFit,"
                               "QuadraticFit,Stride,ChangePoint",
                  "c11.constants.section47", "SPEC", "kind_names", sha,
                  "H0,H1,H2,Runs,Period,Repeat16,Skew,BitComplexity,AffineFit,QuadraticFit,"
                  "Stride,ChangePoint",
                  got_names);
        ev.either(kSampleThreshold == (2ull << 20), "c11.constants.section49", "SPEC",
                  "sample_threshold", sha, u64_dec(2ull << 20), u64_dec(kSampleThreshold));
        ev.either(kSampleWindowBytes == 65536u, "c11.constants.section49", "SPEC",
                  "sample_window", sha, "65536", u64_dec(kSampleWindowBytes));
        ev.either(kSampleWindowCount == 16u, "c11.constants.section49", "SPEC",
                  "sample_windows", sha, "16", u64_dec(kSampleWindowCount));
        ev.either(kRepeat16Window == 16u, "c11.constants.section48", "SPEC", "repeat16_window",
                  sha, "16", u64_dec(kRepeat16Window));
        ev.either(kStrideMinImprovementQ24 == (1ull << 23), "c11.constants.section48", "SPEC",
                  "stride_threshold", sha, u64_dec(1ull << 23),
                  u64_dec(kStrideMinImprovementQ24));
        ev.either(kChangeWindow == 4096u && kChangeHop == 2048u, "c11.constants.section45",
                  "SPEC", "change_window_hop", sha, "4096;2048",
                  u64_dec(kChangeWindow) + ";" + u64_dec(kChangeHop));
        ev.either(kMaxProbeBytes == (1ull << 32) && kMaxProbeObservations == (1ull << 20),
                  "c11.constants.limits", "SPEC", "caps", sha, "2^32;2^20",
                  u64_dec(kMaxProbeBytes) + ";" + u64_dec(kMaxProbeObservations));
        std::string stride_text;
        for (const u64 s : kStrideSet) {
            if (!stride_text.empty()) stride_text += ',';
            stride_text += std::to_string(s);
        }
        ev.either(stride_text == "2,3,4,8,16,32,64,256,4096", "c11.constants.section48", "SPEC",
                  "stride_set", sha, "2,3,4,8,16,32,64,256,4096", stride_text);
        std::string reduced_text;
        for (const u64 s : kStrideSetReduced) {
            if (!reduced_text.empty()) reduced_text += ',';
            reduced_text += std::to_string(s);
        }
        ev.either(reduced_text == "2,4,8", "c11.constants.section410", "SPEC",
                  "stride_set_reduced", sha, "2,4,8", reduced_text);
        for (const u8 effort : {u8{0}, u8{2}, u8{3}, u8{5}, u8{9}}) {
            const auto planes = bit_complexity_planes(effort);
            const auto set = stride_set_for_effort(effort);
            const u32 want_planes = effort <= 2u ? 2u : 8u;
            const u32 want_count = effort <= 2u ? 3u : 9u;
            ev.either(planes.ok() && planes.value() == want_planes &&
                          set.ok() && set.value().count == want_count,
                      "c11.constants.section410", "SPEC",
                      "effort" + std::to_string(effort), sha,
                      "bm_planes=" + u64_dec(want_planes) + ";strides=" + u64_dec(want_count),
                      "bm_planes=" + u64_dec(planes.ok() ? planes.value() : 0) +
                          ";strides=" + u64_dec(set.ok() ? set.value().count : 0));
        }
    }

    // =======================================================================
    // c11.fixed — ilog2 and entropy KATs
    // =======================================================================
    {
        const std::string sha = "pinned";
        const std::array<u64, 14> kats = {1,   2,   3,   4,   7,   8,    255,
                                          256, 257, 1023, 1024, 1025, 1ull << 20,
                                          0xFFFFFFFFull};
        for (const u64 x : kats) {
            const u64 ref = reference_ilog2_q24(x);
            const u64 got = ilog2_q24(x);
            ev.either(ref == got, "c11.fixed.ilog2.kat", "KAT", "x=" + u64_dec(x), sha,
                      u64_dec(ref), u64_dec(got));
        }
        ev.either(ilog2_q24(0) == 0u, "c11.fixed.ilog2.kat", "KAT", "x=0", sha, "0",
                  u64_dec(ilog2_q24(0)));
        for (u32 e = 0; e <= 62; ++e) {
            const u64 x = 1ull << e;
            ev.either(ilog2_q24(x) == (static_cast<u64>(e) << 24), "c11.fixed.ilog2.kat", "KAT",
                      "x=2^" + u64_dec(e), sha, u64_dec(static_cast<u64>(e) << 24),
                      u64_dec(ilog2_q24(x)));
        }
        u64 probe_seed = 0x494c4f47324b4154ull;
        for (u32 round = 0; round < 200; ++round) {
            probe_seed += 0x9E3779B97F4A7C15ull;
            u64 z = probe_seed;
            z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
            z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
            z = z ^ (z >> 31);
            ev.either(reference_ilog2_q24(z) == ilog2_q24(z), "c11.fixed.ilog2.reference", "KAT",
                      "rnd" + u64_dec(round), sha, u64_dec(reference_ilog2_q24(z)),
                      u64_dec(ilog2_q24(z)));
        }
        // Entropy KATs with hand-computed values.
        std::array<u64, 256> counts{};
        counts[0] = 1;
        counts[255] = 1;
        ev.either(h0_q24_from_counts(std::span<const u64, 256>(counts)) == (1ull << 24),
                  "c11.fixed.entropy.kat", "KAT", "h0_pair", sha, u64_dec(1ull << 24),
                  u64_dec(h0_q24_from_counts(std::span<const u64, 256>(counts))));
        counts.fill(0);
        counts[7] = 9;
        ev.either(h0_q24_from_counts(std::span<const u64, 256>(counts)) == 0u,
                  "c11.fixed.entropy.kat", "KAT", "h0_single", sha, "0",
                  u64_dec(h0_q24_from_counts(std::span<const u64, 256>(counts))));
        counts.fill(1);
        ev.either(h0_q24_from_counts(std::span<const u64, 256>(counts)) == (8ull << 24),
                  "c11.fixed.entropy.kat", "KAT", "h0_uniform256", sha,
                  u64_dec(8ull << 24),
                  u64_dec(h0_q24_from_counts(std::span<const u64, 256>(counts))));
        u64 rng = 0x454e54524f505921ull;
        for (u32 round = 0; round < 100; ++round) {
            std::array<u64, 256> c{};
            for (u32 i = 0; i < 256; ++i) {
                rng += 0x9E3779B97F4A7C15ull;
                u64 z = rng;
                z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
                z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
                z = z ^ (z >> 31);
                c[i] = (z >> 3) & 0x3FFu;
            }
            const u64 ref = reference_h0_q24(std::span<const u64>(c.data(), c.size()));
            const u64 got = h0_q24_from_counts(std::span<const u64, 256>(c));
            ev.either(ref == got, "c11.fixed.h0.reference", "KAT", "vec" + u64_dec(round), sha,
                      u64_dec(ref), u64_dec(got));
        }
    }

    // =======================================================================
    // c11.probe.* — every observation against the independent references
    // =======================================================================
    for (const Fixture& fx : fixtures) {
        const std::string sha = hex_digest_of_bytes(fx.bytes);
        const std::span<const u8> bytes(fx.bytes.data(), fx.bytes.size());
        SpanSource src(fx.bytes);
        const Segment seg{BigInt(0), BigInt(fx.bytes.size()), 0, 0};
        Policy pol;
        const auto rows_r = probe(src, seg, pol);
        if (!rows_r.ok()) {
            ev.fail("c11.probe.run", fx.corpus, fx.name, sha, "Ok",
                    std::string(measure_code_name(rows_r.code())));
            continue;
        }
        const std::vector<Observation>& rows = rows_r.value();
        note("[c11.probe:" + fx.name + "] rows=" + u64_dec(rows.size()) +
             " sha256=" + sha);
        // End-to-end probe() contract (§5.3): every row carries the requested
        // `where`, and the row order is (kind ordinal, param, aux).
        {
            bool where_ok = true;
            bool order_ok = true;
            for (size_t i = 0; i < rows.size(); ++i) {
                if (rows[i].where != seg) where_ok = false;
                if (i > 0) {
                    const auto k_a = std::make_tuple(static_cast<int>(rows[i - 1].kind),
                                                     rows[i - 1].param, rows[i - 1].aux);
                    const auto k_b = std::make_tuple(static_cast<int>(rows[i].kind),
                                                     rows[i].param, rows[i].aux);
                    if (k_a > k_b) order_ok = false;
                }
            }
            ev.either(where_ok && order_ok, "c11.probe.run", fx.corpus, fx.name, sha,
                      "where=segment;order=kind,param,aux",
                      std::string("where=") + (where_ok ? "1" : "0") +
                          ";order=" + (order_ok ? "1" : "0"));
        }
        for (const Observation& o : rows) {
            note("[c11.obs:" + fx.name + "] " + observation_text(o));
        }

        // H0 / H1 / H2 / Runs.
        if (const Observation* o = find_obs(rows, ProbeKind::H0, 0)) {
            std::array<u64, 256> counts{};
            for (const u8 v : bytes) ++counts[v];
            const u64 ref = reference_h0_q24(std::span<const u64>(counts.data(), counts.size()));
            ev.either(o->value == ref && o->aux == fx.bytes.size(),
                      "c11.probe.h0.reference", fx.corpus, fx.name, sha,
                      "v=" + u64_dec(ref) + ";a=" + u64_dec(fx.bytes.size()),
                      "v=" + u64_dec(o->value) + ";a=" + u64_dec(o->aux));
        } else {
            ev.fail("c11.probe.h0.reference", fx.corpus, fx.name, sha, "row present", "absent");
        }
        if (const Observation* o = find_obs(rows, ProbeKind::H1, 0)) {
            const u64 ref = reference_h1_q24(bytes);
            const u64 want_aux = fx.bytes.size() >= 2u ? fx.bytes.size() - 1u : 0u;
            ev.either(o->value == ref && o->aux == want_aux, "c11.probe.h1.reference", fx.corpus,
                      fx.name, sha, "v=" + u64_dec(ref) + ";a=" + u64_dec(want_aux),
                      "v=" + u64_dec(o->value) + ";a=" + u64_dec(o->aux));
        } else {
            ev.fail("c11.probe.h1.reference", fx.corpus, fx.name, sha, "row present", "absent");
        }
        if (const Observation* o = find_obs(rows, ProbeKind::H2, 0)) {
            const bool sampled = fx.bytes.size() > kSampleThreshold;
            std::string want = "exact";
            std::string got = o->sampled ? "sampled" : "exact";
            bool ok = (o->sampled == sampled) && (o->sample_count == (sampled ? 16u : 0u));
            if (!sampled) {
                const u64 ref = reference_h2_q24(bytes);
                const u64 want_aux = fx.bytes.size() >= 3u ? fx.bytes.size() - 2u : 0u;
                ok = ok && o->value == ref && o->aux == want_aux;
                want += ";v=" + u64_dec(ref) + ";a=" + u64_dec(want_aux);
            } else {
                std::unordered_map<u32, u64> agg;
                for (const u64 off : reference_sample_offsets(fx.bytes.size())) {
                    for (std::size_t i = 2; i < kSampleWindowBytes; ++i) {
                        const u8* w = fx.bytes.data() + off;
                        ++agg[(static_cast<u32>(w[i - 2u]) << 16) |
                              (static_cast<u32>(w[i - 1u]) << 8) | w[i]];
                    }
                }
                const u64 ref = reference_h2_q24_from(agg);
                const u64 want_aux = 16ull * 65534ull;
                ok = ok && o->value == ref && o->aux == want_aux;
                want = "sampled;v=" + u64_dec(ref) + ";a=" + u64_dec(want_aux);
            }
            ev.either(ok, "c11.probe.h2.reference", fx.corpus, fx.name, sha, want,
                      got + ";v=" + u64_dec(o->value) + ";a=" + u64_dec(o->aux) +
                          ";sc=" + u64_dec(o->sample_count));
        } else {
            ev.fail("c11.probe.h2.reference", fx.corpus, fx.name, sha, "row present", "absent");
        }
        if (const Observation* o = find_obs(rows, ProbeKind::Runs, 0)) {
            const u64 ref_count = reference_run_count(bytes);
            const u64 ref_max = reference_max_run(bytes);
            ev.either(o->value == ref_count && o->aux == ref_max, "c11.probe.runs.reference",
                      fx.corpus, fx.name, sha,
                      "v=" + u64_dec(ref_count) + ";a=" + u64_dec(ref_max),
                      "v=" + u64_dec(o->value) + ";a=" + u64_dec(o->aux));
        } else {
            ev.fail("c11.probe.runs.reference", fx.corpus, fx.name, sha, "row present", "absent");
        }

        // Period: value, verification, and minimality against the definition.
        if (const Observation* o = find_obs(rows, ProbeKind::Period, 0)) {
            const u64 ref = reference_minimal_period(bytes);
            const std::optional<u64> p = o->period.to_u64_checked();
            const bool holds = p.has_value() && reference_period_holds(bytes, *p);
            const bool minimal =
                p.has_value() && (*p == 0u || *p == 1u || !reference_period_holds(bytes, *p - 1u));
            ev.either(p.has_value() && *p == ref && o->verified && o->value == 0u && o->aux == 0u,
                      "c11.probe.period.reference", fx.corpus, fx.name, sha,
                      "p=" + u64_dec(ref) + ";verified=1",
                      "p=" + (p.has_value() ? u64_dec(*p) : std::string("?")) +
                          ";verified=" + (o->verified ? "1" : "0"));
            ev.either(holds, "c11.probe.period.fullcheck", fx.corpus, fx.name, sha,
                      "b[i]==b[i-p] for all i>=p",
                      holds ? "holds" : "violated");
            ev.either(minimal, "c11.probe.period.minimality", fx.corpus, fx.name, sha,
                      "p-1 fails (or p<=1)", minimal ? "minimal" : "not minimal");
            auto vr = verify_period(src, *o);
            ev.either(vr.ok() && vr.value(), "c11.probe.period.verify_api", fx.corpus, fx.name,
                      sha, "Ok(true)", vr.ok() ? (vr.value() ? "Ok(true)" : "Ok(false)")
                                               : std::string(measure_code_name(vr.code())));
        } else {
            ev.fail("c11.probe.period.reference", fx.corpus, fx.name, sha, "row present",
                    "absent");
        }

        // Repeat16.
        if (const Observation* o = find_obs(rows, ProbeKind::Repeat16, kRepeat16Window)) {
            const bool sampled = fx.bytes.size() > kSampleThreshold;
            u64 ref_matches = 0;
            u64 ref_positions = 0;
            if (!sampled) {
                ref_matches = reference_repeat16_matches(bytes, ref_positions);
            } else {
                for (const u64 off : reference_sample_offsets(fx.bytes.size())) {
                    u64 win_positions = 0;
                    ref_matches += reference_repeat16_matches(
                        bytes.subspan(static_cast<std::size_t>(off),
                                      static_cast<std::size_t>(kSampleWindowBytes)),
                        win_positions);
                    ref_positions += win_positions;
                }
            }
            const u64 ref_density =
                ref_positions == 0u ? 0u
                                    : static_cast<u64>((static_cast<u128>(ref_matches) << 24u) /
                                                       ref_positions);
            ev.either(o->aux == ref_matches && o->value == ref_density &&
                          o->sampled == sampled && o->sample_count == (sampled ? 16u : 0u),
                      "c11.probe.repeat16.reference", fx.corpus, fx.name, sha,
                      "m=" + u64_dec(ref_matches) + ";d=" + u64_dec(ref_density) +
                          ";sam=" + (sampled ? "1" : "0"),
                      "m=" + u64_dec(o->aux) + ";d=" + u64_dec(o->value) +
                          ";sam=" + (o->sampled ? "1" : "0"));
        } else {
            ev.fail("c11.probe.repeat16.reference", fx.corpus, fx.name, sha, "row present",
                    "absent");
        }

        // Skew planes.
        for (u32 plane = 0; plane < kBitPlanes; ++plane) {
            if (const Observation* o = find_obs(rows, ProbeKind::Skew, plane)) {
                const u64 ref = reference_ones_q24(bytes, plane);
                ev.either(o->value == ref && o->aux == fx.bytes.size(),
                          "c11.probe.skew.reference", fx.corpus,
                          fx.name + "@plane" + u64_dec(plane), sha,
                          "v=" + u64_dec(ref) + ";a=" + u64_dec(fx.bytes.size()),
                          "v=" + u64_dec(o->value) + ";a=" + u64_dec(o->aux));
            } else {
                ev.fail("c11.probe.skew.reference", fx.corpus,
                        fx.name + "@plane" + u64_dec(plane), sha, "row present", "absent");
            }
        }

        // BitComplexity planes (naive reference only where affordable).
        for (u32 plane = 0; plane < kBitPlanes; ++plane) {
            const Observation* o = find_obs(rows, ProbeKind::BitComplexity, plane);
            if (o == nullptr) {
                ev.fail("c11.probe.bitcomplexity.reference", fx.corpus,
                        fx.name + "@plane" + u64_dec(plane), sha, "row present", "absent");
                continue;
            }
            if (!fx.bm_reference) continue;  // covered by reproducibility instead
            std::vector<u8> bits(fx.bytes.size(), 0u);
            for (std::size_t i = 0; i < fx.bytes.size(); ++i) {
                bits[i] = static_cast<u8>((fx.bytes[i] >> plane) & 1u);
            }
            const RefBm ref = reference_bm(bits);
            const std::array<u8, 32> ref_digest = reference_poly_digest(ref.coeffs);
            ev.either(o->value == ref.length && same_digest(o->digest, ref_digest),
                      "c11.probe.bitcomplexity.reference", fx.corpus,
                      fx.name + "@plane" + u64_dec(plane), sha,
                      "L=" + u64_dec(ref.length) + ";d=" + digest_hex(ref_digest),
                      "L=" + u64_dec(o->value) + ";d=" + digest_hex(o->digest));
        }

        // AffineFit / QuadraticFit.
        if (const Observation* o = find_obs(rows, ProbeKind::AffineFit, 0)) {
            u64 ref_aux = 0;
            const u64 ref = reference_affine(bytes, ref_aux);
            ev.either(o->value == ref && o->aux == ref_aux, "c11.probe.affine.reference",
                      fx.corpus, fx.name, sha,
                      "v=" + u64_dec(ref) + ";a=" + u64_dec(ref_aux),
                      "v=" + u64_dec(o->value) + ";a=" + u64_dec(o->aux));
        } else {
            ev.fail("c11.probe.affine.reference", fx.corpus, fx.name, sha, "row present",
                    "absent");
        }
        if (const Observation* o = find_obs(rows, ProbeKind::QuadraticFit, 0)) {
            u64 ref_aux = 0;
            const u64 ref = reference_quadratic(bytes, ref_aux);
            ev.either(o->value == ref && o->aux == ref_aux, "c11.probe.quadratic.reference",
                      fx.corpus, fx.name, sha,
                      "v=" + u64_dec(ref) + ";a=" + u64_dec(ref_aux),
                      "v=" + u64_dec(o->value) + ";a=" + u64_dec(o->aux));
        } else {
            ev.fail("c11.probe.quadratic.reference", fx.corpus, fx.name, sha, "row present",
                    "absent");
        }

        // Stride.
        {
            std::vector<u64> candidates;
            for (const u64 s : kStrideSet) candidates.push_back(s);
            const RefStride ref = reference_stride(bytes, candidates);
            const Observation* o = nullptr;
            for (const Observation& row : rows) {
                if (row.kind == ProbeKind::Stride) o = &row;
            }
            if (ref.reported) {
                if (o != nullptr) {
                    ev.either(o->aux == ref.stride && o->value == ref.h &&
                                  o->param == static_cast<u32>(ref.stride),
                              "c11.probe.stride.reference", fx.corpus, fx.name, sha,
                              "reported;s=" + u64_dec(ref.stride) + ";h=" + u64_dec(ref.h),
                              "reported;s=" + u64_dec(o->aux) + ";h=" + u64_dec(o->value));
                } else {
                    ev.fail("c11.probe.stride.reference", fx.corpus, fx.name, sha,
                            "reported;s=" + u64_dec(ref.stride), "absent");
                }
            } else {
                ev.either(o == nullptr, "c11.probe.stride.reference", fx.corpus, fx.name, sha,
                          "absent", o != nullptr ? "reported;s=" + u64_dec(o->aux) : "absent");
            }
        }

        // ChangePoint list.
        {
            std::vector<u64> got;
            for (const Observation& row : rows) {
                if (row.kind == ProbeKind::ChangePoint) got.push_back(row.aux);
            }
            const std::vector<u64> ref = reference_change_points(bytes);
            const bool ordered = std::is_sorted(got.begin(), got.end());
            ev.either(got == ref && ordered, "c11.probe.changepoint.reference", fx.corpus,
                      fx.name, sha, "n=" + u64_dec(ref.size()) + ";[" + list_text(ref) + "]",
                      "n=" + u64_dec(got.size()) + ";[" + list_text(got) + "]");
        }

        // Field discipline on every row (§4.7, §9).
        {
            bool all_ok = true;
            for (const Observation& row : rows) {
                if (!validate_observation(row, static_cast<u64>(fx.bytes.size())).ok()) {
                    all_ok = false;
                }
            }
            ev.either(all_ok, "c11.fields.discipline", fx.corpus, fx.name, sha,
                      "every row validates (§4.7)",
                      all_ok ? "all rows valid" : "invalid row present");
        }

        // Reproducibility: re-run on the recorded `where` (O8.5).
        {
            SpanSource src2(fx.bytes);
            const auto again = probe(src2, seg, pol);
            bool same = again.ok() && again.value().size() == rows.size();
            if (same) {
                for (std::size_t i = 0; i < rows.size(); ++i) {
                    if (observation_text(rows[i]) != observation_text(again.value()[i])) {
                        same = false;
                    }
                }
            }
            std::string digest_a;
            std::string digest_b;
            for (const Observation& row : rows) digest_a += observation_text(row) + "\n";
            if (again.ok()) {
                for (const Observation& row : again.value()) digest_b += observation_text(row) + "\n";
            }
            ev.either(same, "c11.reproducibility.rerun", fx.corpus, fx.name, sha,
                      "sha256=" + sha256_text_hex(digest_a),
                      "sha256=" + sha256_text_hex(digest_b));
        }
    }

    // =======================================================================
    // c11.sampling — the §4.9 threshold and window offsets
    // =======================================================================
    for (const Fixture& fx : fixtures) {
        if (fx.corpus != "C11-SAMPLE") continue;
        const std::string sha = hex_digest_of_bytes(fx.bytes);
        const bool sampled = fx.bytes.size() > kSampleThreshold;
        const std::string want = sampled ? "sampled=1;sc=16" : "sampled=0;sc=0";
        SpanSource src(fx.bytes);
        const Segment seg{BigInt(0), BigInt(fx.bytes.size()), 0, 0};
        const auto rows = probe(src, seg, Policy{});
        if (!rows.ok()) {
            ev.fail("c11.sampling.path", fx.corpus, fx.name, sha, want, "probe failed");
            continue;
        }
        std::string got_h2;
        std::string got_r16;
        for (const Observation& o : rows.value()) {
            if (o.kind == ProbeKind::H2) {
                got_h2 = std::string("sampled=") + (o.sampled ? "1" : "0") +
                         ";sc=" + u64_dec(o.sample_count);
            }
            if (o.kind == ProbeKind::Repeat16) {
                got_r16 = std::string("sampled=") + (o.sampled ? "1" : "0") +
                          ";sc=" + u64_dec(o.sample_count);
            }
        }
        ev.either(got_h2 == want, "c11.sampling.path", fx.corpus, fx.name + "#H2", sha, want,
                  got_h2);
        ev.either(got_r16 == want, "c11.sampling.path", fx.corpus, fx.name + "#Repeat16", sha,
                  want, got_r16);
        if (sampled) {
            const auto offsets = sample_window_offsets(fx.bytes.size());
            const std::array<u64, 16> ref = reference_sample_offsets(fx.bytes.size());
            if (!offsets.ok()) {
                ev.fail("c11.sampling.offsets", fx.corpus, fx.name, sha, "16 offsets",
                        "Invalid");
            } else {
                for (u64 j = 0; j < 16; ++j) {
                    const u64 got = offsets.value()[static_cast<std::size_t>(j)];
                    const bool inside = got + kSampleWindowBytes <= fx.bytes.size();
                    ev.either(got == ref[static_cast<std::size_t>(j)] && inside,
                              "c11.sampling.offsets", fx.corpus,
                              fx.name + "#w" + u64_dec(j), sha,
                              u64_dec(ref[static_cast<std::size_t>(j)]) + ";inside",
                              u64_dec(got) + (inside ? ";inside" : ";outside"));
                }
            }
        } else {
            ev.either(!sample_window_offsets(fx.bytes.size()).ok(), "c11.sampling.threshold",
                      fx.corpus, fx.name, sha, "offsets Invalid at or below threshold",
                      "checked");
        }
    }

    // =======================================================================
    // c11.effort — budget selects existence, never values
    // =======================================================================
    {
        const Fixture* fx = nullptr;
        for (const Fixture& f : fixtures) {
            if (f.name == "rand-4096") fx = &f;
        }
        if (fx != nullptr) {
            const std::string sha = hex_digest_of_bytes(fx->bytes);
            SpanSource src(fx->bytes);
            const Segment seg{BigInt(0), BigInt(fx->bytes.size()), 0, 0};
            std::map<std::string, std::string> by_effort[10];
            for (const u8 effort : {u8{0}, u8{2}, u8{3}, u8{5}, u8{9}}) {
                Policy pol;
                pol.effort = effort;
                const auto rows = probe(src, seg, pol);
                if (!rows.ok()) {
                    ev.fail("c11.effort.budget", "C11-EFFORT",
                            "effort" + std::to_string(effort), sha, "Ok", "error");
                    continue;
                }
                const bool full = effort >= 3u;
                u32 bm_count = 0;
                bool has_h2 = false;
                bool has_r16 = false;
                bool stride_in_set = true;
                for (const Observation& o : rows.value()) {
                    if (o.kind == ProbeKind::H2) has_h2 = true;
                    if (o.kind == ProbeKind::Repeat16) has_r16 = true;
                    if (o.kind == ProbeKind::BitComplexity) ++bm_count;
                    if (o.kind == ProbeKind::Stride) {
                        bool member = false;
                        for (const u64 s : kStrideSet) {
                            if (s == o.aux) member = true;
                        }
                        if (!full) {
                            bool reduced = false;
                            for (const u64 s : kStrideSetReduced) {
                                if (s == o.aux) reduced = true;
                            }
                            member = member && reduced;
                        }
                        if (!member) stride_in_set = false;
                    }
                    const std::string key =
                        std::string(probe_kind_name(o.kind)) + ":" + std::to_string(o.param);
                    by_effort[effort][key] = observation_text(o);
                }
                ev.either(has_h2 == full && has_r16 == full && bm_count == (full ? 8u : 2u) &&
                              stride_in_set,
                          "c11.effort.budget", "C11-EFFORT",
                          "effort" + std::to_string(effort), sha,
                          std::string("h2=") + (full ? "1" : "0") +
                              ";r16=" + (full ? "1" : "0") +
                              ";bm=" + u64_dec(full ? 8u : 2u) + ";stride-in-set=1",
                          std::string("h2=") + (has_h2 ? "1" : "0") + ";r16=" +
                              (has_r16 ? "1" : "0") + ";bm=" + u64_dec(bm_count) +
                              ";stride-in-set=" + (stride_in_set ? "1" : "0"));
                // Shared rows agree across efforts (budget never changes a value).
                bool agree = true;
                std::string divergent;
                for (const u8 other : {u8{0}, u8{2}, u8{3}, u8{5}, u8{9}}) {
                    if (other == effort) continue;
                    for (const auto& [key, text] : by_effort[effort]) {
                        const auto it = by_effort[other].find(key);
                        if (it == by_effort[other].end()) continue;
                        if (it->second != text) {
                            agree = false;
                            divergent = key;
                        }
                    }
                }
                ev.either(agree, "c11.effort.values", "C11-EFFORT",
                          "effort" + std::to_string(effort), sha, "shared rows identical",
                          agree ? "identical" : "divergent:" + divergent);
            }
        }
    }

    // =======================================================================
    // c11.locality — bytes outside `where` cannot reach an observation (E4-I2)
    // =======================================================================
    {
        u32 mutation = 0;
        for (const Fixture& fx : fixtures) {
            if (fx.name != "rand-4096" && fx.name != "tile256-4096" && fx.name != "runs-ladder" &&
                fx.name != "affine-a7-s3" && fx.name != "chg-64k" && fx.name != "quad-d2-1") {
                continue;
            }
            // source = pad(37) ++ fixture ++ pad(53); `where` covers the fixture only.
            std::vector<u8> source;
            const std::vector<u8> pad_a = splitmix_bytes(37, 0x4c4f43414c000000ull + mutation);
            const std::vector<u8> pad_b = splitmix_bytes(53, 0x4c4f43414c0000ffull + mutation);
            source.insert(source.end(), pad_a.begin(), pad_a.end());
            const std::size_t begin = source.size();
            source.insert(source.end(), fx.bytes.begin(), fx.bytes.end());
            const std::size_t end = source.size();
            source.insert(source.end(), pad_b.begin(), pad_b.end());

            SpanSource src(source);
            const Segment seg{BigInt(begin), BigInt(end), 0, 0};
            const auto before = probe(src, seg, Policy{});
            if (!before.ok()) {
                ev.fail("c11.locality.mutation", fx.corpus, fx.name, "na", "Ok", "error");
                continue;
            }
            std::string digest_before;
            for (const Observation& o : before.value()) digest_before += observation_text(o) + "\n";

            // Mutate one byte outside `where` (in the leading pad), re-probe.
            for (u32 round = 0; round < 2; ++round) {
                std::vector<u8> mutated = source;
                const std::size_t at = round == 0u ? (pad_a.size() / 2u) : (end + pad_b.size() / 2u);
                mutated[at] = static_cast<u8>(mutated[at] ^ 0xFFu);
                SpanSource src2(mutated);
                const auto after = probe(src2, seg, Policy{});
                std::string digest_after;
                bool ok = after.ok();
                if (ok) {
                    for (const Observation& o : after.value()) {
                        digest_after += observation_text(o) + "\n";
                    }
                    ok = digest_after == digest_before;
                }
                ev.either(ok, "c11.locality.mutation", fx.corpus,
                          fx.name + "#m" + u64_dec(mutation), hex_digest_of_bytes(fx.bytes),
                          "sha256=" + sha256_text_hex(digest_before),
                          "sha256=" + sha256_text_hex(digest_after));
                ++mutation;
            }
        }
    }

    // =======================================================================
    // c11.merge — §5.4 order is canonical (begin, ordinal, param)
    // =======================================================================
    {
        const Fixture* fx = nullptr;
        for (const Fixture& f : fixtures) {
            if (f.name == "chg-64k") fx = &f;
        }
        if (fx != nullptr) {
            const std::string sha = hex_digest_of_bytes(fx->bytes);
            SpanSource src(fx->bytes);
            // Four 16 KiB sub-segments, probed independently.
            std::vector<std::vector<Observation>> parts;
            bool ok = true;
            for (u32 part = 0; part < 4u; ++part) {
                const Segment seg{BigInt(part * 16384u), BigInt((part + 1u) * 16384u), part, 0};
                const auto rows = probe(src, seg, Policy{});
                if (!rows.ok()) {
                    ok = false;
                    break;
                }
                parts.push_back(rows.value());
            }
            std::vector<Observation> serial;
            for (const auto& part : parts) {
                serial.insert(serial.end(), part.begin(), part.end());
            }
            std::vector<Observation> shuffled;
            for (std::size_t i = parts.size(); i-- > 0;) {
                shuffled.insert(shuffled.end(), parts[i].begin(), parts[i].end());
            }
            std::reverse(shuffled.begin(), shuffled.end());
            merge_observations(shuffled);
            std::string text_serial;
            std::string text_merged;
            for (const Observation& o : serial) text_serial += observation_text(o) + "\n";
            for (const Observation& o : shuffled) text_merged += observation_text(o) + "\n";
            ev.either(ok && text_serial == text_merged, "c11.merge.order", "C11-MERGE",
                      "chg-64k#4x16KiB", sha, "sha256=" + sha256_text_hex(text_serial),
                      "sha256=" + sha256_text_hex(text_merged));

            // The merged list is sorted by (begin, ordinal, param).
            bool sorted_ok = true;
            for (std::size_t i = 1; i < shuffled.size(); ++i) {
                const Observation& a = shuffled[i - 1u];
                const Observation& b = shuffled[i];
                const bool in_order =
                    (a.where.begin < b.where.begin) ||
                    (a.where.begin == b.where.begin &&
                     (probe_kind_ordinal(a.kind) < probe_kind_ordinal(b.kind) ||
                      (probe_kind_ordinal(a.kind) == probe_kind_ordinal(b.kind) &&
                       a.param <= b.param)));
                if (!in_order) sorted_ok = false;
            }
            ev.either(sorted_ok, "c11.merge.order", "C11-MERGE", "chg-64k#sorted", sha,
                      "sorted by (begin, ordinal, param)",
                      sorted_ok ? "sorted" : "unsorted");
        }
    }

    // =======================================================================
    // c11.verify_period — the §5.3 API contract
    // =======================================================================
    {
        const std::vector<u8> tile = {1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4};
        SpanSource src(tile);
        Observation obs;
        obs.where = Segment{BigInt(0), BigInt(12), 0, 0};
        obs.kind = ProbeKind::Period;
        obs.period = BigInt(4);
        obs.verified = true;
        auto r = verify_period(src, obs);
        ev.either(r.ok() && r.value(), "c11.verify_period.api", "C11-API", "true-claim", "na",
                  "Ok(true)", r.ok() ? (r.value() ? "Ok(true)" : "Ok(false)")
                                     : std::string(measure_code_name(r.code())));
        obs.period = BigInt(3);
        r = verify_period(src, obs);
        ev.either(r.ok() && !r.value(), "c11.verify_period.api", "C11-API", "false-claim", "na",
                  "Ok(false)", r.ok() ? (r.value() ? "Ok(true)" : "Ok(false)")
                                      : std::string(measure_code_name(r.code())));
        obs.period = BigInt(4);
        obs.verified = false;
        r = verify_period(src, obs);
        ev.either(!r.ok() && r.code() == MeasureCode::Invalid, "c11.verify_period.api", "C11-API",
                  "unverified-claim", "na", "Invalid",
                  r.ok() ? "Ok" : std::string(measure_code_name(r.code())));
        obs.verified = true;
        obs.kind = ProbeKind::H0;
        r = verify_period(src, obs);
        ev.either(!r.ok() && r.code() == MeasureCode::Invalid, "c11.verify_period.api", "C11-API",
                  "wrong-kind", "na", "Invalid",
                  r.ok() ? "Ok" : std::string(measure_code_name(r.code())));
        obs.kind = ProbeKind::Period;
        obs.period = BigInt(13);
        r = verify_period(src, obs);
        ev.either(!r.ok() && r.code() == MeasureCode::Invalid, "c11.verify_period.api", "C11-API",
                  "p-greater-than-N", "na", "Invalid",
                  r.ok() ? "Ok" : std::string(measure_code_name(r.code())));
        obs.period = BigInt(0);
        r = verify_period(src, obs);
        ev.either(!r.ok() && r.code() == MeasureCode::Invalid, "c11.verify_period.api", "C11-API",
                  "p-zero-nonempty", "na", "Invalid",
                  r.ok() ? "Ok" : std::string(measure_code_name(r.code())));
        obs.where = Segment{BigInt(0), BigInt(20), 0, 0};
        obs.period = BigInt(1);
        r = verify_period(src, obs);
        ev.either(!r.ok() && r.code() == MeasureCode::Invalid, "c11.verify_period.api", "C11-API",
                  "where-outside-source", "na", "Invalid",
                  r.ok() ? "Ok" : std::string(measure_code_name(r.code())));
        // p = N vacuous truth.
        const std::vector<u8> distinct = {9, 7, 3, 5, 2, 8, 1, 4, 6, 0};
        SpanSource src2(distinct);
        Observation vacuous;
        vacuous.where = Segment{BigInt(0), BigInt(10), 0, 0};
        vacuous.kind = ProbeKind::Period;
        vacuous.period = BigInt(10);
        vacuous.verified = true;
        r = verify_period(src2, vacuous);
        ev.either(r.ok() && r.value(), "c11.verify_period.api", "C11-API", "p-equals-N", "na",
                  "Ok(true)", r.ok() ? (r.value() ? "Ok(true)" : "Ok(false)")
                                     : std::string(measure_code_name(r.code())));
    }

    // =======================================================================
    // c11.errors — §9
    // =======================================================================
    {
        const std::vector<u8> data(64, 0x22);
        SpanSource src(data);
        Policy pol;
        pol.effort = 255;
        auto r = probe(src, Segment{BigInt(0), BigInt(64), 0, 0}, pol);
        ev.either(!r.ok() && r.code() == MeasureCode::Invalid, "c11.errors.invalid", "C11-API",
                  "effort-out-of-domain", "na", "Invalid",
                  r.ok() ? "Ok" : std::string(measure_code_name(r.code())));
        r = probe(src, Segment{BigInt(0), BigInt(65), 0, 0}, Policy{});
        ev.either(!r.ok() && r.code() == MeasureCode::Invalid, "c11.errors.invalid", "C11-API",
                  "segment-outside-input", "na", "Invalid",
                  r.ok() ? "Ok" : std::string(measure_code_name(r.code())));
        r = probe(src, Segment{BigInt(10), BigInt(5), 0, 0}, Policy{});
        ev.either(!r.ok() && r.code() == MeasureCode::Invalid, "c11.errors.invalid", "C11-API",
                  "begin-greater-than-end", "na", "Invalid",
                  r.ok() ? "Ok" : std::string(measure_code_name(r.code())));
        FailingSource failing(0);
        r = probe(failing, Segment{BigInt(0), BigInt(64), 0, 0}, Policy{});
        ev.either(!r.ok() && r.code() == MeasureCode::Io, "c11.errors.io", "C11-API",
                  "unreadable-source", "na", "Io",
                  r.ok() ? "Ok" : std::string(measure_code_name(r.code())));
        Observation bad;
        bad.where = Segment{BigInt(0), BigInt(64), 0, 0};
        bad.kind = ProbeKind::Period;
        bad.period = BigInt(4);
        bad.verified = false;
        ev.either(!validate_observation(bad, 64).ok(), "c11.errors.invalid", "C11-API",
                  "period-verified-false", "na", "Invalid",
                  validate_observation(bad, 64).ok() ? "Ok" : "Invalid");
        bad.verified = true;
        bad.kind = ProbeKind::H0;
        ev.either(!validate_observation(bad, 64).ok(), "c11.errors.invalid", "C11-API",
                  "period-on-nonperiod-kind", "na", "Invalid",
                  validate_observation(bad, 64).ok() ? "Ok" : "Invalid");
    }

    // =======================================================================
    // c11.isolation — source-level authority boundary, asserted from the gate
    // =======================================================================
    {
        const fs::path header = repo_root / "include" / "mapr" / "e4" / "e4_probe.hpp";
        const fs::path impl = repo_root / "engine" / "src" / "e4" / "e4_probe.cpp";
        std::string text;
        for (const fs::path& path : {header, impl}) {
            std::ifstream in(path, std::ios::binary);
            std::string line;
            while (std::getline(in, line)) {
                const std::size_t comment = line.find("//");
                if (comment != std::string::npos) line.resize(comment);
                text += line;
                text += '\n';
            }
        }
        const auto has = [&](std::string_view pattern) {
            return text.find(pattern) != std::string::npos;
        };
        ev.either(!has("mapr/e2/") && !has("mapr/e3/") && !has("mapr/e5/") && !has("mapr/e6/") &&
                      !has("mapr/e7/") && !has("marp/harness"),
                  "c11.isolation.includes", "C11-API", "forbidden-includes", "na",
                  "no E2-E7, no harness", "checked");
        ev.either(!has("std::filesystem") && !has("fstream") && !has("std::chrono") &&
                      !has("getenv") && !has("std::random_device") && !has("std::thread") &&
                      !has("filename"),
                  "c11.isolation.environment", "C11-API", "no-environment-access", "na",
                  "no clock/locale/random/thread/file-name", "checked");
        ev.either(!has("struct Ir") && !has("class Dag") && !has("struct Candidate") &&
                      !has("struct Atom") && !has("discover") && !has("induce"),
                  "c11.isolation.no_terms", "C11-API", "no-term-surfaces", "na",
                  "no term/candidate/atom shapes", "checked");
    }

    // =======================================================================
    // Artefacts
    // =======================================================================
    const fs::path gates = out_root / "specs_and_reports" / "v2" / "gates";
    const fs::path logs = out_root / "specs_and_reports" / "v2" / "logs";
    const fs::path evidence_dir = out_root / "specs_and_reports" / "v2" / "evidence" / "C11";
    const fs::path tsv_path = gates / "C11-PROBE.tsv";
    const fs::path log_path = logs / "C11-PROBE.log";
    const fs::path sums_path = evidence_dir / "SHA256SUMS";
    {
        std::error_code ec;
        fs::create_directories(evidence_dir, ec);
        fs::create_directories(logs, ec);
    }

    std::vector<Row> rows = ev.rows();
    {
        std::vector<Row> sorted_rows = rows;
        std::stable_sort(sorted_rows.begin(), sorted_rows.end(),
                         [](const Row& a, const Row& b) {
                             if (a.check != b.check) return a.check < b.check;
                             if (a.corpus != b.corpus) return a.corpus < b.corpus;
                             return a.item_id < b.item_id;
                         });
        std::size_t i = 0;
        while (i < sorted_rows.size()) {
            std::size_t j = i;
            std::size_t pass = 0;
            while (j < sorted_rows.size() && sorted_rows[j].check == sorted_rows[i].check) {
                if (sorted_rows[j].verdict == "PASS") ++pass;
                ++j;
            }
            note("[summary:" + sorted_rows[i].check + "] rows=" + u64_dec(j - i) +
                 " pass=" + u64_dec(pass));
            i = j;
        }
    }

    if (!write_tsv(tsv_path, rows)) {
        std::fprintf(stderr, "failed to write %s\n", tsv_path.string().c_str());
        return 1;
    }

    std::stable_sort(log_lines.begin(), log_lines.end());
    {
        std::ofstream out(log_path, std::ios::binary | std::ios::trunc);
        if (!out) {
            std::fprintf(stderr, "failed to write %s\n", log_path.string().c_str());
            return 1;
        }
        out << "# C11 PROBE deterministic gate log\n";
        out << "# generated by engine/bin/c11_gate; never edited by hand\n";
        out << "component=C11-PROBE\n";
        out << "parent_epic=E4-MEASURE\n";
        out << "spec=MARP2-E4 sections 4.2, 4.7, 4.8, 4.9, 4.10, 5.3, 5.4, 6, 9\n";
        out << "depends=E1 (BigInt, SHA-256); C09 (Source, Policy); C10 (Segment, ilog2_q24); "
               "no E2-E7 linkage\n";
        out << "probes=H0,H1,H2,Runs,Period,Repeat16,Skew,BitComplexity,AffineFit,QuadraticFit,"
               "Stride,ChangePoint\n";
        out << "sampling=2MiB threshold; 16 windows of 64KiB at floor(j*(N-65536)/15); "
               "H2 and Repeat16 only\n";
        out << "rows_total=" << rows.size() << " pass=" << ev.passes()
            << " blocked=" << ev.blocked() << " fail=" << ev.fails() << "\n";
        for (const std::string& line : log_lines) {
            out << line << '\n';
        }
        out.flush();
        if (!out) return 1;
    }

    {
        std::ofstream out(sums_path, std::ios::binary | std::ios::trunc);
        if (!out) {
            std::fprintf(stderr, "failed to write %s\n", sums_path.string().c_str());
            return 1;
        }
        // Repo-root-relative paths, like every other component's manifest.
        const std::array<std::pair<fs::path, const char*>, 4> items = {{
            {repo_root / "include" / "mapr" / "e4" / "e4_probe.hpp",
             "include/mapr/e4/e4_probe.hpp"},
            {repo_root / "engine" / "src" / "e4" / "e4_probe.cpp",
             "engine/src/e4/e4_probe.cpp"},
            {tsv_path, "specs_and_reports/v2/gates/C11-PROBE.tsv"},
            {log_path, "specs_and_reports/v2/logs/C11-PROBE.log"},
        }};
        for (const auto& [path, rel] : items) {
            const std::string hex = sha256_file_hex(path);
            if (hex.empty()) {
                std::fprintf(stderr, "missing file for SHA256SUMS: %s\n",
                             path.string().c_str());
                return 1;
            }
            out << hex << "  " << rel << '\n';
        }
        out.flush();
        if (!out) return 1;
    }

    std::printf("C11 PROBE: rows=%zu pass=%zu blocked=%zu fail=%zu\n", rows.size(),
                ev.passes(), ev.blocked(), ev.fails());
    std::printf("RESULT: %s\n", ev.fails() == 0 ? "PASS" : "FAIL");
    return ev.fails() == 0 ? 0 : 1;
}

}  // namespace

int main(int argc, char** argv) {
    fs::path repo_root = "..";
    fs::path out_root{};
    bool verify_only = false;

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--root" && i + 1 < argc) {
            repo_root = argv[++i];
        } else if (arg == "--out-root" && i + 1 < argc) {
            out_root = argv[++i];
        } else if (arg == "--verify") {
            verify_only = true;
        } else if (arg == "--help") {
            std::printf("usage: c11_gate [--root DIR] [--out-root DIR] [--verify]\n");
            return 0;
        } else {
            std::fprintf(stderr, "unknown argument: %s\n", arg.c_str());
            return 2;
        }
    }

    if (out_root.empty()) out_root = repo_root;

    if (verify_only) {
        const fs::path sums =
            out_root / "specs_and_reports" / "v2" / "evidence" / "C11" / "SHA256SUMS";
        return verify_manifest(fs::weakly_canonical(sums));
    }
    return run_gate(repo_root, out_root);
}
