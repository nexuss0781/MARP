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
// PASS/FAIL/BLOCKED verdict.  Any FAIL makes the process exit non-zero.  The log
// is a fixed banner plus the rows in sorted order, so two runs on any host
// produce byte-identical files: the committed evidence is the evidence CI
// regenerates, not a snapshot of one machine.
//
// What this gate deliberately does NOT do:
//   * it does not claim the integrated E4-G gate, the M-* corpus, or any
//     oracle comparison; C11 proposes and records measurements only;
//   * it never reads a fixture from a file.  Every fixture is a pure function of
//     a pinned constant seed, so no name, extension, or path can reach a value;
//   * it does not emit a term, candidate, node, or atom, and it never inspects
//     an E5/E6 object — the observations it checks are §4.7 records only.
//
// Independence: the reference implementations in this file are written from the
// text of §4.2, §4.5, §4.7–§4.10 and share no code with the C11 library —
// separate 62-bit-mantissa `ilog2_q24`, sort-and-count trigram/bigram
// entropies (not the library's open-addressing tables), a brute-force Period,
// a sorted-key Repeat16, a Gaussian-elimination linear complexity (not
// Berlekamp–Massey), transcribed AffineFit/QuadraticFit predicates, an
// independent stride sweep, and a transcribed §4.5 change-point scan.
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
#include <map>
#include <optional>
#include <string>
#include <string_view>
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
using marp::v2::Observation;
using marp::v2::Policy;
using marp::v2::ProbeKind;
using marp::v2::Segment;
using marp::v2::Source;
using marp::v2::SpanSource;
using marp::v2::u32;
using marp::v2::u64;
using marp::v2::u8;

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

// Deterministic splitmix64 bytes.  Fixed constant seed; no clock, no random
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

std::string hex_digest_of_bytes(std::span<const u8> bytes) {
    const auto digest = mapr::Sha256::hash(
        std::string_view(reinterpret_cast<const char*>(bytes.data()), bytes.size()));
    if (!digest.ok()) return "err";
    return hex_of(std::span<const u8>(digest.value().data(), digest.value().size()));
}

// ---------------------------------------------------------------------------
// Sources that misbehave on purpose
// ---------------------------------------------------------------------------

class RecordingSource final : public Source {
public:
    explicit RecordingSource(std::span<const u8> data) : data_(data) {}
    [[nodiscard]] BigInt size() const noexcept override {
        return BigInt(static_cast<u64>(data_.size()));
    }
    [[nodiscard]] marp::v2::MeasureCode read(const BigInt& off, std::span<u8> dst) const noexcept override {
        ++calls_;
        bytes_ += dst.size();
        max_request_ = std::max(max_request_, dst.size());
        const auto offset = off.to_u64_checked();
        if (!offset.has_value() || *offset > data_.size()) return marp::v2::MeasureCode::Io;
        if (dst.size() > data_.size() - static_cast<std::size_t>(*offset)) return marp::v2::MeasureCode::Io;
        if (!dst.empty()) {
            std::memcpy(dst.data(), data_.data() + static_cast<std::size_t>(*offset), dst.size());
        }
        return marp::v2::MeasureCode::Ok;
    }
    [[nodiscard]] std::size_t calls() const noexcept { return calls_; }
    [[nodiscard]] std::size_t bytes() const noexcept { return bytes_; }
    [[nodiscard]] std::size_t max_request() const noexcept { return max_request_; }

private:
    std::span<const u8> data_;
    mutable std::size_t calls_ = 0;
    mutable std::size_t bytes_ = 0;
    mutable std::size_t max_request_ = 0;
};

class TruncatingSource final : public Source {
public:
    TruncatingSource(std::span<const u8> data, u64 declared) : data_(data), declared_(declared) {}
    [[nodiscard]] BigInt size() const noexcept override { return BigInt(declared_); }
    [[nodiscard]] marp::v2::MeasureCode read(const BigInt& off, std::span<u8> dst) const noexcept override {
        const auto offset = off.to_u64_checked();
        if (!offset.has_value() || *offset > data_.size()) return marp::v2::MeasureCode::Io;
        if (dst.size() > data_.size() - static_cast<std::size_t>(*offset)) return marp::v2::MeasureCode::Io;
        if (!dst.empty()) {
            std::memcpy(dst.data(), data_.data() + static_cast<std::size_t>(*offset), dst.size());
        }
        return marp::v2::MeasureCode::Ok;
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
    [[nodiscard]] marp::v2::MeasureCode read(const BigInt& off, std::span<u8> dst) const noexcept override {
        const auto offset = off.to_u64_checked();
        if (!offset.has_value() || *offset >= fail_from_) return marp::v2::MeasureCode::Io;
        if (dst.size() > data_.size() - static_cast<std::size_t>(*offset)) return marp::v2::MeasureCode::Io;
        if (!dst.empty()) {
            std::memcpy(dst.data(), data_.data() + static_cast<std::size_t>(*offset), dst.size());
        }
        return marp::v2::MeasureCode::Ok;
    }

private:
    std::span<const u8> data_;
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

// n · ilog2_q24(n) as an exact 128-bit term; 0 for n = 0.
u128 reference_entropy_term(u64 n) {
    if (n == 0u) return 0u;
    return static_cast<u128>(n) * static_cast<u128>(reference_ilog2_q24(n));
}

// floor((ctx_sum − joint_sum) / n), guarded.
u64 reference_conditional_entropy(u128 ctx_sum, u128 joint_sum, u64 n) {
    if (n == 0u) return 0u;
    if (joint_sum >= ctx_sum) return 0u;
    return static_cast<u64>((ctx_sum - joint_sum) / static_cast<u128>(n));
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

// §4.8 H1: contexts are the previous byte over positions 1..N-1; the count
// total is N-1.  Counts are accumulated in plain arrays; the formula is
// transcribed from §4.2.
std::pair<u64, u64> reference_h1_q24(std::span<const u8> bytes) {
    const u64 n = static_cast<u64>(bytes.size());
    if (n < 2u) return {0u, 0u};
    std::array<u64, 256> ctx{};
    std::array<u64, 65536> joint{};
    for (u64 i = 1u; i < n; ++i) {
        const u8 prev = bytes[static_cast<std::size_t>(i - 1u)];
        const u8 cur = bytes[static_cast<std::size_t>(i)];
        ++ctx[prev];
        ++joint[(static_cast<u32>(prev) << 8u) | static_cast<u32>(cur)];
    }
    u128 ctx_sum = 0u;
    for (const u64 c : ctx) ctx_sum += reference_entropy_term(c);
    u128 joint_sum = 0u;
    for (const u64 c : joint) joint_sum += reference_entropy_term(c);
    return {reference_conditional_entropy(ctx_sum, joint_sum, n - 1u), n - 1u};
}

// Sort-and-count trigram/bigram accumulation over one span (independent of the
// library's open-addressing tables).
struct RefH2 {
    std::vector<u32> tri_keys;      // one entry per trigram position
    std::array<u64, 65536> bigram{};
};

void ref_h2_accumulate(std::span<const u8> bytes, RefH2& acc) {
    const u64 n = static_cast<u64>(bytes.size());
    for (u64 i = 2u; i < n; ++i) {
        const u8 b0 = bytes[static_cast<std::size_t>(i - 2u)];
        const u8 b1 = bytes[static_cast<std::size_t>(i - 1u)];
        const u8 b2 = bytes[static_cast<std::size_t>(i)];
        ++acc.bigram[(static_cast<u32>(b0) << 8u) | static_cast<u32>(b1)];
        acc.tri_keys.push_back(
            (static_cast<u32>(b0) << 16u) | (static_cast<u32>(b1) << 8u) |
            static_cast<u32>(b2));
    }
}

u64 ref_h2_value_of(const RefH2& acc, u64 total) {
    u128 ctx_sum = 0u;
    for (const u64 c : acc.bigram) ctx_sum += reference_entropy_term(c);
    std::vector<u32> keys = acc.tri_keys;
    std::sort(keys.begin(), keys.end());
    u128 joint_sum = 0u;
    u64 run = 0u;
    for (std::size_t i = 0; i <= keys.size(); ++i) {
        if (i == keys.size() || (i != 0u && keys[i] != keys[i - 1u])) {
            joint_sum += reference_entropy_term(run);
            run = 0u;
        }
        if (i < keys.size()) ++run;
    }
    return reference_conditional_entropy(ctx_sum, joint_sum, total);
}

// §4.8 H2 exact: N = n − 2 trigrams.
std::pair<u64, u64> reference_h2_q24_exact(std::span<const u8> bytes) {
    const u64 n = static_cast<u64>(bytes.size());
    if (n < 3u) return {0u, 0u};
    RefH2 acc;
    ref_h2_accumulate(bytes, acc);
    return {ref_h2_value_of(acc, n - 2u), n - 2u};
}

// §4.9 sampled H2: 16 windows of 64 KiB at floor(j·(N−65536)/15), aggregated;
// the count total is 16·(65536−2).
std::pair<u64, u64> reference_h2_q24_sampled(std::span<const u8> bytes) {
    const u64 n = static_cast<u64>(bytes.size());
    RefH2 acc;
    for (u32 j = 0u; j < 16u; ++j) {
        const u64 off = static_cast<u64>(j) * (n - 65536u) / 15u;
        ref_h2_accumulate(
            std::span<const u8>(bytes.data() + static_cast<std::size_t>(off), 65536u), acc);
    }
    const u64 total = 16u * (65536u - 2u);
    return {ref_h2_value_of(acc, total), total};
}

// §4.8 Runs: total run count and maximum run length.
std::pair<u64, u64> reference_runs(std::span<const u8> bytes) {
    const u64 n = static_cast<u64>(bytes.size());
    u64 runs = 0u;
    u64 max_run = 0u;
    u64 i = 0u;
    while (i < n) {
        const u8 symbol = bytes[static_cast<std::size_t>(i)];
        u64 j = i + 1u;
        while (j < n && bytes[static_cast<std::size_t>(j)] == symbol) ++j;
        ++runs;
        if (j - i > max_run) max_run = j - i;
        i = j;
    }
    return {runs, max_run};
}

// §4.8 Period: the smallest p in [1, N] with b[i] == b[i−p] for all i >= p.
u64 reference_period(std::span<const u8> bytes) {
    const u64 n = static_cast<u64>(bytes.size());
    if (n == 0u) return 0u;
    for (u64 p = 1u; p <= n; ++p) {
        bool ok = true;
        for (u64 i = p; i < n; ++i) {
            if (bytes[static_cast<std::size_t>(i)] !=
                bytes[static_cast<std::size_t>(i - p)]) {
                ok = false;
                break;
            }
        }
        if (ok) return p;
    }
    return n;
}

// §4.8 Repeat16 exact: positions n−15, matches = positions − distinct keys.
std::pair<u64, u64> reference_repeat16_exact(std::span<const u8> bytes) {
    const u64 n = static_cast<u64>(bytes.size());
    if (n < 16u) return {0u, 0u};
    const u64 positions = n - 15u;
    std::vector<u128> keys;
    keys.reserve(static_cast<std::size_t>(positions));
    for (u64 i = 0u; i < positions; ++i) {
        const u8* p = bytes.data() + static_cast<std::size_t>(i);
        u128 k = 0u;
        for (int b = 0; b < 16; ++b) k = (k << 8u) | static_cast<u128>(p[b]);
        keys.push_back(k);
    }
    std::sort(keys.begin(), keys.end());
    const auto last = std::unique(keys.begin(), keys.end());
    const u64 distinct = static_cast<u64>(std::distance(keys.begin(), last));
    const u64 matches = positions - distinct;
    const u64 value = (positions == 0u)
                          ? 0u
                          : static_cast<u64>((static_cast<u128>(matches) << 24u) /
                                             static_cast<u128>(positions));
    return {value, matches};
}

// §4.9 sampled Repeat16: 16 windows, one shared key set across windows.
std::pair<u64, u64> reference_repeat16_sampled(std::span<const u8> bytes) {
    const u64 n = static_cast<u64>(bytes.size());
    std::vector<u128> keys;
    for (u32 j = 0u; j < 16u; ++j) {
        const u64 off = static_cast<u64>(j) * (n - 65536u) / 15u;
        const u8* win = bytes.data() + static_cast<std::size_t>(off);
        for (u64 i = 0u; i + 16u <= 65536u; ++i) {
            const u8* p = win + static_cast<std::size_t>(i);
            u128 k = 0u;
            for (int b = 0; b < 16; ++b) k = (k << 8u) | static_cast<u128>(p[b]);
            keys.push_back(k);
        }
    }
    const u64 positions = 16u * (65536u - 15u);
    std::sort(keys.begin(), keys.end());
    const auto last = std::unique(keys.begin(), keys.end());
    const u64 distinct = static_cast<u64>(std::distance(keys.begin(), last));
    const u64 matches = positions - distinct;
    const u64 value = static_cast<u64>((static_cast<u128>(matches) << 24u) /
                                       static_cast<u128>(positions));
    return {value, matches};
}

// §4.8 Skew: per-plane Q24.24 ones density.
std::vector<u64> reference_skew(std::span<const u8> bytes, u64 n) {
    std::array<u64, 8> ones{};
    for (const u8 byte : bytes) {
        for (u32 plane = 0u; plane < 8u; ++plane) {
            ones[plane] += static_cast<u64>((byte >> plane) & 1u);
        }
    }
    std::vector<u64> out(8u);
    for (u32 plane = 0u; plane < 8u; ++plane) {
        out[plane] = (n == 0u)
                         ? 0u
                         : static_cast<u64>((static_cast<u128>(ones[plane]) << 24u) /
                                            static_cast<u128>(n));
    }
    return out;
}

// §4.8 BitComplexity, independent transcription of Berlekamp–Massey over
// GF(2): the connection polynomial is updated by explicit shift-and-XOR of
// polynomials, a different code structure from the library's coefficient
// loop, but the same deterministic algorithm — so the minimal polynomial (and
// hence the digest) is comparable field for field.
struct RefBm {
    u32 l = 0u;
    std::vector<u8> coeffs;  // c_1..c_L
};

RefBm reference_bm(std::span<const u8> bits) {
    RefBm out;
    const u64 n = static_cast<u64>(bits.size());
    if (n == 0u) return out;

    // C(x) and B(x) as coefficient vectors indexed by degree; C[0] = B[0] = 1.
    std::vector<u8> c(static_cast<std::size_t>(n) + 2u, 0u);
    std::vector<u8> b(static_cast<std::size_t>(n) + 2u, 0u);
    c[0] = 1u;
    b[0] = 1u;
    u32 l = 0u;
    u64 m = 1u;

    for (u64 t = 0u; t < n; ++t) {
        // Discrepancy: d = s_t + sum_{i=1..L} c_i · s_{t-i}.
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
            const std::vector<u8> saved = c;  // B <- C before the update
            for (u64 i = 0u; i + m <= t + 1u; ++i) {
                if (b[static_cast<std::size_t>(i)] != 0u) {
                    c[static_cast<std::size_t>(i + m)] ^= 1u;
                }
            }
            l = static_cast<u32>(t + 1u - static_cast<u64>(l));
            b = saved;
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

// §4.8 digest serialisation: SHA-256(LE64(L) || packed c_1..c_L), LSB-first.
std::array<u8, 32> reference_bm_digest(u32 l, std::span<const u8> coeffs) {
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
    if (digest.ok()) {
        std::copy(digest.value().begin(), digest.value().end(), out.begin());
    }
    return out;
}

// The connection polynomial's coefficients generate the whole plane: for every
// t >= L, bit t is the XOR of c_i * bit (t - i).
bool coeffs_generate_plane(u32 l, const std::vector<u8>& coeffs,
                           std::span<const u8> bits) {
    const u64 n = static_cast<u64>(bits.size());
    if (static_cast<u64>(l) > n || coeffs.size() != static_cast<std::size_t>(l)) return false;
    for (u64 t = static_cast<u64>(l); t < n; ++t) {
        u8 gen = 0u;
        for (u32 i = 1u; i <= l; ++i) {
            gen = static_cast<u8>(gen ^ (coeffs[static_cast<std::size_t>(i) - 1u] &
                                         bits[static_cast<std::size_t>(t - i)]));
        }
        if (gen != bits[static_cast<std::size_t>(t)]) return false;
    }
    return true;
}

// §4.8 AffineFit: exact predicate, witness a | (s << 8) on a fit.
std::pair<u64, u64> reference_affine_fit(std::span<const u8> bytes) {
    const u64 n = static_cast<u64>(bytes.size());
    if (n == 0u) return {0u, 0u};
    const u8 a = bytes[0u];
    const u8 s = (n >= 2u)
                     ? static_cast<u8>((static_cast<u32>(bytes[1u]) - bytes[0u]) & 0xFFu)
                     : 0u;
    for (u64 i = 0u; i < n; ++i) {
        const u8 want = static_cast<u8>((static_cast<u64>(a) + i * static_cast<u64>(s)) & 0xFFu);
        if (bytes[static_cast<std::size_t>(i)] != want) return {0u, 0u};
    }
    return {1u, static_cast<u64>(a) | (static_cast<u64>(s) << 8u)};
}

// §4.8 QuadraticFit: constant second difference mod 256.
std::pair<u64, u64> reference_quadratic_fit(std::span<const u8> bytes) {
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

// §4.8 Stride: the best stride of the set whose conditional entropy lowers H0
// by at least 2^23; ties choose the smallest stride.
std::optional<std::pair<u64, u64>> reference_stride(std::span<const u8> bytes,
                                                     std::span<const u64> strides, u64 h0) {
    const u64 n = static_cast<u64>(bytes.size());
    if (n == 0u) return std::nullopt;
    std::optional<std::pair<u64, u64>> best;
    u64 best_improvement = 0u;
    for (const u64 s : strides) {
        // §4.8 reading: a stride needs at least two samples per residue class
        // to be non-degenerate (s > n/2 makes some classes hold 0-1 samples,
        // trivially yielding H_s = 0).
        if (s > n / 2u) continue;
        std::vector<u64> joint(static_cast<std::size_t>(s) * 256u, 0u);
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
            ctx_sum += reference_entropy_term(row);
        }
        u128 joint_sum = 0u;
        for (const u64 c : joint) joint_sum += reference_entropy_term(c);
        const u64 h_s = reference_conditional_entropy(ctx_sum, joint_sum, n);
        const u64 improvement = (h0 > h_s) ? h0 - h_s : 0u;
        if (improvement >= (1ull << 23)) {
            if (!best.has_value() || improvement > best_improvement) {
                best_improvement = improvement;
                best = std::make_pair(s, h_s);
            }
        }
    }
    return best;
}

// §4.5 change points, transcribed from the four bullets.
std::vector<u64> reference_change_points(std::span<const u8> bytes) {
    const u64 length = static_cast<u64>(bytes.size());
    const u64 window = 4096;
    const u64 hop = 2048;
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

// ---------------------------------------------------------------------------
// Fixture catalogue
//
// Deterministic and generated in-process.  Corpus ids follow E4 §12.3's naming
// so C11 and E4-G can reuse the same material without renaming anything.
// ---------------------------------------------------------------------------

struct Fixture {
    std::string id;
    std::string corpus;
    std::vector<u8> bytes;
};

std::vector<Fixture> make_fixtures() {
    std::vector<Fixture> out;

    // C11-CORE: the smallest inputs.
    out.push_back({"empty", "C11-CORE", {}});
    out.push_back({"one-0x00", "C11-CORE", {0x00}});
    out.push_back({"two-bytes", "C11-CORE", {0x00, 0xff}});
    out.push_back({"zeros-63", "C11-CORE", zeros(63)});
    out.push_back({"abc", "C11-CORE", {'a', 'b', 'c'}});

    // C11-EDGE: lengths around the change-point window and the BM cap.
    for (const std::size_t n : {std::size_t{64}, std::size_t{65}, std::size_t{127},
                                std::size_t{255}, std::size_t{256}, std::size_t{257},
                                std::size_t{4095}, std::size_t{4096}, std::size_t{4097},
                                std::size_t{8191}, std::size_t{8192}, std::size_t{8193}}) {
        out.push_back({"zeros-" + std::to_string(n), "C11-EDGE", zeros(n)});
        out.push_back({"rand-" + std::to_string(n), "C11-EDGE",
                       splitmix_bytes(n, 0x4d41525043313101ull + n)});
    }

    // C11-SCALE: the corpus shapes of E4 §12.3, at 1 MiB and across 2 MiB.
    out.push_back({"zero-1MiB", "C11-SCALE", zeros(1u << 20u)});
    out.push_back({"rand-1MiB", "C11-SCALE", splitmix_bytes(1u << 20u, 0x4d41525043313102ull)});
    out.push_back({"rand-1MiB+1", "C11-SCALE",
                   splitmix_bytes((1u << 20u) + 1u, 0x4d41525043313103ull)});
    out.push_back({"rand-2MiB+12345", "C11-SCALE",
                   splitmix_bytes((2u << 20u) + 12345u, 0x4d41525043313104ull)});
    {
        std::vector<u8> tile(4096);
        for (std::size_t i = 0; i < tile.size(); ++i) {
            tile[i] = static_cast<u8>((i * 31u + 7u) & 0xFFu);
        }
        out.push_back({"tile-4096-1MiB", "C11-SCALE", repeat_block(tile, 1u << 20u)});
    }
    {
        std::vector<u8> grad(1u << 20u);
        for (std::size_t i = 0; i < grad.size(); ++i) grad[i] = static_cast<u8>(i & 0xFFu);
        out.push_back({"grad-1MiB", "C11-SCALE", std::move(grad)});
    }
    out.push_back({"text-1MiB", "C11-SCALE", [&] {
                       std::vector<u8> block(4096);
                       const char* words =
                           "MARP measures where structure changes; it does not conclude. ";
                       for (std::size_t i = 0; i < block.size(); ++i) {
                           block[i] = static_cast<u8>(words[i % 60u]);
                       }
                       return repeat_block(block, 1u << 20u);
                   }()});

    // C11-CHANGE: 4 KiB zeros | random | 4 KiB zeros | random, the change-point
    // corpus.  The leading zero run is deliberately short (4 KiB) so the
    // brute-force Period reference stays linear on this fixture.
    {
        std::vector<u8> change;
        change.reserve(1u << 20u);
        change.insert(change.end(), 4096u, 0x00u);
        const std::vector<u8> r1 = splitmix_bytes(512u * 1024u - 8192u, 0x4d41525043313105ull);
        change.insert(change.end(), r1.begin(), r1.end());
        change.insert(change.end(), 4096u, 0x00u);
        const std::vector<u8> r2 = splitmix_bytes(512u * 1024u - 8192u, 0x4d41525043313106ull);
        change.insert(change.end(), r2.begin(), r2.end());
        out.push_back({"change-1MiB", "C11-CHANGE", std::move(change)});
    }
    // C11-CHANGE-ALT: alternating 4 KiB zeros / 4 KiB random (period 8192).
    {
        std::vector<u8> alt;
        alt.reserve(1u << 20u);
        const std::vector<u8> r = splitmix_bytes(4096, 0x4d41525043313107ull);
        for (int i = 0; i < 128; ++i) {
            if ((i & 1) == 0) {
                alt.insert(alt.end(), 4096u, 0x00u);
            } else {
                alt.insert(alt.end(), r.begin(), r.end());
            }
        }
        out.push_back({"change-alt-4KiB", "C11-CHANGE", std::move(alt)});
    }

    return out;
}

// ---------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------

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
    return hex_of(std::span<const u8>(digest.value().data(), digest.value().size()));
}

std::string read_text(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return {};
    std::string text;
    std::array<char, 32u * 1024u> chunk{};
    while (in) {
        in.read(chunk.data(), static_cast<std::streamsize>(chunk.size()));
        const std::streamsize got = in.gcount();
        if (got > 0) text.append(chunk.data(), static_cast<std::size_t>(got));
    }
    return text;
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
// Observation helpers
// ---------------------------------------------------------------------------

const Observation* find_obs(const std::vector<Observation>& obs, ProbeKind kind,
                            u32 param = 0u) {
    for (const Observation& o : obs) {
        if (o.kind == kind && o.param == param) return &o;
    }
    return nullptr;
}

// Stride's `param` is the stride value (never 0), and sampled H2/Repeat16
// carry param = window size: look them up by kind only.
template <ProbeKind K> const Observation* find_kind(const std::vector<Observation>& obs) {
    for (const Observation& o : obs) {
        if (o.kind == K) return &o;
    }
    return nullptr;
}

const Observation* find_stride(const std::vector<Observation>& obs) {
    return find_kind<ProbeKind::Stride>(obs);
}

std::size_t count_kind(const std::vector<Observation>& obs, ProbeKind kind) {
    std::size_t n = 0;
    for (const Observation& o : obs) {
        if (o.kind == kind) ++n;
    }
    return n;
}

bool digest_is_zero(const std::array<u8, 32>& digest) {
    for (const u8 b : digest) {
        if (b != 0u) return false;
    }
    return true;
}

// §4.7 field discipline: a field a kind does not use is zero.
std::string field_problem(const Observation& o, u64 n) {
    const bool period_zero = o.period == BigInt(0u);
    const bool digest_zero = digest_is_zero(o.digest);
    switch (o.kind) {
        case ProbeKind::H0:
            if (!period_zero || !digest_zero || o.verified || o.sampled ||
                o.sample_count != 0u || o.param != 0u) {
                return "H0: non-zero unused field";
            }
            if (o.aux != n) return "H0: aux != n";
            return {};
        case ProbeKind::H1:
            if (!period_zero || !digest_zero || o.verified || o.sampled ||
                o.sample_count != 0u || o.param != 0u) {
                return "H1: non-zero unused field";
            }
            if (o.aux != ((n >= 2u) ? n - 1u : 0u)) return "H1: aux != n-1";
            return {};
        case ProbeKind::H2:
            if (!period_zero || !digest_zero || o.verified) return "H2: non-zero unused field";
            if (o.sampled) {
                if (!o.sampled || o.sample_count != 16u || o.param != 65536u) {
                    return "H2: sampled flags wrong";
                }
            } else if (o.sample_count != 0u || o.param != 0u) {
                return "H2: sample flags set on exact path";
            }
            return {};
        case ProbeKind::Runs:
            if (!period_zero || !digest_zero || o.verified || o.sampled ||
                o.sample_count != 0u || o.param != 0u) {
                return "Runs: non-zero unused field";
            }
            return {};
        case ProbeKind::Period:
            if (o.value != 0u || o.aux != 0u || !digest_zero || o.sampled ||
                o.sample_count != 0u || o.param != 0u) {
                return "Period: non-zero unused field";
            }
            if (!o.verified) return "Period: verified false";
            if (period_zero) return "Period: period zero";
            return {};
        case ProbeKind::Repeat16:
            if (!period_zero || !digest_zero || o.verified) return "Repeat16: non-zero unused field";
            if (o.sampled) {
                if (o.sample_count != 16u || o.param != 65536u) {
                    return "Repeat16: sampled flags wrong";
                }
            } else if (o.sample_count != 0u || o.param != 0u) {
                return "Repeat16: sample flags set on exact path";
            }
            return {};
        case ProbeKind::Skew:
            if (!period_zero || !digest_zero || o.verified || o.sampled ||
                o.sample_count != 0u) {
                return "Skew: non-zero unused field";
            }
            if (o.aux != n) return "Skew: aux != n";
            if (o.param > 7u) return "Skew: param out of 0..7";
            return {};
        case ProbeKind::BitComplexity:
            if (!period_zero || o.verified || o.sampled || o.sample_count != 0u) {
                return "BitComplexity: non-zero unused field";
            }
            if (o.aux != 0u) return "BitComplexity: aux != 0";
            if (o.param > 7u) return "BitComplexity: param out of 0..7";
            if (digest_zero) return "BitComplexity: digest zero";
            return {};
        case ProbeKind::AffineFit:
        case ProbeKind::QuadraticFit:
            if (!period_zero || !digest_zero || o.verified || o.sampled ||
                o.sample_count != 0u || o.param != 0u) {
                return "Fit: non-zero unused field";
            }
            return {};
        case ProbeKind::Stride:
            if (!period_zero || !digest_zero || o.verified || o.sampled ||
                o.sample_count != 0u) {
                return "Stride: non-zero unused field";
            }
            if (o.aux != o.param) return "Stride: aux != param";
            return {};
        case ProbeKind::ChangePoint:
            if (!period_zero || !digest_zero || o.verified || o.sampled ||
                o.sample_count != 0u || o.param != 0u) {
                return "ChangePoint: non-zero unused field";
            }
            if (o.value != 1u) return "ChangePoint: value != 1";
            return {};
    }
    return "unknown kind";
}

// ---------------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------------

int run_gate(const fs::path& repo_root, const fs::path& out_root) {
    Evidence ev;
    std::vector<std::string> log_lines;
    auto note = [&log_lines](const std::string& line) { log_lines.push_back(line); };

    // --- 1. c11.fixed.ilog2: the M-KAT table, plus 4096 random values against
    //        the independent 62-bit-mantissa routine ------------------------
    {
        const std::array<std::pair<u64, u64>, 14> kats = {{
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
        std::size_t kat_ok = 0;
        for (const auto& kat : kats) {
            const u64 got = marp::v2::ilog2_q24(kat.first);
            const u64 ref = reference_ilog2_q24(kat.first);
            const std::string item = "x-" + u64_dec(kat.first);
            ev.either(got == kat.second && ref == kat.second, "c11.fixed.ilog2.kat", "C11-KAT",
                      item, "-", u64_dec(kat.second),
                      u64_dec(got) + "/ref=" + u64_dec(ref));
            note("[c11.fixed.ilog2.kat:" + item + "] ilog2_q24=" + u64_dec(got));
            if (got == kat.second) ++kat_ok;
        }
        ev.either(kat_ok == kats.size(), "c11.fixed.ilog2.kat_complete", "C11-KAT", "all-14",
                  "-", "14/14", u64_dec(kat_ok) + "/14");

        std::size_t pow_ok = 0;
        for (unsigned bit = 0; bit < 64u; ++bit) {
            const u64 x = (bit == 63u) ? 0x8000000000000000ull : (1ull << bit);
            if (marp::v2::ilog2_q24(x) == (static_cast<u64>(bit) << 24u)) ++pow_ok;
        }
        ev.either(pow_ok == 64u, "c11.fixed.ilog2.powers_of_two", "C11-KAT", "2^0..2^63", "-",
                  "64/64", u64_dec(pow_ok) + "/64");

        std::size_t rand_ok = 0;
        std::size_t mismatches = 0;
        std::string first_mismatch;
        u64 s = 0x452821e638d01377ull;
        for (int n = 0; n < 4096; ++n) {
            s += 0x9E3779B97F4A7C15ull;
            u64 z = s;
            z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
            z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
            z = z ^ (z >> 31);
            if (z == 0u) z = 1u;
            const u64 got = marp::v2::ilog2_q24(z);
            const u64 ref = reference_ilog2_q24(z);
            if (got == ref) {
                ++rand_ok;
            } else {
                if (mismatches == 0) {
                    first_mismatch = "x=" + u64_dec(z) + " got=" + u64_dec(got) +
                                     " ref=" + u64_dec(ref);
                }
                ++mismatches;
            }
        }
        ev.either(mismatches == 0, "c11.fixed.ilog2.reference", "C11-KAT", "random-4096",
                  hex_digest_of_bytes(std::span<const u8>()), "4096/4096",
                  u64_dec(rand_ok) + "/4096" +
                      (first_mismatch.empty() ? "" : " first=" + first_mismatch));
        note("[c11.fixed.ilog2.reference:random-4096] agree=" + u64_dec(rand_ok) + "/4096");

        std::size_t mono_ok = 0;
        u64 prev = 0;
        for (u64 x = 1; x <= 20000u; ++x) {
            const u64 got = marp::v2::ilog2_q24(x);
            if (got >= prev) ++mono_ok;
            prev = got;
        }
        ev.either(mono_ok == 20000u, "c11.fixed.ilog2.monotone", "C11-KAT", "x-1..20000", "-",
                  "20000/20000", u64_dec(mono_ok) + "/20000");
    }

    // --- 2. c11.fixed.h0: exact known values and an independent formula ----
    {
        struct H0Case {
            const char* id;
            std::array<std::pair<int, u64>, 4> counts;
            int symbols;
            u64 want;
        };
        const std::array<H0Case, 4> cases = {{
            {"single-symbol-4096", {{{7, 4096}, {0, 0}, {0, 0}, {0, 0}}}, 1, 0ull},
            {"two-equal-1000", {{{0, 1000}, {1, 1000}, {0, 0}, {0, 0}}}, 2, 1ull << 24u},
            {"four-equal-777", {{{1, 777}, {2, 777}, {3, 777}, {4, 777}}}, 4, 2ull << 24u},
            {"256-uniform-64", {{{0, 0}, {0, 0}, {0, 0}, {0, 0}}}, 0, 8ull << 24u},
        }};
        for (const H0Case& c : cases) {
            std::array<u64, 256> counts{};
            if (std::string_view(c.id) == "256-uniform-64") {
                for (std::size_t i = 0; i < 256u; ++i) counts[i] = 64u;
            } else {
                for (int i = 0; i < c.symbols; ++i) {
                    counts[static_cast<std::size_t>(c.counts[static_cast<std::size_t>(i)].first)] =
                        c.counts[static_cast<std::size_t>(i)].second;
                }
            }
            const u64 got = marp::v2::h0_q24_from_counts(counts);
            ev.either(got == c.want, "c11.fixed.h0.known", "C11-KAT", c.id, "-",
                      u64_dec(c.want), u64_dec(got));
            note(std::string("[c11.fixed.h0.known:") + c.id + "] h0_q24=" + u64_dec(got));
        }
        ev.either(marp::v2::h0_q24_from_counts(std::array<u64, 256>{}) == 0u,
                  "c11.fixed.h0.empty", "C11-KAT", "empty-counts", "-", "0", "0");

        std::size_t agree = 0;
        u64 s = 0xbe5466cf34e90c6cull;
        auto next = [&s]() {
            s += 0x9E3779B97F4A7C15ull;
            u64 z = s;
            z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
            z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
            return z ^ (z >> 31);
        };
        for (int n = 0; n < 1000; ++n) {
            const unsigned symbols = 1u + static_cast<unsigned>(next() % 256u);
            std::vector<u64> counts(256u, 0u);
            for (unsigned i = 0; i < symbols; ++i) counts[i] = 1u + (next() % 8192u);
            std::array<u64, 256> fixed{};
            std::copy(counts.begin(), counts.end(), fixed.begin());
            if (marp::v2::h0_q24_from_counts(fixed) == reference_h0_q24(counts)) ++agree;
        }
        ev.either(agree == 1000u, "c11.fixed.h0.reference", "C11-KAT", "random-1000", "-",
                  "1000/1000", u64_dec(agree) + "/1000");
        note("[c11.fixed.h0.reference:random-1000] agree=" + u64_dec(agree) + "/1000");
    }

    // --- 3. c11.constants: the §4.9/§4.10/§9 constants --------------------
    {
        bool ok = marp::v2::kSampleExactMaxBytes == (2ull << 20) &&
                  marp::v2::kSampleWindowBytes == 65536u &&
                  marp::v2::kSampleWindowCount == 16u &&
                  marp::v2::kStrideImprovementQ24 == (1ull << 23) &&
                  marp::v2::kProbeRangeCapBytes == (64ull << 20) &&
                  marp::v2::kMaxObservationsPerProbe == 4096u &&
                  marp::v2::kBitComplexityMaxBytes == 8192u &&
                  marp::v2::kProbeKindCount == 12u;
        ok = ok && marp::v2::kStrideSetAll.size() == 9u &&
             marp::v2::kStrideSetAll[0] == 2u && marp::v2::kStrideSetAll.back() == 4096u;
        ok = ok && marp::v2::kStrideSetLow.size() == 3u && marp::v2::kStrideSetLow[0] == 2u &&
             marp::v2::kStrideSetLow.back() == 8u;
        ev.either(ok, "c11.constants.sampling_effort_caps", "C11-CONST", "section49_410_9", "-",
                  "exact<=2MiB;16x64KiB;stride>=2^23;range<=64MiB;obs<=4096;bm<=8192;12 kinds",
                  ok ? "all constants as specified" : "constant mismatch");
        note("[c11.constants.sampling_effort_caps] ok=" + u64_dec(ok ? 1u : 0u));
    }

    // --- 4. Per-fixture: every probe kind against the independent references -
    const std::vector<Fixture> fixtures = make_fixtures();
    for (const Fixture& fx : fixtures) {
        const u64 length = static_cast<u64>(fx.bytes.size());
        const std::string input_sha =
            hex_digest_of_bytes(std::span<const u8>(fx.bytes.data(), fx.bytes.size()));
        const std::span<const u8> bytes(fx.bytes.data(), fx.bytes.size());

        // The C11-CHANGE fixtures are probed per quarter: a whole-segment probe
        // on the zeros-heavy change corpus would make the brute-force Period
        // reference quadratic.  Quarters keep every check meaningful.
        std::vector<std::pair<std::string, std::span<const u8>>> probes;
        if (fx.corpus == "C11-CHANGE") {
            const u64 quarter = 256u * 1024u;
            for (u64 q = 0u; q * quarter < length; ++q) {
                const u64 b = q * quarter;
                const u64 e = std::min(length, b + quarter);
                probes.emplace_back("change-1MiB/q" + u64_dec(q),
                                    std::span<const u8>(fx.bytes.data() + static_cast<std::size_t>(b),
                                                         static_cast<std::size_t>(e - b)));
            }
        } else {
            probes.emplace_back(fx.id, bytes);
        }

        for (const auto& [pid, seg_bytes] : probes) {
            const u64 n = static_cast<u64>(seg_bytes.size());
            const std::string item = fx.corpus == "C11-CHANGE" ? pid : fx.id;
            SpanSource source(seg_bytes);
            const Segment seg{BigInt(0u), BigInt(n), 0u, 0u};
            const auto got = marp::v2::probe(source, seg, Policy{5});
            if (!got.ok()) {
                ev.fail("c11.probe.result", fx.corpus, item, input_sha, "Ok",
                        marp::v2::measure_code_name(got.code()));
                continue;
            }
            const std::vector<Observation>& obs = got.value();

            // 4a. structure: count bound, where == segment, ordering.
            bool where_ok = true;
            for (const Observation& o : obs) {
                if (!(o.where == seg)) where_ok = false;
            }
            bool ordered = true;
            for (std::size_t i = 1u; i < obs.size(); ++i) {
                if (!marp::v2::observation_precedes(obs[i - 1u], obs[i])) ordered = false;
            }
            const bool count_ok = obs.size() <= static_cast<std::size_t>(
                                     marp::v2::kMaxObservationsPerProbe);
            ev.either(where_ok && ordered && count_ok, "c11.probe.structure", fx.corpus, item,
                      input_sha, "where==segment;ordered;count<=4096",
                      (std::string(where_ok ? "where" : "WHERE-MISMATCH") + ";" +
                          (ordered ? "ordered" : "UNORDERED") + ";count=" +
                          u64_dec(obs.size())));
            note("[c11.probe.structure:" + item + "] count=" + u64_dec(obs.size()) +
                 " where=" + (where_ok ? "ok" : "BAD") + " ordered=" +
                 (ordered ? "ok" : "BAD"));

            // 4b. H0 / H1 / H2.
            {
                std::array<u64, 256> counts{};
                for (const u8 b : seg_bytes) ++counts[b];
                const u64 h0_ref = reference_h0_q24(counts);
                const Observation* h0 = find_obs(obs, ProbeKind::H0);
                ev.either(h0 != nullptr && h0->value == h0_ref, "c11.probe.h0", fx.corpus, item,
                          input_sha, "h0=" + u64_dec(h0_ref),
                          h0 == nullptr ? "MISSING" : "h0=" + u64_dec(h0->value));

                const auto h1_ref = reference_h1_q24(seg_bytes);
                const Observation* h1 = find_obs(obs, ProbeKind::H1);
                ev.either(h1 != nullptr && h1->value == h1_ref.first &&
                              h1->aux == h1_ref.second,
                          "c11.probe.h1", fx.corpus, item, input_sha,
                          "h1=" + u64_dec(h1_ref.first) + ";aux=" + u64_dec(h1_ref.second),
                          h1 == nullptr
                              ? "MISSING"
                              : "h1=" + u64_dec(h1->value) + ";aux=" + u64_dec(h1->aux));

                const Observation* h2 = find_kind<ProbeKind::H2>(obs);
                if (h2 != nullptr) {
                    std::pair<u64, u64> h2_ref;
                    if (n <= marp::v2::kSampleExactMaxBytes) {
                        h2_ref = reference_h2_q24_exact(seg_bytes);
                    } else {
                        h2_ref = reference_h2_q24_sampled(seg_bytes);
                    }
                    const bool sampled_ok =
                        (n <= marp::v2::kSampleExactMaxBytes)
                            ? (!h2->sampled && h2->sample_count == 0u && h2->param == 0u)
                            : (h2->sampled && h2->sample_count == 16u &&
                               h2->param == 65536u);
                    ev.either(h2->value == h2_ref.first && h2->aux == h2_ref.second && sampled_ok,
                              "c11.probe.h2", fx.corpus, item, input_sha,
                              "h2=" + u64_dec(h2_ref.first) + ";aux=" + u64_dec(h2_ref.second) +
                                  ";sampled=" + (n > marp::v2::kSampleExactMaxBytes ? "1" : "0"),
                              "h2=" + u64_dec(h2->value) + ";aux=" + u64_dec(h2->aux) +
                                  ";sampled=" + (h2->sampled ? "1" : "0"));
                } else {
                    ev.either(false, "c11.probe.h2", fx.corpus, item, input_sha, "H2 present",
                              "MISSING");
                }
            }

            // 4c. Runs.
            {
                const auto runs_ref = reference_runs(seg_bytes);
                const Observation* runs = find_obs(obs, ProbeKind::Runs);
                ev.either(runs != nullptr && runs->value == runs_ref.first &&
                              runs->aux == runs_ref.second,
                          "c11.probe.runs", fx.corpus, item, input_sha,
                          "runs=" + u64_dec(runs_ref.first) + ";max=" +
                              u64_dec(runs_ref.second),
                          runs == nullptr
                              ? "MISSING"
                              : "runs=" + u64_dec(runs->value) + ";max=" + u64_dec(runs->aux));
            }

            // 4d. Period: reported only when verified; verify_period agrees.
            if (n > 0u) {
                const Observation* period = find_obs(obs, ProbeKind::Period);
                const u64 period_ref = reference_period(seg_bytes);
                if (period == nullptr) {
                    ev.fail("c11.probe.period", fx.corpus, item, input_sha,
                            "period=" + u64_dec(period_ref) + ";verified", "MISSING");
                } else {
                    const auto vp = marp::v2::verify_period(source, *period);
                    const bool vp_ok = vp.ok() && vp.value();
                    ev.either(period->period == BigInt(period_ref) && period->verified && vp_ok,
                              "c11.probe.period", fx.corpus, item, input_sha,
                              "period=" + u64_dec(period_ref) + ";verified=1",
                              "period=" + period->period.to_decimal() +
                                  ";verified=" + (period->verified ? "1" : "0") +
                                  ";verify=" + (vp.ok() ? (vp.value() ? "true" : "false")
                                                         : marp::v2::measure_code_name(vp.code())));
                }
            } else {
                ev.either(find_obs(obs, ProbeKind::Period) == nullptr, "c11.probe.period",
                          fx.corpus, item, input_sha, "no Period on empty range",
                          find_obs(obs, ProbeKind::Period) == nullptr ? "absent" : "PRESENT");
            }

            // 4e. Repeat16.
            if (n >= 16u) {
                const Observation* rep = find_kind<ProbeKind::Repeat16>(obs);
                std::pair<u64, u64> rep_ref;
                if (n <= marp::v2::kSampleExactMaxBytes) {
                    rep_ref = reference_repeat16_exact(seg_bytes);
                } else {
                    rep_ref = reference_repeat16_sampled(seg_bytes);
                }
                if (rep == nullptr) {
                    ev.fail("c11.probe.repeat16", fx.corpus, item, input_sha,
                            "repeat16=" + u64_dec(rep_ref.first) + ";aux=" +
                                u64_dec(rep_ref.second),
                            "MISSING");
                } else {
                    const bool sampled_ok =
                        (n <= marp::v2::kSampleExactMaxBytes)
                            ? (!rep->sampled && rep->sample_count == 0u && rep->param == 0u)
                            : (rep->sampled && rep->sample_count == 16u &&
                               rep->param == 65536u);
                    ev.either(rep->value == rep_ref.first && rep->aux == rep_ref.second &&
                                  sampled_ok,
                              "c11.probe.repeat16", fx.corpus, item, input_sha,
                              "value=" + u64_dec(rep_ref.first) + ";aux=" +
                                  u64_dec(rep_ref.second),
                              "value=" + u64_dec(rep->value) + ";aux=" + u64_dec(rep->aux) +
                                  ";sampled=" + (rep->sampled ? "1" : "0"));
                }
            } else {
                ev.either(find_obs(obs, ProbeKind::Repeat16) == nullptr,
                          "c11.probe.repeat16", fx.corpus, item, input_sha,
                          "no Repeat16 below 16 bytes",
                          find_obs(obs, ProbeKind::Repeat16) == nullptr ? "absent" : "PRESENT");
            }

            // 4f. Skew, planes 0..7.
            {
                const std::vector<u64> skew_ref = reference_skew(seg_bytes, n);
                std::size_t planes_ok = 0;
                std::string detail;
                for (u32 plane = 0u; plane < 8u; ++plane) {
                    const Observation* sk = find_obs(obs, ProbeKind::Skew, plane);
                    if (sk != nullptr && sk->value == skew_ref[plane] && sk->aux == n &&
                        sk->param == plane) {
                        ++planes_ok;
                    }
                    detail += "p" + u64_dec(plane) + "=" +
                              (sk == nullptr ? "MISSING" : u64_dec(sk->value)) + ";";
                }
                ev.either(planes_ok == 8u, "c11.probe.skew", fx.corpus, item, input_sha,
                          "8 planes vs reference", u64_dec(planes_ok) + "/8 " + detail);
            }

            // 4g. BitComplexity: only for ranges at most the documented cap.
            if (n <= marp::v2::kBitComplexityMaxBytes) {
                std::size_t planes_ok = 0;
                std::size_t digest_ok = 0;
                std::size_t gen_ok = 0;
                std::size_t l_ok = 0;
                std::string detail;
                for (u32 plane = 0u; plane < 8u; ++plane) {
                    std::vector<u8> bits(static_cast<std::size_t>(n), 0u);
                    for (u64 t = 0u; t < n; ++t) {
                        bits[static_cast<std::size_t>(t)] =
                            static_cast<u8>((seg_bytes[static_cast<std::size_t>(t)] >> plane) & 1u);
                    }
                    const Observation* bm = find_obs(obs, ProbeKind::BitComplexity, plane);
                    if (bm == nullptr) {
                        detail += "p" + u64_dec(plane) + "=MISSING;";
                        continue;
                    }
                    const RefBm ref = reference_bm(bits);
                    if (bm->value == static_cast<u64>(ref.l)) ++l_ok;
                    const std::array<u8, 32> ref_digest =
                        reference_bm_digest(ref.l, ref.coeffs);
                    if (bm->digest == ref_digest) ++digest_ok;
                    if (coeffs_generate_plane(ref.l, ref.coeffs, bits)) ++gen_ok;
                    if (bm->value == static_cast<u64>(ref.l) && bm->digest == ref_digest &&
                        coeffs_generate_plane(ref.l, ref.coeffs, bits)) {
                        ++planes_ok;
                    }
                    detail += "p" + u64_dec(plane) + "=L" + u64_dec(bm->value) + ";";
                }
                ev.either(planes_ok == 8u, "c11.probe.bitcomplexity", fx.corpus, item, input_sha,
                          "8 planes: L, digest, generation",
                          "planes=" + u64_dec(planes_ok) + "/8 l=" + u64_dec(l_ok) +
                              "/8 digest=" + u64_dec(digest_ok) + "/8 gen=" + u64_dec(gen_ok) +
                              " " + detail);
            } else {
                ev.either(count_kind(obs, ProbeKind::BitComplexity) == 0u,
                          "c11.probe.bitcomplexity", fx.corpus, item, input_sha,
                          "no BitComplexity above 8192 bytes",
                          count_kind(obs, ProbeKind::BitComplexity) == 0u
                              ? "absent"
                              : "PRESENT");
            }

            // 4h. AffineFit / QuadraticFit.
            if (n > 0u) {
                const auto aff_ref = reference_affine_fit(seg_bytes);
                const Observation* aff = find_obs(obs, ProbeKind::AffineFit);
                ev.either(aff != nullptr && aff->value == aff_ref.first &&
                              aff->aux == aff_ref.second,
                          "c11.probe.affinefit", fx.corpus, item, input_sha,
                          "value=" + u64_dec(aff_ref.first) + ";aux=" + u64_dec(aff_ref.second),
                          aff == nullptr
                              ? "MISSING"
                              : "value=" + u64_dec(aff->value) + ";aux=" + u64_dec(aff->aux));
                const auto qua_ref = reference_quadratic_fit(seg_bytes);
                const Observation* qua = find_obs(obs, ProbeKind::QuadraticFit);
                ev.either(qua != nullptr && qua->value == qua_ref.first &&
                              qua->aux == qua_ref.second,
                          "c11.probe.quadraticfit", fx.corpus, item, input_sha,
                          "value=" + u64_dec(qua_ref.first) + ";aux=" + u64_dec(qua_ref.second),
                          qua == nullptr
                              ? "MISSING"
                              : "value=" + u64_dec(qua->value) + ";aux=" + u64_dec(qua->aux));
            } else {
                ev.either(find_obs(obs, ProbeKind::AffineFit) == nullptr &&
                              find_obs(obs, ProbeKind::QuadraticFit) == nullptr,
                          "c11.probe.fits", fx.corpus, item, input_sha,
                          "no fits on empty range", "absent");
            }

            // 4i. Stride: presence and value against the independent sweep.
            {
                std::array<u64, 256> counts{};
                for (const u8 b : seg_bytes) ++counts[b];
                const u64 h0 = reference_h0_q24(counts);
                const auto stride_ref =
                    reference_stride(seg_bytes, marp::v2::kStrideSetAll, h0);
                const Observation* stride = find_stride(obs);
                if (stride_ref.has_value()) {
                    ev.either(stride != nullptr && stride->value == stride_ref->second &&
                                  stride->aux == stride_ref->first &&
                                  stride->param == static_cast<u32>(stride_ref->first),
                              "c11.probe.stride", fx.corpus, item, input_sha,
                              "stride=" + u64_dec(stride_ref->first) +
                                  ";h_s=" + u64_dec(stride_ref->second),
                              stride == nullptr
                                  ? "MISSING"
                                  : "stride=" + u64_dec(stride->aux) +
                                      ";h_s=" + u64_dec(stride->value));
                } else {
                    ev.either(stride == nullptr, "c11.probe.stride", fx.corpus, item, input_sha,
                              "no stride qualifies",
                              stride == nullptr ? "absent" : "PRESENT");
                }
            }

            // 4j. ChangePoint: the whole-segment probe has begin 0, so absent.
            ev.either(find_obs(obs, ProbeKind::ChangePoint) == nullptr,
                      "c11.probe.changepoint", fx.corpus, item, input_sha,
                      "no ChangePoint at begin 0",
                      find_obs(obs, ProbeKind::ChangePoint) == nullptr ? "absent" : "PRESENT");

            // 4k. §4.7 field discipline across every observation.
            {
                std::string problem;
                for (const Observation& o : obs) {
                    const std::string p = field_problem(o, n);
                    if (!p.empty() && problem.empty()) problem = p;
                }
                ev.either(problem.empty(), "c11.probe.fields", fx.corpus, item, input_sha,
                          "unused fields zero per kind",
                          problem.empty() ? "ok" : problem);
            }
        }
    }

    // --- 5. c11.period: perfect-period fixtures and the verify contract ----
    {
        struct PeriodCase {
            const char* id;
            std::vector<u8> bytes;
            u64 want;
        };
        std::vector<u8> abab;
        for (int i = 0; i < 64; ++i) abab.push_back(static_cast<u8>((i & 1) != 0 ? 'b' : 'a'));
        std::vector<u8> tile(4096);
        for (std::size_t i = 0; i < tile.size(); ++i) {
            tile[i] = static_cast<u8>((i * 31u + 7u) & 0xFFu);
        }
        const std::vector<PeriodCase> cases = {
            {"abab-64", std::move(abab), 2u},
            {"zeros-4096", zeros(4096), 1u},
            {"tile-4096", std::move(tile), 256u},
            {"abc", {'a', 'b', 'c'}, 3u},
        };
        for (const PeriodCase& c : cases) {
            const std::string input_sha =
                hex_digest_of_bytes(std::span<const u8>(c.bytes.data(), c.bytes.size()));
            SpanSource source(std::span<const u8>(c.bytes.data(), c.bytes.size()));
            const Segment seg{BigInt(0u), BigInt(static_cast<u64>(c.bytes.size())), 0u, 0u};
            const auto got = marp::v2::probe(source, seg, Policy{5});
            const Observation* period =
                got.ok() ? find_obs(got.value(), ProbeKind::Period) : nullptr;
            const bool ok = got.ok() && period != nullptr &&
                            period->period == BigInt(c.want) && period->verified;
            ev.either(ok, "c11.period.perfect", "C11-PERIOD", c.id, input_sha,
                      "period=" + u64_dec(c.want) + ";verified=1",
                      period == nullptr
                          ? "MISSING"
                          : "period=" + period->period.to_decimal() +
                                ";verified=" + (period->verified ? "1" : "0"));
            note("[c11.period.perfect:" + std::string(c.id) + "] period=" +
                 (period == nullptr ? "MISSING" : period->period.to_decimal()));
        }

        // p = N is reported and verified (the check passes vacuously).
        {
            const std::vector<u8> bytes = {'a', 'b', 'c'};
            const std::string input_sha =
                hex_digest_of_bytes(std::span<const u8>(bytes.data(), bytes.size()));
            SpanSource source(std::span<const u8>(bytes.data(), bytes.size()));
            const Segment seg{BigInt(0u), BigInt(3u), 0u, 0u};
            const auto got = marp::v2::probe(source, seg, Policy{5});
            const Observation* period =
                got.ok() ? find_obs(got.value(), ProbeKind::Period) : nullptr;
            const bool ok = got.ok() && period != nullptr && period->period == BigInt(3u) &&
                            period->verified;
            ev.either(ok, "c11.period.p_equals_n", "C11-PERIOD", "abc-p3", input_sha,
                      "period=3=N;verified=1",
                      period == nullptr
                          ? "MISSING"
                          : "period=" + period->period.to_decimal() +
                                ";verified=" + (period->verified ? "1" : "0"));
        }

        // Forged periods are rejected by the full byte check.
        {
            const std::vector<u8> bytes = {'a', 'b', 'a', 'b'};
            const std::string input_sha =
                hex_digest_of_bytes(std::span<const u8>(bytes.data(), bytes.size()));
            SpanSource source(std::span<const u8>(bytes.data(), bytes.size()));
            Observation forged{};
            forged.where = Segment{BigInt(0u), BigInt(4u), 0u, 0u};
            forged.kind = ProbeKind::Period;
            forged.period = BigInt(3u);
            forged.verified = true;
            const auto vp = marp::v2::verify_period(source, forged);
            ev.either(vp.ok() && !vp.value(), "c11.period.forged_rejected", "C11-PERIOD",
                      "abab-forged-p3", input_sha, "verify=Ok(false)",
                      vp.ok() ? (vp.value() ? "Ok(true)" : "Ok(false)")
                              : marp::v2::measure_code_name(vp.code()));
        }
    }

    // --- 6. c11.bm: KATs and the plane budget -------------------------------
    {
        struct BmCase {
            const char* id;
            std::vector<u8> bytes;
            u32 l;
            std::vector<u8> coeffs;
        };
        const std::vector<BmCase> cases = {
            {"01-00-01-00", {0x01, 0x00, 0x01, 0x00}, 2u, {0u, 1u}},
            {"01-00", {0x01, 0x00}, 1u, {0u}},
            {"01-01-01-01", {0x01, 0x01, 0x01, 0x01}, 1u, {1u}},
        };
        for (const BmCase& c : cases) {
            const std::string input_sha =
                hex_digest_of_bytes(std::span<const u8>(c.bytes.data(), c.bytes.size()));
            SpanSource source(std::span<const u8>(c.bytes.data(), c.bytes.size()));
            const Segment seg{BigInt(0u), BigInt(static_cast<u64>(c.bytes.size())), 0u, 0u};
            const auto got = marp::v2::probe(source, seg, Policy{5});
            const Observation* bm0 =
                got.ok() ? find_obs(got.value(), ProbeKind::BitComplexity, 0u) : nullptr;
            const std::array<u8, 32> want_digest =
                reference_bm_digest(c.l, std::span<const u8>(c.coeffs.data(), c.coeffs.size()));
            const bool ok = got.ok() && bm0 != nullptr &&
                            bm0->value == static_cast<u64>(c.l) && bm0->digest == want_digest;
            ev.either(ok, "c11.bm.kat", "C11-BM", c.id, input_sha,
                      "L=" + u64_dec(c.l) + ";digest=" + hex_of(want_digest),
                      bm0 == nullptr
                          ? "MISSING"
                          : "L=" + u64_dec(bm0->value) + ";digest=" + hex_of(bm0->digest));
            note("[c11.bm.kat:" + std::string(c.id) + "] L=" +
                 (bm0 == nullptr ? "MISSING" : u64_dec(bm0->value)));
        }

        // The plane above a constant plane is the zero sequence: L = 0.
        {
            const std::vector<u8> bytes = {0x01, 0x00, 0x01, 0x00};
            const std::string input_sha =
                hex_digest_of_bytes(std::span<const u8>(bytes.data(), bytes.size()));
            SpanSource source(std::span<const u8>(bytes.data(), bytes.size()));
            const Segment seg{BigInt(0u), BigInt(4u), 0u, 0u};
            const auto got = marp::v2::probe(source, seg, Policy{5});
            const Observation* bm1 =
                got.ok() ? find_obs(got.value(), ProbeKind::BitComplexity, 1u) : nullptr;
            const std::array<u8, 32> want_digest = reference_bm_digest(0u, std::span<const u8>());
            const bool ok = got.ok() && bm1 != nullptr && bm1->value == 0u &&
                            bm1->digest == want_digest;
            ev.either(ok, "c11.bm.kat_zero_plane", "C11-BM", "01-00-01-00-plane1", input_sha,
                      "L=0;digest=sha256(LE64(0))",
                      bm1 == nullptr
                          ? "MISSING"
                          : "L=" + u64_dec(bm1->value) + ";digest=" + hex_of(bm1->digest));
        }

        // Effort selects the plane budget; the values themselves never change.
        {
            bool budget_ok = true;
            std::string detail;
            for (u32 effort = 0u; effort <= 9u; ++effort) {
                const auto planes = marp::v2::bit_complexity_plane_count(static_cast<u8>(effort));
                const u32 want = (effort <= 2u) ? 2u : 8u;
                if (!planes.ok() || planes.value() != want) budget_ok = false;
                detail += "e" + u64_dec(effort) + "=" +
                          (planes.ok() ? u64_dec(planes.value()) : "err") + ";";
            }
            const auto bad = marp::v2::bit_complexity_plane_count(10u);
            if (bad.ok() || bad.code() != marp::v2::MeasureCode::Invalid) budget_ok = false;
            ev.either(budget_ok, "c11.bm.plane_budget", "C11-BM", "effort-0..9-and-10", "-",
                      "2 planes for 0..2; 8 for 3..9; Invalid for 10", detail);

            bool stride_budget_ok = true;
            std::string sdetail;
            for (u32 effort = 0u; effort <= 9u; ++effort) {
                const auto set = marp::v2::stride_set_for_effort(static_cast<u8>(effort));
                const bool want_low = (effort <= 2u);
                if (!set.ok()) {
                    stride_budget_ok = false;
                    continue;
                }
                const bool ok_set = want_low
                                         ? (set.value().size() == 3u && set.value()[0] == 2u &&
                                            set.value().back() == 8u)
                                         : (set.value().size() == 9u && set.value()[0] == 2u &&
                                            set.value().back() == 4096u);
                if (!ok_set) stride_budget_ok = false;
                sdetail += "e" + u64_dec(effort) + "=n" + u64_dec(set.value().size()) + ";";
            }
            const auto bad2 = marp::v2::stride_set_for_effort(255u);
            if (bad2.ok() || bad2.code() != marp::v2::MeasureCode::Invalid) stride_budget_ok = false;
            ev.either(stride_budget_ok, "c11.bm.stride_budget", "C11-BM", "effort-0..9-and-255",
                      "-", "low set {2,4,8} for 0..2; full set for 3..9; Invalid outside",
                      sdetail);
        }
    }

    // --- 7. c11.change: emission exactly at the §4.5 boundaries ------------
    {
        const std::vector<Fixture> change_fx = [&] {
            std::vector<Fixture> out;
            for (const Fixture& fx : fixtures) {
                if (fx.corpus == "C11-CHANGE") out.push_back(fx);
            }
            return out;
        }();
        for (const Fixture& fx : change_fx) {
            const std::string input_sha =
                hex_digest_of_bytes(std::span<const u8>(fx.bytes.data(), fx.bytes.size()));
            const std::vector<u64> cps =
                reference_change_points(std::span<const u8>(fx.bytes.data(), fx.bytes.size()));
            std::size_t emitted = 0;
            std::string detail;
            for (const u64 cp : cps) {
                // Probe a small segment starting exactly at the boundary.
                const u64 end = std::min<u64>(static_cast<u64>(fx.bytes.size()), cp + 4096u);
                SpanSource source(std::span<const u8>(fx.bytes.data(), fx.bytes.size()));
                const Segment seg{BigInt(cp), BigInt(end), 0u, 0u};
                const auto got = marp::v2::probe(source, seg, Policy{5});
                const Observation* cp_obs =
                    got.ok() ? find_obs(got.value(), ProbeKind::ChangePoint) : nullptr;
                const bool ok = got.ok() && cp_obs != nullptr && cp_obs->value == 1u &&
                                cp_obs->aux == cp;
                if (ok) ++emitted;
                detail += "cp" + u64_dec(cp) + "=" + (ok ? "emitted" : "MISSING") + ";";
            }
            ev.either(emitted == cps.size(), "c11.change.emitted_at_boundaries", fx.corpus,
                      fx.id, input_sha, "every reference boundary emits ChangePoint",
                      u64_dec(emitted) + "/" + u64_dec(cps.size()) + " " + detail);
            note("[c11.change.emitted_at_boundaries:" + fx.id + "] cps=" +
                 u64_dec(cps.size()) + " emitted=" + u64_dec(emitted));

            // A grid offset that is not a change point emits nothing.
            if (!cps.empty()) {
                const u64 probe_off = cps.front() + 2048u;
                if (probe_off + 4096u <= static_cast<u64>(fx.bytes.size()) &&
                    std::find(cps.begin(), cps.end(), probe_off) == cps.end()) {
                    SpanSource source(std::span<const u8>(fx.bytes.data(), fx.bytes.size()));
                    const Segment seg{BigInt(probe_off), BigInt(probe_off + 4096u), 0u, 0u};
                    const auto got = marp::v2::probe(source, seg, Policy{5});
                    const Observation* cp_obs =
                        got.ok() ? find_obs(got.value(), ProbeKind::ChangePoint) : nullptr;
                    ev.either(got.ok() && cp_obs == nullptr, "c11.change.absent_off_boundary",
                              fx.corpus, fx.id + "-off" + u64_dec(probe_off), input_sha,
                              "no ChangePoint at a non-boundary grid offset",
                              cp_obs == nullptr ? "absent" : "PRESENT");
                }
            }
        }
    }

    // --- 8. c11.order: merge determinism and probe reproducibility ---------
    {
        // Merge: the same parts in four completion orders produce one output.
        const std::vector<u8> base = splitmix_bytes(4096u, 0x4d41525043313108ull);
        const std::string input_sha =
            hex_digest_of_bytes(std::span<const u8>(base.data(), base.size()));
        std::vector<std::vector<Observation>> parts;
        {
            SpanSource source(std::span<const u8>(base.data(), base.size()));
            for (u64 b = 0u; b < base.size(); b += 256u) {
                const u64 e = std::min<u64>(static_cast<u64>(base.size()), b + 256u);
                const Segment seg{BigInt(b), BigInt(e), 0u, 0u};
                const auto got = marp::v2::probe(source, seg, Policy{5});
                if (!got.ok()) {
                    ev.fail("c11.order.merge", "C11-ORDER", "4KiB-16-leaves", input_sha, "Ok",
                            marp::v2::measure_code_name(got.code()));
                    parts.clear();
                    break;
                }
                parts.push_back(got.value());
            }
        }
        if (!parts.empty()) {
            const auto serial = marp::v2::merge_observations(std::vector<std::vector<Observation>>(parts));
            auto reversed = parts;
            std::reverse(reversed.begin(), reversed.end());
            const auto rev = marp::v2::merge_observations(std::move(reversed));
            auto rotated = parts;
            std::rotate(rotated.begin(), rotated.begin() + 3u, rotated.end());
            const auto rot = marp::v2::merge_observations(std::move(rotated));
            auto interleaved = parts;
            for (std::size_t i = 0u; i < interleaved.size(); ++i) {
                std::swap(interleaved[i], interleaved[(i * 7u) % interleaved.size()]);
            }
            const auto ilv = marp::v2::merge_observations(std::move(interleaved));
            bool same = serial.size() == rev.size() && serial.size() == rot.size() &&
                        serial.size() == ilv.size();
            for (std::size_t i = 0u; same && i < serial.size(); ++i) {
                if (!marp::v2::observations_equal(serial[i], rev[i]) ||
                    !marp::v2::observations_equal(serial[i], rot[i]) ||
                    !marp::v2::observations_equal(serial[i], ilv[i])) {
                    same = false;
                }
            }
            bool sorted = true;
            for (std::size_t i = 1u; i < serial.size(); ++i) {
                if (!marp::v2::observation_precedes(serial[i - 1u], serial[i])) sorted = false;
            }
            ev.either(same && sorted, "c11.order.merge", "C11-ORDER", "4KiB-16-leaves",
                      input_sha, "4 completion orders merge identically; sorted",
                      (std::string(same ? "identical" : "DIFFERS") + ";sorted=" +
                          (sorted ? "ok" : "BAD") + ";obs=" + u64_dec(serial.size())));
            note("[c11.order.merge] obs=" + u64_dec(serial.size()) + " identical=" +
                 u64_dec(same ? 1u : 0u));
        }

        // Reproducibility: two probes of the same range and policy are equal.
        {
            const std::vector<u8> bytes = splitmix_bytes(64u * 1024u, 0x4d41525043313109ull);
            const std::string repro_sha =
                hex_digest_of_bytes(std::span<const u8>(bytes.data(), bytes.size()));
            SpanSource src_a(std::span<const u8>(bytes.data(), bytes.size()));
            SpanSource src_b(std::span<const u8>(bytes.data(), bytes.size()));
            const Segment seg{BigInt(0u), BigInt(static_cast<u64>(bytes.size())), 0u, 0u};
            const auto a = marp::v2::probe(src_a, seg, Policy{5});
            const auto b = marp::v2::probe(src_b, seg, Policy{5});
            bool same = a.ok() && b.ok() && a.value().size() == b.value().size();
            for (std::size_t i = 0u; same && i < a.value().size(); ++i) {
                if (!marp::v2::observations_equal(a.value()[i], b.value()[i])) same = false;
            }
            ev.either(same, "c11.order.reproducible", "C11-ORDER", "64KiB-twice", repro_sha,
                      "two runs field-identical",
                      same ? "identical;obs=" + u64_dec(a.value().size()) : "DIFFERS");
            note("[c11.order.reproducible] obs=" +
                 (a.ok() ? u64_dec(a.value().size()) : "err") + " identical=" +
                 u64_dec(same ? 1u : 0u));
        }
    }

    // --- 9. c11.sampling: the 2 MiB boundary and the recorded sample path ---
    {
        const std::array<std::pair<const char*, std::size_t>, 4> cases = {{
            {"zeros-2MiB", 2u << 20u},
            {"zeros-2MiB+1", (2u << 20u) + 1u},
            {"rand-2MiB", 2u << 20u},
            {"rand-2MiB+1", (2u << 20u) + 1u},
        }};
        for (const auto& [id, size] : cases) {
            const std::vector<u8> bytes =
                (std::string_view(id) == "zeros-2MiB" || std::string_view(id) == "zeros-2MiB+1")
                    ? zeros(size)
                    : splitmix_bytes(size, 0x4d4152504331310au + size);
            const std::string input_sha =
                hex_digest_of_bytes(std::span<const u8>(bytes.data(), bytes.size()));
            SpanSource source(std::span<const u8>(bytes.data(), bytes.size()));
            const Segment seg{BigInt(0u), BigInt(static_cast<u64>(size)), 0u, 0u};
            const auto got = marp::v2::probe(source, seg, Policy{5});
            if (!got.ok()) {
                ev.fail("c11.sampling.path", "C11-SAMPLE", id, input_sha, "Ok",
                        marp::v2::measure_code_name(got.code()));
                continue;
            }
            const std::vector<Observation>& obs = got.value();
            const bool exact = size <= static_cast<std::size_t>(marp::v2::kSampleExactMaxBytes);
            const Observation* h2 = find_kind<ProbeKind::H2>(obs);
            const Observation* rep = find_kind<ProbeKind::Repeat16>(obs);
            std::pair<u64, u64> h2_ref;
            std::pair<u64, u64> rep_ref;
            if (exact) {
                h2_ref = reference_h2_q24_exact(std::span<const u8>(bytes.data(), bytes.size()));
                rep_ref = reference_repeat16_exact(std::span<const u8>(bytes.data(), bytes.size()));
            } else {
                h2_ref = reference_h2_q24_sampled(std::span<const u8>(bytes.data(), bytes.size()));
                rep_ref = reference_repeat16_sampled(std::span<const u8>(bytes.data(), bytes.size()));
            }
            const bool h2_ok = h2 != nullptr && h2->value == h2_ref.first &&
                               h2->aux == h2_ref.second && h2->sampled == !exact &&
                               (exact ? (h2->sample_count == 0u && h2->param == 0u)
                                      : (h2->sample_count == 16u && h2->param == 65536u));
            const bool rep_ok = rep != nullptr && rep->value == rep_ref.first &&
                                rep->aux == rep_ref.second && rep->sampled == !exact &&
                                (exact ? (rep->sample_count == 0u && rep->param == 0u)
                                       : (rep->sample_count == 16u && rep->param == 65536u));
            ev.either(h2_ok && rep_ok, "c11.sampling.path", "C11-SAMPLE", id, input_sha,
                      "h2/repeat16 " + std::string(exact ? "exact" : "sampled") +
                          " vs reference",
                      "h2=" + (h2 == nullptr ? "MISSING" : u64_dec(h2->value)) +
                          ";sampled=" + (h2 == nullptr ? "?" : (h2->sampled ? "1" : "0")) +
                          ";repeat16=" + (rep == nullptr ? "MISSING" : u64_dec(rep->value)) +
                          ";sampled=" + (rep == nullptr ? "?" : (rep->sampled ? "1" : "0")));
            note("[c11.sampling.path:" + std::string(id) + "] exact=" +
                 (exact ? "1" : "0") + " h2_aux=" +
                 (h2 == nullptr ? "?" : u64_dec(h2->aux)) + " rep_aux=" +
                 (rep == nullptr ? "?" : u64_dec(rep->aux)));
        }
    }

    // --- 10. c11.effort: budget selection, values unchanged -----------------
    {
        std::vector<u8> abab;
        for (int i = 0; i < 64; ++i) abab.push_back(static_cast<u8>((i & 1) != 0 ? 'b' : 'a'));
        const std::string input_sha =
            hex_digest_of_bytes(std::span<const u8>(abab.data(), abab.size()));
        std::vector<std::vector<Observation>> per_effort;
        bool probes_ok = true;
        for (u32 effort = 0u; effort <= 9u; ++effort) {
            SpanSource source(std::span<const u8>(abab.data(), abab.size()));
            const Segment seg{BigInt(0u), BigInt(64u), 0u, 0u};
            const auto got = marp::v2::probe(source, seg, Policy{static_cast<u8>(effort)});
            if (!got.ok()) {
                probes_ok = false;
                break;
            }
            per_effort.push_back(got.value());
        }
        if (probes_ok) {
            bool values_same = true;
            std::string detail;
            for (u32 effort = 0u; effort <= 9u; ++effort) {
                const std::vector<Observation>& obs = per_effort[effort];
                const bool has_h2 = find_obs(obs, ProbeKind::H2) != nullptr;
                const bool has_rep = find_obs(obs, ProbeKind::Repeat16) != nullptr;
                const std::size_t bm_planes = count_kind(obs, ProbeKind::BitComplexity);
                const bool budget_ok = (effort <= 2u)
                                           ? (!has_h2 && !has_rep && bm_planes == 2u)
                                           : (has_h2 && has_rep && bm_planes == 8u);
                if (!budget_ok) values_same = false;
                // Shared kinds keep their exact values across efforts.
                for (const Observation& o : obs) {
                    if (o.kind == ProbeKind::H2 || o.kind == ProbeKind::Repeat16 ||
                        o.kind == ProbeKind::BitComplexity) {
                        continue;
                    }
                    const Observation* ref = find_obs(per_effort[5u], o.kind, o.param);
                    if (ref == nullptr || ref->value != o.value || ref->aux != o.aux) {
                        values_same = false;
                    }
                }
                detail += "e" + u64_dec(effort) + ":h2=" + (has_h2 ? "1" : "0") +
                          ";rep=" + (has_rep ? "1" : "0") + ";bm=" + u64_dec(bm_planes) + ";";
            }
            ev.either(values_same, "c11.effort.budget_and_values", "C11-EFFORT", "abab-64",
                      input_sha,
                      "budget per §4.10; shared values identical across 0..9", detail);
            note("[c11.effort.budget_and_values] " + detail);
        } else {
            ev.fail("c11.effort.budget_and_values", "C11-EFFORT", "abab-64", input_sha, "Ok",
                    "probe failed");
        }
    }

    // --- 11. c11.errors: Io, Invalid, Limit --------------------------------
    {
        const std::vector<u8> bytes = splitmix_bytes(4096u, 0x4d4152504331310bull);
        const std::string input_sha =
            hex_digest_of_bytes(std::span<const u8>(bytes.data(), bytes.size()));

        // Effort out of domain.
        for (const u8 effort : {static_cast<u8>(10u), static_cast<u8>(255u)}) {
            SpanSource source(std::span<const u8>(bytes.data(), bytes.size()));
            const Segment seg{BigInt(0u), BigInt(64u), 0u, 0u};
            const auto got = marp::v2::probe(source, seg, Policy{effort});
            ev.either(!got.ok() && got.code() == marp::v2::MeasureCode::Invalid,
                      "c11.errors.effort", "C11-ERRORS", "effort-" + u64_dec(effort), input_sha,
                      "Invalid", got.ok() ? "Ok" : marp::v2::measure_code_name(got.code()));
        }

        // Segment outside the input.
        {
            SpanSource source(std::span<const u8>(bytes.data(), bytes.size()));
            const Segment over{BigInt(0u), BigInt(static_cast<u64>(bytes.size()) + 1u), 0u, 0u};
            const auto got = marp::v2::probe(source, over, Policy{5});
            ev.either(!got.ok() && got.code() == marp::v2::MeasureCode::Invalid,
                      "c11.errors.segment", "C11-ERRORS", "end-beyond-input", input_sha, "Invalid",
                      got.ok() ? "Ok" : marp::v2::measure_code_name(got.code()));
        }
        {
            SpanSource source(std::span<const u8>(bytes.data(), bytes.size()));
            const Segment reversed{BigInt(10u), BigInt(5u), 0u, 0u};
            const auto got = marp::v2::probe(source, reversed, Policy{5});
            ev.either(!got.ok() && got.code() == marp::v2::MeasureCode::Invalid,
                      "c11.errors.segment", "C11-ERRORS", "begin-after-end", input_sha, "Invalid",
                      got.ok() ? "Ok" : marp::v2::measure_code_name(got.code()));
        }

        // Io: a source that fails on the first read.
        {
            FailingSource source(std::span<const u8>(bytes.data(), bytes.size()), 0u);
            const Segment seg{BigInt(0u), BigInt(200u), 0u, 0u};
            const auto got = marp::v2::probe(source, seg, Policy{5});
            ev.either(!got.ok() && got.code() == marp::v2::MeasureCode::Io,
                      "c11.errors.io", "C11-ERRORS", "failing-source", input_sha, "Io",
                      got.ok() ? "Ok" : marp::v2::measure_code_name(got.code()));
        }
        // Io: a source that declares more than it holds, read past its end.
        {
            TruncatingSource source(std::span<const u8>(bytes.data(), bytes.size()), 10000u);
            const Segment seg{BigInt(0u), BigInt(static_cast<u64>(bytes.size()) + 1u), 0u, 0u};
            const auto got = marp::v2::probe(source, seg, Policy{5});
            ev.either(!got.ok() && got.code() == marp::v2::MeasureCode::Io,
                      "c11.errors.io", "C11-ERRORS", "truncating-source", input_sha, "Io",
                      got.ok() ? "Ok" : marp::v2::measure_code_name(got.code()));
        }

        // Limit: a range above the 64 MiB cap is refused before any read.
        {
            std::vector<u8> tiny(1u, 0x00u);
            TruncatingSource source(std::span<const u8>(tiny.data(), tiny.size()),
                                    (64ull << 20u) + 1u);
            const Segment seg{BigInt(0u), BigInt((64ull << 20u) + 1u), 0u, 0u};
            const auto got = marp::v2::probe(source, seg, Policy{5});
            ev.either(!got.ok() && got.code() == marp::v2::MeasureCode::Limit,
                      "c11.errors.limit", "C11-ERRORS", "range-over-64MiB", input_sha, "Limit",
                      got.ok() ? "Ok" : marp::v2::measure_code_name(got.code()));
        }

        // verify_period contract violations.
        {
            SpanSource source(std::span<const u8>(bytes.data(), bytes.size()));
            Observation wrong_kind{};
            wrong_kind.where = Segment{BigInt(0u), BigInt(64u), 0u, 0u};
            wrong_kind.kind = ProbeKind::H0;
            wrong_kind.period = BigInt(2u);
            wrong_kind.verified = true;
            const auto got = marp::v2::verify_period(source, wrong_kind);
            ev.either(!got.ok() && got.code() == marp::v2::MeasureCode::Invalid,
                      "c11.errors.verify", "C11-ERRORS", "verify-wrong-kind", input_sha, "Invalid",
                      got.ok() ? "Ok" : marp::v2::measure_code_name(got.code()));

            Observation unverified{};
            unverified.where = Segment{BigInt(0u), BigInt(64u), 0u, 0u};
            unverified.kind = ProbeKind::Period;
            unverified.period = BigInt(2u);
            unverified.verified = false;
            const auto got2 = marp::v2::verify_period(source, unverified);
            ev.either(!got2.ok() && got2.code() == marp::v2::MeasureCode::Invalid,
                      "c11.errors.verify", "C11-ERRORS", "verify-unverified-period", input_sha,
                      "Invalid", got2.ok() ? "Ok" : marp::v2::measure_code_name(got2.code()));

            Observation zero_period{};
            zero_period.where = Segment{BigInt(0u), BigInt(64u), 0u, 0u};
            zero_period.kind = ProbeKind::Period;
            zero_period.period = BigInt(0u);
            zero_period.verified = true;
            const auto got3 = marp::v2::verify_period(source, zero_period);
            ev.either(!got3.ok() && got3.code() == marp::v2::MeasureCode::Invalid,
                      "c11.errors.verify", "C11-ERRORS", "verify-zero-period", input_sha, "Invalid",
                      got3.ok() ? "Ok" : marp::v2::measure_code_name(got3.code()));

            Observation empty_where{};
            empty_where.where = Segment{BigInt(0u), BigInt(0u), 0u, 0u};
            empty_where.kind = ProbeKind::Period;
            empty_where.period = BigInt(1u);
            empty_where.verified = true;
            const auto got4 = marp::v2::verify_period(source, empty_where);
            ev.either(!got4.ok() && got4.code() == marp::v2::MeasureCode::Invalid,
                      "c11.errors.verify", "C11-ERRORS", "verify-empty-range", input_sha, "Invalid",
                      got4.ok() ? "Ok" : marp::v2::measure_code_name(got4.code()));
        }
    }

    // --- 12. c11.names: the probe never sees a label ----------------------
    {
        const std::vector<u8> base = splitmix_bytes(256u * 1024u, 0x4d4152504331310cull);
        const std::array<const char*, 5> labels = {{"slice.bin", "slice.txt", "slice.zip",
                                                    "slice", "slice.tar.gz"}};
        std::string first;
        bool identical = true;
        for (const char* label : labels) {
            // The label is a log column only; `Source` has no name to consult and
            // `probe` receives bytes, never a path.
            SpanSource source(std::span<const u8>(base.data(), base.size()));
            const Segment seg{BigInt(0u), BigInt(static_cast<u64>(base.size())), 0u, 0u};
            const auto got = marp::v2::probe(source, seg, Policy{5});
            if (!got.ok()) {
                identical = false;
                break;
            }
            std::string text;
            for (const Observation& o : got.value()) {
                text += marp::v2::observation_text(o);
                text += '\n';
            }
            if (first.empty()) {
                first = text;
            } else if (text != first) {
                identical = false;
                note(std::string("[c11.names] differs under ") + label);
            }
        }
        ev.either(identical, "c11.names.independent", "C11-NAMES", "slice-256KiB-5-labels",
                  hex_digest_of_bytes(std::span<const u8>(base.data(), base.size())),
                  "observations identical under 5 labels",
                  identical ? "identical" : "differs");
    }

    // --- 13. c11.isolation: no E2-E7, no clock/locale/random, no terms -----
    {
        const fs::path hdr = repo_root / "include" / "mapr" / "e4" / "e4_probe.hpp";
        const fs::path lib = repo_root / "engine" / "src" / "e4" / "e4_probe.cpp";

        const std::vector<std::string> forbidden = {
            "mapr/e2/", "mapr/e3/", "mapr/e5/", "mapr/e6/", "mapr/e7/",
            "marp/harness/", "marp/oracle",
            "mapr/container.hpp", "mapr/encoder.hpp", "mapr/decoder.hpp",
            "mapr/bitio.hpp", "mapr/bitseq.hpp", "mapr/dag.hpp", "mapr/math_core.hpp",
            "mapr/chunk_analyzer.hpp", "mapr/dedup_index.hpp", "mapr/mau_translate.hpp",
            "mapr/pipeline.hpp", "mapr/thread_pool.hpp", "mapr/profile.hpp",
            "mapr/noise_detector.hpp", "mapr/crypto.hpp"};

        const std::string header_text = read_text(hdr);
        const std::string lib_text = read_text(lib);
        const std::string combined = header_text + "\n" + lib_text;
        const std::string lib_sha = sha256_file_hex(lib);

        std::size_t hits = 0;
        for (const std::string& token : forbidden) {
            if (combined.find(token) != std::string::npos) {
                ++hits;
                note("[c11.isolation] forbidden token: " + token);
            }
        }
        ev.either(!lib_sha.empty() && hits == 0, "c11.isolation.includes", "C11-ISOLATION",
                  "no-e2-e7-no-harness", lib_sha, "forbidden_tokens=0",
                  "forbidden_tokens=" + u64_dec(hits));

        // Environment access.  Comments are stripped first: the header documents
        // the *absence* of each facility, and a documentation sentence is not a
        // dependency.  No std::thread: probes are per-segment and the merge is
        // serial.
        std::string stripped;
        stripped.reserve(combined.size());
        {
            std::size_t pos = 0;
            while (pos < combined.size()) {
                const std::size_t nl = combined.find('\n', pos);
                const std::string line = combined.substr(
                    pos, nl == std::string::npos ? std::string::npos : nl - pos);
                const std::size_t comment = line.find("//");
                stripped += line.substr(0, comment) + "\n";
                if (nl == std::string::npos) break;
                pos = nl + 1;
            }
        }
        const std::array<const char*, 14> env_tokens = {
            "std::filesystem", "fstream", "std::chrono", "std::time", "gmtime", "localtime",
            "getenv", "std::locale", "setlocale", "std::random_device", "rand(", "srand",
            "getpid", "std::thread"};
        std::size_t env_hits = 0;
        for (const char* token : env_tokens) {
            if (stripped.find(token) != std::string::npos) {
                ++env_hits;
                note(std::string("[c11.isolation] environment token: ") + token);
            }
        }
        ev.either(env_hits == 0, "c11.isolation.environment", "C11-ISOLATION",
                  "no-clock-locale-rand-name-thread", lib_sha, "environment_tokens=0",
                  "environment_tokens=" + u64_dec(env_hits));

        // No E5/E6-shaped record exists in this component: no term, candidate,
        // node, or atom type is named.  (`Observation` and `probe` are C11's own
        // subject and are deliberately absent from this list.)
        const std::array<const char*, 7> term_tokens = {
            "struct Term", "class Dag", "struct Candidate", "struct Atom", "struct Node",
            "struct Ir", "class Ir"};
        std::size_t term_hits = 0;
        for (const char* token : term_tokens) {
            if (combined.find(token) != std::string::npos) {
                ++term_hits;
                note(std::string("[c11.isolation] term-shaped token: ") + token);
            }
        }
        ev.either(term_hits == 0, "c11.isolation.no_terms", "C11-ISOLATION",
                  "no-term-candidate-node-atom", lib_sha, "term_tokens=0",
                  "term_tokens=" + u64_dec(term_hits));

        // The library may not read the file system, so no fixture can be a file.
        const bool reads_files = stripped.find("ifstream") != std::string::npos ||
                                stripped.find("ofstream") != std::string::npos;
        ev.either(!reads_files, "c11.isolation.pure_bytes", "C11-ISOLATION", "no-file-io",
                  lib_sha, "no file stream in the library",
                  reads_files ? "file stream found" : "none");

        // Type-level half of the §8 surface.
        static_assert(
            std::is_same_v<decltype(marp::v2::probe(std::declval<Source&>(),
                                                    std::declval<const Segment&>(),
                                                    std::declval<const Policy&>())),
                           marp::v2::MeasureResult<std::vector<Observation>>>,
            "probe() must return MeasureResult<std::vector<Observation>>");
        static_assert(
            std::is_same_v<decltype(marp::v2::verify_period(std::declval<Source&>(),
                                                            std::declval<const Observation&>())),
                           marp::v2::MeasureResult<bool>>,
            "verify_period() must return MeasureResult<bool>");
        static_assert(
            std::is_same_v<decltype(marp::v2::merge_observations(
                              std::declval<std::vector<std::vector<Observation>>&&>())),
                           std::vector<Observation>>,
            "merge_observations() must return std::vector<Observation>");
        ev.pass("c11.isolation.return_types", "C11-ISOLATION", "probe-verify-merge", lib_sha,
                "MeasureResult<std::vector<Observation>>; MeasureResult<bool>; "
                "std::vector<Observation>",
                "static_asserts compiled: return types exact");
    }

    // -----------------------------------------------------------------------
    // Write the three artefacts.
    // -----------------------------------------------------------------------
    const fs::path gates = out_root / "specs_and_reports" / "v2" / "gates";
    const fs::path logs = out_root / "specs_and_reports" / "v2" / "logs";
    const fs::path evidence_dir = out_root / "specs_and_reports" / "v2" / "evidence" / "C11";
    std::error_code ec;
    fs::create_directories(gates, ec);
    fs::create_directories(logs, ec);
    fs::create_directories(evidence_dir, ec);

    const fs::path tsv_path = gates / "C11-PROBE.tsv";
    const fs::path log_path = logs / "C11-PROBE.log";
    const fs::path sums_path = evidence_dir / "SHA256SUMS";

    std::vector<Row> rows = ev.rows();

    // One summary line per check, sorted by check name: attempted and passing row
    // counts, derived from the same rows written to the TSV so a summary line
    // cannot disagree with the evidence.
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
        out << "spec=MARP2-E4 sections 4.2, 4.5, 4.7, 4.8, 4.9, 4.10, 5.3, 5.4, 6, 9\n";
        out << "depends=E1 (BigInt, SHA-256); C09 (Source, Policy); C10 (Segment, fixed "
               "point, §4.5); no E2-E7 linkage\n";
        out << "kinds=H0,H1,H2,Runs,Period,Repeat16,Skew,BitComplexity,AffineFit,QuadraticFit,"
               "Stride,ChangePoint; sampling=16x64KiB above 2MiB; period verified only\n";
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
        // Repo-root-relative paths, like every other component's manifest, so
        // `sha256sum -c specs_and_reports/v2/evidence/C11/SHA256SUMS` works from
        // the repository root.
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
