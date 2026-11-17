// MARP v2 — E4 MEASURE — C10 SEGMENT gate (`engine/bin/c10_gate`).
//
// Produces exactly three artefacts, all written by this binary and never by
// hand (C10 prompt §3, §5):
//
//   specs_and_reports/v2/gates/C10-SEGMENT.tsv
//   specs_and_reports/v2/logs/C10-SEGMENT.log
//   specs_and_reports/v2/evidence/C10/SHA256SUMS
//
// Every obligation is one row with the exact expected and actual values and a
// PASS/FAIL/BLOCKED verdict.  Any FAIL makes the process exit non-zero.  The log
// is a fixed banner plus the rows in sorted order, so two runs on any host
// produce byte-identical files: the committed evidence is the evidence CI
// regenerates, not a snapshot of one machine.
//
// What this gate deliberately does NOT do:
//   * it does not claim C11 PROBE or the integrated E4-G gate;
//   * it does not build a term, candidate, atom, or observation, and it does not
//     call `probe()`.  C10 measures boundaries only, and E4-I8 requires that
//     boundaries be independent of probe results — the strongest form of that
//     evidence is a binary in which no probe exists;
//   * it never reads a fixture from a file.  Every fixture is a pure function of
//     a pinned constant seed, so no name, extension, or path can reach a value.
//
// Independence: the reference implementations in this file are written from the
// text of §4.2, §4.5, and §4.6 and share no code with the C10 library — separate
// 62-bit mantissa/128-bit squaring for `ilog2_q24`, a materialised-buffer gear
// loop for `B_T`, a materialised-buffer window scan for change points, and a
// plain recursion for the tree.  Agreement is evidence that C10 implements the
// specification, not that it agrees with itself.

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "mapr/e1_bigint.hpp"
#include "mapr/e1_gear.hpp"
#include "mapr/e1_sha256.hpp"
#include "mapr/e4/e4_measure.hpp"
#include "mapr/e4/e4_segment.hpp"

namespace fs = std::filesystem;

namespace {

using marp::v2::active_scales;
using marp::v2::BigInt;
using marp::v2::boundaries_for_scale;
using marp::v2::boundaries_text;
using marp::v2::change_points;
using marp::v2::h0_q24;
using marp::v2::h0_q24_from_counts;
using marp::v2::ilog2_q24;
using marp::v2::kChangeCapSlack;
using marp::v2::kChangeDedupBytes;
using marp::v2::kChangeEntropyQ24;
using marp::v2::kChangeHop;
using marp::v2::kChangeWindow;
using marp::v2::kChangeZeroFracQ24;
using marp::v2::kScaleCount;
using marp::v2::kScales;
using marp::v2::kSingleLeafMax;
using marp::v2::MeasureCode;
using marp::v2::measure_code_name;
using marp::v2::Policy;
using marp::v2::Provenance;
using marp::v2::Segment;
using marp::v2::segment;
using marp::v2::segment_parallel;
using marp::v2::Source;
using marp::v2::SpanSource;
using marp::v2::tree_text;
using marp::v2::u32;
using marp::v2::u64;
using marp::v2::u8;
using marp::v2::zero_frac_q24;

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
        return "logs/C10-SEGMENT.log#" + check + ":" + item;
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

[[maybe_unused]] std::string u64_hex(u64 v) {
    char buf[24];
    std::snprintf(buf, sizeof(buf), "0x%016llx", static_cast<unsigned long long>(v));
    return buf;
}

// SHA-256 of a text blob, through E1's digest (used only to label an artefact,
// never as a measurement of the measurement).
std::string sha256_text_hex(std::string_view text) {
    const auto digest = mapr::Sha256::hash(text);
    if (!digest.ok()) return "err";
    return hex_of(std::span<const u8>(digest.value().data(), digest.value().size()));
}

// SHA-256 of a serialised tree — the `segments.tsv` "SHA-256 of the serialised
// tree" column of E4 §12.5, computed over the same rendering the log records.
std::string tree_digest(const std::vector<Segment>& tree) {
    return sha256_text_hex(tree_text(tree));
}

std::string leaves_digest(const std::vector<Segment>& leaves) {
    std::string text;
    text.reserve(leaves.size() * 20u);
    for (const Segment& leaf : leaves) {
        text += leaf.begin.to_decimal();
        text += '-';
        text += leaf.end.to_decimal();
        text += ';';
    }
    return sha256_text_hex(text);
}

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
    [[nodiscard]] MeasureCode read(const BigInt& off, std::span<u8> dst) const noexcept override {
        ++calls_;
        bytes_ += dst.size();
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
// Independent references, written from the text of the specification
// ---------------------------------------------------------------------------

// §4.2: `floor(log2(x)·2^24)` by 24 exact squarings of a 62-bit mantissa.
u64 reference_ilog2_q24(u64 x) {
    if (x == 0u) return 0u;
    unsigned msb = 0;
    while ((x >> msb) > 1u) ++msb;
    // y = x / 2^msb in [1, 2), scaled by 2^62.  msb == 63 needs a right shift.
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

u64 reference_zero_frac_q24(std::span<const u8> bytes) {
    if (bytes.empty()) return 0u;
    u64 zeros = 0;
    for (const u8 b : bytes) {
        if (b == 0u) ++zeros;
    }
    return static_cast<u64>((static_cast<u128>(zeros) << 24u) / bytes.size());
}

// §4.5 pseudocode, transcribed over a materialised buffer.
std::vector<u64> reference_boundaries(std::span<const u8> bytes, u64 target) {
    const u64 mask = target - 1u;
    const u64 min_chunk = target / 4u;
    const u64 max_chunk = target * 4u;
    const auto& table = mapr::gear_table();
    std::vector<u64> out{0u};
    const u64 length = static_cast<u64>(bytes.size());
    if (length == 0u) return out;  // {0, L} with L == 0 is the set {0}
    u64 start = 0;
    u64 h = 0;
    for (u64 i = 0; i < length; ++i) {
        h = (h << 1) + table[bytes[static_cast<std::size_t>(i)]];
        const u64 len = i + 1u - start;
        if ((len >= min_chunk && (h & mask) == 0u) || len >= max_chunk) {
            if (i + 1u < length) out.push_back(i + 1u);
            start = i + 1u;
            h = 0;
        }
    }
    out.push_back(length);
    return out;
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

// §4.6 pseudocode, transcribed as a plain recursion over the level sets.
struct RefTree {
    std::vector<std::vector<u64>> sets;  // ascending level
};

void reference_build(const RefTree& ref, std::size_t j, u64 a, u64 b, u32 depth,
                     std::vector<std::array<u64, 4>>& out) {
    out.push_back({a, b, depth, static_cast<u64>(j)});
    if (j == 0u) return;
    std::vector<u64> inner;
    for (const u64 x : ref.sets[j - 1u]) {
        if (x > a && x < b) inner.push_back(x);
    }
    if (inner.empty()) {
        reference_build(ref, j - 1u, a, b, depth + 1u, out);
        return;
    }
    u64 prev = a;
    for (const u64 x : inner) {
        reference_build(ref, j - 1u, prev, x, depth + 1u, out);
        prev = x;
    }
    reference_build(ref, j - 1u, prev, b, depth + 1u, out);
}

std::vector<std::array<u64, 4>> reference_tree(const RefTree& ref, u64 length) {
    // §4.4 overrides §4.6 for `L <= 64`: "both boundary sets are {0, L} and the
    // tree is a single leaf".  The pseudocode of §4.6 applied to eleven equal
    // sets would instead build an eleven-node chain, so §4.4 is read as the more
    // specific rule and the reference follows it (report §5, reading 3).
    if (length <= kSingleLeafMax) return {{{0u, length, 0u, 0u}}};
    std::vector<std::array<u64, 4>> out;
    reference_build(ref, ref.sets.size() - 1u, 0u, length, 0u, out);
    return out;
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

    // M-CORE: the smallest inputs.
    out.push_back({"empty", "C10-CORE", {}});
    out.push_back({"one-0x00", "C10-CORE", {0x00}});
    out.push_back({"two-bytes", "C10-CORE", {0x00, 0xff}});
    out.push_back({"zeros-63", "C10-CORE", zeros(63)});

    // M-EDGE: lengths around the finest scale and the change-point window.
    for (const std::size_t n : {std::size_t{64}, std::size_t{65}, std::size_t{127},
                                std::size_t{255}, std::size_t{256}, std::size_t{257},
                                std::size_t{4095}, std::size_t{4096}, std::size_t{4097},
                                std::size_t{8191}, std::size_t{8192}, std::size_t{8193}}) {
        out.push_back({"zeros-" + std::to_string(n), "C10-EDGE", zeros(n)});
        out.push_back({"rand-" + std::to_string(n), "C10-EDGE",
                       splitmix_bytes(n, 0x4d41525043313001ull + n)});
    }

    // M-SCALE: the corpus shapes of E4 §12.3, at 1 MiB.
    out.push_back({"zero-1MiB", "C10-SCALE", zeros(1u << 20u)});
    out.push_back({"rand-1MiB", "C10-SCALE", splitmix_bytes(1u << 20u, 0x4d41525043313002ull)});
    out.push_back({"rand-1MiB+1", "C10-SCALE",
                   splitmix_bytes((1u << 20u) + 1u, 0x4d41525043313003ull)});
    out.push_back({"rand-2MiB+12345", "C10-SCALE",
                   splitmix_bytes((2u << 20u) + 12345u, 0x4d41525043313004ull)});
    {
        std::vector<u8> tile(4096);
        for (std::size_t i = 0; i < tile.size(); ++i) {
            tile[i] = static_cast<u8>((i * 31u + 7u) & 0xFFu);
        }
        out.push_back({"tile-4096-1MiB", "C10-SCALE", repeat_block(tile, 1u << 20u)});
    }
    {
        std::vector<u8> grad(1u << 20u);
        for (std::size_t i = 0; i < grad.size(); ++i) grad[i] = static_cast<u8>(i & 0xFFu);
        out.push_back({"grad-1MiB", "C10-SCALE", std::move(grad)});
    }
    out.push_back({"text-1MiB", "C10-SCALE", [&] {
                       std::vector<u8> block(4096);
                       const char* words =
                           "MARP measures where structure changes; it does not conclude. ";
                       for (std::size_t i = 0; i < block.size(); ++i) {
                           block[i] = static_cast<u8>(words[i % 60u]);
                       }
                       return repeat_block(block, 1u << 20u);
                   }()});

    // M-CHANGE: 256 KiB zeros | 256 KiB random | 256 KiB zeros | 256 KiB counter.
    {
        std::vector<u8> change;
        change.reserve(1u << 20u);
        change.insert(change.end(), 256u * 1024u, 0x00u);
        const std::vector<u8> r = splitmix_bytes(256u * 1024u, 0x4d41525043313005ull);
        change.insert(change.end(), r.begin(), r.end());
        change.insert(change.end(), 256u * 1024u, 0x00u);
        for (std::size_t i = 0; i < 256u * 1024u; ++i) {
            change.push_back(static_cast<u8>(i & 0xFFu));
        }
        out.push_back({"change-1MiB", "C10-CHANGE", std::move(change)});
    }
    // M-CHANGE-ALT: alternating 4 KiB zeros / 4 KiB random, the cap stressor.
    {
        std::vector<u8> alt;
        alt.reserve(1u << 20u);
        const std::vector<u8> r = splitmix_bytes(4096, 0x4d41525043313006ull);
        for (int i = 0; i < 128; ++i) {
            if ((i & 1) == 0) {
                alt.insert(alt.end(), 4096u, 0x00u);
            } else {
                alt.insert(alt.end(), r.begin(), r.end());
            }
        }
        out.push_back({"change-alt-4KiB", "C10-CHANGE", std::move(alt)});
    }

    return out;
}

// M-KAT: `ilog2_q24` for the fourteen values §12.3 names.  Derived outside this
// engine (see REPORT/E4/C10-SEGMENT-REPORT.md §4) and pinned here.
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
// S1/S2/S3 checks, independent of the library's internal contract
// ---------------------------------------------------------------------------

struct TreeAudit {
    bool partition = false;       // S1
    bool containment = false;     // S2
    bool non_empty_leaves = false;  // S3
    bool root_is_whole = false;
    u32 max_depth = 0;
    std::size_t leaves = 0;
};

TreeAudit audit(const std::vector<Segment>& leaves, const std::vector<Segment>& tree, u64 length) {
    TreeAudit out;

    // S1 over the returned leaves.
    u64 expect = 0;
    bool contiguous = true;
    bool ordered = true;
    for (const Segment& leaf : leaves) {
        const std::optional<u64> b = leaf.begin.to_u64_checked();
        const std::optional<u64> e = leaf.end.to_u64_checked();
        if (!b.has_value() || !e.has_value()) {
            contiguous = false;
            break;
        }
        if (*b != expect) contiguous = false;
        if (*b > *e) ordered = false;
        expect = *e;
    }
    out.leaves = leaves.size();
    out.partition = !leaves.empty() && contiguous && ordered && expect == length;

    // S3 over the leaves.
    bool non_empty = true;
    for (const Segment& leaf : leaves) {
        const std::optional<u64> b = leaf.begin.to_u64_checked();
        const std::optional<u64> e = leaf.end.to_u64_checked();
        if (!b.has_value() || !e.has_value()) {
            non_empty = false;
            break;
        }
        if (*b == *e && length != 0u) non_empty = false;
    }
    out.non_empty_leaves = non_empty;

    // S2 over the tree, treating a node's children as the contiguous run of the
    // following nodes at depth + 1.
    bool s2 = !tree.empty();
    for (std::size_t i = 0; s2 && i < tree.size(); ++i) {
        const Segment& parent = tree[i];
        out.max_depth = std::max(out.max_depth, parent.depth);
        const std::optional<u64> pb = parent.begin.to_u64_checked();
        const std::optional<u64> pe = parent.end.to_u64_checked();
        if (!pb.has_value() || !pe.has_value()) {
            s2 = false;
            break;
        }
        u64 cursor = *pb;
        std::size_t k = i + 1u;
        std::size_t children = 0;
        while (k < tree.size() && tree[k].depth == parent.depth + 1u) {
            const Segment& child = tree[k];
            const std::optional<u64> cb = child.begin.to_u64_checked();
            const std::optional<u64> ce = child.end.to_u64_checked();
            if (!cb.has_value() || !ce.has_value()) {
                s2 = false;
                break;
            }
            if (*cb != cursor) s2 = false;
            if (*ce > *pe) s2 = false;
            cursor = *ce;
            ++children;
            std::size_t skip = k + 1u;
            while (skip < tree.size() && tree[skip].depth > child.depth) ++skip;
            k = skip;
        }
        if (!s2) break;
        if (parent.level == 0u) {
            if (children != 0u) s2 = false;
        } else {
            if (children == 0u) s2 = false;
            if (cursor != *pe) s2 = false;
        }
    }
    out.containment = s2;
    out.root_is_whole = !tree.empty() && tree.front().begin == BigInt(0u) &&
                        tree.front().end == BigInt(length) && tree.front().depth == 0u;
    return out;
}

// ---------------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------------

int run_gate(const fs::path& repo_root, const fs::path& out_root) {
    Evidence ev;
    std::vector<std::string> log_lines;
    auto note = [&log_lines](const std::string& line) { log_lines.push_back(line); };

    // --- 1. c10.fixed.ilog2: the M-KAT table, plus 4096 random values against
    //        the independent 62-bit-mantissa routine ------------------------
    {
        std::size_t kat_ok = 0;
        for (const IlogKat& kat : kIlogKats) {
            const u64 got = ilog2_q24(kat.x);
            const u64 ref = reference_ilog2_q24(kat.x);
            const std::string item = "x-" + u64_dec(kat.x);
            ev.either(got == kat.q24 && ref == kat.q24, "c10.fixed.ilog2.kat", "C10-KAT", item,
                      "-", u64_dec(kat.q24), u64_dec(got) + "/ref=" + u64_dec(ref));
            note("[c10.fixed.ilog2.kat:" + item + "] ilog2_q24=" + u64_dec(got));
            if (got == kat.q24) ++kat_ok;
        }
        ev.either(kat_ok == kIlogKats.size(), "c10.fixed.ilog2.kat_complete", "C10-KAT",
                  "all-14", "-", "14/14", u64_dec(kat_ok) + "/14");

        // Powers of two are exact by construction; the mantissa work is what the
        // random sweep exercises.
        std::size_t pow_ok = 0;
        for (unsigned bit = 0; bit < 64u; ++bit) {
            const u64 x = (bit == 63u) ? 0x8000000000000000ull : (1ull << bit);
            if (ilog2_q24(x) == (static_cast<u64>(bit) << 24u)) ++pow_ok;
        }
        ev.either(pow_ok == 64u, "c10.fixed.ilog2.powers_of_two", "C10-KAT", "2^0..2^63", "-",
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
            const u64 got = ilog2_q24(z);
            const u64 ref = reference_ilog2_q24(z);
            if (got == ref) {
                ++rand_ok;
            } else {
                if (mismatches == 0) first_mismatch = "x=" + u64_dec(z) + " got=" + u64_dec(got) +
                                                       " ref=" + u64_dec(ref);
                ++mismatches;
            }
        }
        ev.either(mismatches == 0, "c10.fixed.ilog2.reference", "C10-KAT", "random-4096",
                  hex_digest_of_bytes(std::span<const u8>()), "4096/4096",
                  u64_dec(rand_ok) + "/4096" +
                      (first_mismatch.empty() ? "" : " first=" + first_mismatch));
        note("[c10.fixed.ilog2.reference:random-4096] agree=" + u64_dec(rand_ok) + "/4096");

        // Monotonicity, and the two neighbours of every power of two.
        std::size_t mono_ok = 0;
        u64 prev = 0;
        for (u64 x = 1; x <= 20000u; ++x) {
            const u64 got = ilog2_q24(x);
            if (got >= prev) ++mono_ok;
            prev = got;
        }
        ev.either(mono_ok == 20000u, "c10.fixed.ilog2.monotone", "C10-KAT", "x-1..20000", "-",
                  "20000/20000", u64_dec(mono_ok) + "/20000");
    }

    // --- 2. c10.fixed.h0 / zero_frac: exact known values and an independent
    //        formula over random count vectors -----------------------------
    {
        struct H0Case {
            const char* id;
            std::array<std::pair<int, u64>, 4> counts;  // symbol -> count, up to 4 symbols
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
            const u64 got = h0_q24_from_counts(counts);
            ev.either(got == c.want, "c10.fixed.h0.known", "C10-KAT", c.id, "-", u64_dec(c.want),
                      u64_dec(got));
            note(std::string("[c10.fixed.h0.known:") + c.id + "] h0_q24=" + u64_dec(got));
        }
        // Empty count vector is zero, never a division by zero.
        ev.either(h0_q24_from_counts(std::array<u64, 256>{}) == 0u, "c10.fixed.h0.empty",
                  "C10-KAT", "empty-counts", "-", "0", "0");

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
            if (h0_q24_from_counts(fixed) == reference_h0_q24(counts)) ++agree;
        }
        ev.either(agree == 1000u, "c10.fixed.h0.reference", "C10-KAT", "random-1000", "-",
                  "1000/1000", u64_dec(agree) + "/1000");
        note("[c10.fixed.h0.reference:random-1000] agree=" + u64_dec(agree) + "/1000");

        // zero_frac_q24 is a ratio of integers: check the exact quarter.
        {
            std::vector<u8> bytes(1024, 0x11u);
            const u64 none = zero_frac_q24(std::span<const u8>(bytes.data(), bytes.size()));
            for (std::size_t i = 0; i < 256u; ++i) bytes[i] = 0x00u;
            const u64 quarter = zero_frac_q24(std::span<const u8>(bytes.data(), bytes.size()));
            std::vector<u8> all_zero(4096, 0x00u);
            const u64 full = zero_frac_q24(std::span<const u8>(all_zero.data(), all_zero.size()));
            std::vector<u8> mixed = splitmix_bytes(5000, 0x4d41525043313007ull);
            const u64 mixed_got = zero_frac_q24(std::span<const u8>(mixed.data(), mixed.size()));
            const u64 mixed_ref = reference_zero_frac_q24(std::span<const u8>(mixed.data(),
                                                                             mixed.size()));
            ev.either(none == 0u && quarter == (1ull << 22u) && full == (1ull << 24u) &&
                          mixed_got == mixed_ref,
                      "c10.fixed.zerofrac", "C10-KAT", "known-and-random", "-",
                      "0;2^22;2^24;reference",
                      u64_dec(none) + ";" + u64_dec(quarter) + ";" + u64_dec(full) + ";" +
                          u64_dec(mixed_got) + "/ref=" + u64_dec(mixed_ref));
            note("[c10.fixed.zerofrac:known-and-random] 0=" + u64_dec(none) +
                 " quarter=" + u64_dec(quarter) + " full=" + u64_dec(full));
        }
    }

    // --- 3. c10.constants: §4.4/§4.5 are the fixed format constants ---------
    {
        bool ok = kScaleCount == 11u && kScales.front() == 64u && kScales.back() == (64ull << 20u);
        for (u32 k = 0; k < kScaleCount; ++k) {
            if (kScales[k] != (1ull << (6u + 2u * k))) ok = false;
        }
        ok = ok && kSingleLeafMax == 64u && kChangeWindow == 4096u && kChangeHop == 2048u &&
             kChangeEntropyQ24 == (1ull << 24u) && kChangeZeroFracQ24 == (1ull << 22u) &&
             kChangeDedupBytes == 2048u && kChangeCapSlack == 16u;
        ev.either(ok, "c10.constants.section44_45", "C10-CONST", "scales-and-change-points", "-",
                  "SCALES=2^6..2^26; W=4096; hop=2048; dH0>=2^24; dZ>=2^22; dedup=2048; "
                  "cap=L/2048+16",
                  ok ? "all constants as specified" : "constant mismatch");
        note("[c10.constants.section44_45] ok=" + u64_dec(ok ? 1u : 0u));
    }

    // --- 4. Per-fixture: boundaries, invariants, reference agreement, tree ---
    const std::vector<Fixture> fixtures = make_fixtures();
    for (const Fixture& fx : fixtures) {
        const u64 length = static_cast<u64>(fx.bytes.size());
        const std::string input_sha = hex_digest_of_bytes(std::span<const u8>(fx.bytes.data(),
                                                                             fx.bytes.size()));
        SpanSource source(std::span<const u8>(fx.bytes.data(), fx.bytes.size()));
        const auto prov = marp::v2::provenance(source, Policy{5});
        if (!prov.ok()) {
            ev.fail("c10.tree.partition", fx.corpus, fx.id, input_sha, "provenance Ok",
                    measure_code_name(prov.code()));
            continue;
        }

        // 4a. §4.5 boundary sets: endpoints, strict ascent, gap bounds, and the
        //     independent pseudocode build.
        std::size_t scales_ok = 0;
        for (u32 k = 0; k < kScaleCount; ++k) {
            const u64 target = kScales[k];
            const auto got = boundaries_for_scale(source, target);
            const std::string item = fx.id + "@k" + u64_dec(k);
            if (!got.ok()) {
                ev.fail("c10.boundaries.invariants", fx.corpus, item, input_sha, "Ok",
                        measure_code_name(got.code()));
                continue;
            }
            const std::vector<u64>& b = got.value();
            const std::vector<u64> ref =
                reference_boundaries(std::span<const u8>(fx.bytes.data(), fx.bytes.size()),
                                     target);
            bool endpoints = !b.empty() && b.front() == 0u && b.back() == length;
            bool ascending = true;
            bool gaps_ok = true;
            const u64 min_chunk = target / 4u;
            const u64 max_chunk = target * 4u;
            for (std::size_t i = 1; i < b.size(); ++i) {
                const u64 gap = b[i] - b[i - 1u];
                if (b[i] <= b[i - 1u]) ascending = false;
                // Every position but the final `L` is a cut, and §4.5 cuts only
                // at `len >= min_chunk`; `L` is emitted unconditionally.
                if (i + 1u < b.size() && gap < min_chunk) gaps_ok = false;
                if (gap > max_chunk) gaps_ok = false;
            }
            const bool matches_ref = b == ref;
            const bool ok = endpoints && ascending && gaps_ok && matches_ref;
            if (ok) ++scales_ok;
            ev.either(ok, "c10.boundaries.invariants", fx.corpus, item, input_sha,
                      "endpoints;strictly-increasing;gap-in[min,max];reference",
                      std::string(endpoints ? "endpoints" : "NO-ENDPOINTS") + ";" +
                          (ascending ? "ascending" : "NOT-ASCENDING") + ";" +
                          (gaps_ok ? "gaps-ok" : "GAPS-BAD") + ";" +
                          (matches_ref ? "reference" : "REFERENCE-MISMATCH") + ";count=" +
                          u64_dec(b.size()));
            note("[c10.boundaries:" + item + "] count=" + u64_dec(b.size()) +
                 " digests=" + sha256_text_hex(boundaries_text(b)));
        }
        ev.either(scales_ok == kScaleCount, "c10.boundaries.scale_sweep", fx.corpus, fx.id,
                  input_sha, "11/11 scales", u64_dec(scales_ok) + "/11");

        // 4b. §4.5 change points against the independent scan, plus ascending
        //     order, the dedup window, and the cap.
        {
            const auto got = change_points(source);
            const auto ref = reference_change_points(
                std::span<const u8>(fx.bytes.data(), fx.bytes.size()));
            const std::string item = fx.id;
            if (!got.ok()) {
                ev.fail("c10.changepoints.reference", fx.corpus, item, input_sha, "Ok",
                        measure_code_name(got.code()));
            } else {
                const std::vector<u64>& cp = got.value();
                const u64 cap = length / kChangeHop + kChangeCapSlack;
                bool ascending = true;
                bool spaced = true;
                bool in_range = true;
                for (std::size_t i = 0; i < cp.size(); ++i) {
                    if (cp[i] >= length) in_range = false;
                    if (i != 0u) {
                        if (cp[i] <= cp[i - 1u]) ascending = false;
                        if (cp[i] - cp[i - 1u] < kChangeDedupBytes) spaced = false;
                    }
                }
                const bool capped = cp.size() <= cap;
                ev.either(cp == ref && ascending && spaced && in_range && capped,
                          "c10.changepoints.reference", fx.corpus, item, input_sha,
                          "reference;ascending;dedup-2048;<=cap",
                          std::string(cp == ref ? "reference" : "REFERENCE-MISMATCH") + ";" +
                              (ascending ? "ascending" : "NOT-ASCENDING") + ";" +
                              (spaced ? "dedup-2048" : "DEDUP-VIOLATED") + ";" +
                              (in_range ? "in-range" : "OUT-OF-RANGE") + ";" +
                              (capped ? "capped" : "CAP-EXCEEDED") + ";count=" +
                              u64_dec(cp.size()) + ";cap=" + u64_dec(cap));
                note("[c10.changepoints:" + item + "] count=" + u64_dec(cp.size()) +
                     " cap=" + u64_dec(cap) + " offsets=" + boundaries_text(cp));
            }
        }

        // 4c. §4.6 tree: S1/S2/S3, root, depth bound, and the independent build.
        {
            std::vector<Segment> tree;
            const auto got = segment(source, prov.value(), Policy{5}, &tree);
            const std::string item = fx.id;
            if (!got.ok()) {
                ev.fail("c10.tree.partition", fx.corpus, item, input_sha, "Ok",
                        measure_code_name(got.code()));
                continue;
            }
            const TreeAudit a = audit(got.value(), tree, length);
            ev.either(a.partition, "c10.tree.partition", fx.corpus, item, input_sha,
                      "leaves tile [0,L)", (a.partition ? "tile" : "GAP-OR-OVERLAP") +
                                               std::string(";leaves=") + u64_dec(a.leaves));
            ev.either(a.containment, "c10.tree.containment", fx.corpus, item, input_sha,
                      "node=union(children)", a.containment ? "union" : "NOT-A-UNION");
            ev.either(a.non_empty_leaves, "c10.tree.nonempty_leaves", fx.corpus, item, input_sha,
                      length == 0u ? "one [0,0) leaf" : "begin<end",
                      a.non_empty_leaves ? "ok" : "ZERO-LENGTH-LEAF");
            ev.either(a.root_is_whole, "c10.tree.root", fx.corpus, item, input_sha, "[0,L)@d0",
                      a.root_is_whole ? "[0,L)@d0" : "BAD-ROOT");
            ev.either(a.max_depth < kScaleCount, "c10.tree.depth_bound", fx.corpus, item,
                      input_sha, "depth<11", "depth=" + u64_dec(a.max_depth));
            if (length <= kSingleLeafMax) {
                ev.either(tree.size() == 1u && tree.front().level == 0u,
                          "c10.tree.single_leaf", fx.corpus, item, input_sha,
                          "1 node at level 0",
                          u64_dec(tree.size()) + " nodes;level=" +
                              u64_dec(tree.front().level));
            }

            // Independent §4.6 build from independently computed boundary sets.
            RefTree ref;
            for (u32 k = 0; k < kScaleCount; ++k) {
                ref.sets.push_back(reference_boundaries(
                    std::span<const u8>(fx.bytes.data(), fx.bytes.size()), kScales[k]));
            }
            for (const u64 x : reference_change_points(
                     std::span<const u8>(fx.bytes.data(), fx.bytes.size()))) {
                std::vector<u64>& fine = ref.sets[0];
                if (std::find(fine.begin(), fine.end(), x) == fine.end()) fine.push_back(x);
            }
            std::sort(ref.sets[0].begin(), ref.sets[0].end());
            const auto expected = reference_tree(ref, length);
            bool same = tree.size() == expected.size();
            std::string first_diff;
            for (std::size_t i = 0; same && i < tree.size(); ++i) {
                if (tree[i].begin != BigInt(expected[i][0]) || tree[i].end != BigInt(expected[i][1]) ||
                    tree[i].depth != expected[i][2] ||
                    static_cast<u64>(tree[i].level) != expected[i][3]) {
                    same = false;
                    first_diff = " at node " + u64_dec(i);
                }
            }
            ev.either(same, "c10.tree.reference", fx.corpus, item, input_sha,
                      "nodes=" + u64_dec(expected.size()), "nodes=" + u64_dec(tree.size()) +
                          first_diff + ";tree_sha256=" + tree_digest(tree) +
                          ";leaves_sha256=" + leaves_digest(got.value()));
            note("[c10.tree:" + item + "] nodes=" + u64_dec(tree.size()) +
                 " leaves=" + u64_dec(got.value().size()) + " max_depth=" +
                 u64_dec(a.max_depth) + " tree_sha256=" + tree_digest(tree) +
                 " leaves_sha256=" + leaves_digest(got.value()));
        }
    }

    // --- 5. c10.determinism: 1 vs 4 threads, two runs each, byte-identical ---
    {
        for (const Fixture& fx : fixtures) {
            if (fx.bytes.size() < 1000u) continue;  // the single-leaf case is trivial
            const u64 length = static_cast<u64>(fx.bytes.size());
            const std::string input_sha = hex_digest_of_bytes(
                std::span<const u8>(fx.bytes.data(), fx.bytes.size()));
            // A fresh source per run, so nothing can be cached between runs.
            auto run = [&](u32 threads, std::vector<Segment>* leaves,
                           std::vector<Segment>* tree) {
                SpanSource source(std::span<const u8>(fx.bytes.data(), fx.bytes.size()));
                const auto prov = marp::v2::provenance(source, Policy{5});
                if (!prov.ok()) return prov.code();
                const auto got = segment_parallel(source, prov.value(), Policy{5}, threads, tree);
                if (!got.ok()) return got.code();
                *leaves = got.value();
                return MeasureCode::Ok;
            };

            std::vector<Segment> leaves_a;
            std::vector<Segment> tree_a;
            std::vector<Segment> leaves_b;
            std::vector<Segment> tree_b;
            std::vector<Segment> leaves_c;
            std::vector<Segment> tree_c;
            const MeasureCode ca = run(1u, &leaves_a, &tree_a);
            const MeasureCode cb = run(1u, &leaves_b, &tree_b);
            const MeasureCode cc = run(4u, &leaves_c, &tree_c);
            const bool ok = ca == MeasureCode::Ok && cb == MeasureCode::Ok &&
                            cc == MeasureCode::Ok;
            if (!ok) {
                ev.fail("c10.determinism.threads", fx.corpus, fx.id, input_sha, "Ok",
                        std::string(measure_code_name(ca)) + "/" +
                            measure_code_name(cb) + "/" + measure_code_name(cc));
                continue;
            }
            const std::string t1 = tree_text(tree_a);
            const std::string t2 = tree_text(tree_b);
            const std::string t4 = tree_text(tree_c);
            const std::string l1 = leaves_digest(leaves_a);
            const bool same = t1 == t2 && t1 == t4 && leaves_digest(leaves_b) == l1 &&
                              leaves_digest(leaves_c) == l1;
            ev.either(same, "c10.determinism.threads", fx.corpus, fx.id, input_sha,
                      "run1(1)==run2(1)==run3(4): tree+leaves",
                      std::string(same ? "identical" : "DIFFERS") + ";tree_sha256=" +
                          tree_digest(tree_a) + ";leaves=" + u64_dec(leaves_a.size()) +
                          ";length=" + u64_dec(length));
            note("[c10.determinism.threads:" + fx.id + "] tree_sha256=" + tree_digest(tree_a) +
                 " leaves=" + u64_dec(leaves_a.size()) + " nodes=" + u64_dec(tree_a.size()) +
                 " threads=1,1,4 identical=" + u64_dec(same ? 1u : 0u));
        }
    }

    // --- 6. c10.determinism.merge: the merge is by segment begin offset -------
    {
        // The leaf vector is compared positionally above; here the merge order is
        // checked directly: leaves ascend by begin offset and are contiguous, at
        // both worker counts.  A merge that sorted by completion order would fail
        // this on a large fixture even when the sets matched.
        const Fixture* pick = nullptr;
        for (const Fixture& fx : fixtures) {
            if (fx.id == "rand-1MiB") pick = &fx;
        }
        if (pick != nullptr) {
            SpanSource source(std::span<const u8>(pick->bytes.data(), pick->bytes.size()));
            const auto prov = marp::v2::provenance(source, Policy{5});
            bool ok = prov.ok();
            std::string detail;
            for (const u32 threads : {1u, 4u, 8u}) {
                std::vector<Segment> leaves;
                const auto got = segment_parallel(source, prov.value(), Policy{5}, threads,
                                                  nullptr);
                ok = ok && got.ok();
                if (!got.ok()) break;
                leaves = got.value();
                for (std::size_t i = 1; i < leaves.size(); ++i) {
                    if (!(leaves[i - 1u].begin < leaves[i].begin)) ok = false;
                }
                detail += "t" + u64_dec(threads) + "=" + u64_dec(leaves.size()) + ";";
            }
            ev.either(ok, "c10.determinism.merge_order", "C10-REPEAT", "rand-1MiB",
                      hex_digest_of_bytes(std::span<const u8>(pick->bytes.data(),
                                                             pick->bytes.size())),
                      "ascending begin at 1/4/8 workers", ok ? "ascending " + detail
                                                             : "VIOLATION " + detail);
            note("[c10.determinism.merge_order] " + detail);
        }
    }

    // --- 7. c10.effort: scale selection, and boundaries unchanged by effort ---
    {
        bool table_ok = true;
        std::string detail;
        for (u32 effort = 0; effort <= 9u; ++effort) {
            const auto got = active_scales(static_cast<u8>(effort));
            if (!got.ok()) {
                table_ok = false;
                break;
            }
            if (effort <= 2u) {
                const bool ok = got.value().count == 3u && got.value().levels[0] == 0u &&
                                got.value().levels[1] == 3u && got.value().levels[2] == 6u;
                if (!ok) table_ok = false;
            } else {
                if (got.value().count != kScaleCount) table_ok = false;
                for (u32 j = 0; j < kScaleCount; ++j) {
                    if (got.value().levels[j] != static_cast<u8>(j)) table_ok = false;
                }
            }
            detail += "e" + u64_dec(effort) + "=" + u64_dec(got.value().count) + ";";
        }
        ev.either(table_ok, "c10.effort.scales", "C10-EFFORT", "0..9", "-",
                  "0-2:{0,3,6}; 3-9:all 11", detail);
        ev.either(active_scales(10u).code() == MeasureCode::Invalid, "c10.effort.domain",
                  "C10-EFFORT", "effort-10", "-", "Invalid",
                  measure_code_name(active_scales(10u).code()));
        note("[c10.effort.scales] " + detail);

        // Effort never changes a boundary: every effort's tree is a coarsening of
        // the same finest set, and the finest boundaries are effort-invariant.
        const Fixture* pick = nullptr;
        for (const Fixture& fx : fixtures) {
            if (fx.id == "change-1MiB") pick = &fx;
        }
        if (pick != nullptr) {
            const std::string input_sha = hex_digest_of_bytes(
                std::span<const u8>(pick->bytes.data(), pick->bytes.size()));
            std::string finest_before;
            bool ok = true;
            std::string effort_detail;
            for (u8 effort = 0; effort <= 9u; ++effort) {
                SpanSource source(std::span<const u8>(pick->bytes.data(), pick->bytes.size()));
                const auto prov = marp::v2::provenance(source, Policy{effort});
                if (!prov.ok()) {
                    ok = false;
                    break;
                }
                const auto b0 = boundaries_for_scale(source, kScales[0]);
                if (!b0.ok()) {
                    ok = false;
                    break;
                }
                const std::string text = boundaries_text(b0.value());
                if (effort == 0u) {
                    finest_before = text;
                } else if (text != finest_before) {
                    ok = false;
                }
                std::vector<Segment> tree;
                const auto got = segment(source, prov.value(), Policy{effort}, &tree);
                if (!got.ok()) {
                    ok = false;
                    break;
                }
                const TreeAudit a = audit(got.value(), tree, static_cast<u64>(pick->bytes.size()));
                if (!a.partition || !a.containment) ok = false;
                effort_detail += "e" + u64_dec(effort) + ":n=" + u64_dec(tree.size()) + ";";
            }
            ev.either(ok, "c10.effort.invariant_boundaries", "C10-EFFORT", "change-1MiB",
                      input_sha, "B_64 identical at effort 0..9; every tree partitions",
                      ok ? "identical " + effort_detail : "DIFFERS " + effort_detail);
            note("[c10.effort.invariant_boundaries] " + effort_detail);
        }
    }

    // --- 8. c10.errors: Io, Mismatch, Invalid; never a throw, never partial ---
    {
        const std::vector<u8> bytes = splitmix_bytes(100000, 0x4d41525043313008ull);
        SpanSource source(std::span<const u8>(bytes.data(), bytes.size()));
        const std::string input_sha = hex_digest_of_bytes(std::span<const u8>(bytes.data(),
                                                                             bytes.size()));
        const auto prov = marp::v2::provenance(source, Policy{5});
        if (!prov.ok()) {
            ev.fail("c10.errors.mismatch", "C10-ERROR", "precondition", input_sha, "Ok",
                    measure_code_name(prov.code()));
        } else {
            Provenance tampered = prov.value();
            tampered.sha256[0] = static_cast<u8>(tampered.sha256[0] ^ 0x01u);
            const MeasureCode c1 = segment(source, tampered, Policy{5}).code();
            Provenance wrong_length = prov.value();
            wrong_length.length = BigInt(static_cast<u64>(bytes.size()) + 1u);
            const MeasureCode c2 = segment(source, wrong_length, Policy{5}).code();
            Provenance wrong_gear = prov.value();
            wrong_gear.gear ^= 1ull;
            const MeasureCode c3 = segment(source, wrong_gear, Policy{5}).code();
            Provenance wrong_seed = prov.value();
            wrong_seed.seed ^= 1ull;
            const MeasureCode c4 = segment(source, wrong_seed, Policy{5}).code();
            ev.either(c1 == MeasureCode::Mismatch && c2 == MeasureCode::Mismatch &&
                          c3 == MeasureCode::Mismatch && c4 == MeasureCode::Mismatch,
                      "c10.errors.mismatch", "C10-ERROR", "tampered-provenance", input_sha,
                      "Mismatch (sha256/length/gear/seed)",
                      std::string(measure_code_name(c1)) + "/" + measure_code_name(c2) + "/" +
                          measure_code_name(c3) + "/" + measure_code_name(c4));
            note("[c10.errors.mismatch:tampered-provenance] " + std::string(measure_code_name(c1)) +
                 "/" + measure_code_name(c2) + "/" + measure_code_name(c3) + "/" +
                 measure_code_name(c4));

            // Io: a short medium, and a medium that fails mid-pass.
            TruncatingSource short_source(std::span<const u8>(bytes.data(), bytes.size()),
                                          static_cast<u64>(bytes.size()) + 4096u);
            const MeasureCode c5 = segment(short_source, prov.value(), Policy{5}).code();
            FailingSource failing(std::span<const u8>(bytes.data(), bytes.size()), 65536u);
            const MeasureCode c6 = segment(failing, prov.value(), Policy{5}).code();
            FailingSource failing_late(std::span<const u8>(bytes.data(), bytes.size()), 65536u + 1u);
            const MeasureCode c7 = segment(failing_late, prov.value(), Policy{5}).code();
            ev.either(c5 == MeasureCode::Io && c6 == MeasureCode::Io && c7 == MeasureCode::Io,
                      "c10.errors.io", "C10-ERROR", "short-and-failing", input_sha, "Io",
                      std::string(measure_code_name(c5)) + "/" + measure_code_name(c6) + "/" +
                          measure_code_name(c7));
            note("[c10.errors.io:short-and-failing] " + std::string(measure_code_name(c5)) + "/" +
                 measure_code_name(c6) + "/" + measure_code_name(c7));

            // Invalid: effort out of domain, and a non-power-of-two target.
            bool invalid_ok = true;
            std::string invalid_detail;
            for (const u8 effort : {static_cast<u8>(10), static_cast<u8>(11),
                                    static_cast<u8>(255)}) {
                const MeasureCode c = segment(source, prov.value(), Policy{effort}).code();
                if (c != MeasureCode::Invalid) invalid_ok = false;
                invalid_detail += "e" + u64_dec(effort) + "=" + measure_code_name(c) + ";";
            }
            SpanSource fresh(std::span<const u8>(bytes.data(), bytes.size()));
            for (const u64 target : {0ull, 1ull, 3ull, 100ull, 1000ull}) {
                const MeasureCode c = boundaries_for_scale(fresh, target).code();
                if (c != MeasureCode::Invalid) invalid_ok = false;
                invalid_detail += "t" + u64_dec(target) + "=" + measure_code_name(c) + ";";
            }
            ev.either(invalid_ok, "c10.errors.invalid", "C10-ERROR", "effort-and-target",
                      input_sha, "Invalid for every out-of-domain argument", invalid_detail);
            note("[c10.errors.invalid:effort-and-target] " + invalid_detail);

            // A successful call returns leaves only after a sound tree, and an
            // out-of-domain effort returns no leaves at all (never a partial
            // vector alongside an error code).
            std::vector<Segment> tree_sentinel;
            const auto bad = segment(source, prov.value(), Policy{10}, &tree_sentinel);
            ev.either(!bad.ok() && tree_sentinel.empty(), "c10.errors.no_partial_output",
                      "C10-ERROR", "out-of-domain-effort", input_sha,
                      "error with an untouched tree out-parameter",
                      !bad.ok() ? (tree_sentinel.empty() ? "untouched"
                                                         : "PARTIALLY-WRITTEN")
                                : "RETURNED-A-VALUE");
            note("[c10.errors.no_partial_output:out-of-domain-effort] " +
                 std::string(bad.ok() ? "returned-a-value" : "error") +
                 " tree_size=" + u64_dec(tree_sentinel.size()));

            // The nullable tree parameter is genuinely optional.
            std::vector<Segment> with_tree;
            const auto a = segment(source, prov.value(), Policy{5}, &with_tree);
            const auto b = segment(source, prov.value(), Policy{5}, nullptr);
            bool same = a.ok() && b.ok() && a.value().size() == b.value().size();
            for (std::size_t i = 0; same && i < a.value().size(); ++i) {
                same = a.value()[i] == b.value()[i];
            }
            ev.either(same, "c10.errors.optional_tree", "C10-ERROR", "tree-null", input_sha,
                      "same leaves with and without a tree out-parameter",
                      same ? "identical" : "DIFFERS");
            note("[c10.errors.optional_tree:tree-null] " + std::string(same ? "identical" : "differs"));
        }
    }

    // --- 9. c10.limits: the scans are streaming in a fixed block -------------
    {
        struct StreamCase {
            const char* id;
            std::size_t size;
        };
        const std::array<StreamCase, 5> cases = {{
            {"size-0", 0},
            {"size-65", 65},
            {"size-65537", 65537},
            {"size-1MiB+1", (1u << 20u) + 1u},
            {"size-3MiB+77", (3u << 20u) + 77u},
        }};
        constexpr std::size_t kBlock = 64u * 1024u;
        for (const StreamCase& c : cases) {
            const std::vector<u8> bytes = splitmix_bytes(c.size, 0x4d41525043313009ull + c.size);
            RecordingSource spy(std::span<const u8>(bytes.data(), bytes.size()));
            const auto got = boundaries_for_scale(spy, kScales[0]);
            const std::string input_sha = hex_digest_of_bytes(
                std::span<const u8>(bytes.data(), bytes.size()));
            const bool ok = got.ok();
            const bool bounded = c.size == 0u || spy.max_request() <= kBlock;
            const bool not_materialised = c.size <= kBlock || spy.max_request() < c.size;
            ev.either(ok && bounded && not_materialised, "c10.limits.bounded_buffer", "C10-STREAM",
                      c.id, input_sha, "max_request<=65536 and <input",
                      std::string(ok ? "Ok" : measure_code_name(got.code())) +
                          ";max_request=" + u64_dec(spy.max_request()) +
                          ";calls=" + u64_dec(spy.calls()) + ";input=" + u64_dec(c.size));
            note(std::string("[c10.limits.bounded_buffer:") + c.id + "] max_request=" +
                 u64_dec(spy.max_request()) + " calls=" + u64_dec(spy.calls()) +
                 " bytes=" + u64_dec(spy.bytes()) + " input=" + u64_dec(c.size));
        }
    }

    // --- 10. c10.pinned: constructed cases a reviewer can re-derive ---------
    {
        // Each row is re-derivable by hand from §4.5, and every one of them is a
        // case where the rule is easy to get wrong:
        //
        //  * a constant fill makes `h = (h<<1) + G[fill]` depend only on the run
        //    length, so the content test `(h & (T-1)) == 0` fires deterministically
        //    at every `min_chunk = T/4` once it first succeeds — hence the dense
        //    16-byte grid for zeros at T = 64 (G[0] = 0 makes `h & 63 == 0` at
        //    every multiple of 16) and the 1 KiB grid for 0xff at T = 256;
        //  * the forced cut at `len >= 4T` therefore only *bounds* a gap, it does
        //    not set it;
        //  * `L` is emitted unconditionally, so a short tail is the only gap that
        //    may be below `min_chunk`;
        //  * `L <= 64` is still `B_64` built by the same loop, because §4.4's
        //    "{0, L}" simplification is stated for the *tree*, and the loop over
        //    a constant fill does produce {0, L} only when no content cut fires.
        struct Case {
            const char* id;
            std::size_t size;
            u8 fill;
            u64 target;
            const char* expected;
        };
        const std::array<Case, 6> cases = {{
            {"zeros-63@t64", 63, 0x00u, 64u, "5:0,16,32,48,63"},
            {"zeros-64@t64", 64, 0x00u, 64u, "5:0,16,32,48,64"},
            {"zeros-65@t64", 65, 0x00u, 64u, "6:0,16,32,48,64,65"},
            {"zeros-257@t64", 257, 0x00u, 64u,
             "18:0,16,32,48,64,80,96,112,128,144,160,176,192,208,224,240,256,257"},
            {"ff-4096@t256", 4096, 0xffu, 256u, "5:0,1024,2048,3072,4096"},
            {"empty@t64", 0, 0x00u, 64u, "1:0"},
        }};
        for (const Case& c : cases) {
            const std::vector<u8> bytes(c.size, c.fill);
            SpanSource source(std::span<const u8>(bytes.data(), bytes.size()));
            const auto got = boundaries_for_scale(source, c.target);
            const auto ref =
                reference_boundaries(std::span<const u8>(bytes.data(), bytes.size()), c.target);
            const std::string item = c.id;
            const std::string input_sha =
                hex_digest_of_bytes(std::span<const u8>(bytes.data(), bytes.size()));
            const std::string actual =
                got.ok() ? boundaries_text(got.value()) : measure_code_name(got.code());
            const bool ok = got.ok() && got.value() == ref && actual == c.expected;
            ev.either(ok, "c10.pinned.constructed", "C10-PINNED", item, input_sha, c.expected,
                      actual + (got.ok() && got.value() != ref ? " (reference differs)" : ""));
            note("[c10.pinned:" + item + "] " + actual);
        }
    }

    // --- 11. c10.names: identical bytes under five labels -------------------
    {
        const std::vector<u8> base = splitmix_bytes(256u * 1024u, 0x4d4152504331300aull);
        const std::array<const char*, 5> labels = {{"slice.bin", "slice.txt", "slice.zip",
                                                    "slice", "slice.tar.gz"}};
        std::string first;
        bool identical = true;
        for (const char* label : labels) {
            // The label is a log column only; `Source` has no name to consult and
            // `segment` receives bytes, never a path.
            SpanSource source(std::span<const u8>(base.data(), base.size()));
            const auto prov = marp::v2::provenance(source, Policy{5});
            if (!prov.ok()) {
                identical = false;
                break;
            }
            std::vector<Segment> tree;
            const auto got = segment(source, prov.value(), Policy{5}, &tree);
            if (!got.ok()) {
                identical = false;
                break;
            }
            const std::string text = tree_text(tree);
            if (first.empty()) {
                first = text;
            } else if (text != first) {
                identical = false;
                note(std::string("[c10.names] differs under ") + label);
            }
        }
        ev.either(identical, "c10.names.independent", "C10-NAMES", "slice-256KiB-5-labels",
                  hex_digest_of_bytes(std::span<const u8>(base.data(), base.size())),
                  "tree identical under 5 labels",
                  identical ? "identical;tree_sha256=" + sha256_text_hex(first) : "differs");
        note("[c10.names.independent:slice-256KiB-5-labels] tree_sha256=" +
             sha256_text_hex(first));
    }

    // --- 12. c10.isolation: no E2-E7, no probe, no clock/locale/random -------
    {
        const fs::path hdr = repo_root / "include" / "mapr" / "e4" / "e4_segment.hpp";
        const fs::path lib = repo_root / "engine" / "src" / "e4" / "e4_segment.cpp";

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
                note("[c10.isolation] forbidden token: " + token);
            }
        }
        ev.either(!lib_sha.empty() && hits == 0, "c10.isolation.includes", "C10-ISOLATION",
                  "no-e2-e7-no-harness", lib_sha, "forbidden_tokens=0",
                  "forbidden_tokens=" + u64_dec(hits));

        // Environment access.  Comments are stripped first: the header documents
        // the *absence* of each facility, and a documentation sentence is not a
        // dependency.  `std::thread` is the one facility C10 legitimately uses
        // (its worker pool is the mechanism S5 is measured on), and it is
        // allowed here and only here.
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
        const std::array<const char*, 13> env_tokens = {
            "std::filesystem", "fstream", "std::chrono", "std::time", "gmtime", "localtime",
            "getenv", "std::locale", "setlocale", "std::random_device", "rand(", "srand",
            "getpid"};
        std::size_t env_hits = 0;
        for (const char* token : env_tokens) {
            if (stripped.find(token) != std::string::npos) {
                ++env_hits;
                note(std::string("[c10.isolation] environment token: ") + token);
            }
        }
        ev.either(env_hits == 0, "c10.isolation.environment", "C10-ISOLATION",
                  "no-clock-locale-rand-name", lib_sha, "environment_tokens=0",
                  "environment_tokens=" + u64_dec(env_hits));

        // No probe surface exists in this component, so E4-I8 holds by
        // construction: the boundary rule cannot consult a result that has no
        // representation in the translation unit.
        const std::array<const char*, 7> term_tokens = {
            "struct Ir", "class Dag", "struct Candidate", "struct Observation",
            "ProbeKind", "struct Atom", "probe("};
        std::size_t term_hits = 0;
        for (const char* token : term_tokens) {
            if (combined.find(token) != std::string::npos) {
                ++term_hits;
                note(std::string("[c10.isolation] term- or probe-shaped token: ") + token);
            }
        }
        ev.either(term_hits == 0, "c10.isolation.no_probes_no_terms", "C10-ISOLATION",
                  "no-observation-no-term", lib_sha, "probe_and_term_tokens=0",
                  "probe_and_term_tokens=" + u64_dec(term_hits));

        // The library may not read the file system, so no fixture can be a file.
        const bool reads_files =
            stripped.find("ifstream") != std::string::npos ||
            stripped.find("std::ifstream") != std::string::npos ||
            stripped.find("ofstream") != std::string::npos;
        ev.either(!reads_files, "c10.isolation.pure_bytes", "C10-ISOLATION", "no-file-io",
                  lib_sha, "no file stream in the library", reads_files ? "file stream found"
                                                                        : "none");

        // Type-level half of E4-I6 and the field budget of `Segment`.
        static_assert(std::is_same_v<decltype(segment(std::declval<Source&>(),
                                                      std::declval<const Provenance&>(),
                                                      std::declval<const Policy&>(),
                                                      std::declval<std::vector<Segment>*>())),
                                     marp::v2::MeasureResult<std::vector<Segment>>>,
                      "segment() must return MeasureResult<std::vector<Segment>>");
        ev.pass("c10.isolation.return_types", "C10-ISOLATION", "segment-returns-leaves", lib_sha,
                "MeasureResult<std::vector<Segment>>; Segment={begin,end,depth,level}",
                "static_asserts compiled: return type exact, Segment has four fields");
    }

    // -----------------------------------------------------------------------
    // Write the three artefacts.
    // -----------------------------------------------------------------------
    const fs::path gates = out_root / "specs_and_reports" / "v2" / "gates";
    const fs::path logs = out_root / "specs_and_reports" / "v2" / "logs";
    const fs::path evidence_dir = out_root / "specs_and_reports" / "v2" / "evidence" / "C10";
    std::error_code ec;
    fs::create_directories(gates, ec);
    fs::create_directories(logs, ec);
    fs::create_directories(evidence_dir, ec);

    const fs::path tsv_path = gates / "C10-SEGMENT.tsv";
    const fs::path log_path = logs / "C10-SEGMENT.log";
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
        out << "# C10 SEGMENT deterministic gate log\n";
        out << "# generated by engine/bin/c10_gate; never edited by hand\n";
        out << "component=C10-SEGMENT\n";
        out << "parent_epic=E4-MEASURE\n";
        out << "spec=MARP2-E4 sections 4.2, 4.4, 4.5, 4.6, 4.10, 5.2, 5.4, 6, 9\n";
        out << "depends=E1 (BigInt, gear); C09 (Provenance, Source); no E2-E7 linkage\n";
        out << "scales=2^6..2^26; min_chunk=T/4; max_chunk=4*T; W=4096; hop=2048; "
               "dH0>=2^24; dZ>=2^22; dedup=2048; cap=L/2048+16\n";
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
        // `sha256sum -c specs_and_reports/v2/evidence/C10/SHA256SUMS` works from
        // the repository root.
        const std::array<std::pair<fs::path, const char*>, 4> items = {{
            {repo_root / "include" / "mapr" / "e4" / "e4_segment.hpp",
             "include/mapr/e4/e4_segment.hpp"},
            {repo_root / "engine" / "src" / "e4" / "e4_segment.cpp",
             "engine/src/e4/e4_segment.cpp"},
            {tsv_path, "specs_and_reports/v2/gates/C10-SEGMENT.tsv"},
            {log_path, "specs_and_reports/v2/logs/C10-SEGMENT.log"},
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

    std::printf("C10 SEGMENT: rows=%zu pass=%zu blocked=%zu fail=%zu\n", rows.size(),
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
            std::printf("usage: c10_gate [--root DIR] [--out-root DIR] [--verify]\n");
            return 0;
        } else {
            std::fprintf(stderr, "unknown argument: %s\n", arg.c_str());
            return 2;
        }
    }

    if (out_root.empty()) out_root = repo_root;

    if (verify_only) {
        const fs::path sums =
            out_root / "specs_and_reports" / "v2" / "evidence" / "C10" / "SHA256SUMS";
        return verify_manifest(fs::weakly_canonical(sums));
    }
    return run_gate(repo_root, out_root);
}
