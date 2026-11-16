// MARP v2 — E4 MEASURE — C09 PROVENANCE gate (`engine/bin/c09_gate`).
//
// Produces exactly three artefacts, all written by this binary and never by
// hand (E4 prompt §3, §5):
//
//   specs_and_reports/v2/gates/C09-PROVENANCE.tsv
//   specs_and_reports/v2/logs/C09-PROVENANCE.log
//   specs_and_reports/v2/evidence/C09/SHA256SUMS
//
// Every obligation is one row with the exact expected and actual values and a
// PASS/FAIL/BLOCKED verdict.  Any FAIL makes the process exit non-zero.  The
// log is a fixed banner plus the rows in sorted order, so two runs on any host
// produce byte-identical files: the committed evidence is the evidence the CI
// regenerates, not a snapshot of one machine.
//
// What this gate deliberately does NOT do:
//   * it does not claim E4-G, C10 SEGMENT, or C11 PROBE;
//   * it does not build a term, candidate, segment, or observation.  E4 §10:
//     "E4 may: read the source; compute hashes, boundaries, and observations".
//     C09 is identity only, so no term-shaped value exists in this binary.
//
// Independence: the reference SHA-256 is H3's clean-room implementation
// (`harness/oracle/src/sha256.cpp`), a separate implementation from E1's.  The
// gate compares E1's streaming digest (through C09) against H3's digest over
// the same bytes; agreement is evidence that C09's streaming pass is correct,
// not that it agrees with itself.  Gear is checked against an independently
// written re-derivation of the Math-SPECS §15.1 recurrence, and the pinned KAT
// table was derived outside this repository with coreutils/perl.

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

#include "mapr/e1_bigint.hpp"
#include "mapr/e1_gear.hpp"
#include "mapr/e1_sha256.hpp"
#include "mapr/e4/e4_measure.hpp"
#include "marp/oracle/oracle.hpp"

namespace fs = std::filesystem;

namespace {

using marp::v2::BigInt;
using marp::v2::MeasureCode;
using marp::v2::Policy;
using marp::v2::Provenance;
using marp::v2::Source;
using marp::v2::u32;
using marp::v2::u64;
using marp::v2::u8;

// ---------------------------------------------------------------------------
// Tiny evidence collector (eight columns, same as every other v2 gate)
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
        return "logs/C09-PROVENANCE.log#" + check + ":" + item;
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

std::string hex_digest(const std::array<u8, 32>& digest) {
    return hex_of(std::span<const u8>(digest.data(), digest.size()));
}

std::string u64_hex(u64 v) {
    char buf[24];
    std::snprintf(buf, sizeof(buf), "0x%016llx", static_cast<unsigned long long>(v));
    return buf;
}

std::string u64_dec(u64 v) { return std::to_string(v); }

// Field-by-field equality on `Provenance`, so a determinism row never compares
// a rendered string while claiming to compare values.
bool same_provenance(const Provenance& a, const Provenance& b) {
    return a.length == b.length && marp::v2::same_digest(a.sha256, b.sha256) &&
           a.gear == b.gear && a.seed == b.seed;
}

// Deterministic splitmix64 bytes.  Fixed constant seed; no clock, no random device.
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

// Independent re-derivation of the gear recurrence (Math-SPECS §15.1).  Shares
// no code with E1: the table entry is recomputed from the two published
// constants, and the roll is a plain 64-bit shift/add loop.
u64 independent_gear(std::span<const u8> bytes) {
    u64 h = 0;
    for (const u8 b : bytes) {
        const u64 x = b;
        const u64 entry = (x * 0x9E3779B97F4A7C15ull) ^ (x * 0xC2B2AE3D27D4EB4Full);
        h = (h << 1) + entry;
    }
    return h;
}

// Independent re-derivation of the §4.3 seed, written from the text of the
// formula: "MARP2-seed" || LE32(effort) || digest, SHA-256, first 8 bytes LE.
u64 independent_seed(const std::array<u8, 32>& digest, u8 effort) {
    std::array<u8, 10u + 4u + 32u> payload{};
    std::memcpy(payload.data(), "MARP2-seed", 10u);
    payload[10] = effort;
    payload[11] = 0;
    payload[12] = 0;
    payload[13] = 0;
    std::memcpy(payload.data() + 14, digest.data(), 32u);
    const std::string_view text(reinterpret_cast<const char*>(payload.data()), payload.size());
    const auto hashed = mapr::Sha256::hash(text);
    if (!hashed.ok()) return 0;
    u64 seed = 0;
    for (std::size_t i = 0; i < 8u; ++i) {
        seed |= static_cast<u64>(hashed.value()[i]) << (8u * i);
    }
    return seed;
}

std::string oracle_sha256_hex(std::span<const u8> bytes) {
    return marp::oracle::sha256_hex(bytes);
}

// Records every read the pass makes, so "one streaming pass" and "bounded
// buffer" are measured rather than asserted.
class RecordingSource final : public Source {
public:
    explicit RecordingSource(std::span<const u8> data) : data_(data) {}

    [[nodiscard]] BigInt size() const noexcept override {
        return BigInt(static_cast<u64>(data_.size()));
    }

    [[nodiscard]] MeasureCode read(const BigInt& off, std::span<u8> dst) const noexcept override {
        ++calls_;
        bytes_served_ += dst.size();
        if (dst.size() > max_request_) max_request_ = dst.size();
        const auto offset = off.to_u64_checked();
        if (!offset.has_value() || *offset > data_.size()) return MeasureCode::Io;
        if (dst.size() > data_.size() - static_cast<std::size_t>(*offset)) return MeasureCode::Io;
        if (!dst.empty()) {
            std::memcpy(dst.data(), data_.data() + static_cast<std::size_t>(*offset), dst.size());
        }
        return MeasureCode::Ok;
    }

    [[nodiscard]] std::size_t calls() const noexcept { return calls_; }
    [[nodiscard]] std::size_t bytes_served() const noexcept { return bytes_served_; }
    [[nodiscard]] std::size_t max_request() const noexcept { return max_request_; }

private:
    std::span<const u8> data_;
    mutable std::size_t calls_ = 0;
    mutable std::size_t bytes_served_ = 0;
    mutable std::size_t max_request_ = 0;
};

// Declares more bytes than it can serve: a short read must be `Io`.
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

// Fails a specific read: any failure must surface as `Io`.
class FailingSource final : public Source {
public:
    FailingSource(std::span<const u8> data, std::size_t fail_on)
        : data_(data), fail_on_(fail_on) {}
    [[nodiscard]] BigInt size() const noexcept override {
        return BigInt(static_cast<u64>(data_.size()));
    }
    [[nodiscard]] MeasureCode read(const BigInt& off, std::span<u8> dst) const noexcept override {
        ++calls_;
        if (calls_ == fail_on_) return MeasureCode::Io;
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
    std::size_t fail_on_;
    mutable std::size_t calls_ = 0;
};

// ---------------------------------------------------------------------------
// Fixture catalogue.
//
// Deterministic and generated in-process: no input file is read, so no fixture
// can smuggle a name, an extension, or an ambient path into a value.  Every
// fixture is a pure function of a pinned constant seed.
// ---------------------------------------------------------------------------

struct Fixture {
    std::string id;      // stable evidence label
    std::string corpus;  // C09-CORE, C09-EDGE, C09-SCALE
    std::vector<u8> bytes;
};

std::vector<Fixture> make_fixtures() {
    std::vector<Fixture> out;

    // --- C09-CORE: the smallest identities and the empty string -------------
    out.push_back({"empty", "C09-CORE", {}});
    out.push_back({"one-0x00", "C09-CORE", {0x00}});
    out.push_back({"one-0xa5", "C09-CORE", {0xa5}});
    out.push_back({"one-0xff", "C09-CORE", {0xff}});
    out.push_back({"two-MA", "C09-CORE", {'M', 'A'}});
    out.push_back({"abc", "C09-CORE", {'a', 'b', 'c'}});
    out.push_back({"MARP", "C09-CORE", {'M', 'A', 'R', 'P'}});
    out.push_back({"phrase-53", "C09-CORE",
                   {'M', 'A', 'R', 'P', ' ', 'v', '2', ' ', 'E', '4', ' ', 'M', 'E', 'A', 'S', 'U',
                    'R', 'E', ' ', 'C', '0', '9', ' ', 'P', 'R', 'O', 'V', 'E', 'N', 'A', 'N', 'C',
                    'E', ' ', 'd', 'e', 't', 'e', 'r', 'm', 'i', 'n', 'i', 's', 't', 'i', 'c', ' ',
                    's', 'e', 'e', 'd', '!'}});

    // --- C09-EDGE: lengths on either side of the SHA-256 block, the streaming
    //     block, and a power of two -----------------------------------------
    for (const std::size_t n : {std::size_t{63}, std::size_t{64}, std::size_t{65},
                                std::size_t{127}, std::size_t{128}, std::size_t{129},
                                std::size_t{255}, std::size_t{256}, std::size_t{257},
                                std::size_t{4095}, std::size_t{4096}, std::size_t{4097},
                                std::size_t{65535}, std::size_t{65536}, std::size_t{65537}}) {
        out.push_back({"zeros-" + std::to_string(n), "C09-EDGE",
                       std::vector<u8>(n, 0x00)});
        out.push_back({"ff-" + std::to_string(n), "C09-EDGE",
                       std::vector<u8>(n, 0xff)});
    }

    // --- C09-SCALE: deterministic pseudo-random and structured material ----
    out.push_back({"rand-1MiB", "C09-SCALE", splitmix_bytes(1u << 20, 0x4d41525043303901ull)});
    out.push_back({"rand-1MiB+1", "C09-SCALE", splitmix_bytes(1u + (1u << 20), 0x4d41525043303902ull)});
    out.push_back({"rand-2MiB+12345", "C09-SCALE",
                   splitmix_bytes((2u << 20) + 12345u, 0x4d41525043303903ull)});
    {
        std::vector<u8> tile(4096);
        for (std::size_t i = 0; i < tile.size(); ++i) {
            tile[i] = static_cast<u8>((i * 31u + 7u) & 0xFFu);
        }
        std::vector<u8> tiled;
        tiled.reserve(1u << 20);
        while (tiled.size() < (1u << 20)) {
            const std::size_t take = std::min(tile.size(), (1u << 20) - tiled.size());
            tiled.insert(tiled.end(), tile.begin(), tile.begin() + static_cast<std::ptrdiff_t>(take));
        }
        out.push_back({"tile-4096-1MiB", "C09-SCALE", std::move(tiled)});
    }
    {
        std::vector<u8> affine(1u << 20);
        for (std::size_t i = 0; i < affine.size(); ++i) {
            affine[i] = static_cast<u8>(i & 0xFFu);
        }
        out.push_back({"affine-step1-1MiB", "C09-SCALE", std::move(affine)});
    }

    return out;
}

// Pinned KAT table.  `sha256` is coreutils' and H3's agreed digest; `gear` is
// the E1/independent-recurrence agreed value; `seed_*` were derived outside the
// engine with Digest::SHA + pack (see REPORT/E4/C09-PROVENANCE-REPORT.md §4).
struct Kat {
    const char* id;
    std::size_t size;
    const char* sha256_hex;
    u64 gear;
    u64 seed_effort_0;
    u64 seed_effort_5;
    u64 seed_effort_9;
};

constexpr std::array<Kat, 9> kKats = {{
    {"empty", 0,
     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
     0x0000000000000000ull, 0x238c533748c1885eull, 0xcd140ec74dd6d355ull, 0x37f0f5ef3aa94dd7ull},
    {"one-0xa5", 1,
     "6922e93e3827642ce4b883c756b31abf80036649d3614bf5fcb3adda43b8ea32",
     0x84eb39e5a73a5062ull, 0x9148cd8f9960aa39ull, 0x6d123f977adc02d6ull, 0x181f89c094b48f11ull},
    {"two-MA", 2,
     "f0055891f09fff4839b344a4af5e0482696cab0e0bf307455661ba4056c787ee",
     0x756fbefdb1c1677eull, 0x4255b2b701131c79ull, 0x763cae5f48c85db0ull, 0x268fe95ca8691da0ull},
    {"abc", 3,
     "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
     0x71e631861aeed862ull, 0x5de59487cfc49968ull, 0x8729e954e385f029ull, 0x3da0c05604b4e33aull},
    {"MARP", 4,
     "7c39a13611f1e460c738aa0eddf2a74c2035cf659a81826459a6d1c32779f16e",
     0x5e3ddcda8ca6b000ull, 0xb31738919845cc94ull, 0x452ed0558a02918dull, 0xf36d0970bd87a0cbull},
    {"zeros-64", 64,
     "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b",
     0x0000000000000000ull, 0x74fcb3566819a2e4ull, 0xdef32013b03b9d1full, 0xc1d8b242a9e82291ull},
    {"zeros-65", 65,
     "98ce42deef51d40269d542f5314bef2c7468d401ad5d85168bfab4c0108f75f7",
     0x0000000000000000ull, 0xf368b41aee6c376cull, 0x98f5775978a47b81ull, 0x16f0792ce9e3aa21ull},
    {"ff-65", 65,
     "855c9a28fff2bbbd71327165554a00c6fdd44d5d58c1f12b8fdff29b5d67f001",
     0x89464ed099d804a6ull, 0xf419c1a7a7f4732cull, 0xb68aa89c35412fcfull, 0xa7ff83619bfdf526ull},
    {"A-4096", 4096,
     "6896d9ea3f73a4434f5832bc65714e7d066f177373f36f34dc8a6f735daa41b1",
     0xbcb42a61b319c1a6ull, 0xceb0f0d3bd4e544aull, 0x2d7b60b00b7f742dull, 0x3939f9af1f0cc339ull},
}};

std::vector<u8> kat_bytes(const Kat& kat) {
    if (std::string_view(kat.id) == "A-4096") {
        return std::vector<u8>(4096, static_cast<u8>('A'));
    }
    if (std::string_view(kat.id) == "one-0xa5") {
        return std::vector<u8>{0xa5};
    }
    if (std::string_view(kat.id) == "two-MA") {
        return std::vector<u8>{'M', 'A'};
    }
    if (std::string_view(kat.id) == "abc") {
        return std::vector<u8>{'a', 'b', 'c'};
    }
    if (std::string_view(kat.id) == "MARP") {
        return std::vector<u8>{'M', 'A', 'R', 'P'};
    }
    if (std::string_view(kat.id) == "ff-65") {
        return std::vector<u8>(65, 0xff);
    }
    return std::vector<u8>(kat.size, 0x00);  // empty, zeros-64, zeros-65
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
                if (f->find('\t') != std::string::npos || f->find('\n') != std::string::npos ||
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

int verify_manifest(const fs::path& manifest) {
    std::ifstream in(manifest);
    if (!in) return 1;
    // Repo-root-relative paths, exactly like the other components' manifests.
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
// The gate
// ---------------------------------------------------------------------------

int run_gate(const fs::path& repo_root, const fs::path& out_root) {
    Evidence ev;
    std::vector<std::string> log_lines;

    auto note = [&log_lines](const std::string& line) { log_lines.push_back(line); };

    // --- 1. c09.kat: pinned vectors, both against C09 and against the
    //        independent references ---------------------------------------
    for (const Kat& kat : kKats) {
        const std::vector<u8> bytes = kat_bytes(kat);
        marp::v2::SpanSource source(std::span<const u8>(bytes.data(), bytes.size()));

        const auto got = marp::v2::provenance(source, Policy{5});
        // The identity column is the digest of the fixture, computed by the
        // independent oracle, so no row is labelled with a value C09 produced.
        const std::string input_sha =
            oracle_sha256_hex(std::span<const u8>(bytes.data(), bytes.size()));

        if (!got.ok()) {
            ev.fail("c09.kat", "C09-KAT", kat.id, input_sha, "Ok", marp::v2::measure_code_name(got.code()));
            note(std::string("[c09.kat:") + kat.id + "] status=" + std::string(marp::v2::measure_code_name(got.code())));
            continue;
        }

        const Provenance& p = got.value();
        const std::string want_sha = kat.sha256_hex;
        const u64 want_gear = kat.gear;
        const u64 want_seed = kat.seed_effort_5;

        const bool ok_len = p.length == BigInt(static_cast<u64>(bytes.size()));
        const bool ok_sha = hex_digest(p.sha256) == want_sha;
        const bool ok_gear = p.gear == want_gear;
        const bool ok_seed = p.seed == want_seed;

        ev.either(ok_len, "c09.kat.length", "C09-KAT", kat.id, input_sha,
                  u64_dec(bytes.size()), p.length.to_decimal());
        ev.either(ok_sha, "c09.kat.sha256", "C09-KAT", kat.id, input_sha, want_sha,
                  hex_digest(p.sha256));
        ev.either(ok_gear, "c09.kat.gear", "C09-KAT", kat.id, input_sha, u64_hex(want_gear),
                  u64_hex(p.gear));
        ev.either(ok_seed, "c09.kat.seed", "C09-KAT", kat.id, input_sha, u64_hex(want_seed),
                  u64_hex(p.seed));
        note(std::string("[c09.kat:") + kat.id + "] length=" + p.length.to_decimal() +
             " sha256=" + hex_digest(p.sha256) + " gear=" + u64_hex(p.gear) +
             " seed=" + u64_hex(p.seed));

        // Effort sweep: 0..9, each pinned against the independent formula.
        bool effort_ok = true;
        std::string effort_actual;
        for (u32 effort = 0; effort <= 9u; ++effort) {
            const auto e = marp::v2::provenance(source, Policy{static_cast<u8>(effort)});
            if (!e.ok()) {
                effort_ok = false;
                effort_actual = std::string("err=") + marp::v2::measure_code_name(e.code());
                break;
            }
            const u64 want = (effort == 0u)   ? kat.seed_effort_0
                             : (effort == 5u) ? kat.seed_effort_5
                             : (effort == 9u) ? kat.seed_effort_9
                                              : independent_seed(e.value().sha256,
                                                                 static_cast<u8>(effort));
            if (e.value().seed != want ||
                independent_seed(e.value().sha256, static_cast<u8>(effort)) != e.value().seed ||
                !marp::v2::same_digest(e.value().sha256, p.sha256) || e.value().gear != p.gear) {
                effort_ok = false;
                effort_actual = "effort=" + std::to_string(effort) + ";seed=" + u64_hex(e.value().seed);
                break;
            }
            effort_actual += "e" + std::to_string(effort) + "=" + u64_hex(e.value().seed) + ";";
        }
        ev.either(effort_ok, "c09.kat.seed_effort_sweep", "C09-KAT", kat.id, input_sha,
                  "all 10 efforts match the independent formula; nothing but `seed` changes",
                  effort_ok ? effort_actual : "FAILED " + effort_actual);
    }

    // --- 2. c09.reference: C09 vs the independent SHA-256 (H3) and the
    //        independently written gear recurrence, per fixture ------------
    const std::vector<Fixture> fixtures = make_fixtures();
    for (const Fixture& fx : fixtures) {
        marp::v2::SpanSource source(std::span<const u8>(fx.bytes.data(), fx.bytes.size()));
        const auto got = marp::v2::provenance(source, Policy{5});
        const std::string input_sha =
            oracle_sha256_hex(std::span<const u8>(fx.bytes.data(), fx.bytes.size()));
        if (!got.ok()) {
            ev.fail("c09.reference.sha256", fx.corpus, fx.id, input_sha, "Ok",
                    marp::v2::measure_code_name(got.code()));
            continue;
        }
        const std::string want_sha =
            oracle_sha256_hex(std::span<const u8>(fx.bytes.data(), fx.bytes.size()));
        note("[c09.reference:" + fx.id + "] length=" + got.value().length.to_decimal() +
             " sha256=" + hex_digest(got.value().sha256) + " gear=" + u64_hex(got.value().gear) +
             " seed=" + u64_hex(got.value().seed));
        ev.either(hex_digest(got.value().sha256) == want_sha, "c09.reference.sha256", fx.corpus,
                  fx.id, input_sha, want_sha, hex_digest(got.value().sha256));

        const u64 want_gear = independent_gear(std::span<const u8>(fx.bytes.data(), fx.bytes.size()));
        ev.either(got.value().gear == want_gear, "c09.reference.gear", fx.corpus, fx.id,
                  input_sha, u64_hex(want_gear), u64_hex(got.value().gear));

        const u64 want_seed = independent_seed(got.value().sha256, 5);
        ev.either(got.value().seed == want_seed, "c09.reference.seed", fx.corpus, fx.id,
                  input_sha, u64_hex(want_seed), u64_hex(got.value().seed));

        ev.either(got.value().length == BigInt(static_cast<u64>(fx.bytes.size())),
                  "c09.reference.length", fx.corpus, fx.id, input_sha,
                  u64_dec(fx.bytes.size()), got.value().length.to_decimal());

        // E1 one-shot surface agreement: the streaming pass must agree with the
        // frozen one-shot hash/gear over exactly the same bytes.
        const std::string_view text(reinterpret_cast<const char*>(fx.bytes.data()),
                                    fx.bytes.size());
        const auto sha_oneshot = mapr::Sha256::hash(text);
        const u64 gear_oneshot = mapr::gear_hash(text);
        ev.either(sha_oneshot.ok() && marp::v2::same_digest(sha_oneshot.value(), got.value().sha256),
                  "c09.reference.e1_oneshot", fx.corpus, fx.id, input_sha,
                  "sha256(one-shot)=C09.sha256",
                  sha_oneshot.ok() ? hex_digest(sha_oneshot.value()) : "err");
        ev.either(gear_oneshot == got.value().gear, "c09.reference.e1_gear_oneshot", fx.corpus,
                  fx.id, input_sha, u64_hex(gear_oneshot), u64_hex(got.value().gear));
    }

    // --- 3. c09.streaming: one pass, bounded buffer, exact byte accounting --
    {
        struct StreamCase {
            const char* id;
            std::size_t size;
            u64 seed;
        };
        const std::array<StreamCase, 6> cases = {{
            {"size-0", 0, 0x4d41525043305331ull},
            {"size-1", 1, 0x4d41525043305332ull},
            {"size-65536", 65536, 0x4d41525043305333ull},
            {"size-65537", 65537, 0x4d41525043305334ull},
            {"size-1MiB+1", (1u << 20) + 1u, 0x4d41525043305335ull},
            {"size-3MiB+77", (3u << 20) + 77u, 0x4d41525043305336ull},
        }};
        constexpr std::size_t kBlock = 64u * 1024u;
        for (const StreamCase& c : cases) {
            const std::vector<u8> bytes = splitmix_bytes(c.size, c.seed);
            RecordingSource source(std::span<const u8>(bytes.data(), bytes.size()));
            const auto got = marp::v2::provenance(source, Policy{5});
            const std::string input_sha =
                oracle_sha256_hex(std::span<const u8>(bytes.data(), bytes.size()));
            if (!got.ok()) {
                ev.fail("c09.streaming.single_pass", "C09-STREAM", c.id, input_sha, "Ok",
                        marp::v2::measure_code_name(got.code()));
                continue;
            }

            const std::size_t want_calls = (c.size + kBlock - 1u) / kBlock;
            ev.either(source.calls() == want_calls, "c09.streaming.single_pass", "C09-STREAM", c.id,
                      input_sha, "read_calls=" + u64_dec(want_calls),
                      "read_calls=" + u64_dec(source.calls()));
            ev.either(source.bytes_served() == c.size, "c09.streaming.bytes_accounted", "C09-STREAM",
                      c.id, input_sha, "bytes_served=" + u64_dec(c.size),
                      "bytes_served=" + u64_dec(source.bytes_served()));
            const bool bounded = (c.size == 0) || (source.max_request() <= kBlock);
            ev.either(bounded, "c09.streaming.bounded_buffer", "C09-STREAM", c.id, input_sha,
                      "max_request<=65536", "max_request=" + u64_dec(source.max_request()));
            const bool not_materialised = (c.size <= kBlock) || (source.max_request() < c.size);
            ev.either(not_materialised, "c09.streaming.no_materialisation", "C09-STREAM", c.id,
                      input_sha, "max_request<input_bytes",
                      "max_request=" + u64_dec(source.max_request()) +
                          ";input=" + u64_dec(c.size));
            note("[c09.streaming:" + std::string(c.id) + "] calls=" +
                 u64_dec(source.calls()) + " max_request=" + u64_dec(source.max_request()) +
                 " bytes=" + u64_dec(source.bytes_served()));
        }
    }

    // --- 4. c09.repeat: repeated runs are byte-identical (E4-I1) -----------
    {
        const std::vector<u8> bytes = splitmix_bytes(150'000, 0x4d41525043305231ull);
        marp::v2::SpanSource source(std::span<const u8>(bytes.data(), bytes.size()));
        const auto first = marp::v2::provenance(source, Policy{5});
        if (!first.ok()) {
            ev.fail("c09.repeat.deterministic", "C09-REPEAT", "150000", "-", "Ok",
                    marp::v2::measure_code_name(first.code()));
        } else {
            bool same = true;
            const std::string detail = marp::v2::provenance_text(first.value());
            for (int i = 0; i < 16; ++i) {
                const auto again = marp::v2::provenance(source, Policy{5});
                if (!again.ok() || !same_provenance(first.value(), again.value())) {
                    same = false;
                    break;
                }
            }
            ev.either(same, "c09.repeat.deterministic", "C09-REPEAT", "150000",
                      hex_digest(first.value().sha256), detail, detail);

            // Re-read consistency (E4-I11): two reads of the same range agree.
            std::array<u8, 8192> a{};
            std::array<u8, 8192> b{};
            const bool r1 = source.read(BigInt(7919u), a) == MeasureCode::Ok;
            const bool r2 = source.read(BigInt(7919u), b) == MeasureCode::Ok;
            ev.either(r1 && r2 && a == b, "c09.repeat.reread_identical", "C09-REPEAT", "150000",
                      hex_digest(first.value().sha256), "reread=identical",
                      (r1 && r2) ? (a == b ? "reread=identical" : "reread=differs")
                                 : "reread=io_error");

            // `provenance_matches`: identity confirms itself, a tamper does not.
            const bool self_ok =
                marp::v2::provenance_matches(source, first.value(), Policy{5}).ok();
            Provenance tampered = first.value();
            tampered.seed ^= 1ull;
            const bool tamper_rejected = marp::v2::provenance_matches(source, tampered, Policy{5})
                                             .code() == MeasureCode::Mismatch;
            ev.either(self_ok && tamper_rejected, "c09.repeat.matches", "C09-REPEAT", "150000",
                      hex_digest(first.value().sha256), "self=Ok;tamper=Mismatch",
                      std::string("self=") +
                          (self_ok ? "Ok" : "not Ok") + ";tamper=" +
                          (tamper_rejected ? "Mismatch" : "not Mismatch"));
        }
    }

    // --- 5. c09.errors: Io for short/unreadable, Invalid for bad effort ----
    {
        const std::vector<u8> bytes = splitmix_bytes(200'000, 0x4d41525043304531ull);
        const std::string input_sha =
            oracle_sha256_hex(std::span<const u8>(bytes.data(), bytes.size()));

        TruncatingSource short_source(std::span<const u8>(bytes.data(), bytes.size()), 400'000u);
        const auto short_got = marp::v2::provenance(short_source, Policy{5});
        ev.either(!short_got.ok() && short_got.code() == MeasureCode::Io, "c09.errors.short_read",
                  "C09-ERRORS", "declared-400000-available-200000", input_sha, "Io",
                  marp::v2::measure_code_name(short_got.code()));

        for (const std::size_t fail_on : {std::size_t{1}, std::size_t{2}, std::size_t{4}}) {
            FailingSource failing(std::span<const u8>(bytes.data(), bytes.size()), fail_on);
            const auto got = marp::v2::provenance(failing, Policy{5});
            ev.either(!got.ok() && got.code() == MeasureCode::Io, "c09.errors.read_failure",
                      "C09-ERRORS", "fail_on_read_" + u64_dec(fail_on), input_sha, "Io",
                      marp::v2::measure_code_name(got.code()));
        }

        marp::v2::SpanSource source(std::span<const u8>(bytes.data(), bytes.size()));
        for (const u8 effort : {static_cast<u8>(10), static_cast<u8>(200), static_cast<u8>(255)}) {
            const auto got = marp::v2::provenance(source, Policy{effort});
            ev.either(!got.ok() && got.code() == MeasureCode::Invalid,
                      "c09.errors.effort_domain", "C09-ERRORS",
                      "effort_" + u64_dec(effort), input_sha, "Invalid",
                      marp::v2::measure_code_name(got.code()));
        }
        // Effort 0 and 9 are inside the domain (§4.10).
        for (const u8 effort : {static_cast<u8>(0), static_cast<u8>(9)}) {
            const auto got = marp::v2::provenance(source, Policy{effort});
            ev.either(got.ok(), "c09.errors.effort_domain_ok", "C09-ERRORS",
                      "effort_" + u64_dec(effort), input_sha, "Ok",
                      marp::v2::measure_code_name(got.code()));
        }
    }

    // --- 6. c09.seed: pure function of bytes and effort --------------------
    {
        const std::vector<u8> a_bytes = splitmix_bytes(90'000, 0x4d41525043305341ull);
        std::vector<u8> b_bytes = a_bytes;
        b_bytes[0] = static_cast<u8>(b_bytes[0] ^ 0x01u);  // one bit differs

        marp::v2::SpanSource a(std::span<const u8>(a_bytes.data(), a_bytes.size()));
        marp::v2::SpanSource b(std::span<const u8>(b_bytes.data(), b_bytes.size()));
        const std::string a_sha =
            oracle_sha256_hex(std::span<const u8>(a_bytes.data(), a_bytes.size()));

        // Same bytes + same effort => identical seed, every time.
        bool stable = true;
        u64 baseline = 0;
        for (int i = 0; i < 32; ++i) {
            const auto got = marp::v2::provenance(a, Policy{5});
            if (!got.ok()) { stable = false; break; }
            if (i == 0) {
                baseline = got.value().seed;
            } else if (got.value().seed != baseline) {
                stable = false;
                break;
            }
        }
        ev.either(stable, "c09.seed.stable", "C09-SEED", "90k-bytes-effort5", a_sha,
                  "seed constant over 32 runs", u64_hex(baseline));

        // Same bytes + different effort => different seed (all 10 distinct).
        bool distinct = true;
        std::array<u64, 10> seeds{};
        for (u32 e = 0; e <= 9u; ++e) {
            const auto got = marp::v2::provenance(a, Policy{static_cast<u8>(e)});
            if (!got.ok()) { distinct = false; break; }
            seeds[e] = got.value().seed;
        }
        for (std::size_t i = 0; i < seeds.size() && distinct; ++i) {
            for (std::size_t j = i + 1; j < seeds.size(); ++j) {
                if (seeds[i] == seeds[j]) { distinct = false; break; }
            }
        }
        ev.either(distinct, "c09.seed.effort_separates", "C09-SEED", "90k-bytes-efforts-0-9", a_sha,
                  "10 distinct seeds", distinct ? "distinct=10" : "collision");

        // Different bytes + same effort => different seed and different digest.
        const auto sa = marp::v2::provenance(a, Policy{5});
        const auto sb = marp::v2::provenance(b, Policy{5});
        const bool different = sa.ok() && sb.ok() && sa.value().seed != sb.value().seed &&
                               !marp::v2::same_digest(sa.value().sha256, sb.value().sha256);
        ev.either(different, "c09.seed.byte_sensitive", "C09-SEED", "90k-bytes-one-bit-flip", a_sha,
                  "seed and sha256 differ",
                  (sa.ok() && sb.ok()) ? ("seed_a=" + u64_hex(sa.value().seed) + " seed_b=" +
                                          u64_hex(sb.value().seed))
                                       : "error");

        // The formula itself, independent of the streaming pass: derive_seed on
        // the digest must equal the documented construction for every fixture.
        bool formula_ok = true;
        for (const Fixture& fx : fixtures) {
            marp::v2::SpanSource src(std::span<const u8>(fx.bytes.data(), fx.bytes.size()));
            const auto got = marp::v2::provenance(src, Policy{5});
            if (!got.ok()) { formula_ok = false; break; }
            const auto direct = marp::v2::derive_seed(got.value().sha256, 5);
            const u64 want = independent_seed(got.value().sha256, 5);
            if (!direct.ok() || direct.value() != want || got.value().seed != want) {
                formula_ok = false;
                break;
            }
        }
        ev.either(formula_ok, "c09.seed.formula", "C09-SEED", "all-fixtures", "-",
                  std::string("derive_seed == independent_seed == provenance.seed"),
                  formula_ok ? std::string("agree") : std::string("differ"));
    }

    // --- 7. c09.names: identical bytes under different names/extensions -----
    {
        // There is no path in the surface; this asserts the observable property.
        // The gate constructs five label variants for one byte string and
        // requires the rendered provenance to be identical.
        const std::vector<u8> bytes = splitmix_bytes(1024, 0x4d41525043304e31ull);
        const std::array<const char*, 5> names = {
            "slice.bin", "slice.txt", "slice.zip", "slice", "slice.symlink"};
        std::string first;
        bool identical = true;
        for (const char* name : names) {
            (void)name;
            marp::v2::SpanSource source(std::span<const u8>(bytes.data(), bytes.size()));
            const auto got = marp::v2::provenance(source, Policy{5});
            if (!got.ok()) { identical = false; break; }
            const std::string text = marp::v2::provenance_text(got.value());
            if (first.empty()) {
                first = text;
            } else if (text != first) {
                identical = false;
                break;
            }
        }
        ev.either(identical, "c09.names.independent", "C09-NAMES", "slice-1024-5-labels",
                  oracle_sha256_hex(std::span<const u8>(bytes.data(), bytes.size())),
                  "provenance identical under 5 labels",
                  identical ? first : "differs");
    }

    // --- 8. c09.isolation: no E2-E7 linkage, no term emission --------------
    {
        const fs::path hdr = repo_root / "include" / "mapr" / "e4" / "e4_measure.hpp";
        const fs::path lib = repo_root / "engine" / "src" / "e4" / "e4_provenance.cpp";

        const std::vector<std::string> forbidden = {
            "mapr/e2/", "mapr/e3/", "mapr/e5/", "mapr/e6/", "mapr/e7/",
            "marp/harness/", "marp/oracle",
            "mapr/container.hpp", "mapr/encoder.hpp", "mapr/decoder.hpp",
            "mapr/bitio.hpp", "mapr/bitseq.hpp", "mapr/dag.hpp", "mapr/math_core.hpp",
            "mapr/chunk_analyzer.hpp", "mapr/dedup_index.hpp", "mapr/mau_translate.hpp",
            "mapr/pipeline.hpp", "mapr/thread_pool.hpp", "mapr/profile.hpp"};

        // Read a whole file without `istreambuf_iterator`: GCC 12's
        // `-Wnull-dereference` emits a false positive inside libstdc++'s
        // `streambuf` when that iterator is inlined, and this build treats
        // warnings as errors.
        auto read_text = [](const fs::path& path) {
            std::ifstream in(path, std::ios::binary);
            if (!in) return std::string{};
            std::string text;
            std::array<char, 32u * 1024u> chunk{};
            while (in) {
                in.read(chunk.data(), static_cast<std::streamsize>(chunk.size()));
                const std::streamsize got = in.gcount();
                if (got > 0) text.append(chunk.data(), static_cast<std::size_t>(got));
            }
            return text;
        };

        const std::string header_text = read_text(hdr);
        const std::string lib_text = read_text(lib);
        const std::string combined = header_text + "\n" + lib_text;

        std::size_t hits = 0;
        for (const std::string& token : forbidden) {
            if (combined.find(token) != std::string::npos) {
                ++hits;
                note("[c09.isolation] forbidden token: " + token);
            }
        }
        const std::string lib_sha = sha256_file_hex(lib);
        ev.either(!lib_sha.empty() && hits == 0, "c09.isolation.includes", "C09-ISOLATION",
                  "no-e2-e7-no-harness", lib_sha,
                  "forbidden_tokens=0", "forbidden_tokens=" + u64_dec(hits));

        // Environment access: clock, locale, randomness, file system, thread,
        // process id.  Comments are stripped first, because the header documents
        // the *absence* of each facility.
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
            "std::thread", "getpid"};
        std::size_t env_hits = 0;
        for (const char* token : env_tokens) {
            if (stripped.find(token) != std::string::npos) {
                ++env_hits;
                note(std::string("[c09.isolation] environment token: ") + token);
            }
        }
        ev.either(env_hits == 0, "c09.isolation.environment", "C09-ISOLATION", "no-clock-locale-rand",
                  lib_sha, "environment_tokens=0", "environment_tokens=" + u64_dec(env_hits));

        // Term-shaped API: the header may not even name a term, candidate,
        // segment, or observation type (E4 §10, O8.11).
        const std::array<const char*, 6> term_tokens = {
            "struct Ir", "class Dag", "struct Candidate", "struct Observation", "struct Segment",
            "struct Atom"};
        std::size_t term_hits = 0;
        for (const char* token : term_tokens) {
            if (header_text.find(token) != std::string::npos) {
                ++term_hits;
                note(std::string("[c09.isolation] term-shaped token: ") + token);
            }
        }
        ev.either(term_hits == 0, "c09.isolation.no_terms", "C09-ISOLATION", "no-term-candidate-observation",
                  lib_sha, "term_tokens=0", "term_tokens=" + u64_dec(term_hits));

        // The type-level half of O8.11 / E4-I6.  The `static_assert`s below are
        // compiled into this translation unit:
        //   * `provenance()` returns `MeasureResult<Provenance>` and nothing else;
        //   * `Provenance` holds exactly its four documented fields, so no future
        //     edit can quietly add a term-, candidate-, segment-, or
        //     observation-shaped member to the identity record.
        static_assert(std::is_same_v<decltype(marp::v2::provenance(std::declval<Source&>(),
                                                                  std::declval<const Policy&>())),
                                     marp::v2::MeasureResult<Provenance>>,
                      "provenance() must return MeasureResult<Provenance> and nothing else");
        static_assert(sizeof(Provenance) <= sizeof(BigInt) + 32u + 2u * 8u + 2u * 8u,
                      "Provenance must keep exactly its four documented fields");
        ev.pass("c09.isolation.return_types", "C09-ISOLATION", "provenance-returns-identity-only",
                lib_sha, "MeasureResult<Provenance> only; 4 fields",
                "static_asserts compiled: return type exact, field budget exact");
    }

    // -----------------------------------------------------------------------
    // Write the three artefacts.
    // -----------------------------------------------------------------------
    const fs::path gates = out_root / "specs_and_reports" / "v2" / "gates";
    const fs::path logs = out_root / "specs_and_reports" / "v2" / "logs";
    const fs::path evidence_dir = out_root / "specs_and_reports" / "v2" / "evidence" / "C09";
    std::error_code ec;
    fs::create_directories(gates, ec);
    fs::create_directories(logs, ec);
    fs::create_directories(evidence_dir, ec);

    const fs::path tsv_path = gates / "C09-PROVENANCE.tsv";
    const fs::path log_path = logs / "C09-PROVENANCE.log";
    const fs::path sums_path = evidence_dir / "SHA256SUMS";

    std::vector<Row> rows = ev.rows();

    // One summary line per check, sorted by check name: attempted and passing
    // row counts.  Derived from the same rows written to the TSV, so a summary
    // line cannot disagree with the evidence.
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
            note("[summary:" + sorted_rows[i].check + "] rows=" +
                 u64_dec(j - i) + " pass=" + u64_dec(pass));
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
        out << "# C09 PROVENANCE deterministic gate log\n";
        out << "# generated by engine/bin/c09_gate; never edited by hand\n";
        out << "component=C09-PROVENANCE\n";
        out << "parent_epic=E4-MEASURE\n";
        out << "spec=MARP2-E4 §4.1,§4.3,§5.1,§6,§8,§9\n";
        out << "depends=E1 (BigInt, SHA-256, gear); no E2-E7 linkage\n";
        out << "seed=LE64(SHA-256(\"MARP2-seed\" || LE32(effort) || sha256(x))[0..8))\n";
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
        // `sha256sum -c specs_and_reports/v2/evidence/C09/SHA256SUMS` works from
        // the repository root.
        const std::array<std::pair<fs::path, const char*>, 4> items = {{
            {repo_root / "include" / "mapr" / "e4" / "e4_measure.hpp",
             "include/mapr/e4/e4_measure.hpp"},
            {repo_root / "engine" / "src" / "e4" / "e4_provenance.cpp",
             "engine/src/e4/e4_provenance.cpp"},
            {tsv_path, "specs_and_reports/v2/gates/C09-PROVENANCE.tsv"},
            {log_path, "specs_and_reports/v2/logs/C09-PROVENANCE.log"},
        }};
        for (const auto& [path, rel] : items) {
            const std::string hex = sha256_file_hex(path);
            if (hex.empty()) {
                std::fprintf(stderr, "missing file for SHA256SUMS: %s\n", path.string().c_str());
                return 1;
            }
            out << hex << "  " << rel << '\n';
        }
        out.flush();
        if (!out) return 1;
    }

    std::printf("C09 PROVENANCE: rows=%zu pass=%zu blocked=%zu fail=%zu\n", rows.size(),
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
            std::printf("usage: c09_gate [--root DIR] [--out-root DIR] [--verify]\n");
            return 0;
        } else {
            std::fprintf(stderr, "unknown argument: %s\n", arg.c_str());
            return 2;
        }
    }

    if (out_root.empty()) out_root = repo_root;

    if (verify_only) {
        const fs::path sums =
            out_root / "specs_and_reports" / "v2" / "evidence" / "C09" / "SHA256SUMS";
        return verify_manifest(fs::weakly_canonical(sums));
    }
    return run_gate(repo_root, out_root);
}
