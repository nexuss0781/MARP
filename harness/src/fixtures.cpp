#include "marp/harness/fixtures.hpp"

#include <mapr/e1_sha256.hpp>

#include <algorithm>
#include <bit>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

#include <fcntl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/utsname.h>
#include <unistd.h>

namespace marp::harness {
namespace fs = std::filesystem;

namespace {

// ---------------------------------------------------------------------------
// Pinned fixture constants. Provenance: H1 FIXTURES work item, normative
// catalogue in SPECS/SPECS-V2.md §12.3 and LFSR definition in §3.5. The parent
// spec's F10 "/dev/urandom" wording is overridden by the H1 requirement for a
// pinned PRNG and fixed seed; no entropy source is consulted.
// ---------------------------------------------------------------------------
constexpr std::uint64_t KIB = 1024;
constexpr std::uint64_t MIB = 1024 * KIB;
constexpr std::uint64_t GIB = 1024 * MIB;
constexpr std::size_t IO_BYTES = 64 * 1024;

constexpr std::uint64_t F03_BLOCK = 64 * KIB;
constexpr std::uint64_t F03_COUNT = 16384;
constexpr std::uint64_t F03_LINE = 64;
constexpr std::string_view F03_TEXT =
    "MARP v2 H1 FIXTURES: a byte string is opaque; no file-type classes. ";

constexpr std::uint64_t F04_TILE = 64 * KIB;
constexpr std::uint64_t F04_COUNT = 65536;
constexpr std::uint64_t F04_STRIDE = 13;
constexpr std::uint64_t F04_SALT = 0x5A;

constexpr std::uint64_t F07_CONN = 0xD800000000000000ULL;
constexpr std::uint64_t F07_INIT = 0x4D41525048314637ULL;

constexpr std::uint64_t F08_LEAF = 256;
constexpr std::uint64_t F08_COPIES = 16;
constexpr std::uint64_t F08_GROUPS = 16;
constexpr std::uint64_t F08_BLOCKS = 16384;
constexpr std::uint64_t F08_SEED = 0x4D415250463038ULL;
constexpr std::uint64_t F08_MUTATION_STRIDE = 17;

constexpr std::uint64_t F09_MEMBERS = 10;
constexpr std::uint64_t F09_MEMBER_BYTES = 100 * KIB;
constexpr std::uint64_t F09_SEED = 0x4D415250463039ULL;
constexpr std::uint64_t F09_MUTATION_BPS = 100; // per 10000, exact 1%
constexpr std::uint64_t F09_MUTATIONS = F09_MEMBER_BYTES * F09_MUTATION_BPS / 10000;
constexpr std::uint64_t F09_MUTATION_STRIDE = 101; // coprime with 102400
constexpr std::uint64_t F09_MEMBER_STRIDE = 97;

constexpr std::uint64_t F10_SEED = 0x4D415250463130ULL;
constexpr std::uint64_t F15_SEG4_BYTES = 768 * MIB;

constexpr std::uint64_t SPLITMIX_GAMMA = 0x9E3779B97F4A7C15ULL;
constexpr std::uint64_t SPLITMIX_MUL1 = 0xBF58476D1CE4E5B9ULL;
constexpr std::uint64_t SPLITMIX_MUL2 = 0x94D049BB133111EBULL;

std::string hex_of(const std::array<std::uint8_t, 32>& digest) {
    constexpr char digits[] = "0123456789abcdef";
    std::string out;
    out.reserve(64);
    for (std::uint8_t byte : digest) {
        out.push_back(digits[byte >> 4]);
        out.push_back(digits[byte & 0x0FU]);
    }
    return out;
}

template <typename T>
T unwrap(mapr::Result<T>&& result) {
    if (!result.ok()) {
        throw std::runtime_error("E1 operation failed");
    }
    return std::move(result).value();
}

std::uint64_t u64_exact(const BigInt& value) {
    const auto checked = value.to_u64_checked();
    if (!checked.has_value()) {
        throw std::overflow_error("integer exceeds uint64");
    }
    return checked.value();
}

BigInt big_add(const BigInt& a, const BigInt& b) {
    return unwrap(a.add(b));
}

BigInt big_sub(const BigInt& a, const BigInt& b) {
    return unwrap(a.sub(b));
}

BigInt power_of_two(std::size_t exponent) {
    return unwrap(BigInt::one().shl(exponent));
}

std::uint64_t min_u64(std::uint64_t a, std::uint64_t b) {
    return a < b ? a : b;
}

std::string decimal(std::uint64_t value) {
    return std::to_string(value);
}

std::string hex_u64(std::uint64_t value) {
    std::ostringstream out;
    out << "0x" << std::hex << std::nouppercase << value;
    return out.str();
}

bool is_lower_hex_sha(std::string_view text) {
    if (text.size() != 64) return false;
    for (char c : text) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    }
    return true;
}

bool is_canonical_decimal(std::string_view text) {
    if (text.empty()) return false;
    if (text == "0") return true;
    if (text[0] == '0') return false;
    for (char c : text) {
        if (c < '0' || c > '9') return false;
    }
    auto parsed = BigInt::from_decimal(text);
    return parsed.ok() && parsed.value().to_decimal() == text;
}

void require_field(std::string_view field) {
    if (field.find_first_of("\t\r\n") != std::string_view::npos) {
        throw std::runtime_error("TSV field contains a tab or newline");
    }
}

std::vector<std::string> split(std::string_view text, char delimiter) {
    std::vector<std::string> parts;
    std::size_t start = 0;
    while (true) {
        const std::size_t pos = text.find(delimiter, start);
        if (pos == std::string_view::npos) {
            parts.emplace_back(text.substr(start));
            break;
        }
        parts.emplace_back(text.substr(start, pos - start));
        start = pos + 1;
    }
    return parts;
}

void atomic_write(const fs::path& path, std::string_view text) {
    if (path.has_parent_path()) {
        fs::create_directories(path.parent_path());
    }
    fs::path temp = path;
    temp += ".tmp";
    {
        std::ofstream out(temp, std::ios::binary | std::ios::trunc);
        if (!out) throw std::runtime_error("cannot write " + temp.string());
        out.write(text.data(), static_cast<std::streamsize>(text.size()));
        out.flush();
        if (!out) throw std::runtime_error("short write " + temp.string());
    }
    fs::rename(temp, path);
}

bool files_equal(const fs::path& a, const fs::path& b) {
    std::ifstream left(a, std::ios::binary);
    std::ifstream right(b, std::ios::binary);
    if (!left || !right) return false;
    std::array<char, IO_BYTES> lb{};
    std::array<char, IO_BYTES> rb{};
    while (true) {
        left.read(lb.data(), static_cast<std::streamsize>(lb.size()));
        right.read(rb.data(), static_cast<std::streamsize>(rb.size()));
        const std::streamsize ln = left.gcount();
        const std::streamsize rn = right.gcount();
        if (ln != rn) return false;
        if (ln == 0) return left.eof() && right.eof();
        if (!std::equal(lb.begin(), lb.begin() + ln, rb.begin())) return false;
    }
}

std::string repo_relative(const fs::path& root, const fs::path& path) {
    std::error_code ec;
    const fs::path abs = fs::absolute(path, ec);
    if (ec) return "-";
    const fs::path rel = fs::relative(abs, fs::absolute(root, ec), ec);
    if (ec || rel.empty()) return "-";
    return rel.generic_string();
}

std::uint64_t hash_update(mapr::Sha256& ctx, std::span<const std::uint8_t> bytes) {
    const auto err = ctx.update(std::string_view(
        reinterpret_cast<const char*>(bytes.data()), bytes.size()));
    if (err != mapr::ErrCode::Ok) {
        throw std::runtime_error("SHA-256 update failed");
    }
    return static_cast<std::uint64_t>(bytes.size());
}

std::array<std::uint8_t, 32> hash_finish(mapr::Sha256& ctx) {
    return unwrap(ctx.finish());
}

std::array<std::uint8_t, 32> hash_bytes(std::span<const std::uint8_t> bytes) {
    mapr::Sha256 ctx;
    hash_update(ctx, bytes);
    return hash_finish(ctx);
}

std::uint64_t splitmix_next(std::uint64_t& state) {
    state += SPLITMIX_GAMMA;
    std::uint64_t z = state;
    z = (z ^ (z >> 30)) * SPLITMIX_MUL1;
    z = (z ^ (z >> 27)) * SPLITMIX_MUL2;
    return z ^ (z >> 31);
}

std::vector<std::uint8_t> prng_bytes(std::uint64_t seed, std::size_t len) {
    std::vector<std::uint8_t> out(len);
    std::uint64_t state = seed;
    std::size_t pos = 0;
    while (pos < len) {
        const std::uint64_t word = splitmix_next(state);
        for (unsigned byte = 0; byte < 8 && pos < len; ++byte) {
            out[pos++] = static_cast<std::uint8_t>((word >> (8 * byte)) & 0xFFU);
        }
    }
    return out;
}

std::vector<std::uint8_t> text_block() {
    std::vector<std::uint8_t> out(static_cast<std::size_t>(F03_BLOCK));
    for (std::size_t i = 0; i < out.size(); ++i) {
        if (static_cast<std::uint64_t>(i) % F03_LINE == F03_LINE - 1) {
            out[i] = static_cast<std::uint8_t>('\n');
        } else {
            out[i] = static_cast<std::uint8_t>(F03_TEXT[i % F03_TEXT.size()]);
        }
    }
    return out;
}

std::vector<std::uint8_t> periodic_tile() {
    std::vector<std::uint8_t> out(static_cast<std::size_t>(F04_TILE));
    for (std::size_t i = 0; i < out.size(); ++i) {
        const std::uint64_t v = (static_cast<std::uint64_t>(i) * F04_STRIDE) ^
                                (static_cast<std::uint64_t>(i) >> 8) ^ F04_SALT;
        out[i] = static_cast<std::uint8_t>(v & 0xFFU);
    }
    return out;
}

std::vector<std::uint8_t> grammar_block() {
    const std::vector<std::uint8_t> leaf =
        prng_bytes(F08_SEED, static_cast<std::size_t>(F08_LEAF));
    std::vector<std::uint8_t> out(static_cast<std::size_t>(
        F08_LEAF * F08_COPIES * F08_GROUPS));
    for (std::uint64_t group = 0; group < F08_GROUPS; ++group) {
        for (std::uint64_t copy = 0; copy < F08_COPIES; ++copy) {
            for (std::uint64_t j = 0; j < F08_LEAF; ++j) {
                std::uint8_t value = leaf[static_cast<std::size_t>(j)];
                if (group != 0 && j == (group * F08_MUTATION_STRIDE) % F08_LEAF) {
                    value = static_cast<std::uint8_t>(value ^ group);
                }
                const std::size_t pos = static_cast<std::size_t>(
                    (group * F08_COPIES + copy) * F08_LEAF + j);
                out[pos] = value;
            }
        }
    }
    return out;
}

std::vector<std::uint8_t> f09_base() {
    return prng_bytes(F09_SEED, static_cast<std::size_t>(F09_MEMBER_BYTES));
}

std::vector<std::uint8_t> f09_member(std::uint64_t member) {
    std::vector<std::uint8_t> out = f09_base();
    for (std::uint64_t j = 0; j < F09_MUTATIONS; ++j) {
        const std::size_t pos = static_cast<std::size_t>(
            (j * F09_MUTATION_STRIDE + member * F09_MEMBER_STRIDE) % F09_MEMBER_BYTES);
        const std::uint8_t delta = static_cast<std::uint8_t>(
            1 + ((j + member) % 255));
        out[pos] = static_cast<std::uint8_t>((out[pos] + delta) & 0xFFU);
    }
    return out;
}

// ---------------------------------------------------------------------------
// Deterministic, rewindable streams. All buffers are bounded by IO_BYTES or a
// pinned 64 KiB block; no stream allocates memory proportional to fixture size.
// ---------------------------------------------------------------------------
class VectorStream final : public FixtureStream {
public:
    explicit VectorStream(std::vector<std::uint8_t> data) : data_(std::move(data)) {}
    std::size_t read(std::span<std::uint8_t> out) override {
        const std::size_t n = std::min(out.size(), data_.size() - pos_);
        std::copy_n(data_.begin() + static_cast<std::ptrdiff_t>(pos_), n, out.begin());
        pos_ += n;
        return n;
    }
    void rewind() override { pos_ = 0; }
private:
    std::vector<std::uint8_t> data_;
    std::size_t pos_ = 0;
};

class ZeroStream final : public FixtureStream {
public:
    explicit ZeroStream(BigInt bytes) : bytes_(std::move(bytes)), pos_(0) {
        (void)u64_exact(bytes_);
    }
    std::size_t read(std::span<std::uint8_t> out) override {
        const std::uint64_t total = u64_exact(bytes_);
        const std::uint64_t n = min_u64(static_cast<std::uint64_t>(out.size()), total - pos_);
        std::memset(out.data(), 0, static_cast<std::size_t>(n));
        pos_ += n;
        return static_cast<std::size_t>(n);
    }
    void rewind() override { pos_ = 0; }
    bool supports_range() const override { return true; }
    void read_range(const BigInt& offset, std::span<std::uint8_t> out) override {
        const std::uint64_t start = u64_exact(offset);
        const std::uint64_t total = u64_exact(bytes_);
        if (start > total || static_cast<std::uint64_t>(out.size()) > total - start) {
            throw std::out_of_range("zero range outside fixture");
        }
        std::memset(out.data(), 0, out.size());
    }
private:
    BigInt bytes_;
    std::uint64_t pos_ = 0;
};

class RepeatStream final : public FixtureStream {
public:
    RepeatStream(std::vector<std::uint8_t> tile, BigInt bytes)
        : tile_(std::move(tile)), bytes_(std::move(bytes)), pos_(0) {
        (void)u64_exact(bytes_);
        if (tile_.empty()) throw std::invalid_argument("empty repeat tile");
    }
    std::size_t read(std::span<std::uint8_t> out) override {
        const std::uint64_t total = u64_exact(bytes_);
        std::uint64_t done = 0;
        const std::uint64_t want = min_u64(static_cast<std::uint64_t>(out.size()), total - pos_);
        while (done < want) {
            const std::size_t tile_pos = static_cast<std::size_t>((pos_ + done) % tile_.size());
            const std::uint64_t n = min_u64(want - done,
                static_cast<std::uint64_t>(tile_.size() - tile_pos));
            std::copy_n(tile_.begin() + static_cast<std::ptrdiff_t>(tile_pos),
                        static_cast<std::size_t>(n), out.begin() + static_cast<std::ptrdiff_t>(done));
            done += n;
        }
        pos_ += done;
        return static_cast<std::size_t>(done);
    }
    void rewind() override { pos_ = 0; }
    bool supports_range() const override { return true; }
    void read_range(const BigInt& offset, std::span<std::uint8_t> out) override {
        const std::uint64_t start = u64_exact(offset);
        const std::uint64_t total = u64_exact(bytes_);
        if (start > total || static_cast<std::uint64_t>(out.size()) > total - start) {
            throw std::out_of_range("repeat range outside fixture");
        }
        for (std::size_t i = 0; i < out.size(); ++i) {
            out[i] = tile_[static_cast<std::size_t>(
                (start + static_cast<std::uint64_t>(i)) % tile_.size())];
        }
    }
private:
    std::vector<std::uint8_t> tile_;
    BigInt bytes_;
    std::uint64_t pos_ = 0;
};

class AffineStream final : public FixtureStream {
public:
    AffineStream(BigInt bytes, std::uint64_t step, std::uint64_t bias)
        : total_(u64_exact(bytes)), step_(step), bias_(bias) {}
    std::size_t read(std::span<std::uint8_t> out) override {
        const std::uint64_t n = min_u64(static_cast<std::uint64_t>(out.size()), total_ - pos_);
        for (std::uint64_t i = 0; i < n; ++i) {
            out[static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(
                (((pos_ + i) % 256) * step_ + bias_) % 256);
        }
        pos_ += n;
        return static_cast<std::size_t>(n);
    }
    void rewind() override { pos_ = 0; }
private:
    std::uint64_t total_ = 0;
    std::uint64_t step_ = 0;
    std::uint64_t bias_ = 0;
    std::uint64_t pos_ = 0;
};

class LfsrStream final : public FixtureStream {
public:
    LfsrStream(BigInt bytes, std::uint64_t conn, std::uint64_t init)
        : total_(u64_exact(bytes)), conn_(conn), init_(init), state_(init) {
        if (conn_ == 0 || init_ == 0) throw std::invalid_argument("invalid LFSR constant");
    }
    std::size_t read(std::span<std::uint8_t> out) override {
        const std::uint64_t n = min_u64(static_cast<std::uint64_t>(out.size()), total_ - pos_);
        for (std::uint64_t i = 0; i < n; ++i) {
            std::uint8_t byte = 0;
            for (unsigned bit_index = 0; bit_index < 8; ++bit_index) {
                const std::uint64_t bit = static_cast<std::uint64_t>(
                    std::popcount(state_ & conn_) & 1);
                state_ = (state_ >> 1) | (bit << 63);
                byte = static_cast<std::uint8_t>((byte << 1) | bit);
            }
            out[static_cast<std::size_t>(i)] = byte;
        }
        pos_ += n;
        return static_cast<std::size_t>(n);
    }
    void rewind() override { pos_ = 0; state_ = init_; }
private:
    std::uint64_t total_ = 0;
    std::uint64_t conn_ = 0;
    std::uint64_t init_ = 0;
    std::uint64_t state_ = 0;
    std::uint64_t pos_ = 0;
};

class PrngStream final : public FixtureStream {
public:
    PrngStream(BigInt bytes, std::uint64_t seed)
        : total_(u64_exact(bytes)), seed_(seed), state_(seed) {}
    std::size_t read(std::span<std::uint8_t> out) override {
        const std::uint64_t n = min_u64(static_cast<std::uint64_t>(out.size()), total_ - pos_);
        for (std::uint64_t i = 0; i < n; ++i) {
            if (used_ == 8) {
                word_ = splitmix_next(state_);
                used_ = 0;
            }
            out[static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(
                (word_ >> (8 * used_)) & 0xFFU);
            ++used_;
        }
        pos_ += n;
        return static_cast<std::size_t>(n);
    }
    void rewind() override { pos_ = 0; state_ = seed_; used_ = 8; word_ = 0; }
private:
    std::uint64_t total_ = 0;
    std::uint64_t seed_ = 0;
    std::uint64_t state_ = 0;
    std::uint64_t word_ = 0;
    unsigned used_ = 8;
    std::uint64_t pos_ = 0;
};

class FileStream final : public FixtureStream {
public:
    explicit FileStream(const fs::path& path) : in_(path, std::ios::binary) {
        if (!in_) throw std::runtime_error("cannot open supplied bytes: " + path.string());
    }
    std::size_t read(std::span<std::uint8_t> out) override {
        in_.read(reinterpret_cast<char*>(out.data()),
                 static_cast<std::streamsize>(out.size()));
        const std::streamsize got = in_.gcount();
        if (in_.bad()) throw std::runtime_error("supplied byte read failed");
        return static_cast<std::size_t>(got);
    }
    void rewind() override {
        in_.clear();
        in_.seekg(0, std::ios::beg);
        if (!in_) throw std::runtime_error("supplied byte rewind failed");
    }
private:
    std::ifstream in_;
};

class ConcatStream final : public FixtureStream {
public:
    explicit ConcatStream(std::vector<std::unique_ptr<FixtureStream>> parts)
        : parts_(std::move(parts)) {}
    std::size_t read(std::span<std::uint8_t> out) override {
        std::size_t done = 0;
        while (done < out.size() && current_ < parts_.size()) {
            const std::size_t got = parts_[current_]->read(out.subspan(done));
            if (got == 0) {
                ++current_;
            } else {
                done += got;
            }
        }
        return done;
    }
    void rewind() override {
        for (auto& part : parts_) part->rewind();
        current_ = 0;
    }
private:
    std::vector<std::unique_ptr<FixtureStream>> parts_;
    std::size_t current_ = 0;
};

const std::vector<std::string>& ordered_ids() {
    static const std::vector<std::string> ids = {
        "F00", "F01", "F02", "F03", "F04", "F05", "F06", "F07", "F08",
        "F09", "F09.0", "F09.1", "F09.2", "F09.3", "F09.4",
        "F09.5", "F09.6", "F09.7", "F09.8", "F09.9",
        "F10", "F11", "F12", "F13", "F14", "F15",
        "F15.seg0", "F15.seg1", "F15.seg2", "F15.seg3", "F15.seg4"
    };
    return ids;
}

bool is_segment(std::string_view id) {
    return id.rfind("F15.seg", 0) == 0;
}

std::string segment_source(std::string_view id) {
    if (id == "F15.seg0") return "F02";
    if (id == "F15.seg1") return "F03";
    if (id == "F15.seg2") return "F05";
    if (id == "F15.seg3") return "F06";
    if (id == "F15.seg4") return "F10";
    throw std::invalid_argument("unknown segment");
}

std::uint64_t segment_bytes(std::string_view id) {
    if (id == "F15.seg0") return GIB;
    if (id == "F15.seg1") return GIB;
    if (id == "F15.seg2") return 256 * MIB;
    if (id == "F15.seg3") return GIB;
    if (id == "F15.seg4") return F15_SEG4_BYTES;
    throw std::invalid_argument("unknown segment");
}

std::string segment_params(std::string_view id) {
    const std::size_t index = static_cast<std::size_t>(id.back() - '0');
    return "kind=segment;segment=" + std::to_string(index) +
           ";source=" + segment_source(id) + ";source_offset=0;bytes=" +
           decimal(segment_bytes(id));
}

std::string f15_layout() {
    return "F02:" + decimal(GIB) + ",F03:" + decimal(GIB) +
           ",F05:" + decimal(256 * MIB) + ",F06:" + decimal(GIB) +
           ",F10:" + decimal(F15_SEG4_BYTES);
}

const FixtureSpec* find_spec(const std::vector<FixtureSpec>& specs, std::string_view id) {
    for (const auto& spec : specs) {
        if (spec.id == id) return &spec;
    }
    return nullptr;
}

std::unique_ptr<FixtureStream> stream_for_spec(const FixtureSpec& spec,
                                               const GenerateOptions& options) {
    const std::string id = spec.id;
    if (id == "F00") return std::make_unique<VectorStream>(std::vector<std::uint8_t>{});
    if (id == "F01") return std::make_unique<VectorStream>(std::vector<std::uint8_t>{0xA5});
    if (id == "F02") return std::make_unique<ZeroStream>(spec.bytes);
    if (id == "F03") return std::make_unique<RepeatStream>(text_block(), spec.bytes);
    if (id == "F04") return std::make_unique<RepeatStream>(periodic_tile(), spec.bytes);
    if (id == "F05") return std::make_unique<AffineStream>(spec.bytes, 3, 11);
    if (id == "F06") return std::make_unique<AffineStream>(spec.bytes, 1, 0);
    if (id == "F07") return std::make_unique<LfsrStream>(spec.bytes, F07_CONN, F07_INIT);
    if (id == "F08") return std::make_unique<RepeatStream>(grammar_block(), spec.bytes);
    if (id == "F09") {
        std::vector<std::unique_ptr<FixtureStream>> parts;
        for (std::uint64_t member = 0; member < F09_MEMBERS; ++member) {
            parts.push_back(std::make_unique<VectorStream>(f09_member(member)));
        }
        return std::make_unique<ConcatStream>(std::move(parts));
    }
    if (id.size() == 5 && id.rfind("F09.", 0) == 0 && id[4] >= '0' && id[4] <= '9') {
        return std::make_unique<VectorStream>(f09_member(static_cast<std::uint64_t>(id[4] - '0')));
    }
    if (id == "F10") return std::make_unique<PrngStream>(spec.bytes, F10_SEED);
    if (id == "F11") return std::make_unique<FileStream>(options.real);
    if (id == "F12") return std::make_unique<FileStream>(options.coded);
    if (id == "F13") return std::make_unique<ZeroStream>(spec.bytes);
    if (id == "F14") return std::make_unique<RepeatStream>(periodic_tile(), spec.bytes);
    if (id == "F15") {
        std::vector<std::unique_ptr<FixtureStream>> parts;
        const auto specs = catalogue(options);
        for (int segment = 0; segment < 5; ++segment) {
            const std::string seg_id = "F15.seg" + std::to_string(segment);
            const FixtureSpec* seg = find_spec(specs, seg_id);
            if (seg == nullptr) throw std::invalid_argument("missing F15 segment");
            parts.push_back(stream_for_spec(*seg, options));
        }
        return std::make_unique<ConcatStream>(std::move(parts));
    }
    if (is_segment(id)) {
        const std::string source = segment_source(id);
        if (source == "F02") return std::make_unique<ZeroStream>(spec.bytes);
        if (source == "F03") return std::make_unique<RepeatStream>(text_block(), spec.bytes);
        if (source == "F05") return std::make_unique<AffineStream>(spec.bytes, 3, 11);
        if (source == "F06") return std::make_unique<AffineStream>(spec.bytes, 1, 0);
        if (source == "F10") return std::make_unique<PrngStream>(spec.bytes, F10_SEED);
    }
    throw std::invalid_argument("unknown fixture id");
}

struct StreamIdentity {
    std::uint64_t bytes = 0;
    std::array<std::uint8_t, 32> sha256{};
};

StreamIdentity hash_stream(FixtureStream& stream, const BigInt* expected) {
    std::array<std::uint8_t, IO_BYTES> buffer{};
    mapr::Sha256 ctx;
    std::uint64_t total = 0;
    const std::uint64_t expected_u64 = expected ? u64_exact(*expected) : 0;
    while (true) {
        const std::size_t got = stream.read(std::span<std::uint8_t>(buffer));
        if (got == 0) break;
        total += hash_update(ctx, std::span<const std::uint8_t>(buffer.data(), got));
        if (expected && total > expected_u64) {
            throw std::runtime_error("stream exceeded exact fixture length");
        }
    }
    if (expected && total != expected_u64) {
        throw std::runtime_error("stream length mismatch");
    }
    return {total, hash_finish(ctx)};
}

struct Identified {
    Fixture fixture;
    FixtureMode mode = FixtureMode::Generated;
    std::string params;
    std::string path;
    std::string gates;
};

Identified identify_spec(const FixtureSpec& spec, const GenerateOptions& options) {
    Identified out;
    out.fixture.id = spec.id;
    out.fixture.bytes = spec.bytes;
    out.mode = spec.mode;
    out.params = spec.params;
    out.path = "-";
    out.gates = "-";

    if (spec.mode == FixtureMode::Virtual) {
        return out;
    }
    if (spec.mode == FixtureMode::Supplied) {
        const fs::path supplied = spec.id == "F11" ? options.real : options.coded;
        const std::string option = spec.id == "F11" ? "--real" : "--coded";
        out.gates = affected_gates();
        if (supplied.empty()) {
            out.mode = FixtureMode::Blocked;
            out.fixture.bytes = BigInt::zero();
            out.params = "source=supplied;option=" + option + ";reason=missing_path;requested=-";
            std::cerr << "BLOCKED " << spec.id << " missing path: (" << option
                      << " not supplied) affected gates: " << out.gates << "\n";
            return out;
        }
        try {
            auto stream = stream_for_spec(spec, options);
            const StreamIdentity identity = hash_stream(*stream, nullptr);
            out.fixture.bytes = BigInt(identity.bytes);
            out.fixture.sha256 = identity.sha256;
            out.path = repo_relative(options.root, supplied);
            out.fixture.path = out.path == "-" ? supplied.string() : out.path;
            out.params = "source=supplied;option=" + option;
            return out;
        } catch (const std::exception& ex) {
            out.mode = FixtureMode::Blocked;
            out.fixture.bytes = BigInt::zero();
            out.fixture.sha256.fill(0);
            out.path = "-";
            out.params = "source=supplied;option=" + option + ";reason=unreadable_path;requested=" +
                         supplied.string();
            std::cerr << "BLOCKED " << spec.id << " missing path: " << supplied.string()
                      << " (" << ex.what() << ") affected gates: " << out.gates << "\n";
            return out;
        }
    }

    auto stream = stream_for_spec(spec, options);
    const StreamIdentity identity = hash_stream(*stream, &spec.bytes);
    out.fixture.bytes = BigInt(identity.bytes);
    out.fixture.sha256 = identity.sha256;
    return out;
}

ManifestRow to_row(const Identified& identified) {
    ManifestRow row;
    row.fixture = identified.fixture.id;
    row.mode = mode_name(identified.mode);
    row.bytes = identified.fixture.bytes.to_decimal();
    row.sha256 = (identified.mode == FixtureMode::Virtual ||
                  identified.mode == FixtureMode::Blocked)
                     ? "-" : hex_of(identified.fixture.sha256);
    row.params = identified.params;
    row.path = identified.path;
    row.gates = identified.gates;
    return row;
}

FixtureEvidenceRow make_row(std::string check, std::string item,
                            std::string input_sha, std::string expected,
                            std::string actual, std::string verdict) {
    FixtureEvidenceRow row;
    row.check = std::move(check);
    row.corpus = "FIXTURES";
    row.item_id = std::move(item);
    row.input_sha256 = std::move(input_sha);
    row.expected = std::move(expected);
    row.actual = std::move(actual);
    row.verdict = std::move(verdict);
    row.log = "logs/H1-FIXTURES.log#" + row.check + ":" + row.item_id;
    return row;
}

fs::path evidence_tsv_path(const fs::path& root) {
    return root / "specs_and_reports" / "v2" / "gates" / "H1-FIXTURES.tsv";
}
fs::path evidence_log_path(const fs::path& root) {
    return root / "specs_and_reports" / "v2" / "logs" / "H1-FIXTURES.log";
}
fs::path evidence_sums_path(const fs::path& root) {
    return root / "specs_and_reports" / "v2" / "evidence" / "H1" / "SHA256SUMS";
}
fs::path evidence_report_path(const fs::path& root) {
    return root / "REPORT" / "HARNESS" / "H1-FIXTURES-REPORT.md";
}

std::vector<FixtureEvidenceRow> read_evidence(const fs::path& path) {
    std::vector<FixtureEvidenceRow> rows;
    std::ifstream in(path);
    if (!in) return rows;
    std::string line;
    if (!std::getline(in, line)) return rows;
    if (line != "check\tcorpus\titem_id\tinput_sha256\texpected\tactual\tverdict\tlog") {
        throw std::runtime_error("invalid H1 evidence header");
    }
    while (std::getline(in, line)) {
        if (line.empty()) continue;
        const auto fields = split(line, '\t');
        if (fields.size() != 8) throw std::runtime_error("invalid H1 evidence row");
        rows.push_back({fields[0], fields[1], fields[2], fields[3],
                        fields[4], fields[5], fields[6], fields[7]});
    }
    return rows;
}

std::string evidence_text(std::vector<FixtureEvidenceRow> rows) {
    std::stable_sort(rows.begin(), rows.end(), [](const auto& a, const auto& b) {
        if (a.check != b.check) return a.check < b.check;
        return a.item_id < b.item_id;
    });
    std::ostringstream out;
    out << "check\tcorpus\titem_id\tinput_sha256\texpected\tactual\tverdict\tlog\n";
    for (const auto& row : rows) {
        for (const std::string* field : {&row.check, &row.corpus, &row.item_id,
                                         &row.input_sha256, &row.expected,
                                         &row.actual, &row.verdict, &row.log}) {
            require_field(*field);
        }
        if (row.verdict != "PASS" && row.verdict != "FAIL" && row.verdict != "BLOCKED") {
            throw std::runtime_error("invalid evidence verdict");
        }
        out << row.check << '\t' << row.corpus << '\t' << row.item_id << '\t'
            << row.input_sha256 << '\t' << row.expected << '\t' << row.actual << '\t'
            << row.verdict << '\t' << row.log << '\n';
    }
    return out.str();
}

std::string utc_now() {
    const auto now = std::chrono::system_clock::now();
    const std::time_t time = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
    gmtime_r(&time, &tm);
    std::array<char, 64> buffer{};
    std::strftime(buffer.data(), buffer.size(), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return std::string(buffer.data());
}

std::string capture_command(const char* command) {
    std::string out;
    FILE* pipe = popen(command, "r");
    if (pipe == nullptr) return "-";
    std::array<char, 512> buffer{};
    while (std::fgets(buffer.data(), static_cast<int>(buffer.size()), pipe) != nullptr) {
        out += buffer.data();
    }
    pclose(pipe);
    while (!out.empty() && (out.back() == '\n' || out.back() == '\r')) out.pop_back();
    return out.empty() ? "-" : out;
}

std::string environment_header(const EvidenceContext& context,
                               const std::string& manifest_sha) {
    std::ostringstream out;
    utsname uts{};
    uname(&uts);
    std::array<char, 256> host{};
    gethostname(host.data(), host.size());
    long nproc = sysconf(_SC_NPROCESSORS_ONLN);
    if (nproc < 0) nproc = 0;
    std::ifstream meminfo("/proc/meminfo");
    std::string mem_line;
    std::string mem_total = "-";
    if (meminfo && std::getline(meminfo, mem_line)) {
        std::istringstream iss(mem_line);
        std::string label;
        std::uint64_t value = 0;
        std::string unit;
        if (iss >> label >> value >> unit) mem_total = decimal(value);
    }
    struct statvfs disk_stat {};
    std::string disk = "-";
    if (statvfs(context.root.c_str(), &disk_stat) == 0) {
        const std::uint64_t bytes = static_cast<std::uint64_t>(disk_stat.f_blocks) *
                                    static_cast<std::uint64_t>(disk_stat.f_frsize);
        disk = decimal(bytes);
    }
    rusage usage{};
    getrusage(RUSAGE_SELF, &usage);
    std::string binary_sha = "-";
    std::error_code ec;
    const fs::path self = fs::read_symlink("/proc/self/exe", ec);
    if (!ec) binary_sha = sha256_file_hex(self);
    out << "date_utc: " << utc_now() << "\n"
        << "host: " << host.data() << "\n"
        << "kernel: " << uts.release << "\n"
        << "nproc: " << nproc << "\n"
        << "mem_total_kib: " << mem_total << "\n"
        << "disk: " << disk << "\n"
#ifdef __VERSION__
        << "compiler: " << __VERSION__ << "\n"
#else
        << "compiler: -\n"
#endif
        << "make: " << capture_command("make --version | head -1") << "\n"
        << "engine_sha256: " << binary_sha << "\n"
        << "test_sha256: -\n"
        << "fixture_manifest_sha256: " << manifest_sha << "\n"
        << "max_rss_kib: " << usage.ru_maxrss << "\n"
        << "ci_run_id: " << (context.ci_run_id.empty() ? "-" : context.ci_run_id) << "\n"
        << "ci_run_url: " << (context.ci_run_url.empty() ? "-" : context.ci_run_url) << "\n"
        << "commit: " << (context.commit.empty() ? "-" : context.commit) << "\n"
        << "runner_os: " << (context.runner_os.empty() ? "-" : context.runner_os) << "\n"
        << "command_line: " << context.command_line << "\n";
    return out.str();
}

std::map<std::string, std::vector<std::string>> read_log_sections(const fs::path& path) {
    std::map<std::string, std::vector<std::string>> sections;
    std::ifstream in(path);
    if (!in) return sections;
    std::string line;
    std::string current;
    while (std::getline(in, line)) {
        if (line.rfind("[#/", 0) == 0) {
            current.clear();
        } else if (line.rfind("[#", 0) == 0 && line.back() == ']') {
            current = line.substr(2, line.size() - 3);
            sections[current];
        } else if (!current.empty()) {
            sections[current].push_back(line);
        }
    }
    return sections;
}

void write_report(const EvidenceContext& context,
                  const std::vector<ManifestRow>& manifest,
                  const std::vector<FixtureEvidenceRow>& rows,
                  const fs::path& log_path) {
    bool fail = false;
    bool blocked = false;
    std::size_t pass_count = 0;
    std::size_t fail_count = 0;
    std::size_t blocked_count = 0;
    for (const auto& row : rows) {
        if (row.verdict == "FAIL") {
            fail = true;
            ++fail_count;
        } else if (row.verdict == "BLOCKED") {
            blocked = true;
            ++blocked_count;
        } else {
            ++pass_count;
        }
    }
    const std::string status = fail ? "FAIL" : (blocked ? "BLOCKED" : "PASS");
    std::ostringstream out;
    out << "# H1 FIXTURES — Identity Report\n\n"
        << "Generated by `bin/mapr_fixtures`; do not hand-edit measured rows.\n\n"
        << "## 1. Environment\n\n"
        << "- Root: `" << fs::absolute(context.root).generic_string() << "`\n"
        << "- Commit: `" << (context.commit.empty() ? "-" : context.commit) << "`\n"
        << "- Authoritative artifact CI run: "
        << (context.ci_run_id.empty() ? "-" : context.ci_run_id) << "\n"
        << "- CI run URL: " << (context.ci_run_url.empty() ? "-" : context.ci_run_url) << "\n"
        << "- Runner OS: " << (context.runner_os.empty() ? "-" : context.runner_os) << "\n"
        << "- Environment/log: `" << repo_relative(context.root, log_path) << "`\n"
        << "- Manifest SHA-256: `" << sha256_file_hex(context.manifest) << "`\n\n"
        << "## 2. Files\n\n"
        << "`harness/include/marp/harness/fixtures.hpp`, `harness/src/fixtures.cpp`, "
        << "`harness/src/fixtures_cli.cpp`, `harness/tests/fixtures_test.cpp`, "
        << "`engine/Makefile.h1`, `.github/workflows/h1-fixtures.yml`, "
        << "`specs_and_reports/v2/fixtures.tsv`, "
        << "`specs_and_reports/v2/gates/H1-FIXTURES.tsv`, "
        << "`specs_and_reports/v2/logs/H1-FIXTURES.log`, "
        << "`specs_and_reports/v2/evidence/H1/SHA256SUMS`, and this report.\n\n"
        << "## 3. Fixture catalogue and pinned constants\n\n"
        << "| fixture | mode | bytes | sha256 | params | path | gates |\n"
        << "|---|---|---:|---|---|---|---|\n";
    for (const auto& row : manifest) {
        out << "| " << row.fixture << " | " << row.mode << " | " << row.bytes
            << " | " << row.sha256 << " | " << row.params << " | " << row.path
            << " | " << row.gates << " |\n";
    }
    out << "\nPinned patterns: F03 uses the recorded 64 KiB text block; F04 uses "
           "`tile[i]=((i*13)^(i>>8)^0x5a)&255`; F07 uses conn/init recorded in "
           "params with MSB-first packing; F08 uses the recorded nested "
           "leaf/copy/group/block grammar; F09 uses SplitMix64 base bytes and "
           "exactly 1024 distinct mutations per 102400-byte member; F10 and "
           "F15.seg4 use SplitMix64 with the recorded seed and little-endian "
           "8-byte draws. F13/F14 are descriptors only.\n\n"
        << "## 4. Determinism and identity evidence\n\n";
    for (const auto& row : rows) {
        if (row.check == "fixtures.determinism" || row.check == "fixtures.catalog" ||
            row.check == "fixtures.concat") {
            out << "- `" << row.check << "/" << row.item_id << "`: expected `"
                << row.expected << "`, actual `" << row.actual << "`, verdict `"
                << row.verdict << "`.\n";
        }
    }
    out << "\nEvery generated identity is recomputed by `--verify`; the per-item "
           "`fixtures.identity` rows record expected and measured byte counts "
           "and digests. Two independent generations are compared byte-for-byte "
           "when `--determinism` is used.\n\n"
        << "## 5. Storage and virtual policy\n\n"
        << "Default generation streams through bounded 64 KiB buffers and writes "
        << "no fixture payloads. F13/F14 are never materialised and have no "
        << "digest; end-range reads are supported. Explicit materialisation uses "
        << "sparse zero runs. Peak RSS and host measurements are in the log.\n\n"
        << "## 6. Supplied fixtures\n\n";
    for (const auto& row : rows) {
        if (row.check == "fixtures.supplied") {
            out << "- `" << row.item_id << "`: " << row.actual << " — verdict `"
                << row.verdict << "`; affected gates `" << affected_gates() << "`.\n";
        }
    }
    out << "\nMissing F11/F12 are BLOCKED, never PASS. H1 records identity only; "
           "it does not claim wire-level E0-G or any downstream gate verdict.\n\n"
        << "## 7. Decisions and deviations\n\n"
        << "- Manifest order is hierarchical: F00..F15 with F09 members immediately "
           "after F09 and F15 segments immediately after F15.\n"
        << "- F09.0..F09.9 each have exactly 1% mutated positions relative to the "
           "pinned base; the aggregate is their true concatenation.\n"
        << "- F10 uses a pinned SplitMix64 seed, not `/dev/urandom`, as required by H1.\n"
        << "- F15.seg4 is the first 768 MiB of F10, preserving the stated 4 GiB total.\n"
        << "- Evidence TSV rows are deterministic; the log/report carry run environment "
           "and artifact-run provenance. Final CI verifies and uploads committed evidence.\n"
        << "- Current Arena branch is used; the workflow also accepts the requested "
           "`h1-fixtures` branch name.\n\n"
        << "## 8. Acceptance summary\n\n"
        << "- Evidence rows: " << rows.size() << "\n"
        << "- PASS rows: " << pass_count << "\n"
        << "- FAIL rows: " << fail_count << "\n"
        << "- BLOCKED rows: " << blocked_count << "\n"
        << "- Report status: **" << status << "**\n\n"
        << "A BLOCKED report is intentional when supplied fixtures are absent; "
        << "generated-fixture identity checks can still be validated by green CI. "
        << "No overall PASS is claimed while any required row is FAIL/BLOCKED.\n\n"
        << "## 9. Next work\n\n"
        << "H3 ORACLE, then wire-level E0-G once E3 exists.\n";
    atomic_write(evidence_report_path(context.root), out.str());
}

void write_sums(const EvidenceContext& context) {
    const fs::path tsv = evidence_tsv_path(context.root);
    const fs::path log = evidence_log_path(context.root);
    const fs::path report = evidence_report_path(context.root);
    std::ostringstream out;
    for (const fs::path& path : {context.manifest, tsv, log, report}) {
        const std::string rel = repo_relative(context.root, path);
        if (rel == "-" || fs::path(rel).is_absolute()) {
            throw std::runtime_error("evidence path is outside root: " + path.string());
        }
        out << sha256_file_hex(path) << "  " << rel << "\n";
    }
    atomic_write(evidence_sums_path(context.root), out.str());
}

FixtureEvidenceRow virtual_check(const FixtureSpec& spec, const GenerateOptions& options) {
    constexpr std::size_t len = 64;
    const BigInt offset = big_sub(spec.bytes, BigInt(len));
    auto stream = stream_for_spec(spec, options);
    std::array<std::uint8_t, len> actual{};
    stream->read_range(offset, std::span<std::uint8_t>(actual));
    std::array<std::uint8_t, len> expected{};
    if (spec.id == "F14") {
        const auto tile = periodic_tile();
        const std::uint64_t start = u64_exact(offset);
        for (std::size_t i = 0; i < len; ++i) {
            expected[i] = tile[static_cast<std::size_t>(
                (start + static_cast<std::uint64_t>(i)) % tile.size())];
        }
    }
    const std::string expected_sha = hex_of(hash_bytes(expected));
    const std::string actual_sha = hex_of(hash_bytes(actual));
    const std::string value = "bytes=" + spec.bytes.to_decimal() +
                              ";offset=" + offset.to_decimal() +
                              ";len=" + decimal(len) + ";sha=" + expected_sha;
    const std::string measured = "bytes=" + spec.bytes.to_decimal() +
                                 ";offset=" + offset.to_decimal() +
                                 ";len=" + decimal(len) + ";sha=" + actual_sha;
    return make_row("fixtures.virtual", spec.id, "-", value, measured,
                    expected == actual ? "PASS" : "FAIL");
}

void validate_manifest_rows(const std::vector<ManifestRow>& rows) {
    const auto ids = catalogue_ids();
    if (rows.size() != ids.size()) {
        throw std::runtime_error("manifest catalogue is incomplete");
    }
    for (std::size_t i = 0; i < rows.size(); ++i) {
        const auto& row = rows[i];
        if (row.fixture != ids[i]) throw std::runtime_error("manifest order/duplicate mismatch");
        if (row.mode != "generated" && row.mode != "supplied" &&
            row.mode != "virtual" && row.mode != "blocked") {
            throw std::runtime_error("invalid manifest mode");
        }
        if (!is_canonical_decimal(row.bytes)) throw std::runtime_error("invalid manifest byte count");
        if (row.mode == "virtual" || row.mode == "blocked") {
            if (row.sha256 != "-") throw std::runtime_error("virtual/blocked digest must be -");
        } else if (!is_lower_hex_sha(row.sha256)) {
            throw std::runtime_error("invalid manifest digest");
        }
        for (const std::string* field : {&row.fixture, &row.mode, &row.bytes,
                                         &row.sha256, &row.params, &row.path, &row.gates}) {
            require_field(*field);
        }
        if (row.path != "-" && fs::path(row.path).is_absolute()) {
            throw std::runtime_error("manifest path must be repo-relative or -");
        }
    }
}

} // namespace

void FixtureStream::read_range(const BigInt& offset, std::span<std::uint8_t> out) {
    rewind();
    BigInt remaining = offset;
    std::array<std::uint8_t, IO_BYTES> scratch{};
    while (!remaining.is_zero()) {
        const std::uint64_t available = u64_exact(remaining);
        const std::size_t want = static_cast<std::size_t>(
            min_u64(available, static_cast<std::uint64_t>(scratch.size())));
        const std::size_t got = read(std::span<std::uint8_t>(scratch.data(), want));
        if (got != want) throw std::out_of_range("range offset outside stream");
        remaining = big_sub(remaining, BigInt(static_cast<std::uint64_t>(got)));
    }
    std::size_t done = 0;
    while (done < out.size()) {
        const std::size_t got = read(out.subspan(done));
        if (got == 0) throw std::out_of_range("range end outside stream");
        done += got;
    }
}

std::string mode_name(FixtureMode mode) {
    switch (mode) {
        case FixtureMode::Generated: return "generated";
        case FixtureMode::Supplied: return "supplied";
        case FixtureMode::Virtual: return "virtual";
        case FixtureMode::Blocked: return "blocked";
    }
    throw std::invalid_argument("invalid fixture mode");
}

std::string digest_hex(const std::array<std::uint8_t, 32>& digest) {
    return hex_of(digest);
}

std::string sha256_hex(std::span<const std::uint8_t> bytes) {
    return hex_of(hash_bytes(bytes));
}

std::string sha256_file_hex(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return "";
    std::array<std::uint8_t, IO_BYTES> buffer{};
    mapr::Sha256 ctx;
    while (true) {
        in.read(reinterpret_cast<char*>(buffer.data()),
                static_cast<std::streamsize>(buffer.size()));
        const std::streamsize got = in.gcount();
        if (got > 0) {
            hash_update(ctx, std::span<const std::uint8_t>(
                buffer.data(), static_cast<std::size_t>(got)));
        }
        if (got == 0) break;
    }
    if (in.bad()) return "";
    return hex_of(hash_finish(ctx));
}

std::string affected_gates() {
    return "V2-G1,V2-G6,V2-G7,V2-G14";
}

std::vector<std::string> catalogue_ids() {
    return ordered_ids();
}

std::vector<FixtureSpec> catalogue(const GenerateOptions& options) {
    (void)options;
    std::vector<FixtureSpec> specs;
    const auto add = [&](std::string id, FixtureMode mode, BigInt bytes, std::string params) {
        specs.push_back({std::move(id), mode, std::move(bytes), std::move(params)});
    };
    const std::string text_sha = hex_of(hash_bytes(text_block()));
    const std::string tile_sha = hex_of(hash_bytes(periodic_tile()));
    const std::string grammar_sha = hex_of(hash_bytes(grammar_block()));
    const std::string base_sha = hex_of(hash_bytes(f09_base()));

    add("F00", FixtureMode::Generated, BigInt::zero(), "kind=empty");
    add("F01", FixtureMode::Generated, BigInt(1), "kind=literal;value=0xa5");
    add("F02", FixtureMode::Generated, BigInt(GIB), "kind=zero;bytes=" + decimal(GIB));
    add("F03", FixtureMode::Generated, BigInt(F03_BLOCK * F03_COUNT),
        "kind=text-repeat;block=" + decimal(F03_BLOCK) + ";count=" + decimal(F03_COUNT) +
        ";line=" + decimal(F03_LINE) + ";text_sha256=" + text_sha);
    add("F04", FixtureMode::Generated, BigInt(F04_TILE * F04_COUNT),
        "kind=tile-repeat;tile=" + decimal(F04_TILE) + ";count=" + decimal(F04_COUNT) +
        ";stride=" + decimal(F04_STRIDE) + ";salt=" + hex_u64(F04_SALT) +
        ";tile_sha256=" + tile_sha);
    add("F05", FixtureMode::Generated, BigInt(256 * MIB), "kind=affine;step=3;bias=11;mod=256");
    add("F06", FixtureMode::Generated, BigInt(GIB), "kind=affine;step=1;bias=0;mod=256");
    add("F07", FixtureMode::Generated, BigInt(GIB),
        "kind=lfsr;bits=64;conn=" + hex_u64(F07_CONN) + ";init=" + hex_u64(F07_INIT) + ";pack=msb");
    add("F08", FixtureMode::Generated, BigInt(F08_LEAF * F08_COPIES * F08_GROUPS * F08_BLOCKS),
        "kind=grammar;leaf=" + decimal(F08_LEAF) + ";copies=" + decimal(F08_COPIES) +
        ";groups=" + decimal(F08_GROUPS) + ";blocks=" + decimal(F08_BLOCKS) +
        ";seed=" + hex_u64(F08_SEED) + ";mutation_stride=" + decimal(F08_MUTATION_STRIDE) +
        ";block_sha256=" + grammar_sha);
    add("F09", FixtureMode::Generated, BigInt(F09_MEMBERS * F09_MEMBER_BYTES),
        "kind=near-corpus;members=" + decimal(F09_MEMBERS) + ";member_bytes=" + decimal(F09_MEMBER_BYTES) +
        ";layout=concat;seed=" + hex_u64(F09_SEED) + ";mutation_bps=" + decimal(F09_MUTATION_BPS) +
        ";mutations_per_member=" + decimal(F09_MUTATIONS) + ";mutation_stride=" + decimal(F09_MUTATION_STRIDE) +
        ";member_stride=" + decimal(F09_MEMBER_STRIDE) + ";base_sha256=" + base_sha);
    for (std::uint64_t member = 0; member < F09_MEMBERS; ++member) {
        add("F09." + std::to_string(member), FixtureMode::Generated, BigInt(F09_MEMBER_BYTES),
            "kind=near-member;member=" + std::to_string(member) + ";bytes=" + decimal(F09_MEMBER_BYTES) +
            ";seed=" + hex_u64(F09_SEED) + ";mutation_bps=" + decimal(F09_MUTATION_BPS) +
            ";mutations=" + decimal(F09_MUTATIONS) + ";stride=" + decimal(F09_MUTATION_STRIDE) +
            ";member_stride=" + decimal(F09_MEMBER_STRIDE));
    }
    add("F10", FixtureMode::Generated, BigInt(GIB),
        "kind=prng;prng=splitmix64;seed=" + hex_u64(F10_SEED) + ";order=le;bytes_per_draw=8");
    add("F11", FixtureMode::Supplied, BigInt::zero(), "source=supplied;option=--real");
    add("F12", FixtureMode::Supplied, BigInt::zero(), "source=supplied;option=--coded");
    add("F13", FixtureMode::Virtual, power_of_two(40),
        "kind=spec-zero;virtual=true;materialize=false");
    add("F14", FixtureMode::Virtual, power_of_two(50),
        "kind=spec-repeat;virtual=true;tile=" + decimal(F04_TILE) +
        ";tile_sha256=" + tile_sha + ";materialize=false");
    add("F15", FixtureMode::Generated, BigInt(4 * GIB),
        "kind=concat;segments=" + f15_layout());
    for (int segment = 0; segment < 5; ++segment) {
        const std::string id = "F15.seg" + std::to_string(segment);
        add(id, FixtureMode::Generated, BigInt(segment_bytes(id)), segment_params(id));
    }
    return specs;
}

std::unique_ptr<FixtureStream> open_stream(std::string_view id,
                                           const GenerateOptions& options) {
    const auto specs = catalogue(options);
    const FixtureSpec* spec = find_spec(specs, id);
    if (spec == nullptr) throw std::invalid_argument("unknown fixture id");
    if (spec->mode == FixtureMode::Supplied) {
        const fs::path supplied = id == "F11" ? options.real : options.coded;
        if (supplied.empty()) throw std::runtime_error("supplied fixture is blocked");
    }
    return stream_for_spec(*spec, options);
}

Fixture identify(std::string_view id, const GenerateOptions& options) {
    const auto specs = catalogue(options);
    const FixtureSpec* spec = find_spec(specs, id);
    if (spec == nullptr) throw std::invalid_argument("unknown fixture id");
    return identify_spec(*spec, options).fixture;
}

std::vector<std::uint8_t> read_range(std::string_view id, const BigInt& offset,
                                     std::size_t len, const GenerateOptions& options) {
    const auto specs = catalogue(options);
    const FixtureSpec* spec = find_spec(specs, id);
    if (spec == nullptr) throw std::invalid_argument("unknown fixture id");
    auto stream = stream_for_spec(*spec, options);
    if (!stream->supports_range()) {
        throw std::invalid_argument("range reads require a Zero/Repeat stream");
    }
    const BigInt end = big_add(offset, BigInt(static_cast<std::uint64_t>(len)));
    if (end > spec->bytes) throw std::out_of_range("range outside fixture");
    std::vector<std::uint8_t> out(len);
    stream->read_range(offset, std::span<std::uint8_t>(out));
    return out;
}

MaterializeResult materialize(std::string_view id, const fs::path& to,
                              const GenerateOptions& options) {
    const auto specs = catalogue(options);
    const FixtureSpec* spec = find_spec(specs, id);
    if (spec == nullptr) throw std::invalid_argument("unknown fixture id");
    if (spec->mode == FixtureMode::Virtual) {
        throw std::invalid_argument("virtual fixtures must never be materialised");
    }
    if (spec->mode != FixtureMode::Generated) {
        throw std::invalid_argument("only generated fixtures can be materialised");
    }
    const std::uint64_t total = u64_exact(spec->bytes);
    if (total > static_cast<std::uint64_t>(std::numeric_limits<off_t>::max())) {
        throw std::overflow_error("materialisation offset exceeds off_t");
    }
    if (to.has_parent_path()) fs::create_directories(to.parent_path());
    const int fd = ::open(to.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) throw std::runtime_error("cannot create materialisation target");
    auto stream = stream_for_spec(*spec, options);
    std::array<std::uint8_t, IO_BYTES> buffer{};
    mapr::Sha256 ctx;
    std::uint64_t written = 0;
    try {
        while (written < total) {
            const std::size_t want = static_cast<std::size_t>(
                min_u64(total - written, static_cast<std::uint64_t>(buffer.size())));
            const std::size_t got = stream->read(std::span<std::uint8_t>(buffer.data(), want));
            if (got != want) throw std::runtime_error("short fixture stream");
            hash_update(ctx, std::span<const std::uint8_t>(buffer.data(), got));
            const bool zero = std::all_of(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(got),
                                          [](std::uint8_t byte) { return byte == 0; });
            if (zero) {
                if (::lseek(fd, static_cast<off_t>(got), SEEK_CUR) == static_cast<off_t>(-1)) {
                    throw std::runtime_error("sparse seek failed");
                }
            } else {
                std::size_t done = 0;
                while (done < got) {
                    const ssize_t n = ::write(fd, buffer.data() + done, got - done);
                    if (n < 0) {
                        if (errno == EINTR) continue;
                        throw std::runtime_error("materialisation write failed");
                    }
                    if (n == 0) throw std::runtime_error("zero-length materialisation write");
                    done += static_cast<std::size_t>(n);
                }
            }
            written += static_cast<std::uint64_t>(got);
        }
        if (::ftruncate(fd, static_cast<off_t>(total)) != 0) {
            throw std::runtime_error("ftruncate failed");
        }
        struct stat stat_result {};
        if (::fstat(fd, &stat_result) != 0) throw std::runtime_error("fstat failed");
        if (stat_result.st_blocks < 0) throw std::runtime_error("negative block count");
        MaterializeResult result;
        result.fixture.id = spec->id;
        result.fixture.bytes = spec->bytes;
        result.fixture.sha256 = hash_finish(ctx);
        result.fixture.path = repo_relative(options.root, to);
        result.logical_bytes = total;
        result.allocated_bytes = static_cast<std::uint64_t>(stat_result.st_blocks) * 512U;
        result.sparse = total > 0 && result.allocated_bytes < total / 2;
        ::close(fd);

        if (!options.manifest.empty() && fs::exists(options.manifest)) {
            const auto rows = read_manifest(options.manifest);
            for (const auto& row : rows) {
                if (row.fixture == id && row.sha256 != hex_of(result.fixture.sha256)) {
                    throw std::runtime_error("materialised digest does not match manifest");
                }
            }
        }
        return result;
    } catch (...) {
        ::close(fd);
        throw;
    }
}

std::string manifest_text(const std::vector<ManifestRow>& rows) {
    validate_manifest_rows(rows);
    std::ostringstream out;
    out << "fixture\tmode\tbytes\tsha256\tparams\tpath\tgates\n";
    for (const auto& row : rows) {
        out << row.fixture << '\t' << row.mode << '\t' << row.bytes << '\t'
            << row.sha256 << '\t' << row.params << '\t' << row.path << '\t'
            << row.gates << '\n';
    }
    return out.str();
}

void write_manifest(const fs::path& path, const std::vector<ManifestRow>& rows) {
    atomic_write(path, manifest_text(rows));
}

std::vector<ManifestRow> read_manifest(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) throw std::runtime_error("cannot read manifest " + path.string());
    std::string line;
    if (!std::getline(in, line) ||
        line != "fixture\tmode\tbytes\tsha256\tparams\tpath\tgates") {
        throw std::runtime_error("invalid manifest header");
    }
    std::vector<ManifestRow> rows;
    while (std::getline(in, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;
        const auto fields = split(line, '\t');
        if (fields.size() != 7) throw std::runtime_error("invalid manifest column count");
        rows.push_back({fields[0], fields[1], fields[2], fields[3],
                        fields[4], fields[5], fields[6]});
    }
    validate_manifest_rows(rows);
    return rows;
}

int generate(const fs::path& out, const fs::path& manifest) {
    GenerateOptions options;
    options.root = fs::current_path();
    options.out = out;
    options.manifest = manifest;
    return generate(options);
}

int generate(const GenerateOptions& options) {
    GenerateOptions opt = options;
    opt.root = fs::absolute(opt.root);
    if (opt.out.empty()) opt.out = opt.root / "out" / "h1-fixtures";
    if (opt.manifest.empty()) opt.manifest = opt.root / "specs_and_reports" / "v2" / "fixtures.tsv";
    fs::create_directories(opt.out);
    const auto specs = catalogue(opt);
    std::vector<ManifestRow> rows;
    std::vector<FixtureEvidenceRow> evidence;
    bool blocked = false;
    for (const auto& spec : specs) {
        const Identified identified = identify_spec(spec, opt);
        rows.push_back(to_row(identified));
        if (identified.mode == FixtureMode::Blocked) blocked = true;
        if (opt.evidence && spec.mode == FixtureMode::Supplied) {
            const std::string expected = "mode=supplied";
            const std::string actual = "mode=" + mode_name(identified.mode) +
                                       ";params=" + identified.params + ";gates=" + identified.gates;
            evidence.push_back(make_row("fixtures.supplied", spec.id,
                identified.mode == FixtureMode::Supplied ? hex_of(identified.fixture.sha256) : "-",
                expected, actual,
                identified.mode == FixtureMode::Supplied ? "PASS" : "BLOCKED"));
        }
        if (opt.evidence && spec.mode == FixtureMode::Virtual) {
            evidence.push_back(virtual_check(spec, opt));
        }
        if (opt.evidence && spec.id.size() == 5 && spec.id.rfind("F09.", 0) == 0) {
            const std::uint64_t member = static_cast<std::uint64_t>(spec.id[4] - '0');
            const auto base = f09_base();
            const auto mutated = f09_member(member);
            std::uint64_t mutations = 0;
            for (std::size_t i = 0; i < base.size(); ++i) {
                if (base[i] != mutated[i]) ++mutations;
            }
            const std::string expected = "bytes=" + decimal(F09_MEMBER_BYTES) +
                                         ";mutations=" + decimal(F09_MUTATIONS);
            const std::string actual = "bytes=" + decimal(static_cast<std::uint64_t>(mutated.size())) +
                                       ";mutations=" + decimal(mutations);
            evidence.push_back(make_row("fixtures.mutations", spec.id,
                                        hex_of(identified.fixture.sha256), expected, actual,
                                        mutations == F09_MUTATIONS &&
                                                mutated.size() == F09_MEMBER_BYTES ? "PASS" : "FAIL"));
        }
    }
    write_manifest(opt.manifest, rows);
    const std::string manifest_sha = sha256_file_hex(opt.manifest);
    if (opt.evidence) {
        evidence.push_back(make_row("fixtures.catalog", "manifest", manifest_sha,
                                    decimal(static_cast<std::uint64_t>(catalogue_ids().size())),
                                    decimal(static_cast<std::uint64_t>(rows.size())),
                                    rows.size() == catalogue_ids().size() ? "PASS" : "FAIL"));
        const ManifestRow* f15 = nullptr;
        std::vector<const ManifestRow*> segments;
        for (const auto& row : rows) {
            if (row.fixture == "F15") f15 = &row;
            if (is_segment(row.fixture)) segments.push_back(&row);
        }
        BigInt sum;
        std::string layout;
        for (const auto* segment : segments) {
            sum = big_add(sum, unwrap(BigInt::from_decimal(segment->bytes)));
            if (!layout.empty()) layout += ',';
            layout += segment_source(segment->fixture) + ":" + segment->bytes;
        }
        const bool concat_ok = f15 && segments.size() == 5 &&
                               sum.to_decimal() == f15->bytes &&
                               layout == f15_layout();
        evidence.push_back(make_row("fixtures.concat", "F15", f15 ? f15->sha256 : "-",
                                    "segments=" + f15_layout() + ";bytes=" + decimal(4 * GIB),
                                    "segments=" + layout + ";bytes=" + sum.to_decimal(),
                                    concat_ok ? "PASS" : "FAIL"));
    }
    if (opt.determinism) {
        GenerateOptions second = opt;
        second.evidence = false;
        second.determinism = false;
        second.allow_blocked = true;
        second.manifest = opt.out / "fixtures.second.tsv";
        const int second_status = generate(second);
        const bool equal = files_equal(opt.manifest, second.manifest);
        if (opt.evidence) {
            evidence.push_back(make_row("fixtures.determinism", "manifest", manifest_sha,
                                        manifest_sha, sha256_file_hex(second.manifest),
                                        equal && second_status == 0 ? "PASS" : "FAIL"));
        }
        if (!equal || second_status != 0) return 1;
    }
    if (opt.evidence) {
        EvidenceContext context{opt.root, opt.manifest, opt.command_line, opt.ci_run_id,
                                opt.ci_run_url, opt.commit, opt.runner_os};
        upsert_evidence(context, evidence, {});
    }
    return blocked && !opt.allow_blocked ? 1 : 0;
}

int verify(const GenerateOptions& options) {
    GenerateOptions opt = options;
    opt.root = fs::absolute(opt.root);
    if (opt.manifest.empty()) opt.manifest = opt.root / "specs_and_reports" / "v2" / "fixtures.tsv";
    const auto rows = read_manifest(opt.manifest);
    const auto specs = catalogue(opt);
    std::vector<FixtureEvidenceRow> evidence;
    std::map<std::string, StreamIdentity> cache;
    bool ok = true;
    bool blocked = false;
    for (const auto& row : rows) {
        const FixtureSpec* spec = find_spec(specs, row.fixture);
        if (spec == nullptr) throw std::runtime_error("manifest fixture missing from catalogue");
        std::string expected = "bytes=" + row.bytes + ";sha=" + row.sha256 + ";mode=" + row.mode;
        std::string actual = expected;
        std::string verdict = "PASS";
        std::string input_sha = row.sha256;
        try {
            if (row.mode == "blocked") {
                blocked = true;
                verdict = "BLOCKED";
                if (row.bytes != "0" || row.sha256 != "-" || row.gates != affected_gates() ||
                    row.path != "-" || row.params.rfind("source=supplied;", 0) != 0) {
                    verdict = "FAIL";
                    ok = false;
                }
                actual = "mode=blocked;gates=" + row.gates;
                expected = "mode=blocked;gates=" + affected_gates();
                input_sha = "-";
            } else if (row.mode == "virtual") {
                if (row.fixture != spec->id || row.mode != mode_name(spec->mode) ||
                    row.bytes != spec->bytes.to_decimal() || row.params != spec->params ||
                    row.sha256 != "-" || row.path != "-" || row.gates != "-") {
                    throw std::runtime_error("virtual descriptor mismatch");
                }
                const auto range_row = virtual_check(*spec, opt);
                if (range_row.verdict != "PASS") {
                    throw std::runtime_error("virtual end-range mismatch");
                }
                actual = "bytes=" + row.bytes + ";sha=-;mode=virtual;range=" + range_row.actual;
                expected = actual;
            } else if (row.mode == "supplied") {
                if (row.path == "-" || row.gates != affected_gates() ||
                    row.params != spec->params) {
                    throw std::runtime_error("supplied row mismatch");
                }
                const fs::path supplied = opt.root / row.path;
                FileStream stream(supplied);
                const StreamIdentity identity = hash_stream(stream, nullptr);
                actual = "bytes=" + decimal(identity.bytes) + ";sha=" + hex_of(identity.sha256) + ";mode=supplied";
                input_sha = hex_of(identity.sha256);
                if (BigInt(identity.bytes).to_decimal() != row.bytes || input_sha != row.sha256) {
                    verdict = "FAIL";
                    ok = false;
                }
            } else {
                if (row.mode != mode_name(spec->mode) || row.bytes != spec->bytes.to_decimal() ||
                    row.params != spec->params || row.path != "-" || row.gates != "-") {
                    throw std::runtime_error("generated row metadata mismatch");
                }
                std::string key = row.fixture;
                if (is_segment(row.fixture)) {
                    const std::string source = segment_source(row.fixture);
                    const FixtureSpec* source_spec = find_spec(specs, source);
                    if (source_spec && segment_bytes(row.fixture) == u64_exact(source_spec->bytes)) {
                        key = source;
                    }
                }
                auto it = cache.find(key);
                if (it == cache.end()) {
                    auto stream = stream_for_spec(*spec, opt);
                    it = cache.emplace(key, hash_stream(*stream, &spec->bytes)).first;
                }
                actual = "bytes=" + decimal(it->second.bytes) + ";sha=" + hex_of(it->second.sha256) + ";mode=generated";
                input_sha = hex_of(it->second.sha256);
                if (decimal(it->second.bytes) != row.bytes || input_sha != row.sha256) {
                    verdict = "FAIL";
                    ok = false;
                }
            }
        } catch (const std::exception& ex) {
            verdict = row.mode == "blocked" ? "BLOCKED" : "FAIL";
            if (verdict == "FAIL") ok = false;
            actual = std::string("error=") + ex.what();
        }
        if (opt.evidence) {
            evidence.push_back(make_row("fixtures.identity", row.fixture, input_sha,
                                        expected, actual, verdict));
        }
    }
    if (opt.evidence) {
        EvidenceContext context{opt.root, opt.manifest, opt.command_line, opt.ci_run_id,
                                opt.ci_run_url, opt.commit, opt.runner_os};
        upsert_evidence(context, evidence, {});
    }
    if (!ok) return 1;
    return blocked && !opt.allow_blocked ? 1 : 0;
}

void upsert_evidence(const EvidenceContext& context,
                     const std::vector<FixtureEvidenceRow>& rows,
                     const std::vector<std::string>& log_lines) {
    const fs::path root = fs::absolute(context.root);
    EvidenceContext ctx = context;
    ctx.root = root;
    ctx.manifest = fs::absolute(context.manifest);
    const fs::path tsv = evidence_tsv_path(root);
    const fs::path log = evidence_log_path(root);
    auto all = read_evidence(tsv);
    auto sections = read_log_sections(log);
    for (const auto& row : rows) {
        const std::string key = row.check + ":" + row.item_id;
        bool replaced = false;
        for (auto& existing : all) {
            if (existing.check == row.check && existing.item_id == row.item_id) {
                existing = row;
                replaced = true;
                break;
            }
        }
        if (!replaced) all.push_back(row);
        sections[key] = {
            "command_line: " + ctx.command_line,
            "expected: " + row.expected,
            "actual: " + row.actual,
            "verdict: " + row.verdict
        };
    }
    std::stable_sort(all.begin(), all.end(), [](const auto& a, const auto& b) {
        if (a.check != b.check) return a.check < b.check;
        return a.item_id < b.item_id;
    });
    atomic_write(tsv, evidence_text(all));
    const std::string manifest_sha = sha256_file_hex(ctx.manifest);
    std::ostringstream log_out;
    log_out << environment_header(ctx, manifest_sha);
    for (const auto& line : log_lines) log_out << line << "\n";
    for (const auto& [key, lines] : sections) {
        log_out << "[#" << key << "]\n";
        for (const auto& line : lines) log_out << line << "\n";
        log_out << "[#/" << key << "]\n";
    }
    atomic_write(log, log_out.str());
    write_report(ctx, read_manifest(ctx.manifest), all, log);
    write_sums(ctx);
}

void record_check(const EvidenceContext& context, std::string check,
                  std::string item_id, std::string expected,
                  std::string actual, std::string input_sha256,
                  std::string verdict) {
    upsert_evidence(context, {make_row(std::move(check), std::move(item_id),
                                       std::move(input_sha256), std::move(expected),
                                       std::move(actual), std::move(verdict))}, {});
}

void record_small(const EvidenceContext& context, std::string_view id,
                  const fs::path& file, std::string_view external_sha256) {
    const auto rows = read_manifest(context.manifest);
    const ManifestRow* row = nullptr;
    for (const auto& candidate : rows) {
        if (candidate.fixture == id) row = &candidate;
    }
    if (row == nullptr) throw std::invalid_argument("unknown small fixture");
    const std::string harness_sha = sha256_file_hex(file);
    const std::string external(external_sha256);
    const bool pass = is_lower_hex_sha(external) && harness_sha == row->sha256 &&
                      external == row->sha256;
    upsert_evidence(context,
        {make_row("fixtures.small_bytes", std::string(id), harness_sha,
                  row->sha256, external, pass ? "PASS" : "FAIL")}, {});
    if (!pass) throw std::runtime_error("small fixture SHA-256 cross-check failed");
}

void record_sparse(const EvidenceContext& context, const MaterializeResult& result) {
    const std::string sha = hex_of(result.fixture.sha256);
    const std::string expected = "logical=" + decimal(result.logical_bytes) +
                                 ";sha=" + sha + ";sparse=true;allocated_max=" +
                                 decimal(result.logical_bytes / 2);
    const std::string actual = "logical=" + decimal(result.logical_bytes) +
                               ";allocated=" + decimal(result.allocated_bytes) +
                               ";sparse=" + (result.sparse ? "true" : "false") + ";sha=" + sha;
    upsert_evidence(context,
        {make_row("fixtures.sparse", result.fixture.id, sha, expected, actual,
                  result.sparse ? "PASS" : "FAIL")}, {});
    if (!result.sparse) throw std::runtime_error("materialisation was not sparse");
}

int verify_evidence_sums(const fs::path& root) {
    const fs::path sums = evidence_sums_path(root);
    std::ifstream in(sums);
    if (!in) return 1;
    std::string line;
    bool any = false;
    while (std::getline(in, line)) {
        if (line.empty()) continue;
        any = true;
        if (line.size() < 67 || line[64] != ' ' || line[65] != ' ') return 1;
        const std::string expected = line.substr(0, 64);
        const fs::path path = root / line.substr(66);
        if (!is_lower_hex_sha(expected) || sha256_file_hex(path) != expected) return 1;
    }
    return any ? 0 : 1;
}

} // namespace marp::harness
