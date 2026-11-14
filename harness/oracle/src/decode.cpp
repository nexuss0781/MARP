#include "oracle_internal.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <limits>
#include <map>
#include <ostream>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace marp::oracle {

const char* stage_name(ValidationStage stage) noexcept {
    switch (stage) {
        case ValidationStage::None:      return "none";
        case ValidationStage::Size:      return "stage1_size";
        case ValidationStage::Header:    return "stage2_header";
        case ValidationStage::Bounds:    return "stage3_bounds";
        case ValidationStage::HeaderCrc: return "stage4_header_crc";
        case ValidationStage::Trailer:   return "stage5_trailer";
        case ValidationStage::Regions:   return "stage6_regions";
        case ValidationStage::Atoms:     return "stage7_atoms";
        case ValidationStage::Nodes:     return "stage8_nodes";
        case ValidationStage::Root:      return "stage9_root";
        case ValidationStage::Index:     return "stage10_index";
        case ValidationStage::Eval:      return "stage11_eval";
    }
    return "unknown";
}

const char* error_name(int code) noexcept {
    switch (code) {
        case 0: return "ok";
        case 2: return "usage";
        case 3: return "io";
        case 4: return "invalid";
        case 5: return "unsupported";
        case 6: return "mismatch";
        case 7: return "limit";
        default: return "unknown";
    }
}

namespace detail {

namespace {

inline std::uint16_t load_le16(const std::uint8_t* p) noexcept {
    return static_cast<std::uint16_t>(
        static_cast<std::uint16_t>(p[0]) |
        static_cast<std::uint16_t>(static_cast<std::uint16_t>(p[1]) << 8));
}

inline std::uint32_t load_le32(const std::uint8_t* p) noexcept {
    return static_cast<std::uint32_t>(p[0]) |
           (static_cast<std::uint32_t>(p[1]) << 8) |
           (static_cast<std::uint32_t>(p[2]) << 16) |
           (static_cast<std::uint32_t>(p[3]) << 24);
}

inline std::uint64_t load_le64(const std::uint8_t* p) noexcept {
    return static_cast<std::uint64_t>(load_le32(p)) |
           (static_cast<std::uint64_t>(load_le32(p + 4)) << 32);
}

inline void store_le32(std::uint8_t* p, std::uint32_t v) noexcept {
    p[0] = static_cast<std::uint8_t>(v & 0xFFU);
    p[1] = static_cast<std::uint8_t>((v >> 8) & 0xFFU);
    p[2] = static_cast<std::uint8_t>((v >> 16) & 0xFFU);
    p[3] = static_cast<std::uint8_t>((v >> 24) & 0xFFU);
}

int fail(Diagnostic* diag, ErrorCode code, ValidationStage stage, std::string msg) {
    const int c = static_cast<int>(code);
    if (diag != nullptr) {
        diag->code = c;
        diag->stage = stage;
        diag->message = std::move(msg);
    }
    return c;
}

class MemorySource final : public ByteSource {
public:
    explicit MemorySource(std::span<const std::uint8_t> data) noexcept : data_(data) {}

    std::uint64_t size() const noexcept override {
        return static_cast<std::uint64_t>(data_.size());
    }

    bool read_at(std::uint64_t offset, std::span<std::uint8_t> dst) const override {
        if (offset > data_.size() || dst.size() > data_.size() - offset) {
            return false;
        }
        if (!dst.empty()) {
            std::memcpy(dst.data(), data_.data() + offset, dst.size());
        }
        return true;
    }

private:
    std::span<const std::uint8_t> data_;
};

class FileSource final : public ByteSource {
public:
    bool open(const std::filesystem::path& path, std::string& err) {
        std::error_code ec;
        if (!std::filesystem::exists(path, ec) || ec) {
            err = "file does not exist: " + path.string();
            return false;
        }
        if (!std::filesystem::is_regular_file(path, ec) || ec) {
            err = "not a regular file: " + path.string();
            return false;
        }
        const auto fsz = std::filesystem::file_size(path, ec);
        if (ec) {
            err = "failed to stat file size: " + path.string();
            return false;
        }
        file_.open(path, std::ios::binary);
        if (!file_.is_open()) {
            err = "failed to open file: " + path.string();
            return false;
        }
        size_ = static_cast<std::uint64_t>(fsz);
        return true;
    }

    std::uint64_t size() const noexcept override { return size_; }

    bool read_at(std::uint64_t offset, std::span<std::uint8_t> dst) const override {
        if (offset > size_ || dst.size() > size_ - offset) {
            return false;
        }
        if (dst.empty()) {
            return true;
        }
        if (offset > static_cast<std::uint64_t>(std::numeric_limits<std::streamoff>::max())) {
            return false;
        }
        file_.clear();
        file_.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
        if (!file_) {
            return false;
        }
        file_.read(reinterpret_cast<char*>(dst.data()),
                   static_cast<std::streamsize>(dst.size()));
        return file_.good() &&
               static_cast<std::size_t>(file_.gcount()) == dst.size();
    }

private:
    mutable std::ifstream file_;
    std::uint64_t size_ = 0;
};

class RegionReader {
public:
    RegionReader(const ByteSource& src, std::uint64_t start, std::uint64_t end) noexcept
        : src_(src), pos_(start), end_(end) {}

    std::uint64_t pos() const noexcept { return pos_; }
    std::uint64_t remaining() const noexcept { return end_ - pos_; }

    bool skip(std::uint64_t n) noexcept {
        if (n > remaining()) {
            return false;
        }
        pos_ += n;
        return true;
    }

    bool read_exact(std::span<std::uint8_t> dst) {
        if (static_cast<std::uint64_t>(dst.size()) > remaining()) {
            return false;
        }
        if (!src_.read_at(pos_, dst)) {
            return false;
        }
        pos_ += static_cast<std::uint64_t>(dst.size());
        return true;
    }

    bool read_u8(std::uint8_t& out) {
        std::array<std::uint8_t, 1> b{};
        if (!read_exact(b)) {
            return false;
        }
        out = b[0];
        return true;
    }

    bool read_u16_le(std::uint16_t& out) {
        std::array<std::uint8_t, 2> b{};
        if (!read_exact(b)) {
            return false;
        }
        out = load_le16(b.data());
        return true;
    }

    bool read_u32_le(std::uint32_t& out) {
        std::array<std::uint8_t, 4> b{};
        if (!read_exact(b)) {
            return false;
        }
        out = load_le32(b.data());
        return true;
    }

    bool read_u64_le(std::uint64_t& out) {
        std::array<std::uint8_t, 8> b{};
        if (!read_exact(b)) {
            return false;
        }
        out = load_le64(b.data());
        return true;
    }

    // Canonical unsigned LEB128 uvarint (E3 §4.9):
    // - at most 10 bytes
    // - last byte MUST NOT be 0x00 when encoding has > 1 byte
    // - 10th byte MUST be 0x01 (0x00 violates canonicality, >= 0x02 overflows u64)
    bool read_uvarint(std::uint64_t& out) {
        std::uint64_t val = 0;
        for (unsigned idx = 0; idx < 10; ++idx) {
            std::uint8_t b = 0;
            if (!read_u8(b)) {
                return false;
            }
            const bool more = (b & 0x80U) != 0U;
            const std::uint8_t low = static_cast<std::uint8_t>(b & 0x7FU);
            if (idx == 9) {
                if (more || low != 1U) {
                    return false;
                }
                val |= (1ULL << 63);
                out = val;
                return true;
            }
            if (!more && idx > 0 && low == 0U) {
                return false; // redundant trailing zero group (non-canonical)
            }
            val |= static_cast<std::uint64_t>(low) << (idx * 7U);
            if (!more) {
                out = val;
                return true;
            }
        }
        return false;
    }

    // Canonical tagged BigInt (E3 §4.9):
    // 0x00                         -> 0
    // 0x01 <uvarint v>             -> 1 <= v <= 2^64-1 (v == 0 rejected)
    // 0x02 <u32 len> <len bytes>   -> len >= 9, bytes[len-1] != 0 (value >= 2^64)
    bool read_bigint(BigInt& out) {
        std::uint8_t tag = 0;
        if (!read_u8(tag)) {
            return false;
        }
        if (tag == 0x00U) {
            out = BigInt();
            return true;
        }
        if (tag == 0x01U) {
            std::uint64_t v = 0;
            if (!read_uvarint(v) || v == 0ULL) {
                return false;
            }
            out = BigInt(v);
            return true;
        }
        if (tag == 0x02U) {
            std::uint32_t len = 0;
            if (!read_u32_le(len)) {
                return false;
            }
            if (len < 9U || static_cast<std::uint64_t>(len) > remaining()) {
                return false;
            }
            std::vector<std::uint8_t> buf(len);
            if (!read_exact(buf)) {
                return false;
            }
            if (buf.back() == 0U) {
                return false; // non-canonical leading zero byte in magnitude
            }
            out = BigInt::from_le_bytes(buf);
            return true;
        }
        return false;
    }

private:
    const ByteSource& src_;
    std::uint64_t pos_;
    std::uint64_t end_;
};

bool payloads_equal(const ByteSource& src,
                    std::uint64_t off_a,
                    std::uint64_t off_b,
                    std::uint64_t len) {
    constexpr std::size_t kChunk = 16384;
    std::array<std::uint8_t, kChunk> ba{};
    std::array<std::uint8_t, kChunk> bb{};
    std::uint64_t done = 0;
    while (done < len) {
        const std::size_t take = static_cast<std::size_t>(
            std::min<std::uint64_t>(kChunk, len - done));
        if (!src.read_at(off_a + done, std::span<std::uint8_t>(ba.data(), take)) ||
            !src.read_at(off_b + done, std::span<std::uint8_t>(bb.data(), take))) {
            return false;
        }
        if (std::memcmp(ba.data(), bb.data(), take) != 0) {
            return false;
        }
        done += take;
    }
    return true;
}

// Structural node key for hash-consing dedup check (exact canonical fields)
struct NodeKey {
    std::uint8_t kind = 0;
    std::vector<std::uint32_t> args;
    std::uint32_t atom_id = 0;
    BigInt param_a;
    BigInt param_b;
    std::uint8_t morph = 0;
    std::uint8_t morph_k = 0;
    std::uint32_t stride = 0;
    std::uint64_t lfsr_conn = 0;
    std::uint64_t lfsr_init = 0;
    std::uint8_t affine_start = 0;
    std::uint8_t affine_step = 0;
    std::uint8_t predictor_id = 0;
    std::uint32_t predictor_param = 0;

    bool operator<(const NodeKey& o) const noexcept {
        if (kind != o.kind) return kind < o.kind;
        if (args != o.args) return args < o.args;
        if (atom_id != o.atom_id) return atom_id < o.atom_id;
        const int ca = BigInt::compare(param_a, o.param_a);
        if (ca != 0) return ca < 0;
        const int cb = BigInt::compare(param_b, o.param_b);
        if (cb != 0) return cb < 0;
        if (morph != o.morph) return morph < o.morph;
        if (morph_k != o.morph_k) return morph_k < o.morph_k;
        if (stride != o.stride) return stride < o.stride;
        if (lfsr_conn != o.lfsr_conn) return lfsr_conn < o.lfsr_conn;
        if (lfsr_init != o.lfsr_init) return lfsr_init < o.lfsr_init;
        if (affine_start != o.affine_start) return affine_start < o.affine_start;
        if (affine_step != o.affine_step) return affine_step < o.affine_step;
        if (predictor_id != o.predictor_id) return predictor_id < o.predictor_id;
        return predictor_param < o.predictor_param;
    }
};

NodeKey make_node_key(const NodeRecord& n) {
    NodeKey k;
    k.kind = static_cast<std::uint8_t>(n.kind);
    k.args = n.args;
    k.atom_id = n.atom_id;
    k.param_a = n.param_a;
    k.param_b = n.param_b;
    k.morph = n.morph;
    k.morph_k = n.morph_k;
    k.stride = n.stride;
    k.lfsr_conn = n.lfsr_conn;
    k.lfsr_init = n.lfsr_init;
    k.affine_start = n.affine_start;
    k.affine_step = n.affine_step;
    k.predictor_id = n.predictor_id;
    k.predictor_param = n.predictor_param;
    return k;
}

// Find smallest node id whose output starts at offset `target_off` (iterative, no recursion)
bool find_smallest_node_starting_at(const ParsedContainer& c,
                                    const BigInt& target_off,
                                    std::uint32_t& out_smallest_id) {
    struct Entry {
        std::uint32_t node_id;
        BigInt local_off;
    };

    const std::uint32_t root = c.trailer.root_id;
    std::vector<Entry> stack;
    stack.push_back({root, target_off});

    std::vector<std::uint8_t> visited_zero(c.nodes.size(), 0);
    bool found = false;
    std::uint32_t best = std::numeric_limits<std::uint32_t>::max();

    std::size_t steps = 0;
    const std::size_t max_steps = c.nodes.size() * 4 + 64;

    while (!stack.empty() && steps < max_steps) {
        ++steps;
        Entry cur = std::move(stack.back());
        stack.pop_back();

        const NodeRecord& n = c.nodes[cur.node_id];
        const bool at_zero = cur.local_off.is_zero();
        if (at_zero) {
            if (visited_zero[cur.node_id] != 0) {
                continue;
            }
            visited_zero[cur.node_id] = 1;
            if (!found || cur.node_id < best) {
                found = true;
                best = cur.node_id;
            }
        }

        switch (n.kind) {
            case NodeKind::Empty:
            case NodeKind::Atom:
            case NodeKind::Zero:
            case NodeKind::Lfsr:
            case NodeKind::Affine:
                break;

            case NodeKind::Concat: {
                BigInt cum;
                for (std::uint32_t child : n.args) {
                    const BigInt& clen = c.nodes[child].length;
                    if (cum == cur.local_off) {
                        stack.push_back({child, BigInt()});
                        if (!clen.is_zero()) {
                            break;
                        }
                    } else if (cum < cur.local_off) {
                        BigInt next_cum = BigInt::add(cum, clen);
                        if (cur.local_off < next_cum) {
                            stack.push_back({child, BigInt::sub(cur.local_off, cum)});
                            break;
                        }
                        cum = std::move(next_cum);
                    } else {
                        break;
                    }
                }
                break;
            }

            case NodeKind::Repeat: {
                const std::uint32_t child = n.args[0];
                const BigInt& clen = c.nodes[child].length;
                if (!clen.is_zero()) {
                    auto [q_unused, rem] = BigInt::divmod(cur.local_off, clen);
                    (void)q_unused;
                    stack.push_back({child, std::move(rem)});
                }
                break;
            }

            case NodeKind::Slice: {
                const std::uint32_t child = n.args[0];
                stack.push_back({child, BigInt::add(n.param_a, cur.local_off)});
                break;
            }

            case NodeKind::Morph: {
                // Local morphs (1,2,6,7) preserve byte positions; block morphs (3,4,5) align at 0
                if (n.morph == 1 || n.morph == 2 || n.morph == 6 || n.morph == 7) {
                    stack.push_back({n.args[0], cur.local_off});
                } else if ((n.morph == 3 || n.morph == 4 || n.morph == 5) && at_zero) {
                    stack.push_back({n.args[0], BigInt()});
                }
                break;
            }

            case NodeKind::Xor: {
                stack.push_back({n.args[0], cur.local_off});
                stack.push_back({n.args[1], cur.local_off});
                break;
            }

            case NodeKind::Interleave: {
                if (at_zero) {
                    stack.push_back({n.args[0], BigInt()});
                }
                break;
            }

            case NodeKind::Predictor: {
                stack.push_back({n.args[0], cur.local_off});
                break;
            }
        }
    }

    if (found) {
        out_smallest_id = best;
    }
    return found;
}

bool normalize_sha256_hex(std::string_view in, std::string& out_lower) {
    if (in.size() != 64) {
        return false;
    }
    out_lower.clear();
    out_lower.reserve(64);
    for (char ch : in) {
        if (ch >= '0' && ch <= '9') {
            out_lower.push_back(ch);
        } else if (ch >= 'a' && ch <= 'f') {
            out_lower.push_back(ch);
        } else if (ch >= 'A' && ch <= 'F') {
            out_lower.push_back(static_cast<char>(ch - 'A' + 'a'));
        } else {
            return false;
        }
    }
    return true;
}

void fill_info(const ParsedContainer& c,
               const std::string& sha_hex,
               Info* info) {
    if (info == nullptr) {
        return;
    }
    info->file_bytes = c.trailer.file_bytes;
    info->node_count = c.trailer.node_count;
    info->atom_count = c.trailer.atom_count;
    info->root_id = c.trailer.root_id;
    info->total_length = c.total_length.to_decimal();
    info->output_sha256 = sha_hex;
    info->has_index = c.has_index;
}

std::string format_node_params(const NodeRecord& n) {
    switch (n.kind) {
        case NodeKind::Empty:
            return "-";
        case NodeKind::Atom:
            return "atom=" + std::to_string(n.atom_id);
        case NodeKind::Zero:
            return "n=" + n.param_a.to_decimal();
        case NodeKind::Concat:
            return "-";
        case NodeKind::Repeat:
            return "q=" + n.param_a.to_decimal() + ",r=" + n.param_b.to_decimal();
        case NodeKind::Slice:
            return "start=" + n.param_a.to_decimal() + ",len=" + n.param_b.to_decimal();
        case NodeKind::Morph:
            return "morph=" + std::to_string(n.morph) + ",k=" + std::to_string(n.morph_k);
        case NodeKind::Xor:
            return "-";
        case NodeKind::Interleave:
            return "stride=" + std::to_string(n.stride);
        case NodeKind::Lfsr:
            return "conn=0x" + hex_u64(n.lfsr_conn) +
                   ",init=0x" + hex_u64(n.lfsr_init) +
                   ",n=" + n.param_a.to_decimal();
        case NodeKind::Affine:
            return "start=" + std::to_string(n.affine_start) +
                   ",step=" + std::to_string(n.affine_step) +
                   ",n=" + n.param_a.to_decimal();
        case NodeKind::Predictor:
            return "pid=" + std::to_string(n.predictor_id) +
                   ",param=" + std::to_string(n.predictor_param);
    }
    return "-";
}

void write_inspect_tsv(const ParsedContainer& c, std::ostream& out) {
    out << "header\t"
        << c.header.version_major << '\t'
        << c.header.version_minor << '\t'
        << "0x" << hex_u32(c.header.flags) << '\t'
        << c.header.header_bytes << '\t'
        << c.total_length.to_decimal() << '\t'
        << c.header.total_length_big_len << '\t'
        << c.header.atom_offset << '\t'
        << c.header.node_offset << '\t'
        << c.header.index_offset << '\t'
        << c.header.trailer_offset << '\t'
        << hex_u32(c.header.file_crc32) << '\n';

    for (std::size_t i = 0; i < c.atoms.size(); ++i) {
        const AtomRecord& a = c.atoms[i];
        out << "atom\t" << i << '\t'
            << static_cast<unsigned>(a.klass) << '\t'
            << a.length << '\t'
            << Sha256::to_hex(a.sha256) << '\n';
    }

    for (std::size_t i = 0; i < c.nodes.size(); ++i) {
        const NodeRecord& n = c.nodes[i];
        out << "node\t" << i << '\t'
            << static_cast<unsigned>(n.kind) << '\t'
            << kind_name(n.kind) << '\t'
            << n.args.size() << '\t';
        if (n.args.empty()) {
            out << '-';
        } else {
            for (std::size_t j = 0; j < n.args.size(); ++j) {
                if (j > 0) out << ',';
                out << n.args[j];
            }
        }
        out << '\t' << format_node_params(n)
            << '\t' << n.length.to_decimal() << '\n';
    }

    if (c.has_index) {
        for (std::size_t i = 0; i < c.index_entries.size(); ++i) {
            const IndexEntry& e = c.index_entries[i];
            out << "index\t" << i << '\t'
                << e.output_offset.to_decimal() << '\t'
                << e.node_id << '\t'
                << hex_u32(e.crc32_of_prefix) << '\n';
        }
    }

    out << "trailer\t"
        << c.trailer.file_bytes << '\t'
        << c.trailer.root_id << '\t'
        << c.trailer.atom_count << '\t'
        << c.trailer.node_count << '\t'
        << hex_u32(c.trailer.trailer_crc32) << '\n';
}

} // namespace

std::string hex_u32(std::uint32_t v) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string s(8, '0');
    for (int i = 7; i >= 0; --i) {
        s[static_cast<std::size_t>(i)] = kHex[v & 0x0FU];
        v >>= 4;
    }
    return s;
}

std::string hex_u64(std::uint64_t v) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string s(16, '0');
    for (int i = 15; i >= 0; --i) {
        s[static_cast<std::size_t>(i)] = kHex[v & 0x0FU];
        v >>= 4;
    }
    return s;
}

const char* kind_name(NodeKind k) noexcept {
    switch (k) {
        case NodeKind::Empty:      return "Empty";
        case NodeKind::Atom:       return "Atom";
        case NodeKind::Zero:       return "Zero";
        case NodeKind::Concat:     return "Concat";
        case NodeKind::Repeat:     return "Repeat";
        case NodeKind::Slice:      return "Slice";
        case NodeKind::Morph:      return "Morph";
        case NodeKind::Xor:        return "Xor";
        case NodeKind::Interleave: return "Interleave";
        case NodeKind::Lfsr:       return "Lfsr";
        case NodeKind::Affine:     return "Affine";
        case NodeKind::Predictor:  return "Predictor";
    }
    return "Unknown";
}

int parse_and_validate_structure(const ByteSource& src,
                                 ParsedContainer& out,
                                 const Limits& limits,
                                 Diagnostic* diag) {
    out = ParsedContainer{};
    const std::uint64_t fsize = src.size();

    // ------------------------------------------------------------------
    // Stage 1: Minimum container size >= 96 and container limit
    // ------------------------------------------------------------------
    if (fsize < kMinContainerBytes) {
        return fail(diag, ErrorCode::Invalid, ValidationStage::Size,
                    "container smaller than 96 bytes");
    }
    if (fsize > limits.max_container_bytes) {
        return fail(diag, ErrorCode::Limit, ValidationStage::Size,
                    "container exceeds max_container_bytes");
    }

    // ------------------------------------------------------------------
    // Stage 2: Header magic, version, header_bytes, flags
    // ------------------------------------------------------------------
    std::array<std::uint8_t, 64> hdr{};
    if (!src.read_at(0, hdr)) {
        return fail(diag, ErrorCode::Io, ValidationStage::Header,
                    "failed to read header");
    }
    if (!std::equal(kHeaderMagic.begin(), kHeaderMagic.end(), hdr.begin())) {
        return fail(diag, ErrorCode::Invalid, ValidationStage::Header,
                    "bad header magic");
    }

    out.header.version_major        = load_le16(hdr.data() + 8);
    out.header.version_minor        = load_le16(hdr.data() + 10);
    out.header.flags                = load_le32(hdr.data() + 12);
    out.header.header_bytes         = load_le16(hdr.data() + 16);
    out.header.total_length_u64     = load_le64(hdr.data() + 18);
    out.header.total_length_big_len = load_le16(hdr.data() + 26);
    out.header.atom_offset          = load_le64(hdr.data() + 28);
    out.header.node_offset          = load_le64(hdr.data() + 36);
    out.header.index_offset         = load_le64(hdr.data() + 44);
    out.header.trailer_offset       = load_le64(hdr.data() + 52);
    out.header.file_crc32           = load_le32(hdr.data() + 60);

    if (out.header.version_major > kVersionMajor ||
        (out.header.version_major == kVersionMajor &&
         out.header.version_minor > kVersionMinor)) {
        return fail(diag, ErrorCode::Unsupported, ValidationStage::Header,
                    "unsupported future wire version");
    }
    if (out.header.version_major != kVersionMajor ||
        out.header.version_minor != kVersionMinor) {
        return fail(diag, ErrorCode::Invalid, ValidationStage::Header,
                    "invalid wire version");
    }
    if (out.header.header_bytes != kHeaderBytes) {
        return fail(diag, ErrorCode::Invalid, ValidationStage::Header,
                    "header_bytes != 64");
    }
    if ((out.header.flags & ~kFlagKnownMask) != 0U) {
        return fail(diag, ErrorCode::Invalid, ValidationStage::Header,
                    "reserved header flag bits nonzero");
    }
    if ((out.header.flags & kFlagCanonical) == 0U) {
        return fail(diag, ErrorCode::Invalid, ValidationStage::Header,
                    "canonical flag bit 1 must be 1");
    }
    if ((out.header.flags & kFlagByteAligned) == 0U) {
        return fail(diag, ErrorCode::Invalid, ValidationStage::Header,
                    "byte-aligned flag bit 3 must be 1");
    }

    // ------------------------------------------------------------------
    // Stage 3: trailer_offset and file_bytes bounds
    // ------------------------------------------------------------------
    if (out.header.trailer_offset != fsize - kTrailerBytes) {
        return fail(diag, ErrorCode::Invalid, ValidationStage::Bounds,
                    "trailer_offset != file_size - 32");
    }

    std::array<std::uint8_t, 32> trl{};
    if (!src.read_at(out.header.trailer_offset, trl)) {
        return fail(diag, ErrorCode::Io, ValidationStage::Bounds,
                    "failed to read trailer");
    }
    out.trailer.file_bytes    = load_le64(trl.data() + 8);
    out.trailer.root_id       = load_le32(trl.data() + 16);
    out.trailer.atom_count    = load_le32(trl.data() + 20);
    out.trailer.node_count    = load_le32(trl.data() + 24);
    out.trailer.trailer_crc32 = load_le32(trl.data() + 28);

    if (out.trailer.file_bytes != fsize) {
        return fail(diag, ErrorCode::Invalid, ValidationStage::Bounds,
                    "trailer file_bytes != actual file size");
    }

    // ------------------------------------------------------------------
    // Stage 4: Header CRC (file_crc32 over [0, trailer_offset) with [60..64) zeroed)
    // ------------------------------------------------------------------
    {
        Crc32 crc;
        std::array<std::uint8_t, 64> hdr_zeroed = hdr;
        hdr_zeroed[60] = 0;
        hdr_zeroed[61] = 0;
        hdr_zeroed[62] = 0;
        hdr_zeroed[63] = 0;
        crc.update(hdr_zeroed);

        std::array<std::uint8_t, 65536> buf{};
        std::uint64_t pos = kHeaderBytes;
        while (pos < out.header.trailer_offset) {
            const std::size_t take = static_cast<std::size_t>(
                std::min<std::uint64_t>(buf.size(), out.header.trailer_offset - pos));
            if (!src.read_at(pos, std::span<std::uint8_t>(buf.data(), take))) {
                return fail(diag, ErrorCode::Io, ValidationStage::HeaderCrc,
                            "I/O error while computing file_crc32");
            }
            crc.update(std::span<const std::uint8_t>(buf.data(), take));
            pos += take;
        }

        if (crc.value() != out.header.file_crc32) {
            return fail(diag, ErrorCode::Invalid, ValidationStage::HeaderCrc,
                        "file_crc32 mismatch");
        }
    }

    // ------------------------------------------------------------------
    // Stage 5: Trailer magic, trailer CRC, counts bounds
    // ------------------------------------------------------------------
    if (!std::equal(kTrailerMagic.begin(), kTrailerMagic.end(), trl.begin())) {
        return fail(diag, ErrorCode::Invalid, ValidationStage::Trailer,
                    "bad trailer magic");
    }
    {
        // E3 §4.8: trailer_crc32 = CRC32(trailer[0..28) || LE32(file_crc32))
        std::array<std::uint8_t, 32> crc_in{};
        std::memcpy(crc_in.data(), trl.data(), 28);
        store_le32(crc_in.data() + 28, out.header.file_crc32);
        Crc32 tcrc;
        tcrc.update(crc_in);
        if (tcrc.value() != out.trailer.trailer_crc32) {
            return fail(diag, ErrorCode::Invalid, ValidationStage::Trailer,
                        "trailer_crc32 mismatch");
        }
    }
    if (out.trailer.node_count == 0U) {
        return fail(diag, ErrorCode::Invalid, ValidationStage::Trailer,
                    "trailer node_count == 0");
    }
    if (out.trailer.atom_count > limits.max_atoms) {
        return fail(diag, ErrorCode::Limit, ValidationStage::Trailer,
                    "trailer atom_count exceeds max_atoms");
    }
    if (out.trailer.node_count > limits.max_nodes) {
        return fail(diag, ErrorCode::Limit, ValidationStage::Trailer,
                    "trailer node_count exceeds max_nodes");
    }

    // ------------------------------------------------------------------
    // Stage 6: Region offsets monotonic & within [64, trailer_offset];
    //          atom_offset == 64 + total_length_big_len;
    //          total_length canonicality
    // ------------------------------------------------------------------
    const bool has_u64_len = (out.header.flags & kFlagU64Lengths) != 0U;
    out.has_index = (out.header.flags & kFlagIndexPresent) != 0U;

    if (has_u64_len) {
        if (out.header.total_length_big_len != 0U) {
            return fail(diag, ErrorCode::Invalid, ValidationStage::Regions,
                        "flag bit 2 set but total_length_big_len != 0");
        }
    } else {
        if (out.header.total_length_u64 != 0ULL) {
            return fail(diag, ErrorCode::Invalid, ValidationStage::Regions,
                        "flag bit 2 clear but total_length_u64 != 0");
        }
        if (out.header.total_length_big_len < 9U) {
            return fail(diag, ErrorCode::Invalid, ValidationStage::Regions,
                        "big total_length_big_len < 9 (non-canonical)");
        }
    }

    const std::uint64_t expected_atom_off =
        static_cast<std::uint64_t>(kHeaderBytes) +
        static_cast<std::uint64_t>(out.header.total_length_big_len);
    if (out.header.atom_offset != expected_atom_off) {
        return fail(diag, ErrorCode::Invalid, ValidationStage::Regions,
                    "atom_offset != 64 + total_length_big_len");
    }
    if (out.header.atom_offset > out.header.node_offset ||
        out.header.node_offset > out.header.trailer_offset) {
        return fail(diag, ErrorCode::Invalid, ValidationStage::Regions,
                    "non-monotonic or out-of-bounds region offsets");
    }

    std::uint64_t node_end = out.header.trailer_offset;
    if (!out.has_index) {
        if (out.header.index_offset != 0ULL) {
            return fail(diag, ErrorCode::Invalid, ValidationStage::Regions,
                        "index flag clear but index_offset != 0");
        }
    } else {
        if (out.header.index_offset < out.header.node_offset ||
            out.header.index_offset >= out.header.trailer_offset) {
            return fail(diag, ErrorCode::Invalid, ValidationStage::Regions,
                        "index_offset out of bounds");
        }
        node_end = out.header.index_offset;
    }

    if (has_u64_len) {
        out.total_length = BigInt(out.header.total_length_u64);
    } else {
        std::vector<std::uint8_t> mag(out.header.total_length_big_len);
        if (!src.read_at(kHeaderBytes, mag)) {
            return fail(diag, ErrorCode::Io, ValidationStage::Regions,
                        "failed to read Region A.1 total-length magnitude");
        }
        if (mag.back() == 0U) {
            return fail(diag, ErrorCode::Invalid, ValidationStage::Regions,
                        "Region A.1 total-length magnitude has leading zero byte");
        }
        out.total_length = BigInt::from_le_bytes(mag);
    }

    // ------------------------------------------------------------------
    // Stage 7: Atom table
    // ------------------------------------------------------------------
    {
        RegionReader rr(src, out.header.atom_offset, out.header.node_offset);
        std::uint64_t atom_count_u64 = 0;
        if (!rr.read_uvarint(atom_count_u64)) {
            return fail(diag, ErrorCode::Invalid, ValidationStage::Atoms,
                        "invalid or non-canonical atom_count uvarint");
        }
        if (atom_count_u64 > limits.max_atoms) {
            return fail(diag, ErrorCode::Limit, ValidationStage::Atoms,
                        "atom_count exceeds max_atoms");
        }
        if (atom_count_u64 != out.trailer.atom_count) {
            return fail(diag, ErrorCode::Invalid, ValidationStage::Atoms,
                        "atom_count disagrees with trailer");
        }
        // Minimum atom record is 1+1+2+1+32+1 = 38 bytes (length >= 1)
        if (atom_count_u64 > rr.remaining() / 38ULL) {
            return fail(diag, ErrorCode::Invalid, ValidationStage::Atoms,
                        "atom_count exceeds atom region capacity");
        }

        const std::size_t atom_count = static_cast<std::size_t>(atom_count_u64);
        out.atoms.reserve(atom_count);

        using AtomDedupKey = std::pair<std::uint64_t, std::array<std::uint8_t, 32>>;
        std::map<AtomDedupKey, std::vector<std::size_t>> seen_atoms;
        std::array<std::uint8_t, 65536> hash_buf{};

        for (std::size_t i = 0; i < atom_count; ++i) {
            AtomRecord rec;
            std::uint8_t aflags = 0;
            std::uint16_t ares = 0;
            if (!rr.read_u8(rec.klass) ||
                !rr.read_u8(aflags) ||
                !rr.read_u16_le(ares)) {
                return fail(diag, ErrorCode::Invalid, ValidationStage::Atoms,
                            "truncated atom record header");
            }
            if (aflags != 0U || ares != 0U) {
                return fail(diag, ErrorCode::Invalid, ValidationStage::Atoms,
                            "nonzero atom flags or reserved field");
            }

            BigInt len_big;
            if (!rr.read_bigint(len_big)) {
                return fail(diag, ErrorCode::Invalid, ValidationStage::Atoms,
                            "invalid or non-canonical atom length bigint");
            }
            if (len_big.is_zero() || !len_big.fits_u64()) {
                return fail(diag, ErrorCode::Invalid, ValidationStage::Atoms,
                            "atom length must be 1..ATOM_MAX");
            }
            const std::uint64_t alen = len_big.to_u64();
            if (alen > kAtomMax) {
                return fail(diag, ErrorCode::Invalid, ValidationStage::Atoms,
                            "atom length exceeds ATOM_MAX (1 MiB)");
            }
            rec.length = alen;

            if (!rr.read_exact(rec.sha256)) {
                return fail(diag, ErrorCode::Invalid, ValidationStage::Atoms,
                            "truncated atom sha256");
            }
            if (alen > rr.remaining()) {
                return fail(diag, ErrorCode::Invalid, ValidationStage::Atoms,
                            "atom payload exceeds atom region bounds");
            }
            rec.payload_offset = rr.pos();

            // Stream-verify SHA-256 of atom payload
            Sha256 h;
            std::uint64_t hashed = 0;
            while (hashed < alen) {
                const std::size_t take = static_cast<std::size_t>(
                    std::min<std::uint64_t>(hash_buf.size(), alen - hashed));
                if (!rr.read_exact(std::span<std::uint8_t>(hash_buf.data(), take))) {
                    return fail(diag, ErrorCode::Io, ValidationStage::Atoms,
                                "failed to read atom payload");
                }
                h.update(std::span<const std::uint8_t>(hash_buf.data(), take));
                hashed += take;
            }
            const auto digest = h.finalize();
            if (digest != rec.sha256) {
                return fail(diag, ErrorCode::Invalid, ValidationStage::Atoms,
                            "atom payload SHA-256 mismatch");
            }

            // Duplicate atom payload check (E3 §4.5)
            const AtomDedupKey key{rec.length, rec.sha256};
            auto& bucket = seen_atoms[key];
            for (std::size_t prev_idx : bucket) {
                if (payloads_equal(src, out.atoms[prev_idx].payload_offset,
                                   rec.payload_offset, rec.length)) {
                    return fail(diag, ErrorCode::Invalid, ValidationStage::Atoms,
                                "duplicate atom payload in atom table");
                }
            }
            bucket.push_back(i);
            out.atoms.push_back(rec);
        }

        if (rr.remaining() != 0ULL) {
            return fail(diag, ErrorCode::Invalid, ValidationStage::Atoms,
                        "trailing unconsumed bytes in atom table");
        }
    }

    // ------------------------------------------------------------------
    // Stage 8: Node table
    // ------------------------------------------------------------------
    {
        RegionReader rr(src, out.header.node_offset, node_end);
        std::uint64_t node_count_u64 = 0;
        if (!rr.read_uvarint(node_count_u64)) {
            return fail(diag, ErrorCode::Invalid, ValidationStage::Nodes,
                        "invalid or non-canonical node_count uvarint");
        }
        if (node_count_u64 == 0ULL) {
            return fail(diag, ErrorCode::Invalid, ValidationStage::Nodes,
                        "node_count == 0");
        }
        if (node_count_u64 > limits.max_nodes) {
            return fail(diag, ErrorCode::Limit, ValidationStage::Nodes,
                        "node_count exceeds max_nodes");
        }
        if (node_count_u64 != out.trailer.node_count) {
            return fail(diag, ErrorCode::Invalid, ValidationStage::Nodes,
                        "node_count disagrees with trailer");
        }
        // Minimum node record is 1(kind)+1(flags)+2(argc)+1(length_bigint) = 5 bytes
        if (node_count_u64 > rr.remaining() / 5ULL) {
            return fail(diag, ErrorCode::Invalid, ValidationStage::Nodes,
                        "node_count exceeds node region capacity");
        }

        const std::size_t node_count = static_cast<std::size_t>(node_count_u64);
        out.nodes.reserve(node_count);
        std::set<NodeKey> seen_nodes;

        for (std::size_t id = 0; id < node_count; ++id) {
            std::uint8_t kind_u8 = 0;
            std::uint8_t nflags = 0;
            std::uint16_t argc = 0;
            if (!rr.read_u8(kind_u8) ||
                !rr.read_u8(nflags) ||
                !rr.read_u16_le(argc)) {
                return fail(diag, ErrorCode::Invalid, ValidationStage::Nodes,
                            "truncated node record header");
            }
            if (kind_u8 > static_cast<std::uint8_t>(NodeKind::Predictor)) {
                return fail(diag, ErrorCode::Invalid, ValidationStage::Nodes,
                            "unknown node kind");
            }
            if (nflags != 0U) {
                return fail(diag, ErrorCode::Invalid, ValidationStage::Nodes,
                            "nonzero node flags");
            }

            NodeRecord node;
            node.kind = static_cast<NodeKind>(kind_u8);

            // Validate argc per E3 §4.6
            bool argc_ok = false;
            switch (node.kind) {
                case NodeKind::Empty:
                case NodeKind::Atom:
                case NodeKind::Zero:
                case NodeKind::Lfsr:
                case NodeKind::Affine:
                    argc_ok = (argc == 0U);
                    break;
                case NodeKind::Repeat:
                case NodeKind::Slice:
                case NodeKind::Morph:
                case NodeKind::Predictor:
                    argc_ok = (argc == 1U);
                    break;
                case NodeKind::Xor:
                    argc_ok = (argc == 2U);
                    break;
                case NodeKind::Concat:
                    argc_ok = (argc >= 2U);
                    break;
                case NodeKind::Interleave:
                    argc_ok = (argc >= 1U);
                    break;
            }
            if (!argc_ok) {
                return fail(diag, ErrorCode::Invalid, ValidationStage::Nodes,
                            "invalid argc for node kind");
            }
            if (static_cast<std::uint64_t>(argc) > rr.remaining()) {
                return fail(diag, ErrorCode::Invalid, ValidationStage::Nodes,
                            "argc exceeds remaining node region bytes");
            }

            node.args.reserve(argc);
            std::uint32_t max_child_depth = 0;
            for (std::uint16_t a = 0; a < argc; ++a) {
                std::uint64_t arg_u64 = 0;
                if (!rr.read_uvarint(arg_u64)) {
                    return fail(diag, ErrorCode::Invalid, ValidationStage::Nodes,
                                "invalid or non-canonical node arg uvarint");
                }
                if (arg_u64 >= static_cast<std::uint64_t>(id)) {
                    return fail(diag, ErrorCode::Invalid, ValidationStage::Nodes,
                                "node arg >= current node id (non-topological)");
                }
                const std::uint32_t child_id = static_cast<std::uint32_t>(arg_u64);
                node.args.push_back(child_id);
                if (out.nodes[child_id].depth > max_child_depth) {
                    max_child_depth = out.nodes[child_id].depth;
                }
            }

            if (argc == 0U) {
                node.depth = (node.kind == NodeKind::Empty) ? 0U : 1U;
            } else {
                node.depth = max_child_depth + 1U;
            }
            if (node.depth > limits.max_depth) {
                return fail(diag, ErrorCode::Limit, ValidationStage::Nodes,
                            "DAG depth exceeds max_depth");
            }

            BigInt computed_len;
            switch (node.kind) {
                case NodeKind::Empty: {
                    computed_len = BigInt();
                    break;
                }
                case NodeKind::Atom: {
                    std::uint64_t aid = 0;
                    if (!rr.read_uvarint(aid)) {
                        return fail(diag, ErrorCode::Invalid, ValidationStage::Nodes,
                                    "invalid Atom atom_id uvarint");
                    }
                    if (aid >= out.atoms.size()) {
                        return fail(diag, ErrorCode::Invalid, ValidationStage::Nodes,
                                    "Atom atom_id out of range");
                    }
                    node.atom_id = static_cast<std::uint32_t>(aid);
                    computed_len = BigInt(out.atoms[node.atom_id].length);
                    break;
                }
                case NodeKind::Zero: {
                    if (!rr.read_bigint(node.param_a)) {
                        return fail(diag, ErrorCode::Invalid, ValidationStage::Nodes,
                                    "invalid Zero n bigint");
                    }
                    computed_len = node.param_a;
                    break;
                }
                case NodeKind::Concat: {
                    for (std::uint32_t child : node.args) {
                        computed_len = BigInt::add(computed_len, out.nodes[child].length);
                    }
                    break;
                }
                case NodeKind::Repeat: {
                    if (!rr.read_bigint(node.param_a) || !rr.read_bigint(node.param_b)) {
                        return fail(diag, ErrorCode::Invalid, ValidationStage::Nodes,
                                    "invalid Repeat q/r bigint");
                    }
                    const BigInt& clen = out.nodes[node.args[0]].length;
                    if (node.param_a.is_zero()) {
                        if (!node.param_b.is_zero()) {
                            return fail(diag, ErrorCode::Invalid, ValidationStage::Nodes,
                                        "Repeat with q == 0 must have r == 0");
                        }
                    } else {
                        if (node.param_b >= clen) {
                            return fail(diag, ErrorCode::Invalid, ValidationStage::Nodes,
                                        "Repeat with q >= 1 must have r < len(child)");
                        }
                    }
                    computed_len = BigInt::add(BigInt::mul(node.param_a, clen), node.param_b);
                    break;
                }
                case NodeKind::Slice: {
                    if (!rr.read_bigint(node.param_a) || !rr.read_bigint(node.param_b)) {
                        return fail(diag, ErrorCode::Invalid, ValidationStage::Nodes,
                                    "invalid Slice start/len bigint");
                    }
                    const BigInt& clen = out.nodes[node.args[0]].length;
                    if (node.param_a > clen) {
                        return fail(diag, ErrorCode::Invalid, ValidationStage::Nodes,
                                    "Slice start > len(child)");
                    }
                    const BigInt end_off = BigInt::add(node.param_a, node.param_b);
                    if (end_off > clen) {
                        return fail(diag, ErrorCode::Invalid, ValidationStage::Nodes,
                                    "Slice start + len > len(child)");
                    }
                    computed_len = node.param_b;
                    break;
                }
                case NodeKind::Morph: {
                    if (!rr.read_u8(node.morph) || !rr.read_u8(node.morph_k)) {
                        return fail(diag, ErrorCode::Invalid, ValidationStage::Nodes,
                                    "truncated Morph params");
                    }
                    if (node.morph < 1U || node.morph > 9U) {
                        return fail(diag, ErrorCode::Invalid, ValidationStage::Nodes,
                                    "unknown morph id");
                    }
                    if (node.morph == 6U || node.morph == 7U) {
                        if (node.morph_k < 1U || node.morph_k > 7U) {
                            return fail(diag, ErrorCode::Invalid, ValidationStage::Nodes,
                                        "ROTL8/ROTR8 morph k must be 1..7");
                        }
                    } else {
                        if (node.morph_k != 0U) {
                            return fail(diag, ErrorCode::Invalid, ValidationStage::Nodes,
                                        "morph k must be 0 for non-rotation morphs");
                        }
                    }
                    const BigInt& clen = out.nodes[node.args[0]].length;
                    if (node.morph == 3U && BigInt::mod_u64(clen, 2ULL) != 0ULL) {
                        return fail(diag, ErrorCode::Invalid, ValidationStage::Nodes,
                                    "SWAP16 child length not a multiple of 2");
                    }
                    if (node.morph == 4U && BigInt::mod_u64(clen, 4ULL) != 0ULL) {
                        return fail(diag, ErrorCode::Invalid, ValidationStage::Nodes,
                                    "SWAP32 child length not a multiple of 4");
                    }
                    if (node.morph == 5U && BigInt::mod_u64(clen, 8ULL) != 0ULL) {
                        return fail(diag, ErrorCode::Invalid, ValidationStage::Nodes,
                                    "SWAP64 child length not a multiple of 8");
                    }
                    computed_len = clen;
                    break;
                }
                case NodeKind::Xor: {
                    const BigInt& la = out.nodes[node.args[0]].length;
                    const BigInt& lb = out.nodes[node.args[1]].length;
                    if (la != lb) {
                        return fail(diag, ErrorCode::Invalid, ValidationStage::Nodes,
                                    "Xor children have unequal lengths");
                    }
                    computed_len = la;
                    break;
                }
                case NodeKind::Interleave: {
                    if (!rr.read_u32_le(node.stride)) {
                        return fail(diag, ErrorCode::Invalid, ValidationStage::Nodes,
                                    "truncated Interleave stride");
                    }
                    if (node.stride == 0U) {
                        return fail(diag, ErrorCode::Invalid, ValidationStage::Nodes,
                                    "Interleave stride must be >= 1");
                    }
                    const BigInt& clen = out.nodes[node.args[0]].length;
                    for (std::size_t a = 1; a < node.args.size(); ++a) {
                        if (out.nodes[node.args[a]].length != clen) {
                            return fail(diag, ErrorCode::Invalid, ValidationStage::Nodes,
                                        "Interleave children have unequal lengths");
                        }
                    }
                    if (BigInt::mod_u64(clen, node.stride) != 0ULL) {
                        return fail(diag, ErrorCode::Invalid, ValidationStage::Nodes,
                                    "Interleave child length not a multiple of stride");
                    }
                    computed_len = BigInt::mul_u64(clen, static_cast<std::uint64_t>(node.args.size()));
                    break;
                }
                case NodeKind::Lfsr: {
                    if (!rr.read_u64_le(node.lfsr_conn) ||
                        !rr.read_u64_le(node.lfsr_init) ||
                        !rr.read_bigint(node.param_a)) {
                        return fail(diag, ErrorCode::Invalid, ValidationStage::Nodes,
                                    "invalid Lfsr params");
                    }
                    if (node.lfsr_conn == 0ULL) {
                        return fail(diag, ErrorCode::Invalid, ValidationStage::Nodes,
                                    "Lfsr conn must be != 0");
                    }
                    computed_len = node.param_a;
                    break;
                }
                case NodeKind::Affine: {
                    if (!rr.read_u8(node.affine_start) ||
                        !rr.read_u8(node.affine_step) ||
                        !rr.read_bigint(node.param_a)) {
                        return fail(diag, ErrorCode::Invalid, ValidationStage::Nodes,
                                    "invalid Affine params");
                    }
                    computed_len = node.param_a;
                    break;
                }
                case NodeKind::Predictor: {
                    if (!rr.read_u8(node.predictor_id) ||
                        !rr.read_u32_le(node.predictor_param)) {
                        return fail(diag, ErrorCode::Invalid, ValidationStage::Nodes,
                                    "truncated Predictor params");
                    }
                    if (node.predictor_id > 4U) {
                        return fail(diag, ErrorCode::Invalid, ValidationStage::Nodes,
                                    "unknown predictor id");
                    }
                    if (node.predictor_id >= 3U) {
                        if (node.predictor_param == 0U) {
                            return fail(diag, ErrorCode::Invalid, ValidationStage::Nodes,
                                        "stride predictor requires param >= 1");
                        }
                    } else {
                        if (node.predictor_param != 0U) {
                            return fail(diag, ErrorCode::Invalid, ValidationStage::Nodes,
                                        "non-stride predictor requires param == 0");
                        }
                    }
                    computed_len = out.nodes[node.args[0]].length;
                    break;
                }
            }

            if (!rr.read_bigint(node.length)) {
                return fail(diag, ErrorCode::Invalid, ValidationStage::Nodes,
                            "invalid or non-canonical node length bigint");
            }
            if (node.length != computed_len) {
                return fail(diag, ErrorCode::Invalid, ValidationStage::Nodes,
                            "node declared length != recomputed length");
            }

            NodeKey nkey = make_node_key(node);
            if (!seen_nodes.insert(std::move(nkey)).second) {
                return fail(diag, ErrorCode::Invalid, ValidationStage::Nodes,
                            "duplicate structurally identical node");
            }

            out.nodes.push_back(std::move(node));
        }

        if (rr.remaining() != 0ULL) {
            return fail(diag, ErrorCode::Invalid, ValidationStage::Nodes,
                        "trailing unconsumed bytes in node table");
        }

        // Iterative post-order first-use traversal from (node_count - 1):
        // verifies reachability, no unused nodes, post-order first-use node IDs,
        // and first-use atom IDs with no unused atoms.
        struct DfsFrame {
            std::uint32_t id;
            std::size_t next_arg;
        };
        std::vector<std::uint8_t> visit_state(node_count, 0); // 0=new, 1=active, 2=done
        std::vector<DfsFrame> stack;
        stack.push_back({static_cast<std::uint32_t>(node_count - 1), 0});
        visit_state[node_count - 1] = 1;

        std::uint32_t expected_node_id = 0;
        std::uint32_t expected_atom_id = 0;

        while (!stack.empty()) {
            DfsFrame& top = stack.back();
            const NodeRecord& cur = out.nodes[top.id];
            if (top.next_arg < cur.args.size()) {
                const std::uint32_t child = cur.args[top.next_arg++];
                if (visit_state[child] == 0) {
                    visit_state[child] = 1;
                    stack.push_back({child, 0});
                }
            } else {
                const std::uint32_t finished = top.id;
                visit_state[finished] = 2;
                stack.pop_back();
                if (finished != expected_node_id) {
                    return fail(diag, ErrorCode::Invalid, ValidationStage::Nodes,
                                "node table is not in canonical post-order first-use order");
                }
                ++expected_node_id;
                if (out.nodes[finished].kind == NodeKind::Atom) {
                    if (out.nodes[finished].atom_id != expected_atom_id) {
                        return fail(diag, ErrorCode::Invalid, ValidationStage::Nodes,
                                    "atom table is not in canonical first-use order");
                    }
                    ++expected_atom_id;
                }
            }
        }

        if (expected_node_id != static_cast<std::uint32_t>(node_count)) {
            return fail(diag, ErrorCode::Invalid, ValidationStage::Nodes,
                        "unreachable/unused node record present");
        }
        if (expected_atom_id != static_cast<std::uint32_t>(out.atoms.size())) {
            return fail(diag, ErrorCode::Invalid, ValidationStage::Nodes,
                        "unreferenced/unused atom record present");
        }
    }

    // ------------------------------------------------------------------
    // Stage 9: Root id == node_count - 1 and root length == declared total_length
    // ------------------------------------------------------------------
    if (out.trailer.root_id != static_cast<std::uint32_t>(out.nodes.size() - 1)) {
        return fail(diag, ErrorCode::Invalid, ValidationStage::Root,
                    "trailer root_id != node_count - 1");
    }
    if (out.nodes[out.trailer.root_id].length != out.total_length) {
        return fail(diag, ErrorCode::Invalid, ValidationStage::Root,
                    "root node length != header declared total_length");
    }

    // ------------------------------------------------------------------
    // Stage 10: Seek index (optional)
    // ------------------------------------------------------------------
    if (out.has_index) {
        const std::uint64_t idx_start = out.header.index_offset;
        const std::uint64_t idx_end = out.header.trailer_offset;
        const std::uint64_t idx_len = idx_end - idx_start;

        if (idx_len < 16ULL) {
            return fail(diag, ErrorCode::Invalid, ValidationStage::Index,
                        "index region smaller than 16 bytes");
        }

        std::array<std::uint8_t, 8> idx_magic{};
        if (!src.read_at(idx_start, idx_magic)) {
            return fail(diag, ErrorCode::Io, ValidationStage::Index,
                        "failed to read index magic");
        }
        if (!std::equal(kIndexMagic.begin(), kIndexMagic.end(), idx_magic.begin())) {
            return fail(diag, ErrorCode::Invalid, ValidationStage::Index,
                        "bad index magic");
        }

        // Verify index_crc32 over [idx_start, idx_end - 4)
        std::array<std::uint8_t, 4> stored_crc_bytes{};
        if (!src.read_at(idx_end - 4ULL, stored_crc_bytes)) {
            return fail(diag, ErrorCode::Io, ValidationStage::Index,
                        "failed to read index_crc32");
        }
        out.index_crc32 = load_le32(stored_crc_bytes.data());

        {
            Crc32 icrc;
            std::array<std::uint8_t, 65536> buf{};
            std::uint64_t pos = idx_start;
            const std::uint64_t crc_end = idx_end - 4ULL;
            while (pos < crc_end) {
                const std::size_t take = static_cast<std::size_t>(
                    std::min<std::uint64_t>(buf.size(), crc_end - pos));
                if (!src.read_at(pos, std::span<std::uint8_t>(buf.data(), take))) {
                    return fail(diag, ErrorCode::Io, ValidationStage::Index,
                                "I/O error while computing index_crc32");
                }
                icrc.update(std::span<const std::uint8_t>(buf.data(), take));
                pos += take;
            }
            if (icrc.value() != out.index_crc32) {
                return fail(diag, ErrorCode::Invalid, ValidationStage::Index,
                            "index_crc32 mismatch");
            }
        }

        RegionReader rr(src, idx_start + 8ULL, idx_end - 4ULL);
        std::uint32_t entry_count = 0;
        if (!rr.read_u32_le(entry_count)) {
            return fail(diag, ErrorCode::Invalid, ValidationStage::Index,
                        "truncated index entry_count");
        }
        if (entry_count == 0U) {
            return fail(diag, ErrorCode::Invalid, ValidationStage::Index,
                        "empty index region is non-canonical");
        }
        // Minimum index entry: 1(offset bigint) + 1(node_id uvarint) + 4(crc32) = 6 bytes
        if (static_cast<std::uint64_t>(entry_count) > rr.remaining() / 6ULL) {
            return fail(diag, ErrorCode::Invalid, ValidationStage::Index,
                        "index entry_count exceeds region capacity");
        }

        out.index_entries.reserve(entry_count);
        for (std::uint32_t i = 0; i < entry_count; ++i) {
            IndexEntry e;
            std::uint64_t nid = 0;
            if (!rr.read_bigint(e.output_offset) ||
                !rr.read_uvarint(nid) ||
                !rr.read_u32_le(e.crc32_of_prefix)) {
                return fail(diag, ErrorCode::Invalid, ValidationStage::Index,
                            "malformed or non-canonical index entry");
            }
            if (e.output_offset.is_zero() || e.output_offset >= out.total_length) {
                return fail(diag, ErrorCode::Invalid, ValidationStage::Index,
                            "index output_offset out of range (0, total_length)");
            }
            if (BigInt::mod_u64(e.output_offset, kIndexStride) != 0ULL) {
                return fail(diag, ErrorCode::Invalid, ValidationStage::Index,
                            "index output_offset not a multiple of INDEX_STRIDE");
            }
            if (i > 0U && e.output_offset <= out.index_entries.back().output_offset) {
                return fail(diag, ErrorCode::Invalid, ValidationStage::Index,
                            "index entries not strictly increasing");
            }
            if (nid >= out.nodes.size()) {
                return fail(diag, ErrorCode::Invalid, ValidationStage::Index,
                            "index node_id out of range");
            }
            e.node_id = static_cast<std::uint32_t>(nid);

            std::uint32_t expected_smallest = 0;
            if (!find_smallest_node_starting_at(out, e.output_offset, expected_smallest) ||
                expected_smallest != e.node_id) {
                return fail(diag, ErrorCode::Invalid, ValidationStage::Index,
                            "index node_id does not match smallest node starting at output_offset");
            }

            out.index_entries.push_back(std::move(e));
        }

        if (rr.remaining() != 0ULL) {
            return fail(diag, ErrorCode::Invalid, ValidationStage::Index,
                        "trailing unconsumed bytes in index region");
        }
    }

    return static_cast<int>(ErrorCode::Ok);
}

} // namespace detail

// ----------------------------------------------------------------------
// Public API implementations
// ----------------------------------------------------------------------

int validate_bytes(std::span<const std::uint8_t> wire,
                   bool structure_only,
                   Info* info,
                   Diagnostic* diag,
                   const Limits& limits) {
    return verify_bytes(wire, "", structure_only, info, diag, limits);
}

int verify_bytes(std::span<const std::uint8_t> wire,
                 const std::string& expect_sha256_hex,
                 bool structure_only,
                 Info* info,
                 Diagnostic* diag,
                 const Limits& limits) {
    std::string normalized_expect;
    if (!expect_sha256_hex.empty()) {
        if (!detail::normalize_sha256_hex(expect_sha256_hex, normalized_expect)) {
            return detail::fail(diag, ErrorCode::Usage, ValidationStage::None,
                                "invalid --sha256 hex digest (expected 64 hex chars)");
        }
    }

    detail::MemorySource src(wire);
    detail::ParsedContainer c;
    const int rc = detail::parse_and_validate_structure(src, c, limits, diag);
    if (rc != 0) {
        return rc;
    }

    if (structure_only) {
        detail::fill_info(c, "", info);
        return 0;
    }

    std::array<std::uint8_t, 32> digest{};
    const int erc = detail::eval_full_stream(
        c, src,
        [](std::span<const std::uint8_t>) -> int { return 0; },
        digest, limits, diag);
    if (erc != 0) {
        return erc;
    }

    const std::string sha_hex = detail::Sha256::to_hex(digest);
    detail::fill_info(c, sha_hex, info);

    if (!normalized_expect.empty() && sha_hex != normalized_expect) {
        return detail::fail(diag, ErrorCode::Mismatch, ValidationStage::Eval,
                            "output SHA-256 mismatch: expected " + normalized_expect +
                            " got " + sha_hex);
    }
    return 0;
}

int decode_bytes(std::span<const std::uint8_t> wire,
                 std::vector<std::uint8_t>& out,
                 Info* info,
                 Diagnostic* diag,
                 const Limits& limits) {
    out.clear();
    detail::MemorySource src(wire);
    detail::ParsedContainer c;
    const int rc = detail::parse_and_validate_structure(src, c, limits, diag);
    if (rc != 0) {
        return rc;
    }

    // Never reserve from huge total_length before limit check inside eval_full_stream
    std::vector<std::uint8_t> tmp;
    std::array<std::uint8_t, 32> digest{};
    const int erc = detail::eval_full_stream(
        c, src,
        [&tmp](std::span<const std::uint8_t> chunk) -> int {
            tmp.insert(tmp.end(), chunk.begin(), chunk.end());
            return 0;
        },
        digest, limits, diag);
    if (erc != 0) {
        return erc;
    }

    out = std::move(tmp);
    detail::fill_info(c, detail::Sha256::to_hex(digest), info);
    return 0;
}

int decode_range_bytes(std::span<const std::uint8_t> wire,
                       const std::string& start_decimal,
                       const std::string& len_decimal,
                       std::vector<std::uint8_t>& out,
                       Diagnostic* diag,
                       const Limits& limits) {
    out.clear();
    const auto start = detail::BigInt::from_decimal(start_decimal);
    const auto len = detail::BigInt::from_decimal(len_decimal);
    if (!start.has_value() || !len.has_value()) {
        return detail::fail(diag, ErrorCode::Usage, ValidationStage::None,
                            "invalid decimal start or len");
    }

    detail::MemorySource src(wire);
    detail::ParsedContainer c;
    const int rc = detail::parse_and_validate_structure(src, c, limits, diag);
    if (rc != 0) {
        return rc;
    }

    std::vector<std::uint8_t> tmp;
    const int erc = detail::eval_range_stream(
        c, src, *start, *len,
        [&tmp](std::span<const std::uint8_t> chunk) -> int {
            tmp.insert(tmp.end(), chunk.begin(), chunk.end());
            return 0;
        },
        limits, diag);
    if (erc != 0) {
        return erc;
    }

    out = std::move(tmp);
    return 0;
}

int inspect_bytes(std::span<const std::uint8_t> wire,
                  std::ostream& out,
                  Diagnostic* diag,
                  const Limits& limits) {
    detail::MemorySource src(wire);
    detail::ParsedContainer c;
    const int rc = detail::parse_and_validate_structure(src, c, limits, diag);
    if (rc != 0) {
        return rc;
    }
    detail::write_inspect_tsv(c, out);
    return out.good() ? 0 : static_cast<int>(ErrorCode::Io);
}

int decode_file(const std::filesystem::path& wire,
                const std::filesystem::path& out,
                Info* info) {
    return decode_file(wire, out, info, nullptr, Limits{});
}

int decode_file(const std::filesystem::path& wire,
                const std::filesystem::path& out,
                Info* info,
                Diagnostic* diag,
                const Limits& limits) {
    detail::FileSource src;
    std::string io_err;
    if (!src.open(wire, io_err)) {
        return detail::fail(diag, ErrorCode::Io, ValidationStage::None, io_err);
    }

    detail::ParsedContainer c;
    const int rc = detail::parse_and_validate_structure(src, c, limits, diag);
    if (rc != 0) {
        return rc;
    }

    // Check full output limit BEFORE creating output file
    if (!c.total_length.fits_u64() || c.total_length.to_u64() > limits.max_output_bytes) {
        return detail::fail(diag, ErrorCode::Limit, ValidationStage::Eval,
                            "declared total_length exceeds max_output_bytes");
    }

    std::ofstream ofs(out, std::ios::binary | std::ios::trunc);
    if (!ofs.is_open()) {
        return detail::fail(diag, ErrorCode::Io, ValidationStage::Eval,
                            "failed to open output file: " + out.string());
    }

    std::array<std::uint8_t, 32> digest{};
    const int erc = detail::eval_full_stream(
        c, src,
        [&ofs](std::span<const std::uint8_t> chunk) -> int {
            if (!chunk.empty()) {
                ofs.write(reinterpret_cast<const char*>(chunk.data()),
                          static_cast<std::streamsize>(chunk.size()));
                if (!ofs.good()) {
                    return static_cast<int>(ErrorCode::Io);
                }
            }
            return 0;
        },
        digest, limits, diag);

    ofs.flush();
    const bool write_ok = ofs.good();
    ofs.close();

    if (erc != 0 || !write_ok) {
        std::error_code ec;
        std::filesystem::remove(out, ec);
        if (erc != 0) {
            return erc;
        }
        return detail::fail(diag, ErrorCode::Io, ValidationStage::Eval,
                            "failed writing output file: " + out.string());
    }

    detail::fill_info(c, detail::Sha256::to_hex(digest), info);
    return 0;
}

int verify_file(const std::filesystem::path& wire,
                const std::string& expect_sha256_hex,
                bool structure_only) {
    return verify_file(wire, expect_sha256_hex, structure_only, nullptr, nullptr, Limits{});
}

int verify_file(const std::filesystem::path& wire,
                const std::string& expect_sha256_hex,
                bool structure_only,
                Info* info,
                Diagnostic* diag,
                const Limits& limits) {
    std::string normalized_expect;
    if (!expect_sha256_hex.empty()) {
        if (!detail::normalize_sha256_hex(expect_sha256_hex, normalized_expect)) {
            return detail::fail(diag, ErrorCode::Usage, ValidationStage::None,
                                "invalid --sha256 hex digest (expected 64 hex chars)");
        }
    }

    detail::FileSource src;
    std::string io_err;
    if (!src.open(wire, io_err)) {
        return detail::fail(diag, ErrorCode::Io, ValidationStage::None, io_err);
    }

    detail::ParsedContainer c;
    const int rc = detail::parse_and_validate_structure(src, c, limits, diag);
    if (rc != 0) {
        return rc;
    }

    if (structure_only) {
        detail::fill_info(c, "", info);
        return 0;
    }

    std::array<std::uint8_t, 32> digest{};
    const int erc = detail::eval_full_stream(
        c, src,
        [](std::span<const std::uint8_t>) -> int { return 0; },
        digest, limits, diag);
    if (erc != 0) {
        return erc;
    }

    const std::string sha_hex = detail::Sha256::to_hex(digest);
    detail::fill_info(c, sha_hex, info);

    if (!normalized_expect.empty() && sha_hex != normalized_expect) {
        return detail::fail(diag, ErrorCode::Mismatch, ValidationStage::Eval,
                            "output SHA-256 mismatch: expected " + normalized_expect +
                            " got " + sha_hex);
    }
    return 0;
}

int decode_range(const std::filesystem::path& wire,
                 const std::string& start_decimal,
                 const std::string& len_decimal,
                 const std::filesystem::path& out) {
    return decode_range(wire, start_decimal, len_decimal, out, nullptr, Limits{});
}

int decode_range(const std::filesystem::path& wire,
                 const std::string& start_decimal,
                 const std::string& len_decimal,
                 const std::filesystem::path& out,
                 Diagnostic* diag,
                 const Limits& limits) {
    const auto start = detail::BigInt::from_decimal(start_decimal);
    const auto len = detail::BigInt::from_decimal(len_decimal);
    if (!start.has_value() || !len.has_value()) {
        return detail::fail(diag, ErrorCode::Usage, ValidationStage::None,
                            "invalid decimal start or len");
    }

    detail::FileSource src;
    std::string io_err;
    if (!src.open(wire, io_err)) {
        return detail::fail(diag, ErrorCode::Io, ValidationStage::None, io_err);
    }

    detail::ParsedContainer c;
    const int rc = detail::parse_and_validate_structure(src, c, limits, diag);
    if (rc != 0) {
        return rc;
    }

    // Pre-validate range bounds & limits before creating output file
    if (*start > c.total_length || detail::BigInt::add(*start, *len) > c.total_length) {
        return detail::fail(diag, ErrorCode::Invalid, ValidationStage::Eval,
                            "requested range exceeds declared total_length");
    }
    if (!len->fits_u64() || len->to_u64() > limits.max_output_bytes) {
        return detail::fail(diag, ErrorCode::Limit, ValidationStage::Eval,
                            "requested range length exceeds max_output_bytes");
    }
    const detail::BigInt max_expanded =
        detail::BigInt::mul_u64(detail::BigInt(src.size()), limits.max_range_expansion_ratio);
    if (*len > max_expanded) {
        return detail::fail(diag, ErrorCode::Limit, ValidationStage::Eval,
                            "requested range exceeds max_range_expansion_ratio");
    }

    std::ofstream ofs(out, std::ios::binary | std::ios::trunc);
    if (!ofs.is_open()) {
        return detail::fail(diag, ErrorCode::Io, ValidationStage::Eval,
                            "failed to open output file: " + out.string());
    }

    const int erc = detail::eval_range_stream(
        c, src, *start, *len,
        [&ofs](std::span<const std::uint8_t> chunk) -> int {
            if (!chunk.empty()) {
                ofs.write(reinterpret_cast<const char*>(chunk.data()),
                          static_cast<std::streamsize>(chunk.size()));
                if (!ofs.good()) {
                    return static_cast<int>(ErrorCode::Io);
                }
            }
            return 0;
        },
        limits, diag);

    ofs.flush();
    const bool write_ok = ofs.good();
    ofs.close();

    if (erc != 0 || !write_ok) {
        std::error_code ec;
        std::filesystem::remove(out, ec);
        if (erc != 0) {
            return erc;
        }
        return detail::fail(diag, ErrorCode::Io, ValidationStage::Eval,
                            "failed writing output file: " + out.string());
    }
    return 0;
}

int inspect_file(const std::filesystem::path& wire, std::ostream& out) {
    return inspect_file(wire, out, nullptr, Limits{});
}

int inspect_file(const std::filesystem::path& wire,
                 std::ostream& out,
                 Diagnostic* diag,
                 const Limits& limits) {
    detail::FileSource src;
    std::string io_err;
    if (!src.open(wire, io_err)) {
        return detail::fail(diag, ErrorCode::Io, ValidationStage::None, io_err);
    }

    detail::ParsedContainer c;
    const int rc = detail::parse_and_validate_structure(src, c, limits, diag);
    if (rc != 0) {
        return rc;
    }
    detail::write_inspect_tsv(c, out);
    return out.good() ? 0 : static_cast<int>(ErrorCode::Io);
}

} // namespace marp::oracle
