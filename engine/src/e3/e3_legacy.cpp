#include <mapr/e3/e3_legacy.hpp>

#include <mapr/e1_bigint.hpp>
#include <mapr/e1_crc32.hpp>
#include <mapr/e1_length.hpp>
#include <mapr/e1_sha256.hpp>
#include <mapr/e2/e2_canon.hpp>
#include <mapr/e2/e2_dag.hpp>
#include <mapr/e2/e2_eval.hpp>

#include <algorithm>
#include <array>
#include <bit>
#include <cstring>
#include <limits>
#include <numeric>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace marp::v2 {

WireCode SpanSource::read(u64 offset, std::span<u8> dst) {
    const u64 total = static_cast<u64>(bytes_.size());
    const u64 count = static_cast<u64>(dst.size());
    if (offset > total || count > total - offset) {
        return WireCode::Invalid;
    }
    if (count > 0ULL) {
        std::memcpy(dst.data(),
                    bytes_.data() + static_cast<std::size_t>(offset),
                    dst.size());
    }
    return WireCode::Ok;
}

WireResult<std::span<const u8>> HeapArena::store(std::span<const u8> bytes) {
    if (bytes.size() > max_bytes_ || used_bytes_ > max_bytes_ - bytes.size()) {
        return WireResult<std::span<const u8>>{
            WireCode::Limit, "HeapArena capacity exceeded"};
    }
    try {
        std::vector<u8> block(bytes.begin(), bytes.end());
        const u8* ptr = block.data();
        const std::size_t n = block.size();
        blocks_.push_back(std::move(block));
        used_bytes_ += n;
        return std::span<const u8>{ptr, n};
    } catch (...) {
        return WireResult<std::span<const u8>>{
            WireCode::Limit, "HeapArena allocation failed"};
    }
}

namespace {

// Frozen MARP v1 8-byte magic: "\x89MAPR\r\n\x1a" (SPECS/SPECS.md §2.1).
// Distinct from v2 magic "\x89MAPR2\r\n" (89 4D 41 50 52 32 0D 0A) at byte 5.
constexpr std::array<u8, 8> kV1Magic = {
    0x89u, 0x4Du, 0x41u, 0x50u, 0x52u, 0x0Du, 0x0Au, 0x1Au};

constexpr u32 kFlagRawBytesMsb    = 1u << 0;
constexpr u32 kFlagHasIndex       = 1u << 1;
constexpr u32 kFlagStreamedHeader = 1u << 2;
constexpr u32 kKnownHeaderFlags   =
    kFlagRawBytesMsb | kFlagHasIndex | kFlagStreamedHeader;

constexpr u8 kChunkKindRef         = 0u;
constexpr u8 kChunkKindExplicitDag = 1u;

// Normative StreamConfig bounds (FORMAT_SPEC_v1_0_1_ERRATA.md §1.2).
constexpr u32 kNormativeWSync = 64u;
constexpr u32 kNormativeLMax  = 16'777'216u;
constexpr u32 kNormativeWHist = 4096u;

// v2 Morph codes matching V4Op bit actions on MSB-packed byte sequences.
constexpr u8 kV2MorphInvert8     = 2u;
constexpr u8 kV2MorphReverseBits = 9u;

using Digest256 = std::array<u8, 32>;

[[nodiscard]] inline std::string_view sv_of(std::span<const u8> s) noexcept {
    return std::string_view(reinterpret_cast<const char*>(s.data()), s.size());
}

[[nodiscard]] inline u32 crc32_span(std::span<const u8> s) noexcept {
    return mapr::crc32(sv_of(s));
}

[[nodiscard]] inline Digest256 sha256_span(std::span<const u8> s) noexcept {
    return mapr::Sha256::hash(sv_of(s)).value();
}

[[nodiscard]] constexpr u16 read_le16(const u8* p) noexcept {
    return static_cast<u16>(static_cast<u16>(p[0]) |
                            static_cast<u16>(static_cast<u16>(p[1]) << 8));
}

[[nodiscard]] constexpr u32 read_le32(const u8* p) noexcept {
    return static_cast<u32>(p[0]) |
           (static_cast<u32>(p[1]) << 8) |
           (static_cast<u32>(p[2]) << 16) |
           (static_cast<u32>(p[3]) << 24);
}

[[nodiscard]] constexpr u64 read_le64(const u8* p) noexcept {
    return static_cast<u64>(p[0]) |
           (static_cast<u64>(p[1]) << 8) |
           (static_cast<u64>(p[2]) << 16) |
           (static_cast<u64>(p[3]) << 24) |
           (static_cast<u64>(p[4]) << 32) |
           (static_cast<u64>(p[5]) << 40) |
           (static_cast<u64>(p[6]) << 48) |
           (static_cast<u64>(p[7]) << 56);
}

constexpr void write_be64(u8* p, u64 v) noexcept {
    for (int i = 7; i >= 0; --i) {
        p[i] = static_cast<u8>(v & 0xFFULL);
        v >>= 8;
    }
}

[[nodiscard]] constexpr u8 bitrev8(u8 x) noexcept {
    unsigned v = static_cast<unsigned>(x);
    v = ((v & 0x55u) << 1) | ((v & 0xAAu) >> 1);
    v = ((v & 0x33u) << 2) | ((v & 0xCCu) >> 2);
    v = ((v & 0x0Fu) << 4) | ((v & 0xF0u) >> 4);
    return static_cast<u8>(v & 0xFFu);
}

struct BinomTable {
    std::array<std::array<u64, 65>, 65> c{};

    constexpr BinomTable() noexcept {
        for (std::size_t n = 0; n <= 64; ++n) {
            c[n][0] = 1ULL;
            c[n][n] = 1ULL;
            for (std::size_t k = 1; k < n; ++k) {
                c[n][k] = c[n - 1][k - 1] + c[n - 1][k];
            }
        }
    }
};

constexpr BinomTable kBinom{};

[[nodiscard]] constexpr u64 binom64(int n, int k) noexcept {
    if (k < 0 || n < 0 || n > 64 || k > n) return 0ULL;
    return kBinom.c[static_cast<std::size_t>(n)][static_cast<std::size_t>(k)];
}

// Colex unranking on 0 <= p_1 < ... < p_w < b (SPECS.md §2.3).
[[nodiscard]] u64 unrank_colex64(int b, int w, u64 rho) noexcept {
    if (w == 0) return 0ULL;
    if (w == b) return (b == 64) ? ~0ULL : ((1ULL << b) - 1ULL);
    u64 x = 0ULL;
    u64 rem = rho;
    int top = b;
    for (int k = w; k >= 1; --k) {
        for (int p = top - 1; p >= k - 1; --p) {
            const u64 c_pk = binom64(p, k);
            if (c_pk <= rem) {
                x |= (1ULL << p);
                rem -= c_pk;
                top = p;
                break;
            }
        }
    }
    return x;
}

// Dyadic Möbius transform over GF(2) on power-of-two width b in {1,2,4,8,16,32,64}.
[[nodiscard]] u64 mobius_word64(u64 x, int b) noexcept {
    if (b >= 2)  x ^= ((x & 0x5555555555555555ULL) << 1);
    if (b >= 4)  x ^= ((x & 0x3333333333333333ULL) << 2);
    if (b >= 8)  x ^= ((x & 0x0F0F0F0F0F0F0F0FULL) << 4);
    if (b >= 16) x ^= ((x & 0x00FF00FF00FF00FFULL) << 8);
    if (b >= 32) x ^= ((x & 0x0000FFFF0000FFFFULL) << 16);
    if (b >= 64) x ^= (x << 32);
    if (b < 64)  x &= ((1ULL << b) - 1ULL);
    return x;
}

// Compact bit sequence matching frozen v1 LSB-within-word / MSB-per-byte conventions.
class V1BitSeq {
public:
    V1BitSeq() = default;

    explicit V1BitSeq(u64 bit_len)
        : words_(static_cast<std::size_t>((bit_len + 63ULL) >> 6), 0ULL),
          bit_len_(bit_len) {}

    [[nodiscard]] u64 bit_len() const noexcept { return bit_len_; }
    [[nodiscard]] std::size_t storage_bytes() const noexcept {
        return words_.size() * sizeof(u64);
    }

    void clear_memory() noexcept {
        std::vector<u64>().swap(words_);
        bit_len_ = 0ULL;
    }

    [[nodiscard]] bool get_bit(u64 i) const noexcept {
        return ((words_[static_cast<std::size_t>(i >> 6)] >>
                 static_cast<unsigned>(i & 63ULL)) &
                1ULL) != 0ULL;
    }

    void set_bit(u64 i) noexcept {
        words_[static_cast<std::size_t>(i >> 6)] |=
            (1ULL << static_cast<unsigned>(i & 63ULL));
    }

    [[nodiscard]] u64 word(std::size_t idx) const noexcept {
        return idx < words_.size() ? words_[idx] : 0ULL;
    }

    [[nodiscard]] bool is_all_zeros() const noexcept {
        for (u64 w : words_) {
            if (w != 0ULL) return false;
        }
        return true;
    }

    static V1BitSeq from_word(u64 w, int b) {
        V1BitSeq out(static_cast<u64>(b));
        if (b > 0) {
            out.words_[0] = (b == 64) ? w : (w & ((1ULL << b) - 1ULL));
        }
        return out;
    }

    static V1BitSeq from_bytes_msb_sliced(std::span<const u8> bytes, u64 take_bits) {
        V1BitSeq out(take_bits);
        const u64 needed_bytes = (take_bits + 7ULL) >> 3;
        for (u64 i = 0; i < needed_bytes; ++i) {
            const u64 b = static_cast<u64>(bitrev8(bytes[static_cast<std::size_t>(i)]));
            out.words_[static_cast<std::size_t>(i >> 3)] |=
                (b << static_cast<unsigned>((i & 7ULL) * 8ULL));
        }
        out.trim_tail();
        return out;
    }

    [[nodiscard]] std::vector<u8> to_bytes_msb() const {
        const std::size_t n_bytes = static_cast<std::size_t>(bit_len_ >> 3);
        std::vector<u8> out(n_bytes, 0u);
        for (std::size_t i = 0; i < n_bytes; ++i) {
            const std::size_t wi = i >> 3;
            const unsigned shift = static_cast<unsigned>((i & 7u) * 8u);
            out[i] = bitrev8(static_cast<u8>((words_[wi] >> shift) & 0xFFULL));
        }
        return out;
    }

    [[nodiscard]] V1BitSeq slice(u64 start, u64 length) const {
        if (length == 0ULL) return V1BitSeq{};
        V1BitSeq out(length);
        const std::size_t dst_words = out.words_.size();
        const std::size_t word_off = static_cast<std::size_t>(start >> 6);
        const unsigned bit_off = static_cast<unsigned>(start & 63ULL);

        if (bit_off == 0u) {
            std::copy(words_.begin() + static_cast<std::ptrdiff_t>(word_off),
                      words_.begin() + static_cast<std::ptrdiff_t>(word_off + dst_words),
                      out.words_.begin());
        } else {
            for (std::size_t i = 0; i < dst_words; ++i) {
                u64 v = words_[word_off + i] >> bit_off;
                if (word_off + i + 1 < words_.size()) {
                    v |= (words_[word_off + i + 1] << (64u - bit_off));
                }
                out.words_[i] = v;
            }
        }
        out.trim_tail();
        return out;
    }

    void append(const V1BitSeq& other) {
        if (other.bit_len_ == 0ULL) return;
        const u64 old_len = bit_len_;
        const u64 new_len = old_len + other.bit_len_;
        const std::size_t new_words = static_cast<std::size_t>((new_len + 63ULL) >> 6);
        words_.resize(new_words, 0ULL);

        const std::size_t dst_wi = static_cast<std::size_t>(old_len >> 6);
        const unsigned dst_bi = static_cast<unsigned>(old_len & 63ULL);
        const std::size_t src_words = other.words_.size();

        if (dst_bi == 0u) {
            for (std::size_t i = 0; i < src_words; ++i) {
                words_[dst_wi + i] = other.words_[i];
            }
        } else {
            for (std::size_t i = 0; i < src_words; ++i) {
                words_[dst_wi + i] |= (other.words_[i] << dst_bi);
                if (dst_wi + i + 1 < new_words) {
                    words_[dst_wi + i + 1] |= (other.words_[i] >> (64u - dst_bi));
                }
            }
        }
        bit_len_ = new_len;
        trim_tail();
    }

    void reserve_bits(u64 total_bits) {
        words_.reserve(static_cast<std::size_t>((total_bits + 63ULL) >> 6));
    }

    [[nodiscard]] V1BitSeq bitwise_not() const {
        V1BitSeq out(bit_len_);
        for (std::size_t i = 0; i < words_.size(); ++i) {
            out.words_[i] = ~words_[i];
        }
        out.trim_tail();
        return out;
    }

    [[nodiscard]] V1BitSeq reverse_bits() const {
        if (bit_len_ == 0ULL) return V1BitSeq{};
        V1BitSeq out(bit_len_);
        for (u64 i = 0; i < bit_len_; ++i) {
            if (get_bit(bit_len_ - 1ULL - i)) {
                out.set_bit(i);
            }
        }
        return out;
    }

    [[nodiscard]] V1BitSeq apply_v4(u8 mu) const {
        switch (mu) {
            case 0u: return *this;
            case 1u: return bitwise_not();
            case 2u: return reverse_bits();
            case 3u: return reverse_bits().bitwise_not();
            default: return *this;
        }
    }

    [[nodiscard]] V1BitSeq bitwise_xor(const V1BitSeq& other) const {
        V1BitSeq out(bit_len_);
        for (std::size_t i = 0; i < words_.size(); ++i) {
            out.words_[i] = words_[i] ^ other.words_[i];
        }
        out.trim_tail();
        return out;
    }

    static V1BitSeq repeat_seq(const V1BitSeq& child, u64 q, u64 r) {
        const u64 total = q * child.bit_len_ + r;
        V1BitSeq out;
        out.reserve_bits(total);
        for (u64 i = 0; i < q; ++i) {
            out.append(child);
        }
        if (r > 0ULL) {
            out.append(child.slice(0ULL, r));
        }
        return out;
    }

private:
    void trim_tail() noexcept {
        if (words_.empty()) return;
        const unsigned rem = static_cast<unsigned>(bit_len_ & 63ULL);
        if (rem != 0u) {
            words_.back() &= ((1ULL << rem) - 1ULL);
        }
    }

    std::vector<u64> words_{};
    u64 bit_len_ = 0ULL;
};

// Exception-free LSB-first bit reader matching frozen v1 chunk-DAG payload coding.
class BitReader64 {
public:
    explicit BitReader64(std::span<const u8> data) noexcept : data_(data) {}

    [[nodiscard]] bool read_bits(int n, u64& out) noexcept {
        if (n < 0 || n > 64) return false;
        if (n == 0) {
            out = 0ULL;
            return true;
        }
        if (n > 32) {
            u64 lo = 0ULL;
            u64 hi = 0ULL;
            if (!read_bits(32, lo) || !read_bits(n - 32, hi)) return false;
            out = lo | (hi << 32);
            return true;
        }
        refill();
        if (bit_count_ < n) return false;
        out = acc_ & ((1ULL << static_cast<unsigned>(n)) - 1ULL);
        acc_ >>= static_cast<unsigned>(n);
        bit_count_ -= n;
        return true;
    }

    [[nodiscard]] bool read_varint(u64& out) noexcept {
        u64 val = 0ULL;
        int shift = 0;
        for (int idx = 0; idx < 10; ++idx) {
            u64 byte = 0ULL;
            if (!read_bits(8, byte)) return false;
            if (shift > 0 && byte == 0ULL) {
                return false; // Non-canonical overlong ULEB128
            }
            if (shift == 63 && byte > 1ULL) {
                return false; // Overflow past u64
            }
            val |= ((byte & 0x7FULL) << static_cast<unsigned>(shift));
            if ((byte & 0x80ULL) == 0ULL) {
                out = val;
                return true;
            }
            shift += 7;
        }
        return false;
    }

    [[nodiscard]] bool read_trunc_bin(u64 m, u64& out) noexcept {
        if (m <= 1ULL) {
            out = 0ULL;
            return true;
        }
        const int k = static_cast<int>(std::bit_width(m)) - 1;
        const u64 u = (1ULL << static_cast<unsigned>(k + 1)) - m;
        u64 x = 0ULL;
        if (!read_bits(k, x)) return false;
        if (x < u) {
            out = x;
            return true;
        }
        u64 b = 0ULL;
        if (!read_bits(1, b)) return false;
        const u64 res = ((x << 1) | b) - u;
        if (res >= m) return false;
        out = res;
        return true;
    }

    [[nodiscard]] std::size_t unread_whole_bytes() const noexcept {
        const std::size_t in_acc = static_cast<std::size_t>(bit_count_ >> 3);
        const std::size_t in_buf = data_.size() - byte_pos_;
        return in_acc + in_buf;
    }

    [[nodiscard]] bool verify_zero_padding() noexcept {
        if (bit_count_ >= 8) return false;
        if (acc_ != 0ULL) return false;
        if (byte_pos_ != data_.size()) return false;
        bit_count_ = 0;
        return true;
    }

private:
    void refill() noexcept {
        while (bit_count_ <= 56 && byte_pos_ < data_.size()) {
            acc_ |= (static_cast<u64>(data_[byte_pos_++])
                     << static_cast<unsigned>(bit_count_));
            bit_count_ += 8;
        }
    }

    std::span<const u8> data_;
    std::size_t byte_pos_ = 0;
    u64 acc_ = 0ULL;
    int bit_count_ = 0;
};

struct V1DualAtom {
    u8 basis = 0u; // 0 = POS, 1 = ZHEG
    u8 b = 0u;     // 1..64
    u8 w = 0u;     // 0..b
    u64 rho = 0ULL;
};

struct V1EmptyNode {};
struct V1AtomNode { V1DualAtom atom; };
struct V1AtomSpanNode { std::vector<V1DualAtom> atoms; };
struct V1ConcatNode { std::vector<u32> children; };
struct V1RepeatNode { u32 child = 0u; u64 q = 0ULL; u64 r = 0ULL; };
struct V1SliceNode { u32 child = 0u; u64 start = 0ULL; u64 length = 0ULL; };
struct V1MorphNode { u32 child = 0u; u8 mu = 0u; };
struct V1XorDiffNode { u32 base = 0u; u32 delta = 0u; };
struct V1InterleaveNode { u8 stride = 0u; std::vector<u32> lanes; };
struct V1LfsrNode { u8 degree = 0u; u64 conn_mask = 0ULL; u64 init_mask = 0ULL; u64 length = 0ULL; };
struct V1RawNode { std::vector<u8> bytes; u64 bit_len = 0ULL; };
struct V1DedupRefNode { u64 ref_id = 0ULL; };
struct V1DeflateHintNode { u8 cm = 0u; u8 flg = 0u; u16 mtime = 0u; u8 xfl = 0u; u8 os = 0u; };

using V1DagNode = std::variant<
    V1EmptyNode,
    V1AtomNode,
    V1AtomSpanNode,
    V1ConcatNode,
    V1RepeatNode,
    V1SliceNode,
    V1MorphNode,
    V1XorDiffNode,
    V1InterleaveNode,
    V1LfsrNode,
    V1RawNode,
    V1DedupRefNode,
    V1DeflateHintNode>;

struct V1ChunkDag {
    u32 root = 0u;
    std::vector<V1DagNode> nodes{};
    std::vector<u64> bit_lengths{};
};

[[nodiscard]] bool is_valid_atom(const V1DualAtom& a) noexcept {
    if (a.b < 1u || a.b > 64u) return false;
    if (a.basis > 1u) return false;
    if (a.basis == 1u && !std::has_single_bit(static_cast<unsigned>(a.b))) {
        return false;
    }
    if (a.w > a.b) return false;
    const u64 comb = binom64(static_cast<int>(a.b), static_cast<int>(a.w));
    return a.rho < comb;
}

[[nodiscard]] u64 eval_atom_word(const V1DualAtom& a) noexcept {
    u64 x = unrank_colex64(static_cast<int>(a.b), static_cast<int>(a.w), a.rho);
    if (a.basis == 1u) {
        x = mobius_word64(x, static_cast<int>(a.b));
    }
    return x;
}

[[nodiscard]] bool read_atom_fixed_b(BitReader64& br, int b, V1DualAtom& out) noexcept {
    if (b < 1 || b > 64) return false;
    u64 beta = 0ULL;
    if ((b & (b - 1)) == 0) {
        if (!br.read_bits(1, beta)) return false;
    }
    u64 w = 0ULL;
    if (!br.read_trunc_bin(static_cast<u64>(b) + 1ULL, w)) return false;
    const u64 comb = binom64(b, static_cast<int>(w));
    u64 rho = 0ULL;
    if (comb > 1ULL) {
        if (!br.read_trunc_bin(comb, rho)) return false;
    }
    out = V1DualAtom{
        static_cast<u8>(beta),
        static_cast<u8>(b),
        static_cast<u8>(w),
        rho};
    return is_valid_atom(out);
}

[[nodiscard]] bool read_atom(BitReader64& br, V1DualAtom& out) noexcept {
    u64 is64 = 0ULL;
    if (!br.read_bits(1, is64)) return false;
    int b = 64;
    if (is64 == 0ULL) {
        u64 b_minus_1 = 0ULL;
        if (!br.read_bits(6, b_minus_1)) return false;
        b = static_cast<int>(b_minus_1) + 1;
        if (b == 64) return false; // Non-canonical: b=64 uses is64=1 prefix
    }
    return read_atom_fixed_b(br, b, out);
}

[[nodiscard]] bool read_child_ref(BitReader64& br, u32 v, u32& out_u) noexcept {
    if (v == 0u) return false;
    u64 rel = 0ULL;
    if (!br.read_varint(rel)) return false;
    if (rel >= static_cast<u64>(v)) return false;
    out_u = v - 1u - static_cast<u32>(rel);
    return true;
}

[[nodiscard]] WireResult<V1ChunkDag> parse_and_validate_chunk_dag(
    std::span<const u8> payload,
    u64 expected_bit_len,
    const LegacyLimits& limits) {
    if (payload.empty()) {
        return WireResult<V1ChunkDag>{WireCode::Invalid, "empty MCHK DAG payload"};
    }
    BitReader64 br(payload);
    u64 m = 0ULL;
    if (!br.read_varint(m)) {
        return WireResult<V1ChunkDag>{WireCode::Invalid, "invalid DAG node count varint"};
    }

    if (expected_bit_len > (std::numeric_limits<u64>::max() - 16ULL) / 2ULL) {
        return WireResult<V1ChunkDag>{WireCode::Invalid, "chunk bit_len overflow"};
    }
    const u64 max_norm_nodes = 2ULL * expected_bit_len + 16ULL;
    if (m == 0ULL || m > max_norm_nodes) {
        return WireResult<V1ChunkDag>{WireCode::Invalid, "DAG node count out of normative bounds"};
    }
    const u64 max_possible_from_wire = static_cast<u64>(payload.size()) * 2ULL;
    if (m > max_possible_from_wire) {
        return WireResult<V1ChunkDag>{WireCode::Invalid, "truncated MCHK DAG payload"};
    }
    if (m > limits.max_dag_nodes_per_chunk ||
        m > static_cast<u64>(std::numeric_limits<u32>::max())) {
        return WireResult<V1ChunkDag>{WireCode::Limit, "DAG node count exceeds LegacyLimits"};
    }

    u64 root64 = 0ULL;
    if (!br.read_varint(root64) || root64 >= m) {
        return WireResult<V1ChunkDag>{WireCode::Invalid, "invalid DAG root index"};
    }

    V1ChunkDag dag;
    dag.root = static_cast<u32>(root64);
    dag.nodes.reserve(static_cast<std::size_t>(m));
    dag.bit_lengths.assign(static_cast<std::size_t>(m), 0ULL);

    const u64 max_inter_bits =
        (expected_bit_len > (std::numeric_limits<u64>::max() - 4096ULL) / 4ULL)
            ? std::numeric_limits<u64>::max()
            : std::max<u64>(4ULL * expected_bit_len + 4096ULL, 67'108'864ULL);

    bool saw_dedup_ref = false;
    bool saw_deflate_hint = false;

    for (u32 v = 0u; v < static_cast<u32>(m); ++v) {
        u64 op = 0ULL;
        if (!br.read_bits(4, op)) {
            return WireResult<V1ChunkDag>{WireCode::Invalid, "truncated DAG node opcode"};
        }

        switch (op) {
            case 0ULL: { // EMPTY
                dag.nodes.emplace_back(V1EmptyNode{});
                break;
            }
            case 1ULL: { // ATOM
                V1DualAtom a{};
                if (!read_atom(br, a)) {
                    return WireResult<V1ChunkDag>{WireCode::Invalid, "invalid ATOM encoding"};
                }
                dag.nodes.emplace_back(V1AtomNode{a});
                break;
            }
            case 2ULL: { // ATOM_SPAN
                u64 cnt = 0ULL;
                if (!br.read_varint(cnt) || cnt == 0ULL || cnt > max_norm_nodes) {
                    return WireResult<V1ChunkDag>{WireCode::Invalid, "invalid ATOM_SPAN count"};
                }
                const u64 rem_bits_upper = static_cast<u64>(payload.size()) * 8ULL;
                if (cnt > rem_bits_upper) {
                    return WireResult<V1ChunkDag>{WireCode::Invalid, "truncated ATOM_SPAN"};
                }
                u64 homog = 0ULL;
                if (!br.read_bits(1, homog)) {
                    return WireResult<V1ChunkDag>{WireCode::Invalid, "truncated ATOM_SPAN homog"};
                }
                V1AtomSpanNode span_node;
                span_node.atoms.reserve(static_cast<std::size_t>(cnt));
                if (homog != 0ULL) {
                    u64 tail_b_m1 = 0ULL;
                    if (!br.read_bits(6, tail_b_m1)) {
                        return WireResult<V1ChunkDag>{WireCode::Invalid, "truncated ATOM_SPAN tail_b"};
                    }
                    const int tail_b = static_cast<int>(tail_b_m1) + 1;
                    for (u64 i = 0ULL; i + 1ULL < cnt; ++i) {
                        V1DualAtom a{};
                        if (!read_atom_fixed_b(br, 64, a)) {
                            return WireResult<V1ChunkDag>{WireCode::Invalid, "invalid homog ATOM_SPAN body"};
                        }
                        span_node.atoms.push_back(a);
                    }
                    V1DualAtom tail{};
                    if (!read_atom_fixed_b(br, tail_b, tail)) {
                        return WireResult<V1ChunkDag>{WireCode::Invalid, "invalid homog ATOM_SPAN tail"};
                    }
                    span_node.atoms.push_back(tail);
                } else {
                    for (u64 i = 0ULL; i < cnt; ++i) {
                        V1DualAtom a{};
                        if (!read_atom(br, a)) {
                            return WireResult<V1ChunkDag>{WireCode::Invalid, "invalid heterog ATOM_SPAN"};
                        }
                        span_node.atoms.push_back(a);
                    }
                }
                dag.nodes.emplace_back(std::move(span_node));
                break;
            }
            case 3ULL: { // CONCAT
                u64 raw_d = 0ULL;
                if (!br.read_varint(raw_d) || raw_d > max_norm_nodes) {
                    return WireResult<V1ChunkDag>{WireCode::Invalid, "invalid CONCAT arity"};
                }
                const u64 d = raw_d + 2ULL;
                if (d > max_norm_nodes) {
                    return WireResult<V1ChunkDag>{WireCode::Invalid, "CONCAT arity exceeds normative bound"};
                }
                V1ConcatNode cn;
                cn.children.reserve(static_cast<std::size_t>(d));
                for (u64 i = 0ULL; i < d; ++i) {
                    u32 u = 0u;
                    if (!read_child_ref(br, v, u)) {
                        return WireResult<V1ChunkDag>{WireCode::Invalid, "invalid CONCAT child ref"};
                    }
                    cn.children.push_back(u);
                }
                dag.nodes.emplace_back(std::move(cn));
                break;
            }
            case 4ULL: { // REPEAT
                u32 child = 0u;
                if (!read_child_ref(br, v, child)) {
                    return WireResult<V1ChunkDag>{WireCode::Invalid, "invalid REPEAT child ref"};
                }
                u64 raw_q = 0ULL;
                u64 r = 0ULL;
                if (!br.read_varint(raw_q) || raw_q == std::numeric_limits<u64>::max() ||
                    !br.read_varint(r)) {
                    return WireResult<V1ChunkDag>{WireCode::Invalid, "invalid REPEAT params"};
                }
                dag.nodes.emplace_back(V1RepeatNode{child, raw_q + 1ULL, r});
                break;
            }
            case 5ULL: { // SLICE
                u32 child = 0u;
                if (!read_child_ref(br, v, child)) {
                    return WireResult<V1ChunkDag>{WireCode::Invalid, "invalid SLICE child ref"};
                }
                u64 start = 0ULL;
                u64 raw_ln = 0ULL;
                if (!br.read_varint(start) || !br.read_varint(raw_ln) ||
                    raw_ln == std::numeric_limits<u64>::max()) {
                    return WireResult<V1ChunkDag>{WireCode::Invalid, "invalid SLICE params"};
                }
                dag.nodes.emplace_back(V1SliceNode{child, start, raw_ln + 1ULL});
                break;
            }
            case 6ULL: { // MORPH
                u32 child = 0u;
                u64 mu = 0ULL;
                if (!read_child_ref(br, v, child) || !br.read_bits(2, mu)) {
                    return WireResult<V1ChunkDag>{WireCode::Invalid, "invalid MORPH encoding"};
                }
                dag.nodes.emplace_back(V1MorphNode{child, static_cast<u8>(mu)});
                break;
            }
            case 7ULL: { // XOR_DIFF
                u32 base = 0u;
                u32 delta = 0u;
                if (!read_child_ref(br, v, base) || !read_child_ref(br, v, delta)) {
                    return WireResult<V1ChunkDag>{WireCode::Invalid, "invalid XOR_DIFF child ref"};
                }
                dag.nodes.emplace_back(V1XorDiffNode{base, delta});
                break;
            }
            case 8ULL: { // INTERLEAVE
                u64 sc = 0ULL;
                if (!br.read_bits(2, sc)) {
                    return WireResult<V1ChunkDag>{WireCode::Invalid, "truncated INTERLEAVE stride"};
                }
                const u8 stride = static_cast<u8>(8u << static_cast<unsigned>(sc));
                V1InterleaveNode in;
                in.stride = stride;
                in.lanes.reserve(stride);
                for (u8 j = 0u; j < stride; ++j) {
                    u32 u = 0u;
                    if (!read_child_ref(br, v, u)) {
                        return WireResult<V1ChunkDag>{WireCode::Invalid, "invalid INTERLEAVE lane ref"};
                    }
                    in.lanes.push_back(u);
                }
                dag.nodes.emplace_back(std::move(in));
                break;
            }
            case 9ULL: { // LFSR
                u64 deg_m1 = 0ULL;
                if (!br.read_bits(6, deg_m1)) {
                    return WireResult<V1ChunkDag>{WireCode::Invalid, "truncated LFSR degree"};
                }
                const int deg = static_cast<int>(deg_m1) + 1;
                u64 conn = 0ULL;
                u64 init = 0ULL;
                u64 len = 0ULL;
                if (!br.read_bits(deg, conn) || !br.read_bits(deg, init) ||
                    !br.read_varint(len)) {
                    return WireResult<V1ChunkDag>{WireCode::Invalid, "truncated LFSR params"};
                }
                dag.nodes.emplace_back(V1LfsrNode{static_cast<u8>(deg), conn, init, len});
                break;
            }
            case 10ULL: { // RAW (v1.1 additive; also present in Stage 2 v1.0.1 streams)
                u64 byte_cnt = 0ULL;
                if (!br.read_varint(byte_cnt) || byte_cnt == 0ULL) {
                    return WireResult<V1ChunkDag>{WireCode::Invalid, "invalid RAW byte_cnt"};
                }
                if (byte_cnt > static_cast<u64>(br.unread_whole_bytes())) {
                    return WireResult<V1ChunkDag>{WireCode::Invalid, "truncated RAW literal bytes"};
                }
                V1RawNode rn;
                rn.bytes.resize(static_cast<std::size_t>(byte_cnt));
                for (std::size_t i = 0; i < rn.bytes.size(); ++i) {
                    u64 b = 0ULL;
                    if (!br.read_bits(8, b)) {
                        return WireResult<V1ChunkDag>{WireCode::Invalid, "truncated RAW byte"};
                    }
                    rn.bytes[i] = static_cast<u8>(b);
                }
                if (!br.read_varint(rn.bit_len)) {
                    return WireResult<V1ChunkDag>{WireCode::Invalid, "invalid RAW bit_len"};
                }
                dag.nodes.emplace_back(std::move(rn));
                break;
            }
            case 11ULL: { // DEDUP_REF (v1.1 additive — requires external dedup index)
                u64 ref_id = 0ULL;
                if (!br.read_varint(ref_id)) {
                    return WireResult<V1ChunkDag>{WireCode::Invalid, "truncated DEDUP_REF"};
                }
                saw_dedup_ref = true;
                dag.nodes.emplace_back(V1DedupRefNode{ref_id});
                break;
            }
            case 12ULL: { // DEFLATE_HINT (v1.1 additive — non-evaluable hint node)
                u64 cm = 0ULL, flg = 0ULL, mtime = 0ULL, xfl = 0ULL, os = 0ULL;
                if (!br.read_bits(8, cm) || !br.read_bits(8, flg) ||
                    !br.read_bits(16, mtime) || !br.read_bits(8, xfl) ||
                    !br.read_bits(8, os)) {
                    return WireResult<V1ChunkDag>{WireCode::Invalid, "truncated DEFLATE_HINT"};
                }
                saw_deflate_hint = true;
                dag.nodes.emplace_back(V1DeflateHintNode{
                    static_cast<u8>(cm),
                    static_cast<u8>(flg),
                    static_cast<u16>(mtime),
                    static_cast<u8>(xfl),
                    static_cast<u8>(os)});
                break;
            }
            default: {
                return WireResult<V1ChunkDag>{WireCode::Invalid, "unknown v1 DAG opcode"};
            }
        }
    }

    if (!br.verify_zero_padding()) {
        return WireResult<V1ChunkDag>{
            WireCode::Invalid, "non-zero padding or trailing bytes in MCHK payload"};
    }

    if (saw_dedup_ref) {
        return WireResult<V1ChunkDag>{
            WireCode::Unsupported,
            "v1.1 DEDUP_REF (opcode 11) requires external global dedup index"};
    }
    if (saw_deflate_hint) {
        return WireResult<V1ChunkDag>{
            WireCode::Unsupported,
            "v1.1 DEFLATE_HINT (opcode 12) is non-evaluable without approximation"};
    }

    for (std::size_t v = 0; v < dag.nodes.size(); ++v) {
        const V1DagNode& nd = dag.nodes[v];
        if (std::holds_alternative<V1EmptyNode>(nd)) {
            dag.bit_lengths[v] = 0ULL;
        } else if (const auto* an = std::get_if<V1AtomNode>(&nd)) {
            if (!is_valid_atom(an->atom)) {
                return WireResult<V1ChunkDag>{WireCode::Invalid, "invalid AtomNode"};
            }
            dag.bit_lengths[v] = static_cast<u64>(an->atom.b);
        } else if (const auto* asn = std::get_if<V1AtomSpanNode>(&nd)) {
            if (asn->atoms.empty()) {
                return WireResult<V1ChunkDag>{WireCode::Invalid, "empty AtomSpanNode"};
            }
            u64 sum = 0ULL;
            for (const auto& a : asn->atoms) {
                if (!is_valid_atom(a)) {
                    return WireResult<V1ChunkDag>{WireCode::Invalid, "invalid atom in AtomSpanNode"};
                }
                if (static_cast<u64>(a.b) > max_inter_bits - sum) {
                    return WireResult<V1ChunkDag>{WireCode::Invalid, "AtomSpanNode length overflow"};
                }
                sum += static_cast<u64>(a.b);
            }
            if (sum == 0ULL) {
                return WireResult<V1ChunkDag>{WireCode::Invalid, "zero-length AtomSpanNode"};
            }
            dag.bit_lengths[v] = sum;
        } else if (const auto* cn = std::get_if<V1ConcatNode>(&nd)) {
            if (cn->children.size() < 2u) {
                return WireResult<V1ChunkDag>{WireCode::Invalid, "ConcatNode arity < 2"};
            }
            u64 sum = 0ULL;
            for (u32 u : cn->children) {
                if (u >= v) {
                    return WireResult<V1ChunkDag>{WireCode::Invalid, "ConcatNode topological violation"};
                }
                const u64 cl = dag.bit_lengths[u];
                if (cl > max_inter_bits - sum) {
                    return WireResult<V1ChunkDag>{WireCode::Invalid, "ConcatNode length exceeds cap"};
                }
                sum += cl;
            }
            dag.bit_lengths[v] = sum;
        } else if (const auto* rn = std::get_if<V1RepeatNode>(&nd)) {
            if (rn->child >= v) {
                return WireResult<V1ChunkDag>{WireCode::Invalid, "RepeatNode topological violation"};
            }
            const u64 cl = dag.bit_lengths[rn->child];
            if (cl == 0ULL || rn->q == 0ULL || rn->r >= cl) {
                return WireResult<V1ChunkDag>{WireCode::Invalid, "RepeatNode domain violation"};
            }
            if (rn->r > max_inter_bits || rn->q > (max_inter_bits - rn->r) / cl) {
                return WireResult<V1ChunkDag>{WireCode::Invalid, "RepeatNode length exceeds cap"};
            }
            dag.bit_lengths[v] = rn->q * cl + rn->r;
        } else if (const auto* sn = std::get_if<V1SliceNode>(&nd)) {
            if (sn->child >= v) {
                return WireResult<V1ChunkDag>{WireCode::Invalid, "SliceNode topological violation"};
            }
            const u64 cl = dag.bit_lengths[sn->child];
            if (sn->length == 0ULL || sn->start > cl || sn->length > cl - sn->start) {
                return WireResult<V1ChunkDag>{WireCode::Invalid, "SliceNode out of bounds"};
            }
            dag.bit_lengths[v] = sn->length;
        } else if (const auto* mn = std::get_if<V1MorphNode>(&nd)) {
            if (mn->child >= v || mn->mu > 3u) {
                return WireResult<V1ChunkDag>{WireCode::Invalid, "MorphNode invalid"};
            }
            const u64 cl = dag.bit_lengths[mn->child];
            if (cl == 0ULL) {
                return WireResult<V1ChunkDag>{WireCode::Invalid, "MorphNode on empty child"};
            }
            dag.bit_lengths[v] = cl;
        } else if (const auto* xn = std::get_if<V1XorDiffNode>(&nd)) {
            if (xn->base >= v || xn->delta >= v) {
                return WireResult<V1ChunkDag>{WireCode::Invalid, "XorDiffNode topological violation"};
            }
            const u64 bl = dag.bit_lengths[xn->base];
            if (bl == 0ULL || bl != dag.bit_lengths[xn->delta]) {
                return WireResult<V1ChunkDag>{WireCode::Invalid, "XorDiffNode length mismatch"};
            }
            dag.bit_lengths[v] = bl;
        } else if (const auto* in = std::get_if<V1InterleaveNode>(&nd)) {
            if (!(in->stride == 8u || in->stride == 16u ||
                  in->stride == 32u || in->stride == 64u) ||
                in->lanes.size() != static_cast<std::size_t>(in->stride)) {
                return WireResult<V1ChunkDag>{WireCode::Invalid, "InterleaveNode invalid stride"};
            }
            if (in->lanes[0] >= v) {
                return WireResult<V1ChunkDag>{WireCode::Invalid, "InterleaveNode topological violation"};
            }
            const u64 l0 = dag.bit_lengths[in->lanes[0]];
            if (l0 == 0ULL) {
                return WireResult<V1ChunkDag>{WireCode::Invalid, "InterleaveNode empty lane"};
            }
            for (u32 u : in->lanes) {
                if (u >= v || dag.bit_lengths[u] != l0) {
                    return WireResult<V1ChunkDag>{WireCode::Invalid, "InterleaveNode lane mismatch"};
                }
            }
            if (l0 > max_inter_bits / static_cast<u64>(in->stride)) {
                return WireResult<V1ChunkDag>{WireCode::Invalid, "InterleaveNode length exceeds cap"};
            }
            dag.bit_lengths[v] = static_cast<u64>(in->stride) * l0;
        } else if (const auto* ln = std::get_if<V1LfsrNode>(&nd)) {
            if (ln->degree < 1u || ln->degree > 64u || ln->conn_mask == 0ULL) {
                return WireResult<V1ChunkDag>{WireCode::Invalid, "LfsrNode invalid degree/conn"};
            }
            if (ln->degree < 64u) {
                const u64 mask = (1ULL << ln->degree) - 1ULL;
                if ((ln->conn_mask & ~mask) != 0ULL || (ln->init_mask & ~mask) != 0ULL) {
                    return WireResult<V1ChunkDag>{WireCode::Invalid, "LfsrNode mask out of degree"};
                }
            }
            if (ln->length < 2ULL * static_cast<u64>(ln->degree) + 1ULL ||
                ln->length > max_inter_bits) {
                return WireResult<V1ChunkDag>{WireCode::Invalid, "LfsrNode length out of bounds"};
            }
            dag.bit_lengths[v] = ln->length;
        } else if (const auto* rwn = std::get_if<V1RawNode>(&nd)) {
            if (rwn->bit_len == 0ULL || rwn->bit_len > max_inter_bits) {
                return WireResult<V1ChunkDag>{WireCode::Invalid, "RawNode invalid bit_len"};
            }
            const u64 min_bytes = (rwn->bit_len + 7ULL) >> 3;
            if (static_cast<u64>(rwn->bytes.size()) < min_bytes) {
                return WireResult<V1ChunkDag>{WireCode::Invalid, "RawNode bytes shorter than bit_len"};
            }
            dag.bit_lengths[v] = rwn->bit_len;
        } else {
            return WireResult<V1ChunkDag>{WireCode::Unsupported, "unsupported v1 DAG node"};
        }
    }

    if (dag.bit_lengths[dag.root] != expected_bit_len) {
        return WireResult<V1ChunkDag>{
            WireCode::Invalid, "DAG root bit length disagrees with MCHK bit_len"};
    }
    return dag;
}

[[nodiscard]] V1BitSeq eval_v1_lfsr(const V1LfsrNode& ln) {
    V1BitSeq out(ln.length);
    const int deg = static_cast<int>(ln.degree);
    const u64 mask = (deg == 64) ? ~0ULL : ((1ULL << deg) - 1ULL);
    u64 state = 0ULL;
    for (int i = 0; i < deg; ++i) {
        const bool bit = ((ln.init_mask >> static_cast<unsigned>(i)) & 1ULL) != 0ULL;
        if (bit) out.set_bit(static_cast<u64>(i));
        state = ((state << 1) | (bit ? 1ULL : 0ULL)) & mask;
    }
    for (u64 t = static_cast<u64>(deg); t < ln.length; ++t) {
        const u64 fb = static_cast<u64>(std::popcount(state & ln.conn_mask) & 1);
        if (fb != 0ULL) out.set_bit(t);
        state = ((state << 1) | fb) & mask;
    }
    return out;
}

[[nodiscard]] V1BitSeq eval_v1_interleave(
    u8 stride,
    const std::vector<u32>& lanes,
    const std::vector<V1BitSeq>& vals) {
    const u64 lane_len = vals[lanes[0]].bit_len();
    const u64 total = static_cast<u64>(stride) * lane_len;
    V1BitSeq out(total);
    for (u64 k = 0ULL; k < lane_len; ++k) {
        const u64 base = k * static_cast<u64>(stride);
        for (u8 j = 0u; j < stride; ++j) {
            if (vals[lanes[j]].get_bit(k)) {
                out.set_bit(base + static_cast<u64>(j));
            }
        }
    }
    return out;
}

[[nodiscard]] WireResult<u32> map_e2_result(const Result<u32>& r, const char* ctx) {
    if (r.ok()) return r.value();
    const WireCode wc = (r.code() == Code::Limit) ? WireCode::Limit : WireCode::Invalid;
    return WireResult<u32>{wc, ctx};
}

[[nodiscard]] WireResult<u32> emit_bytes_term(Dag& dag, std::span<const u8> bytes) {
    if (bytes.empty()) {
        Node n{};
        n.kind = Kind::Empty;
        return map_e2_result(dag.add_node(std::move(n)), "Dag::add_node(Empty)");
    }

    bool all_zero = true;
    for (u8 b : bytes) {
        if (b != 0u) {
            all_zero = false;
            break;
        }
    }
    if (all_zero) {
        Node n{};
        n.kind = Kind::Zero;
        n.a = mapr::BigInt(static_cast<u64>(bytes.size()));
        return map_e2_result(dag.add_node(std::move(n)), "Dag::add_node(Zero)");
    }

    if (bytes.size() <= static_cast<std::size_t>(kAtomMax)) {
        const auto atom_id = dag.add_atom(bytes, 0u);
        if (!atom_id.ok()) {
            const WireCode wc =
                (atom_id.code() == Code::Limit) ? WireCode::Limit : WireCode::Invalid;
            return WireResult<u32>{wc, "Dag::add_atom"};
        }
        Node n{};
        n.kind = Kind::Atom;
        n.a = mapr::BigInt(static_cast<u64>(atom_id.value()));
        return map_e2_result(dag.add_node(std::move(n)), "Dag::add_node(Atom)");
    }

    std::vector<u32> parts;
    parts.reserve((bytes.size() + static_cast<std::size_t>(kAtomMax) - 1u) /
                  static_cast<std::size_t>(kAtomMax));
    std::size_t pos = 0;
    while (pos < bytes.size()) {
        const std::size_t take =
            std::min<std::size_t>(bytes.size() - pos, static_cast<std::size_t>(kAtomMax));
        auto sub = emit_bytes_term(dag, bytes.subspan(pos, take));
        if (!sub.ok()) return sub;
        parts.push_back(sub.value());
        pos += take;
    }

    Node cn{};
    cn.kind = Kind::Concat;
    cn.args = std::move(parts);
    return map_e2_result(dag.add_node(std::move(cn)), "Dag::add_node(Concat-atoms)");
}

[[nodiscard]] WireResult<u32> emit_v4_morph(Dag& dag, u32 child_id, u8 v4_op) {
    switch (v4_op) {
        case 0u:
            return child_id;
        case 1u: {
            Node m{};
            m.kind = Kind::Morph;
            m.args = {child_id};
            m.morph = kV2MorphInvert8;
            m.morph_k = 0u;
            return map_e2_result(dag.add_node(std::move(m)), "Dag::add_node(Morph Invert8)");
        }
        case 2u: {
            Node m{};
            m.kind = Kind::Morph;
            m.args = {child_id};
            m.morph = kV2MorphReverseBits;
            m.morph_k = 0u;
            return map_e2_result(dag.add_node(std::move(m)), "Dag::add_node(Morph ReverseBits)");
        }
        case 3u: {
            Node rev{};
            rev.kind = Kind::Morph;
            rev.args = {child_id};
            rev.morph = kV2MorphReverseBits;
            rev.morph_k = 0u;
            auto rev_id = map_e2_result(dag.add_node(std::move(rev)), "Dag::add_node(Morph Rev)");
            if (!rev_id.ok()) return rev_id;
            Node inv{};
            inv.kind = Kind::Morph;
            inv.args = {rev_id.value()};
            inv.morph = kV2MorphInvert8;
            inv.morph_k = 0u;
            return map_e2_result(dag.add_node(std::move(inv)), "Dag::add_node(Morph Inv)");
        }
        default:
            return WireResult<u32>{WireCode::Invalid, "invalid V4Op"};
    }
}

[[nodiscard]] bool try_lift_v1_lfsr_to_v2(
    const V1LfsrNode& ln,
    std::span<const u8> expected_bytes,
    u64& out_conn64,
    u64& out_init64) noexcept {
    const int deg = static_cast<int>(ln.degree);
    if (deg < 1 || deg > 64 || ln.conn_mask == 0ULL) return false;
    if (((ln.conn_mask >> static_cast<unsigned>(deg - 1)) & 1ULL) == 0ULL) {
        return false;
    }

    u64 conn64 = 0ULL;
    for (int m = 0; m < deg; ++m) {
        if (((ln.conn_mask >> static_cast<unsigned>(m)) & 1ULL) != 0ULL) {
            conn64 |= (1ULL << static_cast<unsigned>(63 - m));
        }
    }
    if (conn64 == 0ULL) return false;

    u64 init64 = 0ULL;
    for (int t = deg - 1; t >= 0; --t) {
        u64 s_t = 0ULL;
        for (int m = 0; m < t; ++m) {
            const u64 y_prev =
                (ln.init_mask >> static_cast<unsigned>(t - 1 - m)) & 1ULL;
            s_t |= (y_prev << static_cast<unsigned>(63 - m));
        }
        for (int m = t; m < deg - 1; ++m) {
            const u64 x_known =
                (init64 >> static_cast<unsigned>(63 - (m - t))) & 1ULL;
            s_t |= (x_known << static_cast<unsigned>(63 - m));
        }
        const u64 partial_parity = static_cast<u64>(std::popcount(s_t & conn64) & 1);
        const u64 want_y = (ln.init_mask >> static_cast<unsigned>(t)) & 1ULL;
        const u64 x_bit = want_y ^ partial_parity;
        init64 |= (x_bit << static_cast<unsigned>(64 - deg + t));
    }

    LfsrStream stream(conn64, init64);
    for (u8 want : expected_bytes) {
        if (stream.next_byte() != want) return false;
    }
    out_conn64 = conn64;
    out_init64 = init64;
    return true;
}

struct ChunkEvalResult {
    V1BitSeq root_bits{};
    u32 v2_node_id = 0u;
    bool has_v2_node = false;
};

[[nodiscard]] WireResult<ChunkEvalResult> eval_and_lift_chunk_dag(
    const V1ChunkDag& cdag,
    bool build_v2_term,
    Dag& v2_dag,
    u64& live_working_bytes,
    const LegacyLimits& limits) {
    const std::size_t m = cdag.nodes.size();
    const u32 root = cdag.root;

    std::vector<u8> reach(m, 0u);
    reach[root] = 1u;
    for (std::size_t idx = static_cast<std::size_t>(root) + 1u; idx-- > 0;) {
        if (reach[idx] == 0u) continue;
        const V1DagNode& nd = cdag.nodes[idx];
        if (const auto* cn = std::get_if<V1ConcatNode>(&nd)) {
            for (u32 u : cn->children) reach[u] = 1u;
        } else if (const auto* rn = std::get_if<V1RepeatNode>(&nd)) {
            reach[rn->child] = 1u;
        } else if (const auto* sn = std::get_if<V1SliceNode>(&nd)) {
            reach[sn->child] = 1u;
        } else if (const auto* mn = std::get_if<V1MorphNode>(&nd)) {
            reach[mn->child] = 1u;
        } else if (const auto* xn = std::get_if<V1XorDiffNode>(&nd)) {
            reach[xn->base] = 1u;
            reach[xn->delta] = 1u;
        } else if (const auto* in = std::get_if<V1InterleaveNode>(&nd)) {
            for (u32 u : in->lanes) reach[u] = 1u;
        }
    }

    std::vector<u8> struct_needed(m, 0u);
    if (build_v2_term && (cdag.bit_lengths[root] & 7ULL) == 0ULL) {
        struct_needed[root] = 1u;
        for (std::size_t idx = static_cast<std::size_t>(root) + 1u; idx-- > 0;) {
            if (struct_needed[idx] == 0u) continue;
            const V1DagNode& nd = cdag.nodes[idx];
            if (const auto* cn = std::get_if<V1ConcatNode>(&nd)) {
                u64 cum = 0ULL;
                for (u32 u : cn->children) {
                    const u64 cl = cdag.bit_lengths[u];
                    if ((cum & 7ULL) == 0ULL && (cl & 7ULL) == 0ULL) {
                        struct_needed[u] = 1u;
                    }
                    cum += cl;
                }
            } else if (const auto* rn = std::get_if<V1RepeatNode>(&nd)) {
                if ((cdag.bit_lengths[rn->child] & 7ULL) == 0ULL && (rn->r & 7ULL) == 0ULL) {
                    struct_needed[rn->child] = 1u;
                }
            } else if (const auto* sn = std::get_if<V1SliceNode>(&nd)) {
                if ((cdag.bit_lengths[sn->child] & 7ULL) == 0ULL &&
                    (sn->start & 7ULL) == 0ULL &&
                    (sn->length & 7ULL) == 0ULL) {
                    struct_needed[sn->child] = 1u;
                }
            } else if (const auto* mn = std::get_if<V1MorphNode>(&nd)) {
                struct_needed[mn->child] = 1u;
            } else if (const auto* xn = std::get_if<V1XorDiffNode>(&nd)) {
                struct_needed[xn->base] = 1u;
                struct_needed[xn->delta] = 1u;
            }
        }
    }

    std::vector<u32> rem_uses(m, 0u);
    rem_uses[root] = 1u;
    for (std::size_t v = 0; v <= static_cast<std::size_t>(root); ++v) {
        if (reach[v] == 0u) continue;
        const V1DagNode& nd = cdag.nodes[v];
        if (const auto* cn = std::get_if<V1ConcatNode>(&nd)) {
            for (u32 u : cn->children) ++rem_uses[u];
        } else if (const auto* rn = std::get_if<V1RepeatNode>(&nd)) {
            ++rem_uses[rn->child];
        } else if (const auto* sn = std::get_if<V1SliceNode>(&nd)) {
            ++rem_uses[sn->child];
        } else if (const auto* mn = std::get_if<V1MorphNode>(&nd)) {
            ++rem_uses[mn->child];
        } else if (const auto* xn = std::get_if<V1XorDiffNode>(&nd)) {
            ++rem_uses[xn->base];
            ++rem_uses[xn->delta];
        } else if (const auto* in = std::get_if<V1InterleaveNode>(&nd)) {
            for (u32 u : in->lanes) ++rem_uses[u];
        }
    }

    std::vector<V1BitSeq> vals(m);
    std::vector<u32> v2_ids(m, 0u);

    auto release_child = [&](u32 u) noexcept {
        if (rem_uses[u] > 0u) {
            --rem_uses[u];
            if (rem_uses[u] == 0u) {
                const u64 freed = static_cast<u64>(vals[u].storage_bytes());
                live_working_bytes =
                    (freed <= live_working_bytes) ? (live_working_bytes - freed) : 0ULL;
                vals[u].clear_memory();
            }
        }
    };

    for (std::size_t v = 0; v <= static_cast<std::size_t>(root); ++v) {
        if (reach[v] == 0u) continue;

        const u64 need_words_bytes = ((cdag.bit_lengths[v] + 63ULL) >> 6) * sizeof(u64);
        if (need_words_bytes > limits.max_eval_working_bytes ||
            live_working_bytes > limits.max_eval_working_bytes - need_words_bytes) {
            return WireResult<ChunkEvalResult>{
                WireCode::Limit, "chunk DAG working memory exceeds LegacyLimits"};
        }

        const V1DagNode& nd = cdag.nodes[v];
        if (std::holds_alternative<V1EmptyNode>(nd)) {
            vals[v] = V1BitSeq{};
        } else if (const auto* an = std::get_if<V1AtomNode>(&nd)) {
            vals[v] = V1BitSeq::from_word(eval_atom_word(an->atom), static_cast<int>(an->atom.b));
        } else if (const auto* asn = std::get_if<V1AtomSpanNode>(&nd)) {
            V1BitSeq seq;
            seq.reserve_bits(cdag.bit_lengths[v]);
            for (const auto& a : asn->atoms) {
                seq.append(V1BitSeq::from_word(eval_atom_word(a), static_cast<int>(a.b)));
            }
            vals[v] = std::move(seq);
        } else if (const auto* cn = std::get_if<V1ConcatNode>(&nd)) {
            V1BitSeq seq;
            seq.reserve_bits(cdag.bit_lengths[v]);
            for (u32 u : cn->children) {
                seq.append(vals[u]);
            }
            vals[v] = std::move(seq);
        } else if (const auto* rn = std::get_if<V1RepeatNode>(&nd)) {
            vals[v] = V1BitSeq::repeat_seq(vals[rn->child], rn->q, rn->r);
        } else if (const auto* sn = std::get_if<V1SliceNode>(&nd)) {
            vals[v] = vals[sn->child].slice(sn->start, sn->length);
        } else if (const auto* mn = std::get_if<V1MorphNode>(&nd)) {
            vals[v] = vals[mn->child].apply_v4(mn->mu);
        } else if (const auto* xn = std::get_if<V1XorDiffNode>(&nd)) {
            vals[v] = vals[xn->base].bitwise_xor(vals[xn->delta]);
        } else if (const auto* in = std::get_if<V1InterleaveNode>(&nd)) {
            vals[v] = eval_v1_interleave(in->stride, in->lanes, vals);
        } else if (const auto* ln = std::get_if<V1LfsrNode>(&nd)) {
            vals[v] = eval_v1_lfsr(*ln);
        } else if (const auto* rwn = std::get_if<V1RawNode>(&nd)) {
            vals[v] = V1BitSeq::from_bytes_msb_sliced(rwn->bytes, rwn->bit_len);
        }

        live_working_bytes += static_cast<u64>(vals[v].storage_bytes());

        if (struct_needed[v] != 0u) {
            const u64 bit_len = cdag.bit_lengths[v];
            const u64 byte_len = bit_len >> 3;
            WireResult<u32> built{WireCode::Invalid, "uninitialized"};

            if (byte_len == 0ULL) {
                Node e{};
                e.kind = Kind::Empty;
                built = map_e2_result(v2_dag.add_node(std::move(e)), "Dag::add_node(Empty)");
            } else if (vals[v].is_all_zeros()) {
                Node z{};
                z.kind = Kind::Zero;
                z.a = mapr::BigInt(byte_len);
                built = map_e2_result(v2_dag.add_node(std::move(z)), "Dag::add_node(Zero)");
            } else if (const auto* cn = std::get_if<V1ConcatNode>(&nd)) {
                std::vector<u32> seg_ids;
                std::size_t i = 0;
                u64 cum = 0ULL;
                while (i < cn->children.size()) {
                    const u32 u = cn->children[i];
                    const u64 cl = cdag.bit_lengths[u];
                    if ((cum & 7ULL) == 0ULL && (cl & 7ULL) == 0ULL) {
                        if (cl > 0ULL) {
                            seg_ids.push_back(v2_ids[u]);
                        }
                        cum += cl;
                        ++i;
                    } else {
                        V1BitSeq grp;
                        do {
                            const u32 gu = cn->children[i];
                            grp.append(vals[gu]);
                            cum += cdag.bit_lengths[gu];
                            ++i;
                        } while (i < cn->children.size() && (cum & 7ULL) != 0ULL);
                        const std::vector<u8> grp_bytes = grp.to_bytes_msb();
                        auto gid = emit_bytes_term(v2_dag, grp_bytes);
                        if (!gid.ok()) return gid.error();
                        if (!grp_bytes.empty()) {
                            seg_ids.push_back(gid.value());
                        }
                    }
                }
                if (seg_ids.empty()) {
                    Node e{};
                    e.kind = Kind::Empty;
                    built = map_e2_result(v2_dag.add_node(std::move(e)), "Dag::add_node(Empty)");
                } else if (seg_ids.size() == 1u) {
                    built = seg_ids[0];
                } else {
                    Node cat{};
                    cat.kind = Kind::Concat;
                    cat.args = std::move(seg_ids);
                    built = map_e2_result(v2_dag.add_node(std::move(cat)), "Dag::add_node(Concat)");
                }
            } else if (const auto* rn = std::get_if<V1RepeatNode>(&nd)) {
                const u64 cl = cdag.bit_lengths[rn->child];
                if ((cl & 7ULL) == 0ULL && (rn->r & 7ULL) == 0ULL) {
                    Node rep{};
                    rep.kind = Kind::Repeat;
                    rep.args = {v2_ids[rn->child]};
                    rep.a = mapr::BigInt(rn->q);
                    rep.b = mapr::BigInt(rn->r >> 3);
                    built = map_e2_result(v2_dag.add_node(std::move(rep)), "Dag::add_node(Repeat)");
                } else {
                    const u64 g = std::gcd(cl, 8ULL);
                    const u64 p_bytes = cl / g;
                    if (byte_len > p_bytes) {
                        const u64 reps_for_tile = 8ULL / g;
                        const V1BitSeq tile_bits =
                            V1BitSeq::repeat_seq(vals[rn->child], reps_for_tile, 0ULL);
                        const std::vector<u8> tile_bytes = tile_bits.to_bytes_msb();
                        auto tile_id = emit_bytes_term(v2_dag, tile_bytes);
                        if (!tile_id.ok()) return tile_id.error();
                        Node rep{};
                        rep.kind = Kind::Repeat;
                        rep.args = {tile_id.value()};
                        rep.a = mapr::BigInt(byte_len / p_bytes);
                        rep.b = mapr::BigInt(byte_len % p_bytes);
                        built = map_e2_result(v2_dag.add_node(std::move(rep)), "Dag::add_node(Repeat tile)");
                    } else {
                        const std::vector<u8> raw_bytes = vals[v].to_bytes_msb();
                        built = emit_bytes_term(v2_dag, raw_bytes);
                    }
                }
            } else if (const auto* sn = std::get_if<V1SliceNode>(&nd)) {
                if ((cdag.bit_lengths[sn->child] & 7ULL) == 0ULL &&
                    (sn->start & 7ULL) == 0ULL &&
                    (sn->length & 7ULL) == 0ULL) {
                    Node sl{};
                    sl.kind = Kind::Slice;
                    sl.args = {v2_ids[sn->child]};
                    sl.a = mapr::BigInt(sn->start >> 3);
                    sl.b = mapr::BigInt(sn->length >> 3);
                    built = map_e2_result(v2_dag.add_node(std::move(sl)), "Dag::add_node(Slice)");
                } else {
                    const std::vector<u8> raw_bytes = vals[v].to_bytes_msb();
                    built = emit_bytes_term(v2_dag, raw_bytes);
                }
            } else if (const auto* mn = std::get_if<V1MorphNode>(&nd)) {
                built = emit_v4_morph(v2_dag, v2_ids[mn->child], mn->mu);
            } else if (const auto* xn = std::get_if<V1XorDiffNode>(&nd)) {
                Node xr{};
                xr.kind = Kind::Xor;
                xr.args = {v2_ids[xn->base], v2_ids[xn->delta]};
                built = map_e2_result(v2_dag.add_node(std::move(xr)), "Dag::add_node(Xor)");
            } else if (const auto* ln = std::get_if<V1LfsrNode>(&nd)) {
                const std::vector<u8> raw_bytes = vals[v].to_bytes_msb();
                u64 conn64 = 0ULL;
                u64 init64 = 0ULL;
                if (try_lift_v1_lfsr_to_v2(*ln, raw_bytes, conn64, init64)) {
                    Node lf{};
                    lf.kind = Kind::Lfsr;
                    lf.lfsr_conn = conn64;
                    lf.lfsr_init = init64;
                    lf.a = mapr::BigInt(byte_len);
                    built = map_e2_result(v2_dag.add_node(std::move(lf)), "Dag::add_node(Lfsr)");
                } else {
                    built = emit_bytes_term(v2_dag, raw_bytes);
                }
            } else {
                const std::vector<u8> raw_bytes = vals[v].to_bytes_msb();
                built = emit_bytes_term(v2_dag, raw_bytes);
            }

            if (!built.ok()) return built.error();
            v2_ids[v] = built.value();
        }

        if (const auto* cn = std::get_if<V1ConcatNode>(&nd)) {
            for (u32 u : cn->children) release_child(u);
        } else if (const auto* rn = std::get_if<V1RepeatNode>(&nd)) {
            release_child(rn->child);
        } else if (const auto* sn = std::get_if<V1SliceNode>(&nd)) {
            release_child(sn->child);
        } else if (const auto* mn = std::get_if<V1MorphNode>(&nd)) {
            release_child(mn->child);
        } else if (const auto* xn = std::get_if<V1XorDiffNode>(&nd)) {
            release_child(xn->base);
            release_child(xn->delta);
        } else if (const auto* in = std::get_if<V1InterleaveNode>(&nd)) {
            for (u32 u : in->lanes) release_child(u);
        }
    }

    const u64 root_bytes = static_cast<u64>(vals[root].storage_bytes());
    live_working_bytes =
        (root_bytes <= live_working_bytes) ? (live_working_bytes - root_bytes) : 0ULL;

    ChunkEvalResult res;
    res.root_bits = std::move(vals[root]);
    res.v2_node_id = v2_ids[root];
    res.has_v2_node = (struct_needed[root] != 0u);
    return res;
}

struct V1IndexEntry {
    u64 file_offset = 0ULL;
    u64 bit_offset  = 0ULL;
    u32 bit_len     = 0u;
    u32 frame_bytes = 0u;
    u32 ref_target  = 0u;
    u8  chunk_kind  = 0u;
    u8  v4_op       = 0u;
};

struct StreamByteAssembler {
    std::vector<u8> bytes{};
    u64 carry_acc = 0ULL;
    int carry_bits = 0;

    void append_seq(const V1BitSeq& seq) {
        const u64 n = seq.bit_len();
        if (n == 0ULL) return;
        const std::size_t full_words = static_cast<std::size_t>(n >> 6);
        const int tail_bits = static_cast<int>(n & 63ULL);

        for (std::size_t wi = 0; wi < full_words; ++wi) {
            const u64 w = seq.word(wi);
            for (int bi = 0; bi < 8; ++bi) {
                const u64 mb =
                    static_cast<u64>(bitrev8(static_cast<u8>((w >> (bi * 8)) & 0xFFULL)));
                carry_acc = (carry_acc << 8) | mb;
                carry_bits += 8;
                while (carry_bits >= 8) {
                    carry_bits -= 8;
                    bytes.push_back(
                        static_cast<u8>((carry_acc >> static_cast<unsigned>(carry_bits)) & 0xFFULL));
                }
            }
        }

        if (tail_bits > 0) {
            const u64 tw = seq.word(full_words);
            for (int b = 0; b < tail_bits; ++b) {
                const u64 bit = (tw >> static_cast<unsigned>(b)) & 1ULL;
                carry_acc = (carry_acc << 1) | bit;
                ++carry_bits;
                if (carry_bits == 8) {
                    carry_bits = 0;
                    bytes.push_back(static_cast<u8>(carry_acc & 0xFFULL));
                }
            }
        }
    }

    [[nodiscard]] std::vector<u8> finish_msb_padded() const {
        std::vector<u8> out = bytes;
        if (carry_bits > 0) {
            const u8 last = static_cast<u8>(
                (carry_acc << static_cast<unsigned>(8 - carry_bits)) & 0xFFULL);
            out.push_back(last);
        }
        return out;
    }
};

[[nodiscard]] WireResult<Ir> decode_v1_impl(
    Source& src,
    Arena* arena,
    const LegacyLimits& limits) {
    const u64 file_size = src.size();

    // Probe readability on short sources so I/O failures surface as WireCode::Io.
    if (file_size < 192ULL) {
        std::array<u8, 64> probe{};
        const std::size_t n = static_cast<std::size_t>(std::min<u64>(file_size, 64ULL));
        const WireCode rc = src.read(0ULL, std::span<u8>(probe.data(), n));
        if (rc == WireCode::Io) {
            return WireResult<Ir>{WireCode::Io, "source read failure"};
        }
        return WireResult<Ir>{WireCode::Invalid, "truncated v1 container (< 192 bytes)"};
    }

    // 1. Read & verify 64-byte File Header (SPECS.md §2.1, container.cpp).
    std::array<u8, 64> hdr{};
    {
        const WireCode rc = src.read(0ULL, hdr);
        if (rc != WireCode::Ok) {
            return WireResult<Ir>{rc, "failed reading v1 header"};
        }
    }
    if (std::memcmp(hdr.data(), kV1Magic.data(), 8) != 0) {
        return WireResult<Ir>{WireCode::Invalid, "v1 header magic mismatch"};
    }
    const u32 hdr_crc_want = read_le32(hdr.data() + 60);
    const u32 hdr_crc_got  = crc32_span(std::span<const u8>(hdr.data(), 60));
    if (hdr_crc_got != hdr_crc_want) {
        return WireResult<Ir>{WireCode::Invalid, "v1 header CRC-32 mismatch"};
    }

    const u16 ver_major = read_le16(hdr.data() + 8);
    const u16 ver_minor = read_le16(hdr.data() + 10);
    if (ver_major == 0u) {
        return WireResult<Ir>{WireCode::Invalid, "invalid v1 version 0.x"};
    }
    if (ver_major != 1u || ver_minor > 1u) {
        return WireResult<Ir>{
            WireCode::Unsupported,
            "unsupported legacy container version " +
                std::to_string(ver_major) + "." + std::to_string(ver_minor)};
    }

    const u32 flags = read_le32(hdr.data() + 12);
    if ((flags & ~kKnownHeaderFlags) != 0u) {
        return WireResult<Ir>{WireCode::Invalid, "unknown v1 header flags"};
    }
    if ((flags & kFlagHasIndex) == 0u) {
        return WireResult<Ir>{WireCode::Invalid, "FLAG_HAS_INDEX must be set in v1"};
    }

    const u64 hdr_total_bits  = read_le64(hdr.data() + 16);
    const u64 hdr_chunk_count = read_le64(hdr.data() + 24);
    const u32 cfg_w_sync      = read_le32(hdr.data() + 32);
    const u32 cfg_l_min       = read_le32(hdr.data() + 36);
    const u32 cfg_l_target    = read_le32(hdr.data() + 40);
    const u32 cfg_l_max       = read_le32(hdr.data() + 44);
    const u32 cfg_w_hist      = read_le32(hdr.data() + 48);
    const u64 hdr_index_off   = read_le64(hdr.data() + 52);

    if (cfg_w_sync != kNormativeWSync ||
        cfg_l_min == 0u ||
        cfg_l_min > cfg_l_target ||
        cfg_l_target > cfg_l_max ||
        cfg_l_max > kNormativeLMax ||
        cfg_w_hist > kNormativeWHist) {
        return WireResult<Ir>{WireCode::Invalid, "invalid v1 StreamConfig"};
    }

    // 2. Read & verify 72-byte Trailer at EOF - 72 (SPECS.md §2.1).
    const u64 body_limit = file_size - 72ULL;
    std::array<u8, 72> trlr{};
    {
        const WireCode rc = src.read(body_limit, trlr);
        if (rc != WireCode::Ok) {
            return WireResult<Ir>{rc, "failed reading v1 trailer"};
        }
    }
    if (std::memcmp(trlr.data(), "TRLR", 4) != 0 ||
        std::memcmp(trlr.data() + 64, "ENDM", 4) != 0) {
        return WireResult<Ir>{WireCode::Invalid, "invalid v1 trailer magic/sentinel"};
    }
    const u32 trlr_crc_want = read_le32(trlr.data() + 68);
    const u32 trlr_crc_got  = crc32_span(std::span<const u8>(trlr.data(), 68));
    if (trlr_crc_got != trlr_crc_want) {
        return WireResult<Ir>{WireCode::Invalid, "v1 trailer CRC-32 mismatch"};
    }
    if (read_le32(trlr.data() + 4) != 1u) {
        return WireResult<Ir>{WireCode::Invalid, "v1 trailer_flags must equal 1"};
    }

    const u64 total_bits   = read_le64(trlr.data() + 8);
    const u64 chunk_count  = read_le64(trlr.data() + 16);
    const u64 index_offset = read_le64(trlr.data() + 24);
    Digest256 expected_sha{};
    std::memcpy(expected_sha.data(), trlr.data() + 32, 32);

    if ((flags & kFlagStreamedHeader) == 0u) {
        if (hdr_total_bits != total_bits ||
            hdr_chunk_count != chunk_count ||
            hdr_index_off != index_offset) {
            return WireResult<Ir>{WireCode::Invalid, "v1 header/trailer mismatch"};
        }
    } else {
        if ((hdr_total_bits != 0ULL && hdr_total_bits != total_bits) ||
            (hdr_chunk_count != 0ULL && hdr_chunk_count != chunk_count) ||
            (hdr_index_off != 0ULL && hdr_index_off != index_offset)) {
            return WireResult<Ir>{WireCode::Invalid, "contradictory streamed v1 header"};
        }
    }

    if ((flags & kFlagRawBytesMsb) != 0u && (total_bits & 7ULL) != 0ULL) {
        return WireResult<Ir>{
            WireCode::Invalid, "FLAG_RAW_BYTES_MSB set on non-byte-aligned total_bits"};
    }
    if (chunk_count == 0ULL || chunk_count > static_cast<u64>(std::numeric_limits<u32>::max())) {
        return WireResult<Ir>{WireCode::Invalid, "invalid v1 chunk_count"};
    }

    // 3. Validate INDX framing before any allocation (E3-I4, E3 §5.2 truncation -> Invalid).
    if (index_offset < 64ULL || index_offset > body_limit ||
        body_limit - index_offset < 20ULL) {
        return WireResult<Ir>{WireCode::Invalid, "invalid v1 INDX offset"};
    }
    const u64 avail_for_entries = body_limit - index_offset - 20ULL;
    if ((avail_for_entries & 31ULL) != 0ULL || (avail_for_entries >> 5) != chunk_count) {
        return WireResult<Ir>{WireCode::Invalid, "v1 INDX byte span disagrees with chunk_count"};
    }
    if (chunk_count > limits.max_chunks) {
        return WireResult<Ir>{WireCode::Limit, "v1 chunk_count exceeds LegacyLimits::max_chunks"};
    }

    const std::size_t indx_bytes_len = static_cast<std::size_t>(body_limit - index_offset);
    std::vector<u8> indx_buf(indx_bytes_len);
    {
        const WireCode rc = src.read(index_offset, indx_buf);
        if (rc != WireCode::Ok) {
            return WireResult<Ir>{rc, "failed reading v1 INDX"};
        }
    }
    if (std::memcmp(indx_buf.data(), "INDX", 4) != 0 ||
        read_le32(indx_buf.data() + 4) != 32u ||
        read_le64(indx_buf.data() + 8) != chunk_count) {
        return WireResult<Ir>{WireCode::Invalid, "invalid v1 INDX header"};
    }
    const u32 indx_crc_want = read_le32(indx_buf.data() + indx_bytes_len - 4u);
    const u32 indx_crc_got  = crc32_span(
        std::span<const u8>(indx_buf.data(), indx_bytes_len - 4u));
    if (indx_crc_got != indx_crc_want) {
        return WireResult<Ir>{WireCode::Invalid, "v1 INDX CRC-32 mismatch"};
    }

    std::vector<V1IndexEntry> index(static_cast<std::size_t>(chunk_count));
    std::vector<u32> chunk_ref_rem_uses(static_cast<std::size_t>(chunk_count), 0u);
    u64 run_file_off = 64ULL;
    u64 run_bit_off  = 0ULL;

    for (u64 c = 0ULL; c < chunk_count; ++c) {
        const u8* eb = indx_buf.data() + 16u + static_cast<std::size_t>(c) * 32u;
        if (read_le16(eb + 30) != 0u) {
            return WireResult<Ir>{WireCode::Invalid, "non-zero reserved field in v1 INDX"};
        }
        V1IndexEntry e{};
        e.file_offset = read_le64(eb + 0);
        e.bit_offset  = read_le64(eb + 8);
        e.bit_len     = read_le32(eb + 16);
        e.frame_bytes = read_le32(eb + 20);
        e.ref_target  = read_le32(eb + 24);
        e.chunk_kind  = eb[28];
        e.v4_op       = eb[29];

        if (e.file_offset != run_file_off || e.bit_offset != run_bit_off || e.frame_bytes < 33u) {
            return WireResult<Ir>{WireCode::Invalid, "discontinuous v1 INDX offsets"};
        }
        if (static_cast<u64>(e.frame_bytes) > index_offset - run_file_off) {
            return WireResult<Ir>{WireCode::Invalid, "v1 INDX frame_bytes exceeds index_offset"};
        }
        if (total_bits == 0ULL) {
            if (chunk_count != 1ULL || e.bit_len != 0u || e.chunk_kind != kChunkKindExplicitDag) {
                return WireResult<Ir>{WireCode::Invalid, "invalid empty-stream v1 INDX entry"};
            }
        } else {
            if (e.bit_len == 0u || e.bit_len > cfg_l_max ||
                static_cast<u64>(e.bit_len) > total_bits - run_bit_off) {
                return WireResult<Ir>{WireCode::Invalid, "v1 superchunk bit_len out of bounds"};
            }
        }

        if (e.chunk_kind == kChunkKindRef) {
            if (e.frame_bytes != 36u || e.v4_op > 3u ||
                static_cast<u64>(e.ref_target) >= c ||
                cfg_w_hist == 0u ||
                (c - static_cast<u64>(e.ref_target)) > static_cast<u64>(cfg_w_hist) ||
                index[e.ref_target].bit_len != e.bit_len) {
                return WireResult<Ir>{WireCode::Invalid, "invalid CHUNK_REF in v1 INDX"};
            }
            ++chunk_ref_rem_uses[e.ref_target];
        } else if (e.chunk_kind == kChunkKindExplicitDag) {
            if (e.v4_op != 0u || static_cast<u64>(e.ref_target) != c) {
                return WireResult<Ir>{WireCode::Invalid, "invalid EXPLICIT_DAG metadata in v1 INDX"};
            }
        } else {
            return WireResult<Ir>{WireCode::Invalid, "unknown chunk_kind in v1 INDX"};
        }

        index[static_cast<std::size_t>(c)] = e;
        run_file_off += static_cast<u64>(e.frame_bytes);
        run_bit_off  += static_cast<u64>(e.bit_len);
    }

    if (run_file_off != index_offset || run_bit_off != total_bits) {
        return WireResult<Ir>{WireCode::Invalid, "v1 INDX totals disagree with trailer"};
    }

    // Check output byte budget after container/INDX framing is proven valid.
    const u64 needed_out_bytes = (total_bits + 7ULL) >> 3;
    if (needed_out_bytes > limits.max_output_bytes) {
        return WireResult<Ir>{
            WireCode::Limit, "decoded v1 stream exceeds LegacyLimits::max_output_bytes"};
    }

    // 4. Read, authenticate, evaluate, and structurally lift all K MCHK frames.
    Dag v2_dag;
    std::vector<V1BitSeq> chunk_hist(static_cast<std::size_t>(chunk_count));
    std::vector<u32> chunk_v2_ids(static_cast<std::size_t>(chunk_count), 0u);
    std::vector<u8> chunk_has_v2(static_cast<std::size_t>(chunk_count), 0u);

    StreamByteAssembler assembler;
    assembler.bytes.reserve(static_cast<std::size_t>(needed_out_bytes));
    u64 live_working_bytes = 0ULL;

    for (u64 c = 0ULL; c < chunk_count; ++c) {
        const V1IndexEntry& ie = index[static_cast<std::size_t>(c)];

        std::array<u8, 32> fhdr{};
        {
            const WireCode rc = src.read(ie.file_offset, fhdr);
            if (rc != WireCode::Ok) {
                return WireResult<Ir>{rc, "failed reading v1 MCHK header"};
            }
        }
        if (std::memcmp(fhdr.data(), "MCHK", 4) != 0) {
            return WireResult<Ir>{WireCode::Invalid, "invalid MCHK magic"};
        }
        const u32 f_cidx     = read_le32(fhdr.data() + 4);
        const u64 f_boff     = read_le64(fhdr.data() + 8);
        const u32 f_blen     = read_le32(fhdr.data() + 16);
        const u8  f_kind     = fhdr[20];
        const u8  f_v4       = fhdr[21];
        const u16 f_reserved = read_le16(fhdr.data() + 22);
        const u32 p_bytes    = read_le32(fhdr.data() + 24);
        const u32 f_crc_want = read_le32(fhdr.data() + 28);

        if (static_cast<u64>(f_cidx) != c ||
            f_boff != ie.bit_offset ||
            f_blen != ie.bit_len ||
            f_kind != ie.chunk_kind ||
            f_v4 != ie.v4_op ||
            f_reserved != 0u ||
            p_bytes == 0u ||
            p_bytes > 0x7FFFFFFFu ||
            32ULL + static_cast<u64>(p_bytes) != static_cast<u64>(ie.frame_bytes)) {
            return WireResult<Ir>{WireCode::Invalid, "MCHK header disagrees with INDX"};
        }
        if (static_cast<u64>(p_bytes) > limits.max_chunk_payload_bytes) {
            return WireResult<Ir>{
                WireCode::Limit, "MCHK payload exceeds LegacyLimits::max_chunk_payload_bytes"};
        }

        std::vector<u8> payload(p_bytes);
        {
            const WireCode rc = src.read(ie.file_offset + 32ULL, payload);
            if (rc != WireCode::Ok) {
                return WireResult<Ir>{rc, "failed reading v1 MCHK payload"};
            }
        }

        mapr::Crc32 fcrc;
        fcrc.update(sv_of(std::span<const u8>(fhdr.data(), 28)));
        fcrc.update(sv_of(payload));
        if (fcrc.finish() != f_crc_want) {
            return WireResult<Ir>{WireCode::Invalid, "v1 MCHK CRC-32 mismatch"};
        }

        V1BitSeq c_seq;
        if (f_kind == kChunkKindRef) {
            if (p_bytes != 4u) {
                return WireResult<Ir>{WireCode::Invalid, "CHUNK_REF payload_bytes != 4"};
            }
            const u32 ref_target = read_le32(payload.data());
            if (ref_target != ie.ref_target) {
                return WireResult<Ir>{WireCode::Invalid, "CHUNK_REF target disagrees with INDX"};
            }
            c_seq = chunk_hist[ref_target].apply_v4(f_v4);
            if ((f_blen & 7u) == 0u && chunk_has_v2[ref_target] != 0u) {
                auto morphed = emit_v4_morph(v2_dag, chunk_v2_ids[ref_target], f_v4);
                if (!morphed.ok()) return morphed.error();
                chunk_v2_ids[static_cast<std::size_t>(c)] = morphed.value();
                chunk_has_v2[static_cast<std::size_t>(c)] = 1u;
            }
            // Reclaim referenced chunk history if no further CHUNK_REF needs it.
            if (chunk_ref_rem_uses[ref_target] > 0u) {
                --chunk_ref_rem_uses[ref_target];
                if (chunk_ref_rem_uses[ref_target] == 0u) {
                    const u64 freed =
                        static_cast<u64>(chunk_hist[ref_target].storage_bytes());
                    live_working_bytes =
                        (freed <= live_working_bytes) ? (live_working_bytes - freed) : 0ULL;
                    chunk_hist[ref_target].clear_memory();
                }
            }
        } else {
            auto parsed = parse_and_validate_chunk_dag(payload, f_blen, limits);
            if (!parsed.ok()) return parsed.error();

            const bool build_v2_for_chunk = ((f_blen & 7u) == 0u);
            auto evaled = eval_and_lift_chunk_dag(
                parsed.value(), build_v2_for_chunk, v2_dag, live_working_bytes, limits);
            if (!evaled.ok()) return evaled.error();

            c_seq = std::move(evaled.value().root_bits);
            if (evaled.value().has_v2_node) {
                chunk_v2_ids[static_cast<std::size_t>(c)] = evaled.value().v2_node_id;
                chunk_has_v2[static_cast<std::size_t>(c)] = 1u;
            }
        }

        if (c_seq.bit_len() != static_cast<u64>(f_blen)) {
            return WireResult<Ir>{WireCode::Mismatch, "evaluated chunk bit_len mismatch"};
        }

        assembler.append_seq(c_seq);

        if (chunk_ref_rem_uses[static_cast<std::size_t>(c)] > 0u) {
            const u64 hist_bytes = static_cast<u64>(c_seq.storage_bytes());
            if (hist_bytes > limits.max_eval_working_bytes ||
                live_working_bytes > limits.max_eval_working_bytes - hist_bytes) {
                return WireResult<Ir>{
                    WireCode::Limit, "CHUNK_REF history working set exceeds LegacyLimits"};
            }
            live_working_bytes += hist_bytes;
            chunk_hist[static_cast<std::size_t>(c)] = std::move(c_seq);
        }
    }

    // 5. Verify end-to-end trailer SHA-256 according to header digest mode (SPECS.md §2.1).
    if ((flags & kFlagRawBytesMsb) != 0u) {
        if (assembler.carry_bits != 0 ||
            static_cast<u64>(assembler.bytes.size()) != (total_bits >> 3)) {
            return WireResult<Ir>{WireCode::Mismatch, "assembled byte length mismatch"};
        }
        const Digest256 got_sha = sha256_span(assembler.bytes);
        if (got_sha != expected_sha) {
            return WireResult<Ir>{
                WireCode::Mismatch, "v1 stream SHA-256 mismatch against trailer"};
        }
    } else {
        const std::vector<u8> padded = assembler.finish_msb_padded();
        std::array<u8, 8> be_len{};
        write_be64(be_len.data(), total_bits);
        mapr::Sha256 hasher;
        (void)hasher.update(sv_of(be_len));
        (void)hasher.update(sv_of(padded));
        const Digest256 got_sha = hasher.finish().value();
        if (got_sha != expected_sha) {
            return WireResult<Ir>{
                WireCode::Mismatch, "v1 bitseq SHA-256 mismatch against trailer"};
        }
        // Valid sub-byte bitseq container cannot be represented in byte-universal v2 Ir
        // without padding/truncation approximation -> Unsupported (E3 §6.3).
        if ((total_bits & 7ULL) != 0ULL) {
            return WireResult<Ir>{
                WireCode::Unsupported,
                "sub-byte v1 bitseq container (total_bits % 8 != 0) has no exact v2 byte Ir"};
        }
    }

    const u64 total_bytes = total_bits >> 3;
    if (static_cast<u64>(assembler.bytes.size()) != total_bytes) {
        return WireResult<Ir>{WireCode::Mismatch, "assembled byte count disagrees with total_bits"};
    }

    // 6. Assemble top-level v2 Dag across byte-aligned superchunks and unaligned cut groups.
    u32 top_root = 0u;
    if (total_bytes == 0ULL) {
        Node e{};
        e.kind = Kind::Empty;
        auto eid = map_e2_result(v2_dag.add_node(std::move(e)), "Dag::add_node(top Empty)");
        if (!eid.ok()) return eid.error();
        top_root = eid.value();
    } else {
        std::vector<u32> top_segments;
        std::size_t ci = 0;
        while (ci < index.size()) {
            const V1IndexEntry& ie = index[ci];
            if ((ie.bit_offset & 7ULL) == 0ULL &&
                (ie.bit_len & 7u) == 0u &&
                chunk_has_v2[ci] != 0u) {
                if (ie.bit_len > 0u) {
                    top_segments.push_back(chunk_v2_ids[ci]);
                }
                ++ci;
            } else {
                const u64 start_byte = ie.bit_offset >> 3;
                u64 end_bit = ie.bit_offset + static_cast<u64>(ie.bit_len);
                ++ci;
                while (ci < index.size() && (end_bit & 7ULL) != 0ULL) {
                    end_bit += static_cast<u64>(index[ci].bit_len);
                    ++ci;
                }
                const u64 end_byte = end_bit >> 3;
                const std::span<const u8> slice_bytes(
                    assembler.bytes.data() + static_cast<std::size_t>(start_byte),
                    static_cast<std::size_t>(end_byte - start_byte));
                auto sid = emit_bytes_term(v2_dag, slice_bytes);
                if (!sid.ok()) return sid.error();
                if (!slice_bytes.empty()) {
                    top_segments.push_back(sid.value());
                }
            }
        }

        if (top_segments.empty()) {
            Node e{};
            e.kind = Kind::Empty;
            auto eid = map_e2_result(v2_dag.add_node(std::move(e)), "Dag::add_node(Empty)");
            if (!eid.ok()) return eid.error();
            top_root = eid.value();
        } else if (top_segments.size() == 1u) {
            top_root = top_segments[0];
        } else {
            Node cat{};
            cat.kind = Kind::Concat;
            cat.args = std::move(top_segments);
            auto cid = map_e2_result(v2_dag.add_node(std::move(cat)), "Dag::add_node(top Concat)");
            if (!cid.ok()) return cid.error();
            top_root = cid.value();
        }
    }

    auto raw_ir = std::move(v2_dag).finish(top_root);
    if (!raw_ir.ok()) {
        const WireCode wc = (raw_ir.code() == Code::Limit) ? WireCode::Limit : WireCode::Invalid;
        return WireResult<Ir>{wc, "Dag::finish failed on lifted v1 term"};
    }

    // 7. Normalize into unique canonical v2 Ir via frozen E2 CANON so E3-G re-encode
    //    (`encode(decode_v1(src))`) satisfies check_canonical precondition directly.
    auto canon_res = canon(raw_ir.value());
    if (!canon_res.ok()) {
        const WireCode wc =
            (canon_res.code() == Code::Limit) ? WireCode::Limit : WireCode::Invalid;
        return WireResult<Ir>{wc, "E2 canon() failed on lifted v1 Ir"};
    }
    Ir final_ir = std::move(canon_res.value());

    if (!check_canonical(final_ir).ok() || !check_well_formed(final_ir).ok()) {
        return WireResult<Ir>{WireCode::Invalid, "canonicality check failed on decoded v1 Ir"};
    }
    if (final_ir.total_length != mapr::BigInt(total_bytes)) {
        return WireResult<Ir>{WireCode::Mismatch, "v2 Ir total_length disagrees with v1 stream"};
    }

    // 8. Independent end-to-end denotation check on final_ir via frozen E2 eval_stream_digest.
    const Digest256 want_byte_sha =
        ((flags & kFlagRawBytesMsb) != 0u) ? expected_sha : sha256_span(assembler.bytes);
    auto ir_sha = eval_stream_digest(final_ir);
    if (!ir_sha.ok()) {
        const WireCode wc = (ir_sha.code() == Code::Limit) ? WireCode::Limit : WireCode::Invalid;
        return WireResult<Ir>{wc, "E2 eval_stream_digest failed on decoded v1 Ir"};
    }
    if (ir_sha.value().sha256 != want_byte_sha ||
        ir_sha.value().bytes != mapr::BigInt(total_bytes)) {
        return WireResult<Ir>{WireCode::Mismatch, "v2 Ir denotation digest mismatch"};
    }

    // 9. Transfer Atom payload backing into caller Arena when supplied.
    if (arena != nullptr) {
        for (Atom& atom : final_ir.atoms) {
            auto stored = arena->store(atom.payload);
            if (!stored.ok()) return stored.error();
            atom.payload = stored.value();
            atom.owner.reset();
        }
        if (!verify_atom_digests(final_ir).ok()) {
            return WireResult<Ir>{WireCode::Mismatch, "Arena-backed Atom digest mismatch"};
        }
    }

    return final_ir;
}

} // namespace

bool looks_like_v1(Source& src) noexcept {
    try {
        if (src.size() < 8ULL) return false;
        std::array<u8, 8> prefix{};
        if (src.read(0ULL, prefix) != WireCode::Ok) return false;
        return std::memcmp(prefix.data(), kV1Magic.data(), 8) == 0;
    } catch (...) {
        return false;
    }
}

bool looks_like_v1(std::span<const u8> bytes) noexcept {
    if (bytes.size() < 8u) return false;
    return std::memcmp(bytes.data(), kV1Magic.data(), 8) == 0;
}

WireResult<Ir> decode_v1(Source& src, Arena& arena, const LegacyLimits& limits) {
    try {
        return decode_v1_impl(src, &arena, limits);
    } catch (...) {
        return WireResult<Ir>{WireCode::Limit, "allocation failure during decode_v1"};
    }
}

WireResult<Ir> decode_v1(Source& src, const LegacyLimits& limits) {
    try {
        return decode_v1_impl(src, nullptr, limits);
    } catch (...) {
        return WireResult<Ir>{WireCode::Limit, "allocation failure during decode_v1"};
    }
}

WireResult<Ir> decode_v1(std::span<const u8> bytes, Arena& arena, const LegacyLimits& limits) {
    SpanSource src(bytes);
    return decode_v1(src, arena, limits);
}

WireResult<Ir> decode_v1(std::span<const u8> bytes, const LegacyLimits& limits) {
    SpanSource src(bytes);
    return decode_v1(src, limits);
}

} // namespace marp::v2
