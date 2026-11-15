#pragma once

#include "marp/oracle/oracle.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace marp::oracle::detail {

// Normative v2 wire format constants (SPECS-V2 §5, E3 §4)
inline constexpr std::array<std::uint8_t, 8> kHeaderMagic = {
    0x89, 0x4D, 0x41, 0x50, 0x52, 0x32, 0x0D, 0x0A
};
inline constexpr std::array<std::uint8_t, 8> kIndexMagic = {
    0x49, 0x4E, 0x44, 0x58, 0x32, 0x0D, 0x0A, 0x1A
};
inline constexpr std::array<std::uint8_t, 8> kTrailerMagic = {
    0x54, 0x52, 0x4C, 0x52, 0x32, 0x0D, 0x0A, 0x1A
};

inline constexpr std::uint16_t kVersionMajor = 2;
inline constexpr std::uint16_t kVersionMinor = 0;
inline constexpr std::uint16_t kHeaderBytes = 64;
inline constexpr std::uint64_t kTrailerBytes = 32;
inline constexpr std::uint64_t kMinContainerBytes = kHeaderBytes + kTrailerBytes;

inline constexpr std::uint32_t kFlagIndexPresent = 1U << 0;
inline constexpr std::uint32_t kFlagCanonical    = 1U << 1;
inline constexpr std::uint32_t kFlagU64Lengths   = 1U << 2;
inline constexpr std::uint32_t kFlagByteAligned  = 1U << 3;
inline constexpr std::uint32_t kFlagKnownMask    = 0x0FU;

inline constexpr std::uint64_t kAtomMax = 1048576ULL;      // 1 MiB
inline constexpr std::uint64_t kIndexStride = 1048576ULL;  // 1 MiB

enum class NodeKind : std::uint8_t {
    Empty = 0,
    Atom = 1,
    Zero = 2,
    Concat = 3,
    Repeat = 4,
    Slice = 5,
    Morph = 6,
    Xor = 7,
    Interleave = 8,
    Lfsr = 9,
    Affine = 10,
    Predictor = 11,
};

// Clean-room non-negative arbitrary-precision integer (base 2^32, little-endian limbs)
class BigInt {
public:
    BigInt() = default;
    explicit BigInt(std::uint64_t v);

    static std::optional<BigInt> from_decimal(std::string_view s);
    static BigInt from_le_bytes(std::span<const std::uint8_t> bytes);

    bool is_zero() const noexcept { return limbs_.empty(); }
    bool fits_u64() const noexcept { return limbs_.size() <= 2; }
    std::uint64_t to_u64() const noexcept;
    std::string to_decimal() const;
    std::vector<std::uint8_t> to_le_bytes() const;

    std::size_t bit_length() const noexcept;
    bool get_bit(std::size_t idx) const noexcept;

    static int compare(const BigInt& a, const BigInt& b) noexcept;
    bool operator==(const BigInt& o) const noexcept { return limbs_ == o.limbs_; }
    bool operator!=(const BigInt& o) const noexcept { return limbs_ != o.limbs_; }
    bool operator<(const BigInt& o) const noexcept { return compare(*this, o) < 0; }
    bool operator<=(const BigInt& o) const noexcept { return compare(*this, o) <= 0; }
    bool operator>(const BigInt& o) const noexcept { return compare(*this, o) > 0; }
    bool operator>=(const BigInt& o) const noexcept { return compare(*this, o) >= 0; }

    static BigInt add(const BigInt& a, const BigInt& b);
    static BigInt add_u64(const BigInt& a, std::uint64_t b);
    static BigInt sub(const BigInt& a, const BigInt& b); // requires a >= b
    static BigInt mul(const BigInt& a, const BigInt& b);
    static BigInt mul_u64(const BigInt& a, std::uint64_t b);
    static std::pair<BigInt, std::uint64_t> divmod_u64(const BigInt& a, std::uint64_t d);
    static std::uint64_t mod_u64(const BigInt& a, std::uint64_t d);
    static std::pair<BigInt, BigInt> divmod(const BigInt& a, const BigInt& b);

private:
    void trim() noexcept;
    std::vector<std::uint32_t> limbs_;
};

// Clean-room FIPS 180-4 SHA-256
class Sha256 {
public:
    Sha256() noexcept;
    void update(std::span<const std::uint8_t> data) noexcept;
    std::array<std::uint8_t, 32> finalize() noexcept;

    static std::string to_hex(const std::array<std::uint8_t, 32>& digest);

private:
    void process_block(const std::uint8_t block[64]) noexcept;

    std::array<std::uint32_t, 8> state_{};
    std::array<std::uint8_t, 64> buf_{};
    std::size_t buf_len_ = 0;
    std::uint64_t total_bytes_lo_ = 0;
    std::uint64_t total_bytes_hi_ = 0;
};

// Clean-room IEEE 802.3 CRC-32
class Crc32 {
public:
    Crc32() noexcept = default;
    void update(std::span<const std::uint8_t> data) noexcept;
    std::uint32_t value() const noexcept { return state_ ^ 0xFFFFFFFFU; }

private:
    std::uint32_t state_ = 0xFFFFFFFFU;
};

// Random-access read-only byte source (memory or file)
class ByteSource {
public:
    virtual ~ByteSource() = default;
    virtual std::uint64_t size() const noexcept = 0;
    virtual bool read_at(std::uint64_t offset, std::span<std::uint8_t> dst) const = 0;
};

struct HeaderData {
    std::uint16_t version_major = 0;
    std::uint16_t version_minor = 0;
    std::uint32_t flags = 0;
    std::uint16_t header_bytes = 0;
    std::uint64_t total_length_u64 = 0;
    std::uint16_t total_length_big_len = 0;
    std::uint64_t atom_offset = 0;
    std::uint64_t node_offset = 0;
    std::uint64_t index_offset = 0;
    std::uint64_t trailer_offset = 0;
    std::uint32_t file_crc32 = 0;
};

struct TrailerData {
    std::uint64_t file_bytes = 0;
    std::uint32_t root_id = 0;
    std::uint32_t atom_count = 0;
    std::uint32_t node_count = 0;
    std::uint32_t trailer_crc32 = 0;
};

struct AtomRecord {
    std::uint8_t klass = 0;
    std::uint64_t length = 0;
    std::array<std::uint8_t, 32> sha256{};
    std::uint64_t payload_offset = 0; // byte offset inside ByteSource
};

struct NodeRecord {
    NodeKind kind = NodeKind::Empty;
    std::vector<std::uint32_t> args;
    std::uint32_t atom_id = 0;
    BigInt param_a;   // Zero.n, Repeat.q, Slice.start, Lfsr.n, Affine.n
    BigInt param_b;   // Repeat.r, Slice.len
    std::uint8_t morph = 0;
    std::uint8_t morph_k = 0;
    std::uint32_t stride = 0;
    std::uint64_t lfsr_conn = 0;
    std::uint64_t lfsr_init = 0;
    std::uint8_t affine_start = 0;
    std::uint8_t affine_step = 0;
    std::uint8_t predictor_id = 0;
    std::uint32_t predictor_param = 0;
    BigInt length;
    std::uint32_t depth = 0;
};

struct IndexEntry {
    BigInt output_offset;
    std::uint32_t node_id = 0;
    std::uint32_t crc32_of_prefix = 0;
};

struct ParsedContainer {
    HeaderData header;
    TrailerData trailer;
    BigInt total_length;
    std::vector<AtomRecord> atoms;
    std::vector<NodeRecord> nodes;
    bool has_index = false;
    std::vector<IndexEntry> index_entries;
    std::uint32_t index_crc32 = 0;
};

// Format helper (locale-independent lowercase hex)
std::string hex_u32(std::uint32_t v);
std::string hex_u64(std::uint64_t v);
const char* kind_name(NodeKind k) noexcept;

// Validation stages 1..10
int parse_and_validate_structure(const ByteSource& src,
                                 ParsedContainer& out,
                                 const Limits& limits,
                                 Diagnostic* diag);

// Stage 11: full streaming evaluation, SHA-256, and index prefix CRC check
using ChunkSink = std::function<int(std::span<const std::uint8_t>)>;

int eval_full_stream(const ParsedContainer& c,
                     const ByteSource& src,
                     const ChunkSink& sink,
                     std::array<std::uint8_t, 32>& out_sha256,
                     const Limits& limits,
                     Diagnostic* diag);

// Direct range evaluation (without materialising [0, start) or full output)
int eval_range_stream(const ParsedContainer& c,
                      const ByteSource& src,
                      const BigInt& start,
                      const BigInt& len,
                      const ChunkSink& sink,
                      const Limits& limits,
                      Diagnostic* diag);

// Direct range evaluation of one subterm `[start_offset, start_offset+out.size())`.
// Exposed for the E2-G gate, which feeds the oracle a constructed container
// (see engine/src/e2/e2g_oracle.cpp) and compares exact bytes.  No behaviour
// change: this is the same function `eval_full_stream` / `eval_range_stream`
// call internally.
int eval_node_range_iterative(const ParsedContainer& c,
                              const ByteSource& src,
                              std::uint32_t start_node,
                              const BigInt& start_offset,
                              std::span<std::uint8_t> out,
                              const Limits& limits,
                              Diagnostic* diag);

// Structural length recomputation of one node, exactly as the oracle's stage-8
// validator computes it.  Exposed so the E2-G gate can compare the engine's
// stored and recomputed lengths against the oracle's own arithmetic on a
// constructed container.  `ok` is false when the node is structurally invalid.
BigInt oracle_node_length(const ParsedContainer& c, std::uint32_t node, bool& ok);

// LFSR primitives of the clean-room oracle: O(log offset) GF(2) jump-ahead and
// MSB-first bit emission.  Exposed so the E2-G gate can compare the engine's
// jump-ahead state and bytes against this independent implementation
// (E2 §12.4 step 8).
std::uint64_t lfsr_jump_bytes(std::uint64_t conn,
                              std::uint64_t init,
                              const BigInt& byte_offset) noexcept;
void lfsr_emit(std::uint64_t conn,
               std::uint64_t& state,
               std::span<std::uint8_t> out) noexcept;

} // namespace marp::oracle::detail
