// MARP v2 — E3 WIRE — C07 internal shared helpers.
//
// The C07 component is split across three translation units for size only:
//
//   e3_wire.cpp       format constants, sources/arena/reader, integer codecs,
//                     the encode plan, and the writer entry points
//   e3_wire_read.cpp  the staged reader/validator of §5.1 and `decode*`
//   e3_wire_index.cpp the canonical seek-index policy (§4.7), index region
//                     emission/validation, and the streaming wire writer
//
// Nothing here is part of the public surface (§9).  No header outside
// `engine/src/e3/` may include this file.
#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "mapr/e1_bigint.hpp"
#include "mapr/e2/e2_eval.hpp"
#include "mapr/e2/e2_term.hpp"
#include "mapr/e3/e3_wire.hpp"

namespace marp::v2::detail {

// ---------------------------------------------------------------------------
// Little-endian fixed-width fields (§4.1)
// ---------------------------------------------------------------------------

inline u16 load_le16(const u8* p) noexcept {
    return static_cast<u16>(static_cast<u16>(p[0]) | static_cast<u16>(static_cast<u16>(p[1]) << 8));
}

inline u32 load_le32(const u8* p) noexcept {
    return static_cast<u32>(p[0]) | (static_cast<u32>(p[1]) << 8) | (static_cast<u32>(p[2]) << 16) |
           (static_cast<u32>(p[3]) << 24);
}

inline u64 load_le64(const u8* p) noexcept {
    return static_cast<u64>(load_le32(p)) | (static_cast<u64>(load_le32(p + 4)) << 32);
}

inline void store_le16(std::span<u8> p, u16 v) noexcept {
    p[0] = static_cast<u8>(v & 0xFFu);
    p[1] = static_cast<u8>((v >> 8) & 0xFFu);
}

inline void store_le32(std::span<u8> p, u32 v) noexcept {
    p[0] = static_cast<u8>(v & 0xFFu);
    p[1] = static_cast<u8>((v >> 8) & 0xFFu);
    p[2] = static_cast<u8>((v >> 16) & 0xFFu);
    p[3] = static_cast<u8>((v >> 24) & 0xFFu);
}

inline void store_le64(std::span<u8> p, u64 v) noexcept {
    store_le32(p, static_cast<u32>(v & 0xFFFFFFFFull));
    store_le32(p.subspan(4), static_cast<u32>(v >> 32));
}

// Canonical (shortest) uvarint length of a u64 (§4.9).
inline std::size_t uvarint_len(u64 v) noexcept {
    std::size_t n = 1;
    while (v >= 0x80ull) {
        v >>= 7;
        ++n;
    }
    return n;
}

// ---------------------------------------------------------------------------
// Shared small helpers
// ---------------------------------------------------------------------------

WireError err(WireCode code, Stage stage, const char* check, std::string message);

// Magnitude bytes of a value >= 2^64 (§4.9 tag 0x02); trimmed, last byte nonzero.
std::vector<u8> bigint_magnitude(const BigInt& value);

// Number of bytes `write_bigint` emits for `value`.
WireResult<std::size_t> bigint_size_impl(const BigInt& value);

// Appends the canonical encodings (§4.9) to a byte vector.
void append_uvarint(std::vector<u8>& out, u64 value);
void append_bigint(std::vector<u8>& out, const BigInt& value);

// Appends fixed-width little-endian fields.
void append_le16(std::vector<u8>& out, u16 v);
void append_le32(std::vector<u8>& out, u32 v);
void append_le64(std::vector<u8>& out, u64 v);

// Writes `v` at `offset` of `buf` (fixed-width little-endian).
void patch_le32(std::vector<u8>& buf, std::size_t offset, u32 v);

inline bool kind_domain(Kind kind) noexcept {
    return static_cast<u8>(kind) <= static_cast<u8>(Kind::Predictor);
}

// Value of an `Ir` field that carries a small integer, or SIZE_MAX.
inline std::size_t as_index(const BigInt& value) noexcept {
    const std::optional<u64> v = value.to_u64_checked();
    return v.has_value() ? static_cast<std::size_t>(*v) : static_cast<std::size_t>(-1);
}

// Canonical atom length rule of §4.5: 1 <= length <= ATOM_MAX.
bool atom_length_ok(const Atom& atom) noexcept;

// ---------------------------------------------------------------------------
// Seek index (§4.7)
// ---------------------------------------------------------------------------

struct IndexEntryC07 {
    u64 output_offset = 0;    // > 0, a multiple of INDEX_STRIDE
    u32 node_id = 0;          // smallest node id whose output starts here
    u32 crc32_of_prefix = 0;  // CRC-32 of the first `output_offset` denotation bytes
};

// Canonical policy of §4.7 over a canonical `Ir`.  `entries[i].crc32_of_prefix`
// is left zero (it needs the denotation); every other field is final.
struct IndexPolicy {
    std::vector<IndexEntryC07> entries;
    u64 occurrences = 0;  // node/offset visits spent deriving the policy
};

WireError compute_index_policy(const Ir& ir, const WireLimits& limits, IndexPolicy& out);

// Greatest common divisor of two non-negative bigints (Euclid).  Used by the
// canonical index policy to step a Repeat's stride-aligned repetitions without
// iterating once per repetition.  `Limits` are reported as a failed result only
// when the division itself fails, which E1 does not do for non-negative values.
inline WireResult<BigInt> gcd_bigint(const BigInt& a, const BigInt& b) {
    BigInt x = a;
    BigInt y = b;
    BigInt zero{};
    while (!y.is_zero()) {
        auto remainder = x.divmod(y);
        if (!remainder.ok()) return WireResult<BigInt>(err(WireCode::Limit, Stage::Index,
                                                          "E.index-gcd", "gcd division failed"));
        x = std::move(y);
        y = std::move(remainder.value().second);
    }
    if (x < zero) x = zero;  // defensive: gcd is defined on magnitudes
    return WireResult<BigInt>(std::move(x));
}

// Size of the index region for `policy` (0 when the policy yields no entries).
WireResult<u64> index_region_size(const IndexPolicy& policy);

// Appends the whole index region, including its CRC field.
void append_index_region(std::vector<u8>& out, const IndexPolicy& policy);

// Fills `crc32_of_prefix` for every entry by streaming the denotation once.
WireError fill_prefix_crcs(const Ir& ir, const WireLimits& limits, IndexPolicy& policy);

// ---------------------------------------------------------------------------
// Writer (§6.1) — the single assembly point
// ---------------------------------------------------------------------------

// Writes exactly `plan.file_bytes` bytes of the canonical wire for `ir`.  The
// index prefix CRCs are computed by evaluating the denotation prefixes, so the
// writer needs no second serialisation.  Requires `plan == plan(ir)` and a
// canonical `ir`.
WireStatus write_wire(const Ir& ir, const WirePlan& plan, const WireLimits& limits, Sink& sink);

// Appends the canonical wire to `out` using `plan`.
WireError append_wire(const Ir& ir, const WirePlan& plan, const WireLimits& limits,
                      std::vector<u8>& out);

// ---------------------------------------------------------------------------
// Index validation (§5.1 step 10)
// ---------------------------------------------------------------------------

// Validates a parsed index region against the canonical policy of `ir`.
WireError validate_index_entries(const IndexPolicy& canonical,
                                 const std::vector<IndexEntryC07>& parsed);

// ---------------------------------------------------------------------------
// Reader-side shared record
// ---------------------------------------------------------------------------

struct ParsedWire {
    // Header (§4.2)
    u16 version_major = 0;
    u16 version_minor = 0;
    u32 flags = 0;
    u16 header_bytes = 0;
    u64 total_length_u64 = 0;
    u16 total_length_big_len = 0;
    u64 atom_offset = 0;
    u64 node_offset = 0;
    u64 index_offset = 0;
    u64 trailer_offset = 0;
    u32 file_crc32 = 0;
    bool index_present = false;
    bool length_is_u64 = true;

    // Trailer (§4.8)
    u64 file_bytes = 0;
    u32 root_id = 0;
    u32 atom_count = 0;
    u32 node_count = 0;
    u32 trailer_crc32 = 0;

    BigInt total_length;

    // Tables
    bool structure_loaded = false;
    Ir ir;
    // Payload storage backing the `Ir` atom views (populated only when the
    // caller needs a self-contained `Ir`).
    std::deque<std::vector<u8>> retained_payloads;
    IndexPolicy canonical_index;
    std::vector<IndexEntryC07> index_entries;

    // Stage 11 output (filled only when the denotation was verified)
    bool denotation_verified = false;
    std::array<u8, 32> output_sha256{};
};

// Runs §5.1 stages 1–10 and (when `limits.verify_denotation`) step 11 on the
// region up to stage 10.  Shared by `validate`, `decode`, and `decode_stream`.
WireError run_validation(Source& source, const WireLimits& limits, ParsedWire& out);

// Evaluates the validated structure and reports the denotation digest.
WireResult<StreamDigest> evaluate_structure(const ParsedWire& parsed, const WireLimits& limits);

// Parses the index region into `parsed.index_entries` (stage 10 body).
WireError parse_index_region(Source& source, const WireLimits& limits, ParsedWire& parsed);

// Stage 11 checks for the index: prefix CRCs against the actual denotation.
WireError verify_index_prefixes(const ParsedWire& parsed, const WireLimits& limits);

}  // namespace marp::v2::detail
