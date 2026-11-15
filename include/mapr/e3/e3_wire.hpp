// MARP v2 — E3 WIRE — C07 WIRE
//
// The canonical v2 byte container and its reader/writer:
//
//   * `encode` / `encode_to` / `encoded_size` — the unique canonical wire for a
//     canonical `Ir`, with `encoded_size` computed from the same plan that
//     `encode_to` writes;
//   * `validate` / `decode` / `decode_stream` — total, staged validation in the
//     normative order of E3 §5.1, and decoding that either yields a canonical
//     `Ir` (or streams the denotation) or a defined rejection;
//   * the canonical integer codecs `uvarint` and tagged `bigint`.
//
// Normative sources:
//   SPECS/COMPONENTS/e3-wire/SPECS.md            §4, §5, §6, §7, §9, §10, §12
//   SPECS/SPECS-V2.md                           §5.1–5.9, §8.1–8.4
//   SPECS/COMPONENTS-V2.md                      §5 C07
//
// Scope discipline (E3 §2.2, §11):
//   * wire representation and validation only — no canonicalisation or
//     rewriting (E2/C04), no discovery/selection/classification (E4–E6), no
//     translation/CLI/certificate (E7), no v1 emission and no v1 read
//     (`decode_v1` is C08 LEGACY and is absent from this surface);
//   * no file, path, MIME, environment, clock, thread, or global-state access;
//   * C++20 only; E1 `BigInt`, SHA-256, and CRC-32 are the only primitives and
//     E2 is the only authority on term meaning, lengths, and canonicality.
//
// Error model (E3 §10): every fallible operation returns `WireResult<T>`; a
// rejection carries the `Stage` and a stable `check` identifier.  Nothing
// throws past the API boundary, nothing terminates the process, and no
// allocation is sized from an unvalidated count or offset.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "mapr/e1_bigint.hpp"
#include "mapr/e2/e2_term.hpp"

namespace marp::v2 {

using u8 = std::uint8_t;
using u16 = std::uint16_t;
using u32 = std::uint32_t;
using u64 = std::uint64_t;

// ---------------------------------------------------------------------------
// Error model (E3 §10)
// ---------------------------------------------------------------------------

enum class WireCode : u8 {
    Ok = 0,
    Invalid = 1,      // structural / canonicality / CRC / bounds / unknown v2 feature
    Unsupported = 2,  // future major or minor version
    Limit = 3,        // a declared limit was exceeded
    Mismatch = 4,     // evaluation disagrees with the declared length or digest
};

const char* wire_code_name(WireCode code) noexcept;

// Validation stages, in the normative order of E3 §5.1 (parent §5.9).
enum class Stage : u8 {
    None = 0,
    Size = 1,       // 1. source size >= 96
    Header = 2,     // 2. magic, version, header_bytes, reserved flags
    Bounds = 3,     // 3. trailer_offset / file_bytes bounds
    HeaderCrc = 4,  // 4. file_crc32
    Trailer = 5,    // 5. trailer magic, counts, root, CRC
    Regions = 6,    // 6. region monotonicity, atom_offset, total-length form
    Atoms = 7,      // 7. atom table
    Nodes = 8,      // 8. node table (+ E2 canonical shape)
    Root = 9,       // 9. root id == node_count-1
    Index = 10,     // 10. seek index
    Eval = 11,      // 11. full evaluation
};

const char* stage_name(Stage stage) noexcept;

// Structured rejection.  `check` is one of the stable `kStage*` identifiers
// below, so evidence rows can assert "rejected at the correct stage".
struct WireError {
    // A default-constructed `WireError` is the absence of a rejection.
    WireCode code = WireCode::Ok;
    Stage stage = Stage::None;
    const char* check = "";
    std::string message;

    WireError() = default;
    WireError(WireCode c, Stage s, const char* k, std::string m)
        : code(c), stage(s), check(k), message(std::move(m)) {}

    bool ok() const noexcept { return code == WireCode::Ok; }
};

// Stable stage check identifiers (evidence-facing; never renumbered).
constexpr const char* kStageSize = "S1.size";
constexpr const char* kStageMagic = "S2.magic";
constexpr const char* kStageVersion = "S2.version";
constexpr const char* kStageVersionFuture = "S2.version-future";
constexpr const char* kStageHeaderBytes = "S2.header-bytes";
constexpr const char* kStageFlagsReserved = "S2.flags-reserved";
constexpr const char* kStageFlagsCanonical = "S2.flags-canonical";
constexpr const char* kStageFlagsByteAligned = "S2.flags-byte-aligned";
constexpr const char* kStageTrailerBound = "S3.trailer-bounds";
constexpr const char* kStageFileCrc = "S4.file-crc32";
constexpr const char* kStageTrailerMagic = "S5.trailer-magic";
constexpr const char* kStageTrailerCounts = "S5.counts";
constexpr const char* kStageTrailerRoot = "S5.root";
constexpr const char* kStageTrailerCrc = "S5.trailer-crc32";
constexpr const char* kStageRegionOrder = "S6.regions";
constexpr const char* kStageAtomOffset = "S6.atom-offset";
constexpr const char* kStageIndexOffset = "S6.index-offset";
constexpr const char* kStageLengthForm = "S6.total-length-form";
constexpr const char* kStageLengthCap = "S6.total-length-cap";
constexpr const char* kStageOutputCap = "S6.output-cap";
constexpr const char* kStageAtomCount = "S7.count";
constexpr const char* kStageAtomCountTrailer = "S7.count-trailer";
constexpr const char* kStageAtomFlags = "S7.flags";
constexpr const char* kStageAtomLength = "S7.length";
constexpr const char* kStageAtomSha = "S7.sha256";
constexpr const char* kStageAtomDup = "S7.duplicate";
constexpr const char* kStageAtomOrder = "S7.order";
constexpr const char* kStageAtomUnused = "S7.unused";
constexpr const char* kStageAtomRegion = "S7.region-end";
constexpr const char* kStageNodeCount = "S8.count";
constexpr const char* kStageNodeCountTrailer = "S8.count-trailer";
constexpr const char* kStageNodeKind = "S8.kind";
constexpr const char* kStageNodeFlags = "S8.flags";
constexpr const char* kStageNodeArgc = "S8.argc";
constexpr const char* kStageNodeArg = "S8.arg";
constexpr const char* kStageNodeParams = "S8.params";
constexpr const char* kStageNodeLength = "S8.length";
constexpr const char* kStageNodePostOrder = "S8.post-order";
constexpr const char* kStageNodeUnused = "S8.unused";
constexpr const char* kStageNodeDepth = "S8.depth";
constexpr const char* kStageNodeCanon = "S8.canonical-shape";
constexpr const char* kStageNodeRegion = "S8.region-end";
constexpr const char* kStageRoot = "S9.root";
constexpr const char* kStageIndexMagic = "S10.magic";
constexpr const char* kStageIndexCrc = "S10.crc";
constexpr const char* kStageIndexCount = "S10.count";
constexpr const char* kStageIndexOrder = "S10.order";
constexpr const char* kStageIndexNodeId = "S10.node-id";
constexpr const char* kStageIndexPolicy = "S10.policy";
constexpr const char* kStageEvalLength = "S11.length";
constexpr const char* kStageEvalPrefix = "S11.prefix-crc32";
constexpr const char* kStageEvalDigest = "S11.digest";

template <typename T>
class WireResult {
public:
    WireResult(const T& value) noexcept : value_(value) {}         // NOLINT
    WireResult(T&& value) noexcept : value_(std::move(value)) {}    // NOLINT
    WireResult(WireError error) noexcept : error_(std::move(error)), ok_(false) {}  // NOLINT

    bool ok() const noexcept { return ok_; }
    WireCode code() const noexcept { return ok_ ? WireCode::Ok : error_.code; }
    Stage stage() const noexcept { return ok_ ? Stage::None : error_.stage; }
    const WireError& error() const noexcept { return error_; }

    const T& value() const& noexcept { return value_; }
    T& value() & noexcept { return value_; }
    T&& value() && noexcept { return std::move(value_); }

    const T& operator*() const noexcept { return value_; }
    T& operator*() noexcept { return value_; }
    const T* operator->() const noexcept { return &value_; }
    T* operator->() noexcept { return &value_; }
    explicit operator bool() const noexcept { return ok_; }

private:
    T value_{};
    WireError error_{};
    bool ok_ = true;
};

template <>
class WireResult<void> {
public:
    WireResult() noexcept = default;
    WireResult(WireError error) noexcept : error_(std::move(error)), ok_(false) {}  // NOLINT

    bool ok() const noexcept { return ok_; }
    WireCode code() const noexcept { return ok_ ? WireCode::Ok : error_.code; }
    Stage stage() const noexcept { return ok_ ? Stage::None : error_.stage; }
    const WireError& error() const noexcept { return error_; }
    explicit operator bool() const noexcept { return ok_; }

private:
    WireError error_{};
    bool ok_ = true;
};

using WireStatus = WireResult<void>;

// ---------------------------------------------------------------------------
// Format constants (E3 §4; frozen by §14 when E3-G passes)
// ---------------------------------------------------------------------------

constexpr u64 kWireAtomMax = 1'048'576ull;      // ATOM_MAX = 1 MiB (§4.5)
constexpr u64 kWireIndexStride = 1'048'576ull;  // INDEX_STRIDE = 1 MiB (§4.7)
constexpr u16 kWireVersionMajor = 2;
constexpr u16 kWireVersionMinor = 0;
constexpr u16 kWireHeaderBytes = 64;
constexpr u16 kWireTrailerBytes = 32;
constexpr u64 kWireMinContainerBytes =
    static_cast<u64>(kWireHeaderBytes) + static_cast<u64>(kWireTrailerBytes);  // 96

constexpr u32 kWireFlagIndexPresent = 1u << 0;
constexpr u32 kWireFlagCanonical = 1u << 1;
constexpr u32 kWireFlagU64Lengths = 1u << 2;
constexpr u32 kWireFlagByteAligned = 1u << 3;
constexpr u32 kWireKnownFlagsMask = 0x0Fu;

// Header field offsets (§4.2).
constexpr std::size_t kHdrOffMagic = 0;
constexpr std::size_t kHdrOffVersionMajor = 8;
constexpr std::size_t kHdrOffVersionMinor = 10;
constexpr std::size_t kHdrOffFlags = 12;
constexpr std::size_t kHdrOffHeaderBytes = 16;
constexpr std::size_t kHdrOffTotalLengthU64 = 18;
constexpr std::size_t kHdrOffTotalLengthBigLen = 26;
constexpr std::size_t kHdrOffAtomOffset = 28;
constexpr std::size_t kHdrOffNodeOffset = 36;
constexpr std::size_t kHdrOffIndexOffset = 44;
constexpr std::size_t kHdrOffTrailerOffset = 52;
constexpr std::size_t kHdrOffFileCrc32 = 60;

// Trailer field offsets relative to the trailer start (§4.8).
constexpr std::size_t kTrlOffMagic = 0;
constexpr std::size_t kTrlOffFileBytes = 8;
constexpr std::size_t kTrlOffRootId = 16;
constexpr std::size_t kTrlOffAtomCount = 20;
constexpr std::size_t kTrlOffNodeCount = 24;
constexpr std::size_t kTrlOffTrailerCrc32 = 28;

extern const std::array<u8, 8> kHeaderMagic;  // 89 4D 41 50 52 32 0D 0A
extern const std::array<u8, 8> kIndexMagic;   // "INDX2\r\n\x1a"
extern const std::array<u8, 8> kTrailerMagic; // "TRLR2\r\n\x1a"

// ---------------------------------------------------------------------------
// Byte sources, sinks, arena (E3 §6.4, §9)
// ---------------------------------------------------------------------------

// Random-access read-only byte source.  `read` returns false unless the whole
// destination lies inside the source; it never advances or allocates.
class Source {
public:
    virtual ~Source() = default;
    virtual u64 size() const noexcept = 0;
    virtual bool read(u64 offset, std::span<u8> dst) const = 0;
};

// Source over caller-owned bytes.  The bytes must outlive the source.
class SpanSource final : public Source {
public:
    explicit SpanSource(std::span<const u8> data) noexcept : data_(data) {}
    u64 size() const noexcept override { return static_cast<u64>(data_.size()); }
    bool read(u64 offset, std::span<u8> dst) const override;

private:
    std::span<const u8> data_;
};

// Payload store for `decode`.  `store` copies bytes and returns a view whose
// storage outlives every `Ir` that references it (`Atom::owner`).
class Arena {
public:
    virtual ~Arena() = default;
    virtual WireResult<std::span<const u8>> store(std::span<const u8> bytes) = 0;
};

// Heap-backed arena.  `capacity` bounds the total stored bytes; exceeding it is
// `Limit` and never a partial image.
class HeapArena final : public Arena {
public:
    explicit HeapArena(u64 capacity = 1ull << 33);
    WireResult<std::span<const u8>> store(std::span<const u8> bytes) override;

    u64 capacity() const noexcept { return capacity_; }
    u64 used() const noexcept { return used_; }
    const std::shared_ptr<void>& owner() const noexcept { return owner_; }

private:
    u64 capacity_ = 0;
    u64 used_ = 0;
    std::shared_ptr<void> owner_;
};

// Bounded cursor over a `Source` (`[pos, end)`), with the canonical codecs.
class Reader {
public:
    Reader(const Source& src, u64 start, u64 end) noexcept;

    u64 pos() const noexcept { return pos_; }
    u64 end() const noexcept { return end_; }
    u64 remaining() const noexcept { return end_ > pos_ ? end_ - pos_ : 0; }

    bool read_exact(std::span<u8> dst);
    bool skip(u64 n) noexcept;
    bool read_u8(u8& out);
    bool read_u16(u16& out);
    bool read_u32(u32& out);
    bool read_u64(u64& out);

    // Canonical codecs (§4.9).  A non-canonical, truncated, or overflowing
    // encoding is `Invalid`; the cursor is left unspecified on failure and must
    // not be reused.
    WireResult<u64> read_uvarint();
    WireResult<BigInt> read_bigint();

private:
    const Source& src_;
    u64 pos_ = 0;
    u64 end_ = 0;
};

// ---------------------------------------------------------------------------
// Canonical integer codecs (E3 §4.9) — exposed for the harness and E7 only
// ---------------------------------------------------------------------------

std::size_t uvarint_size(u64 value) noexcept;
WireResult<std::size_t> bigint_size(const BigInt& value) noexcept;
WireStatus write_uvarint(Sink& sink, u64 value);
WireStatus write_bigint(Sink& sink, const BigInt& value);
WireResult<u64> read_uvarint(Reader& reader);
WireResult<BigInt> read_bigint(Reader& reader);

// ---------------------------------------------------------------------------
// Limits (E3 §8.3, §12; parent §8.3)
// ---------------------------------------------------------------------------

constexpr u64 kC07DefaultMaxEvalBytes = 1ull << 30;    // 1 GiB of step-11 work
constexpr u64 kC07DefaultArenaCapacity = 1ull << 33;   // 8 GiB of payload storage
constexpr u32 kC07DefaultMaxIndexEntries = 1u << 20;   // resource bound, not a format constant
constexpr u64 kC07DefaultMaxIndexOccurrences = 1ull << 22;

struct WireLimits {
    // Container / table bounds (parent §8.3).
    u64 max_container_bytes = 1ull << 63;
    u32 max_atoms = kMaxRecordsSpec;  // 2^24
    u32 max_nodes = kMaxRecordsSpec;  // 2^24
    u32 max_depth = kMaxDepthSpec;    // 2^16
    BigInt max_output_bytes = marp::v2::max_output_bytes();  // 2^63

    // Step 11 (full evaluation): when the declared total length exceeds this
    // work bound, validation reports `Limit` at stage Eval instead of spending
    // unbounded time.  `verify_denotation = false` skips step 11 entirely; the
    // result is then a *structural* validation and the caller must not treat it
    // as a full E3 §5.1 validation (the `Validation` record says so).
    u64 max_eval_bytes = kC07DefaultMaxEvalBytes;
    bool verify_denotation = true;

    // Canonical shape is enforced through E2's `check_canonical` (E3 §6.2).
    bool enforce_canonical_shape = true;
    // Canonical *wire* rules 2–9 (§4.10) beyond E2's canonical shape: first-use
    // atom/nodes, no unused records, no duplicate payload, topological order.
    // A conformance harness disables this only to test the C07 stage that owns
    // those rules (see REPORT/E3/C07-WIRE-REPORT.md §5).  Nothing inside C07
    // disables it.
    bool enforce_wire_canonicality = true;
    // The §8.3 output cap is enforced by C07 at stage Regions so that the stage
    // attribution is stable; E2's own copy of the check is disabled here.
    bool enforce_output_cap = true;

    // Seek-index resource bounds: the canonical policy can demand more entries
    // (or more node-occurrence visits) than this; that is `Limit`, documented
    // in REPORT/E3/C07-WIRE-REPORT.md §5.
    u32 max_index_entries = kC07DefaultMaxIndexEntries;
    u64 max_index_occurrences = kC07DefaultMaxIndexOccurrences;
    // Largest declared total length a canonical index may span (guard for the
    // u32 `entry_count` bound of §4.7).
    u32 index_entry_count_format_max = 0xFFFFFFFFu;

    // `decode`'s arena bound (E3 §6.2: decode respects the arena cap, while
    // `decode_stream` is the path allowed above it).
    u64 arena_capacity_bytes = kC07DefaultArenaCapacity;
    // `decode_stream` bound (below the hard 2^63 output cap).
    u64 max_stream_bytes = 1ull << 63;
};

// ---------------------------------------------------------------------------
// Plans and validation records
// ---------------------------------------------------------------------------

// Exact region plan of the canonical wire.  `encoded_size` returns
// `file_bytes`; `encode_to` writes exactly `file_bytes` bytes from this plan.
struct WirePlan {
    u64 header_bytes = kWireHeaderBytes;
    u64 total_length_big_len = 0;
    u64 atom_offset = 0;
    u64 node_offset = 0;
    u64 index_offset = 0;   // 0 when absent
    u64 trailer_offset = 0;
    u64 file_bytes = 0;
    u64 atom_region_bytes = 0;
    u64 node_region_bytes = 0;
    u64 index_region_bytes = 0;  // 0 when absent
    u32 atom_count = 0;
    u32 node_count = 0;
    u32 index_entries = 0;
    bool index_present = false;
    bool length_is_u64 = true;
};

struct Validation {
    BigInt total_length;
    std::array<u8, 32> output_sha256{};
    u32 atom_count = 0;
    u32 node_count = 0;
    u32 root_id = 0;
    bool index_present = false;
    u32 index_entries = 0;
    bool denotation_verified = false;  // true iff step 11 ran to completion
    u8 flags = 0;
};

// ---------------------------------------------------------------------------
// Encode (E3 §6.1)
// ---------------------------------------------------------------------------

// Exact plan of `encode_to`.  Requires `check_canonical(ir)`; a non-canonical
// `Ir` is a caller contract violation and is reported as `Invalid`.
WireResult<WirePlan> plan(const Ir& ir, const WireLimits& limits = {});

// Exact byte count of `encode_to(ir)`.  Computed from the plan, never by
// serialising twice.
WireResult<BigInt> encoded_size(const Ir& ir, const WireLimits& limits = {});

// Writes the unique canonical wire.  Deterministic: the bytes depend only on
// the canonical `Ir` and the limits.
WireStatus encode_to(const Ir& ir, Sink& sink, const WireLimits& limits = {});
WireResult<std::vector<u8>> encode(const Ir& ir, const WireLimits& limits = {});

// ---------------------------------------------------------------------------
// Decode / validate (E3 §6.2)
// ---------------------------------------------------------------------------

// Full §5.1 validation: counts, lengths, digest, index summary.  Rejects at the
// first failure with its stage and check identifier.
WireResult<Validation> validate(Source& source, const WireLimits& limits = {});
WireResult<Validation> validate(std::span<const u8> wire, const WireLimits& limits = {});

// Validated `Ir`; atom payloads are copied into `arena`.  The result passes
// `check_canonical`; a non-canonical wire is rejected, never normalised.
WireResult<Ir> decode(Source& source, Arena& arena, const WireLimits& limits = {});

// Convenience decode into a self-contained `Ir` (payload storage is kept alive
// through `Atom::owner`).
WireResult<Ir> decode(std::span<const u8> wire, const WireLimits& limits = {});

// Validates, then evaluates directly to `sink` without retaining an `Ir` across
// the call.  Nothing is written unless stages 1–10 succeeded.
WireStatus decode_stream(Source& source, Sink& sink, const WireLimits& limits = {});

}  // namespace marp::v2
