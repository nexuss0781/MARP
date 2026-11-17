// MARP v2 — E4 MEASURE — C09 PROVENANCE
//
// The identity of an input, established before anything is inferred:
//
//   * exact byte `length` (E1 `BigInt`);
//   * streaming SHA-256 of the whole input;
//   * gear hash of the whole input at seed 0;
//   * the deterministic effort `seed`.
//
// Normative sources:
//   SPECS/COMPONENTS/e4-measure/SPECS.md §4.1, §4.3, §5.1, §6, §8, §9
//   SPECS/SPECS-V2.md                  §6.1 (M0), §8.2 (V2-G2), §12.6 (V2-G14)
//   SPECS/COMPONENTS-V2.md             §6 C09
//
// Scope discipline (E4 §2.2, §10):
//   * E4 measures; it does not conclude.  This surface returns identity only —
//     no term, candidate, node, atom, segment, or observation.
//   * E4 MUST NOT link E2–E7.  E1 is the only provider of arithmetic (`BigInt`),
//     SHA-256, and the gear table; no E2/E3/E5/E6/E7 header is included here or
//     in the implementation.
//   * No file name, extension, or media type is consulted; no clock, locale,
//     random device, environment variable, thread count, process id, or address
//     reaches any value this surface returns.
//
// Error model (E4 §9): every fallible operation returns `MeasureResult<T>`.
// A source that cannot be read, or that returns fewer bytes than it declared,
// is `Io`; a provenance that does not match the source is `Mismatch`.  Nothing
// throws past the API boundary and nothing terminates the process.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <utility>

#include "mapr/e1_bigint.hpp"
#include "mapr/e1_types.hpp"

namespace marp::v2 {

using u8 = std::uint8_t;
using u32 = std::uint32_t;
using u64 = std::uint64_t;

// E1 is the only arithmetic provider (E4 §2.2: arithmetic and digests are E1's).
using BigInt = mapr::BigInt;

// ---------------------------------------------------------------------------
// Errors (E4 §9)
// ---------------------------------------------------------------------------

enum class MeasureCode : int {
    Ok = 0,
    Io = 3,        // source unreadable or short
    Mismatch = 6,  // provenance does not match the source
    Invalid = 4,   // contract violation (caller argument out of domain)
};

[[nodiscard]] constexpr const char* measure_code_name(MeasureCode code) noexcept {
    switch (code) {
        case MeasureCode::Ok: return "Ok";
        case MeasureCode::Io: return "Io";
        case MeasureCode::Mismatch: return "Mismatch";
        case MeasureCode::Invalid: return "Invalid";
    }
    return "Unknown";
}

// `MeasureResult<T>` == T | MeasureCode.  No exceptions, no partial values.
template <typename T>
class MeasureResult {
public:
    MeasureResult(const T& value) noexcept : value_(value), code_(MeasureCode::Ok), has_value_(true) {}  // NOLINT
    MeasureResult(T&& value) noexcept : value_(std::move(value)), code_(MeasureCode::Ok), has_value_(true) {}  // NOLINT
    MeasureResult(MeasureCode code) noexcept : value_(), code_(code), has_value_(false) {}  // NOLINT

    [[nodiscard]] bool ok() const noexcept { return has_value_; }
    [[nodiscard]] explicit operator bool() const noexcept { return has_value_; }
    [[nodiscard]] MeasureCode code() const noexcept { return code_; }
    [[nodiscard]] const T& value() const& noexcept { return value_; }
    [[nodiscard]] T& value() & noexcept { return value_; }
    [[nodiscard]] T&& value() && noexcept { return std::move(value_); }

private:
    T value_{};
    MeasureCode code_ = MeasureCode::Invalid;
    bool has_value_ = false;
};

template <>
class MeasureResult<void> {
public:
    MeasureResult() noexcept : code_(MeasureCode::Ok) {}
    MeasureResult(MeasureCode code) noexcept : code_(code) {}  // NOLINT

    [[nodiscard]] bool ok() const noexcept { return code_ == MeasureCode::Ok; }
    [[nodiscard]] explicit operator bool() const noexcept { return ok(); }
    [[nodiscard]] MeasureCode code() const noexcept { return code_; }

private:
    MeasureCode code_;
};

using MeasureStatus = MeasureResult<void>;

// ---------------------------------------------------------------------------
// Policy (E4 §4.10)
// ---------------------------------------------------------------------------

// The only policy field C09 reads.  `effort 0..9` is the search budget of
// SPECS-V2 §9; the remaining budgets are C10/C11's and are not consulted here.
// The defaults are the §4.10 gate values (every gate runs at effort 5).
struct Policy {
    u8 effort = 5;
};

inline constexpr u8 kEffortMin = 0;
inline constexpr u8 kEffortMax = 9;

[[nodiscard]] constexpr bool effort_in_domain(u32 value) noexcept {
    return value >= static_cast<u32>(kEffortMin) && value <= static_cast<u32>(kEffortMax);
}

// ---------------------------------------------------------------------------
// Source (E4 §4.1)
// ---------------------------------------------------------------------------

// A finite byte string of exact length L in N, readable by offset.
//
// Contract (E4 §4.1, E4-I11):
//   * `size()` is exact and constant for the life of the object;
//   * `read(off, dst)` succeeds only when [off, off + dst.size()) lies inside
//     [0, size()), and on success writes every requested byte;
//   * re-reading a range returns identical bytes;
//   * no implementation may consult the clock, the file name, or the
//     environment (`Io` is the only permitted failure).
//
// `read` deliberately returns the E4 code rather than a bool so that a short
// or unreadable medium is reported as `Io` and never as a silent zero fill.
class Source {
public:
    virtual ~Source() = default;

    [[nodiscard]] virtual BigInt size() const noexcept = 0;
    [[nodiscard]] virtual MeasureCode read(const BigInt& off, std::span<u8> dst) const noexcept = 0;
};

// Source over caller-owned bytes.  The bytes must outlive the source.
class SpanSource final : public Source {
public:
    explicit SpanSource(std::span<const u8> data) noexcept : data_(data) {}

    [[nodiscard]] BigInt size() const noexcept override {
        return BigInt(static_cast<u64>(data_.size()));
    }
    [[nodiscard]] MeasureCode read(const BigInt& off, std::span<u8> dst) const noexcept override;

private:
    std::span<const u8> data_;
};

// ---------------------------------------------------------------------------
// Provenance (E4 §4.3, §8)
// ---------------------------------------------------------------------------

struct Provenance {
    BigInt length;                 // exact byte length
    std::array<u8, 32> sha256{};   // SHA-256 of the whole input
    u64 gear = 0;                  // gear_hash of the whole input, seed 0
    u64 seed = 0;                  // effort seed, §4.3
};

// One streaming pass over `source`.  SHA-256 and the gear hash advance over the
// same buffer; the input is never materialised (O(1) working memory).
//
// Postcondition on success: `length == source.size()`, `sha256` is the SHA-256
// of all `length` bytes, `gear` is the E1 gear hash of all `length` bytes at
// seed 0, and `seed` is the §4.3 effort seed.  On failure nothing is returned.
MeasureResult<Provenance> provenance(Source& source, const Policy& policy);

// ---------------------------------------------------------------------------
// Seed (E4 §4.3) — the normative function, exposed so the gate can pin it
// ---------------------------------------------------------------------------

// `seed = LE64(SHA-256("MARP2-seed" || LE32(effort) || sha256(x))[0..8))`
//
// Pure function of the digest and the effort.  Returns the seed for
// `0 <= effort <= 9`; out-of-domain effort is `Invalid` (the policy is the
// caller's contract, E4 §9).  It never reads a clock, an address, a process id,
// a host name, or a thread count.
[[nodiscard]] MeasureResult<u64> derive_seed(std::span<const u8, 32> digest, u8 effort) noexcept;

// `PROVENANCE_SEED_DOMAIN` — the literal prefix of the seed hash ("MARP2-seed").
inline constexpr char kSeedDomain[] = "MARP2-seed";
inline constexpr std::size_t kSeedDomainLen = sizeof(kSeedDomain) - 1u;

// Stable, byte-reproducible rendering used by the C09 evidence log and by the
// gate's comparisons.  It is a pure function of `Provenance`: lowercase hex
// digest, decimal length, fixed-width hex gear and seed.
[[nodiscard]] std::string provenance_text(const Provenance& prov);

// Digest equality helper (a `std::array` comparison, spelled once).
[[nodiscard]] constexpr bool same_digest(const std::array<u8, 32>& a,
                                        const std::array<u8, 32>& b) noexcept {
    for (std::size_t i = 0; i < a.size(); ++i) {
        if (a[i] != b[i]) return false;
    }
    return true;
}

// `provenance_matches(source, prov)` — re-verifies a recorded provenance against
// the source in a second streaming pass.  Returns `Ok`, `Io`, or `Mismatch`
// (E4 §9).  C10's `segment(source, prov, policy)` uses this as its precondition.
MeasureStatus provenance_matches(Source& source, const Provenance& prov, const Policy& policy);

}  // namespace marp::v2
