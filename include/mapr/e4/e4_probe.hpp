// MARP v2 — E4 MEASURE — C11 PROBE
//
// What can be measured, exactly and reproducibly, inside a region:
//
//   * one `Observation` per probe kind per segment, each carrying its exact
//     evidence range `where` and every parameter the value was computed from;
//   * exact integer and Q24.24 fixed-point statistics — no floating point,
//     no locale, no clock, no randomness (E4 §4.2, E4-I5);
//   * `Period` only ever reported with `verified = true`, after the full byte
//     check `b[i] == b[i-p]` for all `i >= p` (§4.8);
//   * the `H2` / `Repeat16` sample path above 2 MiB, recorded, never claiming
//     full-range observation (§4.9, E4-I10).
//
// Normative sources:
//   SPECS/COMPONENTS/e4-measure/SPECS.md §4.2 (fixed point), §4.7 (observation
//     record), §4.8 (probe definitions), §4.9 (sampling), §4.10 (effort),
//     §5.3 (probe), §5.4 (merge), §6 (invariants), §8 (C++ interface),
//     §9 (errors)
//   SPECS/SPECS-V2.md                  §6.3 (M2)
//   SPECS/COMPONENTS-V2.md             §6 C11
//
// Scope discipline (E4 §2.2, §10):
//   * This surface records measurements.  It cannot emit a term, candidate,
//     node, or atom; it maintains no cross-segment dictionary or index (that is
//     E5's `C15`); it does not classify anything (that is E6).
//   * E4 MUST NOT link E2–E7.  E1 provides `BigInt` and SHA-256; C09 provides
//     `Source`, `Policy`, `MeasureCode`, `MeasureResult`; C10 provides
//     `Segment` and the §4.2 fixed-point routines (`ilog2_q24`,
//     `h0_q24_from_counts`, `zero_frac_q24`) and the §4.5 change-point
//     constants.  Nothing else is used.
//   * Every observation depends only on the bytes inside `where` and the
//     recorded parameters (E4-I2): no file name, extension, media type, clock,
//     locale, random device, environment variable, thread count, or hash-map
//     iteration order reaches a value (E4-I3, E4-I11, E4-I12).
//
// Determinism (E4-I1, E4-I3, §5.4):
//   * `probe()` is per segment and pure in the source bytes of `where`.
//   * Parallel probe results are merged with `merge_observations()`, which
//     orders by segment begin offset, then `ProbeKind` ordinal, then `param`
//     with a stable sort; completion order is discarded, so the merged list is
//     identical to the serial list.
//
// Error model (E4 §9): every fallible operation returns `MeasureResult<T>` and
// nothing throws or terminates.
//   * `Io`      — a source that cannot be read, or that returns fewer bytes
//                 than it declared;
//   * `Invalid` — a segment outside the input, a `period` present with
//                 `verified = false`, a sample window outside the range, or any
//                 other contract violation of this surface;
//   * `Limit`   — the observation-count or range cap of this implementation.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "mapr/e4/e4_segment.hpp"

namespace marp::v2 {

// ---------------------------------------------------------------------------
// ProbeKind and Observation (E4 §4.7, §8)
// ---------------------------------------------------------------------------

// The probe kinds, in the order the specification lists them.  The ordinal is
// the §5.4 merge key's second component, so the declaration order is normative.
enum class ProbeKind : u8 {
    H0,
    H1,
    H2,
    Runs,
    Period,
    Repeat16,
    Skew,
    BitComplexity,
    AffineFit,
    QuadraticFit,
    Stride,
    ChangePoint,
};

inline constexpr u32 kProbeKindCount = 12;

[[nodiscard]] constexpr u8 probe_kind_ordinal(ProbeKind kind) noexcept {
    return static_cast<u8>(kind);
}

[[nodiscard]] constexpr const char* probe_kind_name(ProbeKind kind) noexcept {
    switch (kind) {
        case ProbeKind::H0: return "H0";
        case ProbeKind::H1: return "H1";
        case ProbeKind::H2: return "H2";
        case ProbeKind::Runs: return "Runs";
        case ProbeKind::Period: return "Period";
        case ProbeKind::Repeat16: return "Repeat16";
        case ProbeKind::Skew: return "Skew";
        case ProbeKind::BitComplexity: return "BitComplexity";
        case ProbeKind::AffineFit: return "AffineFit";
        case ProbeKind::QuadraticFit: return "QuadraticFit";
        case ProbeKind::Stride: return "Stride";
        case ProbeKind::ChangePoint: return "ChangePoint";
    }
    return "Unknown";
}

// One exact measurement over one recorded byte range (E4 §4.7).
//
// Field discipline (§4.7): no field is a `double`; no field may be omitted; an
// observation without a valid `where` is invalid; a field not used by its kind
// is zero:
//
//   kind          value              aux           period  digest  verified  sampled  sc  param
//   H0            H0_q24             N             0       0       0         0       0      0
//   H1            H1_q24             N-1           0       0       0         0       0      0
//   H2            H2_q24             N-2           0       0       0         0/1*    0/16*  0
//   Runs          run_count          max_run       0       0       0         0       0      0
//   Period        0                  0             p       0       1         0       0      0
//   Repeat16      density_q24        match_count   0       0       0         0/1*    0/16*  16
//   Skew          ones_q24           N             0       0       0         0       0      plane
//   BitComplexity L (BM)             0             0       sha256  0         0       0      plane
//   AffineFit     1 if exact fit     a|(s<<8)      0       0       0         0       0      0
//   QuadraticFit  1 if exact fit     d2            0       0       0         0       0      0
//   Stride        H_q24              stride        0       0       0         0       0      stride
//   ChangePoint   1                  offset        0       0       0         0       0      4096
//
//   * `aux` of the entropies is the sample count of the statistic: N for H0,
//     N-1 for H1 (byte pairs), N-2 for H2 (byte triples); a sampled H2 row
//     carries `aux = 16 * (65536 - 2)`. Empty input: value = aux = 0.
//   * `sampled` / `sample_count` are the §4.9 sample path of `H2` and
//     `Repeat16` only: `sampled = true`, `sample_count = 16` above the 2 MiB
//     threshold, `sampled = false`, `sample_count = 0` at or below it.
//   * `verified` records that the `Period` full byte check was performed and
//     passed (§4.8); it is `true` on every reported `Period` and zero for every
//     other kind, whose fields it does not describe.
//   * `digest` is the SHA-256 of the packed Berlekamp–Massey connection
//     polynomial for `BitComplexity` and zero for every other kind (§4.8).
//   * `param` is the stride, window, or plane parameter of the kind (§4.7).
//
// `value` / `aux` are exact `u64` integers; entropy and fraction kinds are
// Q24.24 (E4 §4.2).
struct Observation {
    Segment where;
    ProbeKind kind = ProbeKind::H0;
    u64 value = 0;
    u64 aux = 0;
    BigInt period{};                  // Period only; 0 otherwise
    std::array<u8, 32> digest{};      // BitComplexity only; zero otherwise
    bool verified = false;
    bool sampled = false;
    u32 sample_count = 0;
    u32 param = 0;
};

// ---------------------------------------------------------------------------
// Probe parameters and constants (E4 §4.8, §4.9, §4.10)
// ---------------------------------------------------------------------------

// `Repeat16` keys are exactly 16 bytes wide (§4.8).
inline constexpr u32 kRepeat16Window = 16;

// Sampling (§4.9): ranges at or below 2 MiB are exact; above that `H2` and
// `Repeat16` take 16 windows of 64 KiB at `floor(j · (N - 65536) / 15)`.
inline constexpr u64 kSampleThreshold = 2ull << 20;      // 2 MiB
inline constexpr u64 kSampleWindowBytes = 65536;
inline constexpr u32 kSampleWindowCount = 16;

// The fixed `Stride` candidate set (§4.8), ascending.
inline constexpr std::array<u64, 9> kStrideSet = {2, 3, 4, 8, 16, 32, 64, 256, 4096};

// The effort-reduced stride set (§4.10, efforts 0–2).
inline constexpr std::array<u64, 3> kStrideSetReduced = {2, 4, 8};

// The minimum improvement for a stride to be reported (§4.8): 0.5 bit.
inline constexpr u64 kStrideMinImprovementQ24 = 1ull << 23;

// `Skew` and `BitComplexity` run over the eight bit planes 0..7 of each byte
// (§4.8: `param` = plane), plane `p` being bit `p` (LSB = plane 0).
inline constexpr u32 kBitPlanes = 8;

// The window offsets of the §4.9 sample path for a range of `length` bytes:
// `floor(j · (length - 65536) / 15)` for `j = 0..15`.  Only defined for
// `length > kSampleThreshold` (so `length > 65536`); the function returns
// `Invalid` outside that domain.  The offsets are a pure function of `length`,
// which is how "the window offsets are recorded in the observation table"
// (§4.9) stays reproducible from `where` alone.
[[nodiscard]] MeasureResult<std::array<u64, kSampleWindowCount>> sample_window_offsets(
    u64 length) noexcept;

// The stride candidates an effort selects (§4.10): `{2, 4, 8}` for efforts
// 0–2, the full `kStrideSet` for efforts 3–9.  Out-of-domain effort is
// `Invalid`.
struct StrideSet {
    std::array<u64, kStrideSet.size()> strides{};
    u32 count = 0;
};

[[nodiscard]] MeasureResult<StrideSet> stride_set_for_effort(u8 effort) noexcept;

// The number of bit planes `BitComplexity` computes at an effort (§4.10): 2
// for efforts 0–2, 8 for efforts 3–9.  Out-of-domain effort is `Invalid`.
[[nodiscard]] MeasureResult<u32> bit_complexity_planes(u8 effort) noexcept;

// Implementation caps (E4 §9 `Limit`).  Far above anything the §12.3 corpus
// reaches; they exist so a pathological input is a reported code rather than an
// allocation failure.
inline constexpr u64 kMaxProbeBytes = 1ull << 32;    // range cap: 4 GiB buffer
inline constexpr u64 kMaxProbeObservations = 1ull << 20;  // count cap per call

// ---------------------------------------------------------------------------
// Operations (E4 §5.3, §8)
// ---------------------------------------------------------------------------

// `probe(source, segment, policy)` — the normative §8 entry point.
//
// Precondition: `segment` lies inside `source` (`Invalid` otherwise) and
// `policy.effort` is in `[0, 9]` (`Invalid` otherwise).  Postcondition: on
// success the returned vector holds exactly the observations the §4.10 effort
// budget selects, in §5.4 merge order (kind ordinal, then `param`, with
// `ChangePoint` rows ascending in `aux`), every one carrying `where` equal to
// the segment and every field of §4.7.  A `Period` row is present only with
// `verified = true`.  On failure nothing is returned.
//
// `probe` never returns a term, candidate, or node (E4-I6); it only records
// measurements, and no observation may move a boundary (E4-I8).
[[nodiscard]] MeasureResult<std::vector<Observation>> probe(Source& source, const Segment& segment,
                                                           const Policy& policy);

// `verify_period(source, obs)` — the §5.3 verification operation.
//
// Re-reads `obs.where` from the source and performs the full byte check
// `b[i] == b[i - p]` for every `i >= p`, with `p = obs.period`.  Returns
// `Ok(true)` only when every comparison passes; `Ok(false)` when a recorded
// period claim does not hold against the current bytes.  `Invalid` when the
// observation is not a reportable `Period` claim (wrong kind, `verified =
// false`, `period` outside `[1, N]`, or `period = 0` on a non-empty range) or
// when `where` lies outside the source; `Io` when the range cannot be read.
[[nodiscard]] MeasureResult<bool> verify_period(Source& source, const Observation& obs);

// ---------------------------------------------------------------------------
// Contract validation and rendering (evidence only; pure functions)
// ---------------------------------------------------------------------------

// `validate_observation(obs, source_length)` — the §4.7 / §9 contract of one
// observation against the length of the source it claims to come from:
// `where` inside `[0, source_length]`, the field table of the struct comment,
// `Period` only with `verified = true` and `period <= N`, `sampled` rows with
// `sample_count = 16` and a range above `kSampleThreshold`, non-sampled rows
// with `sample_count = 0`, `digest` zero outside `BitComplexity`.  Returns
// `Ok`, or `Invalid` naming no field in particular (the caller renders the
// row).  Used by the gate as an independent statement of the field discipline.
[[nodiscard]] MeasureStatus validate_observation(const Observation& obs, u64 source_length) noexcept;

// `observation_text(obs)` — stable byte-reproducible rendering of one
// observation for the evidence log and the reproducibility comparisons:
// `<kind>@<begin>-<end> v=<value> a=<aux> p=<period> d=<64-hex> ver=<0|1>
// sam=<0|1> sc=<sample_count> par=<param>`.
[[nodiscard]] std::string observation_text(const Observation& obs);

// `merge_observations(rows)` — the §5.4 merge of parallel probe results:
// stable sort by segment begin offset, then `ProbeKind` ordinal, then `param`.
// Equal keys keep insertion order (so several `ChangePoint` rows of one
// segment stay in ascending offset), and the result is identical to the serial
// list whatever the completion order was.
void merge_observations(std::vector<Observation>& rows);

}  // namespace marp::v2
