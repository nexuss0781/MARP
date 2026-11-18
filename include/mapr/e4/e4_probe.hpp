// MARP v2 — E4 MEASURE — C11 PROBE
//
// Exact, deterministic, fixed-point observations per segment:
//
//   * one `Observation` per probe kind and parameter, each carrying its exact
//     evidence range (`where`), statistic (`value`/`aux`/`period`/`digest`),
//     and the flags that state how it was produced (`verified`, `sampled`,
//     `sample_count`, `param`);
//   * no floating point anywhere — entropies are Q24.24 integers over exact
//     128-bit sums, densities and fractions are Q24.24 integers, everything
//     else is an exact integer;
//   * locality: an observation depends only on the bytes of its `where` range
//     and on the recorded parameters (E4-I2), with one documented exception —
//     `ChangePoint` records a boundary classification of `where.begin` made by
//     C10's §4.5 detector, whose decision window necessarily straddles the
//     boundary (see `probe()` below and the report);
//   * merge: parallel per-segment results concatenate and sort by segment
//     begin offset, then `ProbeKind` ordinal, then `param` (E4 §5.4).
//
// Normative sources:
//   SPECS/COMPONENTS/e4-measure/SPECS.md §4.2 (fixed point), §4.7 (observations),
//     §4.8 (probe definitions), §4.9 (sampling), §4.10 (effort), §5.3–§5.4
//     (operations, merge), §6 (invariants), §8 (C++ interface), §9 (errors),
//     §11 (resources)
//   SPECS/SPECS-V2.md          §6.3 (M2)
//   SPECS/COMPONENTS-V2.md     §6 C11
//
// Scope discipline (E4 §2.2, §10):
//   * C11 measures and records; it cannot emit a term, candidate, node, atom,
//     or any other E5/E6 object.  The only record type named here is
//     `Observation`, and its fields are exactly §4.7's.
//   * E4 MUST NOT link E2–E7.  The dependencies are E1 (`BigInt`, SHA-256 for
//     the BitComplexity digest), C09 (`Source`, `Policy`, `MeasureResult`,
//     `MeasureCode`) and C10 (`Segment`, the fixed-point helpers, and the §4.5
//     change-point constants used to classify `ChangePoint`).  Nothing else is
//     included or linked.
//   * No file name, extension, or media type is consulted; no clock, locale,
//     random device, environment variable, thread count, process id, or address
//     reaches any value this surface returns.  There is no global mutable
//     state: every call works on its own locals (E4-I12).
//
// Error model (E4 §9): every fallible operation returns `MeasureResult<T>`.
// Nothing throws past the API boundary and nothing terminates the process.
//   * a source that cannot be read, or that returns fewer bytes than declared,
//     is `Io`;
//   * an out-of-domain effort, a segment outside the input, an empty or
//     zero-length evidence range where a non-empty one is required, a
//     `verify_period` contract violation (including `period` present with
//     `verified = false`), or a range that cannot be addressed as `u64` is
//     `Invalid`;
//   * the per-call range cap or the observation-count cap being exceeded is
//     `Limit` (both caps are constants below; §9 names them explicitly).
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "mapr/e4/e4_measure.hpp"
#include "mapr/e4/e4_segment.hpp"

namespace marp::v2 {

// ---------------------------------------------------------------------------
// Probe kinds and observations (E4 §4.7, §8)
// ---------------------------------------------------------------------------

enum class ProbeKind : u8 {
    H0 = 0,
    H1 = 1,
    H2 = 2,
    Runs = 3,
    Period = 4,
    Repeat16 = 5,
    Skew = 6,
    BitComplexity = 7,
    AffineFit = 8,
    QuadraticFit = 9,
    Stride = 10,
    ChangePoint = 11,
};

inline constexpr u32 kProbeKindCount = 12;

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

// One recorded measurement.  Field discipline (§4.7):
//   * `where` is the exact evidence range and lies inside the probed segment
//     and the input (E4-I7);
//   * a field a kind does not use is zero: `period` is non-zero for `Period`
//     only, `digest` is non-zero for `BitComplexity` only, `sample_count` is
//     non-zero only on the sampled path, and `param` carries the plane
//     (`Skew`, `BitComplexity`), the stride (`Stride`) or the sample window
//     size (`H2`/`Repeat16` when `sampled`) and is zero otherwise;
//   * `verified` is true only where the definition includes a full
//     verification step — `Period`, whose report is gated on the complete
//     byte check (E4-I4).  Every other kind leaves it false;
//   * `sampled` is true only on the §4.9 sample path, and a sampled
//     observation never claims full-range observation (E4-I10);
//   * no field is floating point (E4-I5).
struct Observation {
    Segment where;               // exact evidence range
    ProbeKind kind = ProbeKind::H0;
    u64 value = 0;               // statistic; entropy/fraction kinds are Q24.24
    u64 aux = 0;                 // second exact integer, kind-specific
    BigInt period;               // Period only; 0 otherwise
    std::array<u8, 32> digest{}; // BitComplexity polynomial digest; 0 otherwise
    bool verified = false;       // full-range verification performed (Period)
    bool sampled = false;        // §4.9 sample path
    u32 sample_count = 0;        // 0 when not sampled
    u32 param = 0;               // stride / window / plane parameter
};

// Field-exact equality: every §4.7 field participates, including `period`
// and `digest`.  Used by the reproducibility evidence.
[[nodiscard]] bool observations_equal(const Observation& a, const Observation& b) noexcept;

// §5.4 merge order: segment begin offset, then `ProbeKind` ordinal, then
// `param`.  Completion order is discarded; the comparison is a pure function
// of the two observations.
[[nodiscard]] bool observation_precedes(const Observation& a, const Observation& b) noexcept;

// Deterministic single-line rendering used by the evidence log and the tests:
// `<kind> <begin>-<end>@d<depth>k<level> value=… aux=… period=… digest=<hex>
// verified=… sampled=… sample_count=… param=…`.  A pure function of the
// observation, so two runs compare the same bytes.
[[nodiscard]] std::string observation_text(const Observation& obs);

// ---------------------------------------------------------------------------
// Sampling policy (E4 §4.9)
// ---------------------------------------------------------------------------

// `H2` is exact for ranges of at most 2 MiB; above that, and for `Repeat16`
// likewise, 16 windows of 64 KiB are taken at offsets
// `floor(j · (N − 65536) / 15)`, j = 0..15, and the counts are aggregated
// across windows.  `sampled = true`, `sample_count = 16`, `param = 65536`.
inline constexpr u64 kSampleExactMaxBytes = 2ull << 20;  // 2 MiB inclusive
inline constexpr u64 kSampleWindowBytes = 65536;         // 64 KiB
inline constexpr u32 kSampleWindowCount = 16;            // j = 0..15

// ---------------------------------------------------------------------------
// Effort-selected probe budgets (E4 §4.10)
// ---------------------------------------------------------------------------

// Effort never changes a produced value, only which observations exist:
//   effort 0–2: no `H2`, no `Repeat16`, `BitComplexity` planes {0,1},
//               stride set {2,4,8};
//   effort 3–9: every kind, 8 bit planes, the full stride set below.
// The gate runs at effort 5.
inline constexpr std::array<u64, 9> kStrideSetAll = {2, 3, 4, 8, 16, 32, 64, 256, 4096};
inline constexpr std::array<u64, 3> kStrideSetLow = {2, 4, 8};

// The stride set `effort` selects; out-of-domain effort is `Invalid`.
[[nodiscard]] MeasureResult<std::span<const u64>> stride_set_for_effort(u8 effort) noexcept;

// The number of bit planes `BitComplexity` covers at `effort` (2 or 8);
// planes are always 0..count-1.  Out-of-domain effort is `Invalid`.
[[nodiscard]] MeasureResult<u32> bit_complexity_plane_count(u8 effort) noexcept;

// `Stride` reports only a stride that lowers the range's H0 by at least
// 0.5 bit = 2^23 in Q24.24 (§4.8); ties choose the smallest stride.
inline constexpr u64 kStrideImprovementQ24 = 1ull << 23;

// ---------------------------------------------------------------------------
// Resource caps (E4 §9 `Limit`)
// ---------------------------------------------------------------------------

// The largest range one `probe()` call will materialise, in bytes.  §9's
// `Limit` row names a range cap explicitly; beyond it the call reports
// `Limit` rather than silently truncating a measurement.  The gate corpus is
// bounded far below this (E4 §12.3: under 20 MiB).
inline constexpr u64 kProbeRangeCapBytes = 64ull << 20;  // 64 MiB

// The largest number of observations one `probe()` call may return.  The
// maximum a segment can produce is far below this (at most 3 entropies + Runs
// + Period + Repeat16 + 8 Skew + 8 BitComplexity + 2 fits + 1 Stride + 1
// ChangePoint = 26), so the cap is a contract bound, not a working limit.
inline constexpr u32 kMaxObservationsPerProbe = 4096;

// `BitComplexity` range cap.  Berlekamp–Massey on an incompressible plane
// costs O(N·L) with L ≈ N/2, which is far above the O(8N) §11 sketches for
// ranges beyond a few KiB, so one `probe()` call emits `BitComplexity` only
// for ranges of at most this many bytes.  Leaves are at most 256 bytes
// (max_chunk of the finest scale), so leaf-level coverage is unaffected; the
// cap is a documented C11 resource decision, reported in the C11 report.
inline constexpr u64 kBitComplexityMaxBytes = 8192;

// ---------------------------------------------------------------------------
// Operations (E4 §5.3, §8)
// ---------------------------------------------------------------------------

// `probe(source, segment, policy)` — every §4.8 probe over `segment`.
//
// Precondition: `segment` lies inside the input (E4-I7; `Invalid` otherwise)
// and `policy.effort` is in 0..9 (`Invalid` otherwise).
//
// Postcondition: one observation per well-defined (kind, param) pair, ordered
// by `ProbeKind` ordinal and then `param`, each with `where == segment`:
//   * `H0`, `H1`, `Runs`, `Skew` (planes 0..7) always;
//   * `H2` and `Repeat16` at effort >= 3, exact at or below 2 MiB and on the
//     §4.9 sample path above it (`Repeat16` needs at least 16 bytes to have
//     one full window; `H2` needs at least 3 bytes for one trigram — shorter
//     ranges report the zero entropy with aux = 0);
//   * `BitComplexity` for planes 0..count-1 at effort, when the range is at
//     most `kBitComplexityMaxBytes`;
//   * `AffineFit`, `QuadraticFit` for non-empty ranges (the predicates are
//     exact over the full range, with the witness in `aux` on a fit);
//   * `Stride` — one observation, only when some stride of the effort's set
//     lowers H0 by >= 2^23, ties choosing the smallest stride;
//   * `Period` — the smallest p in [1, N] with `b[i] = b[i-p]` for all
//     `i >= p`, reported with `verified = true` only after the full byte
//     check passes (p = N, the trivial period, is reported and verified);
//     an empty range has no p and reports nothing;
//   * `ChangePoint` — exactly when `segment.begin` is a boundary inserted by
//     the §4.5 change-point detector (`value = 1`, `aux = segment.begin`).
//     Membership is defined by C10's detector over the whole input (cap on
//     pre-dedup candidates, dedup within 2048 bytes keeping the smaller
//     offset); `probe()` re-derives it with a sliding-window scan that stops
//     as soon as the decision is reached.  This is the one kind whose value
//     is not a function of the bytes inside `where` alone: it records a
//     boundary classification, not a byte measurement.
//
// An empty segment (the `[0,0)` leaf of the empty input) yields the
// well-defined zero-valued observations only: H0, H1, H2 (effort >= 3), Runs,
// Skew, BitComplexity.
[[nodiscard]] MeasureResult<std::vector<Observation>> probe(Source& source,
                                                            const Segment& segment,
                                                            const Policy& policy);

// `verify_period(source, obs)` — the §5.3 independent full byte check of a
// recorded `Period` observation: `b[i] = b[i-p]` for every `i >= p` over
// `obs.where`, with `p = obs.period`.
//
// Returns Ok(true) when the full check passes and Ok(false) when it fails.
// Contract violations are `Invalid` (E4 §9): `obs.kind != Period`, an empty
// `where`, a `period` outside [1, N], an observation whose `period` is
// non-zero but whose `verified` flag is false (the §9 row "period present
// with verified = false"), or a range outside the input.  A read failure is
// `Io`.  Observations produced by `probe()` always satisfy the contract.
[[nodiscard]] MeasureResult<bool> verify_period(Source& source, const Observation& obs);

// `merge_observations(parts)` — the §5.4 deterministic merge of parallel
// per-segment results: concatenate and stable-sort by segment begin offset,
// then `ProbeKind` ordinal, then `param`.  Completion order is discarded;
// the output is identical to the serial list, and a deliberately shuffled
// input produces the same output.
[[nodiscard]] std::vector<Observation> merge_observations(
    std::vector<std::vector<Observation>>&& parts);

}  // namespace marp::v2
