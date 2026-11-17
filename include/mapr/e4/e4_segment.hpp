// MARP v2 — E4 MEASURE — C10 SEGMENT
//
// Where the input's structure changes, established before anything is inferred:
//
//   * one content-defined boundary set `B_T` per target `T` in `SCALES`
//     (64 B … 64 MiB), a pure function of the bytes and `T`;
//   * change points inserted into `B_64` from a fixed window/hop scan of
//     order-0 entropy and zero fraction;
//   * a segment tree built top-down from the coarsest scale, every node equal to
//     the union of its children, every leaf a candidate region.
//
// Normative sources:
//   SPECS/COMPONENTS/e4-measure/SPECS.md §4.2 (fixed point), §4.4 (scales and
//     constants), §4.5 (content-defined boundaries, change points), §4.6
//     (segment tree, S1–S5), §4.10 (effort), §5.2 (operations), §5.4 (merge),
//     §6 (invariants), §8 (C++ interface), §9 (errors)
//   SPECS/SPECS-V2.md          §6.2 (M1)
//   SPECS/COMPONENTS-V2.md     §6 C10
//
// Scope discipline (E4 §2.2, §10):
//   * This surface returns boundaries and a tree.  It cannot emit a term,
//     candidate, node, atom, or observation; no `Observation` type is named
//     here, and no call reaches C11.
//   * E4 MUST NOT link E2–E7.  E1 provides `BigInt` and the fixed 256-entry
//     gear table (`mapr/e1_gear.hpp`); C09 provides `Provenance`,
//     `provenance_matches()`, and the `Source` contract.  Nothing else is used.
//   * Boundaries are decided from bytes, `SCALES`, and the fixed constants in
//     this header only.  No file name, extension, media type, clock, locale,
//     random device, environment variable, thread count, or probe result
//     reaches any value returned here (E4-I8, E4-I11, E4-I12).
//
// Determinism (E4-I1, E4-I3, S5):
//   * `segment()` is the serial entry point; `segment_parallel()` takes an
//     explicit worker count.  Both produce byte-identical leaves and trees: the
//     worker count chooses *which* pure pass runs on which thread, never what a
//     pass computes.  Results are merged by scale level and then by segment
//     begin offset (§5.4), and the first error is the one of the lowest job
//     index, so even a failure is schedule-independent.
//
// Error model (E4 §9): every fallible operation returns `MeasureResult<T>`; no
// exceptions cross the boundary and nothing terminates the process.
//   * a source that cannot be read, or that returns fewer bytes than declared,
//     is `Io`;
//   * a provenance that does not match the source is `Mismatch` (§5.2
//     precondition — a boundary set computed over unverified bytes would be a
//     claim about bytes nobody identified);
//   * an out-of-domain effort, a non-power-of-two target, an internal
//     monotonicity violation, or a length that cannot be addressed as a `u64`
//     is `Invalid`.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "mapr/e4/e4_measure.hpp"

namespace marp::v2 {

// ---------------------------------------------------------------------------
// Segment (E4 §4.6, §8)
// ---------------------------------------------------------------------------

// `level` is the index into `kScales` of the boundary set this node came from
// (0 = 64 B, the finest), so the meaning of `level` never depends on effort.
// `depth` is the distance from the root (coarsest node) and therefore grows as
// `level` falls.  Every node interval is `[begin, end)`.
struct Segment {
    BigInt begin;
    BigInt end;
    u32 depth = 0;
    u8 level = 0;
};

[[nodiscard]] inline bool operator==(const Segment& a, const Segment& b) noexcept {
    return a.begin == b.begin && a.end == b.end && a.depth == b.depth && a.level == b.level;
}
[[nodiscard]] inline bool operator!=(const Segment& a, const Segment& b) noexcept {
    return !(a == b);
}

// ---------------------------------------------------------------------------
// Scales and constants (E4 §4.4, §4.5) — fixed format constants
// ---------------------------------------------------------------------------

// SCALES = { 2^6, 2^8, …, 2^26 } = { 64 B, 256 B, 1 KiB, …, 64 MiB }.
// For target T: mask = T-1, min_chunk = T/4, max_chunk = 4·T.
inline constexpr std::array<u64, 11> kScales = {
    1ull << 6,   // 64 B     k = 0, finest
    1ull << 8,   // 256 B
    1ull << 10,  // 1 KiB
    1ull << 12,  // 4 KiB
    1ull << 14,  // 16 KiB
    1ull << 16,  // 64 KiB
    1ull << 18,  // 256 KiB
    1ull << 20,  // 1 MiB
    1ull << 22,  // 4 MiB
    1ull << 24,  // 16 MiB
    1ull << 26,  // 64 MiB   k = 10, coarsest
};
inline constexpr u32 kScaleCount = static_cast<u32>(kScales.size());

// The finest scale, i.e. the level change points are added to (E4 §4.5).
inline constexpr u64 kFinestScale = kScales[0];

// Inputs at or below the finest scale have the boundary set {0, L} and a tree
// that is a single leaf (E4 §4.4).
inline constexpr u64 kSingleLeafMax = kFinestScale;

// Change-point detection (E4 §4.5).  These are format constants of the
// measurement layer, pinned so the gate is reproducible.
inline constexpr u64 kChangeWindow = 4096;          // W
inline constexpr u64 kChangeHop = 2048;             // W / 2
inline constexpr u64 kChangeEntropyQ24 = 1ull << 24;   // dH0 >= 1.0 bit
inline constexpr u64 kChangeZeroFracQ24 = 1ull << 22;  // dZ  >= 0.25
inline constexpr u64 kChangeDedupBytes = 2048;         // dedup window
inline constexpr u64 kChangeCapSlack = 16;             // cap = L/2048 + 16

// ---------------------------------------------------------------------------
// Fixed point (E4 §4.2) — integer only, no floating point anywhere
// ---------------------------------------------------------------------------

// `ilog2_q24(x) = floor(log2(x) · 2^24)` for integer `x >= 1`, computed by 24
// exact squarings of a 64-bit mantissa in a 128-bit intermediate: no `std::log2`
// and no floating point.  `ilog2_q24(0)` is defined as 0 so the entropy
// accumulator can skip an empty symbol without a branch at every call site; no
// normative formula evaluates it.
[[nodiscard]] u64 ilog2_q24(u64 x) noexcept;

// `H0_q24(n) = floor( ( N·ilog2_q24(N) − Σ_{n_i>0} n_i·ilog2_q24(n_i) ) / N )`
// with `N = Σ n_i`.  All sums are exact 128-bit integers; the single division is
// the final floor.  An empty vector (N = 0) is 0.
[[nodiscard]] u64 h0_q24_from_counts(std::span<const u64, 256> counts) noexcept;
[[nodiscard]] u64 h0_q24(std::span<const u8> bytes) noexcept;

// Zero fraction in Q24: `floor(#0 · 2^24 / N)`.  An empty range is 0.
[[nodiscard]] u64 zero_frac_q24(std::span<const u8> bytes) noexcept;

// ---------------------------------------------------------------------------
// Effort (E4 §4.10)
// ---------------------------------------------------------------------------

// `active_scales(effort)` returns the levels of `kScales` that effort selects,
// in ascending level order (`levels[0]` is always 0, the finest scale):
//
//   effort 0–2 -> { 0, 3, 6 }   = { 64 B, 4 KiB, 256 KiB }
//   effort 3–9 -> { 0 … 10 }    = all eleven scales
//
// Effort changes which scales exist in the tree, never a boundary or a value:
// the boundary set at a given scale is the same at every effort (E4 §4.10).
struct ScaleLevels {
    std::array<u8, kScaleCount> levels{};
    u32 count = 0;
};

[[nodiscard]] MeasureResult<ScaleLevels> active_scales(u8 effort) noexcept;

// ---------------------------------------------------------------------------
// Boundary sets (E4 §4.5, §5.2)
// ---------------------------------------------------------------------------

// The content-defined boundary set `B_T` for one target, built left to right
// exactly as §4.5 specifies: cut at `i+1` when `len >= min_chunk` and
// `(h & mask) == 0`, or when `len >= max_chunk`; the gear state resets at every
// cut.  `B_T` always contains 0 and L, is strictly increasing, and depends only
// on the bytes and `T`.
//
// `target` must be a power of two in `[4, 2^60]`; anything else is `Invalid`
// (the mask/min/max relations of §4.4 are only defined for a power of two).
// This is the §5.2 `boundaries(scale)` operation; `segment()` is the user of it.
[[nodiscard]] MeasureResult<std::vector<u64>> boundaries_for_scale(Source& source, u64 target);

// The change points inserted into `B_64`, before dedup against `B_64`:
// interior window boundaries `i` with `W` bytes on both sides, stepping by the
// hop, kept when `dH0 >= 2^24` or `dZ >= 2^22`, capped at `L/2048 + 16` and
// deduplicated within 2048 bytes keeping the smaller offset.  Ascending.
[[nodiscard]] MeasureResult<std::vector<u64>> change_points(Source& source);

// ---------------------------------------------------------------------------
// Resource caps (E4 §9 `Limit`)
// ---------------------------------------------------------------------------

// E4 §9 lists `Limit` for a cap that would otherwise exhaust memory.  The gate
// corpus is bounded by §12.3 (under 20 MiB), so neither cap is reachable there;
// they exist so that a hostile or accidental input of pathological shape
// (every byte a boundary, or a tree far larger than the input) is a reported
// `Limit` rather than an allocation failure.  Both are format constants of this
// implementation, not properties of the boundary rule.
inline constexpr u64 kMaxBoundaries = 1ull << 22;   // 4 Mi positions per scale
inline constexpr u64 kMaxTreeNodes = 1ull << 23;    // 8 Mi nodes across the tree

// ---------------------------------------------------------------------------
// Rendering (evidence only; pure functions of their argument)
// ---------------------------------------------------------------------------

// `boundaries_text` is `<count>:` followed by the comma-separated decimal
// positions, e.g. `4:0,64,192,256`.  `tree_text` is one
// `<begin>-<end>@d<depth>k<level>` token per node separated by `;`, in the order
// the nodes are stored (pre-order from the coarsest scale).  Both are
// byte-reproducible, so the evidence log and the determinism checks compare the
// same rendering the gate writes.
[[nodiscard]] std::string boundaries_text(std::span<const u64> boundaries);
[[nodiscard]] std::string tree_text(std::span<const Segment> nodes);

// ---------------------------------------------------------------------------
// Segment (E4 §5.2, §8)
// ---------------------------------------------------------------------------

// `segment(source, prov, policy, tree)` — the normative §8 entry point.
//
// Precondition: `prov` matches `source` (`Mismatch` otherwise, `Io` if the
// source cannot be re-read).  Postcondition: the returned vector is the leaf
// level, `level = 0`, sorted, contiguous, partitioning `[0, L)` exactly (S1);
// `*tree`, when non-null, holds every node in pre-order from the coarsest
// scale (S2, S3).  The empty input has exactly one zero-length leaf `[0, 0)`.
[[nodiscard]] MeasureResult<std::vector<Segment>> segment(
    Source& source, const Provenance& prov, const Policy& policy,
    std::vector<Segment>* tree = nullptr);

// The same function with an explicit worker count, so S5 ("the tree is
// independent of thread count and completion order") is measurable rather than
// asserted.  `threads == 0` is treated as 1.  `segment(…)` is
// `segment_parallel(…, 1, …)` and the results are byte-identical.
[[nodiscard]] MeasureResult<std::vector<Segment>> segment_parallel(
    Source& source, const Provenance& prov, const Policy& policy, u32 threads,
    std::vector<Segment>* tree = nullptr);

}  // namespace marp::v2
