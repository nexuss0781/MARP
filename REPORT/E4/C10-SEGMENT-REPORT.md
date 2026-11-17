# C10 `SEGMENT` — Implementation Report (E4 MEASURE)

**Scope:** C10 `SEGMENT`, sub-component 2 of 3 of E4 `MEASURE` (MARP v2). This
report claims **C10 only**. C11 `PROBE` and the integrated **E4-G** gate are
**not** claimed and are not affected by this work. E4-G is not claimed complete by
this document.

**Sources:** `SPECS/COMPONENTS/e4-measure/SPECS.md` (MARP2-E4) §4.2, §4.4, §4.5,
§4.6, §4.10, §5.2, §5.4, §6, §8, §9, §11, §12.5; `SPECS/SPECS-V2.md` §6.2 (M1);
`SPECS/COMPONENTS-V2.md` §6 C10 and the project code table in its §2;
`MARP/SPECS/COMPONENTS/e4-measure/C10-SEGMENT-PROMPT.md`.

---

## 1. Environment, base, branch, CI

| Field | Value |
|---|---|
| Repository | `nexuss0781/MARP` |
| Branch | `arena/2d9a5dd9-marp` |
| Base commit | `acbea063b6f65b176098bf174155cdefa0d2c76a` (`h2-gates` HEAD at branch time) |
| Local toolchain | `g++ (Debian 12.2.0-14+deb12u1) 12.2.0`, GNU Make 4.3, 2 vCPU |
| CI toolchain | `ubuntu-latest`, GCC from `build-essential`, GoogleTest built from source at CI time |
| Build flags | `-std=c++20 -pedantic -Wall -Wextra -Werror -Wconversion -Wshadow -Wnull-dereference -Wdouble-promotion -Wformat=2 -O2` |
| Sanitizer flags | same warnings, `-O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined -fno-sanitize-recover=all` |
| Locally observed gate result | `rows=782 pass=782 blocked=0 fail=0` — `RESULT: PASS` |
| Locally observed unit tests | 24/24 GoogleTest cases pass (plain and ASan+UBSan builds) |
| CI workflow | `.github/workflows/e4-c10.yml` — `MARP E4 C10 SEGMENT CI` |

The authoritative CI run on this branch is `MARP E4 C10 SEGMENT CI`:

* run **[44088507598](https://github.com/nexuss0781/MARP/actions/runs/44088507598)**
  at commit `d8cd883` — the final commit of this work, which carries this report.
  `success`, both jobs (`C10 independence and E4 authority boundary (source
  level)`, `C10 build, tests, sanitizers, evidence`).
* run **[44087728894](https://github.com/nexuss0781/MARP/actions/runs/44087728894)**
  at commit `90a394149a82` — the commit that carries the implementation, tests,
  gate and evidence. Also `success`, both jobs; the second run is green with this
  report in the tree, so the report cannot have changed anything the gate checks.
* The eleven pre-existing workflows are green at the same commits, including
  `MARP E4 C09 PROVENANCE CI` (runs `44087728830` and `44088507326`), which is the
  regression check for the one additive header edit of §2.

The claim is also mechanically checkable rather than only a pasted ID: the
workflow diffs the committed TSV, log and manifest against a freshly generated
set and fails on any byte of difference (§4), and it re-runs the gate under
ASan+UBSan and requires that run to reproduce the same three files. A report that
disagreed with the code could not have a green run at all.

---

## 2. Files added or changed

Nothing frozen was modified. C10 is additive except for one enum value, recorded
here and checked by the workflow's no-regression step.

| Path | Role |
|---|---|
| `include/mapr/e4/e4_segment.hpp` | New. C10 surface: `Segment`, `kScales`, the §4.5 change-point constants, `ilog2_q24`, `h0_q24_from_counts`, `h0_q24`, `zero_frac_q24`, `active_scales`, `boundaries_for_scale`, `change_points`, `segment()`, `segment_parallel()`, `boundaries_text`, `tree_text`. |
| `engine/src/e4/e4_segment.cpp` | New. Streaming block scans, 128-bit fixed point, top-down and sharded tree construction. |
| `engine/tests/e4/e4_c10_segment_test.cpp` | New. 24 GoogleTest cases (§5). |
| `engine/src/e4/c10_gate.cpp` | New. The evidence harness (`engine/bin/c10_gate`), with references written separately from §4.2/§4.5/§4.6. |
| `engine/Makefile.c10` | New. Isolated build: E1 + C09 + C10, plus sanitizer targets. |
| `.github/workflows/e4-c10.yml` | New. Isolated workflow: independence, build, tests, determinism, evidence regeneration, schema validation, sanitizers, no-regression. |
| `specs_and_reports/v2/gates/C10-SEGMENT.tsv` | New. 782 evidence rows, all `PASS`. |
| `specs_and_reports/v2/logs/C10-SEGMENT.log` | New. Fixed banner + 582 deterministic log lines, 38 check summaries. |
| `specs_and_reports/v2/evidence/C10/SHA256SUMS` | New. Manifest of the header, the implementation, the TSV and the log. |
| `include/mapr/e4/e4_measure.hpp` | **Changed, additively:** `MeasureCode::Limit = 7`. See §5 reading 1. |
| `specs_and_reports/v2/evidence/C09/SHA256SUMS` | **Regenerated.** C09's manifest pins `e4_measure.hpp`, so the additive `Limit` changed one hash line. The C09 TSV and log are byte-identical to before, and the C09 gate is re-run in CI at this commit. |
| `REPORT/E4/C10-SEGMENT-REPORT.md` | This report. |
| `LEDGER.md` | One appended section recording the C10 outcome. |

### Linkage: what C10 is built from

| Linked | Why |
|---|---|
| `engine/src/e1_bigint.cpp` | `Segment::begin/end` are exact `BigInt`; the tree's positions widen from `u64`. |
| `engine/src/e1_gear.cpp` | E4 §4.5: "`G` is the fixed 256-entry gear table of E1". |
| `engine/src/e1_sha256.cpp` | C09's transitive dependency (`provenance_matches`). |
| `engine/src/e4/e4_provenance.cpp` | C09: `Provenance`, `Source`, `provenance_matches`, `MeasureCode`. |

Not linked: E2, E3, E5, E6, E7, C11, any Stage 1/2 engine object
(`container`, `encoder`, `decoder`, `bitio`, `dag`, `math_core`, `dedup_index`,
`thread_pool`, …), `harness/**`, `marp::oracle`. `c10-isolation` and the
workflow's `nm` check both enforce this; `nm -C obj/c10/e4/e4_segment.o` contains
only C10's own symbols.

### No regressions

* No frozen header changed (`include/mapr/e1_*`, `include/mapr/e2/**`,
  `include/mapr/e3/**`).
* No frozen source changed (`engine/src/e1_*.cpp`, `engine/src/e2/**`,
  `engine/src/e3/**`, `engine/src/e4/e4_provenance.cpp`, `harness/**`).
* No earlier gate TSV or log changed — C09's TSV and log are byte-identical; only
  its manifest's hash of the shared header moved, as it must.
* All 13 evidence manifests verify (`sha256sum -c`), asserted from the tree so a
  later component is covered automatically.
* C09 still builds and is still fully green at this commit — the workflow rebuilds
  it and re-runs its gate (`rows=348 pass=348 fail=0`) as part of the
  no-regression step.

---

## 3. Boundaries, change points, and the tree

### 3.1 Surface

```cpp
namespace marp::v2 {

struct Segment { BigInt begin, end; u32 depth; u8 level; };

inline constexpr std::array<u64, 11> kScales = {2^6, 2^8, …, 2^26};
inline constexpr u64 kChangeWindow = 4096, kChangeHop = 2048;
inline constexpr u64 kChangeEntropyQ24 = 1<<24, kChangeZeroFracQ24 = 1<<22;
inline constexpr u64 kChangeDedupBytes = 2048, kChangeCapSlack = 16;

u64 ilog2_q24(u64 x) noexcept;
u64 h0_q24_from_counts(std::span<const u64, 256>) noexcept;
u64 h0_q24(std::span<const u8>) noexcept;
u64 zero_frac_q24(std::span<const u8>) noexcept;

MeasureResult<ScaleLevels>   active_scales(u8 effort) noexcept;
MeasureResult<std::vector<u64>> boundaries_for_scale(Source&, u64 target);
MeasureResult<std::vector<u64>> change_points(Source&);

MeasureResult<std::vector<Segment>> segment(Source&, const Provenance&, const Policy&,
                                             std::vector<Segment>* tree = nullptr);
MeasureResult<std::vector<Segment>> segment_parallel(Source&, const Provenance&, const Policy&,
                                                     u32 threads,
                                                     std::vector<Segment>* tree = nullptr);

std::string boundaries_text(std::span<const u64>);
std::string tree_text(std::span<const Segment>);

} // namespace marp::v2
```

`level` is the index into `kScales` of the boundary set a node was cut from
(0 = 64 B, the finest), so its meaning never depends on effort. `depth` is the
distance from the root and therefore grows as `level` falls. This is the §4.6
`level = k` of the pseudocode; the §8 sketch shows only `depth`, and both are
kept because S3 and the tree audit need the level to be observable.

### 3.2 Content-defined boundaries (§4.5)

One streaming pass per active scale over fixed 64 KiB blocks, with the §4.5
recurrence `h = ((h << 1) + G[x[i]]) mod 2^64` spelled as a wrapping unsigned
add. The cut test is exactly the specified one:

```
len = i + 1 - start
if (len >= min_chunk && (h & mask) == 0) or (len >= max_chunk): cut at i+1; h = 0
emit L
```

`min_chunk = T/4`, `max_chunk = 4T`, `mask = T-1`, all from §4.4. A boundary is
recorded only when `i + 1 < L`, because §4.5 emits `L` unconditionally at the end
and `B_T` is "strictly increasing": a cut at `L` and the final `L` are the same
position (§5 reading 2). The gear state still resets at such a cut, which cannot
affect the final `L`.

Consequences the gate pins as evidence, rather than assuming:

* **Every position but the last is a cut**, and the loop tests every byte, so an
  interior gap is exactly in `[min_chunk, max_chunk]`. The final gap — the tail
  to the unconditional `L` — may be *shorter* than `min_chunk` but never longer
  than `max_chunk`. `c10.boundaries.invariants` asserts both halves.
* **The forced cut is a bound, not the typical gap.** On a constant fill the gear
  value depends only on the run length, so the content test fires deterministically:
  for `0x00` at `T = 64` (`G[0] = 0`, so `h = 0` and `h & 63 == 0`) every
  multiple of `min_chunk = 16` is a boundary, and a 63-byte input gives
  `{0, 16, 32, 48, 63}` — not `{0, 63}`. Both readings look plausible from the
  prose; the pseudocode decides it, and the gate pins the pseudocode's answer.
* **Content-defined, not fixed-size.** `C10Boundaries.ContentDefinedResynchronisesAfterAnInsertion`
  inserts one byte into 300 KB and requires every boundary beyond one `max_chunk`
  of slack to reappear shifted by exactly one — the property that separates §4.5
  from fixed-size chunking, measured rather than asserted.

### 3.3 Change points (§4.5)

Windows `W = 4096`, hop `W/2 = 2048`, interior boundaries only (`W` bytes on both
sides). For each candidate `i`:

```
dH0 = |H0_q24([i-W,i))  - H0_q24([i,i+W))|
dZ  = |zero_frac_q24([i-W,i)) - zero_frac_q24([i,i+W))|
insert i  if  dH0 >= 2^24  or  dZ >= 2^22
```

then cap at `L/2048 + 16` keeping the first offsets in increasing order, then
dedup within 2048 bytes keeping the smaller offset. Candidates are generated in
ascending order, so "keeping the smaller offset" is "keeping the earlier one" and
the dedup is a single forward pass.

The scan slides one `2W` buffer and reads only the bytes that entered it, so the
pass costs `L + W` bytes of reading rather than `L·(2W/hop)`. Counts are
recomputed from the buffer at every hop, so a window's value never depends on
where the scan began. Change points are added to `B_64` before dedup (§4.5) —
implemented as a sorted union of the gear set with the change-point set, with a
strict-monotonicity check that reports `Invalid` if the union could not hold
(§9's "boundary set not monotone" row).

On the `M-CHANGE` shape (256 KiB zeros ‖ 256 KiB random ‖ 256 KiB zeros ‖
256 KiB counter) the detector finds exactly 9 change points, and they include
`262144`, `524288` and `786432` — distance **0** from the zero→random boundary,
which satisfies O8.10's "within 1 MiB" with no slack needed.

### 3.4 Segment tree (§4.6)

Top-down from the coarsest active level, in pre-order:

```
build(a, b, k, depth):
    emit Segment{a, b, depth, level = k}
    if k == 0: leaf
    inner = { x in B_{k-1} : a < x < b }
    if inner == {}: build(a, b, k-1, depth+1)          // single child, same interval
    else:          for consecutive (x, y) in {a} u inner u {b}: build(x, y, k-1, depth+1)
```

Iterating `order[j]` (the active levels) rather than `k - 1` is what makes the
effort table work: at effort 0–2 the "next finer" set is `4 KiB` below `256 KiB`,
skipping the empty levels, and no node is emitted at a level that is not active.

S1–S5 are enforced in two places, deliberately:

1. **Inside the library**, `tree_is_sound` re-derives the partition, the union
   property and the non-empty-leaf rule from the emitted tree and returns
   `Invalid` rather than a bad value. A violated contract is an error code, never
   a returned vector.
2. **In the gate**, an independently written `audit()` re-checks the same three
   invariants from the returned leaves and tree, so the library's own check is not
   the only witness.

Depth is at most `|SCALES| = 11` (§11's "no recursion without a bound"), and the
gate asserts `depth < 11` on every fixture.

### 3.5 Fixed point (§4.2)

`ilog2_q24(x) = floor(log2(x)·2^24)` by 24 exact squarings of a 62-bit mantissa
in a 128-bit intermediate (`__extension__ unsigned __int128`):

```
msb = floor(log2 x);  m = y·2^62 with y = x/2^msb in [1,2)
repeat 24x: m = (m*m) >> 62;  bit = m >= 2^63;  renormalise; append bit
result = (msb << 24) | fraction
```

Truncation only ever lowers the mantissa, and 24 squarings accumulate less than
`2^-38` of relative error, far below the `2^-24` quantum, so the result is exactly
the floor for every `x` in `u64`. That is a proof sketch, not the evidence: the
evidence is agreement with a *separately written* 62-bit-mantissa routine on the
14 `M-KAT` values, on all 64 powers of two, on 4096 deterministic pseudo-random
values, and on 20 000 monotonicity points. Values do not use `std::log2`, and no
field is floating point (checked at the sanitizer build and by the absence of any
`double` in the surface).

`H0_q24(n) = floor((N·ilog2(N) − Σ_{n_i>0} n_i·ilog2(n_i)) / N)` with all products
in 128 bits and the single division as the final floor. Checked against known
values (0, 1, 2, 8 bits exactly), against an independent formula on 1000 random
count vectors, and by construction on 256-uniform-64 = `8 << 24`.

`zero_frac_q24 = floor(#0·2^24 / N)`, checked exactly at 0, 0.25 and 1.0 and
against an independent formula on a 5000-byte mixed buffer.

---

## 4. Determinism, partition, and evidence

### 4.1 Evidence artefacts

| Artefact | Content |
|---|---|
| `specs_and_reports/v2/gates/C10-SEGMENT.tsv` | 782 rows, eight v2 columns, `pass=782 blocked=0 fail=0` |
| `specs_and_reports/v2/logs/C10-SEGMENT.log` | fixed banner + 582 sorted lines, 38 check summaries, one tree digest and leaf count per fixture |
| `specs_and_reports/v2/evidence/C10/SHA256SUMS` | SHA-256 of the header, the implementation, the TSV and the log |

Check groups (rows): `c10.fixed.ilog2.*` (4114, including 64 powers and 4096
reference comparisons), `c10.fixed.h0.*` (1005), `c10.fixed.zerofrac` (1),
`c10.constants.section44_45` (1), `c10.boundaries.invariants` (407 over 37
fixtures × 11 scales), `c10.boundaries.scale_sweep` (37),
`c10.changepoints.reference` (37), `c10.tree.partition/containment/nonempty_leaves/root/depth_bound/reference`
(37 each), `c10.tree.single_leaf` (6), `c10.determinism.threads` (33),
`c10.determinism.merge_order` (1), `c10.effort.*` (3),
`c10.errors.*` (6), `c10.limits.bounded_buffer` (5),
`c10.pinned.constructed` (6), `c10.names.independent` (1),
`c10.isolation.*` (5).

Two runs to different `--out-root` produce byte-identical TSV, log and manifest;
the ASan+UBSan gate run reproduces all three; CI asserts all of that with
`diff -u` and additionally greps the log for host/date/compiler/pid/timing text.

### 4.2 Partition and tree (S1–S3)

37 fixtures: M-CORE (empty, 1 byte, 2 bytes, 63 zeros), M-EDGE (12 lengths ×
{zeros, random}: 64, 65, 127, 255, 256, 257, 4095, 4096, 4097, 8191, 8192, 8193),
M-SCALE (zeros 1 MiB, random 1 MiB, random 1 MiB+1, random 2 MiB+12345, tile 4096
1 MiB, gradient 1 MiB, text 1 MiB), M-CHANGE (the §12.3 shape at 1 MiB, plus an
alternating 4 KiB stressor).

For every fixture the gate checks: leaves tile `[0, L)` with no gap and no
overlap; every internal node's children tile it exactly and stay inside it; every
leaf is non-empty except the single `[0, 0)` leaf of the empty input; the root is
`[0, L)` at depth 0; `depth < 11`; a node's level is exactly one finer than its
parent's; and the whole tree equals an independent §4.6 build over independently
computed boundary sets.

Largest observed case: `change-1MiB` → 60 756 nodes, 45 657 leaves, max depth 10.

### 4.3 Thread count and completion order (S5)

Do the four required runs per §12.4 step 4 — `segment` twice at 1 thread and
twice at 4 — as the baseline, plus 2, 3 and 8 workers and a repeat of each, on
every fixture of at least 1 KB. All of them are compared as rendered trees and as
leaf digest strings, and the requirement is that all are byte-identical to the
1-thread run. `segment_parallel(…, 0, …)` is defined as one worker, and the
1-worker path is literally the same worker-function code as the sharded path, so
a 1-thread run cannot differ by construction.

The merge itself is checked separately (`c10.determinism.merge_order`): the leaf
vector ascends strictly by begin offset at 1, 4 and 8 workers, which a
completion-order merge would violate on a 1 MiB fixture. Structurally, every unit
of work writes its own result slot and the concatenation is serial and ordered;
the first error returned is the one of the lowest job index, so even a failing run
reports the same code at any worker count.

### 4.4 Effort (§4.10)

`active_scales` implements the table: effort 0–2 → `{64 B, 4 KiB, 256 KiB}` =
levels `{0, 3, 6}`; effort 3–9 → all eleven. Effort 10–255 is `Invalid`.

Evidence that effort changes the *set of scales*, never a boundary: at all ten
efforts, `B_64` on `change-1MiB` is byte-identical, and every effort's tree still
partitions and unions correctly. This is stronger than "the values agree" — it
shows the detector and the fine scale are effort-independent, as §4.10 requires
("Effort never changes exactness. It changes which observations exist, never their
values").

### 4.5 Errors (§9)

| Condition | Code | Evidence row |
|---|---|---|
| provenance digest / length / gear / seed does not match the source | `Mismatch` | `c10.errors.mismatch` |
| declared length exceeds what the medium can serve | `Io` | `c10.errors.io` |
| a read fails mid-pass (first block, second block) | `Io` | `c10.errors.io` |
| effort outside 0..9 | `Invalid` | `c10.errors.invalid` |
| `boundaries_for_scale` target not a power of two in `[4, 2^60]` | `Invalid` | `c10.errors.invalid` |
| internal contract (non-monotone union, unsound tree) | `Invalid` | §3.4, not reachable in evidence |
| boundary/tree cap exceeded | `Limit` | not reachable on the §12.3 corpus |

An error never returns a partial value: the tree out-parameter is written only
after a sound tree exists, and `c10.errors.no_partial_output` asserts it is
untouched when the call fails.

### 4.6 Locality of the measurement

`c10.limits.bounded_buffer` records `max_request` and the call count per fixture
at the finest scale: the largest request is one 64 KiB block and is strictly below
the input for every fixture larger than a block, so no pass materialises the
input (E4 §11). The change-point scan reads `L + W` bytes by sliding one `2W`
buffer; `copy_object`-free, single-buffer, no whole-input array.

---

## 5. Specification readings and decisions

Where the normative text admitted more than one reading, the narrowest reading
consistent with the pseudocode and the invariants was taken. Each is recorded here
because a later change to any of them re-runs E4-G (§13.2).

1. **`Limit` added to `MeasureCode`.** §9 names a `Limit` row ("observation count
   or range cap exceeded"), but C09's enum had only `Ok/Io/Mismatch/Invalid`.
   `Limit = 7` is the project-wide value (`SPECS/COMPONENTS-V2.md` §2), added
   without changing any existing value. This is the only edit to a file outside
   C10's own paths; it is additive, C09's TSV and log are unchanged, and the
   workflow asserts both the value table and that C09 is still green.

2. **A cut is recorded only when `i + 1 < L`.** §4.5 cuts at `i+1` *and* emits
   `L` unconditionally. When a cut lands on `L` both would emit the same position,
   and `B_T` is "strictly increasing". Dropping the redundant cut is the only
   reading under which the sentence is true; the gear reset still happens there.

3. **`L <= 64` is a single leaf, not an eleven-node chain.** §4.4 says "both
   boundary sets are `{0, L}` and the tree is a single leaf"; §4.6 applied
   literally to eleven identical boundary sets would build a chain of eleven nodes
   with the same interval. §4.4 is the more specific rule (it names the tree), so
   a single node at level 0 and depth 0 is emitted. Both the library and the gate's
   independent reference implement this, and `c10.tree.single_leaf` pins it.

4. **The empty input's boundary set is `{0}`.** `{0, L}` with `L = 0` is `{0}` as
   a set. Keeping the duplicate would violate "strictly increasing" and would
   make S1 (`[0,0)` exactly once) unrepresentable. S3 explicitly asks for "one
   zero-length leaf `[0,0)`", which this produces.

5. **`level = k` is the index into `kScales`, not into the effort's active list.**
   Otherwise the same node would mean different scales at different efforts, and
   S4 ("depends only on bytes, `SCALES`, and the fixed constants") would fail for
   a value that is part of the output. Effort selects *which* levels appear; it
   never renumbers them.

6. **Change points belong to level 0 and are added to `B_64` before dedup**, then
   deduped against the gear set. Level 0 is active at every effort in the §4.10
   table, so this is effort-independent in practice; had a future table dropped
   64 B, the code skips the detector rather than attaching change points to a
   scale that is not 64 B.

7. **The cap is truncation, not an error.** §4.5 says "if the cap is exceeded,
   keep the first ones in increasing offset order". That is specified behaviour,
   so reaching the cap is not `Limit`; `Limit` is reserved for the implementation's
   own safety ceilings (`kMaxBoundaries`, `kMaxTreeNodes`), which are far above
   anything the §12.3 corpus can reach and exist so a pathological input is a
   reported code rather than an allocation failure.

8. **`Mismatch` is checked before any boundary is computed.** §5.2's precondition
   is "`prov` matches `source`". Computing boundaries over unverified bytes and
   then reporting `Mismatch` would mean the measurement described bytes nobody
   identified, so the re-verification pass runs first and the result is discarded
   on mismatch.

9. **`Source::read` must fill the whole destination**, per §4.1's contract, so a
   1-byte-at-a-time reader that returns `Io` for a larger request is a *violating*
   source, not a different read shape. S4 (bytes only) is therefore evidenced by
   (a) agreeing results across two independent buffers with the same bytes, and
   (b) the bounded-request measurement — not by a source that contradicts §4.1.

10. **Change points are not filtered by proximity to a gear boundary.** §4.5
    dedups change points among themselves within 2048 bytes; it says nothing about
    merging a change point into an existing `B_64` boundary. The union keeps both
    (a set has no duplicates), and on `M-CHANGE` the change point at `262144`
    coincides with a gear boundary without any special case.

11. **`ilog2_q24(0) = 0`.** §4.2 defines the function for `x >= 1`; the entropy
    accumulator never evaluates it at 0 and skips zero counts anyway. The
    out-of-domain value is 0 rather than an error because the function returns
    `u64` in §8 and cannot report one; the gate asserts the value so no caller
    relies on something undocumented.

12. **`__extension__ unsigned __int128`.** §4.2 requires a 128-bit intermediate.
    The project builds with `-pedantic -Werror`, which rejects `__int128` unless
    the extension is spelled explicitly; a `#error` guards the case where the type
    does not exist, so the alternative is never a silently narrowed sum.

13. **`std::thread` is permitted in C10 and only C10.** §11 says "all parallel work
    is read-only; merge is serial and ordered", and S5 requires thread-count
    independence to be *measurable*. The workflow's environment check therefore
    excludes `std::thread` for this component, while still rejecting clock, locale,
    randomness, file-system, and file-name access. C09's stricter list is
    unchanged.

---

## 6. Limitations and handoff to C11 / E4-G

**What C10 proves.** Boundaries and the tree are exact functions of the bytes,
`SCALES`, the fixed constants, and the effort's scale selection; the leaves
partition the input; the tree is its own witness for S2; and both are identical at
1, 2, 3, 4 and 8 workers and across repeated runs. The fixed-point primitives agree
with an independently written 128-bit implementation on 4114 `ilog2` comparisons
and 1005 `H0` comparisons.

**What C10 does not prove, and does not claim.**

* It does not claim C11 `PROBE`. No `Observation` type exists in this binary, and
  `segment()` does not call a probe.
* It does not claim **E4-G**. The integrated gate still needs the full §12.3 corpus
  (`M-NEAR`, `M-LFSR`, `M-MIX`, `M-TRANSPOSE`, `M-BITPLANE`, `M-NAME`'s symlink),
  `corpus.tsv` / `segments.tsv` / `observations.tsv`, the locality mutation
  campaign (step 8), and coverage counters across every `ProbeKind`.
* It does not prove segmentation is optimal, minimal, or useful for selection
  (§12.7), nor that the change-point thresholds are statistically correct. They
  are format constants pinned so the gate is reproducible.
* It does not exercise the `Limit` path: the caps are `2^22` boundaries and `2^23`
  nodes, above anything the bounded corpus reaches. A future corpus that large
  would need a deliberate cap test.
* Inputs whose length does not fit a `u64` offset are reported as `Invalid`
  rather than segmented. This is a documented implementation bound; the §12.3
  corpus is under 20 MiB and the §11 resource statement is `O(leaves)` memory at
  corpus scale.
* The `2^26` (64 MiB) target never *fires* on a 1–2 MiB fixture: `B_{2^26}` is
  `{0, L}` there and contributes a single-node level. That is correct and is
  exactly the case §4.6's "single child with the same interval" exists for, but it
  means the coarsest scales are exercised as pass-through levels rather than as
  cut levels. E4-G's corpus has the same property; a dedicated large fixture would
  be needed to exercise them as cut levels.

**Handoff to C11.** C11's `probe(source, segment, policy)` takes a `Segment`.
C10's leaves are the natural input, they are already sorted by begin offset and
contiguous, and `segment()` returns them with `level = 0`. C11 must not move a
boundary (E4-I8): the boundary rule names no probe, and the C10 test binary
contains no probe symbol, so the independence is structural rather than a
convention. C11 will need `ilog2_q24`, `h0_q24_from_counts`, `zero_frac_q24` and
`kScales` from this header — they are exported precisely so C11 does not
re-derive them and drift.

**Handoff to E4-G.** `segments.tsv` needs, per fixture, every segment's
`(begin, end, depth, level)` and the SHA-256 of the serialised tree. The gate
already produces exactly that: `tree_text` is the serialisation, `tree_digest`
its SHA-256, and the log records both per fixture, plus a leaf-vector digest. What
E4-G adds is the full corpus, the `M-NAME` symlink, the shuffled-completion-order
repeat (step 10 — C10 covers the worker-count half), and the cross-component
tables.

---

## 7. Acceptance checklist (C10 prompt §8)

- [x] Builds warning-free; tests pass; no regressions. — `make -f Makefile.c10 c10-all`
      under `-Werror -Wconversion -Wshadow -Wformat=2`; 24/24 tests plain and
      ASan+UBSan; C09 rebuilt and re-gated in CI at the same commit; all 13
      evidence manifests verify.
- [x] `segment` produces deterministic boundaries and a segment tree per
      §4.4–§4.6 (S1–S5); leaves partition input. — 37 fixtures, 11 scales,
      independently audited, plus an independent §4.6 reference build.
- [x] 1-vs-4 thread and repeated runs byte-identical. — `c10.determinism.threads`
      over every fixture ≥ 1 KB at 1, 2, 3, 4 and 8 workers, twice each; plus
      `c10.determinism.merge_order`.
- [x] Change points / fixed-point logic per spec; no FP; no dependence on
      probes/filename/type. — `c10.changepoints.reference`,
      `c10.fixed.ilog2.*`, `c10.fixed.h0.*`, `c10.fixed.zerofrac`,
      `c10.names.independent`; `std::log2` absent by isolation check.
- [x] No E2–E7 linkage; no term/candidate emission. — `c10.isolation.*`, plus
      `nm` on the object and on the test binary, plus `static_assert`s on the
      return type.
- [x] Evidence/log/manifest/report committed and matching the final green CI run.
- [x] `REPORT/E4/C10-SEGMENT-REPORT.md` committed.

**Not claimed:** C11 `PROBE`; the integrated **E4-G**.
