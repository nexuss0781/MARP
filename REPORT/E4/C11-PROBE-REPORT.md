# C11 `PROBE` — Implementation Report (E4 MEASURE)

**Scope:** C11 `PROBE`, sub-component 3 of 3 of E4 `MEASURE` (MARP v2). This
report claims **C11 only**. The integrated **E4-G** gate is **not** claimed and
is not affected by this work. E4-G is not claimed complete by this document.

**Sources:** `SPECS/COMPONENTS/e4-measure/SPECS.md` (MARP2-E4) §4.2, §4.7–§4.10,
§5.3–§5.4, §6–§9, §11, §12.5; `SPECS/SPECS-V2.md` §6.2 (M1);
`SPECS/COMPONENTS-V2.md` §6 C11 and the project code table in its §2;
`MARP/SPECS/COMPONENTS/e4-measure/C11-PROBE-PROMPT.md`.

---

## 1. Environment, base, branch, CI

| Field | Value |
|---|---|
| Repository | `nexuss0781/MARP` |
| Branch | `arena/3ece593e-marp` |
| Base commit | `b19483005613f36a2e95f8330daf4ed4201e0aba` (`h2-gates` HEAD at branch time) |
| Local toolchain | `g++ (Debian 12.2.0-14+deb12u1) 12.2.0`, GNU Make 4.3, 2 vCPU |
| CI toolchain | `ubuntu-latest`, GCC from `build-essential`, GoogleTest built from source at CI time |
| Build flags | `-std=c++20 -pedantic -Wall -Wextra -Werror -Wconversion -Wshadow -Wnull-dereference -Wdouble-promotion -Wformat=2 -O2` |
| Sanitizer flags | same warnings, `-O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined -fno-sanitize-recover=all` |
| Locally observed gate result | `rows=651 pass=651 blocked=0 fail=0` — `RESULT: PASS` |
| Locally observed unit tests | 52/52 GoogleTest cases pass (plain and ASan+UBSan builds) |
| CI workflow | `.github/workflows/e4-c11.yml` — `MARP E4 C11 PROBE CI` |

The workflow `MARP E4 C11 PROBE CI` is the authoritative CI run for this work:
independence and E4 authority boundary (source level), strict `-Werror` build,
isolation, 52/52 GoogleTest, determinism of the reproducibility/merge/effort
suites, byte-for-byte evidence regeneration, schema/verdict/check/log-hygiene
validation, independent repeat, ASan+UBSan, and no-regression (C09 and C10
re-built and re-gated green at the same commit, every evidence manifest
verified).

---

## 2. Files added or changed

C11 is **purely additive**: no frozen E1/E2/E3 header or source, no `harness/**`
file, no C09 or C10 file, and no earlier gate TSV or log was modified.

| Path | Role |
|---|---|
| `include/mapr/e4/e4_probe.hpp` | New. C11 surface: `ProbeKind` (12 kinds), `Observation`, `Policy`, the §4.8/§4.9/§4.10 constants, `probe`, `verify_period`, `merge_observations`. |
| `engine/src/e4/e4_probe.cpp` | New. All 12 probes, the fixed-point entropy core, the sampling policy, `verify_period`, and the serial merge. |
| `engine/src/e4/c11_gate.cpp` | New. The evidence harness (`engine/bin/c11_gate`), with references written separately from the specification. |
| `engine/tests/e4/e4_c11_probe_test.cpp` | New. 52 GoogleTest cases (§5). |
| `engine/Makefile.c11` | New. Isolated build: E1 + C09 + C10 + C11, plus sanitizer, shuffled, evidence and isolation targets. |
| `.github/workflows/e4-c11.yml` | New. Isolated workflow: independence, build, tests, determinism, evidence regeneration, schema validation, sanitizers, no-regression. |
| `specs_and_reports/v2/gates/C11-PROBE.tsv` | New. 651 evidence rows, all `PASS`. |
| `specs_and_reports/v2/logs/C11-PROBE.log` | New. Fixed banner + 79 deterministic log lines, 48 check summaries. |
| `specs_and_reports/v2/evidence/C11/SHA256SUMS` | New. Manifest of the header, the implementation, the TSV and the log. |
| `REPORT/E4/C11-PROBE-REPORT.md` | This report. |
| `LEDGER.md` | One appended section recording the C11 outcome. |

### Linkage: what C11 is built from

| Linked | Why |
|---|---|
| `engine/src/e1_bigint.cpp` | `Segment::begin/end` and `Observation::period` are exact `BigInt`; `BigInt` arithmetic underpins every position. |
| `engine/src/e1_sha256.cpp` | The BitComplexity digest is SHA-256 of the documented payload. |
| `engine/src/e1_gear.cpp` | Transitive: C09/C10 dependency chain. |
| `engine/src/e4/e4_provenance.cpp` | C09: `Source`, `MeasureCode`, `Provenance` — the read contract and the error codes. |
| `engine/src/e4/e4_segment.cpp` | C10: `Segment`, `ilog2_q24`, `h0_q24` — the shared fixed-point core and the segment type. |

### No regressions

No frozen component or earlier evidence file was touched. All 14
`evidence/*/SHA256SUMS` manifests verify from the tree at this commit. C09 and
C10 are re-built and re-gated by the workflow's no-regression step.

---

## 3. Probe implementation

### 3.1 Surface

`ProbeKind` enumerates the twelve kinds in §4.7 order: `H0, H1, H2, Runs,
Period, Repeat16, Skew, BitComplexity, AffineFit, QuadraticFit, Stride,
ChangePoint`. `Observation` carries the full field set of §4.7 — `where`,
`kind`, `value`, `aux`, `period`, `digest[32]`, `verified`, `sampled`,
`sample_count`, `param` — with every field the kind does not use zeroed (checked
by the gate's `c11.probe.fields`). `probe(source, segment, policy)` returns
`MeasureResult<std::vector<Observation>>`; `verify_period` returns
`MeasureResult<bool>`; `merge_observations` is the serial merge.

### 3.2 Fixed point (§4.2)

`ilog2_q24(x) = floor(log2(x) · 2^24)` is computed by 24 exact squarings of a
62-bit mantissa in a `__extension__ unsigned __int128`. `H0` is the Q24.24
entropy `Σ n_i · ilog2_q24(n_i) / N` from exact 128-bit sums with one final
floor division. No `std::log2`, no floating point, no locale. The gate's
`c11.fixed.ilog2.*` checks cover 14 known values, all 64 powers of two,
monotonicity, a completeness sweep, and an independent reference.

### 3.3 The twelve probes (§4.8)

- **H0** (always): the order-0 entropy of the range; `aux = N`.
- **H1** (always): order-1 bigram entropy, exact via a 256×256 count table;
  `aux = N − 1`.
- **H2** (effort ≥ 3): order-2 trigram entropy via a 24-bit-key open-addressing
  table; `aux = N − 2` on the exact path.
- **Runs** (always): run count (`value`) and maximum run length (`aux`).
- **Period** (non-empty): the smallest `p` with `b[i] == b[i−p]` for all
  `i ≥ p`; `period = p`, `verified = true` (the full check passes). `p = N` is
  the trivial period and is reported verified. An observation with
  `verified = false` is never emitted.
- **Repeat16** (effort ≥ 3, `N ≥ 16`): exact 16-byte keys in an open-addressing
  table with collision checking; `value = density_q24(matches, positions)`,
  `aux = matches`.
- **Skew** (always, planes 0..7): the Q24.24 density of ones in each bit plane;
  `param = plane`, `aux = N`.
- **BitComplexity** (effort-selected planes, `N ≤ 8192`): Berlekamp–Massey
  over GF(2) per plane; `value = L`, `digest = SHA-256(LE64(L) ‖ packed
  c_1..c_L)` with coefficients LSB-first within each byte. Effort 0–2 selects
  2 planes, effort 3–9 selects 8.
- **AffineFit** / **QuadraticFit** (non-empty): exact predicates over the full
  range; a fit emits `value = 1`, `aux = a | (s << 8)` (affine) or the quadratic
  witness.
- **Stride** (non-empty): the best stride of the effort's set
  (`{2,4,8}` for effort ≤ 2, `{2,3,4,8,16,32,64,256,4096}` for effort ≥ 3)
  whose conditional entropy lowers `H0` by at least `2^23`; ties choose the
  smallest stride. `value = H_s`, `aux = param = stride`.
- **ChangePoint**: emitted exactly when `segment.begin > 0` is a boundary
  inserted by the §4.5 change-point detector; `value = 1`, `aux = begin`.

### 3.4 Sampling (§4.9)

`H2` and `Repeat16` are exact for ranges `≤ 2 MiB`
(`kSampleExactMaxBytes = 2 << 20`). Above that, both use 16 windows of 64 KiB
at offsets `floor(j · (N − 65536) / 15)`, with counts aggregated across
windows. The observation records `sampled = true`, `sample_count = 16`,
`param = 65536` (window size), and the aux counts the sampled trigrams/keys —
so the sample path is recorded and never claims a full-range observation
(`c11.sampling.path`).

### 3.5 Effort (§4.10)

Effort selects the probe budget: the stride set, the BitComplexity plane
count, and the presence of H2/Repeat16. Effort never changes the exactness of
any produced value; `c11.effort.budget_and_values` and the test suite check
this directly. Effort outside 0..9 is `Invalid`.

### 3.6 Errors (§9)

`Io` for unreadable or short reads; `Invalid` for an out-of-domain effort, a
segment outside the input, a period present with `verified = false`, or a
contract violation; `Limit` for a range above 64 MiB or more than 4096
observations. No throw, no floating point, no locale, no clock, no randomness,
no global mutable state.

### 3.7 Locality and determinism (E4-I2, I3, I7, I8, I10, I12)

An observation depends only on the bytes in `where` and the recorded
parameters. Observations never move boundaries. The merge of parallel results
is by segment `begin` offset, then `ProbeKind` ordinal, then `param` — a
serial ordered concatenation, so completion order cannot reach the output.
`c11.names.independent` proves the probe never sees a label: five different
file names over the same 256 KiB slice produce byte-identical observations.

---

## 4. Evidence

### 4.1 Artefacts

`engine/bin/c11_gate --root ..` writes, deterministically:

- `specs_and_reports/v2/gates/C11-PROBE.tsv` — 651 rows in the v2 eight-column
  schema, all `PASS`, sorted by (check, corpus, item_id).
- `specs_and_reports/v2/logs/C11-PROBE.log` — a fixed 8-line banner plus
  79 `stable_sort`-ed note lines and 48 check summaries; no host name, date,
  compiler, pid, timing or absolute path.
- `specs_and_reports/v2/evidence/C11/SHA256SUMS` — the manifest of the header,
  the implementation, the TSV and the log.

The gate's references are written from the specification text, independently of
the implementation: the entropy core, the stride sweep, the Berlekamp–Massey
transcription, the fit predicates, the sampling policy and the change-point
decision are all re-derived in `c11_gate.cpp`.

### 4.2 Check groups (48)

`c11.fixed.ilog2.*` (5), `c11.fixed.h0.*` (3), `c11.bm.*` (4),
`c11.probe.*` (12: structure, fields, h0, h1, h2, runs, period, repeat16,
skew, bitcomplexity, affinefit, quadraticfit, stride, changepoint, fits — 15
with structure and fields), `c11.sampling.path` (1),
`c11.constants.sampling_effort_caps` (1), `c11.period.*` (3),
`c11.change.*` (2), `c11.order.*` (2), `c11.effort.*` (1),
`c11.errors.*` (5), `c11.names.independent` (1), `c11.isolation.*` (5).

---

## 5. Specification readings and decisions

1. **Stride class-size constraint.** §4.8 defines the Stride conditional
   entropy as the aggregate order-1 entropy under `i mod s` with a `2^23`
   improvement threshold, and names no constraint between `s` and `N`. With
   `s > N/2` some residue classes hold 0 or 1 sample, and the floored-log
   plug-in estimator returns `H_s = 0` trivially, so any large stride "wins"
   on random data — a degenerate reading that makes the stride observation
   meaningless. The implementation, the gate reference and the test reference
   therefore all require every residue class to hold at least two samples
   (`s ≤ N/2`). This is recorded as an implementation constraint on the
   degeneracy; the smallest admissible stride still wins ties.

2. **Plug-in estimator bias at small class sizes.** The floored-log
   plug-in estimator is biased downward for classes with few samples. At
   `s = 256` over 512 random bytes (2 samples/class) the bias can exceed the
   `2^23` threshold, so a stride observation can be reported on random data.
   This is a known property of the estimator the specification prescribes, not
   an implementation defect; the `StrideAbsentWhenImprovementZero` test uses a
   constant-byte input (improvement exactly 0) for the absence case, and
   `StrideMatchesReferenceOnRandom` checks the probe against the independent
   reference sweep on random data.

3. **BitComplexity digest.** The digest is SHA-256 of the documented payload
   `LE64(L) ‖ packed c_1..c_L` (coefficients LSB-first within each byte).
   Coefficients cannot be recovered from a SHA-256 digest, so the gate's
   generation check uses the reference BM's coefficients, not the digest bytes.

4. **Berlekamp–Massey update order.** In the branch where `2L ≤ t`, the
   auxiliary polynomial `B` must be set to the **old** `C` before `C` is
   updated. The gate's first reference transcription saved `C` after the
   update, which produced wrong linear complexities; it was fixed to the
   standard order and the gate agrees with the implementation and the test
   reference on every fixture.

5. **Observation field budget.** `Observation` carries the full §4.7 field
   set; unused fields are zeroed. The gate's `c11.probe.fields` re-checks this
   across every observation of every fixture.

6. **Merge order.** Parallel results merge by segment `begin` offset, then
   `ProbeKind` ordinal, then `param`. This is a total order on the
   observation set, so the merge is deterministic regardless of completion
   order.

7. **`p = N` period.** The check `b[i] == b[i−p]` for all `i ≥ p` passes
   vacuously at `p = N`, so `Period` reports `p = N` with `verified = true`
   for any range. This is the specification's own definition applied literally.

8. **Sampled aux counts.** On the sampled path, `aux` counts the trigrams or
   16-byte keys actually sampled (16 windows), not the full range. The
   observation records `sampled = true` and `sample_count = 16`, so the
   aux count is interpretable only together with those fields.

9. **`Io` mid-read.** A source that fails on the first read, or declares more
   than it holds with the segment read past its end, returns `Io`; the gate's
   `FailingSource`/`TruncatingSource` fixtures exercise both.

10. **No global state.** The library holds no global mutable state; every
    probe is a pure function of its `Source`, `Segment` and `Policy`.

---

## 6. Limitations and handoff to E4-G

- **C11 proposes observations only.** It emits no terms, candidates, nodes or
  atoms, maintains no cross-segment or global dictionary, classifies no atoms,
  and never branches on a file name, extension or media type. The integrated
  **E4-G** gate remains to be claimed.
- **The plug-in entropy estimator is biased at small class sizes** (see
  reading 2). This is inherent to the estimator §4.8 prescribes; the stride
  class-size constraint (reading 1) removes the trivial degeneracy but not the
  bias.
- **BitComplexity is capped at 8192 bytes** per the documented range cap; the
  observation set is bounded by the 64 MiB range cap and the 4096-observation
  cap of §9.
- **E4-G** should build on C11's `probe` surface: it consumes observations per
  segment and never asks C11 to move a boundary or emit a term.

---

## 7. Acceptance checklist (C11 prompt §8)

- [x] Builds warning-free; tests pass; no regressions.
- [x] All probe kinds implemented per §4.7–§4.10 with exact fields/semantics;
      no FP; period only when fully verified.
- [x] Observations local to `where`, reproducible from recorded range/params,
      deterministic merge.
- [x] Sampling rules recorded correctly; effort affects budget not exactness.
- [x] No E2–E7 linkage; no terms/candidates/global index; no filename/type
      dependence.
- [x] Evidence/log/manifest/report committed and matching the final green CI
      run.
- [x] `REPORT/E4/C11-PROBE-REPORT.md` committed.
