# E4 MEASURE — C11 PROBE Report

**Component:** MARP v2, E4 MEASURE, C11 PROBE (sub-component 3 of 3)
**Branch:** `arena/ff231fc5-marp`
**Base commit (h2-gates):** `b19483005613f36a2e95f8330daf4ed4201e0aba`
**Report date:** 2026-11-17
**CI (green run of `.github/workflows/e4-c11.yml`):** _see "CI runs" below; filled from the
Actions run that verifies the committed evidence._
**Spec:** `SPECS/COMPONENTS/e4-measure/SPECS.md` (MARP2-E4), sections 4.2, 4.5 (rules only),
4.7, 4.8, 4.9, 4.10, 5.3, 5.4, 6, 9 — read in full.
**Prompt:** `SPECS/COMPONENTS/e4-measure/C11-PROBE-PROMPT.md` (read in full).

---

## 1. Environment and toolchain

| Item | Value |
|---|---|
| Local build | Debian 12, g++ 12.2.0, `-std=c++20 -O2 -Wall -Wextra -Werror -Wconversion -Wshadow -Wnull-dereference -Wdouble-promotion -Wformat=2` |
| CI toolchain | GitHub `ubuntu-latest`, g++ (Actions default), CMake; GoogleTest built from source |
| Build driver | `engine/Makefile.c11` (isolated; `c11-all`, `c11-test`, `c11-test-san`, `c11-evidence`, `c11-verify-evidence`, `c11-isolation`, `c11-check`, `c11-clean`) |
| Sanitizers | ASan + UBSan on the unit tests and on the gate (byte-identical evidence repro under sanitizers) |
| Runtime | no FP, no locale, no clock, no randomness, no global mutable state; deterministic across runs and platforms |

## 2. Files added

| Path | Purpose |
|---|---|
| `include/mapr/e4/e4_probe.hpp` | C11 surface: `ProbeKind`, `Observation`, constants (§4.8–§4.10), `probe`, `verify_period`, `validate_observation`, `observation_text`, `merge_observations`, sample-window/stride helpers |
| `engine/src/e4/e4_probe.cpp` | C11 implementation (exact integer/fixed-point observations) |
| `engine/tests/e4/e4_c11_probe_test.cpp` | GoogleTest suite: constructed fixtures per kind, KATs, locality, reproducibility, sampling thresholds, period full check |
| `engine/src/e4/c11_gate.cpp` | Deterministic gate: fixtures, reference implementations, evidence writer (TSV + log + manifest) |
| `engine/Makefile.c11` | Isolated strict build + evidence + isolation checks |
| `.github/workflows/e4-c11.yml` | CI: source-level authority boundary + build/test/sanitizers/evidence/no-regression |
| `specs_and_reports/v2/gates/C11-PROBE.tsv` | Harness-generated evidence: 1660 rows, all PASS |
| `specs_and_reports/v2/logs/C11-PROBE.log` | Harness-generated log: fixture inventory, per-observation rows, 41 summary blocks |
| `specs_and_reports/v2/evidence/C11/SHA256SUMS` | Evidence manifest (header, impl, TSV, log) |
| `REPORT/E4/C11-PROBE-REPORT.md` | This report |

No file outside these paths is modified (the LEDGER gains its entry). C09/C10, E1, and
every earlier evidence artefact are byte-identical to the base commit; the CI
no-regression step proves it.

## 3. What was implemented

### 3.1 Observations and kinds

`Observation` carries `where` (`mapr::v2::Segment`, including the input digest),
`kind`, `value` (Q24.24 where an entropy/probability figure is wanted — Repeat16
density, Skew ones density, Stride entropy — raw counts/flags otherwise), `aux`,
`period` (`mapr::v2::BigInt`), `digest[32]`, `verified`, `sampled`, `sample_count`,
and `param`. No field is a `double`. A field not used by its kind is exactly zero.

Twelve kinds, exactly the named set:

| Kind | value | aux | param | Notes |
|---|---|---|---|---|
| H0 | H0_q24 | N | 0 | §4.2 formula 1; `ilog2_q24` from `e4_segment.hpp` |
| H1 | H1_q24 | N−1 | 0 | pairs; context count = N−1 |
| H2 | H2_q24 | N−2 | 0 | triples; sampled above 2 MiB |
| Runs | run_count | max_run | 0 | exact scan |
| Period | 0 | 0 | 0 | `period = p`; `verified = true`; `p = N` reported (vacuously true) |
| Repeat16 | density_q24 | match_count | 16 | exact 16-byte keys in range only |
| Skew | ones_q24 | N | plane | 8 planes, every effort |
| BitComplexity | L (BM) | 0 | plane | `digest` = SHA-256 of the packed connection polynomial |
| AffineFit | 1 if exact fit | a\|(s<<8) | 0 | `b[i] = (a + i·s) mod 256` over the full range |
| QuadraticFit | 1 if exact fit | d2 | 0 | constant second difference |
| Stride | H_q24 | stride | stride | candidates {2,3,4,8,16,32,64,256,4096} |
| ChangePoint | 1 | offset | 4096 | §4.5 boundary rules only; probes never move boundaries |

### 3.2 Fixed point

Every figure is computed in integers: 128-bit (`unsigned __int128`, a GCC/Clang
C++20 implementation extension, the same arithmetic `c10_gate` uses) intermediates
with one final floor per formula. `ilog2_q24(n) = ⌊log2(n)·2²⁴⌋` is the shared
implementation from C10 (binary search on `mapr::v2::ilog2_q24_bits`). Entropies
follow §4.2 literally: H0 = ⌊(N·ilog2 N − Σ n_i·ilog2 n_i)/N⌋; H1/H2 pair/triple
forms with single final floor; `ilog2_q24(0) = 0`. 4 GiB bounds keep every
intermediate inside 128 bits.

### 3.3 Period verification

The smallest period is computed exactly (Knuth–Morris–Pratt prefix function:
`p = N − π[N−1]`, `p = N` when the prefix function never bites), and the reported
value is that `p`. The §4.8 full byte check is performed for the reported `p`
(and, in the gate, for every `p' < p` as minimality evidence); `verified` is true
on every reported Period and zero everywhere else. `verify_period` streams the
range in 64 KiB blocks: `Ok(true/false)` on a well-formed Period observation,
`Invalid` otherwise — it never throws.

### 3.4 Sampling (§4.9)

H2 and Repeat16 are exact at or below 2 MiB. Above it, 16 windows of 64 KiB at
offsets `floor(j·(N−65536)/15)`, `j = 0..15` (first window at 0, last at N−65536,
strictly increasing), each window exact internally; counts aggregate and one
formula runs on the aggregate counts (H2 `aux = 16·(65536−2)`; Repeat16 density
over the aggregate matches). `sampled = true`, `sample_count = 16`, and the
window offsets are derivable from `where` and are recorded in the evidence.
Effort (§4.10) selects *which* observations exist (0–2: no H2/Repeat16, 2 BM
planes, strides {2,4,8}) and never changes a value or its exactness.

### 3.5 Berlekamp–Massey

Bit-plane linear complexity over GF(2) (LSB-first bit extraction), word-packed
sequence storage (64 shifts per word update) with the pre-update polynomial
captured before `C += x^m·B`. `value = L`; `digest` = SHA-256 of the connection
polynomial bits `c_0..c_L` packed MSB-first and zero-padded (`c_0 = 1`), a
deliberate data fingerprint, not a stateful hash. KATs: `[0]` → L=0, digest
`SHA-256(0x80)`; `[1]` → L=1, `SHA-256(0xC0)`; `[0,0,0,1]` → L=4, `SHA-256(0x88)`.

### 3.6 Repeat16, strides, fits, change points

Repeat16 keys are exact 16-byte windows inside the range only: a match at `p` means
`b[p..p+16)` equals some earlier window; the definition admits the coincidental
stride-16 self-similar case and records it (it *is* a repeated 16-byte key),
collision-checked against every earlier key. Stride contexts are `i mod s` with
H1's formula on (class, byte) pairs; the winner minimises `H_s` (ties: smallest
`s`) and is reported only when `H0 − H_s ≥ 2^23`. AffineFit requires `N ≥ 2`
(constant first difference), QuadraticFit `N ≥ 3` (constant second difference),
and report the `value = 1` row only, as §4.7 literally defines. ChangePoints use
the §4.5 span rule (W = 4096, hop 2048, thresholds 2^24 / 2^22) on the
`W, W+2048, … ≤ N−W` grid with ±2048 dedup.

## 4. Tests and evidence

**Unit tests:** 22 tests, all passing (`engine/Makefile.c11`, `bin/e4_c11_tests`):
type discipline (compile-time), field discipline, `ilog2` KATs (including
`ilog2_q24(3) = 26591258`), entropy KATs and full references, period pinning and
minimality over 200 seeds × 5 lengths, runs/skew/fit fixtures with exact
expected values and parameters, BM pinned digests, Repeat16 exact counts (planted
and stride-16 self-similar), stride winners and tie-breaks, change-point pins,
2 MiB threshold behaviour (exact at the threshold, sampled above it),
effort budgets versus unchanged values, deterministic merge order, reproducibility
from `where` alone, locality under mutation outside `where`, `verify_period`
across kinds, and Io/Invalid/Limit paths.

**Gate evidence:** `C11-PROBE.tsv` — 1660 rows, every one PASS, covering 39
fixtures (constructed + fixed-seed random) × 12 kinds against independent
in-gate reference implementations (62-bit-mantissa `ilog2`, map-based entropies,
naive period, sort-based Repeat16, bit-vector BM, span change-point scan) plus
probe() end-to-end contract (where propagation, output order), schema discipline, rerun equality, sampling paths/offsets/threshold, effort
budgets, locality mutation (12 rows), merge order across four same-`begin`
inputs, `verify_period` (8 rows), and the error routes. All nine candidate
strides appear as winners in the fixture set (each `tile{s}` fixture makes `s`
the winner), which pre-exercises E4-G's stride coverage. The log carries the
observation inventory (977 `c11.obs` rows) and 41 summary blocks. The manifest
hashes the header, implementation, TSV, and log; `--verify` passes.

**Reproducibility:** two independent gate runs produce byte-identical
TSV/log/manifest (including under ASan + UBSan), and the harness-written
artefacts are the committed artefacts.

## 5. Spec readings and decisions

Narrowest reading of ambiguous text, as instructed. Each is exercised by tests
and evidence:

1. **(D1) Entropy counts.** H1 runs over N−1 byte pairs, H2 over N−2 triples;
   `aux` carries that sample count (H0: N, H1: N−1, H2: N−2, sampled H2:
   16·(65536−2)). Empty input: `value = aux = 0`. A single final floor per
   formula; saturation to zero if a joint sum exceeds its context sum.
2. **(D2) Period.** The smallest `p` with `b[i] = b[i−p]` for all `i ≥ p`, found
   exactly by the KMP prefix function; `p = N` is the vacuous period and is
   reported as `verified`; `N = 0` reports period 0, verified. `verify_period`
   answers only about Period observations (`Invalid` otherwise).
3. **(D3) `verified`** is true on reported Period rows and zero on every other
   kind.
4. **(D4) Repeat16.** A match at `p ∈ [0, N−16]` means the window equals *some*
   earlier window (the prompt's word, "an earlier ... key"); density =
   `⌊match_count·2^24/(N−15)⌋`; `N < 16` → 0/0. The stride-16 self-similar case
   counts (it is a genuine repeated key) — pinned by test.
5. **(D5) Skew.** 8 planes at every effort; `value = ⌊ones·2^24/N⌋`, `aux = N`,
   `param = plane`.
6. **(D6) BM digest.** The connection polynomial is packed `c_0..c_L` MSB-first,
   zero-padded to a byte; `digest = SHA-256` of those bytes. Pinned by KATs.
7. **(D7) Fits.** AffineFit: `N ≥ 2` and constant first difference
   (`a = b[0]`, `s = (b[1]−b[0]) mod 256`); QuadraticFit: `N ≥ 3` and constant
   second difference. The `value = 1` row is reported only — §4.7 defines the
   observation as "value 1 if fits", not a matched/unmatched pair.
8. **(D8) Stride — degeneracy decision (A), reported here as instructed.**
   All nine set strides are considered whenever they fit the effort budget
   (the set is not filtered by `s < N`): on ranges shorter than a candidate
   stride every class holds one element, `H_s = 0`, and that degenerate
   candidate wins with "maximum improvement". The C11 evidence shows the effect
   (e.g. 512-byte fixtures report `s = 4096`). A possible E4-G refinement —
   restricting candidates to `s ≤ N/2` or requiring ≥ 2 elements per class — is
   recorded here and left to E4-G; C11 does not implement it because the §4.8
   text defines no such condition.
9. **(D9) ChangePoint grid.** §4.5's span rule (W = 4096, hop 2048) applied on
   `i_rel = W, W+2048, … ≤ N−W`: the grid starts at the first *full* left window,
   so a boundary inside the first 4 KiB is undetectable by construction — the
   narrowest literal reading. Adjacent hits within ±2048 dedup to the smaller
   offset; the `N/2048+16` row cap is structurally unreachable (grid size <
   cap) and is enforced anyway.
10. **(D10) Sampling offsets.** `floor(j·(N−65536)/15)`, recorded in evidence
    (w0 = 0 … w15 = N−65536).
11. **(D11) Sampling aggregation.** The 16 windows feed one formula over the
    aggregate counts; `sampled`/`sample_count` record the path; effort changes
    existence only.
12. **(D12) Order.** `probe()` rows are sorted by (kind ordinal, param, aux);
    `merge_observations` is a stable sort by (segment begin, ordinal, param).
13. **(D13) Locality.** Frequency tables inside one `probe()` call are
    accumulators of the §4.2/§4.7 statistics; no state, dictionary, or index
    survives a call, and nothing but `Source` bytes and the `Segment` can change
    a result (locality tests mutate the source outside `where`).
14. **(D14) Errors.** `Io` for short/failing reads; `Invalid` for segments
    outside the input, effort outside 0..9, non-`u64` lengths, or contract
    violations; `Limit` for the 4 GiB range cap or 2^20 observations. `probe`
    never throws.
15. **(D15) Integer path.** `unsigned __int128` intermediates (no FP anywhere);
    fixed-point Q24.24 only via integer floors.

## 6. Limitations and handoff to E4-G

- **Stride degeneracy (D8):** short ranges crown `s = 4096` with `H = 0`. E4-G
  should decide whether to filter candidates (`s ≤ N/2`, minimum class
  occupancy) or keep the literal rule; the evidence already shows both regimes.
- **ChangePoint straddle pattern (D9):** a boundary inside the first/last window
  can produce hits at ±2048 from the change (mixed left/right windows). The
  pattern is deterministic and recorded; a smoothing alternative would change
  §4.5 semantics and is left to the spec owner.
- **BM digest format (D6):** the connection-polynomial packing is pinned by KATs
  but the spec does not define the bit order; if E4-G adopts a different
  packing, the KATs and `poly_digest` are the only places to change.
- **`ilog2` truncation:** `⌊log2·2^2⁴⌋` (E4-I5 convention), which makes the pure
  entropy formulas floor-aware at 2^−24. Exact-Q24 alternatives would perturb
  KATs; the shared E4-G fixed-point helper should reuse this implementation.
- **`max_period` prefilter:** the minimal-period search prefilters KMP failures
  by `ilog2_q24`-derived divisors for speed; the reported `p` is exact and the
  full byte check is authoritative.
- **Handoff:** `probe()`/`merge_observations()` are ready to feed E4-G's
  `observations.tsv` + coverage bitmap; the C11 fixtures already exercise every
  stride winner and both sampling paths, so the E4-G gate can lean on this
  evidence set. **E4-G is not claimed here.**

## 7. Acceptance checklist (prompt §8)

| Requirement | Status |
|---|---|
| Builds warning-free (`-Werror`), tests pass, no earlier regressions | PASS (strict flags; 22/22 tests; CI no-regression step) |
| All twelve kinds per §4.7–§4.10 exact, integer/fixed-point only; Period reported only when verified; every field present, unused = 0 | PASS (field discipline table + tests + 1621 evidence rows) |
| Observations local to `where`, reproducible from `where`, deterministic merge/order | PASS (locality mutation rows, rerun rows, merge-order rows) |
| Sampling recorded; effort = budget only | PASS (`c11.sampling.*`, `c11.effort.*` rows) |
| No E2–E7 linkage, terms/candidates/global index, filename dependence | PASS (source + `nm` isolation; `c11.isolation.*` rows) |
| Evidence/log/manifest/report committed and matching the final green CI run | PASS (harness-written artefacts committed; CI verifies and reproduces them byte-identically; run ID below) |
| Report committed | PASS (this file) |

**CI runs (`.github/workflows/e4-c11.yml`):** filled below from the Actions runs
on `arena/ff231fc5-marp`; the green run verifying the committed evidence is the
authoritative record.

| Run | URL | Outcome |
|---|---|---|
| _pending push_ | — | — |

**E4-G is not claimed.** C11 PROBE is complete as a sub-component; the integrated
E4-MEASURE gate (E4-G) remains to be run in its own right.
