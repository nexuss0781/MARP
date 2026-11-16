# C11 — PROBE — End-to-End Prompt (Local-first, CI-validated)

**Work item:** C11 `PROBE` (exact, reproducible observations with recorded evidence ranges), sub-component 3 of 3 of **E4 MEASURE** (MARP v2).  
**Repository/workspace:** You have the full MARP project workspace (complete repo, specs, history, reports). Work inside that project.  
**Base:** Start from the latest **`h2-gates`** head (assumes **C09 PROVENANCE** and **C10 SEGMENT** landed/green or available per integration state; E1/E2/E3-G frozen). Do **not** reimplement H1–H4 or E1–E3/C09/C10 semantics except minimal, justified fixes kept green in CI.  
**Depends on:** **E1**, **C09**, **C10** (`Segment`/tree/leaves). **E4 MUST NOT link E2–E7.** Gate ordering requires **E2-G**. No E5–E7 behavior.  
**Language:** C++20 only. No Python. No third-party libraries beyond GoogleTest (tests) and what the project already uses.  
**Required outcome:** C11 is complete only when its **acceptance checklist is satisfied by a green GitHub Actions CI run** with implementation, tests, harness-written evidence/log/manifest, and report committed and pushed. **E4-G is not claimed complete** by this prompt alone (integrated gate/corpus/coverage remains).

You are an autonomous agent with shell, file, git, and GitHub CLI access. Work independently. If the spec is ambiguous, choose the narrowest interpretation consistent with the normative text, implement it, and record the decision in the report.

> **Ordering:** C09 → C10 → **C11** → E4-G. Probes run on segments; observations depend only on recorded `where` range and parameters (never move boundaries, never emit terms).

---

## 1. Mission
Implement **C11 PROBE**: produce exact, deterministic, fixed-point/integer **observations** per segment with recorded evidence ranges and parameters.

1. **Observations (§4.7):** every observation carries exact `where` (segment/range), `kind`, `value/aux/period/digest/verified/sampled/sample_count/param` per kind; **no floating point**, unused fields zero, no omission. Observation without valid `where` is invalid.
2. **Probe kinds/definitions (§4.8):** implement all specified probes with exact semantics — `H0,H1,H2` (Q24.24 entropies), `Runs`, `Period` (smallest `p` with full byte verification, value in `period`, `verified=true` only when full check passes; `p=N` reported verified), `Repeat16` (exact 16-byte keys, within-range only, collision-checked), `Skew` (per plane 0..7), `BitComplexity` (BM linear complexity per plane, digest as specified), `AffineFit`/`QuadraticFit` (exact predicates over full range), `Stride` (best from `{2,3,4,8,16,32,64,256,4096}` if H0 improvement `>= 2^23`, ties smallest stride), `ChangePoint` (boundary inserted by §4.5). All as normatively defined.
3. **Sampling (§4.9):** `H2` exact for ranges `<= 2 MiB`; above that 16 windows of 64 KiB at specified offsets, aggregate counts, `sampled=true`, `sample_count=16`, window offsets recorded. `Repeat16` same sample policy above `2 MiB`. Sample path is recorded, never claims full-range observation.
4. **Effort (§4.10):** selects probe budget (scales/H2/Repeat16/BM planes/stride set per table); effort never changes exactness of produced values. Gate runs at effort 5.
5. **Locality/determinism:** observation depends only on bytes in `where` and recorded parameters; independent of bytes outside range, thread count, completion order, hash-map iteration, probes do not move boundaries (E4-I2,I3,I7,I8,I10,I12). Merge parallel results by segment begin offset, then `ProbeKind` ordinal, then `param`.

C11 proposes/records measurements only. It must **not** emit terms/candidates/nodes/atoms, maintain cross-segment/global dictionary/index, classify atoms, or branch on filename/extension/media type.

---

## 2. Normative requirements (MARP2-E4, §4.2, §4.7–§4.10, §5.3–§5.4, §6–§9)
- **Surface (align with project):**
  ```cpp
  enum class ProbeKind : u8 { H0,H1,H2,Runs,Period,Repeat16,Skew,BitComplexity,AffineFit,QuadraticFit,Stride,ChangePoint };
  struct Observation { Segment where; ProbeKind kind; u64 value, aux; BigInt period; std::array<u8,32> digest; bool verified, sampled; u32 sample_count, param; };
  Result<std::vector<Observation>> probe(Source&, const Segment&, const Policy&);
  Result<bool> verify_period(Source&, const Observation&);
  u64 ilog2_q24(u64 x);
  ```
- **Period rule:** reported only when `verified=true` (full byte check `b[i]==b[i-p]` for all `i>=p`). `verified=false` must not be reported.
- **Errors:** `Io` unreadable/short; `Invalid` segment outside input, period present with `verified=false`, sample window outside range, contract violations; `Limit` count/range caps. No throw/panic.
- **No FP/locale/clock/random/global mutable state.**

---

## 3. Execution model (local test + CI validation)
- **Local-first:** build/test locally (including reproducibility/locality/period verification checks).
- **CI-authoritative:** green GitHub Actions run with committed harness-generated evidence/log/manifest/report.
- **Isolation:** e.g. `engine/Makefile.c11`, `.github/workflows/e4-c11.yml`, `specs_and_reports/v2/gates/C11-PROBE.tsv`, `specs_and_reports/v2/logs/C11-PROBE.log`, `specs_and_reports/v2/evidence/C11/`, `REPORT/E4/C11-PROBE-REPORT.md`. No regressions.

---

## 4. Deliverables (follow repo conventions)
```text
include/mapr/e4/...
engine/src/e4/...
engine/tests/e4/...
engine/Makefile.c11 (or isolated e4 targets)
.github/workflows/e4-c11.yml
specs_and_reports/v2/gates/C11-PROBE.tsv
specs_and_reports/v2/logs/C11-PROBE.log
specs_and_reports/v2/evidence/C11/SHA256SUMS
REPORT/E4/C11-PROBE-REPORT.md
```
Strict flags, no build artifacts committed.

---

## 5. Test strategy and evidence (C11-focused)
- **Correctness:** each probe kind on constructed fixtures (known periods, affine/quadratic, runs, skew planes, BM/stride/repeat/change points, entropies vs integer KATs/references) with exact expected values/params/digests.
- **Verification/locality:** every verified period passes full byte check; mutating bytes outside `where` leaves observation identical.
- **Reproducibility:** re-running probe on recorded `where`+params yields identical fields; deterministic merge/order.
- **Sampling:** sampled vs exact paths recorded correctly per thresholds.
- **Evidence:** harness-written TSV/log/manifest committed.

---

## 6. Relationship to E4-G (do not overclaim)
- **C11 complete:** probe/observation implementation and C11 evidence green in CI.
- **Not complete:** integrated **E4-G** (full `M-*` corpus, 1-vs-4 segmentation+merge determinism, rename independence, full coverage counters incl. all kinds/planes/sample paths/strides/change point on M-CHANGE, oracle comparisons at gate scale).

---

## 7. Report (`REPORT/E4/C11-PROBE-REPORT.md`)
Include: (1) Environment/base/branch/CI run ID+URL, (2) Files changed/added, (3) Probe implementations (fixed-point, sampling, period/BM/repeat/stride/fit details), (4) Test/evidence results (correctness, locality, reproducibility), (5) Spec readings/decisions, (6) Limitations and handoff to E4-G.

---

## 8. Acceptance checklist (green in CI)
- [ ] Builds warning-free; tests pass; no regressions.
- [ ] All probe kinds implemented per §4.7–§4.10 with exact fields/semantics; no FP; period only when fully verified.
- [ ] Observations local to `where`, reproducible from recorded range/params, deterministic merge.
- [ ] Sampling rules recorded correctly; effort affects budget not exactness.
- [ ] No E2–E7 linkage; no terms/candidates/global index; no filename/type dependence.
- [ ] Evidence/log/manifest/report committed and matching final green CI run.
- [ ] `REPORT/E4/C11-PROBE-REPORT.md` committed.

**Work until the checklist is satisfied by a green CI run with committed evidence/report, or a genuine blocker is proven and documented.**
