# C10 — SEGMENT — End-to-End Prompt (Local-first, CI-validated)

**Work item:** C10 `SEGMENT` (deterministic multi-scale boundaries and segment tree), sub-component 2 of 3 of **E4 MEASURE** (MARP v2).  
**Repository/workspace:** You have the full MARP project workspace (complete repo, specs, history, reports). Work inside that project.  
**Base:** Start from the latest **`h2-gates`** head (assumes **C09 PROVENANCE** landed/green or available per integration state; E1/E2/E3-G frozen). Do **not** reimplement H1–H4 or E1–E3/C09 semantics except minimal, justified fixes kept green in CI.  
**Depends on:** **E1** (arithmetic/digests/ilog2 helpers as needed), **C09** (`Provenance`, `provenance()` context). **E4 MUST NOT link E2–E7.** Gate ordering requires **E2-G**. No E5–E7 behavior.  
**Language:** C++20 only. No Python. No third-party libraries beyond GoogleTest (tests) and what the project already uses.  
**Required outcome:** C10 is complete only when its **acceptance checklist is satisfied by a green GitHub Actions CI run** with implementation, tests, harness-written evidence/log/manifest, and report committed and pushed. **E4-G is not claimed complete** by this prompt alone.

You are an autonomous agent with shell, file, git, and GitHub CLI access. Work independently. If the spec is ambiguous, choose the narrowest interpretation consistent with the normative text, implement it, and record the decision in the report.

> **Ordering:** C09 → **C10** → C11 → E4-G. `segment` takes `(source, provenance, policy)` and must not depend on probe results.

---

## 1. Mission
Implement **C10 SEGMENT**: cut the input into deterministic boundary sets and a **segment tree** (pure function of bytes, fixed scales/constants, and policy/effort as specified).

1. **Scales/constants (§4.4):** `SCALES = {2^6..2^26}` (64 B..64 MiB); for target `T`: `mask=T-1`, `min_chunk=T/4`, `max_chunk=4*T`. For `L <= 64`, boundaries `{0,L}` and single leaf.
2. **Content-defined boundaries (§4.5):** for each `T`, left-to-right gear-rolling with cut at `(len>=min_chunk && (h&mask)==0)` or `len>=max_chunk`; emit `L`. `B_T` includes `0,L`, strictly increasing, depends only on bytes and `T`.
3. **Change points (§4.5):** added to `B_64` before dedup — windows `W=4096`, hop `2048`; interior boundary `i` if `dH0 >= 2^24` (1.0 bit, Q24.24) or `dZ >= 2^22` (0.25, zero-frac Q24); cap at `L/2048 + 16` (keep first in increasing offset order); dedup within 2048 bytes keeping smaller offset. Constants/thresholds/cap are fixed format constants.
4. **Segment tree (§4.6):** build top-down from coarsest; `build(a,b,k,depth)` emits `Segment{begin,end,depth,level=k}`; if no finer boundary inside, single child with same interval at next level; recursion stops at `k==0` (leaf). Invariants S1–S5 must hold.
5. **Determinism/merge:** boundaries/tree independent of thread count and completion order; parallel work merged by segment begin offset (and as specified) — serial-identical.

C10 measures structure boundaries only. It must **not** build terms/candidates, emit observations, index cross-segment, or be influenced by probe results/file metadata.

---

## 2. Normative requirements (MARP2-E4, §4.4–§4.6, §4.10, §5.2, §5.4, §6, §8–§9)
- **Surface (align with project):**
  ```cpp
  struct Segment { BigInt begin, end; u32 depth; u8 level; };
  Result<std::vector<Segment>> segment(Source&, const Provenance&, const Policy&, std::vector<Segment>* tree = nullptr);
  ```
- **Invariants:** S1 leaves partition `[0,L)` exactly (sorted, contiguous, no gap/overlap); S2 node = union of children; S3 non-empty leaf `begin<end` (empty input => one `[0,0)`); S4 depends only on bytes, `SCALES`, fixed constants; S5 independent of thread count/completion order. E4-I1,E4-I3,E4-I8,E4-I9,E4-I11,E4-I12 apply.
- **Fixed-point (no FP):** `ilog2_q24`, `H0_q24`, zero-frac Q24 as defined (§4.2, §4.5) using integer/128-bit intermediates; KAT-pinned where specified.
- **Effort:** selects scales/probe budget context per §4.10 (scales set by effort level as specified); effort never changes exactness of boundaries/values produced.
- **Errors:** `Io` unreadable/short; `Mismatch` if provenance does not match source (where checked); `Invalid` segment outside input / non-monotone boundaries (internal contract); `Limit` caps exceeded as specified. No throw/panic.

---

## 3. Execution model (local test + CI validation)
- **Local-first:** build/test locally (including 1-vs-4 thread determinism checks).
- **CI-authoritative:** green GitHub Actions run with committed harness-generated evidence/log/manifest/report. Push/fix until green.
- **Isolation:** isolated paths/workflow/targets (e.g. `engine/Makefile.c10`, `.github/workflows/e4-c10.yml`, `specs_and_reports/v2/gates/C10-SEGMENT.tsv`, `specs_and_reports/v2/logs/C10-SEGMENT.log`, `specs_and_reports/v2/evidence/C10/`, `REPORT/E4/C10-SEGMENT-REPORT.md`). No regressions to prior components/workflows.

---

## 4. Deliverables (follow repo conventions)
```text
include/mapr/e4/...
engine/src/e4/...
engine/tests/e4/...
engine/Makefile.c10 (or isolated e4 targets)
.github/workflows/e4-c10.yml
specs_and_reports/v2/gates/C10-SEGMENT.tsv
specs_and_reports/v2/logs/C10-SEGMENT.log
specs_and_reports/v2/evidence/C10/SHA256SUMS
REPORT/E4/C10-SEGMENT-REPORT.md
```
Strict flags, no build artifacts committed.

---

## 5. Test strategy and evidence (C10-focused)
- **Partition/tree:** leaves partition `[0,L)` exactly; node/child containment; depth/level/monotonicity; empty and edge lengths.
- **Determinism:** 1-vs-4 threads and repeated runs produce byte-identical boundary vectors/trees (merge by offset, completion order irrelevant).
- **Correctness:** content-defined cuts, change-point insertion/cap/dedup behavior on constructed cases (e.g. sharp boundary sensitivity per spec intent), fixed-point computations match references/KATs as applicable.
- **Evidence:** harness-written TSV/log/manifest committed (commands, counts, PASS/FAIL/BLOCKED).

---

## 6. Relationship to E4-G (do not overclaim)
- **C10 complete:** segmentation/tree implementation and C10 evidence green in CI.
- **Not complete:** C11 PROBE, integrated **E4-G** (full corpus, observation reproducibility/locality/coverage, rename independence) — follow in later prompts.

---

## 7. Report (`REPORT/E4/C10-SEGMENT-REPORT.md`)
Include: (1) Environment/base/branch/CI run ID+URL, (2) Files changed/added, (3) Boundary/change-point/tree implementation and constants, (4) Determinism/partition results, (5) Spec readings/decisions, (6) Limitations and handoff to C11/E4-G.

---

## 8. Acceptance checklist (green in CI)
- [ ] Builds warning-free; tests pass; no regressions.
- [ ] `segment` produces deterministic boundaries and segment tree per §4.4–§4.6 (S1–S5); leaves partition input.
- [ ] 1-vs-4 thread and repeated runs byte-identical.
- [ ] Change points/fixed-point logic per spec; no FP; no dependence on probes/filename/type.
- [ ] No E2–E7 linkage; no term/candidate emission.
- [ ] Evidence/log/manifest/report committed and matching final green CI run.
- [ ] `REPORT/E4/C10-SEGMENT-REPORT.md` committed.

**Work until the checklist is satisfied by a green CI run with committed evidence/report, or a genuine blocker is proven and documented.**
