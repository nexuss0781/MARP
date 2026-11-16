# E4-G — MEASURE Gate — End-to-End Prompt (Local-first, CI-validated)

**Work item:** E4-G, the integrated gate for **E4 MEASURE** (MARP v2) — closes E4 after C09, C10, C11 are complete.  
**Repository/workspace:** You have the full MARP project workspace (complete repo, specs, history, reports). Work inside that project.  
**Base:** Start from the latest **`h2-gates`** head that includes **C09 PROVENANCE, C10 SEGMENT, C11 PROBE** merged/green (or integrate them as part of this work only if necessary, with each meeting its obligations). E1/E2/E3-G frozen; H3 oracle available.  
**Depends on (required):** **E0-G, E1-G, E2-G** PASS with evidence (surfaces frozen). **H3 independent oracle** available for fixed-point/period/stat checks as required. **No E3/E5/E6/E7 code linked into E4.**  
**Language:** C++20 only. No Python. No third-party libraries beyond GoogleTest (tests) and what the project already uses.  
**Required outcome:** E4-G is complete only when the **E4-G gate condition is satisfied by a green GitHub Actions CI run** with implementation/harness, gate-written evidence/logs/corpora/manifests, and report committed and pushed. **E4-G freezes E4.**

You are an autonomous agent with shell, file, git, and GitHub CLI access. Work independently. If the spec is ambiguous, choose the narrowest interpretation consistent with the normative text, implement it, and record the decision in the report.

> **This is the gate that makes E4 green.** C09–C11 prompts deliver components; E4-G delivers the integrated, measured PASS.

---

## 1. Mission (gate condition, §12.2)
On the measurement corpus: segmentation at 1 and 4 threads is **byte-identical** and yields an **exact partition**; every observation reproduces **bit-for-bit** from its recorded byte range and parameters; identical bytes under different names/extensions produce identical output; every verified period passes a full independent byte check; observations are **local** to their ranges; and every probe kind, bit plane, and sample path is exercised. **One mismatch fails the gate.**

---

## 2. Execution model (local test + CI validation)
- **Local-first:** iterate locally (build, run gate, debug 1-vs-4 determinism/locality/repro).
- **CI-authoritative:** green GitHub Actions run with matching committed evidence/logs/corpora/manifests/report is required. Push/fix until green.
- **Bounded runtime:** corpus is bounded by spec (<20 MiB materialised) — CI must complete in bounded time.
- **No partial pass:** one failure/missing coverage/missing evidence fails the gate (§12.6). No tolerance/retry/partial pass.

---

## 3. Normative requirements (implement/verify per MARP2-E4 §12, §4–§11)
- **Preconditions (§12.1):** E0-G/E1-G/E2-G PASS; H3 oracle available; no E3/E5/E6/E7 linked into E4. If unmet => BLOCKED (never PASS).
- **Corpus (§12.3):** generate deterministically with fixed seed and record SHA-256 for every fixture (`corpus/E4/corpus.tsv`): `M-CORE` (5), `M-EDGE` (9), `M-ZERO` (1 MiB), `M-TEXT` (1 MiB), `M-TILE` (1 MiB, period 4096), `M-TILE+1` (1 MiB, period 4097), `M-GRAD` (1 MiB), `M-COUNT` (1 MiB), `M-LFSR` (1 MiB), `M-RAND` (1 MiB), `M-NEAR` (1 MiB, 10×100 KiB, 1% mutation), `M-MIX` (5 MiB), `M-CHANGE` (1 MiB: 256K zeros‖256K random‖256K zeros‖256K counter), `M-TRANSPOSE` (1 MiB), `M-BITPLANE` (1 MiB), `M-KAT` (14 ilog2_q24 values), `M-NAME` (same 256 KiB bytes under 4 names/extensions incl. none + 1 symlink).
- **Procedure (§12.4):**
  1. Build E4, oracle, harness with `-O2 -Wall -Wextra -Werror`.
  2. Generate `M-*`, write `corpus.tsv` (id,length,SHA-256).
  3. Provenance vs independent SHA-256/exact length for every fixture.
  4. For every fixture run `segment` twice at threads=1 and twice at threads=4; require all four boundary vectors and trees byte-identical.
  5. Check S1–S5 (partition, containment, monotonicity, depth, level; empty => one `[0,0)`).
  6. Probe every leaf; for every observation re-run on exact `where` with recorded params/sample policy and require identical `value,aux,period,digest,sampled,sample_count,param`; require `where` inside segment and source.
  7. Every `Period` with `verified=true` passes full independent byte check (`b[i]==b[i-p]`, `i>=p`); `verified=false` must not be reported.
  8. **Locality:** mutate one byte outside a selected observation’s range; observation identical (repeat for 100 observations across fixtures).
  9. Compare `ilog2_q24` and entropies against H3 independent integer implementation on `M-KAT` and 1,000 random count vectors.
  10. 1-vs-4 comparison again with merge deliberately shuffled by completion order; identical output.
  11. **Rename independence (V2-G14):** run `provenance`, `segment`, full probes on every `M-NAME` file; outputs identical to the first byte-for-byte.
  12. **Coverage:** every `ProbeKind`, all 8 bit planes, `H2` full and sampled, `Repeat16` full and sampled, every stride in fixed set, ≥1 change point on `M-CHANGE`, ≥1 exact `AffineFit`, `QuadraticFit`, `Period` with `p<N`, and `Runs` maximum — zero counter fails.
  13. `M-CHANGE` yields a change point within 1 MiB of the zero→random boundary.
  14. One row per check; PASS only if every row PASS.
- **Evidence (§12.5):** `specs_and_reports/v2/gates/E4-G.tsv`, `specs_and_reports/v2/logs/E4-G.log`, `specs_and_reports/v2/corpus/E4/corpus.tsv`, `specs_and_reports/v2/corpus/E4/segments.tsv`, `specs_and_reports/v2/corpus/E4/observations.tsv` (+ manifests as needed). `E4-G.tsv` columns: `check  fixture  item_id  input_sha256  expected  actual  verdict  log`. No hand-edited values.
- **Fail conditions (§12.6):** any mismatch/unverified-period error/KAT or oracle mismatch/missing coverage/missing change point/missing evidence/hand-edit/non-zero exit fails (no tolerance/partial pass).

---

## 4. Isolation / non-regression
- No E3/E5/E6/E7 linked into E4; no terms/candidates/cross-segment index emitted.
- Do not break H1–H4, E1–E3, C03–C11, E2-G/E3-G implementations/evidence/workflows except minimal, justified, compatible fixes kept green in CI and documented.
- Isolated gate workflow/targets (e.g. `engine/Makefile.e4` or e4-g targets, `.github/workflows/e4-gate.yml`) without breaking existing workflows. Strict flags, no build artifacts committed.

---

## 5. Deliverables
```text
(engine/include & engine/src & engine/tests for E4 as needed/integrated)
engine/Makefile.e4 or isolated e4-g targets
.github/workflows/e4-gate.yml
specs_and_reports/v2/gates/E4-G.tsv
specs_and_reports/v2/logs/E4-G.log
specs_and_reports/v2/corpus/E4/corpus.tsv
specs_and_reports/v2/corpus/E4/segments.tsv
specs_and_reports/v2/corpus/E4/observations.tsv
specs_and_reports/v2/evidence/E4/SHA256SUMS (and manifests as appropriate)
REPORT/E4/E4-GATE-REPORT.md
```

---

## 6. Report (`REPORT/E4/E4-GATE-REPORT.md`)
Include: (1) Environment/base/branch/authoritative CI run ID(s)+URL(s), (2) Preconditions and component state (C09–C11/H3), (3) Files changed/added and boundary confirmations (no E3/E5–E7 linkage, no regressions), (4) Corpus identities and counts, (5) Results for provenance, 1-vs-4 segmentation/merge determinism, partition, observation reproducibility, period verification, locality (100 cases), oracle/KAT comparisons, rename independence, coverage counters and M-CHANGE sensitivity, (6) Spec readings/decisions/limitations, (7) Evidence summary/manifest, (8) Clear **E4-G PASS** (all rows PASS) or BLOCKED/FAIL with reasons.

---

## 7. Acceptance checklist (CI-authoritative)
- [ ] Preconditions satisfied/recorded; no E3/E5–E7 linked into E4.
- [ ] Builds warning-free; tests pass; no regressions.
- [ ] Corpus generated with recorded SHA-256; provenance correct.
- [ ] Segmentation/trees byte-identical at 1 and 4 threads (and shuffled-merge check), repeated runs identical; S1–S5 hold.
- [ ] Every observation reproduces bit-for-bit from recorded `where`/params; local to range (100 mutations); verified periods pass full byte check, none unverified reported.
- [ ] ilog2/entropy match H3 oracle on M-KAT and 1000 random vectors.
- [ ] Rename independence (M-NAME) holds; coverage complete; M-CHANGE change point within 1 MiB.
- [ ] Evidence/logs/corpora/manifests/report committed and matching final green CI run(s).
- [ ] `REPORT/E4/E4-GATE-REPORT.md` committed stating **E4-G PASS**.

**E4-G is complete only when the gate condition is satisfied by green CI with committed evidence. This freezes E4.**
