# H4 — FUZZ — End-to-End Prompt (Local-first, CI-validated)

**Work item:** H4 `FUZZ` (mutation/fuzz campaign over valid v2 containers), E0 sub-component of MARP v2.  
**Repository/workspace:** You have the full MARP project workspace (complete repo, specs, history, reports). Work inside that project.  
**Base / prerequisite (blocking):** Start from the latest **`h2-gates`** head only after **E3-G is merged and green** with committed, CI-authoritative evidence (C07 WIRE + C08 LEGACY integrated; E3-G PASS). **H4 is blocked on E3** — do **not** run or claim H4 PASS before E3-G is satisfied. Use E3-produced valid canonical wires (and/or canonical E3 fixtures/corpus artifacts committed by E3-G) as seeds.  
**Language:** C++20 only (harness/tooling). No Python committed. No third-party libraries beyond GoogleTest (tests) and what the project already uses.  
**Required outcome:** H4 is complete only when the **H4 acceptance checklist is satisfied by a green GitHub Actions CI run**, with harness-written evidence/log/manifest/report committed and pushed. Do not declare done on a red run except a proven, documented external blocker.

You are an autonomous agent with shell, file, git, and GitHub CLI access. Work independently. If the spec is ambiguous, choose the narrowest interpretation consistent with the normative text, implement it, and record the decision in the report.

---

## 1. Mission
Mutate valid v2 containers and count what escapes verification/decoding (per `SPECS/SPECS-V2.md` §12.8, `SPECS/COMPONENTS-V2.md` H4, E0-G/V2-G9 intent):

1. **Seeds:** use small valid canonical v2 containers plus header/index mutations of large containers, so 100,000 mutants finish in bounded time. Seeds must come from **E3-valid/canonical outputs** (E3-G corpus/fixtures/wires) — never from non-canonical or hand-guessed bytes except spec-derived deterministic mutations of valid seeds.
2. **Mutations:** apply bit flips, truncation, field swaps, and length/count/offset corruption (and equivalent container mutations) to produce mutants.
3. **Execution:** feed every mutant to v2 **verify** and **decode** paths (C07/E3 APIs and/or the product/verification entry points as appropriate and available) with per-mutant bounds/timeouts so runs complete in bounded time.
4. **Accounting:** count `total`, `accepted_invalid`, `crashes`, `timeouts`, and `valid` decodes/verifications as applicable. Record each category clearly and reproducibly.
5. **Target (hard):** over **100,000 mutants**: `accepted_invalid = 0`, `crashes = 0`, `timeouts = 0`.

H4 is a **harness** component (measurement). It must not change E1–E7 semantics; any discovered engine/oracle bug is fixed at the source with evidence, not by weakening the harness.

---

## 2. Execution model (local test + CI validation)
- **Local-first allowed:** build, run, and iterate locally (`make`, `g++`, sanitizers, smaller trial campaigns) to debug quickly.
- **CI is authoritative:** final acceptance must be proven by **GitHub Actions** on your pushed branch. Push, run the H4 workflow, fix failures, and repeat until green. Completion requires a **green CI run ID and URL** with matching committed evidence.
- **Bounded runtime:** design the campaign (seed sizes, mutation mix, per-mutant timeout/limits) so CI completes in bounded time while still reaching 100,000 mutants and covering header/index/field/truncation classes.
- **Validate by push:** commit/push, trigger/watch CI (`gh`), ensure committed evidence/report correspond to the green run.

---

## 3. Non-negotiable rules
1. **C++20 only** in the repository. No Python or scripts committed.
2. **Prerequisite enforced:** H4 may be implemented/scaffolded, but **PASS/acceptance requires E3-G green** and valid E3 seed availability. Do not claim H4 complete without satisfying the 100k campaign on CI.
3. **No weakening:** do not suppress crashes/timeouts/accepts by skipping mutants, loosening checks, or narrowing mutation classes beyond spec intent. Every mutant is accounted for.
4. **Deterministic/reproducible harness:** record seed source identities (paths/digests), mutation seed/PRNG seed, mutant counts, and configuration so results are reproducible from committed inputs/config.
5. **Isolation:** do **not** break or regress H1/H2/H3, E1, E2, E2-G, C03–C06, C07, C08, or E3-G implementations/evidence/workflows except additive, compatible fixes if strictly necessary and fully justified (document and keep CI green). Use isolated H4 paths (e.g. `engine/Makefile.h4` or harness targets, `.github/workflows/h4-fuzz.yml`, `specs_and_reports/v2/gates/H4-FUZZ.tsv` or as specified by harness conventions, `specs_and_reports/v2/logs/H4-FUZZ.log`, `specs_and_reports/v2/evidence/H4/`, `REPORT/HARNESS/H4-FUZZ-REPORT.md`).
6. **Safety:** mutants must never cause unbounded allocation/hangs in the harness; enforce per-mutant resource/timeout limits and report violations as `timeouts`/failures per spec (target zero).
7. **No build artifacts committed**. **Honest reporting:** never claim PASS without green CI + committed generated evidence.

---

## 4. Spec-derived behavior (normative intent)
- **Mutation classes (§12.8):** bit flips, truncation, field swaps, length corruption. Include header/index mutations, especially for/derived from large containers (without requiring full large-container processing per mutant where bounded handling suffices).
- **Targets:** 100,000 mutants total; `accepted_invalid = 0`, `crashes = 0`, `timeouts = 0`.
- **Subjects:** `verify` and `decode` (and range/decode paths as applicable) must reject malformed/non-canonical mutants per E3/C07 contract (no accepted-invalid). Valid decodes, if any, must correspond to genuinely valid containers only.
- **Evidence alignment:** support V2-G9-style reporting expectations where applicable (`accepted_invalid`, crashes, hangs/timeouts = 0 over 100,000) in harness records.

---

## 5. Deliverables (isolated paths — follow repo conventions)
```text
harness/fuzz/... or harness/src/fuzz...       (H4 implementation: mutators, runner, accounting)
engine/Makefile.h4 (or isolated harness targets)
.github/workflows/h4-fuzz.yml
specs_and_reports/v2/gates/H4-FUZZ.tsv        (or project-conventional gate/evidence path)
specs_and_reports/v2/logs/H4-FUZZ.log
specs_and_reports/v2/evidence/H4/SHA256SUMS
REPORT/HARNESS/H4-FUZZ-REPORT.md
```
- Integrate with existing E3/C07 verify/decode surfaces and committed E3-G seed artifacts; do not duplicate E3 logic.
- Workflow: build, run 100k campaign (bounded), emit evidence/log/manifest, upload artifact (`if: always()`), hard-fail on unmet targets.

---

## 6. Test strategy and evidence
- **Campaign:** run full 100,000-mutant campaign in CI with recorded seed list/digests, mutation seed, mutation mix, and per-mutant limits.
- **Sanity:** include deterministic small dry-runs/tests (subset) in unit tests if useful; CI must still prove the full campaign.
- **Failure handling:** any accepted-invalid/crash/timeout is a hard failure — diagnose, fix root cause (engine/harness as appropriate), re-run until targets met; document fixes.
- **Evidence:** harness-written TSV/log/manifest committed (no hand-edited measured values). Must include at minimum: total mutants, accepted_invalid, crashes, timeouts, valid, verdict, seed/config identifiers, and log path. `RESULT: PASS` only when targets hold and evidence exists.

---

## 7. Report (`REPORT/HARNESS/H4-FUZZ-REPORT.md`)
Include: (1) Environment/base commit/branch/worktree/authoritative CI run ID+URL, (2) Prerequisite proof (E3-G green/merged, seed sources/digests), (3) Files added/changed and integration points (confirm no regressions), (4) Mutation classes/mix, seed strategy, per-mutant limits/timeouts, (5) Campaign results (counts, categories, determinism/repro notes), (6) Bugs found/fixed (if any) with evidence, (7) Evidence summary and manifest, (8) Known limitations.

---

## 8. Acceptance checklist (must be green in CI)
- [ ] E3-G prerequisite satisfied and cited (merged/green with committed evidence); valid E3 seeds identified by digest/path.
- [ ] Builds warning-free under required flags on CI; H4 tests pass (if any); no regressions to H1/H2/H3/E1/E2/E2-G/C03–C06/C07/C08/E3-G.
- [ ] Full 100,000-mutant campaign executed in CI with recorded configuration.
- [ ] `accepted_invalid = 0`, `crashes = 0`, `timeouts = 0` (all mutants accounted for).
- [ ] Evidence/log/manifest/report generated, committed, and matching the final green CI run.
- [ ] `REPORT/HARNESS/H4-FUZZ-REPORT.md` committed.

Any unchecked item means not done.

**H4 is the next harness after E3, but it may be executed/claimed complete only after E3-G is green. Work until the checklist is satisfied by a green CI run with committed evidence/report, or a genuine blocker is proven and documented.**
