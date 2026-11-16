# C09 — PROVENANCE — End-to-End Prompt (Local-first, CI-validated)

**Work item:** C09 `PROVENANCE` (exact input identity, streaming digests, deterministic seed), sub-component 1 of 3 of **E4 MEASURE** (MARP v2).  
**Repository/workspace:** You have the full MARP project workspace (complete repo, specs, history, reports). Work inside that project.  
**Base:** Start from the latest **`h2-gates`** head (E1/E2/E3-G PASS/frozen as required; H3 `oracle.f00-f08` and H4 green). Do **not** reimplement H1/H2/H3/H4 or E1–E3 semantics except minimal, justified integration fixes kept green in CI.  
**Depends on (frozen/required):** **E0-G, E1-G** required (E1 `DIGEST`/`ARITH`); gate ordering requires **E2-G** PASS. **E4 MUST NOT link E2–E7 code** (use E1 surfaces for SHA-256/gear/arithmetic). **No E5–E7 behavior.**  
**Language:** C++20 only. No Python. No third-party libraries beyond GoogleTest (tests) and what the project already uses.  
**Required outcome:** C09 is complete only when its **acceptance checklist is satisfied by a green GitHub Actions CI run** with implementation, tests, harness-written evidence/log/manifest, and report committed and pushed. **E4-G is not claimed complete** by this prompt alone (C10, C11 and integrated E4-G remain).

You are an autonomous agent with shell, file, git, and GitHub CLI access. Work independently. If the spec is ambiguous, choose the narrowest interpretation consistent with the normative text, implement it, and record the decision in the report.

> **Ordering:** C09 → C10 → C11 → E4-G. C10 (`segment`) takes `(source, provenance, policy)`; implement C09 first.

---

## 1. Mission
Implement **C09 PROVENANCE**: establish the deterministic identity of an input `Source` before anything is inferred.

1. **Exact identity:** compute exact byte `length` (`BigInt`), streaming **SHA-256** of the whole input, **gear hash** of the whole input (E1 gear, seed 0), and deterministic **effort seed**.
2. **Seed (normative):** `seed = LE64(SHA-256("MARP2-seed" ‖ LE32(effort) ‖ sha256(x))[0..8))` — pure function of bytes and effort only (never time, address, pid, host, thread count).
3. **Streaming/single pass:** provenance computed in **one streaming pass** (hash and gear roll simultaneously); **do not materialise** the whole input. Re-reading a range returns identical bytes (Source contract).
4. **Determinism:** same bytes + effort ⇒ identical `Provenance` on any host/run/thread count.

C09 observes identity only. It must **not** build terms/candidates/observations, segment, probe, parse wire, or depend on file name/extension/media type.

---

## 2. Normative requirements (MARP2-E4, §4.1, §4.3, §5.1, §6, §8–§9)
- **Types/surface (align with project):**
  ```cpp
  struct Provenance { BigInt length; std::array<u8,32> sha256; u64 gear, seed; };
  Result<Provenance> provenance(Source&, const Policy&);
  ```
- **Source:** finite, exact length `L ∈ ℕ`, readable by offset; `read` deterministic, no clock/filename/env.
- **Errors:** unreadable/short read => `Io`; provenance mismatch vs source (where checked) => `Mismatch`. No throw/panic.
- **Invariants:** E4-I1 (determinism of provenance), E4-I11 (re-read identical) apply; no global mutable state.
- **No FP/locale/clock/random.**

---

## 3. Execution model (local test + CI validation)
- **Local-first:** build/test locally (`make`, `g++`, sanitizers).
- **CI-authoritative:** final acceptance requires a **green GitHub Actions run** on your pushed branch with committed, harness-generated evidence/log/manifest/report. Push, fix, repeat until green.
- **Isolation:** isolated paths/workflow/targets (e.g. `engine/Makefile.c09` or e4 targets, `.github/workflows/e4-c09.yml`, `specs_and_reports/v2/gates/C09-PROVENANCE.tsv`, `specs_and_reports/v2/logs/C09-PROVENANCE.log`, `specs_and_reports/v2/evidence/C09/`, `REPORT/E4/C09-PROVENANCE-REPORT.md`). Do not break H1–H4/E1–E3/C03–C08/E2-G/E3-G workflows or evidence.

---

## 4. Deliverables (follow repo conventions)
```text
include/mapr/e4/... or engine/include/...      (Provenance/Source/Policy interfaces as needed)
engine/src/e4/...                             (provenance implementation)
engine/tests/e4/...                           (tests)
engine/Makefile.c09 (or isolated e4 targets)
.github/workflows/e4-c09.yml
specs_and_reports/v2/gates/C09-PROVENANCE.tsv
specs_and_reports/v2/logs/C09-PROVENANCE.log
specs_and_reports/v2/evidence/C09/SHA256SUMS
REPORT/E4/C09-PROVENANCE-REPORT.md
```
Build strict: `-Werror -Wconversion -Wshadow -Wnull-dereference -Wdouble-promotion -Wformat=2`. No build artifacts committed.

---

## 5. Test strategy and evidence (C09-focused)
- **Correctness:** `length`, `sha256`, `gear`, `seed` match independent E1/H1 references and known vectors/fixtures (incl. empty, 1 byte, deterministic corpus cases as available).
- **Seed:** pure function of bytes+effort (same bytes different effort differs as specified; same bytes+effort identical across runs).
- **Streaming:** no whole-input materialisation required (verify by design/tests on chunked reads); re-read consistency respected.
- **Determinism:** repeated runs identical.
- **Evidence:** harness-written TSV/log/manifest committed. Record environment, commands, counts, PASS/FAIL/BLOCKED.

---

## 6. Relationship to E4-G (do not overclaim)
- **C09 complete:** provenance API/implementation and C09 evidence green in CI.
- **Not complete:** C10 SEGMENT, C11 PROBE, integrated **E4-G** (partition/1-vs-4 segmentation identity, observation reproducibility/locality/coverage, rename independence) — follow in later prompts.

---

## 7. Report (`REPORT/E4/C09-PROVENANCE-REPORT.md`)
Include: (1) Environment/base/branch/CI run ID+URL, (2) Files changed/added (no E2–E7 linkage, no regressions), (3) API/implementation and seed/digest details, (4) Test/evidence results and determinism, (5) Spec readings/decisions, (6) Limitations and handoff to C10.

---

## 8. Acceptance checklist (green in CI)
- [ ] Builds warning-free under required flags; tests pass; no regressions.
- [ ] `provenance` returns exact `length`, whole-input SHA-256, gear (seed 0), and seed per spec; one streaming pass, no whole-input materialisation.
- [ ] Seed/outputs deterministic (bytes+effort only); correct vs references.
- [ ] No E2–E7 linkage; no term/candidate emission; no filename/type dependence.
- [ ] Evidence/log/manifest/report committed and matching final green CI run.
- [ ] `REPORT/E4/C09-PROVENANCE-REPORT.md` committed.

**Work until the checklist is satisfied by a green CI run with committed evidence/report, or a genuine blocker is proven and documented.**
