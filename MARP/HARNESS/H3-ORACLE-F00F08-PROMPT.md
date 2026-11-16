# H3 — ORACLE F00–F08 Unblock — End-to-End Prompt (Local-first, CI-validated)

**Work item:** Unblock **H3 ORACLE** check `oracle.f00-f08` by producing and recording **F00–F08** cross-check evidence now that **E3 (C07/C08) and E3-G are PASS**.  
**Repository/workspace:** You have the full MARP project workspace (complete repo, specs, history, reports). Work inside that project.  
**Base:** Start from the latest **`h2-gates`** head (includes E3-G closed/merged, H4 merged, current H3 oracle). Create your branch/worktree from `origin/h2-gates`.  
**Depends on (satisfied/required):** **H3 ORACLE** implementation merged and previously green (17 PASS / 1 BLOCKED). **E1/E2/E3-G PASS** with evidence; **C07/E3** can emit/validate/decode v2 canonical wires. **H1 fixtures** / deterministic fixture generation available as specified. **No regression** to any existing H3 check, H3 clean-room isolation, or prior component evidence/workflows.  
**Language:** C++20 only in repo (no Python committed). No third-party libraries beyond GoogleTest and what the project already uses.  
**Required outcome:** `oracle.f00-f08` is **PASS** (not BLOCKED) only when **F00–F08** are emitted as v2 wires via E3, independently decoded/verified by **H3 oracle** byte-exactly against the source fixture bytes/digests with engine-vs-oracle agreement as required, and **all evidence/logs/TSV/manifest/report are updated and committed** with a **green GitHub Actions CI run** proving no regressions. **Do not claim PASS without green CI + committed measured evidence.**

You are an autonomous agent with shell, file, git, and GitHub CLI access. Work independently. If the spec is ambiguous, choose the narrowest interpretation consistent with the normative text, implement it, and record the decision in the report.

---

## 1. Mission
Remove the last H3 blocker:

1. **Identify F00–F08 fixtures (normative, §12.3):**
   - **F00** empty (0)
   - **F01** one byte (`0xA5`)
   - **F02** zeros (1 GiB)
   - **F03** repeated text (1 GiB, repeated 64 KiB text block)
   - **F04** periodic tile (4 GiB, 64 KiB tile × count)
   - **F05** gradient (256 MiB, affine bytes)
   - **F06** counter (1 GiB, affine with step 1)
   - **F07** LFSR (1 GiB, `spec-lfsr` per spec)
   - **F08** grammar (1 GiB, nested repeats and near-duplicates)
   Obtain/generate them **deterministically** per harness/spec (use H1/FIXTURES generators or spec-equivalent deterministic generation already in-repo). Record fixture identity (id, size, SHA-256 of source bytes) in evidence.

2. **Emit v2 wires for F00–F08 using E3 (C07):** for each fixture, produce the canonical v2 wire via the E3 encode path (from the appropriate canonical term/IR or pipeline input as supported by landed components). Record wire bytes/size/SHA-256 and encoding details. Wires must be valid/canonical per E3.

3. **Oracle cross-check (core obligation):** using the **clean-room H3 oracle** (separate from engine), decode/verify each F00–F08 wire and prove **byte-exact reproduction** of the fixture output (`sha256(out)==sha256(in)` / byte-for-byte equality) as applicable. Record engine-vs-oracle agreement and any structural/denotation checks required. Do **not** use engine decode as the oracle; H3 must perform the independent decode/verification.

4. **Unblock `oracle.f00-f08`:** update `specs_and_reports/v2/gates/H3-ORACLE.tsv` so `oracle.f00-f08` is **PASS** with real `input_sha256`, `expected`, `actual`, and log references (remove `BLOCKED: E3 wire producer absent`). Update `specs_and_reports/v2/logs/H3-ORACLE.log` and `specs_and_reports/v2/evidence/H3/SHA256SUMS` (and any H3 evidence artifacts) consistently via the harness/tests — **no hand-edited measured values**.

5. **Preserve H3 integrity:** keep `harness/oracle/**` clean-room (no `mapr/` engine includes, no engine linkage/symbols, no C07/C08 source reuse in oracle). Existing H3 checks must remain PASS. H3 isolation/workflow/Makefile targets remain valid.

---

## 2. Execution model (local test + CI-validated, handle scale)
- **Local-first allowed:** iterate locally (`make -f engine/Makefile.h3`, oracle tests/binaries, targeted F00–F08 runs, sanitizers as feasible).
- **CI is authoritative:** final unblock must be proven by **green GitHub Actions** (H3 oracle workflow and any affected workflows). Commit, push, run/fix until green. Cite the **green run ID(s)/URL(s)** matching committed evidence.
- **Large fixtures (F02–F08 are 256 MiB–4 GiB):** handle deterministically and within CI/resource bounds. Prefer streaming generation/encode/decode, sparse/virtual handling where valid, scratch/temp storage, and recorded hashes over retaining unnecessary intermediates. If a fixture’s full materialisation is infeasible in CI, implement the narrowest spec-consistent, measured approach (e.g. chunked/streamed verification with recorded digests) and **document exactly** what was measured; do not claim byte-exact reproduction you did not verify. (F00/F01 must be trivial.)
- **Determinism:** results must be reproducible from committed inputs/config; re-runs match.

---

## 3. Non-negotiable rules
1. **No regression:** all previously PASS H3 checks remain PASS; H3 independence proofs (grep/nm/ldd/include-path isolation) must still hold. Do not break H1/H2/H4, E1/E2/E3, or other workflows/evidence except minimal, justified, compatible updates (e.g. H3 evidence refresh required by this unblock) fully documented and CI-green.
2. **Clean-room oracle:** `bin/mapr_oracle` / `harness/oracle/**` must not include or link engine/C07/C08 code. F00–F08 wire emission may use E3; **decoding/verification evidence for the oracle check must come from H3**.
3. **No hand-edited measured values:** TSV/log/manifest rows and hashes are harness/test generated. If H3 hashes `src_tree_sha256` or similar manifests, regenerate them correctly via the harness so committed state is self-consistent and CI-verified.
4. **No build artifacts committed.** No v1 write; no E4–E7 scope creep.
5. **Honest reporting:** if any F00–F08 case cannot be fully byte-exact verified in CI for a documented reason, report it precisely (and keep status honest) — but the goal is to fully unblock `oracle.f00-f08` to PASS.

---

## 4. Implementation guidance (follow repo conventions)
- Reuse existing H3 surfaces: `bin/mapr_oracle decode|verify|range|inspect`, `harness/oracle/tests/oracle_test.cpp` evidence emission (`--write-evidence` or existing mechanism), `engine/Makefile.h3`, `.github/workflows/h3-oracle.yml`.
- Add/extend a deterministic F00–F08 cross-check path (test/harness) that: (a) obtains/generates fixtures F00–F08 with recorded identities, (b) invokes E3 to emit wires, (c) runs H3 oracle decode/verify and compares output bytes/digests to fixture sources, (d) emits the `oracle.f00-f08` row(s)/logs with measured values.
- Integrate with H1 fixture generation or spec-defined generators where available; prefer existing in-repo deterministic generators over ad hoc ones.
- Keep emitted wires/evidence artifacts manageable (store hashes/manifests and necessary evidence; avoid committing multi-GB intermediates unless required).

---

## 5. Deliverables (update/commit)
- Updated H3 evidence: `specs_and_reports/v2/gates/H3-ORACLE.tsv` (`oracle.f00-f08` now PASS with real data), `specs_and_reports/v2/logs/H3-ORACLE.log`, `specs_and_reports/v2/evidence/H3/SHA256SUMS` (and any additional H3 evidence/manifests produced).
- Any necessary updates to `harness/oracle/**`, `engine/Makefile.h3`, `.github/workflows/h3-oracle.yml` to generate/verify F00–F08 cross-checks and keep CI green (minimal, isolated).
- `REPORT/HARNESS/H3-ORACLE-REPORT.md` updated (or addendum consistent with repo convention) documenting: base/head commits, CI run ID(s)/URL(s), F00–F08 fixture identities (size, source SHA-256), wire identities (size, SHA-256), per-fixture oracle decode/verify results, confirmation of clean-room independence and no regressions, and that `oracle.f00-f08` is **PASS** (no longer BLOCKED).

---

## 6. Acceptance checklist (CI-authoritative)
- [ ] F00–F08 fixtures obtained/generated deterministically with recorded identities (id, bytes/size, SHA-256).
- [ ] E3-emitted v2 wires produced for F00–F08 (recorded wire SHA-256/size); wires valid/canonical.
- [ ] H3 oracle independently decodes/verifies each wire with **byte-exact** reproduction of the fixture output/digest (and agreement recorded) for F00–F08.
- [ ] `oracle.f00-f08` row in `H3-ORACLE.tsv` is **PASS** with measured values; all prior H3 rows remain PASS.
- [ ] H3 clean-room isolation and independence checks still pass; no engine linkage in oracle; no regressions to existing components/workflows.
- [ ] `H3-ORACLE.log`, `evidence/H3/SHA256SUMS` (and manifests) regenerated consistently; committed state matches generated/CI-verified evidence.
- [ ] `REPORT/HARNESS/H3-ORACLE-REPORT.md` updated and cites final **green GitHub Actions CI** run ID(s)/URL(s).
- [ ] Changes committed/pushed and (if via PR) merged to `h2-gates` with green CI.

**Definition of done:** `oracle.f00-f08` unblocked to PASS with green CI and committed measured evidence; H3 fully green (no BLOCKED rows remaining for this check), no regressions.
