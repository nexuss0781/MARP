# E3-G — W-V1 Fixture Preparation & Gate Closure — FORCED COMPLETION (Local-first, CI-validated)

**Work item:** Source/pin **W-V1** legacy fixtures and **fully close E3-G to PASS** (MARP v2). This is a closure task, not an investigation: drive to green completion.  
**Repository/workspace:** You have the full MARP project workspace (complete repo, specs, history, reports). Work inside that project.  
**Base:** Start from the latest **`h2-gates`** head (must include PR #13, e.g. `e0518bb` or newer) where E3-G runnable evidence is green but **W-V1 is BLOCKED** (no pinned v1 fixture corpus). Create your own branch/worktree from `origin/h2-gates`, implement, commit, push, and open/land PR(s) as needed to merge the closure into `h2-gates`.  
**Depends on:** C07 WIRE and C08 LEGACY merged; E3-G harness/procedure/evidence in place (PR #12/#13). H3 oracle independent as required. E1/E2/E0 prerequisites satisfied. No E4–E7.  
**Language:** C++20 only. No Python committed. No third-party libraries beyond GoogleTest and what the project already uses.  
**Required outcome:** **E3-G fully closed: PASS** on a **green GitHub Actions CI run** with **all required rows/checks PASS, 0 FAIL, 0 BLOCKED** (including W-V1), gate exit 0, and all evidence/logs/corpus/manifests/report committed and matching the green run. **Do not stop at BLOCKED.** No false PASS, no fabricated fixtures/digests, no hand-edited measured values.

You are an autonomous agent with shell, file, git, and GitHub CLI access. Work independently and persist until closure is complete. If the spec or harness behavior is ambiguous, choose the narrowest interpretation consistent with the normative text, implement/fix it correctly, and record the decision.

---

## 1. Non-negotiable completion mandate
- **Finish and close E3-G.** W-V1 is the only blocker — remove it by sourcing valid fixtures, pinning them correctly, and making the gate pass.
- **Provided source (in-repo, do not ask for it again):** use **`specs_and_reports/v2/W-V1/imported/`** (relative to repo root) — v1-magic (`\x89MAPR\r\n\x1a`, v1.x) `.mapr` containers copied into the repo for closure (selected, CI-appropriate set). W-V1 candidates: `imported/small.mapr`, `imported/test_simd.mapr`, `imported/test_simd_out.mapr`, `imported/test_1mb.mapr`, `imported/test_10mb.mapr`. **Provenance:** record these as imported from `/home/nexuss0781/Desktop/Nex/MARP` (local legacy artifacts, now committed in-repo at `specs_and_reports/v2/W-V1/imported/`), then validate support/version by `looks_like_v1` + C08 `decode_v1`, pin by actual decode, and record container SHA-256 + expected denotation/output SHA-256. Exclude any malformed/PoC/defect containers from W-V1 decode-success set (none included in this set). Additional valid v1.0.1/v1.1 fixtures may be added if legitimately available.
- **Do not accept “blocked” as the outcome** if valid, supported fixtures can be found or legitimately produced from available legacy artifacts. Only if, after exhaustive, documented sourcing, **no valid/supported v1 fixture exists anywhere accessible**, you must prove that with evidence — but your default objective is closure to PASS.
- **CI-authoritative:** closure is proven only by a **green GitHub Actions E3-G run** (and no regressions in affected workflows) with committed, harness-generated evidence.

---

## 2. Mission (execute end-to-end)

### 2.1 Source and curate W-V1 fixtures
- Locate `.mapr`/legacy containers and determine which are **valid, supported v1.0.1 or v1.1** (check v1 magic/version; use `looks_like_v1` and **C08 `decode_v1`** to validate). Include fixtures that decode successfully per spec; exclude malformed/PoC/defect containers (e.g. `**/poc_defects/**`, intentionally invalid cases) from the decode-success W-V1 set and document exclusions.
- **Copy/import** selected fixtures into **`specs_and_reports/v2/W-V1/`** (commit the pinned fixture bytes) with stable names. Record provenance (source path/repo/history/context) for each fixture in the report and/or manifest notes.

### 2.2 Pin identities and expected outputs (correct and verifiable)
- For every included W-V1 fixture pin at minimum:
  - fixture filename/identity,
  - **container SHA-256** (exact file bytes),
  - **expected denotation/output SHA-256** = SHA-256 of the **byte-exact decoded output (the root term’s denotation)** as required by E3-G/W-V1 (§13.3, §13.4 step 8, O7.7).
- Create the manifest the gate consumes at **`specs_and_reports/v2/W-V1/manifest.tsv`**. **Align with the actual E3-G/C08 readers** (currently 3 columns: `<name>\t<container_sha256>\t<output_sha256>`); if formats differ across consumers, make them consistent and correct. Do **not** guess digests — compute them from actual decodes/evaluation.

### 2.3 Fix harness/handling issues required for correct closure (minimal, justified)
Known issues to resolve if they affect closure (fix properly, do not paper over):
- **C08 vs E3-G manifest parsing/handling consistency** (format/field interpretation must match).
- **Denotation/output hash correctness:** the expected/observed output digest must represent the **actual decoded root denotation/output** as specified (not an incorrect proxy such as raw atom-payload concatenation when that differs for general terms). Ensure the legacy side/gate computes and compares the correct output/denotation digest for valid fixtures, and that the full legacy checks (decode byte-exact, term valid/canonical as required, **v2 re-encode + decode again with equality**, oracle agreement as required) pass.
- Any other minimal, spec-correct fix needed so valid pinned fixtures are accepted and evidenced correctly. Keep C08 read-only and unreachable from v2 encode; no v1 write; no E4–E7. Document all fixes.

### 2.4 Satisfy full E3-G and regenerate evidence
- For every W-V1 fixture: `decode_v1` byte-exact to recorded denotation digest; decoded term legal/canonical as required; v2 re-encode and decode again with equality (and oracle agreement per gate). Per-fixture results logged in `E3-G-legacy.log`/TSV rows.
- Re-run the **complete E3-G procedure** via the harness (all corpora/checks: canonical/non-canonical/seed/big/fuzz/coverage/determinism/oracle, legacy, etc.) and regenerate/commit all evidence: `specs_and_reports/v2/gates/E3-G.tsv`, `specs_and_reports/v2/logs/E3-G.log`, `specs_and_reports/v2/logs/E3-G-fuzz.log`, `specs_and_reports/v2/logs/E3-G-legacy.log`, `specs_and_reports/v2/corpus/E3/*`, `specs_and_reports/v2/evidence/E3/*` (SHA256SUMS/MANIFEST as produced). **All required rows PASS, 0 FAIL, 0 BLOCKED.**
- Update `REPORT/E3/E3-GATE-REPORT.md` (and `specs_and_reports/v2/W-V1/README.md` or equivalent) with W-V1 inventory, provenance, container/output hashes, exclusions, fixes/decisions, final results, and authoritative CI run ID(s)/URL(s) stating **E3-G PASS (closed)**.

### 2.5 Integrate, CI, merge
- Keep/build isolated and existing workflows compatible; fix regressions if introduced. Push, run CI, and **iterate until all required checks are green** on the final head (E3-G must exit 0 / final verdict PASS, plus affected/predecessor checks as applicable).
- Open PR(s) and **merge closure into `h2-gates`** once green and evidence/report are committed. Report final merge commit on `h2-gates`.

---

## 3. Constraints (must hold)
- **No false PASS / no fabrication:** never invent fixtures or hashes; never hand-edit measured evidence values. “PASS” only with real fixtures, correct validation, and green CI.
- **Scope/boundaries:** C08 remains read-only, no v1 write, not callable from v2 encode; no E4–E7; no regressions to H1/H2/H3/E1/E2/E2-G/C03–C06/C07/C08 except minimal, justified, documented integration fixes kept green in CI.
- **Fixture policy:** valid/supported v1.0.1/v1.1 only for success rows; exclude malformed PoCs/defects from decode-success set; sizes/content appropriate to commit/CI.
- **No build artifacts committed.**

---

## 4. Definition of done (must satisfy all)
- [ ] Valid v1 fixtures sourced (including from `/home/nexuss0781/Desktop/Nex/MARP` and any other available locations), curated, copied, and pinned in `specs_and_reports/v2/W-V1/` with manifest and provenance.
- [ ] Container SHA-256 and correct expected denotation/output SHA-256 recorded per fixture; manifest/handling consistent and correct; denotation hashing/comparison fixed if needed.
- [ ] Every W-V1 fixture: byte-exact legacy decode to expected digest, term valid/canonical as required, v2 re-encode+decode equality (and oracle agreement) — all PASS with per-fixture logs.
- [ ] **Full E3-G: all required rows/checks PASS, 0 FAIL, 0 BLOCKED**, gate exit 0; fuzz/canonical/non-canonical/coverage/determinism/oracle checks remain green.
- [ ] All evidence/logs/corpus/manifests/report regenerated by harness, committed, and matching final **green GitHub Actions CI** run(s); report cites CI IDs/URLs and states **E3-G PASS (closed)**.
- [ ] Changes merged into `h2-gates` (or final merge commit reported) with no regressions.

**Work until the checklist is fully satisfied and E3-G is closed on `h2-gates`.** After closure: proceed to **H4 FUZZ** (`MARP/HARNESS/H4-FUZZ-PROMPT.md`) and unblock **H3 `oracle.f00-f08`** as applicable, then **E4 → E5 → E6 → E7 → H5**.
