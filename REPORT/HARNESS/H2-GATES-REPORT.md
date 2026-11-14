# H2 GATES — Closeout Report

## 1. Environment / authoritative run
- **Repository**: `nexuss0781/MARP`
- **Branch**: `h2-gates`
- **Worktree**: `/tmp/opencode/MARP-h2`
- **Head commit (green)**: `f1c5f7204fcdf8c35b1a7269c3e4617ecaa06b81`
- **Base context**: `abe4472` (E1 foundation), prior H2 attempt `3a16b0f` was repaired/replaced
- **CI workflow**: `MARP E1 Foundation CI` (rewritten for hard-fail H2 gates flow)
- **Authoritative green run**: [#43612525259](https://github.com/nexuss0781/MARP/actions/runs/43612525259) — **SUCCESS**
- **Runner**: Ubuntu (GitHub Actions), g++/C++20, dependencies installed in CI (build-essential, cmake, libgtest-dev, zlib1g-dev; googletest built in CI)

### CI jobs/steps (all PASS)
| Job / step | Result |
|---|---|
| `oracle-isolation` (grep: no `mapr/e1_` includes in oracle sources) | ✅ PASS |
| Build E1 and harness | ✅ PASS |
| Run E1 tests | ✅ PASS |
| Run harness tests | ✅ PASS |
| Run E0-G (`--gate E0-G --root ..`) | ✅ PASS |
| Run E1-G 1-thread (`--gate E1-G --root .. --threads 1`) | ✅ PASS |
| External 1-vs-4 thread diff (`E1-G.1.tsv` vs regenerated `E1-G.tsv` with `--threads 4`) | ✅ PASS (identical) |
| Run with AddressSanitizer (E1 + harness) | ✅ PASS |
| Verify gate artifacts | ✅ PASS |
| Verify evidence manifest (`--verify-evidence`) | ✅ PASS |
| Upload gate evidence (`gate-evidence-h2`) | ✅ PASS |

> Note: an earlier run on this closeout line ([#43611722584](https://github.com/nexuss0781/MARP/actions/runs/43611722584)) had all gate/test/ASan/artifact steps passing but failed only at manifest verification because ASan cleanup removed `bin/mapr_gate` (exit 127). Fixed in `f1c5f72` by rebuilding `bin/mapr_gate` before verification.

## 2. Committed evidence (from authoritative run #43612525259)
Artifacts committed under `specs_and_reports/v2/`:
- `gates/E0-G.tsv`
- `gates/E1-G.tsv`
- `gates/E1-G.1.tsv` (1-thread output captured before external 4-thread rerun; identical to `E1-G.tsv`)
- `logs/E0-G.log`
- `logs/E1-G.log`
- `corpus/E1/corpus.tsv`
- `evidence/E1/SHA256SUMS`

Manifest entries (`evidence/E1/SHA256SUMS`) cover: `gates/E0-G.tsv`, `logs/E0-G.log`, `gates/E1-G.tsv`, `logs/E1-G.log`, `corpus/E1/corpus.tsv` (verified in CI).

### Gate results
| Gate | Verdict | Evidence rows | FAIL | BLOCKED |
|---|---|---:|---:|---:|
| **E0-G** | **PASS** | 3 | 0 | 0 |
| **E1-G** | **PASS** | 6586 | 0 | 0 |

- External 1-vs-4 determinism: `diff -u gates/E1-G.1.tsv gates/E1-G.tsv` → no differences.
- `--verify-evidence` passed in CI against the produced manifest/artifacts.

## 3. H2 implementation summary (repaired harness)
Key changes on `h2-gates` (commits `2f18278`, `e3499f2`, `a111b10`, `1adbd15`, `47f286a`, `75afe84`, `f1c5f72`):
- **Evidence/TSV layer** (`harness/src/gates.cpp`, `gates.hpp`): 8-column evidence TSVs (`check, corpus, item_id, input_sha256, expected, actual, verdict, log`), atomic write/sort/validation, readback, `all_rows_pass`, SHA-256 helpers, render writes `ACCEPTANCE.FAIL.md` and leaves `ACCEPTANCE.md` untouched on non-PASS, env/timestamp helpers.
- **E1 corpus/terms** (`e1_corpus.cpp`, `e1_terms.cpp/.hpp`, `e1_gate.hpp`): deterministic seed-recorded corpus (`E1_CORPUS_SEED=0x4D415250`), typed payloads and stable `corpus.tsv`, harness term DAG (`TermSet : mapr::TermView`) covering all `NodeKind`s, deterministic `pick` (no `std::uniform_int_distribution`), term fingerprints and independent oracle length computation.
- **E1 gate** (`e1_gate.cpp`): measured checks for `arith.add/mul/sub/ring`, `div.divmod`, `conv.dec`, `conv.le`, `len.node`, `len.identity`, `len.no_trust`, `digest.sha256/crc32/sha_incremental/crc_incremental/zeroed`, `gear.stable`, `corpus.determinism`, internal `threads.identical` (1 vs 4), two-phase manifest/`evidence.present` handling, honest FAIL/BLOCKED behavior, env + command line logged.
- **E0-G** (`e0_selftest.cpp/.hpp`): MARP-H0 accept/reject, scratch-TSV false-gate proof with committed `E0-G.tsv` containing only PASS verdict rows, env + command line logged.
- **CLI/build/CI** (`harness/src/main.cpp`, `engine/Makefile`, `.github/workflows/ci.yml`): wired gate/threads/self-test/render/verify, removed harness fork/SIGSEGV-masking runner in favor of gtest/gates, added `e1_terms`, sanitized targets, hard-fail CI flow with oracle isolation, E0/E1 gates, external thread diff, ASan, verify, artifact upload.
- **E1/support fixes included**: CRC incremental/combine and SHA finish/reset/surface-contract alignment retained; added SHA-256 test-only bit-counter hook and a real `LimitBoundary` test; oracle/harness compile and oracle-bitlength test fixes applied to keep CI green under `-Werror`.

## 4. Documented deviations / policies
- **SHA-256 incremental, 1 MiB message**: bounded policy (all `0..128`, all `n-128..n`, every 4096th byte, plus 1024 seeded splits), with tested/total counts recorded; not exhaustive for the 1 MiB case.
- **CRC-32 incremental**: messages ≤ 4 KiB tested at every split point directly; larger message uses full split coverage via prefix states/combine plus bounded direct incremental sample (documented in evidence/log).
- **`evidence.present` / manifest phasing**: phase-1 manifest computed and verified over the pre-`evidence.present` state, `evidence.present` appended, then final manifest rewritten over the final TSV/log; committed authoritative state is the final CI artifact.
- **TSV regeneration**: gate evidence TSVs are written atomically per run (not appended across runs); the committed CI artifact for the green run is authoritative.
- **Row encoding policy**: item-scoped checks emit per-item rows where applicable (e.g. `S-DEC`, `S-BYTES`, `T-LEN`, `D-KAT` families as implemented); some checks emit aggregate rows with expected/actual counts/hashes (e.g. arithmetic/div/ring, digest incremental summaries, gear, determinism, threads/evidence presence). `len.*` rows encode expected/actual as SHA-256 of canonical per-node length sequences where used; mismatch details are recorded in `E1-G.log`.
- **E0 scope**: this closeout covers the `MARP-H0` harness self-test (E0-G as implemented). Full wire-level E0-G remains dependent on later wire/oracle components (H3/E3).

## 5. Next work (post-H2 closeout)
- **H1 FIXTURES** and **H3 ORACLE** can proceed in parallel (per their isolated prompts/files), then **E2/C03** and subsequent E2–E7 components/gates in dependency order.
- Remaining harness: **H4 FUZZ** requires E3 wire containers; **H5 FLOOR** requires E7 CLI. Full wire-level E0-G depends on H3/E3.