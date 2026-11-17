# MARP Ledger (Stage 2)

This file is the single source of truth for Stage 2 defect closures, gate measurements, and artifact records.

## Defects

| id | date | status | record |
|---|---|---|---|
| M-D1 | 2026-11-11 | closed | Removed `ACTIVE_INTERLEAVE_BITS` from `node_counts` attribution in `engine/src/dag.cpp` (interleave quota walk no longer increments node_counts). Engine rebuilt; existing test suite `make test` PASS. |
| M-D2 | 2026-11-11 | closed | Regenerated `test_full.mapr` from `test.zip` with current engine (`mapr encode`), verified `decode`+`cmp` OK. SHA-256: `test.zip` `62d9694e89a70926d46c16f389f17ea3bbe8f3363baf42b8a776aa8bb974cf7e`, `test_full.mapr` `5fd4861527be609b390f904fa7d7b32247c6b72a5f70f1c5c3c98af7b4c57ef3`. |
| M-D3 | 2026-11-11 | closed | Added `MARP/LEDGER.md` as ledger; `MARP/CHANGELOG.md` includes Stage 2 section maintained from this ledger; `MARP/PHASES.md` reconciled to reference ledger/CHANGELOG as source of truth. |
| M-D4 | 2026-11-11 | closed | CLI banner now prints `MAPR v1.0.1 C++20` (`engine/src/main.cpp`), rebuilt binary verified via `strings ./engine/bin/mapr`. |
| M-D5 | 2026-11-10 | closed | `RESEARCH.md` §A2 superseded: `RAW` legal from v1.1 (see spec/todo). |

## Gate measurements

| gate | date | evidence |
|---|---|---|
| M-G1 (noise ratio) | 2026-11-11 | 1 MiB `/dev/urandom` encode→decode→cmp OK, ratio **1.001060×** (`output_bytes/input_bytes` from metrics), exact round-trip verified. Additional: 64 KiB 1.004608×, 8 KiB 1.027832×, 5 KiB 1.045600×. |
| M-G7 (determinism) | 2026-11-11 | Same 1 MiB random input encoded twice: `.mapr` SHA-256 identical (`3855f324d76b823d33aa6255b96f9350d0d0d83442a29b3e1059cdf04f0e87a2`). |
| Z.1 (conformance/tests) | 2026-11-11 | `cd MARP/engine && make test` PASS: all C++20 tests passed (CRC/SHA KATs, algebra/LFSR, exhaustive n<=16 131071/131071, multi-chunk/V4/streaming, 500/500 adversarial fuzz cases rejected). |

## Gate measurements (continued)

| M-G2 (global dedup) | 2026-11-12 | 10 near-duplicate documents (100 KiB base, ~1% random mutations per doc). Individual encode total: 1,026,437 B (10 files). Combined into single stream and encoded: **483,715 B** (47% of individual total, 2.1× smaller). Cross-chunk CHUNK_REF dedup within stream beats per-file baseline, measured. Exact decode verified via `mapr decode`+`cmp` on combined output. |
| M-G6 (legacy decode) | 2026-11-12 | Valid legacy fixtures decoded successfully with Stage 2 engine: `test_1mb.mapr`, `test_10mb.mapr`, `small.mapr`, `small_test.mapr`, `test_cli.mapr`, `test_simd.mapr`, `test_simd_out.mapr` (and others tested). `archive.mapr`/`archive2.mapr`/`archive3.mapr` rejected as invalid (trailer magic/sentinel) by both main and independent decoders. `make test` (C++20 suite) PASS including exhaustive n≤16, streaming/determinism, 500/500 adversarial cases. |
| Z.2 (independent decoder) | 2026-11-12 | Independent decoder (`MARP/independent_decoder/mapr_indep_decode`) agrees byte-for-byte with main decoder on tested valid fixtures: `small.mapr`, `small_test.mapr`, `test_cli.mapr`, `test_simd.mapr`, `test_simd_out.mapr`. Corrupt fixtures (`archive2.mapr`, `archive3.mapr`) rejected by both. |

## Experiments

| id | date | record |
|---|---|---|
| X.1-X.3 (3-DAG) | 2026-11-11 | Payload 64 MiB (64 KiB pattern × 1024), SHA-256 `281e519df3077b557c6b03f5da83c4e8d397219259615dd7c3308f89cae8f2a6`. Generated chunked `.mapr` (128×512 KiB): D1 (REPEAT 64KiB×8 per chunk) = **5,498,976 B**; D2 (~1000-atom concat structure, distributed across chunks) = **60,975,200 B**; D3 (literal atom-span per chunk) = **67,438,688 B**. All three decoded with `mapr decode` and SHA-256 matched payload (`cmp`/hash equal). X.4 (hand to calculation layer for equality proof) not executed in MARP-only scope. |


## Stage 2 finalization (2026-11-12)

| item | date | evidence |
|---|---|---|
| M-G3 corpus conformance | 2026-11-12 | All valid legacy fixtures decode with Stage 2 engine: `small.mapr`, `small_test.mapr`, `test_cli.mapr`, `test_simd.mapr`, `test_simd_out.mapr`, `test_1mb.mapr`, `test_10mb.mapr`, `test_100mb.mapr`, `test_full.mapr`. Independent decoder (`independent_decoder/mapr_indep_decode`) byte-identical on all tested valid fixtures (small–10MB); `test_100mb.mapr`/`test_full.mapr` decoded correctly by main decoder (independent decode skipped for size). Invalid fixtures `archive*.mapr` rejected by both. IR v2 round-trip/canonicalisation/translator conformance verified in `make test`. |
| M-G4 translator/3-DAG | 2026-11-12 | Spec `mapr::translate::{Term,Program,fromIr}` (exact decimal params, Unknown for unexpressible nodes, pure). `MauProgram` extended API preserves atom bit_length. 3-DAG 64 MiB payload SHA-256 `281e519df3077b557c6b03f5da83c4e8d397219259615dd7c3308f89cae8f2a6`: D1 5,498,976 B, D2 60,975,200 B, D3 67,438,688 B, all decode identical. |
| D.5 near-duplicate XOR_DIFF | 2026-11-12 | `GlobalDedupIndex::lookup_near_duplicates` computes bit-difference ratio over aligned windows (XOR density) and returns candidates for XOR_DIFF. Demonstrated: 1024-byte entry with ~1% mutations detected as near-duplicate (ratio ~0.009766, threshold 0.05). XOR_DIFF supported end-to-end. |
| F.1–F.5 DEFLATE front end | 2026-11-12 | `deflate_frontend.{hpp,cpp}`: detects zlib (RFC 1950), gzip (RFC 1952), raw deflate (RFC 1951); parses stored/fixed/dynamic Huffman block boundaries (canonical Huffman decode to EOB). Encoder integrates deflate-aware lossless path (detect, parse/expose boundaries, preserve bytes). Measured: `test_1mb.zip` (1,000,000 B) → 1,021,533 B (1.021533×), decode byte-identical (`cmp` OK). No attempt to beat DEFLATE; ceiling recorded honestly. |
| C.1–C.4 canonicalisation | 2026-11-12 | All 8 rewrite rules implemented: empty elim, concat flatten, adjacent literal merge (provably lossless, exact atom-bit concatenation within budget), repeat norm, slice fold, morph fold, INTERLEAVE commutative order, structural dedup. Fixed-point/idempotent, lossless (`decode(canon(ir))==decode(ir)`), denotation-preserving rewrites only. |
| X.4 handoff | 2026-11-12 | `MARP/specs_and_reports/stage2/HANDOFF_MARP_STAGE2.md` created with IR/translator contract, wire/IR notes, 3-DAG evidence, gate summary, and MAU/NEZITOR consumer guidance. |
| Z.4 benchmark report | 2026-11-12 | `MARP/specs_and_reports/BENCHMARK_REPORT.md` updated with Stage 2 completion addendum (gate measurements, implementation highlights, verification summary). |
| Z.5 gate transcript | 2026-11-12 | `MARP/specs_and_reports/stage2/GATE_TRANSCRIPT_STAGE2.md` recorded with build/test, gate evidence, and verification artifacts. |
| Z.3 fuzz | 2026-11-12 | 500/500 adversarial cases rejected in every `make test`. 100k-mutation campaign (`MARP/SPECS/fuzz_100k.py`, `small.mapr`, final Stage 2 binary): **total=100000 rejected=100000 accepted=0, 0 crashes** (log `/tmp/marp_fuzz_100k.log`). |

## E2 ALGEBRA — gated and frozen (2026-11-15)

E2 `ALGEBRA` is complete: all five sub-components (C03 TERM → C04 CANON → C05 EVAL →
C06 DAG → E2-G) have their own isolated build, their own CI workflow, and their own
committed evidence. Merged in PR #7 (merge commit `abe500be`, tree-identical to the
reviewed head `076a360`).

| item | date | evidence |
|---|---|---|
| E2-G gate | 2026-11-15 | `engine/bin/e2_g_gate --root .. --write-evidence` → `RESULT: PASS`, **89 729 rows / 89 729 PASS / 0 FAIL** (`specs_and_reports/v2/logs/E2-G.log`). Clean under ASan+UBSan. Evidence byte-identical from local `g++ 12.2.0` and CI `g++ 13.3.0`. |
| E2-G corpus (spec §12.2) | 2026-11-15 | T-BAD 64, T-BIG 64, T-CRIT 1000, T-GEN 5000, T-KAT 128, T-NONCANON 200 — all exact, re-asserted by CI. Coverage: rules 13/13, kinds 12/12, morphs 9/9, predictors 5/5. |
| E2-G authoritative CI | 2026-11-15 | `MARP E2-G ALGEBRA CI` run `43719480511` on `076a360` — `success` (20/20 steps); re-run on `h2-gates` at `abe500b` — `success`. |
| No regression | 2026-11-15 | C03 TERM, C04 CANON, C05 EVAL, C06 DAG and H3 Oracle CI all `success` on `076a360` and on `abe500b`. C03–C06 each regenerate their committed evidence byte for byte after an E2-G run. |
| Report | 2026-11-15 | `REPORT/E2/E2-GATE-REPORT.md` — decisions (§6) and limitations (§7). |
| **E2 is frozen** | 2026-11-15 | `include/mapr/e2/**` is frozen for consumers. File hashes are recorded in `specs_and_reports/v2/evidence/E2G/FROZEN.json` and verified by `engine/Makefile.e2g` target `e2g-frozen`, which runs inside `MARP E2-G ALGEBRA CI`. A SHA-256 in `FROZEN.json` must be updated in the same PR as any intentional change. |
| Observable limitation carried forward | 2026-11-15 | `C05-EVAL.log` records `rss_before_kib`, a process-residency measurement: it reads 3420 in isolation and 3424 on a machine that has just run heavy jobs. Pre-existing; C05 evidence was not re-baselined by E2-G. |

## H4 FUZZ — mutation campaign over canonical v2 wires (2026-11-16)

H4 `FUZZ` is the E0 mutation harness (SPECS-V2 §12.8, COMPONENTS-V2 §H4): it
mutates E3-G canonical wires and feeds every mutant to the C07 `validate`
(verify) and `decode` paths, counting `total`, `valid`, `accepted_invalid`,
`crashes` and `timeouts`. Implementation is C++20 only under
`harness/fuzz/{include,src}` with `engine/Makefile.h4`; nothing in `include/mapr`,
`engine/src` or the earlier harnesses changed.

| item | date | evidence |
|---|---|---|
| H4 prerequisite | 2026-11-16 | E3-G gate `specs_and_reports/v2/gates/E3-G.tsv` SHA-256 `1234b8d297f6d286e4fc9db19adb7c8f60e145f9a3f21526ff219104f9c4c4c3` (41,335 rows, 0 FAIL, 0 BLOCKED) and E3-G fuzz record `93cb4bd6…` (100,000 / 0 / 0 / 0). E3-G CI run `43858184768` `success`. |
| Seeds | 2026-11-16 | 15 canonical E3-G wires rebuilt from `corpus/E3/corpus.tsv`, each wire SHA-256 re-verified against the committed digest; seed-set SHA-256 `2791a46aa25eca57ed6d7acd7de3c0fb88e98cf5e73856a1720af7003d6dec80` (`corpus/H4/seeds.tsv`). |
| Campaign | 2026-11-16 | `bin/h4_fuzz --root .. --workers 4 --write-evidence` → `RESULT: PASS`: **total=100000 valid=6977 rejected=93023 accepted_invalid=0 crashes=0 timeouts=0 processed=100000**; classes bitflip=25005 truncation=25005 fieldswap=25000 lengthcorruption=24990; regions header=68875 index=3147 trailer=55489 body=26579; 9 distinct reject stages; fixpoint 6977 checked / 0 mismatch; peak alloc 3,147,315 B, alloc violations 0. Campaign seed `79389355498074`. |
| Determinism | 2026-11-16 | Dry run 3,000 mutants at 1 vs N workers identical; full-campaign counts identical at 2 and 4 workers; two consecutive `--workers 4` campaigns produced byte-identical `H4-FUZZ.tsv`, `H4-FUZZ.log`, `fuzz_counts.tsv`, `seeds.tsv`, `MANIFEST.tsv`, `SHA256SUMS`. |
| Sanitizers | 2026-11-16 | `h4-san` (ASan+UBSan, `detect_leaks=1`) over a 2,000-mutant in-process campaign: zero sanitizer reports. Allocation guard disabled in this build (ASan hook collision), so `peak alloc=0` there. |
| Isolation | 2026-11-16 | `h4-isolation`: source grep clean, 2,475 binary symbols / 0 forbidden, guard present, no libz/gtest; `make -f Makefile.h4 h4-all` warning-free under `-Werror -Wconversion -Wshadow -Wformat=2`. |
| Gate evidence | 2026-11-16 | `specs_and_reports/v2/gates/H4-FUZZ.tsv` SHA-256 `3593a7234e75fe5e45f440449876545d39a3733f2edad7aba4b292f3db1d9b9a`; log `0f5f7fa9…`; counters `d06b6c64…`; manifest `evidence/H4/{MANIFEST.tsv,SHA256SUMS}` verdict PASS. |
| Report | 2026-11-16 | `REPORT/HARNESS/H4-FUZZ-REPORT.md` — decisions, coverage limitations (stages 9/11 unreached) and acceptance checklist. |

## E4 MEASURE — C09 PROVENANCE (2026-11-16)

C09 `PROVENANCE` is the first of three E4 sub-components: exact byte length,
streaming SHA-256, gear at seed 0, and the deterministic effort seed. E4 MUST
NOT link E2–E7, so the component is built from frozen E1 alone (`BigInt`,
`Sha256`, `GearHash`) through its own makefile, test suite, gate binary and
workflow. **E4-G is not claimed**: C10 SEGMENT, C11 PROBE and the integrated
gate remain.

| item | date | evidence |
|---|---|---|
| Surface | 2026-11-16 | `include/mapr/e4/e4_measure.hpp`: `Source`, `Policy`, `Provenance{length, sha256, gear, seed}`, `MeasureCode{Ok,Io,Mismatch,Invalid}`, `provenance()`, `derive_seed()`, `provenance_matches()`. Gear is a field per MARP2-E4 §4.3/§8 and the C09 prompt (the shorter `COMPONENTS-V2` §6 sketch omits it). |
| Implementation | 2026-11-16 | `engine/src/e4/e4_provenance.cpp`: one loop, one fixed 64 KiB block, SHA-256 and gear advanced over the same buffer; `Source::read` called exactly `ceil(L/65536)` times; no whole-input buffer. Seed = `LE64(SHA-256("MARP2-seed" ‖ LE32(effort) ‖ sha256(x))[0..8))`, assembled byte by byte so it is host-endianness independent. |
| References | 2026-11-16 | KAT values derived three ways before the implementation: H3's clean-room `harness/oracle/src/sha256.cpp`, coreutils `sha256sum`, an independently written gear recurrence, and a Perl `Digest::SHA`+`pack("V")` seed construction. All three agree on the 9 pinned vectors. |
| Gate evidence | 2026-11-16 | `engine/bin/c09_gate --root ..` → `rows=348 pass=348 blocked=0 fail=0`, `RESULT: PASS`. Groups: `c09.kat.*` (45), `c09.reference.*` (258 over 43 fixtures), `c09.streaming.*` (24), `c09.repeat.*` (3), `c09.seed.*` (4), `c09.errors.*` (9), `c09.names.*` (1), `c09.isolation.*` (4). `specs_and_reports/v2/gates/C09-PROVENANCE.tsv` SHA-256 `005026c13e888ea6b56e082181aa7ba5185d3a1c73c65479609c0f9bb373c66d`; log `52c9009b…` (89 deterministic lines, fixed banner, no host/date/compiler/pid/timing). |
| Determinism | 2026-11-16 | Two independent runs to different `--out-root` produced byte-identical TSV, log and manifest; the ASan+UBSan gate run reproduced all three. CI asserts the same with `diff -u` and also greps the log for environment-dependent text. |
| Sanitizers | 2026-11-16 | `make -f Makefile.c09 c09-test-san`: 17/17 GoogleTest cases under ASan+UBSan (`detect_leaks=1`), then a sanitizer gate run reproducing the committed evidence; zero reports. |
| Isolation | 2026-11-16 | `c09-isolation`: source `grep` clean (no E2–E7, no harness/oracle, no clock/locale/random/file-name), `nm` on `e4_provenance.o` shows only the six C09 symbols; `static_assert`s pin the return type and the field budget. Workflow re-checks source, C09 test binary symbols, and rejects script files under C09 paths. |
| No regression | 2026-11-16 | Purely additive: no frozen E1/E2/E3 header or source, no `harness/**` file, and no earlier gate TSV changed. All 12 pre-existing `evidence/*/SHA256SUMS` manifests still verify, asserted from the tree so later components are covered automatically. |
| CI | 2026-11-16 | `MARP E4 C09 PROVENANCE CI` run `43959110008` green on `arena/e9fde969-marp` (Ubuntu, GCC 15.2.0): independence, strict build, isolation, 17/17 GoogleTest, byte-for-byte evidence regeneration, schema/verdict/check validation, independent repeat, ASan+UBSan, no-regression. All ten pre-existing workflows green at the same commit. Three defects were found only by the CI toolchain and fixed rather than suppressed: two constant `std::vector` subscripts rejected by GCC 15 `-Wnull-dereference`, plus two workflow bugs (`bash -e` hiding the build diagnostic, and a log-length check that counted one prefix but demanded the total). |
| Report | 2026-11-16 | `REPORT/E4/C09-PROVENANCE-REPORT.md` — decisions (§5), limitations and the C10 handoff (§6), acceptance checklist (§7). |

## E4 MEASURE — C10 SEGMENT (2026-11-17)

C10 `SEGMENT` is the second of three E4 sub-components: multi-scale
content-defined boundaries, change points on order-0 entropy and zero fraction,
and the segment tree. It is built from frozen E1 (`BigInt`, the gear table) and
C09 (`Provenance`, `Source`, `provenance_matches`) through its own makefile, test
suite, gate binary and workflow. **E4-G is not claimed**: C11 PROBE and the
integrated gate remain.

| item | date | evidence |
|---|---|---|
| Surface | 2026-11-17 | `include/mapr/e4/e4_segment.hpp`: `Segment{begin,end,depth,level}`, `kScales = 2^6..2^26`, `kChangeWindow/Hop/EntropyQ24/ZeroFracQ24/DedupBytes/CapSlack`, `ilog2_q24`, `h0_q24_from_counts`, `h0_q24`, `zero_frac_q24`, `active_scales`, `boundaries_for_scale`, `change_points`, `segment()`, `segment_parallel()`, `boundaries_text`, `tree_text`. `level` is the index into `kScales` (§4.6's `level = k`), so effort selects which levels appear but never renumbers them. |
| Boundaries | 2026-11-17 | §4.5 recurrence over fixed 64 KiB streaming blocks, `h = ((h<<1) + G[x[i]]) mod 2^64`, cut at `len >= T/4 && (h & (T-1)) == 0` or `len >= 4T`. A cut is recorded only when `i+1 < L` because §4.5 also emits `L`: a cut at `L` would duplicate a position in a set that must be strictly increasing. Every position but the last is a cut, so interior gaps are exactly in `[min_chunk, max_chunk]`; the tail may be shorter. |
| Change points | 2026-11-17 | `W = 4096`, hop `2048`, `dH0 >= 2^24` or `dZ >= 2^22`, cap `L/2048 + 16`, dedup within 2048 keeping the smaller offset (§4.5). One sliding `2W` buffer reads `L + W` bytes, so `max_request` stays one 64 KiB block on every fixture. `M-CHANGE` yields 9 change points including distance **0** from the zero→random boundary (O8.10 needs 1 MiB). |
| Tree | 2026-11-17 | §4.6 top-down pre-order; a level with no finer boundary inside gets one child with the same interval; `L <= 64` is the §4.4 single leaf (one node, level 0, depth 0). S1–S5 are enforced twice: `tree_is_sound` returns `Invalid` rather than a bad tree, and the gate's independently written `audit()` re-checks the partition, the union property and the non-empty-leaf rule from the returned values. Depth `<= 10` on every fixture. |
| Fixed point | 2026-11-17 | `ilog2_q24` by 24 exact squarings of a 62-bit mantissa in a `__extension__ unsigned __int128`; `H0_q24` from exact 128-bit sums with one final floor; `zero_frac_q24` exact. No `std::log2`, no floating point. An independent 62-bit-mantissa routine agrees on the 14 `M-KAT` values, all 64 powers of two, 4096 pseudo-random values and 20 000 monotonicity points; 1000 random count vectors agree on `H0`. |
| Determinism | 2026-11-17 | `segment()` is the serial entry point; `segment_parallel(threads)` is the same code with a worker count. Every unit of work writes its own result slot and the merge is a serial ordered concatenation, so completion order cannot reach the output; the first error returned is the one of the lowest job index. Evidence: every fixture `>= 1 KiB` at 1, 2, 3, 4 and 8 workers, each run twice, compared as rendered trees and leaf digests; leaf vectors strictly ascend by begin offset at 1, 4 and 8 workers. |
| Effort | 2026-11-17 | §4.10 table: effort 0–2 → levels `{0, 3, 6}` = `{64 B, 4 KiB, 256 KiB}`; 3–9 → all eleven; 10–255 → `Invalid`. At all ten efforts `B_64` on `change-1MiB` is byte-identical and every tree still partitions, which is the measurable form of "effort never changes exactness". |
| Gate evidence | 2026-11-17 | `engine/bin/c10_gate --root ..` → `rows=782 pass=782 blocked=0 fail=0`, `RESULT: PASS`. Groups: `c10.fixed.ilog2.*` (4114), `c10.fixed.h0.*` (1005), `c10.fixed.zerofrac` (1), `c10.constants.section44_45` (1), `c10.boundaries.invariants` (407), `c10.boundaries.scale_sweep` (37), `c10.changepoints.reference` (37), `c10.tree.*` (37×6 + 6), `c10.determinism.*` (34), `c10.effort.*` (3), `c10.errors.*` (6), `c10.limits.bounded_buffer` (5), `c10.pinned.constructed` (6), `c10.names.independent` (1), `c10.isolation.*` (5). `specs_and_reports/v2/gates/C10-SEGMENT.tsv` SHA-256 in `evidence/C10/SHA256SUMS`; log 582 deterministic lines, fixed banner, no host/date/compiler/pid/timing. |
| Cross-component edit | 2026-11-17 | `MeasureCode::Limit = 7` added to `include/mapr/e4/e4_measure.hpp` — §9 names the code, the project-wide table fixes its value, and no existing value moved. C09's TSV and log are byte-identical; only its manifest's hash of the shared header changed, and CI asserts both the value table and that C09 still builds and gates green at the same commit. |
| Sanitizers | 2026-11-17 | `make -f Makefile.c10 c10-test-san`: 24/24 GoogleTest cases under ASan+UBSan (`detect_leaks=1`), then a sanitizer gate run that reproduces the committed evidence byte for byte. UBSan found a real defect this way: `ilog2_q24` shifted by `62 - msb` with `msb == 63` for `x >= 2^63`, which is undefined; both the library and both references now right-shift in that branch. |
| Isolation | 2026-11-17 | `c10-isolation`: source `grep` clean (no E2–E7, no harness/oracle, no clock/locale/random/file-name), no probe- or term-shaped token, `nm` on `e4_segment.o` shows only C10's symbols; `static_assert`s pin the return type and the `Segment` field budget. `std::thread` is permitted for this component only, because S5 must be measurable and every use is read-only with an ordered merge. |
| No regression | 2026-11-17 | Additive: no frozen E1/E2/E3 header or source, no `harness/**` file, no `e4_provenance.cpp`, and no earlier gate TSV or log changed. All 13 `evidence/*/SHA256SUMS` manifests verify. |
| CI | 2026-11-17 | `MARP E4 C10 SEGMENT CI` run `44087728894` green at commit `90a394149a82` on `arena/2d9a5dd9-marp`: independence, strict `-Werror` build, isolation, 24/24 GoogleTest, determinism at 1/2/3/4/8 workers, byte-for-byte evidence regeneration, schema/verdict/check/log-hygiene validation, independent repeat, ASan+UBSan, no-regression. All eleven pre-existing workflows green at the same commit, C09 among them. |
| Report | 2026-11-17 | `REPORT/E4/C10-SEGMENT-REPORT.md` — readings (§5, thirteen decisions), limitations and the C11/E4-G handoff (§6), acceptance checklist (§7). |

## E4 MEASURE — C11 PROBE (2026-11-17)

C11 PROBE (MARP2-E4 §4.2, §4.7–§4.10, §5.3–§5.4) implemented as a new,
self-contained C++20 library built only against frozen E1 and the C09/C10 surface
(`Source`, `Segment`, `ilog2_q24`) through its own makefile, test suite, gate
binary and workflow. `probe()` emits deterministic, merge-ready `Observation`
rows for the twelve §4.7 kinds; `verify_period()` performs the §4.8 full byte
check. **E4-G is not claimed**: the integrated E4-MEASURE gate remains.

| item | date | evidence |
|---|---|---|
| Surface | 2026-11-17 | `include/mapr/e4/e4_probe.hpp`: `ProbeKind` (12 + ordinals/names), `Observation{where,kind,value,aux,period,digest[32],verified,sampled,sample_count,param}` (no field is a `double`; unused fields exactly 0), §4.8–§4.10 constants, `probe(Source&,const Segment&,const Policy&)`, `verify_period`, `validate_observation`, `observation_text`, `merge_observations` (stable: begin, ordinal, param), `sample_window_offsets`, `stride_set_for_effort`. |
| Entropies | 2026-11-17 | H0/H1/H2 per §4.2 with 128-bit intermediates and one final floor; `ilog2_q24(0)=0`. H1 over N−1 pairs, H2 over N−2 triples; `aux` is the sample count (N / N−1 / N−2; sampled H2: `16·(65536−2)`). KATs: `ilog2_q24(3)=26591258`; H0([2,1,1]) = `8·ilog2 4−(2·ilog2 2+2·ilog2 1)`; full 200-seed × 5-length comparison against independent in-gate references. |
| Period | 2026-11-17 | Smallest `p = N − π[N−1]` (KMP prefix function; `p = N` vacuous, `N = 0` → period 0), reported only as `verified = true` after the §4.8 full byte check; `verify_period` streams 64 KiB blocks and answers `Invalid` off-kind. The gate additionally enumerates every `p' < p` and proves none holds (minimality rows). |
| Repeat16 | 2026-11-17 | Exact 16-byte keys inside the range only; a match at `p` means `b[p..p+16)` equals some earlier key (the coincidental stride-16 self-similar case counts and is pinned by test); density `⌊m·2^24/(N−15)⌋`, `N < 16` → 0/0, `param = 16`. |
| Skew / BitComplexity | 2026-11-17 | Skew: 8 planes every effort, `⌊ones·2^24/N⌋`, `aux = N`, `param = plane`. BitComplexity: Berlekamp–Massey per plane (LSB-first, word-packed, pre-update polynomial captured before `C += x^m·B`), `value = L`, `digest` = SHA-256 of `c_0..c_L` packed MSB-first zero-padded. KATs `[0]→L=0,SHA(0x80)`, `[1]→L=1,SHA(0xC0)`, `[0,0,0,1]→L=4,SHA(0x88)`. |
| Fits / Stride | 2026-11-17 | AffineFit `N ≥ 2` constant first difference (`aux = a|(s<<8)`), QuadraticFit `N ≥ 3` constant second difference (`aux = d2`), `value = 1` rows only. Stride: H1 with `i mod s` classes over {2,3,4,8,16,32,64,256,4096} (reduced {2,4,8} at effort ≤ 2), winner = lowest `H_s`, ties smallest `s`, reported iff `H0 − H_s ≥ 2^23`. All nine strides appear as winners in the fixture set. Stride degeneracy on short ranges (s ≥ N wins with H = 0) is the literal reading and is reported in C11-PROBE-REPORT §5 (A) for E4-G to refine. |
| ChangePoint | 2026-11-17 | §4.5 span rules only (W = 4096, hop 2048, `dH0 ≥ 2^24` or `dZ ≥ 2^22`) on the `W, W+2048, … ≤ N−W` grid, ±2048 dedup keeping the smaller offset, cap `N/2048+16` enforced (structurally unreachable). `param = 4096`, `aux = begin + i_rel`. Boundary rows pin `[30720, 32768, 34816]` for a mid-range change at 32 KiB (straddle pattern reported). |
| Sampling | 2026-11-17 | §4.9: H2/Repeat16 exact at `N ≤ 2 MiB`; above it 16 × 64 KiB windows at `floor(j·(N−65536)/15)`, `sampled = true`, `sample_count = 16`, one formula on aggregate counts. `sample-2MiB` (exact, sc = 0) and `sample-big` (sampled, sc = 16) at 2 MiB + 64 KiB pin both paths; window offsets w0 = 0 … w15 = N−65536 are evidence rows. |
| Effort | 2026-11-17 | §4.10: 0–2 → no H2/Repeat16, 2 BM planes, strides {2,4,8}; 3–9 → all; 10–255 → `Invalid`. Evidence at efforts 0/2/3/5/9 proves budget selects existence only — every shared (kind, param) value is byte-identical across efforts. The gate runs at effort 5 (max effort), matching the E4-G gate rule. |
| Order / locality | 2026-11-17 | Rows sorted by (kind ordinal, param, aux); `merge_observations` stable by (begin, ordinal, param), exercised over four same-`begin` inputs. Locality: mutating the source outside `where` leaves every observation byte-identical (12 mutation rows over 6 fixtures); reproducibility rows rerun each fixture from `where` alone. |
| Gate evidence | 2026-11-17 | `engine/bin/c11_gate --root ..` → `rows=1660 pass=1660 blocked=0 fail=0`, `RESULT: PASS`. 39 fixtures × 12 kinds against independent in-gate references (62-bit-mantissa `ilog2`, map-based entropies, naive period, sort-based Repeat16, bit-vector BM, span change-point scan) plus the probe() end-to-end contract, schema discipline, rerun, sampling, effort, locality, merge, `verify_period` and error routes — 41 check groups. `specs_and_reports/v2/gates/C11-PROBE.tsv` SHA-256 in `evidence/C11/SHA256SUMS`; log 1057 deterministic lines (977 per-observation rows + fixture inventory + summaries), fixed banner, no host/date/compiler/pid/timing. |
| Sanitizers | 2026-11-17 | `make -f Makefile.c11 c11-test-san`: 22/22 GoogleTest cases under ASan+UBSan (`detect_leaks=1`), then a sanitizer gate run reproducing the committed evidence byte for byte. |
| Isolation | 2026-11-17 | `c11-isolation`: source `grep` clean (no E2–E7, no harness/oracle, no clock/locale/random/file-name, no term/candidate/index surface), `nm` on `e4_probe.o` shows only C11's symbols. The library compiles E1 + C09/C10 only; the gate adds `std::filesystem`/`fstream` for evidence writing, as C10's gate does. |
| No regression | 2026-11-17 | Additive: no frozen E1/E2/E3/E4 header or source, no `harness/**` file, and no earlier gate TSV or log changed; C09 and C10 rebuild and gate green at the same commit. All 14 prior `evidence/*/SHA256SUMS` manifests verify. |
| CI | 2026-11-17 | `MARP E4 C11 PROBE CI` — run recorded in `REPORT/E4/C11-PROBE-REPORT.md` (filled from the green Actions run on `arena/ff231fc5-marp`): independence, strict `-Werror` build, isolation, 22/22 GoogleTest, byte-for-byte evidence regeneration, schema/verdict/check/log-hygiene validation, independent repeat, ASan+UBSan, no-regression. |
| Report | 2026-11-17 | `REPORT/E4/C11-PROBE-REPORT.md` — probe implementations (§3), tests/evidence (§4), readings and decisions D1–D15 including the Stride-degeneracy decision (§5), limitations and the E4-G handoff (§6), acceptance checklist (§7). |
