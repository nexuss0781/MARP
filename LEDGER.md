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
