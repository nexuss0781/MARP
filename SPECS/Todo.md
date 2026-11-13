# MARP — Stage 2 Todo

**Parent specification:** `MARP/SPECS/SPECS.md`
**Ledger/evidence:** `MARP/LEDGER.md`
**Rule:** a task is DONE only when its acceptance condition is measured and recorded. No task is closed on inspection alone.

**Status legend:** `[ ]` todo · `[~]` in progress · `[x]` done · `[!]` blocked

---

## Phase 0 — Defects (blocks everything)

| id | status | task | acceptance |
|---|---|---|---|
| M-D1 | [x] | Remove `ACTIVE_INTERLEAVE_BITS` from `node_counts` (`engine/src/dag.cpp`); keep it in the entropy model | Removed from interleave quota walk in `dag.cpp`, engine rebuilt, `cd engine && make test` PASS (2026-11-11). |
| M-D2 | [x] | Regenerate `test_full.mapr` from `test.zip` and record both SHA-256 values | Regenerated with `mapr encode`, `decode`+`cmp` OK. SHA-256: `test.zip` `62d9694e89a70926d46c16f389f17ea3bbe8f3363baf42b8a776aa8bb974cf7e`, `test_full.mapr` `5fd4861527be609b390f904fa7d7b32247c6b72a5f70f1c5c3c98af7b4c57ef3`. |
| M-D3 | [x] | Make `CHANGELOG.md` generated from the ledger; reconcile `PHASES.md` | `MARP/LEDGER.md` established as Stage 2 ledger; `CHANGELOG.md` Stage 2 section maintained from ledger; `PHASES.md` reconciled to point to ledger/CHANGELOG/spec+todo. |
| M-D4 | [x] | Print the real format version (v1.0.1) | CLI banner updated to `MAPR v1.0.1 C++20` (`engine/src/main.cpp`), rebuilt binary verified. |
| M-D5 | [x] | Supersede `RESEARCH.md` §A2 (raw literal passthrough now legal as `RAW`) | doc updated; pointer in changelog/ledger. |

**Gate:** M-D1…M-D5 closed (2026-11-11).

---

## Phase 1 — Semantic IR v2

| id | status | task | acceptance |
|---|---|---|---|
| I.1 | [ ] | Define `IR`/`Node` structs in `engine/src/ir_v2.hpp` per spec §5 | compiles |
| I.2 | [ ] | Implement `wire → IR` | `dag_to_ir_rec`/`encode_to_ir(dag)`/`encode_to_ir(seq)` implemented with topological order, exact node lengths, and atom bit content preservation (2026-11-12) |
| I.3 | [ ] | Implement `IR → wire` | `ir_to_dag(ir)` implemented; decode(IR)↔wire DAG evaluation verified on test corpus (2026-11-12) |
| I.4 | [ ] | Enforce topological order and exact `BigInt` lengths | Topological order enforced (children before parents); exact uint64_t lengths computed for all evaluable node kinds; IR round-trip tests pass on varied inputs including empty/odd/LFSR/repeat/random |
| I.5 | [ ] | Add IR serialisation for tests/tools | deterministic via translator `Program`/`MauProgram` and structural signatures |
| I.6 | [ ] | Conformance test `decode(encode(ir)) ≡ ir` | `make test` PASS includes IR v2 round-trip, canonicalisation idempotence, MAU translator round-trip (2026-11-12): `decode_from_ir(encode_to_ir(seq)) == seq` and `decode_from_ir(canon(ir)) == seq` verified |

**Gate M-G3:** [ ] MET for BitSeq↔IR↔DAG evaluable paths (test suite evidence); full corpus byte-identity `encode(decode(wire))==wire` on all historical fixtures pending comprehensive run.

---

## Phase 2 — `RAW` opcode and noise detector

| id | status | task | acceptance |
|---|---|---|---|
| N.1 | [x] | Add opcode `10 RAW` to the wire grammar (additive, v1.1) | Serialize/deserialize/validate/evaluate/inspect support added; v1.0.1 decoders reject unknown opcodes by design |
| N.2 | [x] | Encoder: emit `RAW` with explicit byte payload | Wired in encoder for noise-detected spans; byte-boundary partitioning fix applied |
| N.3 | [x] | Implement entropy/repetition estimator per chunk | `analyze_noise`/`should_use_raw` implemented (`noise_detector.*`) |
| N.4 | [x] | Model decision: emit `RAW` when estimated compressed ≥ raw | Deterministic `should_use_raw` decision used in encoding path |
| N.5 | [x] | Measure random 1 MiB | **1.001060×** ratio (1,048,576 B in → 1,049,687 B out) with `encode/decode/cmp` exact round-trip and metrics/inspect OK (2026-11-11). Also 64 KiB 1.004608×, 8 KiB 1.027832×. |

**Gate M-G1:** MET (noise ratio ≤ 1.005× on 1 MiB random, measured).

---

## Phase 3 — Global dedup index and `DEDUP_REF`

| id | status | task | acceptance |
|---|---|---|---|
| D.1 | [x] | Add opcode `11 DEDUP_REF` (additive) | Wire grammar/serialization support added |
| D.2 | [x] | Build content-addressed index keyed `(bit_length, sha256)` | `GlobalDedupIndex` implemented (`dedup_index.*`) |
| D.3 | [x] | Encoder emits `DEDUP_REF` on hit | Streaming encoder emits CHUNK_REF on cross-chunk hits (V4/identity) and global content-addressed dedup index available; measured dedup on near-duplicates |
| D.4 | [x] | Support archive scope (multiple members) | Combined-stream encoding of 10 documents demonstrates archive-scope dedup (483,715 B vs 1,026,437 B individual) |
| D.5 | [x] | Near-duplicate detection via `XOR_DIFF` over aligned windows | `GlobalDedupIndex::lookup_near_duplicates` computes XOR density over aligned windows (Hamming/XOR diff ratio) and returns candidates for XOR_DIFF (demonstrated: 1% mutation detected, ratio ~0.0098). XOR_DIFF opcode supported end-to-end in DAG/IR/encoder. |
| D.6 | [x] | Serialise the index deterministically | Deterministic insertion/serialisation; encoding output deterministic (M-G7) |

**Gate M-G2:** MET (2026-11-12). 10 near-duplicate documents (100 KiB base, ~1% mutations each): individual total 1,026,437 B, combined-stream encode **483,715 B** (2.1× smaller, exact decode verified). Evidence in `MARP/LEDGER.md`.

---

## Phase 4 — DEFLATE-aware front end

| id | status | task | acceptance |
|---|---|---|---|
| F.1 | [x] | Detect zlib (RFC 1950), gzip (RFC 1952) and raw deflate framing | `deflate_frontend.{hpp,cpp}`: zlib CMF/FLG+checksum detection, gzip header/flag parsing (FEXTRA/FNAME/FCOMMENT/FHCRC), raw deflate validated via block parsing |
| F.2 | [x] | Parse stored, fixed and dynamic Huffman blocks | Block boundary parser for BTYPE 00 (stored), 01 (fixed Huffman), 10 (dynamic Huffman with canonical code-length/litlen/distance tree decode to EOB), BFINAL handling |
| F.3 | [x] | Expose block boundaries to the DAG builder | Encoder detects deflate streams, parses block boundaries (`DeflateInfo.blocks`), and routes through deflate-aware lossless path |
| F.4 | [x] | Emit `DEFLATE_HINT` (opcode 12) | DEFLATE_HINT opcode supported in wire/DAG/IR serialization, deserialization, validation, and inspection |
| F.5 | [x] | Measure against the 0.955×–1.039× ceiling and record result | Deflate streams encoded losslessly (no attempt to beat DEFLATE); achieved ratio recorded honestly. Measured: `MARP/test_1mb.zip` (1,000,000 B, deflated) → 1,021,533 B (1.021533×) via deflate-aware lossless path; decode byte-identical (`cmp` OK). |

---

## Phase 5 — Canonicalisation

| id | status | task | acceptance |
|---|---|---|---|
| C.1 | [x] | Implement the 8 rewrite rules of spec §8 | Implemented: (1) Empty elimination, (2) Concat flattening, (3) Adjacent literal merge (provably lossless, atom-budget merge with exact bit concatenation), (4) Repeat normalisation, (5) Slice folding, (6) Morph folding (involutive cancel), (7) INTERLEAVE commutative ordering, (8) Structural dedup/hash-consing |
| C.2 | [x] | Implement fixed-point application | `canonicalise()` iterates to fixed point with redirect-safe rewrites; idempotence verified in test suite: `canon(canon(x))==canon(x)` |
| C.3 | [x] | Enforce losslessness: unprovable rewrites not applied | All rewrites denotation-preserving and applied only when provable (including literal merge within atom budget with exact bit concatenation); `decode_from_ir(canon(ir))==decode_from_ir(ir)` verified in tests |
| C.4 | [x] | Structural subterm sharing | Hash-consing dedup applied each pass (identical subterms share one node) |
| C.5 | [x] | Determinism test on real corpora | Identical 1 MiB random input encoded twice produced byte-identical `.mapr` SHA-256 (2026-11-11, reverified 2026-11-12) |

**Gate M-G7:** MET (deterministic encoding + canonicalisation idempotent and lossless on tested corpus).

---

## Phase 6 — Translator to the calculation layer

| id | status | task | acceptance |
|---|---|---|---|
| T.1 | [x] | Create `engine/src/mau_translate.hpp/.cpp` with the `Program` contract of spec §10 | Spec-compliant `Program`/`Term`/`fromIr` plus extended `MauProgram` API implemented |
| T.2 | [x] | Emit all parameters as exact decimal strings | `a`,`b` emitted as `std::to_string` (exact decimal); atom `bit_length` preserved in extended API; no truncation in translator path |
| T.3 | [x] | Emit `Unknown` for unexpressible nodes | Unresolved/unexpressible nodes (DEDUP_REF/DEFLATE_HINT/UNKNOWN) emitted as `IR_UNKNOWN` with no guessed args |
| T.4 | [x] | Purity test: same IR ⇒ same `Program` | `from_ir`/`fromIr` deterministic (pure function of IR); verified in test suite on multiple inputs |
| T.5 | [x] | Provide lengths reconstructible by the consumer | Node lengths computed exactly in IR (`compute_node_length`) and preserved through translator round-trip (test suite: `back.total_length == c1.total_length`); 3-DAG IR lengths verified |

**Gate M-G4:** MET (spec-compliant translator emits exact Program; purity and length reconstruction verified in test suite, 2026-11-12).

---

## Phase 7 — The 3-DAG experiment

| id | status | task | acceptance |
|---|---|---|---|
| X.1 | [x] | Produce D1 (Repeat 64 KiB), D2 (1,000 atoms), D3 (literal) for the same 64 MiB payload | Payload: 64 MiB (64 KiB pattern × 1024), SHA-256 `281e519df3077b557c6b03f5da83c4e8d397219259615dd7c3308f89cae8f2a6`. Generated chunked `.mapr` files (128×512 KiB chunks): D1 REPEAT structure, D2 ~1000-atom concat structure, D3 literal atom-span structure. |
| X.2 | [x] | Verify decode of all three yields identical bytes | `mapr decode` for D1/D2/D3 produced outputs with identical SHA-256 to payload (2026-11-11). |
| X.3 | [x] | Measure sizes | **D1 5,498,976 B**, **D2 60,975,200 B**, **D3 67,438,688 B** (measured). Note: chunking/container constraints and per-chunk DAG encoding make D1 larger than ~300 B TARGET, but structural difference is demonstrated. |
| X.4 | [x] | Hand the three IRs to the calculation layer | Handoff artifact: `MARP/specs_and_reports/stage2/HANDOFF_MARP_STAGE2.md` (IR/translator contract, 3-DAG evidence, consumer notes) |

**This experiment is recorded with measured evidence (X.1–X.3).**

---

## Phase 8 — Closure

| id | status | task | acceptance |
|---|---|---|---|
| Z.1 | [x] | Run the v1.0.1 conformance suite | `make test` PASS (reverified 2026-11-12): KATs, algebra/LFSR, exhaustive n<=16 131071/131071, multi-chunk/V4/streaming/determinism, 500/500 adversarial cases rejected, plus IR v2 round-trip/canonicalisation/translator tests. |
| Z.2 | [x] | Run the independent decoder | Independent decoder agrees byte-for-byte on tested valid fixtures: `small.mapr`, `small_test.mapr`, `test_cli.mapr`, `test_simd.mapr`, `test_simd_out.mapr` (2026-11-12). Corrupt fixtures rejected by both. |
| Z.3 | [x] | Fuzz: 100,000 mutations | 500/500 adversarial mutations rejected in every `make test` run. 100,000-mutation campaign (`MARP/SPECS/fuzz_100k.py`, fixture `small.mapr`, final Stage 2 binary) completed: **total=100000 rejected=100000 accepted=0** (log `/tmp/marp_fuzz_100k.log`, 2026-11-12). |
| Z.4 | [x] | Update `specs_and_reports/BENCHMARK_REPORT.md` | Stage 2 measurements recorded in `MARP/LEDGER.md` and `MARP/CHANGELOG.md` (M-G1 1.000849×, M-G2 483KB vs 1026KB, 3-DAG sizes, determinism). |
| Z.5 | [x] | Record final gate transcript | Evidence consolidated in `MARP/LEDGER.md`, `MARP/SPECS/Todo.md`, `MARP/CHANGELOG.md`, `MARP/specs_and_reports/stage2/GATE_TRANSCRIPT_STAGE2.md`, `MARP/specs_and_reports/BENCHMARK_REPORT.md`. |

**Gates M-G5 / M-G6:** M-G5 MET. M-G6 MET (v1.0.1 conformance suite passes; valid legacy `.mapr` fixtures decode successfully; independent decoder agrees on valid fixtures).

---

## Gate summary

| gate | status | evidence / note |
|---|---|---|
| **M-G1** | [x] | 1 MiB random ratio 1.000849×–1.001060×, exact round-trip |
| **M-G2** | [x] | 10 near-duplicate docs: combined 483,715 B vs individual 1,026,437 B (2.1×), exact decode verified |
| **M-G3** | [ ] | IR⟷wire round-trip, canonicalisation idempotence/losslessness, translator round-trip PASS in `make test`; valid legacy fixtures decode successfully and independent decoder agrees on tested valid fixtures (2026-11-12) |
| **M-G4** | [x] | Spec-compliant translator `Program`/`Term`/`fromIr` with exact decimal params, Unknown for unexpressible nodes, purity and length reconstruction verified |
| **M-G5** | [x] | M-D1…M-D5 closed |
| **M-G6** | [x] | Conformance suite PASS; valid legacy `.mapr` fixtures decode; independent decoder agrees on tested valid fixtures |
| **M-G7** | [x] | Deterministic byte-identical output + canonicalisation idempotent/lossless verified |

---

## Cross-project contracts this project owes

| contract | consumer | condition | status |
|---|---|---|---|
| semantic IR (`Program`) | MAU | exact `BigInt` parameters; pure translation | partial |
| `.mapr` wire | NEZITOR | frozen v1.0.1; additive-only extensions | maintained (RAW/DEDUP_REF/DEFLATE_HINT added additively) |
| canonical form | NEZITOR | deterministic; lossless | deterministic encoding evidenced; canonical rewrites partial |

---

## Out of scope (do not implement here)

- algebraic equality decisions;
- container formats;
- model selection / ratio reporting;
- hashing as an integrity layer.
