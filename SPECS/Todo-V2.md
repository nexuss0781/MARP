# MARP v2 — Fresh Todo

**Parent specification:** `MARP/SPECS/SPECS-V2.md`
**Predecessor (v1 Stage 2):** `MARP/SPECS/Todo.md` — closed record, not modified by v2 work.
**Harness:** `MARP/harness/v2/run_all.sh` → `MARP/specs_and_reports/v2/ACCEPTANCE.md`

**Rule:** an item is `[x]` only when its acceptance condition is measured by the v2 harness and the evidence path exists. No item is closed on inspection, estimate, or a hand-typed number.

**Status legend:** `[ ]` todo · `[~]` in progress · `[x]` done · `[!]` blocked

**Scope law:** the engine is byte-universal. No task may introduce a ZIP, PDF, video, tensor, ELF, or JSON code path into the core. Optional accelerators are advisory and MUST NOT be required by any gate.

---

## Phase 0 — Harness, fixtures, floor audit

| id | status | task | acceptance | evidence |
|---|---|---|---|---|
| P.1 | [ ] | Create `harness/v2/` layout and `run_all.sh` skeleton | `run_all.sh` builds, prints version, and exits 0 with an empty gate set | `logs/v2p1_bootstrap.log` |
| P.2 | [ ] | Implement `gen_fixtures.py` for F00–F10, F13–F15 | every fixture reproduces its recorded SHA-256 on a second generation; `fixtures.tsv` is generated, not typed | `fixtures.tsv`, `logs/v2p2_fixtures.log` |
| P.3 | [ ] | Add `--real` and `--coded` inputs for F11/F12 | arbitrary paths are accepted as opaque bytes; SHA-256 and size recorded; no type inspection | `logs/v2p3_real.log` |
| P.4 | [ ] | Implement `mapr floor` best-of-ensemble audit | `xz -9e`, `zstd -19`, `brotli -q 11`, `bzip2 -9` rows emitted with sizes and versions; an unavailable tool is recorded, never silently skipped | `floor.tsv`, `logs/v2p4_floor.log` |
| P.5 | [ ] | Implement TSV/JSON row writer and `render_acceptance.py` | `ACCEPTANCE.md` is generated from TSVs; a missing row makes rendering fail | `logs/v2p5_render.log` |
| P.6 | [ ] | Implement corrupted-container self-test | V2-G0 rejects a header CRC flip and a truncated trailer; valid minimal v2 container decodes | `logs/v2g0_selftest.log` |
| P.7 | [ ] | Implement `ref_coder.py` for atom-residual measurement | actual coded bytes emitted for each atom class; deterministic; bounded memory | `logs/v2p7_refcoder.log` |

**Gate V2-P0:** P.1–P.7 closed; harness runs end to end with the v1 binary and writes `FAIL` rows without crashing.

---

## Phase 1 — Core algebra and canonical IR

| id | status | task | acceptance | evidence |
|---|---|---|---|---|
| C.1 | [ ] | Implement `BigInt` (non-negative, exact, canonical decimal/bytes) | add/sub/mul/div/mod/compare/shift/parse/format tests for values above 2^128 | `logs/v2c1_bigint.log` |
| C.2 | [ ] | Define `Node`/`Atom`/`Ir` per spec §4 | structs compile; no floating point; no `size_t` truncation | `logs/v2c2_build.log` |
| C.3 | [ ] | Implement exact `length()` for all 12 node kinds | property test: random terms, `length` matches evaluated byte count | `logs/v2c3_length.log` |
| C.4 | [ ] | Implement `denote()` for all node kinds | exhaustive small-term test vs a reference byte evaluator | `logs/v2c4_denote.log` |
| C.5 | [ ] | Implement canonicalisation §3.8 rules 1–13 | `canon(canon(x)) == canon(x)` on 10,000 random terms; denotation preserved | `logs/v2c5_canon.log` |
| C.6 | [ ] | Implement hash-consing and first-use id assignment | identical subterms share one id; atom/node ids dense and ordered | `logs/v2c6_ids.log` |
| C.7 | [ ] | Implement deterministic tie-breaking §7.4 | two runs and `--threads 1|4` produce identical canonical bytes | `logs/v2c7_determinism.log` |
| C.8 | [ ] | Implement unused-node/atom pruning and root = last node | every emitted IR is minimal; root invariant holds | `logs/v2c8_prune.log` |

**Gate V2-P1:** C.1–C.8 closed; canonicalisation is total, idempotent, and denotation-preserving on the test corpus.

---

## Phase 2 — Wire v2, validation, decoder

| id | status | task | acceptance | evidence |
|---|---|---|---|---|
| W.1 | [ ] | Implement canonical uvarint and bigint codecs | round-trip for 0, 1, 2^63, 2^64, 2^128, 2^4096; non-canonical forms rejected | `logs/v2w1_int.log` |
| W.2 | [ ] | Implement header, atom table, node table, trailer writer | byte layout matches spec §5; CRCs correct | `logs/v2w2_writer.log` |
| W.3 | [ ] | Implement optional seek index | index is sorted, bounded, and never changes denotation | `logs/v2w3_index.log` |
| W.4 | [ ] | Implement validator in the order of §5.9 | every malformed class in the fuzz corpus is rejected with the expected exit code | `logs/v2w4_validate.log` |
| W.5 | [ ] | Implement streaming full decoder | F00–F10 decode byte-exactly with RSS <= 128 MiB | `logs/v2w5_decode.log`, `perf.tsv` |
| W.6 | [ ] | Implement `--range START:LEN` decoder | F13/F14 end slices are exact; direct evaluation for Zero/Affine/Lfsr/Repeat | `logs/v2w6_range.log` |
| W.7 | [ ] | Implement atomic output and self-verification | a forced encode mismatch exits 6 and leaves no partial file | `logs/v2w7_atomic.log` |
| W.8 | [ ] | Implement `inspect` and `term` JSON | every field is populated from the wire; lengths are decimal-exact | `logs/v2w8_inspect.log` |

**Gate V2-P2:** W.1–W.8 closed; v2 wire round-trips exactly and rejects malformed containers.

---

## Phase 3 — Discovery primitives

| id | status | task | acceptance | evidence |
|---|---|---|---|---|
| D.1 | [ ] | Implement M0 provenance and rolling hashes | SHA-256, length, and gear fingerprints match a reference on 1 GiB | `logs/v2d1_provenance.log` |
| D.2 | [ ] | Implement M1 multi-scale content-defined segmentation | boundaries reproduce on repeated runs and across thread counts | `logs/v2d2_segment.log` |
| D.3 | [ ] | Implement order-0/1/2 entropy and run statistics | measured values match an independent Python computation | `logs/v2d3_entropy.log` |
| D.4 | [ ] | Implement minimal-period and tile detection | exact period is found on F03/F04 and verified on the full segment | `logs/v2d4_period.log` |
| D.5 | [ ] | Implement `Zero`, `Repeat`, `Slice`, `Concat` candidate generation | every emitted candidate expands byte-exactly | `logs/v2d5_basic.log` |
| D.6 | [ ] | Implement `Affine` detection | F05/F06 emit `Affine`; expansion exact | `logs/v2d6_affine.log` |
| D.7 | [ ] | Implement Berlekamp–Massey and `Lfsr` detection | F07 emits `Lfsr` with order <= 64; expansion exact | `logs/v2d7_lfsr.log` |
| D.8 | [ ] | Implement morph search (catalogue §3.4) | transformed match on a synthetic corpus; false matches rejected by exact compare | `logs/v2d8_morph.log` |
| D.9 | [ ] | Implement `Xor` and `Interleave` candidates | equal-length checks enforced; plane transpose round-trips exactly | `logs/v2d9_xor_interleave.log` |
| D.10 | [ ] | Implement exact verifier for every candidate | no candidate enters the IR without byte-exact expansion | `logs/v2d10_verify.log` |

**Gate V2-P3:** D.1–D.10 closed; F02–F08 are expressible with exact terms and <= 1 % atom residual (report the measured value).

---

## Phase 4 — Grammar and global references

| id | status | task | acceptance | evidence |
|---|---|---|---|---|
| G.1 | [ ] | Implement bounded Re-Pair / Sequitur phrase discovery | dictionary size bounded; expansion exact; overflow stops cleanly | `logs/v2g1_grammar.log` |
| G.2 | [ ] | Desugar grammar rules into `Concat`/`Repeat`/shared nodes | no grammar-specific node appears in the wire | `logs/v2g2_desugar.log` |
| G.3 | [ ] | Implement content-addressed exact dedup | duplicate fixtures share one node; decode exact | `logs/v2g3_dedup.log` |
| G.4 | [ ] | Implement near-duplicate candidate search + exact `Xor` | 1 % mutation corpus improves over per-file baseline; false positives rejected | `logs/v2g4_neardup.log` |
| G.5 | [ ] | Implement deterministic global index serialisation | insertion order is first-use; no hash-map iteration leaks | `logs/v2g5_index.log` |
| G.6 | [ ] | Measure grammar/dedup gain on F08/F09 | gain recorded in `perf.tsv`; atom residual reported | `perf.tsv` |

**Gate V2-P4:** G.1–G.6 closed; grammar and dedup improve measured size with exact decode.

---

## Phase 5 — Transforms, predictors, atom classes

| id | status | task | acceptance | evidence |
|---|---|---|---|---|
| T.1 | [ ] | Implement all nine morphisms | exhaustive small-input KATs for each morph and inverse | `logs/v2t1_morph_kats.log` |
| T.2 | [ ] | Implement predictor catalogue §3.6 | each predictor reconstructs its input exactly from a residual | `logs/v2t2_predictors.log` |
| T.3 | [ ] | Implement predictor selection by residual entropy | selected predictor reduces estimated coded bits on F05/F06 | `logs/v2t3_predictor_select.log` |
| T.4 | [ ] | Implement stride/reshape and plane transforms | synthetic matrix/tensor-shaped bytes are transposed exactly | `logs/v2t4_stride.log` |
| T.5 | [ ] | Implement atom classifier §6.9 | classes are assigned from measured features; no filename/type input | `logs/v2t5_classifier.log` |
| T.6 | [ ] | Implement per-class coded-size estimate | estimates are monotone and bounded by 8 bits/byte | `logs/v2t6_estimate.log` |
| T.7 | [ ] | Verify classifier never changes denotation | encode/decode exact with classifier on and off | `logs/v2t7_exact.log` |
| T.8 | [ ] | Measure transform/predictor gain on F11/F12 | gain over baseline recorded; no size claim below floor | `perf.tsv` |

**Gate V2-P5:** T.1–T.8 closed; transforms and predictors are exact and measurably useful.

---

## Phase 6 — MDL selector and streaming planner

| id | status | task | acceptance | evidence |
|---|---|---|---|---|
| S.1 | [ ] | Implement the MDL cost model of Appendix A | cost is deterministic and recomputable from the IR | `logs/v2s1_cost.log` |
| S.2 | [ ] | Implement beam search over segments and candidates | same input/effort yields the same selected term | `logs/v2s2_beam.log` |
| S.3 | [ ] | Implement effort levels 0–9 | higher effort never increases measured wire size on the corpus | `perf.tsv` |
| S.4 | [ ] | Implement bounded-memory atom spill | 4 GiB encode RSS <= 256 MiB | `perf.tsv` |
| S.5 | [ ] | Implement deterministic parallel segment discovery | `--threads 1|4` byte-identical output | `logs/v2s5_parallel.log` |
| S.6 | [ ] | Implement atom budget and fallback to `Atom` | budget respected; exactness preserved | `logs/v2s6_budget.log` |

**Gate V2-P6:** S.1–S.6 closed; the selector is deterministic, bounded, and honest.

---

## Phase 7 — CLI, legacy compatibility, MAU bridge

| id | status | task | acceptance | evidence |
|---|---|---|---|---|
| L.1 | [ ] | Implement the v2 CLI of spec §11 | every command in the help text works and has a test | `logs/v2l1_cli.log` |
| L.2 | [ ] | Implement `spec-zero`, `spec-repeat`, `spec-lfsr`, `spec-affine` | generators produce exact virtual containers without materialising the payload | `logs/v2l2_spec.log` |
| L.3 | [ ] | Implement v1.0.1/v1.1 legacy decode | every legacy fixture decodes byte-exactly | `logs/v2l3_legacy.log` |
| L.4 | [ ] | Implement `mapr floor` CLI integration | floor rows are emitted for F11/F12/F15 | `floor.tsv` |
| L.5 | [ ] | Implement `mapr term --json` | pure translator; decimal strings; no truncation | `logs/v2l5_term.log` |
| L.6 | [ ] | Implement certificate emission/verification | forged fact is rejected; valid fact accepted | `logs/v2l6_cert.log` |

**Gate V2-P7:** L.1–L.6 closed; CLI and legacy paths are exact.

---

## Phase 8 — MAU contract and exact arithmetic

| id | status | task | acceptance | evidence |
|---|---|---|---|---|
| M.1 | [ ] | Publish `translate::Program` per spec §9 | header/API compiles; versioned | `logs/v2m1_api.log` |
| M.2 | [ ] | Emit all lengths/params as exact decimal | values above 2^64 survive a round-trip through MAU | `logs/v2m2_bigdec.log` |
| M.3 | [ ] | Reconstruct every node length from `Program` alone | 3-DAG experiment and random-term test agree with IR | `logs/v2m3_lengths.log` |
| M.4 | [ ] | Implement `eval(Program, range)` contract test | MAU-side reference evaluates F13/F14 slices exactly | `logs/v2m4_range.log` |
| M.5 | [ ] | Purity and unknown-node policy | same IR -> same `Program`; unknown nodes marked, never guessed | `logs/v2m5_purity.log` |

**Gate V2-P8:** M.1–M.5 closed; MAU can compute every declared fact exactly.

---

## Phase 9 — Acceptance harness and evidence

| id | status | task | acceptance | evidence |
|---|---|---|---|---|
| H.1 | [ ] | V2-G0 harness self-test | corrupted rejected, valid decoded | `logs/v2g0_selftest.log` |
| H.2 | [ ] | V2-G1 exact round-trip F00–F12, F15 | SHA-256 and `cmp` match on every fixture | `gates.tsv` |
| H.3 | [ ] | V2-G2 determinism | two runs × two thread counts byte-identical | `logs/v2g2_determinism.log` |
| H.4 | [ ] | V2-G3 structured size | F02/F03 <= 1 MiB; F04 4 GiB <= 8 MiB | `gates.tsv` |
| H.5 | [ ] | V2-G4 structural coverage | >= 99.9 % non-atom bytes on F02–F08; residual reported | `gates.tsv` |
| H.6 | [ ] | V2-G5 noise ratio | F10 <= 1.005× | `gates.tsv` |
| H.7 | [ ] | V2-G6 best-of-ensemble | F11/F15 `wire + ref_coder` <= 1.02× best generic; F12 <= 1.02× | `floor.tsv` |
| H.8 | [ ] | V2-G7 floor honesty | atom residual and best generic reported for every size-claim fixture; no claim below floor | `floor.tsv` |
| H.9 | [ ] | V2-G8 range probe | F13/F14 end slices exact without full materialisation | `logs/v2g8_range.log` |
| H.10 | [ ] | V2-G9 fuzz 100k | `accepted_invalid=0`, `crashes=0`, `timeouts=0` | `logs/v2g9_fuzz.log` |
| H.11 | [ ] | V2-G10 memory | encode 4 GiB <= 256 MiB; decode <= 128 MiB | `perf.tsv` |
| H.12 | [ ] | V2-G11 throughput | structured >= 25 MiB/s; RAW >= 100 MiB/s; decode >= 100 MiB/s on tmpfs | `perf.tsv` |
| H.13 | [ ] | V2-G12 independent decoder | clean-room Python decodes F00–F08 byte-exactly | `logs/v2g12_indep.log` |
| H.14 | [ ] | V2-G13 legacy | v1.0.1/v1.1 fixtures decode byte-exactly | `logs/v2g13_legacy.log` |
| H.15 | [ ] | V2-G14 byte-universal real files | F11/F12 exact; gates pass with plugins disabled | `gates.tsv` |
| H.16 | [ ] | V2-G15/V2-G16 MAU + canonical idempotence | decimal-exact lengths; `canon(canon(x))==canon(x)`; re-canonicalising the decoded IR re-emits identical wire | `logs/v2g15_mau.log`, `logs/v2g16_canon.log` |

**Gate V2-P9:** H.1–H.16 all `PASS`; `ACCEPTANCE.md` rendered from TSVs; `GATE_TRANSCRIPT.txt` and `logs/SHA256SUMS` complete.

---

## Phase 10 — Real-byte stress and closure

| id | status | task | acceptance | evidence |
|---|---|---|---|---|
| A.1 | [ ] | Run the full harness on the reference host | `RESULT: PASS`; environment recorded | `GATE_TRANSCRIPT.txt` |
| A.2 | [ ] | Run F11 on at least three opaque real byte strings of different kinds (e.g. a PDF, a video sample, a zip) | all exact; no type-specific code path; floor rows present | `logs/v2a2_real.log` |
| A.3 | [ ] | Run F12 on at least one already entropy-coded input | exact; ratio reported honestly; no KB claim | `logs/v2a3_coded.log` |
| A.4 | [ ] | Run the 1 GiB and 4 GiB structured demonstrations | wire sizes meet V2-G3; decode exact | `gates.tsv` |
| A.5 | [ ] | Produce the v2 acceptance report | `ACCEPTANCE.md`, `perf.md`, `floor.md` generated; every row has a verdict | `specs_and_reports/v2/` |
| A.6 | [ ] | Update `LEDGER.md` and `CHANGELOG.md` for v2 | entries reference gate rows and evidence paths | `MARP/LEDGER.md`, `MARP/CHANGELOG.md` |

**Gate V2-P10:** A.1–A.6 closed; MARP v2 is accepted for the byte-universal contract and handed to NEZITOR.

---

## Definition of done

MARP v2 is done when:

1. Any finite byte string round-trips exactly (V2-G1, V2-G14).
2. The wire is canonical and deterministic (V2-G2, V2-G16).
3. Low-complexity multi-GB input is expressed in <= 1 MiB (V2-G3) with >= 99.9 % structural coverage (V2-G4).
4. High-entropy input is not overclaimed; the floor is reported (V2-G5–V2-G7).
5. The decoder is total, bounded, and independently cross-checked (V2-G8–V2-G13).
6. MAU receives exact decimal programs and can compute every length and range (V2-G15).
7. The harness regenerates every number in `ACCEPTANCE.md` with no hand edits.

---

## Blocked / open questions

| id | question | owner | resolution |
|---|---|---|---|
| Q.1 | Default effort level and atom budget | MARP | choose after P.4 floor audit |
| Q.2 | Whether to keep the optional index in v2.0 or defer | MARP | implement behind flag; decide at P2 |
| Q.3 | Legacy v1 writer retirement date | MARP | after V2-G13 and one full release |
| Q.4 | Predictor catalogue expansion beyond §3.6 | MARP + MAU | v2.1 only; v2.0 is closed |

---

*End of MARP v2 fresh todo.*
