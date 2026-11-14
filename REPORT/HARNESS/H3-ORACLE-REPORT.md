# H3 ORACLE — Clean-Room MARP v2 Wire Decoder, Validator, and Evaluator Report

## 1. Environment & Authoritative CI Run

- **Repository**: `nexuss0781/MARP`
- **Branch**: `arena/c3a96df3-marp`
- **Base commit**: `a61e2a254b70e4bc0a767f2927b8da31d158b7ca` (H2 GATES closeout)
- **Implementation commits**:
  - `304096744e1f492d8a2b376d4779defe3f8c459e` — clean-room H3 oracle implementation, test suite, `engine/Makefile.h3`, and `.github/workflows/h3-oracle.yml` (CI run [#43619069466](https://github.com/nexuss0781/MARP/actions/runs/43619069466), **SUCCESS**)
  - `614b7f4209e4cfbad61a9b9970002c23326b5639` — deterministic harness-written evidence (`H3-ORACLE.tsv`, `H3-ORACLE.log`, `SHA256SUMS`) and hard-fail CI committed-vs-generated TSV verification
- **CI workflow**: `MARP H3 Oracle CI` (`.github/workflows/h3-oracle.yml` — hard-fail throughout; zero `continue-on-error`, zero `|| true`)
- **Authoritative green run (evidence verification)**:
  - **Run ID**: `43619508436`
  - **URL**: https://github.com/nexuss0781/MARP/actions/runs/43619508436
  - **Conclusion**: **SUCCESS** (2026-11-14T17:08:58Z → 2026-11-14T17:10:29Z)
  - **Uploaded artifact**: `h3-evidence` (Artifact ID `14122959123`, 2,803 bytes, digest `sha256:bef4883d6dd9f6f7209d31733ea86898fbf681a3423e19264bbb442a947b9225`)
- **Runner & toolchain**: Ubuntu (`ubuntu-latest`), GCC C++20 (`-std=c++20 -pedantic -Wall -Wextra -Werror -Wconversion -Wshadow -Wnull-dereference -Wdouble-promotion -Wformat=2`), GoogleTest built in CI for `bin/oracle_tests` only; **`zlib1g-dev` intentionally omitted** to prove zero third-party dependency in `bin/mapr_oracle`.

### CI Jobs & Steps (Run `#43619508436` — All PASS)

| Job | Step | Result |
|---|---|---|
| `oracle-independence` | Verify clean-room source independence (`grep` + no `.py`/`.sh`) | PASS |
| `build-test-oracle` | Install dependencies (C++20 toolchain only, no zlib) | PASS |
| `build-test-oracle` | Build GoogleTest (tests only) | PASS |
| `build-test-oracle` | Build H3 oracle and tests (strict `-Werror`) | PASS |
| `build-test-oracle` | Verify binary independence (`grep`, `nm -C`, `ldd`) | PASS |
| `build-test-oracle` | Snapshot committed evidence & verify committed `SHA256SUMS` | PASS |
| `build-test-oracle` | Run H3 oracle test suite and write evidence | PASS |
| `build-test-oracle` | Verify committed `H3-ORACLE.tsv` matches CI-generated TSV byte-for-byte (`diff -u`) | PASS |
| `build-test-oracle` | External determinism check (repeat run `diff -u`) | PASS |
| `build-test-oracle` | Verify evidence schema, manifest, and honest `BLOCKED` state | PASS |
| `build-test-oracle` | Run H3 oracle suite with ASan and UBSan | PASS |
| `build-test-oracle` | Upload H3 oracle evidence artifact (`h3-evidence`) | PASS |

> Note: A subsequent commit adds this report (`REPORT/HARNESS/H3-ORACLE-REPORT.md`), triggering a final green CI verification run over the complete deliverable tree without altering any oracle source or evidence file.

---

## 2. Clean-Room Independence Proof

H3 `ORACLE` is structurally isolated from the MARP engine (`include/mapr/**`, `engine/src/**`) and H2 gate harness (`harness/include/marp/harness/**`, `harness/src/**`) at four independent layers:

1. **Source-level include scan** (enforced in CI job `oracle-independence` and inside `oracle_tests`):
   ```sh
   grep -rnE '^[[:space:]]*#[[:space:]]*include[[:space:]]*["<](mapr/|marp/harness/)' harness/oracle/
   ```
   Result: **0 matches** across all 10 files under `harness/oracle/` (`src_tree_sha256 = f01e2422e9c331948fb49bf9e0296a85ddfecc39ccb92af009ea852acf130e41`). No `.py` or `.sh` scripts exist under `harness/oracle/`.
2. **Compiler include-path isolation** (`engine/Makefile.h3`):
   - `H3_CXXFLAGS` passes `-I../harness/oracle/include` **only** (never `-I../include` or `-I../harness/include`). Any accidental `#include "mapr/..."` or `#include "marp/harness/..."` is a hard compile error.
3. **Link-time & symbol isolation** (`engine/Makefile.h3` target `h3-independence`):
   - `bin/mapr_oracle` links strictly `obj/h3/{bigint,crc32,sha256,decode,eval,cli}.o` + `-lpthread`. Zero `$(E1_OBJS)`, zero harness objects, zero `wire_builder.hpp` test code.
   - Verified via `nm -C bin/mapr_oracle | grep -E 'mapr::|marp::harness::|marp::v2::|test_wire'` → **0 matches**.
4. **Shared-library isolation** (`ldd bin/mapr_oracle`):
   - Links only standard C/C++ runtime libraries (`libstdc++`, `libgcc_s`, `libc`, `libm`). Zero `libz`, zero `libgtest`. All cryptographic/checksum/math primitives (FIPS 180-4 SHA-256, IEEE 802.3 CRC-32, base-`2^32` arbitrary-precision `BigInt`, canonical `uvarint`/`BigInt` wire codecs, 64-bit Fibonacci LFSR + GF(2) jump-ahead, morphisms, predictors) are implemented clean-room directly from the normative specifications.

---

## 3. Architecture & File Inventory

All H3 deliverables live in strictly isolated paths; **zero H2/E1 files** (`engine/Makefile`, `.github/workflows/ci.yml`, `harness/src/gates.cpp`, `specs_and_reports/v2/gates/E*-G.tsv`, etc.) were modified.

| Path | Role |
|---|---|
| `harness/oracle/include/marp/oracle/oracle.hpp` | Public clean-room API in `namespace marp::oracle`: `ErrorCode`, `ValidationStage`, `Limits`, `Info`, `Diagnostic`, required file APIs (`decode_file`, `verify_file`, `decode_range`, `inspect_file`), extended diagnostic/span overloads, and SHA-256/CRC-32 self-test helpers. |
| `harness/oracle/src/oracle_internal.hpp` | Internal declarations: `BigInt`, `Sha256`, `Crc32`, `ByteSource`, wire layout constants, `ParsedContainer`, stages 1–10 validator, and streaming full/range evaluators. |
| `harness/oracle/src/sha256.cpp` | Clean-room FIPS 180-4 streaming SHA-256 (standard IVs and 64 round constants). |
| `harness/oracle/src/crc32.cpp` | Clean-room IEEE 802.3 reflected CRC-32 (`0xEDB88320`, `constexpr` 256-entry table, no zlib). |
| `harness/oracle/src/bigint.cpp` | Pure ISO C++20 arbitrary-precision non-negative `BigInt` (no `__uint128_t` extensions; base-`2^32` limbs, add/sub/mul/binary long division, canonical decimal & little-endian byte codecs). |
| `harness/oracle/src/decode.cpp` | Bounded `FileSource`/`MemorySource`, `RegionReader` (canonical `uvarint` & tagged `BigInt`), strict E3 §5.1 stages 1–10 validator (iterative post-order first-use traversal & seek-index node-start verification), stable TSV `inspect` emitter, and file/span API wrappers (never leaving partial output files on error). |
| `harness/oracle/src/eval.cpp` | Iterative explicit-stack DAG evaluator (zero C++ recursion, 128 MiB scratch cap), 64×64 GF(2) matrix binary exponentiation LFSR jump-ahead (`O(log offset)`), all 9 morphisms (with unaligned word-swap and reversed-offset range support), all 5 predictors (streaming `O(N)` root fast path + pass-through optimization when `start+len <= param`), periodic `Repeat` copy, Stage 11 full streaming SHA-256 + exact-boundary index prefix CRC verification, and direct range streaming. |
| `harness/oracle/src/cli.cpp` | Standalone CLI driver (`bin/mapr_oracle`): `decode`, `verify`, `range`, `inspect` with normative exit codes (`0, 2, 3, 4, 5, 6, 7`) and structured TSV diagnostics on stderr. |
| `harness/oracle/tests/wire_builder.hpp` | **Test-only** spec-derived canonical & tamperable wire builder (never linked into `bin/mapr_oracle`, never presented as E3 output). |
| `harness/oracle/tests/oracle_test.cpp` | 15-suite GoogleTest verification harness covering digests, stages 1–11, stage precedence, canonical integers, 353 mutations, all 12 kinds / 9 morphisms / 5 predictors / LFSR jump-ahead / virtual `2^70` ranges, resource limits, CLI smoke matrix, determinism, source independence, honest `oracle.f00-f08` `BLOCKED` row, and atomic evidence/manifest emission (`--write-evidence`). |
| `engine/Makefile.h3` | Includes `Makefile` without editing it; defines isolated `h3-all`, `h3-test`, `h3-test-san`, `h3-independence`, `h3-clean` targets. |
| `.github/workflows/h3-oracle.yml` | Dedicated hard-fail CI workflow for H3 ORACLE. |

---

## 4. Wire Format & Validation Coverage (E3 §5.1 Stages 1–11)

The oracle enforces E3 §5.1 stages 1–11 strictly in order, stopping at the first failing stage and reporting both the normative exit code and the exact `ValidationStage`:

| Stage | Name | Normative Checks Enforced | Tested Coverage |
|---|---|---|---|
| 1 | `stage1_size` | `96 <= file_size <= max_container_bytes` (`2^63`) | Under-size (`0`, `64`, `95` B), exact `96` B empty container, over-limit custom cap → exit 7. |
| 2 | `stage2_header` | 8-byte magic `89 4D 41 50 52 32 0D 0A`, `major == 2 && minor == 0` (future `major > 2` or `(2, minor > 0)` → **exit 5 `Unsupported`**; `major < 2` → exit 4), `header_bytes == 64`, `flags` reserved bits `3..31 == 0`, required bits `1` (`canonical`) and `3` (`byte_aligned`) set | Pinned hand-assembled hex vectors (Empty 96 B, 1-byte Atom, `Zero(2^64)` 139 B with Region A.1 + tag `0x02`), bad magic, `v1.0` (4), `v2.1` (5), `v3.0` (5), `header_bytes != 64`, bad flag bits. |
| 3 | `stage3_bounds` | `trailer_offset == file_size - 32` and `trailer.file_bytes == file_size` | Misplaced `trailer_offset`, mismatched `trailer.file_bytes`, appended trailing garbage. |
| 4 | `stage4_header_crc` | Streaming CRC-32 over `[0, trailer_offset)` with `[60..64)` zeroed equals `header.file_crc32` | Single-bit flips across header, regions A.1/B/C/D, and `file_crc32`. |
| 5 | `stage5_trailer` | Trailer magic `TRLR2\r\n\x1a`, `trailer_crc32 == CRC32(trailer[0..28) \|\| LE32(file_crc32))`, `node_count >= 1`, `atom_count <= max_atoms`, `node_count <= max_nodes` | Bad trailer magic, bad `trailer_crc32`, `node_count == 0`, over-limit counts. |
| 6 | `stage6_regions` | Bit 2 (`total_len_u64`) vs Region A.1 (`big_len == 0` when bit 2=1; `big_len >= 9`, `total_length_u64 == 0`, non-zero MSB when bit 2=0), `atom_offset == 64 + big_len`, monotonic `atom_offset <= node_offset <= index/trailer`, bit 0 (`has_index`) vs `index_offset != 0` | Bit-2/big_len contradictions, leading-zero A.1 MSB, non-monotonic offsets, bit-0/`index_offset` contradictions. |
| 7 | `stage7_atoms` | Canonical `uvarint` count matching trailer, canonical `uvarint` atom lengths (`1..ATOM_MAX`), valid `codec_hint` (`0..4`), bounds check before reading, streaming SHA-256 computation, zero duplicate payloads (exact-byte dedup via SHA-256 + length + byte compare), exact Region B consumption | 0-length atom rejected, `codec_hint = 5` rejected, duplicate atoms (different hints) rejected, truncated payload, trailing junk byte, non-canonical count/len. |
| 8 | `stage8_nodes` | Canonical `uvarint` count matching trailer, valid kind (`0..11`), `flags == 0`, exact `argc` per kind, `arg < node_id` (acyclic DAG), kind-specific well-formedness & parameter canonicality, recomputed `BigInt` length == declared length, depth `<= max_depth`, structural deduplication, iterative post-order first-use order over nodes & atoms (no unused nodes/atoms), exact Region C consumption | Wrong `argc` for all 12 kinds, unknown kind, `node.flags != 0`, self/forward ref, every WF violation (`Slice` OOB, `Repeat` `q=0,r>0` / `r>=len(child)`, `Xor` len mismatch, `Interleave` `stride=0` / non-divisible / unequal children, `Morph` divisibility & `k`, `Lfsr` `conn=0`, `Predictor` `pid>4` / param rules), declared length mismatch, duplicate node, non-post-order, unused node, unused atom, depth `65537 > 2^16`. |
| 9 | `stage9_root` | `trailer.root_id == node_count - 1` and `nodes[root_id].length == total_length` | `root_id != node_count - 1`, root length mismatch vs header `total_length`. |
| 10 | `stage10_index` | Optional; when present: magic `IDX2\r\n\x1a\0`, `index_crc32 == CRC32(index[0..len-4))`, `entry_count >= 1`, canonical offsets that are strictly increasing multiples of `INDEX_STRIDE = 1 MiB` (`< total_length`), `node_id < node_count` equal to smallest node starting at that output offset (verified via iterative DAG start-offset map), exact Region D consumption | Valid 3 MiB indexed & unindexed equivalence, bad magic, bad `index_crc32`, empty index, unsorted entries, non-1-MiB-aligned offset, wrong `node_id` (non-smallest), trailing junk. |
| 11 | `stage11_eval` | `total_length <= max_output_bytes`, iterative chunked evaluation, exact-boundary seek-index prefix CRC-32 match (mismatch → exit 4 `Invalid`), total emitted byte count & `--sha256` match (mismatch → exit 6 `Mismatch`) | Valid full decode, corrupt index prefix CRC (exit 4 at `stage11_eval`), `--sha256` match (0) vs mismatch (6), over-limit full verify (exit 7). |

- **Adjacent stage-order precedence (`wire.stage_order`)**: 11/11 multi-defect precedence pairs (`1 < 2 < 3 < 4 < 5 < 6 < 7 < 8 < 9 < 10 < 11`) verified to stop at the earlier stage.
- **Canonical integer enforcement (`wire.bigint`)**: 24/24 accept/reject cases covering `uvarint` (overlong 2-byte `0`, `10`-byte overflow, truncated) and tagged `BigInt` (`0x00` vs `0x01` vs `0x02` boundary values `0`, `2^64-1`, `2^64`, `2^128`, non-minimal tags, leading zero MSB in tag `0x02`, invalid tag `0x03`, `len < 9`).
- **Systematic mutation sweep (`wire.mutations`)**: 353/353 mutations (every byte flip across header, atoms, nodes, trailer + every truncation length `0..N-1` + appended garbage) rejected with **0 invalid containers accepted**.

---

## 5. Semantics & Evaluation Coverage

- **Published digest KATs (`digest.vectors`)**: 8/8 exact matches — FIPS 180-4 SHA-256 (`""`, `"abc"`, 448-bit 2-block, `1,000,000 × 'a'`) and IEEE 802.3 CRC-32 (`""`, `"123456789"` = `0xCBF43926`, 32×`0x00`, 32×`0xFF`).
- **All 12 node kinds (`eval.kinds`)**: 13/13 exact tests (`Empty`, `Atom`, `Zero`, `Concat` multi-way, `Repeat` with `q=0,r=0` and `q>0,r>0`, `Slice`, `Morph`, `Xor` 2-way & 3-way, `Interleave` multi-stride & `argc=1`, `Lfsr`, `Affine`, `Predictor`, plus nested composite DAGs).
- **All 9 morphisms (`eval.morph`)**: 21/21 exact tests covering `BIT_REVERSE8` (1), `INVERT8` (2), `SWAP16` (3), `SWAP32` (4), `SWAP64` (5), `ROTL8` (6, all `k = 1..7`), `ROTR8` (7, all `k = 1..7`), `REVERSE_BYTES` (8), `REVERSE_BITS` (9), including unaligned sub-ranges across word swaps and involution round-trips.
- **All 5 predictors (`eval.predictor`)**: 18/18 exact tests covering `DELTA8` (0), `XOR8` (1), `LINEAR2` (2), `STRIDE_XOR` (3, including `param > len`), `STRIDE_DELTA` (4, including `param > len`), plus **multi-chunk 100,000-byte (`> 64 KiB`) streaming & mid-range decode** for all 5 predictors verified byte-for-byte against naive reference loops.
- **64-bit Fibonacci LFSR & GF(2) jump-ahead (`eval.lfsr`)**: 5/5 exact tests — bit-by-bit reference comparison, `init=0` all-zero stream, arbitrary-offset range jump vs full stream, and **virtual `2^70`-byte LFSR end-range decode** (`start = 2^70 - 64`) verified against an independent GF(2) state transition matrix exponentiation in <1 ms.
- **Range decode & huge virtual containers (`eval.range`)**: 7/7 exact tests — `Zero(2^70)` tail, `Affine(2^70)` tail, `Concat(Zero(2^50), Atom("TAIL_MARK"))` boundary-crossing range, `Repeat(Atom("ABCDE"), q=2^64, r=3)` tail, `Morph(REVERSE_BYTES, Affine(2^70))` start range (evaluating reversed `2^70` tail in `O(1)` memory), `Interleave` `argc=1` + exhaustive unaligned sub-ranges, and out-of-bounds / invalid decimal rejections.
- **Iterative explicit-stack evaluation**: Zero C++ recursion in either Stage 8 post-order traversal or Stage 11/range evaluation; tested cleanly at DAG depth `5,000` (and ASan/UBSan clean).

---

## 6. Resource Limits & Allocation Safety

Every declared count, offset, and length is bounds-checked against container size and resource limits **before** any allocation:

| Resource | Default Limit | Behaviour on Violation |
|---|---|---|
| Container size (`max_container_bytes`) | `2^63` bytes | Stage 1 → exit `7` (`Limit`) |
| Atom count (`max_atoms`) | `2^24` | Stage 5 → exit `7` (`Limit`) |
| Node count (`max_nodes`) | `2^24` | Stage 5 → exit `7` (`Limit`) |
| DAG depth (`max_depth`) | `2^16` (`65536`) | Stage 8 → exit `7` (`Limit`) (tested at `65537` with default limits) |
| Full output (`max_output_bytes`) | `2^63` bytes | Stage 11 → exit `7` (`Limit`) (tested on `Zero(2^64)` and `Zero(2^70)`) |
| Range expansion (`max_range_expansion_factor`) | `file_bytes * 2^20` | Range decode → exit `7` (`Limit`) |
| Predictor prefix (`max_predictor_prefix`) | `2^28` bytes | Range decode → exit `7` (`Limit`) (tested at `start = 270,000,000`) |
| Stride predictor ring buffer (`max_stride_ring_bytes`) | `64 MiB` | Exit `7` (`Limit`); bypassed when `start + len <= param` (pass-through) |
| Evaluator scratch memory (`max_eval_scratch_bytes`) | `128 MiB` | Exit `7` (`Limit`) |

`resource.limits` verifies 6/6 safety scenarios: `Zero(2^70)` `verify --structure-only` (exit 0) vs full `verify` (exit 7), expansion-factor cap (exit 7), absurd declared `atom_count`/`node_count` = `1,000,000` on tiny containers (exit 4, zero huge allocation), depth `5000` pass + depth `65537` exit 7, and predictor prefix `> 2^28` exit 7. Failed `decode_file` / `decode_range` calls are verified to leave no partial output file on disk.

---

## 7. Spec Conflicts, Ambiguities, and Defects Discovered

Per precedence rules, where `SPECS/SPECS-V2.md` (parent) and `SPECS/COMPONENTS/e3-wire/SPECS.md` (E3 component spec) disagree, H3 follows the more specific E3 component specification and records every conflict/ambiguity below:

1. **BigInt canonical encoding (`SPECS-V2.md` §5.3 vs `e3-wire/SPECS.md` §4.9)**:
   - Parent §5.3 omits explicit minimum-tag canonicality rules; E3 §4.9 mandates `0` → tag `0x00` (1 B), `1..2^64-1` → tag `0x01` + `u64` (9 B), `>= 2^64` → tag `0x02` + `uvarint(len >= 9)` + LE magnitude with `MSB != 0`.
   - **Resolution**: E3 §4.9 enforced strictly; all non-canonical encodings rejected with exit `4`.
2. **Header flag bit 2 (`total_len_u64`) (`SPECS-V2.md` §5.2 vs `e3-wire/SPECS.md` §4.3)**:
   - Parent §5.2 describes Region A.1 coarsely; E3 §4.3 pins bit 2 = 1 iff `total_length <= 2^64 - 1` (`total_length_big_len == 0`) and bit 2 = 0 iff `total_length >= 2^64` (`total_length_u64 == 0`, `total_length_big_len >= 9`, non-zero MSB).
   - **Resolution**: E3 §4.3 enforced strictly in Stage 6.
3. **Atom payload minimum length (`SPECS-V2.md` §5.4 vs `e3-wire/SPECS.md` §4.5)**:
   - Parent §5.4 does not explicitly forbid 0-byte atoms; E3 §4.5 requires `1 <= len <= ATOM_MAX` (`Empty` node represents length-0 strings).
   - **Resolution**: E3 §4.5 enforced in Stage 7 (`len == 0` rejected with exit `4`).
4. **Seek index policy & prefix CRC stage (`e3-wire/SPECS.md` §4.7, §5.1)**:
   - Seek index is optional (bit 0 = 1 iff `index_offset != 0`), uses `INDEX_STRIDE = 1 MiB`, must be non-empty when present, entries must have strictly increasing 1-MiB-aligned offsets `< total_length`, and `node_id` must be the smallest node starting at that output offset. Prefix CRCs are verified during Stage 11 streaming evaluation (not Stage 10 structure-only), returning exit `4` on mismatch.
   - **Resolution**: E3 §4.7 & §5.1 followed exactly.
5. **Trailer CRC input (`SPECS-V2.md` §5.7 vs `e3-wire/SPECS.md` §4.8)**:
   - Parent §5.7 leaves the exact byte span ambiguous; E3 §4.8 specifies `trailer_crc32 = CRC32(trailer[0..28) || LE32(file_crc32))`.
   - **Resolution**: E3 §4.8 implemented in Stage 5.
6. **Index CRC input (`e3-wire/SPECS.md` §4.7)**:
   - Narrowest normative reading: `index_crc32 = CRC32(index[0..index_len - 4))` covering the magic, `entry_count`, and all entries immediately preceding the trailing 4-byte CRC.
   - **Resolution**: Documented and enforced in Stage 10.
7. **Spec defect in `LINEAR2` (`predictor_id = 2`) (`SPECS-V2.md` §3.6 and `e2-algebra/SPECS.md` §4.11 vs §7 O3.3)**:
   - **Defect**: Both `SPECS-V2.md` §3.6 and `SPECS/COMPONENTS/e2-algebra/SPECS.md` §4.11 define `LINEAR2` as:
     `out[0] = r[0]`, `out[1] = r[1]`, `out[i] = (2 * out[i-1] - out[i-2]) mod 256` — **omitting `+ r[i]`**, which contradicts E2 §7 O3.3 ("exact inverse of the residual") because residuals `r[2..n-1]` are ignored!
   - **Resolution**: Per the clean-room rule (do not silently diverge from the written normative formula), H3 implements the literal normative formula `(2 * out[i-1] - out[i-2]) mod 256` and explicitly flags this spec defect here for upstream resolution before E2/E3 freeze.
8. **`Predictor` parameter domain (`e3-wire/SPECS.md` §4.6)**:
   - E3 §4.6 specifies `param` is used for stride predictors (`pid in {3, 4}`) and unused for `pid in {0, 1, 2}`.
   - **Resolution**: Narrowest canonical reading enforced: `param == 0` required for `pid <= 2`; `param >= 1` required for `pid in {3, 4}`.
9. **`Interleave` minimum `argc` (`e3-wire/SPECS.md` §4.6 vs `e2-algebra/SPECS.md` §4.7)**:
   - E3 §4.6 allows `argc >= 1` at the wire layer, whereas E2 §4.7 algebraic canonicality folds `argc == 1` away.
   - **Resolution**: E3 §4.6 followed at the wire decoder (`argc >= 1` accepted; `argc == 0` rejected).
10. **Independent oracle implementation language (`SPECS-V2.md` §12.7 vs `COMPONENTS-V2.md` A1)**:
    - Parent §12.7 references an older `indep_decode_v2.py` script; `COMPONENTS-V2.md` A1 mandates **C++20 only** with zero Python scripts committed.
    - **Resolution**: `bin/mapr_oracle` (pure C++20) supersedes `indep_decode_v2.py`.

---

## 8. Evidence & Verification Summary

Harness-written evidence artifacts committed under `specs_and_reports/v2/`:
- `specs_and_reports/v2/gates/H3-ORACLE.tsv` (18 rows: **17 PASS, 0 FAIL, 1 BLOCKED**; SHA-256 `171a95451efd15eb5191b4e1855ff01479fd5254a7da4e0f957dbdee5686d067`)
- `specs_and_reports/v2/logs/H3-ORACLE.log` (SHA-256 `43c443690adf87f98fe93c1cf0450d6bf571c7e2b88e49eea414b47cfe9fa2f9`)
- `specs_and_reports/v2/evidence/H3/SHA256SUMS`

### Summary of `H3-ORACLE.tsv` Rows (Verified Byte-Identical in CI Run `#43619508436`)

| Check | Item ID | Expected / Actual | Verdict |
|---|---|---|---|
| `determinism` | `repeat-decode-and-inspect` | Repeated library + CLI decode/inspect byte-identical | PASS |
| `digest.vectors` | `sha256-crc32-kat` | `8/8 published KATs match` | PASS |
| `eval.kinds` | `all-12-node-kinds` | `13/13 exact` | PASS |
| `eval.lfsr` | `lfsr-kats-and-2p70-jump` | `5/5 exact` | PASS |
| `eval.morph` | `all-9-morphs-all-k` | `21/21 exact` | PASS |
| `eval.predictor` | `all-5-predictors` | `18/18 exact` | PASS |
| `eval.range` | `virtual-2p50-2p70-and-bounds` | `7/7 exact` | PASS |
| `independence` | `grep-and-nm-clean-room` | `0 forbidden includes across 10 oracle files; nm_clean=YES` | PASS |
| `oracle.f00-f08` | `f00-f08-cross-check` | `BLOCKED: E3 wire producer absent` | **BLOCKED** |
| `resource.limits` | `limits-oom-depth-expansion` | `6/6 safe` | PASS |
| `wire.atoms` | `atom-table-rules` | `11/11 passed` | PASS |
| `wire.bigint` | `canonical-uvarint-bigint` | `24/24 passed` | PASS |
| `wire.header` | `stages-1-2-3-4-6-pinned` | `22/22 passed` | PASS |
| `wire.index` | `seek-index-3mib` | `8/8 passed` | PASS |
| `wire.mutations` | `exhaustive-byte-flip-and-trunc` | `353 rejected / 0 accepted` | PASS |
| `wire.nodes` | `node-table-rules` | `37/37 passed` | PASS |
| `wire.stage_order` | `stages-1-to-11-precedence` | `11/11 ordered` | PASS |
| `wire.trailer` | `stages-5-9-trailer-root` | `5/5 passed` | PASS |

### Verification Highlights
- **Committed vs CI diff**: In CI run `#43619508436`, `diff -u /tmp/committed-H3-ORACLE.tsv specs_and_reports/v2/gates/H3-ORACLE.tsv` exited `0` (byte-for-byte identical).
- **External determinism**: Second independent CI run produced a byte-for-byte identical `H3-ORACLE.tsv`.
- **Sanitizers**: Full 15-suite test matrix + CLI binary ran cleanly under `-fsanitize=address,undefined` (`h3-test-san`) with 0 ASan, 0 LSan, and 0 UBSan findings.
- **CLI smoke matrix**: Verified `decode <wire> <out> [--info]`, `verify <wire> [--sha256 <hex>] [--structure-only]`, `range <wire> <start> <len> <out>`, and `inspect <wire>` (stable TSV, zero prose) across valid, large `2^70`, mismatch (`6`), invalid (`4`), unsupported future version (`5`), missing file (`3`), limit (`7`), and bad CLI args (`2`).

---

## 9. Honest Blockers (`oracle.f00-f08`)

- **Status**: `oracle.f00-f08` is recorded as **`BLOCKED`** (never `PASS`), and `H3-ORACLE.log` reports `RESULT: BLOCKED (all implemented H3 oracle checks PASS; oracle.f00-f08 BLOCKED awaiting E3)`.
- **Reason**: Component **E3 (`e3-wire`)** has not yet been implemented in this repository, so no engine-produced MARP v2 wire files exist for fixtures `F00–F08`. Test-only `wire_builder.hpp` exercises the oracle against spec-derived synthetic wires and is explicitly **never** presented as E3 output.
- **Unblock condition**: Once E3 emits MARP v2 containers for `F00–F08`, cross-check every E3 container with `bin/mapr_oracle verify <wire> --sha256 <fixture_sha256>` and `bin/mapr_oracle decode` / `range` (and `verify --structure-only` + tail `range` for huge virtual fixtures) to transition `oracle.f00-f08` from `BLOCKED` to `PASS`.

---

## 10. Next Work & Handoff

- **H1 FIXTURES**: Can continue independently without file conflicts.
- **E2 ALGEBRA**: Should resolve the `LINEAR2` (`pid=2`) `+ r[i]` formula defect noted in §7 before wire freeze; once resolved in both `SPECS-V2.md` §3.6 and `e2-algebra/SPECS.md` §4.11, update the single `case 2U` line in `harness/oracle/src/eval.cpp` and `oracle_test.cpp` in lockstep.
- **E3 WIRE**: Immediately after E3 builds, integrate `bin/mapr_oracle` as the independent cross-decoder for `E3-G` and unblock `oracle.f00-f08`.
- **H4 FUZZ & E7 CLI**: `marp::oracle::validate_bytes` / `decode_bytes` / `bin/mapr_oracle` provide a zero-dependency differential oracle for corpus fuzzing and end-to-end CLI verification.
