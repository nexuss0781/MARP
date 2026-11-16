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

### Addendum: `oracle.f00-f08` unblock (F00–F08 cross-check)

- **Branch**: `arena/d4f43dd9-marp`
- **Base commit**: `fa41289c3f15605a17e6858001ca345af8adab02` (`origin/h2-gates`, the H3 unblock prompt commit)
- **Implementation commit**: `4c907e9` — E3-side F00–F08 wire producer, H3 cross-check suite, refreshed H3 evidence, refreshed C07 evidence, `h3-oracle.yml` unblock checks
- **Authoritative green run for that commit**: `MARP H3 Oracle CI` run [`43891189743`](https://github.com/nexuss0781/MARP/actions/runs/43891189743) — **SUCCESS** (all 15 steps PASS, including the committed-vs-CI TSV byte diff, the independent determinism re-run, the `oracle.f00-f08` PASS-state checks, and the ASan/UBSan subset)
- **Result**: `oracle.f00-f08` is **PASS** (measured; 9/9 byte-exact). No `BLOCKED` row remains anywhere in `H3-ORACLE.tsv`.
- Full method, measured identities and per-fixture results: §11. This report commit is report-and-evidence only and triggers a final green verification run over the complete deliverable tree.

### CI Jobs & Steps (Runs `#43619508436` and `#43891189743` — All PASS)

| Job | Step | Result |
|---|---|---|
| `oracle-independence` | Verify clean-room source independence (`grep` + no `.py`/`.sh`) | PASS |
| `build-test-oracle` | Install dependencies (C++20 toolchain only, no zlib) | PASS |
| `build-test-oracle` | Build GoogleTest (tests only) | PASS |
| `build-test-oracle` | Build H3 oracle and tests (strict `-Werror`) | PASS |
| `build-test-oracle` | Verify binary independence (`grep`, `nm -C`, `ldd`) | PASS |
| `build-test-oracle` | **_new_**: Build the E3 F00–F08 wire producer and prove no engine/C07 symbol leaked into the oracle binaries | PASS |
| `build-test-oracle` | **_new_**: Emit the F00–F08 canonical v2 wires via C07 and record their identities | PASS |
| `build-test-oracle` | Snapshot committed evidence & verify committed `SHA256SUMS` | PASS |
| `build-test-oracle` | Run H3 oracle test suite and write evidence (`--cross-check-dir …`) | PASS |
| `build-test-oracle` | Verify committed `H3-ORACLE.tsv` matches CI-generated TSV byte-for-byte (`diff -u`) | PASS |
| `build-test-oracle` | External determinism check (repeat run `diff -u`) | PASS |
| `build-test-oracle` | Verify evidence schema, manifest, and **unblocked F00–F08** state (row is `PASS`, 0 `BLOCKED`, 9-row manifest, `RESULT: PASS`) | PASS |
| `build-test-oracle` | Run H3 oracle suite with ASan and UBSan (with a sanitizer-sized cross-check subset `F00,F01,F02,F03,F05`) | PASS |
| `build-test-oracle` | Upload H3 oracle evidence artifact (`h3-evidence`, now also carrying the fixture/wire manifest and the producer log) | PASS |

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
| `.github/workflows/h3-oracle.yml` | Dedicated hard-fail CI workflow for H3 ORACLE (addendum: also builds/runs the E3 producer, requires the `oracle.f00-f08` PASS state, and runs a sanitizer-sized cross-check subset). |
| `harness/crosscheck/f00f08_producer.cpp` | **E3 side** of the cross-check (added by the unblock): builds the canonical E2 term per fixture, canonicalises it, emits the C07 wire, validates it, and writes the deterministic identity manifest. Separate binary; never linked into, referenced by, or included from `harness/oracle/**`. |
| `specs_and_reports/v2/evidence/H3/f00-f08-manifest.tsv` | Harness-published fixture/wire identity manifest (9 rows) for F00–F08; hash-pinned by `evidence/H3/SHA256SUMS`. |

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

Harness-written evidence artifacts committed under `specs_and_reports/v2/` (state after the F00–F08 unblock; `H3-ORACLE.log` carries the host/date banner by design, so only the TSV and the manifests are compared across runs):
- `specs_and_reports/v2/gates/H3-ORACLE.tsv` (18 rows: **18 PASS, 0 FAIL, 0 BLOCKED**; SHA-256 `fa6474b7e3539dcb00531ec66b2eae6663800dfdb89a16264d401fab2a02b66f`)
- `specs_and_reports/v2/logs/H3-ORACLE.log` (`RESULT: PASS`; SHA-256 `f578665748729ce4c2edcf91116faea8f808fd4ab44ba0c91428aa75128780f9` as committed)
- `specs_and_reports/v2/evidence/H3/f00-f08-manifest.tsv` (9 rows; SHA-256 `78fa069b2b62938678cc8ea2e3d5028f4cfb9e76d60f63b011decb044b103421`)
- `specs_and_reports/v2/evidence/H3/SHA256SUMS` (3 entries: TSV, log, F00–F08 manifest)

### Summary of `H3-ORACLE.tsv` Rows (Verified Byte-Identical in CI Run `#43891189743`; the 17 pre-existing rows and their values are unchanged from run `#43619508436`)

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
| `oracle.f00-f08` | `f00-f08-cross-check` | `9/9 byte-exact; wire_bytes=264651; engine_vs_oracle=9/9 digests agree` | **PASS** |
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

## 9. F00–F08 Cross-Check (`oracle.f00-f08`) — Unblocked

- **Status**: `oracle.f00-f08` is **`PASS`**, measured, and no longer `BLOCKED`. `H3-ORACLE.log` reports `RESULT: PASS` with `totals: total=18 pass=18 fail=0 blocked=0`.
- **What was blocked before**: H3 itself was complete, but the row could only be an honest `BLOCKED` because no engine-produced MARP v2 wire existed for `F00–F08`. The test-only `wire_builder.hpp` was never presented as E3 output, and still is not.
- **What unblocked it**: E3 (C07/C08) landed and is green, so an *E3-side* producer (`harness/crosscheck/f00f08_producer.cpp`) now emits the unique canonical v2 wire for each of `F00–F08`, and the clean-room oracle independently decodes and verifies each one against the H1 fixture identity. See §11 for the measured evidence.
- **Residual limitations (honest)**: byte-exactness is proven by full-stream SHA-256 equality (`sha256(out)==sha256(in)`) plus literal byte comparison for `F00`/`F01`; no multi-gigabyte fixture is materialised anywhere (see §11.6). No claim is made about `F09–F15`, which are outside this work item.

---

## 10. Next Work & Handoff

- **H1 FIXTURES**: Can continue independently without file conflicts.
- **E2 ALGEBRA**: Should resolve the `LINEAR2` (`pid=2`) `+ r[i]` formula defect noted in §7 before wire freeze; once resolved in both `SPECS-V2.md` §3.6 and `e2-algebra/SPECS.md` §4.11, update the single `case 2U` line in `harness/oracle/src/eval.cpp` and `oracle_test.cpp` in lockstep.
- **E3 WIRE**: Landed. `bin/mapr_oracle` is the independent cross-decoder for `E3-G`, and `oracle.f00-f08` is unblocked (§9, §11). Future C07 wire-format changes must re-run `make -f Makefile.h3 h3-test-cross` and refresh the H3 evidence; the C07 gate records the `H3-ORACLE.tsv` digest in its `precondition.h3` row, so C07 evidence must be regenerated in the same change (see §11.9).
- **H4 FUZZ & E7 CLI**: `marp::oracle::validate_bytes` / `decode_bytes` / `bin/mapr_oracle` provide a zero-dependency differential oracle for corpus fuzzing and end-to-end CLI verification.

---

## 11. Addendum — F00–F08 Cross-Check Implementation and Measured Evidence

### 11.1 Base, head, and CI

| Item | Value |
|---|---|
| Base | `fa41289c3f15605a17e6858001ca345af8adab02` (`origin/h2-gates`) |
| Implementation commit | `4c907e9` |
| Authoritative green run (H3 Oracle CI) | [`43891189743`](https://github.com/nexuss0781/MARP/actions/runs/43891189743) — **SUCCESS**, 15/15 steps |
| Green regression runs on the same commit | E2 C03/C04/C05/C06, E2-G, E3 C07, E3 C08, E3-G, H4 FUZZ (see §11.9) |
| Evidence refresh required by the unblock | `specs_and_reports/v2/gates/C07-WIRE.tsv` (`precondition.h3` digest only), `evidence/C07/SHA256SUMS` |

### 11.2 Separation of duties

| Side | Artefact | Duty |
|---|---|---|
| E3 (engine) | `harness/crosscheck/f00f08_producer.cpp` → `bin/h3_f00f08_producer` | Build the canonical E2 term per fixture, `canon` + `check_canonical`, `encode` (twice), full §5.1 `validate`, and write the wires + identity manifest. Links E1/E2/C07 and the H1 fixture generators. |
| H3 (clean room) | `harness/oracle/tests/oracle_test.cpp` → `OracleF00F08CrossCheck` | Read the wire files as **opaque bytes**, run stages 1–11 itself, and require its own output SHA-256 to equal the **H1** fixture digest. Links nothing from the engine. |

The oracle test never receives an `Ir`, a term, or an engine-provided digest: it gets file paths and a manifest, and re-derives everything. `bin/mapr_oracle` and `bin/oracle_tests` contain **zero** `marp::v2::`/`h3_f00f08` symbols (CI checks this with `nm` immediately after the producer is built).

### 11.3 Fixture and wire identities (measured)

Fixtures come from the H1 §12.3 generators (`harness/src/fixtures.cpp`); the producer re-identifies each one with `marp::harness::identify()` (streaming re-hash) and requires exact agreement with the committed `specs_and_reports/v2/fixtures.tsv`. Committed copy: `specs_and_reports/v2/evidence/H3/f00-f08-manifest.tsv`.

| Fixture | Bytes | Source SHA-256 (= H1 identity) | Canonical E2 term | Wire bytes | Wire SHA-256 |
|---|---|---|---|---|---|
| `F00` | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | `empty` | 103 | `75d1ba312e42aa98297e8ff30ef9c0afb8f2c2455a1d7848c3a93e1eb48e439f` |
| `F01` | 1 | `6922e93e3827642ce4b883c756b31abf80036649d3614bf5fcb3adda43b8ea32` | `atom(n=1)` | 144 | `9b89ab60a9ac21786151d9157e5634330a3e7822c7cdf17c11921acafc57b0a7` |
| `F02` | 1,073,741,824 | `49bc20df15e412a64472421e13fe86ff1c5165e18b2afccf160d4dc19fe68a14` | `zero(n=1073741824)` | 114 | `6392d69fcc0ac3832dc9c2d48fecbb28f6c13779ca972a525918d40ab94e738f` |
| `F03` | 1,073,741,824 | `265ddb125876c185ec1ac81fb97b0f3fb8f11b0c1b175da6831af5fd0589b950` | `repeat(atom(n=65536),q=16384,r=0)` | 76,712 | `28c92786144945edbb13a87ec5caeea1045cdcb276b58ad67b7f384cc264f1f6` |
| `F04` | 4,294,967,296 | `57b3ff1cda55685e82d65cf335c912657f5faf077855a82721deb573681f4fc8` | `repeat(atom(n=65536),q=65536,r=0)` | 110,504 | `48c51af6f2a39f8f53d0b0f9154b9789b2a89acf86bc8f345e17b050713cf76e` |
| `F05` | 268,435,456 | `dc29c5647a3c395caa2190dcce07cc7249bdcda02e9c68c7960992df3e394263` | `affine(n=268435456,start=11,step=3)` | 116 | `c9aefd67e87fbab83894b2a73cb84c3ab2753371b47390b88cdbe60ba4685c42` |
| `F06` | 1,073,741,824 | `2c06ade942ee3f17a048dd1064b2fab046a4bb95386d8bb41b68dc6711ac2af3` | `affine(n=1073741824,start=0,step=1)` | 116 | `5edfa4636c7745e747f14f157c195853342028f03a36cdfa050c00833e84a4aa` |
| `F07` | 1,073,741,824 | `6856a2756d4bdb7b1338cff249793b3cc3a39dfb7eaa7d0d2eb8bfb91bbb3bb9` | `lfsr(n=1073741824,conn=0xd800000000000000,init=0x4d41525048314637)` | 130 | `1deb0f8efadf42f80bf9f1de714f0b7693d4eed0701136484551d05072c94a25` |
| `F08` | 1,073,741,824 | `11d734012586d248dccbba7a241b88b9030bcb21b847875cd3c07e7744332107` | `repeat(atom(n=65536),q=16384,r=0)` | 76,712 | `8ef782089c25dfcd4f5050d2b09e87031a73c31b1065cddfc83c9a2dc5a40c76` |

Totals: **9,932,111,873 fixture bytes → 264,651 wire bytes** (all nine wires together are ~254 KiB). Every wire is canonical per E3: `canon` fixed point, `check_canonical` clean, `encode` byte-identical on a second call, `encoded_size` equal to the emitted size, and full §5.1 validation PASS.

### 11.4 Per-fixture oracle verification (clean-room, independent)

Expected digests are the H1 identities above — never the wire's own trailer. Each row is a full `verify_bytes(wire, expected_sha256)` by the oracle, plus a structural re-validation (stages 1–10) and a node/atom-count agreement check against the canonical term.

| Fixture | Oracle output SHA-256 | = H1? | Emitted length | = H1? | nodes/atoms | index | literal bytes | Verdict |
|---|---|---|---|---|---|---|---|---|
| `F00` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | yes | 0 | yes | 1/0 | absent | `equal` (empty) | PASS |
| `F01` | `6922e93e3827642ce4b883c756b31abf80036649d3614bf5fcb3adda43b8ea32` | yes | 1 | yes | 1/1 | absent | `equal` (`A5`) | PASS |
| `F02` | `49bc20df15e412a64472421e13fe86ff1c5165e18b2afccf160d4dc19fe68a14` | yes | 1,073,741,824 | yes | 1/0 | absent | n/a | PASS |
| `F03` | `265ddb125876c185ec1ac81fb97b0f3fb8f11b0c1b175da6831af5fd0589b950` | yes | 1,073,741,824 | yes | 2/1 | present | n/a | PASS |
| `F04` | `57b3ff1cda55685e82d65cf335c912657f5faf077855a82721deb573681f4fc8` | yes | 4,294,967,296 | yes | 2/1 | present | n/a | PASS |
| `F05` | `dc29c5647a3c395caa2190dcce07cc7249bdcda02e9c68c7960992df3e394263` | yes | 268,435,456 | yes | 1/0 | absent | n/a | PASS |
| `F06` | `2c06ade942ee3f17a048dd1064b2fab046a4bb95386d8bb41b68dc6711ac2af3` | yes | 1,073,741,824 | yes | 1/0 | absent | n/a | PASS |
| `F07` | `6856a2756d4bdb7b1338cff249793b3cc3a39dfb7eaa7d0d2eb8bfb91bbb3bb9` | yes | 1,073,741,824 | yes | 1/0 | absent | n/a | PASS |
| `F08` | `11d734012586d248dccbba7a241b88b9030bcb21b847875cd3c07e7744332107` | yes | 1,073,741,824 | yes | 2/1 | present | n/a | PASS |

Evidence row: `oracle.f00-f08	ORACLE	f00-f08-cross-check	d3ed8e4cb39432535ee4e4b79698f9eb6ef453d6b693ed6c02acd85c2d1e42e0	9/9 byte-exact (sha256(out)==sha256(in))	9/9 byte-exact; wire_bytes=264651; engine_vs_oracle=9/9 digests agree	PASS`. The `input_sha256` is the SHA-256 of the canonical `id, bytes, H1 sha256, wire bytes, wire sha256` summary built from the oracle's own measurements, so it is host-independent.

### 11.5 Decisions on ambiguity (narrowest interpretation)

1. **F08 term shape.** The H1 generator nests leaf/copy/group repeats *inside* the pinned 64 KiB grammar block and mutates one byte per group; the fixture stream is that block repeated 16 384 times. No E2 kind expresses "the same block with a single mutated byte", and an `Atom` is a leaf under E2 §4.7, so the canonical term that denotes the fixture's bytes is `Repeat(Atom(64 KiB), q=16384, r=0)` — exactly the shape used for F03. This is recorded, not silently assumed.
2. **Byte-exactness measurement.** All nine fixtures are verified by full-stream SHA-256 equality of the oracle's own evaluation against the H1 digest (equal length + equal digest over the same bytes), and `F00`/`F01` additionally by literal byte comparison. `cmp`-style comparison of two 8.6 GiB materialisations is deliberately not performed: it would require writing both sides to disk for no additional cryptographic strength. Nothing here claims more than that.
3. **Stage-11 work bound.** The producer raises `WireLimits::max_eval_bytes` to `2^42` so stage 11 actually evaluates F04's 4 GiB (the default 1 GiB bound would return `Limit` at stage `Eval`). This is a resource bound, not a format constant: the emitted bytes depend only on the canonical `Ir`.
4. **No stale row is representable.** `oracle_tests --write-evidence` now requires `--cross-check-dir` and exits `2` without it; `write_h3_evidence()` emits a `FAIL` row (never `BLOCKED`, never a hand-written verdict) if the cross-check test did not run. The row itself is written by the test that measured it.
5. **C07 evidence refresh.** The C07 gate records the `H3-ORACLE.tsv` digest in its `precondition.h3` row, so changing H3 evidence necessarily changes one C07 value. It was regenerated by the gate itself (`./bin/c07_wire_gate --root .. --oracle-bin bin/mapr_oracle --write-evidence`); only that digest changed and `C07-WIRE.log` is byte-identical (§11.9).

### 11.6 Scale and resource handling

- **No fixture is materialised.** The producer streams the H1 generators (`identify()`), and the oracle streams its evaluation into its own SHA-256 in stage 11; peak memory is the wire itself (≤ 110,504 B), ≤ 1 MiB of atom payload, and the evaluator's 128 MiB scratch cap.
- **Committed evidence stays small**: 9-row manifest (~2.2 KiB), 3-entry `SHA256SUMS`; the wires (254 KiB total) are build output under the git-ignored `engine/build/h3-crosscheck/` and are **never committed**.
- **Measured wall clock** (2-core sandbox, single-threaded work): producer 212 s (identify + encode + full validate over 9.93 GB), oracle cross-check 85 s, whole H3 CI job 7 m 33 s.

### 11.7 Clean-room independence (unchanged and re-proven)

- `grep -rnE '#include ["<](mapr/|marp/harness/)' harness/oracle/` → **0 matches**; no `.py`/`.sh` under `harness/oracle/`.
- `-I../harness/oracle/include` only for the oracle; `nm -C bin/mapr_oracle` free of `mapr::`/`marp::harness::`/`marp::v2::`/`test_wire`; `ldd` shows only libstdc++/libgcc/libc/libm (no `libz`, no `libgtest`).
- CI now additionally asserts, right after the producer is built, that `bin/mapr_oracle` and `bin/oracle_tests` contain no `marp::v2::`/`h3_f00f08` symbol — i.e. building the E3 side cannot leak into the oracle.
- The cross-check data path is file-based only: `harness/oracle/**` names no engine header, and the oracle test contains no engine type.

### 11.8 Determinism

- `encode()` is called twice per fixture and the bytes must match; the manifest contains no clock, host, path or ordering that varies.
- CI compares the committed `H3-ORACLE.tsv` with the CI-generated one byte-for-byte, then re-runs the whole suite into a separate root and diffs the two TSVs again — both green in run `43891189743`.
- The committed `evidence/H3/f00-f08-manifest.tsv` is regenerated by the producer on every CI run and re-published by the harness, so a drifted or hand-edited manifest breaks `SHA256SUMS`.

### 11.9 Regressions and compatible evidence refresh

- **H3**: 17 previously PASS rows unchanged (same `input_sha256`/`expected`/`actual` values); `oracle.f00-f08` flipped `BLOCKED → PASS`; 0 FAIL, 0 BLOCKED. The `independence` row's `src_tree_sha256` moved from `f01e2422…` to `1e2354de…` only because `oracle_test.cpp` changed — the include scan result is still `0 forbidden includes across 10 oracle files`.
- **C07**: `precondition.h3` actual `1567d07d… → fa6474b7…` (the new `H3-ORACLE.tsv` digest); every other C07 row and the whole `C07-WIRE.log` byte-identical (`1170/1170` rows PASS).
- **E2-G**: its H3 precondition hashes `harness/oracle/src/eval.cpp` (unchanged) and reads the `independence` verdict (`PASS` before and after) — no E2-G evidence change.
- **E3-G / C08 / H4**: use the oracle binary (unchanged sources) and the predecessor manifests; all green on `4c907e9`.
- Green on `4c907e9`: `MARP H3 Oracle CI` `43891189743`, `MARP E2 C03 TERM CI` `43891189985`, `MARP E2 C04 CANON CI` `43891189758`, `MARP E2 C05 EVAL CI` `43891189973`, `MARP E2 C06 DAG CI` `43891189638`, `MARP E2-G ALGEBRA CI` `43891189700`, `MARP E3 C07 WIRE CI` `43891189784` (failed only on the stale C07 evidence refreshed in this commit), `MARP E3 C08 LEGACY CI` `43891189980`, `MARP E3-G integrated gate CI` `43891189654`, `MARP H4 FUZZ CI` `43891189680`.

### 11.10 Reproducing the evidence locally

```sh
cd engine
make -f Makefile.h3 h3-clean && make -f Makefile.h3 h3-all -j4
make -f Makefile.h3 h3-producer -j4
./bin/h3_f00f08_producer --root .. --out build/h3-crosscheck   # wires + manifest
./bin/oracle_tests --oracle-bin ./bin/mapr_oracle --nm-verified --write-evidence .. \
    --cross-check-dir build/h3-crosscheck --repo-root ..       # evidence + oracle cross-check
diff <committed H3-ORACLE.tsv> specs_and_reports/v2/gates/H3-ORACLE.tsv
```

`make -f Makefile.h3 h3-test-cross` performs the producer + oracle run in one step; `h3-test` and `h3-test-san` remain the plain (no-evidence) runs, and the sanitizer run accepts `H3_SAN_ARGS="--cross-check-dir build/h3-crosscheck --cross-check-only F00,F01,F02,F03,F05 --repo-root .."`.
