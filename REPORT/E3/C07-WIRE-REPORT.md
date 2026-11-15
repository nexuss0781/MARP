# C07 WIRE — E3 v2 canonical container — implementation report

**Component**: C07 WIRE (E3 WIRE, first sub-component of E3).
**Branch**: `arena/0c5e3d50-marp` (base `abe500b4a98725a214c7074ab0aa4ef90b0fbd18`).
**Green CI run**: **[43743973411](https://github.com/nexuss0781/MARP/actions/runs/43743973411)** —
conclusion `success`, commit **`4cd3b6f90e13aa737705dc15bb2fed71cbf1187b`**.
Both jobs passed: `C07 independence (source level)` and `C07 build, tests, evidence`.

**Status: C07 WIRE is complete and green.** 1170 of 1170 evidence rows `PASS`, 0 `FAIL`,
0 `BLOCKED`. 48 of 48 unit tests pass in the strict build *and* under
AddressSanitizer + UndefinedBehaviorSanitizer.

> **This report does not claim E3-G.** E3-G additionally requires C08 LEGACY (v1
> decode), the `W-V1` legacy corpus, the 100 000-case fuzz campaign, and the full
> E3 §13.4 gate matrix. None of that is implemented here and none of it is claimed.
> §9 lists exactly what remains for E3-G.

---

## 1. What was delivered

| Path | Contents |
|---|---|
| `include/mapr/e3/e3_wire.hpp` | The whole C07 public surface: `plan`, `encoded_size`, `encode_to`, `encode`, `validate`, `decode`, `decode_stream`; `WirePlan`, `Validation`, `WireLimits`, `WireError`/`WireCode`/`Stage`; the canonical `uvarint` and tagged-`bigint` codecs; `Source`/`SpanSource`/`Arena`/`HeapArena`/`Reader`; all format constants. |
| `engine/src/e3/e3_wire.cpp` | Constants, `SpanSource`, `HeapArena`, `Reader`, codecs, `measure_tables`, `plan`, `encoded_size`, `encode_to`, `encode`, and the §12 limit checks. |
| `engine/src/e3/e3_wire_index.cpp` | Canonical seek-index policy, `append_index_region`, `fill_prefix_crcs`, `validate_index_entries`, `append_wire`, `write_wire`. |
| `engine/src/e3/e3_wire_read.cpp` | The 11-stage §5.1 driver: header, bounds, CRC, trailer, regions, atom table, node table, root, index, evaluation, index-prefix verification; `validate`/`decode`/`decode_stream`. |
| `engine/src/e3/e3_wire_internal.hpp` | `detail::` internals shared by the three translation units (no public surface leaks). |
| `engine/tests/e3/c07_wire_test.cpp` | 48 GoogleTest cases over the public API only. |
| `engine/src/e3g/c07_corpus.{hpp,cpp}` | The corpus: 60 items built through E2's `Dag` (or directly, then certified by E2, where `Dag::finish`'s output cap forbids the shape). |
| `engine/src/e3g/c07_gate.cpp` | The C07 gate: every obligation becomes one TSV row with exact expected/actual values. |
| `engine/src/e3g/c07_report.{hpp,cpp}`, `c07_checks.hpp`, `c07_oracle.{hpp,cpp}`, `c07_main.cpp` | Evidence rows, log lines, and the process-isolated H3 oracle cross-check. |
| `engine/Makefile.c07` | Isolated build: strict flags, `-O2` build, sanitizer build, test target, evidence target, `c07-isolation`. |
| `.github/workflows/e3-c07.yml` | Isolated CI: independence, build, tests, evidence byte-identity, schema, determinism, ASan/UBSan, no-regression. |
| `specs_and_reports/v2/gates/C07-WIRE.tsv` | 1170 rows of harness-written evidence. |
| `specs_and_reports/v2/logs/C07-WIRE.log` | The run log, per-section totals, `RESULT: PASS (C07 WIRE)`. |
| `specs_and_reports/v2/evidence/C07/SHA256SUMS` | Manifest of the two files above. |

Nothing outside these paths was modified. No existing workflow, makefile, header,
or source file was touched; the C07 addition is purely additive (§10).

---

## 2. Format implemented (E3 §4, which governs over parent §5)

### 2.1 Header — 64 bytes

| Off | Size | Field | Canonical value |
|---|---|---|---|
| 0 | 8 | magic | `89 4D 41 50 52 32 0D 0A` (`\x89MAPR2\r\n`) |
| 8 | 2 | `version_major` | 2 |
| 10 | 2 | `version_minor` | 0 |
| 12 | 4 | `flags` | §2.2 |
| 16 | 2 | `header_bytes` | 64 |
| 18 | 8 | `total_length_u64` | 0 when the big form is used |
| 26 | 2 | `total_length_big_len` | 0 when the u64 form is used |
| 28 | 8 | `atom_offset` | `64 + total_length_big_len` |
| 36 | 8 | `node_offset` | end of the atom table |
| 44 | 8 | `index_offset` | 0 if absent |
| 52 | 8 | `trailer_offset` | end of the last region before the trailer |
| 60 | 4 | `file_crc32` | CRC-32 over `[0, trailer_offset)` with this field zeroed |

### 2.2 Flags

`b0` index present, `b1` canonical (must be 1), `b2` all lengths fit u64,
`b3` byte-aligned (must be 1), `b4–b31` zero. `encode` sets exactly the bits the
content requires, so the checked-in corpus exercises `b0` set, `b0` clear,
`b2` set and `b2` clear.

### 2.3 Total length — u64 vs Region A.1 (E3 §4.4)

```text
if total_length <= 2^64-1 : total_length_u64 = value, big_len = 0, Region A.1 absent
else                      : total_length_u64 = 0, big_len = len(magnitude) >= 9
                            Region A.1 = little-endian magnitude, no leading zero byte
```

Region A.1 sits at `[64, 64 + big_len)` and `atom_offset = 64 + big_len`. It is a
raw magnitude, **not** a tagged bigint. Measured: `Zero(2^64)` gives `big_len = 9`,
`atom_offset = 73`, `node_offset = 74`, `trailer_offset = 107`, 139 bytes total.

### 2.4 Canonical integers (E3 §4.9)

| Tag | Payload | Rule |
|---|---|---|
| `0x00` | none | value 0 **only** |
| `0x01` | `uvarint v` | `1 <= v <= 2^64-1` |
| `0x02` | `u32 len`, `len` LE magnitude bytes | value `>= 2^64`; `len >= 9`; **last** byte nonzero |

`uvarint` is the shortest form, at most 10 bytes, and a 10-byte form must not
overflow u64. Rejected: `uvarint` with a redundant trailing zero group, `0x01`
with `v = 0`, `0x02` with `len < 9`, `0x02` with a zero most-significant byte, and
any unknown tag.

### 2.5 Atom table (E3 §4.5)

`uvarint atom_count`, then `atom_count ×` `{ u8 klass, u8 flags(0), u16 reserved(0),
bigint length, u8[32] sha256, length × payload }`. `length` must be in
`[1, ATOM_MAX = 1 048 576]` and equal the record's payload size, which is what
the wire implies; `sha256` must be SHA-256 of the payload. Canonical order is
first use in post-order, with no duplicates.

### 2.6 Node table (E3 §4.6)

`uvarint node_count`, then `node_count ×` `{ u8 kind, u8 flags(0), u16 argc,
argc × uvarint arg, kind params, bigint length }`.

| kind | id | params | argc |
|---|---|---|---|
| `Empty` | 0 | — | 0 |
| `Atom` | 1 | `uvarint atom_id` | 0 |
| `Zero` | 2 | `bigint n` | 0 |
| `Concat` | 3 | — | `>= 2` |
| `Repeat` | 4 | `bigint q`, `bigint r` | 1 |
| `Slice` | 5 | `bigint start`, `bigint len` | 1 |
| `Morph` | 6 | `u8 morph`, `u8 k` | 1 |
| `Xor` | 7 | — | 2 |
| `Interleave` | 8 | `u32 stride` | `>= 1` |
| `Lfsr` | 9 | `u64 conn`, `u64 init`, `bigint n` | 0 |
| `Affine` | 10 | `u8 start`, `u8 step`, `bigint n` | 0 |
| `Predictor` | 11 | `u8 pid`, `u32 param` | 1 |

Every arg must be `< own record index`; the order is post-order first use; the
root is the last record; every record is reachable and none is unused; `length`
must equal E2's §3.7 recomputation. E2's canonicality (`check_canonical`) is the
authority and is consulted inside stage 8.

### 2.7 Seek index (E3 §4.7)

Present iff `b0`. `magic "INDX2\r\n\x1a"`, `u32 entry_count`,
`entry_count × { bigint output_offset, uvarint node_id, u32 crc32_of_prefix }`,
`u32 index_crc32`.

Canonical policy with `INDEX_STRIDE = 1 048 576`: an entry exists for offset `s`
iff `s > 0`, `s mod STRIDE = 0`, and at least one node starts at `s`; `node_id` is
the smallest such node id; offsets strictly increase; **no entries means no index
region at all** (an empty region is non-canonical). `crc32_of_prefix` is CRC-32 of
the first `output_offset` denotation bytes; `index_crc32` covers every index byte
before it with the field treated as zero.

### 2.8 Trailer — 32 bytes

`magic "TRLR2\r\n\x1a"`, `u64 file_bytes`, `u32 root_id` (`= node_count - 1`),
`u32 atom_count`, `u32 node_count`, `u32 trailer_crc32`.
`trailer_crc32 = CRC32(trailer[0..28) ‖ LE32(file_crc32))` — the chaining that
makes a single corrupt byte detectable even if the header CRC is recomputed.

---

## 3. §5.1 validation order, as implemented

Rejections stop at the first failing stage and carry the stage, a stable `check`
identifier, and a code. **Nothing is normalised**: a wire either validates as-is
or is rejected.

| # | Stage | What is checked | Codes |
|---|---|---|---|
| 1 | `stage1_size` | source `< 96` bytes | `Invalid` |
| 2 | `stage2_header` | magic, `header_bytes = 64`, reserved flag bits, canonical/byte-aligned bits, version | `Invalid`; future major/minor → `Unsupported` |
| 3 | `stage3_bounds` | `trailer_offset + 32 = file_bytes = source size`; no trailing bytes | `Invalid` |
| 4 | `stage4_header_crc` | `file_crc32` over `[0, trailer_offset)` with the field zeroed | `Invalid` |
| 5 | `stage5_trailer` | trailer magic, `file_bytes`, `root_id`, counts, `trailer_crc32` chain | `Invalid` |
| 6 | `stage6_regions` | region monotonicity and containment; `atom_offset = 64 + big_len`; total-length form rules; §8.3 output cap | `Invalid`; cap → `Limit` |
| 7 | `stage7_atoms` | count vs trailer; record shape; `klass`/flags; length range and equality; SHA-256; first-use order; no duplicate payload; every atom referenced | `Invalid` |
| 8 | `stage8_nodes` | count vs trailer; kind domain; flags; argc per kind; args `< own index`; params; length recomputation; post-order first use; no unused/duplicate records; E2 canonical shape | `Invalid` |
| 9 | `stage9_root` | `root_id = node_count - 1` | `Invalid` |
| 10 | `stage10_index` | index magic, `entry_count`, entry shape, `index_crc32`, and equality with the canonical policy | `Invalid` |
| 11 | `stage11_eval` | full denotation: length agreement, output SHA-256, every `crc32_of_prefix` | `Mismatch`; work bound → `Limit` |

The order matters and is tested: the harness mutates a real container in exactly
one way per case and asserts the **stage and code**, not just "rejected".

---

## 4. Obligations, and where each is proven

| Obligation | Evidence rows | Count |
|---|---|---|
| **O7.1** `encoded_size` == emitted bytes == region sum | `o7.1.encoded_size`, `o7.1.region_offsets`, `o7.1.region_sum` | 174 |
| **E3-I1** `decode(encode(t)) = t` structurally | `o7.2.decode_encode` | 58 |
| **E3-I2** `encode(decode(w)) = w` byte-for-byte | `o7.3.encode_decode` | 58 |
| Fixed point on a second pass | `o7.6.fixed_point` | 58 |
| Decoded `Ir` is E2-canonical | `decode.canonical` | 58 |
| Flags minimal and consistent with the plan | `encode.flags` | 58 |
| Region arithmetic re-read from the produced wire | `o7.1.region_sum` | 58 |
| Any truncation is rejected, never partly decoded | `truncation.rejected` | 58 |
| `validate` accepts and agrees on length/counts/digest | `validate.*` | 228 |
| `decode_stream` equals the `Ir` denotation | `decode_stream.equals_ir` | 54 |
| Canonical codecs, accept **and** reject vectors | `codec.*` | 42 |
| Stage/code contract for 37 violations (29 also re-checked through `decode`) | `noncanon.*` | 66 |
| Canonical index policy, round trip, fixed point | `index.*` | 120 |
| Determinism, 1 vs N threads, threaded round trip | `determinism.*` | 61 |
| Independent H3 agreement | `oracle.*` | 55 |
| Fuzz: no accepted-invalid, no crash | `fuzz.*` | 2 |
| Coverage of every kind/morph/predictor/tag/form | `coverage.*` | 7 |
| Independence | `isolation.*` | 2 |
| Preconditions (E0-G, E1-G, E2-G, H3 all green) | `precondition.*` | 6 |

`encoded_size` is computed from the plan (`WirePlan::file_bytes`), never by
serialising twice; the harness compares it against both `encode().size()` and the
sum of the planned regions, and separately re-reads the produced wire to confirm
the regions really do partition the file.

---

## 5. Decisions taken where the spec needed narrowing

Each is a deliberate choice; the criterion was "the narrowest reading consistent
with the normative text", as instructed.

1. **E3 governs over parent §5** wherever they differ. Recorded here; no runtime
   conflict remains.
2. **`WireError` defaults to `WireCode::Ok`.** A default-constructed error is the
   *absence* of a rejection. Otherwise a successful path could be read as failed.
3. **C07 enforces its own limits before asking E2.** E2's `check_canonical` folds
   the record-count limits into `W1.counts` and reports them as `Invalid`; §12
   says exceeding a *declared* limit is `Limit`. C07 therefore checks
   `max_atoms`/`max_nodes` first and only then asks E2 about shape. This is the
   only way the code class comes out right, and it is what `Limits.*` tests pin.
4. **C07 enforces the §8.3 output cap itself**, at stage 6, so the stage
   attribution is stable; E2's copy is disabled inside C07's own `Limits`.
   `enforce_output_cap = false` is the documented way to reach the Region A.1
   form, which is why the corpus uses it for the 2^64+ cases.
5. **The encoder never recomputes a stale `Atom::sha256`.** A record whose stored
   hash disagrees with its payload is `Invalid` at stage 7. Silently repairing it
   would be normalisation, which §5.1 forbids. `Dag::add_atom` is the one place in
   the pipeline that computes the hash, and the corpus uses it (or
   `payload_sha`) for every hand-built atom.
6. **Encode writes to a buffer and hands it to the sink in one call**, and reports
   `Limit` above 16 GiB, rather than streaming. The wire is assembled once, in
   plan order; no second serialisation exists anywhere in the writer.
7. **`decode_stream` is the only path that may exceed `arena_capacity_bytes`**;
   `decode` respects the arena bound (E3 §6.2).
8. **Index prefix CRCs are checked at stage 11, index *structure* at stage 10.**
   §5.1 puts "full evaluation" last, and `crc32_of_prefix` is a denotation
   property. A corrupted prefix CRC with a recomputed `index_crc32` is therefore
   `Invalid@stage11_eval`, and a corrupted `index_crc32` is `Invalid@stage10_index`.
9. **`Repeat` above the index budget is refused with `Limit`.** See §6.
10. **The H3 oracle's own `oracle.f00-f08` BLOCKED row is tolerated** as a
    precondition. That row literally reads `BLOCKED: E3 wire producer absent` — it
    is H3 waiting for C07. Any other non-PASS row in any prior gate manifest fails
    the precondition, and the harness logs the tolerated row with its reason.
11. **`h3_pending` is the only allowance in the TSV reader**, and it is keyed on
    `check == "oracle.f00-f08"` plus `verdict == "BLOCKED"`; there is no generic
    "ignore BLOCKED" path.

---

## 6. The one shape C07 refuses to encode (documented limitation)

§4.7 says `entry_count` is `u32`, so a canonical container has at most `2^32-1`
index entries. A declared total length **above 2^64** whose denotation has more
stride boundaries than that therefore has **no canonical v2 wire at all** — the
format cannot express it. Concretely, `Repeat(1 MiB atom, 2^44, 0)` declares
`2^64` bytes and needs exactly `2^64 / 2^20` entries.

C07 reports this as `Limit` at stage 10 from `plan`, `encoded_size`, `encode` and
`encode_to`, and produces no bytes. The gate records it as
`encode.limit.index_entry_cap` and both affected corpus items
(`limit-repeat-16x2pow59`, `limit-repeat-entry-budget`) are carried with
`expect_encode_limit = true` rather than silently dropped.

Above-`u64` container **encoding still works** for every sparse-boundary shape:
`Zero(2^64)`, `Zero(2^64+1)`, `Zero(2^128)` and `Lfsr(2^65)` all produce and
accept canonical Region A.1 wires (139, 139, 163 and 155 bytes). So the limitation
is narrow and its boundary is exactly where the format's own constant puts it.

Two consequences worth recording:

- The index-policy walk visits only the repetitions that can matter — those whose
  child start lands on a stride multiple — stepping `INDEX_STRIDE / gcd(child_len,
  INDEX_STRIDE)` at a time, and rejects on the `entry_count` budget *before*
  doing the work. Without that, `Repeat(q = 2^60)` would spin forever; with it,
  the refusal is immediate. `gcd_bigint` is the only helper this added.
- The work bound is `max_eval_bytes` (default 1 GiB). Stage 11 reports `Limit`
  rather than spending unbounded time, which is why `verify_denotation = false`
  exists for the huge declared lengths.

---

## 7. Evidence

`specs_and_reports/v2/gates/C07-WIRE.tsv` — 10 columns, 1170 rows, all `PASS`:

```text
check  corpus  item_id  input_sha256  wire_sha256  wire_bytes  expected  actual  verdict  log
```

Every row binds the corpus item (`input_sha256` is the SHA-256 of a stable
description of the term), the wire it produced (`wire_sha256`, `wire_bytes`) and a
log anchor. Rows are grouped by prefix: `o7.*` 348, `validate.*` 228, `index.*` 120, `noncanon.*` 66,
`determinism.*` 61, `encode.*` 60, `truncation.*` 58, `decode.*` 58, `oracle.*` 55,
`decode_stream.*` 54, `codec.*` 42, `coverage.*` 7, `precondition.*` 6, `isolation.*` 2,
`fuzz.*` 2, `c07.*` 2, `corpus` 1.

The corpus is 60 items: 58 encode a wire and 2 are the documented
`encode.limit.index_entry_cap` refusals of §6. Of the 58, 54 are small enough for
the H3 oracle to evaluate end to end (the 4 remaining are the above-`2^64`
declared lengths, which have no bounded denotation to compare).

`specs_and_reports/v2/logs/C07-WIRE.log` — 59 lines: a **fixed** banner (the
harness reads no clock, host, locale or environment, so two runs on one commit are
comparable byte for byte), per-section cumulative totals, and
`RESULT: PASS (C07 WIRE)`.

`specs_and_reports/v2/evidence/C07/SHA256SUMS`:

```text
03e25e7fe2b7afb5d630983a53e899426d5facafc8d16d1a8ce1fa48a2d57e74  specs_and_reports/v2/gates/C07-WIRE.tsv
41a5edecfb375056096c42b470d651a40c43f741de5edfc49d073409cbf4bf53  specs_and_reports/v2/logs/C07-WIRE.log
```

All three files are **written by the harness**; no measured value was entered by
hand. CI regenerates them and `diff`s against the committed copies, so a
hand-edited value would fail the build.

---

## 8. CI, and how it maps to the §10 checklist

Green run: **[43743973411](https://github.com/nexuss0781/MARP/actions/runs/43743973411)**
at commit `4cd3b6f90e13aa737705dc15bb2fed71cbf1187b` — `success`.

| §10 requirement | How CI proves it | Result |
|---|---|---|
| Warning-free build under `-Werror -Wconversion -Wshadow -Wnull-dereference -Wdouble-promotion -Wformat=2` | `make -f Makefile.c07 c07-all` builds all three C07 TUs, E1, E2, the harness and the tests with exactly those flags | **PASS** |
| Tests pass | `./bin/c07_tests` — 48/48 | **PASS** |
| Bijection round-trips on the corpus | `o7.2.decode_encode`, `o7.3.encode_decode`, `o7.6.fixed_point` over all 58 encodable items | **PASS** |
| Rejection at the correct stage with the correct code class | 37 mutations; 29 of them also re-checked through `decode` (stages 1–8, 10, 11) | **PASS** |
| Deterministic | `determinism.repeat` (3×), `determinism.threads` (4 and 8 threads), `determinism.threads_roundtrip`; plus a full second evidence run under a `diff` | **PASS** |
| No E4–E7 linkage | `make -f Makefile.c07 c07-isolation`: source grep + `nm` on the objects (775 symbols, 0 forbidden) + `nm`/`ldd` on the binary | **PASS** |
| No C08 in the encode path | `decode_v1`/`looks_like_v1` absent from C07 code (comment-stripped grep) and from the public header | **PASS** |
| No regression to H1/H2/H3/E1/E2/E2-G evidence | The independence job verifies **every** `specs_and_reports/v2/evidence/*/SHA256SUMS` that predates C07 (8 manifests) | **PASS** |
| No regression to other builds | `make -f Makefile.c06 c06-all` + `e2_c06_tests` still build and pass with C07 present | **PASS** |
| Committed evidence matches the green run | `diff` of the CI-generated TSV/log against the committed copies, byte for byte | **PASS** |
| No build artefacts committed | Only sources, `Makefile.c07`, the workflow, and the three evidence files are added | **PASS** |
| ASan + UBSan clean | `c07-test-san` (48/48) and a sanitizer evidence run whose output `diff`s identically | **PASS** |

Every other workflow also ran green on the same commit — E2 C03, C04, C05, C06,
E2-G, and H3 Oracle — so the C07 addition regresses nothing. The E2-G run
(43740087529) is the one that matters most for the "no regression" claim, because
it is the gate that owns the E2 surfaces C07 builds on.

The H3 cross-check is a genuine independent decoder: `harness/oracle/` is a
clean-room implementation that shares no code with C07. The harness reaches it
**only** by running `engine/bin/mapr_oracle` on a temporary file and reading its
exit status — never by linking it and never by including its headers. 54 of 54
comparable containers agree, and the row reports `expected=54 actual=54/54`.

---

## 9. Honest scope: what is *not* done

This is the C06-style component gate for C07, not the E3-G gate. Still open for
E3-G, and **not claimed here**:

1. **C08 LEGACY** — `decode_v1`, `looks_like_v1`, the `W-V1` corpus, and v1→v2
   migration. Absent by design (`decode_v1` must not be callable from any encode
   path, §11). C07 can neither read nor write v1.
2. **The 100 000-case fuzz campaign.** This gate runs 20 000 deterministic
   mutants over 43 small canonical seeds; measured `rejected=19993 valid=7
   accepted_invalid=0 crashes=0`. A mutant that is itself canonical is counted as
   `valid` only because re-encoding it reproduces the same bytes byte for byte —
   never as "accepted invalid". That is a real check at *this* gate's scale, not
   the E3-G campaign.
3. **E3-G's full corpus.** `W-CANON` here is 60 items chosen for breadth of kind,
   morph, predictor, integer form and payload edge; E3-G asks for 5 000+.
4. **The `W-SEED` hand-built corpus** of 5 000+ canonical wires exercising tag 0/1/2
   bigints and Region A.1 in every position.
5. **`--range` / virtual-range decoding of unbounded outputs.** `decode_stream`
   bounds its output; a range interface above `2^64` is E3-G scope.
6. **Interoperability with a C08-produced v2 wire.** Same reason as (1).

Nothing in this report should be read as an E3-G claim.

---

## 10. What changed outside C07: nothing

No existing file was modified. `.github/workflows/e3-c07.yml` is a new, isolated
workflow (`on: push` to `h2-gates`/`arena/**`, `pull_request`,
`workflow_dispatch`) and does not touch any other workflow's triggers. The
`Makefile.c07` addition does not alter `Makefile`, `Makefile.c06`, `Makefile.e2g`
or `Makefile.h3`. `include/mapr/e3/` and `engine/src/e3/` are new directories; no
C05/C06 source digest covers them (those manifests cover only
`include/mapr/e2` + `engine/src/e2`), which the independence job confirms by
re-verifying all eight prior manifests.

---

## 11. Reproducing locally

```bash
# GoogleTest is needed for the unit tests only.
# (CI installs it system-wide; the Makefile also probes /tmp/gtest-lib.)

cd engine
make -f Makefile.c07 c07-clean
make -f Makefile.c07 c07-all -j4          # strict -Werror -O2 build
make -f Makefile.h3 bin/mapr_oracle -j4   # independent decoder for the cross-check
make -f Makefile.c07 c07-isolation        # source + symbol independence
./bin/c07_tests --gtest_color=no          # 48/48
./bin/c07_wire_gate --root .. --oracle-bin bin/mapr_oracle --write-evidence
make -f Makefile.c07 c07-test-san         # ASan + UBSan, 48/48
cd .. && sha256sum -c specs_and_reports/v2/evidence/C07/SHA256SUMS
```

---

## 12. Summary

C07 WIRE implements the unique canonical v2 container — encode, decode, validate —
on the frozen E1/E2 surfaces, with the §5.1 stage order enforced in order and every
rejection attributed to the stage that owns it. `encoded_size` comes from the plan
and equals the emitted bytes exactly. Encoding is deterministic under repetition
and under threading; decoding never normalises and never allocates from an
unvalidated count. One format-level limitation (`entry_count` is `u32`, so a
denotation above 2^64 with dense stride boundaries has no canonical wire) is
refused with `Limit` and documented in §6.

1170/1170 evidence rows `PASS`; 48/48 unit tests pass in the strict build and
under ASan+UBSan; CI run
[43743973411](https://github.com/nexuss0781/MARP/actions/runs/43743973411) is green
at commit `4cd3b6f90e13aa737705dc15bb2fed71cbf1187b`, and the committed evidence
is byte-identical to what that run generated.

**E3-G is not claimed.** C08 LEGACY, the 100 000-case fuzz campaign, the `W-V1`
and `W-SEED` corpora, and virtual-range decoding remain open, as listed in §9.
