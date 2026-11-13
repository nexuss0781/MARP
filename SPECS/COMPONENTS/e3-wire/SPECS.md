# E3 — WIRE — Component Specification

| Field | Value |
|---|---|
| **Document ID** | MARP2-E3 |
| **Version** | 1.0 |
| **Status** | Normative for E3. Derived from `SPECS-V2.md`. |
| **Parent** | `MARP/SPECS/SPECS-V2.md` |
| **Decomposition** | `MARP/SPECS/COMPONENTS-V2.md` |
| **Depends on** | E1, E2 (frozen). E3 MUST NOT link E4–E7. |
| **Language** | C++20. No third-party libraries. No Python. |
| **Gate** | `E3-G` |

---

## 0. Reading rules

1. This document is normative for E3 only. The parent governs the format; on conflict the parent wins and this document is amended.
2. `MUST` / `MUST NOT` are normative.
3. The wire is a **contract between independent implementations**, not an internal serialisation. A reader that accepts a non-canonical container is a defect even if it decodes correctly.
4. Every obligation in §8 is measured by the gate in §13.
5. The gate is the only exit from this component.

---

## 1. Purpose

E3 owns the only accepted byte representation of a term.

It answers two questions:

1. **What is the unique wire for this canonical term?** (C07 `WIRE`)
2. **What canonical term does this wire denote, or why is it rejected?** (C07, C08 `LEGACY`)

E3 does not choose terms, rewrite them, or discover structure. It serialises what E2 has already frozen and validates what it reads.

---

## 2. Scope

### 2.1 In scope

- The v2 container: header, optional total-length region, atom table, node table, optional seek index, trailer.
- Canonical integer codecs: `uvarint` and tagged `bigint`.
- Canonicality validation, including ordering, deduplication, minimal flags, and shortest integers.
- Full structural validation and full denotation verification.
- Read-only decoding of v1.0.1 and v1.1 containers into the v2 `Ir`.
- Independent verification input for the fuzz campaign.

### 2.2 Out of scope

| Excluded | Owner |
|---|---|
| Arithmetic, lengths, digests | E1 |
| Term meaning, canonicalisation, evaluation | E2 |
| Discovery, probing, candidates | E4–E5 |
| Selection, classification, planning | E6 |
| CLI, atomic file write, certificate | E7 |
| Writing v1 containers | retired; MUST NOT be reachable |
| `.nez` containers | NEZITOR |

E3 MUST NOT read the environment, branch on file names, or inspect media types.

---

## 3. Sub-components

| id | role | deliverable |
|---|---|---|
| C07 | `WIRE` | `encode_to`, `encoded_size`, `decode`, `validate`, integer codecs |
| C08 | `LEGACY` | `looks_like_v1`, `decode_v1` |

C07 and C08 MAY share a translation unit. C08 MUST NOT be callable from C07's encode path.

---

## 4. Container model

### 4.1 Layout

```
Region A    Fixed header              64 B
Region A.1  Total-length magnitude    total_length_big_len B, optional
Region B    Atom table                variable
Region C    Node table                variable
Region D    Seek index                optional, variable
Region E    Trailer                   32 B
```

All offsets are absolute from byte 0. Multi-byte fixed integers are little-endian.

### 4.2 Header

| offset | size | field | canonical value |
|---|---|---|---|
| 0 | 8 | magic | `89 4D 41 50 52 32 0D 0A` (`\x89MAPR2\r\n`) |
| 8 | 2 | `version_major` | 2 |
| 10 | 2 | `version_minor` | 0 |
| 12 | 4 | `flags` | see §4.3 |
| 16 | 2 | `header_bytes` | 64 |
| 18 | 8 | `total_length_u64` | 0 if the length does not fit |
| 26 | 2 | `total_length_big_len` | 0 if `total_length_u64` is used |
| 28 | 8 | `atom_offset` | `64 + total_length_big_len` |
| 36 | 8 | `node_offset` | end of atom table |
| 44 | 8 | `index_offset` | 0 if absent, else end of node table |
| 52 | 8 | `trailer_offset` | end of last region before trailer |
| 60 | 4 | `file_crc32` | CRC-32 over `[0, trailer_offset)` with this field zeroed |

### 4.3 Flags

| bit | meaning | v2.0 canonical |
|---|---|---|
| 0 | seek index present | `1` iff an index region exists |
| 1 | canonical encoding | MUST be `1` |
| 2 | all lengths fit in `u64` | `1` iff `total_length <= 2^64-1` |
| 3 | atoms byte-aligned | MUST be `1` |
| 4–31 | reserved | MUST be `0` |

`total_length_big_len > 0` and bit 2 are independent fields but must agree: a big length is used exactly when the value exceeds `u64`.

### 4.4 Total length

Canonical encoding:

```
if total_length <= 2^64-1:
    total_length_u64 = total_length
    total_length_big_len = 0
    Region A.1 absent
else:
    total_length_u64 = 0
    total_length_big_len = len(magnitude)  > 0
    Region A.1 = little-endian magnitude, no leading zero byte
```

`total_length_big_len` is `u16`, so a magnitude is at most 65 535 bytes. This bounds the v2.0 total length at `2^(8·65535) - 1`, which is far beyond every declared limit.

Rejected as non-canonical:

- both forms present;
- neither form present but a nonzero length is implied elsewhere;
- big form whose value fits in `u64`;
- big form with a leading zero byte, or `big_len = 0`;
- `total_length_u64` nonzero while `big_len > 0`.

### 4.5 Atom table

```
uvarint atom_count
atom_count × AtomRecord
```

```text
u8     klass
u8     flags          MUST be 0
u16    reserved       MUST be 0
bigint length         payload byte length, 1 <= length <= ATOM_MAX
u8[32] sha256         SHA-256 of payload
u8[length] payload
```

Atom ids are record indices. Canonical order is **first use in post-order traversal of the canonical term**; duplicate payloads MUST NOT appear twice; every atom MUST be referenced.

`ATOM_MAX = 1 048 576` (1 MiB). `klass` is advisory and does not affect decoding; it is preserved exactly.

### 4.6 Node table

```
uvarint node_count
node_count × NodeRecord
```

```text
u8     kind
u8     flags          MUST be 0
u16    argc
argc × uvarint arg    absolute node id, MUST be < current record index
kind-specific params
bigint length         MUST equal §3.7 recomputation
```

| kind | value | params | argc |
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

Canonical order is post-order first use (§4.8 of E2). The root is the last record. Every node is reachable; no record is unused.

### 4.7 Seek index

Present iff flag bit 0 is `1`.

```
magic u8[8] = "INDX2\r\n\x1a"
u32 entry_count
entry_count × {
    bigint output_offset
    uvarint node_id
    u32 crc32_of_prefix
}
u32 index_crc32
```

`crc32_of_prefix` is CRC-32 of the first `output_offset` bytes of the denotation. `index_crc32` is CRC-32 over every index byte before the field, with the field treated as zero.

Canonical index policy (v2.0 format constant `INDEX_STRIDE = 1 048 576`):

- an entry exists for output offset `s` iff `s > 0`, `s mod INDEX_STRIDE = 0`, and at least one node starts at `s`;
- the `node_id` is the smallest node id whose output start is `s`;
- entries are strictly increasing in `output_offset`;
- if the policy yields no entries, the index is absent and flag bit 0 is `0`; an empty index region is non-canonical;
- `entry_count` is `u32`, so a canonical container has at most `2^32-1` entries.

The index is an optimisation. Decoding with it ignored MUST produce the same bytes. A reader MUST still validate it when present.

### 4.8 Trailer

| offset | size | field |
|---|---|---|
| 0 | 8 | magic `TRLR2\r\n\x1a` |
| 8 | 8 | `file_bytes` (total container size) |
| 16 | 4 | `root_id` |
| 20 | 4 | `atom_count` |
| 24 | 4 | `node_count` |
| 28 | 4 | `trailer_crc32` |

`trailer_crc32 = CRC32(trailer[0..28) ‖ LE32(file_crc32))`.

`file_bytes` MUST equal `trailer_offset + 32` and the actual source size. Counts MUST equal the table counts. `root_id` MUST equal `node_count-1`.

### 4.9 Integer codecs

**uvarint.** Unsigned LEB128, at most 10 bytes, canonical: the last byte MUST NOT be `0x00` when the encoding has more than one byte; a 10th byte MUST be `0x00` or `0x01` and the value MUST fit `u64`.

**bigint.**

| tag | encoding | canonical use |
|---|---|---|
| `0x00` | none | value `0` only |
| `0x01` | `uvarint v` | `1 <= v <= 2^64-1` |
| `0x02` | `u32 len`, `len` little-endian bytes | value `>= 2^64`; `len >= 9`; last byte nonzero |

Rejected as non-canonical: tag `0x02` with a value below `2^64`; tag `0x01` with `v = 0`; tag `0x02` with `len = 0`, leading zero magnitude, or trailing bytes; any unknown tag.

### 4.10 Canonical wire rules

A wire is canonical iff all of:

1. header flags are minimal and reserved bits are zero;
2. the total length uses the canonical form;
3. atoms are first-use ordered and deduplicated, each `<= ATOM_MAX`;
4. nodes are post-order first-use, topological, root last, no unused records;
5. every integer is shortest-form;
6. the index, if present, equals the canonical policy output;
7. `file_crc32` and `trailer_crc32` are correct;
8. every declared length equals recomputation;
9. the full denotation length equals `total_length`;
10. encoding the decoded term reproduces the same bytes.

Rule 10 is the fixed-point property that makes `enc` a bijection on canonical wires.

---

## 5. Validation

### 5.1 Order

Validation follows parent §5.9 exactly and stops at the first failure:

1. source size `>= 96` (64-byte header + 32-byte trailer);
2. magic, version, `header_bytes`, reserved flags, flag invariants;
3. `trailer_offset` and `file_bytes` bounds;
4. header CRC (`file_crc32`);
5. trailer magic, counts, root, CRC;
6. region offsets monotonic and within `[64, trailer_offset]`; `atom_offset = 64 + total_length_big_len`; total-length canonicality;
7. atom table: count, canonical bigints, payload bounds, `sha256` matches payload, `ATOM_MAX`, first-use order, dedup;
8. node table: count, kinds, argc, arg range, params, canonical bigints, length equality, post-order first-use, root last, reachability, atom references;
9. root id equals `node_count-1`;
10. index: magic, count, ordering, node ids, prefix CRCs, index CRC;
11. full evaluation: output length equals `total_length`; the streaming SHA-256 of the output is computed and recorded in `Validation`; index prefix CRCs match the actual prefix.

A failure at step `n` never reaches step `n+1`. No allocation is sized from an unvalidated count.

### 5.2 Errors by stage

| stage | rejection code |
|---|---|
| magic/version/flags/header | `Invalid`, except a future major/minor version → `Unsupported` |
| any bound, CRC, count, ordering, canonicality | `Invalid` |
| unknown kind, morph, predictor, or unsupported legacy feature | `Invalid` (unknown v2 feature: `Invalid`; future version: `Unsupported`) |
| a declared limit exceeded | `Limit` |
| full evaluation disagrees with the declared length | `Mismatch` |
| source shorter than declared | `Invalid` (truncation), never `Limit` |

A v2 reader MUST reject v1 containers with `Invalid` in `decode`; `decode_v1` is the only path that accepts them.

---

## 6. Operations

### 6.1 Encode

| operation | precondition | postcondition |
|---|---|---|
| `encoded_size(ir)` | `check_canonical(ir)` | exact byte count of `encode_to` |
| `encode_to(ir, sink)` | `check_canonical(ir)` | writes the unique canonical wire |
| `encode(ir)` | same | convenience; `Limit` above a caller cap |

`encoded_size` MUST equal the bytes actually written. It is computed from the same plan, not by serialising twice.

Encode MUST NOT consult effort, time, thread count, locale, or environment. `klass` is written as-is; it never changes the term.

### 6.2 Decode

| operation | precondition | postcondition |
|---|---|---|
| `validate(source)` | — | full §5.1 validation; returns counts, lengths, digest, index summary |
| `decode(source, arena)` | — | validated `Ir`; payload views point into `arena` |
| `decode_stream(source, sink)` | — | validates, then evaluates directly to `sink` without retaining a full `Ir` |
| `looks_like_v1(source)` | — | magic/version probe only |

`decode` MUST produce an `Ir` that passes `check_canonical`. It does not canonicalise; if the wire is non-canonical it rejects.

`decode_stream` is the only path allowed to decode a declared total length above the arena cap. It still rejects before writing if validation fails.

### 6.3 Legacy

| operation | precondition | postcondition |
|---|---|---|
| `looks_like_v1(source)` | — | true iff the v1 magic matches |
| `decode_v1(source)` | — | `Ir` for a supported v1 container |

Supported versions are exactly 1.0.1 and 1.1, as frozen in `MARP/SPECS/SPECS.md`. The v1 format is not redefined here. Unsupported v1 features return `Unsupported`, never an approximation. `decode_v1` MUST NOT be callable from any encode path, and v1 emission is absent from the binary.

### 6.4 Arena

```cpp
struct Arena {
    virtual ~Arena() = default;
    virtual Result<std::span<const u8>> store(std::span<const u8>) = 0;
};
```

The arena may be heap-backed, memory-mapped, or file-backed. A failed `store` is `Limit`; it is never a partial image.

---

## 7. Invariants

| id | invariant |
|---|---|
| E3-I1 | `decode(encode(t)) = t` for every canonical `t`. |
| E3-I2 | `encode(decode(w)) = w` for every canonical `w`. |
| E3-I3 | A non-canonical wire is rejected, never normalised. |
| E3-I4 | No allocation is sized from an unvalidated count or offset. |
| E3-I5 | Every offset and length is bounds-checked before use. |
| E3-I6 | `encoded_size` equals emitted bytes. |
| E3-I7 | Encode is deterministic across runs and thread counts. |
| E3-I8 | `klass` round-trips exactly and never affects decoding. |
| E3-I9 | Legacy code is read-only and cannot influence v2 emission. |
| E3-I10 | A truncated container is `Invalid`, never a partial decode. |
| E3-I11 | Unknown critical fields are rejected, never ignored. |
| E3-I12 | The index never changes denotation. |

---

## 8. Proof obligations

| id | obligation | measurement |
|---|---|---|
| O7.1 | `encoded_size(t)` equals the written size, and the region sum equals the file size | exact integer comparison per term |
| O7.2 | `dec(enc(t)) = t` structurally, including ids, lengths, params, `klass`, and payloads | W-CANON, engine + oracle |
| O7.3 | `enc(dec(w)) = w` byte-for-byte | canonical W-SEED |
| O7.4 | every non-canonical encoding is rejected with the expected code | W-NONCANON |
| O7.5 | 100,000 fuzz mutants yield zero accepted-invalid, zero crashes, zero timeouts | H4 fuzz campaign |
| O7.6 | every canonical wire re-decodes to the same bytes on a second pass | fixed-point check |
| O7.7 | every v1 fixture decodes byte-exactly | W-V1 |
| O7.8 | every kind, integer form, length form, and index state is exercised | coverage counters |
| O7.9 | encode output is identical at 1 and 4 threads | determinism run |
| O7.10 | no mutant causes an allocation beyond its declared container size | fuzz runner RSS/allocator guard |

O7.5 is a campaign result, not a proof of safety. The gate states the measured counts; it does not claim the decoder is secure against all adversaries.

---

## 9. C++ interface

```cpp
namespace marp::v2 {

struct Validation {
    BigInt total_length;
    std::array<u8,32> output_sha256;
    u32 atom_count, node_count, root_id;
    bool index_present;
    u32 index_entries;
};

Result<BigInt>        encoded_size(const Ir&);
Result<void>          encode_to(const Ir&, Sink&);
Result<std::vector<u8>> encode(const Ir&);

Result<Validation>    validate(Source&);
Result<Ir>            decode(Source&, Arena&);
Result<void>          decode_stream(Source&, Sink&);

bool                  looks_like_v1(Source&);
Result<Ir>            decode_v1(Source&, Arena&);

// canonical integer codecs, exposed for the harness and E7 only
Result<u64>           read_uvarint(Reader&);
Result<BigInt>        read_bigint(Reader&);
Result<void>          write_uvarint(Sink&, u64);
Result<void>          write_bigint(Sink&, const BigInt&);

} // namespace marp::v2
```

`Source` is a random-access byte source with `size()` and `read(offset, span)`. `Reader` is a bounded cursor. Neither may be backed by a network or an ambient file lookup inside encode/decode.

---

## 10. Error taxonomy

| condition | code |
|---|---|
| bad magic, version 2.x mismatch, header bytes, flags | `Invalid` |
| future major or minor version | `Unsupported` |
| bounds, overlap, non-monotonic offsets | `Invalid` |
| CRC mismatch | `Invalid` |
| non-canonical integer or total length | `Invalid` |
| atom ordering, duplicate payload, `> ATOM_MAX` | `Invalid` |
| node ordering, arg range, argc, params, length mismatch | `Invalid` |
| unknown kind/morph/predictor | `Invalid` |
| index malformed or non-canonical | `Invalid` |
| declared limit exceeded | `Limit` |
| evaluation length disagreement | `Mismatch` |
| unsupported legacy feature | `Unsupported` |

No operation panics, throws past `Result`, or terminates the process.

---

## 11. Authority boundary

**E3 may:**
- serialise and validate the canonical wire;
- call E2 for canonicality, lengths, and evaluation;
- provide wire bytes to the harness and E7;
- read v1 containers.

**E3 may not:**
- canonicalise or rewrite a term;
- select, discover, classify, or translate;
- accept a term it did not validate;
- write v1;
- branch on file extension, MIME type, or name;
- call E4–E7.

Any E3 call into E4–E7 is an architecture violation.

---

## 12. Determinism and resources

- Encode is a pure function of the canonical `Ir`. No time, address, locale, thread, or map order.
- Decode allocates from validated sizes only. Counts are checked against the remaining region before allocation.
- Peak memory is bounded by the container size plus the arena cap; `decode_stream` is bounded by the block buffer plus node table.
- The node table is `O(nodes)`. Atom payloads are `O(container)` unless spilled by the arena.
- No recursion without a bound; DAG depth is checked during node-table validation.
- CRC and SHA-256 state are local; no globals.

---

## 13. Success gate E3-G

### 13.1 Preconditions

| requirement | state |
|---|---|
| `E0-G` PASS with evidence | required |
| `E1-G`, `E2-G` PASS with evidence; both surfaces frozen | required |
| H3 independent wire decoder available, sharing no code with E3 | required |
| Pinned v1 fixtures with recorded SHA-256 | required |
| No E4–E7 code linked into E3 | required |

If any precondition is unmet, E3-G is `BLOCKED`, never `PASS`.

### 13.2 The condition

> **For every canonical corpus term, `decode(encode(t)) = t` and `encode(decode(encode(t))) = encode(t)`; for every canonical wire seed, `encode(decode(w)) = w` byte-for-byte; every non-canonical encoding is rejected with the specified code; 100,000 fuzz mutants produce zero accepted-invalid containers, zero crashes, and zero timeouts; every pinned v1 fixture decodes byte-exactly; and every kind, integer form, length form, and index state is exercised. One failure fails the gate.**

### 13.3 Corpus

| id | contents | count |
|---|---|---|
| `W-CANON` | canonical terms from E2's `T-KAT`/`T-GEN`, plus: empty, one byte, atom exactly `ATOM_MAX`, `ATOM_MAX+1` split, total `2^32`, `2^64-1`, `2^64`, `2^64+1`, `2^128`, `Zero(2^40)`, `Lfsr(2^40)`, index-present terms (`>= 3 MiB`), index-absent terms | 5 000+ |
| `W-SEED` | every `W-CANON` wire, plus hand-built canonical wires exercising tag 0/1/2 bigints and Region A.1 | 5 000+ |
| `W-NONCANON` | one container per violation in §4.10 and §5.1: redundant/overlong uvarint, wrong bigint tag, big form below `2^64`, leading-zero magnitude, atom `> ATOM_MAX`, duplicate atom payload, wrong atom order, unused atom, node arg `>= id`, root not last, unused node, wrong argc, nonzero flags/reserved, bad magic/version/header bytes, overlap, non-monotonic offsets, bad header/trailer CRC, count mismatch, total-length mismatch, length-field mismatch, unsorted/duplicate index, bad prefix CRC, bad index CRC, morph `k`, predictor param, `Lfsr conn=0`, slice bounds | 80 |
| `W-V1` | pinned v1.0.1 and v1.1 containers from the legacy fixture set, with recorded SHA-256 and expected output SHA-256 | all available |
| `W-FUZZ` | small valid seeds (empty, 1, 2, 16, 256, 4 096, 65 536 bytes) plus header/trailer/index fields of large virtual containers | 8 seeds |

`W-V1` is a hard dependency. A missing or mis-hashed v1 fixture makes the legacy half `BLOCKED`; it does not make the gate PASS.

### 13.4 Procedure

1. Build E3, the oracle, and the harness with `-O2 -Wall -Wextra -Werror`.
2. Encode every `W-CANON` term. For each: record `encoded_size`, actual bytes, and SHA-256; require equality.
3. Decode each wire with E3 and with H3. Require both `Ir`s structurally equal (ids, kinds, args, params, lengths, `klass`, payload hashes) and both denotations equal to the source term.
4. Re-encode each decoded `Ir`. Require byte equality with the original wire.
5. For every `W-SEED` wire, including hand-built canonical wires: `decode` must succeed; `encode` must reproduce the exact bytes.
6. For every `W-NONCANON` container: `validate` and `decode` must both reject with the expected code. An accepted container fails; a wrong code fails.
7. Fuzz: run 100,000 mutants from `W-FUZZ` through `validate` and `decode`, with a 10 s per-mutant timeout and the allocation guard. Count `accepted_invalid`, `crashes`, `timeouts`, `valid`. All three failure counts MUST be zero.
8. Legacy: decode every `W-V1` fixture; require byte-exact denotation against its recorded SHA-256; re-encode as v2 and decode again; require equality.
9. Re-run steps 2–8 with 1 and 4 threads; all wire bytes and all verdicts must be identical.
10. Check coverage counters: every node kind, every morph id, every predictor id, bigint tags 0/1/2, both total-length forms, index present and absent, atom at `ATOM_MAX`. Any zero counter fails.
11. Write one row per check; PASS only if every row is `PASS`.

### 13.5 Evidence

```
specs_and_reports/v2/gates/E3-G.tsv
specs_and_reports/v2/logs/E3-G.log
specs_and_reports/v2/logs/E3-G-fuzz.log
specs_and_reports/v2/logs/E3-G-legacy.log
specs_and_reports/v2/corpus/E3/corpus.tsv
specs_and_reports/v2/corpus/E3/fuzz_counts.tsv
```

`E3-G.tsv` columns:

```
check  corpus  item_id  input_sha256  wire_sha256  wire_bytes  expected  actual  verdict  log
```

`E3-G-fuzz.log` records the seed, mutant count, and the four counters. `E3-G-legacy.log` records each fixture's identity and output digest.

### 13.6 Fail conditions

The gate fails on any of:

- one `dec(enc(t))` structural mismatch;
- one `enc(dec(w))` byte mismatch;
- one non-canonical container accepted, or rejected with the wrong code;
- one accepted-invalid, crash, or timeout in the fuzz campaign;
- one v1 fixture that fails to decode byte-exactly;
- one `encoded_size` mismatch;
- one oracle/engine disagreement;
- one missing kind, morph, predictor, integer form, length form, or index state;
- one thread-count mismatch;
- a missing corpus row, missing log, missing fixture, or hand-edited TSV value;
- a non-zero exit from any stage.

There is no tolerance, no retry, and no partial pass.

### 13.7 What E3-G does not prove

- It does not prove the discovery pipeline. E4–E6 do.
- It does not prove v1 **writing**. v1 emission is retired.
- It does not prove the index is useful, only that it is canonical and correct.
- It does not prove the fuzzer is exhaustive. It proves the stated campaign result.
- It does not prove defences against a hostile container beyond the measured mutants and the structural invariants.
- It does not prove the CLI writes atomically. E7 does.

---

## 14. Freeze rule

When E3-G passes:

1. The wire format constants (`ATOM_MAX`, `INDEX_STRIDE`), canonical order, codecs, and signatures in §9 are frozen.
2. Any change to the format, canonicality rules, or validation order re-runs E3-G **and every later gate**.
3. Gate rows and logs are append-only. A new run appends rows; it never edits old ones.

---

## 15. Traceability

| this document | parent |
|---|---|
| §4.1–4.2 layout, header | §5.1, §5.2 |
| §4.3 flags | §5.2 |
| §4.4 total length | §5.2, §5.3 |
| §4.5 atom table | §5.4 |
| §4.6 node table | §5.5 |
| §4.7 seek index | §5.6 |
| §4.8 trailer | §5.7 |
| §4.9 integer codecs | §5.3 |
| §4.10 canonical rules | §5.8 |
| §5.1 validation order | §5.9, §8.1 |
| §6.2 decode streams | §8.2, §8.3 |
| §6.3 legacy | §15 |
| §13 gate | V2-G2, V2-G9, V2-G13, V2-G16 (second half) |

**Derived detail.** `INDEX_STRIDE = 1 MiB` and the canonical index policy are not stated numerically in the parent. They are a v2.0 format constant required to make "minimal and sorted" (§5.8 rule 6) testable. If the parent adopts another policy, this section is amended before E3-G is run.

**Parent gap.** V2-G12 (independent decoder) is measured by E0's H3 oracle, not by E3-G; E3-G consumes the oracle as a precondition.

---

*End of MARP2-E3.*
