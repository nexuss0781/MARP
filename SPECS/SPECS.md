# MARP — Stage 2 Expression Specification

**Document:** `MARP/SPECS/SPECS.md`
**Version:** 2.0-spec — architecture frozen, implementation pending
**Date:** 2026-11-10
**Status of this document:** the complete Stage 2 specification for MARP. It is self-contained:
nothing here requires another project's document to be understood or implemented.
**Rule:** every number is either **measured** (source named) or labelled **TARGET**.

---

## 1. Mandate

MARP is the **expression engine**. It converts a byte string into a canonical **term DAG** and a
compact **wire stream**. It captures structure. It is explicitly allowed to be larger than its
input.

> **MARP represents to express.**

MARP is the syntax layer of the Nezistor system. It does not compress, does not certify by
itself, and does not store the payload as a materialised object.

### 1.1 Non-goals

MARP is **not**:

- a compressor in the entropy-coding sense;
- a lossy system;
- a decision procedure for algebraic equality (that is the calculation layer's job);
- a container format for applications.

### 1.2 Design principle

> **Coverage over size.**

A representation that captures more structure is better even when its own byte size grows,
because the structure it exposes is what the representation layer removes. Size reduction is a
downstream concern.

---

## 2. Frozen wire format v1.0.1

The v1.0.1 wire format is **normative and frozen**. Existing `.mapr` files must decode forever.
This document does not replace `specs_and_reports/FORMAT_SPEC.md`; it records the invariants
Stage 2 must not break.

### 2.1 Top-level layout

```
Region 1  Fixed file header      64 B
Region 2  Superchunk records K × (32 B + payload)
Region 3  Seek index  INDX       16 B + K × 32 B + 4 B
Region 4  Fixed trailer TRLR     72 B
```

Header magic: `89 4D 41 50 52 0D 0A 1A` (`\x89MAPR\r\n\x1a`).
`version_major = 1`; decoders reject any other major version.
Superchunk magic `MCHK`; index magic `INDX`; trailer magic `TRLR`; end sentinel `ENDM`.

### 2.2 Chunk kinds

| value | kind | meaning |
|---|---|---|
| `0x00` | `KIND_CHUNK_REF` | reference to an earlier superchunk |
| `0x01` | `KIND_EXPLICIT_DAG` | explicit DAG payload |

### 2.3 DAG opcodes (4-bit, values 0–9)

| code | name | semantics |
|---|---|---|
| 0 | `EMPTY` | length 0 |
| 1 | `ATOM` | one literal block |
| 2 | `ATOM_SPAN` | `t` atoms, optional homogeneous 64-bit tail |
| 3 | `CONCAT` | `d` children (`d ≥ 2`) |
| 4 | `REPEAT` | `q` copies of child plus `r` leading bits |
| 5 | `SLICE` | `[start, start+length)` of child |
| 6 | `MORPH` | one of four involutive bit morphisms |
| 7 | `XOR_DIFF` | XOR of two equal-length children |
| 8 | `INTERLEAVE` | `s ∈ {8,16,32,64}` equal-length children |
| 9 | `LFSR` | Fibonacci LFSR, `L ≤ 64`, connection/init masks |

All child offsets are **relative and backward** (`u = v − 1 − rel`), which guarantees acyclicity
and permits single-pass validation.

### 2.4 Normative decoder checks (must not weaken)

- magic, version, flags, header CRC;
- `TRLR`/`ENDM`, trailer CRC;
- `INDX` magic, entry size 32, monotonic offsets, index CRC;
- per-superchunk magic and CRC, zero trailing padding;
- static DAG validity: `u < v`, domain bounds, `λ(r) = ℓ`, `CHUNK_REF` window.

Unknown critical flags, unknown opcodes and unknown chunk kinds are **rejected**, never guessed.

---

## 3. Verified baseline (measured)

| corpus | size in | `.mapr` out | ratio | note |
|---|---|---|---|---|
| 1 MiB zeros | 1,048,576 | 299 B | 0.00029× | pure repeat |
| 1 MiB repeated text | 1,048,576 | 562 B | 0.00054× | repeat |
| 256 KiB gradient | 262,144 | 704 B | 0.0027× | affine structure |
| 1 MiB counter | 1,048,576 | 16,579 B | 0.0158× | arithmetic stream |
| **1 MiB random** | 1,048,576 | **1,091,348 B** | **1.0408×** | **expansion** |
| 10 near-duplicate docs (stored) | 1.04 MB | 5,270 B | 0.0051× | shared structure |
| 10 near-duplicate docs (deflated) | 5,677 B | 1,068 B | 0.188× | post-deflate |
| repo `test_1mb.zip` | 1,000,000 | 1,038,503 B | 1.0385× | 100 % atoms |
| repo `test_10mb.zip` | 10,000,000 | 10,388,756 B | 1.0389× | 100 % atoms |
| repo `test_100mb.zip` | 100,000,000 | 94,140,847 B | 0.9414× | 9.17 % `CHUNK_REF` |

**Interpretation.** MARP is a strong *syntax*: on structure its gain is 3–4 orders of magnitude.
On deflated/noise data it **expands by ~4 %** because raw literal passthrough is currently
forbidden. That is the first thing Stage 2 fixes.

---

## 4. Stage 2 requirement analysis

### MR1 — Noise expansion

Measured 1.0408× on random 1 MiB. Cause: `RESEARCH.md` §A2 forbids raw literal passthrough, so
every byte becomes a structural atom with per-node overhead.

**Resolution: `RAW` opcode (§6) + a noise detector (§7.1).**

### MR2 — No cross-file / cross-chunk deduplication

The 100 MB archive shows only 9.17 % `CHUNK_REF`; duplicate content across members is not shared
globally.

**Resolution: global dedup index + `DEDUP_REF` opcode (§6, §7.2).**

### MR3 — Deflate is opaque

Deflated streams are treated as noise. The measured ceiling for DEFLATE-aware handling is
0.955×–1.039× (`specs_and_reports/MATHEMATICAL_SPEC.md` §6.3). The goal is to *reach* the
ceiling, not to exceed it.

**Resolution: DEFLATE-aware front end (§7.3).**

### MR4 — Wire and semantics are conflated

The compact wire format is also used as the internal representation, which limits what can be
expressed for downstream calculation.

**Resolution: a separate semantic IR v2 (§5). The wire stays compact and frozen.**

### MR5 — Known defects

See §9.

---

## 5. Semantic IR v2

The IR is a **separate artifact** from the wire. It is typed, canonicalisable and
proof-friendly. It may be larger than the wire.

```
IR := {
  atoms: [ { id: u32, bit_length: BigInt, sha256: [32]u8 } ],
  nodes: [ Node ],                       // topological order
  root:  u32,
  total_length: BigInt
}

Node := {
  id: u32,
  kind: 0..11,                           // see §6
  args: [u32],                           // child ids
  a: BigInt,                             // q | start | count | length
  b: BigInt,                             // r | length | init
  flags: u32
}
```

**Invariants.**

1. `nodes` is topologically ordered; every `arg` is a smaller id.
2. Every node has an exact `length : BigInt`.
3. `atoms` are the only place payload bytes live, and they are opaque.
4. The IR contains no encoder state: all parameters are explicit.
5. Canonicalisation is a total function on the IR (§8).

### 5.1 Wire ⟷ IR round-trip

`encode(ir) → wire` and `decode(wire) → ir` must satisfy:

```
decode(encode(ir)) ≡ ir        (structural identity)
encode(decode(wire)) == wire   (byte identity, when the wire is canonical)
```

This is gate **M-G3** and is tested on the full conformance corpus.

---

## 6. Opcode extensions (v1.1, additive)

The 4-bit opcode space currently uses 0–9. Stage 2 adds:

| code | name | length | meaning | purpose |
|---|---|---|---|---|
| 10 | `RAW` | `8·|bytes|` | opaque literal with explicit byte payload | removes noise expansion |
| 11 | `DEDUP_REF` | `len(target)` | reference to a previously emitted term by global id | cross-file / cross-chunk dedup |
| 12 | `DEFLATE_HINT` | declared | deflate block parameters for a subordinate stream | DEFLATE-aware front end |

**Additive rules.**

- v1.0.1 decoders must reject codes 10–12 (they already reject unknown opcodes).
- `version_minor` is bumped only when a new opcode is actually emitted.
- `RAW` and `DEDUP_REF` never change the denotation of an existing file.
- `DEFLATE_HINT` is metadata; the payload remains independently decodable.

---

## 7. Encoder architecture

```
input stream
   │
   ├─ chunker (bounded memory)
   │
   ├─ profiler
   │     entropy estimate · repetition estimate · run-length estimate · deflate framing
   │
   ├─ model decision
   │     RAW          if estimated compressed ≥ raw
   │     DEDUP_REF    if content hash is already in the global index
   │     DEFLATE_HINT if a valid deflate frame is detected
   │     structural DAG otherwise
   │
   ├─ DAG builder (10 structural ops)
   │
   └─ wire writer (CRC, index, trailer)
```

### 7.1 Noise detector

- Estimate entropy on each chunk (order-0 and order-1) plus a cheap LZ match estimate.
- If `estimated_compressed_size ≥ raw_size`, emit `RAW` with the bytes verbatim.
- Threshold is configurable; default is the break-even point plus a 0.5 % safety margin.

**Target.** Random 1 MiB ratio ≤ 1.005× (baseline 1.0408×).

### 7.2 Global dedup index

- Content-addressed: key `(bit_length, sha256)`.
- Scope: all superchunks in a `.mapr` and, optionally, all members of an archive.
- On hit, emit `DEDUP_REF`; on miss, encode normally and register the new term.
- Near-duplicates use `XOR_DIFF` over aligned windows (already an opcode), not approximate
  hashing.
- Index is deterministic: insertion order is the emission order.

**Target.** 10 near-duplicate documents strictly smaller than the per-file baseline (measured
comparison, not a claim).

### 7.3 DEFLATE-aware front end

- Detect zlib (RFC 1950), gzip (RFC 1952) and raw deflate framing.
- Parse stored/fixed/dynamic Huffman blocks and expose block boundaries to the DAG builder.
- Represent each block as a subordinate stream with a `DEFLATE_HINT`.
- Do **not** attempt to beat DEFLATE on already-deflated data. The measured ceiling is
  0.955×–1.039×; record the achieved value honestly.

### 7.4 Determinism

- Identical input ⇒ byte-identical `.mapr` on repeated runs.
- No timestamps, no addresses, no hash-map iteration order in the output.
- The dedup index must be serialised deterministically.

---

## 8. Canonicalisation

A canonical IR is the unique representative of a term's denotation under the following
rewrites, applied to a fixed point:

1. `Empty` elimination: `concat(…, Empty, …) → concat(…)`; `concat(x) → x`.
2. Concatenation flattening: `concat(a, concat(b,c)) → concat(a,b,c)`.
3. Adjacent literal merge: `concat(Atom(a), Atom(b)) → Atom(a‖b)` when the merged size is within
   the atom budget.
4. `Repeat` normalisation: `q ≥ 1`; `0 ≤ r < len(child)`; `q = 1, r = 0` folds to the child.
5. `Slice` folding: nested slices compose; a full-cover slice folds to the child.
6. `Morph` folding: two identical involutions cancel.
7. Commutative ordering: `INTERLEAVE` children sorted by `(length, sha256)`.
8. Structural dedup: identical subterms share one node.

Canonicalisation is **lossless**: every rewrite is an equality of denotations. When a rewrite is
not provable locally, it is not applied.

---

## 9. Defects to fix

| id | defect (measured) | required fix |
|---|---|---|
| M-D1 | `ACTIVE_INTERLEAVE_BITS` is inserted into `node_counts` (`engine/src/dag.cpp:467`) | remove from the node counter, keep in the entropy model |
| M-D2 | `test_full.mapr` does not correspond to `test.zip` | regenerate the fixture and record its SHA-256 |
| M-D3 | `PHASES.md` and `CHANGELOG.md` disagree | single source of truth; generate the changelog from the ledger |
| M-D4 | binary prints v1.0 while the format is v1.0.1 | print the version from the errata document |
| M-D5 | `RESEARCH.md` §A2 forbids raw literal passthrough, causing the 1.0408× expansion | supersede §A2; `RAW` is a legal opcode from v1.1 |

---

## 10. Translator to the calculation layer

`engine/src/mau_translate.*` exposes a public, versioned contract:

```cpp
namespace marp::translate {

struct Term {              // mirrors the semantic IR node kinds
    uint8_t kind;
    std::vector<uint32_t> args;
    std::string a, b;      // decimal BigInt, exact
    uint64_t u;
};

struct Program {
    std::vector<std::string> atoms;   // opaque literals
    std::vector<Term> nodes;          // topological
    uint32_t root;
};

Program fromIr(const Ir&);

} // namespace marp::translate
```

**Rules.**

- All parameters are emitted as exact decimal strings, never `uint64_t`, so lengths above 2⁶⁴
  survive translation.
- Unknown or unexpressible nodes emit an `Unknown` marker; the translator never guesses.
- No payload bytes are emitted except atom contents.
- The translator is pure: same IR ⇒ same `Program`.

**Contract.** The calculation layer must be able to reconstruct the exact `length` of every node
from the `Program` alone. This is tested by the 3-DAG experiment (§12).

---

## 11. Acceptance gates

| gate | condition |
|---|---|
| **M-G1** | noise: 1 MiB random ratio ≤ 1.005× (baseline 1.0408×) |
| **M-G2** | global dedup: 10 near-duplicate documents improve on the per-file baseline, measured |
| **M-G3** | IR ⟷ wire round-trip on the full conformance corpus |
| **M-G4** | translator emits exact `Program`; 3-DAG lengths correct |
| **M-G5** | M-D1…M-D5 closed |
| **M-G6** | v1.0.1 conformance suite passes; every legacy `.mapr` still decodes |
| **M-G7** | determinism: identical input ⇒ byte-identical output on two runs |

---

## 12. The 3-DAG experiment

Three `.mapr` files for the same 64 MiB payload:

- **D1** — one `REPEAT` of a 64 KiB pattern;
- **D2** — 1,000 random `ATOM` chunks under `CONCAT`;
- **D3** — one literal `ATOM`.

MARP's obligation:

| file | expected size (TARGET) |
|---|---|
| D1 | ~300 B |
| D2 | ~64 MiB |
| D3 | ~64 MiB |

The experiment demonstrates the central thesis: **the same bytes can have descriptions differing
by five orders of magnitude, and the choice of description is the product.**

---

## 13. Performance baselines and targets

| metric | measured / target |
|---|---|
| random expansion | 1.0408× measured → **≤ 1.005×** target |
| structured gain | 0.00029×–0.0158× measured |
| archive gain (100 MB) | 0.9414× measured |
| deflate ceiling | 0.955×–1.039× measured (`MATHEMATICAL_SPEC` §6.3) |
| encode throughput | TARGET ≥ 200 MiB/s structured, ≥ 500 MiB/s `RAW` |
| decoder random access | `O(W_hist)` via `INDX` (design invariant) |

---

## 14. Security and robustness

- Every region is length-delimited and CRC-checked.
- The decoder is total: every input either decodes to a unique output or is rejected.
- No decoder path recurses without a depth bound; DAG depth is bounded by the node count.
- Fuzzing target: 100,000 mutations with zero accepts of invalid containers (existing harness
  discipline).
- Unknown flags/opcodes/kinds are critical errors, never ignored.

---

## 15. Glossary

| term | meaning |
|---|---|
| **wire** | the compact `.mapr` byte format (frozen v1.0.1) |
| **IR** | semantic intermediate representation (v2, may be larger) |
| **atom** | opaque literal block |
| **superchunk** | self-framed record containing one DAG or a chunk reference |
| **denotation** | the byte string a term denotes |
| **canonical form** | unique representative under the rewrite system |
| **RAW** | v1.1 opcode: literal bytes without structural interpretation |
| **DEDUP_REF** | v1.1 opcode: reference into the global dedup index |

---

*End of MARP Stage 2 specification.*
