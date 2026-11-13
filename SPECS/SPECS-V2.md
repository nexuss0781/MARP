# MARP v2 — Byte-Universal Expression Specification

**Document:** `MARP/SPECS/SPECS-V2.md`
**Version:** 2.0-spec
**Date:** 2026-11-12
**Status:** normative specification for the MARP v2 rewrite. Implementation starts at Phase 0 of `MARP/SPECS/Todo-V2.md`.
**Supersedes for new work:** the Stage 2 additions in `MARP/SPECS/SPECS.md`. The v1.0.1 wire remains frozen and readable; v2 is a new major format.

**Rule:** every number in this document is either **measured** (source named) or labelled **TARGET**. No number is a claim until the harness in §12 has produced it.

---

## 1. Mandate

MARP is the **expression engine** of the Nezistor system. Its input is an arbitrary byte string. Its output is a canonical, exact term DAG and a compact wire representation of that term.

```
arbitrary bytes  ──MARP──▶  exact term T  ──MAU──▶  exact arithmetic / certificate
                                      └──NEZITOR──▶  .nez container
```

MARP does **not** compress, does **not** certify by itself, and does **not** materialise the payload as an external object. It discovers and records exact structure. The only payload bytes that survive are the atoms that no exact term can explain.

> **MARP expresses. MAU computes. NEZITOR stores the irreducible remainder.**

The engine is **byte-universal**. It never asks what a file "is". A zip, a PDF, a video, a model, a database page, or a stream from a pipe are all the same object: a finite byte string.

### 1.1 The size law

For any exact representation `R` of a byte string `x`:

```
|R|  >=  K(x)  +  irreducible residual
```

`K(x)` is the Kolmogorov complexity of `x`. This is not a limitation of MARP; it is the definition of information. MARP v2 is designed to approach the best exact description it can find, and to report the residual honestly when no structure exists.

Consequences:

- A low-complexity multi-gigabyte input (repetition, generators, grammar, near-duplicates) can be expressed in KB–MB.
- A high-complexity input (noise, already entropy-coded data, trained model weights) cannot be expressed below its information content by any lossless system.
- The engine MUST report which case it is in. It MUST NOT claim a size below the measured floor.

### 1.2 Non-goals

MARP v2 is **not**:

- a compressor in the entropy-coding sense;
- a lossy system or an approximate model;
- a file-type classifier;
- a zip/PDF/video/tensor parser;
- a decision procedure for algebraic equality (that is MAU);
- a container format for applications (that is NEZITOR).

### 1.3 No file-type classes

The core MUST NOT contain code paths keyed on ZIP, PDF, video, GGUF, ELF, JSON, or tensor structure. Those formats are byte patterns like any other.

Optional accelerators (§6.11) MAY propose candidate terms for a detected byte pattern. They are advisory only. **No acceptance gate may depend on an accelerator.** Every gate must pass with accelerators disabled.

---

## 2. Normative language and invariants

The words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are normative.

### 2.1 Exactness invariants

1. `decode(encode(x)) = x` for every finite byte string `x`.
2. Every term has an exact byte length, computed as an arbitrary-precision integer.
3. Every term denotes exactly one byte string.
4. No term is emitted unless its denotation has been verified against the source bytes (or against a verified child).
5. No probabilistic acceptance at the final gate. A hash may guide discovery; the final comparison is byte-exact.

### 2.2 Canonicality invariants

1. The canonical form of a term is unique.
2. Atom ids and node ids are assigned in first-use order.
3. The node table is topologically ordered; every child id is strictly smaller than its parent id.
4. Identical subterms share one node.
5. No unused atoms or nodes are emitted.
6. The root is the last node (`root_id = node_count - 1`).
7. Identical input bytes and identical encoder effort produce a byte-identical `.mapr`.

### 2.3 Totality and safety invariants

1. The decoder is total: every byte string either decodes to a unique output or is rejected with a defined error.
2. Unknown critical flags, unknown node kinds, unknown morphisms, and unknown predictor ids are rejected, never guessed.
3. Every offset and length is bounds-checked before use.
4. DAG depth and expansion are bounded by declared limits.
5. No decoder path recurses without a bound; evaluation uses an explicit work stack.

---

## 3. Formal term algebra

### 3.1 Sorts

```
ByteString  = finite sequence of 8-bit bytes
BigInt      = non-negative arbitrary-precision integer
NodeId      = u32, 0 <= NodeId < node_count
AtomId      = u32, 0 <= AtomId < atom_count
```

All lengths are byte counts. There are no sub-byte lengths in the wire. Bit-level structure is expressed with byte-level morphisms and generators whose output is byte-aligned.

### 3.2 Node grammar

```
Node ::=
    Empty                                  -- length 0
  | Atom(AtomId)                           -- opaque atom bytes
  | Zero(BigInt n)                         -- n zero bytes
  | Concat(NodeId[1..k])                   -- k >= 2
  | Repeat(NodeId child, BigInt q, BigInt r)
  | Slice(NodeId child, BigInt start, BigInt len)
  | Morph(NodeId child, u8 morph, u8 k)
  | Xor(NodeId a, NodeId b)                -- equal lengths
  | Interleave(NodeId[1..k], u32 stride)
  | Lfsr(u64 conn, u64 init, BigInt n)
  | Affine(u8 start, u8 step, BigInt n)
  | Predictor(u8 pid, u32 param, NodeId residual)
```

`Repeat` is normalised so that `q >= 0`, `0 <= r < len(child)` when `q >= 1`, and `r = 0` when `q = 0`.

`Slice` requires `0 <= start <= len(child)` and `start + len <= len(child)`.

`Xor` requires `len(a) = len(b)`.

`Interleave` requires every child to have the same length `L`, `L % stride = 0`, and `stride >= 1`.

`Predictor` requires `len(residual) = n`; the output length is `n`.

### 3.3 Denotation

| node | denotation |
|---|---|
| `Empty` | the empty string |
| `Atom(a)` | the bytes of atom `a` |
| `Zero(n)` | `0x00` repeated `n` times |
| `Concat(c1..ck)` | `denote(c1) ‖ … ‖ denote(ck)` |
| `Repeat(c,q,r)` | `denote(c)` repeated `q` times, followed by the first `r` bytes of `denote(c)` |
| `Slice(c,s,l)` | bytes `[s, s+l)` of `denote(c)` |
| `Morph(c,m,k)` | `morph_m(k, denote(c))` |
| `Xor(a,b)` | `denote(a) XOR denote(b)` bytewise |
| `Interleave(c1..ck,s)` | for each block of `s` bytes, output the block from `c1`, then `c2`, … |
| `Lfsr(conn,init,n)` | `n` bytes from the Fibonacci LFSR defined in §3.5 |
| `Affine(start,step,n)` | `out[i] = (start + i*step) mod 256` |
| `Predictor(pid,param,r)` | predictor catalogue §3.6 applied to `denote(r)` |

### 3.4 Morphism catalogue

| id | name | exact operation | involution |
|---|---|---|---|
| 1 | `BIT_REVERSE8` | reverse the 8 bits of every byte | yes |
| 2 | `INVERT8` | bitwise NOT of every byte | yes |
| 3 | `SWAP16` | swap each adjacent byte pair | yes |
| 4 | `SWAP32` | reverse byte order in each 4-byte word | yes |
| 5 | `SWAP64` | reverse byte order in each 8-byte word | yes |
| 6 | `ROTL8` | rotate each byte left by `k` (1..7) | no |
| 7 | `ROTR8` | rotate each byte right by `k` (1..7) | no |
| 8 | `REVERSE_BYTES` | reverse the whole segment | yes |
| 9 | `REVERSE_BITS` | reverse the whole segment bit order | yes |

Morphisms 3, 4, and 5 require the segment length to be a multiple of 2, 4, and 8 bytes respectively; otherwise the node is invalid. The decoder MUST reject an invalid morph rather than pad or truncate. `k` MUST be 0 for morphisms 1–5 and 8–9, and 1–7 for morphisms 6–7; any other `k` is invalid.

### 3.5 LFSR definition

The generator is a 64-bit Fibonacci LFSR:

```
state = init
repeat n*8 times:
    bit = parity(state AND conn)          -- XOR of set bits
    state = (state >> 1) OR (bit << 63)
    emit bit
pack emitted bits MSB-first into bytes
```

`conn != 0`. The encoder MUST verify the generated bytes exactly.

### 3.6 Predictor catalogue

Predictors are closed, deterministic, and byte-exact. `r` is the residual string; `n = len(r)`.

| id | name | operation |
|---|---|---|
| 0 | `DELTA8` | `out[0]=r[0]`; `out[i]=(out[i-1]+r[i]) mod 256` |
| 1 | `XOR8` | `out[0]=r[0]`; `out[i]=out[i-1] XOR r[i]` |
| 2 | `LINEAR2` | `out[0]=r[0]`, `out[1]=r[1]`; `out[i]=(2*out[i-1]-out[i-2]) mod 256` |
| 3 | `STRIDE_XOR` | `param=s>0`; `out[i]=r[i]` for `i<s`; `out[i]=out[i-s] XOR r[i]` |
| 4 | `STRIDE_DELTA` | `param=s>0`; `out[i]=r[i]` for `i<s`; `out[i]=(out[i-s]+r[i]) mod 256` |

Any other id is invalid. Predictors have no hidden state beyond `out` and the parameter; the decoder reconstructs the same `out` from the same residual.

### 3.7 Length arithmetic

Every node has an exact `length`:

```
len(Empty) = 0
len(Atom(a)) = atom_length(a)
len(Zero(n)) = n
len(Concat) = sum(len(child))
len(Repeat(c,q,r)) = q*len(c) + r
len(Slice(c,s,l)) = l
len(Morph(c)) = len(c)
len(Xor(a,b)) = len(a)                      -- requires equal
len(Interleave(c1..ck,s)) = k*len(c1)       -- requires equal
len(Lfsr(_,_,n)) = n
len(Affine(_,_,n)) = n
len(Predictor(_,_,r)) = len(r)
```

All arithmetic is exact and arbitrary-precision. The wire carries the length of every node so MAU and the decoder can validate without evaluating.

### 3.8 Canonicalisation

Canonicalisation is a total function `canon(T)` applied to a fixed point. It MUST preserve denotation.

1. `Concat` flattening: `Concat(a, Concat(b,c)) -> Concat(a,b,c)`.
2. `Empty` elimination: remove `Empty` children; `Concat(x) -> x`.
3. `Atom` merge: atoms MUST NOT exceed the fixed normative `ATOM_MAX` (1 MiB); an atom above the limit is split into 1 MiB atoms. Adjacent atoms merge when the merged size is at most `ATOM_MAX`. These limits are format constants, not effort parameters, so canonicalisation does not depend on `--effort`.
4. `Zero` merge: adjacent `Zero` nodes merge.
5. `Repeat` normalisation:
   - `q=0` → `Empty` when `r=0`, else `Slice(child,0,r)`;
   - `q=1, r=0` → child;
   - `q=1, r>0` → `Concat(child, Slice(child,0,r))`;
   - if `r >= len(child)`, fold the excess into `q`.
6. `Slice` folding: nested slices compose; a full-cover slice folds to the child; zero-length slice → `Empty`.
7. `Morph` folding: two identical involutions cancel; adjacent rotations compose; an identity morph is removed.
8. `Xor` folding: `Xor(x,x) -> Zero(len(x))`; `Xor(x,Zero) -> x`; `Xor(Zero,x) -> x`; `Xor(a,b)` and `Xor(b,a)` canonicalise to the order `(canonical_bytes, length, child_id)`.
9. `Interleave` folding: a single child folds to the child; child order is semantic and MUST NOT be sorted or reordered.
10. `Affine` folding: `step=0` → `Zero(n)` if `start=0`, otherwise `Repeat(Atom(byte), n, 0)`.
11. `Zero` folding: `Repeat(Zero, q, r) -> Zero(q*len+r)`; `Slice(Zero, s, l) -> Zero(l)`.
12. Structural dedup: identical subterms share one node (hash-consing).
13. Unused nodes and atoms are pruned.

Tie-breaking is deterministic and documented in §7.4.

---

## 4. Semantic IR v2

The IR is the MAU-facing artifact. It is separate from the wire and may be larger.

```cpp
struct Atom {
    uint32_t id;
    uint8_t  klass;          // statistical class, §6.9
    uint64_t bit_length;     // always a multiple of 8 in v2
    Sha256   sha256;
    // payload lives in the atom stream, not in this descriptor
};

struct Node {
    uint32_t id;
    uint8_t  kind;           // §3.2
    uint8_t  flags;
    std::vector<uint32_t> args;
    BigInt   a, b;           // q/r, start/len, n, ...
    uint8_t  morph, morph_k;
    uint64_t lfsr_conn, lfsr_init;
    uint8_t  affine_start, affine_step;
    uint8_t  predictor_id;
    uint32_t predictor_param;
    BigInt   length;
};

struct Ir {
    std::vector<Atom> atoms;
    std::vector<Node> nodes;
    uint32_t root;
    BigInt   total_length;
};
```

### 4.1 IR invariants

1. Nodes are topologically ordered; every arg is `< node.id`.
2. Every node has an exact `length` (§3.7).
3. Atoms are the only place payload bytes live.
4. Atom ids and node ids are dense and first-use ordered.
5. The IR contains no encoder state, timestamps, addresses, or hash-map iteration order.
6. `canon(ir)` is idempotent.
7. `eval(ir) = source bytes`.

---

## 5. Wire format v2

The v2 wire is a new major format. It is canonical: one term has exactly one wire encoding.

### 5.1 Top-level layout

```
Region A   Fixed header              64 B
Region A.1 Total-length magnitude    optional, `total_length_big_len` bytes
Region B   Atom table                variable
Region C   Node table                variable
Region D   Seek index                optional, variable
Region E   Trailer                   32 B
```

Region A.1 is present only when `total_length_big_len > 0`. It holds the
little-endian magnitude of `total_length` with no leading zero byte. `atom_offset`
MUST equal `64 + total_length_big_len` in that case, and `64` otherwise.

### 5.2 Header (64 bytes)

| offset | size | field |
|---|---|---|
| 0 | 8 | magic `89 4D 41 50 52 32 0D 0A` (`\x89MAPR2\r\n`) |
| 8 | 2 | `version_major = 2` |
| 10 | 2 | `version_minor = 0` |
| 12 | 4 | flags |
| 16 | 2 | `header_bytes = 64` |
| 18 | 8 | `total_length_u64` (0 if the length does not fit) |
| 26 | 2 | `total_length_big_len` (0 if `total_length_u64` is used) |
| 28 | 8 | `atom_offset` |
| 36 | 8 | `node_offset` |
| 44 | 8 | `index_offset` (0 if absent) |
| 52 | 8 | `trailer_offset` |
| 60 | 4 | `file_crc32` |

Flag bits:

| bit | meaning |
|---|---|
| 0 | seek index present |
| 1 | canonical encoding (MUST be 1 in v2) |
| 2 | all lengths fit in u64 |
| 3 | atoms are byte-aligned (MUST be 1 in v2) |
| 4–31 | reserved, MUST be 0 |

`file_crc32` is CRC-32 (IEEE) over every byte before `trailer_offset`, with the 4-byte `file_crc32` field treated as zero. The header, the optional total-length magnitude, the atom table, the node table, and the index are covered.

`total_length` is encoded canonically: if it fits in `u64`, `total_length_u64` holds it and
`total_length_big_len = 0`; otherwise `total_length_u64 = 0`, `total_length_big_len > 0`, and
the magnitude follows the header in Region A.1 with no leading zero byte.

### 5.3 Integer encodings

**uvarint:** unsigned LEB128, canonical (no redundant trailing zero groups), at most 10 bytes for a u64.

**bigint:**

```
0x00                     -> 0
0x01 <uvarint>           -> value fits in u64
0x02 <u32 len> <bytes>   -> little-endian magnitude, no leading zero byte, len >= 1
```

Encoding a value with the wrong tag is non-canonical and MUST be rejected by a v2 reader.

### 5.4 Atom table

```
uvarint atom_count
atom_count × AtomRecord
```

`AtomRecord`:

```
u8   klass
u8   flags          (reserved, MUST be 0)
u16  reserved       (MUST be 0)
bigint length       (payload byte length)
u8[32] sha256       (SHA-256 of the payload)
u8[length] payload
```

Atoms are byte-aligned. Atom ids are implicit record indices. Atom records are ordered by first use in the canonical node traversal; duplicate payloads MUST NOT appear twice.

### 5.5 Node table

```
uvarint node_count
node_count × NodeRecord
```

`NodeRecord`:

```
u8   kind
u8   flags          (reserved, MUST be 0)
u16  argc
argc × uvarint arg  (absolute node id, MUST be < current node id)
kind-specific params
bigint length
```

Kind-specific params:

| kind | value | params |
|---|---|---|
| 0 | `Empty` | none |
| 1 | `Atom` | `uvarint atom_id` |
| 2 | `Zero` | `bigint n` |
| 3 | `Concat` | none (`argc >= 2`) |
| 4 | `Repeat` | `bigint q`, `bigint r` (`argc = 1`) |
| 5 | `Slice` | `bigint start`, `bigint len` (`argc = 1`) |
| 6 | `Morph` | `u8 morph`, `u8 k` (`argc = 1`) |
| 7 | `Xor` | none (`argc = 2`) |
| 8 | `Interleave` | `u32 stride` (`argc >= 1`) |
| 9 | `Lfsr` | `u64 conn`, `u64 init`, `bigint n` (`argc = 0`) |
| 10 | `Affine` | `u8 start`, `u8 step`, `bigint n` (`argc = 0`) |
| 11 | `Predictor` | `u8 pid`, `u32 param` (`argc = 1`) |

All multi-byte fixed integers are little-endian. The `length` field MUST equal the value computed by §3.7; a mismatch is invalid. Any `argc` not listed for the node kind is invalid, and any child id that is not strictly smaller than the current node id is invalid.

### 5.6 Seek index (optional)

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

Entries are strictly increasing in `output_offset`. The index is an optimisation; a decoder MUST be able to decode without it. It MUST NOT change the denotation.

### 5.7 Trailer (32 bytes)

| offset | size | field |
|---|---|---|
| 0 | 8 | magic `TRLR2\r\n\x1a` |
| 8 | 8 | `file_bytes` (total container size) |
| 16 | 4 | `root_id` |
| 20 | 4 | `atom_count` |
| 24 | 4 | `node_count` |
| 28 | 4 | `trailer_crc32` |

`trailer_crc32` is CRC-32 over the first 28 trailer bytes (with the CRC field treated as zero) followed by the 4-byte `file_crc32`.

### 5.8 Canonical wire rules

1. Header flags are minimal; reserved bits are zero.
2. Atoms are first-use ordered and deduplicated.
3. Nodes are topological and first-use ordered; the root is the last node.
4. No unused atoms or nodes.
5. Every integer uses the shortest canonical encoding.
6. The index, if present, is minimal and sorted.
7. Identical bytes at identical effort produce identical wire bytes.

### 5.9 Decoder validation order

1. Size >= 64 + 32.
2. Magic, version, `header_bytes`, reserved flags.
3. `trailer_offset` and `file_bytes` bounds.
4. Header CRC.
5. Trailer magic, counts, root, trailer CRC.
6. Region offsets are monotonic and within bounds; `atom_offset` equals `64 + total_length_big_len`; the total-length magnitude is canonical and matches the declared length.
7. Atom table: counts, canonical bigints, payload bounds, SHA-256 matches payload.
8. Node table: counts, kinds, argc, arg range, params, canonical bigints, length equality.
9. Root id equals `node_count - 1`.
10. Index (if present): magic, count, ordering, CRC.
11. Full evaluation: output length equals declared total length; output SHA-256 matches the certificate if present.

Any failure rejects the container. There is no partial acceptance.

---

## 6. Discovery pipeline

Discovery is heuristic. Acceptance is exact. The encoder MAY miss structure; it MUST NOT emit a false term.

### 6.1 M0 — Provenance

- Streaming SHA-256 and exact byte length.
- Rolling gear hash and sample fingerprints for segmentation.
- Deterministic effort seed derived from the bytes, never from time or address.

### 6.2 M1 — Multi-scale segmentation

- Content-defined chunking with a gear hash at target sizes `64 B … 64 MiB`.
- Change-point detection on order-0/1 entropy, run density, match density, and periodicity.
- A segment tree; each leaf is a candidate region for a term.
- Boundaries are deterministic and independent of thread scheduling.

### 6.3 M2 — Statistical probes

Per segment:

- order-0/1/2 byte entropy;
- run-length histogram;
- minimal period (KMP prefix function, then full verification);
- repeated-substring density (suffix automaton or rolling-hash dictionary);
- bit-plane and byte-plane skew;
- Berlekamp–Massey over GF(2) on each bit plane;
- affine/polynomial recurrence fit;
- stride/reshape detection;
- exact-match density against the global dictionary.

### 6.4 M3 — Grammar induction

- Re-Pair / Sequitur-style phrase discovery over byte tokens and bit-plane tokens.
- A bounded global phrase dictionary.
- Grammar rules are **desugared** into `Concat`/`Repeat`/shared node ids before wire emission; the wire has no grammar-specific node.
- Expansion is verified against the source before acceptance.
- Memory is bounded by the phrase budget; overflow stops induction, never corrupts output.

### 6.5 M4 — Transform and symmetry search

- Bit/byte plane transpose via `Slice` + `Interleave`.
- Stride reshape.
- Endianness swaps, bit reversal, inversion, rotation, whole-segment reversal.
- XOR/delta against a dictionary or neighbouring segment.
- Alignment search for long exact matches at arbitrary offsets.
- A transform is accepted only when `B = g(A)` exactly.

### 6.6 M5 — Generator synthesis

Catalogue:

- `Zero`;
- `Repeat`/periodic tile;
- `Lfsr`;
- `Affine`;
- `Predictor` residuals;
- grammar-generated streams (desugared).

Every candidate is expanded and compared byte-for-byte before acceptance.

### 6.7 M6 — Global reference index

- Content-addressed by `(length, SHA-256)`.
- Exact duplicate → shared node id.
- Near duplicate → `Xor` over aligned windows, then exact verification.
- Cross-segment and cross-scale references.
- Deterministic insertion order.

### 6.8 M7 — MDL selector

For each segment, beam-search candidate terms and choose the one minimising:

```
cost(T) = 8 * wire_bytes(T) + coded_bits_estimate(atoms(T)) + model_bits
```

`coded_bits_estimate` is supplied by the class models of §6.9; it is an estimate, not a claim. The selector may choose `Atom` — the honest case. The final measured size is the wire size plus the NEZITOR coding of atoms; MARP reports both.

### 6.9 M9 — Atom classifier

Atoms are classified by measured statistical signature, never by file type:

| class | name | signature |
|---|---|---|
| 0 | `OPAQUE` | order-1 entropy >= 7.9 bits/byte, no exact structure |
| 1 | `SPARSE` | zero fraction >= 0.5 |
| 2 | `LOW_ENTROPY` | order-0 entropy <= 4 bits/byte |
| 3 | `PERIODIC_RESIDUAL` | periodic candidate rejected but long matches remain |
| 4 | `TEXTUAL` | printable ratio >= 0.9, token diversity above threshold |
| 5 | `NUMERIC_PLANE` | bit-plane skew and stride structure |
| 6 | `CODE_LIKE` | high order-2 predictability with local repeats |
| 7 | `TOKEN_STREAM` | grammar/LZ token residual |

The classifier is advisory to NEZITOR. It does not change the denotation. Classification runs **after** canonicalisation, on the final atom payloads; it never changes atom boundaries.

### 6.10 M10 — Streaming planner

- Profile in one pass; re-read only for candidate verification.
- Segment-level parallelism with deterministic merge.
- Atoms spill to temporary streams; peak memory is bounded.
- The output depends only on the bytes and effort level.

### 6.11 M11 — Optional accelerators

A plugin MAY detect a byte pattern (for example a compressed frame or an executable header) and propose a decomposition. The proposal goes through the same exact verifier and MDL selector. Plugins:

- are disabled by default in the gate harness;
- cannot be required by any gate;
- cannot change the wire format;
- cannot introduce file-type semantics into the IR.

---

## 7. Encoder algorithm

### 7.1 Passes

1. **Profile:** length, SHA-256, rolling hashes, entropy samples.
2. **Segment:** build the segment tree and candidate boundaries.
3. **Discover:** run M2–M6 per segment; collect exact-verified candidate terms.
4. **Select:** beam-search the MDL objective over the segment tree.
5. **Canonicalise:** apply §3.8 to a fixed point.
6. **Emit:** write the canonical v2 wire.
7. **Verify:** decode the emitted wire and compare SHA-256 and bytes with the input. A mismatch aborts with exit 6 and leaves no output file.

### 7.2 Effort levels

`--effort 0..9` scales the candidate budget, grammar budget, and beam width. Effort does not change exactness or canonicality. Default is 5.

### 7.3 Parallelism

- Segment discovery is parallel.
- Merge order is by segment offset, never by completion order.
- Hash-consing and atom id assignment are serialised in canonical order.

### 7.4 Deterministic tie-breaking

When two candidates have equal cost, choose by:

```
(kind, argc, canonical child ids, a, b, morph, predictor_id, lexicographic wire bytes)
```

No pointer values, timestamps, or hash-map iteration order may influence the choice.

### 7.5 Failure behaviour

- Usage error: exit 2, no output.
- I/O error: exit 3, no output.
- Invalid or unrepresentable input: exit 4, no output.
- Encoder self-verification failure: exit 6, no output.
- Resource limit: exit 7, no output.

Output is written atomically: temporary sibling file, then rename.

---

## 8. Decoder algorithm

### 8.1 Validation

Run §5.9 in order. Reject on the first failure. Do not allocate based on unvalidated counts.

### 8.2 Evaluation

- Build the node table; compute lengths; validate every child length.
- Evaluate with an explicit stack in topological order.
- For full decode, stream to the output through a fixed block buffer; hash incrementally.
- For `--range START:LEN`, evaluate only the intersecting subterms; `Zero`, `Affine`, `Lfsr`, and `Repeat` support direct range evaluation without materialising the whole prefix. LFSR range evaluation uses GF(2) jump-ahead (matrix or polynomial exponentiation) so an offset is reached in `O(log offset)` time; it never advances bit-by-bit from zero.
- Predictor residuals are evaluated sequentially; the range decoder may skip whole predictor blocks only if the predictor state is restored exactly.

### 8.3 Resource limits

Configurable, with conservative defaults:

| limit | default |
|---|---|
| max container bytes | 2^63 |
| max atoms | 2^24 |
| max nodes | 2^24 |
| max DAG depth | 2^16 |
| max output bytes | declared total length, hard cap 2^63 |
| max expansion ratio | 2^20 for range decode, unlimited for declared full decode |

A container that exceeds a limit is rejected with exit 7; it is never partially decoded.

### 8.4 Error taxonomy

| code | meaning |
|---|---|
| 0 | success |
| 2 | usage |
| 3 | I/O |
| 4 | invalid container |
| 5 | unsupported version/feature |
| 6 | verification mismatch |
| 7 | resource limit |

---

## 9. MAU boundary

MARP exposes a pure translator to the calculation layer.

```cpp
namespace marp::translate {

struct Atom {
    std::string bit_length;   // exact decimal, multiple of 8
    std::string sha256_hex;
};

struct Term {
    uint8_t kind;
    std::vector<uint32_t> args;
    std::string a;            // exact decimal BigInt
    std::string b;            // exact decimal BigInt
    std::string length;       // exact decimal BigInt
    uint8_t morph, morph_k;
    uint64_t lfsr_conn, lfsr_init;
    uint8_t affine_start, affine_step;
    uint8_t predictor_id;
    uint32_t predictor_param;
};

struct Program {
    std::vector<Atom> atoms;
    std::vector<Term> nodes;
    uint32_t root;
    std::string total_length; // exact decimal BigInt
};

Program fromIr(const Ir&);

} // namespace marp::translate
```

### 9.1 Contract

1. Every length, count, offset, and generator parameter is emitted as an exact decimal string. No truncation to `uint64_t`.
2. No payload bytes are emitted except atom contents in the separate atom stream.
3. The translator is pure: the same IR produces the same `Program`.
4. Unknown or unexpressible nodes are emitted as an explicit `UNKNOWN` marker; the translator never guesses.
5. MAU can reconstruct every node length from the `Program` alone.
6. MAU can evaluate `Program` over any `[start, end)` range, including offsets and counts above 2^64, without materialising the whole stream.

### 9.2 Certificate

The certificate binds:

- total byte length (exact decimal);
- root SHA-256;
- canonical term SHA-256;
- atom count and node count;
- format version and effort.

`verify` recomputes the term denotation and the hash. A certificate is accepted only if the recomputed facts match. MARP never certifies a fact it did not derive from the emitted wire.

---

## 10. NEZITOR boundary

MARP does not implement the `.nez` container. It exposes:

- the canonical v2 wire;
- the IR (`term --json`);
- the atom classes of §6.9;
- exact atom payloads;
- the MAU `Program`.

NEZITOR is expected to:

- code atom streams with a model selected per class;
- store the canonical term and generator parameters;
- store the certificate;
- reconstruct the term and evaluate it exactly;
- support range decode through §9.1(6);
- never claim a size below the measured atom residual.

The MARP harness measures MARP's wire size and reports the atom residual separately. A `.nez` size claim belongs to the NEZITOR harness.

---

## 11. CLI v2

```
mapr encode   --input <in> --output <out.mapr>
              [--threads N] [--effort 0..9]
              [--atom-budget BYTES] [--metrics-out <m.json>]
              [--plugin ID]...

mapr decode   --input <in.mapr> --output <out>
              [--range START:LEN] [--threads N]

mapr verify   --input <in.mapr>
mapr inspect  --input <in.mapr> [--json-out <i.json>]
mapr term     --input <in.mapr> [--json-out <t.json>]
mapr floor    --input <in> [--json-out <f.json>]
mapr bench    --corpus <dir> [--json-out <b.json>]

mapr spec-zero    <length> <out.mapr>
mapr spec-repeat  <tile-file> <count> <out.mapr>
mapr spec-lfsr    <conn> <init> <length> <out.mapr>
mapr spec-affine  <start> <step> <length> <out.mapr>
```

`mapr floor` runs the best-of-ensemble comparison (`xz -9e`, `zstd -19`, `brotli -q 11`, `bzip2 -9`) and reports:

- input bytes;
- best generic size and which tool;
- MARP wire bytes;
- atom residual bytes;
- reference-coder residual bytes (actual coded size from `ref_coder.py`);
- honest floor note.

`mapr term --json` emits the MAU `Program` with decimal strings.

The v1 CLI names remain available for legacy files; v2 is selected by the output format, not by a file extension.

---

## 12. Complete acceptance harness

The harness is the contract. A feature that is not measured by the harness is not done.

### 12.1 Principles

1. Every gate writes one row to `gates.tsv`.
2. Every number in `ACCEPTANCE.md` is copied from a row or log written by the harness.
3. `PASS` is printed only when every row's condition is true and every required evidence file exists.
4. A missing fixture, a missing log, or a hand-edited number is a hard failure.
5. The harness runs with accelerators disabled.
6. The harness runs on the same host and records the environment.
7. Multi-gigabyte fixtures are generated deterministically or are sparse; their SHA-256 is recorded.

### 12.2 Directory layout

```
MARP/
  harness/v2/
    run_all.sh                 # entry point
    gen_fixtures.py            # deterministic fixture generator
    indep_decode_v2.py         # clean-room reference decoder
    ref_coder.py               # reference class-conditioned atom coder (measurement only)
    fuzz_v2.py                 # mutation fuzzer
    gates.tsv                  # one row per gate measurement
    perf.tsv                   # performance rows
    fixtures.tsv               # fixture identity
    floor.tsv                  # best-of-ensemble rows
  specs_and_reports/v2/
    ACCEPTANCE.md              # generated from gates.tsv
    GATE_TRANSCRIPT.txt        # full stdout/stderr
    logs/                      # per-gate logs
    perf.md                    # generated from perf.tsv
    floor.md                   # generated from floor.tsv
```

### 12.3 Fixture catalogue

Fixtures are byte strings. No fixture is classified by file type. `F11` and `F12` are opaque real files supplied on the command line.

| id | fixture | size | generation |
|---|---|---|---|
| F00 | empty | 0 | deterministic |
| F01 | one byte | 1 | `0xA5` |
| F02 | zeros | 1 GiB | sparse/generator |
| F03 | repeated text | 1 GiB | repeated 64 KiB text block |
| F04 | periodic tile | 4 GiB | 64 KiB tile × count |
| F05 | gradient | 256 MiB | affine bytes |
| F06 | counter | 1 GiB | affine with step 1 |
| F07 | LFSR | 1 GiB | `spec-lfsr` |
| F08 | grammar | 1 GiB | nested repeats and near-duplicates |
| F09 | near-duplicate corpus | 10 × 100 KiB | 1 % mutations |
| F10 | random | 1 GiB | `/dev/urandom` draw, hashed once |
| F11 | arbitrary real bytes | any | `--real <path>` (PDF, video, zip, binary, …) |
| F12 | already entropy-coded bytes | any | `--coded <path>` (compressed/encrypted) |
| F13 | virtual 2^40 probe | 2^40 | `spec-zero` / `spec-repeat`, no materialisation |
| F14 | virtual 2^50 probe | 2^50 | `spec-zero` / `spec-repeat`, no materialisation |
| F15 | mixed 4 GiB | 4 GiB | concatenation of F02/F03/F05/F06/F10 segments |

`F11` and `F12` are exactness/floor fixtures. They do not carry a size expectation. They are how the harness covers PDF, video, zip, and any other real byte string without special-casing them.

If a required F11/F12 path is not supplied, the dependent gate is `BLOCKED`, never `PASS`. The harness prints the missing path and the affected gate ids.

### 12.4 Gate table

| gate | condition | measured evidence |
|---|---|---|
| **V2-G0** | harness self-test: a deliberately corrupted container is rejected; a valid one decodes | `logs/v2g0_*.log` |
| **V2-G1** | exact round-trip on F00–F12 and F15: `sha256(out) == sha256(in)` and `cmp` equal | `gates.tsv` |
| **V2-G2** | determinism: two encodes at the same effort are byte-identical | `logs/v2g2_*.log` |
| **V2-G3** | structured size: F02/F03/F04 → wire <= 1 MiB for >= 1 GiB input; F04 4 GiB → wire <= 8 MiB | `gates.tsv` |
| **V2-G4** | structural coverage: >= 99.9 % of bytes on F02–F08 are in non-atom nodes; atom residual reported | `gates.tsv` |
| **V2-G5** | noise: F10 random ratio <= 1.005× | `gates.tsv` |
| **V2-G6** | best-of-ensemble: on F11/F15, `wire_bytes + ref_coder_bytes` <= 1.02× the best of `xz -9e`/`zstd -19`/`brotli -q 11`; on F12 <= 1.02× | `floor.tsv`, `gates.tsv` |
| **V2-G7** | floor honesty: every size-claim fixture (F02–F08, F10–F12, F15) reports atom residual and the best generic size; no claim below the floor | `floor.tsv` |
| **V2-G8** | range probe: F13/F14 slices at the end are byte-exact; no full materialisation | `logs/v2g8_*.log` |
| **V2-G9** | fuzz: 100,000 mutations, zero accepted invalid containers, zero crashes, zero hangs | `logs/v2g9_fuzz.log` |
| **V2-G10** | memory: encode 4 GiB <= 256 MiB RSS; decode <= 128 MiB RSS | `perf.tsv` |
| **V2-G11** | throughput: structured encode >= 25 MiB/s and RAW encode >= 100 MiB/s on tmpfs; decode >= 100 MiB/s | `perf.tsv` |
| **V2-G12** | independent decoder: clean-room Python decoder decodes every F00–F08 wire byte-exactly | `logs/v2g12_*.log` |
| **V2-G13** | legacy: v1.0.1 and v1.1 `.mapr` fixtures still decode byte-exactly | `logs/v2g13_*.log` |
| **V2-G14** | byte-universal real files: F11/F12 round-trip exactly; no type-specific code path is required | `gates.tsv` |
| **V2-G15** | MAU program: pure, decimal-exact, every node length reconstructible; 3-DAG lengths correct | `logs/v2g15_*.log` |
| **V2-G16** | canonical idempotence: `canon(canon(x)) == canon(x)`; re-canonicalising the decoded IR and re-emitting yields byte-identical wire | `logs/v2g16_*.log` |

### 12.5 Measurement method

- Wall time and maximum RSS: `/usr/bin/time -v`.
- Input and output identity: `sha256sum` and `cmp`.
- Wire size: `stat -c %s`.
- Atom residual: `mapr inspect --json`.
- Best-of-ensemble: one row per tool in `floor.tsv`, with command and version. An unavailable tool is recorded as `unavailable`; availability is part of the evidence, never an invisible skip.
- Multi-GB fixtures: generated to a scratch directory; SHA-256 recorded before use; removed only after the gate row is written.
- Every gate log contains the exact command line, exit code, and the measured values.
- `ref_coder.py` is a simple class-conditioned range coder used only to measure the actual coded atom bytes for V2-G6 and V2-G7. It is a measurement instrument, not a product and not part of MARP's contract.
- `gates.tsv` columns:

```
gate  fixture  input_bytes  wire_bytes  ratio  encode_s  encode_rss_kib
decode_s  decode_rss_kib  sha_match  atom_bytes  best_generic_bytes
best_tool  condition  verdict  log
```

### 12.6 Harness entry point

`run_all.sh` MUST:

1. Build the engine and the tests.
2. Verify the binary version and SHA-256.
3. Generate or verify fixtures; write `fixtures.tsv`.
4. Run V2-G0 through V2-G16 in order; stop on a failed gate.
5. Write `gates.tsv`, `perf.tsv`, `floor.tsv`, and `GATE_TRANSCRIPT.txt`.
6. Render `ACCEPTANCE.md` from the TSVs, not by hand.
7. Print `RESULT: PASS` only if every gate row is `PASS` and every evidence file exists.

A failed gate leaves the previous `ACCEPTANCE.md` untouched and writes `FAIL` rows; there is no partial acceptance.

### 12.7 Independent decoder

`indep_decode_v2.py` MUST:

- share no code with the C++ engine;
- parse the header, atoms, nodes, index, and trailer;
- validate CRCs and canonical integers;
- evaluate all node kinds;
- reject malformed containers;
- reproduce F00–F08 byte-exactly.

A difference between the two decoders is a gate failure, not a warning.

### 12.8 Fuzzer

`fuzz_v2.py`:

- mutates valid containers (bit flips, truncation, field swaps, length corruption);
- uses small valid containers plus header/index mutations of large containers, so 100,000 mutants finish in bounded time;
- feeds each mutant to `mapr verify` and `mapr decode`;
- counts accepted invalid containers, crashes, timeouts, and valid decodes;
- target: `accepted_invalid = 0`, `crashes = 0`, `timeouts = 0` over 100,000 mutants.

### 12.9 Determinism

- Encode the same fixture twice at the same effort.
- Compare raw wire bytes with `cmp`.
- Repeat with `--threads 1` and `--threads 4`.
- All four outputs MUST be byte-identical.

### 12.10 Floor audit

`mapr floor` runs the best available generic exact compressors and records:

```
input_bytes, xz_bytes, zstd_bytes, brotli_bytes, bzip2_bytes,
best_bytes, best_tool, marp_wire_bytes, atom_residual_bytes,
ref_coder_bytes, note
```

The note states whether the input is structurally expressible or information-limited. This is the honesty gate: a size claim is accepted only if it is consistent with this row.

### 12.11 Environment record

`GATE_TRANSCRIPT.txt` begins with:

```
date_utc, host, kernel, nproc, mem_total_kib, disk, compiler, cmake/make,
engine_sha256, test_sha256, fixture_manifest_sha256
```

### 12.12 Report rendering

`ACCEPTANCE.md` contains:

- generated date;
- gate table with measured values and verdicts;
- performance table;
- floor table for F10–F12, F15;
- fixture identity table;
- environment;
- a list of every log file with its SHA-256.

No prose number is typed by hand. Prose may explain; it may not introduce a new measurement.

---

## 13. Performance targets

These are **TARGETS**, not measurements.

| metric | target | note |
|---|---|---|
| structured wire | <= 1 MiB for 1 GiB, <= 8 MiB for 4 GiB | F02–F04 |
| random ratio | <= 1.005× | F10 |
| mixed real vs best generic | <= 1.02× | F11/F15 |
| already-coded vs best generic | <= 1.02× | F12 |
| encode structured | >= 25 MiB/s | tmpfs, effort 5 |
| encode RAW | >= 100 MiB/s | tmpfs |
| decode | >= 100 MiB/s | tmpfs |
| encode RSS (4 GiB) | <= 256 MiB | `/usr/bin/time -v` |
| decode RSS | <= 128 MiB | `/usr/bin/time -v` |
| atom overhead | <= 64 B descriptor per atom + payload | wire |
| index overhead | <= 0.1 % of container | when present |

Throughput is reported both as CPU throughput (tmpfs) and wall-clock on the host disk. I/O-bound wall time is not a gate failure; the CPU throughput and exactness gates are.

---

## 14. Security and robustness

- Every region is length-delimited and CRC-checked.
- The decoder is total: valid input decodes uniquely; invalid input is rejected.
- No recursion without a bound; DAG depth is bounded.
- No allocation based on unvalidated counts.
- No integer overflow: all lengths and offsets are big integers or checked u64.
- Reject unknown critical flags, kinds, morphisms, predictors, and versions.
- Reject non-canonical integers and non-canonical node orderings.
- The fuzzer runs on every change to the decoder.
- The encoder writes atomically and verifies its own output before rename.
- No external references, network access, or ambient files are used by encode/decode.

---

## 15. Compatibility and migration

- v1.0.1 and v1.1 `.mapr` files remain readable by the v2 decoder (V2-G13).
- v2 is a new major version; v1 decoders reject it.
- The v2 writer always emits v2.
- The v1 writer is retired after v2 passes V2-G1, V2-G12, and V2-G13.
- Legacy tests remain in the harness; they are not deleted.
- No silent fallback from v2 to v1. A failed v2 encode exits non-zero and leaves no output.

---

## 16. Defect and risk register

| id | risk | required mitigation |
|---|---|---|
| V2-D1 | grammar induction memory blow-up | bounded phrase budget; stop, never corrupt |
| V2-D2 | false-positive term | exact expansion before acceptance |
| V2-D3 | non-deterministic output | fixed tie-breaking; thread-independent merge |
| V2-D4 | big-int overflow | arbitrary-precision everywhere; checked conversions |
| V2-D5 | atom explosion | atom budget; MDL selector may choose larger structure |
| V2-D6 | predictor drift | closed catalogue; exact residual reconstruction |
| V2-D7 | range decode incorrect | V2-G8; independent decoder cross-check |
| V2-D8 | legacy regression | V2-G13 |
| V2-D9 | size overclaim | V2-G7 floor audit |
| V2-D10 | plugin dependency | all gates run with plugins disabled |
| V2-D11 | canonical drift | V2-G16 idempotence and re-encode identity |
| V2-D12 | decoder resource exhaustion | hard limits; reject, never partial decode |

---

## 17. Out of scope

- Lossy representation.
- External references, network fetches, or ambient artifact lookup.
- File-type-specific semantics in the core.
- Tensor, zip, PDF, or video parsing as a required path.
- A `.nez` container implementation (NEZITOR owns it).
- A compression claim below the measured floor.
- Application-level metadata, thumbnails, or previews.

---

## 18. Glossary

| term | meaning |
|---|---|
| **atom** | opaque byte payload that no exact term explains |
| **canonical** | unique representative under §3.8 |
| **denotation** | the byte string a term denotes |
| **effort** | encoder search budget, 0–9 |
| **floor** | best size achieved by the best-of-ensemble exact compressors on the same bytes |
| **IR** | semantic term representation handed to MAU |
| **K(x)** | Kolmogorov complexity of byte string `x` |
| **MDL** | minimum description length; the selector objective |
| **morph** | exact byte/bit transformation |
| **node** | one term constructor with exact length |
| **residual** | bytes left after predictors/transforms, stored as atoms |
| **term** | a DAG node denoting a byte string |
| **wire** | the canonical `.mapr` v2 byte format |

---

## 19. Appendix A — Reference cost model

The selector uses an estimate, never a claim:

```
wire_bits(T) = 8 * canonical_wire_bytes(T)
atom_bits(T) = sum over atoms:
    if class == OPAQUE:      8 * length
    if class == SPARSE:      min(8*length, 1 + ceil(length * H0))
    if class == LOW_ENTROPY: ceil(length * H0)
    if class == TEXTUAL:     ceil(length * H1)
    if class == NUMERIC:     ceil(length * H_plane)
    if class == CODE_LIKE:   ceil(length * H2)
    if class == TOKEN:       ceil(length * H_token)
    otherwise:               8 * length
cost(T) = wire_bits(T) + atom_bits(T) + model_bits
```

`H0`, `H1`, `H2`, `H_plane`, `H_token` are measured on the candidate atom. `model_bits` is a fixed overhead per class. The estimate is used only to choose among exact terms. The harness reports the actual wire size and the actual NEZITOR size separately.

---

## 20. Appendix B — Reference harness flow

```
run_all.sh
  ├─ make -C engine -j
  ├─ ./engine/bin/mapr --version
  ├─ python3 harness/v2/gen_fixtures.py --out "$SCRATCH" --manifest fixtures.tsv
  ├─ for gate in V2-G0 .. V2-G16:
  │     run_gate "$gate" | tee "logs/${gate}.log"
  │     append_row gates.tsv
  │     on failure: render FAIL, exit 1
  ├─ python3 harness/v2/render_acceptance.py \
  │     gates.tsv perf.tsv floor.tsv fixtures.tsv > ACCEPTANCE.md
  ├─ sha256sum logs/* > logs/SHA256SUMS
  └─ print RESULT: PASS
```

The harness is deliberately boring: one row per measurement, one log per gate, one generated report. Nothing is accepted on inspection alone.

---

*End of MARP v2 specification.*
