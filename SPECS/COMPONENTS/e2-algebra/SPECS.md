# E2 — ALGEBRA — Component Specification

| Field | Value |
|---|---|
| **Document ID** | MARP2-E2 |
| **Version** | 1.0 |
| **Status** | Normative for E2. Derived from `SPECS-V2.md`. |
| **Parent** | `MARP/SPECS/SPECS-V2.md` |
| **Decomposition** | `MARP/SPECS/COMPONENTS-V2.md` |
| **Depends on** | E1 (frozen). E2 MUST NOT link E3–E7. |
| **Language** | C++20. No third-party libraries. No Python. |
| **Gate** | `E2-G` |

---

## 0. Reading rules

1. This document is normative for E2 only. The parent governs the format; on conflict the parent wins and this document is amended.
2. `MUST` / `MUST NOT` are normative.
3. Every obligation in §7 is measured by the gate in §12. Nothing is accepted on inspection.
4. E2 is the only component allowed to say what a term **means**. Every other component consumes that meaning.
5. The gate is the only exit from this component. A green unit test is not an exit.

---

## 1. Purpose

E2 turns the term grammar into a closed, executable algebra.

It answers four questions and no others:

1. **Is this term well formed?** (C03 `TERM`)
2. **What bytes does it denote, and what is its exact length?** (C03, C05 `EVAL`)
3. **What is its unique canonical representative?** (C04 `CANON`)
4. **What is the identity of a subterm?** (C06 `DAG`)

It does not know how terms are written to bytes, discovered, selected, or translated. Those are E3, E4–E6, and E7.

---

## 2. Scope

### 2.1 In scope

- The `Ir` type of parent §4 and its well-formedness predicate.
- Denotation `⟦·⟧` for all twelve node kinds, including the closed morphism and predictor catalogues and the LFSR.
- Length validation: stored node lengths MUST equal the §3.7 length recomputed from children.
- Canonicalisation to a fixed point under parent §3.8 rules 1–13.
- Full streaming evaluation and indexed range evaluation.
- Deterministic node and atom identity, interning, and id assignment.

### 2.2 Out of scope

| Excluded | Owner |
|---|---|
| Arbitrary-precision arithmetic and digests | E1 |
| Wire encoding, decoding, and integer codecs | E3 |
| Discovery, probing, candidate generation | E4–E5 |
| Selection, classification, planning, plugins | E6 |
| MAU program, CLI, certificate | E7 |
| Hash-consed **persistence** across runs | not required |
| Proving global confluence of the rewrite system | see §7, O4.2 |
| Constant-time predictor range access | impossible without checkpoints; see §5.5 |

E2 MUST NOT read or write files, spawn processes, or inspect the environment.

---

## 3. Sub-components

| id | role | deliverable |
|---|---|---|
| C03 | `TERM` | `Ir`, well-formedness, `⟦·⟧`, morph/predictor/LFSR semantics |
| C04 | `CANON` | `canon`, `is_canonical`, `canonical_key` |
| C05 | `EVAL` | `eval_stream`, `eval_range`, `TermCursor`, LFSR jump-ahead |
| C06 | `DAG` | `Dag` builder, interning, post-order ids |

A sub-component is a responsibility, not a file. E2 MAY be one translation unit. The authority boundaries in §10 MUST NOT blur.

---

## 4. Formal model

### 4.1 Sorts and types

```
Σ            {0, 1, …, 255}
Σ*           finite byte strings
ℕ            non-negative arbitrary-precision integers        (E1)
Term         the DAG of parent §3.2
NodeId       u32, 0 <= NodeId < node_count
AtomId       u32, 0 <= AtomId < atom_count
```

### 4.2 IR

```cpp
namespace marp::v2 {

struct Atom {
    u8  klass;                     // advisory class, parent §6.9; 0 = unclassified
    u8  flags;                     // MUST be 0
    BigInt length;                 // payload byte length
    std::array<u8,32> sha256;      // SHA-256 of payload
    std::span<const u8> payload;   // view; storage outlives the Ir
};

struct Node {
    Kind kind;                     // parent §3.2
    u8   flags;                    // MUST be 0
    std::vector<u32> args;         // absolute ids, strictly < own index
    BigInt a, b;                   // q/r, start/len, n
    u8  morph, morph_k;
    u64 lfsr_conn, lfsr_init;
    u8  affine_start, affine_step;
    u8  predictor_id;
    u32 predictor_param;
    BigInt length;                 // MUST equal §3.7
};

struct Ir {
    std::vector<Atom> atoms;
    std::vector<Node> nodes;
    u32 root;
    BigInt total_length;           // MUST equal nodes[root].length
};

} // namespace marp::v2
```

`Kind` values are exactly parent §5.5: `Empty=0, Atom=1, Zero=2, Concat=3, Repeat=4, Slice=5, Morph=6, Xor=7, Interleave=8, Lfsr=9, Affine=10, Predictor=11`.

Atom ids are vector indices. Node ids are vector indices. There is no separate id field, and no id may be renumbered without re-canonicalising.

### 4.3 Well-formedness

`WF(ir)` is the conjunction of:

| id | condition |
|---|---|
| W1 | `nodes.size() <= 2^24`, `atoms.size() <= 2^24` |
| W2 | `root < nodes.size()`; every node is reachable from `root`; every atom is referenced by a reachable `Atom` node |
| W3 | for every node `i`, every `arg < i` |
| W4 | every `flags` byte is `0` |
| W5 | `total_length == nodes[root].length` |
| W6 | every `nodes[i].length` equals the value computed by §4.4 from children |
| W7 | DAG depth `<= 2^16`, computed as `1 + max(child depth)` with `Empty` depth 0 |
| W8 | kind-specific constraints in §4.5 |

W2 forbids unused nodes and unused atoms. It does not require first-use ordering; that is canonical shape (§4.7).

### 4.4 Length

The length of node `i` is computed bottom-up:

```
len(Empty)            = 0
len(Atom(a))          = atoms[a].length
len(Zero(n))          = n
len(Concat(c1..ck))   = Σ len(ci)
len(Repeat(c,q,r))    = q*len(c) + r
len(Slice(c,s,l))     = l
len(Morph(c))         = len(c)
len(Xor(a,b))         = len(a)
len(Interleave(c…,s)) = k*len(c1)
len(Lfsr(_,_,n))      = n
len(Affine(_,_,n))    = n
len(Predictor(_,_,r)) = len(r)
```

All arithmetic is E1 `BigInt` arithmetic. No `u64` intermediate is permitted.

### 4.5 Kind-specific constraints

| kind | argc | constraint |
|---|---|---|
| `Empty` | 0 | — |
| `Atom` | 0 | `a < atoms.size()`; `atoms[a].length > 0` |
| `Zero` | 0 | — |
| `Concat` | `>= 2` | — |
| `Repeat` | 1 | if `q = 0` then `r = 0`; if `q >= 1` then `0 <= r < len(child)` |
| `Slice` | 1 | `0 <= start <= len(child)`, `start + len <= len(child)` |
| `Morph` | 1 | see §4.6 |
| `Xor` | 2 | `len(a) = len(b)` |
| `Interleave` | `>= 1` | all children have length `L`; `stride >= 1`; `L mod stride = 0`; `length = k*L` |
| `Lfsr` | 0 | `conn != 0` |
| `Affine` | 0 | — |
| `Predictor` | 1 | `pid <= 4`; `pid >= 3` requires `param >= 1`; `len(residual) = n` |

A zero-length `Atom` is invalid. An empty input has its own term: `Empty`, not `Atom(0)`.

### 4.6 Morphisms

Morph ids are exactly parent §3.4. Applicability:

| id | name | `k` | length constraint | local? |
|---|---|---|---|---|
| 1 | `BIT_REVERSE8` | 0 | — | yes |
| 2 | `INVERT8` | 0 | — | yes |
| 3 | `SWAP16` | 0 | `len mod 2 = 0` | block-local, 2 |
| 4 | `SWAP32` | 0 | `len mod 4 = 0` | block-local, 4 |
| 5 | `SWAP64` | 0 | `len mod 8 = 0` | block-local, 8 |
| 6 | `ROTL8` | 1..7 | — | yes |
| 7 | `ROTR8` | 1..7 | — | yes |
| 8 | `REVERSE_BYTES` | 0 | — | mirrored range |
| 9 | `REVERSE_BITS` | 0 | — | mirrored range + bit reverse |

`REVERSE_BITS` is exactly `REVERSE_BYTES ∘ BIT_REVERSE8`: output byte `j` = `bit_reverse8(input[n-1-j])`. This identity is normative and is used for range evaluation.

Any other morph id, or any wrong `k`, is `Invalid`. A length constraint violation is `Invalid`; the decoder MUST NOT pad or truncate.

### 4.7 Canonical shape

An `Ir` is **canonical** iff `WF(ir)` holds and no §3.8 rewrite applies:

| rule | canonicality condition |
|---|---|
| 1 | no `Concat` has a `Concat` child |
| 2 | no `Empty` node; every `Concat` has `argc >= 2` |
| 3 | every atom has `length <= ATOM_MAX`; no adjacent `Atom` children in a `Concat` have `len(a)+len(b) <= ATOM_MAX` |
| 4 | no adjacent `Zero` children in a `Concat` |
| 5 | every `Repeat` has `q >= 2` and `0 <= r < len(child)` |
| 6 | no `Slice` child is a `Slice`; no `Slice` has `len = 0`; no `Slice` has `start = 0` and `len = len(child)` |
| 7 | no identity morph; no `Morph` child is a `Morph`; no `ROTL8`/`ROTR8` with `k` that composes to identity |
| 8 | no `Xor(x,x)`; no `Xor` with a `Zero` operand (length-compatible); operands ordered by `canonical_key` ascending |
| 9 | every `Interleave` has `argc >= 2`; child order is the source order |
| 10 | no `Affine` with `step = 0` |
| 11 | no `Repeat` whose child is `Zero`; no `Slice` whose child is `Zero` |
| 12 | structurally identical subterms are the same node |
| 13 | no unused nodes or atoms; ids are post-order first-use; `root = nodes.size()-1`; atom ids are first-use order; no two atom records have the same payload |

`ATOM_MAX = 1 MiB = 1 048 576` bytes. It is a format constant, not an effort parameter.

Rules 5 and 6 interact, and the interaction is normative:

- `Repeat(c,0,0)` → `Empty`; `Repeat(c,0,r)` for `r > 0` → `Slice(c,0,r)`.
- `Repeat(c,1,0)` → `c`; `Repeat(c,1,r)` for `r > 0` → `Concat(c, Slice(c,0,r))`, exactly as parent §3.8 rule 5 states.
- `Repeat(c,q,r)` for `q >= 2` → `Repeat(c,q,r)` after folding any excess `r >= len(c)` into `q`.

So the only canonical `Repeat` has `q >= 2` and `0 <= r < len(c)`. A `Slice(c,0,r)` with `0 < r < len(c)` **is** canonical, because it can only arise from `Repeat` normalisation and folding it further would cycle. `Slice` folding runs after `Repeat` normalisation, in the fixed strategy of §5.2.

This detail is normative because it determines whether `canon` terminates. Note that parent rule 8's operand order is written `(canonical_bytes, length, child_id)`; E2 realises it by `canonical_key`, which is a total order over the subterm and does not depend on ids or on E3's wire bytes. E2 MUST NOT serialise wire to order operands.

### 4.8 Canonical traversal and ids

`canon` emits nodes in **post-order first use**:

```
visit(node):
    for child in args order:
        visit(child)
    if structurally equal node already emitted: return its id
    else: append node; return new id
```

Atoms are appended on first encounter, in the same traversal. Consequences:

- every child id is strictly smaller than its parent;
- `root = nodes.size()-1`;
- identical subterms share one node;
- no unused records;
- output depends only on the canonical term, never on hash-map order.

Atom dedup key is `(length, sha256)`. Structurally equal atoms with equal payload MUST be one record. Byte-identical payloads necessarily have equal `(length, sha256)`; a SHA-256 collision is treated as `Mismatch` by E3's full evaluation, never as permission to merge.

### 4.9 Denotation

`⟦·⟧` is parent §3.3 exactly:

| kind | denotation |
|---|---|
| `Empty` | `ε` |
| `Atom(a)` | `atoms[a].payload` |
| `Zero(n)` | `00` repeated `n` |
| `Concat` | concatenation in arg order |
| `Repeat(c,q,r)` | `⟦c⟧^q · prefix(⟦c⟧, r)` |
| `Slice(c,s,l)` | `⟦c⟧[s, s+l)` |
| `Morph(c,m,k)` | `m(⟦c⟧)` |
| `Xor(a,b)` | bytewise XOR |
| `Interleave(c1..ck,s)` | for each block of `s` bytes, emit the block from `c1`, then `c2`, … |
| `Lfsr(conn,init,n)` | §4.10 |
| `Affine(start,step,n)` | `out[i] = (start + i·step) mod 256` |
| `Predictor(pid,param,r)` | §4.11 applied to `⟦r⟧` |

`Interleave` is defined only when every child has the same length `L` and `L` is a multiple of `stride`. The output has `L/stride` blocks.

### 4.10 LFSR

Exactly parent §3.5:

```
state = init
repeat n*8 times:
    bit = parity(state & conn)
    state = (state >> 1) | (bit << 63)
    emit bit
pack emitted bits MSB-first into bytes
```

`conn != 0`. Bit order is part of the format: the first emitted bit is the most significant bit of output byte 0.

**Jump-ahead.** The state transition is GF(2)-linear. `read_range` for an LFSR at byte offset `b` computes `state_b = T^(8b)·init` by 64×64 GF(2) matrix exponentiation in `O(log b)`, then emits from that state. It MUST NOT advance bit by bit from zero.

### 4.11 Predictors

Exactly parent §3.6. With `r = ⟦residual⟧`, `n = len(r)`:

| pid | name | reconstruction |
|---|---|---|
| 0 | `DELTA8` | `out[0]=r[0]`; `out[i]=(out[i-1]+r[i]) mod 256` |
| 1 | `XOR8` | `out[0]=r[0]`; `out[i]=out[i-1] xor r[i]` |
| 2 | `LINEAR2` | `out[0]=r[0]`, `out[1]=r[1]`; `out[i]=(2·out[i-1]-out[i-2]) mod 256` |
| 3 | `STRIDE_XOR` | `s=param`; `out[i]=r[i]` for `i<s`; else `out[i]=out[i-s] xor r[i]` |
| 4 | `STRIDE_DELTA` | `s=param`; `out[i]=r[i]` for `i<s`; else `out[i]=(out[i-s]+r[i]) mod 256` |

For `n = 0` the output is empty. For pid 2 with `n = 1`, only `out[0]` is defined.

---

## 5. Operations

### 5.1 Validation

| operation | precondition | postcondition |
|---|---|---|
| `check_well_formed(ir)` | — | `Ok` iff `WF(ir)`; else `Invalid` with the first failing id |
| `check_canonical(ir)` | — | `Ok` iff §4.7; else `Invalid` |

Validation is deterministic and reports the **first** failure in a fixed order: counts, flags, root, reachability, args, lengths, depth, kind constraints, canonical shape.

### 5.2 Canonicalisation

`canon(ir)` requires `WF(ir)` and returns a canonical `Ir` with the same denotation.

Rules are applied in a fixed strategy until no rule fires:

1. flatten nested `Concat`;
2. remove `Empty` children, collapse unary `Concat`;
3. split atoms above `ATOM_MAX`, merge adjacent atoms whose sum is `<= ATOM_MAX`;
4. merge adjacent `Zero`;
5. normalise `Repeat`: `q=0,r=0` → `Empty`; `q=0,r>0` → `Slice(child,0,r)`; `q=1,r=0` → child; `q=1,r>0` → `Concat(child, Slice(child,0,r))`; fold `r >= len(child)` into `q`;
6. fold `Slice` (nested, full-cover, zero-length);
7. fold `Morph` (identity, identical involutions, adjacent rotations);
8. fold `Xor` (`x xor x`, zero operands, operand order);
9. fold single-child `Interleave`;
10. fold `Affine` with `step = 0`;
11. fold `Repeat(Zero)` and `Slice(Zero)`;
12. hash-cons structurally identical subterms;
13. prune unused nodes and atoms, reassign ids in post-order first use.

The strategy is fixed. Where two rules overlap, the lower-numbered rule is applied first. This makes `canon` a deterministic function even without a confluence proof; see O4.2.

Rules 3 and 5 may interact. The fixed point is: no atom above `ATOM_MAX`, no mergeable adjacent atoms, no non-normal `Repeat`. A term that reaches that state is canonical.

### 5.3 Evaluation

| operation | precondition | postcondition |
|---|---|---|
| `eval_stream(ir, sink)` | `check_well_formed(ir)` | writes `⟦root⟧` to `sink` |
| `TermCursor(ir, node)` | `WF(ir)` | cursor over `⟦node⟧` |
| `cursor.read(buf)` | — | writes up to `buf.size()` bytes; returns count; `0` only at end |
| `cursor.remaining()` | — | exact bytes left |
| `read_range(ir, node, start, out)` | `WF(ir)`; `start + out.size() <= ℓ(node)` | writes `⟦node⟧[start, start+out.size())` |
| `eval_range(ir, start, len, sink)` | `WF(ir)`; `start + len <= ℓ(root)` | writes that range |

Full evaluation uses a fixed block buffer, an explicit stack, and incremental SHA-256. Recursion depth is bounded by W7.

### 5.4 Range evaluation

`read_range` recurses into children with translated ranges:

| kind | translation |
|---|---|
| `Atom` | slice payload |
| `Zero` | zero fill |
| `Concat` | locate intersecting children by cumulative length |
| `Repeat` | modulo child length across `q` copies |
| `Slice` | add `start` to child range |
| `Morph` local | same range |
| `Morph` block (3–5) | expand the requested range outward to the morph block size `b ∈ {2,4,8}`, read the expanded child range, apply the block morph to whole blocks, then return the requested slice |
| `Morph` mirrored (8–9) | mirrored child range; 9 also bit-reverses bytes |
| `Xor` | read both children, XOR |
| `Interleave` | per-child block ranges |
| `Lfsr` | jump to `start`, emit `len` |
| `Affine` | direct formula |
| `Predictor` | sequential from 0; see §5.5 |

A range call MUST NOT allocate memory proportional to `ℓ(node)` or to `start`.

### 5.5 Predictor ranges

Predictor output at `i` depends on all previous output. `read_range` for a `Predictor` therefore:

1. evaluates the residual from 0 to `start`, discarding output, to restore state; then
2. emits the requested range.

The discard pass reads only the residual prefix; it does not materialise the output. If `start > 2^28`, the operation MAY return `Limit` instead of spending unbounded time, unless the caller supplies a checkpoint. A checkpoint is `(offset, out[i-1], out[i-2])` for the predictor kind, and is derived from a prior full evaluation. No checkpoint is required by any gate.

This is an explicit performance limitation, not a correctness exception: when it returns `Ok`, the bytes are exact.

### 5.6 DAG construction

```cpp
class Dag {
public:
    Result<u32> add_atom(std::span<const u8>, u8 klass);
    Result<u32> add_node(Node);          // args must already be ids in this Dag
    Result<Ir> finish(u32 root) &&;      // canonical post-order ids
};
```

`finish` performs a post-order traversal from `root`, interns equal subterms and equal atom payloads, and emits the canonical `Ir`. It MUST NOT preserve caller construction order in the output.

### 5.7 Canonical key

`canonical_key(ir, node)` returns a deterministic byte string that is equal for structurally equal subterms and distinct otherwise. It is used only for ordering `Xor` operands and for diagnostics. It MUST be independent of node ids outside the subterm. A simple pre-order encoding of `(kind, params, canonical_key(child)…)` is sufficient and is normative only in its equality and ordering behaviour, not its exact bytes.

---

## 6. Invariants

| id | invariant |
|---|---|
| E2-I1 | `⟦·⟧` is total on `WF` terms and undefined (rejected) otherwise. |
| E2-I2 | `ℓ(t) = |⟦t⟧|` for every `WF` term. |
| E2-I3 | Stored lengths are never trusted; `check_well_formed` recomputes every one. |
| E2-I4 | `canon` preserves denotation and is idempotent. |
| E2-I5 | `canon` does not depend on `--effort`, thread count, or time. |
| E2-I6 | `Interleave` child order is semantic and is never sorted. |
| E2-I7 | No id assignment depends on pointer values, hash-map iteration, or construction order. |
| E2-I8 | `read_range(t,s,l) = ⟦t⟧[s,s+l)` whenever it returns `Ok`. |
| E2-I9 | No allocation proportional to declared length during range decode. |
| E2-I10 | Unknown kinds, morphs, predictors, or wrong `k` are rejected, never approximated. |
| E2-I11 | Atom `klass` never affects denotation and is never used for control flow. |
| E2-I12 | Evaluation and canonicalisation are reentrant; no mutable global state. |

---

## 7. Proof obligations

These are measured by §12, not asserted here.

| id | obligation | measurement |
|---|---|---|
| O3.1 | `ℓ(t) = |⟦t⟧|` on every corpus term | independent evaluator, exact length |
| O3.2 | every morph matches its definition; every declared involution is involutive; rotations compose | pinned KATs per morph and `k`; round-trip |
| O3.3 | every predictor reconstructs its input from its residual exactly | pinned KATs per pid, including `param` edges |
| O3.4 | LFSR matches pinned vectors and jump-ahead matches independent GF(2) exponentiation | KATs + offsets `1, 2^20, 2^40, 2^50` |
| O3.5 | every malformed term is rejected with `Invalid` | `T-BAD` corpus, one case per constraint |
| O3.6 | every node kind and every morph/predictor id is exercised | coverage counters, all non-zero |
| O4.1 | canonicalisation terminates on the corpus within `64·(nodes+1)` rewrites | instrumented rewrite counter |
| O4.2 | critical pairs do not diverge | generated `T-CRIT` corpus; both orders compared |
| O4.3 | `⟦canon(t)⟧ = ⟦t⟧` | independent evaluator |
| O4.4 | `canon(canon(t)) = canon(t)` and `is_canonical(canon(t))` | structural equality |
| O4.5 | every rewrite rule 1–13 fires at least once across the corpus | instrumented rule counters |
| O5.1 | streaming equals independent full materialisation | exact bytes |
| O5.2 | `read_range` equals the independent slice, including offsets above `2^32` | sampled ranges on virtual terms |
| O5.3 | range decode allocates no memory proportional to total length | allocator counter / RSS bound |
| O6.1 | construction order does not affect ids | shuffled `Dag` builds |
| O6.2 | `root = nodes.size()-1`; no unused records | canonical shape |
| O6.3 | no two atom records share a payload | canonical shape |
| O6.4 | `check_canonical` rejects every non-canonical corpus term | `T-NONCANON` corpus |

O4.2 does not claim a global confluence proof. It claims that the generated finite critical-pair set does not diverge. Global uniqueness is claimed only for terms in the corpus and for terms reachable by the fixed strategy; the parent's uniqueness claim is inherited, not re-proved here.

---

## 8. C++ interface

```cpp
namespace marp::v2 {

enum class Kind : u8 { Empty=0, Atom=1, Zero=2, Concat=3, Repeat=4, Slice=5,
                       Morph=6, Xor=7, Interleave=8, Lfsr=9, Affine=10, Predictor=11 };

struct Sink { virtual ~Sink() = default;
              virtual Result<void> write(std::span<const u8>) = 0; };

Result<void> check_well_formed(const Ir&);
Result<void> check_canonical(const Ir&);

Ir canon(const Ir&);
bool is_canonical(const Ir&);
std::string canonical_key(const Ir&, u32 node);

class TermCursor {
public:
    TermCursor(const Ir&, u32 node);
    Result<std::size_t> read(std::span<u8> out);
    BigInt remaining() const;
};

Result<std::size_t> read_range(const Ir&, u32 node, const BigInt& start,
                               std::span<u8> out);
Result<void> eval_stream(const Ir&, Sink&);
Result<void> eval_range(const Ir&, const BigInt& start, const BigInt& len, Sink&);

u8 apply_morph_byte(u8 morph, u8 k, u8 in);
u8 apply_predictor_step(u8 pid, u32 param, u8 residual, u8 prev1, u8 prev2);

class Dag {
public:
    Result<u32> add_atom(std::span<const u8>, u8 klass);
    Result<u32> add_node(Node);
    Result<Ir> finish(u32 root) &&;
    u32 node_count() const;
    u32 atom_count() const;
};

} // namespace marp::v2
```

`Sink` is the E2 output boundary; E3 and E7 supply concrete sinks. `TermCursor` is a convenience wrapper over `eval_range` with a monotone offset.

---

## 9. Error taxonomy

| condition | code | detail |
|---|---|---|
| any `WF` violation | `Invalid` | first failure |
| non-canonical input to `canon` | `Invalid` | `WF` required |
| morph `k` wrong | `Invalid` | §4.6 |
| morph length not a multiple | `Invalid` | §4.6 |
| `Lfsr` with `conn = 0` | `Invalid` | §4.10 |
| unknown predictor id | `Invalid` | §4.11 |
| slice out of bounds | `Invalid` | §4.5 |
| `Xor`/`Interleave` length mismatch | `Invalid` | §4.5 |
| range past declared length | `Invalid` | §5.3 |
| depth `> 2^16` | `Limit` | W7 |
| output `> 2^63` | `Limit` | §8.3 of parent |
| rewrite budget exhausted | `Limit` | O4.1 |
| predictor range past checkpoint policy | `Limit` | §5.5 |

No operation panics, throws past `Result`, or terminates the process.

---

## 10. Authority boundary

**E2 may:**
- define, validate, canonicalise, and evaluate terms;
- compute lengths from structure;
- assign ids inside a `Dag`;
- be called by E3, E5, E6, E7, and the harness oracle.

**E2 may not:**
- encode or decode wire bytes;
- choose which term represents an input;
- discover structure;
- classify atoms (E6 assigns `klass`);
- read files, inspect paths, or branch on media type;
- call E3–E7.

Any E2 call into E3–E7 is an architecture violation.

---

## 11. Determinism and resources

- `canon` is a pure function of the canonical term. It does not consult effort, threads, time, locale, addresses, or hash-map order.
- Evaluation is pure. `eval_stream` writes bytes in one fixed order.
- Atom id and node id assignment are serialised in post-order; parallel discovery may construct fragments, but the final `Dag::finish` is serial.
- Full evaluation uses `O(depth + block)` memory. Range evaluation uses `O(depth + block)`, except the predictor prefix pass and mirrored morphs, which use `O(range)` and `O(depth)` respectively.
- Depth is bounded at `2^16`; no unbounded recursion.
- No floating point.
- `canon` uses `O(nodes)` memory plus intern tables. Intern keys never leak into output order.

---

## 12. Success gate E2-G

### 12.1 Preconditions

| requirement | state |
|---|---|
| `E0-G` PASS with evidence | required |
| `E1-G` PASS with evidence, E1 surface frozen | required |
| Independent denotation oracle (H3) available and not linked to E2 | required |
| No E3–E7 code linked into E2 | required |

If any precondition is unmet, E2-G is `BLOCKED`, never `PASS`.

### 12.2 The condition

> **For every term in the E2 corpus, an independent denotation oracle and the engine agree on the exact bytes; every stored length equals the recomputed length and the denotation length; canonicalisation preserves denotation, is idempotent, and yields a canonical term; every sampled range equals the corresponding oracle slice, including offsets above `2^32`; every malformed term is rejected; every LFSR jump-ahead matches independent GF(2) exponentiation; and every node kind, morph id, predictor id, and rewrite rule is exercised. One mismatch fails the gate.**

### 12.3 Corpus

All corpora are seed-generated except the pinned KATs; seeds and SHA-256 are recorded in `corpus.tsv`.

| id | contents | count |
|---|---|---|
| `T-KAT` | pinned terms covering every kind, every morph id with valid `k`, every predictor id with `param` edges, LFSR pinned vectors, empty term, one-byte atom, atom exactly `ATOM_MAX`, `Interleave` strides 1/2/3/7 | 128 |
| `T-GEN` | seeded well-formed terms, depth 1–8, expansion `<= 4 MiB` each, every kind at least 100 times | 5 000 |
| `T-BIG` | virtual terms: `Zero(2^40)`, `Affine(n=2^40)`, `Lfsr(n=2^40)`, `Repeat` with huge `q`, `Slice` of those; no materialisation | 64 |
| `T-BAD` | one term per violation: each `argc`, each `k`, each length constraint, `conn=0`, unknown pid, child id `>=` parent, depth `2^16+1`, `r >= len(child)`, unused node, unused atom, zero-length atom, stored-length mismatch | 64 |
| `T-NONCANON` | terms with each rewrite redex present, including adjacent atoms at the merge boundary, nested slices, morph pairs, `Xor` with `Zero`, single-child `Interleave`, `Affine` step 0, `Repeat(Zero)` | 200 |
| `T-CRIT` | term pairs where two rules overlap, generated by enumerating local patterns depth `<= 4` | 1 000 |
| `T-RANGE` | for each `T-KAT`/`T-GEN` term, ranges `(0,0)`, `(0,1)`, `(ℓ-1,1)`, `(ℓ/2,min(4096,ℓ))`, `(0,ℓ)`, plus 8 seeded random ranges; for `T-BIG`, starts above `2^32` | 13 per term |
| `M-KAT` | pinned input/output bytes for all morphs and predictors, including involution pairs and rotation composition | 96 |
| `L-KAT` | pinned LFSR byte vectors for 8 `(conn,init)` pairs and lengths 1, 7, 8, 9, 64, 65 | 48 |

`T-BIG` total lengths exceed `2^40`; the corpus never materialises them.

### 12.4 Procedure

1. Build E2, the oracle, and the gate runner with `-O2 -Wall -Wextra -Werror`.
2. Generate the corpus; write `corpus.tsv` with id, kind, length, and SHA-256 of its canonical description.
3. For every `T-BAD`: require `check_well_formed` returns `Invalid` and identifies the expected constraint. Any `Ok` fails.
4. For every `T-KAT`, `T-GEN`, and `T-CANON = canon(T-KAT ∪ T-GEN)`:
   - `check_well_formed(canon(t))` must be `Ok`;
   - `is_canonical(canon(t))` must be true;
   - `canon(canon(t))` must be structurally equal to `canon(t)`;
   - `⟦canon(t)⟧` from the engine must equal `⟦t⟧` from the independent oracle;
   - `ℓ(t)` from E1 recomputation must equal `|⟦t⟧|`;
   - every stored `length` must equal the recomputed length.
4b. For every `T-BIG`: require well-formedness, canonicality, idempotence, stored-length equality, and `ℓ(t)` equal to the oracle's structurally computed exact length. Its denotation is never materialised; it is checked only by the sampled ranges of step 9.
5. For every `T-NONCANON`: `is_canonical(t)` must be false; `canon(t)` must be canonical; `⟦canon(t)⟧ = ⟦t⟧`; `canon(canon(t)) = canon(t)`.
6. For every `T-CRIT` pair: apply each applicable rule first in both orders, canonicalise fully, and require equal `canonical_key` of the results. A divergence fails O4.2.
7. For every `M-KAT`: compare exact output bytes for every morph and predictor; verify every declared involution `m(m(x)) = x`; verify rotations compose modulo 8; verify invalid lengths/`k` are rejected.
8. For every `L-KAT`: compare exact bytes; for offsets `1, 2^20, 2^40, 2^50`, compare the engine's jump-ahead state and next 64 bytes against an independent 64×64 GF(2) matrix exponentiation implemented in the oracle.
9. For every `T-RANGE`: call `read_range` and compare to the oracle slice. For `T-BIG`, include starts at `2^32`, `2^32+1`, `2^39`, and `ℓ-1`.
10. Build every `T-KAT`/`T-GEN` term through `Dag` in 8 shuffled construction orders; require identical `Ir` bytes (ids, lengths, atom order, payload hashes) in every order.
11. Check instrumented counters: every node kind, morph id, predictor id, and rewrite rule 1–13 fired at least once. Any zero counter fails.
12. Re-run steps 4–11 with 1 and 4 threads; every output must be byte-identical.
13. Write one row per check; PASS only if every row is `PASS`.

### 12.5 Evidence

```
specs_and_reports/v2/gates/E2-G.tsv
specs_and_reports/v2/logs/E2-G.log
specs_and_reports/v2/corpus/E2/corpus.tsv
specs_and_reports/v2/corpus/E2/rewrites.tsv
specs_and_reports/v2/evidence/E2/critical_pairs.md
```

`E2-G.tsv` columns:

```
check  corpus  item_id  input_sha256  expected  actual  verdict  log
```

`E2-G.log` begins with the environment record of parent §12.11, then the exact command line and exit code. `rewrites.tsv` records, per term, the number of rewrites and the rule counts, so O4.1/O4.5 can be audited.

### 12.6 Fail conditions

The gate fails on any of:

- one denotation mismatch against the independent oracle;
- one length mismatch, including a stored length that disagrees with recomputation;
- one canonicalisation that changes denotation, is not idempotent, or yields a non-canonical term;
- one critical pair that diverges;
- one malformed term accepted, or one rejection with the wrong code;
- one morph/predictor/LFSR KAT mismatch;
- one jump-ahead mismatch;
- one range mismatch, including offsets above `2^32`;
- one construction-order-dependent `Ir`;
- one zero coverage counter for a kind, morph, predictor, or rewrite rule;
- one thread-count mismatch;
- a rewrite budget overflow on a corpus term;
- a missing corpus row, missing log, missing rewrite table, or hand-edited TSV value;
- a non-zero exit from any stage.

There is no tolerance, no retry, and no partial pass.

### 12.7 What E2-G does not prove

- It does not prove wire encoding or decoding. E3 does.
- It does not prove global confluence of the rewrite system; it proves no divergence on the generated critical-pair set (`T-CRIT`).
- It does not prove constant-time predictor range access. The predictor prefix pass is linear and may return `Limit`.
- It does not prove that discovery finds good terms. E4–E6 do.
- It does not prove memory bounds on multi-gigabyte full evaluation. `T-BIG` is range-only.
- It does not prove `read_range` for a range larger than the declared limit; that is `Limit` by contract.

---

## 13. Freeze rule

When E2-G passes:

1. The `Ir`, `Kind`, and signatures in §8 are frozen.
2. Any change to node semantics, canonicalisation rules, morph/predictor catalogues, or id assignment re-runs E2-G **and every later gate**.
3. Gate rows and logs are append-only.

---

## 14. Traceability

| this document | parent |
|---|---|
| §4.2 `Ir` | §4, §4.1 |
| §4.3–4.5 well-formedness | §3.2, §3.7, §4.1 |
| §4.6 morphisms | §3.4 |
| §4.7–4.8 canonical shape and ids | §3.8, §2.2, §5.8 |
| §4.9 denotation | §3.3 |
| §4.10 LFSR | §3.5 |
| §4.11 predictors | §3.6 |
| §5.2 canonicalisation | §3.8 |
| §5.3–5.5 evaluation and range | §8.2, §8.3 |
| §5.6 DAG | §2.2, §4.1, §7.3 |
| O3.x–O6.x | §12.4 (canonical idempotence, round-trip, range probe) |
| E2-G | V2-G1 (evaluator half), V2-G8 (range correctness half), V2-G16 (first half) |

**Parent gap.** V2-G8 also requires virtual large-range probes (`F13`/`F14`) through the CLI. That end-to-end half is measured at `E7-G`; E2-G owns the range algebra. V2-G16's second half (re-canonicalise decoded IR and re-emit identical wire) is measured at `E3-G`, because it requires the wire.

---

*End of MARP2-E2.*
