# E1 — FOUNDATION — Component Specification

| Field | Value |
|---|---|
| **Document ID** | MARP2-E1 |
| **Version** | 1.0 |
| **Status** | Normative for E1. Derived from `SPECS-V2.md`. |
| **Parent** | `MARP/SPECS/SPECS-V2.md` |
| **Decomposition** | `MARP/SPECS/COMPONENTS-V2.md` |
| **Language** | C++20. No third-party libraries. No Python. |
| **Gate** | `E1-G` |

---

## 0. Reading rules

1. This document is normative for E1 only. The parent governs the format and the overall mandate; on conflict, the parent wins and this document is amended.
2. `MUST` / `MUST NOT` are normative.
3. Every obligation in §7 is measured by the gate in §12. Nothing is accepted on inspection.
4. The gate is the only exit from this component. A green unit test is not an exit.

---

## 1. Purpose

E1 provides the exact arithmetic and the hash functions on which every other component depends.

It answers exactly two questions:

1. **What is the exact value of this integer, and what is the exact length of this term?**
2. **What is the identity of these bytes?**

It answers nothing else. It does not know what a term means, how a term is written, or how a term is found.

---

## 2. Scope

### 2.1 In scope

- Arbitrary-precision non-negative integers: representation, conversion, comparison, addition, subtraction, multiplication, division, remainder, shifts.
- The length algebra `ℓ` of the term grammar: structural evaluation of declared node lengths.
- SHA-256, CRC-32, and the rolling gear hash.
- Checked narrowing to `u64`.

### 2.2 Out of scope

| Excluded | Owner |
|---|---|
| Term well-formedness and denotation | E2 (C03) |
| Canonicalisation | E2 (C04) |
| Evaluation of terms to bytes | E2 (C05) |
| Node identity and interning | E2 (C06) |
| Wire integer codecs (`uvarint`, tagged bigint) | E3 (C07) |
| Any compression, discovery, or selection | E4–E6 |
| Any file or process interface | E7 |

E1 MUST NOT acquire a dependency on any of the above.

---

## 3. Sub-components

| id | role | deliverable |
|---|---|---|
| C01 | `ARITH` | `BigInt`, `ℓ`, exact operations |
| C02 | `DIGEST` | SHA-256, CRC-32, gear hash |

A sub-component is a responsibility, not necessarily a file. C01 and C02 MAY share a translation unit. Their authority boundaries MUST NOT blur.

---

## 4. Formal model

### 4.1 Sorts

```
ℕ            non-negative integers, unbounded
Σ            {0, 1, …, 255}
Σ*           finite byte strings
BitString    finite bit strings
Term         the node DAG of parent §3.2
```

### 4.2 Integer representation

A `BigInt` is a finite sequence of limbs

```
a = (a₀, a₁, …, a_{k−1}),   aᵢ ∈ [0, 2³²)
value(a) = Σᵢ aᵢ · 2^{32i}
```

`a` is **canonical** iff `k = 0` (value 0) or `a_{k−1} ≠ 0`.

Every operation returns a canonical value. A non-canonical input is a violation of contract, not a value to normalise silently.

### 4.3 Length algebra

For a well-formed term, `ℓ` is the total function defined by parent §3.7:

```
ℓ(Empty)            = 0
ℓ(Atom a)           = a.length
ℓ(Zero n)           = n
ℓ(Concat c₁…c_k)    = Σ ℓ(cᵢ)
ℓ(Repeat c q r)     = q·ℓ(c) + r
ℓ(Slice c s l)      = l
ℓ(Morph c)          = ℓ(c)
ℓ(Xor a b)          = ℓ(a) = ℓ(b)
ℓ(Interleave c… s)  = k·ℓ(c₁)
ℓ(Lfsr _ _ n)       = n
ℓ(Affine _ _ n)     = n
ℓ(Predictor _ _ r)  = ℓ(r)
```

E1 evaluates this function structurally. The identity `ℓ(t) = |⟦t⟧|` requires the evaluator and is therefore measured at **E2-G**, not here. E1-G measures the arithmetic identities that make that equality possible.

### 4.4 Digests

**SHA-256.** FIPS 180-4. Message schedule, 64 rounds, big-endian length. Streaming state is `(h₀…h₇, buffer, bit_count)`.

**CRC-32.** IEEE 802.3: polynomial `0x04C11DB7`, reflected input and output, init `0xFFFFFFFF`, final xor `0xFFFFFFFF`.

**Zeroed-field CRC.** For a region `R` and a 4-byte field at offset `f`:

```
crc32_zeroed(R, f) = CRC32(R[0,f) ‖ 00 00 00 00 ‖ R[f+4, |R|))
```

This is the only permitted way to checksum the header and trailer.

**Gear hash.** A rolling hash over bytes with a fixed 256-entry table `G`:

```
h₀ = seed
h_{i+1} = ((h_i << 1) + G[b_i]) mod 2⁶⁴
```

The table is a format constant, pinned in the source. It is not generated at runtime and not seeded from time or address.

---

## 5. Operations

### 5.1 Conversion

| operation | precondition | postcondition |
|---|---|---|
| `from_u64(v)` | — | `value = v` |
| `from_dec(s)` | `s` matches `0 \| [1-9][0-9]*` | `value = Σ digit·10^k`, canonical |
| `from_le(b)` | — | `value = Σ bᵢ·256^i`, canonical |
| `to_dec()` | — | shortest decimal, no leading zero except `"0"` |
| `to_le()` | — | little-endian magnitude, no trailing zero byte |
| `bit_length()` | — | `0` for zero; else `⌊log₂(value)⌋ + 1` |
| `to_u64_checked()` | — | value, or `Err{Invalid}` |

### 5.2 Arithmetic

| operation | precondition | postcondition |
|---|---|---|
| `a + b` | — | exact sum |
| `a − b` | `a ≥ b` | exact difference |
| `a × b` | — | exact product |
| `divmod(a, b)` | `b ≠ 0` | `(q, r)` with `a = q·b + r`, `0 ≤ r < b` |
| `compare(a, b)` | — | `−1`, `0`, `1` |
| `shl(a, n)` | — | `a·2ⁿ` |
| `shr(a, n)` | — | `⌊a / 2ⁿ⌋` |

### 5.3 Length

| operation | precondition | postcondition |
|---|---|---|
| `length_of(ir, id)` | `ir` well-formed, `id < nodes.size()` | `ℓ(node)` per §4.3 |
| `length_of(ir)` | `ir` well-formed | `ℓ(root)` |

`length_of` MUST NOT trust a stored `length` field. It recomputes from the node and its children. Where a stored length is present, the caller compares it; E1 does not.

### 5.4 Digests

| operation | precondition | postcondition |
|---|---|---|
| `Sha256::update(b)` | — | state advanced |
| `Sha256::finish()` | exactly once | 32-byte digest |
| `Sha256::of(b)` | — | digest of `b` |
| `Crc32::update(b)` | — | state advanced |
| `Crc32::finish()` | — | 32-bit CRC |
| `Crc32::of(b)` | — | CRC of `b` |
| `Crc32::of_with_zeroed(b, f)` | `f + 4 ≤ |b|` | zeroed-field CRC |
| `gear_hash(b, seed)` | — | §4.4 value |

---

## 6. Invariants

| id | invariant |
|---|---|
| E1-I1 | Every `BigInt` in circulation is canonical. |
| E1-I2 | No operation silently narrows to `u64`; narrowing is explicit and checked. |
| E1-I3 | `divmod` satisfies `a = q·b + r` and `0 ≤ r < b`. |
| E1-I4 | `to_le` has no trailing zero byte; `from_le` has no leading byte requirement (it treats input as a magnitude). |
| E1-I5 | Digest streaming and one-shot produce identical results. |
| E1-I6 | `of_with_zeroed` zeroes exactly the 4 bytes at `f`, nothing else. |
| E1-I7 | Gear hash is a pure function of `(bytes, position)`; no ambient state. |
| E1-I8 | No global mutable state; all functions are reentrant. |

---

## 7. Proof obligations

These are obligations to be **measured**, not theorems asserted here.

| id | obligation | measurement |
|---|---|---|
| O1.1 | Ring laws: `(a+b)+c = a+(b+c)`, `a·(b+c) = a·b + a·c`, `a·b = b·a` | generated operands, exact compare |
| O1.2 | Division law: `a = (a/b)·b + a mod b`, `0 ≤ a mod b < b` | generated operands, `b ≠ 0` |
| O1.3 | Decimal round-trip: `to_dec(from_dec(s)) = s` | canonical decimal corpus |
| O1.4 | Byte round-trip: `to_le(from_le(b)) = trim(b)` | byte corpus, trimming trailing zeros |
| O1.5 | Length identities: `ℓ(Concat) = Σℓ`, `ℓ(Repeat) = q·ℓ(c)+r`, `ℓ(Slice) = l`, `ℓ(Interleave) = k·ℓ(c₁)` | generated well-formed terms |
| O1.6 | Digest KATs: SHA-256 and CRC-32 match pinned vectors | pinned vector table |
| O1.7 | Incremental equals one-shot on every split point | random split corpus |
| O1.8 | Gear hash is stable across runs, threads, and hosts | repeated runs, pinned table |

O1.5 is structural. It does not assert `ℓ(t) = |⟦t⟧|`; that is O2.x at E2-G.

---

## 8. C++ interface

```cpp
namespace marp::v2 {

struct BigInt {
    // canonical: limbs little-endian, no trailing zero limb
    std::vector<u32> limb;

    static BigInt from_u64(u64 v);
    static BigInt from_dec(std::string_view s);
    static BigInt from_le(std::span<const u8> b);

    std::string to_dec() const;
    std::vector<u8> to_le() const;
    std::size_t bit_length() const;
    bool is_zero() const;
    bool is_canonical() const;
    u64 to_u64_checked() const;          // Err{Invalid} on overflow
};

BigInt operator+(const BigInt&, const BigInt&);
BigInt operator*(const BigInt&, const BigInt&);
BigInt operator-(const BigInt&, const BigInt&);      // requires a >= b
std::pair<BigInt, BigInt> divmod(const BigInt&, const BigInt&);
int compare(const BigInt&, const BigInt&);
BigInt shl(const BigInt&, std::size_t);
BigInt shr(const BigInt&, std::size_t);

BigInt length_of(const Ir&, u32 node_id);
BigInt length_of(const Ir&);

struct Sha256 {
    void update(std::span<const u8>);
    std::array<u8, 32> finish();
    static std::array<u8, 32> of(std::span<const u8>);
private:
    u32 h[8]; u8 buf[64]; u64 bits; std::size_t fill;
};

struct Crc32 {
    void update(std::span<const u8>);
    u32 finish() const;
    static u32 of(std::span<const u8>);
    static u32 of_with_zeroed(std::span<const u8>, std::size_t field_off);
private:
    u32 state = 0xFFFFFFFFu;
};

u64 gear_hash(std::span<const u8>, u64 seed = 0);

} // namespace marp::v2
```

`Ir` is declared in `SPECS/COMPONENTS/e2-algebra/SPECS.md`. E1 sees it as data and does not interpret it beyond node lengths.

---

## 9. Error taxonomy

| condition | code | detail |
|---|---|---|
| non-canonical decimal | `Invalid` | `from_dec` |
| empty decimal | `Invalid` | `from_dec` |
| negative subtraction | `Invalid` | `a < b` |
| zero divisor | `Invalid` | `divmod` |
| `to_u64_checked` overflow | `Invalid` | value ≥ 2⁶⁴ |
| unknown node kind in `length_of` | `Invalid` | foreign IR |
| node id out of range | `Invalid` | `length_of` |
| digest used after `finish` | `Invalid` | contract violation |
| zeroed-field offset out of range | `Invalid` | `of_with_zeroed` |

No operation panics, throws past the `Result` boundary, or terminates the process.

---

## 10. Authority boundary

**E1 may:**
- compute values and lengths;
- compute digests;
- be called by every other component.

**E1 may not:**
- define, validate, or denote terms;
- read or write wire bytes;
- decide whether a term is acceptable;
- allocate node or atom ids;
- perform I/O;
- depend on any E2–E7 header.

Any call from E1 into E2–E7 is an architecture violation.

---

## 11. Determinism and resources

- All operations are deterministic: same inputs ⇒ same outputs, on any host.
- No use of locale for decimal conversion.
- No floating point anywhere in E1.
- Memory is `O(limbs)` for arithmetic and `O(1)` for streaming digests.
- Worst-case multiplication is schoolbook `O(n²)` at this stage. This is acceptable for E1; a subquadratic path is a later optimisation and MUST NOT change any output.

---

## 12. Success gate E1-G

### 12.1 Preconditions

| requirement | state |
|---|---|
| `E0-G` PASS with evidence | required |
| Corpus generator H1 available | required |
| Gate runner H2 available | required |
| No E2–E7 code linked into E1 | required |

If any precondition is unmet, E1-G is `BLOCKED`, never `PASS`.

### 12.2 The condition

> **On the generated operand and term corpora, all arithmetic and length identities in §7 hold exactly, both digest families match their pinned vectors, and incremental equals one-shot at every split point. One mismatch fails the gate.**

### 12.3 Corpus

| id | contents | size |
|---|---|---|
| `A-EDGE` | `0, 1, 2, 2³²−1, 2³², 2³²+1, 2⁶⁴−1, 2⁶⁴, 2⁶⁴+1, 2¹²⁸−1, 2¹²⁸, 2¹²⁸+1` | 12 |
| `A-BITS` | every bit length in `{0,1,2,3,7,8,15,16,31,32,33,63,64,65,127,128,129,255,256,257,511,512,513,1023,1024,1025}` | 26 |
| `A-RAND` | seeded random values at those bit lengths, 8 each | 208 |
| `A-ARITH` | seeded pairs from `A-EDGE ∪ A-BITS ∪ A-RAND`, 10 000 pairs | 10 000 |
| `S-DEC` | canonical decimal strings of `A-EDGE ∪ A-BITS` | 38 |
| `S-BYTES` | little-endian magnitudes, with trailing zeros added and removed | 512 |
| `T-LEN` | well-formed terms covering every node kind and nesting depth 1–4 | 2 000 |
| `D-KAT` | pinned SHA-256 and CRC-32 vectors (empty, `"abc"`, 55/56/63/64-byte boundaries, 1 MiB) | 24 |

All corpora are produced by seed, not stored as blobs. The seed and the corpus SHA-256 are recorded.

### 12.4 Procedure

1. Build E1 and the gate runner with `-O2 -Wall -Wextra -Werror`.
2. Generate the corpus; write `corpus.tsv` with one row per item and its SHA-256.
3. For every pair in `A-ARITH`: compute `+`, `×`, compare, and — where `a ≥ b` — `−`. Compare against the independent oracle (base 10⁹ limbs, no shared code).
4. For every ordered pair with `b ≠ 0`: compute `divmod`; check `a = q·b + r` and `0 ≤ r < b`; compare `q` and `r` against the oracle.
5. For every `S-DEC`: `from_dec` → `to_dec`; require byte equality. For `S-BYTES`: `from_le` → `to_le`; require equality after trimming input trailing zeros.
6. For every `T-LEN`: compute `ℓ` for every node; check the identities O1.5; check no stored-length trust by corrupting the stored `length` and requiring `length_of` to ignore it.
7. For every `D-KAT`: compare SHA-256 and CRC-32. For every split point of every `D-KAT` message: incremental must equal one-shot. For 1 000 random regions: `of_with_zeroed` must equal the definition in §4.4.
8. Re-run steps 3–7 with 1 and 4 threads; all outputs must be identical.
9. Write the rows; compute the verdict; emit `RESULT: PASS` only if every row is `PASS`.

### 12.5 Evidence

```
specs_and_reports/v2/gates/E1-G.tsv
specs_and_reports/v2/logs/E1-G.log
specs_and_reports/v2/corpus/E1/corpus.tsv
```

`E1-G.tsv` columns:

```
check  corpus  item_id  input_sha256  expected  actual  verdict  log
```

`E1-G.log` begins with the environment record required by parent §12.11, then the exact command line and exit code.

### 12.6 Fail conditions

The gate fails on any of:

- one arithmetic mismatch against the oracle;
- one division invariant violation;
- one decimal or byte round-trip mismatch;
- one length identity violation;
- one digest KAT mismatch;
- one incremental/one-shot mismatch;
- one thread-count mismatch;
- a missing corpus row, missing log, or hand-edited TSV value;
- a non-zero exit from any stage.

There is no tolerance, no retry, and no partial pass.

### 12.7 What E1-G does not prove

- It does not prove `ℓ(t) = |⟦t⟧|`. That needs E2's evaluator and is measured at E2-G.
- It does not prove multiplication is asymptotically fast. Speed is not this gate.
- It does not prove the wire codecs. Those are E3.
- It does not prove the gear table is optimal. It proves it is fixed and deterministic.

---

## 13. Freeze rule

When E1-G passes:

1. The signatures in §8 are frozen.
2. Any change to a signature re-runs E1-G and every later gate.
3. The gate row and log are append-only.

---

## 14. Traceability

| this document | parent |
|---|---|
| §4.2 representation | §5.3 integer encodings (magnitude form) |
| §4.3 length algebra | §3.7 |
| §4.4 SHA-256, CRC-32 | §5.2, §5.4, §5.7, §6.1 |
| §5.2 division | implied by §5.3 bigint and §9 decimal exactness |
| §7 O1.1–O1.8 | §12.4 (gaps noted in A6) |
| §12 gate | new; parent has no arithmetic gate — see amendment A6 |

---

*End of MARP2-E1.*
