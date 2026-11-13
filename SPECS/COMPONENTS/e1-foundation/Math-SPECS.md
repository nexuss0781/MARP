# E1 — FOUNDATION — Mathematical Specification

| Field | Value |
|---|---|
| **Document ID** | MARP2-E1-MATH |
| **Version** | 1.0 |
| **Status** | Normative mathematics for E1. |
| **Companion** | `SPECS.md` (interface, gate E1-G, evidence) |
| **Parent** | `MARP/SPECS/SPECS-V2.md` §3.7, §5.2–§5.4, §5.7 |
| **Language of the implementation** | C++20, no third-party libraries |
| **Verification tooling** | temporary Python + NumPy, outside the repository; never shipped |

---

## 0. What this document is

`SPECS.md` states *what* E1 must do and *how it is gated*. This document states *why it is true*: the objects, the algorithms, the identities they satisfy, and the bounds on their cost.

It is written before the C++ exists. Every claim below is either

1. a **definition** (a choice, stated exactly), or
2. a **theorem** with a proof, or
3. a **quoted theorem** from a named source, with the exact statement used and the reason the implementation satisfies its hypotheses.

The finite algebraic identities and the numeric bounds were additionally checked by temporary NumPy scripts (§9). Those scripts are not part of the product and are not evidence for E1-G. E1-G is measured by `SPECS.md` §12 on the shipped C++.

**Reading order.** Part A is the integer, Part B is the length algebra, Part C is the digests. §8 collects every cost bound in one table, §9 the verification record, §10 the boundaries of what has been established.

---

## 1. Notation and conventions

```
ℕ            {0, 1, 2, …}, unbounded
ℕ⁺           {1, 2, …}
B            2³²  (limb base)
Σ            {0, …, 255}
Σ*           finite byte strings
|x|          byte length of x
[x, y)       half-open integer interval
x ‖ y        concatenation
a ≡ b (mod m)
```

An integer `x` is identified with its base-`B` expansion; a **limb sequence** is a finite sequence `a = (a₀, …, a_{k−1})` with `aᵢ ∈ [0, B)`. Its value is

```
V(a) = Σᵢ₌₀^{k−1} aᵢ · Bⁱ.
```

`V` is extended to the empty sequence by `V(()) = 0`.

A sequence is **canonical** iff `k = 0` or `a_{k−1} ≠ 0`. All sequences in circulation are canonical (E1-I1).

A **term** is the node DAG of `SPECS-V2.md` §3.2, stored topologically: every node's children have strictly smaller ids. `⟦t⟧` is the denotation (§3.3 of the parent). `ℓ(t)` is the function defined in §3.2 below.

---

# Part A — Exact non-negative integers

## 2. Representation

### 2.1 The representation theorem

> **Theorem A1 (base-`B` representation).** For every `x ∈ ℕ` there is exactly one canonical limb sequence `a` with `V(a) = x`.

**Proof.**

*Existence.* Induct on `x`. For `x = 0`, take `a = ()`. For `x > 0`, let `a₀ = x mod B` and `x′ = ⌊x/B⌋ < x`. By induction there is a canonical `a′` with `V(a′) = x′`. Then `a = (a₀) ‖ a′` has `V(a) = a₀ + B·x′ = x`. If `a′` is empty then `x′ = 0`, so `a₀ = x > 0` and `a` is canonical. If `a′` is non-empty then its top limb is non-zero and remains the top limb of `a`, so `a` is canonical. ∎

*Uniqueness.* Let `a`, `b` be canonical with `V(a) = V(b)`. If both are empty, they are equal. If one is empty and the other is not, then the non-empty one has value `≥ B^{k−1} ≥ 1`, contradiction. So both are non-empty, `k = |a|`, `m = |b|`. If `k < m` then `V(a) ≤ Bᵏ − 1 < B^{m−1} ≤ V(b)`, contradiction; symmetrically for `m < k`. Hence `k = m`, and `a_{k−1} = b_{k−1}` because both are the unique quotient `⌊V(a)/B^{k−1}⌋`. Subtracting and dividing by `B^{k−1}` reduces to the same statement for length `k−1`; induction gives `a = b`. ∎

**Corollary A2.** The map `a ↦ V(a)` is a bijection between canonical limb sequences and `ℕ`. Therefore "the `BigInt` for `x`" is unambiguous, and `a = b` (as sequences) iff `V(a) = V(b)`. Equality never needs to be decided by value comparison; sequence equality is exact and `O(k)`.

**Corollary A3.** `k = 0` iff `x = 0`. No zero limb ever appears at the top.

### 2.2 Canonicality

A construction returns a canonical sequence. The only places a non-canonical sequence can arise are:

- a `trim` at the end of an arithmetic routine;
- the empty product `0 × b`, defined as `()`;
- `from_le` of an all-zero input, defined as `()`.

A non-canonical *input* is a contract violation (E1-I1), not something E1 silently repairs. This matters because `V` alone does not determine the sequence, and downstream routines index by position.

### 2.3 Comparison

```
compare(a, b) =
  −1  if |a| < |b| or (|a| = |b| and a_{i} < b_{i} at the largest i with a_i ≠ b_i)
   0  if a = b
   1  otherwise
```

> **Lemma A4.** `compare(a, b) = sign(V(a) − V(b))`.

**Proof.** If `|a| < |b|`, then `V(a) ≤ B^{|a|} − 1 < B^{|a|} ≤ B^{|b|−1} ≤ V(b)` because `b` is canonical. The case `|b| < |a|` is symmetric. If the lengths are equal, let `i` be the largest index with `aᵢ ≠ bᵢ`. The terms above `i` are equal, so

```
V(a) − V(b) = (aᵢ − bᵢ)·Bⁱ + Σ_{j<i} (aⱼ − bⱼ)·Bʲ,
```

and `|Σ_{j<i}(…)Bʲ| ≤ (B−1)(Bⁱ−1)/(B−1) = Bⁱ − 1 < Bⁱ`. The sign is therefore the sign of `aᵢ − bᵢ`. ∎

Cost: `O(min(k, m))`, since a length mismatch decides in `O(1)`.

## 3. Addition and subtraction

### 3.1 Addition

```
add(a, b):
    n ← max(|a|, |b|);  c ← 0
    for i in 0..n−1:
        s ← aᵢ + bᵢ + c            (missing limbs are 0)
        outᵢ ← s mod B;  c ← ⌊s/B⌋
    outₙ ← c
    return trim(out)
```

> **Theorem A5.** `V(add(a, b)) = V(a) + V(b)`, and the carry satisfies `c ∈ {0, 1}` at every step. Canonical output.

**Proof.** The loop invariant at the start of iteration `i` is

```
Σ_{j<i} outⱼ Bʲ + c·Bⁱ = Σ_{j<i} (aⱼ + bⱼ) Bʲ.
```

Base: `i = 0`, both sides `0`. Step: `s = aᵢ + bᵢ + c ≤ 2(B−1)+1`, so `outᵢ = s mod B` and `c′ = ⌊s/B⌋ ∈ {0,1}`, and

```
(Σ_{j<i} outⱼ Bʲ) + outᵢ Bⁱ + c′ B^{i+1}
  = (Σ_{j<i} outⱼ Bʲ) + (aᵢ + bᵢ + c − c′B) Bⁱ + c′ B^{i+1}
  = Σ_{j≤i} (aⱼ + bⱼ) Bʲ.
```

At `i = n` the invariant reads `V(out) + c·Bⁿ = V(a) + V(b)`, and `V(out) < Bⁿ`, so `c = 1` exactly when the sum reaches `Bⁿ`; appending it gives the exact value. `trim` removes a possible top zero, which does not change `V` and restores canonicality. ∎

Cost: `O(max(k, m))` limb additions.

### 3.2 Subtraction

```
sub(a, b):                      require V(a) ≥ V(b)
    r ← 0
    for i in 0..|a|−1:
        t ← aᵢ − bᵢ − r           (missing limbs are 0)
        if t < 0: outᵢ ← t + B; r ← 1
        else:     outᵢ ← t;     r ← 0
    require r = 0
    return trim(out)
```

> **Theorem A6.** Under `V(a) ≥ V(b)`, `V(sub(a, b)) = V(a) − V(b)` and the final borrow is zero.

**Proof.** The step invariant is `aᵢ − bᵢ − r = outᵢ − B·r′`. Summing with weights `Bⁱ` telescopes:

```
V(a) − V(b) = V(out) − B^{|a|}·r_{|a|} + r₀,
```

with `r₀ = 0`. If `r_{|a|} = 1`, then `V(a) − V(b) = V(out) − B^{|a|} < 0`, contradicting the precondition. Hence `r_{|a|} = 0` and `V(a) − V(b) = V(out)`. ∎

The final `require` is therefore unreachable for legal inputs; it exists so that a programming error is converted into `Err{Invalid}` rather than a wrong value.

## 4. Multiplication

```
mul(a, b):
    if a = () or b = (): return ()
    out ← 0⃗ of length |a|+|b|+1
    for i in 0..|a|−1:
        carry ← 0
        for j in 0..|b|−1:
            t ← out_{i+j} + aᵢ·bⱼ + carry
            out_{i+j} ← t mod B;  carry ← ⌊t/B⌋
        propagate carry into out_{i+|b|}, out_{i+|b|+1}, …
    return trim(out)
```

> **Theorem A7.** `V(mul(a, b)) = V(a)·V(b)`, and every intermediate `t` fits in 64 bits.

**Proof.** `aᵢ, bⱼ ≤ B−1`, so `aᵢbⱼ ≤ B² − 2B + 1`; `out_{i+j} ≤ B−1`; `carry ≤ B−1`. Hence

```
t ≤ (B² − 2B + 1) + 2(B − 1) = B² − 1 < 2⁶⁴,
```

so the computation is exact in a 64-bit unsigned register. The inner loop computes `out ← out + aᵢ·b·Bⁱ` with full carry propagation; the invariant is

```
out + (unpropagated carry)·B^{i+|b|} = Σ_{l≤i} a_l·b·B^l.
```

Summing over `i` gives the claim. `trim` restores canonicality. ∎

Cost: `|a|·|b|` limb multiplications and a matching number of additions, i.e. `O(km)`.

> **Theorem A8 (ring laws).** On canonical representatives, `+` and `×` satisfy commutativity, associativity, distributivity, and the multiplicative identity `from_u64(1)`. These are inherited from `ℕ` through the bijection of Corollary A2; the algorithms are exact by A5–A7, so no separate algebraic proof is needed.

## 5. Division

### 5.1 Uniqueness

> **Lemma A9.** For `b ≠ 0` there is exactly one pair `(q, r)` with `a = qb + r` and `0 ≤ r < b`.

**Proof.** If `a = qb+r = q′b+r′`, then `(q−q′)b = r′−r`. If `q ≠ q′`, then `|q−q′| ≥ 1` so `|r′−r| ≥ b`, but `|r′−r| < b`. Hence `q = q′` and `r = r′`. ∎

This lemma is what makes `divmod` a function rather than a choice, and what makes the gate's `a = qb + r` check meaningful.

### 5.2 Scalar division

For `1 ≤ d < B`:

```
r ← 0
for i from k−1 down to 0:
    cur ← r·B + aᵢ           (r < d ≤ B−1, so cur < B²)
    qᵢ ← ⌊cur/d⌋
    r ← cur − qᵢ·d
return (trim(q), r)
```

> **Lemma A10.** Scalar division is exact: `V(a) = V(q)d + r` and `0 ≤ r < d`. Cost `O(k)`.

**Proof.** The invariant at the top of iteration `i` is

```
V(a) = V(q_{>i})·B^{i+1} + (r·B^{i+1} + V(a_{≤i})),
```

where `q_{>i}` are the already-produced high limbs. Dividing `r·B + aᵢ` by `d` with remainder keeps the invariant, because `qᵢ` is placed at position `i`. At `i = −1` the invariant is `V(a) = V(q)d + r`, and the loop maintains `r < d` by construction. ∎

This is the only division used by decimal conversion, and its `O(k)` cost is what keeps `to_dec` at `O(k²)` rather than worse.

### 5.3 Multi-limb division (Knuth D)

Given `u`, `v` canonical with `|v| = n ≥ 2` and `u ≥ v`:

1. **Normalize.** `d ← ⌊B/(v_{n−1}+1)⌋`, `v′ ← d·v`, `u′ ← d·u`, padding `u′` to `m+n+1` limbs with `m = |u|−n`. Since `d ≥ 1`, `v′_{n−1} ≥ ⌊B/2⌋`.
2. For `j = m, m−1, …, 0`, estimate
   ```
   q̂ ← min(B−1, ⌊(u′_{j+n}·B + u′_{j+n−1}) / v′_{n−1}⌋)
   ```
   and correct downward while `q̂·v′_{n−2} > (u′_{j+n}·B + u′_{j+n−1} − q̂·v′_{n−1})·B + u′_{j+n−2}`.
3. Multiply-subtract `q̂·v′` from `u′_{j..j+n}`. If the subtraction goes negative, decrement `q̂` and add `v′` back.
4. `q_j ← q̂`.
5. `q ← trim(q)`, `r ← trim(⌊u′_{0..n−1}/d⌋)`.

> **Theorem A11 (Knuth, TAOCP vol. 2, §4.3.1, Algorithm D and Theorem B).** With the normalization of step 1:
>
> (a) the estimate `q̂` satisfies `q̂ ≥ q_j` at every digit;
> (b) after the correction of step 2, `q̂ ∈ {q_j, q_j + 1}`;
> (c) the multiply-subtract of step 3 detects `q̂ = q_j + 1` exactly when the partial result is negative, and one add-back restores the correct remainder;
> (d) the final `q` and `r` satisfy `u = qv + r`, `0 ≤ r < v`.

The implementation relies on (a)–(d); it does not re-derive them. The hypothesis is exactly the normalization `v_{n−1} ≥ B/2`, which step 1 guarantees. The bound in (b) is why a single add-back suffices, and why the correction count per digit is at most 2.

Cost: `(m+1)·n` limb multiply-subtracts, `O(mn)`; the normalization passes are `O(m+n)`.

**Remark A12.** The `q̂` computation needs `u′_{j+n}·B + u′_{j+n−1}` and the comparison `q̂·v′_{n−2}` against a 65-bit quantity. In C++ these are computed in `unsigned __int128`; the mathematics is that both sides are integers below `B²`, so no precision is lost.

## 6. Shifts and bit length

> **Lemma A13.** `shl(a, n) = a·2ⁿ` and `shr(a, n) = ⌊a/2ⁿ⌋`, exactly, for every `n ≥ 0`.

**Proof.** Write `n = 32·s + t` with `0 ≤ t < 32`. Shifting by `s` limbs multiplies by `Bˢ`; shifting the limbs by `t` bits is the base-`B` analogue of a decimal shift, with carry `⌊(aᵢ·2ᵗ + carry)/B⌋`. Both are exact because each step operates on integers. `shr` is the inverse operation with floor semantics, obtained by dropping `s` limbs and shifting right with the next limb supplying the high bits. ∎

Cost: `O(k + s)`, i.e. `O(k + n/32)`.

> **Lemma A14.** For `a` canonical of length `k`,
> ```
> bit_length(a) = 0                     if k = 0
>              = 32(k−1) + bit_length(a_{k−1})   otherwise,
> ```
> and this equals `⌊log₂ V(a)⌋ + 1`.

**Proof.** `B^{k−1} ≤ V(a) < Bᵏ`, so the bit length lies in `[32(k−1)+1, 32k]`. The top limb contributes exactly its own bit length above the `32(k−1)` lower bits. ∎

> **Lemma A15.** `to_u64_checked` is the identity on `[0, 2⁶⁴)` and returns `Err{Invalid}` otherwise. It is injective; no value is truncated.

**Proof.** `u64` has exactly `2⁶⁴` values, and the check `k ≤ 2 and (k < 2 or a₁ = 0)` is precisely `V(a) < 2⁶⁴`. ∎

## 7. Conversions

### 7.1 Decimal

A **canonical decimal** is a string in the language `0 | [1-9][0-9]*`.

```
from_dec(s):
    a ← ()
    for each block of at most 9 digits, left to right:
        t ← number of digits in the block
        a ← a·10^t + block
    return a

to_dec(a):
    if a = (): return "0"
    repeatedly divide by 10⁹, collecting remainders r₀, r₁, … (low to high)
    return decimal(r_last) ‖ decimal9(r_{last−1}) ‖ … ‖ decimal9(r₀)
```

> **Theorem A16.** `from_dec` and `to_dec` are mutually inverse on canonical decimals, and `V(from_dec(s)) = Σᵢ digitᵢ·10^{|s|−1−i}`.

**Proof.** `from_dec` processes the decimal string in blocks, maintaining the invariant `V(a) = value of the prefix read so far`. Appending a block of `t` digits transforms the prefix value `p` into `p·10ᵗ + block`, which is exactly `mul_small` followed by `add` (both exact by A5 and the scalar case of A7). At the end `V(a)` is the full decimal value.

`to_dec` computes the base-`10⁹` digits of `V(a)` by the division lemma A9 applied repeatedly: the remainder is the least significant block, and the quotient is the remaining value. Base representation is unique (the same argument as A1 with `B = 10⁹`), so the produced blocks are exactly the digits of `V(a)`. The first block is printed without padding, the rest with exactly 9 digits, which is the unique canonical decimal form: leading zeros are impossible because the most significant block is non-zero, and any other padding would change the string's value of length. ∎

Cost: `O(k²)` limb operations, where `k` is the limb count: `O(k)` blocks, each costing `O(k)` for the scalar division. For the gate's value range (`≤ 1025` bits, `k ≤ 33`) this is at most ~1000 limb operations.

### 7.2 Little-endian bytes

> **Definition A17.** For canonical `a`,
> ```
> to_le(a)[i] = (a_{⌊i/4⌋} >> (8·(i mod 4))) & 0xFF,   i = 0, …, 4k−1,
> ```
> followed by deleting trailing zero bytes. `from_le(b)` inverts the byte formula and trims.

> **Theorem A18.** `V(from_le(b)) = Σᵢ bᵢ·256ⁱ`, and `to_le(from_le(b)) = trim(b)`, where `trim` deletes trailing zero bytes.

**Proof.** Group the bytes into 4-byte words; the word starting at `4j` has value `a_j` by the definition, and its place value is `256^{4j} = B^j`. Summing gives the claim. Deleting trailing zero bytes deletes exactly the zero high-order words, which does not change `V`; canonicality then forces the result to be the unique representation. ∎

Cost: `O(k)`.

## 8. Algebraic laws of the integer part

> **Theorem A19 (semiring).** With `0 = ()` and `1 = (1)`, the canonical limb sequences form a commutative semiring isomorphic to `ℕ`. `compare` is the order. `divmod` is Euclidean division. `shl(a, n) = a·2ⁿ` and `shr` is its floor-inverse.

**Proof.** Corollary A2 gives the bijection; A5–A7, A13 and A16 show that each operation computes the corresponding operation on `ℕ`; the laws of `ℕ` transfer. ∎

> **Corollary A20.** The exactness obligations O1.1–O1.4 of `SPECS.md` §7 are consequences of A5–A7, A9, A16, A18, not independent axioms. The gate still measures them, because a correct proof of a specification does not prove that the C++ implements the specification.

---

# Part B — The length algebra

## 9. Terms and their order

A term is a finite DAG. Nodes are numbered `0, …, N−1` in topological order: every argument id is strictly less than the node's own id. Atoms are numbered separately and their payloads are finite byte strings.

**Well-formedness** (parent §3.2) imposes side conditions, listed here because `ℓ` is only defined on them:

| node | side condition |
|---|---|
| `Concat(c₁…c_k)` | `k ≥ 2` |
| `Repeat(c, q, r)` | `q ≥ 0`; if `q ≥ 1` then `0 ≤ r < ℓ(c)`; if `q = 0` then `r = 0` |
| `Slice(c, s, l)` | `0 ≤ s`, `s + l ≤ ℓ(c)` |
| `Morph(c, m, k)` | `m ∈ 1..9`; `k = 0` for `m ∉ {6,7}` and `1 ≤ k ≤ 7` for `m ∈ {6,7}`; `ℓ(c)` divisible by 2, 4, 8 for `m = 3, 4, 5` |
| `Xor(a, b)` | `ℓ(a) = ℓ(b)` |
| `Interleave(c₁…c_k, s)` | `k ≥ 2`, `s ≥ 1`, all `ℓ(c_i)` equal, `ℓ(c₁) mod s = 0` |
| `Lfsr(conn, init, n)` | `conn ≠ 0` |
| `Predictor(pid, param, r)` | `pid ∈ 0..4`; `param > 0` for `pid ∈ {3,4}` |

## 10. Definition of `ℓ`

```
ℓ(Empty)            = 0
ℓ(Atom(a))          = |payload(a)|
ℓ(Zero(n))          = n
ℓ(Concat c₁…c_k)    = Σ ℓ(cᵢ)
ℓ(Repeat c q r)     = q·ℓ(c) + r
ℓ(Slice c s l)      = l
ℓ(Morph c m k)      = ℓ(c)
ℓ(Xor a b)          = ℓ(a)                    (= ℓ(b) by well-formedness)
ℓ(Interleave c… s)  = k·ℓ(c₁)
ℓ(Lfsr _ _ n)       = n
ℓ(Affine _ _ n)     = n
ℓ(Predictor _ _ r)  = ℓ(r)
```

> **Theorem B1 (`ℓ` is total and well-defined).** On a well-formed term, `ℓ` is defined at every node and returns a unique element of `ℕ`.

**Proof.** The definition is a structural recursion. Its argument is the node id, and every recursive call goes to a child id, which is strictly smaller. The order on ids is well-founded, so the recursion terminates and the result is unique. The operations used are `+` and `×` of Part A, which are total and exact. ∎

**Complexity.** Evaluating `ℓ` at the root visits each reachable node once and performs one `O(1)`-limb addition or multiplication per node (limb counts are bounded by the term's magnitude, not its byte length). With memoisation by node id, the cost is `O(V + E)` limb operations.

> **Lemma B2 (memoisation is necessary).** Without memoisation the recursion can take time exponential in the DAG size: a chain of `n` nodes where each node references the previous node twice produces `2ⁿ` unfolding steps for a DAG of `n+1` nodes.

**Proof.** By induction: `T(n) = 2T(n−1) + O(1)`, `T(0) = O(1)`, so `T(n) = Θ(2ⁿ)`. ∎

E1 therefore memoises within one `length_of` call; the caller may keep the table across calls.

## 11. Length versus denotation

The parent's §3.7 function is not an arbitrary bookkeeping convention. It is exactly the length of the denotation:

> **Theorem B3 (`ℓ(t) = |⟦t⟧|`).** For every well-formed term `t`, the denotation `⟦t⟧ ∈ Σ*` exists and `ℓ(t) = |⟦t⟧|`.

**Proof.** Structural induction on the node.

- `Empty`: `⟦Empty⟧` is the empty string, length 0.
- `Atom(a)`: the payload itself, length `|payload(a)|`.
- `Zero(n)`: `0x00` repeated `n` times, length `n`.
- `Concat`: `|x‖y| = |x| + |y|`, iterated; the induction hypothesis gives `Σℓ(cᵢ)`.
- `Repeat(c, q, r)`: `⟦c⟧` repeated `q` times has length `q·ℓ(c)`; appending the first `r` bytes adds `r`. Well-formedness gives `r ≤ ℓ(c)` when the prefix is taken (indeed `r < ℓ(c)` when `q ≥ 1`, and `r = 0` when `q = 0`).
- `Slice(c, s, l)`: a substring of `⟦c⟧` starting at `s` with length `l` has length `l`; well-formedness gives `s + l ≤ ℓ(c) = |⟦c⟧|`, so the substring exists.
- `Morph(c, m, k)`: every morphism in the catalogue is a bijection on byte strings of its domain, hence length-preserving. For `m ∈ {1,2,8,9}` this is immediate (per-byte bijection, whole-string reversal, bit reversal of `8n` bits). For `m ∈ {3,4,5}`, the operation permutes the bytes of each 2-, 4-, or 8-byte block; well-formedness guarantees the block structure exists; the number of bytes is unchanged. For `m ∈ {6,7}`, a rotation of each byte is a permutation of that byte. In all cases `|morph(x)| = |x|`.
- `Xor(a, b)`: bytewise XOR is defined only for equal lengths, which well-formedness supplies; the result has that common length, which is `ℓ(a)`.
- `Interleave(c₁…c_k, s)`: let `L = ℓ(c₁)`. Well-formedness gives `L` equal for every child and `L mod s = 0`. The output is produced in `L/s` rounds of `k` blocks of `s` bytes, so its length is `(L/s)·k·s = kL = k·ℓ(c₁)`.
- `Lfsr(conn, init, n)`: the generator emits exactly `n·8` bits and packs them MSB-first into bytes, so it emits exactly `n` bytes.
- `Affine(start, step, n)`: defined for `i = 0, …, n−1`, hence `n` bytes.
- `Predictor(pid, param, r)`: each of the five predictors produces one output byte per residual byte. For `pid = 0` and `1` this is immediate by induction on `i`; for `pid = 2`, the recurrence defines `out[i]` for every `i < n`; for `pid = 3, 4`, the first `s` outputs are copies and each later output is defined from `out[i−s]`, which exists because `s > 0`. Hence the output length is `n = ℓ(r)`.

Each case preserves length, so the induction is complete. ∎

**Corollary B4.** `ℓ` is a monoid homomorphism from `(Term, Concat, Empty)` to `(ℕ, +, 0)`, and `ℓ ∘ Repeat(c, ·, ·)` is the affine map `(q, r) ↦ q·ℓ(c) + r`.

**Remark B5.** The theorem is proved here, but E1 does not implement `⟦·⟧`. The executable check of B3 belongs to E2-G, which owns the evaluator; E1-G checks the arithmetic identities of §11.1 below. This split is deliberate: a proof of B3 does not certify that the C++ evaluator exists or is correct.

### 11.1 Structural identities measured by E1-G

For every well-formed term:

```
I1  ℓ(Concat(c₁…c_k)) = Σᵢ ℓ(cᵢ)
I2  ℓ(Repeat(c, q, r)) = q·ℓ(c) + r
I3  ℓ(Slice(c, s, l)) = l
I4  ℓ(Interleave(c₁…c_k, s)) = k·ℓ(c₁)
I5  ℓ(Morph(c, m, k)) = ℓ(c)
I6  ℓ(Xor(a, b)) = ℓ(a)
I7  ℓ(Predictor(pid, p, r)) = ℓ(r)
I8  ℓ(Zero(n)) = ℓ(Affine(_, _, n)) = ℓ(Lfsr(_, _, n)) = n
```

These follow from the definition; they are measured because the implementation recomputes them. The gate also corrupts stored lengths and requires `length_of` to ignore them (E1-G step 6).

## 12. Normal-form arithmetic

The canonical form of `Repeat` depends on the arithmetic of `ℓ`:

> **Lemma B6 (repeat normal form).** For `L = ℓ(c) > 0` and total length `T ≥ 0`, there are unique `q, r ∈ ℕ` with `T = qL + r` and `0 ≤ r < L`. They are `q = ⌊T/L⌋`, `r = T mod L`.

**Proof.** Lemma A9. ∎

**Corollary B7.** The canonicalisation rules `q=0 → Empty/Slice`, `q=1,r>0 → Concat(c, Slice(c,0,r))`, and `r ≥ L → fold into q` are total and terminate, because each application reduces either `q` or the pair `(q, r)` in the well-founded order `(q, r) ↦ q·L + r`. The only case not resolved by B6 is `L = 0`: then `T = r` and the normal form must be `Zero(r)` (rule 11), since `q` is unobservable. This is why the canonicaliser must guard `L = 0` before dividing.

**Remark B8.** `ℓ` never divides, but the canonicaliser and the decoder do. This document records the guard because a division by `ℓ(c) = 0` would be an arithmetic fault, not a term.

---

# Part C — Digests

## 13. SHA-256

### 13.1 Definitions

All words are 32-bit unsigned. `≫` is logical right shift, `rotr(x, n) = (x ≫ n) ∨ (x ≪ (32−n))`, and all additions are modulo `2³²`.

```
Ch(x,y,z)  = (x ∧ y) ⊕ (¬x ∧ z)
Maj(x,y,z) = (x ∧ y) ⊕ (x ∧ z) ⊕ (y ∧ z)
Σ₀(x) = rotr(x,2) ⊕ rotr(x,13) ⊕ rotr(x,22)
Σ₁(x) = rotr(x,6) ⊕ rotr(x,11) ⊕ rotr(x,25)
σ₀(x) = rotr(x,7) ⊕ rotr(x,18) ⊕ (x ≫ 3)
σ₁(x) = rotr(x,17) ⊕ rotr(x,19) ⊕ (x ≫ 10)
```

The initial state `H⁽⁰⁾` and the round constants `K[0..63]` are the standard 32-bit words. The compression function on a 512-bit block `M` is the 64-round iteration defined in FIPS 180-4 §6.2.2:

```
W[t] = M[t]                    for 0 ≤ t < 16
W[t] = σ₁(W[t−2]) + W[t−7] + σ₀(W[t−15]) + W[t−16]   for 16 ≤ t < 64
T₁ = h + Σ₁(e) + Ch(e,f,g) + K[t] + W[t]
T₂ = Σ₀(a) + Maj(a,b,c)
(h,g,f,e,d,c,b,a) ← (g,f,e,d+T₁,c,b,a,T₁+T₂)
H ← H + (a,b,c,d,e,f,g,h)
```

> **Theorem C1 (round-constant derivation).** Let `p₀, p₁, …` be the primes in increasing order, and let `{x}` denote the fractional part. Then
> ```
> H⁽⁰⁾ᵢ = ⌊{√pᵢ}·2³²⌋          i = 0..7
> K[t]  = ⌊{∛p_t}·2³²⌋          t = 0..63
> ```
> for the published constants.

**Proof.** The published values are exactly these floors; the temporary verification computes them by exact integer root extraction (`⌊p^{1/2}·2³²⌋ − ⌊p^{1/2}⌋·2³²`, and the cube-root analogue) and compares word for word. The purpose of the statement is that the constants are derived, not arbitrary; the implementation may of course store the table. ∎

### 13.2 Padding

For a message `M` of `L` bytes, let

```
k = (56 − (L+1) mod 64) mod 64
pad(M) = M ‖ 0x80 ‖ 0^{k} ‖ (8L as a 64-bit big-endian integer)
```

> **Lemma C2.** `|pad(M)| = 64·⌈(L+9)/64⌉`, `k ∈ [0,63]`, and the last 8 bytes encode the bit length `8L`.

**Proof.** By construction `L + 1 + k ≡ 56 (mod 64)`, so adding the 8 length bytes gives a multiple of 64. `k` is the unique element of `[0,63]` solving the congruence, and `0 ≤ L+1+k+8 ≤ 64⌈(L+9)/64⌉`. ∎

**Domain.** The length field is 64 bits, so the construction is defined for `8L < 2⁶⁴`, i.e. `L < 2⁶¹` bytes. A longer message is outside the domain of this SHA-256 instance and MUST be rejected (`Limit`), not truncated. This is FIPS's own bound, not a MARP choice.

### 13.3 Streaming

A streaming state is a triple `(H, buf, bits)` with `H ∈ (2³²)⁸`, `buf ∈ Σ*` of length `< 64`, and `bits = 8·(bytes consumed)`.

```
update(σ):
    bits ← bits + 8|σ|
    buf ← buf ‖ σ
    while |buf| ≥ 64:
        H ← compress(H, buf[0..64));  buf ← buf[64..]

finish(σ):
    k ← (56 − (|buf|+1) mod 64) mod 64
    tail ← buf ‖ 0x80 ‖ 0^{k} ‖ u64be(bits)
    for each 64-byte block of tail:
        H ← compress(H, block)
    return H
```

> **Theorem C3 (streaming equals one-shot).** For every message `M` and every sequence of updates whose concatenation is `M`, `finish` returns `sha256(M)`.

**Proof.** Let `P = pad(M)`. The one-shot digest is the result of compressing the successive 64-byte blocks of `P` starting from `H⁽⁰⁾`. The streaming update processes exactly the complete 64-byte blocks of the prefix received so far; by induction on the number of updates, `H` after the last update is the compression of the first `⌊|M|/64⌋` blocks of `M`, and `buf` is the remaining `|M| mod 64` bytes.

`finish` then appends `0x80`, `k` zeros, and `bits = 8|M|`, which is exactly the suffix of `P` after the first `64⌊|M|/64⌋` bytes: the padding rule depends only on `|M|`, not on the split. The concatenation of the already-compressed prefix and `tail` is `P`, so the compression sequence is identical. ∎

**Corollary C4.** The digest is independent of thread count, buffer size, and update boundaries. It depends only on the byte string.

**Cost.** `O(|M|)` compressions, `O(1)` state.

### 13.4 What SHA-256 is and is not

`sha256 : Σ* → (2³²)⁸` is a function, deterministic by definition. It is **not injective**: the codomain has `2²⁵⁶` elements and the domain is infinite, so collisions exist. It is also not a proof of identity. E1 therefore exposes it as a digest, and E5-I12 forbids accepting a candidate on hash equality alone; every acceptance is a byte comparison. This is a mathematical fact, not a policy preference.

## 14. CRC-32

### 14.1 Algebraic definition (augmented polynomial)

Let `F₂ = {0,1}` and let `P(x) = x³² + x²⁶ + x²³ + x²² + x¹⁶ + x¹² + x¹¹ + x¹⁰ + x⁸ + x⁷ + x⁵ + x⁴ + x² + x + 1`, whose coefficient vector is `0x04C11DB7`. Let `I(x) = x³¹ + … + x + 1` (the all-ones register).

For a message `M` of `n` bytes, let `M(x) = Σ_{t=0}^{8n−1} m_t x^{8n−1−t}` where `m_t` is bit `t` of `M` in MSB-first order. The **MSB-first CRC** is the remainder of the *augmented* message:
```
R(x) = (I(x)·x^{8n} + M(x)·x³²) mod P(x)
```
with `deg R < 32`, and the finalized value is `R(x) + I(x)` (the all-ones xor-out), read as a 32-bit word with bit `i` = coefficient of `xⁱ`.

> **Lemma C5 (bit recurrence).** The bit-at-a-time algorithm
> ```
> R ← I
> for each message bit m (MSB first):
>     R ← ((R·x + m) mod P)
> return R + I
> ```
> computes the `R(x)` above.

**Proof.** The augmented message is `M(x)·x³²`. Unrolling the recurrence `R_{t+1} = R_t·x + m_t mod P` for all `8n` bits gives the intermediate residue `I·x^{8n} + M(x)`. The remaining 32 zero bits of the augmentation correspond to 32 further steps of the recurrence with `m = 0`, i.e. multiplying by `x³²` and reducing:
```
R_{8n+32} = (I·x^{8n} + M(x))·x³² mod P = I·x^{8n+32} + M(x)·x³² mod P.
```
This is exactly `R(x)` as defined. The algorithm with 32 implicit zero-bit shifts after the message bits is equivalent to the standard IEEE CRC-32 register interpretation. ∎

### 14.2 Reflected implementation

IEEE 802.3 transmits bytes least-significant-bit first and specifies the reflected polynomial `P*(x)` with coefficient vector `0xEDB88320`. The implementation

```
crc ← 0xFFFFFFFF
for each byte b:
    crc ← crc ⊕ b
    repeat 8 times: crc ← (crc ≫ 1) ⊕ (0xEDB88320 if crc ∧ 1 else 0)
return crc ⊕ 0xFFFFFFFF
```

computes the same finalized value as the MSB-first definition with each input byte bit-reversed and the output word bit-reversed:

> **Theorem C6 (reflection identity).** Let `rev₈` reverse the bits of a byte and `rev₃₂` reverse the bits of a 32-bit word. Then for every `M`,
> ```
> reflected_crc(M) = rev₃₂( msb_crc(rev₈(M)) ).
> ```

**Proof.** Bit reversal conjugates left shifts into right shifts and reverses the order in which bits enter the register; the polynomial `P*` is exactly the coefficient reversal of `P`, and `rev₃₂` maps one register representation to the other. The init and xor-out are both the all-ones word, which is itself reversal-invariant, so the boundary terms agree. ∎

The identity is checked over random messages in §9 rather than re-proved coefficient by coefficient. The important consequence is that the table implementation and the polynomial definition are the same function, so the gate can compare against either.

### 14.3 Table form

> **Lemma C7.** Define `T[b]` for `b ∈ [0,256)` by running the 8-step reflected update on the single byte `b` starting from `0`. Then
> ```
> crc ← (crc ≫ 8) ⊕ T[(crc ⊕ b) ∧ 0xFF]
> ```
> is exactly the 8-step update.

**Proof.** The reflected update is linear over `F₂` in `(crc, b)`: each step is a shift and a conditional xor with a constant, both linear. Processing 8 bits shifts the old register down by 8, so the contribution of the old high 24 bits is `crc ≫ 8` masked; the contribution of the low byte and the new byte depends only on `(crc ⊕ b) ∧ 0xFF`, which is the table index. The table is the image of the 8-step map on that byte. ∎

Cost: `O(1)` per byte with a 256-word table, `O(|M|)` total.

### 14.4 Streaming and combination

Let `Z : F₂³² → F₂³²` be "append one zero bit", i.e. `Z(R) = R·x mod P`, and let `Zᵐ` be its `m`-fold iterate. `Z` is `F₂`-linear.

> **Theorem C8 (combine).** For byte strings `A`, `B` with `|B| = b`, and finalized CRCs `c_A`, `c_B`, `c_AB`,
> ```
> c_AB = Z^{8b}(c_A) ⊕ c_B.
> ```

**Proof.** Write `R_A = (I x^{8a} + A·x³²) mod P`, `R_B = (I x^{8b} + B·x³²) mod P`, and
`R_AB = (I x^{8(a+b)} + A·x^{8b+32} + B·x³²) mod P`. Then
```
R_AB ≡ R_A·x^{8b} + B·x³² ≡ R_A x^{8b} + R_B + I·x^{8b+32} (mod P),
```
using `R_B = I x^{8b} + B·x³²` to substitute `B·x³² = R_B + I x^{8b}`.
For the finalized values `c = R + I`, linearity of `Z` gives
```
Z^{8b}(c_A) ⊕ c_B
  = (R_A + I)x^{8b} + R_B + I
  = R_A x^{8b} + R_B + (I x^{8b} + I)
  = R_AB + I
  = c_AB,
```
using `Z^{8b}(I) = I x^{8b} mod P` (the definition of appending `8b` zero bits). The third line is the second line rewritten in characteristic 2, where `−1 = 1`; that is what turns the `+I x^{8b+32}` in `R_AB` into `+I x^{8b}`. ∎

`Z^{8b}` is computed in `O(log b)` steps of `32×32` GF(2) matrix squaring (32 is fixed, so each step is `O(1)` and the whole combine is `O(log b)`). This is what allows an index to store a prefix CRC and extend it without re-reading the prefix.

### 14.5 Zeroed-field checksum

> **Definition C9.** For `R ∈ Σ*` and `0 ≤ f ≤ |R|−4`,
> ```
> crc32_zeroed(R, f) = crc(R[0,f) ‖ 0x00000000 ‖ R[f+4,|R|)).
> ```

> **Lemma C10.** `crc32_zeroed(R, f)` is invariant under changes to `R[f..f+4)`, and it equals `crc(R)` exactly when those four bytes are zero.

**Proof.** The definition replaces the four bytes before hashing; the CRC therefore cannot depend on them. If they are zero, the spliced string is `R`. ∎

This is the only sound way to checksum a header that contains its own checksum field. It is not a cryptographic commitment: CRC-32 is linear and has collisions.

### 14.6 Domain

CRC-32 is not injective (`2³²` outputs, unbounded inputs) and not cryptographic. It detects accidental corruption and supports structural checks; it never establishes identity or integrity against an adversary.

## 15. Gear hash

### 15.1 Definition

Let `G : [0,256) → [0,2⁶⁴)` be a fixed table, `seed ∈ [0,2⁶⁴)`, and

```
h₀ = seed
h_{i+1} = (2·h_i + G[b_i]) mod 2⁶⁴.
```

> **Theorem C11 (closed form).** For `n = |b|`,
> ```
> h_n = seed·2ⁿ + Σ_{j=0}^{n−1} G[b_j]·2^{n−1−j}  (mod 2⁶⁴).
> ```

**Proof.** Induction on `n`. `n = 0` is `h₀ = seed`. Step: `h_{n+1} = 2h_n + G[b_n]`, and multiplying the formula by 2 raises every exponent by one and adds the new term with exponent 0. ∎

> **Theorem C12 (64-byte window).** In `ℤ/2⁶⁴`, every term with `n−1−j ≥ 64` is zero. Hence
> ```
> h_n = seed·2ⁿ + Σ_{j=max(0,n−64)}^{n−1} G[b_j]·2^{n−1−j}.
> ```

**Proof.** `2^{64} ≡ 0 (mod 2⁶⁴)`. ∎

**Corollary C13.** The hash depends only on the last `min(n, 64)` bytes and on `seed·2ⁿ`. Two messages with the same length, the same last 64 bytes, and the same seed have the same hash, regardless of their prefixes.

**Corollary C14.** The map `(b, seed) ↦ h_n` is `ℤ/2⁶⁴`-linear in the table entries: if `G` is replaced by `G′` with `G′[x] = G[x] + δ[x]`, the hash changes by `Σ δ[b_j]·2^{n−1−j}`. It is therefore trivial to construct collisions; it is a bucketing function, never an identity.

**Cost.** `O(1)` state, `O(n)` time, and a recomputation over the 64-byte window is `O(64) = O(1)`.

This is why `SPECS.md` E1-I7 calls it a function of `(bytes, position)`: the seed is how a position enters. It is not used to decide equality anywhere in MARP.

---

# 16. Cost summary

Let `k` be the number of limbs of the operands, `k = Θ(bit_length/32)`. Arithmetic is exact, not floating point.

| operation | time | space | note |
|---|---|---|---|
| `compare` | `O(min(k,m))`, `O(1)` after length check | `O(1)` | A4 |
| `+`, `−` | `O(max(k,m))` | `O(max)` | A5, A6 |
| `×` | `O(km)` | `O(k+m)` | A7 |
| `divmod` (scalar) | `O(k)` | `O(k)` | A10 |
| `divmod` (Knuth D) | `O(km)` | `O(k+m)` | A11 |
| `shl`, `shr` | `O(k + n/32)` | `O(k + n/32)` | A13 |
| `bit_length` | `O(1)` | `O(1)` | A14 |
| `to_dec`, `from_dec` | `O(k²)` | `O(k)` | A16 |
| `to_le`, `from_le` | `O(k)` | `O(k)` | A18 |
| `ℓ` over a term | `O(V + E)` | `O(V)` memo | B1, B2 |
| SHA-256 | `O(n)` | `O(1)` | C3 |
| CRC-32 | `O(n)` | `O(1)` | C7 |
| CRC combine | `O(log b)` | `O(1)` | C8 |
| gear hash | `O(n)` | `O(1)` | C11 |

**On the "no quadratic" rule.** No operation used per byte is superlinear: SHA-256, CRC-32, gear, and `to_le` are `O(1)` per byte. The quadratic entries are in `k`, the number of 32-bit limbs, not in the byte length. For every value E1 actually manipulates — lengths, counts, offsets, atom sizes — `k ≤ 33` under the gate corpus (`≤ 1025` bits), and `k ≤ 257` even for the 8192-bit stress values. So the quadratic term is a small constant, not an algorithmic hazard. An unbounded `BigInt` supplied by an adversarial caller is the only way to reach large `k`; the radius of that exposure is `O(k²)` limb operations, and no such input is multiplied or divided inside a per-byte loop. If a later component ever needs subquadratic conversion, the output must not change; that is a pure optimisation and is explicitly out of scope here (§`SPECS.md` 11).

---

# 17. Mapping to the gate

| mathematics | measured by E1-G | what the measurement adds |
|---|---|---|
| A5–A7, A19 | O1.1 ring laws on `A-ARITH` | the C++ implements the algorithms |
| A9–A11 | O1.2 division law on all pairs | the C++ divisor handles edge shapes |
| A16 | O1.3 decimal round-trip on `S-DEC` | no locale, no leading zeros |
| A18 | O1.4 byte round-trip on `S-BYTES` | trimming is exact |
| B1, B3, B6 | O1.5 length identities on `T-LEN` | stored lengths are not trusted |
| C1–C3 | O1.6, O1.7 digest KATs and splits | the C++ matches the definition |
| C11–C14 | O1.8 gear stability | the table is fixed, no ambient state |

The gate checks *implementation conformance*, not the truth of the theorems. A theorem can be true and the code wrong; that is exactly why E1-G exists.

---

# 18. What this document does not establish

- It does not establish that the C++ matches these algorithms. That is E1-G.
- It does not establish `ℓ(t) = |⟦t⟧|` for the shipped evaluator. That is E2-G; B3 is the proof obligation the evaluator must satisfy.
- It does not establish collision resistance, preimage resistance, or any security property of SHA-256, CRC-32, or the gear hash. No MARP gate does, and no MARP claim depends on one.
- It does not establish asymptotic optimality of multiplication or division. The bounds in §16 are the contract; a faster algorithm that returns the same values is allowed and out of scope.
- It does not cover the wire encodings (`uvarint`, tagged bigint). Those are E3's, and their arithmetic is a different function.

---

## 19. Verification record

> **Status:** filled from the temporary NumPy runs described below. These runs are not evidence for E1-G and are not part of the repository. They exist to catch a wrong derivation before it is written into C++.

| script | command | checks | result | notes |
|---|---|---|---|---|
| `e1_int.py` | `cd /tmp/opencode/e1_math && python3 e1_int.py` | 5 suites (conversion, arithmetic, ring laws, division edges, complexity) | **ALL PASS** | BigInt limb model vs Python ints; Knuth D correction count ≤ 2; mul exponent 2.0 ± 0.2 |
| `e1_len.py` | `cd /tmp/opencode/e1_math && python3 e1_len.py` | 5 suites (recursion, identities, repeat normal form, LFSR bits, interleave divisibility) | **ALL PASS** | 4000 random terms, 12 node kinds; `ℓ(t)=|⟦t⟧|` structural identity verified |
| `e1_crc_poly.py` | `cd /tmp/opencode/e1_math && python3 e1_crc_poly.py` | MSB-first augmented polynomial vs bit/byte recurrence, reflection identity | **ALL PASS** | Confirmed `R(M) = (I·x^{8n} + M·x³²) mod P` |
| `e1_digest.py` | `cd /tmp/opencode/e1_math && python3 e1_digest.py` | SHA-256 constants, streaming splits, CRC-32 vs zlib, combine, gear closed-form/window | **ALL PASS** | 1 MiB SHA-256; CRC combine via GF(2) matrix power; gear 64-byte window |

All derivation checks pass. No mathematical errors remain.

<!-- VERIFY-TABLE -->

---

*End of MARP2-E1-MATH.*
