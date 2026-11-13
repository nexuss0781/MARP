# E4 — MEASURE — Component Specification

| Field | Value |
|---|---|
| **Document ID** | MARP2-E4 |
| **Version** | 1.0 |
| **Status** | Normative for E4. Derived from `SPECS-V2.md`. |
| **Parent** | `MARP/SPECS/SPECS-V2.md` |
| **Decomposition** | `MARP/SPECS/COMPONENTS-V2.md` |
| **Depends on** | E1 (frozen). E4 MUST NOT link E2–E7. Gate ordering still requires `E2-G`. |
| **Language** | C++20. No third-party libraries. No Python. |
| **Gate** | `E4-G` |

---

## 0. Reading rules

1. This document is normative for E4 only. The parent governs the mandate; on conflict the parent wins.
2. `MUST` / `MUST NOT` are normative.
3. E4 measures; it does not conclude. No observation is a term, and no observation may be reported as a size claim.
4. Every number E4 reports MUST be recomputable from the exact byte range and parameters recorded with it.
5. The gate is the only exit from this component.

---

## 1. Purpose

E4 establishes **what the input is** and **where its structure changes**, before anything is inferred.

It answers three questions:

1. **What is the identity of these bytes?** (C09 `PROVENANCE`)
2. **Where are the deterministic region boundaries?** (C10 `SEGMENT`)
3. **What can be measured, exactly and reproducibly, inside each region?** (C11 `PROBE`)

It does not propose a term. It does not decide that a period is a `Repeat`, that a fit is an `Affine`, or that a match is a reference. Those are E5 and E6.

---

## 2. Scope

### 2.1 In scope

- Exact length, streaming SHA-256, gear fingerprint, deterministic seed.
- Multi-scale content-defined segmentation with change-point detection and a segment tree.
- Exact, fixed-point statistical probes with recorded evidence ranges and parameters.
- Deterministic merge of parallel segment work.
- Locality: an observation depends only on its recorded range and parameters.

### 2.2 Out of scope

| Excluded | Owner |
|---|---|
| Arithmetic and digests | E1 |
| Term meaning, canonicalisation, evaluation | E2 |
| Wire format | E3 |
| Phrase induction, transforms, generators, index | E5 |
| Selection, classification, planning | E6 |
| CLI, MAU translation, certificate | E7 |
| Cross-segment reference index | E5 (`C15`) |
| Any candidate term | E5 |

E4 MUST NOT write to an `Ir`. It returns only `Provenance`, `Segment`, and `Observation`.

---

## 3. Sub-components

| id | role | deliverable |
|---|---|---|
| C09 | `PROVENANCE` | `Provenance`, `provenance()` |
| C10 | `SEGMENT` | `segment()`, segment tree, boundary sets |
| C11 | `PROBE` | `probe()`, `Observation` records |

A sub-component is a responsibility, not a file. The authority boundary is: E4 observes, never constructs.

---

## 4. Formal model

### 4.1 Input

A `Source` is a finite byte string of exact length `L ∈ ℕ`, readable by offset:

```cpp
struct Source {
    virtual ~Source() = default;
    virtual BigInt size() const = 0;
    virtual Result<std::size_t> read(const BigInt& off, std::span<u8>) = 0;
};
```

`read` is deterministic. Re-reading a range returns identical bytes. No source may consult the clock, the file name, or the environment.

### 4.2 Fixed-point numbers

E4 uses **no floating point**. Every statistic is an exact integer or a fixed-point value with a declared scale.

`ilog2_q24(x)` for integer `x >= 1` is

```
floor(log2(x) * 2^24)
```

computed with integer arithmetic only, using a 128-bit intermediate and a pin-testable integer log algorithm. It is not `std::log2`. It is defined by its KAT table in §12.3.

For a count vector `n = (n_0, …, n_{k-1})` with `N = Σ n_i > 0`, the order-0 entropy in Q24.24 is

```
H0_q24(n) = floor( ( N·ilog2_q24(N) - Σ_{n_i>0} n_i·ilog2_q24(n_i) ) / N )
```

For order-1 and order-2, with context counts `n_c` and joint counts `n_{c,b}`:

```
H1_q24 = floor( ( Σ_c n_c·ilog2_q24(n_c) - Σ_{c,b} n_{c,b}·ilog2_q24(n_{c,b}) ) / N )
H2_q24 = floor( ( Σ_{c,b} n_{c,b}·ilog2_q24(n_{c,b}) - Σ_{c,b,d} n_{c,b,d}·ilog2_q24(n_{c,b,d}) ) / N )
```

All sums are exact integers; the single division is the final floor. Iteration order cannot change the result.

### 4.3 Provenance

```cpp
struct Provenance {
    BigInt length;                 // exact
    std::array<u8,32> sha256;      // SHA-256 of the whole input
    u64 gear;                      // gear_hash of the whole input, seed 0
    u64 seed;                      // effort seed
};
```

The seed is

```
seed = LE64( SHA-256( "MARP2-seed" ‖ LE32(effort) ‖ sha256(x) )[0..8) )
```

It is a pure function of the bytes and effort. It is never derived from time, address, process id, or host.

### 4.4 Scales and constants

```
SCALES = { 2^6, 2^8, 2^10, 2^12, 2^14, 2^16, 2^18, 2^20, 2^22, 2^24, 2^26 }
       = { 64 B, 256 B, 1 KiB, 4 KiB, 16 KiB, 64 KiB, 256 KiB, 1 MiB, 4 MiB, 16 MiB, 64 MiB }
```

For target `T`:

```
mask(T)      = T - 1                 (T is a power of two)
min_chunk(T) = T / 4
max_chunk(T) = 4·T
```

For `L <= 64`, both boundary sets are `{0, L}` and the tree is a single leaf.

### 4.5 Content-defined boundaries

For each `T ∈ SCALES`, `B_T` is built left to right:

```
start = 0
h = 0
for i in [0, L):
    h = ((h << 1) + G[x[i]]) mod 2^64
    len = i + 1 - start
    if len >= min_chunk(T) and (h & mask(T)) == 0:
        emit boundary at i+1; start = i+1; h = 0
    else if len >= max_chunk(T):
        emit boundary at i+1; start = i+1; h = 0
emit L
```

`G` is the fixed 256-entry gear table of E1. `B_T` always contains `0` and `L`, is strictly increasing, and depends only on the bytes and `T`.

Change points are added to `B_64` before dedup:

- windows of `W = 4096` bytes, hop `W/2 = 2048`;
- for each interior window boundary `i` (with `W` bytes available on both sides):
  - `dH0 = |H0_q24(left) - H0_q24(right)|`;
  - `dZ  = |zero_frac_q24(left) - zero_frac_q24(right)|`;
  - insert `i` if `dH0 >= 2^24` (1.0 bit) or `dZ >= 2^22` (0.25);
- cap inserted change points at `L/2048 + 16`; if the cap is exceeded, keep the first ones in increasing offset order;
- dedup within 2048 bytes, keeping the smaller offset.

The cap and thresholds are format constants. They make the boundary set finite and deterministic; they do not claim optimal segmentation.

### 4.6 Segment tree

`B_k` denotes the boundary set for `SCALES[k]`, with `k = 0` finest.

Build top-down from `k = last`:

```
build(a, b, k, depth):
    emit Segment{begin=a, end=b, depth=depth, level=k}
    if k == 0: return leaf
    inner = { x ∈ B_{k-1} : a < x < b } ∪ {a, b}
    if inner == {a, b}:
        build(a, b, k-1, depth+1)          // single child, same interval
    else:
        for each consecutive pair (x, y) in inner:
            build(x, y, k-1, depth+1)
```

If a node has no finer boundary inside, it gets one child with the same interval at the next level. The recursion stops at `k = 0`, where the node is a leaf. This guarantees a tree even when coarse and fine boundary sets disagree.

Invariants:

| id | invariant |
|---|---|
| S1 | the leaves partition `[0, L)` exactly: sorted, contiguous, no gap, no overlap |
| S2 | every node interval equals the union of its children |
| S3 | `begin < end` for every non-empty leaf; the empty input has one zero-length leaf `[0,0)` |
| S4 | boundaries depend only on bytes, `SCALES`, and the fixed constants |
| S5 | the tree is independent of thread count and completion order |

### 4.7 Observations

```cpp
struct Segment { BigInt begin, end; u32 depth; u8 level; };

enum class ProbeKind : u8 {
    H0, H1, H2, Runs, Period, Repeat16, Skew, BitComplexity,
    AffineFit, QuadraticFit, Stride, ChangePoint
};

struct Observation {
    Segment where;             // exact evidence range
    ProbeKind kind;
    u64 value;                 // statistic; entropy kinds are Q24.24
    u64 aux;                   // second exact integer, kind-specific
    BigInt period;             // Period only; 0 otherwise
    std::array<u8,32> digest{};// BitComplexity polynomial digest; zero otherwise
    bool verified;             // full-range verification performed
    bool sampled;              // H2/Repeat16 sample path
    u32 sample_count;          // 0 if not sampled
    u32 param;                 // stride, window, or plane parameter
};
```

No field is a `double`. No field may be omitted. An observation without `where` is invalid. A field not used by its kind is zero.

### 4.8 Probe definitions

All probes are exact and deterministic.

| probe | definition | `value` | `aux` |
|---|---|---|---|
| `H0` | order-0 entropy of the range | `H0_q24` | `N` |
| `H1` | order-1 conditional entropy | `H1_q24` | `N` |
| `H2` | order-2 conditional entropy | `H2_q24` | `N` |
| `Runs` | histogram of maximal equal-byte runs | `run_count` | `max_run` |
| `Period` | smallest `p` with `b[i]=b[i-p]` for all `i>=p` | 0 | 0 |
| `Repeat16` | positions whose 16-byte window occurred earlier in the range | `density_q24` | `match_count` |
| `Skew` | per-bit-plane one fraction, `param` = plane 0..7 | `ones_q24` | `N` |
| `BitComplexity` | Berlekamp–Massey linear complexity, `param` = plane | `L` | 0 |
| `AffineFit` | `b[i]=(a+i·s) mod 256` over the whole range | 1 if exact fit | `a \| (s<<8)` |
| `QuadraticFit` | second difference constant over the whole range | 1 if exact fit | `d2` |
| `Stride` | best stride from `{2,3,4,8,16,32,64,256,4096}` if it lowers H0 by `>= 0.5 bit` | `H_q24` | `stride` |
| `ChangePoint` | a boundary inserted by §4.5 | 1 | `offset` |

`Period` reports its value in the `period` field; `digest` holds the SHA-256 prefix of the connection polynomial for `BitComplexity` and is zero for every other kind. Entropy and fraction kinds use Q24.24 in `value`; exact-integer kinds use `value` as an integer.

`Period` is reported only when `verified = true`. `p = N` means "no nontrivial period"; it is still reported, with `verified = true`, because the full check passed trivially.

`Repeat16` uses exact 16-byte keys with collision-checked comparison. It counts a position only if the same 16 bytes occurred at an earlier position **inside the same range**. Cross-segment references are E5's; E4 does not own a global dictionary.

`AffineFit` and `QuadraticFit` are exact predicates over the full range, not regressions.

`Stride` computes the aggregate order-1 entropy under `i mod s` and compares with `H0`; ties choose the smallest stride; no stride is reported if the improvement is below `2^23`.

### 4.9 Sampling

`H2` is computed exactly for ranges `<= 2 MiB`. Above that, E4 takes 16 windows of 64 KiB at offsets

```
floor( j · (N - 65536) / 15 ),  j = 0..15
```

and computes `H2` within each window, aggregating counts across windows. `sampled = true`, `sample_count = 16`, and the window offsets are recorded in the observation table. `Repeat16` uses the same sample policy above `2 MiB`.

The sample path is a performance policy, not a statistical claim. The gate verifies that the recorded sample reproduces exactly.

### 4.10 Effort

`effort 0..9` selects the probe budget:

| effort | scales | H2 | Repeat16 | BM planes | stride set |
|---|---|---|---|---|---|
| 0–2 | `{64, 4 KiB, 256 KiB}` | no | no | 2 | `{2,4,8}` |
| 3–5 | all 11 | yes | yes | 8 | all |
| 6–9 | all 11 | yes | yes | 8 | all |

Effort never changes exactness. It changes which observations exist, never their values. Every gate runs at effort 5.

---

## 5. Operations

### 5.1 Provenance

| operation | precondition | postcondition |
|---|---|---|
| `provenance(source, policy)` | source readable | `length`, `sha256`, `gear`, `seed` |
| one streaming pass | — | no re-read of the whole input |

The pass reads the input once. It hashes and rolls the gear hash simultaneously. It does not materialise the input.

### 5.2 Segment

| operation | precondition | postcondition |
|---|---|---|
| `segment(source, prov, policy)` | `prov` matches `source` | boundary sets, segment tree |
| `boundaries(scale)` | — | sorted, deduplicated, includes `0` and `L` |
| `leaves()` | — | exact partition |

Segmentation may read the input multiple times, once per scale, but every read is deterministic. Change-point detection reads the input once at window granularity.

### 5.3 Probe

| operation | precondition | postcondition |
|---|---|---|
| `probe(source, segment, policy)` | segment within source | observations, each with exact `where` |
| `verify_period(source, obs)` | `obs.kind = Period` | full byte verification; `verified` true only on success |

`probe` never returns a term, candidate, or node. Its return type contains none.

### 5.4 Merge

Parallel work is merged by **segment begin offset**, then by `ProbeKind` ordinal, then by `param`. Completion order is discarded. The merged observation list is identical to the serial list.

---

## 6. Invariants

| id | invariant |
|---|---|
| E4-I1 | Same bytes and effort ⇒ same provenance, boundaries, tree, and observations, on any host. |
| E4-I2 | No observation depends on bytes outside its `where` range. |
| E4-I3 | No observation depends on thread count, completion order, or hash-map iteration. |
| E4-I4 | Every `Period` with `verified = true` passes the full byte check. |
| E4-I5 | No field is floating point. |
| E4-I6 | No probe writes to an `Ir` or returns a term. |
| E4-I7 | Every observation's range lies inside its segment and inside the input. |
| E4-I8 | Boundaries are independent of the probe results; probes never move boundaries. |
| E4-I9 | The leaves partition the input exactly. |
| E4-I10 | Sampling is recorded; a sampled result never claims full-range observation. |
| E4-I11 | Re-reading the same range yields the same bytes. |
| E4-I12 | No global mutable state; parallel probes are isolated. |

---

## 7. Proof obligations

| id | obligation | measurement |
|---|---|---|
| O8.1 | provenance matches an independent SHA-256 and exact length | pinned digest |
| O8.2 | seed is a pure function of bytes and effort | same bytes, different hosts/threads/runs |
| O8.3 | boundaries are identical at 1 and 4 threads, two runs | exact vector compare |
| O8.4 | leaves partition the input | gap/overlap scan |
| O8.5 | every observation reproduces from its `where` and parameters | re-run each probe |
| O8.6 | every verified period satisfies the full byte check | independent scan |
| O8.7 | observations are local: bytes outside `where` do not affect them | mutation outside range |
| O8.8 | fixed-point and integer KATs match the independent oracle | pinned table |
| O8.9 | every probe kind, every bit plane, and the sampled path are exercised | coverage counters |
| O8.10 | change points are detected at a pinned sharp boundary within 1 MiB | pinned fixture |
| O8.11 | no probe can emit a term | API/type check plus runtime count |

O8.10 is a sensitivity check on one constructed boundary. It does not claim optimal change-point detection.

---

## 8. C++ interface

```cpp
namespace marp::v2 {

struct Provenance { BigInt length; std::array<u8,32> sha256; u64 gear, seed; };

struct Segment { BigInt begin, end; u32 depth; u8 level; };

enum class ProbeKind : u8 { H0, H1, H2, Runs, Period, Repeat16, Skew,
                            BitComplexity, AffineFit, QuadraticFit, Stride,
                            ChangePoint };

struct Observation {
    Segment where;
    ProbeKind kind;
    u64 value, aux;
    BigInt period;
    std::array<u8,32> digest;
    bool verified, sampled;
    u32 sample_count, param;
};

Result<Provenance> provenance(Source&, const Policy&);
Result<std::vector<Segment>> segment(Source&, const Provenance&, const Policy&,
                                     std::vector<Segment>* tree = nullptr);
Result<std::vector<Observation>> probe(Source&, const Segment&, const Policy&);
Result<bool> verify_period(Source&, const Observation&);

u64 ilog2_q24(u64 x);                       // integer only

} // namespace marp::v2
```

---

## 9. Error taxonomy

| condition | code |
|---|---|
| source unreadable or short | `Io` |
| provenance does not match the source | `Mismatch` |
| segment outside the input | `Invalid` |
| `period` present with `verified = false` | `Invalid` |
| sample window outside the range | `Invalid` |
| boundary set not monotone | `Invalid` (internal contract) |
| observation count or range cap exceeded | `Limit` |

E4 does not throw or panic. A failed read is `Io`; a contract violation is `Invalid`.

---

## 10. Authority boundary

**E4 may:**
- read the source;
- compute hashes, boundaries, and observations;
- call E1 for arithmetic, digests, and lengths;
- be called by E6 (and by the harness for measurement).

**E4 may not:**
- build a term, candidate, node, or atom;
- call E5, E6, E7, or E3;
- maintain a cross-segment reference index (E5);
- classify atoms (E6);
- decide boundaries from anything other than bytes and fixed constants;
- use file names, extensions, or media types.

---

## 11. Determinism and resources

- Provenance is one streaming pass: `O(1)` memory.
- Segmentation is `O(|SCALES| · L / min_chunk)` boundary work, `O(leaves)` memory.
- Probes are per segment. H2 uses a sparse count map; its memory is `O(observed trigrams)`, not `O(2^24)`.
- Bit-complexity is `O(8N)` time, `O(L)` memory per plane.
- `Repeat16` is `O(N)` with a hash map and exact key comparison.
- All parallel work is read-only; merge is serial and ordered.
- No recursion without a bound; the segment tree depth is at most `|SCALES|`.
- No floating point, no locale, no clock, no random device.

---

## 12. Success gate E4-G

### 12.1 Preconditions

| requirement | state |
|---|---|
| `E0-G` PASS with evidence | required |
| `E1-G`, `E2-G` PASS with evidence; surfaces frozen | required |
| Independent statistic oracle (H3) available for fixed-point and period checks | required |
| No E3/E5/E6/E7 code linked into E4 | required |

If any precondition is unmet, E4-G is `BLOCKED`, never `PASS`.

### 12.2 The condition

> **On the measurement corpus, segmentation at one and four threads is byte-identical and yields an exact partition; every observation reproduces bit-for-bit from its recorded byte range and parameters; identical bytes under different names and extensions produce identical output; every verified period passes a full independent byte check; observations are local to their ranges; and every probe kind, bit plane, and sample path is exercised. One mismatch fails the gate.**

### 12.3 Corpus

| id | contents | size |
|---|---|---|
| `M-CORE` | empty, 1 byte, 2 bytes, `0x00`, `0xFF` | 5 |
| `M-EDGE` | lengths 63, 64, 65, 255, 256, 257, 4095, 4096, 4097 | 9 |
| `M-ZERO` | zeros | 1 MiB |
| `M-TEXT` | repeated 64 KiB printable text block | 1 MiB |
| `M-TILE` | 4 096-byte tile repeated, period `4096` | 1 MiB |
| `M-TILE+1` | 4 097-byte tile repeated, period `4097` | 1 MiB |
| `M-GRAD` | affine bytes, step 1 | 1 MiB |
| `M-COUNT` | affine bytes, step 3 | 1 MiB |
| `M-LFSR` | pinned LFSR stream | 1 MiB |
| `M-RAND` | seeded random | 1 MiB |
| `M-NEAR` | 10 × 100 KiB near-duplicates, 1 % mutation | 1 MiB |
| `M-MIX` | zeros, text, gradient, counter, random concatenated | 5 MiB |
| `M-CHANGE` | 256 KiB zeros ‖ 256 KiB random ‖ 256 KiB zeros ‖ 256 KiB counter | 1 MiB |
| `M-TRANSPOSE` | 1 KiB × 1 KiB matrix transposed | 1 MiB |
| `M-BITPLANE` | 8 bit planes with distinct skew | 1 MiB |
| `M-KAT` | `ilog2_q24` values for `1,2,3,4,7,8,255,256,257,1023,1024,1025,2^20,2^32-1` | 14 |
| `M-NAME` | a 256 KiB slice of the `M-CHANGE` bytes written under four names and extensions (`.bin`, `.txt`, `.zip`, no extension) plus one symlink | 5 × 256 KiB |

The corpus is generated from a fixed seed; every fixture's SHA-256 is recorded. Total materialised size is under 20 MiB, so the gate does not require multi-gigabyte local work.

### 12.4 Procedure

1. Build E4, the oracle, and the harness with `-O2 -Wall -Wextra -Werror`.
2. Generate `M-*`; write `corpus.tsv` with id, length, and SHA-256.
3. Compare `provenance` against an independent SHA-256 and exact length for every fixture.
4. For every fixture, run `segment` twice at `threads = 1` and twice at `threads = 4`. Require all four boundary vectors and segment trees to be byte-identical.
5. Check S1–S5: partition, containment, monotonicity, depth, level; empty input yields one `[0,0)` leaf.
6. Run `probe` on every leaf. For every observation:
   - re-run the stated probe on exactly `where` with the recorded `param` and sample policy;
   - require identical `value`, `aux`, `period`, `digest`, `sampled`, `sample_count`, `param`;
   - require `where` inside its segment and the source.
7. For every `Period` with `verified = true`: independently scan the range and require `b[i] = b[i-p]` for all `i >= p`. For `verified = false`, require the observation is absent (the API must not report an unverified period).
8. Locality: for each fixture, mutate one byte outside a selected observation's range; require that observation to be identical. Repeat for 100 observations across fixtures.
9. Compare `ilog2_q24` and every entropy value against H3's independent integer implementation on `M-KAT` and on 1 000 random count vectors.
10. Run the 1-vs-4-thread comparison again with the merge deliberately shuffled by completion order; require identical output.
11. Rename independence: run `provenance`, `segment`, and the full probe set on every `M-NAME` file; require outputs identical to the first, byte-for-byte. Any difference fails `V2-G14`.
12. Check coverage counters: every `ProbeKind`, all 8 bit planes, `H2` full and sampled paths, `Repeat16` full and sampled paths, every stride in the fixed set, at least one change point on `M-CHANGE`, and at least one exact `AffineFit`, `QuadraticFit`, `Period` with `p < N`, and `Runs` maximum. Any zero counter fails.
13. Assert `M-CHANGE` yields a change point within 1 MiB of the zero→random boundary.
14. Write one row per check; PASS only if every row is `PASS`.

### 12.5 Evidence

```
specs_and_reports/v2/gates/E4-G.tsv
specs_and_reports/v2/logs/E4-G.log
specs_and_reports/v2/corpus/E4/corpus.tsv
specs_and_reports/v2/corpus/E4/segments.tsv
specs_and_reports/v2/corpus/E4/observations.tsv
```

`segments.tsv` records, per fixture, every segment `(begin, end, depth, level)` and the SHA-256 of the serialised tree. `observations.tsv` records every observation's full fields. `E4-G.tsv` columns:

```
check  fixture  item_id  input_sha256  expected  actual  verdict  log
```

### 12.6 Fail conditions

The gate fails on any of:

- one provenance mismatch;
- one boundary or tree difference between thread counts or runs;
- one partition gap or overlap;
- one non-local observation;
- one observation that does not reproduce exactly;
- one unverified period reported as verified;
- one verified period that fails the full byte check;
- one fixed-point KAT or entropy mismatch against the independent oracle;
- one missing probe kind, bit plane, stride, or sample path;
- no change point within 1 MiB on `M-CHANGE`;
- a missing corpus row, missing log, or hand-edited TSV value;
- a non-zero exit from any stage.

There is no tolerance, no retry, and no partial pass.

### 12.7 What E4-G does not prove

- It does not prove segmentation is optimal, minimal, or useful for selection.
- It does not prove probe thresholds are statistically correct.
- It does not prove cross-segment structure; E5's index does.
- It does not prove a term can be built from any observation.
- It does not prove performance on multi-gigabyte inputs; the corpus is bounded by design.
- It does not prove the absence of structure; it proves only that the recorded observations reproduce.

---

## 13. Freeze rule

When E4-G passes:

1. `SCALES`, chunk constants, change-point thresholds, fixed-point definitions, `ProbeKind`, `Observation`, and the signatures in §8 are frozen.
2. Any change to a boundary rule, threshold, probe definition, or sampling policy re-runs E4-G **and every later gate**.
3. Gate rows and logs are append-only.

---

## 14. Traceability

| this document | parent |
|---|---|
| §4.3 provenance | §6.1 |
| §4.5–4.6 boundaries and tree | §6.2 |
| §4.8–4.9 probes and sampling | §6.3 |
| §5.4 deterministic merge | §7.3, §12.9 |
| O8.1–O8.11 | §12.4, Appendix B |
| E4-G | V2-G2 (determinism half), V2-G14 (no type branching) |

**Derived detail.** The parent fixes target sizes `64 B … 64 MiB` but not the mask, minimum, maximum, change-point windows, thresholds, or fixed-point scale. Those are pinned here so the gate can be reproduced. They are format constants of the measurement layer and do not change the denotation of any term.

**Split.** Parent §6.3 names "exact-match density against the global dictionary". E4 measures within-range exact matches only. The global dictionary is E5's `C15 INDEX`; E4 MUST NOT own it, because a global index would make E4 depend on discovery state and would violate observation locality.

---

*End of MARP2-E4.*
