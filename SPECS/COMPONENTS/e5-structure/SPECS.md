# E5 — STRUCTURE — Component Specification

| Field | Value |
|---|---|
| **Document ID** | MARP2-E5 |
| **Version** | 1.0 |
| **Status** | Normative for E5. Derived from `SPECS-V2.md`. |
| **Parent** | `MARP/SPECS/SPECS-V2.md` |
| **Decomposition** | `MARP/SPECS/COMPONENTS-V2.md` |
| **Depends on** | E1, E2, E4 (frozen). E5 MUST NOT link E3, E6, E7. |
| **Language** | C++20. No third-party libraries. No Python. |
| **Gate** | `E5-G` |

---

## 0. Reading rules

1. This document is normative for E5 only. The parent governs the mandate; on conflict the parent wins.
2. `MUST` / `MUST NOT` are normative.
3. **Discovery is heuristic. Acceptance is exact.** E5 may miss structure; it may never emit a candidate that does not expand to its source bytes.
4. A candidate is not a term choice. E5 proposes; E6 selects.
5. The gate is the only exit from this component.

---

## 1. Purpose

E5 answers one question:

> **Which exact terms could describe each measured region?**

It proposes candidates from four sources — grammar, transforms, generators, and a global reference index — and it verifies every one byte-for-byte against the source before returning it.

It does not choose among candidates, label atoms, write wire, or translate to MAU.

---

## 2. Scope

### 2.1 In scope

- Phrase induction over byte tokens and, where expressible, bit-plane tokens.
- Exact transform search: transpose, stride, endianness, bit reversal, inversion, rotation, reversal, XOR, delta, alignment.
- Generator synthesis from the closed catalogue: `Zero`, periodic tile, `Lfsr`, `Affine`, predictor residual, desugared grammar streams.
- A deterministic global reference index for exact and near duplicates.
- Exact verification of every candidate against its declared source range.
- Bounded budgets with clean stop-on-overflow behaviour.

### 2.2 Out of scope

| Excluded | Owner |
|---|---|
| Arithmetic, digests, term semantics, canonicalisation | E1, E2 |
| Wire format | E3 |
| Provenance, segmentation, probes | E4 |
| Candidate selection, MDL, atom class, planning, plugins | E6 |
| MAU program, CLI, certificate | E7 |
| Final wire-size claims and full-fixture coverage | E6 |

E5 MUST NOT write to the wire, choose a root term, or assign an atom `klass`.

---

## 3. Sub-components

| id | role | deliverable |
|---|---|---|
| C12 | `GRAMMAR` | `induce()`, desugared phrase candidates |
| C13 | `TRANSFORM` | `find_transforms()`, exact witnesses |
| C14 | `GENERATE` | `generate()`, generator candidates |
| C15 | `INDEX` | `RefIndex`, exact and near references |

A sub-component is a responsibility, not a file. All four share one verifier and one budget ledger. None may select.

---

## 4. Formal model

### 4.1 Candidate

```cpp
enum class Origin : u8 { Grammar, Transform, Generator, IndexExact, IndexNear };

struct Witness {
    BigInt a_begin, b_begin, len;     // source ranges; a may be empty
    u8     morph;                     // 0 if none
    u32    param;                     // stride, predictor param, generator id
    std::array<u8,32> sha256;         // digest of the witness inputs
};

struct Candidate {
    Segment  where;                   // exact source range
    Ir       fragment;                // well-formed, canonical, exact
    Origin   origin;
    u8       family;                  // sub-family id, see §4.6
    Witness  witness;                 // exact evidence; zeroed if unused
    bool     verified;                // true only after full byte compare
    u64      est_bits;                // E6 cost estimate input; never a claim
};
```

`fragment` denotes exactly `source[where.begin, where.end)`. A candidate whose root is an `Atom` is a **residual**; it is still verified, but it contributes no structural coverage.

### 4.2 Verification predicate

For a candidate `c`:

```
verified(c) :=
    check_well_formed(c.fragment) = Ok
  ∧ check_canonical(c.fragment)
  ∧ ℓ(c.fragment) = c.where.end − c.where.begin
  ∧ eval_stream(c.fragment) = source[c.where.begin, c.where.end)
  ∧ c.where ⊆ [0, L)
```

`verified` MUST be set only by this predicate. The gate re-runs it with an independent evaluator.

### 4.3 Budget ledger

```cpp
struct Budget {
    u64 grammar_rules;        // default 1 << 16
    u64 grammar_tokens;       // default 1 << 24
    u64 transform_trials;     // default 1 << 20
    u64 generator_trials;     // default 1 << 18
    u64 index_candidates;     // default 1 << 16
    u64 candidates;           // default 1 << 20
};
```

Every trial consumes one unit before it runs. Exhaustion stops that source and returns the already-verified candidates. It MUST NOT return a partial, unverified, or corrupt candidate. The ledger is per encode run and is not shared across threads except through a deterministic atomic counter; merge order is by candidate key, never by completion.

### 4.4 Candidate ordering

The returned set is sorted by:

```
(where.begin, where.end, origin, family, canonical_key(fragment), witness.sha256)
```

The order is total and independent of discovery order, thread count, and hash-map iteration.

### 4.5 Coverage

For a fixture, **structural coverage** is measured over the input offsets covered by accepted candidates whose root is a structural node. `Atom`, `Empty`, and a plain `Concat` of residuals do not count by themselves.

```
structural = ⋃ { [begin, end) : c ∈ accepted,
                 c.fragment.root.kind ∉ {Atom, Empty, Concat} }
covered     = |structural|
coverage_q24 = floor(covered · 2^24 / L)
```

`Zero`, `Repeat`, `Slice`, `Morph`, `Xor`, `Interleave`, `Lfsr`, `Affine`, and `Predictor` roots count. This is deliberately the same interval-union definition E6 uses on the final term (§4.5 of `MARP2-E6`), so an E5 pass cannot be bought with a `Concat` of raw atoms.

Atoms are residuals and never count as coverage. A candidate is either fully verified or absent. For `L = 0`, coverage is defined as full.

### 4.6 Families

| origin | family | meaning |
|---|---|---|
| `Grammar` | 0 | byte-token Re-Pair rule |
| `Grammar` | 1 | bit-plane rule, desugared |
| `Grammar` | 2 | shared phrase |
| `Transform` | 0 | transpose / stride reshape |
| `Transform` | 1 | endianness / bit reversal |
| `Transform` | 2 | inversion / rotation |
| `Transform` | 3 | whole-segment reversal |
| `Transform` | 4 | XOR against reference |
| `Transform` | 5 | delta / predictor residual |
| `Transform` | 6 | alignment / long exact match |
| `Generator` | 0 | `Zero` |
| `Generator` | 1 | periodic tile |
| `Generator` | 2 | `Lfsr` |
| `Generator` | 3 | `Affine` |
| `Generator` | 4 | `Predictor` |
| `Generator` | 5 | grammar stream |
| `IndexExact` | 0 | duplicate reference |
| `IndexNear` | 0 | aligned XOR reference |

The gate requires every family to be exercised by at least one verified candidate, except where a family is structurally impossible for the corpus; impossible families MUST be named in the evidence with a reason.

---

## 5. Operations

### 5.1 Grammar induction (C12)

**Token alphabets.**

- Byte tokens: the segment's bytes.
- Bit-plane tokens: 8 sequences `plane_j[i] = (b[i] >> j) & 1`, one token per bit.

**Algorithm.** Re-Pair:

1. Start with the token sequence (or 8 plane sequences).
2. Count adjacent pairs. Choose the most frequent pair with count `>= 3`; break ties by lexicographic pair order.
3. Replace every non-overlapping occurrence left-to-right with a new rule symbol.
4. Repeat until no pair reaches the threshold or the budget is exhausted.

Sequitur is an allowed alternative only if it produces the same deterministic rule set for the same input; the gate is on the desugared result, not on the algorithm name.

**Desugaring.** A rule is emitted only as:

- `Concat` of child nodes, or
- `Repeat(child, q, r)` where the repetition is exact, or
- a shared DAG node id for an identical subterm.

The wire has no grammar node. The candidate is verified by expansion (§4.2).

**Bit-plane limit.** The term algebra has no bit-plane selection node: `Slice` is byte-addressed and `Morph` is per-byte or whole-segment. A bit-plane rule is therefore admissible only when it desugars to byte-level `Concat`/`Repeat`/`Xor`/`Interleave` and expands exactly. A rule that cannot be expressed is **discarded**, never approximated. This is a parent gap, recorded in §14.

**Budget.** `grammar_tokens` and `grammar_rules` bound induction. Overflow stops the pass; verified candidates already found are kept.

### 5.2 Transform search (C13)

For each segment, E5 tries the following transforms, bounded by `transform_trials`:

| family | transform | candidate form |
|---|---|---|
| transpose/stride | interpret range as `k × m` (row-major); children are `k` contiguous rows via `Slice`; `Interleave(children, 1)` yields the column-major transpose | `Interleave` |
| stride reshape | `Interleave(children, s)` for `s` dividing the row length | `Interleave` |
| endianness | `Morph(SWAP16/32/64)` | `Morph` |
| bit reversal | `Morph(BIT_REVERSE8)` or `Morph(REVERSE_BITS)` | `Morph` |
| inversion | `Morph(INVERT8)` | `Morph` |
| rotation | `Morph(ROTL8/ROTR8, k)` | `Morph` |
| reversal | `Morph(REVERSE_BYTES)` | `Morph` |
| XOR | choose a reference range `A`, aligned with `B`; candidate `Xor(A, Atom(B ⊕ A))` | `Xor` |
| delta | `Predictor(DELTA8,0,Atom(residual))` or `STRIDE_*` | `Predictor` |
| alignment | longest exact match at any offset, via the index | shared node / `Slice` |

A transform is reported only when `B = g(A)` holds byte-exactly over the whole range. An approximate match is not a transform. Every witness records both ranges, the morph or parameter, and a digest of the inputs.

Transpose is only offered when the range is exactly `k × m`; otherwise it is skipped, not padded.

### 5.3 Generator synthesis (C14)

Closed catalogue only. No generator is invented at runtime.

| family | search | candidate |
|---|---|---|
| `Zero` | all bytes zero | `Zero(n)` |
| periodic tile | minimal period `p` from E4, fully verified; `p < n` | `Repeat(Atom(tile), q, r)` or `Repeat(child, q, r)` when the tile is itself structured |
| `Lfsr` | for ranges `<= 64 KiB`, take the bit sequence MSB-first; Berlekamp–Massey; if linear complexity `<= 64`, derive `(conn, init)` from the recurrence and initial state | `Lfsr(conn, init, n)` after exact expansion |
| `Affine` | exact affine check from E4 | `Affine(start, step, n)` |
| `Predictor` | for pid 0–4 and valid `param`, compute the residual and check exact reconstruction | `Predictor(pid, param, Atom(residual))` |
| grammar stream | desugared grammar candidate | `Concat`/`Repeat` |

`Lfsr` synthesis is attempted only on the stated size; above it, a pinned catalogue of `(conn, init)` pairs may be tried, but every candidate is still exactly verified. No statistical fit is accepted. For a segment at offset `s` of a longer LFSR stream, E5 derives the state at `s` with E2's jump-ahead and emits `Lfsr(conn, state_s, n)` for that segment; the candidate is therefore local even when the source stream is long.

### 5.4 Reference index (C15)

```cpp
struct RefEntry {
    Segment where;          // an earlier range that is already verified
    Ir      fragment;       // self-contained fragment, verified on `where`
};

class RefIndex {
public:
    // Called only with a verified candidate; the fragment is stored by value.
    Result<void> insert(const Candidate&);
    // `window` is source[where.begin, where.end); earlier bytes are read from `src`.
    std::optional<RefEntry> exact(Source& src, Segment where,
                                  std::span<const u8> window) const;
    std::vector<RefEntry> near(Source& src, Segment where,
                               std::span<const u8> window,
                               u32 max_candidates) const;
    void clear();
};
```

- Key: `(length, SHA-256)` of the window payload.
- The index stores **earlier ranges and their already-verified fragments**, never node ids. A node id is meaningful only inside one `Ir`; each `Candidate.fragment` is self-contained, so a cross-fragment id would be meaningless. The index answers "where did these exact bytes occur before, and with which term", and sharing of identical subtrees at the DAG level is E6's job, not E5's.
- Exact duplicate: return the earliest entry whose stored payload compares byte-equal to `window` (not merely digest-equal). The new candidate reuses that entry's `fragment` unchanged, with `where` set to the new range, and is accepted only after §4.2 re-verifies it against the new range. Its `witness.a_begin`/`witness.len` record the earlier range and its `witness.sha256` the payload digest. A hash hit is a filter, never an acceptance.
- Near duplicate: aligned windows of equal length; the candidate is `Xor(base_fragment, Atom(residual))`, where `base_fragment` is the earlier entry's fragment and `residual = window ⊕ src[entry.where]` over the aligned offsets. Earlier bytes are read from the source, not stored twice. The residual is never assumed sparse. The result is verified like any other candidate; a near hit whose XOR does not expand exactly is dropped.
- Digest collision with unequal payload is not merged: both entries stay distinct, ordered by `(where.begin, length, sha256)`, and `exact` returns the first entry that byte-matches or nothing. Collisions never change denotation.
- Insertion order is deterministic: segment begin, then candidate order. Hash-map iteration is never used to order output.
- The index is per encode run, not per segment. Cross-segment and cross-scale references are allowed.
- Removing the index changes only candidate availability and size, never any denotation.

### 5.5 Verification

Every candidate passes §4.2 before it enters the result. Verification re-reads the source range; it does not trust the discovery buffer. A failed candidate is dropped, counted, and never returned.

### 5.6 Budget exhaustion

When a ledger counter reaches zero:

1. the current source stops;
2. no partial rule, transform, or generator is emitted;
3. all previously verified candidates are returned;
4. the run continues with the next source;
5. the overflow is recorded in the evidence.

A budget overflow is not a gate failure by itself. Returning an unverified candidate is.

---

## 6. Invariants

| id | invariant |
|---|---|
| E5-I1 | Every returned candidate is verified against its source range. |
| E5-I2 | `ℓ(fragment) = where.end − where.begin`. |
| E5-I3 | No candidate range lies outside the input or outside its segment. |
| E5-I4 | Candidate output is sorted by the total key of §4.4. |
| E5-I5 | Discovery order, thread count, and map iteration never affect the result. |
| E5-I6 | The generator catalogue is closed. |
| E5-I7 | A transform is accepted only when exact over the whole range. |
| E5-I8 | The index never changes denotation; removal changes only size. |
| E5-I9 | Budget exhaustion never emits a partial candidate. |
| E5-I10 | `est_bits` is an estimate for E6 and is never reported as a size claim. |
| E5-I11 | E5 never assigns `klass` and never writes wire. |
| E5-I12 | No candidate is accepted by hash equality alone; expansion is compared byte-for-byte. |

---

## 7. Proof obligations

| id | obligation | measurement |
|---|---|---|
| O9.1 | every candidate expands byte-exactly | independent evaluator, every candidate |
| O9.2 | zero false candidates on every fixture, including adversarial traps | exact compare |
| O9.3 | every candidate is well formed, canonical, and length-exact | E2 checks |
| O9.4 | candidate set is identical at 1 and 4 threads and across two runs | full set compare |
| O9.5 | structural coverage `>= 99.9 %` on every structured family of the corpus | exact union count |
| O9.6 | every grammar/transform/generator/index family is exercised | coverage counters |
| O9.7 | budget exhaustion terminates and returns only verified candidates | forced small budgets |
| O9.8 | index exact and near paths both produce verified candidates | pinned duplicate fixtures |
| O9.9 | no candidate depends on a file name, extension, or media type | source review plus all bytes fixtures |
| O9.10 | candidate ordering is total and deterministic | permuted input order, shuffled threads |

O9.2 is the core obligation: a single false candidate fails the gate, regardless of coverage.

---

## 8. C++ interface

```cpp
namespace marp::v2 {

struct CandidateSet {
    std::vector<Candidate> items;
    u64 grammar_rules, grammar_tokens, transform_trials, generator_trials;
    u64 index_exact_hits, index_near_hits, dropped_candidates;
    bool budget_exhausted;
};

Result<CandidateSet> discover(Source&, const std::vector<Segment>&, const Policy&);

Result<std::vector<Candidate>> induce(Source&, const Segment&, const Policy&);
Result<std::vector<Candidate>> find_transforms(Source&, const Segment&, const Policy&);
Result<std::vector<Candidate>> generate(Source&, const Segment&, const Policy&);

struct RefEntry {
    Segment where;
    Ir      fragment;
};

class RefIndex {
public:
    Result<void> insert(const Candidate&);
    std::optional<RefEntry> exact(Source&, Segment, std::span<const u8>) const;
    std::vector<RefEntry> near(Source&, Segment, std::span<const u8>, u32) const;
    void clear();
};

} // namespace marp::v2
```

`discover` is the only public entry point. The sub-component functions are exposed for gate isolation and MUST obey the same verification predicate.

---

## 9. Error taxonomy

| condition | code |
|---|---|
| unreadable source | `Io` |
| malformed segment input | `Invalid` |
| fragment fails well-formedness or canonicality | dropped (`Invalid` internally), not returned |
| candidate length mismatch | dropped |
| candidate expansion mismatch | dropped |
| budget exhausted | recorded, not an error |
| candidate count cap exceeded | `Limit` after all found candidates are verified |
| index digest collision with unequal payload | both entries retained; `exact` returns a byte-equal entry or nothing; never merged |
| index memory cap exceeded | `Limit` for near search; exact search continues |

A dropped candidate is counted. It is never returned with `verified = false`.

---

## 10. Authority boundary

**E5 may:**
- read the source and E4 observations;
- call E2 for term construction, canonicality, lengths, and evaluation;
- build candidates and verify them;
- maintain a per-run reference index;
- be called by E6 and the harness.

**E5 may not:**
- choose the root term or compare candidates by cost (E6);
- classify atoms (E6);
- encode wire (E3);
- translate to MAU, write files, or parse CLI (E7);
- branch on file names, extensions, or media types;
- accept a candidate on hash equality alone;
- invent a generator outside the catalogue.

---

## 11. Determinism and resources

- Grammar pair selection is by `(count desc, pair bytes asc)`; no hash-map order.
- Transform trials are ordered by family, then by range begin, then by parameter.
- Index insertion order is segment begin, then candidate key.
- Candidate output is sorted by §4.4.
- All budgets are explicit and deterministic; no wall-clock limit participates in a decision.
- Grammar memory is `O(rules + tokens)`, bounded by the ledger.
- Index memory is `O(entries)`; each entry stores one range and one fragment by value, and near search is bounded by `index_candidates`.
- Verification streams the candidate and the source range; it does not materialise both whole.
- Parallel discovery is per segment; merge is serial and sorted. No shared mutable index during parallel search: index queries use a frozen snapshot; insertion happens in the serial merge.

---

## 12. Success gate E5-G

### 12.1 Preconditions

| requirement | state |
|---|---|
| `E0-G` PASS with evidence | required |
| `E1-G`, `E2-G`, `E4-G` PASS with evidence; surfaces frozen | required |
| Independent evaluator (H3) available | required |
| No E3/E6/E7 code linked into E5 | required |

If any precondition is unmet, E5-G is `BLOCKED`, never `PASS`.

### 12.2 The condition

> **On the structure corpus, every accepted candidate expands byte-exactly to its declared source range — zero false candidates, including on adversarial traps — and every structured fixture family reaches at least 99.9 % structural coverage, with every sub-component family exercised and the candidate set identical across two runs and one versus four threads. One false candidate fails the gate.**

### 12.3 Corpus

| id | contents | size |
|---|---|---|
| `S-ZERO` | zeros | 4 MiB |
| `S-TEXT` | repeated 64 KiB printable text | 4 MiB |
| `S-TILE` | 4 KiB tile repeated | 4 MiB |
| `S-GRAD` | affine bytes | 4 MiB |
| `S-COUNT` | affine step 3 | 4 MiB |
| `S-LFSR` | pinned LFSR stream | 4 MiB |
| `S-GRAM` | nested 4 KiB base → 1 MiB unit, 1 mutation per MiB | 4 MiB |
| `S-MIX` | zero/text/gradient/counter quarters | 4 MiB |
| `S-RAND` | 10 seeded random fixtures | 1 MiB each |
| `S-CODED` | already entropy-coded bytes (compressed output) | 1 MiB |
| `S-RANDCO` | zero/text/gradient/random quarters | 4 MiB |
| `S-EDGE` | empty, 1, 2, 3, 7, 63, 64, 65, 4 095, 4 096, 4 097, all `0xFF`, alternating | 13 |
| `S-TRAP` | periodic with one mismatch; affine with one bad byte; LFSR prefix plus mutation; near-duplicate shifted by one byte; repeated 16-byte block with a single break | 5 × 1 MiB |
| `S-BUDGET` | `S-TILE` and `S-GRAM` under a 1 KiB grammar budget and a 64-candidate cap | 2 |

The structured families are constructed so 99.9 % is attainable by exact terms. `S-RAND`, `S-CODED`, `S-RANDCO`, and `S-TRAP` carry **no coverage requirement**; they carry the zero-false-candidate requirement.

### 12.4 Procedure

1. Build E5, the oracle, and the harness with `-O2 -Wall -Wextra -Werror`.
2. Generate the corpus; write `corpus.tsv` with id, length, and SHA-256.
3. Run `discover` on every fixture at effort 5, `threads = 1` and `threads = 4`, twice each.
4. For every returned candidate:
   - require `where` inside the input and inside its segment;
   - require `check_well_formed` and `check_canonical`;
   - require `ℓ(fragment) = where length`;
   - evaluate `fragment` with H3 and compare byte-for-byte with `source[where]`;
   - require `verified = true`.
   Any failure is a false candidate and fails the gate immediately.
5. On `S-TRAP`, require zero false candidates. A candidate may be absent; a wrong candidate may not exist.
6. Compute structural coverage per structured family. Require `covered · 1000 >= 999 · L` (99.9 %). Record the exact numerator and denominator.
7. Compare the full candidate sets across the four runs. Require identical sorted keys and identical fragments.
8. Re-run `S-BUDGET` with the forced tiny budget; require termination within the budget, no unverified candidate, and no crash.
9. Check coverage counters: grammar byte rule, grammar bit-plane attempt (success or recorded discard), each transform family, each generator family, index exact hit, index near hit, at least one dropped candidate, at least one budget overflow. Any missing family must be named with a structural reason in the evidence; an unexplained zero fails.
10. Write one row per check; PASS only if every row is `PASS`.

### 12.5 Evidence

```
specs_and_reports/v2/gates/E5-G.tsv
specs_and_reports/v2/logs/E5-G.log
specs_and_reports/v2/logs/E5-G-verify.log
specs_and_reports/v2/corpus/E5/corpus.tsv
specs_and_reports/v2/corpus/E5/candidates.tsv
specs_and_reports/v2/corpus/E5/coverage.tsv
```

`candidates.tsv` records, per candidate: fixture, `where`, origin, family, fragment SHA-256, witness SHA-256, and verdict. `coverage.tsv` records covered bytes, total bytes, and Q24.24 coverage per fixture.

### 12.6 Fail conditions

The gate fails on any of:

- one false candidate;
- one candidate that fails well-formedness, canonicality, or length equality;
- one candidate that depends on thread count or run order;
- one structured family below 99.9 % coverage;
- one missing sub-component family without a recorded structural reason;
- one budget run that emits an unverified candidate, crashes, or fails to terminate;
- one index path that changes denotation;
- a missing corpus row, missing log, or hand-edited TSV value;
- a non-zero exit from any stage.

There is no tolerance, no retry, and no partial pass.

### 12.7 What E5-G does not prove

- It does not prove the candidate set is complete or optimal.
- It does not prove final wire size, selection quality, or MDL optimality. E6 does.
- It does not prove coverage on the full `F02–F08` fixtures. E6 owns the full-size claim.
- It does not prove bit-plane grammars are expressible in general; the algebra lacks a bit-plane node.
- It does not prove LFSR synthesis beyond the 64 KiB search bound or the pinned catalogue.
- It does not prove the index is useful in every case; it proves exactness and determinism.

---

## 13. Freeze rule

When E5-G passes:

1. `Candidate`, `Origin`, the family table, the verification predicate, budgets, and the signatures in §8 are frozen.
2. Any change to a generator, transform family, grammar rule, index key, or ordering re-runs E5-G **and every later gate**.
3. Gate rows and logs are append-only.

---

## 14. Traceability

| this document | parent |
|---|---|
| §5.1 grammar | §6.4 |
| §5.2 transforms | §6.5 |
| §5.3 generators | §6.6 |
| §5.4 index | §6.7 |
| §4.2 verification | §6 preamble, V2-D2 |
| §12 gate | V2-G3, V2-G4 (candidate half) |

**Parent gap — bit planes.** §6.4 requires grammar induction over bit-plane tokens and §6.4 requires desugaring into `Concat`/`Repeat`/shared ids. The term algebra (§3.2) has no bit-plane selection node, and `Slice` is byte-addressed. An arbitrary bit-plane rule therefore cannot be emitted as a term. E5 treats bit-plane induction as a **proposal source only**; non-expressible rules are discarded. If the parent wants bit-plane grammars to be first-class, the algebra needs a new node, which is a format change and not in v2.0.

**Split.** §6.3's "exact-match density against the global dictionary" is measured by E5's index, not E4's probe. E4 stays local; E5 owns cross-segment references.

**Coverage scope.** E5-G measures candidate availability on a bounded structure corpus. V2-G4's full-fixture coverage is measured at E6-G, after selection and canonicalisation.

---

*End of MARP2-E5.*
