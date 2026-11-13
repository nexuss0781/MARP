# E6 — SELECT — Component Specification

| Field | Value |
|---|---|
| **Document ID** | MARP2-E6 |
| **Version** | 1.0 |
| **Status** | Normative for E6. Derived from `SPECS-V2.md`. |
| **Parent** | `MARP/SPECS/SPECS-V2.md` |
| **Decomposition** | `MARP/SPECS/COMPONENTS-V2.md` |
| **Depends on** | E1, E2, E3 (`encoded_size` only), E4, E5 (frozen). E6 MUST NOT link E7. |
| **Language** | C++20. No third-party libraries. No Python. |
| **Gate** | `E6-G` |

---

## 0. Reading rules

1. This document is normative for E6 only. The parent governs the mandate; on conflict the parent wins.
2. `MUST` / `MUST NOT` are normative.
3. **The selector chooses among verified terms. It never verifies by choosing.** A candidate that fails verification is an error, not a lower-ranked option.
4. The selector's cost is an **estimate**. The size claim is the wire E3 emits, measured by the harness.
5. The gate is the only exit from this component.

---

## 1. Purpose

E6 turns a verified candidate set into one root term and runs the end-to-end pipeline that produces it.

It answers four questions:

1. **Which verified term should represent each region?** (C16 `SELECT`)
2. **What statistical class does each final atom carry?** (C17 `CLASSIFY`)
3. **How does the pipeline run in bounded memory with deterministic parallelism?** (C18 `PLAN`)
4. **May an optional accelerator propose a candidate without changing the contract?** (C19 `PLUGIN`)

It does not write the final file. E7 does that.

---

## 2. Scope

### 2.1 In scope

- Bottom-up beam selection over the segment tree under the MDL estimate.
- Exact re-verification of every admitted candidate.
- Deterministic tie-breaking per parent §7.4.
- Canonicalisation of the assembled term and final atom classification.
- Deterministic streaming plan, parallel discovery merge, and memory bound.
- Optional plugins behind the same verifier, disabled in every gate run.
- End-to-end exactness, determinism, noise ratio, size bound, and structural coverage on the fixture set.

### 2.2 Out of scope

| Excluded | Owner |
|---|---|
| Arithmetic, digests, term semantics | E1, E2 |
| Wire format and validation | E3 |
| Provenance, segments, probes | E4 |
| Candidates | E5 |
| CLI, atomic file write, MAU, certificate | E7 |
| Throughput and 1.02× ensemble claims | report rows only (amendment A2) |
| Global optimality | not claimed |

E6 MUST NOT write a file, parse a command line, or translate to MAU.

---

## 3. Sub-components

| id | role | deliverable |
|---|---|---|
| C16 | `SELECT` | `select`, `estimate_bits`, tie-break |
| C17 | `CLASSIFY` | `classify_atom`, class thresholds |
| C18 | `PLAN` | `run`, streaming and parallel merge |
| C19 | `PLUGIN` | optional proposal interface |

A sub-component is a responsibility, not a file. Selection is the only authority that admits a term into the root.

---

## 4. Formal model

### 4.1 Inputs

```cpp
struct SelectionInput {
    const CandidateSet& candidates;      // E5, all verified
    const std::vector<Segment>& tree;    // E4, post-order or indexable
    const Provenance& provenance;
    const Policy& policy;
};
```

The tree is the E4 segment tree. A candidate is **selectable at** a node iff `candidate.where` equals that node's interval exactly. Candidates that do not align with a node are not selectable; E5 emits per-leaf candidates, which align.

### 4.2 Alternatives

For each tree node, bottom-up, E6 builds up to `beam_width` alternatives. An alternative is a canonical term with exact length:

1. **Candidate**: `canon(c.fragment)` for every selectable verified candidate `c`.
2. **Atom**: `Atom(residual)` for the node's bytes. If the node is larger than `ATOM_MAX`, canonicalisation splits it into 1 MiB atoms under a `Concat`. This alternative is always available, subject to the atom budget.
3. **Concat**: `canon(Concat(best_1, …, best_k))` over the node's children, where each `best_i` ranges over that child's beam.
4. **Repeat**: if all children alternatives are structurally identical and the node length is an exact multiple, `canon(Repeat(child, k, 0))`.

Every alternative is re-verified against the node's source range before it can be ranked. A candidate that fails re-verification aborts selection with `Invalid`; it is never silently dropped.

The Atom alternative guarantees that every node has at least one alternative whenever the atom budget suffices.

### 4.3 Cost

For a term `T`:

```
cost_bits(T) = 8 * encoded_size(canon(T))
             + Σ_{atom ∈ atoms(T)} atom_bits(atom)
             + Σ_{atom ∈ atoms(T)} model_bits(class(atom))
```

- `encoded_size` is E3's exact canonical wire size function. E6 MAY call **only** this function from E3; it MUST NOT call `encode`, `decode`, or `validate`.
- `atom_bits` follows parent Appendix A, using a provisional class for each atom payload. A provisional class never changes boundaries or denotation.
- `model_bits` is a fixed table per atom:

| class | `model_bits` |
|---|---|
| `OPAQUE` | 128 |
| `SPARSE` | 64 |
| `LOW_ENTROPY` | 64 |
| `PERIODIC_RESIDUAL` | 64 |
| `TEXTUAL` | 128 |
| `NUMERIC_PLANE` | 64 |
| `CODE_LIKE` | 64 |
| `TOKEN_STREAM` | 64 |

The cost is an integer number of bits. It is an estimate used only to rank exact terms. It is never reported as a size.

`encoded_size` includes the raw atom payload bytes. Parent §6.8 adds `atom_bits` on top, so the estimate counts atom payloads twice. This is a property of the parent's model, not a licence to change it: E6 implements the parent formula, records the double count, and never claims the estimate is a size. A later parent revision may redefine `wire_bits` as payload-free; until then E6 follows §6.8 literally.

`cost_bits` is memoised by `canonical_key`. Shared subtrees are costed once.

### 4.4 Ranking and beam

Alternatives at a node are sorted by

```
(cost_bits, tie_key)
```

`tie_key` is exactly parent §7.4:

```
(kind, argc, canonical child ids, a, b, morph, predictor_id, lexicographic wire bytes)
```

with `a`, `b` compared as exact integers, `kind` by numeric value, and child ids by their canonical order. The first `beam_width` distinct `canonical_key`s are kept. Duplicate keys are collapsed before ranking.

The root's best alternative is the selected term.

### 4.5 Structural coverage

Structural coverage is measured on the final canonical term over the expanded output:

```
structural = { offset : offset is inside the denotation range of at least one
                        reachable node whose kind is not Atom and not Empty and
                        not a plain Concat }
```

Kinds that count: `Zero`, `Repeat`, `Slice`, `Morph`, `Xor`, `Interleave`, `Lfsr`, `Affine`, `Predictor`.
`Concat` and `Atom` do not count by themselves.

`covered = |structural|`, `coverage_q24 = floor(covered · 2^24 / L)`. For `L = 0`, coverage is defined as full.

This definition makes `Repeat(Atom(tile), q, 0)` fully covered — the repetition is structure — while `Concat(Atom, Atom)` is uncovered. It is the measurement used by E6-G; E5's candidate coverage is a looser, earlier metric.

`stored_atom_bytes = Σ atom.length` over the final atom table. `uncovered_output_bytes = L − covered`, reported separately.

### 4.6 Noise ratio

For an input of `L > 0` bytes and wire of `W` bytes:

```
ratio_ok(F10) := W · 1000 <= L · 1005
```

That is `W/L <= 1.005`, compared exactly in integers. No floating point.

### 4.7 Classification

`classify_atom(payload)` is a pure decision list over exact integer statistics. All thresholds are Q24.24 or exact counts.

Definitions on payload `x` of length `N > 0`:

- `H0`, `H1`, `H2`: E4's integer entropies, with H2 sampled above 2 MiB.
- `zero = #{i : x[i]=0} / N` in Q24.24.
- `printable = #{i : x[i] ∈ [0x20,0x7E] ∪ {09,0A,0D}} / N`.
- `diversity = |{4-byte tokens}| / min(N, 4096)` in Q24.24.
- `skew = max_j |2·ones_j − N| / N` over the 8 bit planes.
- `stride_gain = H0 − H1_stride` in Q24.24, where `H1_stride` is the aggregate entropy of positions modulo the best `s ∈ {2,3,4,8,16,32,64,256,4096}`.
- `repeat16 =` fraction of positions whose 16-byte window occurred earlier in `x`, in Q24.24.
- `period`: smallest `p < N` with full verification, else `N`.

Decision list, first match wins. Every threshold is an exact integer comparison; no decimal literal is evaluated at runtime:

| order | class | condition |
|---|---|---|
| 1 | `SPARSE` | `zero_q24 >= 2^23` |
| 2 | `OPAQUE` | `H1_q24 · 10 >= 79 · 2^24` |
| 3 | `TEXTUAL` | `printable_q24 · 10 >= 9 · 2^24` and `diversity_q24 >= 2^23` |
| 4 | `NUMERIC_PLANE` | `skew_q24 >= 2^23` and (`H0_q24 <= 4 · 2^24` or `stride_gain_q24 >= 2^23`) |
| 5 | `LOW_ENTROPY` | `H0_q24 <= 4 · 2^24` |
| 6 | `CODE_LIKE` | `H2_q24 <= 6 · 2^24` and `repeat16_q24 · 20 >= 2^24` |
| 7 | `PERIODIC_RESIDUAL` | `repeat16_q24 >= 2^22` and `period = N` |
| 8 | `TOKEN_STREAM` | `H1_q24 · 2 <= 13 · 2^24` and `repeat16_q24 · 10 >= 2^24` |
| 9 | `OPAQUE` | fallback |

`zero_q24`, `printable_q24`, `diversity_q24`, `skew_q24`, `stride_gain_q24`, and `repeat16_q24` are each `floor(ratio · 2^24)` computed with E1 integer arithmetic. `2^24` is the Q24.24 unit; `2^23` is one half, `2^22` is one quarter. Multiplication by a small integer is exact before comparison.

The parent gives eight signatures but no precedence. The decision list above is the derived total order; it is normative for E6. Classification is advisory to NEZITOR and never changes denotation or atom boundaries.

Classification runs **after** final canonicalisation, on final atom payloads. A provisional class used during selection is discarded.

### 4.8 Atom class numbering

Exactly parent §6.9: `OPAQUE=0`, `SPARSE=1`, `LOW_ENTROPY=2`, `PERIODIC_RESIDUAL=3`, `TEXTUAL=4`, `NUMERIC_PLANE=5`, `CODE_LIKE=6`, `TOKEN_STREAM=7`.

An empty atom is invalid at E3; classification is total on non-empty payloads.

---

## 5. Operations

### 5.1 Selection

| operation | precondition | postcondition |
|---|---|---|
| `select(input)` | E4 tree, E5 candidates all verified | one canonical `Ir` for the root |
| `estimate_bits(ir)` | `check_canonical(ir)` | exact integer estimate |

Selection is bottom-up. It is deterministic: node order, candidate order, and child order are fixed by the tree and the candidate sort key.

Re-verification per alternative:

```
check_well_formed(t) ∧ check_canonical(t)
∧ ℓ(t) = node length
∧ eval_stream(t) = source[node]
```

A failure returns `Invalid`; there is no fallback that admits the term.

### 5.2 Assembly

After the root alternative is chosen:

1. `canon(root)`.
2. Re-verify denotation against the source.
3. Assign final `klass` to every atom via §4.7.
4. Re-run `check_canonical`; classification MUST NOT alter ids, lengths, payloads, or order.
5. Return the `Ir`. E7 encodes it.

Atom sharing is applied by E2's `Dag` rules. The selector's cost does not model sharing exactly; the final wire size is measured by E7/E0.

### 5.3 Pipeline

`run(source, policy)` executes:

1. provenance (E4);
2. segmentation (E4);
3. probes (E4, parallel by segment);
4. discovery (E5, parallel by segment, frozen index snapshot, serial merge);
5. selection (E6, serial bottom-up);
6. canonicalisation (E2);
7. classification (E6);
8. return the `Ir`.

E7 adds encoding, self-verification, and atomic write.

Merge order is segment begin, then candidate key. Completion order is discarded. Phase 8 is outside E6.

### 5.4 Plugins

```cpp
struct Plugin {
    virtual ~Plugin() = default;
    virtual std::string_view id() const = 0;
    virtual Result<std::vector<Candidate>> propose(Source&, const Segment&) = 0;
};
```

A plugin proposal enters the same verification predicate and the same selector. It cannot:

- change the wire format;
- introduce file-type semantics;
- bypass verification;
- be required by any gate;
- alter `klass` after classification.

Plugins are disabled by default and in every gate run. The gate binary MUST NOT load a plugin.

### 5.5 Memory and streaming

- Profile and segmentation stream the source; they do not materialise it.
- Discovery re-reads ranges for verification.
- Atom payloads spill to a temporary stream when the configured memory cap is reached. Spill files are unnamed temporary handles, deleted on exit.
- Selection holds the candidate set and beam; it does not hold the full source.
- Classification reads atoms again; it does not change them.

The declared design bound is parent §13: encode 4 GiB `<= 256 MiB` RSS, decode `<= 128 MiB`. This is measured as a **report row**, not a binary gate (amendment A2/A7).

### 5.6 Effort

`effort 0..9` scales `beam_width`, `atom_budget`, `grammar_budget`, and candidate caps. It never changes exactness or canonicality. Gate runs use effort 5 and default policy unless a row names another effort.

---

## 6. Invariants

| id | invariant |
|---|---|
| E6-I1 | The selector admits only terms that pass exact re-verification. |
| E6-I2 | The Atom alternative is always available within the atom budget. |
| E6-I3 | The cost is an estimate; the measured wire is the claim. |
| E6-I4 | The selector is not a global minimiser and is never reported as one. |
| E6-I5 | The output is identical at 1 and 4 threads and across repeated runs. |
| E6-I6 | Classification is a pure function of payload bytes. |
| E6-I7 | Classification never changes denotation, boundaries, ids, or order. |
| E6-I8 | No plugin is required by any gate or by the default path. |
| E6-I9 | No phase inspects a file name, extension, or media type. |
| E6-I10 | Spill failure is an error; it never yields a partial term. |
| E6-I11 | Peak memory is bounded by the policy and measured as a report row. |
| E6-I12 | The final term is canonical and its denotation equals the source. |

---

## 7. Proof obligations

| id | obligation | measurement |
|---|---|---|
| O10.1 | end-to-end exactness on every fixture | `decode(encode(x)) = x`, SHA-256 |
| O10.2 | two runs and 1 vs 4 threads are byte-identical | four-way wire compare |
| O10.3 | F10 noise ratio `<= 1.005` | exact integer comparison |
| O10.4 | F02/F03 `<= 1 MiB`, F04 `<= 8 MiB` | wire size |
| O10.5 | structural coverage `>= 99.9 %` on F02–F08 | §4.5 interval union |
| O10.6 | every admitted candidate is verified | corrupted-candidate injection must abort |
| O10.7 | tie-breaking matches §7.4 | constructed equal-cost alternatives |
| O10.8 | classification is pure and every class is exercised | KAT payloads, repeated runs |
| O10.9 | plugins are absent from every gate run | binary/API check |
| O10.10 | empty and one-byte inputs round-trip | F00, F01 |
| O10.11 | F11/F12 round-trip exactly when supplied | exact compare |

O10.4 and O10.5 are measured on full-size fixtures at the declared gate host. A host that cannot materialise them records `BLOCKED`, never `PASS`.

---

## 8. C++ interface

```cpp
namespace marp::v2 {

struct SelectionInput {
    const CandidateSet& candidates;
    const std::vector<Segment>& tree;
    const Provenance& provenance;
    const Policy& policy;
};

Result<Ir>  select(const SelectionInput&);
BigInt      estimate_bits(const Ir&);

u8          classify_atom(std::span<const u8>);

Result<Ir>  run(Source&, const Policy&);

struct Plugin {
    virtual ~Plugin() = default;
    virtual std::string_view id() const = 0;
    virtual Result<std::vector<Candidate>> propose(Source&, const Segment&) = 0;
};

} // namespace marp::v2
```

E6 calls E3 `encoded_size` only. It MUST NOT call `encode`, `decode`, `validate`, or any E7 symbol.

---

## 9. Error taxonomy

| condition | code |
|---|---|
| candidate fails re-verification | `Invalid` (abort) |
| candidate length does not match its node | `Invalid` |
| tree and candidate ranges disagree | `Invalid` |
| atom budget exhausted and no alternative | `Limit` |
| beam budget exhausted | not an error; the best current alternative stands |
| spill I/O failure | `Io` |
| plug-in proposal unverified | dropped, not admitted |
| source becomes unreadable during verification | `Io` |
| output term length mismatch | `Mismatch` |

No operation panics, throws past `Result`, or terminates the process.

---

## 10. Authority boundary

**E6 may:**
- call E2 for canonicalisation, lengths, evaluation, and `Dag`;
- call E3 `encoded_size` only;
- call E4 and E5;
- choose the root term and assign atom classes;
- run optional plugins through the same verifier;
- return an `Ir`.

**E6 may not:**
- encode, decode, or validate wire;
- write a file or parse a command line;
- translate to MAU or certify;
- admit an unverified candidate;
- let a plugin change the format or bypass verification;
- branch on file names, extensions, or media types.

The edge `E6 → E3 encoded_size` is a derived decomposition correction: the parent's cost model (§6.8, Appendix A) needs the canonical wire size, and duplicating the format inside E6 would create a second source of truth. The edge is size-only and read-only.

---

## 11. Determinism and resources

- Selection order is post-order over the tree; ties are broken by §4.4.
- Candidate and beam order are total and independent of discovery order.
- Classification uses exact integers; no floating point and no locale.
- Parallel discovery uses a frozen index snapshot; insertion happens in the serial merge.
- No wall-clock limit participates in a decision.
- Memory is bounded by the policy: beam width, candidate caps, atom budget, spill cap.
- Decode memory bound is E3/E7's; E6's encode bound is measured as a report row.

---

## 12. Success gate E6-G

### 12.1 Preconditions

| requirement | state |
|---|---|
| `E0-G` … `E5-G` PASS with evidence; surfaces frozen | required |
| Fixtures `F00–F10`, `F15` generated and hashed | required |
| `F11` and `F12` supplied with recorded paths and SHA-256 | required for the real-bytes rows |
| No plugin linked or loaded | required |
| Host able to materialise the declared fixture sizes, or the gate is `BLOCKED` | required |

If `F11`/`F12` are missing, the real-bytes rows are `BLOCKED`; the gate cannot be `PASS`.

### 12.2 The condition

> **For every fixture in the gate set, `decode(encode(discover(x))) = x` byte-exactly and by SHA-256; two encodes and one-versus-four-thread encodes are byte-identical; F10 satisfies `wire/input <= 1.005`; F02/F03 wire `<= 1 MiB` and F04 wire `<= 8 MiB`; structural coverage on F02–F08 is at least 99.9 %; a deliberately corrupted candidate aborts selection; and every atom class is exercised. One failure fails the gate.**

### 12.3 Fixtures

Exactly parent §12.3, with the measured sizes:

| id | fixture | size |
|---|---|---|
| `F00` | empty | 0 |
| `F01` | one byte `0xA5` | 1 |
| `F02` | zeros | 1 GiB |
| `F03` | repeated 64 KiB text | 1 GiB |
| `F04` | 64 KiB tile repeated | 4 GiB |
| `F05` | affine gradient | 256 MiB |
| `F06` | affine counter | 1 GiB |
| `F07` | LFSR | 1 GiB |
| `F08` | nested 4 KiB base → 1 MiB unit, 1 mutation/MiB | 1 GiB |
| `F09` | 10 × 100 KiB near-duplicates, 1 % mutation | 1 MiB |
| `F10` | seeded random | 1 GiB |
| `F11` | supplied real bytes | any |
| `F12` | supplied entropy-coded bytes | any |
| `F15` | mixed 4 GiB | 4 GiB |

`F13`/`F14` virtual probes are E7-G.

Classification KAT (`C-KAT`, 8 payloads, pinned by SHA-256 in `classify.tsv`): one payload per intended class, built from that class's signature in §4.7 — zeros for `SPARSE`, high-entropy random for `OPAQUE`, printable text for `TEXTUAL`, a skewed bit-plane pattern with stride correlation for `NUMERIC_PLANE`, a two-symbol alphabet for `LOW_ENTROPY`, an order-2-predictable cyclic pattern for `CODE_LIKE`, a repeated-16-byte-block pattern with no global period for `PERIODIC_RESIDUAL`, and a low-order-1 token stream for `TOKEN_STREAM`. Each payload is 4 KiB. The gate records the actual label; an intended label that disagrees with the implemented decision list is a specification defect to be resolved before the gate run, never by changing the verdict.

### 12.4 Procedure

1. Build the engine and harness with `-O2 -Wall -Wextra -Werror`.
2. Generate `F00–F10`, `F15`; record SHA-256. Register `F11`/`F12` or mark rows `BLOCKED`.
3. For every fixture, run `run` + `encode` at effort 5, `threads = 1`, twice, and `threads = 4`, twice.
4. For each of the four wires:
   - decode with E3 and with H3; compare bytes to the input and compare SHA-256;
   - record input bytes, wire bytes, ratio, encode/decode exit codes, and RSS.
5. Require all four wires to be byte-identical for each fixture.
6. F10: require `wire · 1000 <= input · 1005`; record atom residual and structurally uncovered bytes.
7. F02/F03: require `wire <= 1 048 576`; F04: require `wire <= 8 388 608`.
8. Coverage: compute §4.5 on the canonical decoded `Ir` for F02–F08. Require `covered · 1000 >= 999 · L` for each. Record `covered`, `L`, `coverage_q24`, `stored_atom_bytes`, `uncovered_output_bytes`.
9. Corrupted-candidate injection: construct a `CandidateSet` with one fragment whose denotation differs from its declared range; call `select`; require `Invalid` and no root term.
10. Tie-break: construct equal-cost alternatives in both input orders; require the §7.4 winner. Repeat with permuted child order where semantics allow.
11. Classification: run `classify_atom` on the eight KAT payloads and on every final atom; require deterministic labels, all eight classes present across the KAT set, and no label change on a second run.
12. Plugin check: verify the gate binary has no plugin loaded and that the default `run` path uses none.
13. Record memory and throughput as report rows. They do not decide the gate.
14. Write one row per fixture and check; PASS only if every row is `PASS`.

### 12.5 Evidence

```
specs_and_reports/v2/gates/E6-G.tsv
specs_and_reports/v2/logs/E6-G.log
specs_and_reports/v2/logs/E6-G-determinism.log
specs_and_reports/v2/logs/E6-G-tiebreak.log
specs_and_reports/v2/logs/E6-G-classify.log
specs_and_reports/v2/corpus/E6/coverage.tsv
specs_and_reports/v2/corpus/E6/classify.tsv
```

`E6-G.tsv` columns:

```
fixture  input_bytes  wire_bytes  ratio  sha_match  covered_bytes  coverage_q24
atom_bytes  threads  run  verdict  log
```

`coverage.tsv` records the interval-union count, stored atom bytes, and uncovered output bytes per fixture.

### 12.6 Fail conditions

The gate fails on any of:

- one fixture that does not round-trip byte-exactly;
- one SHA-256 mismatch;
- one non-identical wire across the four runs;
- F10 ratio above 1.005;
- F02/F03 above 1 MiB, or F04 above 8 MiB;
- F02–F08 coverage below 99.9 %;
- a corrupted candidate admitted, or selection not aborting;
- a tie-break decision that disagrees with §7.4;
- a non-deterministic or impure classification;
- any plugin active in the gate run;
- a missing fixture, missing log, or hand-edited TSV value;
- a non-zero exit from any stage.

There is no tolerance, no retry, and no partial pass.

### 12.7 What E6-G does not prove

- It does not prove the selector finds the global minimum.
- It does not prove the cost estimate is accurate; the measured wire is the claim.
- It does not prove throughput or the 1.02× ensemble target; those are report rows (A2).
- It does not prove MAU correctness or CLI atomicity. E7 does.
- It does not prove robustness beyond E3's fuzz campaign.
- It does not prove decode memory on 4 GiB inputs; that is a report row.
- It does not prove coverage on fixtures outside F02–F08.

---

## 13. Freeze rule

When E6-G passes:

1. The selection algorithm, cost weights, tie-break, class decision list, thresholds, budget semantics, and signatures in §8 are frozen.
2. Any change to a weight, threshold, precedence, beam rule, or plugin contract re-runs E6-G **and every later gate**.
3. Gate rows and logs are append-only.

---

## 14. Traceability

| this document | parent |
|---|---|
| §4.2 alternatives | §6.8, §7.1 |
| §4.3 cost | §6.8, Appendix A |
| §4.4 tie-break | §7.4 |
| §4.5 coverage | §12.4 V2-G4 |
| §4.6 noise ratio | §12.4 V2-G5 |
| §4.7 classification | §6.9 |
| §5.3 pipeline | §7.1, §7.3, §6.10 |
| §5.4 plugins | §6.11 |
| E6-G | V2-G1, G2, G3, G4, G5, G14 |

**Derived details.** The parent gives class signatures without precedence, and does not pin `model_bits`, the coverage interval definition, or the H2 sampling policy. Those are pinned in E4/E6 so the gate is reproducible. The cost remains an estimate.

**Demoted rows.** V2-G6 (1.02× ensemble) and V2-G11 (throughput) are report rows under amendment A2. V2-G10 (memory) is a report row under the same resource policy. They do not decide E6-G.

**Decomposition correction.** E6 needs E3's `encoded_size`. The original authority matrix allowed only E0/E7 to call E3. The corrected edge is size-only and read-only; it does not let E6 emit wire.

---

*End of MARP2-E6.*
