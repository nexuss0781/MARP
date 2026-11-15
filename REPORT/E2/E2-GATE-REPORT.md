# E2-G — Integrated `ALGEBRA` Gate — Implementation Report (E2 ALGEBRA)

**Work item:** E2-G, the integrated gate for E2 `ALGEBRA` (§12 of the component spec).
**Component:** E2 `ALGEBRA`, sub-component 5 of 5 (C03 TERM → C04 CANON → C05 EVAL → C06 DAG → **E2-G**).
**Normative sources:**
`SPECS/COMPONENTS/e2-algebra/SPECS.md` §12 (E2-G: steps 1–13, corpus families
T-BAD/T-BIG/T-CRIT/T-GEN/T-KAT/T-NONCANON, coverage, determinism, evidence),
§5.1–5.3 (WF, lengths, ranges), §3.8 (rewrite rules 1–13);
`SPECS/SPECS-V2.md` §2.2 (canonicality), §4.1 (IR invariants), §4.4 (lengths);
`SPECS/COMPONENTS-V2.md` §4.
**Language:** C++20 only. No Python, no shell, and no third-party library in the
gate; the denotation oracle is the H3 clean-room implementation in `harness/oracle`.

**This report claims E2-G only.** It does not claim any wire-level (E3) behaviour,
adds no C03/C04/C05/C06 semantics, and changes no earlier component's evidence.

---

## 1. Environment, base, branch, and toolchain

| Field | Value |
|---|---|
| Repository | `nexuss0781/MARP` |
| Branch | `arena/1fd16877-marp` |
| Base commit | `59c716bfa9e3c3b812499ba63f8a4772e998e2c9` (`h2-gates`, PR #6 merge of C06 DAG) |
| Local toolchain | `g++ 12.2.0` (Debian 12.2.0-14+deb12u1), Linux x86-64 |
| Build | `engine/Makefile.e2g`, `-std=c++20 -pedantic -Wall -Wextra -Werror -Wconversion -Wshadow -Wnull-dereference -Wdouble-promotion -Wformat=2 -O2` |
| Sanitizer build | `bin/e2_g_gate_san`, `-O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all` |
| Gate binary | `engine/bin/e2_g_gate` |
| Invocation | `cd engine && ./bin/e2_g_gate --root .. --write-evidence` |
| Evidence | `specs_and_reports/v2/{gates/E2-G.tsv, logs/E2-G.log, corpus/E2/{corpus,rewrites}.tsv, evidence/E2/{critical_pairs.md, SHA256SUMS}}` |

`E2-G.log` records the tool, root, exact command line and the fixed build-flag set, and is
deliberately compiler-version free — the same property C06 adopted (§6.2 of the C06
report), so the log is byte-reproducible on any conforming C++20 toolchain and the CI
"committed evidence is byte-identical to CI output" step is meaningful.

---

## 2. Files added — and what was **not** touched

**Added under `engine/`:**

| Path | Role |
|---|---|
| `Makefile.e2g` | isolated build: E1 + E2 (all four sub-components) + E2-G harness + H3 oracle; target `bin/e2_g_gate`, `bin/e2_g_gate_san`, `e2g-isolation`, `e2g-evidence`, `e2g-clean` |
| `src/e2/e2g_terms.hpp/.cpp` | `Desc` description arena, `bind()` (description → engine `Ir`), canonical digests, T-BAD constraint plumbing |
| `src/e2/e2g_oracle.hpp/.cpp` | adapter from an engine `Ir` to the H3 oracle's `ParsedContainer`, plus exact-byte range/length/LFSR entry points |
| `src/e2/e2g_corpus.hpp/.cpp` | the six corpus families (§12.2) and the T-CRIT critical-pair templates |
| `src/e2/e2g_report.hpp/.cpp` | evidence writers: TSV rows, log, `corpus/E2/*.tsv`, `evidence/E2/critical_pairs.md` |
| `src/e2/e2g_gate.cpp` | the gate: steps 0–13, verdict, evidence writing, `SHA256SUMS` |

**Added under `harness/oracle/`:** three *accessors* only —
`detail::eval_node_range_iterative` (the same function `eval_full_stream`/`eval_range_stream`
already call), `detail::oracle_node_length` (the stage-8 validator's own length arithmetic)
and the LFSR primitives `lfsr_jump_bytes`/`lfsr_emit`. No oracle behaviour changed; they were
made callable so the gate can compare bytes, lengths and jump-ahead states directly instead of
re-deriving them. The H3 workflow continues to pass.

**Added evidence:** the six files in §1, plus `.github/workflows/e2-g.yml` and this report.

**Not touched:** `include/mapr/e2/**`, `engine/src/e2/e2_{term,canon,eval,dag}.cpp`,
`engine/Makefile`, `Makefile.c03`–`c06`, any C03–C06 test, any C03–C06 evidence file.
`e2-g.yml` fails the build if C03–C06 evidence or `harness/oracle` differ after an E2-G run.

---

## 3. What the gate measures (steps 0–13)

| Step | Check rows | What is asserted |
|---|---|---|
| 0 | `precondition.*` (5) | E0-G/E1-G/H3 evidence present; no E3–E7 object linked; the gate may report a verdict |
| 2 | `corpus.count` (8), `corpus.bind`, `corpus.shape`, `corpus.kat` | corpus sizes against §12.2; every description binds and every bound term is WF |
| 3 | `t_bad.reject` (64), `t_bad.constraint` (21), `t_bad.summary` | each T-BAD term is rejected **with the specific §9 code / §5 constraint the spec names**, not merely "some error" |
| 4 | `step4.t_kat`, `step4.t_gen`, `step4.t_canon` | 128 T-KAT and 5000 T-GEN terms: canonicalisation is WF, idempotent, canonical, denotation-preserving, length-preserving |
| 4b | `step4b.t_big` (64 + 64) | 64 T-BIG terms have length ≥ 2^40 and are never materialised |
| 5 | `t_noncanon.*` (8 × 200 + 13) | 200 non-canonical terms: the expected rule fires, the result is canonical and idempotent, and every one of rules 1–13 fires |
| 6 | `t_crit.{join,wf,rules_exercised}` (3000) | 1000 critical pairs: both members WF, both members' rules fire, and the two full canonicalisations join |
| 7 | `m_kat.*` (207) | morph family (9) and predictor family (5) against the oracle, per kind |
| 8 | `l_kat.*` (538) | LFSR: 432 jump states, 8 large-offset jumps, 48 oracle byte comparisons |
| 9 | `t_range.term` (5192), `t_range.overrun` (67 444), `t_range.big_start` (192) | 13 ranges × 5192 terms against the oracle's exact bytes; every overrun is `Invalid`; T-BIG starts at 2^32, 2^32+1, 2^39 |
| 10 | `dag.order` (1168) | canonical DAG order, root last, no unused node or atom |
| 11 | `coverage.{rule,kind,morph,predictor}` (13/12/9/5) | every rule, node kind, morph and predictor is exercised at least once |
| 12 | `determinism.*` (6) | 1-thread vs 4-thread identity for canon/WF/length/range, and eval-vs-`read_range` agreement |
| 13 | `e2g.summary`, `e2g.verdict` | totals and the final verdict |

Every row is written to `gates/E2-G.tsv` with
`check corpus item_id input_sha256 expected actual verdict log`, so a failure names the term
and the expected value, and `evidence/E2/critical_pairs.md` carries the 1000-pair table.

---

## 4. Verdict

```
RESULT: PASS
# rows: 89729 pass=89729 fail=0
```

`e2g.verdict` = **PASS**; `e2g.summary` = `rows=89727 pass=89727 fail=0` (the two summary rows
are themselves counted in the 89729 total). The run is reproducible byte for byte, and it is
clean under AddressSanitizer + UBSan (`detect_leaks=1`, `-fno-sanitize-recover=all`) with the
TSV identical to the primary run.

---

## 5. Corpus (spec §12.2)

| Corpus | Required | Actual |
|---|---|---|
| T-BAD | 64 | 64 |
| T-BIG | 64 | 64 |
| T-CRIT | 1000 | 1000 |
| T-GEN | 5000 | 5000 |
| T-KAT | 128 | 128 |
| T-NONCANON | 200 | 200 |

All six counts are asserted by `corpus.count` rows and re-asserted independently by the CI
workflow, so a corpus shrinking to make a check pass cannot go unnoticed.

---

## 6. Spec readings, ambiguities, and recorded decisions

The spec is unambiguous about the quantities but silent or self-inconsistent in the places
below. Each decision is marked in the source with the section number it is recorded under.

### 6.1 A critical pair is judged by *both* members rewriting, not by which member is "first"

§12.4 step 6 requires each member of a critical pair to exercise its own rule. The engine's
fixed §5.2 strategy always starts at the lowest-numbered redex, so "member A fires rule `a`"
cannot be asserted as "the *first* firing in A is rule `a`" — several templates legitimately
start with a different rule and reach `a` later. The gate therefore asserts
`ra.rewrites > 0 && rb.rewrites > 0` **after checking that both members join**, which is the
observable content of "each member exercises its rule".

### 6.2 Rule 1 is reachable — but only through rule 5

A probe (`scratch/probe23.cpp`) showed that describing a nested `Concat` never yields a rule-1
redex: `canon_impl`'s `build_node` re-creates every node bottom-up through the smart
constructors, so `concat(x, concat(y,z))` is already associated by the time rewriting starts.
Rule 1 does fire — `mk_concat` fires it (`src/e2/e2_canon.cpp:502-515`) — and it is reachable
in the corpus only when rule 5 expands a `Repeat` into a `Concat` child
(`concat(x, repeat(atom8,1,3))` → rules `[1,3,5,13]`, 6 rewrites). Rule 1 is therefore
exercised (376 firings, `coverage.rule`) and is **not** labelled non-overlappable.

### 6.3 Which rule overlaps cannot be exhibited as a well-formed critical pair

Four families were removed or replaced during development because the pattern they described
is not well formed or not a local overlap, and a corpus that "passes" with an ill-formed pair
proves nothing. What is *not* in the 1000 pairs:

- **rules 9 and 13** — they have no local overlap with each other: a single-child `Interleave`
  is not well formed (§5.1 requires `L mod stride = 0` and the child list to be consistent),
  and rule 13 is an id-ordering property rather than a local rewrite.
- **rule 12** needs two distinct atom records with equal payload — the gate builds both
  explicitly rather than relying on interning.
- **`slice-assoc`** was respun: a `p`-dependent nested-slice spine gave 19 WF failures and 48
  join failures because the two members did not denote the same term. Both members now have
  fixed, in-range sizes over the same base and the same denotation.

### 6.4 T-BAD: one constraint is unreachable, one is reached only by patching the `Ir`

`t_bad.constraint` has **21 rows**, one per §5 constraint the corpus is required to exhibit.
Two needed a decision.

**`W1.counts` (node half) — not exercised through a 2^24-node table.** W1 bounds 2^24 nodes and
2^24 atoms; building 2^24+1 records is not a corpus-sized operation. `bad-counts-nodes` instead
exhibits the *same* W1 row through its **atom** bound: the term is bound under an explicit
`Limits{max_atoms = 1}` and the gate requires `W1.counts`. The constraint identifier asserted is
identical to the one a 2^24-node table would produce; only the half of W1 exercised differs, and
the atom half is the one a corpus can actually build.

**`W8.atom-id` — reachable, but only from a patched `Ir`.** §5.1 checks lengths (W6) before kind
constraints, and it is tempting to conclude that an out-of-table atom id is therefore always a
length failure first. That is wrong, and an earlier draft of this report said so. The term
`Concat(Atom(p), Atom(q), Atom(q))` has every stored length equal to its §4.4 value even after the
**middle** node's payload index is patched past the atom table, because the third node keeps atom
`q` referenced and W2 therefore reports no unused atom. The description format cannot express an
out-of-table atom id (the binder substitutes a dangling reference), so `bind_patched` writes it
into the emitted `Ir` — the same technique `bad-arg-range` uses for an out-of-table child id.
`bad-atom-id` now asserts `Invalid:W8.atom-id` and passes; the earlier `bad-interleave-argc`
entry was dropped because it duplicated the existing `bad-argc-interleave-0` row.

**`W7.depth` is `Limit`, not `Invalid`.** `bad-depth` / `bad-depth-limit` / `bad-manual-depth`
are explicit `Limit` terms, because §9 classifies depth and output-cap exhaustion as `Limit`.
An earlier version of the gate expected `Invalid` here and failed; the corpus, not the engine,
was wrong.

### 6.5 Range sampling: the oracle is a denotation engine, not a bounds checker

`§12.3` pins 13 range samples per term. Two facts forced the sampler's final shape
(`scratch/probe31.cpp`):

1. `oracle_range` **does not bounds-check**. For the empty term it happily reports 1 byte for
   `(0,1)`, while the engine correctly returns `Invalid`. So "compare to the oracle" is only
   meaningful for *in-range* samples; bounds behaviour must be asserted against the spec
   directly. The gate now enforces §5.3 (`start + len <= ℓ`) in `e2g_oracle.cpp` from the
   oracle's **own** structural length analysis, and separately asserts engine-side `Invalid`
   via the `t_range.overrun` rows (67 444 of them, one per term per overrun site).
2. A uniform sampler can produce out-of-range starts on short terms, silently yielding
   "0 samples" and a vacuous PASS. The sampler now always emits `(0,0)`, the spec's five fixed
   ranges guarded by ℓ, and eight seeded samples whose start **and** length are bounded by the
   remaining length.

Two consequences are recorded decisions rather than spec text:

- **The empty term** admits exactly one legal range, `(0,0)`. §12.3 pins 13 samples, so the
  remaining twelve are that same range; the term is still measured 13 times and every sample is
  a legal range. (`tkat-empty`, `tkat-zero0`.)
- **The `(0, ℓ)` sample on T-BIG** is clamped to `min(ℓ, 2^20)`. The gate holds both sides in
  memory, so a literal 2^40-byte comparison is not a definable operation. Every T-BIG property
  §12.4 step 4b actually names — length ≥ 2^40, never materialised, and the `2^32` / `2^32+1` /
  `2^39` / `ℓ-1` starts — is covered by its own rows (`t_range.big_start`, 192 rows;
  `not_materialised.aggregate`).

---

## 7. Known limitations, stated plainly

1. **The W1 *node* bound** is exercised only through W1's atom bound, under an explicit
   `Limits{max_atoms = 1}` (§6.4). Building a 2^24+1-node table is not a corpus-sized operation,
   so the node half of W1 is asserted by this gate's code review, not by a term.
2. **The H3 oracle's range evaluator does not validate bounds.** The gate compensates (§6.5)
   and never relies on the oracle to detect an overrun. The bound check lives in the gate's
   adapter (`e2g_oracle.cpp`) and uses the oracle's own structural length analysis, so it is
   still independent of the engine's length arithmetic.
3. **The T-BIG `(0, ℓ)` range is clamped** to 2^20 bytes (§6.5); the literal full-length
   comparison is not performed.
4. **Rule 1 is only reachable through rule 5 expansion** (§6.2); a corpus of raw nested
   `Concat` descriptions would not exercise it.
5. **The gate is single-threaded** except for the explicit 1-vs-4 thread determinism check
   (step 12), which is the only concurrency this component claims.
6. **The 8 large-offset LFSR jumps** reach 2^39-ish offsets, not 2^64; jump correctness beyond
   that is argued by the GF(2) jump-ahead construction, not measured.

---

## 8. Acceptance checklist (E2-G)

| # | Requirement (spec §12) | Status | Evidence |
|---|---|---|---|
| 1 | Isolated build, E1 + E2 only, no E3–E7 | ✅ | `e2g-isolation` (2 290 symbols, 0 forbidden), `isolation.e3_e7` |
| 2 | Oracle independent of `mapr/` | ✅ | `isolation.oracle_independent`, `e2g.yml` job `independence` |
| 3 | T-BAD 64, each rejected with its named code/constraint | ✅ | `t_bad.reject` 64, `t_bad.constraint` 21 (§6.4 caveat) |
| 4 | T-KAT 128 / T-GEN 5000 canonical, idempotent, denotation- and length-preserving | ✅ | `corpus.count`, `step4.*`, 10 320 `term.verify` rows |
| 5 | T-BIG 64 above 2^40, never materialised | ✅ | `t_big.length_above_2pow40` 64, `not_materialised.aggregate` |
| 6 | T-NONCANON 200, rules 1–13 all fire | ✅ | `t_noncanon.*` 8 × 200, `coverage.rule` 13/13 |
| 7 | T-CRIT 1000 WF, both rules fire, both members join | ✅ | `t_crit.{wf,join,rules_exercised}` 3 × 1000 |
| 8 | M-KAT morph 9/9 and predictor 5/5 against the oracle | ✅ | `m_kat.*` 207 rows |
| 9 | L-KAT jump-ahead and streaming bytes | ✅ | `l_kat.*` 538 rows |
| 10 | Ranges: 13 per term, exact bytes, overruns `Invalid`, T-BIG big starts | ✅ | 72 828 range rows (§6.5 caveat) |
| 11 | DAG canonical order, root last, no unused node/atom | ✅ | `dag.order` 1168 |
| 12 | Coverage: rule 13/13, kind 12/12, morph 9/9, predictor 5/5 | ✅ | `coverage.*` 39 rows |
| 13 | Determinism: 1-vs-4 threads, eval-vs-range | ✅ | `determinism.*` 6 rows |
| 14 | Evidence reproducible, manifest verified, ASan+UBSan clean | ✅ | byte-identical reruns; §4 |
| 15 | No earlier component regressed | ✅ | `e2-g.yml` step *No-regression check* |

---

## 9. Handoff

E2 `ALGEBRA` is complete: C03 TERM, C04 CANON, C05 EVAL, C06 DAG and E2-G each have their own
isolated build, their own workflow and their own committed evidence. The next component (E3)
may consume `include/mapr/e2/**` as frozen; the E2-G workflow will fail if a later change
alters `harness/oracle` or any C03–C06 evidence file.
