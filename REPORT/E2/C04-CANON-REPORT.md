# C04 `CANON` — Implementation Report (E2 ALGEBRA)

**Work item:** C04 `CANON` — canonicalisation to a fixed point, canonical shape,
canonical identity, and the canonical key.
**Component:** E2 `ALGEBRA`, sub-component 2 of 4 (C03 TERM → **C04 CANON** → C05 EVAL → C06 DAG).
**Normative sources:**
`SPECS/SPECS-V2.md` §3.8 (canonicalisation), §2.2, §4.1 (IR invariants), §7.4 (tie-breaking),
§3.1–3.2 (IR/semantics), §3.7 (lengths);
`SPECS/COMPONENTS/e2-algebra/SPECS.md` §4.3 (WF), §4.5 (kind constraints), §4.7 (canonical
shape), §4.8 (canonical traversal and ids), §5.1 (validation order), §5.2 (canonicalisation
strategy), §5.6 (DAG — informative), §5.7 (canonical key), §6 (E2-I4…I7, I11, I12),
§7 (O4.1…O4.5), §9 (error model), §12 (E2-G — **not claimed**);
`SPECS/COMPONENTS-V2.md` §4 (C04);
`SPECS/SPECS-V2.md` §12 (gate structure).
**Language:** C++20 only. No Python, no shell, no third-party library except GoogleTest in
the unit tests.

**This report claims C04 only.** It does **not** claim E2-G, does not claim any wire-level
(E3) behaviour, and does not claim C05 `EVAL` or C06 `DAG`. See §7 for the exact handoff
and the honest list of what was not measured.

---

## 1. Environment, base, branch, and authoritative CI run

| Field | Value |
|---|---|
| Repository | `nexuss0781/MARP` |
| Branch | `arena/7a2621b1-marp` |
| Base commit | `78b817437cf38fc069edcd1bd749ec8e54511966` (`h2-gates`, PR #3 merge of C03 TERM) |
| **Authoritative CI run (C04 implementation commit `ac1625a`)** | **`43644403193` — `MARP E2 C04 CANON CI` — conclusion `success`** |
| **CI run URL** | https://github.com/nexuss0781/MARP/actions/runs/43644403193 |
| CI commit (ac1625a) | `ac1625a03940130a1e24b97c5cadae8f108f920c` |
| **No-regression, C03 CI on the evidence-refresh commit `a356fed`** | **`43644650764` — `MARP E2 C03 TERM CI` — conclusion `success`** (both jobs) |
| No-regression, H3 Oracle CI on `ac1625a` | `43644402697` — conclusion `success` |
| Local toolchain | Debian `g++ 12.2.0`, GNU make 4.3, x86-64 |
| CI toolchain | `ubuntu-latest` (Ubuntu 24.04), `g++ 13.3.0`, GoogleTest built from source at CI time |
| Flags | `-std=c++20 -pedantic -Wall -Wextra -Werror -Wconversion -Wshadow -Wnull-dereference -Wdouble-promotion -Wformat=2 -O2` (E2 §12.4 build level; sanitizer variants add `-fsanitize=address,undefined -O1 -g`) |
| Evidence harness | `engine/src/e2/e2_c04_gate.cpp` → `bin/e2_c04_gate --root .. --write-evidence` |
| Unit tests | `engine/tests/e2/e2_canon_test.cpp` → `bin/e2_c04_tests` (40 cases) |

The report itself is a documentation-only commit; it changes no source and no evidence
file. CI re-runs the identical pipeline on it.

Baseline preserved and verified on this branch (2026-11-14, local):

- `make -f Makefile.e2 e2-all && ./bin/e2_c03_tests` → **33/33 PASS** (with the single
  additive `Atom::owner` change in §2; see §5.10).
- `sha256sum -c specs_and_reports/v2/evidence/E1/SHA256SUMS` / `…/H1/SHA256SUMS` /
  `…/H3/SHA256SUMS` / `…/E2/SHA256SUMS` (updated in `a356fed`) — all **OK**.
- The C04 CI `independence` job re-verifies the E1/H1/H3/E2 manifests on every run.

---

## 2. Files added / changed — and what was **not** touched

Added (11 files):

```text
include/mapr/e2/e2_canon.hpp              C04 public surface (135 lines)
engine/src/e2/e2_canon.cpp               C04 implementation (1633 lines)
engine/src/e2/e2_c04_gate.cpp            evidence harness (1168 lines)
engine/tests/e2/e2_canon_test.cpp        GoogleTest suite (710 lines, 40 cases)
engine/Makefile.c04                      isolated build (includes base Makefile for flags only)
.github/workflows/e2-c04.yml             isolated CI workflow
specs_and_reports/v2/gates/C04-CANON.tsv harness-written evidence (403 data rows + header)
specs_and_reports/v2/logs/C04-CANON.log  harness-written log (34 lines)
specs_and_reports/v2/evidence/C04/SHA256SUMS  harness-written manifest
```

Changed (one pre-existing file, one-line semantic addition):

```text
include/mapr/e2/e2_term.hpp  adds `Atom::owner` (std::shared_ptr<void>, default nullptr)
```

`Atom::owner` keeps the payload storage referenced through `Atom::payload` alive for as
long as the atom lives. `canon` returns **self-contained** `Ir` values (atoms built by
`canon` own their merged/split payload storage through this handle); atoms built by other
tools leave it `nullptr`, matching the pre-C04 contract that the caller keeps storage
alive. No C03 source file, test, Makefile, workflow, or check reads `owner`; the C03
suite passes unchanged (33/33). See §5.10.

Changed (evidence refresh, commit `a356fed`, documented there):

```text
specs_and_reports/v2/gates/C03-TERM.tsv  independence row only: 5 files → 8 files, 0 violations
specs_and_reports/v2/logs/C03-TERM.log   the matching log line
specs_and_reports/v2/evidence/E2/SHA256SUMS  manifest hashes updated to match
```

Rationale: the C03 gate's independence scan covers `include/mapr/e2` and
`engine/src/e2`, and C04 adds three source files there. The committed C03
`C03-TERM.tsv` could otherwise never equal CI's regenerated output on a branch that
contains the C04 sources. This is an evidence regeneration forced by the tree change,
**not** a relaxation: no C03 check was edited, merged, or removed; the only differing
row is the file-count digest; violations stay 0. Without this refresh the C03 CI
byte-for-byte comparison would fail on every such branch (and it did, on the first
push `ac1625a` → run `43644402689`, step *Committed C03-TERM.tsv must match the
CI-generated TSV byte for byte*). After the refresh, C03 CI run `43644650764` is green.

Untouched, verified by the C04 CI `independence` job and by the pre-commit checks:
`SPECS/**`, all H1/H2/H3/E1 evidence and manifests, `engine/Makefile.e2`, `engine/Makefile`,
`engine/src/e2/e2_term.cpp`, `engine/src/e2/c03_build.hpp`, `engine/src/e2/c03_reference.hpp`,
`engine/tests/e2/e2_term_test.cpp`, `.github/workflows/e2-c03.yml`, `.github/workflows/h3-oracle.yml`,
`.github/workflows/e2-c04.yml` (added), all C03 gate rows other than the independence file-count digest.

---

## 3. C04 API / surface implemented

```cpp
// Canonicalisation (E2 §5.2, parent §3.8)
Result<Ir> canon(const Ir& ir);                    // requires WF(ir)
Result<Ir> canon(const Ir& ir, CanonReport& report);
Result<Ir> canon_with_budget(const Ir& ir, u64 max_rewrites, CanonReport* report);

// Validation (E2 §4.7, §5.1)
WfReport check_canonical(const Ir& ir);
WfReport check_canonical(const Ir& ir, const Limits& limits);
bool is_canonical(const Ir& ir);
bool is_canonical(const Ir& ir, const Limits& limits);

// Canonical key (E2 §5.7) and diagnostic equality
std::string canonical_key(const Ir& ir, u32 node);
bool structurally_equal(const Ir& ir, u32 a, u32 b);

// Constraint identifiers, disjoint from the kC_* WF identifiers
constexpr const char* kCanon1 .. kCanon13;          // "C1.concat-child-concat" ..
```

Semantics and error model (E2 §9):

- `canon` requires `WF(ir)`. Non-WF input → `Invalid`, **no** output term. Rewrite-budget
  exhaustion → `Limit`; `CanonReport::budget_exhausted` is set. Nothing throws past the
  API; nothing terminates the process.
- The default budget is `64 * (nodes + 1)` rewrites, derived from the **input** node
  count (O4.1). `canon_with_budget` exposes the budget for testing (an additive
  testability hook mirroring C03's `Limits`).
- `check_canonical` reports the **first** failure in the fixed order: WF constraints in
  §5.1 order (counts, flags, root, reachability, args, lengths, depth, kind constraints),
  then canonical rules `C1…C13` in table order. The WF half is exactly the C03
  `check_well_formed` result, so canonical checks never run on non-WF input via the API.
- `canon` on `WF` input returns a `WF`-valid, canonical `Ir` with the same denotation,
  post-order first-use node ids, children before parents, `root == nodes.size() - 1`
  (E2 §4.8), dense first-use atom ids, no unused nodes or atoms, and structurally
  identical subterms sharing one node.
- `CanonReport` instruments O4.1/O4.5: `rewrites`, `rule_fires[13]` (index `i` counts
  firings of rule `i+1`), `nodes_in/atoms_in/nodes_out/atoms_out`, `budget_exhausted`.
  Instrumentation caveats are documented in §5.5.
- **`Interleave` child order is semantic and is never sorted or reordered (E2-I6)** — no
  rule touches it; a single-child `Interleave` folds to its child (rule 9).
- `canonical_key` is equal for structurally equal subterms and distinct otherwise on
  inputs up to a documented deterministic 1 MiB descriptor cap (§5.11); independent of
  node ids outside the subterm; total and deterministic on any `Ir`. Equality and
  ordering behaviour are normative (E2 §5.7); the byte form is not. Used for `Xor`
  operand order and for diagnostics only.

---

## 4. What `canon` does (algorithm)

The implementation is a single bottom-up rewrite pass over a work arena, followed by a
pruning emission pass.

1. **Work arena.** Nodes are built by per-kind `mk_*` helpers. Every helper first
   rewrites/normalises its result and only then interns it in a hash-cons table keyed by an
   exact descriptor (`work_key`: kind tag, encoded parameters, child **work ids** —
   never pointers, never hashes of pointers, never map iteration order). Two distinct
   records never merge; structurally identical subtrees always do (rule 12).
2. **Atoms.** Adjacent atoms in a `Concat` whose combined length is `≤ ATOM_MAX`
   (1 048 576 bytes) are merged into a fresh atom whose payload is the concatenation of
   the two payloads; an atom record above `ATOM_MAX` is split into `ATOM_MAX`-sized
   pieces (rule 3 both arms). Records are deduplicated by **payload bytes** (exact
   equality), with SHA-256 carried as a key only; colliding digests never merge distinct
   payloads (E2-I11: `klass` never affects anything).
3. **Fixed strategy.** Rules fire in the fixed §5.2 order with the lower-numbered rule
   winning on overlap — realized by construction order: every `mk_*` emits an
   already-canonical sub-result, so a redex at a parent is always detected against
   canonical children. Equivalently, the loop applies rules bottom-up until no rule
   applies; on WF input both strategies coincide because every §3.8 rule is
   subterm-local and denotation-preserving.
4. **Emission.** A post-order first-use traversal from the root assigns the final dense
   ids (children before parents; root last), appends atoms on first encounter
   (E2 §4.8), re-uses the emitted node for structurally identical subterms (rule 12
   again), prunes records that became dead (rule 13: nodes/atoms with no path from the
   root after folding, e.g. the 64 morph nodes cancelled in
   `t-deep-morph-chain`), and renumbers atoms to dense first-use ids.
5. **Denotation preservation.** Every rule is a denotation-preserving local rewrite
   (parent §3.8), so preservation holds by construction; it is additionally *measured* by
   the harness on every materialisable term (47 corpus rows + 19 redex rows + 2
   `ATOM_MAX` rows), comparing `denote_root(ir)` with `denote_root(canon(ir))` byte for
   byte. For virtual (`T-BIG`) terms the denotation is not materialised — `canon` never
   materialises `n` for `Repeat`/`Affine`/`Lfsr` — and only structural checks plus
   idempotence are applied (denotation rows are skipped, and the skip is logged).
6. **Determinism (E2-I5/I7).** Output depends only on the input term: no effort
   parameter, no threads, no clock, no addresses; hash tables are probed, never iterated;
   operand order for `Xor` is by `canonical_key` ascending; `Interleave` is never
   reordered (E2-I6). The gate measures a full extra `canon` pass over every corpus term
   (`determinism-repeat-corpus`) plus in-battery repeated runs (52/52 identical).

---

## 5. Spec readings, conflicts, and decisions

1. **Rule strategy vs. table (§4.7 / §5.2).** E2 §5.2 fixes the order (flatten → empty →
   atoms/zero → repeat → slice → morph → xor → interleave → affine → zero-fold →
   hash-cons → prune) and §4.7 defines canonical shape as "`WF(ir)` holds and no §3.8
   rewrite applies". The implementation follows that preamble literally: `check_canonical`
   reports exactly the applicable rewrites (plus the identity-shape invariants of rule
   13), and `canon` iterates to the fixed point. Where the two readings differ, the
   preamble governs (§5.4, §5.6 below).

2. **`Xor` operand order: parent §3.8 rule 8 vs. E2.** Parent §3.8 orders `Xor` operands
   by `(canonical_bytes, length, child_id)`. `child_id` is construction-order-dependent,
   so that tie-break violates E2-I5/E2-I7 (no construction-order dependence) and is
   unimplementable deterministically. E2 §4.7 rule 8 (the more specific component spec)
   orders operands by `canonical_key` ascending, and E2 §5.7 forbids serialising the wire
   for ordering ("E2 MUST NOT serialise wire to order operands").
   **Decision: `canonical_key` ascending.** The parent's `child_id` tie-break is ignored
   and recorded here. Note `canonical_key` is content-derived and id-independent, so the
   order is a pure function of the two subterms.

3. **Repeat normal form (rule 5): two arms unreachable from WF.** WF (E2 §4.5 kind
   constraint; parent §3.2) requires `r = 0` when `q = 0`, and `0 ≤ r < len(child)` when
   `q ≥ 1`. Therefore on WF input:
   - `Repeat(c, 0, r>0) → Slice(c,0,r)` is **vacuous** (such a term is `Invalid` before
     `canon` runs; the harness pins this with the C03 rejection row family and with
     `canon` returning `Invalid` for non-WF input).
   - `Repeat(c, q, r≥len(c))` is likewise **vacuous** (W8 kind constraint violation).
   The "fold `r` into `q`" arm of `mk_repeat` is kept as a defensive path only and can
   never fire through the public API. The **reachable** rule-5 redexes — `q=0,r=0 → Empty`,
   `q=1,r=0 → child`, `q=1,r>0 → Concat(child, Slice(child,0,r))` — are implemented,
   unit-tested, and measured (redex rows `r5-repeat-*`; rule fired 4× across the gate).
   The normative note that `Slice(c,0,r)` with `0 < r < len(c)` **is** canonical is
   respected: `find_c6` reports only nested-slice / zero-length / full-cover slices, and
   `Slice(c,0,r)` produced by rule-5 normalisation is not further folded (it is not a
   full-cover slice unless `r == len(c)`).

4. **Morph rule 7: table row vs. preamble.** E2 §4.7's row reads "no identity morph; no
   `Morph` child is a `Morph`; no `ROTL8`/`ROTR8` with `k` that composes to identity".
   Taken literally as "any `Morph`-of-`Morph` is non-canonical", it is **unsatisfiable**:
   the v2 catalogue has pairs no §3.8 rule folds — e.g. `REVERSE_BYTES ∘ BIT_REVERSE8 =
   REVERSE_BITS` (morph 9) is a valid composite with no single rewrite; `INVERT8 ∘ SWAP16`
   likewise. Such a term would be irreducible and therefore non-canonical forever, making
   the postcondition "`canon` returns a canonical term" unsatisfiable. The operative
   definition is the §4.7 preamble — *canonical iff WF holds and no §3.8 rewrite
   applies* — which the parent's rule 7 (`two identical involutions cancel; adjacent
   rotations compose; an identity morph is removed`) can satisfy. v2 has no identity
   morph id (id 0 is `Invalid`), so "identity is removed" is vacuous.
   **Decision:** `find_c7` reports rule 7 exactly when an applicable fold exists
   (identical adjacent k=0 involutions; adjacent `ROTL8`/`ROTR8` pairs, which always
   compose modulo 8). Morph-of-Morph pairs for which no fold exists are canonical, per
   the preamble. This is the same reading the implementation applies inside `mk_morph`,
   and the reading under which the fixed strategy terminates (O4.1, measured: 34 rule-7
   firings; `t-deep-morph-chain` cancelled 64 even-count `INVERT8`s → one atom).

5. **`Empty` root and `Slice` of `Empty`.** A canonical term may consist of a single
   `Empty` (the empty term); `find_c2` allows exactly that one shape. A zero-length
   `Slice` of a zero-length child arises only as `Slice(Empty, 0, 0)`, which is WF
   (`start = 0 ≤ ℓ(Empty) = 0`, `0 + 0 ≤ 0`) and folds to `Empty`. The `mk_slice`/`mk_repeat`
   constructors contain defensive arms for `Empty` children and `r = 0` with `ℓ = 0`;
   these are unreachable through the public API on WF input and exist to keep the
   constructors total.

6. **Rule 12 / rule 13 reachability on WF input (identity shape).**
   - *Unreachable nodes/atoms* are `W2` violations ("root &lt; nodes.size(); every node
     reachable; every atom referenced") — **unreachable on WF input**, reported first as
     `W2.*` by `check_canonical`. The arms of `find_c13` for "unreachable records" and
     "root is not the last node" are defensive (they guard emitted output, which the
     first-use emission makes impossible by construction; an earlier internal cut left
     unreachable/shared nodes in the emitted output and `find_c13` caught exactly that;
     the emission was fixed to skip already-emitted shared subtrees and
     `C04Canon.StructurallyIdenticalSubtermsShareOneNode` pins the fixed behaviour).
   - *Atom payload uniqueness*: two atom records with the same payload are always used
     (W2) and their `Atom` nodes are therefore structurally identical, so `find_c12`
     (hash-consing) fires **first** and reports `C12`; the payload-uniqueness arm of
     `find_c13` is likewise unreachable on WF input and kept as a safety net.
   - The **reachable** `C13` arm is **atom first-use order**: atom ids not assigned in
     order of first use (gate redex `r13-atom-first-use-order`; `check_canonical` reports
     `C13.identity-shape`, `canon` restores dense first-use ids).
   - Post-order node ids and dense ids: `emit_canonical` builds them by construction;
     `find_c13` verifies (child &lt; parent, root last, exact identity
     `order[i] == i`).
   Rule 13 pruning is *measured* (input records that became dead are dropped at emission;
   `rule_fires[12] ≥ 1` held across the gate, e.g. 64 pruned morph work nodes in
   `t-deep-morph-chain`, 29 total across the run; `t-nest-morph-slice-xor` and
   `t-deep-morph-chain` log lines show the counts).

7. **Instrumentation honesty (`CanonReport`).** `rule_fires[i]` counts rule `i+1`
   firings; `rewrites` is their sum plus emission pruning. `rule_fires[11]` (rule 12)
   counts hash-cons hits; `rule_fires[12]` (rule 13) counts **emission pruning only** —
   atom renumbering to dense first-use order, a rule-13 duty, is *not* counted, and the
   redex `r13-atom-first-use-order` is therefore evidenced by a dedicated semantic row
   (`dense first-use ids restored`) instead of the rule counter; this is stated in the
   harness itself. A no-op canonical input canonicalised with budget 0 succeeds with
   `rewrites == 0` (evidence row `budget-zero-noop`).

8. **`canonical_key` cap (deliberate deviation from §5.7's "distinct otherwise").**
   Both the public `canonical_key` and the internal arena ordering key are capped at
   1 MiB of descriptor bytes and truncated deterministically; atoms above that size are
   identified by `(length, sha256)` regardless (SHA-256 block + 8 length bytes total per
   atom, so the atom table is unaffected). Above the cap, two *distinct* subterms with
   equal 1 MiB descriptor prefixes compare equal; ordering then falls back to the input
   operand order of the `Xor` node, which is deterministic and, by commutativity of
   `Xor`, denotation-safe. The hash-consing/identity path does **not** use the capped key
   at all (see §5.9), so distinct subterms are never *merged*; only the operand order of
   `Xor` and diagnostics see ties. Real corpus terms produce keys of a few KiB. The cap
   exists so a hostile descriptor cannot exhaust memory; removing it (restoring full
   injectivity) is a one-line change if a future E2 revision demands it. Recorded as a
   conscious, bounded deviation, not as a hidden property.

9. **Identity vs. ordering keys.** `work_key` (hash-cons interning) is exact and
   uncapped: kind tag + encoded parameters + child work ids (uvarint) — no cap, no
   hashing of pointers, no map iteration. `arena_key` (used for `Xor` ordering) and
   `canonical_key` (public) share the same pre-order descriptor encoding and the same cap.
   `child_id ≥ self` in a *non-canonical* input maps to a deterministic `\xFF?` marker;
   out-of-range atom id maps to `\xFE`; both keep the functions total on arbitrary `Ir`
   (tested: `CanonicalKeyIsIdIndependentAndTotal`, `key-out-of-range`).

10. **`Atom::owner` (the one additive change to C03's surface).** `canon` merges/splits
    atoms, i.e. it *invents* payloads (e.g. merged `A‖B`, split 1 MiB pieces). Pre-C04,
    `Atom::payload` was a view tied to caller storage; a `canon`-returned `Ir` would dangle.
    The additive `Atom::owner` handle (default `nullptr`) makes `canon` outputs
    self-contained without touching any C03 code path, test, or evidence row. C03's
    acceptance evidence does not hash or depend on the `Atom` struct layout, and the
    C03 suite passes 33/33 on this tree. If a future cleanup removes `owner`, `canon`
    must carry an owned payload deque alongside the `Ir` instead — same semantics, wider
    API; the handle was chosen as the minimal additive change.

11. **Fixed-order first failure (§5.1, §4.7).** `check_canonical` evaluates WF first
   (the C03 report, §5.8 there, documents the W5 placement), then `C1…C13` in table
   order; each finder is a pure scan with no shared state; the first failure wins. The
   unit tests pin representative first-failure orderings (`CheckCanonicalReportsFirstFailureInRuleOrder`);
   the gate pins it per redex (each `redex-first-failure` row).

12. **`ATOM_MAX` boundary semantics.** Atom length is payload bytes; `1 MiB = 1 048 576`
    is a format constant, not an effort parameter (E2 §4.7, parent §3.8 rule 3). Adjacent
    atoms with `sum ≤ 1 MiB` merge (left-to-right with a trailing fixup loop, so freshly
    merged pieces re-merge left); a source atom **above** 1 MiB is split into a final 1 MiB
    piece plus the remainder (rule 3). Gate rows: exact-1 MiB merge (passes, denotation
    equal), above-1 MiB stay-split (passes), 1 MiB+7 split (two atoms, `1 048 576` + `7`,
    denotation equal). `known-accepted` splits/merges are denoted identically before/after.

13. **Determinism vs. construction order (E2-I7).** Nothing in `canon` depends on node
    construction order beyond the input term's own argument order: the hash-cons table is
    probed by exact key (never iterated), the memo tables are vectors indexable by work id,
    and the emission traversal visits children in argument order. The gate re-runs `canon`
    over every corpus term twice and requires structural equality of the outputs; the C03
    `structural_key` fingerprinting of inputs is used for the `input_sha256` column.

14. **Success gate boundary.** E2-G requires (§12.2) the full corpus program: T-KAT v2
    scale, T-GEN (5 000 seeded terms), T-BIG, T-BAD, T-NONCANON (200), T-CRIT (1 000
    critical-pair order comparisons), range probes against the independent oracle, Dag
    shuffles, thread re-runs, and `rewrites.tsv`. **None of that is claimed here.** This
    report measures O4.1 (budget respected on every gate term), O4.3 (denotation
    preserved vs the **engine's own** `denote_root`, not the independent H3 oracle), O4.4
    (idempotence + canonical output), O4.5 (every rule fired ≥ 1 in the gate), and
    E2-I4/I5/I6/I7/I11/I12 on the measured set. O4.2 (critical pairs) is **not measured**
    — no T-CRIT corpus exists yet. See §7.2.

---

## 6. Evidence summary

| Artifact | Value |
|---|---|
| Gate TSV | `specs_and_reports/v2/gates/C04-CANON.tsv` — 403 data rows + header, **0 FAIL**, schema 8 columns |
| Gate log | `specs_and_reports/v2/logs/C04-CANON.log` — `RESULT: PASS (C04 CANON)`, 402 checks, 121 rule firings |
| Manifest | `specs_and_reports/v2/evidence/C04/SHA256SUMS` — `sha256sum -c` OK (verified locally and in CI) |
| Unit tests | 40/40 PASS (also 40/40 under ASan+UBSan) |
| Gate under ASan+UBSan | runs clean, byte-identical TSV (CI step) |
| Corpus | 52 pinned T-KAT terms (12 kinds, 9 morphs, 5 predictors, LFSR vectors, empty term, atom boundary) + 5 T-BIG virtual terms |
| Redex corpus | 19 well-formed non-canonical terms, one or more per rule `C1…C13`, each pinned to the expected first-failure constraint, the rewrite correctness, denotation, idempotence, and the rule counter |
| `ATOM_MAX` gate cases | exact merge at 1 MiB, no-merge above 1 MiB, split of 1 MiB+7 |
| Denotation | equal before/after `canon` on 47 T-KAT rows + 19 redex rows + 2 boundary rows (vs `denote_root`); skipped for 5 T-BIG virtual terms (logged) |
| Idempotence | 52/52 corpus, 19/19 redex fixed points |
| Determinism | repeat run over all 52 corpus terms: 0 mismatches (plus per-term in-battery repeats) |
| `canonical_key` | out-of-range total function; id independence; injectivity over all corpus node pairs (0 mismatches); payload-addressed atoms |
| Budget | `Limit` on budget 0 with work pending; `Ok` on budget 0 with no work pending; `rewrites ≤ 64·(n+1)` on default budget; report accounting consistent |
| Coverage | all 12 kinds, 9/9 morph ids, 5/5 predictor ids exercised by corpus construction; **13/13 rewrite rules fired ≥ 1** (C1 ×1, C2 ×4, C3 ×2, C4 ×1, C5 ×4, C6 ×4, C7 ×34, C8 ×4, C9 ×1, C10 ×2, C11 ×3, C12 ×32, C13 ×29) |
| C03 no-regression | 33/33 tests; C03 CI run `43644650764` green after the `a356fed` evidence refresh; E1/H1/H3/E2 manifests verified in the C04 CI independence job |
| C04 CI | run `43644403193` success (jobs: independence, build-test-evidence); byte-for-byte TSV reproduced on the CI toolchain; sanitizer suite green |
| Independence | `nm`/`grep` scans: 0 forbidden includes (E3–E7/harness/container), 0 forbidden symbols; 8 files scanned, library scan clean |

Row census (checks that must appear, enforced by the CI schema step):
`canon`, `canon-canonical-out`, `canon-idempotent`, `canon-determinism`, `canon-denotation`,
`redex-first-failure`, `rewrite`, `rewrite-canonical-out`, `rewrite-denotation`,
`rewrite-idempotent`, `rewrite-rule-fired`, `coverage.rule` (13 rows, one per rule),
`coverage.kind`, `coverage.morph`, `coverage.predictor`, `atom-max-exact-merge`,
`atom-max-over-stay-split`, `atom-max-oversize-split`, `atom-max-exact-merge-denotation`,
`atom-max-oversize-split-denotation`, `key-out-of-range`, `key-id-independent`,
`key-injective-corpus`, `key-payload-addressed`, `budget-zero-limit`, `budget-zero-noop`,
`budget-default-64x`, `presupposition-wf-required`, `report-accounting`,
`determinism-repeat-corpus`, `independence`, `independence.library`, `c04.summary`.

---

## 7. Known limitations and handoff

### 7.1 Not claimed by this work

- **E2-G is not claimed.** E2-G (§12.2) needs the full corpus program and the independent
  oracle comparison; this work builds the C04 sub-component and its own evidence only.
- **O4.2 (critical pairs) is not measured.** No `T-CRIT` corpus exists; no two-order
  comparison has been run. The fixed-order strategy is the design's answer to confluence
  risk (§5.1), not a proof.
- **O4.3 was measured against the engine's own `denote_root`**, not against the
  independent H3 oracle. Cross-oracle agreement is part of E2-G, not of C04.
- **No C05 (`EVAL`) or C06 (`DAG`) code** is claimed; range evaluation, cursor/stream
  sinks, LFSR jump-ahead assembly, and `Dag` are out of scope here.
- **No E3–E7 code** is linked or referenced (CI enforces this; §6).
- **`E2-G` will not be green until C05 and C06 land** with the same evidence discipline.

### 7.2 Deliberate scope edges inside C04

- The rule-5 fold arm and the zero-`ℓ` slice/repeat defensive paths are unreachable from
  WF input (§5.3, §5.5); they exist to keep the constructors total, are unit-exercised
  only through the internal paths, and are **not** counted as evidence of reachable
  coverage.
- Rule 13's prune counter does not include atom renumbering; the redex `r13-atom-first-use-order`
  evidences that duty semantically (`dense first-use ids restored`) rather than through
  `rule_fires[12]` (§5.7).
- `canonical_key` and the arena ordering key truncate at 1 MiB deterministically
  (§5.8); the identity/hash-cons path is unaffected and exact (§5.9).
- `Atom::owner` is an additive, default-`nullptr` handle; C03's caller-owns-storage
  contract is unchanged (§5.10).
- The 64-rewrite deep-morph-chain (65 nodes → 1 atom) is the largest rule-firing count
  observed in the gate; `canon`'s default budget on that input is 64·66 = 4 224.
- The gate's corpus is pinned (not seed-generated); there is no `T-GEN`-scale fuzzing in
  C04; idempotence and determinism are measured on 52 pinned terms, not on 5 000.

### 7.3 Handoff to C05 / C06 / E2-G

- **C05 `EVAL`** consumes canonical IR: it may rely on ids being post-order first-use,
  root last, atoms dense-first-use, subterms shared (structural equality ⇔ pointer
  equality of work ids after interning — but note the `Ir` returned by `canon` is a
  plain vector IR; the sharing is observable only as repeated subtrees with equal
  `canonical_key`, not as pointer identity). Range evaluation on canonical shapes is the
  natural next measurement.
- **C06 `DAG`**: `Dag::finish` must reuse the work-arena interning and the first-use
  emission (`emit_canonical`) from `e2_canon.cpp` — it is the reference implementation of
  "intern equal subterms and equal atom payloads, then emit post-order first use".
  C06 should not fork a second copy.
- **E2-G**: needs T-GEN/T-CRIT/T-RANGE and the H3 oracle; the `rewrites.tsv` instrumentation
  in `CanonReport` is the seed of O4.1/O4.5's per-term counters.
- **Upstream text debt (pre-existing, inherited from C03):** the `Repeat(c,0,r>0)`
  normal form is `Invalid` in WF yet described as a rule-5 rewrite (C03 report §5.5); the
  `LINEAR2` predictor formula (C03 report §5.4). Neither is this report's to fix; both are
  recorded for the format freeze.

### 7.4 Acceptance checklist (this work)

| Requirement | Status |
|---|---|
| Implementation builds clean with strict `-Werror` flags incl. `-Wconversion` | ✅ |
| `canon` returns denotation-preserving, canonical, idempotent output on WF input | ✅ (measured, §6) |
| Non-WF input → `Invalid`; budget exhaustion → `Limit`; nothing throws past the API | ✅ (tests + evidence rows) |
| Canonical shape = fixed-order first failure; `WF` reported first | ✅ (tests + redex rows) |
| Post-order first-use ids; root last; dense first-use atom ids; no unused records | ✅ (`find_c13` + emission; measured) |
| `Interleave` never reordered | ✅ (test `InterleaveOrderIsNeverSorted`, E2-I6) |
| Hash-consing (rule 12); atom dedup by payload bytes exact (rule 13) | ✅ (tested; 32/29 firings) |
| Determinism: no pointer/hash/iteration/construction-order dependence | ✅ (E2-I5/I7 tests + gate determinism rows) |
| `ATOM_MAX = 1 048 576` split/merge boundary | ✅ (gate rows + unit tests) |
| E2-I4 (idempotence), E2-I11 (klass unused), E2-I12 (no mutable globals) | ✅ (tested) |
| E2-I5 (no effort/thread/time dependence) | ✅ (single-threaded; budget purely input-derived) |
| O4.1 budget `64·(n+1)` respected | ✅ (instrumented; measured max well below bound) |
| O4.4 `canon∘canon = canon` | ✅ (52/52 + 19/19 fixed points) |
| O4.5 every rule fires ≥ 1 | ✅ (13/13 coverage rows) |
| O4.3 denotation preserved | ✅ vs `denote_root` (not vs oracle — E2-G scope) |
| O4.2 critical pairs | ❌ not measured (§7.1) |
| Evidence committed; manifest verifies; TSV reproduced byte-for-byte in CI | ✅ (CI run `43644403193`) |
| C03 unaffected (33/33 tests; C03 CI green on this branch) | ✅ (run `43644650764`; evidence refresh `a356fed` documented in §2) |
| E2-G | ❌ **not claimed** (§7.1) |
