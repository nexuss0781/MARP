# C06 `DAG` — Implementation Report (E2 ALGEBRA)

**Work item:** C06 `DAG` — identity inside the term: interning, canonical ordering,
sharing, and id assignment via the `Dag` builder.
**Component:** E2 `ALGEBRA`, sub-component 4 of 4 (C03 TERM → C04 CANON → C05 EVAL → **C06 DAG**).
**Normative sources:**
`SPECS/SPECS-V2.md` §2.2 (canonicality invariants), §4.1 (IR invariants), §7.3 (serialised
hash-consing), §3.1–3.2 (IR/semantics), §4.4 (lengths);
`SPECS/COMPONENTS/e2-algebra/SPECS.md` §4.2 (IR), §4.3 (WF), §4.5 (kind constraints),
§4.7 (canonical shape), §4.8 (canonical traversal and ids), §5.6 (DAG construction),
§5.7 (canonical key), §6 (E2-I3, I4, I6, I7, I11, I12), §7 (O6.1–O6.4 context),
§8 (C++ surface), §9 (error taxonomy), §11 (determinism and resources), §12 (E2-G — **not claimed**);
`SPECS/COMPONENTS-V2.md` §4 C06.
**Language:** C++20 only. No Python, no shell, no third-party library except GoogleTest in
the unit tests.

**This report claims C06 only.** It does **not** claim E2-G, does not claim any wire-level
(E3) behaviour, and does not add or change C03/C04/C05 semantics. See §7 for the exact
handoff and the honest list of what was not measured.

---

## 1. Environment, base, branch, and authoritative CI run

| Field | Value |
|---|---|
| Repository | `nexuss0781/MARP` |
| Branch | `arena/8997f281-marp` |
| Base commit | `b6125cde28149a831566c7d15f90b83d1cfb5c17` (`h2-gates`, PR #5 merge of C05 EVAL) |
| Implementation commit | `5567608200df829764190830c4303b1a285da9e4` |
| Evidence-bookkeeping commit | `6c72655` (source-scan rows, §2.1) |
| **Authoritative CI run (C06 DAG, on `6c72655`)** | **`43697399789` — `MARP E2 C06 DAG CI` — conclusion `success`** (both jobs, 27/27 steps) |
| **CI run URL** | https://github.com/nexuss0781/MARP/actions/runs/43697399789 |
| No-regression, C03 TERM CI on `6c72655` | `43697399782` — `success` (18/18 steps) |
| No-regression, C04 CANON CI on `6c72655` | `43697399836` — `success` (18/18 steps) |
| No-regression, C05 EVAL CI on `6c72655` | `43697399777` — `success` (18/18 steps) |
| No-regression, H3 Oracle CI on `6c72655` | `43697399833` — `success` (16/16 steps) |
| Local toolchain | Debian `g++ 12.2.0`, GNU make 4.3, x86-64 |
| CI toolchain | `ubuntu-latest` (Ubuntu 24.04), `g++ 13.3.0` (recorded as a CI notice, not in the manifest — §6.2) |
| Flags | `-std=c++20 -pedantic -Wall -Wextra -Werror -Wconversion -Wshadow -Wnull-dereference -Wdouble-promotion -Wformat=2 -O2` (E2 §12.4 build level); sanitizer variants add `-fsanitize=address,undefined -fno-sanitize-recover=all -O1 -g` |
| Evidence harness | `engine/src/e2/e2_c06_gate.cpp` → `bin/e2_c06_gate --root .. --write-evidence` |
| Unit tests | `engine/tests/e2/e2_dag_test.cpp` → `bin/e2_c06_tests` (20 cases) |

The C06 CI job on `6c72655` re-verified, on GitHub's infrastructure: the strict `-Werror`
build, source- and link-level isolation from E3–E7/harness, all 20 unit tests, the
byte-for-byte identity between the committed `C06-DAG.tsv`/`C06-DAG.log` and the
CI-generated ones, the evidence schema and every required check, an independent re-run
determinism check, both ASan+UBSan runs (suite and evidence harness), the evidence
manifest, and that the C03/C04/C05 evidence files were **not** modified by the C06 run.
The whole-workflow conclusion is `success`.

`ci.yml` triggers on `master`/`main`/`h2-gates` and does not run on `arena/**` branches, so
the push of `6c72655` triggered exactly the five workflows listed above.

### 1.1 What CI actually asserted (C06 job)

| Step | Assertion |
|---|---|
| independence job | no E3–E7/harness include under `include/mapr/e2` or `engine/src/e2`; no `.py`/`.sh` under an E2 path; `sha256sum -c` on the E1, H1, H3, E2(C03), C04 and C05 manifests |
| Build C06 | `make -f Makefile.c06 c06-clean && make -f Makefile.c06 c06-all -j4` under `-Werror` |
| Independence (binary) | `make -f Makefile.c06 c06-isolation` + `nm -C` on both C06 binaries for `mapr::(container\|Encoder\|Decoder)::` and `marp::harness::` |
| Committed evidence | `sha256sum -c evidence/C06/SHA256SUMS` **before** regeneration |
| Unit tests | `./bin/e2_c06_tests` → 20/20 PASS |
| Regeneration | `./bin/e2_c06_gate --root .. --write-evidence` |
| Byte identity | `diff` of the committed vs. CI-generated `C06-DAG.tsv` **and** `C06-DAG.log` |
| Schema | 8 tab-separated columns, header exact, every verdict `PASS`, 15 required check ids present, 13 `errors` rows, kind 12/12, morph 9/9, predictor 5/5, every `o6.2.shape` row the full canonical-shape string, threaded row `4/4`, `RESULT: PASS (C06 DAG)` in the log, manifest self-check |
| Determinism | a second evidence run reproduces both files byte for byte |
| Sanitizers | `c06-test-san` (20/20) and `e2_c06_gate_san` reproducing the committed TSV |
| Restore | primary evidence re-generated and manifest re-verified |
| No regression | `git diff --quiet` on the C03/C04/C05 gate and log files |

Baseline preserved and verified on this branch (2026-11-15, local):

- `make -f Makefile.e2 e2-all && ./bin/e2_c03_gate --root ..` → 1321/1321 PASS.
- `make -f Makefile.c04 c04-all && ./bin/e2_c04_gate --root ..` → PASS.
- `make -f Makefile.c05 c05-all && ./bin/e2_c05_gate --root ..` → PASS (162 checks).
- `sha256sum -c` on the E1, H1, H3, E2(C03), C04, C05 and C06 manifests — all OK.

---

## 2. Files added / changed — and what was **not** touched

Added (9 files):

```text
include/mapr/e2/e2_dag.hpp                    C06 public surface (130 lines)
engine/src/e2/e2_dag.cpp                     Dag + finish implementation (480 lines)
engine/src/e2/e2_c06_gate.cpp                evidence harness (1253 lines, 255 checks + summary row)
engine/tests/e2/e2_dag_test.cpp              GoogleTest suite (670 lines, 20 cases)
engine/Makefile.c06                          isolated build (E1 + E2 only; c06-isolation target)
.github/workflows/e2-c06.yml                 isolated CI workflow (239 lines)
specs_and_reports/v2/gates/C06-DAG.tsv       harness-written evidence (256 data rows + header)
specs_and_reports/v2/logs/C06-DAG.log        harness-written log
specs_and_reports/v2/evidence/C06/SHA256SUMS harness-written manifest
```

Changed (evidence bookkeeping only — §2.1):

```text
specs_and_reports/v2/gates/C03-TERM.tsv, logs/C03-TERM.log, evidence/E2/SHA256SUMS
specs_and_reports/v2/gates/C04-CANON.tsv, logs/C04-CANON.log, evidence/C04/SHA256SUMS
specs_and_reports/v2/gates/C05-EVAL.tsv, evidence/C05/SHA256SUMS
```

Intentionally **not** touched: `include/mapr/e2/e2_term.hpp`, `e2_canon.hpp`, `e2_eval.hpp`,
every `engine/src/e2/e2_{term,canon,eval}.cpp`, `c03_build.hpp`, `c03_reference.hpp`, the
C03/C04/C05 Makefiles and gate binaries, `engine/Makefile`, `engine/Makefile.e2`,
`harness/`, `tests/`, and anything wire (E3), container, discovery, rewrite, selection,
CLI (E4–E7). The C06 header is purely additive: no existing header, source file, or
signature changed.

### 2.1 The one bookkeeping change, and why it is not a regression

The C03/C04/C05 harnesses each emit a `independence` row whose `actual` column counts the
`.hpp`/`.h`/`.cpp` files under `include/mapr/e2` and `engine/src/e2` (their source-scan
coverage). C06 adds three files to those directories (`e2_dag.hpp`, `e2_dag.cpp`,
`e2_c06_gate.cpp`), so that count legitimately moves from `11` to `14` and the tree digest
moves with it. Both CI workflows re-run their harness and require the committed TSV to be
byte-identical, so the row had to be refreshed — the exact additive bookkeeping C05 already
did to C03/C04 (see `REPORT/E2/C05-EVAL-REPORT.md` §1.1).

The regenerated diff, verified after the fact, is **only** that row:

```diff
-independence  C04  source-scan  98e9dab5…  0 forbidden includes  0 forbidden includes across 11 files  PASS
+independence  C04  source-scan  95c14016…  0 forbidden includes  0 forbidden includes across 14 files  PASS
```

`violations=0` and `PASS` are unchanged; no C03/C04/C05 *check* changed, no test changed,
no verdict changed. `C05-EVAL.log` was restored byte-for-byte (it carries a process RSS
figure, so re-running the harness on a differently-loaded machine perturbs it); only the
source-scan row of `C05-EVAL.tsv` changes, and `evidence/C05/SHA256SUMS` was recomputed
over the unchanged log and the refreshed TSV. CI verified all of this: the C03/C04/C05 jobs
reproduce their committed evidence byte for byte on `6c72655`.

---

## 3. C06 API and `finish` design

### 3.1 Surface

Exactly the surface of E2 §5.6 / COMPONENTS-V2 §4 C06, plus a `Limits` constructor and
diagnostic accessors (all additive):

```cpp
namespace marp::v2 {
class Dag {
public:
    Dag();                                   // default Limits (W1 = 2^24, W7 = 2^16)
    explicit Dag(const Limits& limits);      // W1 counts + W7 depth bound
    Result<u32> add_atom(std::span<const u8> payload, u8 klass = 0);
    Result<u32> add_node(Node node);         // args must already be ids in this Dag
    Result<Ir> finish(u32 root) &&;          // canonical post-order ids
    u32 node_count() const noexcept;         // builder-local events
    u32 atom_count() const noexcept;         // builder-local events
    const Limits& limits() const noexcept;
    const Node& builder_node(u32 id) const;
    std::span<const u8> builder_atom_payload(u32 id) const;
    u8 builder_atom_klass(u32 id) const;
};
}
```

Move-only (a `Dag` is used once); `finish` is `&&`-qualified as the spec writes it. Nothing
throws across the boundary; every fallible path returns `Result<T>`.

### 3.2 Construction semantics

- `add_atom` **copies** the payload (the caller's span need not outlive the call) and
  returns a builder-local atom id. `klass` is advisory (E2-I11): it is stored on the
  record, never read for control flow, and never participates in payload identity.
  Empty payload → `Invalid` (a zero-length `Atom` is not a WF term, E2 §4.5); atom count at
  `max_atoms` → `Limit`.
- `add_node` validates what is *local to the call*: kind domain (`< kKindCount`),
  `flags == 0`, every `arg` already an existing builder node id, `Atom` argc 0 and its `a`
  an existing builder atom id, W1 node count, and W7 depth (`1 + max(child depth)`,
  `Empty` = 0, bound inclusive). Unknown references → `Invalid`; count/depth exhaustion →
  `Limit`. Everything else (argc tables, `r < len(child)`, `Xor` length equality,
  `Interleave` stride/length, `Slice` bounds, morph/predictor domains, §8.3 output cap) is
  a property of the *term*, not of the event, so it is reported by `finish` — one place,
  one code, the C03-pass order.
- `Node::length` supplied by the caller is **ignored and recomputed** from structure
  (E2 §4.4, `BigInt` throughout), exactly as E1/E2 demand: lengths are never trusted.
  Fields a kind does not own are normalised to their neutral value so they cannot split an
  intern key (`normalise()`), and `flags` is forced to 0 for the emitted record.

### 3.3 `finish(root)` — canonical emission

One **serial** pass (SPECS-V2 §7.3) on an explicit `std::vector<Frame>` stack (no recursion,
so a 2^16-deep chain cannot overflow the C stack):

```
push {root, 0}
while stack non-empty:
    top = stack.back()
    if top.next_child < args.size():        # visit children in argument order
        child = args[top.next_child]; ++top.next_child
        if child not yet emitted: push {child, 0}
        continue                            # continue => enter child first
    if top already emitted: pop; continue   # shared subterm, already interned
    build output node from emitted child ids (+ atom record id lookup)
    if intern key already present: map to existing id; pop; continue
    append node; record key -> new id; pop
```

Properties that follow by construction:

- **Post-order first use / topological.** A node is appended only after every child has
  been emitted, so every child id is strictly smaller than its own.
- **Root last.** The traversal starts at `root`, which is therefore the last node appended;
  `root == nodes.size()-1` is then asserted, not assumed.
- **No unused records.** Only nodes reachable from `root` are emitted; atoms are appended
  on first encounter during that traversal, so no atom record is unreferenced and atom ids
  are first-use order.
- **Sharing.** The intern key is `kind ‖ own params ‖ argc ‖ output child ids`. Because
  children are already canonical output ids, the key is a pure function of the subterm, and
  an identical subterm encountered anywhere produces the same key → one node. Verified
  externally as `distinct(canonical_key) == nodes.size()` on every corpus term (§4).
- **Atom dedup.** Key = the exact payload bytes, a refinement of the normative
  `(length, SHA-256)` key: equal bytes always agree on `(length, SHA-256)`, and a SHA-256
  collision between two *different* payloads can never merge them (that is `Mismatch` at
  E3, never a merge permit). Emitted `Atom` records carry `length`, `sha256` and a
  lifetime-extending `owner` handle, the C04 convention.
- **Determinism.** No pointer value, address, allocation index, thread, or hash-map
  iteration order ever reaches the output. The two `unordered_map`s are **probed only**;
  emission order comes exclusively from the traversal. Id assignment is therefore a pure
  function of the logical term (E2-I7).
- **Exactness.** Every length is a `BigInt`; there is no `u64` intermediate, no floating
  point, and no `double` anywhere in C06.
- **Validation.** The emitted term is handed to `check_well_formed(ir, limits)` before it is
  returned, so a term that a caller built out of contract is rejected with the normative
  code (`Invalid`, or `Limit` for the §8.3 2^63 cap) rather than emitted.

Scope discipline: `finish` performs **only** the canonical traversal/identity emission
required by §4.8. It does **not** rewrite (`CheckRepeat` normal forms, atom merging, `Xor`
operand ordering, …) — that is C04 — and it does not evaluate, encode, or select.

Complexity: `O(nodes + atoms)` time for the traversal plus `O(bytes)` SHA-256 for each
*first-use* atom; `O(nodes + atoms)` memory plus the intern-key strings. Depth is bounded by
W7 and the traversal stack is heap-allocated.

---

## 4. Determinism / sharing / shape results (O6.1–O6.3)

Corpus: **39 logical terms** (see `C06-DAG.tsv`), covering every kind (12/12), every morph
id (9/9), and every predictor id (5/5), plus duplicate-payload terms, diamonds, a
24-child wide `Concat` with repeated children, a 300-deep unary chain, a 10-level `Xor`
chain, `Zero(2^40)`, and a composite term that stacks `Lfsr → Predictor → SWAP64 →
REVERSE_BITS → Interleave → Repeat → Slice`.

| Obligation | Measurement | Result |
|---|---|---|
| **O6.1** construction order does not affect ids | For each term, 9 construction orders (`orders[0]` = natural, 8 = independent random linear extensions via randomised Kahn) through `Dag`; **every** emitted field compared, not just a digest: `kind`, `flags`, `args`, `a`, `b`, `morph`, `morph_k`, `lfsr_conn/init`, `affine_start/step`, `predictor_id/param`, every stored `length`, `root`, `total_length`, and every atom `(klass, length, sha256, payload bytes)`. Half the orders also register atom payloads in reverse order. | **39/39 rows `9/9 orders byte-identical`** |
| **O6.1** thread completion order | 4 threads concurrently replay `e-composite-all` from different construction orders and different atom-registration directions | **`4/4 threads identical Ir`** |
| **O6.1** repeat determinism | every corpus term rebuilt 3 more times (alternating atom order) and compared to the first | **`117/117 identical`** |
| **O6.1** atom insertion order | same logical term, payloads registered forward vs. reversed | **identical `Ir`** |
| **O6.2** `root == nodes.size()-1`, no unused records | per term: root-last, every `arg < id`, every node reachable from root, every atom referenced, `total_length == nodes[root].length`, `check_well_formed` `Ok` | **39/39 rows `root-last+topological+no-unused-nodes+no-unused-atoms+total-length+wf`** |
| **O6.1/O6.2** maximal interning | per term: `#distinct canonical_key == nodes.size()` (C04's id-free key, so this is not a tautology) and `#distinct payloads == atoms.size()` | **39/39 rows PASS** |
| **O6.3** no two atom records share a payload | per term: distinct payload count vs. atom count | **39/39 rows `n/n distinct payloads`** |
| **O6.3** duplicate registration | same payload registered twice but used once → one record | **`1 atom record`** |
| Errors / limits | 13 rows: empty payload, missing child, unknown atom, kind domain, non-zero flags, unknown root, ill-formed at `finish` (argc), `Xor` length mismatch, node/atom count `Limit`, depth `Limit` (bound inclusive: depth 3 == `max_depth` is `Ok`, depth 4 is `Limit`), §8.3 output cap `Limit` | **13/13 PASS** |
| Integration | per term: `Dag` output vs. the C03 reference denotation vs. C05 `eval_stream`; `canon` of a canonical `Dag` output reproduced exactly, otherwise denotation-preserving and idempotent | **39/39 + 39/39 PASS** |
| Isolation | source scan of `include/mapr/e2` + `engine/src/e2` | **`0 forbidden includes across 14 files`** |

Totals: **255 checks, 255 PASS, 0 FAIL**, plus the `c06.summary` row — `RESULT: PASS (C06
DAG)`. Of these, 32 terms are canonical in C04's sense (`canon(dag)==dag`), 6 are
deliberately not (`canon(dag) preserves denotation`), and 1 — `e-zero-2pow40` — has a
declared length above the harness's 4 MiB materialisation cap, so its denotation row pins
that the C03 surface returns `Limit` rather than approximating (§7.1).

The harness is deterministic: two independent CI runs and repeated local runs produce
byte-identical `C06-DAG.tsv` and `C06-DAG.log`, and the ASan+UBSan build reproduces the same
TSV.

### 4.1 What would have to break for a false PASS

The order-independence row compares two *different* replays of the same logical term, so it
cannot pass if `finish` leaked a construction id: for every corpus term with two or more
nodes, at least one of the eight orders permutes builder ids relative to the natural
construction (the single-node terminal terms are trivially order-free and are kept only as
shape/hygiene rows).
The interning row uses C04's id-free `canonical_key` rather than C06's own intern key, so a
broken C06 key that under-interns would show up as `distinct > nodes`. The atom-dedup row
compares payload *bytes*, not just digests. The shape row re-derives reachability itself
instead of trusting C03's WF pass.

---

## 5. Spec readings, ambiguities, and decisions

1. **`klass` and atom identity (decision).** E2 §4.8 fixes the atom dedup key as
   `(length, sha256)`; `klass` is explicitly advisory and "never used for control flow"
   (E2-I11). Two records with equal payload but different `klass` are therefore *one*
   record. C06 keeps the `klass` of the first `Atom` node met by the canonical traversal —
   the same "first-encountered record wins" rule C04 uses (`WorkAtom::klass`). Consequence:
   `klass` is a property of the emitted record, and *not* of the intern key; a term
   differing only in `klass` interns to the same node ids. Row
   `e-atom-dup-klass` pins this. Nothing in E2's normative text makes `klass` semantic.
2. **Dedup key: exact bytes, not the digest.** The prompt and §4.8 name `(length,
   SHA-256)`; COMPONENTS-V2 C06 postconditions also say "deduplicated by `(length,
   SHA-256)`". C06 uses the exact payload bytes as the key, which is a strict refinement:
   it is *at least* as strong as the digest key, it can never merge two different payloads
   (so it cannot turn a would-be E3 `Mismatch` into a silent merge), and on the corpus the
   two coincide. Recorded here because it is the narrowest reading consistent with
   "no merging that violates payload equality" (prompt §1.5).
3. **Where validation lives (decision).** The prompt's §4.2 lists `Invalid`/`Limit`
   behaviour for `add_node`, but many WF constraints (§4.5 kind tables) need the whole term.
   C06 rejects at `add_node` exactly the conditions a single call can decide (unknown
   child/atom id, kind domain, `flags`, counts, depth) and defers the rest to `finish`,
   which runs the C03 WF pass in the §5.1 order and returns that code. This keeps one
   normative validation order rather than a second, partial one.
4. **Builder ids vs. output ids.** `node_count()`/`atom_count()` report *construction
   events*, not output records; the prompt allows "as applicable". The emitted counts are
   `Ir::nodes.size()`/`Ir::atoms.size()`. Documented in the header so a reader cannot
   mistake one for the other; the harness measures both.
5. **`Limits` reuse.** C06 reuses C03's `Limits` (`max_nodes`, `max_atoms`, `max_depth`,
   `enforce_output_cap`) rather than adding a parallel struct, so C06 and C03 cannot
   disagree about W1/W7/§8.3. The header is additive; `Limits` is unchanged.
6. **`total_length` / stored lengths.** `finish` computes every length from structure and
   never reads a caller-supplied one. `total_length` is copied from `nodes[root].length`
   after the passes, and WF then checks the two agree — so a length bug cannot hide behind
   a consistent pair of wrong numbers written by the same code path.
7. **O6.4 is not claimed here.** O6.4 (`check_canonical` rejects every non-canonical corpus
   term) is a C04 obligation measured on `T-NONCANON`. C06 asserts only the weaker,
   checkable statement that a `Dag` output for a *canonical* logical term equals its own
   canonicalisation, and that for a non-canonical term `canon` preserves denotation and is
   idempotent. Six C06 corpus terms are deliberately **non-canonical** in C04's sense —
   `e-atom-dup`, `e-shared-xor`, `e-slice-nested`, `e-composite-all`, `e-deep-xor-chain`,
   `e-deep-morph-chain` — and the harness reports exactly those six as
   `canon(dag) preserves denotation` (32 of the rest as `canon(dag)==dag`, and
   `e-zero-2pow40` under the materialisation cap). For example
   `e-shared-xor` is `Xor(m, m)` (rule 8), `e-slice-nested` is `Slice(Slice(·))` (rule 6),
   and `e-deep-morph-chain` is 300 stacked `INVERT8` morphs (rule 7). C06 owns identity,
   not normal form, and must not silently canonicalise.
   The harness reports this explicitly per term (`o6.canon_consistency`).

No conflict was found between `SPECS-V2.md` and `SPECS/COMPONENTS/e2-algebra/SPECS.md` on
C06; where COMPONENTS-V2 states postconditions more finely (atom dedup key, thread
completion order) it was followed, and it agrees with E2 §4.8.

---

## 6. Evidence summary

### 6.1 Row counts and verdicts

`specs_and_reports/v2/gates/C06-DAG.tsv` — 256 data rows, 8 columns
(`check corpus item_id input_sha256 expected actual verdict log`):

| check | rows |
|---|---|
| `o6.1.order_independence` | 39 |
| `o6.2.shape` | 39 |
| `o6.2.interned` | 39 |
| `o6.3.atom_dedup` | 39 |
| `o6.denotation` | 39 |
| `o6.canon_consistency` | 39 |
| `errors` | 13 |
| `o6.1.threaded_fragments` | 1 |
| `o6.1.repeat_determinism` | 1 |
| `o6.3.atom_insertion_order` | 1 |
| `o6.3.atom_reuse_single_record` | 1 |
| `independence` | 1 |
| `coverage.kind` / `coverage.morph` / `coverage.predictor` | 3 |
| `c06.summary` | 1 |
| **total** | **256** |

**255 PASS / 0 FAIL / 0 BLOCKED**, plus the summary row. Coverage: kind 12/12, morph 9/9,
predictor 5/5.

`specs_and_reports/v2/logs/C06-DAG.log` records the tool, root, exact command line, the
build flags, per-section cumulative counts, totals and `RESULT: PASS (C06 DAG)`.
`specs_and_reports/v2/evidence/C06/SHA256SUMS` covers the TSV and the log and is verified by
CI both before and after regeneration.

### 6.2 One deliberate deviation: the log carries no compiler version

The C03/C04/C05 logs embed `__VERSION__`. That makes their logs differ between the local
`g++ 12.2.0` and the CI `g++ 13.3.0`, so those logs cannot be covered by a manifest that
CI re-verifies after regeneration — and in fact C05's manifest currently pins a log that a
CI re-run on a different compiler would not reproduce. C06 avoids that trap: `C06-DAG.log`
records the tool, root, command line, and the fixed build-flag set, all of which are
toolchain-independent, while the CI workflow prints the compiler into the build log and a
CI notice (this run: `compiler=13.3.0`, §1). Consequence: `C06-DAG.log` is byte-reproducible
on any conforming C++20 toolchain, which is what makes the CI "committed evidence is byte
identical to CI output" step meaningful. The local run (`g++ 12.2.0`) and the CI run
(`g++ 13.3.0`) produce the same TSV and the same log, which is itself a determinism data
point.

### 6.3 Why there is no compiler-version-dependent number in the evidence

The C05 harness logs process RSS; the C04 harness logs a rewrite count. C06 logs only
counts, digests, and `PASS` verdicts. The one place a machine-dependent number could have
entered (a peak-RSS figure) is deliberately absent: the C06 "memory" evidence offered by
§6 of the prompt is the `O(nodes + atoms)` argument in §3.3 plus the ASan+UBSan run, not a
wall-clock or RSS number that would make the artifact irreproducible.

---

## 7. Known limitations and the exact handoff to E2-G

### 7.1 Limitations, stated plainly

1. **This is not E2-G.** C06 is validated against a 39-term C06 corpus focused on identity,
   sharing, and construction order — not against the full §12 corpus. No `T-KAT`/`T-GEN`/
   `T-BIG`/`T-BAD`/`T-NONCANON`/`T-CRIT`/`T-RANGE`/`M-KAT`/`L-KAT` corpus was assembled, no
   independent oracle run over it, no rewrite/range/canon/DAG counters, no 1-vs-4-thread
   byte-identity over the full corpus, no `E2-G.tsv`. **E2-G is not PASS and is not
   claimed.** §12.4 step 10 ("build every `T-KAT`/`T-GEN` term through `Dag` in 8 shuffled
   construction orders") is exactly the step C06 *implements* — the harness and its order
   generator are reusable for it — but the corpus it must be run against is E2-G scope.
2. **Denotation is not materialised above 4 MiB** in the C06 harness. One corpus term
   (`e-zero-2pow40`, `Zero(2^40)`) is checked for well-formedness, canonical shape,
   interning, and order independence, and its denotation row pins that the C03 surface
   returns `Limit` rather than approximating — it is not evaluated byte-for-byte. C05 owns
   bounded/virtual evaluation; O5.x/O3.1 are C05's obligations.
3. **`klass` normalisation.** As recorded in §5.1, a term whose duplicate payloads carry
   different `klass` values emits one atom record with the first-encountered `klass`. This
   is deliberate (E2-I11) and pinned by `e-atom-dup-klass`, but it does mean `Dag` is not
   byte-preserving in `klass` for such (advisory-only) inputs.
4. **No persistence, no parallel construction.** E2 §5.6/§11 place a serial `finish` after
   any parallel discovery; C06 implements exactly that. Hash-consed persistence across runs
   is explicitly out of scope (`SPECS-V2.md` §1).
5. **No wire byte identity.** C06 proves structural `Ir` identity (ids, params, lengths,
   payload bytes/digests), not wire identity — that is E3's.
6. **The C03/C04/C05 evidence bookkeeping change** described in §2.1 is additive and was
   re-proven by the C03/C04/C05 CI jobs on `6c72655`, but it *is* a change to four earlier
   evidence files (one row each, `PASS` → `PASS`) and is disclosed here rather than buried.

### 7.2 Handoff to E2-G

For the E2-G integration run, C06 provides:

- `marp::v2::Dag` with `add_atom`/`add_node`/`finish`/`node_count`/`atom_count` and a
  `Limits` constructor — the §12.4 step 10 builder, usable directly on any corpus `Ir`
  (`replay()` in `engine/src/e2/e2_c06_gate.cpp` is a ~40-line reference for turning a
  reference `Ir` into construction events).
- `specs_and_reports/v2/gates/C06-DAG.tsv` as the C06 evidence set, with the `O6.1`/`O6.2`/
  `O6.3` obligation ids already aligned to the E2 §7 table.
- A proven-irreproducible-number-free evidence convention (§6.2) that E2-G should copy, if
  E2-G's manifest is also to be CI-regenerated and `diff`ed.

Still required for E2-G (none of it C06 work): the full §12.1 corpus and `corpus.tsv`; the
independent oracle and O3.1–O3.6/O4.1–O4.5/O5.1–O5.3 measurements; O6.4 over `T-NONCANON`;
counters for every kind, morph, predictor and rewrite rule 1–13; 1-vs-4-thread byte
identity over the whole corpus; `E2-G.tsv`, `E2-G.log`, `corpus.tsv`, `rewrites.tsv`,
`evidence/E2/critical_pairs.md`; and the O4.2 critical-pair non-divergence measurement.

---

## 8. Acceptance checklist (C06)

- [x] Builds warning-free under the required flags on CI (`g++ 13.3.0`, `-Werror`,
      `-Wconversion -Wshadow -Wnull-dereference -Wdouble-promotion -Wformat=2`); 20/20 C06
      unit tests pass; ASan+UBSan suite and harness runs pass; C03/C04/C05 behaviour not
      regressed (their CI jobs are green on the same commit).
- [x] `Dag` (`add_atom`, `add_node`, `finish`, counts) implemented per spec and repo
      conventions.
- [x] `finish` emits post-order first-use, topological, root-last `Ir` with no unused
      nodes/atoms (39/39 shape rows).
- [x] Structurally identical subterms and equal atom payloads interned/deduped; construction
      order does not affect output (39/39 order rows `9/9`, threaded `4/4`).
- [x] Deterministic and reentrant; no E3–E7 linkage or behaviour (binary `nm` check +
      source scan); no H1/H2/H3 evidence regressions.
- [x] Evidence/log/manifest/report generated, committed, and matching the final green CI run
      `43697399789`.
- [x] `REPORT/E2/C06-DAG-REPORT.md` committed.

**C06 DAG is complete.** **E2-G is not claimed.**

---

*End of REPORT/E2/C06-DAG-REPORT.md*
