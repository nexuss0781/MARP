# E3-G — the E3 gate matrix — implementation report

**Component**: E3-G (the gate over C07 WIRE and C08 LEGACY; the last sub-component of E3).
**Branch**: `arena/d7f4f950-marp` (base `967f19fae265bff622375caeae12a98e86583eda`).
**Status: E3-G is `BLOCKED`, and it is green while blocked.** Every obligation that
*can* be discharged against the tree is discharged: **41 274 of 41 274 runnable
evidence rows `PASS`, 0 `FAIL`, 1 `BLOCKED`**. The single `BLOCKED` row is `W-V1`,
and it is blocked for one honest reason: **the repository contains no v1 fixture**,
and `SPECS/COMPONENTS/e3-wire/SPECS.md` §13.3 says a missing fixture is `BLOCKED`,
never `PASS`. The gate exits **4**, not 0, so CI cannot mistake this for completion.

> **What is being claimed, exactly.** The canonical-wire half of E3-G (W-CANON,
> W-NONCANON, W-SEED, W-BIG, W-FUZZ, W-COVER) is complete and green. The legacy
> half (W-V1) is *implemented and demonstrated*, but not *certified* against a
> committed corpus, because no such corpus exists. §6 is explicit about which of
> the two readings of "W-V1 works" the evidence supports.

---

## 1. What "green while BLOCKED" means

`SPECS/COMPONENTS/e3-wire/SPECS.md` §13.3 defines a corpus table with three cell
states and forbids conflating them:

| State | Meaning | Exit code |
|---|---|---|
| `PASS` | every certificate for this corpus was produced and matched | 0 |
| `FAIL` | at least one certificate was produced and did not match | 2 |
| `BLOCKED` | the corpus is required but absent, so no certificate could be produced | 4 |

A gate that turned an absent input into `PASS` would be claiming a verification it
never performed. A gate that turned it into `FAIL` would be blaming the code for a
missing input. `BLOCKED` is the third answer, and it is only honest if the gate
*also* proves the machinery that would consume the input is correct — otherwise
"blocked" is indistinguishable from "unimplemented". That is what §6 does, and it
is why the gate was driven end-to-end against a scratch fixture during
development, outside the repository.

---

## 2. Evidence inventory

| Path | Contents |
|---|---|
| `specs_and_reports/v2/gates/E3-G.tsv` | 41 275 rows. Columns: `check`, `workload`, `item`, `input_sha`, `output_sha`, `wire_bytes`, `expected`, `actual`, `status`, `log_ref`. |
| `specs_and_reports/v2/logs/E3-G.log` | Per-section totals, coverage counters, `RESULT: BLOCKED (E3-G)`. |
| `specs_and_reports/v2/logs/E3-G-fuzz.log` | Per-stage rejection histogram and the diagnostic worst-case wall time. |
| `specs_and_reports/v2/logs/E3-G-legacy.log` | The legacy subprocess transcript: surface, per-fixture hashes, structure records. |
| `specs_and_reports/v2/corpus/E3/corpus.tsv` | The corpus, item by item, with its provenance (`e2-dag`, `hand`, `noncanon`, `fuzz`, `edge`). |
| `specs_and_reports/v2/corpus/E3/fuzz_counts.tsv` | The fuzz campaign counters — the deterministic obligations. |
| `specs_and_reports/v2/evidence/E3/SHA256SUMS` | Manifest over the six files above. |
| `specs_and_reports/v2/evidence/E3/MANIFEST.tsv` | The same, as `path\tsha256\tbytes`. |

Row counts by check family:

| Family | Rows | What each row asserts |
|---|---|---|
| `e3g.canon.*` | 36 002 | seven wire obligations × 5143 canonical terms, plus the one `encode_limit` row |
| `e3g.seed.member` | 5143 | the term is a member of the canonical seed set |
| `e3g.noncanon.*` | 96 | 48 non-canonical shapes, rejected by both `validate` and `decode` |
| `e3g.seed.oracle` / `.fixpoint` | 16 | the hand-built seed terms agree with H3 and are wire fixpoints |
| `e3g.big.default_limits` | 8 | the limit boundary: default `Limit`, with the lifted-limit results on the `canon.*` rows |
| `e3g.fuzz.*` | 5 | the campaign's deterministic counters |
| `e3g.legacy.*` | 3 | the legacy half: 1 `BLOCKED` corpus row + 2 machinery rows (`half`, `readonly_surface`) |
| `e3g.coverage.counters` | 1 | every coverage bucket non-zero |
| `e3g.determinism.threads` | 1 | §13.4 step 9: every configured thread count measures the same wires and verdicts, and two in-process passes agree |

### 2.1 Determinism — a requirement, not a nicety

§13.4 step 9 requires the evidence to be reproducible byte for byte. It was not,
at first, for two independent reasons, and both are worth recording because both
classes of mistake are easy to make again:

1. **Process-global allocation counters.** The W-FUZZ allocator guard reported a
   *peak* across concurrently running workers, so under 4 workers the peak depended
   on scheduling — 329 211 bytes on one run, 394 610 on the next. Fixed by making
   every counter `thread_local`, so a worker's peak is a property of the mutants it
   saw and not of what its neighbours were doing.
2. **Wall-clock timing in committed evidence.** `slowest_mutant_us` varied 16–20 ms
   between runs. It has been **removed from `fuzz_counts.tsv` entirely** and is now
   printed to stdout only, labelled
   `W-FUZZ worst-case mutant wall time: … (diagnostic only, not evidence)`.
   The deterministic obligations are the counters — `timeouts`, `crashes`,
   `accepted_invalid`, `alloc_violations` — and a `timeout` verdict is only
   *enforced* when `fuzz_threads == 1`, because a wall-clock timeout measured under
   concurrent load is not a statement about the code.

`e3g.determinism.threads` is the assertion, and it is not vacuous: it compares the
full measurement vector — item id, wire SHA-256, size and verdict — across every
configured thread count and across a repeated in-process pass. With `--threads 1,4`
all three vectors hash to the same value
(`17d178cc31230d6b2c31b48643dc51ea004371469a74db416052c8e3212a08cd`, 5143 items),
which is what makes the `--fuzz-threads 4` campaign defensible: concurrency does not
change a single measured byte.

Two consecutive full 100 000-mutant runs now produce identical SHA-256 for all
eight artefacts. The CI workflow proves this on every run: it checks the committed
evidence against `SHA256SUMS`, regenerates it, and `diff -u`s all eight files.

---

## 3. The one integration fix — and why it was justified

`engine/src/e3/e3_wire_read.cpp`, `check_atom_order()`.

**Defect.** Stage 7's atom-order check verifies that atoms appear in the order in
which nodes first reference them, and that every atom is referenced. The check
walked the node table and, for each reference to an already-seen atom, re-marked
it. On a shape where the *same* atom is referenced by two sibling nodes, the second
visit re-armed the "expected next atom" state, so the next **new** atom was reported
as out of order. The result was a false rejection of a perfectly canonical wire:
200 of C07's own corpus entries failed a check C07 itself had written.

**Why this is an integration fix and not a scope change.** The bug is entirely
inside the C07 implementation of a rule C07 already claimed (§4.10 "atoms are
numbered in first-reference order", §5.1 stage 7). The specification is not
ambiguous here: an atom is "first referenced" exactly once, and later references to
it are not first references. The fix makes the code match the rule it was already
subject to — a visit-once `entered` array — without changing the rule, the error
code, the stage, the wire format, or any other check.

**Cost of not fixing it.** E3-G's W-CANON obligation is "every canonical term
round-trips". With the defect, 200 canonical terms could not be encoded and decoded
at all, so W-CANON would have been unachievable without either (a) removing those
200 terms from the corpus — which is exactly the kind of corpus-shopping that makes
a gate worthless — or (b) shipping a gate that fails. Neither is acceptable, so the
fix is the only honest route.

**Blast radius, verified.** After the fix: C07's gate is still **1170/1170** and
C07's 48 unit tests still pass; C07's own committed evidence is **byte-identical**
to what it was before the change (`specs_and_reports/v2/gates/C07-WIRE.tsv` and
`logs/C07-WIRE.log` are unmodified in this branch — `git status` shows no change to
them). C08 is untouched. This is the only change to any pre-existing component in
the whole of E3-G.

---

## 4. Process separation — why the legacy half is a subprocess

`include/mapr/e3/e3_wire.hpp` and `include/mapr/e3/e3_legacy.hpp` cannot be
included in the same translation unit: the second defines
`MAPR_E3_WIRE_TYPES_DEFINED`, and its `WireCode` is a plain `int` where C07's is a
scoped enum. They are layout-incompatible by construction, and that is *by design* —
the v1 decoder is a read-only compatibility surface, not a second implementation of
the same types.

The first attempt bridged them at the allocator (`HeapArena::store`). It is
unsound: C07's arena is `{capacity_, used_, owner_}`, C08's is
`{max_bytes_, used_bytes_, blocks_}`, so the bridge implemented `store` against one
layout and was called with the other. The failure was not subtle — `free(): double
free detected in tcache 2` — and both component files were reverted rather than
patched around.

The answer is process separation, which is also what §13.1 mandates ("H3 is reached
only as a subprocess"):

- `engine/src/e3g/wire_half_main.cpp` links C07 and E4–E7 and *nothing* from C08.
- `engine/src/e3g/e3g_legacy_side.cpp` links C08 and E1 only, and *nothing* from C07.
- `bin/e3g_legacy_half <root>` speaks a line-oriented TSV protocol on stdout:
  `dir`, `fixtures`, `surface`, `fixture`, `hash`, `decode`, `structure`, `payload`,
  `fail`. Every record is one line; `structure` repeats once per structural record
  (`header`, `atom`, `node`, `trailer`) so the transcript is greppable and diffable.
- `bin/e3_g_gate` runs it with `popen` and parses the transcript. For the v2
  re-encode (step 8) the gate rebuilds an `Ir` from the transcript alone — the
  legacy side cannot hand it a `WireCode`, and the gate cannot hand the legacy side
  a C07 type.

`make -f Makefile.e3g e3g-isolation` proves the separation mechanically:

```
legacy half: 689 symbols, 0 v2 entry points
wire   half: 2403 symbols, 0 legacy entry points
gate      : 2466 symbols, 0 forbidden, guard present
PASS: E3-G is separated from C08 on the encode side and from E4-E7 entirely
```

`nm -C bin/e3_g_gate | grep -cE 'decode_v1|looks_like_v1'` is **0**;
`nm -C bin/e3g_legacy_half | grep -cE 'marp::v2::(encode|encode_to|plan|validate|decode)\('`
is **0**.

---

## 5. The limit boundary (W-BIG)

Two independent bounds can stop a canonical term, and conflating them would be a
real error:

| Bound | Value | Enforced by | Meaning |
|---|---|---|---|
| §8.3 output cap | 2^63 | `validate`/`decode` stage 6 regions | do not claim to emit more than addressable bytes |
| Stage 11 work bound | 1 GiB | `validate`/`decode` stage 11 | do not claim to evaluate an unbounded denotation |

Both are **policy**, not format. A term whose declared length exceeds them is still
a canonical wire — `Zero(2^128)` has one canonical encoding, and its *declared
length* is a bigint that the header carries exactly. So the gate asserts three
distinct things, and records all three:

| Item | Default limits | Lifted limits |
|---|---|---|
| `big-total-2pow64{,,-plus-one}`, `-2pow128`, `-lfsr-2pow65` | `Limit@stage6_regions` for `encode`, `encoded_size` **and** `validate` | `Ok`; decoded `Ir` structurally equal; re-encode byte-identical |
| `edge-zero-2pow32`, `edge-zero-2pow40`, `edge-lfsr-2pow40` | `encode`/`encoded_size` `Ok`; `validate` `Limit@stage11_eval` | `Ok`; byte-identical re-encode |
| `big-limit-repeat-entry-cap` | `Limit@stage10_index` | `Limit@stage10_index` (the index really cannot be planned) |

The lift is applied to the §8.3 output cap only and **never** to stage 11, and the
reason is a measurement rather than a preference: lifting the stage-11 bound made
the gate attempt a 2^128-byte denotation and it did not finish in 1 800 s. A gate
that hangs is not more rigorous than a gate that says "structural check"; it is
just slower at being useless. So for those items `verify_denotation = false`, the
row's `expected` text reads
`validate=Ok (structural: declared length above the stage-11 work bound)`, and the
companion `validate_evaluated` row asserts that the stage-11 result is *not* being
claimed. On every other item — 5136 of 5143 — `denotation_verified` must be `true`,
and is.

The lift flags are **derived** in `build_corpus` from C07's own constants
(`max_output_bytes()` and `kC07DefaultMaxEvalBytes`), not hand-marked per item, so
the corpus cannot drift out of agreement with the limits it is testing.

---

## 6. The legacy half (W-V1) — implemented, demonstrated, not certified

**The repository has no v1 fixture.** `specs_and_reports/v2/W-V1/` does not exist,
has never existed, and no `.mapr` file appears anywhere in the tree or in the
repository's history. The gate therefore reports:

```
e3g.legacy.w_v1_corpus | BLOCKED | verified=0 decode_ok=0 blocked=yes (missing_w_v1_corpus)
```

`BLOCKED` here is not a placeholder for "not written". Everything downstream of the
missing input was exercised end-to-end before the report was written, using a
fixture built and kept **outside the repository** (`/tmp/proto/testroot/`, never
committed — no `.mapr` file is added by this branch):

| Step | Machinery | Scratch-fixture result |
|---|---|---|
| fixture discovery | `e3g_legacy_check.cpp` walks `specs_and_reports/v2/W-V1/*.mapr` | `fixtures 1` |
| read-only surface probe | `nm` on the legacy half | `C08 read-only: decode_v1, looks_like_v1` |
| input hash certification | manifest `sha256` vs. bytes on disk | `match` |
| v1 decode | `marp::v2::decode_v1` | `decode_v1=Ok` |
| denotation digest | gate recomputes SHA-256 of the decoded payload | `1a835ed8…` — equals the atom's recorded digest |
| term canonicality | `check_canonical` on the decoded `Ir` | `Ok` |
| structure transcript | header/atom/node/trailer, one record per line | 4 records, all parseable |
| **v2 re-encode** (step 8) | gate rebuilds an `Ir` from the transcript, `encode` | `encode=Ok` |
| **v2 roundtrip** | `decode(encode(t))` vs. `t` | `equal` |
| **v2 fixpoint** | `encode(decode(encode(t)))` vs. `encode(t)` | `byte-identical` |

Full gate against the scratch root: `E3-G: PASS — rows=5264 pass=5264 fail=0
blocked=0`, `W-V1 fixtures=1 verified=1 decode_ok=1 blocked=no`. With the fixture
removed: `BLOCKED`, one row, and 41 274 passes.

**What this establishes and what it does not.** It establishes that the legacy
pipeline is *correct on a real v1 container* — a 229-byte file produced by C08's
own assembler, decoded, digested, canonicalised, re-encoded to v2 and round-tripped.
It does **not** establish that the pipeline is correct on *the corpus the
specification names*, because that corpus does not exist. One fixture is a smoke
test, not a certificate. That distinction is the entire content of the `BLOCKED`
state, and it is why the row is `BLOCKED` in the committed evidence while the
scratch run was `PASS`.

Two parsing defects were found and fixed by this exercise, and both would have
misfired against a real corpus:

- The `structure` records were emitted as a single newline-escaped TSV field, so
  four records arrived as one line. Now one record per line.
- The `Ir` reconstruction read the node table positionally, but `Atom` carries its
  atom id in `a` with `argc == 0`, while the rendering prints it in the *params*
  column and `-` in the args column. Reading by kind rather than by position fixed
  it; the roundtrip then went from `Invalid@stage8_nodes (W3.arg-order)` to `Ok`.

To unblock: place one or more v1 containers plus a `manifest.tsv` of
`<name>\t<sha256>\t<denotation_sha256>` under `specs_and_reports/v2/W-V1/`, and
re-run the gate. Nothing else needs to change.

---

## 7. Coverage and the fuzz campaign

`e3g.coverage.counters` asserts every bucket is non-zero — 12 kinds, 9 morphs,
5 predictors, `idx_present = 3`, `atom_max = 7`, both length forms, bigint tags:

```
all non-zero (cb77fc4b9ea1c0490dbe54e7a0b2bf15e1668a70a28850324215076f0a0ac163)
```

Corpus: `canon=5144 hand=8 noncanon=48 v1=0 fuzz=7 tkat=128 tgen=5000`,
`canonicalised=607`, `expect_limit=1` — 9 089 615 B in total. One `canon` item is
excluded from "encoded" by construction: `big-limit-repeat-entry-cap` is *supposed*
to fail at stage 10, and it does, so `encoded=5143/5144` is the correct count and
not a shortfall.

The fuzz campaign mutates corpus wires and asserts that no mutant is ever
*accepted invalid*:

| Counter | Value |
|---|---|
| `mutants` | 100 000 |
| `accepted_valid` | 4049 |
| `accepted_invalid` | **0** |
| `rejected` | 95 951 |
| `crashes` | **0** |
| `timeouts` | **0** |
| `alloc_violations` | **0** |
| `peak_alloc_bytes` (per worker) | 197 635 |
| `workers` / `seeds` / `timeout_seconds` | 4 / 7 / 10 |

Rejections by stage — every stage of §5.2 is reached, which is the point of the
histogram: `stage1_size 4907`, `stage2_header 6138`, `stage3_bounds 48322`,
`stage4_header_crc 14883`, `stage5_trailer 7479`, `stage6_regions 6257`,
`stage7_atoms 7268`, `stage8_nodes 697`. The invariant
`accepted_valid + rejected == mutants` is asserted, so a mutant cannot be silently
lost between the counters.

---

## 8. Verification performed

| Check | Result |
|---|---|
| Full gate, 100 000 mutants, 4 workers, `--threads 1,4` | `BLOCKED`; `rows=41275 pass=41274 fail=0 blocked=1`; exit 4 |
| Two consecutive evidence runs, 8 artefacts | **byte-identical** |
| `make -f Makefile.e3g e3g-isolation` | PASS (0 v2 entry points in the legacy half, 0 legacy entry points in the wire half, 0 forbidden symbols in the gate) |
| ASan + UBSan gate run (`e3g-san`, 2000 mutants, 1 thread) | 0 sanitizer reports, same `BLOCKED` summary |
| C07 gate (predecessor, unmodified evidence) | 1170/1170 |
| C07 tests | 48/48 |
| C08 gate | exit 0 |
| C08 tests | 13/13 |
| Full gate against a scratch v1 fixture (outside the repo) | `PASS`, `rows=5264 pass=5264 fail=0 blocked=0` |
| Repository v1 fixtures | **0** (nothing added, nothing to add) |

### 8.1 Two defects the workflow found that reading it did not

Both are worth recording because both are the kind that make a green CI run
meaningless:

1. **`--oracle-bin` was resolved against `--root`, `--legacy-half` against the working
   directory.** In CI's sanitizer step (`cd engine` + `--root ..`) the two spellings
   disagreed: `engine/bin/mapr_oracle` resolved to `/home/user/MARP/bin/mapr_oracle`,
   which does not exist, so **all 5143 `oracle_agreement` rows silently became
   `BLOCKED`** and the summary read `blocked=5144` — while the step still printed
   "PASS". Every external helper is now resolved against `--root`, and the schema
   step forbids any `BLOCKED` row that is not the W-V1 corpus row, so a mis-specified
   path fails loudly instead of producing thousands of quietly-blocked rows.

2. **The sanitizer step could not reach its own assertions.** It ran the gate under
   `set -euo pipefail` without `set +e`, so the expected exit 4 (BLOCKED) killed the
   script before `rc=${PIPESTATUS[0]}` and before any sanitizer/oracle assertion ran.
   The step now captures the exit code the same way the main gate step does.

A third, structural problem: the schema step exited 1 as soon as it saw the BLOCKED
W-V1 row, which skipped the counter, sanitizer and no-regression steps entirely — so
CI failed for the right reason while never running half its checks. The W-V1 verdict
is now a dedicated **final** step, after every other check, so a red job is
attributable to the missing fixture and to nothing else.

Neither failure changes the evidence — the committed artefacts are byte-identical
before and after — but both meant the CI could have gone green while checking less
than it claimed to check.

The strict build is `-std=c++20 -pedantic -Wall -Wextra -Werror -Wconversion
-Wshadow -Wnull-dereference -Wdouble-promotion -Wformat=2 -O2`; the harness compiles
clean under it. The sanitizer build passes `-DE3G_ALLOC_GUARD_DISABLED` because the
guard's replacement `operator new`/`delete` would otherwise mask ASan's own
interception of the same calls.

---

## 9. What remains for E3-G to be `PASS`

Exactly one thing: **the W-V1 corpus.** Everything else is complete, reproducible
and asserted. When a v1 fixture set is committed under
`specs_and_reports/v2/W-V1/` with its `manifest.tsv`, the gate will consume it, the
`BLOCKED` row will become a set of per-fixture `PASS` rows, and the exit code will
become 0 — provided the pipeline behaves as it did on the scratch fixture, which is
the strongest statement that can honestly be made before the corpus exists.

Until then the gate exits **4**, and the CI workflow turns that into a failing job
with `::error::` text naming W-V1. A blocked gate that CI reports as success would
be the one failure mode this design exists to prevent.
