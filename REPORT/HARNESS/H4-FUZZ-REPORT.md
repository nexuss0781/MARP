# H4 FUZZ — MARP v2 mutation campaign report

**Verdict: PASS** — 100,000 mutants over E3-G canonical wires, executed by the
harness itself, with `accepted_invalid = 0`, `crashes = 0`, `timeouts = 0` and
every mutant accounted for. Evidence in this report is harness-written and
reproduced byte-for-byte by the authoritative CI run (§1 and §7).

---

## 1. Environment and authoritative run

| item | value |
|---|---|
| Repository | `nexuss0781/MARP` |
| Branch | `arena/34de26e1-marp` |
| Base commit | `b840971653f34d8cf2f57447421b3fd4ef1485dc` (`h2-gates` head, E3-G merged and green) |
| Local toolchain | `g++ (Debian 12.2.0-14+deb12u1) 12.2.0`, `-std=c++20` |
| Local platform | Linux x86-64, 2 cores, 3.8 GiB RAM |
| CI workflow | `.github/workflows/h4-fuzz.yml` (`MARP H4 FUZZ CI`) |
| Authoritative CI run | `43866731951` — `MARP H4 FUZZ CI`, **SUCCESS** (https://github.com/nexuss0781/MARP/actions/runs/43866731951), head `2faa1b38` |
| CI toolchain | `ubuntu-latest`, GCC 15.2.0 (H4 builds warning-free under `-Werror` there too) |
| Third-party libraries | none in `bin/h4_fuzz` (GoogleTest is not used; no zlib, no Python, no scripts) |

Build and run:

```sh
cd engine
make -f Makefile.h4 h4-all          # bin/h4_fuzz, -Werror -Wconversion -Wshadow -Wformat=2
./bin/h4_fuzz --root .. --self-test
./bin/h4_fuzz --root .. --workers 4 --write-evidence
make -f Makefile.h4 h4-isolation    # source grep + nm + ldd
make -f Makefile.h4 h4-san          # ASan+UBSan binary, campaign in-process
```

## 2. Prerequisite: E3-G is merged and green

H4 refuses to run a campaign unless the committed E3-G prerequisite is present
and clean; `bin/h4_fuzz` exits `4` (`BLOCKED`) otherwise. The check is performed
by the harness (`check_prerequisite`) and re-asserted by the workflow before any
campaign step.

| prerequisite | committed artifact | digest / value |
|---|---|---|
| E3-G gate, zero FAIL/BLOCKED | `specs_and_reports/v2/gates/E3-G.tsv` | SHA-256 `1234b8d297f6d286e4fc9db19adb7c8f60e145f9a3f21526ff219104f9c4c4c3`, 41,335 rows, 0 FAIL, 0 BLOCKED |
| E3-G fuzz campaign record | `specs_and_reports/v2/corpus/E3/fuzz_counts.tsv` | SHA-256 `93cb4bd69377a80f23ecbfed76209d6edc35cf08d9e2fa4998939ef404724cc4`, `mutants=100000 accepted_invalid=0 crashes=0 timeouts=0` |
| E3 corpus (seed provenance) | `specs_and_reports/v2/corpus/E3/corpus.tsv` | SHA-256 `be73443e6826fa4e88b8b37952c1eaac858212fa45a45d4f4be3d036a845eea5`, 5,144 items |
| E3-G evidence manifest | `specs_and_reports/v2/evidence/E3/SHA256SUMS` | verified with `sha256sum -c` in CI |
| E3-G authoritative CI | run `43858184768` (`MARP E3-G integrated gate CI`, `success`) | https://github.com/nexuss0781/MARP/actions/runs/43858184768 |

H4 does not import E3-G's evidence as its own result: the prerequisite only
permits the campaign to start. Every number in §6 is produced by H4.

## 3. What H4 is, and where it lives

`H4 FUZZ` is E0's mutation harness: it mutates *valid* v2 containers, feeds every
mutant to the C07 `verify` path (`validate`) and to `decode`, and counts
`total`, `valid`, `accepted_invalid`, `crashes`, `timeouts` (SPECS-V2 §12.8,
COMPONENTS-V2 §H4). It is a measurement component: no E1–E7 semantic code was
changed, and the campaign found no engine defect to fix.

| file | role |
|---|---|
| `include/marp/harness/h4_fuzz.hpp` | public `marp::harness::fuzz(root, mutants, seed)` surface, `FuzzConfig`, `FuzzCounts`, `FuzzReport`, `FuzzTally` |
| `harness/fuzz/src/h4_mutate.{hpp,cpp}` | SplitMix64 planning, the four mutation classes, sparse edit map, outer-CRC repair, region tagging |
| `harness/fuzz/src/h4_alloc_guard.{hpp,cpp}` | thread-local allocation accounting (`raw_allocate`/`raw_release` hooks, hard budget) |
| `harness/fuzz/src/h4_runner.cpp` | per-mutant execution (fork + watchdog, or in-process), classification, per-stage/region/class/seed tallies |
| `harness/fuzz/src/h4_seeds.{hpp,cpp}` | builds the 15 canonical seeds from the committed E3 corpus, verifies each wire digest and emits `corpus/H4/seeds.tsv` |
| `harness/fuzz/src/h4_evidence.{hpp,cpp}` | renders `gates/H4-FUZZ.tsv`, `logs/H4-FUZZ.log`, `corpus/H4/fuzz_counts.tsv`, `evidence/H4/*` |
| `harness/fuzz/src/h4_selftest.{hpp,cpp}` | 30 self-checks (mutation determinism, bounds, class/region coverage, worker invariance, verdict logic, evidence determinism) |
| `harness/fuzz/src/h4_main.cpp` | CLI (`--root`, `--mutants`, `--seed`, `--workers`, `--dry-run-mutants`, `--per-mutant-timeout-ms`, `--alloc-budget-bytes`, `--no-fork`, `--no-prereq`, `--write-evidence`, `--print-seeds`, `--self-test`) |
| `engine/Makefile.h4` | isolated build (`obj/h4/**`, `bin/h4_fuzz`), `h4-test`, `h4-gate`, `h4-san`, `h4-isolation`, `h4-seeds-preview`, `h4-clean` |

Integration points are additive only: the new header, the new `harness/fuzz`
tree, `engine/Makefile.h4`, the new workflow, and the H4 evidence paths. The
existing `harness/` (H1–H3 sources), `engine/Makefile`, `engine/CMakeLists.txt`,
`include/mapr/**`, `engine/src/**` and every earlier gate's evidence are
untouched — the CI job diffs all of them and fails on any change.

## 4. Seeds

Seeds must be E3-produced, committed, canonical wires. H4 rebuilds each seed
from the E3 corpus (`build_corpus` + `encode`) and asserts the full wire
SHA-256 against the digest committed in `corpus/E3/corpus.tsv`; a mismatch is a
BLOCKED prerequisite, not a seed. 15 seeds are used (set SHA-256
`2791a46aa25eca57ed6d7acd7de3c0fb88e98cf5e73856a1720af7003d6dec80`, written to
`corpus/H4/seeds.tsv`):

| seed | source | bytes | index | role |
|---|---|---:|---|---|
| `tkat-empty` | E3-G `W-CANON` | 103 | absent | small |
| `tkat-atom1` | E3-G `W-CANON` | 144 | absent | small |
| `tkat-atom16` | E3-G `W-CANON` | 159 | absent | small |
| `tkat-zero0` | E3-G `W-CANON` | 104 | absent | small |
| `tkat-zero5` | E3-G `W-CANON` | 106 | absent | small |
| `tkat-lfsr0` | E3-G `W-CANON` | 122 | absent | small |
| `tkat-atom1023` | E3-G `W-CANON` | 1,168 | absent | small |
| `tkat-concat2` | E3-G `W-CANON` | 175 | absent | small |
| `tkat-repeat35` | E3-G `W-CANON` | 170 | absent | small |
| `tkat-slicemid` | E3-G `W-CANON` | 185 | absent | small |
| `tkat-xor` | E3-G `W-CANON` | 228 | absent | small |
| `tkat-ilv-s1` | E3-G `W-CANON` | 206 | absent | small |
| `tkat-atom-max` | E3-G `W-CANON` | 1,048,723 | absent | large header/index |
| `edge-index-repeat-5x1mib` | E3-G `W-CANON-EDGE` | 1,048,791 | present | large index |
| `edge-atom-max-plus-one` | E3-G `W-CANON-EDGE` | 1,048,804 | present | large index/trailer |

All 15 digests are reproduced exactly (one `h4.seed.reproduced` row per seed in
`gates/H4-FUZZ.tsv`); the seed bytes themselves live in `engine/obj/h4/seeds/`
(`--print-seeds` prints the catalogue, build artifacts are not committed).

**Index representation decision.** The E3-G catalogue also contains
`edge-index-3x-atom-max` (3,146,020 B). It was considered and rejected as a
third large seed: its CRC work per mutant is ~3× the other large seeds and would
have dominated campaign wall time without adding a new mutation class. Two
index-bearing seeds remain (`edge-index-repeat-5x1mib`, `edge-atom-max-plus-one`,
both `index=present`), and `region.index = 3,147` mutants (~3.1% of the
campaign) exercise the index region with zero escapes. Adding the 3 MiB seed is
a one-line catalogue change if a future campaign wants a deeper index sweep.

## 5. Mutation model

Every mutant is a pure function of `(campaign seed, index)`; sharding is only an
execution detail, so any worker count yields the same mutant sequence.

* **Campaign seed**: `79389355498074` (`0x483446555A5A`, "H4FUZZ"), SplitMix64.
  Recorded in `corpus/H4/fuzz_counts.tsv` (`campaign.seed`).
* **Assignment**: `index % 15` selects the seed, `(index / 15) % 4` selects the
  class, and the remaining bits select edits — the observed mix is therefore
  balanced by construction (25,005 / 25,005 / 25,000 / 24,990).
* **Classes** (SPECS-V2 §12.8's list, implemented as four):
  1. `bitflip` — one to three bit flips at deterministic offsets, biased toward
     the header and trailer on large seeds;
  2. `truncation` — drop 1..N bytes from the tail (header-only mutants never
     reach 96 B) and optionally rewrite the declared sizes so the region table
     stays self-consistent;
  3. `fieldswap` — swap or replace scalar fields (magic, version, flags, atom
     count, node count, root id, total length fields) and body ranges;
  4. `lengthcorruption` — set a length field to 0, 1, `±1`, `u32`/`u64` boundary
     values, or `2^N`, rewriting the trailer atom/node counts consistently.
* **CRC repair**: half of the mutants get their outer CRCs recomputed
  (`repair_outer_crcs`) so the campaign reaches stages *after* the CRC checks;
  the other half keep the corrupted CRCs. Materialisation of a repaired mutant
  copies at most one seed (≤ 1,048,804 B).
* **Region tags**: each mutant is tagged with the regions its edits touch
  (`header`, `index`, `trailer`, `body`); counts are recorded per class and per
  region, so "no escapes" cannot hide behind an untested region.
* **Per-mutant limits** (safety requirement): 5,000 ms wall bound enforced by a
  forked worker watchdog (`SIGKILL` on expiry), plus an allocation budget of
  `mutant_size + 64 MiB` enforced by the alloc guard. A mutant that returns
  outside its time budget is a timeout; a worker that dies abnormally is a
  crash. Neither is retried or dropped, and the caller aborts the campaign on
  the first crash/timeout.
* **Limits used for the C07 API**: the normative defaults (`WireLimits{}`):
  output cap enforced, denotation evaluated with the 1 GiB step-11 work bound,
  canonical shape and canonical wire rules enforced. This is stricter than
  E3-G's fuzz configuration (`enforce_output_cap=false`,
  `verify_denotation=false`) and keeps each mutant's work bounded; a mutant that
  exceeds the eval bound is a `Limit` rejection at stage 11, never accepted.
* **Classification** (`accepted_invalid` is never inferred, always counted):
  * `valid` — `validate` Ok, `decode` Ok, and `encode(decode(m))` reproduces the
    mutant bytes exactly (canonical fixpoint);
  * `accepted_invalid` — exactly one surface accepted, or both accepted but the
    re-encode differs (`non-canonical-accepted`);
  * `rejected` — both surfaces rejected; `validate`'s stage is recorded in the
    stage histogram;
  * `timeout` / `crash` — as above.

## 6. Campaign result

Authoritative configuration: `--mutants 100000 --workers 4 --per-mutant-timeout-ms 5000
--alloc-budget-bytes 67108864`.

```
total=100000 valid=6977 accepted_invalid=0 crashes=0 timeouts=0 rejected=93023 processed=100000
class mix bitflip=25005 truncation=25005 fieldswap=25000 lengthcorruption=24990
regions header=68875 index=3147 trailer=55489 body=26579
stages distinct=9  stage1_size=13898 stage2_header=19101 stage3_bounds=22690
  stage4_header_crc=12975 stage5_trailer=12494 stage6_regions=5685 stage7_atoms=3589
  stage8_nodes=1990 stage9_root=0 stage10_index=601 stage11_eval=0
fixpoint checked=6977 mismatch=0  peak alloc=3147315  alloc_violations=0
```

* Accounting: `processed = valid + rejected = 6977 + 93023 = 100000`, so no
  mutant vanished into a worker or a skipped shard.
* All three hard targets hold exactly: **accepted_invalid 0, crashes 0,
  timeouts 0**.
* 6,977 mutants are genuinely canonical and re-encode byte-identically
  (fixpoint verified for every one, 0 mismatches).
* Rejections are distributed over 9 distinct validation stages (size, header,
  bounds, header CRC, trailer, regions, atoms, nodes, index).
* Peak per-mutant allocation 3,147,315 B, far below the 64 MiB budget; no
  allocation violation.

### Determinism

* Dry run before every campaign: the first 3,000 indices are executed at
  `workers=1` and at `workers=N`; counts, class mix and failure list must be
  identical (`determinism.dry_run.equal = yes`).
* Full-campaign invariance measured locally: identical counts at `--workers 2`
  and `--workers 4` (`total=100000 valid=6977 rejected=93023 accepted_invalid=0
  crashes=0 timeouts=0`).
* Whole-pipeline reproducibility: two consecutive full campaigns at the final
  configuration (`--workers 4`, same build, same campaign seed) produced
  byte-identical `H4-FUZZ.tsv`, `H4-FUZZ.log`, `fuzz_counts.tsv`, `seeds.tsv`,
  `MANIFEST.tsv` and `SHA256SUMS`; CI repeats this comparison between its own
  run and the committed files, and again between two CI runs.
* Wall time: 93 s for the 100,000-mutant campaign (plus 2 × 3,000 dry-run
  mutants) on the 2-core local machine; CI asserts the same artifacts.

## 7. Evidence

| artifact | content |
|---|---|
| `specs_and_reports/v2/gates/H4-FUZZ.tsv` | 8-column gate table: prerequisite rows, one row per seed digest, campaign counters/targets, class/region/stage coverage, determinism, `h4.verdict` |
| `specs_and_reports/v2/logs/H4-FUZZ.log` | harness log with the same measured values and section markers referenced by the TSV `log` column |
| `specs_and_reports/v2/corpus/H4/fuzz_counts.tsv` | machine-readable counters (mutants, valid, accepted_invalid, crashes, timeouts, alloc, classes, regions, stages, campaign seed, workers, config) |
| `specs_and_reports/v2/corpus/H4/seeds.tsv` | seed catalogue with E3 item id, source group, bytes, full SHA-256, index flag, role |
| `specs_and_reports/v2/evidence/H4/MANIFEST.tsv` | artifact → SHA-256 → bytes → required, plus `verdict PASS` |
| `specs_and_reports/v2/evidence/H4/SHA256SUMS` | `sha256sum -c` manifest over the four H4 artifacts and the four E3-G prerequisite artifacts |

`SHA256SUMS` (generated by the harness):

```
3593a7234e75fe5e45f440449876545d39a3733f2edad7aba4b292f3db1d9b9a  specs_and_reports/v2/gates/H4-FUZZ.tsv
0f5f7fa94b37aaddb626f401de23c580695a239b315296421c0eb1d7e24aa626  specs_and_reports/v2/logs/H4-FUZZ.log
d06b6c64e515c42f4d3abb318eb7c5cd8a3aef602aa8d67c6869eb08432656e9  specs_and_reports/v2/corpus/H4/fuzz_counts.tsv
89a9c18909fd877727fcda8e46c2a2865789df11b8e649bb5030a3e58cdde5cb  specs_and_reports/v2/corpus/H4/seeds.tsv
1234b8d297f6d286e4fc9db19adb7c8f60e145f9a3f21526ff219104f9c4c4c3  specs_and_reports/v2/gates/E3-G.tsv
be73443e6826fa4e88b8b37952c1eaac858212fa45a45d4f4be3d036a845eea5  specs_and_reports/v2/corpus/E3/corpus.tsv
93cb4bd69377a80f23ecbfed76209d6edc35cf08d9e2fa4998939ef404724cc4  specs_and_reports/v2/corpus/E3/fuzz_counts.tsv
feeb2030f0b8a8a2410e203663bfa32926cacc659eda1bd5cbce21a87b0864ca  specs_and_reports/v2/evidence/E3/SHA256SUMS
```

(The full `fuzz_counts.tsv` and `MANIFEST.tsv` are in the tree; the report does
not duplicate every row.)

## 8. Bugs found and fixed

The campaign itself found **no engine or oracle defect**: every mutant was
classified by the C07 surfaces without a single escape, crash or hang. The
defects found and fixed were in the harness while making it honest:

| defect | evidence | fix |
|---|---|---|
| Prerequisite parser looked for a non-existent `c07.verdict` row in `E3-G.tsv` | self-test failure #1 | require `e3g.fuzz.accepted_invalid/crashes/timeouts` rows to be `PASS` with value `0` |
| Seed directory round-trip was not byte-stable (catalogue order) | self-test failure #2 | sort the catalogue by item id before writing/reading |
| `fieldswap` body swap could pick two overlapping ranges (a no-op mutation) | self-test failure #3 | swap disjoint halves of the body |
| Self-test compared bytes of mutants whose planned repair intentionally rewrites CRCs | self-test failure #4 | skip the byte-equality assertion for `repair_outer_crcs` plans |
| Gate-verdict parser accepted rows with the wrong column count | self-test failure #5 | require 8 tab fields and `verdict == PASS` |
| Alloc guard API mismatch (`allocate_for_new*` does not exist) | build failure | use C07's `raw_allocate` / `raw_release` |
| Runner passed `const Source&` to `validate`/`decode` | build failure | hold `Source*`, `SpanSource` in an `optional` |
| `-Werror` unused-helper cycle in the runner | build failure | delete `shard_range_text`, move `mutation_class_name` to `marp::harness` |
| Isolation target flagged H4's own `marp::harness::fuzz` symbol | `h4-isolation` failure | forbid only H1/H3 symbols (`generate`, `run_gate`, `decode_file`) |

No check was loosened, no mutant skipped, and no timeout/crash/acceptance was
suppressed to reach the target.

## 9. Decisions on ambiguity (narrow interpretation)

1. **Verification surface**: "feed every mutant to `verify` and `decode`" is
   implemented as C07 `validate` (verify) + `decode` on the same bytes, with
   `encode(decode(m)) == m` as the canonicality condition. A mutant accepted by
   only one surface is `accepted_invalid`, which is stricter than comparing
   verdicts alone.
2. **What a `valid` mutant means**: structurally valid *and* canonically
   encoded. The corpus is canonical (E3), so a mutation that is accepted but not
   canonical is a bug, not a pass.
3. **Timeouts**: both the fork watchdog (killed at the bound) and a mutant that
   returns after the bound are counted as timeouts. Both are zero.
4. **Allocation**: an over-budget allocation is recorded as an alloc violation
   and failure (`allocation-budget-exceeded`); zero observed.
5. **`total`**: the requested mutant count, always executed in full. `total` is
   never reduced by "skip" logic; a mutant that cannot be materialised within
   bounds would be a failure, not a skipped index.
6. **Seed limitation**: only seeds whose digests are committed by E3-G are used
   (no H4-invented wires), and `fuzz-virtual-2pow40` (an unassembled T-GEN
   descriptor, not a wire) is not a seed.
7. **CI authority**: the campaign is run on CI over the pushed branch with
   `--write-evidence`; committed evidence is compared byte-for-byte with the CI
   output, and a second CI campaign must reproduce it again.
8. **Index coverage**: see §4 — two index-bearing seeds give 3,147 index-region
   mutants; the 3 MiB seed is deliberately not used because it triples per-mutant
   CRC cost for no new class coverage.

## 10. Known limitations

* **Stages 9 and 11 are not reached** by in-place mutation (`stage9_root=0`,
  `stage11_eval=0`): a mutated root id or total-length field that survives the
  canonical shape checks is rejected earlier (trailer/region rules), and the
  eval stage requires a fully consistent container whose declared length
  disagrees with its denotation, which a single-field mutation cannot produce
  while keeping the CRCs and region table coherent. E3-G's `W-NONCANON` corpus
  covers those stages with hand-built cases. This is recorded rather than
  papered over.
* **Allocation accounting is thread-local**: the campaign runs one mutant per
  thread at a time, so the accounting is exact for the mutant; it is not a
  whole-process RSS measurement.
* **Fork model**: the authoritative campaign uses one forked worker per shard,
  so a crash is observed as a worker death rather than a signal in the harness
  process; the in-process mode (`--no-fork`) is exercised by the sanitizer leg
  and by the determinism dry run.
* **Sanitizer leg**: `h4-san` builds with `-DH4_ALLOC_GUARD_DISABLED` because
  the replacement allocation hooks collide with the ASan runtime, so the
  sanitizer campaign reports `peak alloc=0` and its evidence records
  `alloc_guard_enabled=false`. The guard-enabled campaign (§6) is the
  authoritative allocation measurement.
* **Wall time** on a 2-core machine is ~93 s per 100,000-mutant campaign; the CI
  job runs two campaigns plus an ASan campaign to prove reproducibility within
  its 40-minute budget.
* **Mutation classes** are the four named by §12.8; E3-G's reference mutator has
  additional classes (CRC repair modes, index rewrites) that H4 covers through
  field swaps and length corruption rather than by copying E3-G.

## 11. CI verification

The authoritative run executes the campaign on GitHub Actions over the pushed
branch (`2faa1b38`) and regenerates every committed artifact itself.

| item | value |
|---|---|
| Workflow | `MARP H4 FUZZ CI` (`.github/workflows/h4-fuzz.yml`) |
| Run | `43866731951` — https://github.com/nexuss0781/MARP/actions/runs/43866731951 |
| Conclusion | **SUCCESS**, 2026-11-16T12:27:22Z → 12:31:17Z |
| Head commit | `2faa1b38` (`2faa1b3` — harness, evidence, workflow, report) |
| Final-tree run | `43873262895`, head `d74fc89` — same jobs, same evidence diff, green |
| Jobs | `h4-source-independence` ✓, `h4-selftest` ✓, `h4-campaign` ✓ (2m10s) — all hard-fail |
| Campaign in CI | `--root .. --workers 4 --write-evidence`; counters identical to §6; evidence diffed byte-for-byte against the committed files |
| Independent repeat | second full CI campaign diffed byte-for-byte against the first, and `sha256sum -c` re-run |
| Sanitizers | ASan+UBSan campaign, 2,000 mutants in-process, `detect_leaks=1`, zero reports |
| Artifact | `h4-evidence`, ID `14225942124`, 8,437 bytes, digest `sha256:c26ecc319ed45f343b0008702c5b2414779303459f6e4d923a084b8bc477cd2b` |
| Final-tree verification | run `43873262895` (SUCCESS, head `d74fc89`) executes the same three jobs over the tree that contains this report; it re-ran the 100,000-mutant campaign, diffed all six artifacts byte-for-byte against the committed files, repeated the campaign, and passed the ASan+UBSan leg |
| Later documentation edits | a further documentation-only commit pins the run IDs above and triggers one more identical verification run; because it changes no source, seeds or evidence, the measured values remain those of run `43866731951` |

No-regression runs on the same head `2faa1b38` (all `success`): C03 TERM
`43866731815`, C04 CANON `43866731783`, C05 EVAL `43866731784`, C06 DAG
`43866731847`, C07 WIRE `43866732100`, C08 LEGACY `43866731743`, H3 Oracle
`43866731733`, E2-G `43866731712`, E3-G `43866731756`. The H1 and H2 workflows
are branch-pinned (`h1-fixtures` / `h2-gates`) and do not trigger on this
branch; their sources are unchanged and the `h4-selftest` job's frozen-path
`git diff` fails the build if that stops being true.

## 12. Acceptance checklist

| requirement | evidence | status |
|---|---|---|
| E3-G merged and green before H4 | §2 (run `43858184768`, committed gate) | PASS |
| Seeds are E3-produced committed canonical wires | §4, 15 × `h4.seed.reproduced`, set digest | PASS |
| Warning-free build under required flags | `make -f Makefile.h4 h4-all` (`-Werror -Wconversion -Wshadow -Wformat=2`) | PASS |
| H4 tests pass | `--self-test`: `PASS 0 self-test failure(s)` | PASS |
| No regression to H1/H2/H3, E1/E2/E2-G, C03–C08, E3-G | §11: nine earlier workflows green on the same head; CI diff over frozen paths; H4 adds only new files | PASS |
| Full 100,000-mutant campaign in CI with recorded config | §6, `fuzz_counts.tsv` | PASS |
| `accepted_invalid = crashes = timeouts = 0` | §6 | PASS |
| Every mutant accounted for | `processed = valid + rejected = 100000` | PASS |
| Evidence/log/manifest generated, committed, matching the run | §7, CI byte-diff | PASS |
| Report committed | this file | PASS |
