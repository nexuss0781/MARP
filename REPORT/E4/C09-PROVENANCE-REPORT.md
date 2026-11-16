# C09 `PROVENANCE` — Implementation Report (E4 MEASURE)

**Scope:** C09 `PROVENANCE`, sub-component 1 of 3 of E4 `MEASURE` (MARP v2). This
report claims **C09 only**. C10 `SEGMENT`, C11 `PROBE` and the integrated
**E4-G** gate are **not** claimed and are not affected by this work.

**Sources:** `SPECS/COMPONENTS/e4-measure/SPECS.md` (MARP2-E4) §4.1, §4.3, §5.1,
§6, §8, §9, §11; `SPECS/SPECS-V2.md` §6.1 (M0), §8.2 (V2-G2), §12.6 (V2-G14);
`SPECS/COMPONENTS-V2.md` §6 C09; `MARP/SPECS/COMPONENTS/e4-measure/C09-PROVENANCE-PROMPT.md`.

---

## 1. Environment, base, branch, CI

| Field | Value |
|---|---|
| Repository | `nexuss0781/MARP` |
| Branch | `arena/e9fde969-marp` |
| Base commit | `879ecd15c05d1b1471dc2161b33fcf4f8bdf28da` (`h2-gates` HEAD at branch time) |
| Local toolchain | `g++ (Debian 12.2.0-14+deb12u1) 12.2.0`, GNU Make 4.3, 2 vCPU |
| CI toolchain | `ubuntu-latest`, GCC from `build-essential`, GoogleTest built from source at CI time |
| Build flags | `-std=c++20 -pedantic -Wall -Wextra -Werror -Wconversion -Wshadow -Wnull-dereference -Wdouble-promotion -Wformat=2 -O2` |
| Sanitizer flags | same warnings, `-O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined -fno-sanitize-recover=all` |
| Locally observed gate result | `rows=348 pass=348 blocked=0 fail=0` — `RESULT: PASS` |
| Locally observed unit tests | 17/17 GoogleTest cases pass (plain and ASan+UBSan builds) |

The authoritative CI run on this branch is the `MARP E4 C09 PROVENANCE CI`
workflow run recorded on the GitHub PR/commit for the implementation commit. Its
run ID and URL are recorded in the pull request body at push time; the evidence
files committed with this report are byte-identical to the artefacts that run
regenerates (the workflow diffs them, §4).

**Why no run ID is written here:** this report is committed in the same push as
the code it describes, so any run ID written at that moment would describe the
*previous* commit. The workflow instead makes the claim mechanically checkable —
`diff -u` against the committed files — which is a stronger statement than an ID
pasted into prose. See §4.

---

## 2. Files added or changed

Nothing that existed was modified. C09 is additive: every new path is new, and
no frozen file, no earlier evidence file, and no earlier workflow changed.

| Path | Role |
|---|---|
| `include/mapr/e4/e4_measure.hpp` | New. C09 surface: `MeasureCode`, `MeasureResult<T>`, `Policy`, `Source`, `SpanSource`, `Provenance`, `provenance()`, `derive_seed()`, `provenance_matches()`, `provenance_text()`. |
| `engine/src/e4/e4_provenance.cpp` | New. The one-pass implementation and the seed formula. |
| `engine/src/e4/c09_gate.cpp` | New. The evidence harness (`engine/bin/c09_gate`). |
| `engine/tests/e4/e4_c09_provenance_test.cpp` | New. 17 GoogleTest cases. |
| `engine/Makefile.c09` | New. Isolated build: E1 + C09 + the H3 SHA-256 reference (gate only). |
| `.github/workflows/e4-c09.yml` | New. Isolated workflow: independence, build, tests, sanitizers, evidence regeneration, determinism, no-regression. |
| `specs_and_reports/v2/gates/C09-PROVENANCE.tsv` | New. 348 evidence rows, all `PASS`. |
| `specs_and_reports/v2/logs/C09-PROVENANCE.log` | New. Fixed banner + 89 deterministic log lines. |
| `specs_and_reports/v2/evidence/C09/SHA256SUMS` | New. Manifest of the header, the implementation, the TSV and the log. |
| `REPORT/E4/C09-PROVENANCE-REPORT.md` | This report. |
| `LEDGER.md` | One appended section recording the C09 outcome. |

### Linkage: what C09 is built from

| Linked | Why |
|---|---|
| `engine/src/e1_bigint.cpp` | `Provenance::length` is an exact `BigInt` (E4 §4.3). |
| `engine/src/e1_sha256.cpp` | The only digest implementation (E4 §2.2: digests belong to E1). |
| `engine/src/e1_gear.cpp` | The only gear table and roll (E4 §4.5: "`G` is the fixed 256-entry gear table of E1"). |
| `harness/oracle/src/sha256.cpp` | **Gate only.** H3's clean-room SHA-256, used as the independent reference. It is not in the C09 library and not in the C09 test binary. |

Not linked: E2, E3, E5, E6, E7, Stage 1/2 engine (`container`, `encoder`,
`decoder`, `bitio`, `dag`, `math_core`, `dedup_index`, `deflate_frontend`,
`thread_pool`, …), `harness/src/*`, `marp::oracle` in the library. `c09-isolation`
and the workflow's `nm` check both enforce this; the `nm` output for
`obj/c09/e4/e4_provenance.o` contains exactly the six C09 symbols and nothing
else.

### No regressions

* No frozen header changed (`include/mapr/e1_*`, `include/mapr/e2/**`,
  `include/mapr/e3/**` byte-identical to the base commit).
* No frozen source changed (`engine/src/e1_*.cpp`, `engine/src/e2/**`,
  `engine/src/e3/**`, `harness/**`).
* All 12 pre-existing evidence manifests still verify (`sha256sum -c`), and the
  workflow asserts that from the tree so a later component is covered
  automatically.
* No earlier workflow's trigger, job, or evidence path was touched.

---

## 3. API, implementation, seed and digest details

### 3.1 Surface

```cpp
namespace marp::v2 {

enum class MeasureCode : int { Ok = 0, Io = 3, Mismatch = 6, Invalid = 4 };
template <typename T> class MeasureResult;   // T | MeasureCode, no exceptions

struct Policy { u8 effort = 5; };            // E4 §4.10: every gate runs at effort 5

class Source {                                // E4 §4.1
  virtual BigInt size() const noexcept = 0;
  virtual MeasureCode read(const BigInt& off, std::span<u8> dst) const noexcept = 0;
};

struct Provenance {
  BigInt length;                 // exact
  std::array<u8, 32> sha256;     // SHA-256 of the whole input
  u64 gear;                      // gear_hash of the whole input, seed 0
  u64 seed;                      // effort seed
};

MeasureResult<Provenance> provenance(Source&, const Policy&);
MeasureResult<u64>        derive_seed(std::span<const u8, 32> digest, u8 effort);
MeasureStatus             provenance_matches(Source&, const Provenance&, const Policy&);
std::string               provenance_text(const Provenance&);
}
```

`Source` returns `MeasureCode`, not a `bool`: E4 §9 makes "unreadable or short"
a named error (`Io`), and a bool would collapse it into "some failure".
`measure_code_name()` renders the codes, so the evidence never prints an
integer the reader has to decode.

The surface is deliberately smaller than the E4 §8 sketch, which also lists
`segment` and `probe`. Those are C10 and C11; adding them now would mean
declaring an entry point with no implementation, which invites a caller to
believe C10 exists.

### 3.2 The pass

One loop, one fixed 64 KiB block:

```
remaining = source.size(); pos = 0
while remaining > 0:
    want = min(65536, remaining)
    rc = source.read(pos, block[0..want))     -> anything but Ok is Io
    sha.update(block[0..want))
    gear.update(block[0..want))               // E1 GearHash, seed 0
    pos += want; remaining -= want
length = the declared size; sha256 = sha.finish(); gear = gear.finish()
```

Properties that follow from the shape and are measured in evidence:

* **one pass** — `Source::read` is called exactly `ceil(L / 65536)` times
  (`c09.streaming.single_pass`, six sizes including 0 and 1);
* **no materialisation** — no request exceeds 65536 bytes
  (`c09.streaming.bounded_buffer`) and for every input larger than a block the
  largest request is strictly smaller than the input
  (`c09.streaming.no_materialisation`);
* **exact accounting** — bytes served equals `L`
  (`c09.streaming.bytes_accounted`);
* **O(1) working memory** — one 64 KiB block, one SHA-256 state, one `u64`
  (`E4 §11`).

The loop bound is the exact remaining `BigInt`, not a scan for end-of-input, so
a source that under-delivers produces `Io` and never a silently truncated
digest (E4 §9). There is no `try`, no `throw`, and no `abort` in the library.

### 3.3 Seed

```
seed = LE64( SHA-256( "MARP2-seed" ‖ LE32(effort) ‖ sha256(x) )[0..8) )
```

* The domain literal is exactly the 10 bytes `4D 41 52 50 32 2D 73 65 65 64`
  (`"MARP2-seed"`). Its length is asserted twice (`kSeedDomainLen == 10` in the
  unit test, and a source-level check in the gate).
* `LE32(effort)` is four bytes, little-endian, zero-extended from the `u8`.
* The digest is the whole-input SHA-256 from the same pass, so the seed is
  derived from bytes already hashed rather than from a second read.
* The result is assembled byte by byte from `digest[0..8)`, so the seed is a
  little-endian *value* on every host, independent of host endianness.
* `effort > 9` is `Invalid` (E4 §4.10 defines `0..9`; the policy is the
  caller's contract). Nothing else about the policy reaches the value.

`derive_seed` is exposed so the gate can check the formula directly against an
independent construction, rather than checking `provenance` against a second
call to `provenance`.

### 3.4 Errors

| Condition | Code | Evidence row |
|---|---|---|
| source declares more bytes than it serves | `Io` | `c09.errors.short_read` |
| source fails a read (block 1, 2, 4) | `Io` | `c09.errors.read_failure` |
| effort outside `0..9` | `Invalid` | `c09.errors.effort_domain` |
| recorded provenance ≠ source | `Mismatch` | `c09.repeat.matches` |
| effort inside `0..9` | `Ok` | `c09.errors.effort_domain_ok` |

`provenance_matches` is the C10 precondition (`segment(source, prov, policy)`
requires "`prov` matches `source`"). It re-runs the pass and compares all four
fields field-by-field; a mismatch of `length`, `sha256`, `gear`, or `seed` is
`Mismatch`, and a failing source is `Io` (not `Mismatch`), which keeps the two
causes distinguishable in C10's evidence.

---

## 4. Tests and evidence

### 4.1 GoogleTest (`engine/tests/e4/e4_c09_provenance_test.cpp`, 17 cases)

| Case | Obligation |
|---|---|
| `KatTable` | length / sha256 / gear / seed against a pinned reference for 9 vectors |
| `SeedPerEffort` | the same 9 vectors at efforts 0, 5, 9; effort changes only `seed` |
| `SeedDomainLiteral` | the domain is exactly `"MARP2-seed"`, 10 bytes |
| `DeriveSeedIsPureAndInjectiveEnough` | `derive_seed` is deterministic, 10 efforts give 10 distinct seeds, `10..255` is `Invalid` |
| `MatchesE1SurfacesOnGeneratedBytes` | 8 sizes (0, 1, 63, 64, 65, 4095, 65536, 65537) against E1 one-shot `Sha256::hash` and `gear_hash` |
| `StreamingSinglePassBoundedBuffer` | exactly `ceil(L/65536)` reads, no request > 65536, no request ≥ `L` |
| `StreamingChunkSizeInvariance` | two `Source` implementations, identical `Provenance` |
| `DeterminismAcrossRuns` | 8 repeats identical; two reads of the same range identical (E4-I11) |
| `BytewiseSensitivity` | a one-bit flip at 4 positions changes the digest |
| `ShortReadIsIo`, `ReadFailureIsIo` | `Io` |
| `OutOfDomainEffortIsInvalid` | `Invalid` |
| `SpanSourceBoundsAreIo` | boundary reads: `start == size` non-empty, straddle, exact fit, empty read |
| `MatchesReportsMismatch` | tampering each of the 4 fields is `Mismatch`; a different source is `Mismatch`; a failing source is `Io` |
| `NameAndExtensionIndependent` | 5 different labels, identical rendered provenance |
| `ProvenanceTextIsStable` | the rendering is a pure function |
| `LargeInputIsExact` | 4 MiB + 12345 against E1 one-shot references |

### 4.2 Gate (`engine/src/e4/c09_gate.cpp` → `bin/c09_gate`)

348 rows, all `PASS`, in ten groups:

| check | rows | what it pins |
|---|---|---|
| `c09.kat.length` / `.sha256` / `.gear` / `.seed` | 9 each | pinned vectors (empty, 1 byte, 2 bytes, `0x00`×64/65, `0xFF`×65, `"abc"`, `"MARP"`, `'A'`×4096) |
| `c09.kat.seed_effort_sweep` | 9 | every vector at all 10 efforts against the independent formula; only `seed` moves |
| `c09.reference.sha256` | 43 | C09 vs **H3's clean-room SHA-256** over 43 generated fixtures |
| `c09.reference.gear` | 43 | C09 vs an **independently written** gear recurrence |
| `c09.reference.seed` | 43 | C09 vs **coreutils/perl-derived** seed values |
| `c09.reference.length` | 43 | C09 length vs the fixture length |
| `c09.reference.e1_oneshot` / `.e1_gear_oneshot` | 43 each | the streaming pass vs E1's frozen one-shot surface |
| `c09.streaming.single_pass` / `.bounded_buffer` / `.no_materialisation` / `.bytes_accounted` | 6 each | one pass, 64 KiB bound, no materialisation (0, 1, 64 KiB, 64 KiB+1, 1 MiB+1, 3 MiB+77) |
| `c09.repeat.deterministic` / `.reread_identical` / `.matches` | 1 each | 17 identical runs, re-read identity, self-match + tamper rejection |
| `c09.seed.stable` / `.effort_separates` / `.byte_sensitive` / `.formula` | 1 each | 32 runs identical; 10 distinct seeds; one bit changes seed and digest; `derive_seed` == independent formula for all fixtures |
| `c09.errors.*` | 9 | `Io` and `Invalid` paths |
| `c09.names.independent` | 1 | 5 labels, one identity |
| `c09.isolation.*` | 4 | no E2–E7 include, no clock/locale/randomness/file access, no term-shaped type, return type pinned by `static_assert` |

The 43 reference fixtures come from three corpora: `C09-CORE` (8 hand-written
identities), `C09-EDGE` (30 — zeros and `0xFF` at 63/64/65, 127/128/129,
255/256/257, 4095/4096/4097, 65535/65536/65537), `C09-SCALE` (5 —
1 MiB and 2 MiB+12345 splitmix streams, a 4 KiB tile repeated to 1 MiB, and an
affine ramp). All fixtures are generated in-process from pinned constant seeds;
the gate reads no input file, so no fixture can carry a name or a path into any
value.

### 4.3 How the pinned values were derived (not by the code under test)

Three independent derivations were made before the implementation was written:

1. **SHA-256** — H3's clean-room `harness/oracle/src/sha256.cpp` (compiled from
   its own sources with its own include path; it includes no `mapr/` header) and
   coreutils `sha256sum` for the literal vectors. The two agree on all nine
   vectors; for example `sha256("")` is
   `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` and
   `sha256("abc")` is
   `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad`.
2. **Gear** — a separate implementation of Math-SPECS §15.1
   (`h = (h << 1) + ((x*C1) ^ (x*C2))` with the two published constants)
   compared against E1's `gear_hash` on all nine vectors: 9/9 equal.
3. **Seed** — built outside the repository with Perl `Digest::SHA` and
   `pack("V", $effort)` / `pack("H*", $digest)`, reading the first eight bytes
   little-endian. The values agree with the independent C++ construction used by
   the gate. For example, for the empty input, `effort 5`, the seed is
   `0xcd140ec74dd6d355`, and `effort 0` / `effort 9` give
   `0x238c533748c1885e` / `0x37f0f5ef3aa94dd7`.

The KAT table in the gate and in the unit test is therefore a **reference**, not
a regression snapshot: three implementations that share no code produce it.

### 4.4 Determinism and reproducibility

* Two independent runs to different `--out-root` directories produce
  byte-identical TSV, log, and manifest (verified locally and asserted again in
  CI with `diff -u`).
* The ASan+UBSan gate binary reproduces the same three files byte for byte.
* The log has a fixed banner and no host, date, compiler string, pid, path, or
  duration. The workflow greps the committed log for those tokens and fails if
  any appears.
* Every committed file's digest is in `specs_and_reports/v2/evidence/C09/SHA256SUMS`
  (repo-root-relative, so `sha256sum -c` works from the repository root):

```
2f8c156c47f607f69f8f50068c8e41296befcf57ab22d87dc3b88833dc24aa76  include/mapr/e4/e4_measure.hpp
c2004af625044cf039abf5d01521c95e7f4e115186236610092228e181e18147  engine/src/e4/e4_provenance.cpp
005026c13e888ea6b56e082181aa7ba5185d3a1c73c65479609c0f9bb373c66d  specs_and_reports/v2/gates/C09-PROVENANCE.tsv
52c9009bcf9b5c229b43cba636f0ecd19c87d0edbe04a6272319a397102eb487  specs_and_reports/v2/logs/C09-PROVENANCE.log
```

### 4.5 CI

`.github/workflows/e4-c09.yml`, two jobs:

1. `c09-independence` (source level): forbidden includes, environment/clock/
   locale/randomness access, term-shaped types, non-C++ artefacts under C09
   paths, and every pre-existing evidence manifest.
2. `build-test-evidence`: strict `-O2` build of the isolated target, `c09-isolation`
   (`grep` + `nm`), `nm` on the test binary, manifest verification *before*
   regeneration, the GoogleTest suite, regeneration + `diff -u` against the
   committed evidence, schema/verdict/required-check/log-hygiene validation, an
   independent repeat run, ASan+UBSan tests and a sanitizer gate run that must
   also reproduce the committed evidence, and a no-regression `git diff --quiet`
   over every frozen path and every earlier gate TSV.

Local equivalents were run before pushing: `c09-all`, `c09-isolation`,
`c09-test`, `c09-test-san`, `c09-evidence`, `c09-verify-evidence`, the workflow's
four `grep`/`find` gates, the schema/verdict/required-check/hygiene assertions,
and the repeat-run diff.

---

## 5. Spec readings and decisions

Each is the narrowest reading consistent with the normative text.

1. **`Provenance` includes `gear`.** `SPECS/COMPONENTS-V2.md` §6 C09 shows
   `{ length, sha256, seed }`; MARP2-E4 §4.3 and §8 show
   `{ length, sha256, gear, seed }`, and the C09 prompt §1/§2 requires "gear hash
   of the whole input (E1 gear, seed 0)". The component spec and the prompt are
   the more specific and more recent statements, so `gear` is a field. This is
   additive: a consumer written against the shorter record still finds every
   field it expects.
2. **`Policy` is defined here, minimally.** No `Policy` exists in the tree yet;
   E4 §8's signature needs one and §4.10 defines `effort 0..9`. C09 declares
   `struct Policy { u8 effort = 5; }`. A C10 or C11 field will extend this
   struct; nothing in C09 reads it, so the extension cannot change a C09 value.
3. **`Source::read` returns `MeasureCode`, not `bool`.** E4 §4.1's sketch is
   illustrative; §9 requires `Io` for an unreadable or short source. Returning
   the code keeps the taxonomy in the type, and a bool would force a second
   error channel. C09's `Source` is a distinct type from E3's (`include/mapr/e3`)
   on purpose: E4 §2.2 forbids linking E3, and reusing its header would create
   exactly the dependency the gate exists to prevent.
4. **Length is `source.size()`, not "bytes actually read".** E4 §4.3 says
   `length` is exact for the input, and E4 §9 makes a short read `Io`. A
   successful return therefore always satisfies `length == source.size()`, and
   the pass compares its consumed `BigInt` against that exactness rather than
   trusting it. A source that lies is rejected, not measured.
5. **Effort outside `0..9` is `Invalid`, not a clamp.** §4.10 defines the
   domain; silently clamping would make two different policies produce the same
   evidence, which is exactly the kind of ambiguity E4 §4 forbids. `0` and `9`
   are in the domain and are exercised.
6. **`provenance_matches` is provided now.** C10's precondition is "`prov`
   matches `source`" (E4 §5.2), and §9 gives `Mismatch` for that condition. C09
   owns the function so C10 does not have to re-derive it; it is implemented as
   a second pass plus a field compare, and it distinguishes `Io` from `Mismatch`.
   It is not used by `provenance` itself.
7. **The 64 KiB block is a constant, not a policy knob.** E4 §11 requires O(1)
   memory; making the block configurable would let a caller make provenance
   depend on a resource parameter, which E4-I1 does not allow. The block affects
   neither the value nor the number of *bytes* read, only the number of calls.
8. **`provenance_text` exists for evidence, not for the wire.** E3 owns the wire;
   E4 §2.2 forbids E4 writing one. The renderer is a diagnostic string used by
   the log and by the name-independence row, and it is a pure function of
   `Provenance`.
9. **No `BLOCKED` rows.** C08 recorded `BLOCKED` for a genuinely missing input
   (W-V1). C09 has no external corpus dependency — every fixture is generated
   in-process — so a `BLOCKED` row would be a way of avoiding a check, not a
   fact about the world. There are none; if a precondition were ever missing the
   gate would fail rather than skip.
10. **The gate does not claim E4-G.** E4 §12.2's condition is about segmentation
    at 1 and 4 threads, partition exactness, observation reproducibility,
    locality, coverage counters, and rename independence across
    `provenance` + `segment` + `probe`. Only the provenance clause is measurable
    today. The workflow name says C09, the log says C09, and this report says
    C09.

---

## 6. Limitations and handoff to C10

### Limitations

* **No performance claim.** The pass hashes at the speed of E1's portable
  SHA-256 (measured locally at ≈219 MB/s on this 2-vCPU sandbox for the
  SHA-256 + gear combination). E4-G does not gate provenance throughput, and no
  number here is presented as one.
* **No multi-gigabyte exercise.** The largest gate fixture is 3 MiB + 77 B, and
  the unit suite reaches 4 MiB + 12345. The `BigInt` length arithmetic and the
  block loop are exact for any length, but a >2^32-byte input is not measured.
  The `Source` contract permits it; no fixture materialises it.
* **One `Source` implementation ships.** `SpanSource` is the only concrete
  source; file-backed sources are the harness's or E6/E7's business, and E4
  §10 forbids E4 from deciding boundaries from anything but bytes.
* **`Mismatch` has no producer inside `provenance`.** It can only arise from
  `provenance_matches` (or from C10's precondition). That is a property of the
  spec, not a gap: a function that computes an identity cannot mismatch itself.
* **The seed's collision properties are not claimed.** Two different
  (bytes, effort) pairs *can* produce the same 64-bit seed; the gate pins the
  seed's value, not its injectivity. Effort separation is measured on one fixed
  byte string only (`c09.seed.effort_separates`), which is a property of the
  formula, not a statistical claim.

### Handoff to C10 `SEGMENT`

C10 needs, and now has:

* `Source` with the exact-length, re-readable, deterministic contract (§4.1);
* `Provenance` carrying `length`, `sha256`, `gear`, and `seed`;
* `provenance_matches(Source&, const Provenance&, const Policy&)` for the
  `segment(source, prov, policy)` precondition, with `Io` and `Mismatch`
  separated;
* the E1 gear table surfaced through `Provenance::gear` as the whole-input
  roll — C10's per-scale rolls restart at 0 inside each chunk (E4 §4.5) and must
  not be derived from the whole-input value;
* `Policy` as the single extension point for C10's budgets.

C10's `SCALES`, chunk constants, and change-point thresholds (`E4 §4.4`–`4.5`)
are **not** pre-empted here. No boundary, segment, or observation type exists in
this commit.

### Handoff to E4-G

E4-G will need `c09.*` rows to remain reproducible when `segment` and `probe`
land. Nothing in this work blocks that: `Provenance` is frozen by this evidence
manifest, and the C09 gate is independent of C10/C11 by construction (it links
neither).

---

## 7. Acceptance checklist (C09 prompt §8)

| # | Item | State |
|---|---|---|
| 1 | Builds warning-free under the required flags; tests pass; no regressions | **Met** — `-Werror` build of the isolated target; 17/17 tests plain and under ASan+UBSan; no frozen file touched; 12 prior manifests verify |
| 2 | `provenance` returns exact `length`, whole-input SHA-256, gear (seed 0), seed per spec; one streaming pass, no whole-input materialisation | **Met** — `c09.kat.*`, `c09.reference.*`, `c09.streaming.*` |
| 3 | Seed/outputs deterministic (bytes+effort only); correct vs references | **Met** — `c09.repeat.*`, `c09.seed.*`, `c09.kat.seed`, `c09.reference.seed` |
| 4 | No E2–E7 linkage; no term/candidate emission; no filename/type dependence | **Met** — `c09.isolation.*` (source `grep`, `nm`, `static_assert`), `c09.names.independent` |
| 5 | Evidence/log/manifest/report committed and matching the final green CI run | **Met on push** — the workflow diffs the committed TSV/log/manifest against a fresh run, an independent repeat run, and a sanitizer run; a mismatch fails CI |
| 6 | `REPORT/E4/C09-PROVENANCE-REPORT.md` committed | **Met** — this file |

**Not claimed:** C10 `SEGMENT`, C11 `PROBE`, **E4-G**, and any E5–E7 behavior.
