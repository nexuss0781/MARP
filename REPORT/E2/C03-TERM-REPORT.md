# C03 `TERM` — Implementation Report (E2 ALGEBRA)

**Work item:** C03 `TERM` — term grammar, well-formedness, denotation, and the closed
morphism / predictor / LFSR catalogues.
**Component:** E2 `ALGEBRA`, sub-component 1 of 4 (C03 TERM → C04 CANON → C05 EVAL → C06 DAG).
**Normative sources:** `SPECS/SPECS-V2.md` §3.1–3.7, §4, §5.5, §8.2–8.3;
`SPECS/COMPONENTS/e2-algebra/SPECS.md` §4, §5.1, §5.3–5.5, §8, §9;
`SPECS/COMPONENTS-V2.md` §4 (C03).
**Language:** C++20 only. No Python, no third-party library except GoogleTest in the
unit tests.

**This report claims C03 only.** It does **not** claim E2-G, and it does not claim
any wire-level (E3) behaviour. See §7 for the exact handoff.

---

## 1. Environment, base, branch, and authoritative CI run

| Field | Value |
|---|---|
| Repository | `nexuss0781/MARP` |
| Branch | `arena/ef2b1162-marp` |
| Base commit | `b8ac4e9ede0afad236fc24c19895f4ffbf4bf24f` (`h2-gates`, H2 closeout + H3 + H1 merged) |
| Worktree | clean except the files listed in §2 (no pre-existing file is modified) |
| **Authoritative CI run** | **`43637200859` — `MARP E2 C03 TERM CI` — conclusion `success`** |
| **CI run URL** | https://github.com/nexuss0781/MARP/actions/runs/43637200859 |
| CI commit | `878257b812a94d5caff8d4c59d64a4312ade36f3` |
| No-regression check | `MARP H3 Oracle CI` run `43637200866` — `success` on the same commit |
| Local toolchain | Debian `g++ 12.2.0`, GNU make 4.3, x86-64, 2 vCPU |
| CI toolchain | `ubuntu-latest`, `g++ 13.3.0`, GoogleTest built from source at CI time |
| Flags | `-std=c++20 -pedantic -Wall -Wextra -Werror -Wconversion -Wshadow -Wnull-dereference -Wdouble-promotion -Wformat=2 -O2` (E2 §12.4 build level; sanitizer variants add `-fsanitize=address,undefined -O1 -g`) |
| Evidence harness | `engine/src/e2/e2_c03_gate.cpp` → `bin/e2_c03_gate --root .. --write-evidence` |
| Unit tests | `engine/tests/e2/e2_term_test.cpp` → `bin/e2_c03_tests` (33 cases) |

The report itself is a documentation-only follow-up commit; it adds no measured value and
changes no evidence file. CI re-runs the identical pipeline on it, and the cited run above
is the run in which the committed evidence was reproduced byte for byte.

---

## 2. Files added / changed — and what was **not** touched

Added (11 files, no deletions, no edits to existing files):

```text
include/mapr/e2/e2_term.hpp              C03 public surface (429 lines)
engine/src/e2/e2_term.cpp               C03 implementation (1640 lines)
engine/src/e2/c03_build.hpp             harness/test IR builder (evidence support)
engine/src/e2/c03_reference.hpp         independent reference semantics (evidence support)
engine/src/e2/e2_c03_gate.cpp           evidence harness (1818 lines)
engine/tests/e2/e2_term_test.cpp        GoogleTest suite (1085 lines, 33 cases)
engine/Makefile.e2                      isolated build (includes base Makefile for flags only)
.github/workflows/e2-c03.yml            isolated CI workflow
specs_and_reports/v2/gates/C03-TERM.tsv harness-written evidence (1322 rows)
specs_and_reports/v2/logs/C03-TERM.log  harness-written log
specs_and_reports/v2/evidence/E2/SHA256SUMS  harness-written manifest
```

`git status` on the branch shows **only** additions. Verified untouched:

- E0-G / E1-G / H1 / H3 evidence, corpora, manifests and logs
  (`specs_and_reports/v2/{gates,logs,corpus,evidence}/{E0-G,E1-G*,H1-*,H3-*}`) —
  CI re-verifies all three committed manifests (`sha256sum -c`) on every run;
- `engine/Makefile`, `.github/workflows/ci.yml`, `.github/workflows/h1-fixtures.yml`,
  `.github/workflows/h3-oracle.yml`, `harness/src/gates.cpp`;
- the E1 surface (`include/mapr/e1_*.hpp`, `engine/src/e1_*.cpp`) — used, not changed;
- no E3–E7 file exists or is referenced by this work.

Deployment of the new target does not alter the default `make` target of
`engine/Makefile`: `Makefile.e2` `include`s it and adds only its own targets.

---

## 3. C03 API / surface implemented

All in `namespace marp::v2`, header `include/mapr/e2/e2_term.hpp`.

### 3.1 IR and closed domains

```cpp
enum class Kind : u8 { Empty=0, Atom=1, Zero=2, Concat=3, Repeat=4, Slice=5,
                       Morph=6, Xor=7, Interleave=8, Lfsr=9, Affine=10, Predictor=11 };
struct Atom { u8 klass; u8 flags; BigInt length; std::array<u8,32> sha256;
              std::span<const u8> payload; };
struct Node { Kind kind; u8 flags; std::vector<u32> args; BigInt a, b;
              u8 morph, morph_k; u64 lfsr_conn, lfsr_init;
              u8 affine_start, affine_step; u8 predictor_id; u32 predictor_param;
              BigInt length; };
struct Ir   { std::vector<Atom> atoms; std::vector<Node> nodes; u32 root;
              BigInt total_length; };
```

`parse_kind` / `check_kind_domain` / `kind_name` make the kind domain total and closed
(values 12…255 are `Invalid`, never mapped to a nearest kind).

### 3.2 Validation and lengths

```cpp
WfReport check_well_formed_report(const Ir&);                     // first failure + id
WfReport check_well_formed_report(const Ir&, const Limits&);      // testability hook
Status   check_well_formed(const Ir&);                            // normative predicate
Status   check_well_formed(const Ir&, const Limits&);
Status   verify_atom_digests(const Ir&);                          // E1 SHA-256, opt-in
Result<std::vector<std::optional<BigInt>>> recompute_lengths(const Ir&);
Result<std::vector<BigInt>> recompute_lengths_checked(const Ir&);
```

### 3.3 Denotation / evaluation building blocks

```cpp
class Sink { virtual Status write(std::span<const u8>) = 0; };
Status eval_stream(const Ir&, Sink&);
Status eval_stream(const Ir&, u32 node, Sink&);
Status eval_range(const Ir&, const BigInt& start, const BigInt& length, Sink&);
Result<std::size_t> read_range(const Ir&, u32 node, const BigInt& start,
                               std::span<u8> out);
class TermCursor { Result<std::size_t> read(std::span<u8>);
                   const BigInt& remaining(); const BigInt& offset(); bool at_end(); };
Result<std::vector<u8>> denote_node(const Ir&, u32 node, u64 max_bytes);  // C03 helper
Result<std::vector<u8>> denote_root(const Ir&, u64 max_bytes);
```

### 3.4 Closed catalogues and LFSR

```cpp
u8     apply_morph_byte(u8 morph, u8 k, u8 in);            // E2 §8 surface
Result<u8> apply_morph_byte_checked(u8 morph, u8 k, u8 in);
Status apply_morph_to_buffer(u8 morph, u8 k, std::span<u8>);   // all nine morphs
Status check_morph_domain / check_morph_params / morph_block_size / morph_is_byte_local
u8     apply_predictor_step(u8 pid, u32 param, u8 residual, u8 prev1, u8 prev2);
Result<u8> apply_predictor_step_checked(...);
Status apply_predictor_to_buffer(u8 pid, u32 param,
                                 std::span<const u8> residual, std::span<u8> out);
Status check_predictor_domain / check_predictor_params
Status check_lfsr_conn; u64 lfsr_parity / lfsr_step; u8 lfsr_next_byte(u64&, u64);
struct Gf2Matrix64; lfsr_step_matrix / gf2_apply / gf2_compose / gf2_power;
Result<u64> lfsr_state_at_byte_offset(u64 conn, u64 init, const BigInt& byte_offset);
class LfsrStream;  Status lfsr_read_range(u64 conn, u64 init, const BigInt&, std::span<u8>);
std::string structural_key(const Ir&, u32 node);           // C03 helper, §5.7 shape
```

Deliberately **not** implemented (owned elsewhere): `canon`, `is_canonical`,
`check_canonical`, the `canonical_key` ordering policy (C04); incremental predictor
checkpoints (C05); `Dag` interning and id assignment (C06); any encode/decode, discovery,
selection, CLI, MAU, certificate (E3–E7).

---

## 4. Coverage and key vectors

### 4.1 Well-formedness (W1–W8, §5.1 order)

The first-failure order implemented is the fixed order of E2 §5.1: **counts → flags (+ kind
domain, atom record consistency) → root → reachability/atom usage → total length →
argument ordering → recomputed lengths → §8.3 output cap → depth → kind constraints**.
Canonical shape (§4.7) is explicitly *not* evaluated here (C04).

Constraint identifiers reported by the harness: `W1.counts`, `W4.atom-flags`,
`W4.node-flags`, `W8.kind-domain`, `W6.atom-payload-length`, `W2.root`,
`W2.unreachable-node`, `W3.arg-range`, `W2.unused-atom`, `W5.total-length`,
`W3.arg-order`, `W6.length`, `S1.output-cap`, `W7.depth`, `W8.argc`, `W8.atom-id`,
`W8.atom-length`, `W8.repeat`, `W8.slice`, `W8.morph`, `W8.xor`, `W8.interleave`,
`W8.lfsr`, `W8.predictor`.

Evidence: **52 `wf.accept` rows** (every kind plus compositions, including a 65 536-deep
chain that is exactly at the W7 bound) and **61 `wf.reject` rows**, one per violation
class, each asserting the *exact* code **and** constraint identifier — including all twelve
`argc` mismatches, both `flags` bytes, root out of range, unreachable node, unused atom,
arg out of range, arg ≥ own index, `total_length` mismatch, ten stored-length mismatches
(one per kind family), `Lfsr conn = 0`, unknown morph/predictor ids, every wrong `k`,
`SWAP16/32/64` length violations, `Xor`/`Interleave` length mismatches, `stride = 0`,
`L % stride ≠ 0`, stride outside `u32`, `Repeat q=0 ∧ r>0`, `r ≥ ℓ(child)`, `Slice`
`start > ℓ` and `start+len > ℓ`, zero-length atom, atom id out of range, `pid = 5`,
`pid ∈ {3,4}` with `param = 0`, depth `2^16+1` → **`Limit`**, output `> 2^63` → **`Limit`**,
and tightened record-count limit → **`Invalid`**.

**Stored lengths are never trusted.** `length.stored` (48 rows) corrupts the root stored
length of every materialisable corpus term (keeping `total_length` consistent so `W5`
passes) and on an intermediate atom node; every case is rejected with `W6.length` at the
offending id. `recompute_lengths_checked` is computed bottom-up from structure only.

### 4.2 Length and denotation (§4.4, §4.9)

All twelve kinds are exercised on two independent axes:

- **length**: `47` `length` rows compare the engine's recomputed `ℓ(root)` against an
  independent recursive structural length **and** against `|⟦t⟧|` of the reference
  denotation; `5` `length.big` rows do the same for virtual terms
  (`Repeat(atom(4), 2^60, 3) = 2^62+3`, `Zero(2^62+1)`, `Slice(Zero(2^62+5), 2^40+7, 100)`,
  `Slice(Affine(2^39), 2^40)`, `Slice(Lfsr(2^40), 2^32+5, 64)`), never materialised.
- **denotation**: `47` `denotation` rows compare the engine's ⟦root⟧ with the independent
  reference (`engine/src/e2/c03_reference.hpp`), which materialises recursively, reverses
  bits through a runtime 256-entry table, and iterates the LFSR bit by bit — no code is
  shared with the engine.

### 4.3 Range evaluation (§5.3–5.5)

- `607` `range` rows: for each materialisable term, ranges `(0,0)`, `(0,1)`, `(ℓ-1,1)`,
  `(ℓ/2, min(4096,·))`, `(0,ℓ)` and eight seeded pseudo-random ranges, each compared to the
  corresponding slice of the materialised reference.
- `17` `range.big` rows at offsets `0, 1, 2^32, 2^32+1, 2^39, ℓ-64` over the virtual terms,
  with analytically derived expected bytes (period-4 payload for `Repeat`, zeros for
  `Zero`/`Slice(Zero)`, the affine formula, and the LFSR jump-ahead tail).
- `5` `range.beyond` rows: any range past the declared length is `Invalid`.
- `2` `range.limit` rows: a predictor range at `start > 2^28` on `Predictor(XOR8, Zero(2^30))`
  returns **`Limit`** (§5.5 policy) while the same term at offset 1024 returns the exact
  bytes.
- `47` × 4 rows of `eval.stream`, `eval.range-all`, `eval.cursor`, `eval.sink-error`:
  streaming, whole-range, monotone-cursor (deliberately awkward chunk sizes 1,3,7,2,13,…)
  and sink-error propagation all agree with the full denotation.

No range path allocates proportional to `ℓ(node)` or to `start`: the only allocations are
`O(range)`, plus `O(block)` in mirrored morphs and `O(s)` for a stride-predictor window.

### 4.4 Morphisms (§4.6) — all nine

`21` `morph.kat` rows (ids 1,2,3,4,5,8,9 with `k=0`; id 6 and id 7 with **every** `k` in
1..7), `7` `morph.involution` rows (1,2,3,4,5,8,9 applied twice = identity), `49`
`morph.compose` rows (`ROTL8(a)∘ROTL8(b) = ROTL8((a+b) mod 8)` for all 49 pairs), `12`
`morph.reject` rows (unknown ids 0 and 10, wrong `k` for ids 1,2,6,7 including `k=0` and
`k=8`, and `SWAP16`/`SWAP32`/`SWAP64` length violations), `11` `morph.byte` rows for the
byte-local primitive plus its rejection of the five non-byte-local ids.

Pinned values in the unit tests (hand-derived from §3.4): `BIT_REVERSE8(0x01)=0x80`,
`BIT_REVERSE8(0x96)=0x69`, `INVERT8(0xA5)=0x5A`, `ROTL8(0x81,1)=0x03`,
`ROTR8(0x81,1)=0xC0`, `SWAP16(1,2,3,4)=(2,1,4,3)`, `SWAP32(1..8)=(4,3,2,1,8,7,6,5)`,
`SWAP64(1..8)=(8..1)`, `REVERSE_BITS(0x01,0x00)=(0x00,0x80)`, and the normative identity
`REVERSE_BITS = REVERSE_BYTES ∘ BIT_REVERSE8`.

### 4.5 Predictors (§4.11) — pids 0–4

`13` `predictor.kat` rows (pid 0,1,2; pid 3 with `param ∈ {1,2,5,64,65}`; pid 4 with
`param ∈ {1,3,7,64,2000}`), `15` `predictor.short` rows (`n = 0..4` for pids 0–2, pinning
the seeding rules), `4` `predictor.reject` rows (`pid = 5`, `pid = 9`, `param = 0` for
pids 3 and 4), `3` `predictor.step` rows. Pinned values:
`DELTA8([10,15,3,4,250]) = [10,25,28,32,26]`, `XOR8 → [10,5,6,2,248]`,
`LINEAR2 → [10,15,20,25,30]`, `STRIDE_XOR(s=2) → [10,15,9,11,243]`,
`STRIDE_DELTA(s=2) → [10,15,13,19,7]`; `param ≥ n` degenerates to the identity, exactly as
the seeding rule `out[i] = r[i]` for `i < s` requires.

### 4.6 LFSR (§4.10) — exact bit order and jump-ahead

`42` `lfsr.kat` rows: six `(conn, init)` pairs × lengths `1,7,8,9,64,65,129`, compared
against a literal transcription of the §3.5 pseudocode (parity by bit loop, MSB-first
packing). `1` `lfsr.bitorder` row asserts the first emitted bit becomes the MSB of byte 0.
`54` `lfsr.jump` rows: six pairs × nine offsets `{1,2,3,255,256,2^20,2^32,2^40,2^50}` compare
the engine's `T^(8·offset)·init` **and** the following 64 bytes against an independent
**row-oriented** 64×64 GF(2) exponentiation; `1` `lfsr.reject` row for `conn = 0`.

`lfsr_state_at_byte_offset` performs matrix square-and-multiply over the `BigInt` exponent
`8·offset`, so an offset costs `O(log offset)` matrix products; nothing advances bit by bit
from zero on the range path. Pinned first bytes for `conn=0x80200003, init=1`:
`80 00 00 00 40 10 00 01 …` (derived by hand for the first two bits and then by the
independent implementation).

### 4.7 Determinism, coverage, independence

`2` `determinism` rows: a digest over every corpus term's WF verdict, length and 4096-byte
denotation is computed twice and must agree; two structurally identical terms built in
different construction orders must denote identically. `3` coverage rows assert
12/12 kinds, 9/9 morphs, 5/5 predictors exercised. `1` `independence` row scans
`include/mapr/e2` + `engine/src/e2` for forbidden includes (E3–E7, harness, container,
encoder, decoder, DAG, pipeline, MAU) and digests the scan.
CI additionally enforces: `grep` on the C03 sources, `nm -uC` on `obj/e2/e2_term.o`, and
`nm -C` on the test binary, all of which must show no E3–E7/harness symbol.

---

## 5. Spec readings, conflicts, and decisions

1. **`Atom` has `argc = 0`; the atom id lives in `Node::a`.**
   E2 §4.5 gives `Atom` argc `0` with the constraint `a < atoms.size()`, while parent §5.5
   lists `uvarint atom_id` as an `Atom` *param*. Taken literally this means the atom id is
   carried in the `a`/`b` slot pair, not in `args`. Consequence: `Atom` never participates in
   W3 ordering, and the atom-usage rule of W2 reads `Node::a`. The narrow reading is used and
   documented in the header's field-mapping comment.

2. **`Interleave` stride is carried in `Node::a`.**
   E2 §4.2's `Node` has no stride field, while parent §5.5 types it `u32`. `a` is therefore
   used and must fit `u32` (`interleave_stride` returns `Invalid` otherwise); the W6 length
   rule `k·ℓ(c₁)` is unaffected. Flagged for the C04 wire-parameter check.

3. **`Predictor` has no separate `n`.**
   E2 §4.5 writes "`len(residual) = n`" but neither parent §3.2 nor §5.5 gives `Predictor`
   an `n` parameter; `ℓ(Predictor) = ℓ(residual)` is W6. Read as a redundant statement of
   that equality; nothing is approximated.

4. **`LINEAR2` (`pid = 2`) — inherited spec defect, implemented literally.**
   Both `SPECS/SPECS-V2.md` §3.6 and `e2-algebra/SPECS.md` §4.11 define
   `out[0]=r[0], out[1]=r[1], out[i]=(2·out[i-1]-out[i-2]) mod 256`, which never consults
   `r[i]` for `i ≥ 2` and therefore contradicts E2 §7 O3.3 ("every predictor reconstructs its
   input from its residual exactly"). H3 reported this defect (`REPORT/HARNESS/H3-ORACLE-REPORT.md`
   §7 item 7) and implemented the literal text. **C03 does the same**: the literal formula is
   the normative text, and the residual argument of `apply_predictor_step(2, …)` is unused by
   design. The defect is *not* silently repaired; it is pinned by `predictor.step/linear2-literal`
   and by `PredictorDenotationShortResiduals`, and it must be resolved upstream (both
   documents) before E2-G/E3 freeze — at which point one line of `e2_term.cpp`, one line of
   `c03_reference.hpp`, and the H3 oracle's `case 2U` change in lockstep.

5. **`Repeat` with `q = 0 ∧ r > 0` is rejected by WF — a real conflict with §4.7.**
   E2 §4.5 (and parent §3.2's normal form) require `r = 0` when `q = 0`, so such a term is
   `Invalid`. §4.7 rule 5 / §5.2 rule 5 nevertheless describe the rewrite
   `Repeat(c,0,r>0) → Slice(c,0,r)`, which presupposes that the term can exist. Since
   `canon` takes `WF` terms as its precondition, the pre-canonical form is unreachable.
   **Decision:** WF follows §4.5 literally (the narrower, explicitly normative statement);
   the rewrite rule becomes vacuous. Recorded for C04, which must not depend on that redex
   firing (O4.5 "every rule fires at least once" will need this rule counted as unreachable
   or the upstream text amended).

6. **`param` for `pid ≤ 2`.**
   E2 §4.5 constrains only `pid ≥ 3 ⇒ param ≥ 1`; E3 §4.6 / H3 additionally require
   `param = 0` for `pid ≤ 2`. Per the reading rules, the E2 component text governs E2:
   `param` is *unused* for pids 0–2 and any value is well formed. The stricter wire rule is
   E3's, and it is invisible through the wire path. Recorded so that C04 can decide whether a
   canonicality rule (`param = 0` for `pid ≤ 2`) is desirable.

7. **Atom record consistency is part of WF.**
   `Atom::length` is documented as "payload byte length". WF therefore rejects
   `length ≠ payload.size()` (`W6.atom-payload-length`); without it, E2-I2
   (`ℓ(t) = |⟦t⟧|`) could not hold and range reads could leave the payload. Digests are
   *not* re-hashed by `check_well_formed` (E3 owns payload/digest verification); the explicit
   `verify_atom_digests` surface is used by the harness.

8. **Placement of W5 and the output cap in the first-failure order.**
   §5.1 lists counts, flags, root, reachability, args, lengths, depth, kind constraints.
   `total_length` (W5) is checked immediately after root/reachability (it is a root-level
   consistency fact), and the §8.3 output cap immediately after the length pass, before depth
   and kind constraints. Both are documented in code order and pinned by evidence rows.

9. **`apply_morph_byte` is byte-local only.**
   The E2 §8 signature returns `u8` and cannot express SWAP16/32/64 or the mirrored morphs.
   Implemented exactly for ids 1, 2, 6, 7; for the other ids it returns its input unchanged
   and the engine never calls it. The checked variant `apply_morph_byte_checked` returns
   `Invalid` for every non-byte-local id, and `apply_morph_to_buffer` is the exact primitive
   used by evaluation and by the KATs — so nothing is approximated anywhere.

10. **`apply_predictor_step` seeding contract.**
    `out[0] = r[0]` for every pid, `out[1] = r[1]` for pid 2, and `out[i] = r[i]` for
    `i < s` (pids 3, 4) cannot be expressed by a stateless step function; the caller seeds
    (passing `prev1 = 0` for `i < s` makes the recurrence identical to the table). The
    contract is documented in the header and pinned by `predictor.short`.

11. **`Limits` struct for W1/W7/§8.3 testability.**
    `check_well_formed_report(ir, Limits)` exists only so a `2^24`-record or `2^16`-depth
    bound can be exercised without allocating gigabytes; the defaults are the normative
    constants and `check_well_formed(ir)` uses them. No semantic change.

12. **Predictor window resource policy.**
    For `pid ∈ {3,4}` with `s < ℓ(residual)` the prefix pass keeps `s` output bytes
    (§5.5's `O(range)` allowance). A window above 16 MiB returns `Limit` rather than
    allocating unbounded memory; when `Ok` is returned the bytes are exact. No checkpoint
    support (C05 scope).

13. **Range before policy.**
    `read_range` rejects out-of-length ranges with `Invalid` before the §5.5 predictor
    policy applies; the policy `Limit` is therefore observable only for legal ranges.

14. **`structural_key` is a C03 helper, not the C04 policy.**
    It is a pre-order encoding with atom identity `(length, sha256)` — never the atom index,
    so it is id-independent as §5.7 requires. Its exact bytes are not normative.

---

## 6. Evidence summary

Generated by `engine/src/e2/e2_c03_gate.cpp`; nothing in the TSV is hand-edited.

| Artefact | SHA-256 (from the committed manifest) |
|---|---|
| `specs_and_reports/v2/gates/C03-TERM.tsv` | `12e1fcddcf9afeea84de6c5144cd2e71347e5137892a842335e37f9e72ceefe5` |
| `specs_and_reports/v2/logs/C03-TERM.log` | `ff3b4497119243c089d4ee9583c0b904dd940752b6e055a067a70251e273e181` |

**Rows: 1321 checks, 1321 PASS, 0 FAIL, 0 BLOCKED** (plus one `c03.summary` row).

| check | rows | check | rows | check | rows |
|---|---|---|---|---|---|
| `range` | 607 | `wf.reject` | 61 | `lfsr.jump` | 54 |
| `wf.accept` | 52 | `morph.compose` | 49 | `length.stored` | 48 |
| `length` | 47 | `denotation` | 47 | `eval.stream` | 47 |
| `eval.range-all` | 47 | `eval.cursor` | 47 | `eval.sink-error` | 47 |
| `lfsr.kat` | 42 | `morph.kat` | 21 | `range.big` | 17 |
| `predictor.short` | 15 | `predictor.kat` | 13 | `morph.reject` | 12 |
| `morph.byte` | 11 | `morph.involution` | 7 | `length.big` | 5 |
| `range.beyond` | 5 | `predictor.reject` | 4 | `wf.limit` | 3 |
| `predictor.step` | 3 | `range.limit` | 2 | `determinism` | 2 |
| `lfsr.reject` | 1 | `lfsr.bitorder` | 1 | `independence` | 1 |
| `coverage.kind` | 1 | `coverage.morph` | 1 | `coverage.predictor` | 1 |

Determinism is enforced three ways:

1. in-harness: `determinism/repeat-run` and `determinism/construction-order` rows;
2. in CI: the evidence run is executed **twice** and the two TSVs are diffed;
3. in CI: the TSV committed on the branch is diffed against the CI-generated TSV
   byte for byte, and the ASan/UBSan evidence run must reproduce it as well.

The TSV deliberately contains no compiler, host, timestamp, or absolute path data, so a
clean checkout on a different machine reproduces it exactly; only the log's environment
record is machine-specific, which is why CI byte-compares the TSV (as H3 does) and
re-verifies the committed log through its manifest before regeneration.

Sanitizers: `e2-test-san` (33 tests, ASan+UBSan) and the sanitizer evidence binary both
pass in CI and locally. Independence: `e2-independence` (source `grep` + `nm` on the C03
objects) plus CI's `nm` on the test binary.

CI steps in the green run (`43637200859`), all successful:

```
Reject E3-E7 / harness includes in C03 sources
Reject non-C++ artefacts in C03 paths
Confirm H1/H2/H3 artefacts untouched by this work   (sha256sum -c on E1, H1, H3 manifests)
Build C03 (strict -Werror, -O2 per E2 §12.4)
Verify C03 independence (grep + nm on the built objects)
Snapshot committed evidence and verify manifest
Run C03 unit tests                                   (33/33 PASS)
Generate C03 evidence                                (1321/1321 PASS)
Committed C03-TERM.tsv must match the CI-generated TSV byte for byte
Evidence schema, verdicts and required checks
Determinism (independent re-run must reproduce the TSV)
AddressSanitizer + UBSan C03 unit tests
AddressSanitizer + UBSan C03 evidence run
Restore the primary evidence set
Upload C03 evidence artifact
```

---

## 7. Known limitations and handoff

### 7.1 Not claimed by this work

- **E2-G is not claimed.** C03 is the first of four E2 sub-components. The E2-G gate
  (§12.2) additionally requires `canon`/`is_canonical`/`canonical_key` (C04), the
  streaming/range integration and predictor checkpoints (C05), `Dag` interning and
  construction-order independence (C06), the full corpus (`T-GEN` 5000, `T-BIG` 64,
  `T-NONCANON` 200, `T-CRIT` 1000, `T-RANGE` 13 per term, `M-KAT` 96, `L-KAT` 48),
  rewrite counters (O4.1/O4.5), thread-count invariance, and agreement with the
  independent H3 oracle.
- No wire behaviour, no discovery/selection, no CLI/MAU/certificate.

### 7.2 Deliberate scope edges inside C03

- The C03 corpus is 52 `T-KAT`-style terms and 5 virtual `T-BIG`-style terms, not the
  full E2-G corpus. `T-GEN`, `T-NONCANON`, `T-CRIT` and the 13-ranges-per-term matrix
  belong to the E2-G harness, which will reuse the same `read_range`/denotation surfaces.
- The independent oracle used here is `engine/src/e2/c03_reference.hpp` (C03 semantics).
  E2-G additionally requires the clean-room **H3** oracle, which is wire-level and
  currently has no `Ir` entry point; wiring it is E2-G/C05 work, not C03's.
- `TermCursor` recomputes lengths once and then evaluates block by block through
  `read_range`. For a predictor-heavy term each block re-runs the prefix pass
  (`O(ℓ/block · start)`); C05's incremental streaming state and checkpoints remove that.
  Correctness is unaffected — the cursor never returns wrong bytes, only more slowly.
- `check_canonical`, `is_canonical`, `canon` are absent by design; `structural_key` is
  C03's id-independent description helper and must not be mistaken for C04's
  `canonical_key` ordering policy.
- Canonical shape (§4.7) is not enforced anywhere in C03; a WF term with a nested
  `Concat`, a `Concat` with an `Empty` child, a full-cover `Slice`, etc. is well formed and
  denotes correctly. C04 owns that predicate.
- Predictor ranges above `2^28` return `Limit` (§5.5 permits this); checkpoints are C05.

### 7.3 Handoff to C04 / C05 / C06

| Consumer | What C03 gives it |
|---|---|
| C04 CANON | `check_well_formed`, `recompute_lengths_checked` (postcondition checks for every rewrite), `apply_morph_to_buffer` (morph folding/composition), `structural_key` (interning keys, id-independent), the `Kind`/param field mapping of §5.1, and the decision that `Repeat(q=0, r>0)` is WF-invalid (decision 5). |
| C05 EVAL | `read_range`, `TermCursor`, `eval_stream`, `eval_range`, `Sink`, the `LfsrStream` jump-ahead (`lfsr_state_at_byte_offset`), the predictor recurrence (`apply_predictor_step`) and the `2^28` prefix policy constant. |
| C06 DAG | `Ir`/`Atom`/`Node` as declared, `recompute_lengths_checked` for `finish`, atom identity `(length, sha256)`, and `structural_key` equality semantics (atom-index independent). |
| E2-G | 1321 PASS evidence rows, a reusable harness-written TRS generator pattern (`check/corpus/item/sha/expected/actual/verdict/log`), CI wiring that proves byte-identical reproduction, and 33 pinned unit tests. |

### 7.4 Acceptance checklist (this work)

| Item | Status |
|---|---|
| Builds warning-free under the required flags on CI; C03 tests pass (incl. sanitizers) | **yes** — `-Werror` build, 33/33 tests, ASan+UBSan run in CI |
| All 12 node kinds with correct denotation/length semantics | **yes** — §4.2, 47 denotation + 47 length rows |
| All 9 morphisms and 5 predictors with correct ids/params/constraints/formulas | **yes** — §4.4/§4.5, 21+49+12+7+11 morph and 13+15+4+3 predictor rows |
| LFSR semantics/bit order/jump-ahead | **yes** — 42 KAT + 1 bit-order + 54 jump rows vs independent GF(2) |
| `WF` rejects invalid cases; no stored-length trust | **yes** — 61 reject + 48 stored-length rows |
| No E3–E7 linkage; no H1/H2/H3 regressions | **yes** — grep/`nm` checks, E1/H1/H3 manifests re-verified in CI |
| Evidence/log/manifest/report generated and committed, matching the green run | **yes** — run `43637200859` |
| This report committed | **yes** |

*End of C03 report.*
