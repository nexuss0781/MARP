# E7 — BOUNDARY — Component Specification

| Field | Value |
|---|---|
| **Document ID** | MARP2-E7 |
| **Version** | 1.0 |
| **Status** | Normative for E7. Derived from `SPECS-V2.md`. |
| **Parent** | `MARP/SPECS/SPECS-V2.md` |
| **Decomposition** | `MARP/SPECS/COMPONENTS-V2.md` |
| **Depends on** | E1–E6 (frozen). Gate requires `E0-G`. E7 wraps; it adds no algebra and no discovery. |
| **Language** | C++20. No third-party libraries. No Python. |
| **Gate** | `E7-G` |

---

## 0. Reading rules

1. This document is normative for E7 only. The parent governs the mandate; on conflict the parent wins.
2. `MUST` / `MUST NOT` are normative.
3. E7 introduces no new term semantics, no new candidate, and no new measurement of structure. If E7 fails, the defect is in the wrapper.
4. Every number in the MAU program is an exact decimal string. There is no truncation, no floating point, and no locale.
5. The gate is the only exit from this component.

---

## 1. Purpose

E7 is the boundary between the engine and everything outside it.

It answers three questions:

1. **What exact program does MAU receive?** (C20 `TRANSLATE`)
2. **What is the process contract: commands, exits, files?** (C21 `CLI`)
3. **What facts does the engine certify about a wire, and how are they recomputed?** (C22 `CERTIFY`)

It wraps what already passes. It does not repair, reinterpret, or extend it.

---

## 2. Scope

### 2.1 In scope

- The MAU `Program` projection with exact decimal strings.
- Purity and self-sufficiency of that projection.
- The complete v2 CLI: encode, decode, verify, inspect, term, floor, bench, spec-*.
- Exit codes 0/2/3/4/5/6/7.
- Atomic output: temporary sibling, self-verification, rename, no file on failure.
- Range decode for virtual `2^40`/`2^50` probes.
- The certificate: fields, recomputation, tamper rejection.
- Floor command *schema* and small-size measurement.

### 2.2 Out of scope

| Excluded | Owner |
|---|---|
| Term algebra, canonicalisation, evaluation | E2 |
| Wire format | E3 |
| Segmentation and probes | E4 |
| Candidates | E5 |
| Selection and classification | E6 |
| Full-size floor measurement and acceptance report | E0 (H5, H2) |
| MAU's own evaluator | MAU |
| `.nez` container | NEZITOR |
| Throughput and 1.02× ensemble claims | report rows (A2) |

E7 MUST NOT reimplement any E2–E6 rule. It calls them.

---

## 3. Sub-components

| id | role | deliverable |
|---|---|---|
| C20 | `TRANSLATE` | `Program`, `from_ir`, decimal projection |
| C21 | `CLI` | `run_cli`, commands, exits, atomic write |
| C22 | `CERTIFY` | `Certificate`, `certify`, `verify` |

A sub-component is a responsibility, not a file. C21 may call C20 and C22; neither may call C21.

---

## 4. Formal model

### 4.1 Program

```cpp
namespace marp::v2::translate {

struct Atom {
    std::string bit_length;        // decimal, multiple of 8
    std::string sha256_hex;        // 64 lowercase hex chars
};

struct Term {
    u8 kind;
    std::vector<u32> args;         // absolute node ids, child < parent
    std::string a, b, length;      // decimal BigInt, see §4.2
    std::string conn, init;        // decimal, Lfsr only; empty otherwise
    u8 morph, morph_k;
    u8 affine_start, affine_step;
    u8 predictor_id;
    std::string predictor_param;   // decimal, Predictor only
};

struct Program {
    std::vector<Atom> atoms;
    std::vector<Term> nodes;
    u32 root;
    std::string total_length;      // decimal BigInt
};

Program from_ir(const Ir&);

} // namespace marp::v2::translate
```

`conn`, `init`, and `predictor_param` are decimal strings. The parent snippet (§9) carries `uint64_t`/`uint32_t` fields; those are exact by format but do not satisfy §9.1(1) literally. The decimal strings are the MAU-facing values; the fixed-width mirrors, if retained, MUST equal them. This is a derived correction, recorded in §14.

### 4.2 Numeric mapping

Every decimal string matches `0 | [1-9][0-9]*`. No sign, whitespace, leading zero, `+`, or exponent.

| kind | `a` | `b` | `length` | other |
|---|---|---|---|---|
| `Empty` | `0` | `0` | `0` | — |
| `Atom` | atom id | `0` | payload bytes | `args = {}` |
| `Zero` | `n` | `0` | `n` | — |
| `Concat` | `0` | `0` | sum | `args` = children |
| `Repeat` | `q` | `r` | `q·ℓ(child)+r` | `args = {child}` |
| `Slice` | `start` | `len` | `len` | `args = {child}` |
| `Morph` | `0` | `0` | `ℓ(child)` | `morph`, `morph_k`, `args = {child}` |
| `Xor` | `0` | `0` | `ℓ(a)` | `args = {a,b}` |
| `Interleave` | `stride` | `0` | `k·ℓ(child)` | `args` = children |
| `Lfsr` | `0` | `0` | `n` | `conn`, `init` decimal |
| `Affine` | `0` | `0` | `n` | `affine_start`, `affine_step` |
| `Predictor` | `0` | `0` | `ℓ(residual)` | `predictor_id`, `predictor_param`, `args = {residual}` |

`Atom.bit_length = 8 · payload_bytes`. Atom payload bytes are **not** in the Program; they form the separate atom stream in atom-id order.

### 4.3 Purity

`from_ir` is a pure function of the `Ir`:

- no locale;
- no clock;
- no address;
- no thread count;
- no file system;
- no hash-map iteration order;
- no dependence on the wire's optional index.

Two calls on the same `Ir` produce byte-identical programs under any `LC_ALL` and any thread count.

### 4.4 Self-sufficiency

MAU can reconstruct every node length from the Program alone:

```
recon(Empty)            = 0
recon(Atom)             = atoms[a].bit_length / 8     (= length)
recon(Zero)             = a
recon(Concat)           = Σ recon(child)
recon(Repeat)           = a·recon(child) + b
recon(Slice)            = b
recon(Morph)            = recon(child)
recon(Xor)              = recon(arg0)
recon(Interleave)       = |args| · recon(arg0)
recon(Lfsr)             = length
recon(Affine)           = length
recon(Predictor)        = recon(arg0)
```

For every node, `recon(node) = length` as exact decimal. `total_length = recon(root)`. The harness implements `recon` independently (H3) and fails the gate on any mismatch.

`Zero`, `Affine`, and `Lfsr` are directly evaluable from the Program at any range; `Repeat` and `Slice` translate the requested range onto their child; the other kinds descend into children. No payload is needed to compute any length.

### 4.5 Unknown kinds

A `Kind` outside 0..11 is emitted as:

```
kind = 255
args = {}
a = b = "0"
length = exact decimal (the declared node length)
```

This is parent §9.1(4)'s explicit `UNKNOWN` marker. No node is dropped, no length is guessed: the declared length is carried as a decimal string, and it is the caller's declared length, not a reconstruction. `from_ir` has no `Unsupported` path for an unknown kind — the marker exists precisely so the boundary never truncates a future IR. `Unsupported` is reserved for a future wire version at E3.

### 4.6 Certificate

```cpp
struct Certificate {
    u16 format_major, format_minor;
    u8  effort;
    std::string total_length;          // decimal
    std::array<u8,32> root_sha256;     // SHA-256 of the denotation
    std::array<u8,32> term_sha256;     // SHA-256 of the canonical wire
    u32 atom_count, node_count;
};
```

`term_sha256 = SHA-256(encode(canon(decode(wire))))`. The canonical wire is unique for the term, so this binds the term, its ids, its classes, and its payloads.

Canonical certificate text (UTF-8, one field per line, sorted keys):

```
atom_count=<decimal>
effort=<decimal>
format_major=<decimal>
format_minor=<decimal>
node_count=<decimal>
root_sha256=<64 lowercase hex>
term_sha256=<64 lowercase hex>
total_length=<decimal>
```

No trailing whitespace. A missing, duplicated, reordered, or non-canonical field is `Invalid`.

### 4.7 CLI

Commands and options are exactly parent §11. The only additive flag is `verify --cert <path>`, which compares a stored certificate; without it, `verify` recomputes and prints the facts.

| command | output |
|---|---|
| `encode` | `.mapr` wire, atomic |
| `decode` | exact bytes, optional `--range START:LEN` |
| `verify` | recomputed certificate, optional comparison |
| `inspect` | counts, sizes, atom residual, classes, coverage |
| `term` | MAU `Program` as JSON, decimal strings |
| `floor` | best-of-ensemble measurement row |
| `bench` | corpus timing rows |
| `spec-zero` | canonical wire for `Zero(n)` |
| `spec-repeat` | canonical wire for a repeated tile |
| `spec-lfsr` | canonical wire for `Lfsr` |
| `spec-affine` | canonical wire for `Affine` |

Exit codes:

| code | meaning |
|---|---|
| 0 | success |
| 2 | usage |
| 3 | I/O |
| 4 | invalid container or unrepresentable input |
| 5 | unsupported version or feature |
| 6 | verification mismatch |
| 7 | resource limit |

A failed command leaves no output file. A pre-existing output file is left byte-identical on failure. No temporary sibling remains.

### 4.8 Atomic write

`encode`, `decode`, `term`, `inspect`, `floor`, and `bench` write via:

1. create a temporary sibling in the destination directory with a unique name;
2. write and flush;
3. for `encode`, decode the temporary wire, compare bytes and SHA-256 with the input; on mismatch, unlink and exit 6;
4. rename the temporary sibling to the destination;
5. on any failure, unlink the temporary sibling.

The temporary name MUST NOT be derived from the input name in a way that changes semantics; it is an implementation detail and MUST NOT appear in output.

### 4.9 Range probe

`decode --range START:LEN` parses decimal `START` and `LEN`, requires `START + LEN <= total_length`, and writes exactly `LEN` bytes. It evaluates only intersecting subterms:

- `Zero`, `Affine`, `Lfsr`, `Repeat`, `Slice` support direct range evaluation;
- LFSR uses E2's `O(log offset)` jump-ahead;
- `Predictor` may evaluate a prefix and return `Limit` above the E2 policy;
- no allocation is proportional to `total_length`;
- the process MUST NOT materialise the full output.

For `F13 = 2^40` and `F14 = 2^50`, decoding the last 64 bytes is the gate's virtual probe.

### 4.10 Floor command

`mapr floor` runs the best available generic exact compressors (`xz -9e`, `zstd -19`, `brotli -q 11`, `bzip2 -9`), records one row per tool with command and version, marks unavailable tools `unavailable`, and reports:

```
input_bytes  xz_bytes  zstd_bytes  brotli_bytes  bzip2_bytes
best_bytes  best_tool  marp_wire_bytes  atom_residual_bytes  note
```

It is a measurement instrument. It is the only command allowed to spawn processes. `encode` and `decode` MUST NOT spawn anything. Full-size floor rows belong to H5/E0; E7-G checks the schema and a small-size row.

---

## 5. Operations

### 5.1 Translate

| operation | precondition | postcondition |
|---|---|---|
| `from_ir(ir)` | structurally coherent: child ids `<` parent id; every declared length is a valid decimal | `Program` with exact decimals, no payload; kind outside 0..11 becomes `255` |
| `program_json(program)` | — | canonical JSON, numbers as strings |

`from_ir` does not re-run E2 canonicality. The CLI path only receives a canonical `Ir` from E6; re-validating here would block the parent-mandated `UNKNOWN` marker and would duplicate E2's authority. A structurally incoherent `Ir` is `Invalid`; a merely non-canonical one is an upstream defect that E6 prevents. No atom payload is copied into the Program.

### 5.2 Certify

| operation | precondition | postcondition |
|---|---|---|
| `certify(source)` | wire validates | `Certificate` recomputed from the wire |
| `verify(source, cert)` | wire validates | `Ok` iff every field matches |
| `certificate_text(cert)` | — | canonical text |
| `parse_certificate(text)` | — | `Certificate` or `Invalid` |

`certify` recomputes the denotation, its SHA-256, and the canonical wire hash. It never copies a fact from the input certificate.

### 5.3 CLI

| operation | precondition | postcondition |
|---|---|---|
| `run_cli(argc, argv)` | — | exit code 0/2/3/4/5/6/7 |
| command handlers | — | atomic output, no ambient semantic input |

`run_cli` never throws past `main`. A signal, allocation failure, or uncaught exception is a crash and fails the gate.

### 5.4 Self-verification

`encode` verifies its own output before rename. A mismatch exits 6 and leaves the previous destination untouched. The self-check is the same decode path as `mapr verify`; it is not a second implementation.

---

## 6. Invariants

| id | invariant |
|---|---|
| E7-I1 | `from_ir` is pure and locale-independent. |
| E7-I2 | Every numeric Program field is canonical decimal. |
| E7-I3 | No atom payload appears in the Program. |
| E7-I4 | Every node length is reconstructible from the Program alone. |
| E7-I5 | A failed command leaves no output file and no temporary sibling. |
| E7-I6 | A pre-existing output file is unchanged on failure. |
| E7-I7 | Encode self-verifies before rename. |
| E7-I8 | Every exit code is one of 0/2/3/4/5/6/7. |
| E7-I9 | `verify` accepts only recomputed facts. |
| E7-I10 | A tampered certificate or wire is rejected. |
| E7-I11 | Range decode never materialises the full output. |
| E7-I12 | No command selects semantics by file extension. |
| E7-I13 | Only `floor` and `bench` may spawn processes. |

---

## 7. Proof obligations

| id | obligation | measurement |
|---|---|---|
| O11.1 | `from_ir` is byte-identical across runs, threads, and locales | repeated calls under two locales |
| O11.2 | every decimal is canonical and round-trips | regex + parse/render |
| O11.3 | every length is reconstructible from the Program | independent H3 reconstructor |
| O11.4 | the Program evaluates to the decoded bytes over sampled ranges | independent H3 evaluator |
| O11.5 | no payload byte is in the Program; the atom stream matches | byte scan and SHA-256 |
| O11.6 | `certify` matches an independent recomputation | certificate compare |
| O11.7 | every certificate field and wire region is tamper-rejecting | mutation matrix |
| O11.8 | every CLI failure exits non-zero and writes no file | failure matrix |
| O11.9 | a pre-existing output survives a failed command | sentinel compare |
| O11.10 | a successful write leaves no temporary sibling | directory scan |
| O11.11 | `F13`/`F14` end-range decode is exact and bounded | RSS and wall row |
| O11.12 | `floor` schema is complete on a small input | parsed TSV |
| O11.13 | unknown kind becomes `UNKNOWN`, never dropped | fabricated IR |

O11.11's RSS bound is part of the gate; wall time is reported. O11.12 checks schema, not the 1.02× claim (A2).

---

## 8. C++ interface

```cpp
namespace marp::v2 {

struct Certificate {
    u16 format_major, format_minor;
    u8 effort;
    std::string total_length;
    std::array<u8,32> root_sha256, term_sha256;
    u32 atom_count, node_count;
};

Result<Certificate> certify(Source& wire);
Result<void>        verify(Source& wire, const Certificate&);
std::string         certificate_text(const Certificate&);
Result<Certificate> parse_certificate(std::string_view);

int run_cli(int argc, char** argv);

namespace translate {
    Program from_ir(const Ir&);
    std::string program_json(const Program&);
}

} // namespace marp::v2
```

`run_cli` owns `main`'s process contract. No engine header except E7's may be included by `main.cpp`.

---

## 9. Error taxonomy

| condition | code |
|---|---|
| unknown command, missing value, bad flag, bad decimal | 2 |
| input, output, or temporary file failure | 3 |
| invalid container, non-canonical term, unrepresentable input | 4 |
| future major/minor version, unsupported legacy feature | 5 |
| self-verification or certificate mismatch | 6 |
| resource limit: depth, expansion, memory, range | 7 |
| certificate parse error | 4 |
| certificate field mismatch | 6 |

A crash (signal or uncaught exception) is never an accepted exit code.

---

## 10. Authority boundary

**E7 may:**
- call E2–E6;
- read and write files;
- spawn the floor ensemble;
- expose the process contract.

**E7 may not:**
- reimplement term semantics, wire validation, discovery, selection, or classification;
- accept a certificate it did not recompute;
- write an output file before success;
- select semantics by file name or extension;
- change the wire format or the Program schema;
- be required by any earlier gate.

---

## 11. Determinism and resources

- `from_ir` and certificate rendering are pure.
- CLI output bytes depend only on input bytes, flags, and effort.
- Atomic write uses a temporary sibling and rename; no cross-device rename is attempted.
- `decode --range` memory is `O(block + depth)`, independent of `total_length`.
- `encode` streams; peak memory is E6's bound.
- Locale is fixed internally for decimal parsing and formatting; `LC_ALL` cannot change output.
- `floor` records the tool version and command; an unavailable tool is recorded, never skipped silently.

---

## 12. Success gate E7-G

### 12.1 Preconditions

| requirement | state |
|---|---|
| `E0-G` … `E6-G` PASS with evidence; surfaces frozen | required |
| H3 independent Program reconstructor/evaluator available | required |
| `F13`/`F14` virtual specs runnable | required |
| Small CLI fixtures and a writable scratch directory | required |

If any precondition is unmet, E7-G is `BLOCKED`, never `PASS`.

### 12.2 The condition

> **For every IR in the boundary corpus, the MAU program is pure, canonical-decimal, payload-free, and self-sufficient for every node length; an independent evaluator reproduces the decoded bytes from the program over sampled ranges; `certify` matches an independent recomputation and rejects every tamper; every CLI failure exits with its declared code and leaves no output or temporary file; and the `2^40`/`2^50` end-range probes are byte-exact within the memory bound. One mismatch fails the gate.**

### 12.3 Corpus

| id | contents | count |
|---|---|---|
| `P-KIND` | canonical IRs covering all 12 kinds, nesting depth 1–4, atom sizes 1, 4 096, `ATOM_MAX`, lengths `0, 1, 63, 64, 65, 2^32, 2^64-1, 2^64, 2^64+1, 2^100, 2^128` via `Zero`/`Affine`/`Lfsr`/`Repeat`/`Slice` | 128 |
| `P-DEC` | decimal edge values for every numeric field: `0`, `1`, `9`, `10`, `2^64-1`, `2^64`, `2^128-1`, `2^128`, `2^256` | 32 |
| `P-UNKNOWN` | fabricated `kind = 255` with a declared length | 4 |
| `P-WIRE` | canonical wires from E3 for `F00`, `F01`, and small structured inputs | 16 |
| `P-TAMPER` | each certificate field altered, plus wire header/trailer/atom/node/index bit flips and truncations | 64 |
| `P-CLI` | success and failure cases: empty, 1 B, 4 KiB text, 4 KiB random; bad flag, missing input, unwritable dir, truncated wire, future version, length mismatch, resource limit | 24 |
| `P-RANGE` | `spec-zero 2^40`, `spec-zero 2^50`, `spec-repeat` with a 4 KiB tile at `2^40` | 3 |
| `P-FLOOR` | 1 MiB structured and 1 MiB random inputs | 2 |
| `P-JSON` | `term` and `inspect` on `P-WIRE` | 16 |

### 12.4 Procedure

1. Build the engine, CLI, and harness with `-O2 -Wall -Wextra -Werror`.
2. `from_ir` purity: call 10 times per IR, with `LC_ALL=C` and `LC_ALL=C.UTF-8`, at 1 and 4 threads; require byte-identical Program serialisation.
3. Decimal check: every numeric string matches `0|[1-9][0-9]*`; parse to `BigInt`, render, require equality.
4. Reconstruct every node length with H3's independent `recon` for every `P-KIND`, `P-DEC`, and `P-WIRE` item; require equality with `length` and `total_length`. `P-UNKNOWN` is excluded here and checked in step 7.
5. Evaluate the Program with H3 over `(0,1)`, `(L/2,min(4096,L))`, `(L-1,1)`, and `(0,L)` for small IRs, excluding `P-UNKNOWN`; require equality with E3 decode. For virtual IRs, evaluate only the sampled end range.
6. Payload check: scan the Program serialisation for any atom payload byte sequence of length `>= 8`; require none. Compare the separate atom stream with the IR payloads by SHA-256.
7. Unknown kind: require `kind = 255`, exact length, no drop; `term --json` emits it as `UNKNOWN`.
8. Certificate: `certify` each `P-WIRE`; compare every field with H3's independent recomputation; require equality.
9. Tamper matrix: for each certificate field and each wire region, flip one bit; `verify` MUST fail with 6 (field mismatch) or 4 (invalid container). No tampered input may be accepted.
10. CLI failure matrix: run each `P-CLI` case; require the exact exit code, no output file, no temporary sibling, and an unchanged pre-existing destination sentinel.
11. Atomic success: encode to an existing path; require the destination replaced, no temporary sibling, and the decoded bytes equal the source.
12. Range probe: `spec-zero` at `2^40` and `2^50`, then `decode --range L-64:64`; require 64 zero bytes, exit 0, and `/usr/bin/time -v` maximum RSS `<= 65 536 KiB`. Record wall time as a report value.
13. `spec-repeat`: same range probe over a repeated tile; require the exact modulo-tile bytes.
14. `floor`: run on `P-FLOOR`; parse the TSV; require all columns, one row per tool, unavailable tools marked, atom residual present, best generic size present. Do not gate the 1.02× claim.
15. JSON: `term --json` must contain only decimal strings for numeric fields; `inspect --json` counts must match E3.
16. Write one row per check; PASS only if every row is `PASS`.

### 12.5 Evidence

```
specs_and_reports/v2/gates/E7-G.tsv
specs_and_reports/v2/logs/E7-G.log
specs_and_reports/v2/logs/E7-G-cli.log
specs_and_reports/v2/logs/E7-G-tamper.log
specs_and_reports/v2/logs/E7-G-range.log
specs_and_reports/v2/corpus/E7/programs.tsv
specs_and_reports/v2/corpus/E7/certificates.tsv
```

`E7-G.tsv` columns:

```
check  corpus  item_id  expected  actual  exit_code  file_written  verdict  log
```

### 12.6 Fail conditions

The gate fails on any of:

- one non-identical Program across runs, threads, or locales;
- one non-canonical decimal;
- one length not reconstructible from the Program;
- one Program evaluator mismatch;
- one payload byte in the Program, or one atom-stream mismatch;
- an unknown kind dropped or misrepresented;
- one certificate field that disagrees with recomputation;
- one tampered certificate or wire accepted;
- one CLI case with the wrong exit code;
- one failure that leaves an output file or a temporary sibling;
- one success that does not replace the destination atomically;
- one range probe that is not byte-exact, or exceeds the memory bound;
- one `floor` row missing a required column;
- a missing corpus item, missing log, or hand-edited TSV value;
- a crash or timeout.

There is no tolerance, no retry, and no partial pass.

### 12.7 What E7-G does not prove

- It does not prove MAU evaluates the Program correctly. It proves the Program is self-sufficient and matches H3.
- It does not prove the certificate implies optimality. A certificate is a fact, not a proof of minimality.
- It does not prove the full-size 1.02× floor claim; H5/E0 owns it.
- It does not prove throughput.
- It does not prove resistance to every hostile file-system condition; it proves the declared failure matrix.
- It does not prove the CLI is free of all signal or OS failures.

---

## 13. Freeze rule

When E7-G passes:

1. The Program schema, decimal rules, CLI surface, exit codes, atomic-write contract, certificate fields, and signatures in §8 are frozen.
2. Any change re-runs E7-G.
3. Gate rows and logs are append-only.

---

## 14. Traceability

| this document | parent |
|---|---|
| §4.1–4.5 Program | §9, §9.1 |
| §4.6 certificate | §9.2 |
| §4.7 CLI | §11 |
| §4.8 atomic write | §7.5, §8.4 |
| §4.9 range probe | §8.2, V2-G8 |
| §4.10 floor | §12.10 |
| O11.1–O11.13 | §12.4, §12.5 |
| E7-G | V2-G7 (schema half), V2-G8, V2-G15 |

**Parent gaps and derived details.**

1. §9's `Term` uses `uint64_t` for `lfsr_conn`/`lfsr_init`, while §9.1(1) requires every generator parameter as an exact decimal string. E7 emits decimal `conn`/`init`/`predictor_param`; any fixed-width mirror must equal them. This closes the gap without changing the value.
2. §9.2 does not specify how a certificate is stored or compared. E7 defines canonical text and adds the optional `verify --cert` flag. No existing command changes.
3. §12.4 places V2-G7 (floor honesty) beside V2-G15 (MAU). E7-G checks the `floor` schema and small row; the full-size honesty table is measured by H5 and rendered by H2. The gate does not claim the 1.02× target.
4. §12.4's V2-G8 is split: E2-G owns range algebra; E7-G owns the CLI and the virtual `F13`/`F14` probe.

---

*End of MARP2-E7.*
