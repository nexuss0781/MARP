# MARP v2 — Role-Based Component Specification (C++20)

**Derived from:** `MARP/SPECS/SPECS-V2.md` (normative parent).
**Status:** derived decomposition. Non-normative until adopted. It adds no capability that the parent does not already require; it assigns every required capability to exactly one role.
**Language:** C++20. One toolchain. No Python in engine or harness.
**Rule:** a component is a role with one authority. If two components can do the same job, the decomposition is wrong.

---

## 0. Reading rules

1. Every role has one responsibility, one output type, and one authority boundary.
2. A role may not perform another role's job, even when it is convenient.
3. Every formal obligation is **measured**, never assumed. The gate table is the acceptance authority.
4. Where the parent has no gate for an obligation, the row says `no gate in §12.4 — add`. That is a specification gap, not permission.
5. `MUST` / `MUST NOT` are normative.

### 0.1 Shared notation

```
Σ            finite byte alphabet {0..255}
Σ*           finite byte strings
|x|          byte length of x
Term         node DAG per parent §3.2
Ir           atoms + nodes + root + total_length per parent §4
⟦t⟧          denotation of t, an element of Σ*  (parent §3.3)
ℓ(t)         exact byte length of t, an element of ℕ (parent §3.7)
canon(t)     canonical form per parent §3.8
enc(t)       canonical wire bytes per parent §5
dec(w)       inverse of enc on canonical w
discover(x,π) best exact term found under policy π
cost(t)      estimated bits per parent Appendix A
floor(x)     min size over the generic ensemble (§12.10)
K(x)         Kolmogorov complexity — uncomputable; never a gate value
π            policy {effort, atom_budget, grammar_budget, beam_width, threads, index, plugins}
```

`K(x)` appears in parent §1.1 as the information bound. It is not computable, so **no gate may use it**. `floor(x)` is the only operative lower bound, and V2-G7 is the honesty gate over it.

### 0.2 Shared C++ types

```cpp
namespace marp::v2 {

using u8  = std::uint8_t;
using u32 = std::uint32_t;
using u64 = std::uint64_t;

struct BigInt;                 // exact, non-negative, canonical

enum class Code : int { Ok = 0, Usage = 2, Io = 3, Invalid = 4, Unsupported = 5, Mismatch = 6, Limit = 7 };
struct Err { Code code; std::string what; };

template <class T> struct ResultOf     { using type = std::variant<T, Err>; };
template <>         struct ResultOf<void> { using type = std::variant<std::monostate, Err>; };
template <class T> using Result = typename ResultOf<T>::type;
// Result<void> is valid through the monostate specialisation; Ok is the empty alternative.

enum class Kind : u8 {
    Empty=0, Atom=1, Zero=2, Concat=3, Repeat=4, Slice=5,
    Morph=6, Xor=7, Interleave=8, Lfsr=9, Affine=10, Predictor=11
};

struct Atom {
    u8  klass;                     // parent §6.9
    u8  flags;                     // MUST be 0
    BigInt length;
    std::array<u8,32> sha256;
    std::span<const u8> payload;   // view; ownership held by E4/E6
};

struct Node {
    Kind kind; u8 flags;
    std::vector<u32> args;         // absolute ids, strictly < own id
    BigInt a, b, length;
    u8 morph, morph_k;
    u64 lfsr_conn, lfsr_init;
    u8 affine_start, affine_step, predictor_id;
    u32 predictor_param;
};

struct Ir {
    std::vector<Atom> atoms;
    std::vector<Node> nodes;
    u32 root;
    BigInt total_length;
};

struct Policy {
    u8 effort = 5;
    u64 atom_budget = 1ull << 34;
    u64 grammar_budget = 1ull << 24;
    u32 beam_width = 64;
    u32 threads = 1;
    bool index = false;
    std::vector<u32> plugins;      // empty in every gate run
};

struct Certificate {
    BigInt total_length;
    std::array<u8,32> root_sha256;
    std::array<u8,32> term_sha256;
    u32 atom_count, node_count;
    u16 format_major, format_minor;
    u8 effort;
};

} // namespace marp::v2
```

### 0.3 Global invariants

| id | invariant |
|---|---|
| M2-I1 | `decode(encode(x)) = x` for every finite `x`. |
| M2-I2 | Every length, offset, count, and parameter is exact; no implicit `u64`. |
| M2-I3 | The decoder is total: unique output or defined rejection. |
| M2-I4 | No role branches on file name, extension, or media type. The only magic that may select a path is the v1/v2 container magic at E3/E7; there is no media sniffing. |
| M2-I5 | No term enters the IR without exact verification. |
| M2-I6 | Canonical form is unique per rewrite class; `canon∘canon = canon`. |
| M2-I7 | Output depends only on input bytes and policy — never time, address, thread schedule, or hash-map order. |
| M2-I8 | No size claim below `floor(x)`; residual is always reported separately. |
| M2-I9 | One language: C++20. No Python in engine, harness, fixtures, fuzz, or report. |
| M2-I10 | All gates run with plugins disabled. |

---

## 1. Engineering components

The 22 roles are not 22 builds. They are grouped into **seven engineering components plus the harness**. Each engineering component is built, gated, then frozen. No work starts on the next one until its gate is PASS with an evidence file.

| id | engineering component | sub-components | one-line responsibility |
|---|---|---|---|
| **E0** | `HARNESS` | H1 FIXTURES, H2 GATES, H3 ORACLE, H4 FUZZ, H5 FLOOR | measure everything; accept nothing on inspection |
| **E1** | `FOUNDATION` | C01 ARITH, C02 DIGEST | exact ℕ, length algebra, hashes |
| **E2** | `ALGEBRA` | C03 TERM, C04 CANON, C05 EVAL, C06 DAG | meaning, normal form, evaluation, identity |
| **E3** | `WIRE` | C07 WIRE, C08 LEGACY | canonical encode/decode; v1 read |
| **E4** | `MEASURE` | C09 PROVENANCE, C10 SEGMENT, C11 PROBE | identity, boundaries, verified observations |
| **E5** | `STRUCTURE` | C12 GRAMMAR, C13 TRANSFORM, C14 GENERATE, C15 INDEX | sound candidates; zero false terms |
| **E6** | `SELECT` | C16 SELECT, C17 CLASSIFY, C18 PLAN, C19 PLUGIN | choose, label, stream, parallelise |
| **E7** | `BOUNDARY` | C20 TRANSLATE, C21 CLI, C22 CERTIFY | MAU program, process contract, certificate |

Build order is **E0 → E1 → E2 → E3 → E4 → E5 → E6 → E7**.
E0 is first because every later gate is measured by it. E7 is last because it wraps things that already pass.

A sub-component is a **responsibility, not a file**. E1 may be one translation unit; E2 may be four. What must not blur is the authority boundary.

### 1.1 The gate law

**One engineering component = one gate. A gate is a single binary condition.**

It is PASS only if the measurement ran, the evidence file exists, and the condition held. It fails on the first mismatch. No partial pass, no "mostly", no phase exit.

| gate | component | the single condition |
|---|---|---|
| **E0-G** | HARNESS | A deliberately corrupted container is rejected, a valid one is accepted, and a deliberately false gate reports FAIL. |
| **E1-G** | FOUNDATION | On a generated operand and term corpus, ring and division laws hold exactly, every digest matches its pinned vectors, and every structural length identity holds; one mismatch fails. |
| **E2-G** | ALGEBRA | On a generated term corpus, the engine and an independent oracle agree on the exact denotation; every stored length equals recomputation; `⟦canon(t)⟧ = ⟦t⟧`, `canon∘canon = canon`, and `read_range(t,s,l) = ⟦t⟧[s,s+l)` including offsets above `2^32`; one mismatch fails. |
| **E3-G** | WIRE | For every canonical term, `dec(enc(t)) = t` and `enc(dec(w)) = w`; 100k mutants yield zero accepted-invalid; every v1 fixture decodes. |
| **E4-G** | MEASURE | Segmentation at 1 and 4 threads is identical, the leaves partition the input, and every reported period, entropy, or match reproduces from its stated byte range; one unverified observation fails. |
| **E5-G** | STRUCTURE | Every accepted candidate expands byte-exactly to its source range on every structure fixture — zero false terms — and every structured family reaches 99.9 % structural coverage. |
| **E6-G** | SELECT | For F00–F15, `decode(encode(discover(x))) = x`; two runs and 1 vs 4 threads are byte-identical; F10 ratio ≤ 1.005; F02–F04 meet the size bound; F02–F08 reach 99.9 % structural coverage. |
| **E7-G** | BOUNDARY | `translate(ir)` is pure and decimal-exact, every node length is reconstructible, certificate verify recomputes and rejects tampering, every CLI failure exits with its declared code and no output file, and the `2^40`/`2^50` range probes are byte-exact within the memory bound. |

Parent gates map **into** these, not beside them:

| engineering gate | parent gates covered |
|---|---|
| E0-G | V2-G0 |
| E1-G | — (parent gap; amendment A6) |
| E2-G | V2-G1 (evaluator half), V2-G8 (range algebra half), V2-G16 (first half) |
| E3-G | V2-G2, G9, G13, G16 (second half) |
| E4-G | V2-G2 (determinism half), V2-G14 (segmentation half) |
| E5-G | V2-G3, G4 (candidate coverage on the structure corpus; final coverage gated at E6) |
| E6-G | V2-G1, G2, G3, G4, G5, G14 (end-to-end half) |
| E7-G | V2-G7 (schema half), G8 (CLI half), G15 |

G6 and G11 are deliberately absent — see amendment A2. G10 is a report row — see A7.

### 1.2 What a gate is not

- **Not a phase.** There are no phases. There are eight components and a go/no-go after each.
- **Not a test-suite pass.** The suite may be green while the gate fails.
- **Not a report.** A number in prose is not a result; only a TSV row plus a log is.
- **Not cumulative by default.** E3-G does not re-run E1-G. It assumes it and is void if E1-G's evidence is missing.
- **Not renegotiable after the fact.** The threshold is fixed before the component is built.

### 1.3 The freeze rule

When `E<n>-G` passes:

1. The component's public surface is frozen.
2. Any later change to that surface re-runs `E<n>-G` **and** every later gate.
3. The gate row and log are never edited. A new run appends a new row.

### 1.4 Role index

| id | role | parent | produces | engineering component |
|---|---|---|---|---|
| C01 | `ARITH` exact integer and length arithmetic | §3.7, §5.3 | `BigInt`, `ℓ` | E1 |
| C02 | `DIGEST` hashing and checksums | §6.1, §5.2, §5.7 | SHA-256, CRC-32, gear | E1 |
| C03 | `TERM` algebra and denotation | §3.2–3.6 | well-formed terms, `⟦·⟧` | E2 |
| C04 | `CANON` rewrite to fixpoint | §3.8 | canonical terms | E2 |
| C05 | `EVAL` full and range evaluation | §8.2 | bytes, byte ranges | E2 |
| C06 | `DAG` interning, order, identity | §2.2, §4.1 | deterministic ids | E2 |
| C07 | `WIRE` encode, decode, validate | §5, §8 | `.mapr` v2 wire, `Ir` | E3 |
| C08 | `LEGACY` v1 read-only path | §15 | `Ir` from v1 | E3 |
| C09 | `PROVENANCE` identity and seed | §6.1 | length, hashes, seed | E4 |
| C10 | `SEGMENT` multi-scale segmentation | §6.2 | segment tree | E4 |
| C11 | `PROBE` statistical observation | §6.3 | observation records | E4 |
| C12 | `GRAMMAR` phrase induction | §6.4 | desugared candidates | E5 |
| C13 | `TRANSFORM` exact transforms | §6.5 | transform witnesses | E5 |
| C14 | `GENERATE` generator synthesis | §6.6 | generator candidates | E5 |
| C15 | `INDEX` global reference index | §6.7 | shared ids, XOR refs | E5 |
| C16 | `SELECT` MDL beam selection | §6.8 | verified term | E6 |
| C17 | `CLASSIFY` atom class labelling | §6.9 | atom `klass` | E6 |
| C18 | `PLAN` streaming and parallel execution | §6.10, §7.3 | deterministic pipeline | E6 |
| C19 | `PLUGIN` advisory accelerators | §6.11 | proposals only | E6 |
| C20 | `TRANSLATE` IR to MAU `Program` | §4, §9 | exact decimal program | E7 |
| C21 | `CLI` commands, exits, atomic write | §7.5, §11 | files, exit codes | E7 |
| C22 | `CERTIFY` self-verification and certificate | §7.1(7), §9.2 | certificate | E7 |
| H1 | `FIXTURES` deterministic corpus | §12.3 | fixtures + manifest | E0 |
| H2 | `GATES` runner and report | §12.1–12.6 | `gates.tsv`, `ACCEPTANCE.md` | E0 |
| H3 | `ORACLE` independent decoder | §12.7 | second opinion | E0 |
| H4 | `FUZZ` mutation campaign | §12.8 | counts | E0 |
| H5 | `FLOOR` ensemble measurement | §12.10 | `floor.tsv` | E0 |

---

## 2. E0 — HARNESS

**Build order:** 0 of 7, built first.
**Gate:** E0-G (§1.1).
**Sub-components:** H1 FIXTURES, H2 GATES, H3 ORACLE, H4 FUZZ, H5 FLOOR.

**Why it is one component.** Every later gate is a measurement. If the measurement instrument is not itself gated, every downstream PASS is worthless. E0 is the only component that may declare FAIL, and it must be proven able to do so.

The parent names Python files in §12.2, §12.7, §12.8, and Appendix B. Under M2-I9 these become C++20 binaries. The independent decoder must remain an independent implementation: separate source tree, no linking against the engine, no shared parsing code.

### H1 — `FIXTURES`

**Role.** Generate the corpus deterministically and record its identity.

**Derives from.** §12.3.

**Postconditions.** F00–F10 and F13–F15 generated from a fixed seed; F11/F12 supplied by path; every fixture has a recorded SHA-256; `fixtures.tsv` is written by the generator, never typed. Multi-gigabyte fixtures are sparse or virtual where the spec allows. Regeneration reproduces the same digest.

**Invariants.** No fixture is classified by file type. A missing F11/F12 marks dependent gates `BLOCKED`, never `PASS`.

**C++ surface.**

```cpp
namespace marp::harness {
struct Fixture { std::string id; BigInt bytes; std::array<u8,32> sha256; std::string path; };
int generate(const std::filesystem::path& out, const std::filesystem::path& manifest);
} // namespace marp::harness
```

---

### H2 — `GATES`

**Role.** Run one gate at a time, write one measured row, and render the report from rows.

**Derives from.** §12.1–12.6, §12.9, §12.11, §12.12.

**Postconditions.** Each gate writes one TSV row and one log with the exact command line, exit code, and measured values. `PASS` is printed only when the condition holds and every evidence file exists. A missing fixture, missing log, or hand-edited number is a hard failure. `ACCEPTANCE.md` is rendered from the TSVs.

**Invariants.** No prose number is typed. A failed gate leaves the previous `ACCEPTANCE.md` untouched and writes `FAIL`. There is no partial acceptance.

**C++ surface.**

```cpp
namespace marp::harness {
struct Row {
    std::string gate, fixture;
    BigInt input_bytes, wire_bytes;
    i64 ratio_num, ratio_den;     // exact; never a double
    bool sha_match;
    std::string verdict, log;
};
int run_gate(std::string_view gate_id, const std::filesystem::path& root);  // "E0-G" … "E7-G"
int render(const std::filesystem::path& tsv_dir, const std::filesystem::path& out);
} // namespace marp::harness
```

---

### H3 — `ORACLE`

**Role.** Decode every emitted wire with an implementation that shares no code with the engine.

**Derives from.** §12.7.

**Postconditions.** Parses header, atoms, nodes, index, trailer; validates CRCs and canonical integers; evaluates all node kinds; rejects malformed containers; reproduces F00–F08 byte-exactly.

**Invariants.** Separate implementation. No include of engine headers, no linkage. A disagreement is a gate failure, not a warning.

**C++ surface.**

```cpp
namespace marp::oracle {
int decode_file(const std::filesystem::path& wire, const std::filesystem::path& out);
} // namespace marp::oracle
```

---

### H4 — `FUZZ`

**Role.** Mutate valid containers and count what escapes.

**Derives from.** §12.8.

**Postconditions.** Bit flips, truncation, field swaps, length corruption; small valid containers plus header/index mutations of large ones; every mutant fed to `verify` and `decode`; counts accepted-invalid, crashes, timeouts, valid decodes.

**Invariants.** 100,000 mutants: `accepted_invalid = 0`, `crashes = 0`, `timeouts = 0`.

**C++ surface.**

```cpp
namespace marp::harness {
struct FuzzCounts { u64 total, accepted_invalid, crashes, timeouts, valid; };
FuzzCounts fuzz(const std::filesystem::path& seeds, u64 mutants, u64 seed);
} // namespace marp::harness
```

---

### H5 — `FLOOR`

**Role.** Measure the honest lower bound with the generic ensemble.

**Derives from.** §12.10.

**Postconditions.** One row per tool (`xz -9e`, `zstd -19`, `brotli -q 11`, `bzip2 -9`), with command and version; unavailable tools recorded as `unavailable`, never silently skipped; reports input bytes, best generic bytes and tool, MARP wire bytes, atom residual, honesty note.

**Invariants.** No size claim below the measured floor. `K(x)` is never used as a gate value.

**C++ surface.**

```cpp
namespace marp::harness {
struct FloorRow { std::string tool, version; std::optional<BigInt> bytes; };
int measure(const std::filesystem::path& input, std::ostream& tsv);
} // namespace marp::harness
```

---

## 3. E1 — FOUNDATION

**Build order:** 1 of 7.
**Gate:** E1-G.
**Sub-components:** C01 ARITH, C02 DIGEST.

**Why it is one component.** Every later gate is meaningless if ℕ or ℓ is wrong. This is the only component small enough to exhaustively test.

### C01 — `ARITH`

**Role.** Provide the only exact arithmetic in the system: arbitrary-precision non-negative integers and the length algebra of the term grammar.

**Derives from.** §3.7 (length arithmetic), §5.3 (integer encodings), M2-I2.

**Domain → codomain.** `ℕ × ℕ → ℕ` for `+`, `×`; partial `−` with `a ≥ b`; `divmod` with `b > 0`; `Term → ℕ` for `ℓ`.

**Preconditions.** Operands are canonical `BigInt` (no leading zeros). Divisor non-zero.

**Postconditions.**
- `a + b`, `a × b`, `a − b`, `a / b`, `a mod b` are exact at any magnitude.
- `ℓ` implements §3.7 literally: `ℓ(Empty)=0`, `ℓ(Atom)=atom.length`, `ℓ(Zero n)=n`, `ℓ(Concat)=Σℓ`, `ℓ(Repeat c q r)=q·ℓ(c)+r`, `ℓ(Slice)=len`, `ℓ(Morph)=ℓ(child)`, `ℓ(Xor)=ℓ(a)=ℓ(b)`, `ℓ(Interleave)=k·ℓ(c1)`, `ℓ(Lfsr)=n`, `ℓ(Affine)=n`, `ℓ(Predictor)=ℓ(residual)`.

**Invariants.** No operation silently converts to `u64`. `ℓ(t) = |⟦t⟧|` is an obligation of E2-G, not an assumption; E1 proves the structural identities it rests on.

**Obligations (measured).**
- O1.1 ring laws: `(a+b)+c = a+(b+c)`, `a·(b+c) = a·b+a·c`, `a = (a/b)·b + a mod b`.
- O1.2 structural length identities of §3.7 hold for every generated term; `ℓ(t) = |⟦t⟧|` itself is measured at E2-G.
- O1.3 decimal round-trip: `to_dec(from_dec(s)) = s` for canonical `s`.

**C++ surface.**

```cpp
namespace marp::v2 {
struct BigInt {
    static BigInt from_u64(u64);
    static BigInt from_dec(std::string_view);
    static BigInt from_le(std::span<const u8>);
    std::string to_dec() const;
    std::vector<u8> to_le() const;
    u64 to_u64_checked() const;
    std::size_t bit_length() const;
    bool is_zero() const;
};
BigInt operator+(const BigInt&, const BigInt&);
BigInt operator*(const BigInt&, const BigInt&);
BigInt operator-(const BigInt&, const BigInt&);
std::pair<BigInt,BigInt> divmod(const BigInt&, const BigInt&);
int compare(const BigInt&, const BigInt&);
BigInt shl(const BigInt&, std::size_t);
BigInt shr(const BigInt&, std::size_t);

BigInt length_of(const Ir&, u32 node_id);
BigInt length_of(const Ir&);
} // namespace marp::v2
```

**Errors.** `Invalid` on non-canonical input, negative subtraction, zero divisor, or checked overflow.

**Authority boundary.** May not define terms, denote bytes, or parse wire. It computes a length; it does not choose one.

---

### C02 — `DIGEST`

**Role.** Provide every hash and checksum used for identity, integrity, and provenance.

**Derives from.** §6.1, §5.2, §5.7, §5.4.

**Domain → codomain.** `Σ* → {0,1}^256` (SHA-256); `Σ* → {0,1}^32` (CRC-32); `Σ* → u64` (gear).

**Postconditions.**
- SHA-256 matches FIPS 180-4 vectors.
- CRC-32 is IEEE 802.3, reflected, init/final `0xFFFFFFFF`.
- `crc32_zeroed(region, field_offset)` treats the 4-byte field as zero.
- Gear hash is a pure function of `(bytes, position)`.

**Invariants.** Streaming and one-shot agree. State is copyable and resumable.

**Obligations.** O2.1 known-answer vectors. O2.2 incremental equals one-shot on random splits.

**C++ surface.**

```cpp
namespace marp::v2 {
struct Sha256 {
    void update(std::span<const u8>);
    std::array<u8,32> finish();
    static std::array<u8,32> of(std::span<const u8>);
};
struct Crc32 {
    void update(std::span<const u8>);
    u32 finish() const;
    static u32 of(std::span<const u8>);
    static u32 of_with_zeroed(std::span<const u8>, std::size_t field_off);
};
u64 gear_hash(std::span<const u8>, u64 seed = 0);
} // namespace marp::v2
```

**Errors.** None; total.

**Authority boundary.** May not decide validity. A digest match is evidence for E3/E7, never acceptance by itself.

---

## 4. E2 — ALGEBRA

**Build order:** 2 of 7.
**Gate:** E2-G.
**Sub-components:** C03 TERM, C04 CANON, C05 EVAL, C06 DAG.

**Why it is one component.** Meaning, normal form, evaluation, and identity are one closed system. No wire, no discovery, no I/O. It is the last component that can be tested with in-memory terms only.

### C03 — `TERM`

**Role.** Define the term grammar, its well-formedness, its denotation, and its closed catalogues. The only place where bytes acquire meaning.

**Derives from.** §3.1–3.6, §4.1.

**Domain → codomain.** `Ir → Σ*` for `⟦·⟧`; well-formedness is a predicate on `Ir`.

**Preconditions.** Node arguments strictly smaller than the node id; node count fits `u32`.

**Postconditions.**
- `⟦Empty⟧ = ε`; `⟦Atom a⟧ = payload`; `⟦Zero n⟧ = 0^n`; `⟦Concat⟧ = ‖`; `⟦Repeat c q r⟧ = ⟦c⟧^q · prefix(⟦c⟧, r)`; `⟦Slice c s l⟧ = ⟦c⟧[s, s+l)`; `⟦Morph⟧ = morph_m(k, ⟦c⟧)`; `⟦Xor a b⟧ = ⟦a⟧ ⊕ ⟦b⟧`; `⟦Interleave⟧ = block-strided concatenation`; `⟦Lfsr⟧` per §3.5; `⟦Affine⟧` per §3.3; `⟦Predictor⟧` per §3.6.
- Well-formedness enforces: `Repeat` normal form; `Slice` bounds; `Xor` equal lengths; `Interleave` equal child lengths, `stride≥1`, `L%stride=0`; `Predictor` `ℓ(residual)=n`; morph length multiples and `k` ranges; `Lfsr conn≠0`; closed predictor ids.

**Invariants.**
- `⟦·⟧` is total on well-formed terms and undefined otherwise.
- Morphisms and predictors are closed catalogues; unknown ids are invalid.
- LFSR bit order is exactly §3.5: parity of `state & conn`, shift right, feedback into bit 63, emit MSB-first.
- `Xor` and `Interleave` are byte-level only; no sub-byte lengths exist.

**Obligations.**
- O3.1 `ℓ(t) = |⟦t⟧|` on every generated well-formed term.
- O3.2 every morphism marked "yes" in §3.4 is an involution; rotations compose correctly.
- O3.3 every predictor reconstructs its input from its residual exactly.
- O3.4 the LFSR matches the v1 generator on pinned vectors.

**C++ surface.**

```cpp
namespace marp::v2 {
Result<void> check_well_formed(const Ir&);

class TermCursor {                 // streaming denotation
public:
    explicit TermCursor(const Ir&, u32 node);
    Result<std::size_t> read(std::span<u8> out);
    BigInt remaining() const;
};

Result<std::size_t> read_range(const Ir&, u32 node, const BigInt& start, std::span<u8> out);

u8 apply_morph_byte(u8 morph, u8 k, u8 in);
u8 apply_predictor_step(u8 pid, u32 param, u8 residual, u8 prev1, u8 prev2);
} // namespace marp::v2
```

**Errors.** `Invalid` for every well-formedness violation; `Limit` for depth or expansion beyond §8.3.

**Authority boundary.** May not allocate ids, intern nodes, rewrite, or encode. It defines; it does not manage.

---

### C04 — `CANON`

**Role.** Apply the rewrite system to a fixed point and produce the unique canonical representative of a term's rewrite class.

**Derives from.** §3.8, §2.2, §7.4.

**Domain → codomain.** `Term → Term`.

**Postconditions.** Rules 1–13 of §3.8 applied until none fires: `Concat` flattening; `Empty` elimination; atom merge under `ATOM_MAX = 1 MiB`; `Zero` merge; `Repeat` normalisation; `Slice` folding; `Morph` folding; `Xor` folding and symmetric ordering; `Interleave` folding with child order preserved; `Affine` folding; `Zero` folding; structural dedup; dead-node pruning.

**Invariants.**
- `⟦canon(t)⟧ = ⟦t⟧`.
- `canon(canon(t)) = canon(t)`.
- Independent of `--effort`; `ATOM_MAX` is a format constant.
- `Interleave` child order is semantic and never sorted.
- Output ids are dense, first-use ordered, topological, root last.

**Obligations.**
- O4.1 termination: exhibit `μ(t)` and show every rule strictly decreases it lexicographically.
- O4.2 local confluence: finite critical-pair enumeration over rules 1–13.
- O4.3 denotation preservation on the full corpus.
- O4.4 idempotence on the full corpus.

**C++ surface.**

```cpp
namespace marp::v2 {
Ir canon(const Ir&);
bool is_canonical(const Ir&);
std::string canonical_key(const Ir&, u32 node);
} // namespace marp::v2
```

**Errors.** `Invalid` if the input is not well-formed.

**Authority boundary.** May not change denotation, consult effort, reorder `Interleave`, or emit wire.

---

### C05 — `EVAL`

**Role.** Turn a term into bytes: streaming for full decode, indexed for range decode.

**Derives from.** §8.2, §8.3.

**Domain → codomain.** `Ir × [start, start+len) → Σ^len`.

**Postconditions.**
- Full evaluation streams through a fixed block buffer and hashes incrementally.
- Range evaluation touches only intersecting subterms.
- `Zero`, `Affine`, `Lfsr`, `Repeat` support direct range evaluation without materialising the prefix.
- LFSR range evaluation uses GF(2) jump-ahead in `O(log offset)`.
- Predictor residuals are sequential unless state is restored exactly.

**Invariants.** `read_range(t, s, l) = ⟦t⟧[s, s+l)` for every sampled range.

**Obligations.**
- O5.1 streaming equals full materialisation on small fixtures.
- O5.2 range equals slice on random ranges, including starts above `2^32` on virtual fixtures.
- O5.3 no allocation proportional to declared total length during range decode.

**C++ surface.**

```cpp
namespace marp::v2 {
Result<void> eval_stream(const Ir&, Sink&);
Result<void> eval_range(const Ir&, const BigInt& start, const BigInt& len, Sink&);
} // namespace marp::v2
```

**Errors.** `Invalid` on child-length mismatch; `Limit` on depth, expansion, or memory.

**Authority boundary.** May not validate wire structure (E3 owns that), rewrite, or decide terms.

---

### C06 — `DAG`

**Role.** Own identity inside the term: interning, canonical ordering, sharing, id assignment.

**Derives from.** §2.2, §4.1, §7.3.

**Domain → codomain.** `construction events → deterministic Ir`.

**Postconditions.**
- Identical subterms share exactly one node.
- Atom and node ids assigned in first-use order during canonical traversal.
- Node table topological; every child id strictly smaller.
- Root is the last node.
- No unused atoms or nodes.
- Atom payloads deduplicated by `(length, SHA-256)`.

**Invariants.** Id assignment is a pure function of the canonical term. Thread completion order cannot influence it.

**Obligations.**
- O6.1 interning in any construction order yields the same ids.
- O6.2 `root == node_count − 1`.
- O6.3 no two atom records share a payload.

**C++ surface.**

```cpp
namespace marp::v2 {
class Dag {
public:
    Result<u32> add_atom(std::span<const u8>, u8 klass);
    Result<u32> add_node(Node);
    Result<Ir> finish(u32 root) &&;
    u32 node_count() const;
    u32 atom_count() const;
};
} // namespace marp::v2
```

**Errors.** `Limit` on count or depth; `Invalid` on a child id not already present.

**Authority boundary.** May not verify denotation, rewrite, or serialise.

---

## 5. E3 — WIRE

**Build order:** 3 of 7.
**Gate:** E3-G.
**Sub-components:** C07 WIRE, C08 LEGACY.

**Why it is one component.** The format and its reader are one contract. This is the first component that can be tested against bytes rather than terms, and the last that can be tested without discovery.

### C07 — `WIRE`

**Role.** Own the canonical byte format. Encode exactly; decode totally.

**Derives from.** §5, §5.9, §8.3, §8.4.

**Domain → codomain.** `Term ⇀ Σ*` (encode); `Σ* ⇀ Term` (decode).

**Preconditions (encode).** `is_canonical(t)`.

**Postconditions (encode).** Header 64 bytes with magic, version 2.0, minimal flags, total length in `u64` form when it fits, otherwise canonical Region A.1; atom table first-use ordered and deduplicated; node table topological with exact lengths; optional minimal sorted index; trailer 32 bytes with counts and CRCs; `file_crc32` over every byte before `trailer_offset` with its own field zeroed.

**Postconditions (decode).** Validation in exactly §5.9 order: size, magic/version/flags, offsets, header CRC, trailer, region monotonicity and total-length canonicality, atom table, node table, root id, index, full evaluation. Reject on first failure.

**Invariants.**
- `dec(enc(t)) = t` for canonical `t`.
- `enc(dec(w)) = w` for canonical `w`.
- Non-canonical integers, flags, orderings, unused records are rejected, never normalised.
- No allocation sized from an unvalidated count.
- Unknown kind, morph, predictor, or version is rejection.

**Obligations.**
- O7.1 `|enc(t)|` equals the computed sum of regions; the harness recomputes independently.
- O7.2 every emitted wire re-decodes and re-encodes to identical bytes.
- O7.3 encode writes a temporary sibling and renames only after self-verification.

**C++ surface.**

```cpp
namespace marp::v2 {
Result<std::vector<u8>> encode(const Ir&);
Result<Ir> decode(std::span<const u8>);
Result<void> validate(std::span<const u8>);
BigInt encoded_size(const Ir&);
} // namespace marp::v2
```

**Errors.** `Invalid` for structural or canonicality violations; `Unsupported` for future versions; `Limit` for §8.3; `Mismatch` when evaluation disagrees with declared length or digest.

**Authority boundary.** May not rewrite terms, choose terms, or certify facts it did not decode.

---

### C08 — `LEGACY`

**Role.** Read v1.0.1 and v1.1 containers into the v2 IR. Never write v1.

**Derives from.** §15.

**Postconditions.** Every legacy fixture decodes byte-exactly; unsupported legacy features are rejected with `Unsupported`, never approximated. The v1 writer is not reachable.

**Invariants.** Legacy code is read-only and cannot influence v2 emission.

**C++ surface.**

```cpp
namespace marp::v2 {
bool looks_like_v1(std::span<const u8>);
Result<Ir> decode_v1(std::span<const u8>);
} // namespace marp::v2
```

**Errors.** `Invalid`, `Unsupported`, `Limit`.

**Authority boundary.** May not be used by encode.

---

## 6. E4 — MEASURE

**Build order:** 4 of 7.
**Gate:** E4-G.
**Sub-components:** C09 PROVENANCE, C10 SEGMENT, C11 PROBE.

**Why it is one component.** Identity, boundaries, and observations are one measurement pass over the input. None of them may produce a term. Discovery is heuristic here; acceptance remains exact.

### C09 — `PROVENANCE`

**Role.** Establish identity of the input before anything is inferred.

**Derives from.** §6.1 (M0).

**Postconditions.** Exact byte length; streaming SHA-256; gear hash and sample fingerprints for segmentation; effort seed derived from the bytes only.

**Invariants.** Same bytes ⇒ same seed, on any host, thread count, or run.

**C++ surface.**

```cpp
namespace marp::v2 {
struct Provenance { BigInt length; std::array<u8,32> sha256; u64 seed; };
Result<Provenance> provenance(Source&, const Policy&);
} // namespace marp::v2
```

---

### C10 — `SEGMENT`

**Role.** Cut the input into a deterministic segment tree of candidate regions.

**Derives from.** §6.2 (M1).

**Postconditions.** Content-defined chunks at targets `64 B … 64 MiB`; change points on order-0/1 entropy, run density, match density, periodicity; leaves are candidate regions; boundaries are a pure function of bytes and policy.

**Invariants.** Boundaries are independent of thread scheduling and completion order.

**C++ surface.**

```cpp
namespace marp::v2 {
struct Segment { BigInt begin, end; u32 depth; };
Result<std::vector<Segment>> segment(Source&, const Provenance&, const Policy&);
} // namespace marp::v2
```

---

### C11 — `PROBE`

**Role.** Measure each segment and produce observations with exact evidence ranges. Propose hypotheses; never terms.

**Derives from.** §6.3 (M2).

**Postconditions.** Per segment: order-0/1/2 entropy, run histogram, minimal period by KMP plus full verification, repeated-substring density, bit-plane skew, Berlekamp–Massey over GF(2), affine and polynomial fit, stride detection, exact-match density. Each observation carries its byte range and the measurement that produced it.

**Invariants.** No probe writes to the IR. A period is a period only after full byte verification.

**C++ surface.**

```cpp
namespace marp::v2 {
struct Observation {
    Segment where;
    enum class Kind { Entropy, Period, Run, Repeat, Skew, Lfsr, Affine, Stride, Match } kind;
    double value;
    BigInt period;
    bool verified;
};
Result<std::vector<Observation>> probe(Source&, const Segment&, const Policy&);
} // namespace marp::v2
```

**Authority boundary.** May not emit a candidate term.

---

## 7. E5 — STRUCTURE

**Build order:** 5 of 7.
**Gate:** E5-G.
**Sub-components:** C12 GRAMMAR, C13 TRANSFORM, C14 GENERATE, C15 INDEX.

**Why it is one component.** Grammar, transform, generator, and index answer one question: does this candidate expand exactly? They share the verifier and the phrase budget. None may select.

### C12 — `GRAMMAR`

**Role.** Induce phrase structure over byte and bit-plane tokens, then desugar it.

**Derives from.** §6.4 (M3).

**Postconditions.** Re-Pair or Sequitur over tokens; bounded global phrase dictionary; every rule desugared into `Concat`, `Repeat`, or an id shared within the emitted fragment — the wire has no grammar node; expansion verified against the source; budget overflow stops induction without corrupting output.

**Invariants.** A grammar candidate is accepted only after exact expansion equals the source range.

**C++ surface.**

```cpp
namespace marp::v2 {
struct Phrase { std::vector<u32> tokens; };
Result<std::vector<Phrase>> induce(Source&, const Segment&, const Policy&);
} // namespace marp::v2
```

---

### C13 — `TRANSFORM`

**Role.** Find exact byte-level transformations that expose structure.

**Derives from.** §6.5 (M4).

**Postconditions.** Bit/byte plane transpose via `Slice`+`Interleave`; stride reshape; endianness swap; bit reversal; inversion; rotation; whole-segment reversal; XOR/delta against dictionary or neighbour; alignment search for long exact matches.

**Invariants.** A transform is reported only when `B = g(A)` holds byte-exactly over the full range. An approximate match is not a transform.

**C++ surface.**

```cpp
namespace marp::v2 {
struct TransformWitness { BigInt a_begin, b_begin, len; u8 morph; u32 param; bool verified; };
Result<std::vector<TransformWitness>> find_transforms(Source&, const Segment&, const Policy&);
} // namespace marp::v2
```

---

### C14 — `GENERATE`

**Role.** Synthesise generator candidates from the closed catalogue.

**Derives from.** §6.6 (M5).

**Postconditions.** Catalogue: `Zero`, `Repeat`/periodic tile, `Lfsr`, `Affine`, `Predictor` residual, grammar-generated streams (desugared). Every candidate expanded and compared byte-for-byte before acceptance.

**Invariants.** Closed catalogue. No generator invented at runtime.

**C++ surface.**

```cpp
namespace marp::v2 {
struct Generated { Kind kind; BigInt n; bool verified; };
Result<std::vector<Generated>> generate(Source&, const Segment&, const Policy&);
} // namespace marp::v2
```

---

### C15 — `INDEX`

**Role.** Own cross-segment and cross-scale sharing.

**Derives from.** §6.7 (M6).

**Postconditions.** Key `(length, SHA-256)`; exact duplicate → the earlier range plus its verified fragment; near duplicate → aligned `Xor` plus exact verification; deterministic insertion order. Entries carry ranges and fragments, never node ids, because each `Candidate.fragment` is self-contained.

**Invariants.** The index never changes denotation. Removing it changes only size, never output.

**C++ surface.**

```cpp
namespace marp::v2 {
struct RefEntry { Segment where; Ir fragment; };
class RefIndex {
public:
    Result<void> insert(const Candidate&);
    std::optional<RefEntry> exact(Source&, Segment, std::span<const u8>) const;
    std::vector<RefEntry> near(Source&, Segment, std::span<const u8>, u32) const;
};
} // namespace marp::v2
```

---

## 8. E6 — SELECT

**Build order:** 6 of 7.
**Gate:** E6-G.
**Sub-components:** C16 SELECT, C17 CLASSIFY, C18 PLAN, C19 PLUGIN.

**Why it is one component.** Choice, labelling, execution, and plugin policy are one decision loop. Selection is the only authority that admits a term into the root.

### C16 — `SELECT`

**Role.** Choose one verified term per region and assemble the root under the MDL objective and the policy budget.

**Derives from.** §6.8 (M7), Appendix A, §7.4.

**Postconditions.** Beam search over the segment tree minimising `cost(T) = 8·wire_bytes(T) + atom_bits(T) + model_bits`; candidate costs use the Appendix A estimate; admitted candidates are exact-verified; tie-breaking is `(kind, argc, canonical child ids, a, b, morph, predictor_id, lexicographic wire bytes)`; `Atom` is always available.

**Invariants.**
- The selector never admits a term it did not verify.
- **The selector's cost is an estimate, never a size claim.** The claim is `encode(select(...))`, measured by E3 and E0.
- The selector is not a global minimiser and must not be reported as one.

**C++ surface.**

```cpp
namespace marp::v2 {
Result<Ir> select(const std::vector<Candidate>&, const Provenance&, const Policy&);
BigInt estimate_bits(const Ir&);
} // namespace marp::v2
```

**Errors.** `Limit` when beam or atom budget is exhausted; `Invalid` if a candidate fails re-verification.

---

### C17 — `CLASSIFY`

**Role.** Label atom payloads by measured statistical signature for NEZITOR's benefit.

**Derives from.** §6.9 (M9).

**Postconditions.** Eight classes: `OPAQUE`, `SPARSE`, `LOW_ENTROPY`, `PERIODIC_RESIDUAL`, `TEXTUAL`, `NUMERIC_PLANE`, `CODE_LIKE`, `TOKEN_STREAM`, by measured signature. Runs after canonicalisation, on final atom payloads.

**Invariants.** Pure function of payload bytes. Never changes boundaries or denotation. Advisory only.

**C++ surface.**

```cpp
namespace marp::v2 {
u8 classify_atom(std::span<const u8>);
} // namespace marp::v2
```

---

### C18 — `PLAN`

**Role.** Run the pipeline in bounded memory and with deterministic parallel merge.

**Derives from.** §6.10 (M10), §7.3, §8.3.

**Postconditions.** One profiling pass; re-read only for candidate verification; segment-level parallelism; merge by segment offset, never by completion order; atoms spill to temporary streams; peak memory bounded; output depends only on bytes and effort.

**Invariants.** Byte-identical output at `--threads 1` and `--threads 4`. Peak RSS within the declared bound.

**C++ surface.**

```cpp
namespace marp::v2 {
Result<Ir> run(Source&, const Policy&);
} // namespace marp::v2
```

**Errors.** `Limit` on memory, budget, or stream failure; `Io` on spill failure.

---

### C19 — `PLUGIN`

**Role.** Offer optional pattern proposals to the same verifier.

**Derives from.** §6.11 (M11).

**Postconditions.** A plugin proposes a decomposition; the proposal goes through the same exact verifier and MDL selector. Plugins disabled by default and in every gate run.

**Invariants.** A plugin cannot change the wire format, introduce file-type semantics, or be required by any gate. Removing all plugins changes nothing except possibly candidate quality.

**C++ surface.**

```cpp
namespace marp::v2 {
struct Plugin {
    virtual ~Plugin() = default;
    virtual std::string id() const = 0;
    virtual std::vector<Candidate> propose(Source&, const Segment&) = 0;
};
} // namespace marp::v2
```

---

## 9. E7 — BOUNDARY

**Build order:** 7 of 7.
**Gate:** E7-G.
**Sub-components:** C20 TRANSLATE, C21 CLI, C22 CERTIFY.

**Why it is one component.** It wraps what already passes. It introduces no new algebra and no new discovery. If it fails, the failure is in the wrapper, not in the engine.

### C20 — `TRANSLATE`

**Role.** Emit the MAU `Program` from the IR, exactly and purely.

**Derives from.** §9, §4.

**Postconditions.** Every length, count, offset, and generator parameter is an exact decimal string; no payload bytes except the separate atom stream; translator is pure; unknown nodes become an explicit `UNKNOWN`; MAU can reconstruct every node length from the program alone; range beyond `2^64` is expressible.

**Invariants.** `translate(ir)` depends only on `ir`. No truncation to `u64`.

**C++ surface.**

```cpp
namespace marp::v2::translate {
struct Term { u8 kind; std::vector<u32> args; std::string a, b, length; };
struct Program { std::vector<AtomRef> atoms; std::vector<Term> nodes; u32 root; std::string total_length; };
Program from_ir(const Ir&);
} // namespace marp::v2::translate
```

**Errors.** `Unsupported` for unknown node kinds; never a silent drop.

---

### C21 — `CLI`

**Role.** Own the process contract: commands, exit codes, atomic output.

**Derives from.** §11, §7.5, §8.4.

**Postconditions.** Commands `encode`, `decode`, `verify`, `inspect`, `term`, `floor`, `bench`, `spec-zero`, `spec-repeat`, `spec-lfsr`, `spec-affine`. Exit codes: 0 success, 2 usage, 3 I/O, 4 invalid container, 5 unsupported, 6 verification mismatch, 7 resource limit. Output written to a temporary sibling and renamed only on success. Encode self-verifies before rename.

**Invariants.** A failed command leaves no output file. No command selects semantics by file extension.

**C++ surface.**

```cpp
namespace marp::v2 {
int run_cli(int argc, char** argv);
} // namespace marp::v2
```

---

### C22 — `CERTIFY`

**Role.** Bind measured facts to a wire and recompute them on demand.

**Derives from.** §7.1(7), §9.2.

**Postconditions.** Certificate binds exact total length, root SHA-256, canonical term SHA-256, atom count, node count, format version, effort. `verify` recomputes denotation and hash; acceptance requires recomputed facts to match.

**Invariants.** Never certifies a fact not derived from the emitted wire. A certificate is not a proof of optimality.

**C++ surface.**

```cpp
namespace marp::v2 {
Result<Certificate> certify(std::span<const u8> wire);
Result<void> verify(std::span<const u8> wire, const Certificate&);
} // namespace marp::v2
```

---

## 10. Authority matrix

`→` means "may call". No edge exists in the reverse direction.

```
E1 ARITH/DIGEST  ← every component
E2 TERM          ← E2 CANON/EVAL/DAG, E3, E5, E6, E7
E2 CANON         ← E3, E5, E6
E2 EVAL          ← E3, E5, E6, E7, E0 ORACLE (its own implementation)
E2 DAG           ← E5, E6
E3 WIRE          ← E0, E7
E3 encoded_size  ← E6            (size-only, read-only edge; amendment A8)
E3 LEGACY        ← E7
E4 PROVENANCE    ← E5, E6
E4 SEGMENT       ← E5, E6
E4 PROBE         ← E5, E6
E5 GRAMMAR       ← E6
E5 TRANSFORM     ← E6
E5 GENERATE      ← E6
E5 INDEX         ← E6
E6 SELECT        ← E6 PLAN
E6 CLASSIFY      ← E2 DAG metadata, E7
E6 PLAN          ← E7
E6 PLUGIN        ← E6 PLAN (optional, off in gates)
E7 TRANSLATE     ← E7 CLI/CERTIFY
E7 CLI           ← process entry
E7 CERTIFY       ← E7 CLI
E0 H1..H5        ← external; may call only E7 CLI and E3 wire files
```

**Prohibited edges.**

- E4/E5 may not call E3. They produce `Ir`, not wire.
- E6 may call E3 `encoded_size` only. It may not call `encode`, `decode`, or `validate`, and it may not emit wire.
- E2 CANON may not call discovery.
- E3 may not call E6.
- E0 may not import engine internals beyond the public CLI and a wire file.

---

## 11. Gate ownership

| gate | condition | owning components | parent |
|---|---|---|---|
| E0-G | corrupted rejected, valid accepted, false gate fails | H1–H5 | V2-G0 |
| E1-G | ring/division/digest/structural-length laws | C01, C02 | parent gap (A6) |
| E2-G | denotation + lengths + canon + range algebra | C03–C06 | G1 (half), G8 (half), G16 (half) |
| E3-G | wire bijection + mutant rejection + v1 | C07, C08 | G2, G9, G13, G16 |
| E4-G | deterministic segmentation + reproducible observations | C09–C11 | G2 (half), G14 |
| E5-G | zero false candidates + 99.9 % on the structure corpus | C12–C15 | G3, G4 (candidate) |
| E6-G | end-to-end exactness, determinism, size, noise, full-fixture coverage | C16–C19 | G1–G5, G14 |
| E7-G | MAU program, certificate, CLI exits, virtual range probe, floor schema | C20–C22 | G7 (schema), G8 (CLI), G15 |

A gate with no owner is unimplemented. A component with no gate is unmeasured.

---

## 12. Amendments required in the parent spec

These are points where `SPECS-V2.md` as written cannot be implemented under the stated rules. Listed here, not applied to the parent.

**Ratification record — 2026-11-13.** The owner delegated the decision ("do the best") and the assistant ratified **A1, A2, A6, A7, A8, A9** as written below. What that means in plain terms: no exactness, coverage, or honesty condition is weakened. What changes is only *where* a measurement is taken and *whether* a speed or memory number is allowed to block the build. Speed, memory, and ensemble ratio become report rows; exactness, zero false candidates, honest size reporting, determinism, and the pinned 99.9 % coverage stay binding. A1, A3, A4, A5 are recorded as constraints on the harness, not as weakening. If any of these is later found wrong, the amendment is rewritten in the open and every gate it touched is re-run; the ratification does not make a defect permanent.

**A1 — Python in the harness.** §12.2, §12.7, §12.8, and Appendix B name `gen_fixtures.py`, `indep_decode_v2.py`, `ref_coder.py`, `fuzz_v2.py`, `render_acceptance.py`. Under M2-I9 these become C++ binaries H1–H5. V2-G12 independence is preserved by a separate source tree and no shared headers, not by a different language.

**A2 — Targets promoted to gates.** §13 labels size and throughput `TARGETS, not measurements`, yet §12.4 gates V2-G6 (1.02× ensemble) and V2-G11 (25/100 MiB/s). If speed is not the objective and a larger-than-input representation is not automatically a failure, then G6 and G11 are report rows. Binding gates remain exactness, coverage, honesty.

**A3 — `K(x)` is not a gate value.** §1.1 states `|R| ≥ K(x) + residual`. True, but `K` is uncomputable. G7 must measure `floor(x)` and must not claim to compute `K(x)`.

**A4 — Fixture weight.** F02–F08 and F15 are 1–4 GiB; F13/F14 are `2^40`/`2^50`. H2 must support per-gate invocation and virtual fixtures so no gate requires full local materialisation.

**A5 — Held-out corpus.** Every fixture is visible to discovery and gating. If coverage is to mean generalization rather than fitting, the harness needs a held-out family never used during tuning, reported separately. This is the one idea worth importing from MBP; it changes no architecture.

**A6 — E1 has no parent gate.** §12.4 jumps from harness self-test to full round-trip. E1-G is therefore ratified as a real gate (2026-11-13): without it, arithmetic errors surface only at E3 with no way to localise them.

**A7 — Gate splitting and resource rows.** Several parent gates bundle measurements that belong to different components, and some gate resource targets that the mandate does not treat as goals. The component gates split them as follows, without weakening any exactness condition:

- **V2-G8** (range algebra and virtual probe): the algebra half is measured at `E2-G`; the CLI and `F13`/`F14` half at `E7-G`.
- **V2-G16** (canonical idempotence): the canonicalisation half is measured at `E2-G`; the re-emit-decoded-wire half at `E3-G`, because it needs the wire.
- **V2-G7** (floor honesty): the `floor` schema and a small-size row are measured at `E7-G`; full-size honesty rows belong to `E0/H5`.
- **V2-G10** (memory): a report row, not a gate. The design bounds remain declared in E6/E7 and are rendered by H2.
- **V2-G6, V2-G11** (ensemble ratio, throughput): report rows under A2.

No exactness, coverage, or honesty condition is demoted. The demoted rows are resource and speed targets, which §13 of the parent already calls targets.

**A8 — E6 needs `encoded_size`.** §6.8 and Appendix A define the selector's cost over the canonical wire size. The authority matrix originally let only E0 and E7 call E3. Duplicating the size formula inside E6 would create a second source of truth for the format. The corrected edge is `E6 → E3 encoded_size`, size-only and read-only: E6 may not call `encode`, `decode`, or `validate`, and may not emit wire. All byte claims remain E3's or the harness's.

**A9 — Coverage fractions.** The parent requires structure coverage (V2-G4) but names no fraction, and its corpus mixes structured and incompressible fixtures. The component gates pin:

- `E5-G`: 99.9 % structural coverage on each structured family of its bounded measurement corpus (4 MiB each). `S-RAND`, `S-CODED`, `S-RANDCO`, and `S-TRAP` carry the zero-false-candidate requirement only.
- `E6-G`: 99.9 % interval-union structural coverage on each of `F02–F08`, measured on the final canonical decoded term.

These fractions are derived, not parent values, and were ratified on 2026-11-13 under the record above. A fraction that cannot be met by exact terms on its corpus is a spec defect, not a gate result: the corpus or the fraction is amended first, in the open.

---

*End of component specification. It derives every role from `SPECS-V2.md`; it introduces no new capability.*
