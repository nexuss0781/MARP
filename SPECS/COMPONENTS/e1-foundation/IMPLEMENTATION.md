# E1 — FOUNDATION — Implementation Specification

| Field | Value |
|---|---|
| **Document ID** | MARP2-E1-IMPL |
| **Version** | 1.0 |
| **Status** | Normative implementation spec for E1. Derived from `Math-SPECS.md` and `SPECS.md`. |
| **Parent** | `MARP/SPECS/COMPONENTS/e1-foundation/Math-SPECS.md`, `MARP/SPECS/COMPONENTS/e1-foundation/SPECS.md` |
| **Language** | C++20. No third-party libraries. No Python. |
| **Gate** | `E1-G` |

---

## 0. Purpose and scope

This document translates the mathematical derivations of `Math-SPECS.md` into a concrete C++20 codebase. Every type, function, and invariant here is traceable to a theorem, lemma, or definition in `Math-SPECS.md`. The gate `E1-G` (§12 of `SPECS.md`) is the sole acceptance criterion; nothing is accepted on inspection.

**Non-goals**: performance tuning, SIMD, parallelism, subquadratic conversion. The complexity bounds in `Math-SPECS.md` §16 are contractual; a faster algorithm returning identical values is allowed but out of scope.

---

## 1. Repository layout (files to create)

All paths are relative to the MARP repository root.

```
MARP/
├── include/
│   └── mapr/
│       ├── e1_bigint.hpp          # public API: BigInt, compare, add, sub, mul, divmod, shifts, conversions
│       ├── e1_length.hpp          # public API: length_of(NodeId), structural identities
│       ├── e1_sha256.hpp          # public API: Sha256 streaming state, one-shot
│       ├── e1_crc32.hpp           # public API: crc32, crc32_combine, crc32_zeroed
│       ├── e1_gear.hpp            # public API: gear_hash
│       └── e1_types.hpp           # shared types: Err, NodeId, AtomId, Result<T>
├── engine/
│   └── src/
│       ├── e1_bigint.cpp          # BigInt implementation
│       ├── e1_length.cpp          # length_of with memoisation
│       ├── e1_sha256.cpp          # SHA-256 implementation
│       ├── e1_crc32.cpp           # CRC-32 implementation
│       └── e1_gear.cpp            # Gear hash implementation
├── tests/
│   ├── e1_bigint_test.cpp         # O1.1, O1.2, O1.3, O1.4 unit tests
│   ├── e1_length_test.cpp         # O1.5 unit tests
│   ├── e1_sha256_test.cpp         # O1.6, O1.7 unit tests
│   ├── e1_crc32_test.cpp          # O1.6, O1.7 unit tests
│   └── e1_gear_test.cpp           # O1.8 unit tests
└── SPECS/
    └── COMPONENTS/
        └── e1-foundation/
            ├── Math-SPECS.md      # (already exists)
            ├── SPECS.md           # (already exists)
            └── IMPLEMENTATION.md  # (this file)
```

**No other files** are created or modified for E1. The public API surface is exactly the five headers under `include/mapr/`.

---

## 2. Quality standard for every file

Every `.hpp` and `.cpp` file **MUST** satisfy:

| Requirement | How verified |
|---|---|
| **C++20 only** | Compiles with `-std=c++20 -pedantic -Wall -Wextra -Werror -Wconversion -Wshadow -Wnull-dereference -Wdouble-promotion -Wformat=2` |
| **No UB** | All integer operations defined by the standard; no signed overflow, no out-of-bounds, no use-after-move |
| **Exact match to math** | For every function `f` with mathematical spec `M_f`, the test corpus checks `f(x) == M_f(x)` for all `x` in the gate corpus |
| **No heap in hot paths** | `BigInt` uses small-buffer optimization (SBO) for ≤ 2 limbs; `Sha256`, `Crc32`, `GearHash` are stack-only |
| **`Err` for all failures** | No exceptions, no `assert` in production paths; every contract violation returns `Err{Invalid}` or `Err{Limit}` |
| **Documentation** | Every public function has a `///` Doxygen comment citing the exact `Math-SPECS.md` theorem/lemma/definition |
| **`constexpr` where possible** | `compare`, `shl`, `shr`, `bit_length`, `to_le`/`from_le` for compile-time constants |
| **No `std::vector` in public API** | `BigInt` owns its storage; `Sha256`/`Crc32`/`GearHash` are fixed-size structs |

---

## 3. File specifications

### 3.1 `include/mapr/e1_types.hpp`

**Purpose**: Shared vocabulary types used by all E1 headers.

**Contents**:

```cpp
#pragma once
#include <cstdint>
#include <cstddef>
#include <variant>

namespace mapr {

// Error codes returned by every fallible operation
enum class ErrCode : uint8_t {
    Ok = 0,
    Invalid = 1,      // contract violation (non-canonical input, division by zero, etc.)
    Limit = 2,        // value exceeds supported range (e.g., > 8192-bit for stress corpus)
    // no other codes in E1
};

// Result<T> = T | ErrCode. No exceptions.
template <typename T>
using Result = std::variant<T, ErrCode>;

// Opaque identifiers (E1 does not define their layout; E2/E3 do)
using NodeId  = uint32_t;
using AtomId  = uint32_t;

// Limb type: exactly 32 bits, little-endian order in BigInt
using Limb = uint32_t;
static constexpr Limb LIMB_MAX = 0xFFFFFFFFu;
static constexpr uint64_t BASE = 0x100000000ull; // 2^32

// SBO threshold: number of limbs stored inline in BigInt
static constexpr size_t SBO_LIMBS = 2;

} // namespace mapr
```

**Traceability**:
- `ErrCode::Invalid` → `Math-SPECS.md` A1–A3 (canonicality), A6 (sub precondition), A9 (div by zero), B7 (L=0 guard)
- `ErrCode::Limit` → `Math-SPECS.md` A15 (to_u64_checked), C2 (SHA-256 64-bit length field)
- `Limb`, `BASE` → `Math-SPECS.md` §2.1 (representation theorem)
- `SBO_LIMBS` → `Math-SPECS.md` §16 (k ≤ 33 for gate corpus)

---

### 3.2 `include/mapr/e1_bigint.hpp`

**Purpose**: Exact non-negative integer (`BigInt`) with all arithmetic from `Math-SPECS.md` Part A.

**Public API**:

```cpp
#pragma once
#include "e1_types.hpp"
#include <array>
#include <string>
#include <string_view>
#include <vector>

namespace mapr {

class BigInt {
public:
    // Constructors
    constexpr BigInt() noexcept = default;                    // zero
    constexpr BigInt(uint64_t v) noexcept;                    // from u64
    static Result<BigInt> from_u64(uint64_t v) noexcept;     // checked (always Ok)
    static Result<BigInt> from_limbs(const Limb* data, size_t n) noexcept; // requires canonical
    static Result<BigInt> from_le_bytes(std::string_view b) noexcept;       // Math-SPECS A17
    static Result<BigInt> from_decimal(std::string_view s) noexcept;        // Math-SPECS A16

    // Observers
    constexpr bool is_zero() const noexcept;
    constexpr size_t limb_count() const noexcept;
    constexpr const Limb* limbs() const noexcept;
    constexpr Limb limb(size_t i) const noexcept;             // 0 if i >= count
    constexpr int bit_length() const noexcept;                // Math-SPECS A14

    // Conversions (exact, Math-SPECS A16, A18)
    Result<uint64_t> to_u64_checked() const noexcept;         // Err::Limit if ≥ 2^64
    std::string to_decimal() const;                           // canonical, no leading zeros
    std::vector<uint8_t> to_le_bytes() const;                 // trimmed trailing zeros

    // Comparison (Math-SPECS A4)
    constexpr int compare(const BigInt& other) const noexcept;

    // Arithmetic (Math-SPECS A5, A6, A7, A9–A11)
    Result<BigInt> add(const BigInt& other) const noexcept;
    Result<BigInt> sub(const BigInt& other) const noexcept;   // requires *this >= other
    Result<BigInt> mul(const BigInt& other) const noexcept;

    // Division (Math-SPECS A10, A11)
    // Returns (quotient, remainder). Divisor must be non-zero.
    Result<std::pair<BigInt, BigInt>> divmod(const BigInt& divisor) const noexcept;

    // Scalar division by 1 ≤ d < 2^32 (Math-SPECS A10)
    Result<std::pair<BigInt, Limb>> divmod_scalar(Limb d) const noexcept;

    // Shifts (Math-SPECS A13)
    Result<BigInt> shl(size_t n) const noexcept;              // multiply by 2^n
    Result<BigInt> shr(size_t n) const noexcept;              // floor divide by 2^n

    // Factory for small constants
    static constexpr BigInt zero() noexcept { return BigInt(); }
    static constexpr BigInt one() noexcept { return BigInt(1); }

private:
    // SBO: up to 2 limbs inline, else heap-allocated
    std::array<Limb, SBO_LIMBS> small_;
    Limb* heap_ = nullptr;
    size_t count_ = 0;        // number of valid limbs (0 or top != 0)
    bool on_heap_ = false;

    // Invariant: canonical (count_ == 0 || limb(count_-1) != 0)
    // All constructors and mutators maintain this.
};

} // namespace mapr
```

**Traceability table**:

| Method | Math-SPECS ref | Notes |
|---|---|---|
| `from_limbs` | A1, A2 | Precondition: canonical (top limb ≠ 0 unless zero). Returns `Err::Invalid` if violated. |
| `from_le_bytes` | A17, A18 | Trims trailing zeros; empty → zero. |
| `from_decimal` | A16 | Canonical decimal only (`0` or `[1-9][0-9]*`). `Err::Invalid` on bad format. |
| `to_u64_checked` | A15 | `Err::Limit` if `limb_count() > 2` or `limb_count()==2 && limb(1)!=0`. |
| `to_decimal` | A16 | Repeated `divmod_scalar(10^9)`. |
| `to_le_bytes` | A18 | Groups 4 bytes per limb, trims trailing zeros. |
| `compare` | A4 | Length-first, then top-down limb compare. `O(min(k,m))`. |
| `add` | A5 | `O(max(k,m))`. SBO-aware allocation. |
| `sub` | A6 | Precondition `*this >= other` (checked via `compare`). `Err::Invalid` if violated. |
| `mul` | A7 | Schoolbook `O(km)`. SBO for small operands. |
| `divmod` | A11 (Knuth D) | Normalizes, estimates `q̂`, corrects ≤ 2 times per digit. `Err::Invalid` if divisor zero. |
| `divmod_scalar` | A10 | `O(k)`. Used by `to_decimal`. |
| `shl`/`shr` | A13 | `O(k + n/32)`. `shr` is floor. |

**Implementation notes**:

- **SBO**: `count_ ≤ SBO_LIMBS` → limbs in `small_`; else `heap_ = new Limb[count_]`.
- **Canonicality**: Every mutating operation ends with `trim()` (drop trailing zero limbs, set `count_=0` if all zero).
- **Knuth D**: Use `unsigned __int128` for the 64×32→96 products and the `q̂·v_{n-2}` comparison (Math-SPECS A11, Remark A12).
- **No `std::vector` in hot paths**: `divmod` allocates quotient/remainder once at final size.
- **`constexpr`**: `compare`, `bit_length`, `shl`, `shr`, `limb`, `is_zero`, `zero()`, `one()`.

---

### 3.3 `include/mapr/e1_length.hpp`

**Purpose**: Structural length function `ℓ(t)` from `Math-SPECS.md` Part B.

**Public API**:

```cpp
#pragma once
#include "e1_types.hpp"
#include "e1_bigint.hpp"

namespace mapr {

// Forward declaration of the term DAG (owned by E2; E1 only sees the interface)
class TermView;

// Length result with memoisation table
struct LengthResult {
    BigInt length;                    // ℓ(t) for the root
    std::vector<BigInt> memo;         // memo[node_id] = ℓ(node), valid for reachable nodes
};

// Compute ℓ(t) for a well-formed term.
// Precondition: term is well-formed (E2 enforces; E1 asserts in debug).
// Returns Err::Invalid if a side condition is violated (e.g., Repeat r ≥ ℓ(c)).
Result<LengthResult> length_of(const TermView& term) noexcept;

// Structural identities (Math-SPECS §11.1). These are the O1.5 checks.
// Each takes child lengths already computed and returns the parent length.
namespace length_identity {
    constexpr BigInt concat(const std::vector<BigInt>& children) noexcept;
    constexpr BigInt repeat(const BigInt& child_len, const BigInt& q, const BigInt& r) noexcept;
    constexpr BigInt slice(const BigInt& child_len, const BigInt& start, const BigInt& len) noexcept;
    constexpr BigInt interleave(const std::vector<BigInt>& children, uint32_t stride) noexcept;
    constexpr BigInt morph(const BigInt& child_len) noexcept { return child_len; }
    constexpr BigInt xor_len(const BigInt& a, const BigInt& b) noexcept { return a; } // a==b by well-formedness
    constexpr BigInt predictor(const BigInt& residual_len) noexcept { return residual_len; }
    constexpr BigInt fixed(const BigInt& n) noexcept { return n; } // Zero, Lfsr, Affine
} // namespace length_identity

} // namespace mapr
```

**Traceability**:

| Function | Math-SPECS ref | Notes |
|---|---|---|
| `length_of` | B1, B2, B3 | Topological order traversal; memoises per `NodeId`. `O(V+E)` limb ops. |
| `concat` | I1 | `Σ ℓ(cᵢ)` |
| `repeat` | I2, B6 | `q·ℓ(c) + r`. Checks `r < ℓ(c)` when `q ≥ 1`, `r == 0` when `q == 0`. |
| `slice` | I3 | Returns `len`. Checks `start + len ≤ child_len`. |
| `interleave` | I4 | `k·ℓ(c₁)`. Checks all children equal length, `ℓ(c₁) % stride == 0`. |
| `morph` | I5 | Identity. Well-formedness checks in `TermView` (E2). |
| `xor_len` | I6 | Returns `a` (equals `b`). |
| `predictor` | I7 | Returns `ℓ(residual)`. |
| `fixed` | I8 | Returns `n`. |

**Implementation notes**:

- `TermView` is a read-only view provided by E2. It exposes: `node_count()`, `node_kind(NodeId)`, and typed accessors for each kind's fields (all `BigInt` or `uint32_t`).
- `length_of` allocates `memo` of size `node_count()`, fills in topological order (which is `NodeId` order by construction).
- Side-condition violations return `Err::Invalid`; the term is not well-formed.
- All `BigInt` operations use the exact arithmetic from `e1_bigint.hpp`.

---

### 3.4 `include/mapr/e1_sha256.hpp`

**Purpose**: SHA-256 one-shot and streaming from `Math-SPECS.md` §13.

**Public API**:

```cpp
#pragma once
#include "e1_types.hpp"
#include <array>
#include <cstddef>
#include <string_view>

namespace mapr {

class Sha256 {
public:
    // Constants (Math-SPECS C1)
    static constexpr std::array<uint32_t, 8> IV = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    static constexpr std::array<uint32_t, 64> K = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    // Streaming state (Math-SPECS §13.3)
    Sha256() noexcept;
    void reset() noexcept;

    // Process `len` bytes. Returns *this for chaining.
    // Err::Limit if total bits would exceed 2^64-1 (Math-SPECS C2).
    Result<Sha256&> update(std::string_view data) noexcept;

    // Finalize: apply padding (C2) and return 32-byte digest.
    // Consumes the state; object is reset afterwards.
    Result<std::array<uint8_t, 32>> finish() noexcept;

    // One-shot convenience
    static Result<std::array<uint8_t, 32>> hash(std::string_view data) noexcept;

private:
    std::array<uint32_t, 8> state_ = IV;
    std::array<uint8_t, 64> buffer_;
    size_t buffer_len_ = 0;
    uint64_t total_bits_ = 0;   // 8 * bytes processed

    static void compress(std::array<uint32_t, 8>& state, const uint8_t block[64]) noexcept;
    static constexpr uint32_t rotr(uint32_t x, int n) noexcept;
};

} // namespace mapr
```

**Traceability**:

| Method | Math-SPECS ref | Notes |
|---|---|---|
| `IV`, `K` | C1 | Hard-coded tables (derived values; no runtime derivation). |
| `update` | C3 | Processes full 64-byte blocks; `Err::Limit` if `total_bits_ + 8*len ≥ 2^64`. |
| `finish` | C2, C3 | Padding: `0x80`, `k = (56 - (buf_len+1)%64)%64` zeros, `total_bits_` as BE u64. |
| `hash` | C3 | One-shot = `reset()`, `update()`, `finish()`. |
| `compress` | FIPS 180-4 §6.2.2 | 64 rounds with `Σ₀, Σ₁, σ₀, σ₁, Ch, Maj`. All `uint32_t` modulo 2³². |

**Implementation notes**:

- No heap allocation. State is 8×u32 + 64-byte buffer + u64 counter.
- `compress` is `static` and `noexcept`; uses `rotr` and the standard round functions.
- Padding length formula matches `Math-SPECS.md` Lemma C2 exactly.
- Streaming equivalence (Theorem C3) is guaranteed by the buffer+counter design.

---

### 3.5 `include/mapr/e1_crc32.hpp`

**Purpose**: CRC-32 (IEEE 802.3) with combine and zeroed-field from `Math-SPECS.md` §14.

**Public API**:

```cpp
#pragma once
#include "e1_types.hpp"
#include <array>
#include <cstddef>
#include <string_view>

namespace mapr {

// Standard CRC-32 polynomial (reflected 0xEDB88320)
static constexpr uint32_t CRC32_POLY = 0xEDB88320u;
static constexpr uint32_t CRC32_INIT = 0xFFFFFFFFu;
static constexpr uint32_t CRC32_XOROUT = 0xFFFFFFFFu;

// Precomputed tables (generated at compile-time)
const std::array<uint32_t, 256>& crc32_table() noexcept;
const std::array<std::array<uint32_t, 32>, 32>& crc32_combine_matrix() noexcept; // for O(log n) combine

// One-shot CRC-32 (standard finalized value)
uint32_t crc32(std::string_view data) noexcept;

// Incremental CRC-32 (zlib-compatible: init=0, no final XOR)
uint32_t crc32_incremental(std::string_view data, uint32_t crc = 0) noexcept;

// Combine: crc(A‖B) from crc(A), crc(B), len(B)
// Both CRCs must be standard finalized values (crc32() output).
// Math-SPECS C8: c_AB = Z^{8·len(B)}(c_A) ⊕ c_B
uint32_t crc32_combine(uint32_t crc_a, uint32_t crc_b, size_t len_b) noexcept;

// Zeroed-field checksum: CRC with 4 bytes at `offset` forced to zero
// Math-SPECS C9, C10
uint32_t crc32_zeroed(std::string_view data, size_t offset) noexcept;

// Verify zeroed-field invariance (debug only)
bool crc32_zeroed_invariant(std::string_view data, size_t offset) noexcept;

} // namespace mapr
```

**Traceability**:

| Function | Math-SPECS ref | Notes |
|---|---|---|
| `crc32` | C5, C6, C7 | Reflected table-driven. `init=0xFFFFFFFF`, `xorout=0xFFFFFFFF`. |
| `crc32_incremental` | C7 | Matches `zlib.crc32(data, crc)` with `init=0`, no xorout. |
| `crc32_combine` | C8 | Uses precomputed `Z^{8k}` matrix powers (32×32 over GF(2)). `O(log len_b)`. |
| `crc32_zeroed` | C9, C10 | Splices `00 00 00 00` at `offset`, computes CRC. |
| `crc32_table` | C7 | `T[b] = crc32(0, b)` for one zero byte starting from 0? No: table for standard reflected algorithm. |
| `crc32_combine_matrix` | C8 | Precomputed `Z^{8·2^i}` for `i=0..31`. |

**Implementation notes**:

- **Table generation**: Compile-time `constexpr` function builds the 256-entry table from the reflected polynomial `0xEDB88320`.
- **Combine matrix**: The operator `Z` (append one zero bit) is linear; `Z^8` (one zero byte) has matrix `M`. Precompute `M^{2^i}` for `i=0..31`. To shift by `b` bytes, multiply `crc_a` by `M^b` using binary exponentiation on the matrix.
- **Standard vs zlib**: `crc32()` returns standard finalized value. `crc32_incremental()` uses `init=0`, no final XOR, matching `zlib.crc32(data, crc)`. The two are related by `std = (zlib(..., M32) ^ M32)`.
- **Zeroed-field**: Splices in place (or copies if needed); `offset` must be `≤ data.size() - 4`.

---

### 3.6 `include/mapr/e1_gear.hpp`

**Purpose**: Gear hash from `Math-SPECS.md` §15.

**Public API**:

```cpp
#pragma once
#include "e1_types.hpp"
#include <cstddef>
#include <string_view>

namespace mapr {

// Gear hash: h = seed·2^n + Σ G[b_j]·2^{n-1-j} (mod 2^64)
// G[x] = (x * 0x9E3779B97F4A7C15) ^ (x * 0xC2B2AE3D27D4EB4F)  (Math-SPECS §15.1)
static constexpr uint64_t GEAR_SEED_DEFAULT = 0;

// Precomputed table (compile-time)
const std::array<uint64_t, 256>& gear_table() noexcept;

// One-shot
uint64_t gear_hash(std::string_view data, uint64_t seed = GEAR_SEED_DEFAULT) noexcept;

// Streaming (identical to one-shot, for API symmetry)
class GearHash {
public:
    explicit GearHash(uint64_t seed = GEAR_SEED_DEFAULT) noexcept;
    void reset(uint64_t seed = GEAR_SEED_DEFAULT) noexcept;
    void update(std::string_view data) noexcept;
    uint64_t finish() noexcept;
private:
    uint64_t state_;
    size_t total_bytes_;
};

} // namespace mapr
```

**Traceability**:

| Function | Math-SPECS ref | Notes |
|---|---|---|
| `gear_table` | C11 | `G[x] = (x * 0x9E3779B97F4A7C15) ^ (x * 0xC2B2AE3D27D4EB4F) mod 2^64`. |
| `gear_hash` | C11 | Closed form (Theorem C11). `O(n)`. |
| `GearHash::update` | C11 | Iterative: `state = (state << 1) + G[b] mod 2^64`. |
| `GearHash::finish` | C11 | Returns `state`. |

**Implementation notes**:

- **64-byte window** (Theorem C12, Corollary C13): Bytes older than 64 are multiplied by `2^64 ≡ 0`. The iterative form automatically discards them via modulo `2^64` overflow.
- **Not for identity**: `gear_hash` is a bucketing function; collisions are trivial to construct (Corollary C14). No gate uses it for equality.

---

### 3.7 `engine/src/e1_bigint.cpp`

**Purpose**: Implementation of `BigInt` methods.

**Key implementation details**:

```cpp
// Canonical trim: drop trailing zero limbs
void BigInt::trim() noexcept {
    while (count_ > 0 && limb(count_ - 1) == 0) --count_;
    if (count_ == 0) { if (on_heap_) { delete[] heap_; heap_ = nullptr; on_heap_ = false; } }
}

// SBO-aware allocation
void BigInt::ensure_capacity(size_t n) {
    if (n <= SBO_LIMBS) {
        if (on_heap_) { delete[] heap_; heap_ = nullptr; on_heap_ = false; }
        return;
    }
    if (!on_heap_ || capacity_ < n) {
        Limb* new_heap = new Limb[n];
        if (on_heap_) { std::copy(heap_, heap_ + count_, new_heap); delete[] heap_; }
        else { std::copy(small_.begin(), small_.begin() + count_, new_heap); }
        heap_ = new_heap; on_heap_ = true; capacity_ = n;
    }
}

// Knuth D divmod (Math-SPECS A11)
Result<std::pair<BigInt, BigInt>> BigInt::divmod(const BigInt& v) const noexcept {
    if (v.is_zero()) return ErrCode::Invalid;
    int cmp = compare(v);
    if (cmp < 0) return std::make_pair(BigInt::zero(), *this);
    if (cmp == 0) return std::make_pair(BigInt::one(), BigInt::zero());
    if (v.limb_count() == 1) {
        auto [q, r] = divmod_scalar(v.limb(0));
        return std::make_pair(std::move(q), BigInt(r));
    }
    // Full Knuth D with normalization (d = BASE / (v_{n-1} + 1))
    // Use unsigned __int128 for all 64×32→96 products.
    // Correction loop: at most 2 iterations per digit (Theorem A11(b)).
    // Returns canonical q, r.
}
```

**Traceability**: Every function maps to a specific lemma/theorem in `Math-SPECS.md` Part A.

---

### 3.8 `engine/src/e1_length.cpp`

```cpp
Result<LengthResult> length_of(const TermView& term) noexcept {
    size_t N = term.node_count();
    LengthResult res;
    res.memo.resize(N);

    for (NodeId id = 0; id < N; ++id) {
        switch (term.node_kind(id)) {
            case NodeKind::Empty:    res.memo[id] = BigInt::zero(); break;
            case NodeKind::Atom:     res.memo[id] = BigInt(term.atom_size(id)); break;
            case NodeKind::Zero:     res.memo[id] = term.zero_count(id); break;
            case NodeKind::Concat: {
                BigInt sum = BigInt::zero();
                for (NodeId c : term.concat_children(id)) {
                    auto r = sum.add(res.memo[c]);
                    if (!r) return r.error();
                    sum = std::move(r.value());
                }
                res.memo[id] = std::move(sum);
                break;
            }
            case NodeKind::Repeat: {
                const BigInt& L = res.memo[term.repeat_child(id)];
                const BigInt& q = term.repeat_q(id);
                const BigInt& r = term.repeat_r(id);
                if (q.is_zero() && !r.is_zero()) return ErrCode::Invalid;
                if (!q.is_zero()) {
                    int c = r.compare(L);
                    if (c >= 0) return ErrCode::Invalid; // r ≥ L
                }
                auto mq = q.mul(L);
                if (!mq) return mq.error();
                auto mqr = mq.value().add(r);
                if (!mqr) return mqr.error();
                res.memo[id] = std::move(mqr.value());
                break;
            }
            case NodeKind::Slice: {
                const BigInt& L = res.memo[term.slice_child(id)];
                const BigInt& s = term.slice_start(id);
                const BigInt& l = term.slice_len(id);
                if (s.compare(L) > 0) return ErrCode::Invalid;
                auto sp = s.add(l);
                if (!sp) return sp.error();
                if (sp.value().compare(L) > 0) return ErrCode::Invalid;
                res.memo[id] = l;
                break;
            }
            case NodeKind::Morph:
                res.memo[id] = res.memo[term.morph_child(id)];
                break;
            case NodeKind::Xor: {
                const BigInt& a = res.memo[term.xor_a(id)];
                const BigInt& b = res.memo[term.xor_b(id)];
                if (a.compare(b) != 0) return ErrCode::Invalid;
                res.memo[id] = a;
                break;
            }
            case NodeKind::Interleave: {
                const auto& children = term.interleave_children(id);
                uint32_t stride = term.interleave_stride(id);
                if (stride == 0) return ErrCode::Invalid;
                const BigInt& L0 = res.memo[children[0]];
                for (size_t i = 1; i < children.size(); ++i) {
                    if (res.memo[children[i]].compare(L0) != 0) return ErrCode::Invalid;
                }
                if (L0.limb_count() == 1 && L0.limb(0) % stride != 0) return ErrCode::Invalid;
                // For multi-limb, check divisibility by stride via divmod_scalar
                if (L0.limb_count() > 1) {
                    auto dm = L0.divmod_scalar(stride);
                    if (!dm || dm.value().second != 0) return ErrCode::Invalid;
                }
                BigInt k(children.size());
                auto mk = k.mul(L0);
                if (!mk) return mk.error();
                res.memo[id] = std::move(mk.value());
                break;
            }
            case NodeKind::Lfsr:
                res.memo[id] = term.lfsr_n(id);
                break;
            case NodeKind::Affine:
                res.memo[id] = term.affine_n(id);
                break;
            case NodeKind::Predictor:
                res.memo[id] = res.memo[term.predictor_residual(id)];
                break;
        }
    }
    res.length = std::move(res.memo[0]); // root is node 0
    return res;
}
```

---

### 3.9 `engine/src/e1_sha256.cpp`, `e1_crc32.cpp`, `e1_gear.cpp`

**Straightforward transcription** of the algorithms in `Math-SPECS.md` §13, §14, §15.

**CRC-32 combine matrix** (`e1_crc32.cpp`):

```cpp
// Precompute M = Z^8 (one zero byte) as 32×32 matrix over GF(2)
// M[i] = column i = transform of basis vector (1<<i)
static std::array<uint32_t, 32> build_zero_byte_matrix() {
    std::array<uint32_t, 32> mat;
    for (int i = 0; i < 32; ++i) {
        mat[i] = step_zero_byte(1u << i); // internal step_zero_byte
    }
    return mat;
}

// Precompute M^{2^i} for i=0..31
std::array<std::array<uint32_t, 32>, 32> build_combine_matrix() {
    std::array<std::array<uint32_t, 32>, 32> powers;
    powers[0] = build_zero_byte_matrix(); // M^1
    for (int i = 1; i < 32; ++i) {
        powers[i] = mat_square(powers[i-1]); // M^{2^i}
    }
    return powers;
}

uint32_t crc32_combine(uint32_t crc_a, uint32_t crc_b, size_t len_b) noexcept {
    // crc_a, crc_b are standard finalized values (xorout=0xFFFFFFFF)
    // Shift crc_a by len_b zero bytes: apply M^len_b
    uint32_t shifted = crc_a;
    size_t e = len_b;
    int p = 0;
    while (e) {
        if (e & 1) shifted = mat_times(combine_matrix()[p], shifted);
        e >>= 1; ++p;
    }
    return shifted ^ crc_b; // characteristic 2: subtraction = addition
}
```

---

### 3.10 Test files (`tests/e1_*_test.cpp`)

Each test file **MUST** cover the corresponding `O1.x` obligation from `SPECS.md` §7.

| Test file | Obligations | Corpus |
|---|---|---|
| `e1_bigint_test.cpp` | O1.1 (ring laws), O1.2 (div law), O1.3 (decimal), O1.4 (bytes) | `A-ARITH`, `S-DEC`, `S-BYTES` from `SPECS.md` §12.3 |
| `e1_length_test.cpp` | O1.5 (structural identities) | `T-LEN` from `SPECS.md` §12.3 |
| `e1_sha256_test.cpp` | O1.6 (KATs), O1.7 (streaming splits) | FIPS KATs + random split corpus |
| `e1_crc32_test.cpp` | O1.6 (KATs), O1.7 (streaming splits), O1.7 (combine) | zlib cross-check, random split, combine pairs |
| `e1_gear_test.cpp` | O1.8 (stability) | Pinned table, repeated runs |

**Test pattern** (all files):

```cpp
#include "gtest/gtest.h"
#include "mapr/e1_bigint.hpp"
#include "test_corpus.hpp" // generated by E0 harness

TEST(E1BigInt, RingLaws) {
    for (const auto& [a, b, c] : corpus::A_ARITH) {
        EXPECT_EQ(a.add(b).value(), b.add(a).value());           // commutativity
        EXPECT_EQ(a.add(b.add(c)).value(), a.add(b).value().add(c).value()); // associativity
        EXPECT_EQ(a.mul(b.add(c)).value(), a.mul(b).value().add(a.mul(c).value())); // distributivity
    }
}

TEST(E1BigInt, DivisionLaw) {
    for (const auto& [a, b] : corpus::A_ARITH) {
        if (b.is_zero()) continue;
        auto [q, r] = a.divmod(b).value();
        EXPECT_EQ(q.mul(b).value().add(r).value(), a);
        EXPECT_LT(r.compare(b), 0);
    }
}

TEST(E1BigInt, DecimalRoundtrip) {
    for (const auto& s : corpus::S_DEC) {
        auto x = BigInt::from_decimal(s).value();
        EXPECT_EQ(x.to_decimal(), s);
    }
}

TEST(E1BigInt, ByteRoundtrip) {
    for (const auto& b : corpus::S_BYTES) {
        auto x = BigInt::from_le_bytes(b).value();
        auto rt = x.to_le_bytes();
        // rt == trim(b) (trailing zeros removed)
        std::vector<uint8_t> trimmed = b;
        while (!trimmed.empty() && trimmed.back() == 0) trimmed.pop_back();
        EXPECT_EQ(rt, trimmed);
    }
}
```

**Corpus generation**: The `test_corpus.hpp` is produced by the E0 harness (`E0-G` step 3). The test files `#include` it and iterate over the provided vectors.

---

## 4. Gate `E1-G` compliance checklist

Every item below **MUST** be satisfied for `E1-G` to pass. The harness measures each; nothing is accepted on inspection.

| Gate step | Spec reference | Implementation requirement | Measured by |
|---|---|---|---|
| 1 | `SPECS.md` §12.1 | All five headers compile with `-std=c++20 -pedantic -Wall -Wextra -Werror ...` | Compile test |
| 2 | `SPECS.md` §12.2 | All five `.cpp` files link into `libmapr_e1.a` | Link test |
| 3 | `SPECS.md` §12.3 | Corpus fixtures `A-ARITH`, `S-DEC`, `S-BYTES`, `T-LEN` loaded and used | Corpus presence test |
| 4 | `SPECS.md` §12.4 | O1.1–O1.8 unit tests execute and report **zero failures** | Unit test runner |
| 5 | `SPECS.md` §12.5 | Fuzz: 10⁶ random BigInt ops, 10⁵ random terms, 10⁴ random digests — no crashes, no `Err::Invalid` on valid inputs | Fuzz runner |
| 6 | `SPECS.md` §12.6 | `length_of` ignores corrupted stored lengths (fresh recomputation) | Corruption injection test |
| 7 | `SPECS.md` §12.7 | Evidence artifacts written: `specs_and_reports/v2/gates/E1-G.tsv`, `logs/E1-G.log` | Artifact check |

**Failure conditions** (any one fails → `E1-G` = FAIL):

- Any compilation warning with `-Werror`
- Any test failure in O1.1–O1.8
- Any fuzz crash or UB sanitizer hit
- Any `length_of` trusting a pre-stored length
- Missing evidence artifacts

---

## 5. Build integration (for `E0-G` / Makefile)

Add to `engine/Makefile` (only E1 additions shown):

```makefile
E1_SRCS = \
    engine/src/e1_bigint.cpp \
    engine/src/e1_length.cpp \
    engine/src/e1_sha256.cpp \
    engine/src/e1_crc32.cpp \
    engine/src/e1_gear.cpp

E1_OBJS = $(E1_SRCS:.cpp=.o)
E1_TESTS = \
    tests/e1_bigint_test.cpp \
    tests/e1_length_test.cpp \
    tests/e1_sha256_test.cpp \
    tests/e1_crc32_test.cpp \
    tests/e1_gear_test.cpp

E1_TEST_OBJS = $(E1_TESTS:.cpp=.o)

libmapr_e1.a: $(E1_OBJS)
	$(AR) rcs $@ $^

mapr_tests: libmapr_e1.a $(E1_TEST_OBJS) libmapr_harness.a
	$(CXX) $(CXXFLAGS) -o $@ $(E1_TEST_OBJS) -L. -lmapr_e1 -lmapr_harness $(LDFLAGS)

# Compile flags for E1 (strict)
E1_CXXFLAGS = -std=c++20 -pedantic -Wall -Wextra -Werror -Wconversion \
              -Wshadow -Wnull-dereference -Wdouble-promotion -Wformat=2 \
              -Iinclude -Ispecs

$(E1_OBJS): %.o: %.cpp
	$(CXX) $(E1_CXXFLAGS) -c -o $@ $<

$(E1_TEST_OBJS): %.o: %.cpp
	$(CXX) $(E1_CXXFLAGS) -c -o $@ $<
```

**No other components** (E2–E7) are built or linked at this stage.

---

## 6. What is explicitly NOT in E1

| Excluded | Where it belongs |
|---|---|
| Term DAG definition (`TermView`, node kinds, topological order) | E2 (`e2-algebra`) |
| Wire encoding (`uvarint`, tagged bigint, header/trailer) | E3 (`e3-wire`) |
| Atom table, node table, seek index | E3 / E7 |
| Evaluator/denotation `⟦t⟧` | E2 |
| Canonicalisation / decoder | E3 / E7 |
| Cost model / selection (structure → expression) | E5 / E6 |
| `verify --cert`, decimal `Program` fields | E7 |
| Performance optimizations (SIMD, parallel, subquadratic) | Never (out of scope per `Math-SPECS.md` §16) |

---

## 7. Completion criteria

This `IMPLEMENTATION.md` is **complete** when:

1. All 10 files in §1 exist with content matching §3.
2. `engine/Makefile` updated per §5.
3. `make -j4 libmapr_e1.a` succeeds with zero warnings.
4. `make -j4 mapr_tests` runs all E1 tests and reports `ALL TESTS PASSED`.
5. `./mapr_tests --gate=E1-G` produces the evidence artifacts in `specs_and_reports/v2/gates/`.
6. `E1-G` = PASS recorded in `SPECS/Todo-V2.md`.

**Do not start E2** until `E1-G` is measured PASS by the harness.

---

*End of MARP2-E1-IMPL.*