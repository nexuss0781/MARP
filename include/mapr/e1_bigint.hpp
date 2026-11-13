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
    BigInt() noexcept = default;                    // zero
    BigInt(uint64_t v) noexcept;                    // from u64
    static Result<BigInt> from_u64(uint64_t v) noexcept;     // checked (always Ok)
    static Result<BigInt> from_limbs(const Limb* data, size_t n) noexcept; // requires canonical
    static Result<BigInt> from_le_bytes(std::string_view b) noexcept;       // Math-SPECS A17
    static Result<BigInt> from_decimal(std::string_view s) noexcept;        // Math-SPECS A16

    // Observers
    bool is_zero() const noexcept;
    size_t limb_count() const noexcept;
    const Limb* limbs() const noexcept;
    Limb limb(size_t i) const noexcept;             // 0 if i >= count
    int bit_length() const noexcept;                // Math-SPECS A14

    // Conversions (exact, Math-SPECS A16, A18)
    std::optional<uint64_t> to_u64_checked() const noexcept;         // nullopt if ≥ 2^64
    std::string to_decimal() const;                           // canonical, no leading zeros
    std::vector<uint8_t> to_le_bytes() const noexcept;                 // trimmed trailing zeros

    // Comparison (Math-SPECS A4)
    int compare(const BigInt& other) const noexcept;
    bool operator==(const BigInt& other) const noexcept { return compare(other) == 0; }
    bool operator!=(const BigInt& other) const noexcept { return compare(other) != 0; }
    bool operator<(const BigInt& other) const noexcept { return compare(other) < 0; }
    bool operator<=(const BigInt& other) const noexcept { return compare(other) <= 0; }
    bool operator>(const BigInt& other) const noexcept { return compare(other) > 0; }
    bool operator>=(const BigInt& other) const noexcept { return compare(other) >= 0; }

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
    static BigInt zero() noexcept { return BigInt(); }
    static BigInt one() noexcept { return BigInt(1); }

    // Destructor / move / copy
    ~BigInt() noexcept;
    BigInt(const BigInt& other) noexcept;
    BigInt& operator=(const BigInt& other) noexcept;
    BigInt(BigInt&& other) noexcept;
    BigInt& operator=(BigInt&& other) noexcept;

private:
    // SBO: up to 2 limbs inline, else heap-allocated
    std::array<Limb, SBO_LIMBS> small_;
    Limb* heap_ = nullptr;
    size_t count_ = 0;        // number of valid limbs (0 or top != 0)
    size_t capacity_ = 0;     // valid only when on_heap_
    bool on_heap_ = false;

    // Invariant: canonical (count_ == 0 || limb(count_-1) != 0)
    // All constructors and mutators maintain this.

    // Internal helpers
    void trim() noexcept;
    void ensure_capacity(size_t n);
    Limb* mutable_limbs() noexcept;
    const Limb* limbs_ptr() const noexcept;

    // Static helpers for divmod
    static Result<std::pair<BigInt, BigInt>> divmod_knuth(const BigInt& u, const BigInt& v) noexcept;
};

} // namespace mapr