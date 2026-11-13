#pragma once
#include <cstdint>
#include <cstddef>
#include <utility>

namespace mapr {

// Error codes returned by every fallible operation
enum class ErrCode : uint8_t {
    Ok = 0,
    Invalid = 1,      // contract violation (non-canonical input, division by zero, etc.)
    Limit = 2,        // value exceeds supported range (e.g., > 8192-bit for stress corpus)
    // no other codes in E1
};

// Result<T> = T | ErrCode. No exceptions.
// Simple tag-based implementation to avoid std::variant ambiguity issues.
template <typename T>
class Result {
    bool has_value_;
    T value_;
    ErrCode err_;

public:
    constexpr Result() noexcept : has_value_(false), value_(), err_(ErrCode::Invalid) {}
    constexpr Result(const T& value) noexcept : has_value_(true), value_(value), err_(ErrCode::Invalid) {}
    constexpr Result(T&& value) noexcept : has_value_(true), value_(std::move(value)), err_(ErrCode::Invalid) {}
    constexpr Result(ErrCode err) noexcept : has_value_(false), value_(), err_(err) {}

    constexpr bool ok() const noexcept { return has_value_; }
    constexpr bool is_err() const noexcept { return !has_value_; }
    constexpr ErrCode error() const noexcept { return err_; }
    constexpr T& value() & noexcept { return value_; }
    constexpr const T& value() const& noexcept { return value_; }
    constexpr T&& value() && noexcept { return std::move(value_); }
    constexpr const T&& value() const&& noexcept { return std::move(value_); }

    constexpr explicit operator bool() const noexcept { return ok(); }
};

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