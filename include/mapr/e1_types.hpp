#pragma once
#include <cstdint>
#include <cstddef>
#include <variant>
#include <optional>

namespace mapr {

// Error codes returned by every fallible operation
enum class ErrCode : uint8_t {
    Ok = 0,
    Invalid = 1,      // contract violation (non-canonical input, division by zero, etc.)
    Limit = 2,        // value exceeds supported range (e.g., > 8192-bit for stress corpus)
    // no other codes in E1
};

// Result<T> = T | ErrCode. No exceptions.
// Use std::variant with a helper for ergonomics.
template <typename T>
class Result {
    std::variant<T, ErrCode> storage_;

public:
    constexpr Result() noexcept : storage_(ErrCode::Invalid) {} // default to invalid
    constexpr Result(const T& value) noexcept : storage_(value) {}
    constexpr Result(T&& value) noexcept : storage_(std::move(value)) {}
    constexpr Result(ErrCode err) noexcept : storage_(err) {}

    constexpr bool ok() const noexcept { return std::holds_alternative<T>(storage_); }
    constexpr bool is_err() const noexcept { return std::holds_alternative<ErrCode>(storage_); }
    constexpr ErrCode error() const noexcept { return std::get<ErrCode>(storage_); }
    constexpr T& value() & noexcept { return std::get<T>(storage_); }
    constexpr const T& value() const& noexcept { return std::get<T>(storage_); }
    constexpr T&& value() && noexcept { return std::get<T>(std::move(storage_)); }
    constexpr const T&& value() const&& noexcept { return std::get<T>(std::move(storage_)); }

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