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

// One-shot CRC-32 (standard finalized value: init=0xFFFFFFFF, xorout=0xFFFFFFFF)
uint32_t crc32(std::string_view data) noexcept;

// Incremental CRC-32: accepts a **finalized** CRC (xorout applied) and returns a finalized CRC.
// This is the zlib continuation convention: crc32_incremental(B, crc32(A)) == crc32(A+B)
// and crc32_incremental(data) == crc32(data) when called with default argument (0 = finalized CRC of empty).
uint32_t crc32_incremental(std::string_view data, uint32_t prev_finalized = 0) noexcept;

// Combine: crc(A‖B) from crc(A), crc(B), len(B)
// Both CRCs must be standard finalized values (crc32() output).
// Math-SPECS C8: c_AB = Z^{8·len(B)}(c_A) ⊕ c_B
uint32_t crc32_combine(uint32_t crc_a, uint32_t crc_b, size_t len_b) noexcept;

// Zeroed-field checksum: CRC with 4 bytes at `offset` forced to zero
// Math-SPECS C9, C10
uint32_t crc32_zeroed(std::string_view data, size_t offset) noexcept;

// Verify zeroed-field invariance (debug only)
bool crc32_zeroed_invariant(std::string_view data, size_t offset) noexcept;

// Crc32 class (surface alias per SPECS §5.4)
class Crc32 {
public:
    Crc32() noexcept : state_(CRC32_INIT) {}
    explicit Crc32(uint32_t initial_finalized) noexcept : state_(initial_finalized ^ CRC32_INIT) {}

    void reset() noexcept { state_ = CRC32_INIT; }
    void reset(uint32_t initial_finalized) noexcept { state_ = initial_finalized ^ CRC32_INIT; }

    // Process data, returns *this for chaining
    Crc32& update(std::string_view data) noexcept {
        const uint8_t* bytes = reinterpret_cast<const uint8_t*>(data.data());
        for (size_t i = 0; i < data.size(); ++i) {
            state_ = crc32_table()[(state_ ^ bytes[i]) & 0xFF] ^ (state_ >> 8);
        }
        return *this;
    }

    // Finalize and return standard finalized CRC; resets to initial state
    uint32_t finish() noexcept {
        uint32_t result = state_ ^ CRC32_XOROUT;
        state_ = CRC32_INIT;
        return result;
    }

    // One-shot convenience
    static uint32_t of(std::string_view data) noexcept { return crc32(data); }
    static uint32_t of_with_zeroed(std::string_view data, size_t offset) noexcept { return crc32_zeroed(data, offset); }

private:
    uint32_t state_;
};

} // namespace mapr