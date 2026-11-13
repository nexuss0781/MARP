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