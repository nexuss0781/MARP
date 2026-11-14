#pragma once
#include <vector>
#include <string>
#include <string_view>
#include <array>
#include <cstdint>
#include <optional>
#include <utility>

namespace marp::harness::oracle {

// Base-10^9 limb type (each limb < 1,000,000,000)
// Little-endian order in vectors
using Limb = uint32_t;
static constexpr Limb BASE = 1000000000; // 10^9
using BigInt = std::vector<Limb>; // little-endian, no leading zero limbs (except for zero)

// Remove leading zero limbs (maintain at least one limb for zero)
BigInt trim(const BigInt& x);

// Comparison: -1 if a < b, 0 if a == b, 1 if a > b
int compare(const BigInt& a, const BigInt& b);

// From decimal string (canonical, no leading zeros except "0")
// Returns nullopt on invalid input
std::optional<BigInt> from_decimal(std::string_view s);

// To decimal string (canonical, no leading zeros except "0")
std::string to_decimal(const BigInt& a);

// From little-endian bytes
BigInt from_le_bytes(std::string_view b);

// To little-endian bytes (trimmed trailing zeros)
std::vector<uint8_t> to_le_bytes(const BigInt& a);

// Bit length (0 for zero)
int bit_length(const BigInt& a);

// Arithmetic
BigInt add(const BigInt& a, const BigInt& b);
std::optional<BigInt> sub(const BigInt& a, const BigInt& b); // nullopt if a < b
BigInt mul(const BigInt& a, const BigInt& b);

// Division: returns (quotient, remainder), divisor must be non-zero
std::pair<BigInt, BigInt> divmod(const BigInt& a, const BigInt& b);

// Scalar division by 1 <= d < 2^32
std::pair<BigInt, Limb> divmod_scalar(const BigInt& a, Limb d);

// SHA-256 from FIPS 180-4
std::array<uint8_t, 32> sha256(std::string_view data);

// CRC-32 (reflected polynomial 0xEDB88320, init=0xFFFFFFFF, xorout=0xFFFFFFFF)
uint32_t crc32(std::string_view data);

// Incremental CRC-32 (zlib-compatible: init=0, no final XOR)
// Accepts finalized CRC (with xorout applied) and returns finalized CRC
uint32_t crc32_incremental(std::string_view data, uint32_t prev_finalized);

// CRC-32 combine: crc(A||B) from crc(A), crc(B), len(B)
// Both CRCs are standard finalized values
uint32_t crc32_combine(uint32_t crc_a, uint32_t crc_b, size_t len_b);

// Zeroed-field CRC: CRC with 4 bytes at offset forced to zero
uint32_t crc32_zeroed(std::string_view data, size_t offset);

// Gear hash (Math-SPECS §15.1)
uint64_t gear_hash(std::string_view data, uint64_t seed = 0);

// Oracle self-check: run known vectors and return true if all pass
bool self_check();

} // namespace marp::harness::oracle