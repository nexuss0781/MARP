// MARP v2 — E2-G integrated ALGEBRA gate — H3 oracle binding.
//
// E2-G §12.1 requires an *independent* denotation oracle that is not linked to
// E2.  The oracle is H3 (`harness/oracle`), a clean-room v2 implementation that
// shares no code with `engine/src/e2` and includes no `mapr/` header (proved by
// the `e2-g.yml` independence job and by the harness rows).
//
// The oracle works on the *wire* `ParsedContainer`, so this header contains the
// one piece of translation code the gate needs: an `Ir` → `ParsedContainer`
// bridge.  It is evidence-glue only: it copies structure, it never computes a
// denotation, a length, or a canonical form.  Lengths are copied from the
// engine's `Ir` and are compared against the oracle's independently recomputed
// lengths as part of the gate (§12.4 step 4b), so a wrong length cannot hide.
//
// Nothing here is compiled into any E2 library object; it lives in the gate
// binary only.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include "oracle_internal.hpp"

#include "mapr/e2/e2_term.hpp"

namespace e2g {

using namespace marp::v2;  // NOLINT
namespace od = marp::oracle::detail;

// Owns the payload bytes of one bound container; the oracle's `ByteSource`
// abstraction is satisfied by a source that reads from `payload`, which lives
// as long as the binding.
struct OracleBinding {
    std::shared_ptr<const std::vector<std::uint8_t>> payload;
    od::ParsedContainer container;
    std::unique_ptr<od::ByteSource> source;
    std::string error;
};

// Bridge: engine `Ir` → oracle `ParsedContainer` (structure only).
OracleBinding make_binding(const Ir& ir);

// Exact oracle recomputation of the structural length of a node, in the
// oracle's own arbitrary-precision arithmetic (§4.4).  `ok` is false when the
// node is structurally invalid in the oracle's own analysis.
BigInt oracle_length(const OracleBinding& binding, std::uint32_t node, bool& ok);

// The oracle self-test KATs (H3 `tests/oracle_test.cpp` helpers) re-expressed
// here so the gate can compare the engine against the oracle's own reference
// vectors without linking test code.  These call the oracle's `Crc32` /
// `Sha256` classes, i.e. the oracle's implementation, not the engine's.
std::uint32_t oracle_crc32(std::span<const std::uint8_t> bytes);

// Full denotation through the oracle (materialised; the caller bounds size).
bool oracle_denote(const OracleBinding& binding, std::uint32_t node,
                   std::vector<std::uint8_t>& out, std::string& error);

// Oracle range slice `[start, start + len)` of `node`.
bool oracle_range(const OracleBinding& binding, std::uint32_t node,
                  const od::BigInt& start, std::size_t len,
                  std::vector<std::uint8_t>& out, std::string& error);

// Independent 64x64 GF(2) matrix exponentiation of the LFSR byte transition
// (`T^(8*offset)`), calculated by the oracle implementation.
std::uint64_t oracle_lfsr_state(u64 conn, u64 init, const od::BigInt& byte_offset);

// Bytes emitted by the oracle implementation from an already-computed state.
void oracle_lfsr_emit(u64 conn, std::uint64_t& state, std::span<std::uint8_t> out);

// Conversion helpers between the engine and oracle `BigInt` types.
od::BigInt to_oracle(const BigInt& value);
BigInt from_oracle(const od::BigInt& value);

// SHA-256 from the oracle (independent digest implementation).
std::array<std::uint8_t, 32> oracle_sha256(std::span<const std::uint8_t> bytes);

}  // namespace e2g
