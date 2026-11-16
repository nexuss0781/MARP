// MARP v2 — H4 FUZZ — per-mutant allocation guard.
//
// E3 C07 already refuses to size an allocation from an unvalidated count; H4
// measures that property per mutant instead of assuming it.  The guard replaces
// the global allocation functions for the harness binary only, is armed around
// one mutant's `validate` + `decode` + canonical re-encode, and never aborts a
// mutant: a decoder that allocates beyond its budget must be *measured* to fail
// the obligation, not to crash the harness.
//
// With `H4_ALLOC_GUARD_DISABLED` (the sanitizer build, whose runtime supplies
// these symbols) the accounting API still exists but the replacement functions
// are omitted; `enabled()` then reports false and the evidence says so.
#pragma once

#include <cstddef>

namespace marp::harness::h4::alloc_guard {

void begin(std::size_t budget_bytes) noexcept;
void end() noexcept;
std::size_t peak_bytes() noexcept;
std::size_t outstanding_bytes() noexcept;
bool violated() noexcept;
bool enabled() noexcept;

}  // namespace marp::harness::h4::alloc_guard
