#pragma once
#include "gates.hpp"
#include <filesystem>

namespace marp::harness {

// E0-G self-test: MARP-H0 envelope accept/reject/false-gate
// Returns 0 on PASS (all three checks pass), nonzero on FAIL
int run_e0_selftest(const std::filesystem::path& root);

} // namespace marp::harness