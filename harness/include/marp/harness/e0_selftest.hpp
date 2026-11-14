#pragma once
#include "gates.hpp"
#include <filesystem>
#include <string_view>

namespace marp::harness {

// E0-G self-test: MARP-H0 envelope accept/reject/false-gate.
// Returns 0 only when all three checks pass and E0-G.tsv contains only PASS
// verdicts. `command_line` is recorded in the log.
int run_e0_selftest(const std::filesystem::path& root,
                    std::string_view command_line = {});

} // namespace marp::harness