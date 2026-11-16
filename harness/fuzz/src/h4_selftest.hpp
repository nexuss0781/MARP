// MARP v2 — H4 FUZZ — deterministic self-checks.
//
// Proves the instrument works before the campaign is trusted:
//   * every mutation class is produced, and each class actually changes bytes;
//   * a mutation is a pure function of (campaign seed, index) — repeated plans
//     are byte-identical;
//   * the four classes cover header, index, trailer and body regions;
//   * a seed-directory round trip preserves every seed identity;
//   * the runner classifies an unchanged valid container as valid and a
//     truncated/flipped one as rejected;
//   * a worker-count change does not change a single count;
//   * the §12.8 target predicate fails when an accepted-invalid, crash or
//     timeout appears (E0 must be able to declare FAIL);
//   * the evidence renderer is deterministic.
#pragma once

#include <filesystem>

namespace marp::harness::h4 {

// Returns 0 when every check passes; prints one line per check.
int run_self_test(const std::filesystem::path& root, const std::filesystem::path& seed_dir);

}  // namespace marp::harness::h4
