// MARP v2 — C07 WIRE — H3 oracle cross-check through a separate process.
//
// Independence (E3 §13.1, §13.4 step 3): the H3 decoder is an independent
// clean-room implementation.  The harness reaches it only by *running its
// binary* on a temporary file and parsing its exit code and stdout — never by
// linking it, and never by including its headers.  The path is passed in by the
// makefile/CI so a missing oracle is a reported BLOCKED row, not a silent skip.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace c07 {

struct OracleResult {
    bool available = false;      // binary present and executable
    bool ran = false;            // process started and exited
    int exit_code = -1;          // process exit status
    std::string output_sha256;   // parsed from `verify`/`inspect` stdout
    std::string total_length;    // parsed from `inspect` stdout
    std::string raw;             // full stdout/stderr (for the log)
};

// Runs `mapr_oracle inspect <file>` (structure) and, when `want_digest`,
// `mapr_oracle verify <file>` (full denotation) on a temporary file holding
// `wire`.  `expected_sha256` is the engine's own digest, cross-checked when the
// oracle reports one.
OracleResult oracle_inspect(const std::string& oracle_path,
                            const std::vector<std::uint8_t>& wire,
                            bool want_digest);

// Writes `bytes` to a unique temporary file and removes it again.
bool write_temp_file(const std::vector<std::uint8_t>& bytes, std::string& path);

}  // namespace c07
