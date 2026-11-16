// MARP v2 — E3 WIRE — E3-G integrated gate — independent H3 oracle adapter.
//
// Independence (E3 §13.1, §13.4 step 3): the H3 decoder is a clean-room
// implementation that includes no `mapr/` header and links no E1/E2/E3 object.
// The harness reaches it only by *running its binary* and parsing its stdout —
// never by linking it and never by including its headers.  A missing binary is a
// reported BLOCKED row, not a silent skip.
#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include "e3g_support.hpp"

namespace e3g {

// Parsed result of one oracle invocation on one container.
struct OracleOutcome {
    bool available = false;      // the binary exists and is executable
    bool ran = false;            // the process started and exited
    int exit_code = -1;          // verify/inspect exit status (0 == accepted)
    // `inspect` fields (see harness/oracle/src/decode.cpp write_inspect_tsv).
    std::string file_bytes;
    std::string version_major;
    std::string version_minor;
    std::string flags;
    std::string header_bytes;
    std::string total_length;
    std::string total_length_big_len;
    std::string atom_offset;
    std::string node_offset;
    std::string index_offset;
    std::string trailer_offset;
    std::string file_crc32;
    std::string trailer_file_bytes;
    std::string trailer_root_id;
    std::string trailer_atom_count;
    std::string trailer_node_count;
    std::string trailer_crc32;
    std::vector<std::string> atoms;    // "klass<TAB>len<TAB>sha"
    std::vector<std::string> nodes;    // "kind<TAB>argc<TAB>args<TAB>params<TAB>len"
    std::vector<std::string> index;    // "offset<TAB>node_id<TAB>crc32"
    std::string output_sha256;         // from a `decode` run, when requested
    // A structural key assembled *by the oracle's own rendering*: the version-2
    // header fields the oracle parsed, its atom table, its node table (with H3's
    // parameter text) and the trailer's structural counts.  Comparing this against
    // `e3g::structural_key` of the harness's `Ir` compares two independent readers
    // of the same bytes without either one dictating the other's format.
    std::string key_text;
    std::string raw;                   // full stdout+stderr, for the log
    std::string error;                 // parser/process-level problem
};

// Runs `mapr_oracle inspect <file>` on a temporary file holding `wire`.
OracleOutcome oracle_inspect(const std::string& oracle_path, const std::vector<u8>& wire);

// Runs `mapr_oracle decode <in> <out>` (full denotation) and reports the digest of
// the decoded bytes plus the exit status.  Used by the legacy half (step 8) where
// the expected output digest is recorded.
OracleOutcome oracle_decode(const std::string& oracle_path, const std::vector<u8>& wire);

// Runs `mapr_oracle verify <file> [--sha256 <hex>]`; exit 0 means the oracle both
// accepted the container and reproduced the expected denotation digest.
OracleOutcome oracle_verify(const std::string& oracle_path, const std::vector<u8>& wire,
                            const std::string& expect_sha256);

// True iff the oracle is present and executable.  Checked once by the gate so a
// missing oracle produces one BLOCKED row and a clear reason.
bool oracle_available(const std::string& oracle_path);

// Writes `bytes` to a unique temporary file, returning its path (empty on
// failure).  The caller removes it.
std::string write_temp_file(const std::vector<u8>& bytes, const char* tag);
void remove_temp_file(const std::string& path);

}  // namespace e3g
