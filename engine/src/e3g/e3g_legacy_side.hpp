// MARP v2 — E3 WIRE — E3-G integrated gate — legacy (W-V1) half, POD interface.
//
// The legacy half runs as `bin/e3g_legacy_half` (see `e3g_legacy_side.cpp` for why
// it must be a process and not a second translation unit or a shared definition).
// This header is the gate's side of that boundary: it names no `mapr/` type at
// all, so `e3g_main.cpp` can drive both halves without including either component
// header.  That is what makes "C08 is not callable from the v2 encode path" a
// structural property of the build rather than a review promise.
#pragma once

#include <cstddef>
#include <string>
#include <vector>

namespace e3g {

// One row of §13.5, already reduced to strings.
struct LegacyRow {
    std::string check;
    std::string item_id;
    std::string input_sha256;
    std::string wire_sha256;
    std::string wire_bytes;
    std::string expected;
    std::string actual;
    std::string verdict;  // PASS | FAIL | BLOCKED
    std::string log;
    // The term C08 decoded, as a `structural_key` rendering plus the atom payloads
    // in hex, so the wire side can rebuild it and re-encode it as v2 (§13.4 step 8).
    std::string structure_text;
    std::vector<std::string> payload_hex;
};

struct LegacySummary {
    std::string root;
    std::string binary;            // path of the legacy-half process
    bool binary_available = false;
    bool ran = false;
    int exit_code = -1;
    std::size_t fixtures_found = 0;
    std::size_t fixtures_hashed = 0;
    std::size_t fixtures_verified = 0;   // hash matched and decode succeeded
    std::size_t decode_ok = 0;
    std::size_t digest_ok = 0;
    std::size_t canonical_ok = 0;
    std::size_t v2_reencoded = 0;   // fixtures whose v2 re-encode was a fixpoint
    std::size_t failures = 0;
    bool blocked = false;
    std::string blocked_reason;
    std::string surface;
    // Structure digests of the decoded terms, so the wire side can re-encode them
    // as v2 and prove the roundtrip (§13.4 step 8).
    std::vector<std::string> structure_sha;   // one per verified fixture
    std::size_t payloads_received = 0;
    std::vector<LegacyRow> rows;
    std::vector<std::string> log_lines;
    std::vector<std::string> raw;
};

// Runs the legacy half for `root`.  `binary` is the path to `bin/e3g_legacy_half`.
LegacySummary run_legacy_checks(const std::string& root, const std::string& binary);

}  // namespace e3g
