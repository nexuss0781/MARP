#pragma once
#include <mapr/e1_types.hpp>
#include <mapr/e1_bigint.hpp>
#include <string>
#include <string_view>
#include <filesystem>
#include <vector>
#include <cstdint>

namespace marp::harness {

using BigInt = mapr::BigInt;
using i64 = std::int64_t;

// Generic row used by the parent gate surface (SPECS-V2 §12). E0-G/E1-G
// evidence uses EvidenceRow below, whose eight columns are normative for E1-G.
struct Row {
    std::string gate;
    std::string fixture;
    BigInt input_bytes;
    BigInt wire_bytes;
    i64 ratio_num = 0;
    i64 ratio_den = 1;
    bool sha_match = false;
    std::string verdict;
    std::string log;
};

// One eight-column evidence row:
//   check  corpus  item_id  input_sha256  expected  actual  verdict  log
struct EvidenceRow {
    std::string check;
    std::string corpus;
    std::string item_id;
    std::string input_sha256;
    std::string expected;
    std::string actual;
    std::string verdict; // exactly PASS, FAIL, or BLOCKED
    std::string log;

    bool operator==(const EvidenceRow& other) const = default;
};

// Write a single generic row to a TSV file (append, header on first write).
// Kept for the generic parent surface and harness unit tests.
bool write_row(const std::filesystem::path& tsv_path, const Row& row);

// Write an evidence TSV atomically: rows are sorted by (check, corpus, item_id),
// then written to a temporary file and renamed. A crash cannot leave a half-row.
// Verdicts must be exactly PASS, FAIL, or BLOCKED, and no field may contain a
// tab or newline.
bool write_evidence_tsv(const std::filesystem::path& tsv_path,
                        std::vector<EvidenceRow> rows);

// Read evidence rows back from a TSV, skipping the header.
std::vector<EvidenceRow> read_evidence_tsv(const std::filesystem::path& tsv_path);

// Lowercase hex SHA-256 of a byte string.
std::string sha256_hex(std::string_view data);

// Lowercase hex SHA-256 of a file. Empty string if the file cannot be read.
std::string sha256_file_hex(const std::filesystem::path& path);

// Render ACCEPTANCE.md from the TSVs in tsv_dir. Returns 0 only when every row
// is PASS. On a non-PASS verdict the report is written to a sidecar
// (ACCEPTANCE.FAIL.md) and the primary ACCEPTANCE.md is left untouched.
int render(const std::filesystem::path& tsv_dir, const std::filesystem::path& out);

// True when every row in every TSV under tsv_dir has verdict == PASS.
bool all_rows_pass(const std::filesystem::path& tsv_dir);

// Verify SHA256SUMS. Manifest lines are "<hex>  <repo-relative path>".
// Returns 0 if every entry matches, nonzero otherwise.
int verify_evidence(const std::filesystem::path& manifest_path);

// Environment record for logs.
struct EnvRecord {
    std::string date_utc;
    std::string host;
    std::string kernel;
    int nproc = 0;
    long mem_total_kib = 0;
    std::string disk;
    std::string compiler;
    std::string make;
    std::string engine_sha256;
    std::string test_sha256;
    std::string fixture_manifest_sha256;
};

EnvRecord capture_env_record();
EnvRecord capture_env_record(const std::filesystem::path& root);

} // namespace marp::harness
