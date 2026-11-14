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

// Write a single row to a TSV file atomically (via temp + rename).
// Returns true on success.
bool write_row(const std::filesystem::path& tsv_path, const Row& row);

// Run a gate by ID (E0-G or E1-G). Returns 0 on PASS, nonzero on FAIL/BLOCKED.
int run_gate(std::string_view gate_id, const std::filesystem::path& root);

// Render ACCEPTANCE.md from TSV files in tsv_dir.
// Returns 0 on success, nonzero on failure.
int render(const std::filesystem::path& tsv_dir, const std::filesystem::path& out);

// Verify evidence manifest (SHA256SUMS). Returns 0 if all match, nonzero on mismatch.
int verify_evidence(const std::filesystem::path& manifest_path);

// Environment record for logs
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

} // namespace marp::harness