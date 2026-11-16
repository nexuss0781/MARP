// MARP v2 — H4 FUZZ — E3-G prerequisite and seed provenance.
//
// §12.8 permits only valid containers as seeds.  H4 takes them from E3-G:
// every seed is C07's `encode` of an E2-canonical `T-KAT`/edge term of the
// E3-G corpus, and it is admitted only if its byte count *and* SHA-256 equal
// the identity E3-G committed in `specs_and_reports/v2/corpus/E3/corpus.tsv`.
// The committed E3-G gate evidence is re-checked as a prerequisite: H4 may not
// claim a campaign over seeds whose provenance gate is missing, failed, or
// blocked.
#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

#include "marp/harness/h4_fuzz.hpp"

namespace marp::harness::h4 {

struct Prereq {
    bool ok = false;
    std::string failure;
    std::string gate_path;
    std::string gate_sha256;
    std::string corpus_path;
    std::string corpus_sha256;
    std::string counts_path;
    std::string counts_sha256;
    std::string gate_verdict;
    std::size_t gate_rows = 0;
    std::size_t gate_fail = 0;
    std::size_t gate_blocked = 0;
    std::size_t corpus_items = 0;
    std::uint64_t e3_mutants = 0;
};

Prereq check_prerequisite(const std::filesystem::path& root);

struct SeedBuild {
    bool ok = false;
    std::string failure;
    std::vector<SeedInfo> seeds;
    std::vector<std::string> note;
};

SeedBuild build_seeds(const std::filesystem::path& root);

bool write_seed_dir(const std::filesystem::path& dir, const std::vector<SeedInfo>& seeds,
                    std::string& why);

std::string seeds_manifest(const std::vector<SeedInfo>& seeds);
std::string seeds_sha256_set(const std::vector<SeedInfo>& seeds);

// sha256sum-compatible line: "<digest>  <path>".
std::string sha256sum_line(const std::filesystem::path& path,
                           const std::filesystem::path& relative_to);

}  // namespace marp::harness::h4
