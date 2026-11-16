// MARP v2 — H4 FUZZ — evidence rendering and writing.
//
// The evidence is *written by the harness*, never typed: gate rows, counters,
// seed identities, the manifest and the SHA-256 list are all functions of the
// measured campaign.  Nothing in the committed set depends on the clock, the
// host, the locale, the worker scheduling or the path the binary was run from,
// so a CI re-run must reproduce it byte-for-byte.
#pragma once

#include <cstdint>
#include <filesystem>
#include <string>

#include "h4_seeds.hpp"
#include "marp/harness/h4_fuzz.hpp"

namespace marp::harness::h4 {

struct EvidenceInput {
    const Prereq* prereq = nullptr;
    const SeedBuild* seeds = nullptr;
    const FuzzReport* campaign = nullptr;
    const FuzzReport* workers_one = nullptr;
    const FuzzReport* workers_many = nullptr;
    const FuzzConfig* config = nullptr;
    std::uint64_t dry_mutants = 0;
    bool determinism_equal = false;
    bool alloc_guard_enabled = false;
    std::string seed_dir;  // recorded path (regenerable artifact)
};

struct EvidenceText {
    std::string gate_tsv;
    std::string log;
    std::string counts_tsv;
    std::string seeds_tsv;
};

// Pure rendering: the same measurements always produce the same text.  This is
// what the in-process self-test compares to prove the renderer is deterministic.
EvidenceText render_evidence(const EvidenceInput& input);

// Writes gate/log/counts/seeds, then MANIFEST.tsv and SHA256SUMS over them and
// over the prerequisite inputs, then verifies the written SHA-256 list.
bool write_evidence(const std::filesystem::path& root, const EvidenceInput& input,
                    std::string& why);

// Verifies a sha256sum-compatible manifest produced by this harness.
bool verify_sums(const std::filesystem::path& sums_path, const std::filesystem::path& root,
                 std::string& why);

}  // namespace marp::harness::h4
