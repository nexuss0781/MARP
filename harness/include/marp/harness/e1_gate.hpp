#pragma once
#include "gates.hpp"
#include <string>
#include <filesystem>

namespace marp::harness {

// E1-G gate entry point
// Runs all E1 checks against the independent oracle.
// Returns 0 on PASS (all rows PASS), nonzero on FAIL/BLOCKED.
int run_e1_gate(const std::filesystem::path& root, int threads = 1);

// Corpus generation for E1-G
// Generates deterministic corpus and writes corpus.tsv.
// Returns 0 on success.
int generate_e1_corpus(const std::filesystem::path& root);

// Corpus item for deterministic generation
struct CorpusItem {
    std::string corpus_id;      // A-EDGE, A-BITS, A-RAND, A-ARITH, S-DEC, S-BYTES, T-LEN, D-KAT
    std::string item_id;        // Unique identifier within corpus
    std::string description;    // Canonical description
    int bit_length = 0;
    std::string description_sha256;
    uint64_t seed = 0;
};

// Read corpus from TSV
std::vector<CorpusItem> read_corpus(const std::filesystem::path& corpus_tsv);

} // namespace marp::harness