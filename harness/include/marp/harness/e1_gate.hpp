#pragma once
#include "gates.hpp"
#include "e1_terms.hpp"
#include <mapr/e1_bigint.hpp>
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace marp::harness {

// Fixed corpus seeds. Never derived from time, PID, address, or environment.
inline constexpr uint64_t E1_CORPUS_SEED = 0x4D415250ull; // "MARP"
inline constexpr size_t E1_TERM_COUNT = 2000;
inline constexpr size_t E1_ARITH_PAIRS = 10000;
inline constexpr size_t E1_BYTES_COUNT = 512;
inline constexpr size_t E1_KAT_MESSAGE_COUNT = 12;

// One row of the harness-written corpus.tsv.
struct CorpusItem {
    std::string corpus_id;        // A-EDGE, A-BITS, A-RAND, A-ARITH, S-DEC,
                                  // S-BYTES, T-LEN, D-KAT
    std::string item_id;          // unique within the corpus
    std::string description;      // canonical description
    std::string description_sha256;
    uint64_t seed = 0;
    int bit_length = 0;
    bool parse_ok = true;
};

// In-memory corpus. The gate measures these payloads directly; it never
// reconstructs an operand from free-form text in the TSV.
struct E1Corpus {
    std::vector<mapr::BigInt> a_edge;
    std::vector<mapr::BigInt> a_bits;
    std::vector<mapr::BigInt> a_rand;
    std::vector<std::pair<mapr::BigInt, mapr::BigInt>> a_arith;
    std::vector<std::string> s_dec;

    struct BytesItem {
        std::vector<uint8_t> raw;      // little-endian bytes as fed to from_le_bytes
        std::vector<uint8_t> trimmed;  // canonical magnitude (trailing zeros removed)
        std::string item_id;
        std::string description;
        std::string description_sha256;
        int bit_length = 0;
    };
    std::vector<BytesItem> s_bytes;

    std::vector<TermSet> t_len;
    std::vector<std::string> kat_messages;

    // Every corpus.tsv row, in stable generation order.
    std::vector<CorpusItem> items;
};

// The twelve digest KAT messages (empty, "abc", 55/56/57/63/64/65/127/128-byte
// boundaries, the quick-brown-fox sentence, and one 1 MiB message).
std::vector<std::string> e1_kat_messages();

// Deterministically build the whole E1 corpus.
E1Corpus build_e1_corpus();

// Write corpus.tsv atomically. Returns false on I/O failure.
bool write_corpus(const E1Corpus& corpus, const std::filesystem::path& path);

// Read corpus.tsv rows back (metadata only).
std::vector<CorpusItem> read_corpus(const std::filesystem::path& path);

// Result of one measurement pass.
struct Measurement {
    std::vector<EvidenceRow> rows;
    std::vector<std::string> log;
    bool blocked = false;
};

// Run every E1 measurement check except the cross-thread comparison and the
// evidence-manifest check (both owned by run_e1_gate). `threads` controls the
// real worker pool; rows and log lines are independent of the thread count.
Measurement measure_e1(const E1Corpus& corpus, int threads);

// Full E1-G entry point. Returns 0 only on PASS. `command_line` is recorded in
// the log so the evidence names the exact invocation that produced it.
int run_e1_gate(const std::filesystem::path& root, int threads = 1,
                std::string_view command_line = {});

} // namespace marp::harness
