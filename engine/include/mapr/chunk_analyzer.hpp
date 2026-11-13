#pragma once

#include "mapr/bitseq.hpp"
#include "mapr/profile.hpp"
#include <cstdint>
#include <vector>
#include <array>

namespace mapr {

// ──────────────────────────────────────────────────────────────
// Chunk Feature Extraction
// ──────────────────────────────────────────────────────────────

struct ChunkFeatures {
    // Entropy measures
    double bit_entropy = 0.0;           // Shannon entropy per bit [0,1]
    double byte_entropy = 0.0;          // Shannon entropy per byte [0,8]
    double word_entropy = 0.0;          // Shannon entropy per 64-bit word [0,64]

    // Periodicity
    uint64_t exact_period = 0;          // Exact period if detected, 0 = none
    bool has_exact_period = false;
    uint64_t approx_period = 0;         // Approximate period
    double period_strength = 0.0;       // 0-1 confidence

    // Subword complexity
    size_t unique_64bit_words = 0;      // Number of unique 64-bit words
    double subword_complexity = 0.0;    // unique_words / total_words [0,1]

    // Self-similarity
    double autocorr_1 = 0.0;            // Autocorrelation at lag 1
    double autocorr_8 = 0.0;            // Autocorrelation at lag 8 (byte)
    double autocorr_64 = 0.0;           // Autocorrelation at lag 64 (word)

    // Sparsity
    double density = 0.0;               // Fraction of 1 bits [0,1]
    double run_length_avg = 0.0;        // Average run length
    double run_length_max = 0.0;        // Maximum run length

    // Structural hints
    bool looks_like_text = false;       // High byte entropy, low bit entropy
    bool looks_like_code = false;       // Repetitive patterns, low entropy
    bool looks_like_image = false;      // 2D correlation patterns
    bool looks_like_compressed = false; // High entropy, no patterns
};

// ──────────────────────────────────────────────────────────────
// Chunk Feature Extraction
// ──────────────────────────────────────────────────────────────

ChunkFeatures analyze_chunk(const BitSeq& chunk, const EncodeConfig& config);

// ──────────────────────────────────────────────────────────────
// Encoding Strategy Selection
// ──────────────────────────────────────────────────────────────

enum class EncodeStrategy : uint8_t {
    REPEAT_NODE      = 0,  // Exact repetition -> RepeatNode
    LFSR             = 1,  // LFSR sequence -> LfsrNode
    INTERLEAVE       = 2,  // Bit-plane decomposition -> InterleaveNode
    MORPHIC_WORD     = 3,  // V4 morphic word recompression
    CHUNK_REF        = 4,  // Cross-chunk reference -> CHUNK_REF
    XOR_DIFF         = 5,  // Sparse XOR difference -> XorDiffNode
    MORPHIC_LIFT     = 6,  // V4 morphic lifting
    MINIMIZER_ANCHOR = 7,  // Minimizer anchor + V4 + Slice
    ATOM_SPAN        = 8,  // Fallback: atom span encoding
};

struct StrategyDecision {
    EncodeStrategy strategy = EncodeStrategy::ATOM_SPAN;
    double confidence = 0.0;           // 0-1 confidence in strategy
    std::vector<EncodeStrategy> fallbacks; // Ordered fallback strategies
    // Strategy-specific parameters
    uint64_t repeat_period = 0;
    uint64_t lfsr_degree = 0;
    int interleave_planes = 0;
    // ... add more as needed
};

StrategyDecision select_strategy(const ChunkFeatures& features, const EncodeConfig& config);

} // namespace mapr