#include "mapr/chunk_analyzer.hpp"
#include "mapr/bitseq.hpp"
#include "mapr/simd/encoder_kernels.hpp"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <unordered_map>

namespace mapr {

// ──────────────────────────────────────────────────────────────
// Helper: Entropy Calculation
// ──────────────────────────────────────────────────────────────

static double shannon_entropy(const double* probs, size_t n) {
    double h = 0.0;
    for (size_t i = 0; i < n; ++i) {
        if (probs[i] > 0.0) {
            h -= probs[i] * std::log2(probs[i]);
        }
    }
    return h;
}

static void compute_bit_entropy(const BitSeq& seq, double& bit_entropy, double& density) {
    uint64_t ones = 0;
    uint64_t n = seq.bit_len();
    if (n == 0) {
        bit_entropy = 0.0;
        density = 0.0;
        return;
    }
    // Count ones
    for (uint64_t w : seq.words()) {
        ones += simd::popcount64(w);
    }
    density = static_cast<double>(ones) / static_cast<double>(n);
    double p0 = 1.0 - density;
    double p1 = density;
    if (p0 > 0 && p1 > 0) {
        bit_entropy = -p0 * std::log2(p0) - p1 * std::log2(p1);
    } else {
        bit_entropy = 0.0;
    }
}

static void compute_word_entropy(const BitSeq& seq, double& word_entropy, size_t& unique_words) {
    size_t n_words = seq.word_count();
    if (n_words == 0) {
        word_entropy = 0.0;
        unique_words = 0;
        return;
    }
    std::unordered_map<uint64_t, uint32_t> counts;
    counts.reserve(n_words * 2);
    for (uint64_t w : seq.words()) {
        counts[w]++;
    }
    unique_words = counts.size();
    double h = 0.0;
    for (const auto& kv : counts) {
        double p = static_cast<double>(kv.second) / static_cast<double>(n_words);
        h -= p * std::log2(p);
    }
    word_entropy = h;
}

static void compute_byte_entropy(const BitSeq& seq, double& byte_entropy) {
    // Only if byte-aligned
    if ((seq.bit_len() & 7ULL) != 0ULL) {
        byte_entropy = 0.0;
        return;
    }
    std::unordered_map<uint8_t, uint32_t> counts;
    counts.reserve(256);
    auto bytes = seq.to_bytes_msb();
    for (uint8_t b : bytes) {
        counts[b]++;
    }
    size_t n = bytes.size();
    double h = 0.0;
    for (const auto& kv : counts) {
        double p = static_cast<double>(kv.second) / static_cast<double>(n);
        h -= p * std::log2(p);
    }
    byte_entropy = h;
}

// ──────────────────────────────────────────────────────────────
// Periodicity Detection (simplified)
// ──────────────────────────────────────────────────────────────

static uint64_t detect_period(const BitSeq& seq, uint64_t max_period) {
    uint64_t n = seq.bit_len();
    if (n < 16) return 0;

    // Quick check: word-level periodicity
    size_t n_words = seq.word_count();
    if (n_words >= 4) {
        // Simple prefix function for word-level KMP
        std::vector<size_t> pi(n_words, 0);
        for (size_t i = 1; i < n_words; ++i) {
            size_t j = pi[i - 1];
            while (j > 0 && seq.word(j) != seq.word(i)) {
                j = pi[j - 1];
            }
            if (seq.word(j) == seq.word(i)) ++j;
            pi[i] = j;
        }
        size_t p = n_words - pi[n_words - 1];
        if (p > 0 && p <= (max_period >> 6) && (n_words / p) >= 2) {
            // Verify full sequence
            bool ok = true;
            for (size_t i = p; i < n_words; ++i) {
                if (seq.word(i) != seq.word(i - p)) { ok = false; break; }
            }
            if (ok) return p * 64ULL;
        }
    }
    return 0;
}

// ──────────────────────────────────────────────────────────────
// Autocorrelation
// ──────────────────────────────────────────────────────────────

static double autocorr_at_lag(const BitSeq& seq, uint64_t lag) {
    uint64_t n = seq.bit_len();
    if (lag >= n) return 0.0;
    uint64_t matches = 0;
    uint64_t total = n - lag;
    for (uint64_t i = 0; i < total; ++i) {
        if (seq.get_bit(i) == seq.get_bit(i + lag)) ++matches;
    }
    return static_cast<double>(matches) / static_cast<double>(total);
}

// ──────────────────────────────────────────────────────────────
// Run Length Statistics
// ──────────────────────────────────────────────────────────────

static void compute_run_stats(const BitSeq& seq, double& avg_run, double& max_run) {
    uint64_t n = seq.bit_len();
    if (n == 0) { avg_run = 0; max_run = 0; return; }
    uint64_t runs = 1;
    uint64_t max_len = 1;
    uint64_t cur_len = 1;
    uint8_t prev = seq.get_bit(0);
    for (uint64_t i = 1; i < n; ++i) {
        uint8_t cur = seq.get_bit(i);
        if (cur == prev) {
            ++cur_len;
            if (cur_len > max_len) max_len = cur_len;
        } else {
            ++runs;
            cur_len = 1;
            prev = cur;
        }
    }
    avg_run = static_cast<double>(n) / static_cast<double>(runs);
    max_run = static_cast<double>(max_len);
}

// ──────────────────────────────────────────────────────────────
// Main Analysis Function
// ──────────────────────────────────────────────────────────────

ChunkFeatures analyze_chunk(const BitSeq& chunk, const EncodeConfig& config) {
    ChunkFeatures f{};

    // Basic entropy and density
    compute_bit_entropy(chunk, f.bit_entropy, f.density);
    compute_word_entropy(chunk, f.word_entropy, f.unique_64bit_words);
    compute_byte_entropy(chunk, f.byte_entropy);

    // Subword complexity
    size_t n_words = chunk.word_count();
    if (n_words > 0) {
        f.subword_complexity = static_cast<double>(f.unique_64bit_words) / static_cast<double>(n_words);
    }

    // Periodicity
    if (config.enable_periodicity) {
        f.exact_period = detect_period(chunk, config.max_period);
        f.has_exact_period = (f.exact_period > 0);
    }

    // Autocorrelation
    f.autocorr_1 = autocorr_at_lag(chunk, 1);
    f.autocorr_8 = autocorr_at_lag(chunk, 8);
    f.autocorr_64 = autocorr_at_lag(chunk, 64);

    // Run statistics
    compute_run_stats(chunk, f.run_length_avg, f.run_length_max);

    // Structural hints
    f.looks_like_text = (f.byte_entropy > 5.5 && f.bit_entropy < 0.9);
    f.looks_like_code = (f.subword_complexity < 0.3 && f.autocorr_64 > 0.5);
    f.looks_like_compressed = (f.bit_entropy > 0.99 && f.byte_entropy > 7.5);
    f.looks_like_image = (f.autocorr_8 > 0.7 && f.autocorr_64 > 0.3);

    return f;
}

// ──────────────────────────────────────────────────────────────
// Strategy Selection
// ──────────────────────────────────────────────────────────────

StrategyDecision select_strategy(const ChunkFeatures& f, const EncodeConfig& config) {
    StrategyDecision d{};
    d.confidence = 0.0;

    // Priority 1: Exact repetition (highest compression)
    if (f.has_exact_period && (f.exact_period * 2 <= f.exact_period * (1 + (f.exact_period > 0)))) {
        d.strategy = EncodeStrategy::REPEAT_NODE;
        d.confidence = 0.95;
        d.repeat_period = f.exact_period;
        d.fallbacks = {EncodeStrategy::MORPHIC_WORD, EncodeStrategy::MINIMIZER_ANCHOR};
        return d;
    }

    // Priority 2: LFSR sequence
    if (config.enable_lfsr_detection && f.bit_entropy < 0.5 && f.autocorr_1 > 0.9) {
        d.strategy = EncodeStrategy::LFSR;
        d.confidence = 0.8;
        d.fallbacks = {EncodeStrategy::MORPHIC_WORD, EncodeStrategy::MINIMIZER_ANCHOR};
        return d;
    }

    // Priority 3: Interleave (bit-plane decomposition)
    if (config.enable_interleave && f.looks_like_image && f.autocorr_8 > 0.7) {
        d.strategy = EncodeStrategy::INTERLEAVE;
        d.confidence = 0.75;
        d.interleave_planes = 8; // default
        d.fallbacks = {EncodeStrategy::MORPHIC_WORD, EncodeStrategy::MINIMIZER_ANCHOR};
        return d;
    }

    // Priority 4: Morphic word recompression (low subword complexity)
    if (f.subword_complexity < 0.15 || f.word_entropy < 20.0) {
        d.strategy = EncodeStrategy::MORPHIC_WORD;
        d.confidence = 0.7;
        d.fallbacks = {EncodeStrategy::MINIMIZER_ANCHOR, EncodeStrategy::ATOM_SPAN};
        return d;
    }

    // Priority 5: CHUNK_REF (cross-chunk reference) - handled at pipeline level
    // Priority 6: XOR_DIFF (sparse differences)
    if (config.enable_xor_diff && f.density > 0.4 && f.density < 0.6 && f.autocorr_64 > 0.8) {
        d.strategy = EncodeStrategy::XOR_DIFF;
        d.confidence = 0.65;
        d.fallbacks = {EncodeStrategy::MINIMIZER_ANCHOR, EncodeStrategy::ATOM_SPAN};
        return d;
    }

    // Priority 7: Morphic lifting (V4)
    if (config.enable_morphic_lifting && f.autocorr_64 > 0.5) {
        d.strategy = EncodeStrategy::MORPHIC_LIFT;
        d.confidence = 0.6;
        d.fallbacks = {EncodeStrategy::MINIMIZER_ANCHOR, EncodeStrategy::ATOM_SPAN};
        return d;
    }

    // Priority 8: Minimizer anchor (general case)
    d.strategy = EncodeStrategy::MINIMIZER_ANCHOR;
    d.confidence = 0.5;
    d.fallbacks = {EncodeStrategy::ATOM_SPAN};

    // Ultimate fallback
    if (d.confidence < 0.3) {
        d.strategy = EncodeStrategy::ATOM_SPAN;
        d.confidence = 0.1;
    }

    return d;
}

} // namespace mapr