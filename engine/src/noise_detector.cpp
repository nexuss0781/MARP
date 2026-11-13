// =====================================================================
//  MARP  ::  Stage 2  ::  Noise Detector  ::  noise_detector.cpp
// =====================================================================

#include "mapr/noise_detector.hpp"
#include "mapr/bitseq.hpp"
#include <cmath>
#include <unordered_map>
#include <algorithm>

namespace mapr {

NoiseProfile analyze_noise(const BitSeq& seq) {
    NoiseProfile prof;
    uint64_t n = seq.bit_len();
    if (n == 0) return prof;
    
    // Order-0 entropy (byte-level)
    uint64_t byte_count = n / 8;
    if (byte_count > 0) {
        uint32_t freq[256] = {0};
        for (size_t i = 0; i < byte_count; ++i) {
            uint8_t b = static_cast<uint8_t>(seq.get_bits64(i * 8, 8));
            freq[b]++;
        }
        double h0 = 0.0;
        for (int i = 0; i < 256; ++i) {
            if (freq[i] > 0) {
                double p = static_cast<double>(freq[i]) / byte_count;
                h0 -= p * std::log2(p);
            }
        }
        prof.entropy_order0 = h0;  // bits per byte
    }
    
    // Order-1 entropy (simple bigram)
    if (byte_count > 1) {
        uint32_t bigram[256][256] = {{0}};
        uint8_t prev = static_cast<uint8_t>(seq.get_bits64(0, 8));
        for (size_t i = 1; i < byte_count; ++i) {
            uint8_t curr = static_cast<uint8_t>(seq.get_bits64(i * 8, 8));
            bigram[prev][curr]++;
            prev = curr;
        }
        double h1 = 0.0;
        double total_bigrams = byte_count - 1;
        for (int i = 0; i < 256; ++i) {
            for (int j = 0; j < 256; ++j) {
                if (bigram[i][j] > 0) {
                    double p = static_cast<double>(bigram[i][j]) / total_bigrams;
                    h1 -= p * std::log2(p);
                }
            }
        }
        prof.entropy_order1 = h1;  // bits per byte
    }
    
    // LZ-style match ratio (sample)
    size_t sample_words = std::min<size_t>(seq.word_count(), 16384);
    if (sample_words >= 32) {
        std::unordered_map<uint64_t, uint32_t> seen;
        seen.reserve(sample_words * 2);
        uint32_t matches = 0;
        for (size_t i = 0; i < sample_words; ++i) {
            uint64_t w = seq.word(i);
            if (seen.count(w)) matches++;
            seen[w] = 1;
        }
        prof.lz_match_ratio = static_cast<double>(matches) / sample_words;
    }
    
    // Estimate compressed ratio
    // If entropy is high (near 8) and few LZ matches, it's noise
    double entropy_factor = prof.entropy_order0 / 8.0;
    double lz_factor = 1.0 - prof.lz_match_ratio * 0.5;
    prof.estimated_compressed_ratio = entropy_factor * lz_factor;
    
    // Decision threshold: if estimated ratio >= 1.0, it's noise
    prof.is_noise = (prof.estimated_compressed_ratio >= 0.995);
    
    return prof;
}

bool should_use_raw(const BitSeq& seq) {
    return analyze_noise(seq).is_noise;
}

} // namespace mapr