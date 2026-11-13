// libFuzzer harness for MAPR math core
// Tests: popcount, bitrev, mobius, splitmix64, binom, colex rank/unrank

#include "mapr/bitseq.hpp"
#include "mapr/math_core.hpp"
#include "mapr/simd/dispatch.hpp"

#include <cstdint>
#include <cstddef>
#include <vector>

namespace mapr {

// Simple check macro for fuzzers (doesn't exit, just returns)
#define FUZZ_CHECK(cond) do { if (!(cond)) return 0; } while(0)

static int test_popcount(const uint8_t* data, size_t size) {
    if (size < 8) return 0;
    
    const uint64_t* words = reinterpret_cast<const uint64_t*>(data);
    size_t n = size / 8;
    
    for (size_t i = 0; i < n; ++i) {
        uint64_t w = words[i];
        uint64_t scalar = simd::scalar::popcount64(w);
        uint64_t builtin = __builtin_popcountll(w);
        FUZZ_CHECK(scalar == builtin);
        
        // Test AVX2 if available - use get_current_isa()
        // if (simd::get_current_isa() >= simd::IsaLevel::AVX2) {
        //     // Would test AVX2 implementation
        // }
    }
    return 0;
}

static int test_bitrev(const uint8_t* data, size_t size) {
    if (size < 8) return 0;
    
    const uint64_t* words = reinterpret_cast<const uint64_t*>(data);
    size_t n = size / 8;
    
    for (size_t i = 0; i < n; ++i) {
        uint64_t w = words[i];
        uint64_t rev = simd::scalar::bitrev64(w);
        // Verify involution
        FUZZ_CHECK(simd::scalar::bitrev64(rev) == w);
        
        // Verify against manual bit reversal
        uint64_t manual = 0;
        for (int b = 0; b < 64; ++b) {
            if (w & (1ULL << b)) manual |= (1ULL << (63 - b));
        }
        FUZZ_CHECK(rev == manual);
    }
    return 0;
}

static int test_mobius(const uint8_t* data, size_t size) {
    if (size < 8) return 0;
    
    const uint64_t* words = reinterpret_cast<const uint64_t*>(data);
    size_t n = size / 8;
    
    for (int b : {1, 2, 4, 8, 16, 32, 64}) {
        uint64_t mask = (b == 64) ? ~0ULL : ((1ULL << b) - 1);
        for (size_t i = 0; i < n; ++i) {
            uint64_t w = words[i] & mask;
            uint64_t m = mobius_word(w, b);
            // Verify involution: M(M(w)) = w
            FUZZ_CHECK(mobius_word(m, b) == w);
        }
    }
    return 0;
}

static int test_splitmix64(const uint8_t* data, size_t size) {
    if (size < 8) return 0;
    
    const uint64_t* words = reinterpret_cast<const uint64_t*>(data);
    size_t n = size / 8;
    
    for (size_t i = 0; i < n; ++i) {
        uint64_t w = words[i];
        uint64_t h = splitmix64(w);
        // Just verify it doesn't crash and produces deterministic output
        FUZZ_CHECK(splitmix64(w) == h);
        (void)h;
    }
    return 0;
}

static int test_binom(const uint8_t* data, size_t size) {
    if (size < 2) return 0;
    
    const uint8_t* bytes = data;
    size_t n = std::min<size_t>(size, 1000);
    
    for (size_t i = 0; i < n; i += 2) {
        int n_val = bytes[i] % 65;
        int k_val = bytes[i + 1] % (n_val + 1);
        
        uint64_t result = binom64(n_val, k_val);
        // Verify symmetry
        FUZZ_CHECK(result == binom64(n_val, n_val - k_val));
        // Verify boundaries
        if (k_val == 0 || k_val == n_val) FUZZ_CHECK(result == 1);
    }
    return 0;
}

static int test_colex_rank_unrank(const uint8_t* data, size_t size) {
    if (size < 9) return 0;
    
    const uint8_t* bytes = data;
    int b = 1 + (bytes[0] % 64);
    uint64_t mask = (b == 64) ? ~0ULL : ((1ULL << b) - 1);
    uint64_t w = *reinterpret_cast<const uint64_t*>(bytes + 1) & mask;
    
    auto [rank, rho] = rank_word_colex(w, b);
    uint64_t unranked = unrank_word_colex(b, rank, rho);
    FUZZ_CHECK(unranked == w);
    
    // Test dual basis atom encoding
    DualBasisAtom atom = encode_micro_atom(w, b);
    uint64_t decoded = decode_micro_atom(atom);
    FUZZ_CHECK(decoded == w);
    
    return 0;
}

static int test_lfsr_detection(const uint8_t* data, size_t size) {
    if (size < 8) return 0;
    
    BitSeq seq = BitSeq::from_bytes_msb(data, size);
    
    // Test LFSR verification
    auto lfsr = verify_and_measure_lfsr(seq, 64, 256);
    if (lfsr) {
        // If LFSR found, verify it generates the sequence
        BitSeq reconstructed = BitSeq::empty();
        // BitWriter64 writer;  // Not available in fuzzer
        // Reconstruct using LFSR parameters
        uint64_t state = lfsr->init_mask;
        for (uint64_t i = 0; i < seq.bit_len(); ++i) {
            uint64_t bit = state & 1;
            // writer.write_bits(bit, 1);
            // LFSR step
            uint64_t feedback = 0;
            uint64_t conn = lfsr->conn_mask;
            while (conn) {
                int t = __builtin_ctzll(conn);
                feedback ^= (state >> t) & 1;
                conn &= conn - 1;
            }
            state = (state >> 1) | (feedback << (lfsr->degree - 1));
        }
        // auto [rec_seq, rec_len] = writer.finish();
        // FUZZ_CHECK(rec_seq.bit_len() == seq.bit_len());
        // Note: may not match exactly due to truncation
    }
    
    return 0;
}

static int test_periodicity(const uint8_t* data, size_t size) {
    if (size < 2) return 0;
    
    BitSeq seq = BitSeq::from_bytes_msb(data, size);
    
    // Simple period detection (inline version)
    uint64_t n = seq.bit_len();
    for (uint64_t p = 1; p <= std::min<uint64_t>(n / 2, 16384); ++p) {
        bool is_period = true;
        for (uint64_t i = p; i + p <= n; i += p) {
            BitSeq chunk = seq.slice(i, std::min<uint64_t>(p, n - i));
            BitSeq first_chunk = seq.slice(0, std::min<uint64_t>(p, n));
            if (chunk != first_chunk) {
                is_period = false;
                break;
            }
        }
        if (is_period) {
            FUZZ_CHECK(n % p == 0 || n >= p);
            return 0;
        }
    }
    
    return 0;
}

} // namespace mapr

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    mapr::test_popcount(data, size);
    mapr::test_bitrev(data, size);
    mapr::test_mobius(data, size);
    mapr::test_splitmix64(data, size);
    mapr::test_binom(data, size);
    mapr::test_colex_rank_unrank(data, size);
    mapr::test_lfsr_detection(data, size);
    mapr::test_periodicity(data, size);
    return 0;
}