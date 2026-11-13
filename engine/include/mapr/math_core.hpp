#pragma once

#include "mapr/bitseq.hpp"
#include "mapr/common.hpp"
#include <array>
#include <cstdint>
#include <optional>
#include <utility>
#include <vector>

namespace mapr {

struct DualBasisAtom {
    AtomBasis beta = AtomBasis::POS;
    uint8_t b = 64;   // 1 <= b <= 64
    uint8_t w = 0;    // 0 <= w <= b
    uint64_t rho = 0; // 0 <= rho < C(b, w)

    bool operator==(const DualBasisAtom& o) const noexcept {
        return beta == o.beta && b == o.b && w == o.w && rho == o.rho;
    }
};

// Exact 64-bit Pascal binomial table C[b][w] for 0 <= w <= b <= 64
const std::array<std::array<uint64_t, 65>, 65>& pascal_table() noexcept;

inline uint64_t binom64(int b, int w) noexcept {
    if (w < 0 || w > b || b > 64) return 0ULL;
    return pascal_table()[static_cast<size_t>(b)][static_cast<size_t>(w)];
}

int shell_bit_cost(int b, int w) noexcept;

// Colexicographic rank & unrank on {0,1}^b (1 <= b <= 64)
std::pair<uint8_t, uint64_t> rank_word_colex(uint64_t word, int b) noexcept;
uint64_t unrank_word_colex(int b, int w, uint64_t rho);

// Self-inverse GF(2) Möbius / Zhegalkin transform M_k for b in {1, 2, 4, 8, 16, 32, 64}
uint64_t mobius_word(uint64_t x, int b);

// Dual-Basis Micro-Atom synthesis & exact reconstruction
DualBasisAtom encode_micro_atom(uint64_t word, int b);
uint64_t decode_micro_atom(const DualBasisAtom& atom);

// Klein 4-Group word action & canonicalization
uint64_t apply_v4_word(uint64_t word, int b, V4Op op) noexcept;
std::pair<uint64_t, V4Op> canonical_v4_word(uint64_t word, int b) noexcept;

// 8x8 SWAR bit-plane transpose & stride s in {8, 16, 32, 64} interleave/deinterleave
uint64_t transpose8x8_swar(uint64_t x) noexcept;
std::vector<BitSeq> deinterleave_bitplanes(const BitSeq& seq, int stride);
BitSeq interleave_bitplanes(const std::vector<BitSeq>& lanes, int stride);

// Berlekamp-Massey GF(2) minimal polynomial synthesis (1 <= L <= 64, using __uint128_t) & fast evaluator
struct LfsrSpec {
    uint8_t degree;
    uint64_t conn_mask;
    uint64_t init_mask;
    uint64_t length;
};

std::optional<std::pair<uint8_t, uint64_t>> berlekamp_massey_gf2(
    const uint8_t* bits, size_t n, int max_degree = 64) noexcept;

BitSeq evaluate_lfsr(int degree, uint64_t conn_mask, uint64_t init_mask, uint64_t length);

std::optional<LfsrSpec> verify_and_measure_lfsr(
    const BitSeq& seq, int max_degree = 64, size_t sample_prefix = 256);

} // namespace mapr
