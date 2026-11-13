#include "mapr/math_core.hpp"
#include <bit>
#include <stdexcept>

namespace mapr {

const std::array<std::array<uint64_t, 65>, 65>& pascal_table() noexcept {
    static const auto tab = []() {
        std::array<std::array<uint64_t, 65>, 65> t{};
        for (size_t n = 0; n <= 64; ++n) {
            t[n][0] = 1ULL;
            t[n][n] = 1ULL;
            for (size_t k = 1; k < n; ++k) {
                t[n][k] = t[n - 1][k - 1] + t[n - 1][k];
            }
        }
        return t;
    }();
    return tab;
}

int shell_bit_cost(int b, int w) noexcept {
    uint64_t c = binom64(b, w);
    int ord_bits = (c <= 1ULL) ? 0 : static_cast<int>(std::bit_width(c - 1ULL));
    int hdr_bits = (b == 64 ? 1 : 7) + (is_dyadic_atom_len(b) ? 1 : 0) +
                   static_cast<int>(std::bit_width(static_cast<uint64_t>(b)));
    return hdr_bits + ord_bits;
}

std::pair<uint8_t, uint64_t> rank_word_colex(uint64_t word, int b) noexcept {
    word &= low_mask(b);
    uint64_t rho = 0ULL;
    uint8_t t = 0;
    const auto& C = pascal_table();
    uint64_t temp = word;
    while (temp != 0ULL) {
        int i_t = std::countr_zero(temp);
        ++t;
        rho += C[static_cast<size_t>(i_t)][static_cast<size_t>(t)];
        temp &= (temp - 1ULL);
    }
    return {t, rho};
}

uint64_t unrank_word_colex(int b, int w, uint64_t rho) {
    if (b < 1 || b > 64) throw std::invalid_argument("unrank b out of [1,64]");
    if (w < 0 || w > b) throw std::invalid_argument("unrank w out of [0,b]");
    const auto& C = pascal_table();
    if (rho >= C[static_cast<size_t>(b)][static_cast<size_t>(w)]) {
        throw std::invalid_argument("unrank rho >= C(b,w)");
    }
    if (w == 0) return 0ULL;
    if (w == b) return low_mask(b);

    uint64_t word = 0ULL;
    uint64_t rem = rho;
    int upper = b - 1;
    for (int t = w; t >= 1; --t) {
        int lo = t - 1;
        int hi = upper;
        int best = lo;
        while (lo <= hi) {
            int mid = (lo + hi) >> 1;
            uint64_t cm = C[static_cast<size_t>(mid)][static_cast<size_t>(t)];
            if (cm <= rem) {
                best = mid;
                lo = mid + 1;
            } else {
                hi = mid - 1;
            }
        }
        word |= (1ULL << best);
        rem -= C[static_cast<size_t>(best)][static_cast<size_t>(t)];
        upper = best - 1;
    }
    return word;
}

uint64_t mobius_word(uint64_t x, int b) {
    if (!is_dyadic_atom_len(b)) throw std::invalid_argument("mobius_word requires dyadic b");
    x &= low_mask(b);
    if (b >= 2)  x ^= (x & 0x5555555555555555ULL) << 1;
    if (b >= 4)  x ^= (x & 0x3333333333333333ULL) << 2;
    if (b >= 8)  x ^= (x & 0x0F0F0F0F0F0F0F0FULL) << 4;
    if (b >= 16) x ^= (x & 0x00FF00FF00FF00FFULL) << 8;
    if (b >= 32) x ^= (x & 0x0000FFFF0000FFFFULL) << 16;
    if (b == 64) x ^= (x & 0x00000000FFFFFFFFULL) << 32;
    return x & low_mask(b);
}

DualBasisAtom encode_micro_atom(uint64_t word, int b) {
    word &= low_mask(b);
    auto [w_pos, rho_pos] = rank_word_colex(word, b);

    if (b == 4 || b == 8 || b == 16 || b == 32 || b == 64) {
        uint64_t z_word = mobius_word(word, b);
        int w_zh = std::popcount(z_word);
        if (binom64(b, w_zh) < binom64(b, w_pos)) {
            auto [wz, rhoz] = rank_word_colex(z_word, b);
            return DualBasisAtom{AtomBasis::ZHEG, static_cast<uint8_t>(b), wz, rhoz};
        }
    }
    return DualBasisAtom{AtomBasis::POS, static_cast<uint8_t>(b), w_pos, rho_pos};
}

uint64_t decode_micro_atom(const DualBasisAtom& atom) {
    uint64_t raw = unrank_word_colex(atom.b, atom.w, atom.rho);
    if (atom.beta == AtomBasis::ZHEG) {
        return mobius_word(raw, atom.b);
    }
    return raw;
}

uint64_t apply_v4_word(uint64_t word, int b, V4Op op) noexcept {
    uint64_t m = low_mask(b);
    word &= m;
    switch (op) {
        case V4Op::ID: return word;
        case V4Op::NOT: return (~word) & m;
        case V4Op::REV: {
            uint64_t r = bitrev64(word);
            return (b == 64) ? r : (r >> (64 - b));
        }
        case V4Op::REV_NOT: {
            uint64_t r = bitrev64(word);
            uint64_t s = (b == 64) ? r : (r >> (64 - b));
            return (~s) & m;
        }
    }
    return word;
}

std::pair<uint64_t, V4Op> canonical_v4_word(uint64_t word, int b) noexcept {
    uint64_t m = low_mask(b);
    uint64_t c0 = word & m;
    uint64_t best = c0;
    V4Op best_op = V4Op::ID;

    uint64_t c1 = (~c0) & m;
    if (c1 < best) { best = c1; best_op = V4Op::NOT; }

    uint64_t r = bitrev64(c0);
    uint64_t c2 = (b == 64) ? r : (r >> (64 - b));
    if (c2 < best) { best = c2; best_op = V4Op::REV; }

    uint64_t c3 = (~c2) & m;
    if (c3 < best) { best = c3; best_op = V4Op::REV_NOT; }

    return {best, best_op};
}

uint64_t transpose8x8_swar(uint64_t x) noexcept {
    uint64_t t = (x ^ (x >> 7)) & 0x00AA00AA00AA00AAULL;
    x = x ^ t ^ (t << 7);
    t = (x ^ (x >> 14)) & 0x0000CCCC0000CCCCULL;
    x = x ^ t ^ (t << 14);
    t = (x ^ (x >> 28)) & 0x00000000F0F0F0F0ULL;
    x = x ^ t ^ (t << 28);
    return x;
}

std::vector<BitSeq> deinterleave_bitplanes(const BitSeq& seq, int stride) {
    if (stride != 8 && stride != 16 && stride != 32 && stride != 64) {
        throw std::invalid_argument("Unsupported bitplane stride");
    }
    uint64_t n = seq.bit_len();
    if (n % static_cast<uint64_t>(stride) != 0ULL) {
        throw std::invalid_argument("deinterleave bit_len must be divisible by stride");
    }
    uint64_t m = n / static_cast<uint64_t>(stride);
    if (m == 0) {
        return std::vector<BitSeq>(static_cast<size_t>(stride), BitSeq::empty());
    }

    // Fast 64-record block transpose when m is divisible by 64 (or handle blocks of 64 + remainder)
    size_t s = static_cast<size_t>(stride);
    size_t lane_words = static_cast<size_t>((m + 63ULL) >> 6);
    std::vector<std::vector<uint64_t>> lw(s, std::vector<uint64_t>(lane_words, 0ULL));

    // Process 8x8 SWAR tiles when stride == 8 and m >= 8, else clean word-scatter
    uint64_t q = 0;
    if (stride == 8) {
        uint64_t full8 = m >> 3;
        for (uint64_t blk = 0; blk < full8; ++blk) {
            uint64_t in64 = seq.get_bits64(blk * 64ULL, 64);
            uint64_t tr = transpose8x8_swar(in64);
            size_t out_w = static_cast<size_t>((blk * 8ULL) >> 6);
            int out_sh = static_cast<int>((blk * 8ULL) & 63ULL);
            for (size_t j = 0; j < 8; ++j) {
                uint64_t byte_j = (tr >> (8 * j)) & 0xFFULL;
                lw[j][out_w] |= (byte_j << out_sh);
            }
        }
        q = full8 * 8ULL;
    }
    for (; q < m; ++q) {
        uint64_t rec = seq.get_bits64(q * static_cast<uint64_t>(stride), stride);
        size_t w_idx = static_cast<size_t>(q >> 6);
        uint64_t bit = 1ULL << (q & 63ULL);
        for (size_t j = 0; j < s; ++j) {
            if ((rec >> j) & 1ULL) lw[j][w_idx] |= bit;
        }
    }

    std::vector<BitSeq> out;
    out.reserve(s);
    for (size_t j = 0; j < s; ++j) {
        out.emplace_back(std::move(lw[j]), m);
    }
    return out;
}

BitSeq interleave_bitplanes(const std::vector<BitSeq>& lanes, int stride) {
    if (static_cast<int>(lanes.size()) != stride ||
        (stride != 8 && stride != 16 && stride != 32 && stride != 64)) {
        throw std::invalid_argument("Invalid interleave lanes/stride");
    }
    uint64_t m = lanes[0].bit_len();
    for (const auto& ln : lanes) {
        if (ln.bit_len() != m) throw std::invalid_argument("Lane length mismatch");
    }
    if (m == 0) return BitSeq();

    uint64_t total = m * static_cast<uint64_t>(stride);
    size_t out_words = static_cast<size_t>((total + 63ULL) >> 6);
    std::vector<uint64_t> out(out_words, 0ULL);

    uint64_t q = 0;
    if (stride == 8) {
        uint64_t full8 = m >> 3;
        for (uint64_t blk = 0; blk < full8; ++blk) {
            size_t in_w = static_cast<size_t>((blk * 8ULL) >> 6);
            int in_sh = static_cast<int>((blk * 8ULL) & 63ULL);
            uint64_t packed = 0ULL;
            for (size_t j = 0; j < 8; ++j) {
                uint64_t byte_j = (lanes[j].word(in_w) >> in_sh) & 0xFFULL;
                packed |= (byte_j << (8 * j));
            }
            out[static_cast<size_t>(blk)] = transpose8x8_swar(packed);
        }
        q = full8 * 8ULL;
    }

    size_t s = static_cast<size_t>(stride);
    for (; q < m; ++q) {
        size_t in_w = static_cast<size_t>(q >> 6);
        int in_sh = static_cast<int>(q & 63ULL);
        uint64_t rec = 0ULL;
        for (size_t j = 0; j < s; ++j) {
            rec |= ((lanes[j].word(in_w) >> in_sh) & 1ULL) << j;
        }
        uint64_t dst_bit = q * static_cast<uint64_t>(stride);
        size_t ow = static_cast<size_t>(dst_bit >> 6);
        int osh = static_cast<int>(dst_bit & 63ULL);
        out[ow] |= (rec << osh);
        if (osh + stride > 64 && ow + 1 < out_words) {
            out[ow + 1] |= (rec >> (64 - osh));
        }
    }
    return BitSeq(std::move(out), total);
}

std::optional<std::pair<uint8_t, uint64_t>> berlekamp_massey_gf2(
    const uint8_t* bits, size_t n, int max_degree) noexcept {
    if (n == 0 || max_degree < 1 || max_degree > 64) return std::nullopt;
#if defined(__GNUC__) && !defined(__clang__)
    using u128 = unsigned __int128;
#else
    using u128 = unsigned long long; // fallback, limited to 64 bits
#endif
    u128 C = 1;
    u128 B = 1;
    int L = 0;
    int m = 1;

    for (size_t r = 0; r < n; ++r) {
        uint8_t d = bits[r] & 1u;
        for (int j = 1; j <= L; ++j) {
            if ((C >> j) & 1u) {
                d ^= (bits[r - static_cast<size_t>(j)] & 1u);
            }
        }
        if (d == 0) {
            ++m;
        } else {
            if (m >= 120) return std::nullopt;
            u128 T = C;
            C ^= (B << m);
            if (2 * L <= static_cast<int>(r)) {
                int L_new = static_cast<int>(r) + 1 - L;
                if (L_new > max_degree) return std::nullopt;
                L = L_new;
                B = T;
                m = 1;
            } else {
                ++m;
            }
        }
    }
    if (L <= 0 || L > max_degree) return std::nullopt;
    uint64_t conn_mask = static_cast<uint64_t>(C >> 1) & low_mask(L);
    if (conn_mask == 0ULL) return std::nullopt;
    return std::make_pair(static_cast<uint8_t>(L), conn_mask);
}

BitSeq evaluate_lfsr(int degree, uint64_t conn_mask, uint64_t init_mask, uint64_t length) {
    if (degree < 1 || degree > 64) throw std::invalid_argument("LFSR degree out of [1,64]");
    if (length < static_cast<uint64_t>(degree)) throw std::invalid_argument("LFSR length < degree");

    uint64_t mL = low_mask(degree);
    conn_mask &= mL;
    init_mask &= mL;

    size_t n_words = static_cast<size_t>((length + 63ULL) >> 6);
    std::vector<uint64_t> out(n_words, 0ULL);

    uint64_t state = 0ULL;
    for (int i = 0; i < degree; ++i) {
        uint64_t b = (init_mask >> i) & 1ULL;
        if (b) out[0] |= (1ULL << i);
        state = (degree == 64) ? ((state << 1) | b) : (((state << 1) | b) & mL);
    }

    for (uint64_t t = static_cast<uint64_t>(degree); t < length; ++t) {
        uint64_t fb = static_cast<uint64_t>(std::popcount(state & conn_mask) & 1);
        if (fb) out[static_cast<size_t>(t >> 6)] |= (1ULL << (t & 63ULL));
        state = (degree == 64) ? ((state << 1) | fb) : (((state << 1) | fb) & mL);
    }
    return BitSeq(std::move(out), length);
}

std::optional<LfsrSpec> verify_and_measure_lfsr(
    const BitSeq& seq, int max_degree, size_t sample_prefix) {
    uint64_t n = seq.bit_len();
    if (n < 256) return std::nullopt;
    size_t pref_len = static_cast<size_t>(std::min<uint64_t>(n, sample_prefix));
    std::vector<uint8_t> pref(pref_len);
    for (size_t i = 0; i < pref_len; ++i) pref[i] = static_cast<uint8_t>(seq.get_bit(i));

    auto bm = berlekamp_massey_gf2(pref.data(), pref_len, max_degree);
    if (!bm) return std::nullopt;
    int L = bm->first;
    uint64_t conn = bm->second;
    if (2 * static_cast<size_t>(L) > pref_len || 4ULL * static_cast<uint64_t>(L) > n) {
        return std::nullopt;
    }
    uint64_t init_mask = seq.get_bits64(0, static_cast<uint8_t>(L));
    uint64_t mL = low_mask(L);
    uint64_t state = 0ULL;
    for (int i = 0; i < L; ++i) {
        uint64_t b = (init_mask >> i) & 1ULL;
        state = (L == 64) ? ((state << 1) | b) : (((state << 1) | b) & mL);
    }

    // Verify full sequence word-by-word with zero allocation
    uint64_t matched = static_cast<uint64_t>(L);
    const auto& words = seq.words();
    while (matched < n) {
        uint64_t fb = static_cast<uint64_t>(std::popcount(state & conn) & 1);
        uint64_t actual = (words[static_cast<size_t>(matched >> 6)] >> (matched & 63ULL)) & 1ULL;
        if (fb != actual) break;
        state = (L == 64) ? ((state << 1) | fb) : (((state << 1) | fb) & mL);
        ++matched;
    }
    if (matched >= std::max<uint64_t>(256ULL, 4ULL * static_cast<uint64_t>(static_cast<uint8_t>(L)))) {
        return LfsrSpec{static_cast<uint8_t>(L), conn, init_mask, matched};
    }
    return std::nullopt;
}

} // namespace mapr
