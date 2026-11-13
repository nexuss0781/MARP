#include "mapr/bitseq.hpp"
#include "mapr/crypto.hpp"
#include <algorithm>
#include <stdexcept>

namespace mapr {

BitSeq::BitSeq(std::vector<uint64_t> words, uint64_t bit_len)
    : words_(std::move(words)), bit_len_(bit_len) {
    size_t expected = static_cast<size_t>((bit_len_ + 63ULL) >> 6);
    words_.resize(expected, 0ULL);
    mask_tail();
}

BitSeq BitSeq::from_word(uint64_t val, int bit_len) {
    if (bit_len < 0 || bit_len > 64) throw std::invalid_argument("from_word bit_len out of [0,64]");
    if (bit_len == 0) return BitSeq();
    return BitSeq({val & low_mask(bit_len)}, static_cast<uint64_t>(bit_len));
}

BitSeq BitSeq::from_bytes_msb(const uint8_t* data, size_t n_bytes) {
    if (n_bytes == 0) return BitSeq();
    uint64_t n_bits = static_cast<uint64_t>(n_bytes) * 8ULL;
    size_t n_words = (n_bytes + 7u) >> 3;
    std::vector<uint64_t> words(n_words, 0ULL);

    size_t full_words = n_bytes >> 3;
    for (size_t i = 0; i < full_words; ++i) {
        uint64_t raw = read_le64(data + 8 * i);
        words[i] = bitrev_bytes64(raw);
    }
    size_t tail = n_bytes & 7u;
    if (tail > 0) {
        uint64_t w = 0;
        for (size_t b = 0; b < tail; ++b) {
            w |= static_cast<uint64_t>(bitrev8(data[8 * full_words + b])) << (8 * b);
        }
        words[full_words] = w;
    }
    return BitSeq(std::move(words), n_bits);
}

BitSeq BitSeq::from_bitstring(const std::string& s) {
    BitSeqAppender app(s.size());
    uint64_t cur = 0;
    int cnt = 0;
    for (char c : s) {
        if (c == '0' || c == '1') {
            cur |= static_cast<uint64_t>(c - '0') << cnt;
            if (++cnt == 64) {
                app.append_word(cur, 64);
                cur = 0;
                cnt = 0;
            }
        } else {
            throw std::invalid_argument("Invalid character in bitstring");
        }
    }
    if (cnt > 0) app.append_word(cur, cnt);
    return app.finish();
}

BitSeq BitSeq::slice(uint64_t start, uint64_t length) const {
    if (start + length > bit_len_) {
        throw std::out_of_range("BitSeq::slice out of bounds");
    }
    if (length == 0) return BitSeq();

    size_t out_words = static_cast<size_t>((length + 63ULL) >> 6);
    std::vector<uint64_t> res(out_words, 0ULL);
    size_t w_start = static_cast<size_t>(start >> 6);
    int sh = static_cast<int>(start & 63ULL);

    if (sh == 0) {
        std::copy_n(words_.begin() + static_cast<ptrdiff_t>(w_start), out_words, res.begin());
    } else {
        int rsh = 64 - sh;
        for (size_t i = 0; i < out_words; ++i) {
            uint64_t lo = words_[w_start + i] >> sh;
            uint64_t hi = (w_start + i + 1 < words_.size()) ? (words_[w_start + i + 1] << rsh) : 0ULL;
            res[i] = lo | hi;
        }
    }
    return BitSeq(std::move(res), length);
}

void BitSeqAppender::append_seq(const BitSeq& seq) {
    uint64_t n = seq.bit_len();
    if (n == 0) return;
    int rem = static_cast<int>(bit_len_ & 63ULL);
    const auto& sw = seq.words();
    size_t n_full = static_cast<size_t>(n >> 6);
    int tail = static_cast<int>(n & 63ULL);

    if (rem == 0) {
        words_.insert(words_.end(), sw.begin(), sw.end());
        bit_len_ += n;
    } else {
        for (size_t i = 0; i < n_full; ++i) {
            uint64_t val = sw[i];
            words_.back() |= (val << rem);
            words_.push_back(val >> (64 - rem));
        }
        bit_len_ += static_cast<uint64_t>(n_full) * 64ULL;
        if (tail > 0) {
            append_word(sw[n_full], tail);
        }
    }
}

BitSeq BitSeq::concat(const std::vector<BitSeq>& parts) {
    uint64_t total = 0;
    for (const auto& p : parts) total += p.bit_len();
    if (total == 0) return BitSeq();
    BitSeqAppender app(total);
    for (const auto& p : parts) app.append_seq(p);
    return app.finish();
}

BitSeq BitSeq::repeat(uint64_t q, uint64_t r) const {
    if (bit_len_ == 0) {
        if (r != 0) throw std::invalid_argument("Repeat remainder on empty BitSeq");
        return BitSeq();
    }
    if (r >= bit_len_) throw std::invalid_argument("Repeat remainder r >= motif length");
    uint64_t total = q * bit_len_ + r;
    if (total == 0) return BitSeq();

    // Doubling construction for large q on short motifs
    BitSeq acc;
    if (q > 0) {
        BitSeq base = *this;
        uint64_t rem_q = q;
        BitSeqAppender res_app(q * bit_len_ + r);
        // Fast doubling up to 65536 bits, then linear append
        while (base.bit_len() < 65536 && rem_q >= 2) {
            if (rem_q & 1ULL) res_app.append_seq(base);
            BitSeqAppender dbl(base.bit_len() * 2);
            dbl.append_seq(base);
            dbl.append_seq(base);
            base = dbl.finish();
            rem_q >>= 1;
        }
        for (uint64_t i = 0; i < rem_q; ++i) res_app.append_seq(base);
        if (r > 0) res_app.append_seq(slice(0, r));
        return res_app.finish();
    }
    return slice(0, r);
}

BitSeq BitSeq::bitwise_not() const {
    if (bit_len_ == 0) return BitSeq();
    std::vector<uint64_t> res(words_.size());
    for (size_t i = 0; i < words_.size(); ++i) res[i] = ~words_[i];
    return BitSeq(std::move(res), bit_len_);
}

BitSeq BitSeq::reverse_bits() const {
    if (bit_len_ == 0) return BitSeq();
    size_t nw = words_.size();
    std::vector<uint64_t> rev_full(nw);
    for (size_t i = 0; i < nw; ++i) {
        rev_full[i] = bitrev64(words_[nw - 1 - i]);
    }
    int rem = static_cast<int>(bit_len_ & 63ULL);
    if (rem == 0) {
        return BitSeq(std::move(rev_full), bit_len_);
    }
    int pad = 64 - rem;
    BitSeq padded(std::move(rev_full), static_cast<uint64_t>(nw) * 64ULL);
    return padded.slice(static_cast<uint64_t>(pad), bit_len_);
}

BitSeq BitSeq::apply_v4(V4Op op) const {
    switch (op) {
        case V4Op::ID: return *this;
        case V4Op::NOT: return bitwise_not();
        case V4Op::REV: return reverse_bits();
        case V4Op::REV_NOT: return reverse_bits().bitwise_not();
    }
    return *this;
}

BitSeq BitSeq::bitwise_xor(const BitSeq& other) const {
    if (bit_len_ != other.bit_len_) throw std::invalid_argument("XOR length mismatch");
    if (bit_len_ == 0) return BitSeq();
    std::vector<uint64_t> res(words_.size());
    for (size_t i = 0; i < words_.size(); ++i) res[i] = words_[i] ^ other.words_[i];
    return BitSeq(std::move(res), bit_len_);
}

uint64_t BitSeq::popcount() const noexcept {
    uint64_t total = 0;
    for (uint64_t w : words_) total += static_cast<uint64_t>(std::popcount(w));
    return total;
}

void BitSeq::to_bytes_msb_padded(std::vector<uint8_t>& out) const {
    size_t n_bytes = static_cast<size_t>((bit_len_ + 7ULL) >> 3);
    out.resize(n_bytes);
    size_t full_words = n_bytes >> 3;
    for (size_t i = 0; i < full_words; ++i) {
        write_le64(out.data() + 8 * i, bitrev_bytes64(words_[i]));
    }
    size_t tail = n_bytes & 7u;
    if (tail > 0) {
        uint64_t revw = bitrev_bytes64(words_[full_words]);
        for (size_t b = 0; b < tail; ++b) {
            out[8 * full_words + b] = static_cast<uint8_t>((revw >> (8 * b)) & 0xFFu);
        }
    }
}

std::vector<uint8_t> BitSeq::to_bytes_msb() const {
    if ((bit_len_ & 7ULL) != 0ULL) {
        throw std::invalid_argument("to_bytes_msb requires bit_len % 8 == 0");
    }
    std::vector<uint8_t> out;
    to_bytes_msb_padded(out);
    return out;
}

std::string BitSeq::to_bitstring() const {
    std::string s(static_cast<size_t>(bit_len_), '0');
    for (uint64_t i = 0; i < bit_len_; ++i) {
        if (get_bit(i)) s[static_cast<size_t>(i)] = '1';
    }
    return s;
}

std::array<uint8_t, 32> BitSeq::canonical_sha256() const {
    Sha256 sha;
    uint8_t len_be[8];
    write_be64(len_be, bit_len_);
    sha.update(len_be, 8);
    if (bit_len_ > 0) {
        std::vector<uint8_t> padded;
        to_bytes_msb_padded(padded);
        sha.update(padded.data(), padded.size());
    }
    return sha.finalize();
}

bool BitSeq::lex_less(const BitSeq& other) const noexcept {
    if (bit_len_ != other.bit_len_) return bit_len_ < other.bit_len_;
    for (size_t i = 0; i < words_.size(); ++i) {
        if (words_[i] != other.words_[i]) {
            uint64_t diff = words_[i] ^ other.words_[i];
            int first_bit = std::countr_zero(diff);
            return ((words_[i] >> first_bit) & 1ULL) < ((other.words_[i] >> first_bit) & 1ULL);
        }
    }
    return false;
}

} // namespace mapr
