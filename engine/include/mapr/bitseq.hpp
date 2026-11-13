#pragma once

#include "mapr/common.hpp"
#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace mapr {

class BitSeq {
public:
    BitSeq() noexcept : bit_len_(0) {}
    BitSeq(std::vector<uint64_t> words, uint64_t bit_len);

    static BitSeq empty() noexcept { return BitSeq(); }
    static BitSeq from_word(uint64_t val, int bit_len);
    static BitSeq from_bytes_msb(const uint8_t* data, size_t n_bytes);
    static BitSeq from_bitstring(const std::string& s);

    uint64_t bit_len() const noexcept { return bit_len_; }
    size_t word_count() const noexcept { return words_.size(); }
    const std::vector<uint64_t>& words() const noexcept { return words_; }
    uint64_t word(size_t idx) const noexcept { return words_[idx]; }

    // Safe arbitrary-offset 64-bit window extraction [bit_pos .. bit_pos + width) where 1 <= width <= 64
    uint64_t get_bits64(uint64_t bit_pos, int width = 64) const noexcept {
        size_t w_idx = static_cast<size_t>(bit_pos >> 6);
        int sh = static_cast<int>(bit_pos & 63ULL);
        uint64_t lo = words_[w_idx] >> sh;
        if (sh != 0 && (w_idx + 1) < words_.size()) {
            lo |= words_[w_idx + 1] << (64 - sh);
        }
        return lo & low_mask(width);
    }

    int get_bit(uint64_t i) const noexcept {
        return static_cast<int>((words_[static_cast<size_t>(i >> 6)] >> (i & 63ULL)) & 1ULL);
    }

    BitSeq slice(uint64_t start, uint64_t length) const;
    static BitSeq concat(const std::vector<BitSeq>& parts);
    BitSeq repeat(uint64_t q, uint64_t r) const;

    BitSeq bitwise_not() const;
    BitSeq reverse_bits() const;
    BitSeq apply_v4(V4Op op) const;
    BitSeq bitwise_xor(const BitSeq& other) const;

    uint64_t popcount() const noexcept;

    void to_bytes_msb_padded(std::vector<uint8_t>& out) const;
    std::vector<uint8_t> to_bytes_msb() const;
    std::string to_bitstring() const;

    // Canonical digest: SHA256(uint64_be(bit_len) || msb_padded_bytes)
    std::array<uint8_t, 32> canonical_sha256() const;

    bool operator==(const BitSeq& other) const noexcept {
        return bit_len_ == other.bit_len_ && words_ == other.words_;
    }
    bool operator!=(const BitSeq& other) const noexcept { return !(*this == other); }
    bool lex_less(const BitSeq& other) const noexcept;

private:
    void mask_tail() noexcept {
        if (words_.empty()) return;
        int rem = static_cast<int>(bit_len_ & 63ULL);
        if (rem != 0) {
            words_.back() &= low_mask(rem);
        }
    }

    std::vector<uint64_t> words_;
    uint64_t bit_len_;
};

//Builder helper to append arbitrary-bit-length BitSeq segments without O(N^2) copying
class BitSeqAppender {
public:
    explicit BitSeqAppender(uint64_t reserve_bits = 0) : bit_len_(0) {
        if (reserve_bits > 0) words_.reserve(static_cast<size_t>((reserve_bits + 63ULL) >> 6));
    }

    void append_word(uint64_t val, int b) {
        if (b <= 0) return;
        val &= low_mask(b);
        int rem = static_cast<int>(bit_len_ & 63ULL);
        if (rem == 0) {
            words_.push_back(val);
        } else {
            words_.back() |= (val << rem);
            if (rem + b > 64) {
                words_.push_back(val >> (64 - rem));
            }
        }
        bit_len_ += static_cast<uint64_t>(b);
    }

    void append_seq(const BitSeq& seq);

    BitSeq finish() {
        return BitSeq(std::move(words_), bit_len_);
    }

private:
    std::vector<uint64_t> words_;
    uint64_t bit_len_;
};

} // namespace mapr
