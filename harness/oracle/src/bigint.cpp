#include "oracle_internal.hpp"

#include <algorithm>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace marp::oracle::detail {

BigInt::BigInt(std::uint64_t v) {
    if (v != 0) {
        limbs_.push_back(static_cast<std::uint32_t>(v & 0xFFFFFFFFULL));
        const std::uint32_t hi = static_cast<std::uint32_t>(v >> 32);
        if (hi != 0) {
            limbs_.push_back(hi);
        }
    }
}

void BigInt::trim() noexcept {
    while (!limbs_.empty() && limbs_.back() == 0U) {
        limbs_.pop_back();
    }
}

std::optional<BigInt> BigInt::from_decimal(std::string_view s) {
    if (s.empty()) {
        return std::nullopt;
    }
    for (char ch : s) {
        if (ch < '0' || ch > '9') {
            return std::nullopt;
        }
    }
    BigInt acc;
    std::size_t i = 0;
    while (i < s.size()) {
        const std::size_t chunk = std::min<std::size_t>(9, s.size() - i);
        std::uint64_t mul = 1;
        std::uint64_t val = 0;
        for (std::size_t j = 0; j < chunk; ++j) {
            mul *= 10ULL;
            val = val * 10ULL + static_cast<std::uint64_t>(s[i + j] - '0');
        }
        acc = add_u64(mul_u64(acc, mul), val);
        i += chunk;
    }
    return acc;
}

BigInt BigInt::from_le_bytes(std::span<const std::uint8_t> bytes) {
    BigInt out;
    if (bytes.empty()) {
        return out;
    }
    const std::size_t nlimbs = (bytes.size() + 3) / 4;
    out.limbs_.assign(nlimbs, 0U);
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        const std::size_t limb_idx = i / 4;
        const unsigned shift = static_cast<unsigned>((i % 4) * 8);
        out.limbs_[limb_idx] |= static_cast<std::uint32_t>(bytes[i]) << shift;
    }
    out.trim();
    return out;
}

std::uint64_t BigInt::to_u64() const noexcept {
    if (limbs_.empty()) {
        return 0ULL;
    }
    std::uint64_t v = limbs_[0];
    if (limbs_.size() >= 2) {
        v |= static_cast<std::uint64_t>(limbs_[1]) << 32;
    }
    return v;
}

std::vector<std::uint8_t> BigInt::to_le_bytes() const {
    std::vector<std::uint8_t> out;
    if (limbs_.empty()) {
        return out;
    }
    out.reserve(limbs_.size() * 4);
    for (std::uint32_t w : limbs_) {
        out.push_back(static_cast<std::uint8_t>(w & 0xFFU));
        out.push_back(static_cast<std::uint8_t>((w >> 8) & 0xFFU));
        out.push_back(static_cast<std::uint8_t>((w >> 16) & 0xFFU));
        out.push_back(static_cast<std::uint8_t>((w >> 24) & 0xFFU));
    }
    while (!out.empty() && out.back() == 0U) {
        out.pop_back();
    }
    return out;
}

std::size_t BigInt::bit_length() const noexcept {
    if (limbs_.empty()) {
        return 0;
    }
    const std::uint32_t top = limbs_.back();
    const unsigned top_bits = static_cast<unsigned>(32 - std::countl_zero(top));
    return (limbs_.size() - 1) * 32 + top_bits;
}

bool BigInt::get_bit(std::size_t idx) const noexcept {
    const std::size_t limb_idx = idx / 32;
    if (limb_idx >= limbs_.size()) {
        return false;
    }
    const unsigned bit_idx = static_cast<unsigned>(idx % 32);
    return ((limbs_[limb_idx] >> bit_idx) & 1U) != 0U;
}

int BigInt::compare(const BigInt& a, const BigInt& b) noexcept {
    if (a.limbs_.size() != b.limbs_.size()) {
        return a.limbs_.size() < b.limbs_.size() ? -1 : 1;
    }
    for (std::size_t i = a.limbs_.size(); i > 0; --i) {
        const std::uint32_t av = a.limbs_[i - 1];
        const std::uint32_t bv = b.limbs_[i - 1];
        if (av != bv) {
            return av < bv ? -1 : 1;
        }
    }
    return 0;
}

BigInt BigInt::add(const BigInt& a, const BigInt& b) {
    const std::size_t n = std::max(a.limbs_.size(), b.limbs_.size());
    BigInt out;
    out.limbs_.resize(n, 0U);
    std::uint64_t carry = 0;
    for (std::size_t i = 0; i < n; ++i) {
        const std::uint64_t av = (i < a.limbs_.size()) ? a.limbs_[i] : 0ULL;
        const std::uint64_t bv = (i < b.limbs_.size()) ? b.limbs_[i] : 0ULL;
        const std::uint64_t sum = av + bv + carry;
        out.limbs_[i] = static_cast<std::uint32_t>(sum & 0xFFFFFFFFULL);
        carry = sum >> 32;
    }
    if (carry != 0) {
        out.limbs_.push_back(static_cast<std::uint32_t>(carry));
    }
    out.trim();
    return out;
}

BigInt BigInt::add_u64(const BigInt& a, std::uint64_t b) {
    if (b == 0) {
        return a;
    }
    return add(a, BigInt(b));
}

BigInt BigInt::sub(const BigInt& a, const BigInt& b) {
    BigInt out;
    out.limbs_.resize(a.limbs_.size(), 0U);
    std::uint64_t borrow = 0;
    for (std::size_t i = 0; i < a.limbs_.size(); ++i) {
        const std::uint64_t av = a.limbs_[i];
        const std::uint64_t bv = (i < b.limbs_.size()) ? b.limbs_[i] : 0ULL;
        const std::uint64_t subtrahend = bv + borrow;
        if (av >= subtrahend) {
            out.limbs_[i] = static_cast<std::uint32_t>(av - subtrahend);
            borrow = 0;
        } else {
            out.limbs_[i] = static_cast<std::uint32_t>((1ULL << 32) + av - subtrahend);
            borrow = 1;
        }
    }
    out.trim();
    return out;
}

BigInt BigInt::mul(const BigInt& a, const BigInt& b) {
    if (a.is_zero() || b.is_zero()) {
        return BigInt();
    }
    BigInt out;
    out.limbs_.assign(a.limbs_.size() + b.limbs_.size(), 0U);
    for (std::size_t i = 0; i < a.limbs_.size(); ++i) {
        std::uint64_t carry = 0;
        const std::uint64_t av = a.limbs_[i];
        for (std::size_t j = 0; j < b.limbs_.size(); ++j) {
            const std::uint64_t prod = av * b.limbs_[j] + out.limbs_[i + j] + carry;
            out.limbs_[i + j] = static_cast<std::uint32_t>(prod & 0xFFFFFFFFULL);
            carry = prod >> 32;
        }
        std::size_t k = i + b.limbs_.size();
        while (carry != 0) {
            const std::uint64_t sum = static_cast<std::uint64_t>(out.limbs_[k]) + carry;
            out.limbs_[k] = static_cast<std::uint32_t>(sum & 0xFFFFFFFFULL);
            carry = sum >> 32;
            ++k;
        }
    }
    out.trim();
    return out;
}

BigInt BigInt::mul_u64(const BigInt& a, std::uint64_t b) {
    if (a.is_zero() || b == 0) {
        return BigInt();
    }
    if (b <= 0xFFFFFFFFULL) {
        BigInt out;
        out.limbs_.resize(a.limbs_.size(), 0U);
        std::uint64_t carry = 0;
        for (std::size_t i = 0; i < a.limbs_.size(); ++i) {
            const std::uint64_t prod = static_cast<std::uint64_t>(a.limbs_[i]) * b + carry;
            out.limbs_[i] = static_cast<std::uint32_t>(prod & 0xFFFFFFFFULL);
            carry = prod >> 32;
        }
        if (carry != 0) {
            out.limbs_.push_back(static_cast<std::uint32_t>(carry));
        }
        out.trim();
        return out;
    }
    return mul(a, BigInt(b));
}

std::pair<BigInt, std::uint64_t> BigInt::divmod_u64(const BigInt& a, std::uint64_t d) {
    if (d == 0 || a.is_zero()) {
        return {BigInt(), 0ULL};
    }
    if (d <= 0xFFFFFFFFULL) {
        BigInt q;
        q.limbs_.resize(a.limbs_.size(), 0U);
        std::uint64_t rem = 0;
        for (std::size_t i = a.limbs_.size(); i > 0; --i) {
            const std::uint64_t cur = (rem << 32) | a.limbs_[i - 1];
            q.limbs_[i - 1] = static_cast<std::uint32_t>(cur / d);
            rem = cur % d;
        }
        q.trim();
        return {std::move(q), rem};
    }
    auto [q, r] = divmod(a, BigInt(d));
    return {std::move(q), r.to_u64()};
}

std::uint64_t BigInt::mod_u64(const BigInt& a, std::uint64_t d) {
    if (d == 0 || a.is_zero()) {
        return 0ULL;
    }
    if (d <= 0xFFFFFFFFULL) {
        std::uint64_t rem = 0;
        for (std::size_t i = a.limbs_.size(); i > 0; --i) {
            const std::uint64_t cur = (rem << 32) | a.limbs_[i - 1];
            rem = cur % d;
        }
        return rem;
    }
    return divmod(a, BigInt(d)).second.to_u64();
}

std::pair<BigInt, BigInt> BigInt::divmod(const BigInt& a, const BigInt& b) {
    if (b.is_zero() || a.is_zero()) {
        return {BigInt(), BigInt()};
    }
    const int cmp = compare(a, b);
    if (cmp < 0) {
        return {BigInt(), a};
    }
    if (cmp == 0) {
        return {BigInt(1), BigInt()};
    }
    if (b.limbs_.size() == 1) {
        auto [q, rem] = divmod_u64(a, b.limbs_[0]);
        return {std::move(q), BigInt(rem)};
    }

    // Binary long division: exact, pure ISO C++20, zero overflow risk
    BigInt q;
    q.limbs_.assign(a.limbs_.size(), 0U);
    BigInt rem;
    rem.limbs_.reserve(b.limbs_.size() + 1);

    const std::size_t total_bits = a.bit_length();
    for (std::size_t step = total_bits; step > 0; --step) {
        const std::size_t bit_idx = step - 1;
        // rem = (rem << 1) | bit
        std::uint32_t carry = a.get_bit(bit_idx) ? 1U : 0U;
        for (std::size_t k = 0; k < rem.limbs_.size(); ++k) {
            const std::uint32_t next_carry = rem.limbs_[k] >> 31;
            rem.limbs_[k] = (rem.limbs_[k] << 1) | carry;
            carry = next_carry;
        }
        if (carry != 0U) {
            rem.limbs_.push_back(carry);
        }
        if (compare(rem, b) >= 0) {
            rem = sub(rem, b);
            q.limbs_[bit_idx / 32] |= (1U << static_cast<unsigned>(bit_idx % 32));
        }
    }

    q.trim();
    rem.trim();
    return {std::move(q), std::move(rem)};
}

std::string BigInt::to_decimal() const {
    if (is_zero()) {
        return "0";
    }
    BigInt cur = *this;
    std::vector<std::uint32_t> chunks;
    while (!cur.is_zero()) {
        auto [q, r] = divmod_u64(cur, 1000000000ULL);
        chunks.push_back(static_cast<std::uint32_t>(r));
        cur = std::move(q);
    }
    if (chunks.empty()) {
        return "0";
    }
    std::string out;
    out.reserve(chunks.size() * 9);
    // Most significant chunk without leading zeros
    {
        std::uint32_t v = chunks.back();
        char tmp[16];
        std::size_t len = 0;
        while (v > 0) {
            tmp[len++] = static_cast<char>('0' + (v % 10U));
            v /= 10U;
        }
        for (std::size_t i = len; i > 0; --i) {
            out.push_back(tmp[i - 1]);
        }
    }
    // Remaining chunks zero-padded to 9 digits
    for (std::size_t idx = chunks.size() - 1; idx > 0; --idx) {
        std::uint32_t v = chunks[idx - 1];
        char tmp[9];
        for (std::size_t d = 9; d > 0; --d) {
            tmp[d - 1] = static_cast<char>('0' + (v % 10U));
            v /= 10U;
        }
        out.append(tmp, 9);
    }
    return out;
}

} // namespace marp::oracle::detail
