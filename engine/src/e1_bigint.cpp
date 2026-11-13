#include "mapr/e1_bigint.hpp"
#include <algorithm>
#include <cstring>
#include <new>

namespace mapr {

// ============================================================================
// Constructors / Destructor / Move / Copy
// ============================================================================

BigInt::BigInt(uint64_t v) noexcept {
    if (v == 0) {
        count_ = 0; on_heap_ = false; heap_ = nullptr; capacity_ = 0;
        return;
    }
    small_[0] = static_cast<Limb>(v & LIMB_MAX);
    uint64_t hi = v >> 32;
    if (hi != 0) {
        small_[1] = static_cast<Limb>(hi);
        count_ = 2;
    } else {
        count_ = 1;
    }
    on_heap_ = false; heap_ = nullptr; capacity_ = 0;
}

BigInt::~BigInt() noexcept {
    if (on_heap_) {
        delete[] heap_;
        heap_ = nullptr;
    }
}

BigInt::BigInt(const BigInt& other) noexcept {
    count_ = other.count_;
    on_heap_ = other.on_heap_;
    capacity_ = other.capacity_;
    if (on_heap_) {
        heap_ = new Limb[capacity_];
        std::copy(other.heap_, other.heap_ + count_, heap_);
    } else {
        heap_ = nullptr;
        small_ = other.small_;
    }
}

BigInt& BigInt::operator=(const BigInt& other) noexcept {
    if (this != &other) {
        if (on_heap_) { delete[] heap_; }
        count_ = other.count_;
        on_heap_ = other.on_heap_;
        capacity_ = other.capacity_;
        if (on_heap_) {
            heap_ = new Limb[capacity_];
            std::copy(other.heap_, other.heap_ + count_, heap_);
        } else {
            heap_ = nullptr;
            small_ = other.small_;
        }
    }
    return *this;
}

BigInt::BigInt(BigInt&& other) noexcept {
    count_ = other.count_;
    on_heap_ = other.on_heap_;
    capacity_ = other.capacity_;
    if (on_heap_) {
        heap_ = other.heap_;
        other.heap_ = nullptr;
    } else {
        heap_ = nullptr;
        small_ = other.small_;
    }
    other.count_ = 0;
    other.on_heap_ = false;
    other.capacity_ = 0;
}

BigInt& BigInt::operator=(BigInt&& other) noexcept {
    if (this != &other) {
        if (on_heap_) { delete[] heap_; }
        count_ = other.count_;
        on_heap_ = other.on_heap_;
        capacity_ = other.capacity_;
        if (on_heap_) {
            heap_ = other.heap_;
            other.heap_ = nullptr;
        } else {
            heap_ = nullptr;
            small_ = other.small_;
        }
        other.count_ = 0;
        other.on_heap_ = false;
        other.capacity_ = 0;
    }
    return *this;
}

// ============================================================================
// Internal helpers
// ============================================================================

void BigInt::trim() noexcept {
    while (count_ > 0 && limb(count_ - 1) == 0) --count_;
    if (count_ == 0) {
        if (on_heap_) {
            delete[] heap_;
            heap_ = nullptr;
            on_heap_ = false;
            capacity_ = 0;
        }
    }
}

void BigInt::ensure_capacity(size_t n) {
    if (n <= SBO_LIMBS) {
        if (on_heap_) {
            delete[] heap_;
            heap_ = nullptr;
            on_heap_ = false;
            capacity_ = 0;
        }
        return;
    }
    if (!on_heap_ || capacity_ < n) {
        size_t new_cap = std::max(n, capacity_ * 2);
        if (new_cap < n) new_cap = n;
        Limb* new_heap = new Limb[new_cap];
        if (on_heap_) {
            std::copy(heap_, heap_ + count_, new_heap);
            delete[] heap_;
        } else {
            std::copy(small_.begin(), small_.begin() + count_, new_heap);
        }
        heap_ = new_heap;
        on_heap_ = true;
        capacity_ = new_cap;
    }
}

Limb* BigInt::mutable_limbs() noexcept {
    return on_heap_ ? heap_ : small_.data();
}

const Limb* BigInt::limbs_ptr() const noexcept {
    return on_heap_ ? heap_ : small_.data();
}

// ============================================================================
// Observers
// ============================================================================

bool BigInt::is_zero() const noexcept {
    return count_ == 0;
}

size_t BigInt::limb_count() const noexcept {
    return count_;
}

const Limb* BigInt::limbs() const noexcept {
    return limbs_ptr();
}

Limb BigInt::limb(size_t i) const noexcept {
    if (i >= count_) return 0;
    return limbs_ptr()[i];
}

int BigInt::bit_length() const noexcept {
    if (count_ == 0) return 0;
    Limb top = limb(count_ - 1);
    return static_cast<int>((count_ - 1) * 32 + (32 - __builtin_clz(top)));
}

// ============================================================================
// Conversions
// ============================================================================

Result<BigInt> BigInt::from_u64(uint64_t v) noexcept {
    return BigInt(v);
}

Result<BigInt> BigInt::from_limbs(const Limb* data, size_t n) noexcept {
    if (n == 0) return BigInt::zero();
    if (data[n - 1] == 0) return ErrCode::Invalid; // not canonical
    BigInt result;
    result.ensure_capacity(n);
    Limb* dst = result.mutable_limbs();
    std::copy(data, data + n, dst);
    result.count_ = n;
    return result;
}

Result<BigInt> BigInt::from_le_bytes(std::string_view b) noexcept {
    if (b.empty()) return BigInt::zero();
    size_t n = (b.size() + 3) / 4;
    BigInt result;
    result.ensure_capacity(n);
    Limb* dst = result.mutable_limbs();
    std::memset(dst, 0, n * sizeof(Limb));
    for (size_t i = 0; i < b.size(); ++i) {
        dst[i / 4] |= static_cast<Limb>(static_cast<uint8_t>(b[i])) << (8 * (i % 4));
    }
    result.count_ = n;
    result.trim();
    return result;
}

Result<BigInt> BigInt::from_decimal(std::string_view s) noexcept {
    if (s.empty()) return ErrCode::Invalid;
    if (s == "0") return BigInt::zero();
    if (s[0] == '0') return ErrCode::Invalid; // no leading zeros
    for (char c : s) {
        if (c < '0' || c > '9') return ErrCode::Invalid;
    }
    BigInt result = BigInt::zero();
    for (char c : s) {
        uint8_t digit = c - '0';
        auto mul_res = result.mul(BigInt(10));
        if (!mul_res.ok()) return mul_res.error();
        result = std::move(mul_res.value());
        if (digit != 0) {
            auto add_res = result.add(BigInt(digit));
            if (!add_res.ok()) return add_res.error();
            result = std::move(add_res.value());
        }
    }
    return result;
}

Result<uint64_t> BigInt::to_u64_checked() const noexcept {
    if (count_ == 0) return 0ull;
    if (count_ > 2) return ErrCode::Limit;
    if (count_ == 2 && limb(1) != 0) return ErrCode::Limit;
    uint64_t lo = limb(0);
    uint64_t hi = (count_ == 2) ? static_cast<uint64_t>(limb(1)) : 0ull;
    return (hi << 32) | lo;
}

std::string BigInt::to_decimal() const {
    if (is_zero()) return "0";
    BigInt temp = *this; // copy
    constexpr Limb CHUNK_BASE = 1000000000; // 10^9
    std::string result;
    while (!temp.is_zero()) {
        auto dm = temp.divmod_scalar(CHUNK_BASE);
        if (!dm.ok()) return "ERROR"; // should not happen
        Limb rem = dm.value().second;
        temp = std::move(dm.value().first);
        if (temp.is_zero()) {
            result = std::to_string(rem);
        } else {
            char buf[10];
            std::snprintf(buf, sizeof(buf), "%09u", rem);
            result = buf + result;
        }
    }
    return result;
}

std::vector<uint8_t> BigInt::to_le_bytes() const noexcept {
    if (is_zero()) return {};
    std::vector<uint8_t> out(count_ * 4);
    const Limb* src = limbs_ptr();
    for (size_t i = 0; i < count_; ++i) {
        Limb v = src[i];
        out[4*i + 0] = static_cast<uint8_t>(v & 0xFF);
        out[4*i + 1] = static_cast<uint8_t>((v >> 8) & 0xFF);
        out[4*i + 2] = static_cast<uint8_t>((v >> 16) & 0xFF);
        out[4*i + 3] = static_cast<uint8_t>((v >> 24) & 0xFF);
    }
    while (!out.empty() && out.back() == 0) out.pop_back();
    return out;
}

// ============================================================================
// Comparison
// ============================================================================

int BigInt::compare(const BigInt& other) const noexcept {
    if (count_ != other.count_) {
        return count_ < other.count_ ? -1 : 1;
    }
    for (size_t i = count_; i-- > 0;) {
        Limb a = limb(i), b = other.limb(i);
        if (a != b) return a < b ? -1 : 1;
    }
    return 0;
}

// ============================================================================
// Addition
// ============================================================================

Result<BigInt> BigInt::add(const BigInt& other) const noexcept {
    size_t n = std::max(count_, other.count_);
    BigInt result;
    result.ensure_capacity(n + 1);
    Limb* dst = result.mutable_limbs();
    uint64_t carry = 0;
    for (size_t i = 0; i < n; ++i) {
        uint64_t ai = (i < count_) ? limb(i) : 0;
        uint64_t bi = (i < other.count_) ? other.limb(i) : 0;
        uint64_t sum = ai + bi + carry;
        dst[i] = static_cast<Limb>(sum & LIMB_MAX);
        carry = sum >> 32;
    }
    dst[n] = static_cast<Limb>(carry);
    result.count_ = n + 1;
    result.trim();
    return result;
}

// ============================================================================
// Subtraction
// ============================================================================

Result<BigInt> BigInt::sub(const BigInt& other) const noexcept {
    if (compare(other) < 0) return ErrCode::Invalid;
    BigInt result;
    result.ensure_capacity(count_);
    Limb* dst = result.mutable_limbs();
    uint64_t borrow = 0;
    for (size_t i = 0; i < count_; ++i) {
        uint64_t ai = limb(i);
        uint64_t bi = (i < other.count_) ? other.limb(i) : 0;
        uint64_t sub = ai - bi - borrow;
        dst[i] = static_cast<Limb>(sub & LIMB_MAX);
        borrow = (sub >> 63) & 1; // 1 if underflow
    }
    result.count_ = count_;
    result.trim();
    return result;
}

// ============================================================================
// Multiplication
// ============================================================================

Result<BigInt> BigInt::mul(const BigInt& other) const noexcept {
    if (is_zero() || other.is_zero()) return BigInt::zero();
    size_t n = count_, m = other.count_;
    BigInt result;
    result.ensure_capacity(n + m);
    Limb* dst = result.mutable_limbs();
    std::fill_n(dst, n + m, Limb(0));
    for (size_t i = 0; i < n; ++i) {
        uint64_t ai = limb(i);
        if (ai == 0) continue;
        uint64_t carry = 0;
        for (size_t j = 0; j < m; ++j) {
            __uint128_t prod = (__uint128_t)ai * other.limb(j) + dst[i + j] + carry;
            dst[i + j] = static_cast<Limb>(prod & LIMB_MAX);
            carry = static_cast<uint64_t>(prod >> 32);
        }
        size_t k = i + m;
        while (carry) {
            __uint128_t sum = (__uint128_t)dst[k] + carry;
            dst[k] = static_cast<Limb>(sum & LIMB_MAX);
            carry = static_cast<uint64_t>(sum >> 32);
            ++k;
        }
    }
    result.count_ = n + m;
    result.trim();
    return result;
}

// ============================================================================
// Scalar Division (Math-SPECS A10)
// ============================================================================

Result<std::pair<BigInt, Limb>> BigInt::divmod_scalar(Limb d) const noexcept {
    if (d == 0) return ErrCode::Invalid;
    if (is_zero()) return std::make_pair(BigInt::zero(), Limb(0));
    BigInt quotient;
    quotient.ensure_capacity(count_);
    Limb* q_dst = quotient.mutable_limbs();
    uint64_t rem = 0;
    for (size_t i = count_; i-- > 0;) {
        uint64_t cur = (rem << 32) | limb(i);
        q_dst[i] = static_cast<Limb>(cur / d);
        rem = cur % d;
    }
    quotient.count_ = count_;
    quotient.trim();
    return std::make_pair(std::move(quotient), static_cast<Limb>(rem));
}

// ============================================================================
// Knuth Division (Math-SPECS A11)
// ============================================================================

Result<std::pair<BigInt, BigInt>> BigInt::divmod_knuth(const BigInt& u, const BigInt& v) noexcept {
    if (v.is_zero()) return ErrCode::Invalid;
    int cmp = u.compare(v);
    if (cmp < 0) return std::make_pair(BigInt::zero(), u);
    if (cmp == 0) return std::make_pair(BigInt::one(), BigInt::zero());
    if (v.count_ == 1) {
        auto dm = u.divmod_scalar(v.limb(0));
        if (!dm.ok()) return dm.error();
        return std::make_pair(std::move(dm.value().first), BigInt(dm.value().second));
    }

    size_t n = v.count_;
    size_t m = u.count_ - n;

    // Normalize: d = BASE / (v_{n-1} + 1)
    uint64_t vn1 = v.limb(n - 1);
    uint64_t d = BASE / (vn1 + 1);

    // v' = d * v
    BigInt vn;
    vn.ensure_capacity(n + 1);
    Limb* vn_dst = vn.mutable_limbs();
    uint64_t carry = 0;
    for (size_t i = 0; i < n; ++i) {
        __uint128_t prod = (__uint128_t)v.limb(i) * d + carry;
        vn_dst[i] = static_cast<Limb>(prod & LIMB_MAX);
        carry = static_cast<uint64_t>(prod >> 32);
    }
    vn_dst[n] = static_cast<Limb>(carry);
    vn.count_ = n + (carry != 0);
    vn.trim();
    // Now vn.limb(n-1) >= BASE/2

    // u' = d * u, padded to m+n+1
    BigInt un;
    un.ensure_capacity(m + n + 1);
    Limb* un_dst = un.mutable_limbs();
    std::fill_n(un_dst, m + n + 1, Limb(0));
    carry = 0;
    for (size_t i = 0; i < u.count_; ++i) {
        __uint128_t prod = (__uint128_t)u.limb(i) * d + carry;
        un_dst[i] = static_cast<Limb>(prod & LIMB_MAX);
        carry = static_cast<uint64_t>(prod >> 32);
    }
    un_dst[u.count_] = static_cast<Limb>(carry);
    un.count_ = m + n + 1;

    BigInt q;
    q.ensure_capacity(m + 1);
    Limb* q_dst = q.mutable_limbs();
    std::fill_n(q_dst, m + 1, Limb(0));

    // Main loop
    for (size_t j = m; ; --j) {
        // Estimate qhat
        uint64_t un_jn = un.limb(j + n);
        uint64_t un_jn1 = un.limb(j + n - 1);
        uint64_t un_jn2 = (j + n - 2 < un.count_) ? un.limb(j + n - 2) : 0;
        uint64_t vn_n1 = vn.limb(n - 1);
        uint64_t vn_n2 = vn.limb(n - 2);

        __uint128_t num = (__uint128_t)un_jn * BASE + un_jn1;
        uint64_t qhat = static_cast<uint64_t>(num / vn_n1);
        uint64_t rhat = static_cast<uint64_t>(num % vn_n1);

        // Correct qhat downward (at most 2 iterations, Theorem A11(b))
        while (qhat >= BASE || (__uint128_t)qhat * vn_n2 > (__uint128_t)rhat * BASE + un_jn2) {
            --qhat;
            rhat += vn_n1;
            if (rhat >= BASE) break;
        }

        // Multiply and subtract: un[j..j+n] -= qhat * vn
        int64_t borrow = 0;
        for (size_t i = 0; i < n; ++i) {
            __uint128_t prod = (__uint128_t)qhat * vn.limb(i) + borrow;
            uint64_t sub = un.limb(j + i) - static_cast<uint64_t>(prod & LIMB_MAX);
            un_dst[j + i] = static_cast<Limb>(sub & LIMB_MAX);
            borrow = static_cast<int64_t>(static_cast<uint64_t>(prod >> 32) + ((sub >> 63) & 1));
        }
        // Handle the (j+n)-th limb
        uint64_t un_jn_orig = un.limb(j + n);
        int64_t sub_top = static_cast<int64_t>(un_jn_orig) - borrow;
        un_dst[j + n] = static_cast<Limb>(sub_top & LIMB_MAX);
        borrow = (sub_top >> 63) & 1;

        if (borrow != 0) {
            // qhat was too large by 1; add vn back
            --qhat;
            uint64_t carry_add = 0;
            for (size_t i = 0; i < n; ++i) {
                uint64_t sum = static_cast<uint64_t>(un.limb(j + i)) + vn.limb(i) + carry_add;
                un_dst[j + i] = static_cast<Limb>(sum & LIMB_MAX);
                carry_add = sum >> 32;
            }
            uint64_t sum_top = un.limb(j + n) + carry_add;
            un_dst[j + n] = static_cast<Limb>(sum_top & LIMB_MAX);
        }
        q_dst[j] = static_cast<Limb>(qhat);
        if (j == 0) break;
    }

    q.count_ = m + 1;
    q.trim();

    // Remainder = un[0..n-1] / d
    BigInt rem_un;
    rem_un.ensure_capacity(n);
    Limb* rem_dst = rem_un.mutable_limbs();
    for (size_t i = 0; i < n; ++i) rem_dst[i] = un.limb(i);
    rem_un.count_ = n;
    rem_un.trim();

    auto dm = rem_un.divmod_scalar(static_cast<Limb>(d));
    if (!dm.ok()) return dm.error();
    return std::make_pair(std::move(q), std::move(dm.value().first));
}

Result<std::pair<BigInt, BigInt>> BigInt::divmod(const BigInt& divisor) const noexcept {
    return divmod_knuth(*this, divisor);
}

// ============================================================================
// Shifts
// ============================================================================

Result<BigInt> BigInt::shl(size_t n) const noexcept {
    if (is_zero() || n == 0) return *this;
    size_t limb_shift = n / 32;
    size_t bit_shift = n % 32;
    size_t new_count = count_ + limb_shift + (bit_shift ? 1 : 0);
    BigInt result;
    result.ensure_capacity(new_count);
    Limb* dst = result.mutable_limbs();
    std::fill_n(dst, new_count, Limb(0));

    if (bit_shift == 0) {
        for (size_t i = 0; i < count_; ++i) {
            dst[i + limb_shift] = limb(i);
        }
    } else {
        uint64_t carry = 0;
        for (size_t i = 0; i < count_; ++i) {
            __uint128_t val = (__uint128_t)limb(i) << bit_shift | carry;
            dst[i + limb_shift] = static_cast<Limb>(val & LIMB_MAX);
            carry = static_cast<uint64_t>(val >> 32);
        }
        dst[count_ + limb_shift] = static_cast<Limb>(carry);
    }
    result.count_ = new_count;
    result.trim();
    return result;
}

Result<BigInt> BigInt::shr(size_t n) const noexcept {
    if (is_zero() || n == 0) return *this;
    size_t limb_shift = n / 32;
    size_t bit_shift = n % 32;
    if (limb_shift >= count_) return BigInt::zero();

    size_t new_count = count_ - limb_shift;
    BigInt result;
    result.ensure_capacity(new_count);
    Limb* dst = result.mutable_limbs();

    if (bit_shift == 0) {
        for (size_t i = 0; i < new_count; ++i) {
            dst[i] = limb(i + limb_shift);
        }
    } else {
        for (size_t i = 0; i < new_count; ++i) {
            uint64_t cur = limb(i + limb_shift);
            uint64_t next = (i + limb_shift + 1 < count_) ? limb(i + limb_shift + 1) : 0;
            dst[i] = static_cast<Limb>((cur >> bit_shift) | (next << (32 - bit_shift)));
        }
    }
    result.count_ = new_count;
    result.trim();
    return result;
}

} // namespace mapr