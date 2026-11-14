#include "marp/harness/e1_oracle.hpp"
#include <algorithm>
#include <array>
#include <cstring>
#include <stdexcept>
#include <zlib.h>

namespace marp::harness::oracle {

// ============================================================================
// Base-10^9 BigInt helpers
// ============================================================================

BigInt trim(const BigInt& x) {
    BigInt result = x;
    while (result.size() > 1 && result.back() == 0) {
        result.pop_back();
    }
    return result;
}

int compare(const BigInt& a, const BigInt& b) {
    BigInt ta = trim(a);
    BigInt tb = trim(b);
    if (ta.size() != tb.size()) {
        return ta.size() < tb.size() ? -1 : 1;
    }
    for (size_t i = ta.size(); i-- > 0;) {
        if (ta[i] != tb[i]) return ta[i] < tb[i] ? -1 : 1;
    }
    return 0;
}

std::optional<BigInt> from_decimal(std::string_view s) {
    if (s.empty()) return std::nullopt;
    if (s == "0") return BigInt{0};
    if (s[0] == '0') return std::nullopt; // no leading zeros
    
    for (char c : s) {
        if (c < '0' || c > '9') return std::nullopt;
    }
    
    BigInt result{0};
    for (char c : s) {
        uint32_t digit = static_cast<uint32_t>(c - '0');
        // result = result * 10 + digit
        uint64_t carry = 0;
        for (size_t i = 0; i < result.size(); ++i) {
            __uint128_t prod = (__uint128_t)result[i] * 10 + carry;
            result[i] = static_cast<Limb>(prod % BASE);
            carry = static_cast<uint64_t>(prod / BASE);
        }
        while (carry) {
            result.push_back(static_cast<Limb>(carry % BASE));
            carry /= BASE;
        }
        if (digit != 0) {
            carry = digit;
            for (size_t i = 0; i < result.size(); ++i) {
                uint64_t sum = static_cast<uint64_t>(result[i]) + carry;
                result[i] = static_cast<Limb>(sum % BASE);
                carry = sum / BASE;
                if (carry == 0) break;
            }
            while (carry) {
                result.push_back(static_cast<Limb>(carry % BASE));
                carry /= BASE;
            }
        }
    }
    return trim(result);
}

std::string to_decimal(const BigInt& a) {
    BigInt temp = trim(a);
    if (temp.size() == 1 && temp[0] == 0) return "0";
    
    std::string result;
    while (!(temp.size() == 1 && temp[0] == 0)) {
        auto dm = divmod_scalar(temp, BASE);
        temp = std::move(dm.first);
        Limb rem = dm.second;
        if (temp.size() == 1 && temp[0] == 0) {
            result = std::to_string(rem) + result;
        } else {
            char buf[10];
            std::snprintf(buf, sizeof(buf), "%09u", rem);
            result = buf + result;
        }
    }
    return result;
}

BigInt from_le_bytes(std::string_view b) {
    if (b.empty()) return BigInt{0};
    // Actually simpler: use 4-byte limbs like E1 but base 10^9
    // We'll convert byte by byte
    BigInt result{0};
    for (size_t i = 0; i < b.size(); ++i) {
        uint8_t byte = static_cast<uint8_t>(b[i]);
        // result += byte * 256^i
        // This is slow but correct; we can optimize by processing in chunks
        BigInt term{0};
        term[0] = byte;
        // Multiply by 256^i
        for (size_t j = 0; j < i; ++j) {
            uint64_t carry = 0;
            for (size_t k = 0; k < term.size(); ++k) {
                __uint128_t prod = (__uint128_t)term[k] * 256 + carry;
                term[k] = static_cast<Limb>(prod % BASE);
                carry = static_cast<uint64_t>(prod / BASE);
            }
            while (carry) {
                term.push_back(static_cast<Limb>(carry % BASE));
                carry /= BASE;
            }
        }
        // Add to result
        uint64_t carry = 0;
        size_t max_size = std::max(result.size(), term.size());
        result.resize(max_size, 0);
        for (size_t k = 0; k < max_size; ++k) {
            uint64_t sum = carry;
            if (k < term.size()) sum += term[k];
            sum += result[k];
            result[k] = static_cast<Limb>(sum % BASE);
            carry = sum / BASE;
        }
        while (carry) {
            result.push_back(static_cast<Limb>(carry % BASE));
            carry /= BASE;
        }
    }
    return trim(result);
}

std::vector<uint8_t> to_le_bytes(const BigInt& a) {
    BigInt temp = trim(a);
    if (temp.size() == 1 && temp[0] == 0) return {};
    
    std::vector<uint8_t> result;
    while (!(temp.size() == 1 && temp[0] == 0)) {
        auto dm = divmod_scalar(temp, 256);
        temp = std::move(dm.first);
        result.push_back(static_cast<uint8_t>(dm.second));
    }
    // Trim trailing zeros
    while (!result.empty() && result.back() == 0) result.pop_back();
    return result;
}

int bit_length(const BigInt& a) {
    BigInt ta = trim(a);
    if (ta.size() == 1 && ta[0] == 0) return 0;
    // Find highest non-zero limb
    uint32_t top = ta.back();
    int bits = 0;
    while (top) {
        top >>= 1;
        bits++;
    }
    return static_cast<int>((ta.size() - 1) * 30 + bits); // ~30 bits per limb (log2(10^9) ≈ 29.9)
}

// ============================================================================
// Arithmetic
// ============================================================================

BigInt add(const BigInt& a, const BigInt& b) {
    BigInt result;
    result.resize(std::max(a.size(), b.size()) + 1, 0);
    uint64_t carry = 0;
    for (size_t i = 0; i < result.size() - 1; ++i) {
        uint64_t ai = i < a.size() ? a[i] : 0;
        uint64_t bi = i < b.size() ? b[i] : 0;
        uint64_t sum = ai + bi + carry;
        result[i] = static_cast<Limb>(sum % BASE);
        carry = sum / BASE;
    }
    result.back() = static_cast<Limb>(carry);
    return trim(result);
}

std::optional<BigInt> sub(const BigInt& a, const BigInt& b) {
    if (compare(a, b) < 0) return std::nullopt;
    BigInt result = a;
    int64_t borrow = 0;
    for (size_t i = 0; i < b.size(); ++i) {
        int64_t diff = static_cast<int64_t>(result[i]) - static_cast<int64_t>(b[i]) - borrow;
        if (diff < 0) {
            diff += BASE;
            borrow = 1;
        } else {
            borrow = 0;
        }
        result[i] = static_cast<Limb>(diff);
    }
    for (size_t i = b.size(); borrow && i < result.size(); ++i) {
        int64_t diff = static_cast<int64_t>(result[i]) - borrow;
        if (diff < 0) {
            diff += BASE;
            borrow = 1;
        } else {
            borrow = 0;
        }
        result[i] = static_cast<Limb>(diff);
    }
    return trim(result);
}

BigInt mul(const BigInt& a, const BigInt& b) {
    if ((a.size() == 1 && a[0] == 0) || (b.size() == 1 && b[0] == 0)) {
        return BigInt{0};
    }
    BigInt result(a.size() + b.size(), 0);
    for (size_t i = 0; i < a.size(); ++i) {
        if (a[i] == 0) continue;
        uint64_t carry = 0;
        for (size_t j = 0; j < b.size(); ++j) {
            __uint128_t prod = (__uint128_t)a[i] * b[j] + result[i + j] + carry;
            result[i + j] = static_cast<Limb>(prod % BASE);
            carry = static_cast<uint64_t>(prod / BASE);
        }
        size_t k = i + b.size();
        while (carry) {
            __uint128_t sum = (__uint128_t)result[k] + carry;
            result[k] = static_cast<Limb>(sum % BASE);
            carry = static_cast<uint64_t>(sum / BASE);
            ++k;
        }
    }
    return trim(result);
}

// ============================================================================
// Division
// ============================================================================

std::pair<BigInt, BigInt> divmod(const BigInt& a, const BigInt& b) {
    BigInt ta = trim(a);
    BigInt tb = trim(b);
    if (tb.size() == 1 && tb[0] == 0) throw std::domain_error("Division by zero");
    
    int cmp = compare(ta, tb);
    if (cmp < 0) return {BigInt{0}, ta};
    if (cmp == 0) return {BigInt{1}, BigInt{0}};
    if (tb.size() == 1) {
        auto dm = divmod_scalar(ta, tb[0]);
        return {std::move(dm.first), BigInt{dm.second}};
    }
    
    // Knuth's Algorithm D (base BASE)
    size_t n = tb.size();
    size_t m = ta.size() - n;
    
    // Normalize: d = BASE / (v_{n-1} + 1)
    uint64_t vn1 = tb[n - 1];
    uint64_t d = BASE / (vn1 + 1);
    
    // v' = d * v
    BigInt vn(n + 1, 0);
    uint64_t carry = 0;
    for (size_t i = 0; i < n; ++i) {
        __uint128_t prod = (__uint128_t)tb[i] * d + carry;
        vn[i] = static_cast<Limb>(prod % BASE);
        carry = static_cast<uint64_t>(prod / BASE);
    }
    vn[n] = static_cast<Limb>(carry);
    vn = trim(vn);
    
    // u' = d * u, padded to m+n+1
    BigInt un(m + n + 1, 0);
    carry = 0;
    for (size_t i = 0; i < ta.size(); ++i) {
        __uint128_t prod = (__uint128_t)ta[i] * d + carry;
        un[i] = static_cast<Limb>(prod % BASE);
        carry = static_cast<uint64_t>(prod / BASE);
    }
    un[ta.size()] = static_cast<Limb>(carry);
    
    BigInt q(m + 1, 0);
    
    for (size_t j = m; ; --j) {
        // Estimate qhat
        uint64_t un_jn = un[j + n];
        uint64_t un_jn1 = un[j + n - 1];
        uint64_t un_jn2 = (j + n - 2 < un.size()) ? un[j + n - 2] : 0;
        uint64_t vn_n1 = vn[n - 1];
        uint64_t vn_n2 = vn[n - 2];
        
        __uint128_t num = (__uint128_t)un_jn * BASE + un_jn1;
        uint64_t qhat = static_cast<uint64_t>(num / vn_n1);
        uint64_t rhat = static_cast<uint64_t>(num % vn_n1);
        
        // Correct qhat downward
        while (qhat >= BASE || (__uint128_t)qhat * vn_n2 > (__uint128_t)rhat * BASE + un_jn2) {
            --qhat;
            rhat += vn_n1;
            if (rhat >= BASE) break;
        }
        
        // Multiply and subtract: un[j..j+n] -= qhat * vn
        int64_t borrow = 0;
        for (size_t i = 0; i < n; ++i) {
            __uint128_t prod = (__uint128_t)qhat * vn[i] + borrow;
            int64_t sub = static_cast<int64_t>(un[j + i]) - static_cast<int64_t>(prod % BASE);
            un[j + i] = static_cast<Limb>((sub % BASE + BASE) % BASE);
            borrow = static_cast<int64_t>(prod / BASE) + (sub < 0 ? 1 : 0);
        }
        int64_t un_jn_orig = static_cast<int64_t>(un[j + n]);
        int64_t sub_top = un_jn_orig - borrow;
        un[j + n] = static_cast<Limb>((sub_top % BASE + BASE) % BASE);
        borrow = (sub_top < 0) ? 1 : 0;
        
        if (borrow != 0) {
            --qhat;
            uint64_t carry_add = 0;
            for (size_t i = 0; i < n; ++i) {
                uint64_t sum = static_cast<uint64_t>(un[j + i]) + vn[i] + carry_add;
                un[j + i] = static_cast<Limb>(sum % BASE);
                carry_add = sum / BASE;
            }
            uint64_t sum_top = un[j + n] + carry_add;
            un[j + n] = static_cast<Limb>(sum_top % BASE);
        }
        q[j] = static_cast<Limb>(qhat);
        if (j == 0) break;
    }
    
    q = trim(q);
    
    // Remainder = un[0..n-1] / d
    BigInt rem_un(n, 0);
    for (size_t i = 0; i < n; ++i) rem_un[i] = un[i];
    rem_un = trim(rem_un);
    
    auto dm = divmod_scalar(rem_un, static_cast<Limb>(d));
    return {std::move(q), std::move(dm.first)};
}

std::pair<BigInt, Limb> divmod_scalar(const BigInt& a, Limb d) {
    if (d == 0) throw std::domain_error("Division by zero");
    BigInt ta = trim(a);
    if (ta.size() == 1 && ta[0] == 0) return {BigInt{0}, 0};
    
    BigInt quotient;
    quotient.resize(ta.size(), 0);
    uint64_t rem = 0;
    for (size_t i = ta.size(); i-- > 0;) {
        uint64_t cur = (rem * BASE) + ta[i];
        quotient[i] = static_cast<Limb>(cur / d);
        rem = cur % d;
    }
    quotient = trim(quotient);
    return {std::move(quotient), static_cast<Limb>(rem)};
}

// ============================================================================
// SHA-256 (FIPS 180-4)
// ============================================================================

static constexpr std::array<uint32_t, 64> K = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static inline uint32_t rotr(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

static void compress(std::array<uint32_t, 8>& state, const uint8_t block[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; ++i) {
        w[i] = (static_cast<uint32_t>(block[4*i]) << 24) |
               (static_cast<uint32_t>(block[4*i+1]) << 16) |
               (static_cast<uint32_t>(block[4*i+2]) << 8) |
               (static_cast<uint32_t>(block[4*i+3]));
    }
    for (int i = 16; i < 64; ++i) {
        uint32_t s0 = rotr(w[i-15], 7) ^ rotr(w[i-15], 18) ^ (w[i-15] >> 3);
        uint32_t s1 = rotr(w[i-2], 17) ^ rotr(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];
    
    for (int i = 0; i < 64; ++i) {
        uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + S1 + ch + K[i] + w[i];
        uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + maj;
        
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

std::array<uint8_t, 32> sha256(std::string_view data) {
    std::array<uint32_t, 8> state = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    std::array<uint8_t, 64> buffer{};
    size_t buffer_len = 0;
    uint64_t total_bits = 0;
    
    const uint8_t* src = reinterpret_cast<const uint8_t*>(data.data());
    size_t len = data.size();
    
    while (len > 0) {
        size_t take = std::min(len, 64 - buffer_len);
        std::memcpy(buffer.data() + buffer_len, src, take);
        buffer_len += take;
        src += take;
        len -= take;
        total_bits += take * 8;
        
        if (buffer_len == 64) {
            compress(state, buffer.data());
            buffer_len = 0;
        }
    }
    
    // Padding
    buffer[buffer_len++] = 0x80;
    if (buffer_len > 56) {
        while (buffer_len < 64) buffer[buffer_len++] = 0;
        compress(state, buffer.data());
        buffer_len = 0;
    }
    while (buffer_len < 56) buffer[buffer_len++] = 0;
    
    // Append length in bits (big-endian)
    for (int i = 7; i >= 0; --i) {
        buffer[buffer_len++] = static_cast<uint8_t>((total_bits >> (8 * i)) & 0xFF);
    }
    compress(state, buffer.data());
    
    std::array<uint8_t, 32> digest;
    for (int i = 0; i < 8; ++i) {
        digest[4*i + 0] = static_cast<uint8_t>((state[i] >> 24) & 0xFF);
        digest[4*i + 1] = static_cast<uint8_t>((state[i] >> 16) & 0xFF);
        digest[4*i + 2] = static_cast<uint8_t>((state[i] >> 8) & 0xFF);
        digest[4*i + 3] = static_cast<uint8_t>(state[i] & 0xFF);
    }
    return digest;
}

// ============================================================================
// CRC-32
// ============================================================================

static constexpr uint32_t CRC32_POLY = 0xEDB88320u;
static constexpr uint32_t CRC32_INIT = 0xFFFFFFFFu;
static constexpr uint32_t CRC32_XOROUT = 0xFFFFFFFFu;

static std::array<uint32_t, 256> build_crc32_table() {
    std::array<uint32_t, 256> table{};
    for (uint32_t i = 0; i < 256; ++i) {
        uint32_t crc = i;
        for (int j = 0; j < 8; ++j) {
            if (crc & 1) crc = (crc >> 1) ^ CRC32_POLY;
            else crc >>= 1;
        }
        table[i] = crc;
    }
    return table;
}

static const std::array<uint32_t, 256>& crc32_table() {
    static const auto table = build_crc32_table();
    return table;
}

uint32_t crc32(std::string_view data) {
    uint32_t crc = CRC32_INIT;
    const uint8_t* bytes = reinterpret_cast<const uint8_t*>(data.data());
    for (size_t i = 0; i < data.size(); ++i) {
        crc = crc32_table()[(crc ^ bytes[i]) & 0xFF] ^ (crc >> 8);
    }
    return crc ^ CRC32_XOROUT;
}

uint32_t crc32_incremental(std::string_view data, uint32_t prev_finalized) {
    // Accept finalized CRC (with xorout), convert to internal state (init=0)
    uint32_t internal = prev_finalized ^ CRC32_INIT;
    const uint8_t* bytes = reinterpret_cast<const uint8_t*>(data.data());
    for (size_t i = 0; i < data.size(); ++i) {
        internal = crc32_table()[(internal ^ bytes[i]) & 0xFF] ^ (internal >> 8);
    }
    // Return finalized CRC
    return internal ^ CRC32_XOROUT;
}

// Combine matrix for CRC-32
static std::array<uint32_t, 32> build_zero_byte_matrix() {
    std::array<uint32_t, 32> mat{};
    for (int i = 0; i < 32; ++i) {
        uint32_t crc = 1u << i;
        // 8 zero bits = process 0 byte with init=0
        for (int j = 0; j < 8; ++j) {
            if (crc & 1) crc = (crc >> 1) ^ CRC32_POLY;
            else crc >>= 1;
        }
        mat[i] = crc;
    }
    return mat;
}

static uint32_t mat_times(const std::array<uint32_t, 32>& mat, uint32_t vec) {
    uint32_t res = 0;
    for (int i = 0; i < 32; ++i) {
        if (vec & 1) res ^= mat[i];
        vec >>= 1;
    }
    return res;
}

static std::array<uint32_t, 32> mat_square(const std::array<uint32_t, 32>& mat) {
    std::array<uint32_t, 32> res{};
    for (int i = 0; i < 32; ++i) {
        res[i] = mat_times(mat, mat[i]);
    }
    return res;
}

static const std::array<std::array<uint32_t, 32>, 32>& combine_matrix() {
    static const auto matrix = []() {
        std::array<std::array<uint32_t, 32>, 32> powers{};
        powers[0] = build_zero_byte_matrix();
        for (int i = 1; i < 32; ++i) {
            powers[i] = mat_square(powers[i-1]);
        }
        return powers;
    }();
    return matrix;
}

uint32_t crc32_combine(uint32_t crc_a, uint32_t crc_b, size_t len_b) {
    // Use zlib's proven crc32_combine.
    // Our crc32() returns standard finalized CRC (init=0xFFFFFFFF, xorout=0xFFFFFFFF)
    // which matches zlib's crc32(0, data, len) return value.
    // zlib's crc32_combine(crc1, crc2, len2) expects:
    //   crc1 = crc32(0, buf1, len1)  (standard finalized)
    //   crc2 = crc32(0, buf2, len2)  (standard finalized)
    //   Returns crc32(0, buf1+buf2, len1+len2) (standard finalized)
    return static_cast<uint32_t>(::crc32_combine(crc_a, crc_b, static_cast<uLong>(len_b)));
}

uint32_t crc32_zeroed(std::string_view data, size_t offset) {
    if (offset + 4 > data.size()) return crc32(data);
    uint32_t crc = CRC32_INIT;
    const uint8_t* bytes = reinterpret_cast<const uint8_t*>(data.data());
    
    for (size_t i = 0; i < offset; ++i) {
        crc = crc32_table()[(crc ^ bytes[i]) & 0xFF] ^ (crc >> 8);
    }
    for (int i = 0; i < 4; ++i) {
        crc = crc32_table()[(crc ^ 0) & 0xFF] ^ (crc >> 8);
    }
    for (size_t i = offset + 4; i < data.size(); ++i) {
        crc = crc32_table()[(crc ^ bytes[i]) & 0xFF] ^ (crc >> 8);
    }
    return crc ^ CRC32_XOROUT;
}

// ============================================================================
// Gear Hash
// ============================================================================

static constexpr uint64_t GEAR_CONST1 = 0x9E3779B97F4A7C15ull;
static constexpr uint64_t GEAR_CONST2 = 0xC2B2AE3D27D4EB4Full;

static const std::array<uint64_t, 256>& gear_table() {
    static const auto table = []() {
        std::array<uint64_t, 256> t{};
        for (int i = 0; i < 256; ++i) {
            t[i] = (static_cast<uint64_t>(i) * GEAR_CONST1) ^ (static_cast<uint64_t>(i) * GEAR_CONST2);
        }
        return t;
    }();
    return table;
}

uint64_t gear_hash(std::string_view data, uint64_t seed) {
    uint64_t state = seed;
    const uint8_t* bytes = reinterpret_cast<const uint8_t*>(data.data());
    const auto& G = gear_table();
    for (size_t i = 0; i < data.size(); ++i) {
        state = (state << 1) + G[bytes[i]];
    }
    return state;
}

// ============================================================================
// Self-check
// ============================================================================

bool self_check() {
    // SHA-256 known vectors
    auto sha_empty = sha256("");
    std::array<uint8_t, 32> expected_empty = {
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
        0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
    };
    if (sha_empty != expected_empty) return false;
    
    auto sha_abc = sha256("abc");
    std::array<uint8_t, 32> expected_abc = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
    };
    if (sha_abc != expected_abc) return false;
    
    // CRC-32 known vectors
    if (crc32("") != 0x00000000u) return false;
    if (crc32("123456789") != 0xCBF43926u) return false;
    if (crc32("abc") != 0x352441C2u) return false;
    
    // CRC-32 incremental property
    std::string a = "Hello, ";
    std::string b = "World!";
    std::string ab = a + b;
    uint32_t crc_a = crc32_incremental(a, CRC32_INIT ^ CRC32_XOROUT); // init=0 finalized
    uint32_t crc_ab = crc32_incremental(ab, CRC32_INIT ^ CRC32_XOROUT);
    uint32_t crc_b_from_a = crc32_incremental(b, crc_a);
    if (crc_b_from_a != crc_ab) return false;
    
    // CRC combine
    uint32_t crc_a_std = crc32(a);
    uint32_t crc_b_std = crc32(b);
    uint32_t crc_ab_std = crc32(ab);
    uint32_t combined = crc32_combine(crc_a_std, crc_b_std, b.size());
    if (combined != crc_ab_std) return false;
    
    // BigInt decimal roundtrip
    std::vector<std::string> test_decimals = {
        "0", "1", "9", "10", "42", "255", "256", "65535", "65536",
        "4294967295", "4294967296", "18446744073709551615",
        "340282366920938463463374607431768211455"
    };
    for (const auto& s : test_decimals) {
        auto parsed = from_decimal(s);
        if (!parsed) return false;
        if (to_decimal(*parsed) != s) return false;
    }
    
    // BigInt a = q*b + r
    for (const auto& sa : test_decimals) {
        for (const auto& sb : test_decimals) {
            auto pa = from_decimal(sa);
            auto pb = from_decimal(sb);
            if (!pa || !pb) continue;
            if (pb->size() == 1 && (*pb)[0] == 0) continue;
            auto dm = divmod(*pa, *pb);
            auto qb = mul(dm.first, *pb);
            auto qbr = add(qb, dm.second);
            if (qbr != *pa) return false;
            if (compare(dm.second, *pb) >= 0) return false;
            if (compare(dm.second, BigInt{0}) < 0) return false;
        }
    }
    
    return true;
}

} // namespace marp::harness::oracle