#include "oracle_internal.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>

namespace marp::oracle::detail {

namespace {

inline constexpr std::array<std::uint32_t, 64> kSha256K = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
    0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
    0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
    0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
    0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
    0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
    0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
    0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
    0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U
};

inline constexpr std::uint32_t rotr32(std::uint32_t x, unsigned n) noexcept {
    return (x >> n) | (x << (32U - n));
}

inline std::uint32_t load_be32(const std::uint8_t* p) noexcept {
    return (static_cast<std::uint32_t>(p[0]) << 24) |
           (static_cast<std::uint32_t>(p[1]) << 16) |
           (static_cast<std::uint32_t>(p[2]) << 8) |
           static_cast<std::uint32_t>(p[3]);
}

inline void store_be32(std::uint8_t* p, std::uint32_t v) noexcept {
    p[0] = static_cast<std::uint8_t>((v >> 24) & 0xFFU);
    p[1] = static_cast<std::uint8_t>((v >> 16) & 0xFFU);
    p[2] = static_cast<std::uint8_t>((v >> 8) & 0xFFU);
    p[3] = static_cast<std::uint8_t>(v & 0xFFU);
}

} // namespace

Sha256::Sha256() noexcept
    : state_{
          0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
          0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U} {}

void Sha256::process_block(const std::uint8_t block[64]) noexcept {
    std::uint32_t w[64];
    for (std::size_t i = 0; i < 16; ++i) {
        w[i] = load_be32(block + i * 4);
    }
    for (std::size_t i = 16; i < 64; ++i) {
        const std::uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        const std::uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    std::uint32_t a = state_[0];
    std::uint32_t b = state_[1];
    std::uint32_t c = state_[2];
    std::uint32_t d = state_[3];
    std::uint32_t e = state_[4];
    std::uint32_t f = state_[5];
    std::uint32_t g = state_[6];
    std::uint32_t h = state_[7];

    for (std::size_t i = 0; i < 64; ++i) {
        const std::uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        const std::uint32_t ch = (e & f) ^ ((~e) & g);
        const std::uint32_t temp1 = h + S1 + ch + kSha256K[i] + w[i];
        const std::uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        const std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        const std::uint32_t temp2 = S0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    state_[0] += a;
    state_[1] += b;
    state_[2] += c;
    state_[3] += d;
    state_[4] += e;
    state_[5] += f;
    state_[6] += g;
    state_[7] += h;
}

void Sha256::update(std::span<const std::uint8_t> data) noexcept {
    const std::uint64_t n = static_cast<std::uint64_t>(data.size());
    const std::uint64_t prev_lo = total_bytes_lo_;
    total_bytes_lo_ += n;
    if (total_bytes_lo_ < prev_lo) {
        ++total_bytes_hi_;
    }

    std::size_t pos = 0;
    if (buf_len_ > 0) {
        const std::size_t take = std::min(64 - buf_len_, data.size());
        std::memcpy(buf_.data() + buf_len_, data.data(), take);
        buf_len_ += take;
        pos += take;
        if (buf_len_ == 64) {
            process_block(buf_.data());
            buf_len_ = 0;
        }
    }

    while (pos + 64 <= data.size()) {
        process_block(data.data() + pos);
        pos += 64;
    }

    if (pos < data.size()) {
        const std::size_t rem = data.size() - pos;
        std::memcpy(buf_.data(), data.data() + pos, rem);
        buf_len_ = rem;
    }
}

std::array<std::uint8_t, 32> Sha256::finalize() noexcept {
    // FIPS 180-4 bit length (low 64 bits of total_bytes * 8)
    const std::uint64_t bit_len = total_bytes_lo_ << 3;

    buf_[buf_len_++] = 0x80U;
    if (buf_len_ > 56) {
        std::memset(buf_.data() + buf_len_, 0, 64 - buf_len_);
        process_block(buf_.data());
        buf_len_ = 0;
    }
    std::memset(buf_.data() + buf_len_, 0, 56 - buf_len_);

    store_be32(buf_.data() + 56, static_cast<std::uint32_t>(bit_len >> 32));
    store_be32(buf_.data() + 60, static_cast<std::uint32_t>(bit_len & 0xFFFFFFFFULL));
    process_block(buf_.data());
    buf_len_ = 0;

    std::array<std::uint8_t, 32> out{};
    for (std::size_t i = 0; i < 8; ++i) {
        store_be32(out.data() + i * 4, state_[i]);
    }
    return out;
}

std::string Sha256::to_hex(const std::array<std::uint8_t, 32>& digest) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string s;
    s.reserve(64);
    for (std::uint8_t b : digest) {
        s.push_back(kHex[(b >> 4) & 0x0FU]);
        s.push_back(kHex[b & 0x0FU]);
    }
    return s;
}

} // namespace marp::oracle::detail

namespace marp::oracle {

std::array<std::uint8_t, 32> sha256_bytes(std::span<const std::uint8_t> data) {
    detail::Sha256 h;
    h.update(data);
    return h.finalize();
}

std::string sha256_hex(std::span<const std::uint8_t> data) {
    return detail::Sha256::to_hex(sha256_bytes(data));
}

} // namespace marp::oracle
