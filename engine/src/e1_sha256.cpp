#include "mapr/e1_sha256.hpp"
#include <cstring>

namespace mapr {

constexpr uint32_t Sha256::rotr(uint32_t x, int n) noexcept {
    return (x >> n) | (x << (32 - n));
}

void Sha256::compress(std::array<uint32_t, 8>& state, const uint8_t block[64]) noexcept {
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

        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

Sha256::Sha256() noexcept {
    reset();
}

void Sha256::reset() noexcept {
    state_ = IV;
    buffer_len_ = 0;
    total_bits_ = 0;
}

ErrCode Sha256::update(std::string_view data) noexcept {
    // Check limit: total_bits + 8*len < 2^64 (Math-SPECS C2)
    uint64_t add_bits = static_cast<uint64_t>(data.size()) * 8;
    if (total_bits_ > UINT64_MAX - add_bits) return ErrCode::Limit;

    total_bits_ += add_bits;
    const uint8_t* src = reinterpret_cast<const uint8_t*>(data.data());
    size_t len = data.size();

    // Fill existing buffer
    if (buffer_len_ > 0) {
        size_t take = std::min(len, 64 - buffer_len_);
        std::memcpy(buffer_.data() + buffer_len_, src, take);
        buffer_len_ += take;
        src += take;
        len -= take;
        if (buffer_len_ == 64) {
            compress(state_, buffer_.data());
            buffer_len_ = 0;
        }
    }

    // Process full blocks
    while (len >= 64) {
        compress(state_, src);
        src += 64;
        len -= 64;
    }

    // Remainder to buffer
    if (len > 0) {
        std::memcpy(buffer_.data(), src, len);
        buffer_len_ = len;
    }
    return ErrCode::Ok;
}

Result<std::array<uint8_t, 32>> Sha256::finish() noexcept {
    // Padding (Math-SPECS C2): 0x80, zeros, 64-bit length in bits (big-endian)
    size_t pad_len = (56 - (buffer_len_ + 1) % 64) % 64;

    // First, append 0x80
    buffer_[buffer_len_] = 0x80;
    buffer_len_++;

    // Append zeros
    if (buffer_len_ + pad_len > 64) {
        std::fill(buffer_.data() + buffer_len_, buffer_.data() + 64, 0);
        compress(state_, buffer_.data());
        buffer_len_ = 0;
        if (pad_len > 0) {
            std::fill(buffer_.data(), buffer_.data() + pad_len, 0);
            buffer_len_ = pad_len;
        }
    } else {
        std::fill(buffer_.data() + buffer_len_, buffer_.data() + buffer_len_ + pad_len, 0);
        buffer_len_ += pad_len;
    }

    // Append 64-bit length (big-endian)
    for (int i = 7; i >= 0; --i) {
        buffer_[buffer_len_++] = static_cast<uint8_t>((total_bits_ >> (8 * i)) & 0xFF);
    }

    // Final block
    compress(state_, buffer_.data());

    // Output digest
    std::array<uint8_t, 32> digest;
    for (int i = 0; i < 8; ++i) {
        digest[4*i + 0] = static_cast<uint8_t>((state_[i] >> 24) & 0xFF);
        digest[4*i + 1] = static_cast<uint8_t>((state_[i] >> 16) & 0xFF);
        digest[4*i + 2] = static_cast<uint8_t>((state_[i] >> 8) & 0xFF);
        digest[4*i + 3] = static_cast<uint8_t>(state_[i] & 0xFF);
    }

    // Reset state
    reset();
    return digest;
}

Result<std::array<uint8_t, 32>> Sha256::hash(std::string_view data) noexcept {
    Sha256 ctx;
    ErrCode err = ctx.update(data);
    if (err != ErrCode::Ok) return err;
    return ctx.finish();
}

} // namespace mapr