#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace mapr {

// IEEE 802.3 CRC-32 (polynomial 0xEDB88320, initial 0xFFFFFFFF, final XOR 0xFFFFFFFF)
uint32_t crc32_update(uint32_t crc_inv, const uint8_t* data, size_t len) noexcept;

inline uint32_t crc32_compute(const uint8_t* data, size_t len) noexcept {
    return crc32_update(0xFFFFFFFFu, data, len) ^ 0xFFFFFFFFu;
}

// FIPS 180-4 Streaming SHA-256
class Sha256 {
public:
    Sha256() noexcept { reset(); }
    void reset() noexcept;
    void update(const uint8_t* data, size_t len) noexcept;
    std::array<uint8_t, 32> finalize() noexcept;

    static std::array<uint8_t, 32> hash(const uint8_t* data, size_t len) noexcept {
        Sha256 s;
        s.update(data, len);
        return s.finalize();
    }

    static std::string to_hex(const std::array<uint8_t, 32>& digest);

private:
    void transform(const uint8_t block[64]) noexcept;

    uint32_t state_[8];
    uint64_t total_bytes_;
    uint8_t buf_[64];
    size_t buf_len_;
};

} // namespace mapr
