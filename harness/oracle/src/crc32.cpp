#include "oracle_internal.hpp"

#include <array>
#include <cstdint>

namespace marp::oracle::detail {

namespace {

constexpr std::array<std::uint32_t, 256> make_crc32_table() noexcept {
    std::array<std::uint32_t, 256> tbl{};
    for (std::uint32_t i = 0; i < 256; ++i) {
        std::uint32_t c = i;
        for (int k = 0; k < 8; ++k) {
            if ((c & 1U) != 0U) {
                c = 0xEDB88320U ^ (c >> 1);
            } else {
                c >>= 1;
            }
        }
        tbl[i] = c;
    }
    return tbl;
}

inline constexpr std::array<std::uint32_t, 256> kCrc32Table = make_crc32_table();

} // namespace

void Crc32::update(std::span<const std::uint8_t> data) noexcept {
    std::uint32_t c = state_;
    for (std::uint8_t b : data) {
        c = kCrc32Table[(c ^ b) & 0xFFU] ^ (c >> 8);
    }
    state_ = c;
}

} // namespace marp::oracle::detail

namespace marp::oracle {

std::uint32_t crc32_bytes(std::span<const std::uint8_t> data) {
    detail::Crc32 crc;
    crc.update(data);
    return crc.value();
}

} // namespace marp::oracle
