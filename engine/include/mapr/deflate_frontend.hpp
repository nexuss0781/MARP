#pragma once
#include <cstdint>
#include <cstddef>
#include <vector>

namespace mapr {

enum class DeflateType { NONE, ZLIB, GZIP, RAW };

struct DeflateBlock {
    size_t offset_bits = 0;
    size_t length_bits = 0;
    bool bfinal = false;
    uint8_t btype = 0; // 0=stored, 1=fixed, 2=dynamic
};

struct DeflateInfo {
    bool detected = false;
    DeflateType type = DeflateType::NONE;
    size_t header_size = 0;
    size_t trailer_size = 0;
    size_t data_offset = 0;
    size_t data_len = 0;
    // zlib/gzip metadata
    uint8_t cm = 0, flg = 0, xfl = 0, os = 0;
    uint32_t mtime = 0;
    std::vector<DeflateBlock> blocks;
};

DeflateInfo detect_deflate(const uint8_t* data, size_t len);
bool parse_deflate_blocks(const uint8_t* data, size_t len, std::vector<DeflateBlock>& blocks);

} // namespace mapr
