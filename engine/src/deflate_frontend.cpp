// =====================================================================
//  MARP  ::  Stage 2  ::  DEFLATE-aware front end  ::  deflate_frontend.cpp
//
//  Detects zlib (RFC 1950), gzip (RFC 1952), raw deflate (RFC 1951)
//  framing and parses block boundaries. Exposes DEFLATE_HINT metadata.
//  Does NOT attempt to beat DEFLATE on already-deflated data.
// =====================================================================

#include "mapr/deflate_frontend.hpp"
#include <algorithm>
#include <cstring>

namespace mapr {

static bool read_le16(const uint8_t* p, uint16_t& v) {
    v = (uint16_t)p[0] | ((uint16_t)p[1] << 8);
    return true;
}

DeflateInfo detect_deflate(const uint8_t* data, size_t len) {
    DeflateInfo info;
    if (len < 2) return info;

    // zlib (RFC 1950): CMF+FLG, CMF&0x0F==8, (CMF*256+FLG)%31==0
    if (len >= 6) {
        uint8_t cmf = data[0];
        uint8_t flg = data[1];
        uint8_t cm = cmf & 0x0F;
        if (cm == 8 && ((cmf * 256u + flg) % 31u == 0u)) {
            info.detected = true;
            info.type = DeflateType::ZLIB;
            info.header_size = 2;
            info.cm = cmf;
            info.flg = flg;
            if (flg & 0x20) info.header_size += 4; // FDICT
            // trailer: 4-byte Adler32
            if (len >= info.header_size + 4) info.trailer_size = 4;
            info.data_offset = info.header_size;
            info.data_len = (len > info.header_size + info.trailer_size)
                            ? len - info.header_size - info.trailer_size : 0;
            return info;
        }
    }

    // gzip (RFC 1952): ID1=0x1f, ID2=0x8b, CM=8
    if (len >= 18 && data[0] == 0x1f && data[1] == 0x8b && data[2] == 0x08) {
        info.detected = true;
        info.type = DeflateType::GZIP;
        info.cm = data[2];
        info.flg = data[3];
        info.mtime = (uint32_t)data[4] | ((uint32_t)data[5] << 8) |
                     ((uint32_t)data[6] << 16) | ((uint32_t)data[7] << 24);
        info.xfl = data[8];
        info.os = data[9];
        size_t off = 10;
        uint8_t flg = data[3];
        if (flg & 0x04) { // FEXTRA
            if (off + 2 > len) return info;
            uint16_t xlen; read_le16(data + off, xlen);
            off += 2 + xlen;
        }
        if (flg & 0x08) { // FNAME
            while (off < len && data[off] != 0) off++;
            if (off < len) off++;
        }
        if (flg & 0x10) { // FCOMMENT
            while (off < len && data[off] != 0) off++;
            if (off < len) off++;
        }
        if (flg & 0x02) { // FHCRC
            if (off + 2 <= len) off += 2;
        }
        info.header_size = off;
        info.trailer_size = 8; // CRC32 + ISIZE
        info.data_offset = off;
        info.data_len = (len > off + 8) ? len - off - 8 : 0;
        return info;
    }

    // Raw deflate (RFC 1951): try to parse first block header
    // BFINAL(1) + BTYPE(2): valid BTYPE 00,01,10
    {
        uint8_t first_byte = data[0];
        uint8_t btype = (first_byte >> 1) & 0x03;
        if (btype <= 2) {
            // Heuristic: attempt to parse as raw deflate
            if (parse_deflate_blocks(data, len, info.blocks)) {
                info.detected = true;
                info.type = DeflateType::RAW;
                info.header_size = 0;
                info.trailer_size = 0;
                info.data_offset = 0;
                info.data_len = len;
                return info;
            }
        }
    }

    return info;
}

bool parse_deflate_blocks(const uint8_t* data, size_t len, std::vector<DeflateBlock>& blocks) {
    blocks.clear();
    if (len == 0) return false;
    size_t bit_pos = 0; // bit position in stream (LSB-first within bytes)
    size_t total_bits = len * 8;
    int safety = 0;

    auto read_bits = [&](int n, uint32_t& out) -> bool {
        if (bit_pos + n > total_bits) return false;
        out = 0;
        for (int i = 0; i < n; ++i) {
            size_t byte_idx = bit_pos / 8;
            int bit_idx = bit_pos % 8;
            out |= ((data[byte_idx] >> bit_idx) & 1u) << i;
            bit_pos++;
        }
        return true;
    };

    auto align_byte = [&]() {
        if (bit_pos % 8 != 0) bit_pos = (bit_pos / 8 + 1) * 8;
    };

    while (bit_pos < total_bits && safety++ < 100000) {
        uint32_t bfinal, btype;
        if (!read_bits(1, bfinal)) break;
        if (!read_bits(2, btype)) break;

        DeflateBlock blk;
        blk.offset_bits = bit_pos - 3;
        blk.bfinal = (bfinal != 0);
        blk.btype = (uint8_t)btype;

        if (btype == 0) { // stored
            align_byte();
            size_t byte_pos = bit_pos / 8;
            if (byte_pos + 4 > len) return false;
            uint16_t stored_len, nlen;
            read_le16(data + byte_pos, stored_len);
            read_le16(data + byte_pos + 2, nlen);
            if ((uint16_t)(~stored_len) != nlen) return false;
            bit_pos = (byte_pos + 4 + stored_len) * 8;
            blk.length_bits = stored_len * 8;
        } else if (btype == 1) { // fixed Huffman
            // Decode fixed Huffman until end-of-block symbol (256)
            // Fixed: lit/len 0-143: 8 bits (00110000+), 144-255: 9 bits (110010000+),
            // 256-279: 7 bits (0000000+), 280-287: 8 bits (11000000+)
            // Dist: 5 bits
            bool eob = false;
            int sym_safety = 0;
            while (!eob && sym_safety++ < 10000000) {
                // Read enough bits for Huffman decode (max 9)
                // Fixed Huffman is well-defined; simplified: scan for EOB
                // We read symbol by symbol per RFC 1951 §3.2.6
                uint32_t sym = 0;
                // Try 7-bit codes first (256-279): 0000000..0010111
                uint32_t b7 = 0;
                // Peek 7 bits
                size_t saved = bit_pos;
                if (!read_bits(7, b7)) return false;
                // Reverse bits for Huffman comparison
                uint32_t rev7 = 0;
                for (int i = 0; i < 7; ++i) rev7 = (rev7 << 1) | ((b7 >> i) & 1);
                if (rev7 <= 0x17) { // 0000000-0010111 => 256-279
                    sym = 256 + rev7;
                } else {
                    // Try 8-bit
                    bit_pos = saved;
                    uint32_t b8 = 0;
                    if (!read_bits(8, b8)) return false;
                    uint32_t rev8 = 0;
                    for (int i = 0; i < 8; ++i) rev8 = (rev8 << 1) | ((b8 >> i) & 1);
                    if (rev8 >= 0x30 && rev8 <= 0xBF) { // 00110000-10111111 => 0-143
                        sym = rev8 - 0x30;
                    } else if (rev8 >= 0xC0 && rev8 <= 0xC7) { // 11000000-11000111 => 280-287
                        sym = 280 + (rev8 - 0xC0);
                    } else {
                        // Try 9-bit
                        bit_pos = saved;
                        uint32_t b9 = 0;
                        if (!read_bits(9, b9)) return false;
                        uint32_t rev9 = 0;
                        for (int i = 0; i < 9; ++i) rev9 = (rev9 << 1) | ((b9 >> i) & 1);
                        if (rev9 >= 0x190 && rev9 <= 0x1FF) { // 110010000-111111111 => 144-255
                            sym = 144 + (rev9 - 0x190);
                        } else {
                            return false; // invalid fixed Huffman
                        }
                    }
                }
                if (sym == 256) { eob = true; break; }
                if (sym < 256) continue; // literal
                if (sym <= 285) {
                    // length code: read extra bits
                    static const int len_extra[29] = {0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0};
                    int idx = (int)sym - 257;
                    if (idx >= 0 && idx < 29 && len_extra[idx] > 0) {
                        uint32_t extra; if (!read_bits(len_extra[idx], extra)) return false;
                    }
                    // distance: 5-bit fixed
                    uint32_t dist_code; if (!read_bits(5, dist_code)) return false;
                    uint32_t rev5 = 0;
                    for (int i = 0; i < 5; ++i) rev5 = (rev5 << 1) | ((dist_code >> i) & 1);
                    // distance extra bits
                    static const int dist_extra[30] = {0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13};
                    int di = (int)rev5;
                    if (di >= 0 && di < 30 && dist_extra[di] > 0) {
                        uint32_t dextra; if (!read_bits(dist_extra[di], dextra)) return false;
                    }
                } else {
                    return false; // invalid
                }
            }
            blk.length_bits = bit_pos - blk.offset_bits - 3;
        } else if (btype == 2) { // dynamic Huffman
            uint32_t hlit, hdist, hclen;
            if (!read_bits(5, hlit)) return false;
            if (!read_bits(5, hdist)) return false;
            if (!read_bits(4, hclen)) return false;
            hlit += 257; hdist += 1; hclen += 4;
            if (hlit > 286 || hdist > 32) return false;
            static const int clen_order[19] = {16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15};
            std::vector<uint8_t> clen(19, 0);
            for (uint32_t k = 0; k < hclen; ++k) {
                uint32_t v; if (!read_bits(3, v)) return false;
                clen[clen_order[k]] = (uint8_t)v;
            }

            struct SymCode { int len; int code; uint32_t sym; };
            auto build_codes = [](const std::vector<uint8_t>& lengths, uint32_t n, std::vector<SymCode>& codes, std::vector<int>& tbits, std::vector<uint16_t>& tval, int& maxb) -> bool {
                maxb = 0;
                std::vector<int> bl_count(16, 0);
                for (uint32_t k = 0; k < n; ++k) {
                    if (lengths[k] > 15) return false;
                    bl_count[lengths[k]]++;
                    if (lengths[k] > maxb) maxb = lengths[k];
                }
                bl_count[0] = 0;
                std::vector<int> next_code(16, 0);
                int code = 0;
                for (int bits = 1; bits <= 15; ++bits) { code = (code + bl_count[bits - 1]) << 1; next_code[bits] = code; }
                codes.clear();
                tbits.assign(512, 0); tval.assign(512, 0);
                for (uint32_t sym = 0; sym < n; ++sym) {
                    int lenb = lengths[sym]; if (!lenb) continue;
                    int c = next_code[lenb]++;
                    int rev = 0; for (int i = 0; i < lenb; ++i) if (c & (1 << i)) rev |= 1 << (lenb - 1 - i);
                    codes.push_back({lenb, c, sym});
                    if (lenb <= 9) {
                        int fill = 1 << (9 - lenb);
                        for (int j = 0; j < fill; ++j) {
                            int idx = rev | (j << lenb);
                            if (idx >= 0 && idx < 512) { tbits[idx] = lenb; tval[idx] = (uint16_t)sym; }
                        }
                    }
                }
                return true;
            };

            auto decode_sym = [&](const std::vector<SymCode>& codes, const std::vector<int>& tbits, const std::vector<uint16_t>& tval, int maxb, uint32_t& out) -> bool {
                size_t saved = bit_pos;
                if (maxb > 0 && maxb <= 9 && tbits.size() == 512 && bit_pos + 9 <= total_bits) {
                    uint32_t b = 0; if (!read_bits(9, b)) { bit_pos = saved; return false; }
                    if (b < tbits.size() && tbits[b]) { bit_pos = saved + tbits[b]; out = tval[b]; return true; }
                }
                bit_pos = saved;
                for (int lenb = 1; lenb <= 15; ++lenb) {
                    if (bit_pos + (size_t)lenb > total_bits) { bit_pos = saved; return false; }
                    bit_pos = saved; uint32_t bb = 0; if (!read_bits(lenb, bb)) { bit_pos = saved; return false; }
                    int rev = 0; for (int i = 0; i < lenb; ++i) if (bb & (1u << i)) rev |= 1 << (lenb - 1 - i);
                    for (const auto& cc : codes) if (cc.len == lenb && cc.code == rev) { out = cc.sym; return true; }
                }
                bit_pos = saved;
                return false;
            };

            std::vector<SymCode> clen_codes; std::vector<int> clen_tbits; std::vector<uint16_t> clen_tval; int clen_max = 0;
            if (!build_codes(clen, 19, clen_codes, clen_tbits, clen_tval, clen_max)) return false;
            if (clen_max == 0) return false;

            std::vector<uint8_t> all_lens(hlit + hdist, 0);
            uint32_t idx2 = 0;
            while (idx2 < hlit + hdist) {
                uint32_t sym; if (!decode_sym(clen_codes, clen_tbits, clen_tval, clen_max, sym)) return false;
                if (sym <= 15) { all_lens[idx2++] = (uint8_t)sym; }
                else if (sym == 16) {
                    if (idx2 == 0) return false;
                    uint32_t rep; if (!read_bits(2, rep)) return false; rep += 3;
                    uint8_t prev = all_lens[idx2 - 1];
                    while (rep-- && idx2 < hlit + hdist) all_lens[idx2++] = prev;
                } else if (sym == 17) {
                    uint32_t rep; if (!read_bits(3, rep)) return false; rep += 3;
                    while (rep-- && idx2 < hlit + hdist) all_lens[idx2++] = 0;
                } else if (sym == 18) {
                    uint32_t rep; if (!read_bits(7, rep)) return false; rep += 11;
                    while (rep-- && idx2 < hlit + hdist) all_lens[idx2++] = 0;
                } else return false;
            }

            std::vector<uint8_t> lit_lens(all_lens.begin(), all_lens.begin() + hlit);
            std::vector<uint8_t> dist_lens(all_lens.begin() + hlit, all_lens.end());
            std::vector<SymCode> lit_codes, dist_codes; std::vector<int> lit_tbits, dist_tbits; std::vector<uint16_t> lit_tval, dist_tval; int lit_max = 0, dist_max = 0;
            if (!build_codes(lit_lens, hlit, lit_codes, lit_tbits, lit_tval, lit_max)) return false;
            if (!build_codes(dist_lens, hdist, dist_codes, dist_tbits, dist_tval, dist_max)) return false;

            bool eob = false; int sym_safety = 0;
            while (!eob && sym_safety++ < 20000000) {
                uint32_t sym; if (!decode_sym(lit_codes, lit_tbits, lit_tval, lit_max, sym)) return false;
                if (sym == 256) { eob = true; break; }
                if (sym < 256) continue;
                if (sym <= 285) {
                    static const int len_extra[29] = {0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0};
                    int lidx = (int)sym - 257;
                    if (lidx >= 0 && lidx < 29 && len_extra[lidx] > 0) { uint32_t ex; if (!read_bits(len_extra[lidx], ex)) return false; }
                    uint32_t dsym; if (!decode_sym(dist_codes, dist_tbits, dist_tval, dist_max, dsym)) return false;
                    static const int dist_extra[30] = {0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13};
                    if (dsym < 30 && dist_extra[dsym] > 0) { uint32_t dex; if (!read_bits(dist_extra[dsym], dex)) return false; }
                } else return false;
            }
            if (!eob) return false;
            blk.length_bits = bit_pos - blk.offset_bits - 3;
        } else {
            return false; // invalid BTYPE 11
        }

        blocks.push_back(blk);
        if (blk.bfinal) break;
    }

    return !blocks.empty();
}

} // namespace mapr
