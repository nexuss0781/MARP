#include "mapr/container.hpp"
#include "mapr/bitio.hpp"
#include <cstring>
#include <stdexcept>
#include <algorithm>

namespace mapr {

ContainerWriter::ContainerWriter(const std::string& path, const StreamConfig& cfg, bool raw_bytes_mode)
    : out_file_(path, std::ios::binary | std::ios::trunc), out_buffer_(nullptr), cfg_(cfg) {
    if (!out_file_) throw std::runtime_error("Cannot open output .mapr file: " + path);
    if (!cfg_.valid()) throw std::invalid_argument("Invalid StreamConfig");
    base_flags_ = FLAG_HAS_INDEX | (raw_bytes_mode ? FLAG_RAW_BYTES_MSB : 0u);
    write_header_block(0, 0, 0, true);
    cur_offset_ = 64;
}

ContainerWriter::ContainerWriter(std::vector<uint8_t>& out_buffer, const StreamConfig& cfg, bool raw_bytes_mode)
    : out_buffer_(&out_buffer), cfg_(cfg) {
    if (!cfg_.valid()) throw std::invalid_argument("Invalid StreamConfig");
    base_flags_ = FLAG_HAS_INDEX | (raw_bytes_mode ? FLAG_RAW_BYTES_MSB : 0u);
    write_header_block(0, 0, 0, true);
    cur_offset_ = 64;
}

void ContainerWriter::write_bytes(const void* data, size_t size) {
    if (out_buffer_) {
        const uint8_t* src = static_cast<const uint8_t*>(data);
        out_buffer_->insert(out_buffer_->end(), src, src + size);
    } else {
        out_file_.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(size));
        if (!out_file_) throw std::runtime_error("Failed writing to .mapr file");
    }
}

void ContainerWriter::write_header_block(uint64_t total_bits, uint64_t chunk_count,
                                         uint64_t index_offset, bool streamed_flag) {
    uint8_t hdr[64]{};
    std::memcpy(hdr, MAPR_MAGIC, 8);
    write_le16(hdr + 8, 1);
    write_le16(hdr + 10, 0);
    uint32_t flags = base_flags_ | (streamed_flag ? FLAG_STREAMED_HEADER : 0u);
    write_le32(hdr + 12, flags);
    write_le64(hdr + 16, total_bits);
    write_le64(hdr + 24, chunk_count);
    write_le32(hdr + 32, cfg_.w_sync);
    write_le32(hdr + 36, cfg_.l_min);
    write_le32(hdr + 40, cfg_.l_target);
    write_le32(hdr + 44, cfg_.l_max);
    write_le32(hdr + 48, cfg_.w_hist);
    write_le64(hdr + 52, index_offset);
    uint32_t crc = crc32_compute(hdr, 60);
    write_le32(hdr + 60, crc);
    write_bytes(hdr, 64);
}

void ContainerWriter::write_chunk_ref(uint32_t chunk_idx, uint64_t bit_offset, uint32_t bit_len,
                                      uint32_t ref_target, V4Op mu) {
    uint8_t fhdr[32]{};
    std::memcpy(fhdr, "MCHK", 4);
    write_le32(fhdr + 4, chunk_idx);
    write_le64(fhdr + 8, bit_offset);
    write_le32(fhdr + 16, bit_len);
    fhdr[20] = KIND_CHUNK_REF;
    fhdr[21] = static_cast<uint8_t>(mu);
    write_le16(fhdr + 22, 0);
    write_le32(fhdr + 24, 4u);

    uint8_t payload[4];
    write_le32(payload, ref_target);

    uint32_t crc = crc32_update(0xFFFFFFFFu, fhdr, 28);
    crc = crc32_update(crc, payload, 4) ^ 0xFFFFFFFFu;
    write_le32(fhdr + 28, crc);

    uint64_t foff = cur_offset_;
    write_bytes(fhdr, 32);
    write_bytes(payload, 4);
    cur_offset_ += 36;

    index_.push_back(IndexEntry{foff, bit_offset, bit_len, 36u, ref_target, KIND_CHUNK_REF, static_cast<uint8_t>(mu)});
}

void ContainerWriter::write_explicit_dag(uint32_t chunk_idx, uint64_t bit_offset, uint32_t bit_len,
                                         const std::vector<uint8_t>& payload) {
    if (payload.empty() || payload.size() > 0x7FFFFFFFu) {
        throw std::invalid_argument("Invalid DAG payload byte length");
    }
    uint8_t fhdr[32]{};
    std::memcpy(fhdr, "MCHK", 4);
    write_le32(fhdr + 4, chunk_idx);
    write_le64(fhdr + 8, bit_offset);
    write_le32(fhdr + 16, bit_len);
    fhdr[20] = KIND_EXPLICIT_DAG;
    fhdr[21] = 0u;
    write_le16(fhdr + 22, 0);
    write_le32(fhdr + 24, static_cast<uint32_t>(payload.size()));

    uint32_t crc = crc32_update(0xFFFFFFFFu, fhdr, 28);
    crc = crc32_update(crc, payload.data(), payload.size()) ^ 0xFFFFFFFFu;
    write_le32(fhdr + 28, crc);

    uint64_t foff = cur_offset_;
    write_bytes(fhdr, 32);
    write_bytes(payload.data(), payload.size());
    uint32_t fbytes = static_cast<uint32_t>(32u + payload.size());
    cur_offset_ += fbytes;

    index_.push_back(IndexEntry{foff, bit_offset, bit_len, fbytes, chunk_idx, KIND_EXPLICIT_DAG, 0u});
}

uint64_t ContainerWriter::finish(uint64_t total_bits, const std::array<uint8_t, 32>& stream_sha256) {
    uint64_t K = index_.size();
    uint64_t idx_off = cur_offset_;

    // Write INDX block
    uint8_t ihdr[16]{};
    std::memcpy(ihdr, "INDX", 4);
    write_le32(ihdr + 4, 32u);
    write_le64(ihdr + 8, K);

    uint32_t icrc = crc32_update(0xFFFFFFFFu, ihdr, 16);
    write_bytes(ihdr, 16);
    cur_offset_ += 16;

    for (const auto& e : index_) {
        uint8_t eb[32]{};
        write_le64(eb + 0, e.file_offset);
        write_le64(eb + 8, e.bit_offset);
        write_le32(eb + 16, e.bit_len);
        write_le32(eb + 20, e.frame_bytes);
        write_le32(eb + 24, e.ref_target);
        eb[28] = e.chunk_kind;
        eb[29] = e.v4_op;
        write_le16(eb + 30, 0);
        icrc = crc32_update(icrc, eb, 32);
        write_bytes(eb, 32);
        cur_offset_ += 32;
    }
    icrc ^= 0xFFFFFFFFu;
    uint8_t icrc_b[4];
    write_le32(icrc_b, icrc);
    write_bytes(icrc_b, 4);
    cur_offset_ += 4;

    // Write 72-byte TRLR block
    uint8_t trlr[72]{};
    std::memcpy(trlr + 0, "TRLR", 4);
    write_le32(trlr + 4, 0x00000001u);
    write_le64(trlr + 8, total_bits);
    write_le64(trlr + 16, K);
    write_le64(trlr + 24, idx_off);
    std::memcpy(trlr + 32, stream_sha256.data(), 32);
    std::memcpy(trlr + 64, "ENDM", 4);
    uint32_t tcrc = crc32_compute(trlr, 68);
    write_le32(trlr + 68, tcrc);
    write_bytes(trlr, 72);
    cur_offset_ += 72;

    // Backfill header if seekable (file only)
    if (!out_buffer_) {
        out_file_.seekp(0, std::ios::beg);
        if (out_file_.good()) {
            write_header_block(total_bits, K, idx_off, false);
        }
        out_file_.flush();
        out_file_.close();
    } else {
        // For memory buffer, directly overwrite the first 64 bytes
        uint8_t hdr[64]{};
        std::memcpy(hdr, MAPR_MAGIC, 8);
        write_le16(hdr + 8, 1);
        write_le16(hdr + 10, 0);
        uint32_t flags = base_flags_; // streamed_flag = false for final
        write_le32(hdr + 12, flags);
        write_le64(hdr + 16, total_bits);
        write_le64(hdr + 24, K);
        write_le32(hdr + 32, cfg_.w_sync);
        write_le32(hdr + 36, cfg_.l_min);
        write_le32(hdr + 40, cfg_.l_target);
        write_le32(hdr + 44, cfg_.l_max);
        write_le32(hdr + 48, cfg_.w_hist);
        write_le64(hdr + 52, idx_off);
        uint32_t crc = crc32_compute(hdr, 60);
        write_le32(hdr + 60, crc);
        std::copy_n(hdr, 64, out_buffer_->begin());
    }
    return cur_offset_;
}

ContainerReader::ContainerReader(const std::string& path)
    : in_(path, std::ios::binary) {
    if (!in_) throw std::runtime_error("Cannot open .mapr file: " + path);
    in_.seekg(0, std::ios::end);
    auto endp = in_.tellg();
    if (endp < 192) throw std::runtime_error("File too small to be a valid .mapr v1.0 container");
    file_size_ = static_cast<uint64_t>(endp);
    parse_and_verify_structure();
}

void ContainerReader::parse_and_verify_structure() {
    // 1. Read & verify 64-byte header
    in_.seekg(0, std::ios::beg);
    uint8_t hdr[64];
    in_.read(reinterpret_cast<char*>(hdr), 64);
    if (in_.gcount() != 64) throw std::runtime_error("Truncated .mapr header");
    if (std::memcmp(hdr, MAPR_MAGIC, 8) != 0) throw std::runtime_error("Invalid .mapr magic signature");
    uint32_t hcrc_expected = read_le32(hdr + 60);
    if (crc32_compute(hdr, 60) != hcrc_expected) throw std::runtime_error("Header CRC-32 mismatch");

    meta_.version_major = read_le16(hdr + 8);
    meta_.version_minor = read_le16(hdr + 10);
    if (meta_.version_major != 1) throw std::runtime_error("Unsupported .mapr major version");

    meta_.flags = read_le32(hdr + 12);
    if ((meta_.flags & ~0x00000007u) != 0u) {
        throw std::runtime_error("Non-zero reserved or unknown flags in .mapr v1.0 header");
    }
    if ((meta_.flags & FLAG_HAS_INDEX) == 0u) {
        throw std::runtime_error("Missing mandatory FLAG_HAS_INDEX in .mapr v1.0 header");
    }

    uint64_t hdr_total_bits = read_le64(hdr + 16);
    uint64_t hdr_chunks = read_le64(hdr + 24);
    meta_.config.w_sync = read_le32(hdr + 32);
    meta_.config.l_min = read_le32(hdr + 36);
    meta_.config.l_target = read_le32(hdr + 40);
    meta_.config.l_max = read_le32(hdr + 44);
    meta_.config.w_hist = read_le32(hdr + 48);
    uint64_t hdr_idx_off = read_le64(hdr + 52);

    if (!meta_.config.valid()) throw std::runtime_error("Invalid StreamConfig in .mapr header");

    // 2. Read & verify 72-byte TRLR at EOF - 72
    in_.seekg(static_cast<std::streamoff>(file_size_ - 72ULL), std::ios::beg);
    uint8_t trlr[72];
    in_.read(reinterpret_cast<char*>(trlr), 72);
    if (in_.gcount() != 72) throw std::runtime_error("Truncated .mapr trailer");
    if (std::memcmp(trlr, "TRLR", 4) != 0 || std::memcmp(trlr + 64, "ENDM", 4) != 0) {
        throw std::runtime_error("Invalid .mapr trailer magic/sentinel");
    }
    if (crc32_compute(trlr, 68) != read_le32(trlr + 68)) {
        throw std::runtime_error("Trailer CRC-32 mismatch");
    }
    if (read_le32(trlr + 4) != 0x00000001u) {
        throw std::runtime_error("Invalid trailer_flags in .mapr v1.0 trailer (MUST equal 1)");
    }
    meta_.total_bits = read_le64(trlr + 8);
    meta_.chunk_count = read_le64(trlr + 16);
    meta_.index_offset = read_le64(trlr + 24);
    std::memcpy(meta_.stream_sha256.data(), trlr + 32, 32);

    if ((meta_.flags & FLAG_STREAMED_HEADER) == 0u) {
        if (hdr_total_bits != meta_.total_bits || hdr_chunks != meta_.chunk_count || hdr_idx_off != meta_.index_offset) {
            throw std::runtime_error("Header / Trailer metadata inconsistency");
        }
    } else {
        if ((hdr_total_bits != 0ULL && hdr_total_bits != meta_.total_bits) ||
            (hdr_chunks != 0ULL && hdr_chunks != meta_.chunk_count) ||
            (hdr_idx_off != 0ULL && hdr_idx_off != meta_.index_offset)) {
            throw std::runtime_error("Contradictory streamed header metadata");
        }
    }
    if ((meta_.flags & FLAG_RAW_BYTES_MSB) != 0u && (meta_.total_bits & 7ULL) != 0ULL) {
        throw std::runtime_error("FLAG_RAW_BYTES_MSB set on non-byte-aligned total_bits");
    }
    if (meta_.chunk_count == 0) {
        throw std::runtime_error("chunk_count cannot be 0");
    }

    // 3. Read & verify INDX block (overflow-safe arithmetic before multiplication!)
    uint64_t body_limit = file_size_ - 72ULL;
    if (meta_.index_offset < 64ULL || meta_.index_offset + 20ULL > body_limit) {
        throw std::runtime_error("Invalid INDX offset bounds");
    }
    uint64_t avail_for_entries = body_limit - meta_.index_offset - 20ULL;
    if ((avail_for_entries & 31ULL) != 0ULL || (avail_for_entries >> 5) != meta_.chunk_count) {
        throw std::runtime_error("Invalid INDX size / chunk_count overflow");
    }
    in_.seekg(static_cast<std::streamoff>(meta_.index_offset), std::ios::beg);
    uint8_t ihdr[16];
    in_.read(reinterpret_cast<char*>(ihdr), 16);
    if (std::memcmp(ihdr, "INDX", 4) != 0 || read_le32(ihdr + 4) != 32u || read_le64(ihdr + 8) != meta_.chunk_count) {
        throw std::runtime_error("Invalid INDX header");
    }
    uint32_t icrc = crc32_update(0xFFFFFFFFu, ihdr, 16);
    meta_.index.resize(static_cast<size_t>(meta_.chunk_count));

    uint64_t run_file_off = 64ULL;
    uint64_t run_bit_off = 0ULL;
    for (uint64_t c = 0; c < meta_.chunk_count; ++c) {
        uint8_t eb[32];
        in_.read(reinterpret_cast<char*>(eb), 32);
        if (in_.gcount() != 32) throw std::runtime_error("Truncated INDX entry");
        icrc = crc32_update(icrc, eb, 32);
        if (read_le16(eb + 30) != 0u) throw std::runtime_error("Non-zero reserved field in INDX");

        IndexEntry e;
        e.file_offset = read_le64(eb + 0);
        e.bit_offset = read_le64(eb + 8);
        e.bit_len = read_le32(eb + 16);
        e.frame_bytes = read_le32(eb + 20);
        e.ref_target = read_le32(eb + 24);
        e.chunk_kind = eb[28];
        e.v4_op = eb[29];

        if (e.file_offset != run_file_off || e.bit_offset != run_bit_off || e.frame_bytes < 33u) {
            throw std::runtime_error("Discontinuous file_offset/bit_offset in INDX");
        }
        if (meta_.total_bits == 0) {
            if (meta_.chunk_count != 1 || e.bit_len != 0 || e.chunk_kind != KIND_EXPLICIT_DAG) {
                throw std::runtime_error("Invalid empty-sequence superchunk record");
            }
        } else {
            if (e.bit_len == 0 || e.bit_len > meta_.config.l_max) {
                throw std::runtime_error("Superchunk bit_len out of [1, L_max]");
            }
        }
        if (e.chunk_kind == KIND_CHUNK_REF) {
            if (e.frame_bytes != 36u || e.v4_op > 3u || e.ref_target >= c || meta_.config.w_hist == 0 ||
                (c - e.ref_target) > meta_.config.w_hist ||
                meta_.index[e.ref_target].bit_len != e.bit_len) {
                throw std::runtime_error("Invalid CHUNK_REF target/window/length in INDX");
            }
        } else if (e.chunk_kind == KIND_EXPLICIT_DAG) {
            if (e.v4_op != 0u || e.ref_target != c) {
                throw std::runtime_error("Invalid EXPLICIT_DAG metadata in INDX");
            }
        } else {
            throw std::runtime_error("Unknown chunk_kind in INDX");
        }

        meta_.index[static_cast<size_t>(c)] = e;
        run_file_off += e.frame_bytes;
        run_bit_off += e.bit_len;
    }

    uint8_t icrc_b[4];
    in_.read(reinterpret_cast<char*>(icrc_b), 4);
    if ((icrc ^ 0xFFFFFFFFu) != read_le32(icrc_b)) {
        throw std::runtime_error("INDX CRC-32 mismatch");
    }
    if (run_file_off != meta_.index_offset || run_bit_off != meta_.total_bits) {
        throw std::runtime_error("Aggregate INDX spans do not match container totals");
    }
}

ContainerReader::ChunkFrame ContainerReader::read_chunk(uint64_t chunk_idx) {
    if (chunk_idx >= meta_.chunk_count) throw std::out_of_range("chunk_idx out of bounds");
    const auto& ie = meta_.index[static_cast<size_t>(chunk_idx)];

    in_.seekg(static_cast<std::streamoff>(ie.file_offset), std::ios::beg);
    uint8_t fhdr[32];
    in_.read(reinterpret_cast<char*>(fhdr), 32);
    if (in_.gcount() != 32) throw std::runtime_error("Truncated MCHK header");
    if (std::memcmp(fhdr, "MCHK", 4) != 0) throw std::runtime_error("Invalid MCHK magic");

    uint32_t f_cidx = read_le32(fhdr + 4);
    uint64_t f_boff = read_le64(fhdr + 8);
    uint32_t f_blen = read_le32(fhdr + 16);
    uint8_t f_kind = fhdr[20];
    uint8_t f_v4 = fhdr[21];
    uint16_t f_res = read_le16(fhdr + 22);
    uint32_t p_bytes = read_le32(fhdr + 24);
    uint32_t expected_crc = read_le32(fhdr + 28);

    if (f_cidx != chunk_idx || f_boff != ie.bit_offset || f_blen != ie.bit_len ||
        f_kind != ie.chunk_kind || f_v4 != ie.v4_op || f_res != 0u ||
        32u + p_bytes != ie.frame_bytes) {
        throw std::runtime_error("MCHK frame header mismatch against INDX");
    }

    std::vector<uint8_t> payload(p_bytes);
    in_.read(reinterpret_cast<char*>(payload.data()), static_cast<std::streamsize>(p_bytes));
    if (static_cast<uint32_t>(in_.gcount()) != p_bytes) {
        throw std::runtime_error("Truncated MCHK payload");
    }

    uint32_t crc = crc32_update(0xFFFFFFFFu, fhdr, 28);
    crc = crc32_update(crc, payload.data(), payload.size()) ^ 0xFFFFFFFFu;
    if (crc != expected_crc) {
        throw std::runtime_error("MCHK chunk CRC-32 mismatch at chunk " + std::to_string(chunk_idx));
    }

    ChunkFrame cf;
    cf.chunk_index = f_cidx;
    cf.bit_offset = f_boff;
    cf.bit_len = f_blen;
    cf.chunk_kind = f_kind;
    cf.v4_op = static_cast<V4Op>(f_v4);

    if (f_kind == KIND_CHUNK_REF) {
        if (p_bytes != 4u) throw std::runtime_error("CHUNK_REF payload_bytes != 4");
        cf.ref_target = read_le32(payload.data());
        if (cf.ref_target != ie.ref_target) throw std::runtime_error("CHUNK_REF target mismatch");
    } else {
        uint64_t cap = static_cast<uint64_t>(f_blen) * 2ULL + 16ULL;
        cf.dag = deserialize_chunk_dag_payload(payload.data(), payload.size(), cap);
        auto vr = validate_chunk_dag(cf.dag, f_blen);
        if (!vr.valid) throw std::runtime_error("Chunk DAG validation failed: " + vr.error);
    }
    return cf;
}

} // namespace mapr
