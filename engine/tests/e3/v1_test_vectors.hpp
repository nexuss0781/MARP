#pragma once

// Test-only helper for assembling synthetic v1.0.1 / v1.1 wire vectors in unit
// and gate tests. Lives strictly under engine/tests/e3/ — never included by or
// linked into the production C08 library (engine/src/e3/e3_legacy.cpp).

#include <mapr/e1_crc32.hpp>
#include <mapr/e1_sha256.hpp>
#include <mapr/e1_types.hpp>

#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string_view>
#include <vector>

namespace marp::v2::test_v1 {

using u8  = std::uint8_t;
using u16 = std::uint16_t;
using u32 = std::uint32_t;
using u64 = std::uint64_t;
using Digest256 = std::array<u8, 32>;

inline std::string_view sv_of(std::span<const u8> s) noexcept {
    return std::string_view(reinterpret_cast<const char*>(s.data()), s.size());
}

inline u32 crc32_span(std::span<const u8> s) noexcept {
    return mapr::crc32(sv_of(s));
}

inline Digest256 sha256_span(std::span<const u8> s) noexcept {
    return mapr::Sha256::hash(sv_of(s)).value();
}

inline void put_le16(std::vector<u8>& out, u16 v) {
    out.push_back(static_cast<u8>(v & 0xFFu));
    out.push_back(static_cast<u8>((v >> 8) & 0xFFu));
}

inline void put_le32(std::vector<u8>& out, u32 v) {
    for (int i = 0; i < 4; ++i) {
        out.push_back(static_cast<u8>((v >> (i * 8)) & 0xFFu));
    }
}

inline void put_le64(std::vector<u8>& out, u64 v) {
    for (int i = 0; i < 8; ++i) {
        out.push_back(static_cast<u8>((v >> (i * 8)) & 0xFFULL));
    }
}

inline void write_le32_at(u8* p, u32 v) noexcept {
    p[0] = static_cast<u8>(v & 0xFFu);
    p[1] = static_cast<u8>((v >> 8) & 0xFFu);
    p[2] = static_cast<u8>((v >> 16) & 0xFFu);
    p[3] = static_cast<u8>((v >> 24) & 0xFFu);
}

inline void write_le16_at(u8* p, u16 v) noexcept {
    p[0] = static_cast<u8>(v & 0xFFu);
    p[1] = static_cast<u8>((v >> 8) & 0xFFu);
}

inline void refresh_header_crc(std::vector<u8>& wire) noexcept {
    if (wire.size() >= 64u) {
        const u32 crc = crc32_span(std::span<const u8>(wire.data(), 60));
        write_le32_at(wire.data() + 60, crc);
    }
}

inline void refresh_trailer_crc(std::vector<u8>& wire) noexcept {
    if (wire.size() >= 72u) {
        u8* trlr = wire.data() + (wire.size() - 72u);
        const u32 crc = crc32_span(std::span<const u8>(trlr, 68));
        write_le32_at(trlr + 68, crc);
    }
}

class TestBitPacker {
public:
    void bits(u64 val, int n) {
        if (n <= 0) return;
        if (n > 32) {
            bits(val & 0xFFFFFFFFULL, 32);
            bits(val >> 32, n - 32);
            return;
        }
        const u64 masked = val & ((1ULL << static_cast<unsigned>(n)) - 1ULL);
        acc_ |= (masked << static_cast<unsigned>(bit_count_));
        bit_count_ += n;
        while (bit_count_ >= 8) {
            buf_.push_back(static_cast<u8>(acc_ & 0xFFULL));
            acc_ >>= 8;
            bit_count_ -= 8;
        }
    }

    void varint(u64 val) {
        do {
            u8 byte = static_cast<u8>(val & 0x7FULL);
            val >>= 7;
            if (val != 0ULL) byte = static_cast<u8>(byte | 0x80u);
            bits(byte, 8);
        } while (val != 0ULL);
    }

    void trunc_bin(u64 x, u64 m) {
        if (m <= 1ULL) return;
        const int k = static_cast<int>(std::bit_width(m)) - 1;
        const u64 u = (1ULL << static_cast<unsigned>(k + 1)) - m;
        if (x < u) {
            bits(x, k);
        } else {
            const u64 y = x + u;
            bits(y >> 1, k);
            bits(y & 1ULL, 1);
        }
    }

    void child_ref(u32 current_v, u32 child_u) {
        const u64 rel = static_cast<u64>(current_v - 1u - child_u);
        varint(rel);
    }

    void atom_fixed_b(int b, bool zheg, int w, u64 comb_bw, u64 rho) {
        if ((b & (b - 1)) == 0) {
            bits(zheg ? 1ULL : 0ULL, 1);
        }
        trunc_bin(static_cast<u64>(w), static_cast<u64>(b) + 1ULL);
        if (comb_bw > 1ULL) {
            trunc_bin(rho, comb_bw);
        }
    }

    void atom(int b, bool zheg, int w, u64 comb_bw, u64 rho) {
        if (b == 64) {
            bits(1ULL, 1);
        } else {
            bits(0ULL, 1);
            bits(static_cast<u64>(b - 1), 6);
        }
        atom_fixed_b(b, zheg, w, comb_bw, rho);
    }

    std::vector<u8> finish() const {
        std::vector<u8> out = buf_;
        if (bit_count_ > 0) {
            out.push_back(static_cast<u8>(acc_ & 0xFFULL));
        }
        return out;
    }

private:
    std::vector<u8> buf_{};
    u64 acc_ = 0ULL;
    int bit_count_ = 0;
};

struct TestChunkSpec {
    u32 bit_len = 0u;
    u8 kind = 1u;          // 0 = CHUNK_REF, 1 = EXPLICIT_DAG
    u8 v4_op = 0u;         // 0..3
    u32 ref_target = 0u;   // used when kind == 0
    std::vector<u8> dag_payload{}; // used when kind == 1
};

struct TestContainerOptions {
    u16 version_major = 1u;
    u16 version_minor = 0u;
    bool streamed_header = false;
    bool raw_bytes_msb = true;
    u32 w_sync = 64u;
    u32 l_min = 1024u;
    u32 l_target = 4096u;
    u32 l_max = 4'194'304u;
    u32 w_hist = 64u;
};

// Computes SHA-256 for v1 trailer: SHA256(bytes) in raw_bytes_msb mode, or
// SHA256(be64(total_bits) || msb_padded_bytes) in bitseq mode.
inline Digest256 compute_v1_trailer_sha(
    std::span<const u8> msb_padded_bytes,
    u64 total_bits,
    bool raw_bytes_msb) {
    if (raw_bytes_msb) {
        return sha256_span(msb_padded_bytes);
    }
    std::array<u8, 8> be{};
    u64 v = total_bits;
    for (int i = 7; i >= 0; --i) {
        be[static_cast<std::size_t>(i)] = static_cast<u8>(v & 0xFFULL);
        v >>= 8;
    }
    mapr::Sha256 h;
    (void)h.update(sv_of(be));
    (void)h.update(sv_of(msb_padded_bytes));
    return h.finish().value();
}

inline std::vector<u8> assemble_v1_container(
    const std::vector<TestChunkSpec>& chunks,
    std::span<const u8> expected_msb_padded_bytes,
    u64 total_bits,
    const TestContainerOptions& opt = {}) {
    std::vector<u8> out;
    out.resize(64u, 0u); // placeholder header

    struct IdxRec {
        u64 file_off;
        u64 bit_off;
        u32 bit_len;
        u32 frame_bytes;
        u32 ref_target;
        u8 kind;
        u8 v4_op;
    };
    std::vector<IdxRec> idx;
    idx.reserve(chunks.size());

    u64 cur_bit_off = 0ULL;
    for (std::size_t c = 0; c < chunks.size(); ++c) {
        const TestChunkSpec& cs = chunks[c];
        const u64 foff = static_cast<u64>(out.size());

        std::vector<u8> payload;
        u32 ref_t = static_cast<u32>(c);
        u8 v4 = 0u;
        if (cs.kind == 0u) {
            put_le32(payload, cs.ref_target);
            ref_t = cs.ref_target;
            v4 = cs.v4_op;
        } else {
            payload = cs.dag_payload;
        }

        std::vector<u8> fhdr;
        fhdr.reserve(32u);
        fhdr.insert(fhdr.end(), {'M', 'C', 'H', 'K'});
        put_le32(fhdr, static_cast<u32>(c));
        put_le64(fhdr, cur_bit_off);
        put_le32(fhdr, cs.bit_len);
        fhdr.push_back(cs.kind);
        fhdr.push_back(v4);
        put_le16(fhdr, 0u);
        put_le32(fhdr, static_cast<u32>(payload.size()));

        mapr::Crc32 fcrc;
        fcrc.update(sv_of(fhdr));
        fcrc.update(sv_of(payload));
        put_le32(fhdr, fcrc.finish());

        out.insert(out.end(), fhdr.begin(), fhdr.end());
        out.insert(out.end(), payload.begin(), payload.end());

        const u32 fbytes = static_cast<u32>(32u + payload.size());
        idx.push_back(IdxRec{foff, cur_bit_off, cs.bit_len, fbytes, ref_t, cs.kind, v4});
        cur_bit_off += static_cast<u64>(cs.bit_len);
    }

    const u64 index_off = static_cast<u64>(out.size());
    std::vector<u8> indx;
    indx.insert(indx.end(), {'I', 'N', 'D', 'X'});
    put_le32(indx, 32u);
    put_le64(indx, static_cast<u64>(idx.size()));
    for (const auto& e : idx) {
        put_le64(indx, e.file_off);
        put_le64(indx, e.bit_off);
        put_le32(indx, e.bit_len);
        put_le32(indx, e.frame_bytes);
        put_le32(indx, e.ref_target);
        indx.push_back(e.kind);
        indx.push_back(e.v4_op);
        put_le16(indx, 0u);
    }
    const u32 icrc = crc32_span(indx);
    put_le32(indx, icrc);
    out.insert(out.end(), indx.begin(), indx.end());

    const Digest256 sha =
        compute_v1_trailer_sha(expected_msb_padded_bytes, total_bits, opt.raw_bytes_msb);
    std::vector<u8> trlr;
    trlr.reserve(72u);
    trlr.insert(trlr.end(), {'T', 'R', 'L', 'R'});
    put_le32(trlr, 1u);
    put_le64(trlr, total_bits);
    put_le64(trlr, static_cast<u64>(idx.size()));
    put_le64(trlr, index_off);
    trlr.insert(trlr.end(), sha.begin(), sha.end());
    trlr.insert(trlr.end(), {'E', 'N', 'D', 'M'});
    const u32 tcrc = crc32_span(trlr);
    put_le32(trlr, tcrc);
    out.insert(out.end(), trlr.begin(), trlr.end());

    // Fill 64-byte header at offset 0.
    std::vector<u8> hdr;
    hdr.reserve(64u);
    const std::array<u8, 8> magic = {0x89u, 0x4Du, 0x41u, 0x50u, 0x52u, 0x0Du, 0x0Au, 0x1Au};
    hdr.insert(hdr.end(), magic.begin(), magic.end());
    put_le16(hdr, opt.version_major);
    put_le16(hdr, opt.version_minor);
    u32 flags = 0x02u; // FLAG_HAS_INDEX
    if (opt.raw_bytes_msb)   flags |= 0x01u; // FLAG_RAW_BYTES_MSB
    if (opt.streamed_header) flags |= 0x04u; // FLAG_STREAMED_HEADER
    put_le32(hdr, flags);
    put_le64(hdr, opt.streamed_header ? 0ULL : total_bits);
    put_le64(hdr, opt.streamed_header ? 0ULL : static_cast<u64>(idx.size()));
    put_le32(hdr, opt.w_sync);
    put_le32(hdr, opt.l_min);
    put_le32(hdr, opt.l_target);
    put_le32(hdr, opt.l_max);
    put_le32(hdr, opt.w_hist);
    put_le64(hdr, opt.streamed_header ? 0ULL : index_off);
    const u32 hcrc = crc32_span(hdr);
    put_le32(hdr, hcrc);
    std::memcpy(out.data(), hdr.data(), 64u);

    return out;
}

// Builds a single-chunk RAW (opcode 10) container for arbitrary bytes.
inline std::vector<u8> make_raw_v1_container(
    std::span<const u8> payload_bytes,
    u16 version_minor = 1u,
    bool streamed_header = false) {
    TestBitPacker bp;
    if (payload_bytes.empty()) {
        bp.varint(1ULL); // m = 1
        bp.varint(0ULL); // root = 0
        bp.bits(0ULL, 4); // op 0 = EMPTY
        TestContainerOptions opt{};
        opt.version_minor = version_minor;
        opt.streamed_header = streamed_header;
        return assemble_v1_container(
            {TestChunkSpec{0u, 1u, 0u, 0u, bp.finish()}}, payload_bytes, 0ULL, opt);
    }
    bp.varint(1ULL); // m = 1
    bp.varint(0ULL); // root = 0
    bp.bits(10ULL, 4); // op 10 = RAW
    bp.varint(static_cast<u64>(payload_bytes.size()));
    for (u8 b : payload_bytes) bp.bits(b, 8);
    const u64 bit_len = static_cast<u64>(payload_bytes.size()) * 8ULL;
    bp.varint(bit_len);

    TestContainerOptions opt{};
    opt.version_minor = version_minor;
    opt.streamed_header = streamed_header;
    return assemble_v1_container(
        {TestChunkSpec{static_cast<u32>(bit_len), 1u, 0u, 0u, bp.finish()}},
        payload_bytes,
        bit_len,
        opt);
}

} // namespace marp::v2::test_v1
