#pragma once

// TEST-ONLY wire builder constructed strictly from SPECS-V2 §5 and E3 §4.
// NEVER linked into bin/mapr_oracle and NOT an E3 implementation.

#include "marp/oracle/oracle.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace marp::oracle::test_wire {

inline constexpr std::array<std::uint8_t, 8> kHdrMagic = {
    0x89, 0x4D, 0x41, 0x50, 0x52, 0x32, 0x0D, 0x0A
};
inline constexpr std::array<std::uint8_t, 8> kIdxMagic = {
    0x49, 0x4E, 0x44, 0x58, 0x32, 0x0D, 0x0A, 0x1A
};
inline constexpr std::array<std::uint8_t, 8> kTrlMagic = {
    0x54, 0x52, 0x4C, 0x52, 0x32, 0x0D, 0x0A, 0x1A
};

inline void put_u8(std::vector<std::uint8_t>& out, std::uint8_t v) {
    out.push_back(v);
}

inline void put_le16(std::vector<std::uint8_t>& out, std::uint16_t v) {
    out.push_back(static_cast<std::uint8_t>(v & 0xFFU));
    out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFFU));
}

inline void put_le32(std::vector<std::uint8_t>& out, std::uint32_t v) {
    out.push_back(static_cast<std::uint8_t>(v & 0xFFU));
    out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFFU));
    out.push_back(static_cast<std::uint8_t>((v >> 16) & 0xFFU));
    out.push_back(static_cast<std::uint8_t>((v >> 24) & 0xFFU));
}

inline void put_le64(std::vector<std::uint8_t>& out, std::uint64_t v) {
    put_le32(out, static_cast<std::uint32_t>(v & 0xFFFFFFFFULL));
    put_le32(out, static_cast<std::uint32_t>(v >> 32));
}

inline void write_le16_at(std::vector<std::uint8_t>& out, std::size_t off, std::uint16_t v) {
    out[off]     = static_cast<std::uint8_t>(v & 0xFFU);
    out[off + 1] = static_cast<std::uint8_t>((v >> 8) & 0xFFU);
}

inline void write_le32_at(std::vector<std::uint8_t>& out, std::size_t off, std::uint32_t v) {
    out[off]     = static_cast<std::uint8_t>(v & 0xFFU);
    out[off + 1] = static_cast<std::uint8_t>((v >> 8) & 0xFFU);
    out[off + 2] = static_cast<std::uint8_t>((v >> 16) & 0xFFU);
    out[off + 3] = static_cast<std::uint8_t>((v >> 24) & 0xFFU);
}

inline void write_le64_at(std::vector<std::uint8_t>& out, std::size_t off, std::uint64_t v) {
    write_le32_at(out, off, static_cast<std::uint32_t>(v & 0xFFFFFFFFULL));
    write_le32_at(out, off + 4, static_cast<std::uint32_t>(v >> 32));
}

inline std::uint32_t read_le32_at(std::span<const std::uint8_t> buf, std::size_t off) {
    return static_cast<std::uint32_t>(buf[off]) |
           (static_cast<std::uint32_t>(buf[off + 1]) << 8) |
           (static_cast<std::uint32_t>(buf[off + 2]) << 16) |
           (static_cast<std::uint32_t>(buf[off + 3]) << 24);
}

inline std::uint64_t read_le64_at(std::span<const std::uint8_t> buf, std::size_t off) {
    return static_cast<std::uint64_t>(read_le32_at(buf, off)) |
           (static_cast<std::uint64_t>(read_le32_at(buf, off + 4)) << 32);
}

inline void put_uvarint(std::vector<std::uint8_t>& out, std::uint64_t v) {
    while (v >= 0x80ULL) {
        out.push_back(static_cast<std::uint8_t>((v & 0x7FULL) | 0x80ULL));
        v >>= 7;
    }
    out.push_back(static_cast<std::uint8_t>(v));
}

// Simple unsigned integer encoded from decimal string to little-endian magnitude bytes
inline std::vector<std::uint8_t> decimal_to_le_bytes(std::string_view dec) {
    std::vector<std::uint8_t> le; // little-endian base-256
    for (char ch : dec) {
        if (ch < '0' || ch > '9') {
            continue;
        }
        std::uint32_t carry = static_cast<std::uint32_t>(ch - '0');
        for (std::uint8_t& b : le) {
            const std::uint32_t v = static_cast<std::uint32_t>(b) * 10U + carry;
            b = static_cast<std::uint8_t>(v & 0xFFU);
            carry = v >> 8;
        }
        while (carry > 0U) {
            le.push_back(static_cast<std::uint8_t>(carry & 0xFFU));
            carry >>= 8;
        }
    }
    while (!le.empty() && le.back() == 0U) {
        le.pop_back();
    }
    return le;
}

inline void put_bigint_u64(std::vector<std::uint8_t>& out, std::uint64_t v) {
    if (v == 0ULL) {
        out.push_back(0x00U);
    } else {
        out.push_back(0x01U);
        put_uvarint(out, v);
    }
}

inline void put_bigint_dec(std::vector<std::uint8_t>& out, std::string_view dec) {
    auto le = decimal_to_le_bytes(dec);
    if (le.empty()) {
        out.push_back(0x00U);
        return;
    }
    if (le.size() <= 8) {
        std::uint64_t v = 0;
        for (std::size_t i = 0; i < le.size(); ++i) {
            v |= static_cast<std::uint64_t>(le[i]) << (i * 8U);
        }
        out.push_back(0x01U);
        put_uvarint(out, v);
        return;
    }
    out.push_back(0x02U);
    put_le32(out, static_cast<std::uint32_t>(le.size()));
    out.insert(out.end(), le.begin(), le.end());
}

struct AtomSpec {
    std::uint8_t klass = 0;
    std::vector<std::uint8_t> payload;
};

struct NodeSpec {
    std::uint8_t kind = 0;
    std::vector<std::uint32_t> args;
    std::uint32_t atom_id = 0;
    std::string param_a;
    std::string param_b;
    std::uint8_t morph = 0;
    std::uint8_t morph_k = 0;
    std::uint32_t stride = 0;
    std::uint64_t lfsr_conn = 0;
    std::uint64_t lfsr_init = 0;
    std::uint8_t affine_start = 0;
    std::uint8_t affine_step = 0;
    std::uint8_t predictor_id = 0;
    std::uint32_t predictor_param = 0;
    std::string length;
};

struct IndexEntrySpec {
    std::string output_offset;
    std::uint32_t node_id = 0;
    std::uint32_t crc32_of_prefix = 0;
};

struct ContainerSpec {
    std::string total_length;
    std::vector<AtomSpec> atoms;
    std::vector<NodeSpec> nodes;
    std::vector<IndexEntrySpec> index_entries; // non-empty => index present
};

inline std::vector<std::uint8_t> encode_atoms(const std::vector<AtomSpec>& atoms) {
    std::vector<std::uint8_t> buf;
    put_uvarint(buf, static_cast<std::uint64_t>(atoms.size()));
    for (const auto& a : atoms) {
        put_u8(buf, a.klass);
        put_u8(buf, 0U);   // flags
        put_le16(buf, 0U); // reserved
        put_bigint_u64(buf, static_cast<std::uint64_t>(a.payload.size()));
        const auto sha = sha256_bytes(a.payload);
        buf.insert(buf.end(), sha.begin(), sha.end());
        buf.insert(buf.end(), a.payload.begin(), a.payload.end());
    }
    return buf;
}

inline std::vector<std::uint8_t> encode_nodes(const std::vector<NodeSpec>& nodes) {
    std::vector<std::uint8_t> buf;
    put_uvarint(buf, static_cast<std::uint64_t>(nodes.size()));
    for (const auto& n : nodes) {
        put_u8(buf, n.kind);
        put_u8(buf, 0U); // flags
        put_le16(buf, static_cast<std::uint16_t>(n.args.size()));
        for (std::uint32_t arg : n.args) {
            put_uvarint(buf, arg);
        }
        switch (n.kind) {
            case 0: break; // Empty
            case 1: put_uvarint(buf, n.atom_id); break;
            case 2: put_bigint_dec(buf, n.param_a); break;
            case 3: break; // Concat
            case 4: put_bigint_dec(buf, n.param_a); put_bigint_dec(buf, n.param_b); break;
            case 5: put_bigint_dec(buf, n.param_a); put_bigint_dec(buf, n.param_b); break;
            case 6: put_u8(buf, n.morph); put_u8(buf, n.morph_k); break;
            case 7: break; // Xor
            case 8: put_le32(buf, n.stride); break;
            case 9:
                put_le64(buf, n.lfsr_conn);
                put_le64(buf, n.lfsr_init);
                put_bigint_dec(buf, n.param_a);
                break;
            case 10:
                put_u8(buf, n.affine_start);
                put_u8(buf, n.affine_step);
                put_bigint_dec(buf, n.param_a);
                break;
            case 11:
                put_u8(buf, n.predictor_id);
                put_le32(buf, n.predictor_param);
                break;
            default: break;
        }
        put_bigint_dec(buf, n.length);
    }
    return buf;
}

inline std::vector<std::uint8_t> encode_index(const std::vector<IndexEntrySpec>& entries) {
    std::vector<std::uint8_t> buf;
    buf.insert(buf.end(), kIdxMagic.begin(), kIdxMagic.end());
    put_le32(buf, static_cast<std::uint32_t>(entries.size()));
    for (const auto& e : entries) {
        put_bigint_dec(buf, e.output_offset);
        put_uvarint(buf, e.node_id);
        put_le32(buf, e.crc32_of_prefix);
    }
    const std::uint32_t icrc = crc32_bytes(buf);
    put_le32(buf, icrc);
    return buf;
}

inline void recompute_outer_crcs(std::vector<std::uint8_t>& wire) {
    if (wire.size() < 96) {
        return;
    }
    const std::size_t trl_off = wire.size() - 32;
    // Zero header file_crc32 before computing
    write_le32_at(wire, 60, 0U);
    const std::uint32_t file_crc = crc32_bytes(
        std::span<const std::uint8_t>(wire.data(), trl_off));
    write_le32_at(wire, 60, file_crc);

    std::array<std::uint8_t, 32> tcrc_in{};
    std::memcpy(tcrc_in.data(), wire.data() + trl_off, 28);
    tcrc_in[28] = static_cast<std::uint8_t>(file_crc & 0xFFU);
    tcrc_in[29] = static_cast<std::uint8_t>((file_crc >> 8) & 0xFFU);
    tcrc_in[30] = static_cast<std::uint8_t>((file_crc >> 16) & 0xFFU);
    tcrc_in[31] = static_cast<std::uint8_t>((file_crc >> 24) & 0xFFU);
    const std::uint32_t trl_crc = crc32_bytes(tcrc_in);
    write_le32_at(wire, trl_off + 28, trl_crc);
}

inline std::vector<std::uint8_t> assemble_raw(
    std::string_view total_length_dec,
    const std::vector<std::uint8_t>& atom_region,
    const std::vector<std::uint8_t>& node_region,
    const std::vector<std::uint8_t>& index_region,
    std::uint32_t trailer_atom_count,
    std::uint32_t trailer_node_count,
    std::uint32_t trailer_root_id) {

    const auto total_le = decimal_to_le_bytes(total_length_dec);
    const bool fits_u64 = (total_le.size() <= 8);
    std::uint64_t total_u64 = 0;
    std::vector<std::uint8_t> region_a1;
    if (fits_u64) {
        for (std::size_t i = 0; i < total_le.size(); ++i) {
            total_u64 |= static_cast<std::uint64_t>(total_le[i]) << (i * 8U);
        }
    } else {
        region_a1 = total_le;
    }

    const bool has_index = !index_region.empty();
    std::uint32_t flags = (1U << 1) | (1U << 3); // canonical + byte-aligned
    if (has_index) flags |= (1U << 0);
    if (fits_u64) flags |= (1U << 2);

    const std::uint64_t atom_off = 64ULL + region_a1.size();
    const std::uint64_t node_off = atom_off + atom_region.size();
    const std::uint64_t index_off = has_index ? (node_off + node_region.size()) : 0ULL;
    const std::uint64_t trailer_off = node_off + node_region.size() + index_region.size();
    const std::uint64_t file_bytes = trailer_off + 32ULL;

    std::vector<std::uint8_t> wire;
    wire.reserve(static_cast<std::size_t>(file_bytes));

    // Region A: 64-byte header
    wire.insert(wire.end(), kHdrMagic.begin(), kHdrMagic.end());
    put_le16(wire, 2U); // major
    put_le16(wire, 0U); // minor
    put_le32(wire, flags);
    put_le16(wire, 64U); // header_bytes
    put_le64(wire, total_u64);
    put_le16(wire, static_cast<std::uint16_t>(region_a1.size()));
    put_le64(wire, atom_off);
    put_le64(wire, node_off);
    put_le64(wire, index_off);
    put_le64(wire, trailer_off);
    put_le32(wire, 0U); // file_crc32 placeholder

    // Region A.1
    wire.insert(wire.end(), region_a1.begin(), region_a1.end());
    // Region B
    wire.insert(wire.end(), atom_region.begin(), atom_region.end());
    // Region C
    wire.insert(wire.end(), node_region.begin(), node_region.end());
    // Region D
    wire.insert(wire.end(), index_region.begin(), index_region.end());
    // Region E: 32-byte trailer
    wire.insert(wire.end(), kTrlMagic.begin(), kTrlMagic.end());
    put_le64(wire, file_bytes);
    put_le32(wire, trailer_root_id);
    put_le32(wire, trailer_atom_count);
    put_le32(wire, trailer_node_count);
    put_le32(wire, 0U); // trailer_crc32 placeholder

    recompute_outer_crcs(wire);
    return wire;
}

inline std::vector<std::uint8_t> build_wire(const ContainerSpec& spec) {
    const auto atoms_bin = encode_atoms(spec.atoms);
    const auto nodes_bin = encode_nodes(spec.nodes);
    std::vector<std::uint8_t> index_bin;
    if (!spec.index_entries.empty()) {
        index_bin = encode_index(spec.index_entries);
    }
    const std::uint32_t root_id = spec.nodes.empty()
                                      ? 0U
                                      : static_cast<std::uint32_t>(spec.nodes.size() - 1);
    return assemble_raw(spec.total_length,
                        atoms_bin,
                        nodes_bin,
                        index_bin,
                        static_cast<std::uint32_t>(spec.atoms.size()),
                        static_cast<std::uint32_t>(spec.nodes.size()),
                        root_id);
}

// Convenience builders for common single-node containers
inline std::vector<std::uint8_t> make_empty_wire() {
    ContainerSpec s;
    s.total_length = "0";
    NodeSpec n;
    n.kind = 0; // Empty
    n.length = "0";
    s.nodes.push_back(n);
    return build_wire(s);
}

inline std::vector<std::uint8_t> make_atom_wire(std::span<const std::uint8_t> payload,
                                                std::uint8_t klass = 0) {
    ContainerSpec s;
    s.total_length = std::to_string(payload.size());
    AtomSpec a;
    a.klass = klass;
    a.payload.assign(payload.begin(), payload.end());
    s.atoms.push_back(std::move(a));
    NodeSpec n;
    n.kind = 1; // Atom
    n.atom_id = 0;
    n.length = s.total_length;
    s.nodes.push_back(std::move(n));
    return build_wire(s);
}

inline std::vector<std::uint8_t> make_zero_wire(std::string_view n_dec) {
    ContainerSpec s;
    s.total_length = std::string(n_dec);
    NodeSpec n;
    n.kind = 2; // Zero
    n.param_a = std::string(n_dec);
    n.length = std::string(n_dec);
    s.nodes.push_back(std::move(n));
    return build_wire(s);
}

} // namespace marp::oracle::test_wire
