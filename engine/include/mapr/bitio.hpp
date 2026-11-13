#pragma once

#include "mapr/common.hpp"
#include "mapr/dag.hpp"
#include "mapr/math_core.hpp"
#include <bit>
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace mapr {

// 128-bit accumulator LSB-first BitWriter (100% UB-free across 0 <= k <= 64)
class BitWriter64 {
public:
    explicit BitWriter64(size_t reserve_bytes = 256) { out_.reserve(reserve_bytes); }

    void write_bits(uint64_t val, int k) {
        if (k <= 0) return;
        val &= low_mask(k);
        acc_ |= (static_cast<unsigned __int128>(val) << bits_);
        bits_ += k;
        while (bits_ >= 64) {
            uint64_t w = static_cast<uint64_t>(acc_);
            size_t pos = out_.size();
            out_.resize(pos + 8);
            write_le64(out_.data() + pos, w);
            acc_ >>= 64;
            bits_ -= 64;
        }
    }

    void write_varint(uint64_t val) {
        while (val >= 0x80ULL) {
            write_bits((val & 0x7FULL) | 0x80ULL, 8);
            val >>= 7;
        }
        write_bits(val & 0x7FULL, 8);
    }

    void write_trunc_bin(uint64_t x, uint64_t M) {
        if (M <= 1ULL) return;
        int k = static_cast<int>(std::bit_width(M)) - 1; // floor(log2(M))
        uint64_t p2 = 1ULL << (k + 1);
        uint64_t T = p2 - M;
        if (x < T) {
            write_bits(x, k);
        } else {
            uint64_t y = x + T;
            write_bits(y >> 1, k);
            write_bits(y & 1ULL, 1);
        }
    }

    void write_atom(const DualBasisAtom& a, int b_known = 0) {
        if (b_known == 0) {
            if (a.b == 64) {
                write_bits(1ULL, 1);
            } else {
                write_bits(0ULL, 1);
                write_bits(static_cast<uint64_t>(a.b - 1), 6);
            }
        }
        if (is_dyadic_atom_len(a.b)) {
            write_bits(a.beta == AtomBasis::ZHEG ? 1ULL : 0ULL, 1);
        }
        write_trunc_bin(a.w, static_cast<uint64_t>(a.b) + 1ULL);
        write_trunc_bin(a.rho, binom64(a.b, a.w));
    }

    std::vector<uint8_t> finish() {
        while (bits_ > 0) {
            out_.push_back(static_cast<uint8_t>(acc_ & 0xFFu));
            acc_ >>= 8;
            bits_ -= 8;
        }
        if (out_.empty()) out_.push_back(0x00u);
        return std::move(out_);
    }

private:
    std::vector<uint8_t> out_;
    unsigned __int128 acc_ = 0;
    int bits_ = 0;
};

// 128-bit accumulator LSB-first BitReader with strict bounds & zero-padding enforcement
class BitReader64 {
public:
    BitReader64(const uint8_t* data, size_t len) : data_(data), len_(len) {}

    uint64_t read_bits(int k) {
        if (k <= 0) return 0ULL;
        refill(k);
        if (bits_ < k) {
            throw std::runtime_error("Unexpected EOF in DAG bitstream");
        }
        uint64_t v = static_cast<uint64_t>(acc_) & low_mask(k);
        acc_ >>= k;
        bits_ -= k;
        return v;
    }

    uint64_t read_varint() {
        uint64_t val = 0ULL;
        int shift = 0;
        for (int iter = 0; iter < 10; ++iter) {
            uint64_t b = read_bits(8);
            if (iter == 9 && ((b & 0x80ULL) != 0ULL || (b & 0x7FULL) > 1ULL)) {
                throw std::runtime_error("ULEB128 64-bit integer overflow on 10th byte");
            }
            if ((b & 0x80ULL) == 0ULL) {
                if (iter > 0 && b == 0ULL) {
                    throw std::runtime_error("Non-canonical overlong ULEB128 varint");
                }
                val |= ((b & 0x7FULL) << shift);
                return val;
            }
            val |= ((b & 0x7FULL) << shift);
            shift += 7;
        }
        throw std::runtime_error("Malformed ULEB128 varint in DAG bitstream");
    }

    uint64_t read_trunc_bin(uint64_t M) {
        if (M == 0ULL) throw std::runtime_error("Invalid alphabet size M=0");
        if (M == 1ULL) return 0ULL;
        int k = static_cast<int>(std::bit_width(M)) - 1;
        uint64_t T = (1ULL << (k + 1)) - M;
        uint64_t v = read_bits(k);
        if (v < T) return v;
        uint64_t extra = read_bits(1);
        uint64_t x = ((v << 1) | extra) - T;
        if (x >= M) throw std::runtime_error("Truncated binary value out of range");
        return x;
    }

    DualBasisAtom read_atom(int b_known = 0) {
        int b = b_known;
        if (b == 0) {
            uint64_t is64 = read_bits(1);
            b = is64 ? 64 : static_cast<int>(read_bits(6) + 1ULL);
        }
        if (b < 1 || b > 64) throw std::runtime_error("Decoded atom b out of [1,64]");
        AtomBasis beta = AtomBasis::POS;
        if (is_dyadic_atom_len(b)) {
            beta = read_bits(1) ? AtomBasis::ZHEG : AtomBasis::POS;
        }
        uint64_t w = read_trunc_bin(static_cast<uint64_t>(b) + 1ULL);
        uint64_t cbw = binom64(b, static_cast<int>(w));
        uint64_t rho = read_trunc_bin(cbw);
        return DualBasisAtom{beta, static_cast<uint8_t>(b), static_cast<uint8_t>(w), rho};
    }

    void verify_zero_padding() {
        if (acc_ != 0) {
            throw std::runtime_error("Non-zero trailing padding bits in DAG payload");
        }
        while (pos_ < len_) {
            if (data_[pos_++] != 0x00u) {
                throw std::runtime_error("Non-zero trailing padding byte in DAG payload");
            }
        }
    }

private:
    void refill(int need) {
        while (bits_ < need && pos_ < len_) {
            if (bits_ <= 56 && pos_ + 8 <= len_) {
                uint64_t w = read_le64(data_ + pos_);
                acc_ |= (static_cast<unsigned __int128>(w) << bits_);
                pos_ += 8;
                bits_ += 64;
            } else {
                acc_ |= (static_cast<unsigned __int128>(data_[pos_++]) << bits_);
                bits_ += 8;
            }
        }
    }

    const uint8_t* data_;
    size_t len_;
    size_t pos_ = 0;
    unsigned __int128 acc_ = 0;
    int bits_ = 0;
};

// Serialize / Deserialize ExplicitChunkDAG per FORMAT_SPEC.md §4.3
inline std::vector<uint8_t> serialize_chunk_dag_payload(const ExplicitChunkDAG& dag) {
    BitWriter64 bw(dag.nodes.size() * 8 + 32);
    bw.write_varint(dag.nodes.size());
    bw.write_varint(dag.root);

    for (uint32_t v = 0; v < static_cast<uint32_t>(dag.nodes.size()); ++v) {
        const auto& nd = dag.nodes[v];
        if (std::holds_alternative<EmptyNode>(nd)) {
            bw.write_bits(static_cast<uint64_t>(NodeOp::EMPTY), 4);
        } else if (const auto* an = std::get_if<AtomNode>(&nd)) {
            bw.write_bits(static_cast<uint64_t>(NodeOp::ATOM), 4);
            bw.write_atom(an->atom, 0);
        } else if (const auto* asn = std::get_if<AtomSpanNode>(&nd)) {
            bw.write_bits(static_cast<uint64_t>(NodeOp::ATOM_SPAN), 4);
            size_t cnt = asn->atoms.size();
            bw.write_varint(cnt);
            bool homog = true;
            for (size_t i = 0; i + 1 < cnt; ++i) {
                if (asn->atoms[i].b != 64) { homog = false; break; }
            }
            if (homog) {
                bw.write_bits(1ULL, 1);
                bw.write_bits(static_cast<uint64_t>(asn->atoms.back().b - 1), 6);
                for (size_t i = 0; i + 1 < cnt; ++i) bw.write_atom(asn->atoms[i], 64);
                bw.write_atom(asn->atoms.back(), asn->atoms.back().b);
            } else {
                bw.write_bits(0ULL, 1);
                for (const auto& a : asn->atoms) bw.write_atom(a, 0);
            }
        } else if (const auto* cn = std::get_if<ConcatNode>(&nd)) {
            bw.write_bits(static_cast<uint64_t>(NodeOp::CONCAT), 4);
            bw.write_varint(cn->children.size() - 2);
            for (uint32_t u : cn->children) bw.write_varint(v - 1u - u);
        } else if (const auto* rn = std::get_if<RepeatNode>(&nd)) {
            bw.write_bits(static_cast<uint64_t>(NodeOp::REPEAT), 4);
            bw.write_varint(v - 1u - rn->child);
            bw.write_varint(rn->q - 1ULL);
            bw.write_varint(rn->r);
        } else if (const auto* sn = std::get_if<SliceNode>(&nd)) {
            bw.write_bits(static_cast<uint64_t>(NodeOp::SLICE), 4);
            bw.write_varint(v - 1u - sn->child);
            bw.write_varint(sn->start);
            bw.write_varint(sn->length - 1ULL);
        } else if (const auto* mn = std::get_if<MorphNode>(&nd)) {
            bw.write_bits(static_cast<uint64_t>(NodeOp::MORPH), 4);
            bw.write_varint(v - 1u - mn->child);
            bw.write_bits(static_cast<uint64_t>(mn->mu), 2);
        } else if (const auto* xn = std::get_if<XorDiffNode>(&nd)) {
            bw.write_bits(static_cast<uint64_t>(NodeOp::XOR_DIFF), 4);
            bw.write_varint(v - 1u - xn->base);
            bw.write_varint(v - 1u - xn->delta);
        } else if (const auto* in = std::get_if<InterleaveNode>(&nd)) {
            bw.write_bits(static_cast<uint64_t>(NodeOp::INTERLEAVE), 4);
            uint64_t sc = (in->stride == 8) ? 0 : (in->stride == 16 ? 1 : (in->stride == 32 ? 2 : 3));
            bw.write_bits(sc, 2);
            for (uint32_t u : in->lanes) bw.write_varint(v - 1u - u);
        } else if (const auto* ln = std::get_if<LfsrNode>(&nd)) {
            bw.write_bits(static_cast<uint64_t>(NodeOp::LFSR), 4);
            bw.write_bits(static_cast<uint64_t>(ln->degree - 1), 6);
            bw.write_bits(ln->conn_mask, ln->degree);
            bw.write_bits(ln->init_mask, ln->degree);
            bw.write_varint(ln->length);
        } else if (const auto* rn = std::get_if<RawNode>(&nd)) {
            bw.write_bits(static_cast<uint64_t>(NodeOp::RAW), 4);
            bw.write_varint(rn->bytes.size());
            for (uint8_t b : rn->bytes) bw.write_bits(b, 8);
            bw.write_varint(rn->bit_len);
        } else if (const auto* dn = std::get_if<DedupRefNode>(&nd)) {
            bw.write_bits(static_cast<uint64_t>(NodeOp::DEDUP_REF), 4);
            bw.write_varint(dn->ref_id);
        } else if (const auto* dn = std::get_if<DeflateHintNode>(&nd)) {
            bw.write_bits(static_cast<uint64_t>(NodeOp::DEFLATE_HINT), 4);
            bw.write_bits(dn->cm, 8);
            bw.write_bits(dn->flg, 8);
            bw.write_bits(dn->mtime, 16);
            bw.write_bits(dn->xfl, 8);
            bw.write_bits(dn->os, 8);
        }
    }
    return bw.finish();
}

inline ExplicitChunkDAG deserialize_chunk_dag_payload(const uint8_t* data, size_t len, uint64_t max_nodes_cap) {
    BitReader64 br(data, len);
    uint64_t m64 = br.read_varint();
    if (m64 == 0 || m64 > max_nodes_cap) {
        throw std::runtime_error("Invalid DAG node count in payload");
    }
    uint64_t root64 = br.read_varint();
    if (root64 >= m64) {
        throw std::runtime_error("Invalid DAG root index in payload");
    }

    ExplicitChunkDAG dag;
    dag.root = static_cast<uint32_t>(root64);
    dag.nodes.reserve(static_cast<size_t>(m64));

    auto rel_to_idx = [](uint32_t v, uint64_t rel) -> uint32_t {
        if (v == 0 || rel >= v) throw std::runtime_error("DAG relative edge index out of bounds");
        return v - 1u - static_cast<uint32_t>(rel);
    };

    for (uint32_t v = 0; v < static_cast<uint32_t>(m64); ++v) {
        uint64_t op = br.read_bits(4);
        switch (op) {
            case 0: // EMPTY
                dag.nodes.emplace_back(EmptyNode{});
                break;
            case 1: // ATOM
                dag.nodes.emplace_back(AtomNode{br.read_atom(0)});
                break;
            case 2: { // ATOM_SPAN
                uint64_t cnt = br.read_varint();
                if (cnt == 0 || cnt > max_nodes_cap) throw std::runtime_error("Invalid ATOM_SPAN count");
                uint64_t homog = br.read_bits(1);
                AtomSpanNode asn;
                asn.atoms.reserve(static_cast<size_t>(cnt));
                if (homog) {
                    int tail_b = static_cast<int>(br.read_bits(6) + 1ULL);
                    for (uint64_t i = 0; i + 1 < cnt; ++i) asn.atoms.push_back(br.read_atom(64));
                    asn.atoms.push_back(br.read_atom(tail_b));
                } else {
                    for (uint64_t i = 0; i < cnt; ++i) asn.atoms.push_back(br.read_atom(0));
                }
                dag.nodes.emplace_back(std::move(asn));
                break;
            }
            case 3: { // CONCAT
                uint64_t raw_d = br.read_varint();
                if (raw_d > max_nodes_cap) throw std::runtime_error("Invalid CONCAT degree");
                uint64_t d = raw_d + 2ULL;
                ConcatNode cn;
                cn.children.reserve(static_cast<size_t>(d));
                for (uint64_t i = 0; i < d; ++i) cn.children.push_back(rel_to_idx(v, br.read_varint()));
                dag.nodes.emplace_back(std::move(cn));
                break;
            }
            case 4: { // REPEAT
                uint32_t u = rel_to_idx(v, br.read_varint());
                uint64_t raw_q = br.read_varint();
                if (raw_q == ~0ULL) throw std::runtime_error("REPEAT count overflow");
                uint64_t q = raw_q + 1ULL;
                uint64_t r = br.read_varint();
                dag.nodes.emplace_back(RepeatNode{u, q, r});
                break;
            }
            case 5: { // SLICE
                uint32_t u = rel_to_idx(v, br.read_varint());
                uint64_t st = br.read_varint();
                uint64_t raw_ln = br.read_varint();
                if (raw_ln == ~0ULL) throw std::runtime_error("SLICE length overflow");
                uint64_t ln = raw_ln + 1ULL;
                dag.nodes.emplace_back(SliceNode{u, st, ln});
                break;
            }
            case 6: { // MORPH
                uint32_t u = rel_to_idx(v, br.read_varint());
                V4Op mu = static_cast<V4Op>(br.read_bits(2));
                dag.nodes.emplace_back(MorphNode{u, mu});
                break;
            }
            case 7: { // XOR_DIFF
                uint32_t b = rel_to_idx(v, br.read_varint());
                uint32_t d = rel_to_idx(v, br.read_varint());
                dag.nodes.emplace_back(XorDiffNode{b, d});
                break;
            }
            case 8: { // INTERLEAVE
                uint64_t sc = br.read_bits(2);
                uint8_t s = static_cast<uint8_t>(8u << sc);
                InterleaveNode in{s, {}};
                in.lanes.reserve(s);
                for (uint8_t i = 0; i < s; ++i) in.lanes.push_back(rel_to_idx(v, br.read_varint()));
                dag.nodes.emplace_back(std::move(in));
                break;
            }
            case 9: { // LFSR
                uint8_t L = static_cast<uint8_t>(br.read_bits(6) + 1ULL);
                uint64_t conn = br.read_bits(L);
                uint64_t init = br.read_bits(L);
                uint64_t length = br.read_varint();
                dag.nodes.emplace_back(LfsrNode{L, conn, init, length});
                break;
            }
            case 10: { // RAW
                uint64_t byte_cnt = br.read_varint();
                if (byte_cnt == 0) throw std::runtime_error("Invalid RAW byte count");
                RawNode rn;
                rn.bytes.resize(static_cast<size_t>(byte_cnt));
                for (uint64_t i = 0; i < byte_cnt; ++i) rn.bytes[i] = static_cast<uint8_t>(br.read_bits(8));
                rn.bit_len = br.read_varint();
                dag.nodes.emplace_back(std::move(rn));
                break;
            }
            case 11: { // DEDUP_REF
                uint64_t ref_id = br.read_varint();
                dag.nodes.emplace_back(DedupRefNode{ref_id});
                break;
            }
            case 12: { // DEFLATE_HINT
                DeflateHintNode dh;
                dh.cm = static_cast<uint8_t>(br.read_bits(8));
                dh.flg = static_cast<uint8_t>(br.read_bits(8));
                dh.mtime = static_cast<uint16_t>(br.read_bits(16));
                dh.xfl = static_cast<uint8_t>(br.read_bits(8));
                dh.os = static_cast<uint8_t>(br.read_bits(8));
                dag.nodes.emplace_back(dh);
                break;
            }
            default:
                throw std::runtime_error("Unknown DAG opcode in payload");
        }
    }
    return dag;
}

} // namespace mapr
