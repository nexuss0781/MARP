// C03 TERM — independent reference implementation (evidence only).
//
// This file is deliberately written in a different style from
// engine/src/e2/e2_term.cpp: it materialises whole byte strings with
// std::vector concatenation, iterates the LFSR bit by bit, uses a runtime
// 256-entry bit-reversal table, and computes GF(2) exponents with a
// *row-oriented* matrix instead of the engine's column-oriented one.  It shares
// no code with the engine so that agreement is evidence rather than a
// tautology.
//
// Scope: reference denotation, reference structural length, reference morph /
// predictor / LFSR including jump-ahead.  Never linked into a MARP target.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "mapr/e2/e2_term.hpp"

namespace c03ref {

using namespace marp::v2;  // NOLINT

// --- reference structural length -------------------------------------------
inline bool ref_length(const Ir& ir, u32 node, BigInt& out) {
    if (node >= ir.nodes.size()) return false;
    const Node& n = ir.nodes[node];
    switch (n.kind) {
        case Kind::Empty:
            out = BigInt::zero();
            return true;
        case Kind::Atom: {
            auto atom_id = n.a.to_u64_checked();
            if (!atom_id.has_value() || *atom_id >= ir.atoms.size()) return false;
            out = ir.atoms[static_cast<std::size_t>(*atom_id)].length;
            return true;
        }
        case Kind::Zero:
            out = n.a;
            return true;
        case Kind::Concat: {
            BigInt sum = BigInt::zero();
            for (u32 child : n.args) {
                BigInt cl;
                if (!ref_length(ir, child, cl)) return false;
                sum = sum.add(cl).value();
            }
            out = sum;
            return true;
        }
        case Kind::Repeat: {
            BigInt cl;
            if (n.args.size() != 1 || !ref_length(ir, n.args[0], cl)) return false;
            out = n.a.mul(cl).value().add(n.b).value();
            return true;
        }
        case Kind::Slice:
            out = n.b;
            return true;
        case Kind::Morph: {
            BigInt cl;
            if (n.args.size() != 1 || !ref_length(ir, n.args[0], cl)) return false;
            out = cl;
            return true;
        }
        case Kind::Xor: {
            BigInt cl;
            if (n.args.size() != 2 || !ref_length(ir, n.args[0], cl)) return false;
            out = cl;
            return true;
        }
        case Kind::Interleave: {
            BigInt cl;
            if (n.args.empty() || !ref_length(ir, n.args[0], cl)) return false;
            out = BigInt(static_cast<u64>(n.args.size())).mul(cl).value();
            return true;
        }
        case Kind::Lfsr:
        case Kind::Affine:
            out = n.a;
            return true;
        case Kind::Predictor: {
            BigInt cl;
            if (n.args.size() != 1 || !ref_length(ir, n.args[0], cl)) return false;
            out = cl;
            return true;
        }
    }
    return false;
}

// --- reference morphisms ----------------------------------------------------
inline const std::array<std::uint8_t, 256>& ref_bitrev_table() {
    static const std::array<std::uint8_t, 256> table = [] {
        std::array<std::uint8_t, 256> t{};
        for (unsigned v = 0; v < 256; ++v) {
            unsigned reversed = 0;
            for (unsigned b = 0; b < 8; ++b) {
                reversed |= ((v >> b) & 1u) << (7u - b);
            }
            t[v] = static_cast<std::uint8_t>(reversed);
        }
        return t;
    }();
    return table;
}

inline std::uint8_t ref_rotl(std::uint8_t v, unsigned k) {
    unsigned x = v;
    for (unsigned i = 0; i < k; ++i) x = ((x << 1) | (x >> 7)) & 0xFFu;
    return static_cast<std::uint8_t>(x);
}

inline std::uint8_t ref_rotr(std::uint8_t v, unsigned k) {
    unsigned x = v;
    for (unsigned i = 0; i < k; ++i) x = ((x >> 1) | (x << 7)) & 0xFFu;  // NOLINT
    return static_cast<std::uint8_t>(x);
}

// Applies a morph to a materialised segment.
inline bool ref_morph(u8 morph, u8 k, std::vector<std::uint8_t>& buf) {
    const std::size_t n = buf.size();
    switch (morph) {
        case 1:
            for (std::size_t i = 0; i < n; ++i) buf[i] = ref_bitrev_table()[buf[i]];
            return true;
        case 2:
            for (std::size_t i = 0; i < n; ++i) buf[i] = static_cast<std::uint8_t>(255u - buf[i]);
            return true;
        case 3:
        case 4:
        case 5: {
            const std::size_t b = (morph == 3) ? 2u : (morph == 4) ? 4u : 8u;
            if (n % b != 0) return false;
            for (std::size_t base = 0; base < n; base += b) {
                for (std::size_t i = 0; i < b / 2; ++i) {
                    std::swap(buf[base + i], buf[base + b - 1 - i]);
                }
            }
            return true;
        }
        case 6:
            if (k < 1 || k > 7) return false;
            for (std::size_t i = 0; i < n; ++i) buf[i] = ref_rotl(buf[i], k);
            return true;
        case 7:
            if (k < 1 || k > 7) return false;
            for (std::size_t i = 0; i < n; ++i) buf[i] = ref_rotr(buf[i], k);
            return true;
        case 8:
            for (std::size_t i = 0; i < n / 2; ++i) std::swap(buf[i], buf[n - 1 - i]);
            return true;
        case 9: {
            // out[j] = bitrev(in[n-1-j]): must not run in place.
            const std::vector<std::uint8_t> source = buf;
            for (std::size_t i = 0; i < n; ++i) {
                buf[i] = ref_bitrev_table()[source[n - 1 - i]];
            }
            return true;
        }
        default:
            return false;
    }
}

// --- reference predictors ---------------------------------------------------
inline bool ref_predictor(u8 pid, u32 param, const std::vector<std::uint8_t>& residual,
                          std::vector<std::uint8_t>& out) {
    const std::size_t n = residual.size();
    if (pid > 4) return false;
    if (pid >= 3 && param == 0) return false;
    out.assign(n, 0);
    if (n == 0) return true;
    if (pid == 0) {
        out[0] = residual[0];
        for (std::size_t i = 1; i < n; ++i) {
            out[i] = static_cast<std::uint8_t>((out[i - 1] + residual[i]) & 0xFFu);
        }
        return true;
    }
    if (pid == 1) {
        out[0] = residual[0];
        for (std::size_t i = 1; i < n; ++i) {
            out[i] = static_cast<std::uint8_t>(out[i - 1] ^ residual[i]);
        }
        return true;
    }
    if (pid == 2) {
        // Literal §4.11 / §3.6 text, including its known defect (the residual is
        // not consulted for i >= 2).
        out[0] = residual[0];
        if (n == 1) return true;
        out[1] = residual[1];
        for (std::size_t i = 2; i < n; ++i) {
            const unsigned v = 2u * out[i - 1] - out[i - 2];
            out[i] = static_cast<std::uint8_t>(v & 0xFFu);
        }
        return true;
    }
    for (std::size_t i = 0; i < n; ++i) {
        const std::uint8_t prev = (i < param) ? std::uint8_t{0} : out[i - param];
        if (pid == 3) {
            out[i] = static_cast<std::uint8_t>(prev ^ residual[i]);
        } else {
            out[i] = static_cast<std::uint8_t>((prev + residual[i]) & 0xFFu);
        }
    }
    return true;
}

// --- reference LFSR ---------------------------------------------------------
inline bool ref_lfsr_bytes(u64 conn, u64 init, std::size_t count,
                           std::vector<std::uint8_t>& out) {
    if (conn == 0) return false;
    out.assign(count, 0);
    std::uint64_t state = init;
    for (std::size_t i = 0; i < count; ++i) {
        unsigned byte = 0;
        for (unsigned b = 0; b < 8; ++b) {
            unsigned parity = 0;
            for (unsigned bit = 0; bit < 64; ++bit) {
                parity ^= static_cast<unsigned>((state >> bit) & 1u) &
                          static_cast<unsigned>((conn >> bit) & 1u);
            }
            state = (state >> 1) | (static_cast<std::uint64_t>(parity) << 63);
            byte = (byte << 1) | parity;
        }
        out[i] = static_cast<std::uint8_t>(byte);
    }
    return true;
}

// Row-oriented GF(2) matrix: row[j] is the mask of input bits feeding output
// bit j.  Independent of the engine's column-oriented representation.
struct RowMatrix {
    std::array<std::uint64_t, 64> row{};
};

inline std::uint64_t row_apply(const RowMatrix& m, std::uint64_t x) {
    std::uint64_t y = 0;
    for (unsigned j = 0; j < 64; ++j) {
        if (__builtin_parityll(m.row[j] & x) != 0) y |= (std::uint64_t{1} << j);
    }
    return y;
}

inline RowMatrix row_compose(const RowMatrix& outer, const RowMatrix& inner) {
    RowMatrix result;
    for (unsigned j = 0; j < 64; ++j) {
        std::uint64_t mask = 0;
        for (unsigned k = 0; k < 64; ++k) {
            if (((outer.row[j] >> k) & 1u) != 0) mask ^= inner.row[k];
        }
        result.row[j] = mask;
    }
    return result;
}

inline RowMatrix row_lfsr_matrix(u64 conn) {
    RowMatrix m;
    for (unsigned j = 0; j < 64; ++j) {
        // bit j of T(x) = bit j+1 of x (for j < 63) XOR (conn parity term at j=63)
        if (j < 63) m.row[j] = std::uint64_t{1} << (j + 1);
        else m.row[j] = conn;
    }
    return m;
}

// T^bits by square-and-multiply over the row-oriented representation.
inline bool ref_lfsr_state_at_bits(u64 conn, u64 init, std::uint64_t bits,
                                   std::uint64_t& state) {
    if (conn == 0) return false;
    RowMatrix result;  // identity
    for (unsigned j = 0; j < 64; ++j) result.row[j] = std::uint64_t{1} << j;
    RowMatrix acc = row_lfsr_matrix(conn);
    std::uint64_t e = bits;
    while (e != 0) {
        if ((e & 1u) != 0) result = row_compose(acc, result);
        acc = row_compose(acc, acc);
        e >>= 1;
    }
    state = row_apply(result, init);
    return true;
}

// Emits bytes from an already-computed LFSR state (jump-ahead support).
inline bool ref_lfsr_from_state(u64 conn, std::uint64_t state, std::size_t count,
                                std::vector<std::uint8_t>& out) {
    if (conn == 0) return false;
    out.assign(count, 0);
    for (std::size_t i = 0; i < count; ++i) {
        unsigned byte = 0;
        for (unsigned b = 0; b < 8; ++b) {
            unsigned parity = 0;
            for (unsigned bit = 0; bit < 64; ++bit) {
                parity ^= static_cast<unsigned>((state >> bit) & 1u) &
                          static_cast<unsigned>((conn >> bit) & 1u);
            }
            state = (state >> 1) | (static_cast<std::uint64_t>(parity) << 63);
            byte = (byte << 1) | parity;
        }
        out[i] = static_cast<std::uint8_t>(byte);
    }
    return true;
}

// --- reference denotation ---------------------------------------------------
inline bool ref_denote(const Ir& ir, u32 node, std::vector<std::uint8_t>& out,
                       std::size_t cap);

inline bool ref_denote_children(const Ir& ir, const Node& n, std::size_t cap,
                                std::vector<std::vector<std::uint8_t>>& parts) {
    parts.clear();
    for (u32 child : n.args) {
        std::vector<std::uint8_t> child_bytes;
        if (!ref_denote(ir, child, child_bytes, cap)) return false;
        parts.push_back(std::move(child_bytes));
    }
    return true;
}

inline bool ref_denote(const Ir& ir, u32 node, std::vector<std::uint8_t>& out,
                       std::size_t cap) {
    if (node >= ir.nodes.size()) return false;
    const Node& n = ir.nodes[node];
    BigInt expected;
    if (!ref_length(ir, node, expected)) return false;
    auto expected_u64 = expected.to_u64_checked();
    if (!expected_u64.has_value() || *expected_u64 > cap) return false;
    out.clear();
    out.reserve(static_cast<std::size_t>(*expected_u64));

    switch (n.kind) {
        case Kind::Empty:
            return true;
        case Kind::Atom: {
            auto atom_id = n.a.to_u64_checked();
            if (!atom_id.has_value() || *atom_id >= ir.atoms.size()) return false;
            const auto& payload = ir.atoms[static_cast<std::size_t>(*atom_id)].payload;
            out.assign(payload.begin(), payload.end());
            return true;
        }
        case Kind::Zero: {
            const std::size_t z = static_cast<std::size_t>(*expected_u64);
            out.assign(z, 0);
            return true;
        }
        case Kind::Concat: {
            std::vector<std::vector<std::uint8_t>> parts;
            if (!ref_denote_children(ir, n, cap, parts)) return false;
            for (const auto& part : parts) out.insert(out.end(), part.begin(), part.end());
            return true;
        }
        case Kind::Repeat: {
            std::vector<std::uint8_t> child;
            if (n.args.size() != 1 || !ref_denote(ir, n.args[0], child, cap)) return false;
            auto q = n.a.to_u64_checked();
            auto r = n.b.to_u64_checked();
            if (!q.has_value() || !r.has_value()) return false;
            if (*q > 0 && child.empty()) return false;
            for (std::uint64_t i = 0; i < *q; ++i) out.insert(out.end(), child.begin(), child.end());
            out.insert(out.end(), child.begin(),
                       child.begin() + static_cast<std::ptrdiff_t>(*r));
            return true;
        }
        case Kind::Slice: {
            std::vector<std::uint8_t> child;
            if (n.args.size() != 1 || !ref_denote(ir, n.args[0], child, cap)) return false;
            auto start = n.a.to_u64_checked();
            auto len = n.b.to_u64_checked();
            if (!start.has_value() || !len.has_value()) return false;
            if (*start + *len > child.size()) return false;
            out.assign(child.begin() + static_cast<std::ptrdiff_t>(*start),
                       child.begin() + static_cast<std::ptrdiff_t>(*start + *len));
            return true;
        }
        case Kind::Morph: {
            std::vector<std::uint8_t> child;
            if (n.args.size() != 1 || !ref_denote(ir, n.args[0], child, cap)) return false;
            if (!ref_morph(n.morph, n.morph_k, child)) return false;
            out = std::move(child);
            return true;
        }
        case Kind::Xor: {
            std::vector<std::vector<std::uint8_t>> parts;
            if (!ref_denote_children(ir, n, cap, parts) || parts.size() != 2) return false;
            if (parts[0].size() != parts[1].size()) return false;
            out.resize(parts[0].size());
            for (std::size_t i = 0; i < out.size(); ++i) {
                out[i] = static_cast<std::uint8_t>(parts[0][i] ^ parts[1][i]);
            }
            return true;
        }
        case Kind::Interleave: {
            std::vector<std::vector<std::uint8_t>> parts;
            if (!ref_denote_children(ir, n, cap, parts) || parts.empty()) return false;
            auto stride = n.a.to_u64_checked();
            if (!stride.has_value() || *stride == 0) return false;
            const std::size_t s = static_cast<std::size_t>(*stride);
            const std::size_t l = parts[0].size();
            if (l % s != 0) return false;
            for (const auto& part : parts) {
                if (part.size() != l) return false;
            }
            const std::size_t blocks = l / s;
            out.reserve(blocks * s * parts.size());
            for (std::size_t b = 0; b < blocks; ++b) {
                for (const auto& part : parts) {
                    out.insert(out.end(), part.begin() + static_cast<std::ptrdiff_t>(b * s),
                               part.begin() + static_cast<std::ptrdiff_t>((b + 1) * s));
                }
            }
            return true;
        }
        case Kind::Lfsr: {
            auto count = n.a.to_u64_checked();
            if (!count.has_value()) return false;
            return ref_lfsr_bytes(n.lfsr_conn, n.lfsr_init,
                                  static_cast<std::size_t>(*count), out);
        }
        case Kind::Affine: {
            const std::size_t z = static_cast<std::size_t>(*expected_u64);
            out.resize(z);
            for (std::size_t i = 0; i < z; ++i) {
                const unsigned v = static_cast<unsigned>(n.affine_start) +
                                   static_cast<unsigned>(i % 256) *
                                       static_cast<unsigned>(n.affine_step);
                out[i] = static_cast<std::uint8_t>(v & 0xFFu);
            }
            return true;
        }
        case Kind::Predictor: {
            std::vector<std::uint8_t> residual;
            if (n.args.size() != 1 || !ref_denote(ir, n.args[0], residual, cap)) return false;
            return ref_predictor(n.predictor_id, n.predictor_param, residual, out);
        }
    }
    return false;
}

}  // namespace c03ref
