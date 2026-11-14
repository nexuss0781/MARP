// C03 TERM — deterministic IR construction helpers for the C03 harness and
// unit tests.  This is *evidence support* code, not part of the C03 library:
// it lives under engine/src/e2/ but is never linked into e2_term.o.
//
// It owns atom payloads so that `Atom::payload` spans stay valid for the
// lifetime of the builder, and it computes every node length from structure
// with a third, independent implementation of the §4.4 formulas (the engine
// recomputation and the reference implementation are the other two).
#pragma once

#include <cstddef>
#include <deque>
#include <initializer_list>
#include <span>
#include <utility>
#include <vector>

#include "mapr/e1_sha256.hpp"
#include "mapr/e2/e2_term.hpp"

namespace c03 {

using namespace marp::v2;  // NOLINT

class Builder {
public:
    Builder() = default;
    Builder(const Builder&) = delete;
    Builder& operator=(const Builder&) = delete;
    Builder(Builder&&) = delete;
    Builder& operator=(Builder&&) = delete;

    u32 add_atom(std::span<const u8> payload, u8 klass = 0) {
        payload_store_.emplace_back(payload.begin(), payload.end());
        const std::vector<u8>& stored = payload_store_.back();
        Atom atom;
        atom.klass = klass;
        atom.flags = 0;
        atom.length = BigInt(static_cast<u64>(stored.size()));
        const std::string_view view(reinterpret_cast<const char*>(stored.data()),
                                    stored.size());
        auto digest = mapr::Sha256::hash(view);
        if (digest.ok()) atom.sha256 = digest.value();
        atom.payload = std::span<const u8>(stored.data(), stored.size());
        ir_.atoms.push_back(atom);
        return static_cast<u32>(ir_.atoms.size() - 1);
    }

    u32 add_atom(std::initializer_list<u8> payload, u8 klass = 0) {
        return add_atom(std::span<const u8>(payload.begin(), payload.size()), klass);
    }

    // --- node constructors (length computed from structure) ----------------
    u32 empty() {
        Node node;
        node.kind = Kind::Empty;
        return push(std::move(node), BigInt::zero());
    }

    // Atom carries its atom id in `a` and has argc 0 (E2 §4.5).
    u32 atom_node(u32 atom) {
        Node node;
        node.kind = Kind::Atom;
        node.a = BigInt(static_cast<u64>(atom));
        return push(std::move(node), atom_len(atom));
    }

    u32 zero(const BigInt& n) {
        Node node;
        node.kind = Kind::Zero;
        node.a = n;
        return push(std::move(node), n);
    }

    u32 zero(u64 n) { return zero(BigInt(n)); }

    u32 concat(std::vector<u32> children) {
        BigInt total = BigInt::zero();
        for (u32 child : children) total = total.add(len(child)).value();
        Node node;
        node.kind = Kind::Concat;
        node.args = std::move(children);
        return push(std::move(node), total);
    }

    u32 repeat(u32 child, const BigInt& q, const BigInt& r) {
        const BigInt length = q.mul(len(child)).value().add(r).value();
        Node node;
        node.kind = Kind::Repeat;
        node.args = {child};
        node.a = q;
        node.b = r;
        return push(std::move(node), length);
    }

    u32 repeat(u32 child, u64 q, u64 r) { return repeat(child, BigInt(q), BigInt(r)); }

    u32 slice(u32 child, const BigInt& start, const BigInt& length_param) {
        Node node;
        node.kind = Kind::Slice;
        node.args = {child};
        node.a = start;
        node.b = length_param;
        return push(std::move(node), length_param);
    }

    u32 slice(u32 child, u64 start, u64 length_param) {
        return slice(child, BigInt(start), BigInt(length_param));
    }

    u32 morph(u32 child, u8 morph_id, u8 k) {
        Node node;
        node.kind = Kind::Morph;
        node.args = {child};
        node.morph = morph_id;
        node.morph_k = k;
        return push(std::move(node), len(child));
    }

    u32 xor_node(u32 a, u32 b) {
        Node node;
        node.kind = Kind::Xor;
        node.args = {a, b};
        return push(std::move(node), len(a));
    }

    u32 interleave(std::vector<u32> children, u32 stride) {
        const BigInt length = BigInt(static_cast<u64>(children.size()))
                                  .mul(len(children.front()))
                                  .value();
        Node node;
        node.kind = Kind::Interleave;
        node.args = std::move(children);
        node.a = BigInt(stride);
        return push(std::move(node), length);
    }

    u32 lfsr(u64 conn, u64 init, const BigInt& n) {
        Node node;
        node.kind = Kind::Lfsr;
        node.lfsr_conn = conn;
        node.lfsr_init = init;
        node.a = n;
        return push(std::move(node), n);
    }

    u32 lfsr(u64 conn, u64 init, u64 n) { return lfsr(conn, init, BigInt(n)); }

    u32 affine(u8 start_byte, u8 step, const BigInt& n) {
        Node node;
        node.kind = Kind::Affine;
        node.affine_start = start_byte;
        node.affine_step = step;
        node.a = n;
        return push(std::move(node), n);
    }

    u32 affine(u8 start_byte, u8 step, u64 n) {
        return affine(start_byte, step, BigInt(n));
    }

    u32 predictor(u8 pid, u32 param, u32 residual) {
        Node node;
        node.kind = Kind::Predictor;
        node.args = {residual};
        node.predictor_id = pid;
        node.predictor_param = param;
        return push(std::move(node), len(residual));
    }

    // --- access / mutation for malformed-term cases ------------------------
    Node& node(u32 id) { return ir_.nodes[id]; }
    Atom& atom(u32 id) { return ir_.atoms[id]; }
    const std::vector<Node>& nodes() const { return ir_.nodes; }
    u32 count() const { return static_cast<u32>(ir_.nodes.size()); }
    const BigInt& len(u32 id) const { return ir_.nodes[id].length; }

    // Assembles the Ir.  `total_length` is taken from nodes[root].length unless
    // overridden, mirroring the IR contract of parent §4.
    Ir finish(u32 root) {
        ir_.root = root;
        ir_.total_length = ir_.nodes[root].length;
        return ir_;
    }

    Ir finish_with_total(u32 root, const BigInt& total) {
        ir_.root = root;
        ir_.total_length = total;
        return ir_;
    }

    const Ir& ir() const { return ir_; }

private:
    BigInt atom_len(u32 atom_id) const {
        return ir_.atoms[atom_id].length;
    }

    u32 push(Node node, const BigInt& computed_length) {
        node.length = computed_length;
        ir_.nodes.push_back(std::move(node));
        return static_cast<u32>(ir_.nodes.size() - 1);
    }

    std::deque<std::vector<u8>> payload_store_;
    Ir ir_;
};

// Byte patterns used across the corpus, kept tiny and deterministic.
inline std::vector<u8> pattern(std::size_t n, u8 seed = 0) {
    std::vector<u8> out(n);
    u8 state = seed;
    for (std::size_t i = 0; i < n; ++i) {
        state = static_cast<u8>((static_cast<unsigned>(state) * 37u + 11u) & 0xFFu);
        out[i] = state;
    }
    return out;
}

}  // namespace c03
