#pragma once
#include "marp/harness/e1_oracle.hpp"
#include <mapr/e1_bigint.hpp>
#include <mapr/e1_length.hpp>
#include <cstdint>
#include <string>
#include <vector>

namespace marp::harness {

// One node of a harness-owned, well-formed term DAG. This is deliberately a
// simple value type that implements mapr::TermView; it is not E2 code and is
// only used to exercise E1's length algebra.
struct TermNode {
    mapr::NodeKind kind = mapr::NodeKind::Empty;

    uint32_t atom_size = 0;             // Atom
    mapr::BigInt zero_n;                // Zero
    std::vector<uint32_t> children;     // Concat / Interleave
    uint32_t child = 0;                 // Repeat / Slice / Morph / Predictor
    mapr::BigInt repeat_q;              // Repeat
    mapr::BigInt repeat_r;              // Repeat
    mapr::BigInt slice_start;           // Slice
    mapr::BigInt slice_len;             // Slice
    mapr::BigInt n;                     // Lfsr / Affine
    uint32_t stride = 0;                // Interleave
    uint32_t xor_a = 0;                 // Xor
    uint32_t xor_b = 0;                 // Xor

    // Generation-time metadata. The view never exposes these, so a corrupted
    // stored length cannot influence mapr::length_of.
    uint64_t generation_length = 0;
    int depth = 1;

    // Deliberately corruptible side-table value used by the len.no_trust check.
    mapr::BigInt stored_length;
};

class TermSet final : public mapr::TermView {
public:
    std::vector<TermNode> nodes;

    mapr::NodeId root() const noexcept {
        return nodes.empty() ? 0u : static_cast<mapr::NodeId>(nodes.size() - 1);
    }

    size_t node_count() const noexcept override { return nodes.size(); }
    mapr::NodeKind node_kind(mapr::NodeId id) const noexcept override {
        return nodes[static_cast<size_t>(id)].kind;
    }
    size_t atom_size(mapr::NodeId id) const noexcept override {
        return static_cast<size_t>(nodes[static_cast<size_t>(id)].atom_size);
    }
    mapr::BigInt zero_count(mapr::NodeId id) const noexcept override {
        return nodes[static_cast<size_t>(id)].zero_n;
    }
    std::vector<mapr::NodeId> concat_children(mapr::NodeId id) const noexcept override {
        return nodes[static_cast<size_t>(id)].children;
    }
    mapr::NodeId repeat_child(mapr::NodeId id) const noexcept override {
        return nodes[static_cast<size_t>(id)].child;
    }
    const mapr::BigInt& repeat_q(mapr::NodeId id) const noexcept override {
        return nodes[static_cast<size_t>(id)].repeat_q;
    }
    const mapr::BigInt& repeat_r(mapr::NodeId id) const noexcept override {
        return nodes[static_cast<size_t>(id)].repeat_r;
    }
    mapr::NodeId slice_child(mapr::NodeId id) const noexcept override {
        return nodes[static_cast<size_t>(id)].child;
    }
    const mapr::BigInt& slice_start(mapr::NodeId id) const noexcept override {
        return nodes[static_cast<size_t>(id)].slice_start;
    }
    const mapr::BigInt& slice_len(mapr::NodeId id) const noexcept override {
        return nodes[static_cast<size_t>(id)].slice_len;
    }
    mapr::NodeId morph_child(mapr::NodeId id) const noexcept override {
        return nodes[static_cast<size_t>(id)].child;
    }
    mapr::NodeId xor_a(mapr::NodeId id) const noexcept override {
        return nodes[static_cast<size_t>(id)].xor_a;
    }
    mapr::NodeId xor_b(mapr::NodeId id) const noexcept override {
        return nodes[static_cast<size_t>(id)].xor_b;
    }
    std::vector<mapr::NodeId> interleave_children(mapr::NodeId id) const noexcept override {
        return nodes[static_cast<size_t>(id)].children;
    }
    uint32_t interleave_stride(mapr::NodeId id) const noexcept override {
        return nodes[static_cast<size_t>(id)].stride;
    }
    mapr::BigInt lfsr_n(mapr::NodeId id) const noexcept override {
        return nodes[static_cast<size_t>(id)].n;
    }
    mapr::BigInt affine_n(mapr::NodeId id) const noexcept override {
        return nodes[static_cast<size_t>(id)].n;
    }
    mapr::NodeId predictor_residual(mapr::NodeId id) const noexcept override {
        return nodes[static_cast<size_t>(id)].child;
    }
};

// Deterministically build `count` well-formed terms (each a separate DAG in
// topological order with the root last). Covers every NodeKind and depths 1-4.
std::vector<TermSet> build_terms(uint64_t seed, size_t count);

// SHA-256 of the canonical serialization of a term.
std::string term_fingerprint(const TermSet& term);

// Independent length computation using the base-10^9 oracle only.
std::vector<oracle::BigInt> oracle_lengths(const TermSet& term);

} // namespace marp::harness
