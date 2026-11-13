#pragma once
#include "e1_types.hpp"
#include "e1_bigint.hpp"
#include <vector>

namespace mapr {

// Node kinds (must match E2 definition)
enum class NodeKind {
    Empty,
    Atom,
    Zero,
    Concat,
    Repeat,
    Slice,
    Morph,
    Xor,
    Interleave,
    Lfsr,
    Affine,
    Predictor
};

// Forward declaration of the term DAG (owned by E2; E1 only sees the interface)
class TermView {
public:
    virtual ~TermView() = default;
    virtual size_t node_count() const noexcept = 0;
    virtual NodeKind node_kind(NodeId id) const noexcept = 0;

    // Atom
    virtual size_t atom_size(NodeId id) const noexcept = 0;

    // Zero
    virtual BigInt zero_count(NodeId id) const noexcept = 0;

    // Concat
    virtual std::vector<NodeId> concat_children(NodeId id) const noexcept = 0;

    // Repeat
    virtual NodeId repeat_child(NodeId id) const noexcept = 0;
    virtual const BigInt& repeat_q(NodeId id) const noexcept = 0;
    virtual const BigInt& repeat_r(NodeId id) const noexcept = 0;

    // Slice
    virtual NodeId slice_child(NodeId id) const noexcept = 0;
    virtual const BigInt& slice_start(NodeId id) const noexcept = 0;
    virtual const BigInt& slice_len(NodeId id) const noexcept = 0;

    // Morph
    virtual NodeId morph_child(NodeId id) const noexcept = 0;

    // Xor
    virtual NodeId xor_a(NodeId id) const noexcept = 0;
    virtual NodeId xor_b(NodeId id) const noexcept = 0;

    // Interleave
    virtual std::vector<NodeId> interleave_children(NodeId id) const noexcept = 0;
    virtual uint32_t interleave_stride(NodeId id) const noexcept = 0;

    // Lfsr
    virtual BigInt lfsr_n(NodeId id) const noexcept = 0;

    // Affine
    virtual BigInt affine_n(NodeId id) const noexcept = 0;

    // Predictor
    virtual NodeId predictor_residual(NodeId id) const noexcept = 0;
};

// Length result with memoisation table
struct LengthResult {
    BigInt length;                    // ℓ(t) for the root
    std::vector<BigInt> memo;         // memo[node_id] = ℓ(node), valid for reachable nodes
};

// Compute ℓ(t) for a well-formed term.
// Precondition: term is well-formed (E2 enforces; E1 asserts in debug).
// Returns Err::Invalid if a side condition is violated (e.g., Repeat r ≥ ℓ(c)).
Result<LengthResult> length_of(const TermView& term) noexcept;

// Structural identities (Math-SPECS §11.1). These are the O1.5 checks.
// Each takes child lengths already computed and returns the parent length.
namespace length_identity {
    inline BigInt concat(const std::vector<BigInt>& children) noexcept {
        BigInt sum = BigInt::zero();
        for (const auto& c : children) {
            auto r = sum.add(c);
            if (!r.ok()) return BigInt::zero();
            sum = std::move(r.value());
        }
        return sum;
    }

    inline BigInt repeat(const BigInt& child_len, const BigInt& q, const BigInt& r) noexcept {
        auto mq = q.mul(child_len);
        if (!mq.ok()) return BigInt::zero();
        auto mqr = mq.value().add(r);
        if (!mqr.ok()) return BigInt::zero();
        return mqr.value();
    }

    inline BigInt slice(const BigInt& /*child_len*/, const BigInt& /*start*/, const BigInt& len) noexcept {
        return len;
    }

    inline BigInt interleave(const std::vector<BigInt>& children, uint32_t /*stride*/) noexcept {
        if (children.empty()) return BigInt::zero();
        BigInt k(children.size());
        auto mk = k.mul(children[0]);
        if (!mk.ok()) return BigInt::zero();
        return mk.value();
    }

    inline BigInt morph(const BigInt& child_len) noexcept { return child_len; }
    inline BigInt xor_len(const BigInt& a, const BigInt& /*b*/) noexcept { return a; }
    inline BigInt predictor(const BigInt& residual_len) noexcept { return residual_len; }
    inline BigInt fixed(const BigInt& n) noexcept { return n; }
} // namespace length_identity

} // namespace mapr