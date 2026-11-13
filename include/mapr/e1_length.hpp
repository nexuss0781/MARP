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
    BigInt concat(const std::vector<BigInt>& children) noexcept;
    BigInt repeat(const BigInt& child_len, const BigInt& q, const BigInt& r) noexcept;
    BigInt slice(const BigInt& child_len, const BigInt& start, const BigInt& len) noexcept;
    BigInt interleave(const std::vector<BigInt>& children, uint32_t stride) noexcept;
    BigInt morph(const BigInt& child_len) noexcept { return child_len; }
    BigInt xor_len(const BigInt& a, const BigInt& /*b*/) noexcept { return a; } // a==b by well-formedness
    BigInt predictor(const BigInt& residual_len) noexcept { return residual_len; }
    BigInt fixed(const BigInt& n) noexcept { return n; } // Zero, Lfsr, Affine
} // namespace length_identity

} // namespace mapr