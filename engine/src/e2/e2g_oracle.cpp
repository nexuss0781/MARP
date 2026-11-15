// MARP v2 — E2-G integrated ALGEBRA gate — H3 oracle binding (implementation).
//
// This file is the only place in the gate where the engine `Ir` and the H3
// oracle meet.  It copies structure; it computes nothing that the gate then
// compares against a copy of itself.

#include "e2g_oracle.hpp"

#include <cstring>
#include <utility>

namespace e2g {

namespace {

// Read-only ByteSource over a vector the binding owns.
class PayloadSource final : public od::ByteSource {
public:
    explicit PayloadSource(std::shared_ptr<const std::vector<std::uint8_t>> bytes)
        : bytes_(std::move(bytes)) {}

    std::uint64_t size() const noexcept override { return bytes_->size(); }

    bool read_at(std::uint64_t offset, std::span<std::uint8_t> dst) const override {
        if (offset > bytes_->size()) return false;
        if (dst.size() > bytes_->size() - static_cast<std::size_t>(offset)) return false;
        const auto* base = bytes_->data() + static_cast<std::size_t>(offset);
        std::memcpy(dst.data(), base, dst.size());
        return true;
    }

private:
    std::shared_ptr<const std::vector<std::uint8_t>> bytes_;
};

od::NodeKind to_oracle_kind(Kind kind) {
    switch (kind) {
        case Kind::Empty: return od::NodeKind::Empty;
        case Kind::Atom: return od::NodeKind::Atom;
        case Kind::Zero: return od::NodeKind::Zero;
        case Kind::Concat: return od::NodeKind::Concat;
        case Kind::Repeat: return od::NodeKind::Repeat;
        case Kind::Slice: return od::NodeKind::Slice;
        case Kind::Morph: return od::NodeKind::Morph;
        case Kind::Xor: return od::NodeKind::Xor;
        case Kind::Interleave: return od::NodeKind::Interleave;
        case Kind::Lfsr: return od::NodeKind::Lfsr;
        case Kind::Affine: return od::NodeKind::Affine;
        case Kind::Predictor: return od::NodeKind::Predictor;
    }
    return od::NodeKind::Empty;
}

}  // namespace

marp::oracle::detail::BigInt to_oracle(const BigInt& value) {
    const std::vector<std::uint8_t> le = value.to_le_bytes();
    return od::BigInt::from_le_bytes(std::span<const std::uint8_t>(le.data(), le.size()));
}

BigInt from_oracle(const od::BigInt& value) {
    const std::vector<std::uint8_t> le = value.to_le_bytes();
    auto parsed = mapr::BigInt::from_le_bytes(
        std::string_view(reinterpret_cast<const char*>(le.data()), le.size()));
    return parsed.ok() ? parsed.value() : BigInt::zero();
}

std::array<std::uint8_t, 32> oracle_sha256(std::span<const std::uint8_t> bytes) {
    od::Sha256 hasher;
    hasher.update(bytes);
    return hasher.finalize();
}

std::uint32_t oracle_crc32(std::span<const std::uint8_t> bytes) {
    od::Crc32 crc;
    crc.update(bytes);
    return crc.value();
}

OracleBinding make_binding(const Ir& ir) {
    OracleBinding binding;
    auto blob = std::make_shared<std::vector<std::uint8_t>>();
    auto& c = binding.container;

    // Atom table + payload blob.
    std::vector<std::uint64_t> atom_offsets(ir.atoms.size(), 0);
    for (std::size_t i = 0; i < ir.atoms.size(); ++i) {
        atom_offsets[i] = blob->size();
        blob->insert(blob->end(), ir.atoms[i].payload.begin(), ir.atoms[i].payload.end());
        od::AtomRecord rec;
        rec.klass = ir.atoms[i].klass;
        rec.length = static_cast<std::uint64_t>(ir.atoms[i].payload.size());
        std::memcpy(rec.sha256.data(), ir.atoms[i].sha256.data(), 32);
        rec.payload_offset = atom_offsets[i];
        c.atoms.push_back(rec);
    }

    // Node table.  Every structural field is copied; nothing is recomputed.
    c.nodes.reserve(ir.nodes.size());
    for (const Node& n : ir.nodes) {
        od::NodeRecord rec;
        rec.kind = to_oracle_kind(n.kind);
        rec.args = n.args;
        if (n.kind == Kind::Atom) {
            const auto atom_id = n.a.to_u64_checked();
            rec.atom_id = atom_id.has_value() ? static_cast<std::uint32_t>(*atom_id) : 0U;
        }
        switch (n.kind) {
            case Kind::Zero:
            case Kind::Lfsr:
            case Kind::Affine:
                rec.param_a = to_oracle(n.a);
                break;
            case Kind::Slice:
                rec.param_a = to_oracle(n.a);
                rec.param_b = to_oracle(n.b);
                break;
            case Kind::Repeat:
                rec.param_a = to_oracle(n.a);
                rec.param_b = to_oracle(n.b);
                break;
            case Kind::Interleave: {
                const auto stride = n.a.to_u64_checked();
                rec.stride = stride.has_value() ? static_cast<std::uint32_t>(*stride) : 0U;
                break;
            }
            default:
                break;
        }
        rec.morph = n.morph;
        rec.morph_k = n.morph_k;
        rec.lfsr_conn = n.lfsr_conn;
        rec.lfsr_init = n.lfsr_init;
        rec.affine_start = n.affine_start;
        rec.affine_step = n.affine_step;
        rec.predictor_id = n.predictor_id;
        rec.predictor_param = n.predictor_param;
        rec.length = to_oracle(n.length);
        rec.depth = 0;
        c.nodes.push_back(std::move(rec));
    }

    // Depth, computed structurally (the oracle evaluator does not need it, but
    // the container contract states it is set).
    for (std::size_t i = 0; i < c.nodes.size(); ++i) {
        std::uint32_t max_child = 0;
        for (const std::uint32_t arg : c.nodes[i].args) {
            if (arg < c.nodes.size() && c.nodes[arg].depth > max_child) {
                max_child = c.nodes[arg].depth;
            }
        }
        c.nodes[i].depth = (c.nodes[i].kind == od::NodeKind::Empty) ? 0U : (max_child + 1U);
    }

    c.trailer.root_id = ir.root;
    c.trailer.node_count = static_cast<std::uint32_t>(c.nodes.size());
    c.trailer.atom_count = static_cast<std::uint32_t>(c.atoms.size());
    c.total_length = to_oracle(ir.total_length);
    c.header.total_length_u64 = 0;
    c.has_index = false;

    binding.payload = std::move(blob);
    binding.source = std::make_unique<PayloadSource>(binding.payload);
    return binding;
}

BigInt oracle_length(const OracleBinding& binding, std::uint32_t node, bool& ok) {
    const od::BigInt value = od::oracle_node_length(binding.container, node, ok);
    return from_oracle(value);
}

bool oracle_denote(const OracleBinding& binding, std::uint32_t node,
                   std::vector<std::uint8_t>& out, std::string& error) {
    out.clear();
    bool length_ok = true;
    const od::BigInt length = od::oracle_node_length(binding.container, node, length_ok);
    if (!length_ok || !length.fits_u64()) {
        error = "denotation length exceeds u64";
        return false;
    }
    std::vector<std::uint8_t> buffer(static_cast<std::size_t>(length.to_u64()));
    marp::oracle::Diagnostic diag;
    const int rc = od::eval_node_range_iterative(binding.container, *binding.source, node,
                                                 od::BigInt(0),
                                                 std::span<std::uint8_t>(buffer.data(),
                                                                         buffer.size()),
                                                 marp::oracle::Limits{}, &diag);
    if (rc != 0) {
        error = "oracle eval failed: " + diag.message;
        return false;
    }
    out = std::move(buffer);
    return true;
}

bool oracle_range(const OracleBinding& binding, std::uint32_t node,
                  const od::BigInt& start, std::size_t len, std::vector<std::uint8_t>& out,
                  std::string& error) {
    // The spec's range contract (§5.3) rejects a range that runs past the
    // declared length: `start + len <= ℓ(node)`.  The oracle's evaluator reads a
    // slice and would happily zero-fill past the end, so the bound is enforced
    // here, from the oracle's *own* structural length analysis.
    bool length_ok = true;
    const od::BigInt length = od::oracle_node_length(binding.container, node, length_ok);
    if (!length_ok) {
        error = "oracle: node length is not defined";
        return false;
    }
    const od::BigInt end = od::BigInt::add(start, od::BigInt(static_cast<std::uint64_t>(len)));
    if (od::BigInt::compare(start, length) > 0 || od::BigInt::compare(end, length) > 0) {
        error = "oracle: range past declared length";
        return false;
    }
    out.assign(len, 0);
    marp::oracle::Diagnostic diag;
    const int rc = od::eval_node_range_iterative(
        binding.container, *binding.source, node, start,
        std::span<std::uint8_t>(out.data(), out.size()), marp::oracle::Limits{}, &diag);
    if (rc != 0) {
        error = "oracle range failed: " + diag.message;
        return false;
    }
    return true;
}

std::uint64_t oracle_lfsr_state(u64 conn, u64 init, const od::BigInt& byte_offset) {
    return od::lfsr_jump_bytes(conn, init, byte_offset);
}

void oracle_lfsr_emit(u64 conn, std::uint64_t& state, std::span<std::uint8_t> out) {
    od::lfsr_emit(conn, state, out);
}

}  // namespace e2g
