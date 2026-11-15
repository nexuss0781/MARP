// MARP v2 — E2 ALGEBRA — C03 TERM implementation.
//
// Every obligation in this file is traceable to:
//   SPECS/COMPONENTS/e2-algebra/SPECS.md §4 (model), §5.1 (validation),
//   §5.3–5.5 (evaluation), §8 (interface), §9 (errors);
//   SPECS/SPECS-V2.md §3 (grammar, morphisms, LFSR, predictors, lengths).
//
// No file, environment, thread, time, or global mutable state is touched.
// No E3–E7 symbol is referenced.

#include "mapr/e2/e2_term.hpp"

#include <algorithm>
#include <cstring>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "mapr/e1_sha256.hpp"
#include "mapr/e2/e2_eval.hpp"

namespace marp::v2 {
namespace {

// --- error mapping ---------------------------------------------------------

Status to_status(mapr::ErrCode code) {
    return code == mapr::ErrCode::Limit ? Code::Limit : Code::Invalid;
}

// --- exact arithmetic helpers (E1 BigInt only) -----------------------------

Result<BigInt> bi_add(const BigInt& x, const BigInt& y) {
    auto r = x.add(y);
    if (!r.ok()) return to_status(r.error()).code();
    return std::move(r.value());
}

Result<BigInt> bi_sub(const BigInt& x, const BigInt& y) {
    auto r = x.sub(y);
    if (!r.ok()) return to_status(r.error()).code();
    return std::move(r.value());
}

Result<BigInt> bi_mul(const BigInt& x, const BigInt& y) {
    auto r = x.mul(y);
    if (!r.ok()) return to_status(r.error()).code();
    return std::move(r.value());
}

// value mod divisor (divisor != 0).
Result<BigInt> bi_mod(const BigInt& value, const BigInt& divisor) {
    if (divisor.is_zero()) return Code::Invalid;
    auto r = value.divmod(divisor);
    if (!r.ok()) return to_status(r.error()).code();
    return std::move(r.value().second);
}

// Converts to u64; values that do not fit are a resource bound, never a
// silent truncation.
Result<u64> bi_to_u64(const BigInt& value) {
    auto v = value.to_u64_checked();
    if (!v.has_value()) return Code::Limit;
    return *v;
}

BigInt bi_min(const BigInt& x, const BigInt& y) {
    return x.compare(y) <= 0 ? x : y;
}

// min(a, b, cap) expressed as u64; all operands non-negative.
Result<u64> min_u64(const BigInt& a, const BigInt& b, u64 cap) {
    const BigInt m = bi_min(a, b);
    if (m.compare(BigInt(cap)) > 0) return cap;
    return bi_to_u64(m);
}

// --- morphism catalogue tables --------------------------------------------

// Byte-local morphs only (1, 2, 6, 7).
bool morph_valid_byte_k(u8 morph, u8 k) {
    switch (morph) {
        case 1: case 2: case 8: case 9:
            return k == 0;
        case 3: case 4: case 5:
            return k == 0;
        case 6: case 7:
            return k >= 1 && k <= 7;
        default:
            return false;
    }
}

inline u8 rotl8(u8 x, unsigned k) noexcept {
    const unsigned v = static_cast<unsigned>(x);
    return static_cast<u8>(((v << k) | (v >> (8u - k))) & 0xFFu);
}

inline u8 rotr8(u8 x, unsigned k) noexcept {
    const unsigned v = static_cast<unsigned>(x);
    return static_cast<u8>(((v >> k) | (v << (8u - k))) & 0xFFu);
}

}  // namespace

// ---------------------------------------------------------------------------
// Names and domains
// ---------------------------------------------------------------------------

const char* code_name(Code code) noexcept {
    switch (code) {
        case Code::Ok: return "Ok";
        case Code::Invalid: return "Invalid";
        case Code::Limit: return "Limit";
    }
    return "?";
}

const char* kind_name(Kind kind) noexcept {
    switch (kind) {
        case Kind::Empty: return "Empty";
        case Kind::Atom: return "Atom";
        case Kind::Zero: return "Zero";
        case Kind::Concat: return "Concat";
        case Kind::Repeat: return "Repeat";
        case Kind::Slice: return "Slice";
        case Kind::Morph: return "Morph";
        case Kind::Xor: return "Xor";
        case Kind::Interleave: return "Interleave";
        case Kind::Lfsr: return "Lfsr";
        case Kind::Affine: return "Affine";
        case Kind::Predictor: return "Predictor";
    }
    return "?";
}

bool parse_kind(u8 raw, Kind& out) noexcept {
    if (raw >= static_cast<u8>(kKindCount)) return false;
    out = static_cast<Kind>(raw);
    return true;
}

Status check_kind_domain(u8 raw) {
    Kind ignored = Kind::Empty;
    return parse_kind(raw, ignored) ? Status{} : Status(Code::Invalid);
}

const char* morph_name(u8 morph) noexcept {
    switch (morph) {
        case 1: return "BIT_REVERSE8";
        case 2: return "INVERT8";
        case 3: return "SWAP16";
        case 4: return "SWAP32";
        case 5: return "SWAP64";
        case 6: return "ROTL8";
        case 7: return "ROTR8";
        case 8: return "REVERSE_BYTES";
        case 9: return "REVERSE_BITS";
        default: return "?";
    }
}

const char* predictor_name(u8 pid) noexcept {
    switch (pid) {
        case 0: return "DELTA8";
        case 1: return "XOR8";
        case 2: return "LINEAR2";
        case 3: return "STRIDE_XOR";
        case 4: return "STRIDE_DELTA";
        default: return "?";
    }
}

const BigInt& max_output_bytes() {
    static const BigInt kCap = [] {
        auto v = BigInt(1).shl(63);
        return v.ok() ? std::move(v.value()) : BigInt::zero();
    }();
    return kCap;
}

const BigInt& predictor_prefix_limit() {
    static const BigInt kLimit = [] {
        auto v = BigInt(1).shl(28);
        return v.ok() ? std::move(v.value()) : BigInt::zero();
    }();
    return kLimit;
}

Result<u32> interleave_stride(const Node& node) noexcept {
    auto v = node.a.to_u64_checked();
    if (!v.has_value()) return Code::Invalid;
    if (*v > 0xFFFFFFFFull) return Code::Invalid;
    return static_cast<u32>(*v);
}

// ---------------------------------------------------------------------------
// Lengths (E2 §4.4)
// ---------------------------------------------------------------------------

namespace {

struct LengthTable {
    std::vector<BigInt> length;
    std::vector<char> known;
};

// Bottom-up recomputation; stored lengths are never consulted.
Result<LengthTable> compute_lengths(const Ir& ir) {
    const std::size_t node_count = ir.nodes.size();
    LengthTable table;
    table.length.assign(node_count, BigInt::zero());
    table.known.assign(node_count, 0);

    for (u32 i = 0; i < node_count; ++i) {
        const Node& node = ir.nodes[i];
        const std::size_t argc = node.args.size();

        auto child_known = [&](std::size_t index) -> bool {
            if (index >= argc) return false;
            const u32 id = node.args[index];
            if (id >= node_count) return false;
            return table.known[id] != 0;
        };
        auto child_len = [&](std::size_t index) -> const BigInt& {
            return table.length[node.args[index]];
        };

        bool known = false;
        BigInt value = BigInt::zero();

        switch (node.kind) {
            case Kind::Empty:
                known = (argc == 0);
                break;
            case Kind::Atom: {
                if (argc == 0) {
                    auto atom_id = node.a.to_u64_checked();
                    if (atom_id.has_value() && *atom_id < ir.atoms.size()) {
                        known = true;
                        value = ir.atoms[static_cast<std::size_t>(*atom_id)].length;
                    }
                }
                break;
            }
            case Kind::Zero:
                if (argc == 0) {
                    known = true;
                    value = node.a;
                }
                break;
            case Kind::Concat: {
                known = true;
                value = BigInt::zero();
                for (std::size_t k = 0; k < argc; ++k) {
                    if (!child_known(k)) { known = false; break; }
                    auto sum = bi_add(value, child_len(k));
                    if (!sum.ok()) return sum.code();
                    value = std::move(sum.value());
                }
                break;
            }
            case Kind::Repeat: {
                if (argc == 1 && child_known(0)) {
                    auto copies = bi_mul(node.a, child_len(0));
                    if (!copies.ok()) return copies.code();
                    auto total = bi_add(copies.value(), node.b);
                    if (!total.ok()) return total.code();
                    known = true;
                    value = std::move(total.value());
                }
                break;
            }
            case Kind::Slice:
                if (argc == 1) {
                    known = true;
                    value = node.b;
                }
                break;
            case Kind::Morph:
                if (argc == 1 && child_known(0)) {
                    known = true;
                    value = child_len(0);
                }
                break;
            case Kind::Xor:
                if (argc == 2 && child_known(0) && child_known(1)) {
                    known = true;
                    value = child_len(0);
                }
                break;
            case Kind::Interleave: {
                if (argc >= 1 && child_known(0)) {
                    auto k = bi_mul(BigInt(static_cast<u64>(argc)), child_len(0));
                    if (!k.ok()) return k.code();
                    known = true;
                    value = std::move(k.value());
                }
                break;
            }
            case Kind::Lfsr:
                if (argc == 0) {
                    known = true;
                    value = node.a;
                }
                break;
            case Kind::Affine:
                if (argc == 0) {
                    known = true;
                    value = node.a;
                }
                break;
            case Kind::Predictor:
                if (argc == 1 && child_known(0)) {
                    known = true;
                    value = child_len(0);
                }
                break;
        }

        table.length[i] = std::move(value);
        table.known[i] = known ? 1 : 0;
    }
    return table;
}

}  // namespace

Result<std::vector<std::optional<BigInt>>> recompute_lengths(const Ir& ir) {
    auto table = compute_lengths(ir);
    if (!table.ok()) return table.code();
    std::vector<std::optional<BigInt>> out;
    out.reserve(table.value().length.size());
    for (std::size_t i = 0; i < table.value().length.size(); ++i) {
        if (table.value().known[i] != 0) {
            out.emplace_back(table.value().length[i]);
        } else {
            out.emplace_back(std::nullopt);
        }
    }
    return out;
}

Result<std::vector<BigInt>> recompute_lengths_checked(const Ir& ir) {
    auto table = compute_lengths(ir);
    if (!table.ok()) return table.code();
    for (std::size_t i = 0; i < table.value().known.size(); ++i) {
        if (table.value().known[i] == 0) return Code::Invalid;
    }
    return std::move(table.value().length);
}

// ---------------------------------------------------------------------------
// Well-formedness (E2 §4.3–4.5)
// ---------------------------------------------------------------------------

namespace {

WfReport make_report(Code code, u32 node, const char* constraint, std::string message) {
    WfReport report;
    report.code = code;
    report.node = node;
    report.constraint = constraint;
    report.message = std::move(message);
    return report;
}

// Fills `used` with the reachable node set from `root`; returns the smallest
// offending arg index pair (node, arg) where the arg is out of range, if any.
struct ReachResult {
    std::vector<char> reachable;
    bool arg_range_ok = true;
    u32 bad_node = 0;
    u32 bad_arg = 0;
};

ReachResult compute_reachability(const Ir& ir, u32 root) {
    const std::size_t node_count = ir.nodes.size();
    ReachResult result;
    result.reachable.assign(node_count, 0);
    result.reachable[root] = 1;

    std::vector<u32> stack;
    stack.push_back(root);
    while (!stack.empty()) {
        const u32 id = stack.back();
        stack.pop_back();
        for (u32 arg : ir.nodes[id].args) {
            if (arg >= node_count) {
                if (result.arg_range_ok ||
                    id < result.bad_node ||
                    (id == result.bad_node && arg < result.bad_arg)) {
                    result.arg_range_ok = false;
                    result.bad_node = id;
                    result.bad_arg = arg;
                }
                continue;
            }
            if (result.reachable[arg] == 0) {
                result.reachable[arg] = 1;
                stack.push_back(arg);
            }
        }
    }
    return result;
}

}  // namespace

WfReport check_well_formed_report(const Ir& ir) {
    return check_well_formed_report(ir, Limits{});
}

WfReport check_well_formed_report(const Ir& ir, const Limits& limits) {
    const std::size_t node_count = ir.nodes.size();
    const std::size_t atom_count = ir.atoms.size();

    // --- W1: counts -------------------------------------------------------
    if (node_count > limits.max_nodes) {
        return make_report(Code::Invalid, 0, kC_counts,
                           "nodes=" + std::to_string(node_count) + " > max_nodes=" +
                               std::to_string(limits.max_nodes));
    }
    if (atom_count > limits.max_atoms) {
        return make_report(Code::Invalid, 0, kC_counts,
                           "atoms=" + std::to_string(atom_count) + " > max_atoms=" +
                               std::to_string(limits.max_atoms));
    }

    // --- W4 + kind domain + atom record consistency ------------------------
    for (u32 i = 0; i < atom_count; ++i) {
        if (ir.atoms[i].flags != 0) {
            return make_report(Code::Invalid, i, kC_atom_flags,
                               "atom flags=" + std::to_string(ir.atoms[i].flags));
        }
        auto declared = ir.atoms[i].length.to_u64_checked();
        if (!declared.has_value() ||
            *declared != static_cast<u64>(ir.atoms[i].payload.size())) {
            return make_report(Code::Invalid, i, kC_atom_payload,
                               "atom declared length disagrees with payload size " +
                                   std::to_string(ir.atoms[i].payload.size()));
        }
    }
    for (u32 i = 0; i < node_count; ++i) {
        const Node& node = ir.nodes[i];
        if (node.flags != 0) {
            return make_report(Code::Invalid, i, kC_node_flags,
                               "node flags=" + std::to_string(node.flags));
        }
        Kind parsed = Kind::Empty;
        if (!parse_kind(static_cast<u8>(node.kind), parsed)) {
            return make_report(Code::Invalid, i, kC_kind, "kind outside closed domain");
        }
    }

    // --- W2: root ---------------------------------------------------------
    if (node_count == 0) {
        return make_report(Code::Invalid, 0, kC_root, "no nodes");
    }
    if (ir.root >= node_count) {
        return make_report(Code::Invalid, ir.root, kC_root,
                           "root=" + std::to_string(ir.root) + " >= nodes=" +
                               std::to_string(node_count));
    }

    // --- W2: reachability and atom usage -----------------------------------
    const ReachResult reach = compute_reachability(ir, ir.root);
    // W2 (reachability) is reported before W3 (argument range), per the fixed
    // §5.1 order.
    for (u32 i = 0; i < node_count; ++i) {
        if (reach.reachable[i] == 0) {
            return make_report(Code::Invalid, i, kC_reachable, "node unreachable from root");
        }
    }
    if (!reach.arg_range_ok) {
        return make_report(Code::Invalid, reach.bad_node, kC_arg_range,
                           "arg " + std::to_string(reach.bad_arg) + " out of range");
    }
    {
        std::vector<char> atom_used(atom_count, 0);
        for (u32 i = 0; i < node_count; ++i) {
            const Node& node = ir.nodes[i];
            if (node.kind == Kind::Atom) {
                auto atom_id = node.a.to_u64_checked();
                if (atom_id.has_value() && *atom_id < atom_count) {
                    atom_used[static_cast<std::size_t>(*atom_id)] = 1;
                }
            }
        }
        for (u32 i = 0; i < atom_count; ++i) {
            if (atom_used[i] == 0) {
                return make_report(Code::Invalid, i, kC_atom_unused, "atom unused");
            }
        }
    }

    // --- W5: total length -------------------------------------------------
    if (ir.total_length.compare(ir.nodes[ir.root].length) != 0) {
        return make_report(Code::Invalid, ir.root, kC_total_length,
                           "total_length=" + ir.total_length.to_decimal() +
                               " != nodes[root].length=" +
                               ir.nodes[ir.root].length.to_decimal());
    }

    // --- W3: argument ordering --------------------------------------------
    for (u32 i = 0; i < node_count; ++i) {
        const Node& node = ir.nodes[i];
        for (std::size_t k = 0; k < node.args.size(); ++k) {
            if (node.args[k] >= i) {
                return make_report(Code::Invalid, i, kC_arg_order,
                                   "arg[" + std::to_string(k) + "]=" +
                                       std::to_string(node.args[k]) + " >= " +
                                       std::to_string(i));
            }
        }
    }

    // --- W6: recomputed lengths -------------------------------------------
    const auto lengths = compute_lengths(ir);
    if (!lengths.ok()) {
        return make_report(lengths.code(), 0, kC_length, "length arithmetic failed");
    }
    const LengthTable& table = lengths.value();
    for (u32 i = 0; i < node_count; ++i) {
        if (table.known[i] == 0) continue;  // rejected by the kind pass below
        if (table.length[i].compare(ir.nodes[i].length) != 0) {
            return make_report(Code::Invalid, i, kC_length,
                               "stored=" + ir.nodes[i].length.to_decimal() +
                                   " recomputed=" + table.length[i].to_decimal());
        }
    }

    // --- §8.3 output cap ---------------------------------------------------
    if (limits.enforce_output_cap && table.known[ir.root] != 0 &&
        table.length[ir.root].compare(max_output_bytes()) > 0) {
        return make_report(Code::Limit, ir.root, kC_output_cap,
                           "output " + table.length[ir.root].to_decimal() + " > 2^63");
    }

    // --- W7: depth --------------------------------------------------------
    {
        std::vector<u32> depth(node_count, 0);
        for (u32 i = 0; i < node_count; ++i) {
            const Node& node = ir.nodes[i];
            if (node.kind == Kind::Empty) {
                depth[i] = 0;
                continue;
            }
            u32 d = 0;
            for (u32 arg : node.args) {
                if (arg >= node_count) continue;  // already rejected above
                d = std::max(d, depth[arg]);
            }
            if (d >= limits.max_depth) {
                return make_report(Code::Limit, i, kC_depth,
                                   "depth " + std::to_string(d + 1) + " > " +
                                       std::to_string(limits.max_depth));
            }
            depth[i] = d + 1;
        }
    }

    // --- W8: kind-specific constraints ------------------------------------
    for (u32 i = 0; i < node_count; ++i) {
        const Node& node = ir.nodes[i];
        const std::size_t argc = node.args.size();
        const auto argc_is = [&](std::size_t expected) { return argc == expected; };
        auto child_len = [&](std::size_t index) -> const BigInt& {
            return table.length[node.args[index]];
        };
        auto fail_kind = [&](const char* constraint, std::string message) {
            return make_report(Code::Invalid, i, constraint, std::move(message));
        };

        switch (node.kind) {
            case Kind::Empty:
                if (!argc_is(0)) return fail_kind(kC_argc, "Empty argc != 0");
                break;
            case Kind::Atom: {
                if (!argc_is(0)) return fail_kind(kC_argc, "Atom argc != 0");
                auto atom_id = node.a.to_u64_checked();
                if (!atom_id.has_value() || *atom_id >= atom_count) {
                    return fail_kind(kC_atom_id, "atom id out of range");
                }
                if (ir.atoms[static_cast<std::size_t>(*atom_id)].length.is_zero()) {
                    return fail_kind(kC_atom_len, "zero-length atom");
                }
                break;
            }
            case Kind::Zero:
                if (!argc_is(0)) return fail_kind(kC_argc, "Zero argc != 0");
                break;
            case Kind::Concat:
                if (argc < 2) return fail_kind(kC_argc, "Concat argc < 2");
                break;
            case Kind::Repeat: {
                if (!argc_is(1)) return fail_kind(kC_argc, "Repeat argc != 1");
                const BigInt& q = node.a;
                const BigInt& r = node.b;
                if (q.is_zero()) {
                    if (!r.is_zero()) {
                        return fail_kind(kC_repeat, "Repeat q=0 requires r=0");
                    }
                } else {
                    if (r.compare(child_len(0)) >= 0) {
                        return fail_kind(kC_repeat, "Repeat r >= len(child)");
                    }
                }
                break;
            }
            case Kind::Slice: {
                if (!argc_is(1)) return fail_kind(kC_argc, "Slice argc != 1");
                const BigInt& start = node.a;
                const BigInt& len = node.b;
                const BigInt& child = child_len(0);
                if (start.compare(child) > 0) {
                    return fail_kind(kC_slice, "Slice start > len(child)");
                }
                auto end = bi_add(start, len);
                if (!end.ok()) return make_report(Code::Limit, i, kC_slice, "slice overflow");
                if (end.value().compare(child) > 0) {
                    return fail_kind(kC_slice, "Slice start+len > len(child)");
                }
                break;
            }
            case Kind::Morph: {
                if (!argc_is(1)) return fail_kind(kC_argc, "Morph argc != 1");
                const Status st = check_morph_params(node.morph, node.morph_k, child_len(0));
                if (!st.ok()) {
                    return make_report(st.code(), i, kC_morph,
                                       std::string("morph ") + std::to_string(node.morph) +
                                           " k=" + std::to_string(node.morph_k));
                }
                break;
            }
            case Kind::Xor: {
                if (!argc_is(2)) return fail_kind(kC_argc, "Xor argc != 2");
                if (child_len(0).compare(child_len(1)) != 0) {
                    return fail_kind(kC_xor, "Xor operand lengths differ");
                }
                break;
            }
            case Kind::Interleave: {
                if (argc < 1) return fail_kind(kC_argc, "Interleave argc < 1");
                auto stride = interleave_stride(node);
                if (!stride.ok()) {
                    return fail_kind(kC_interleave, "Interleave stride not a u32");
                }
                if (stride.value() == 0) {
                    return fail_kind(kC_interleave, "Interleave stride == 0");
                }
                const BigInt& first = child_len(0);
                for (std::size_t k = 1; k < argc; ++k) {
                    if (child_len(k).compare(first) != 0) {
                        return fail_kind(kC_interleave, "Interleave child lengths differ");
                    }
                }
                auto rem = first.divmod_scalar(stride.value());
                if (!rem.ok()) {
                    return make_report(to_status(rem.error()).code(), i, kC_interleave,
                                       "Interleave length division failed");
                }
                if (rem.value().second != 0) {
                    return fail_kind(kC_interleave, "Interleave L % stride != 0");
                }
                break;
            }
            case Kind::Lfsr:
                if (!argc_is(0)) return fail_kind(kC_argc, "Lfsr argc != 0");
                if (node.lfsr_conn == 0) return fail_kind(kC_lfsr, "Lfsr conn == 0");
                break;
            case Kind::Affine:
                if (!argc_is(0)) return fail_kind(kC_argc, "Affine argc != 0");
                break;
            case Kind::Predictor: {
                if (!argc_is(1)) return fail_kind(kC_argc, "Predictor argc != 1");
                const Status st = check_predictor_params(node.predictor_id,
                                                         node.predictor_param);
                if (!st.ok()) {
                    return make_report(st.code(), i, kC_predictor,
                                       std::string("pid ") +
                                           std::to_string(node.predictor_id) + " param " +
                                           std::to_string(node.predictor_param));
                }
                // `len(residual) = n` (§4.5): Predictor carries no separate `n`
                // parameter (parent §3.2, §5.5), so the constraint is exactly
                // ℓ(Predictor) = ℓ(residual), already enforced by W6.
                break;
            }
        }
    }

    // Canonical shape (§4.7) is C04's obligation, not C03's; it is not
    // evaluated here.
    return WfReport{};
}

Status check_well_formed(const Ir& ir) {
    const WfReport report = check_well_formed_report(ir);
    return report.ok() ? Status{} : Status(report.code);
}

Status check_well_formed(const Ir& ir, const Limits& limits) {
    const WfReport report = check_well_formed_report(ir, limits);
    return report.ok() ? Status{} : Status(report.code);
}

Status verify_atom_digests(const Ir& ir) {
    for (const Atom& atom : ir.atoms) {
        const std::string_view payload(
            reinterpret_cast<const char*>(atom.payload.data()), atom.payload.size());
        auto digest = mapr::Sha256::hash(payload);
        if (!digest.ok()) return to_status(digest.error());
        if (digest.value() != atom.sha256) return Code::Invalid;
    }
    return Status{};
}

// ---------------------------------------------------------------------------
// Morphisms (E2 §4.6)
// ---------------------------------------------------------------------------

Status check_morph_domain(u8 morph) {
    return (morph >= 1 && morph <= kMorphCount) ? Status{} : Status(Code::Invalid);
}

u32 morph_block_size(u8 morph) noexcept {
    switch (morph) {
        case 3: return 2;
        case 4: return 4;
        case 5: return 8;
        default: return 0;
    }
}

bool morph_is_byte_local(u8 morph) noexcept {
    return morph == 1 || morph == 2 || morph == 6 || morph == 7;
}

Status check_morph_params(u8 morph, u8 k, const BigInt& length) {
    if (!check_morph_domain(morph).ok()) return Code::Invalid;
    if (!morph_valid_byte_k(morph, k)) return Code::Invalid;
    const u32 block = morph_block_size(morph);
    if (block != 0) {
        auto rem = length.divmod_scalar(block);
        if (!rem.ok()) return to_status(rem.error());
        if (rem.value().second != 0) return Code::Invalid;
    }
    return Status{};
}

u8 bit_reverse8(u8 x) noexcept {
    unsigned v = static_cast<unsigned>(x);
    v = ((v & 0x55u) << 1) | ((v & 0xAAu) >> 1);
    v = ((v & 0x33u) << 2) | ((v & 0xCCu) >> 2);
    v = ((v & 0x0Fu) << 4) | ((v & 0xF0u) >> 4);
    return static_cast<u8>(v & 0xFFu);
}

u8 apply_morph_byte(u8 morph, u8 k, u8 in) noexcept {
    switch (morph) {
        case 1: return bit_reverse8(in);
        case 2: return static_cast<u8>(~in);
        case 6: return rotl8(in, static_cast<unsigned>(k));
        case 7: return rotr8(in, static_cast<unsigned>(k));
        default:
            // Block/mirrored morphs are not byte-local; see header contract.
            return in;
    }
}

Result<u8> apply_morph_byte_checked(u8 morph, u8 k, u8 in) {
    if (!morph_is_byte_local(morph)) return Code::Invalid;
    if (!morph_valid_byte_k(morph, k)) return Code::Invalid;
    return apply_morph_byte(morph, k, in);
}

Status apply_morph_to_buffer(u8 morph, u8 k, std::span<u8> buffer) {
    if (!check_morph_domain(morph).ok()) return Code::Invalid;
    const BigInt len(static_cast<u64>(buffer.size()));
    if (!check_morph_params(morph, k, len).ok()) return Code::Invalid;

    switch (morph) {
        case 1:
            for (u8& byte : buffer) byte = bit_reverse8(byte);
            return Status{};
        case 2:
            for (u8& byte : buffer) byte = static_cast<u8>(~byte);
            return Status{};
        case 3:
        case 4:
        case 5: {
            const std::size_t block = morph_block_size(morph);
            for (std::size_t base = 0; base + block <= buffer.size(); base += block) {
                std::reverse(buffer.begin() + static_cast<std::ptrdiff_t>(base),
                             buffer.begin() + static_cast<std::ptrdiff_t>(base + block));
            }
            return Status{};
        }
        case 6:
            for (u8& byte : buffer) byte = rotl8(byte, static_cast<unsigned>(k));
            return Status{};
        case 7:
            for (u8& byte : buffer) byte = rotr8(byte, static_cast<unsigned>(k));
            return Status{};
        case 8:
            std::reverse(buffer.begin(), buffer.end());
            return Status{};
        case 9:
            std::reverse(buffer.begin(), buffer.end());
            for (u8& byte : buffer) byte = bit_reverse8(byte);
            return Status{};
        default:
            return Code::Invalid;
    }
}

// ---------------------------------------------------------------------------
// Predictors (E2 §4.11)
// ---------------------------------------------------------------------------

Status check_predictor_domain(u8 pid) {
    return pid < kPredictorCount ? Status{} : Status(Code::Invalid);
}

Status check_predictor_params(u8 pid, u32 param) {
    if (!check_predictor_domain(pid).ok()) return Code::Invalid;
    if (pid >= 3 && param < 1) return Code::Invalid;
    return Status{};
}

u8 apply_predictor_step(u8 pid, u32 param, u8 residual, u8 prev1, u8 prev2) noexcept {
    (void)param;
    const unsigned p1 = static_cast<unsigned>(prev1);
    const unsigned p2 = static_cast<unsigned>(prev2);
    const unsigned r = static_cast<unsigned>(residual);
    switch (pid) {
        case 0: return static_cast<u8>((p1 + r) & 0xFFu);                // DELTA8
        case 1: return static_cast<u8>((p1 ^ r) & 0xFFu);                // XOR8
        case 2: return static_cast<u8>((2u * p1 - p2) & 0xFFu);          // LINEAR2, literal §4.11
        case 3: return static_cast<u8>((p1 ^ r) & 0xFFu);                // STRIDE_XOR
        case 4: return static_cast<u8>((p1 + r) & 0xFFu);                // STRIDE_DELTA
        default: return residual;                                        // closed domain guard
    }
}

Result<u8> apply_predictor_step_checked(u8 pid, u32 param, u8 residual, u8 prev1, u8 prev2) {
    if (!check_predictor_params(pid, param).ok()) return Code::Invalid;
    return apply_predictor_step(pid, param, residual, prev1, prev2);
}

Status apply_predictor_to_buffer(u8 pid, u32 param, std::span<const u8> residual,
                                 std::span<u8> out) {
    if (!check_predictor_params(pid, param).ok()) return Code::Invalid;
    if (out.size() != residual.size()) return Code::Invalid;
    const std::size_t n = residual.size();
    if (n == 0) return Status{};
    if (pid == 3 || pid == 4) {
        const std::size_t s = param;
        for (std::size_t i = 0; i < n; ++i) {
            const u8 prev = (i < s) ? 0u : out[i - s];
            out[i] = apply_predictor_step(pid, param, residual[i], prev, 0);
        }
        return Status{};
    }
    out[0] = residual[0];
    for (std::size_t i = 1; i < n; ++i) {
        const u8 prev1 = out[i - 1];
        const u8 prev2 = (i >= 2) ? out[i - 2] : 0u;
        if (pid == 2 && i == 1) {
            out[1] = residual[1];  // §4.11: out[1] = r[1]
            continue;
        }
        out[i] = apply_predictor_step(pid, param, residual[i], prev1, prev2);
    }
    return Status{};
}

// ---------------------------------------------------------------------------
// LFSR (E2 §4.10)
// ---------------------------------------------------------------------------

Status check_lfsr_conn(u64 conn) {
    return conn == 0 ? Status(Code::Invalid) : Status{};
}

u64 lfsr_parity(u64 value) noexcept {
    return static_cast<u64>(__builtin_parityll(value));
}

u64 lfsr_step(u64 state, u64 conn) noexcept {
    const u64 bit = lfsr_parity(state & conn);
    return (state >> 1) | (bit << 63);
}

u8 lfsr_next_byte(u64& state, u64 conn) noexcept {
    unsigned byte = 0;
    for (unsigned b = 0; b < 8; ++b) {
        const u64 bit = lfsr_parity(state & conn);
        state = (state >> 1) | (bit << 63);
        byte = (byte << 1) | static_cast<unsigned>(bit);  // MSB-first packing
    }
    return static_cast<u8>(byte & 0xFFu);
}

u64 gf2_apply(const Gf2Matrix64& map, u64 value) noexcept {
    u64 out = 0;
    u64 x = value;
    while (x != 0) {
        const unsigned index = static_cast<unsigned>(__builtin_ctzll(x));
        out ^= map.col[index];
        x &= x - 1;
    }
    return out;
}

Gf2Matrix64 gf2_compose(const Gf2Matrix64& outer, const Gf2Matrix64& inner) noexcept {
    Gf2Matrix64 result;
    for (unsigned i = 0; i < 64; ++i) result.col[i] = gf2_apply(outer, inner.col[i]);
    return result;
}

Gf2Matrix64 lfsr_step_matrix(u64 conn) noexcept {
    Gf2Matrix64 map;
    for (unsigned i = 0; i < 64; ++i) {
        u64 image = (i >= 1) ? (u64{1} << (i - 1)) : 0;
        if (((conn >> i) & 1u) != 0) image |= (u64{1} << 63);
        map.col[i] = image;
    }
    return map;
}

Gf2Matrix64 gf2_power(const Gf2Matrix64& base, const BigInt& exponent) {
    Gf2Matrix64 result;  // identity
    for (unsigned i = 0; i < 64; ++i) result.col[i] = u64{1} << i;

    const std::size_t limbs = exponent.limb_count();
    bool started = false;
    for (std::size_t k = limbs; k-- > 0;) {
        const mapr::Limb word = exponent.limb(k);
        for (int bit = 31; bit >= 0; --bit) {
            if (started) result = gf2_compose(result, result);
            if (((word >> static_cast<unsigned>(bit)) & 1u) != 0) {
                result = gf2_compose(base, result);
                started = true;
            }
        }
    }
    return result;
}

Result<u64> lfsr_state_at_byte_offset(u64 conn, u64 init, const BigInt& byte_offset) {
    if (!check_lfsr_conn(conn).ok()) return Code::Invalid;
    auto bits = byte_offset.shl(3);  // 8 bit-steps per byte
    if (!bits.ok()) return to_status(bits.error()).code();
    const Gf2Matrix64 map = gf2_power(lfsr_step_matrix(conn), bits.value());
    return gf2_apply(map, init);
}

LfsrStream::LfsrStream(u64 conn, u64 init) : conn_(conn), init_(init), state_(init) {}

Status LfsrStream::jump_to_byte_offset(const BigInt& byte_offset) {
    auto state = lfsr_state_at_byte_offset(conn_, init_, byte_offset);
    if (!state.ok()) return state.code();
    state_ = state.value();
    return Status{};
}

u8 LfsrStream::next_byte() noexcept { return lfsr_next_byte(state_, conn_); }

Status LfsrStream::read(std::span<u8> out) noexcept {
    for (u8& byte : out) byte = next_byte();
    return Status{};
}

Status lfsr_read_range(u64 conn, u64 init, const BigInt& byte_offset, std::span<u8> out) {
    LfsrStream stream(conn, init);
    const Status jumped = stream.jump_to_byte_offset(byte_offset);
    if (!jumped.ok()) return jumped;
    return stream.read(out);
}

// ---------------------------------------------------------------------------
// Denotation & C05 Evaluation Core (E2 §4.9, §5.3–5.5, §11)
//
// Zero C++ call-stack recursion: all full/range/cursor evaluations execute on
// an explicit heap-allocated frame stack bounded by `limits.wf.max_depth`
// (W7 = 2^16), streaming through fixed block buffers with bounded scratch
// memory and per-session predictor/LFSR rolling state.
// ---------------------------------------------------------------------------

namespace {

constexpr std::size_t kConcatBinarySearchMinArgs = 8u;
constexpr std::size_t kMaxPredSlotsPerNode = 4u;
constexpr std::size_t kMaxPredRollingSlots = 32u;
constexpr std::size_t kMaxLfsrSlots = 16u;
constexpr std::size_t kDeepStackThreshold = 64u;
constexpr std::size_t kDeepXorChunkCap = 256u;
constexpr std::size_t kDeepPredChunkCap = 1024u;

Gf2Matrix64 gf2_power_counted(const Gf2Matrix64& base, const BigInt& exponent, u64* mul_ops) {
    Gf2Matrix64 result;  // identity
    for (unsigned i = 0; i < 64; ++i) result.col[i] = u64{1} << i;

    const std::size_t limbs = exponent.limb_count();
    bool started = false;
    u64 ops = 0;
    for (std::size_t k = limbs; k-- > 0;) {
        const mapr::Limb word = exponent.limb(k);
        for (int bit = 31; bit >= 0; --bit) {
            if (started) {
                result = gf2_compose(result, result);
                ++ops;
            }
            if (((word >> static_cast<unsigned>(bit)) & 1u) != 0) {
                result = gf2_compose(base, result);
                ++ops;
                started = true;
            }
        }
    }
    if (mul_ops != nullptr) *mul_ops += ops;
    return result;
}

Result<u64> lfsr_state_at_byte_offset_counted(u64 conn, u64 init, const BigInt& byte_offset,
                                              u64* mul_ops) {
    if (!check_lfsr_conn(conn).ok()) return Code::Invalid;
    if (byte_offset.is_zero()) return init;
    auto bits = byte_offset.shl(3);  // 8 bit-steps per byte
    if (!bits.ok()) return to_status(bits.error()).code();
    const Gf2Matrix64 map = gf2_power_counted(lfsr_step_matrix(conn), bits.value(), mul_ops);
    return gf2_apply(map, init);
}

// Validates only the subterm reachable from `subterm_root` (used exclusively by
// C03's `denote_node` test/harness helper, where sibling nodes in a shared
// Builder may be unreferenced).  All normative C05 entry points (`eval_stream`,
// `eval_range`, `read_range`, `TermCursor`, `PreparedEval`) enforce full `WF(ir)`.
Status check_subterm_well_formed(const Ir& ir, u32 subterm_root, const Limits& limits,
                                 const LengthTable& table, std::vector<char>& out_reach) {
    const std::size_t node_count = ir.nodes.size();
    const std::size_t atom_count = ir.atoms.size();
    if (node_count > limits.max_nodes || atom_count > limits.max_atoms) return Code::Invalid;
    if (subterm_root >= node_count) return Code::Invalid;

    const ReachResult reach = compute_reachability(ir, subterm_root);
    if (!reach.arg_range_ok) return Code::Invalid;

    std::vector<u32> depth(node_count, 0);
    for (u32 i = 0; i < node_count; ++i) {
        if (reach.reachable[i] == 0) continue;
        const Node& node = ir.nodes[i];
        if (node.flags != 0) return Code::Invalid;
        Kind parsed = Kind::Empty;
        if (!parse_kind(static_cast<u8>(node.kind), parsed)) return Code::Invalid;
        for (u32 arg : node.args) {
            if (arg >= i) return Code::Invalid;
        }
        if (table.known[i] == 0) return Code::Invalid;
        if (table.length[i].compare(node.length) != 0) return Code::Invalid;

        if (node.kind != Kind::Empty) {
            u32 d = 0;
            for (u32 arg : node.args) d = std::max(d, depth[arg]);
            if (d >= limits.max_depth) return Code::Limit;
            depth[i] = d + 1;
        }

        const std::size_t argc = node.args.size();
        switch (node.kind) {
            case Kind::Empty:
            case Kind::Zero:
            case Kind::Affine:
                if (argc != 0) return Code::Invalid;
                break;
            case Kind::Atom: {
                if (argc != 0) return Code::Invalid;
                auto atom_id = node.a.to_u64_checked();
                if (!atom_id.has_value() || *atom_id >= atom_count) return Code::Invalid;
                const Atom& atom = ir.atoms[static_cast<std::size_t>(*atom_id)];
                if (atom.flags != 0) return Code::Invalid;
                auto decl = atom.length.to_u64_checked();
                if (!decl.has_value() || *decl != static_cast<u64>(atom.payload.size())) {
                    return Code::Invalid;
                }
                break;
            }
            case Kind::Concat:
                if (argc < 2) return Code::Invalid;
                break;
            case Kind::Repeat: {
                if (argc != 1) return Code::Invalid;
                if (node.a.is_zero()) {
                    if (!node.b.is_zero()) return Code::Invalid;
                } else if (node.b.compare(table.length[node.args[0]]) >= 0) {
                    return Code::Invalid;
                }
                break;
            }
            case Kind::Slice: {
                if (argc != 1) return Code::Invalid;
                const BigInt& cl = table.length[node.args[0]];
                if (node.a.compare(cl) > 0) return Code::Invalid;
                auto end = bi_add(node.a, node.b);
                if (!end.ok()) return Code::Limit;
                if (end.value().compare(cl) > 0) return Code::Invalid;
                break;
            }
            case Kind::Morph: {
                if (argc != 1) return Code::Invalid;
                const Status st = check_morph_params(node.morph, node.morph_k,
                                                     table.length[node.args[0]]);
                if (!st.ok()) return st;
                break;
            }
            case Kind::Xor:
                if (argc != 2) return Code::Invalid;
                if (table.length[node.args[0]].compare(table.length[node.args[1]]) != 0) {
                    return Code::Invalid;
                }
                break;
            case Kind::Interleave: {
                if (argc < 1) return Code::Invalid;
                auto stride = interleave_stride(node);
                if (!stride.ok() || stride.value() == 0) return Code::Invalid;
                const BigInt& first = table.length[node.args[0]];
                for (std::size_t k = 1; k < argc; ++k) {
                    if (table.length[node.args[k]].compare(first) != 0) return Code::Invalid;
                }
                auto rem = first.divmod_scalar(stride.value());
                if (!rem.ok()) return to_status(rem.error());
                if (rem.value().second != 0) return Code::Invalid;
                break;
            }
            case Kind::Lfsr:
                if (argc != 0 || node.lfsr_conn == 0) return Code::Invalid;
                break;
            case Kind::Predictor: {
                if (argc != 1) return Code::Invalid;
                const Status st = check_predictor_params(node.predictor_id,
                                                         node.predictor_param);
                if (!st.ok()) return st;
                break;
            }
        }
    }

    if (limits.enforce_output_cap &&
        table.length[subterm_root].compare(max_output_bytes()) > 0) {
        return Code::Limit;
    }

    out_reach = reach.reachable;
    return Status{};
}

void swap_blocks_in_place(u32 block, std::span<u8> buf) noexcept {
    const std::size_t b = static_cast<std::size_t>(block);
    for (std::size_t base = 0; base + b <= buf.size(); base += b) {
        std::reverse(buf.begin() + static_cast<std::ptrdiff_t>(base),
                     buf.begin() + static_cast<std::ptrdiff_t>(base + b));
    }
}

struct PredRunState {
    u8 pid = 0;
    u32 param = 0;
    u8 prev1 = 0;
    u8 prev2 = 0;
    u8 seeded = 0;                  // 0 at offset 0, 1 at offset 1, 2 at offset >= 2
    std::size_t window = 0;         // ring size (0 for pid 0..2 or when window unused)
    std::size_t ring_slot = 0;      // current index % window
    std::vector<u8> ring;
    bool cacheable = true;          // false only when param > window_cap and end <= param

    u8 step_byte(u8 residual_byte) noexcept {
        u8 value = 0;
        if (pid == 2) {
            if (seeded < 2) {
                value = residual_byte;
                ++seeded;
            } else {
                value = apply_predictor_step(pid, param, residual_byte, prev1, prev2);
            }
            prev2 = prev1;
            prev1 = value;
            return value;
        }
        if (pid == 3 || pid == 4) {
            if (window != 0) {
                const u8 previous = ring[ring_slot];
                value = apply_predictor_step(pid, param, residual_byte, previous, 0);
                ring[ring_slot] = value;
                ++ring_slot;
                if (ring_slot == window) ring_slot = 0;
            } else {
                value = apply_predictor_step(pid, param, residual_byte, 0, 0);
            }
            if (seeded < 2) ++seeded;
            return value;
        }
        value = apply_predictor_step(pid, param, residual_byte, prev1, 0);
        prev1 = value;
        if (seeded < 2) ++seeded;
        return value;
    }

    void discard_span(std::span<const u8> residual) noexcept {
        for (u8 b : residual) (void)step_byte(b);
    }

    void emit_in_place(std::span<u8> buf) noexcept {
        for (u8& b : buf) b = step_byte(b);
    }
};

}  // namespace

namespace detail {

struct PredictorSlot {
    u32 node = 0;
    BigInt offset;
    u8 prev1 = 0;
    u8 prev2 = 0;
    u8 seeded = 0;
    std::size_t ring_slot = 0;
    std::vector<u8> ring;
    u64 last_use = 0;
    bool pinned_checkpoint = false;
};

struct LfsrSlot {
    u32 node = 0;
    BigInt offset;
    u64 state = 0;
    u64 last_use = 0;
};

struct StreamSession {
    std::vector<PredictorSlot> pred_slots;
    std::vector<LfsrSlot> lfsr_slots;
    std::vector<std::vector<u8>> scratch_pool;
    std::size_t rolling_ring_bytes = 0;
    u64 use_clock = 0;
    u64 work_bytes = 0;
};

Result<EvalPlanData> build_eval_plan(const Ir& ir, const EvalLimits& limits,
                                     bool full_wf, u32 subterm_root) {
    if (limits.block_bytes == 0) return Code::Invalid;

    if (full_wf) {
        const WfReport wf = check_well_formed_report(ir, limits.wf);
        if (!wf.ok()) return wf.code;
        if (subterm_root >= ir.nodes.size()) return Code::Invalid;
    }

    auto lengths_res = compute_lengths(ir);
    if (!lengths_res.ok()) return lengths_res.code();
    LengthTable& table = lengths_res.value();

    std::vector<char> reachable;
    if (!full_wf) {
        const Status sub_st =
            check_subterm_well_formed(ir, subterm_root, limits.wf, table, reachable);
        if (!sub_st.ok()) return sub_st.code();
    } else {
        for (std::size_t i = 0; i < table.known.size(); ++i) {
            if (table.known[i] == 0) return Code::Invalid;
        }
    }

    EvalPlanData plan;
    plan.ir = &ir;
    plan.limits = limits;
    plan.concat_cum.resize(ir.nodes.size());
    for (u32 i = 0; i < ir.nodes.size(); ++i) {
        if (!full_wf && reachable[i] == 0) continue;
        const Node& node = ir.nodes[i];
        if (node.kind == Kind::Concat && node.args.size() >= kConcatBinarySearchMinArgs) {
            std::vector<BigInt> cum;
            cum.reserve(node.args.size() + 1);
            BigInt acc = BigInt::zero();
            cum.push_back(acc);
            for (u32 child : node.args) {
                auto next = bi_add(acc, table.length[child]);
                if (!next.ok()) return next.code();
                acc = std::move(next.value());
                cum.push_back(acc);
            }
            plan.concat_cum[i] = std::move(cum);
        }
    }
    plan.lengths = std::move(table.length);
    return plan;
}

Status validate_checkpoint_against_plan(const EvalPlanData& plan,
                                        const PredictorCheckpoint& cp) {
    const Ir& ir = *plan.ir;
    if (cp.node >= ir.nodes.size()) return Code::Invalid;
    const Node& node = ir.nodes[cp.node];
    if (node.kind != Kind::Predictor) return Code::Invalid;
    const u8 pid = node.predictor_id;
    const u32 param = node.predictor_param;
    if (!check_predictor_params(pid, param).ok()) return Code::Invalid;
    const BigInt& total = plan.lengths[cp.node];
    if (cp.offset.compare(total) > 0) return Code::Invalid;

    if (cp.offset.is_zero()) {
        if (cp.prev1 != 0 || cp.prev2 != 0 || !cp.window.empty()) return Code::Invalid;
        return Status{};
    }

    if (pid == 0 || pid == 1) {
        if (cp.prev2 != 0 || !cp.window.empty()) return Code::Invalid;
        return Status{};
    }
    if (pid == 2) {
        if (!cp.window.empty()) return Code::Invalid;
        if (cp.offset.compare(BigInt(1)) == 0 && cp.prev2 != 0) return Code::Invalid;
        return Status{};
    }
    // pid 3 or 4 (stride predictors)
    if (cp.prev1 != 0 || cp.prev2 != 0) return Code::Invalid;
    if (BigInt(param).compare(total) < 0) {
        if (static_cast<std::size_t>(param) > plan.limits.max_predictor_window) {
            return Code::Limit;
        }
        if (cp.window.size() != static_cast<std::size_t>(param)) return Code::Invalid;
    } else {
        if (!cp.window.empty()) {
            if (static_cast<std::size_t>(param) > plan.limits.max_predictor_window) {
                return Code::Limit;
            }
            if (cp.window.size() != static_cast<std::size_t>(param)) return Code::Invalid;
        }
    }
    return Status{};
}

namespace {

Status seed_checkpoint_slot(const EvalPlanData& plan, StreamSession& session,
                            const PredictorCheckpoint& cp) {
    const Status valid = validate_checkpoint_against_plan(plan, cp);
    if (!valid.ok()) return valid;

    PredictorSlot slot;
    slot.node = cp.node;
    slot.offset = cp.offset;
    slot.prev1 = cp.prev1;
    slot.prev2 = cp.prev2;
    slot.seeded = cp.offset.is_zero() ? 0u : (cp.offset.compare(BigInt(1)) == 0 ? 1u : 2u);
    slot.pinned_checkpoint = true;
    slot.last_use = ++session.use_clock;

    const Node& node = plan.ir->nodes[cp.node];
    if ((node.predictor_id == 3 || node.predictor_id == 4) &&
        BigInt(node.predictor_param).compare(plan.lengths[cp.node]) < 0) {
        const std::size_t w = static_cast<std::size_t>(node.predictor_param);
        if (w > plan.limits.max_scratch_bytes) return Code::Limit;
        if (cp.offset.is_zero()) {
            slot.ring.assign(w, 0u);
            slot.ring_slot = 0;
        } else {
            auto rem = cp.offset.divmod_scalar(node.predictor_param);
            if (!rem.ok()) return to_status(rem.error());
            slot.ring = cp.window;
            slot.ring_slot = static_cast<std::size_t>(rem.value().second);
        }
    }
    session.pred_slots.push_back(std::move(slot));
    return Status{};
}

void evict_oldest_rolling_pred_slot(StreamSession& session, bool rings_only) {
    std::size_t victim = session.pred_slots.size();
    u64 best_clock = ~u64{0};
    for (std::size_t i = 0; i < session.pred_slots.size(); ++i) {
        const PredictorSlot& s = session.pred_slots[i];
        if (s.pinned_checkpoint) continue;
        if (rings_only && s.ring.empty()) continue;
        if (s.last_use < best_clock) {
            best_clock = s.last_use;
            victim = i;
        }
    }
    if (victim < session.pred_slots.size()) {
        session.rolling_ring_bytes -= session.pred_slots[victim].ring.size();
        session.pred_slots.erase(session.pred_slots.begin() +
                                 static_cast<std::ptrdiff_t>(victim));
    }
}

void store_rolling_pred_slot(const EvalPlanData& plan, StreamSession& session,
                             u32 node_id, const BigInt& new_offset,
                             PredRunState&& state) {
    if (!state.cacheable) return;
    const std::size_t ring_bytes = state.ring.size();
    if (ring_bytes > plan.limits.max_scratch_bytes) return;

    // Deduplicate: if another DAG branch already cached `new_offset` for `node_id`,
    // simply refresh its LRU timestamp.
    for (PredictorSlot& slot : session.pred_slots) {
        if (!slot.pinned_checkpoint && slot.node == node_id &&
            slot.offset.compare(new_offset) == 0) {
            slot.last_use = ++session.use_clock;
            return;
        }
    }

    // Enforce per-node rolling slot cap (keeps recent offsets alive so sibling
    // DAG branches reading the same chunk hit the predecessor offset with gap == 0).
    std::size_t per_node = 0;
    std::size_t oldest_for_node = session.pred_slots.size();
    u64 oldest_node_clock = ~u64{0};
    std::size_t total_rolling = 0;
    for (std::size_t i = 0; i < session.pred_slots.size(); ++i) {
        const PredictorSlot& s = session.pred_slots[i];
        if (s.pinned_checkpoint) continue;
        ++total_rolling;
        if (s.node == node_id) {
            ++per_node;
            if (s.last_use < oldest_node_clock) {
                oldest_node_clock = s.last_use;
                oldest_for_node = i;
            }
        }
    }
    if (per_node >= kMaxPredSlotsPerNode && oldest_for_node < session.pred_slots.size()) {
        session.rolling_ring_bytes -= session.pred_slots[oldest_for_node].ring.size();
        session.pred_slots.erase(session.pred_slots.begin() +
                                 static_cast<std::ptrdiff_t>(oldest_for_node));
        --total_rolling;
    }
    if (total_rolling >= kMaxPredRollingSlots) {
        evict_oldest_rolling_pred_slot(session, false);
    }
    while (session.rolling_ring_bytes + ring_bytes > plan.limits.max_scratch_bytes) {
        const std::size_t before = session.pred_slots.size();
        evict_oldest_rolling_pred_slot(session, true);
        if (session.pred_slots.size() == before) return;
    }

    PredictorSlot fresh;
    fresh.node = node_id;
    fresh.offset = new_offset;
    fresh.prev1 = state.prev1;
    fresh.prev2 = state.prev2;
    fresh.seeded = state.seeded;
    fresh.ring_slot = state.ring_slot;
    fresh.ring = std::move(state.ring);
    fresh.last_use = ++session.use_clock;
    session.rolling_ring_bytes += fresh.ring.size();
    session.pred_slots.push_back(std::move(fresh));
}

bool lookup_lfsr_slot(StreamSession& session, u32 node_id, const BigInt& offset, u64& out_state) {
    for (LfsrSlot& slot : session.lfsr_slots) {
        if (slot.node == node_id && slot.offset.compare(offset) == 0) {
            slot.last_use = ++session.use_clock;
            out_state = slot.state;
            return true;
        }
    }
    return false;
}

void store_lfsr_slot(StreamSession& session, u32 node_id, const BigInt& old_offset,
                     const BigInt& new_offset, u64 state) {
    for (LfsrSlot& slot : session.lfsr_slots) {
        if (slot.node == node_id && slot.offset.compare(old_offset) == 0) {
            slot.offset = new_offset;
            slot.state = state;
            slot.last_use = ++session.use_clock;
            return;
        }
    }
    if (session.lfsr_slots.size() >= kMaxLfsrSlots) {
        std::size_t victim = 0;
        for (std::size_t i = 1; i < session.lfsr_slots.size(); ++i) {
            if (session.lfsr_slots[i].last_use < session.lfsr_slots[victim].last_use) {
                victim = i;
            }
        }
        session.lfsr_slots[victim] = LfsrSlot{node_id, new_offset, state, ++session.use_clock};
        return;
    }
    session.lfsr_slots.push_back(LfsrSlot{node_id, new_offset, state, ++session.use_clock});
}

struct EvalFrame {
    u32 node_id = 0;
    BigInt start;
    std::span<u8> out;
    u8 phase = 0;
    u8 aux_u8 = 0;

    std::size_t aux_idx = 0;
    std::size_t aux_last_idx = 0;
    std::size_t aux_written = 0;
    std::size_t aux_take = 0;
    u64 stride = 0;
    BigInt aux_pos;
    BigInt aux_bound;
    std::array<u8, 8> block_buf{};
    std::vector<u8> scratch;
    PredRunState pred;
};

// Executes one chunk `[root_start, root_start + root_out.size())` with
// `0 < root_out.size() <= kEvalBlock` on an explicit heap stack.
Status run_chunk_explicit_stack(const EvalPlanData& plan, u32 root_node,
                                const BigInt& root_start, std::span<u8> root_out,
                                StreamSession& session, EvalStats* stats) {
    const Ir& ir = *plan.ir;
    const std::vector<BigInt>& len = plan.lengths;
    const std::size_t max_depth = static_cast<std::size_t>(plan.limits.wf.max_depth);

    std::vector<EvalFrame> stack;
    stack.reserve(32);

    std::size_t active_scratch = 0;
    auto charge_work = [&](std::size_t bytes) -> Status {
        if (plan.limits.max_work_bytes != 0) {
            const u64 add = static_cast<u64>(bytes);
            if (add > plan.limits.max_work_bytes ||
                session.work_bytes > plan.limits.max_work_bytes - add) {
                return Code::Limit;
            }
            session.work_bytes += add;
        }
        return Status{};
    };

    auto reserve_scratch = [&](std::size_t current_owned, std::size_t wanted) -> Status {
        if (wanted <= current_owned) {
            active_scratch -= (current_owned - wanted);
            return Status{};
        }
        const std::size_t delta = wanted - current_owned;
        if (delta > plan.limits.max_scratch_bytes ||
            active_scratch > plan.limits.max_scratch_bytes - delta) {
            return Code::Limit;
        }
        while (active_scratch + session.rolling_ring_bytes + delta >
               plan.limits.max_scratch_bytes) {
            const std::size_t before = session.pred_slots.size();
            evict_oldest_rolling_pred_slot(session, true);
            if (session.pred_slots.size() == before) break;
        }
        active_scratch += delta;
        if (stats != nullptr && active_scratch > stats->peak_scratch_bytes) {
            stats->peak_scratch_bytes = active_scratch;
        }
        return Status{};
    };

    auto recycle_scratch_vec = [&](std::vector<u8>& v) noexcept {
        if (v.capacity() > 0 && v.capacity() <= kEvalBlock && session.scratch_pool.size() < 8u) {
            v.clear();
            session.scratch_pool.push_back(std::move(v));
        } else {
            std::vector<u8>().swap(v);
        }
    };

    auto acquire_scratch = [&](std::vector<u8>& v, std::size_t wanted) -> Status {
        const Status st = reserve_scratch(v.size(), wanted);
        if (!st.ok()) return st;
        if (v.capacity() < wanted && !session.scratch_pool.empty()) {
            recycle_scratch_vec(v);
            v = std::move(session.scratch_pool.back());
            session.scratch_pool.pop_back();
        }
        v.resize(wanted);
        return Status{};
    };

    auto release_frame_scratch = [&](EvalFrame& f) noexcept {
        const std::size_t owned = f.scratch.size() + f.pred.ring.size();
        if (active_scratch >= owned) active_scratch -= owned;
        else active_scratch = 0;
        recycle_scratch_vec(f.scratch);
        std::vector<u8>().swap(f.pred.ring);
    };

    auto pop_top = [&]() noexcept {
        release_frame_scratch(stack.back());
        stack.pop_back();
    };

    auto push_frame = [&](u32 node_id, BigInt start_off, std::span<u8> dst,
                          bool is_subterm) -> Status {
        if (stack.size() > max_depth + 1u) return Code::Limit;
        EvalFrame frame;
        frame.node_id = node_id;
        frame.start = std::move(start_off);
        frame.out = dst;
        stack.push_back(std::move(frame));
        if (stats != nullptr) {
            ++stats->frames_pushed;
            if (is_subterm) ++stats->subterms_touched;
            const u32 d = static_cast<u32>(stack.size());
            if (d > stats->peak_stack_depth) stats->peak_stack_depth = d;
        }
        return Status{};
    };

    {
        const Status st = push_frame(root_node, root_start, root_out, false);
        if (!st.ok()) return st;
    }

    while (!stack.empty()) {
        EvalFrame& cur = stack.back();
        if (cur.out.empty()) {
            pop_top();
            continue;
        }
        const u32 cur_id = cur.node_id;
        const Node& node = ir.nodes[cur_id];

        switch (node.kind) {
            case Kind::Empty:
                return Code::Invalid;

            case Kind::Atom: {
                const Status wk = charge_work(cur.out.size());
                if (!wk.ok()) return wk;
                auto atom_id = node.a.to_u64_checked();
                if (!atom_id.has_value() || *atom_id >= ir.atoms.size()) return Code::Invalid;
                const Atom& atom = ir.atoms[static_cast<std::size_t>(*atom_id)];
                auto off = bi_to_u64(cur.start);
                if (!off.ok()) return off.code();
                const std::size_t from = static_cast<std::size_t>(off.value());
                if (from + cur.out.size() > atom.payload.size()) return Code::Invalid;
                std::memcpy(cur.out.data(), atom.payload.data() + from, cur.out.size());
                pop_top();
                continue;
            }

            case Kind::Zero: {
                const Status wk = charge_work(cur.out.size());
                if (!wk.ok()) return wk;
                std::memset(cur.out.data(), 0, cur.out.size());
                pop_top();
                continue;
            }

            case Kind::Affine: {
                const Status wk = charge_work(cur.out.size());
                if (!wk.ok()) return wk;
                auto rem = cur.start.divmod_scalar(256);
                if (!rem.ok()) return to_status(rem.error());
                unsigned val = (static_cast<unsigned>(node.affine_start) +
                                static_cast<unsigned>(rem.value().second) *
                                    static_cast<unsigned>(node.affine_step)) &
                               0xFFu;
                const unsigned step = static_cast<unsigned>(node.affine_step);
                for (std::size_t j = 0; j < cur.out.size(); ++j) {
                    cur.out[j] = static_cast<u8>(val);
                    val = (val + step) & 0xFFu;
                }
                pop_top();
                continue;
            }

            case Kind::Lfsr: {
                const Status wk = charge_work(cur.out.size());
                if (!wk.ok()) return wk;
                u64 state = 0;
                if (cur.start.is_zero()) {
                    state = node.lfsr_init;
                } else if (!lookup_lfsr_slot(session, cur_id, cur.start, state)) {
                    u64 mul_ops = 0;
                    auto jumped = lfsr_state_at_byte_offset_counted(
                        node.lfsr_conn, node.lfsr_init, cur.start, &mul_ops);
                    if (!jumped.ok()) return jumped.code();
                    state = jumped.value();
                    if (stats != nullptr) {
                        ++stats->lfsr_jumps;
                        stats->lfsr_gf2_mul_ops += mul_ops;
                    }
                }
                for (u8& b : cur.out) b = lfsr_next_byte(state, node.lfsr_conn);
                if (stats != nullptr) stats->lfsr_byte_steps += cur.out.size();
                auto next_off = bi_add(cur.start, BigInt(static_cast<u64>(cur.out.size())));
                if (!next_off.ok()) return next_off.code();
                store_lfsr_slot(session, cur_id, cur.start, next_off.value(), state);
                pop_top();
                continue;
            }

            case Kind::Slice: {
                auto child_start = bi_add(node.a, cur.start);
                if (!child_start.ok()) return child_start.code();
                cur.start = std::move(child_start.value());
                cur.node_id = node.args[0];
                cur.phase = 0;
                if (stats != nullptr) ++stats->subterms_touched;
                continue;
            }

            case Kind::Concat: {
                const std::size_t argc = node.args.size();
                if (cur.phase == 0) {
                    const auto& cum = plan.concat_cum[cur_id];
                    if (!cum.empty()) {
                        std::size_t lo = 0;
                        std::size_t hi = argc;
                        while (lo + 1u < hi) {
                            const std::size_t mid = lo + (hi - lo) / 2u;
                            if (cum[mid].compare(cur.start) <= 0) lo = mid;
                            else hi = mid;
                        }
                        cur.aux_idx = lo;
                        cur.aux_pos = cum[lo];
                        if (stats != nullptr) stats->concat_children_skipped += lo;
                    } else {
                        BigInt pos = BigInt::zero();
                        std::size_t idx = 0;
                        while (idx < argc) {
                            const BigInt& cl = len[node.args[idx]];
                            auto cend = bi_add(pos, cl);
                            if (!cend.ok()) return cend.code();
                            if (cend.value().compare(cur.start) > 0) break;
                            pos = std::move(cend.value());
                            ++idx;
                        }
                        cur.aux_idx = idx;
                        cur.aux_pos = std::move(pos);
                        if (stats != nullptr) stats->concat_children_skipped += idx;
                    }
                    cur.aux_last_idx = cur.aux_idx;
                    cur.aux_written = 0;
                    cur.phase = 1;
                }

                // Skip any zero-length children before dispatching.
                while (cur.aux_written < cur.out.size() && cur.aux_idx < argc &&
                       len[node.args[cur.aux_idx]].is_zero()) {
                    if (stats != nullptr) ++stats->concat_children_skipped;
                    ++cur.aux_idx;
                }

                if (cur.aux_written == cur.out.size()) {
                    if (stats != nullptr && cur.aux_last_idx + 1u < argc) {
                        stats->concat_children_skipped += (argc - 1u - cur.aux_last_idx);
                    }
                    pop_top();
                    continue;
                }
                if (cur.aux_idx >= argc) return Code::Invalid;

                const u32 child = node.args[cur.aux_idx];
                const BigInt& child_len = len[child];
                auto req_pos = bi_add(cur.start, BigInt(static_cast<u64>(cur.aux_written)));
                if (!req_pos.ok()) return req_pos.code();
                auto child_off = bi_sub(req_pos.value(), cur.aux_pos);
                if (!child_off.ok()) return child_off.code();
                auto avail = bi_sub(child_len, child_off.value());
                if (!avail.ok()) return avail.code();
                const u64 want = static_cast<u64>(cur.out.size() - cur.aux_written);
                auto take_res = min_u64(avail.value(), avail.value(), want);
                if (!take_res.ok()) return take_res.code();
                const std::size_t take = static_cast<std::size_t>(take_res.value());
                if (take == 0) return Code::Invalid;

                const std::span<u8> slice = cur.out.subspan(cur.aux_written, take);
                cur.aux_last_idx = cur.aux_idx;
                cur.aux_written += take;
                auto consumed = bi_add(child_off.value(), BigInt(static_cast<u64>(take)));
                if (!consumed.ok()) return consumed.code();
                if (consumed.value().compare(child_len) == 0) {
                    auto next_pos = bi_add(cur.aux_pos, child_len);
                    if (!next_pos.ok()) return next_pos.code();
                    cur.aux_pos = std::move(next_pos.value());
                    ++cur.aux_idx;
                }
                const Status pst = push_frame(child, std::move(child_off.value()), slice, true);
                if (!pst.ok()) return pst;
                continue;
            }

            case Kind::Repeat: {
                const u32 child = node.args[0];
                const BigInt& period = len[child];
                if (cur.phase == 0) {
                    if (period.is_zero()) return Code::Invalid;
                    auto copies_bytes = bi_mul(node.a, period);
                    if (!copies_bytes.ok()) return copies_bytes.code();
                    cur.aux_bound = std::move(copies_bytes.value());
                    cur.aux_pos = cur.start;
                    cur.aux_written = 0;
                    cur.phase = 1;
                }
                if (cur.aux_written == cur.out.size()) {
                    pop_top();
                    continue;
                }
                const u64 want = static_cast<u64>(cur.out.size() - cur.aux_written);
                if (cur.aux_pos.compare(cur.aux_bound) < 0) {
                    auto rem_q = bi_sub(cur.aux_bound, cur.aux_pos);
                    if (!rem_q.ok()) return rem_q.code();
                    auto within = bi_mod(cur.aux_pos, period);
                    if (!within.ok()) return within.code();
                    auto avail = bi_sub(period, within.value());
                    if (!avail.ok()) return avail.code();
                    auto take_res = min_u64(avail.value(), rem_q.value(), want);
                    if (!take_res.ok()) return take_res.code();
                    const std::size_t take = static_cast<std::size_t>(take_res.value());
                    if (take == 0) return Code::Invalid;
                    const std::span<u8> slice = cur.out.subspan(cur.aux_written, take);
                    cur.aux_written += take;
                    auto next_pos = bi_add(cur.aux_pos, BigInt(static_cast<u64>(take)));
                    if (!next_pos.ok()) return next_pos.code();
                    cur.aux_pos = std::move(next_pos.value());
                    const Status pst = push_frame(child, std::move(within.value()), slice, true);
                    if (!pst.ok()) return pst;
                    continue;
                }
                auto off = bi_sub(cur.aux_pos, cur.aux_bound);
                if (!off.ok()) return off.code();
                auto rem_r = bi_sub(node.b, off.value());
                if (!rem_r.ok()) return rem_r.code();
                auto take_res = min_u64(rem_r.value(), rem_r.value(), want);
                if (!take_res.ok()) return take_res.code();
                const std::size_t take = static_cast<std::size_t>(take_res.value());
                if (take == 0) return Code::Invalid;
                const std::span<u8> slice = cur.out.subspan(cur.aux_written, take);
                cur.aux_written += take;
                auto next_pos = bi_add(cur.aux_pos, BigInt(static_cast<u64>(take)));
                if (!next_pos.ok()) return next_pos.code();
                cur.aux_pos = std::move(next_pos.value());
                const Status pst = push_frame(child, std::move(off.value()), slice, true);
                if (!pst.ok()) return pst;
                continue;
            }

            case Kind::Morph: {
                const u32 child = node.args[0];
                const u8 morph = node.morph;
                const u8 k = node.morph_k;
                const u32 block = morph_block_size(morph);

                if (morph_is_byte_local(morph)) {
                    if (cur.phase == 0) {
                        cur.phase = 1;
                        const BigInt cs = cur.start;
                        const std::span<u8> dst = cur.out;
                        const Status pst = push_frame(child, cs, dst, true);
                        if (!pst.ok()) return pst;
                        continue;
                    }
                    const Status mst = apply_morph_to_buffer(morph, k, cur.out);
                    if (!mst.ok()) return mst;
                    pop_top();
                    continue;
                }

                if (block != 0) {
                    const std::size_t b = static_cast<std::size_t>(block);
                    if (cur.phase == 0) {
                        auto rem_res = cur.start.divmod_scalar(block);
                        if (!rem_res.ok()) return to_status(rem_res.error());
                        const u32 rem = rem_res.value().second;
                        if (rem != 0) {
                            auto blk_start = bi_sub(cur.start, BigInt(rem));
                            if (!blk_start.ok()) return blk_start.code();
                            cur.aux_u8 = static_cast<u8>(rem);
                            cur.aux_take = std::min<std::size_t>(cur.out.size(), b - rem);
                            cur.phase = 1;
                            const std::span<u8> buf(cur.block_buf.data(), b);
                            const Status pst =
                                push_frame(child, std::move(blk_start.value()), buf, true);
                            if (!pst.ok()) return pst;
                            continue;
                        }
                        cur.phase = 2;
                    }
                    if (cur.phase == 1) {
                        std::reverse(cur.block_buf.begin(),
                                     cur.block_buf.begin() + static_cast<std::ptrdiff_t>(b));
                        std::memcpy(cur.out.data(), cur.block_buf.data() + cur.aux_u8,
                                    cur.aux_take);
                        cur.out = cur.out.subspan(cur.aux_take);
                        auto next_start = bi_add(cur.start, BigInt(static_cast<u64>(cur.aux_take)));
                        if (!next_start.ok()) return next_start.code();
                        cur.start = std::move(next_start.value());
                        cur.phase = 2;
                    }
                    if (cur.phase == 2) {
                        if (cur.out.empty()) {
                            pop_top();
                            continue;
                        }
                        const std::size_t whole = (cur.out.size() / b) * b;
                        if (whole > 0) {
                            cur.aux_take = whole;
                            cur.phase = 3;
                            const BigInt cs = cur.start;
                            const std::span<u8> mid = cur.out.first(whole);
                            const Status pst = push_frame(child, cs, mid, true);
                            if (!pst.ok()) return pst;
                            continue;
                        }
                        cur.phase = 4;
                    }
                    if (cur.phase == 3) {
                        swap_blocks_in_place(block, cur.out.first(cur.aux_take));
                        cur.out = cur.out.subspan(cur.aux_take);
                        auto next_start = bi_add(cur.start, BigInt(static_cast<u64>(cur.aux_take)));
                        if (!next_start.ok()) return next_start.code();
                        cur.start = std::move(next_start.value());
                        if (cur.out.empty()) {
                            pop_top();
                            continue;
                        }
                        cur.phase = 4;
                    }
                    if (cur.phase == 4) {
                        cur.phase = 5;
                        const BigInt cs = cur.start;
                        const std::span<u8> buf(cur.block_buf.data(), b);
                        const Status pst = push_frame(child, cs, buf, true);
                        if (!pst.ok()) return pst;
                        continue;
                    }
                    // phase == 5: finish tail partial block
                    std::reverse(cur.block_buf.begin(),
                                 cur.block_buf.begin() + static_cast<std::ptrdiff_t>(b));
                    std::memcpy(cur.out.data(), cur.block_buf.data(), cur.out.size());
                    pop_top();
                    continue;
                }

                // Mirrored morphs 8 (`REVERSE_BYTES`) and 9 (`REVERSE_BITS`).
                if (cur.phase == 0) {
                    const BigInt& child_len = len[child];
                    auto mirrored = bi_sub(child_len, cur.start);
                    if (!mirrored.ok()) return mirrored.code();
                    auto from = bi_sub(mirrored.value(),
                                       BigInt(static_cast<u64>(cur.out.size())));
                    if (!from.ok()) return from.code();
                    cur.phase = 1;
                    const std::span<u8> dst = cur.out;
                    const Status pst = push_frame(child, std::move(from.value()), dst, true);
                    if (!pst.ok()) return pst;
                    continue;
                }
                std::reverse(cur.out.begin(), cur.out.end());
                if (morph == 9) {
                    for (u8& b : cur.out) b = bit_reverse8(b);
                }
                pop_top();
                continue;
            }

            case Kind::Xor: {
                if (cur.phase == 0) {
                    if (cur.aux_written == cur.out.size()) {
                        pop_top();
                        continue;
                    }
                    const std::size_t step_cap =
                        (stack.size() < kDeepStackThreshold) ? kEvalBlock : kDeepXorChunkCap;
                    const std::size_t take =
                        std::min<std::size_t>(cur.out.size() - cur.aux_written, step_cap);
                    cur.aux_take = take;
                    cur.phase = 1;
                    auto off = bi_add(cur.start, BigInt(static_cast<u64>(cur.aux_written)));
                    if (!off.ok()) return off.code();
                    const std::span<u8> dst = cur.out.subspan(cur.aux_written, take);
                    const Status pst =
                        push_frame(node.args[0], std::move(off.value()), dst, true);
                    if (!pst.ok()) return pst;
                    continue;
                }
                if (cur.phase == 1) {
                    const Status sst = acquire_scratch(cur.scratch, cur.aux_take);
                    if (!sst.ok()) return sst;
                    cur.phase = 2;
                    auto off = bi_add(cur.start, BigInt(static_cast<u64>(cur.aux_written)));
                    if (!off.ok()) return off.code();
                    const std::span<u8> rhs(cur.scratch.data(), cur.aux_take);
                    const Status pst =
                        push_frame(node.args[1], std::move(off.value()), rhs, true);
                    if (!pst.ok()) return pst;
                    continue;
                }
                // phase == 2: XOR right into left in-place.
                const std::span<u8> dst = cur.out.subspan(cur.aux_written, cur.aux_take);
                for (std::size_t j = 0; j < cur.aux_take; ++j) {
                    dst[j] = static_cast<u8>(dst[j] ^ cur.scratch[j]);
                }
                cur.aux_written += cur.aux_take;
                if (cur.aux_written == cur.out.size()) {
                    pop_top();
                } else {
                    cur.phase = 0;
                }
                continue;
            }

            case Kind::Interleave: {
                if (cur.phase == 0) {
                    auto stride_res = interleave_stride(node);
                    if (!stride_res.ok() || stride_res.value() == 0) return Code::Invalid;
                    cur.stride = stride_res.value();
                    auto block_big = bi_mul(BigInt(static_cast<u64>(node.args.size())),
                                            BigInt(cur.stride));
                    if (!block_big.ok()) return block_big.code();
                    cur.aux_bound = std::move(block_big.value());
                    cur.aux_pos = cur.start;
                    cur.aux_written = 0;
                    cur.phase = 1;
                }
                if (cur.aux_written == cur.out.size()) {
                    pop_top();
                    continue;
                }
                auto div = cur.aux_pos.divmod(cur.aux_bound);
                if (!div.ok()) return to_status(div.error());
                const BigInt& block_idx = div.value().first;
                auto child_div = div.value().second.divmod_scalar(static_cast<u32>(cur.stride));
                if (!child_div.ok()) return to_status(child_div.error());
                auto child_idx_u64 = bi_to_u64(child_div.value().first);
                if (!child_idx_u64.ok()) return child_idx_u64.code();
                const std::size_t child_idx = static_cast<std::size_t>(child_idx_u64.value());
                if (child_idx >= node.args.size()) return Code::Invalid;
                const u64 within_child = child_div.value().second;
                const u64 want = static_cast<u64>(cur.out.size() - cur.aux_written);
                const std::size_t take =
                    static_cast<std::size_t>(std::min<u64>(want, cur.stride - within_child));
                if (take == 0) return Code::Invalid;

                auto base = bi_mul(block_idx, BigInt(cur.stride));
                if (!base.ok()) return base.code();
                auto child_off = bi_add(base.value(), BigInt(within_child));
                if (!child_off.ok()) return child_off.code();

                const std::span<u8> slice = cur.out.subspan(cur.aux_written, take);
                cur.aux_written += take;
                auto next_pos = bi_add(cur.aux_pos, BigInt(static_cast<u64>(take)));
                if (!next_pos.ok()) return next_pos.code();
                cur.aux_pos = std::move(next_pos.value());
                const Status pst =
                    push_frame(node.args[child_idx], std::move(child_off.value()), slice, true);
                if (!pst.ok()) return pst;
                continue;
            }

            case Kind::Predictor: {
                const u32 residual_id = node.args[0];
                const u8 pid = node.predictor_id;
                const u32 param = node.predictor_param;
                if (cur.phase == 0) {
                    if (!check_predictor_params(pid, param).ok()) return Code::Invalid;

                    // Locate closest cached / checkpointed state <= cur.start.
                    PredictorSlot* best = nullptr;
                    for (PredictorSlot& s : session.pred_slots) {
                        if (s.node != cur_id) continue;
                        if (s.offset.compare(cur.start) <= 0) {
                            if (best == nullptr || s.offset.compare(best->offset) > 0) {
                                best = &s;
                            }
                        }
                    }

                    const BigInt base_off = (best != nullptr) ? best->offset : BigInt::zero();
                    auto gap = bi_sub(cur.start, base_off);
                    if (!gap.ok()) return gap.code();
                    if (gap.value().compare(plan.limits.predictor_prefix_max) > 0) {
                        return Code::Limit;
                    }

                    auto end_off = bi_add(cur.start, BigInt(static_cast<u64>(cur.out.size())));
                    if (!end_off.ok()) return end_off.code();
                    const BigInt& total = len[cur_id];

                    std::size_t window = 0;
                    bool cacheable = true;
                    if (pid == 3 || pid == 4) {
                        const BigInt param_big(param);
                        if (param_big.compare(total) < 0) {
                            if (static_cast<std::size_t>(param) <=
                                plan.limits.max_predictor_window) {
                                window = static_cast<std::size_t>(param);
                            } else if (end_off.value().compare(param_big) <= 0) {
                                // Every index in [0, end_off) satisfies i < param,
                                // so out[i] == r[i] with zero ring memory; do not
                                // cache past this range without a full ring.
                                window = 0;
                                cacheable = false;
                            } else {
                                return Code::Limit;
                            }
                        }
                    }

                    cur.pred.pid = pid;
                    cur.pred.param = param;
                    cur.pred.window = window;
                    cur.pred.cacheable = cacheable;

                    if (window > 0) {
                        const Status rst = reserve_scratch(0, window);
                        if (!rst.ok()) return rst;
                    }

                    if (best != nullptr) {
                        best->last_use = ++session.use_clock;
                        cur.aux_pos = best->offset;
                        cur.pred.prev1 = best->prev1;
                        cur.pred.prev2 = best->prev2;
                        cur.pred.seeded = best->seeded;
                        cur.pred.ring_slot = best->ring_slot;
                        if (window > 0) {
                            if (best->ring.size() == window) {
                                cur.pred.ring = best->ring;
                            } else {
                                cur.pred.ring.assign(window, 0u);
                            }
                        }
                    } else {
                        cur.aux_pos = BigInt::zero();
                        if (window > 0) cur.pred.ring.assign(window, 0u);
                    }

                    cur.phase = (cur.aux_pos.compare(cur.start) < 0) ? 1u : 3u;
                }

                if (cur.phase == 1) {
                    auto rem = bi_sub(cur.start, cur.aux_pos);
                    if (!rem.ok()) return rem.code();
                    if (rem.value().is_zero()) {
                        (void)reserve_scratch(cur.scratch.size(), 0);
                        recycle_scratch_vec(cur.scratch);
                        cur.phase = 3;
                    } else {
                        const std::size_t step_cap =
                            (stack.size() < kDeepStackThreshold) ? kEvalBlock : kDeepPredChunkCap;
                        auto take_res = min_u64(rem.value(), rem.value(),
                                                static_cast<u64>(step_cap));
                        if (!take_res.ok()) return take_res.code();
                        const std::size_t take = static_cast<std::size_t>(take_res.value());
                        const Status sst = acquire_scratch(cur.scratch, take);
                        if (!sst.ok()) return sst;
                        cur.aux_take = take;
                        cur.phase = 2;
                        const BigInt pos = cur.aux_pos;
                        const std::span<u8> buf(cur.scratch.data(), take);
                        const Status pst = push_frame(residual_id, pos, buf, true);
                        if (!pst.ok()) return pst;
                        continue;
                    }
                }

                if (cur.phase == 2) {
                    cur.pred.discard_span(
                        std::span<const u8>(cur.scratch.data(), cur.aux_take));
                    if (stats != nullptr) stats->predictor_prefix_bytes += cur.aux_take;
                    auto next_pos = bi_add(cur.aux_pos, BigInt(static_cast<u64>(cur.aux_take)));
                    if (!next_pos.ok()) return next_pos.code();
                    cur.aux_pos = std::move(next_pos.value());
                    if (cur.aux_pos.compare(cur.start) < 0) {
                        cur.phase = 1;
                        continue;
                    }
                    (void)reserve_scratch(cur.scratch.size(), 0);
                    recycle_scratch_vec(cur.scratch);
                    cur.phase = 3;
                }

                if (cur.phase == 3) {
                    cur.phase = 4;
                    const BigInt cs = cur.start;
                    const std::span<u8> dst = cur.out;
                    const Status pst = push_frame(residual_id, cs, dst, true);
                    if (!pst.ok()) return pst;
                    continue;
                }

                // phase == 4: reconstruct cur.out in-place and persist rolling state.
                cur.pred.emit_in_place(cur.out);
                if (stats != nullptr) stats->predictor_emitted_bytes += cur.out.size();
                auto new_off = bi_add(cur.start, BigInt(static_cast<u64>(cur.out.size())));
                if (!new_off.ok()) return new_off.code();

                // Transfer active ring accounting before moving `cur.pred` into session.
                const std::size_t ring_owned = cur.pred.ring.size();
                if (active_scratch >= ring_owned) active_scratch -= ring_owned;
                else active_scratch = 0;
                PredRunState finished = std::move(cur.pred);
                cur.pred.ring.clear();

                store_rolling_pred_slot(plan, session, cur_id, new_off.value(),
                                        std::move(finished));
                pop_top();
                continue;
            }
        }
        return Code::Invalid;
    }
    return Status{};
}

}  // namespace

std::unique_ptr<StreamSession> make_stream_session(
    const EvalPlanData& plan, std::span<const PredictorCheckpoint> checkpoints,
    Status& out_status) {
    auto session = std::make_unique<StreamSession>();
    for (const PredictorCheckpoint& cp : checkpoints) {
        const Status st = seed_checkpoint_slot(plan, *session, cp);
        if (!st.ok()) {
            out_status = st;
            return nullptr;
        }
    }
    out_status = Status{};
    return session;
}

Status eval_range_with_plan(const EvalPlanData& plan, u32 node_id, const BigInt& start,
                            std::span<u8> out, StreamSession* session,
                            std::span<const PredictorCheckpoint> checkpoints,
                            EvalStats* stats) {
    if (node_id >= plan.ir->nodes.size()) return Code::Invalid;
    const BigInt& node_len = plan.lengths[node_id];
    if (start.compare(node_len) > 0) return Code::Invalid;
    auto end = bi_add(start, BigInt(static_cast<u64>(out.size())));
    if (!end.ok()) return end.code();
    if (end.value().compare(node_len) > 0) return Code::Invalid;

    std::unique_ptr<StreamSession> owned_session;
    if (session == nullptr) {
        Status seed_st;
        owned_session = make_stream_session(plan, checkpoints, seed_st);
        if (!seed_st.ok()) return seed_st;
        session = owned_session.get();
    }
    if (out.empty()) return Status{};

    const std::size_t chunk_cap = std::min<std::size_t>(plan.limits.block_bytes, kEvalBlock);
    std::size_t done = 0;
    BigInt pos = start;
    while (done < out.size()) {
        const std::size_t take = std::min<std::size_t>(chunk_cap, out.size() - done);
        const Status st = run_chunk_explicit_stack(
            plan, node_id, pos, out.subspan(done, take), *session, stats);
        if (!st.ok()) return st;
        done += take;
        if (done < out.size()) {
            auto next = bi_add(pos, BigInt(static_cast<u64>(take)));
            if (!next.ok()) return next.code();
            pos = std::move(next.value());
        }
    }
    return Status{};
}

Status stream_range_to_sink(const EvalPlanData& plan, u32 node_id, const BigInt& start,
                            const BigInt& length, Sink& sink,
                            std::span<const PredictorCheckpoint> checkpoints,
                            EvalStats* stats) {
    if (node_id >= plan.ir->nodes.size()) return Code::Invalid;
    const BigInt& node_len = plan.lengths[node_id];
    if (start.compare(node_len) > 0) return Code::Invalid;
    auto end = bi_add(start, length);
    if (!end.ok()) return end.code();
    if (end.value().compare(node_len) > 0) return Code::Invalid;

    Status seed_st;
    auto session = make_stream_session(plan, checkpoints, seed_st);
    if (!seed_st.ok()) return seed_st;
    if (length.is_zero()) return Status{};

    std::vector<u8> buffer(plan.limits.block_bytes);
    BigInt pos = start;
    BigInt left = length;
    while (!left.is_zero()) {
        u64 take = static_cast<u64>(buffer.size());
        if (auto fit = left.to_u64_checked(); fit.has_value()) {
            take = std::min<u64>(take, fit.value());
        }
        const std::span<u8> slice(buffer.data(), static_cast<std::size_t>(take));
        const Status st =
            eval_range_with_plan(plan, node_id, pos, slice, session.get(), {}, stats);
        if (!st.ok()) return st;
        const Status sink_st = sink.write(std::span<const u8>(slice.data(), slice.size()));
        if (!sink_st.ok()) return sink_st;
        if (stats != nullptr) ++stats->sink_writes;

        auto rest = bi_sub(left, BigInt(take));
        if (!rest.ok()) return rest.code();
        left = std::move(rest.value());
        if (!left.is_zero()) {
            auto next = bi_add(pos, BigInt(take));
            if (!next.ok()) return next.code();
            pos = std::move(next.value());
        }
    }
    return Status{};
}

Result<PredictorCheckpoint> capture_checkpoint_with_plan(
    const EvalPlanData& plan, u32 predictor_node, const BigInt& target_offset,
    const PredictorCheckpoint* from, EvalStats* stats) {
    const Ir& ir = *plan.ir;
    if (predictor_node >= ir.nodes.size()) return Code::Invalid;
    const Node& node = ir.nodes[predictor_node];
    if (node.kind != Kind::Predictor) return Code::Invalid;
    const u8 pid = node.predictor_id;
    const u32 param = node.predictor_param;
    if (!check_predictor_params(pid, param).ok()) return Code::Invalid;

    const BigInt& total = plan.lengths[predictor_node];
    if (target_offset.compare(total) > 0) return Code::Invalid;

    BigInt base_off = BigInt::zero();
    if (from != nullptr) {
        if (from->node != predictor_node) return Code::Invalid;
        const Status vst = validate_checkpoint_against_plan(plan, *from);
        if (!vst.ok()) return vst.code();
        if (from->offset.compare(target_offset) > 0) return Code::Invalid;
        base_off = from->offset;
    }

    auto gap = bi_sub(target_offset, base_off);
    if (!gap.ok()) return gap.code();
    if (gap.value().compare(plan.limits.predictor_prefix_max) > 0) return Code::Limit;

    std::size_t window = 0;
    if ((pid == 3 || pid == 4) && BigInt(param).compare(total) < 0) {
        if (static_cast<std::size_t>(param) > plan.limits.max_predictor_window ||
            static_cast<std::size_t>(param) > plan.limits.max_scratch_bytes) {
            return Code::Limit;
        }
        window = static_cast<std::size_t>(param);
    }

    PredRunState state;
    state.pid = pid;
    state.param = param;
    state.window = window;
    if (from != nullptr && !from->offset.is_zero()) {
        state.prev1 = from->prev1;
        state.prev2 = from->prev2;
        state.seeded = (from->offset.compare(BigInt(1)) == 0) ? 1u : 2u;
        if (window > 0) {
            auto rem = from->offset.divmod_scalar(param);
            if (!rem.ok()) return to_status(rem.error()).code();
            state.ring = from->window;
            state.ring_slot = static_cast<std::size_t>(rem.value().second);
        }
    } else if (window > 0) {
        state.ring.assign(window, 0u);
    }

    if (stats != nullptr && window > stats->peak_scratch_bytes) {
        stats->peak_scratch_bytes = window;
    }

    Status seed_st;
    auto session = make_stream_session(plan, {}, seed_st);
    if (!seed_st.ok()) return seed_st.code();

    const u32 residual_id = node.args[0];
    const std::size_t step_cap = std::min<std::size_t>(plan.limits.block_bytes, kEvalBlock);
    std::vector<u8> chunk_buf(step_cap);
    BigInt pos = base_off;
    while (pos.compare(target_offset) < 0) {
        auto rem = bi_sub(target_offset, pos);
        if (!rem.ok()) return rem.code();
        auto take_res = min_u64(rem.value(), rem.value(), static_cast<u64>(step_cap));
        if (!take_res.ok()) return take_res.code();
        const std::size_t take = static_cast<std::size_t>(take_res.value());
        const std::span<u8> slice(chunk_buf.data(), take);
        const Status st =
            eval_range_with_plan(plan, residual_id, pos, slice, session.get(), {}, stats);
        if (!st.ok()) return st.code();
        state.discard_span(std::span<const u8>(slice.data(), take));
        if (stats != nullptr) stats->predictor_prefix_bytes += take;
        auto next = bi_add(pos, BigInt(static_cast<u64>(take)));
        if (!next.ok()) return next.code();
        pos = std::move(next.value());
    }

    PredictorCheckpoint cp;
    cp.node = predictor_node;
    cp.offset = target_offset;
    if (!target_offset.is_zero()) {
        if (pid == 0 || pid == 1) {
            cp.prev1 = state.prev1;
        } else if (pid == 2) {
            cp.prev1 = state.prev1;
            cp.prev2 = (target_offset.compare(BigInt(1)) == 0) ? 0u : state.prev2;
        } else if (window > 0) {
            cp.window = std::move(state.ring);
        }
    }
    return cp;
}

}  // namespace detail

// --- Normative E2 §8 evaluation entry points -------------------------------

Result<std::size_t> read_range(const Ir& ir, u32 node, const BigInt& start,
                               std::span<u8> out) {
    auto plan = detail::build_eval_plan(ir, EvalLimits{}, true, node);
    if (!plan.ok()) return plan.code();
    const Status st =
        detail::eval_range_with_plan(plan.value(), node, start, out, nullptr, {}, nullptr);
    if (!st.ok()) return st.code();
    return out.size();
}

// --- TermCursor ------------------------------------------------------------

struct TermCursor::Impl {
    u32 node = 0;
    detail::EvalPlanData plan;
    std::unique_ptr<detail::StreamSession> session;
    BigInt offset;
    BigInt remaining;
    Code error = Code::Ok;
};

TermCursor::TermCursor(const Ir& ir, u32 node) : impl_(std::make_unique<Impl>()) {
    impl_->node = node;
    auto plan = detail::build_eval_plan(ir, EvalLimits{}, true, node);
    if (!plan.ok()) {
        impl_->error = plan.code();
        return;
    }
    impl_->plan = std::move(plan.value());
    Status seed_st;
    impl_->session = detail::make_stream_session(impl_->plan, {}, seed_st);
    if (!seed_st.ok()) {
        impl_->error = seed_st.code();
        return;
    }
    impl_->remaining = impl_->plan.lengths[node];
}

TermCursor::~TermCursor() = default;
TermCursor::TermCursor(TermCursor&&) noexcept = default;
TermCursor& TermCursor::operator=(TermCursor&&) noexcept = default;

Result<std::size_t> TermCursor::read(std::span<u8> out) {
    if (impl_->error != Code::Ok) return impl_->error;
    if (out.empty()) return std::size_t{0};
    if (impl_->remaining.is_zero()) return std::size_t{0};
    u64 available = static_cast<u64>(out.size());
    if (auto fit = impl_->remaining.to_u64_checked(); fit.has_value()) {
        available = std::min<u64>(available, fit.value());
    }
    const std::span<u8> slice = out.first(static_cast<std::size_t>(available));
    const Status st = detail::eval_range_with_plan(
        impl_->plan, impl_->node, impl_->offset, slice, impl_->session.get(), {}, nullptr);
    if (!st.ok()) return st.code();
    auto next = bi_add(impl_->offset, BigInt(available));
    if (!next.ok()) return next.code();
    impl_->offset = std::move(next.value());
    auto left = bi_sub(impl_->remaining, BigInt(available));
    if (!left.ok()) return left.code();
    impl_->remaining = std::move(left.value());
    return static_cast<std::size_t>(available);
}

const BigInt& TermCursor::remaining() const noexcept { return impl_->remaining; }
const BigInt& TermCursor::offset() const noexcept { return impl_->offset; }
bool TermCursor::at_end() const noexcept { return impl_->remaining.is_zero(); }

// --- streaming / range sinks ----------------------------------------------

Status eval_stream(const Ir& ir, u32 node, Sink& sink) {
    auto plan = detail::build_eval_plan(ir, EvalLimits{}, true, node);
    if (!plan.ok()) return plan.code();
    const BigInt& total = plan.value().lengths[node];
    return detail::stream_range_to_sink(plan.value(), node, BigInt::zero(), total, sink, {},
                                        nullptr);
}

Status eval_stream(const Ir& ir, Sink& sink) { return eval_stream(ir, ir.root, sink); }

Status eval_range(const Ir& ir, const BigInt& start, const BigInt& length, Sink& sink) {
    auto plan = detail::build_eval_plan(ir, EvalLimits{}, true, ir.root);
    if (!plan.ok()) return plan.code();
    return detail::stream_range_to_sink(plan.value(), ir.root, start, length, sink, {},
                                        nullptr);
}

Result<std::vector<u8>> denote_node(const Ir& ir, u32 node, u64 max_bytes) {
    auto plan = detail::build_eval_plan(ir, EvalLimits{}, false, node);
    if (!plan.ok()) return plan.code();
    const BigInt& total = plan.value().lengths[node];
    if (total.compare(BigInt(max_bytes)) > 0) return Code::Limit;
    auto count = bi_to_u64(total);
    if (!count.ok()) return count.code();
    std::vector<u8> out(static_cast<std::size_t>(count.value()));
    if (!out.empty()) {
        const Status st = detail::eval_range_with_plan(
            plan.value(), node, BigInt::zero(), out, nullptr, {}, nullptr);
        if (!st.ok()) return st.code();
    }
    return out;
}

Result<std::vector<u8>> denote_root(const Ir& ir, u64 max_bytes) {
    return denote_node(ir, ir.root, max_bytes);
}

// ---------------------------------------------------------------------------
// Structural key (E2 §5.7) — deterministic, id-independent description.
// ---------------------------------------------------------------------------

std::string structural_key(const Ir& ir, u32 node) {
    constexpr std::size_t kKeyLimit = 1u << 20;
    std::vector<std::string> keys(ir.nodes.size());
    for (u32 i = 0; i < ir.nodes.size(); ++i) {
        const Node& n = ir.nodes[i];
        std::string key;
        key += kind_name(n.kind);
        auto append_param = [&key](const BigInt& v) {
            key.push_back(':');
            key += v.to_decimal();
        };
        switch (n.kind) {
            case Kind::Zero:
            case Kind::Lfsr:
            case Kind::Affine:
                append_param(n.a);
                break;
            case Kind::Repeat:
            case Kind::Slice:
                append_param(n.a);
                append_param(n.b);
                break;
            case Kind::Interleave:
                append_param(n.a);
                break;
            case Kind::Morph:
                key.push_back(':');
                key += std::to_string(n.morph);
                key.push_back(':');
                key += std::to_string(n.morph_k);
                break;
            default:
                break;
        }
        if (n.kind == Kind::Lfsr) {
            key.push_back('[');
            key += std::to_string(n.lfsr_conn);
            key.push_back(',');
            key += std::to_string(n.lfsr_init);
            key.push_back(']');
        }
        if (n.kind == Kind::Affine) {
            key.push_back('[');
            key += std::to_string(n.affine_start);
            key.push_back(',');
            key += std::to_string(n.affine_step);
            key.push_back(']');
        }
        if (n.kind == Kind::Predictor) {
            key.push_back('[');
            key += std::to_string(n.predictor_id);
            key.push_back(',');
            key += std::to_string(n.predictor_param);
            key.push_back(']');
        }
        if (n.kind == Kind::Atom) {
            // Atom identity for structural purposes is (length, sha256), never
            // the atom index: canonical_key must be id-independent (E2 §5.7).
            key.push_back('[');
            auto atom_id = n.a.to_u64_checked();
            if (atom_id.has_value() && *atom_id < ir.atoms.size()) {
                const Atom& atom = ir.atoms[static_cast<std::size_t>(*atom_id)];
                key += atom.length.to_decimal();
                key.push_back(':');
                static const char* digits = "0123456789abcdef";
                for (u8 byte : atom.sha256) {
                    key.push_back(digits[byte >> 4]);
                    key.push_back(digits[byte & 0x0Fu]);
                }
            }
            key.push_back(']');
        }
        key.push_back('(');
        for (std::size_t k = 0; k < n.args.size(); ++k) {
            const u32 arg = n.args[k];
            if (k != 0) key.push_back(',');
            key += (arg < keys.size()) ? keys[arg] : std::string("#oob");
        }
        key.push_back(')');
        keys[i] = std::move(key);
    }
    if (node >= keys.size()) return std::string();
    if (keys[node].size() > kKeyLimit) return std::string("#limit");
    return keys[node];
}

}  // namespace marp::v2
