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
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "mapr/e1_sha256.hpp"

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

BigInt bi_max(const BigInt& x, const BigInt& y) {
    return x.compare(y) >= 0 ? x : y;
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
// Denotation (E2 §4.9, §5.3–5.5)
// ---------------------------------------------------------------------------

namespace {

constexpr u64 kPredictorWindowCap = 16ull << 20;  // 16 MiB resource policy (§5.5 Limit)

// Reads ⟦node⟧[start, start + out.size()); requires the range to be inside
// ℓ(node) (checked by the caller).
Status read_range_impl(const Ir& ir, const std::vector<BigInt>& len, u32 node_id,
                       const BigInt& start, std::span<u8> out);

Status read_child(const Ir& ir, const std::vector<BigInt>& len, u32 child, const BigInt& offset,
                  std::span<u8> out) {
    return read_range_impl(ir, len, child, offset, out);
}

Status read_concat(const Ir& ir, const std::vector<BigInt>& len, const Node& node,
                   const BigInt& start, std::span<u8> out) {
    const auto end = bi_add(start, BigInt(static_cast<u64>(out.size())));
    if (!end.ok()) return end.code();
    BigInt pos = BigInt::zero();
    std::size_t written = 0;
    for (u32 child : node.args) {
        if (written >= out.size()) break;
        const BigInt& child_len = len[child];
        auto child_end = bi_add(pos, child_len);
        if (!child_end.ok()) return child_end.code();
        const BigInt lo = bi_max(start, pos);
        const BigInt hi = bi_min(end.value(), child_end.value());
        if (lo.compare(hi) < 0) {
            auto child_offset = bi_sub(lo, pos);
            if (!child_offset.ok()) return child_offset.code();
            auto take = bi_sub(hi, lo);
            if (!take.ok()) return take.code();
            auto count = bi_to_u64(take.value());
            if (!count.ok()) return count.code();
            const auto slice = out.subspan(written, static_cast<std::size_t>(count.value()));
            const Status st = read_child(ir, len, child, child_offset.value(), slice);
            if (!st.ok()) return st;
            written += static_cast<std::size_t>(count.value());
        }
        pos = std::move(child_end.value());
        if (pos.compare(end.value()) >= 0) break;
    }
    if (written != out.size()) return Code::Invalid;
    return Status{};
}

Status read_repeat(const Ir& ir, const std::vector<BigInt>& len, const Node& node,
                   const BigInt& start, std::span<u8> out) {
    const u32 child = node.args[0];
    const BigInt& period = len[child];
    if (period.is_zero()) return Code::Invalid;
    const auto copies_bytes = bi_mul(node.a, period);
    if (!copies_bytes.ok()) return copies_bytes.code();
    const auto end = bi_add(start, BigInt(static_cast<u64>(out.size())));
    if (!end.ok()) return end.code();

    BigInt pos = start;
    std::size_t written = 0;
    while (written < out.size()) {
        BigInt child_offset;
        BigInt remaining_at_pos;
        if (pos.compare(copies_bytes.value()) < 0) {
            auto rem = bi_sub(copies_bytes.value(), pos);
            if (!rem.ok()) return rem.code();
            auto within = bi_mod(pos, period);
            if (!within.ok()) return within.code();
            const auto avail = bi_sub(period, within.value());
            if (!avail.ok()) return avail.code();
            remaining_at_pos = std::move(rem.value());
            auto take = min_u64(avail.value(), remaining_at_pos,
                                static_cast<u64>(out.size() - written));
            if (!take.ok()) return take.code();
            const auto slice = out.subspan(written, static_cast<std::size_t>(take.value()));
            const Status st = read_child(ir, len, child, within.value(), slice);
            if (!st.ok()) return st;
            written += static_cast<std::size_t>(take.value());
            auto next = bi_add(pos, BigInt(take.value()));
            if (!next.ok()) return next.code();
            pos = std::move(next.value());
            continue;
        }
        // Prefix region: ⟦c⟧[0, r) after q copies.
        auto off = bi_sub(pos, copies_bytes.value());
        if (!off.ok()) return off.code();
        auto to_end = bi_sub(end.value(), pos);
        if (!to_end.ok()) return to_end.code();
        auto take = min_u64(to_end.value(), node.b,
                            static_cast<u64>(out.size() - written));
        if (!take.ok()) return take.code();
        if (take.value() == 0) return Code::Invalid;
        const auto slice = out.subspan(written, static_cast<std::size_t>(take.value()));
        const Status st = read_child(ir, len, child, off.value(), slice);
        if (!st.ok()) return st;
        written += static_cast<std::size_t>(take.value());
        auto next = bi_add(pos, BigInt(take.value()));
        if (!next.ok()) return next.code();
        pos = std::move(next.value());
    }
    return Status{};
}

Status read_morph(const Ir& ir, const std::vector<BigInt>& len, const Node& node,
                  const BigInt& start, std::span<u8> out) {
    const u32 child = node.args[0];
    const BigInt& child_len = len[child];
    const u8 morph = node.morph;
    const u8 k = node.morph_k;
    const u32 block = morph_block_size(morph);

    if (morph_is_byte_local(morph)) {
        const Status read_st = read_child(ir, len, child, start, out);
        if (!read_st.ok()) return read_st;
        return apply_morph_to_buffer(morph, k, out);
    }

    if (block != 0) {
        auto begin_div = start.divmod_scalar(block);
        if (!begin_div.ok()) return to_status(begin_div.error());
        const auto begin_q = bi_mul(begin_div.value().first, BigInt(block));
        if (!begin_q.ok()) return begin_q.code();

        const auto end = bi_add(start, BigInt(static_cast<u64>(out.size())));
        if (!end.ok()) return end.code();
        auto end_div = end.value().divmod_scalar(block);
        if (!end_div.ok()) return to_status(end_div.error());
        BigInt block_end = bi_mul(end_div.value().first, BigInt(block)).value();
        if (end_div.value().second != 0) {
            auto bump = bi_add(block_end, BigInt(block));
            if (!bump.ok()) return bump.code();
            block_end = std::move(bump.value());
        }
        if (block_end.compare(child_len) > 0) block_end = child_len;

        auto span_len = bi_sub(block_end, begin_q.value());
        if (!span_len.ok()) return span_len.code();
        auto span_count = bi_to_u64(span_len.value());
        if (!span_count.ok()) return span_count.code();
        std::vector<u8> expanded(static_cast<std::size_t>(span_count.value()));
        const Status read_st = read_child(ir, len, child, begin_q.value(), expanded);
        if (!read_st.ok()) return read_st;
        const Status morph_st = apply_morph_to_buffer(morph, k, expanded);
        if (!morph_st.ok()) return morph_st;
        auto offset = bi_sub(start, begin_q.value());
        if (!offset.ok()) return offset.code();
        auto offset_u64 = bi_to_u64(offset.value());
        if (!offset_u64.ok()) return offset_u64.code();
        const std::size_t from = static_cast<std::size_t>(offset_u64.value());
        if (from + out.size() > expanded.size()) return Code::Invalid;
        std::memcpy(out.data(), expanded.data() + from, out.size());
        return Status{};
    }

    // Mirrored morphs 8 and 9: out[j] = f(in[n-1-j]).
    auto mirrored_start = bi_sub(child_len, start);
    if (!mirrored_start.ok()) return mirrored_start.code();
    const auto span = BigInt(static_cast<u64>(out.size()));
    auto from = bi_sub(mirrored_start.value(), span);
    if (!from.ok()) return from.code();
    const Status read_st = read_child(ir, len, child, from.value(), out);
    if (!read_st.ok()) return read_st;
    std::reverse(out.begin(), out.end());
    if (morph == 9) {
        for (u8& byte : out) byte = bit_reverse8(byte);
    }
    return Status{};
}

Status read_xor(const Ir& ir, const std::vector<BigInt>& len, const Node& node,
                const BigInt& start, std::span<u8> out) {
    std::vector<u8> left(out.size());
    std::vector<u8> right(out.size());
    Status st = read_child(ir, len, node.args[0], start, left);
    if (!st.ok()) return st;
    st = read_child(ir, len, node.args[1], start, right);
    if (!st.ok()) return st;
    for (std::size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<u8>(left[i] ^ right[i]);
    }
    return Status{};
}

Status read_interleave(const Ir& ir, const std::vector<BigInt>& len, const Node& node,
                       const BigInt& start, std::span<u8> out) {
    auto stride_res = interleave_stride(node);
    if (!stride_res.ok()) return stride_res.code();
    const u64 stride = stride_res.value();
    if (stride == 0) return Code::Invalid;
    const u64 k = static_cast<u64>(node.args.size());
    const u64 block_bytes = k * stride;  // <= 2^24 * 2^32
    const BigInt block_big(block_bytes);

    BigInt pos = start;
    std::size_t written = 0;
    while (written < out.size()) {
        auto div = pos.divmod(block_big);
        if (!div.ok()) return to_status(div.error());
        const BigInt& block_index = div.value().first;
        const auto within_big = bi_to_u64(div.value().second);
        if (!within_big.ok()) return within_big.code();
        const u64 within = within_big.value();
        const u64 child_index = within / stride;
        const u64 within_child = within % stride;
        if (child_index >= k) return Code::Invalid;
        const u64 take = std::min<u64>(static_cast<u64>(out.size() - written),
                                       stride - within_child);
        auto base = bi_mul(block_index, BigInt(stride));
        if (!base.ok()) return base.code();
        auto child_offset = bi_add(base.value(), BigInt(within_child));
        if (!child_offset.ok()) return child_offset.code();
        const auto slice = out.subspan(written, static_cast<std::size_t>(take));
        const Status st = read_child(ir, len, node.args[static_cast<std::size_t>(child_index)],
                                     child_offset.value(), slice);
        if (!st.ok()) return st;
        written += static_cast<std::size_t>(take);
        auto next = bi_add(pos, BigInt(take));
        if (!next.ok()) return next.code();
        pos = std::move(next.value());
    }
    return Status{};
}

Status read_predictor(const Ir& ir, const std::vector<BigInt>& len, const Node& node,
                      const BigInt& start, std::span<u8> out) {
    const u8 pid = node.predictor_id;
    const u32 param = node.predictor_param;
    if (!check_predictor_params(pid, param).ok()) return Code::Invalid;
    if (start.compare(predictor_prefix_limit()) > 0) return Code::Limit;

    const u32 residual_id = node.args[0];
    const BigInt& total = len[residual_id];
    const BigInt prefix_end = bi_min(start, total);
    auto prefix_u64 = bi_to_u64(prefix_end);
    if (!prefix_u64.ok()) return prefix_u64.code();
    const u64 prefix = prefix_u64.value();

    std::size_t window = 0;
    if (pid == 3 || pid == 4) {
        const BigInt param_big(param);
        if (param_big.compare(total) < 0) {
            window = param;
            if (window > kPredictorWindowCap) return Code::Limit;
        }
    }
    std::vector<u8> ring(window, 0);

    u8 prev1 = 0;
    u8 prev2 = 0;
    std::vector<u8> buffer(kEvalBlock);

    auto step = [&](u64 index, u8 residual_byte) -> u8 {
        u8 value;
        if (pid == 2) {
            if (index == 0) {
                value = residual_byte;
            } else if (index == 1) {
                value = residual_byte;
            } else {
                value = apply_predictor_step(pid, param, residual_byte, prev1, prev2);
            }
            prev2 = prev1;
            prev1 = value;
            return value;
        }
        if (pid == 3 || pid == 4) {
            u8 previous = 0;
            if (window != 0) {
                const std::size_t slot = static_cast<std::size_t>(index % window);
                previous = ring[slot];
                value = apply_predictor_step(pid, param, residual_byte, previous, 0);
                ring[slot] = value;
            } else {
                value = apply_predictor_step(pid, param, residual_byte, 0, 0);
            }
            return value;
        }
        value = apply_predictor_step(pid, param, residual_byte, prev1, prev2);
        prev1 = value;
        return value;
    };

    // Pass 1: residual [0, prefix) — state restoration, output discarded.
    {
        u64 index = 0;
        BigInt pos = BigInt::zero();
        while (index < prefix) {
            const u64 take = std::min<u64>(static_cast<u64>(buffer.size()), prefix - index);
            const std::span<u8> chunk(buffer.data(), static_cast<std::size_t>(take));
            const Status st = read_child(ir, len, residual_id, pos, chunk);
            if (!st.ok()) return st;
            for (std::size_t j = 0; j < chunk.size(); ++j) (void)step(index + j, chunk[j]);
            index += take;
            auto next = bi_add(pos, BigInt(take));
            if (!next.ok()) return next.code();
            pos = std::move(next.value());
        }
    }

    // Pass 2: the requested range.
    {
        u64 done = 0;
        BigInt pos = start;
        while (done < out.size()) {
            const u64 take = std::min<u64>(static_cast<u64>(buffer.size()),
                                           static_cast<u64>(out.size() - done));
            const std::span<u8> chunk(buffer.data(), static_cast<std::size_t>(take));
            const Status st = read_child(ir, len, residual_id, pos, chunk);
            if (!st.ok()) return st;
            const u64 base_index = prefix + done;
            for (std::size_t j = 0; j < chunk.size(); ++j) {
                out[done + j] = step(base_index + j, chunk[j]);
            }
            done += take;
            auto next = bi_add(pos, BigInt(take));
            if (!next.ok()) return next.code();
            pos = std::move(next.value());
        }
    }
    return Status{};
}

// Structural guard: evaluation trusts WF(ir) as its precondition (E2 §5.3) but
// must never index an arg list that WF would have rejected.
bool node_shape_ok(const Ir& ir, const Node& node) {
    const std::size_t node_count = ir.nodes.size();
    auto args_in_range = [&]() {
        for (u32 arg : node.args) {
            if (arg >= node_count) return false;
        }
        return true;
    };
    switch (node.kind) {
        case Kind::Empty:
        case Kind::Atom:
        case Kind::Zero:
        case Kind::Lfsr:
        case Kind::Affine:
            return node.args.empty();
        case Kind::Repeat:
        case Kind::Slice:
        case Kind::Morph:
        case Kind::Predictor:
            return node.args.size() == 1 && args_in_range();
        case Kind::Xor:
            return node.args.size() == 2 && args_in_range();
        case Kind::Concat:
        case Kind::Interleave:
            return !node.args.empty() && args_in_range();
    }
    return false;
}

Status read_range_impl(const Ir& ir, const std::vector<BigInt>& len, u32 node_id,
                       const BigInt& start, std::span<u8> out) {
    if (node_id >= ir.nodes.size()) return Code::Invalid;
    const Node& node = ir.nodes[node_id];
    if (!node_shape_ok(ir, node)) return Code::Invalid;
    const BigInt& node_len = len[node_id];

    if (start.compare(node_len) > 0) return Code::Invalid;
    auto end = bi_add(start, BigInt(static_cast<u64>(out.size())));
    if (!end.ok()) return end.code();
    if (end.value().compare(node_len) > 0) return Code::Invalid;
    if (out.empty()) return Status{};

    switch (node.kind) {
        case Kind::Empty:
            return Code::Invalid;  // length 0 cannot host a non-empty range
        case Kind::Atom: {
            auto atom_id = node.a.to_u64_checked();
            if (!atom_id.has_value() || *atom_id >= ir.atoms.size()) return Code::Invalid;
            const Atom& atom = ir.atoms[static_cast<std::size_t>(*atom_id)];
            auto offset = bi_to_u64(start);
            if (!offset.ok()) return offset.code();
            const std::size_t from = static_cast<std::size_t>(offset.value());
            if (from + out.size() > atom.payload.size()) return Code::Invalid;
            std::memcpy(out.data(), atom.payload.data() + from, out.size());
            return Status{};
        }
        case Kind::Zero:
            std::memset(out.data(), 0, out.size());
            return Status{};
        case Kind::Concat:
            return read_concat(ir, len, node, start, out);
        case Kind::Repeat:
            return read_repeat(ir, len, node, start, out);
        case Kind::Slice: {
            auto child_start = bi_add(node.a, start);
            if (!child_start.ok()) return child_start.code();
            return read_child(ir, len, node.args[0], child_start.value(), out);
        }
        case Kind::Morph:
            return read_morph(ir, len, node, start, out);
        case Kind::Xor:
            return read_xor(ir, len, node, start, out);
        case Kind::Interleave:
            return read_interleave(ir, len, node, start, out);
        case Kind::Lfsr: {
            LfsrStream stream(node.lfsr_conn, node.lfsr_init);
            const Status jumped = stream.jump_to_byte_offset(start);
            if (!jumped.ok()) return jumped;
            return stream.read(out);
        }
        case Kind::Affine: {
            auto rem = start.divmod_scalar(256);
            if (!rem.ok()) return to_status(rem.error());
            const unsigned base =
                (static_cast<unsigned>(node.affine_start) +
                 static_cast<unsigned>(rem.value().second) *
                     static_cast<unsigned>(node.affine_step)) &
                0xFFu;
            for (std::size_t j = 0; j < out.size(); ++j) {
                out[j] = static_cast<u8>((base + static_cast<unsigned>(j) *
                                                    static_cast<unsigned>(node.affine_step)) &
                                         0xFFu);
            }
            return Status{};
        }
        case Kind::Predictor:
            return read_predictor(ir, len, node, start, out);
    }
    return Code::Invalid;
}

}  // namespace

Result<std::size_t> read_range(const Ir& ir, u32 node, const BigInt& start,
                               std::span<u8> out) {
    if (node >= ir.nodes.size()) return Code::Invalid;
    auto lengths = recompute_lengths_checked(ir);
    if (!lengths.ok()) return lengths.code();
    const Status st = read_range_impl(ir, lengths.value(), node, start, out);
    if (!st.ok()) return st.code();
    return out.size();
}

// --- TermCursor ------------------------------------------------------------

struct TermCursor::Impl {
    const Ir* ir = nullptr;
    u32 node = 0;
    std::vector<BigInt> lengths;
    BigInt offset;
    BigInt remaining;
    Code error = Code::Ok;
};

TermCursor::TermCursor(const Ir& ir, u32 node) : impl_(std::make_unique<Impl>()) {
    impl_->ir = &ir;
    impl_->node = node;
    if (node >= ir.nodes.size()) {
        impl_->error = Code::Invalid;
        return;
    }
    auto lengths = recompute_lengths_checked(ir);
    if (!lengths.ok()) {
        impl_->error = lengths.code();
        return;
    }
    impl_->lengths = std::move(lengths.value());
    impl_->remaining = impl_->lengths[node];
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
    const Status st = read_range_impl(*impl_->ir, impl_->lengths, impl_->node, impl_->offset,
                                      slice);
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
    TermCursor cursor(ir, node);
    std::vector<u8> buffer(kEvalBlock);
    for (;;) {
        auto count = cursor.read(buffer);
        if (!count.ok()) return count.code();
        if (count.value() == 0) break;
        const Status st = sink.write(std::span<const u8>(buffer.data(), count.value()));
        if (!st.ok()) return st;
    }
    return Status{};
}

Status eval_stream(const Ir& ir, Sink& sink) { return eval_stream(ir, ir.root, sink); }

Status eval_range(const Ir& ir, const BigInt& start, const BigInt& length, Sink& sink) {
    auto lengths = recompute_lengths_checked(ir);
    if (!lengths.ok()) return lengths.code();
    const BigInt& root_len = lengths.value()[ir.root];
    auto end = bi_add(start, length);
    if (!end.ok()) return end.code();
    if (end.value().compare(root_len) > 0) return Code::Invalid;

    std::vector<u8> buffer(kEvalBlock);
    BigInt pos = start;
    BigInt left = length;
    while (!left.is_zero()) {
        u64 take = static_cast<u64>(buffer.size());
        if (auto fit = left.to_u64_checked(); fit.has_value()) {
            take = std::min<u64>(take, fit.value());
        }
        const std::span<u8> slice(buffer.data(), static_cast<std::size_t>(take));
        const Status st = read_range_impl(ir, lengths.value(), ir.root, pos, slice);
        if (!st.ok()) return st;
        const Status sink_st = sink.write(std::span<const u8>(slice.data(), slice.size()));
        if (!sink_st.ok()) return sink_st;
        auto next = bi_add(pos, BigInt(take));
        if (!next.ok()) return next.code();
        pos = std::move(next.value());
        auto rest = bi_sub(left, BigInt(take));
        if (!rest.ok()) return rest.code();
        left = std::move(rest.value());
    }
    return Status{};
}

Result<std::vector<u8>> denote_node(const Ir& ir, u32 node, u64 max_bytes) {
    if (node >= ir.nodes.size()) return Code::Invalid;
    auto lengths = recompute_lengths_checked(ir);
    if (!lengths.ok()) return lengths.code();
    const BigInt& total = lengths.value()[node];
    if (total.compare(BigInt(max_bytes)) > 0) return Code::Limit;
    auto count = bi_to_u64(total);
    if (!count.ok()) return count.code();
    std::vector<u8> out(static_cast<std::size_t>(count.value()));
    if (!out.empty()) {
        const Status st = read_range_impl(ir, lengths.value(), node, BigInt::zero(), out);
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
