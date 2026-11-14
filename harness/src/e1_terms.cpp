#include "marp/harness/e1_terms.hpp"
#include <mapr/e1_sha256.hpp>
#include <algorithm>
#include <array>
#include <cstdint>
#include <map>
#include <optional>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace marp::harness {

namespace {

using mapr::NodeKind;

std::string sha256_hex(std::string_view data) {
    auto digest = mapr::Sha256::hash(data);
    if (!digest.ok()) return "";
    static constexpr char hex[] = "0123456789abcdef";
    std::string out;
    out.reserve(64);
    for (uint8_t byte : digest.value()) {
        out.push_back(hex[byte >> 4]);
        out.push_back(hex[byte & 0x0Fu]);
    }
    return out;
}

// Deterministic replacement for std::uniform_int_distribution. mt19937_64 is
// standardised, so `rng() % span` produces the same sequence on every
// libstdc++ version. Corpus identity must not depend on the standard library.
uint64_t pick(std::mt19937_64& rng, uint64_t lo, uint64_t hi) {
    if (hi <= lo) return lo;
    const uint64_t span = hi - lo + 1;
    return lo + rng() % span;
}

TermNode finish_leaf(TermNode node) {
    node.depth = 1;
    node.stored_length = mapr::BigInt(node.generation_length);
    return node;
}

TermNode make_empty() {
    TermNode n;
    n.kind = NodeKind::Empty;
    n.generation_length = 0;
    return finish_leaf(n);
}

TermNode make_atom(uint32_t size) {
    TermNode n;
    n.kind = NodeKind::Atom;
    n.atom_size = size;
    n.generation_length = size;
    return finish_leaf(n);
}

TermNode make_zero(uint64_t count) {
    TermNode n;
    n.kind = NodeKind::Zero;
    n.zero_n = mapr::BigInt(count);
    n.generation_length = count;
    return finish_leaf(n);
}

TermNode make_lfsr(uint64_t count) {
    TermNode n;
    n.kind = NodeKind::Lfsr;
    n.n = mapr::BigInt(count);
    n.generation_length = count;
    return finish_leaf(n);
}

TermNode make_affine(uint64_t count) {
    TermNode n;
    n.kind = NodeKind::Affine;
    n.n = mapr::BigInt(count);
    n.generation_length = count;
    return finish_leaf(n);
}

TermNode make_simple_leaf(std::mt19937_64& rng) {
    switch (pick(rng, 0, 4)) {
        case 0: return make_empty();
        case 1: return make_atom(static_cast<uint32_t>(pick(rng, 1, 12)));
        case 2: return make_zero(pick(rng, 1, 12));
        case 3: return make_lfsr(pick(rng, 1, 12));
        default: return make_affine(pick(rng, 1, 12));
    }
}

// A leaf of non-zero length. Repeat/Slice need at least one such node in the
// DAG, and supplying it at generation time keeps the generator total.
TermNode make_nonempty_leaf(std::mt19937_64& rng) {
    switch (pick(rng, 0, 3)) {
        case 0: return make_atom(static_cast<uint32_t>(pick(rng, 1, 12)));
        case 1: return make_zero(pick(rng, 1, 12));
        case 2: return make_lfsr(pick(rng, 1, 12));
        default: return make_affine(pick(rng, 1, 12));
    }
}

void set_parent_depth(TermNode& parent, const std::vector<TermNode>& nodes,
                      const std::vector<uint32_t>& child_ids) {
    int depth = 0;
    for (uint32_t id : child_ids) {
        depth = std::max(depth, nodes[static_cast<size_t>(id)].depth);
    }
    parent.depth = depth + 1;
    parent.stored_length = mapr::BigInt(parent.generation_length);
}

TermNode make_concat(std::mt19937_64& rng, const std::vector<TermNode>& nodes) {
    TermNode n;
    n.kind = NodeKind::Concat;
    const size_t count = static_cast<size_t>(pick(rng, 2, std::min<uint64_t>(3, nodes.size())));
    for (size_t i = 0; i < count; ++i) {
        const uint32_t id = static_cast<uint32_t>(pick(rng, 0, nodes.size() - 1));
        n.children.push_back(id);
        n.generation_length += nodes[static_cast<size_t>(id)].generation_length;
    }
    set_parent_depth(n, nodes, n.children);
    return n;
}

TermNode make_repeat(std::mt19937_64& rng, const std::vector<TermNode>& nodes) {
    TermNode n;
    n.kind = NodeKind::Repeat;
    std::vector<uint32_t> candidates;
    for (size_t i = 0; i < nodes.size(); ++i) {
        if (nodes[i].generation_length > 0) candidates.push_back(static_cast<uint32_t>(i));
    }
    if (candidates.empty()) throw std::logic_error("repeat needs a non-empty child");
    n.child = candidates[static_cast<size_t>(pick(rng, 0, candidates.size() - 1))];
    const uint64_t child_len = nodes[static_cast<size_t>(n.child)].generation_length;
    n.repeat_q = mapr::BigInt(pick(rng, 1, 3));
    n.repeat_r = mapr::BigInt(pick(rng, 0, child_len - 1));
    n.generation_length =
        static_cast<uint64_t>(n.repeat_q.to_u64_checked().value()) * child_len +
        static_cast<uint64_t>(n.repeat_r.to_u64_checked().value());
    set_parent_depth(n, nodes, {n.child});
    return n;
}

TermNode make_slice(std::mt19937_64& rng, const std::vector<TermNode>& nodes) {
    TermNode n;
    n.kind = NodeKind::Slice;
    std::vector<uint32_t> candidates;
    for (size_t i = 0; i < nodes.size(); ++i) {
        if (nodes[i].generation_length > 0) candidates.push_back(static_cast<uint32_t>(i));
    }
    if (candidates.empty()) throw std::logic_error("slice needs a non-empty child");
    n.child = candidates[static_cast<size_t>(pick(rng, 0, candidates.size() - 1))];
    const uint64_t child_len = nodes[static_cast<size_t>(n.child)].generation_length;
    const uint64_t len = pick(rng, 1, child_len);
    const uint64_t start = pick(rng, 0, child_len - len);
    n.slice_start = mapr::BigInt(start);
    n.slice_len = mapr::BigInt(len);
    n.generation_length = len;
    set_parent_depth(n, nodes, {n.child});
    return n;
}

TermNode make_morph(std::mt19937_64& rng, const std::vector<TermNode>& nodes) {
    TermNode n;
    n.kind = NodeKind::Morph;
    n.child = static_cast<uint32_t>(pick(rng, 0, nodes.size() - 1));
    n.generation_length = nodes[static_cast<size_t>(n.child)].generation_length;
    set_parent_depth(n, nodes, {n.child});
    return n;
}

TermNode make_predictor(std::mt19937_64& rng, const std::vector<TermNode>& nodes) {
    TermNode n;
    n.kind = NodeKind::Predictor;
    n.child = static_cast<uint32_t>(pick(rng, 0, nodes.size() - 1));
    n.generation_length = nodes[static_cast<size_t>(n.child)].generation_length;
    set_parent_depth(n, nodes, {n.child});
    return n;
}

std::optional<TermNode> make_equal_length_parent(std::mt19937_64& rng,
                                                 const std::vector<TermNode>& nodes,
                                                 NodeKind kind) {
    std::map<uint64_t, std::vector<uint32_t>> by_length;
    for (size_t i = 0; i < nodes.size(); ++i) {
        by_length[nodes[i].generation_length].push_back(static_cast<uint32_t>(i));
    }
    std::vector<uint64_t> usable;
    for (const auto& [len, ids] : by_length) {
        if (ids.size() >= 2) usable.push_back(len);
    }
    if (usable.empty()) return std::nullopt;

    const uint64_t len = usable[static_cast<size_t>(pick(rng, 0, usable.size() - 1))];
    const std::vector<uint32_t>& ids = by_length[len];

    TermNode n;
    n.kind = kind;
    if (kind == NodeKind::Xor) {
        n.xor_a = ids[static_cast<size_t>(pick(rng, 0, ids.size() - 1))];
        n.xor_b = ids[static_cast<size_t>(pick(rng, 0, ids.size() - 1))];
        n.generation_length = len;
        set_parent_depth(n, nodes, {n.xor_a, n.xor_b});
        return n;
    }

    const size_t count = static_cast<size_t>(pick(rng, 2, std::min<uint64_t>(3, ids.size())));
    for (size_t i = 0; i < count; ++i) {
        n.children.push_back(ids[static_cast<size_t>(pick(rng, 0, ids.size() - 1))]);
    }
    n.stride = 1;
    if (len > 0) {
        std::vector<uint32_t> divisors;
        for (uint32_t d = 1; static_cast<uint64_t>(d) <= len; ++d) {
            if (len % d == 0) divisors.push_back(d);
        }
        n.stride = divisors[static_cast<size_t>(pick(rng, 0, divisors.size() - 1))];
    }
    n.generation_length = static_cast<uint64_t>(count) * len;
    set_parent_depth(n, nodes, n.children);
    return n;
}

TermNode make_composite(std::mt19937_64& rng, const std::vector<TermNode>& nodes) {
    // Try a random composite kind, falling back to Concat when the current
    // node set cannot satisfy a constraint (e.g. no two equal lengths).
    const uint64_t choice = pick(rng, 0, 6);
    std::optional<TermNode> result;
    switch (choice) {
        case 0: return make_concat(rng, nodes);
        case 1: return make_repeat(rng, nodes);
        case 2: return make_slice(rng, nodes);
        case 3: return make_morph(rng, nodes);
        case 4: return make_predictor(rng, nodes);
        case 5:
            result = make_equal_length_parent(rng, nodes, NodeKind::Xor);
            break;
        default:
            result = make_equal_length_parent(rng, nodes, NodeKind::Interleave);
            break;
    }
    if (result) return *result;
    return make_concat(rng, nodes);
}

TermSet build_special_term(size_t index) {
    TermSet term;
    switch (index) {
        case 0:
            term.nodes.push_back(make_empty());
            break;
        case 1:
            term.nodes.push_back(make_atom(5));
            break;
        case 2:
            term.nodes.push_back(make_zero(7));
            break;
        case 3: {
            term.nodes.push_back(make_empty());
            term.nodes.push_back(make_atom(5));
            TermNode n;
            n.kind = NodeKind::Concat;
            n.children = {0, 1};
            n.generation_length = 5;
            set_parent_depth(n, term.nodes, n.children);
            term.nodes.push_back(n);
            break;
        }
        case 4: {
            term.nodes.push_back(make_atom(3));
            TermNode n;
            n.kind = NodeKind::Repeat;
            n.child = 0;
            n.repeat_q = mapr::BigInt(2);
            n.repeat_r = mapr::BigInt(1);
            n.generation_length = 7;
            set_parent_depth(n, term.nodes, {0});
            term.nodes.push_back(n);
            break;
        }
        case 5: {
            term.nodes.push_back(make_atom(10));
            TermNode n;
            n.kind = NodeKind::Slice;
            n.child = 0;
            n.slice_start = mapr::BigInt(2);
            n.slice_len = mapr::BigInt(5);
            n.generation_length = 5;
            set_parent_depth(n, term.nodes, {0});
            term.nodes.push_back(n);
            break;
        }
        case 6: {
            term.nodes.push_back(make_atom(4));
            TermNode n;
            n.kind = NodeKind::Morph;
            n.child = 0;
            n.generation_length = 4;
            set_parent_depth(n, term.nodes, {0});
            term.nodes.push_back(n);
            break;
        }
        case 7: {
            term.nodes.push_back(make_atom(3));
            term.nodes.push_back(make_atom(3));
            TermNode n;
            n.kind = NodeKind::Xor;
            n.xor_a = 0;
            n.xor_b = 1;
            n.generation_length = 3;
            set_parent_depth(n, term.nodes, {0, 1});
            term.nodes.push_back(n);
            break;
        }
        case 8: {
            term.nodes.push_back(make_atom(4));
            term.nodes.push_back(make_atom(4));
            TermNode n;
            n.kind = NodeKind::Interleave;
            n.children = {0, 1};
            n.stride = 2;
            n.generation_length = 8;
            set_parent_depth(n, term.nodes, n.children);
            term.nodes.push_back(n);
            break;
        }
        case 9:
            term.nodes.push_back(make_lfsr(9));
            break;
        case 10:
            term.nodes.push_back(make_affine(11));
            break;
        default: {
            term.nodes.push_back(make_atom(6));
            TermNode n;
            n.kind = NodeKind::Predictor;
            n.child = 0;
            n.generation_length = 6;
            set_parent_depth(n, term.nodes, {0});
            term.nodes.push_back(n);
            break;
        }
    }
    return term;
}

TermSet build_random_term(std::mt19937_64& rng) {
    TermSet term;
    const int target_depth = static_cast<int>(pick(rng, 1, 4));
    if (target_depth == 1) {
        term.nodes.push_back(make_simple_leaf(rng));
        return term;
    }

    // At least one non-empty leaf so Repeat/Slice always have a legal child.
    term.nodes.push_back(make_nonempty_leaf(rng));
    term.nodes.push_back(make_simple_leaf(rng));
    for (int level = 2; level <= target_depth; ++level) {
        term.nodes.push_back(make_composite(rng, term.nodes));
    }
    return term;
}

std::string serialize_term(const TermSet& term) {
    std::ostringstream oss;
    for (size_t i = 0; i < term.nodes.size(); ++i) {
        const TermNode& n = term.nodes[i];
        if (i != 0) oss << ';';
        switch (n.kind) {
            case NodeKind::Empty: oss << "E"; break;
            case NodeKind::Atom: oss << "A" << n.atom_size; break;
            case NodeKind::Zero: oss << "Z" << n.zero_n.to_decimal(); break;
            case NodeKind::Concat:
                oss << "C";
                for (size_t c = 0; c < n.children.size(); ++c) {
                    if (c != 0) oss << ',';
                    oss << n.children[c];
                }
                break;
            case NodeKind::Repeat:
                oss << "R" << n.child << ',' << n.repeat_q.to_decimal()
                    << ',' << n.repeat_r.to_decimal();
                break;
            case NodeKind::Slice:
                oss << "S" << n.child << ',' << n.slice_start.to_decimal()
                    << ',' << n.slice_len.to_decimal();
                break;
            case NodeKind::Morph: oss << "M" << n.child; break;
            case NodeKind::Xor: oss << "X" << n.xor_a << ',' << n.xor_b; break;
            case NodeKind::Interleave:
                oss << "I";
                for (size_t c = 0; c < n.children.size(); ++c) {
                    if (c != 0) oss << ',';
                    oss << n.children[c];
                }
                oss << ',' << n.stride;
                break;
            case NodeKind::Lfsr: oss << "L" << n.n.to_decimal(); break;
            case NodeKind::Affine: oss << "F" << n.n.to_decimal(); break;
            case NodeKind::Predictor: oss << "P" << n.child; break;
        }
    }
    return oss.str();
}

bool to_oracle(const mapr::BigInt& value, oracle::BigInt& out) {
    auto parsed = oracle::from_decimal(value.to_decimal());
    if (!parsed) return false;
    out = std::move(*parsed);
    return true;
}

} // namespace

std::vector<TermSet> build_terms(uint64_t seed, size_t count) {
    std::mt19937_64 rng(seed ^ 0x5445524Du); // "TERM"
    std::vector<TermSet> terms;
    terms.reserve(count);

    const size_t special = std::min<size_t>(count, 12);
    for (size_t i = 0; i < special; ++i) {
        terms.push_back(build_special_term(i));
    }
    for (size_t i = special; i < count; ++i) {
        terms.push_back(build_random_term(rng));
    }
    return terms;
}

std::string term_fingerprint(const TermSet& term) {
    return sha256_hex(serialize_term(term));
}

std::vector<oracle::BigInt> oracle_lengths(const TermSet& term) {
    std::vector<oracle::BigInt> memo(term.nodes.size(), oracle::BigInt{0});
    for (size_t i = 0; i < term.nodes.size(); ++i) {
        const TermNode& n = term.nodes[i];
        oracle::BigInt value{0};
        switch (n.kind) {
            case NodeKind::Empty:
                value = oracle::BigInt{0};
                break;
            case NodeKind::Atom:
                value = oracle::BigInt{static_cast<oracle::Limb>(n.atom_size)};
                break;
            case NodeKind::Zero:
                if (!to_oracle(n.zero_n, value)) return {};
                break;
            case NodeKind::Concat: {
                value = oracle::BigInt{0};
                for (uint32_t child : n.children) {
                    value = oracle::add(value, memo[static_cast<size_t>(child)]);
                }
                break;
            }
            case NodeKind::Repeat: {
                oracle::BigInt q;
                oracle::BigInt r;
                if (!to_oracle(n.repeat_q, q) || !to_oracle(n.repeat_r, r)) return {};
                value = oracle::add(oracle::mul(q, memo[static_cast<size_t>(n.child)]), r);
                break;
            }
            case NodeKind::Slice:
                if (!to_oracle(n.slice_len, value)) return {};
                break;
            case NodeKind::Morph:
                value = memo[static_cast<size_t>(n.child)];
                break;
            case NodeKind::Xor: {
                const oracle::BigInt& a = memo[static_cast<size_t>(n.xor_a)];
                const oracle::BigInt& b = memo[static_cast<size_t>(n.xor_b)];
                if (oracle::compare(a, b) != 0) return {};
                value = a;
                break;
            }
            case NodeKind::Interleave: {
                if (n.children.size() < 2) return {};
                const oracle::BigInt& first = memo[static_cast<size_t>(n.children[0])];
                for (uint32_t child : n.children) {
                    if (oracle::compare(memo[static_cast<size_t>(child)], first) != 0) return {};
                }
                value = oracle::mul(oracle::BigInt{static_cast<oracle::Limb>(n.children.size())},
                                    first);
                break;
            }
            case NodeKind::Lfsr:
            case NodeKind::Affine:
                if (!to_oracle(n.n, value)) return {};
                break;
            case NodeKind::Predictor:
                value = memo[static_cast<size_t>(n.child)];
                break;
        }
        memo[i] = std::move(value);
    }
    return memo;
}

} // namespace marp::harness
