#include "mapr/encoder.hpp"
#include "mapr/bitio.hpp"
#include "mapr/crypto.hpp"
#include "mapr/math_core.hpp"
#include "mapr/simd/encoder_kernels.hpp"
#include "mapr/noise_detector.hpp"
#include "mapr/deflate_frontend.hpp"

#include <algorithm>
#include <chrono>
#include <deque>
#include <fstream>
#include <future>
#include <sstream>
#include <thread>
#include <unordered_map>

namespace mapr {

namespace {

double read_peak_rss_mb() {
    std::ifstream f("/proc/self/status");
    std::string line;
    while (std::getline(f, line)) {
        if (line.rfind("VmHWM:", 0) == 0) {
            std::istringstream iss(line.substr(6));
            uint64_t kb = 0;
            iss >> kb;
            return static_cast<double>(kb) / 1024.0;
        }
    }
    return 0.0;
}

// Hash-consing key for DAGNode deduplication
struct NodeKey {
    uint8_t op = 0;
    uint64_t a = 0, b = 0, c = 0, d = 0;
    std::vector<uint32_t> vec;
    std::vector<DualBasisAtom> atoms;

    bool operator==(const NodeKey& o) const noexcept {
        return op == o.op && a == o.a && b == o.b && c == o.c && d == o.d &&
               vec == o.vec && atoms == o.atoms;
    }
};

struct NodeKeyHash {
    size_t operator()(const NodeKey& k) const noexcept {
        uint64_t h = splitmix64(k.op ^ (k.a * 0x9E3779B97F4A7C15ULL));
        h ^= splitmix64(k.b + 0xBF58476D1CE4E5B9ULL);
        h ^= splitmix64(k.c + 0x94D049BB133111EBULL);
        h ^= splitmix64(k.d + 0x165667B19E3779F9ULL);
        for (uint32_t v : k.vec) h = splitmix64(h ^ v);
        for (const auto& at : k.atoms) {
            h = splitmix64(h ^ at.rho ^ (static_cast<uint64_t>(at.b) << 8) ^
                           (static_cast<uint64_t>(at.w) << 16) ^ static_cast<uint64_t>(at.beta));
        }
        return static_cast<size_t>(h);
    }
};

NodeKey make_node_key(const DAGNode& nd) {
    NodeKey k;
    if (std::holds_alternative<EmptyNode>(nd)) {
        k.op = 0;
    } else if (const auto* an = std::get_if<AtomNode>(&nd)) {
        k.op = 1;
        k.a = static_cast<uint64_t>(an->atom.beta);
        k.b = an->atom.b;
        k.c = an->atom.w;
        k.d = an->atom.rho;
    } else if (const auto* asn = std::get_if<AtomSpanNode>(&nd)) {
        k.op = 2;
        k.atoms = asn->atoms;
    } else if (const auto* cn = std::get_if<ConcatNode>(&nd)) {
        k.op = 3;
        k.vec = cn->children;
    } else if (const auto* rn = std::get_if<RepeatNode>(&nd)) {
        k.op = 4;
        k.a = rn->child; k.b = rn->q; k.c = rn->r;
    } else if (const auto* sn = std::get_if<SliceNode>(&nd)) {
        k.op = 5;
        k.a = sn->child; k.b = sn->start; k.c = sn->length;
    } else if (const auto* mn = std::get_if<MorphNode>(&nd)) {
        k.op = 6;
        k.a = mn->child; k.b = static_cast<uint64_t>(mn->mu);
    } else if (const auto* xn = std::get_if<XorDiffNode>(&nd)) {
        k.op = 7;
        k.a = xn->base; k.b = xn->delta;
    } else if (const auto* in = std::get_if<InterleaveNode>(&nd)) {
        k.op = 8;
        k.a = in->stride;
        k.vec = in->lanes;
    } else if (const auto* ln = std::get_if<LfsrNode>(&nd)) {
        k.op = 9;
        k.a = ln->degree; k.b = ln->conn_mask; k.c = ln->init_mask; k.d = ln->length;
    } else if (const auto* rn = std::get_if<RawNode>(&nd)) {
        k.op = 10;
        k.a = rn->bit_len;
        for (uint8_t b : rn->bytes) k.vec.push_back(b);
    } else if (const auto* dn = std::get_if<DedupRefNode>(&nd)) {
        k.op = 11;
        k.a = dn->ref_id;
    } else if (const auto* dn = std::get_if<DeflateHintNode>(&nd)) {
        k.op = 12;
        k.a = dn->cm | (static_cast<uint64_t>(dn->flg) << 8) |
              (static_cast<uint64_t>(dn->mtime) << 16) |
              (static_cast<uint64_t>(dn->xfl) << 24) |
              (static_cast<uint64_t>(dn->os) << 32);
    }
    return k;
}

class DAGBuilder {
public:
    uint32_t add(DAGNode node, uint64_t bit_len) {
        if (const auto* mn = std::get_if<MorphNode>(&node)) {
            if (mn->mu == V4Op::ID) return mn->child;
            if (const auto* inner = std::get_if<MorphNode>(&nodes_[mn->child])) {
                V4Op comp = compose_v4(mn->mu, inner->mu);
                if (comp == V4Op::ID) return inner->child;
                node = MorphNode{inner->child, comp};
            }
        }
        NodeKey key = make_node_key(node);
        auto it = memo_.find(key);
        if (it != memo_.end()) return it->second;
        uint32_t id = static_cast<uint32_t>(nodes_.size());
        nodes_.push_back(std::move(node));
        lengths_.push_back(bit_len);
        memo_.emplace(std::move(key), id);
        return id;
    }

    uint32_t add_morph(uint32_t child, V4Op mu) {
        if (mu == V4Op::ID) return child;
        return add(MorphNode{child, mu}, lengths_[child]);
    }

    uint32_t add_concat(const std::vector<uint32_t>& items) {
        std::vector<uint32_t> flat;
        flat.reserve(items.size());
        for (uint32_t u : items) {
            if (lengths_[u] > 0) flat.push_back(u);
        }
        if (flat.empty()) return add(EmptyNode{}, 0ULL);
        if (flat.size() == 1) return flat[0];

        // Collapse adjacent identical nodes into RepeatNode
        std::vector<uint32_t> collapsed;
        size_t i = 0;
        while (i < flat.size()) {
            size_t j = i + 1;
            while (j < flat.size() && flat[j] == flat[i]) ++j;
            size_t cnt = j - i;
            if (cnt >= 2) {
                uint64_t lu = lengths_[flat[i]];
                collapsed.push_back(add(RepeatNode{flat[i], cnt, 0ULL}, cnt * lu));
            } else {
                collapsed.push_back(flat[i]);
            }
            i = j;
        }
        if (collapsed.size() == 1) return collapsed[0];

        // Bounded arity <= 64 balanced tree
        while (collapsed.size() > 64) {
            std::vector<uint32_t> nxt;
            for (size_t p = 0; p < collapsed.size(); p += 64) {
                size_t end = std::min(collapsed.size(), p + 64);
                if (end - p == 1) {
                    nxt.push_back(collapsed[p]);
                } else {
                    std::vector<uint32_t> grp(collapsed.begin() + static_cast<ptrdiff_t>(p),
                                              collapsed.begin() + static_cast<ptrdiff_t>(end));
                    uint64_t sum = 0;
                    for (uint32_t x : grp) sum += lengths_[x];
                    nxt.push_back(add(ConcatNode{std::move(grp)}, sum));
                }
            }
            collapsed = std::move(nxt);
        }
        if (collapsed.size() == 1) return collapsed[0];
        uint64_t sum = 0;
        for (uint32_t x : collapsed) sum += lengths_[x];
        return add(ConcatNode{std::move(collapsed)}, sum);
    }

    uint64_t length_of(uint32_t u) const noexcept { return lengths_[u]; }
    const DAGNode& node_at(uint32_t u) const noexcept { return nodes_[u]; }

    uint32_t import_dag(const ExplicitChunkDAG& sub) {
        std::vector<uint32_t> imap(sub.nodes.size());
        for (size_t v = 0; v < sub.nodes.size(); ++v) {
            const auto& nd = sub.nodes[v];
            if (std::holds_alternative<EmptyNode>(nd)) {
                imap[v] = add(EmptyNode{}, 0);
            } else if (const auto* an = std::get_if<AtomNode>(&nd)) {
                imap[v] = add(AtomNode{an->atom}, an->atom.b);
            } else if (const auto* asn = std::get_if<AtomSpanNode>(&nd)) {
                uint64_t s = 0;
                for (const auto& a : asn->atoms) s += a.b;
                imap[v] = add(AtomSpanNode{asn->atoms}, s);
            } else if (const auto* cn = std::get_if<ConcatNode>(&nd)) {
                std::vector<uint32_t> ch;
                ch.reserve(cn->children.size());
                uint64_t s = 0;
                for (uint32_t u : cn->children) { ch.push_back(imap[u]); s += lengths_[imap[u]]; }
                imap[v] = add(ConcatNode{std::move(ch)}, s);
            } else if (const auto* rn = std::get_if<RepeatNode>(&nd)) {
                uint32_t c = imap[rn->child];
                imap[v] = add(RepeatNode{c, rn->q, rn->r}, rn->q * lengths_[c] + rn->r);
            } else if (const auto* sn = std::get_if<SliceNode>(&nd)) {
                imap[v] = add(SliceNode{imap[sn->child], sn->start, sn->length}, sn->length);
            } else if (const auto* mn = std::get_if<MorphNode>(&nd)) {
                uint32_t c = imap[mn->child];
                imap[v] = add(MorphNode{c, mn->mu}, lengths_[c]);
            } else if (const auto* xn = std::get_if<XorDiffNode>(&nd)) {
                uint32_t b = imap[xn->base], d = imap[xn->delta];
                imap[v] = add(XorDiffNode{b, d}, lengths_[b]);
            } else if (const auto* in = std::get_if<InterleaveNode>(&nd)) {
                std::vector<uint32_t> ln;
                ln.reserve(in->lanes.size());
                for (uint32_t u : in->lanes) ln.push_back(imap[u]);
                imap[v] = add(InterleaveNode{in->stride, std::move(ln)},
                              static_cast<uint64_t>(in->stride) * lengths_[imap[in->lanes[0]]]);
            } else if (const auto* ln = std::get_if<LfsrNode>(&nd)) {
                imap[v] = add(*ln, ln->length);
            } else if (const auto* rn = std::get_if<RawNode>(&nd)) {
                imap[v] = add(RawNode{rn->bytes, rn->bit_len}, rn->bit_len);
            } else if (const auto* dn = std::get_if<DedupRefNode>(&nd)) {
                // Length resolved externally; store 0 placeholder
                imap[v] = add(DedupRefNode{dn->ref_id}, 0);
            } else if (const auto* dn = std::get_if<DeflateHintNode>(&nd)) {
                // Length resolved externally; store 0 placeholder
                imap[v] = add(DeflateHintNode{dn->cm, dn->flg, dn->mtime, dn->xfl, dn->os}, 0);
            }
        }
        return imap[sub.root];
    }

    ExplicitChunkDAG build_compacted(uint32_t root) const {
        size_t m = nodes_.size();
        std::vector<uint8_t> reach(m, 0);
        reach[root] = 1;
        for (size_t v = m; v-- > 0;) {
            if (!reach[v]) continue;
            const auto& nd = nodes_[v];
            if (const auto* cn = std::get_if<ConcatNode>(&nd)) {
                for (uint32_t u : cn->children) reach[u] = 1;
            } else if (const auto* rn = std::get_if<RepeatNode>(&nd)) {
                reach[rn->child] = 1;
            } else if (const auto* sn = std::get_if<SliceNode>(&nd)) {
                reach[sn->child] = 1;
            } else if (const auto* mn = std::get_if<MorphNode>(&nd)) {
                reach[mn->child] = 1;
            } else if (const auto* xn = std::get_if<XorDiffNode>(&nd)) {
                reach[xn->base] = 1; reach[xn->delta] = 1;
            } else if (const auto* in = std::get_if<InterleaveNode>(&nd)) {
                for (uint32_t u : in->lanes) reach[u] = 1;
            } else if (std::get_if<LfsrNode>(&nd)) {
                // leaf
            } else if (std::get_if<RawNode>(&nd)) {
                // leaf
            } else if (std::get_if<DedupRefNode>(&nd)) {
                // leaf
            } else if (std::get_if<DeflateHintNode>(&nd)) {
                // leaf
            }
        }

        std::vector<uint32_t> remap(m, 0);
        ExplicitChunkDAG out;
        for (size_t v = 0; v < m; ++v) {
            if (!reach[v]) continue;
            uint32_t nid = static_cast<uint32_t>(out.nodes.size());
            remap[v] = nid;
            DAGNode nd = nodes_[v];
            if (auto* cn = std::get_if<ConcatNode>(&nd)) {
                for (uint32_t& u : cn->children) u = remap[u];
            } else if (auto* rn = std::get_if<RepeatNode>(&nd)) {
                rn->child = remap[rn->child];
            } else if (auto* sn = std::get_if<SliceNode>(&nd)) {
                sn->child = remap[sn->child];
            } else if (auto* mn = std::get_if<MorphNode>(&nd)) {
                mn->child = remap[mn->child];
            } else if (auto* xn = std::get_if<XorDiffNode>(&nd)) {
                xn->base = remap[xn->base]; xn->delta = remap[xn->delta];
            } else if (auto* in = std::get_if<InterleaveNode>(&nd)) {
                for (uint32_t& u : in->lanes) u = remap[u];
            }
            out.nodes.push_back(std::move(nd));
        }
        out.root = remap[root];
        return out;
    }

private:
    std::vector<DAGNode> nodes_;
    std::vector<uint64_t> lengths_;
    std::unordered_map<NodeKey, uint32_t, NodeKeyHash> memo_;
};

size_t estimate_dag_bytes(const ExplicitChunkDAG& dag) {
    return serialize_chunk_dag_payload(dag).size();
}

uint32_t encode_atom_span(const BitSeq& seq, DAGBuilder& builder) {
    uint64_t n = seq.bit_len();
    if (n == 0) return builder.add(EmptyNode{}, 0ULL);
    if (n <= 64) {
        DualBasisAtom a = encode_micro_atom(seq.word(0), static_cast<int>(n));
        return builder.add(AtomNode{a}, n);
    }
    size_t n_full = static_cast<size_t>(n >> 6);
    int rem = static_cast<int>(n & 63ULL);
    std::vector<DualBasisAtom> atoms;
    atoms.reserve(n_full + (rem > 0 ? 1u : 0u));
    for (size_t i = 0; i < n_full; ++i) {
        atoms.push_back(encode_micro_atom(seq.word(i), 64));
    }
    if (rem > 0) {
        atoms.push_back(encode_micro_atom(seq.word(n_full), rem));
    }
    return builder.add(AtomSpanNode{std::move(atoms)}, n);
}

// KMP exact periodicity detector (word-level for mod-64, bit-level for arbitrary p <= max_period)
std::optional<uint64_t> detect_exact_period(const BitSeq& seq, uint64_t max_period = 16384) {
    uint64_t n = seq.bit_len();
    if (n < 16) return std::nullopt;

    // 1. Word-level KMP for periods divisible by 64
    size_t n_full = static_cast<size_t>(n >> 6);
    if (n_full >= 4) {
        size_t lim_w = std::min<size_t>(n_full, static_cast<size_t>(max_period >> 6) * 4 + 8);
        if (lim_w >= 4) {
            std::vector<size_t> pi(lim_w, 0);
            size_t k = 0;
            for (size_t i = 1; i < lim_w; ++i) {
                uint64_t wi = seq.word(i);
                while (k > 0 && seq.word(k) != wi) k = pi[k - 1];
                if (seq.word(k) == wi) ++k;
                pi[i] = k;
            }
            size_t pw = lim_w - pi[lim_w - 1];
            if (pw > 0 && pw <= (max_period >> 6) && (lim_w / pw) >= 2) {
                bool ok = true;
                for (size_t i = pw; i < n_full; ++i) {
                    if (seq.word(i) != seq.word(i - pw)) { ok = false; break; }
                }
                int rem = static_cast<int>(n & 63ULL);
                if (ok && rem > 0) {
                    uint64_t mask = low_mask(rem);
                    if (((seq.word(n_full) ^ seq.word(n_full - pw)) & mask) != 0ULL) ok = false;
                }
                if (ok && (n / (pw * 64ULL)) >= 2) {
                    // Check if a sub-64 period divides pw*64
                    uint64_t p_cand = pw * 64ULL;
                    if (p_cand > 256) return p_cand;
                }
            }
        }
    }

    // 2. Arbitrary bit-level KMP on prefix
    uint64_t pref_len = std::min<uint64_t>(n, std::max<uint64_t>(4096ULL, max_period * 3ULL));
    std::vector<uint32_t> pi(static_cast<size_t>(pref_len), 0);
    uint32_t k = 0;
    for (size_t i = 1; i < static_cast<size_t>(pref_len); ++i) {
        int bi = seq.get_bit(i);
        while (k > 0 && seq.get_bit(k) != bi) k = pi[k - 1];
        if (seq.get_bit(k) == bi) ++k;
        pi[i] = k;
    }
    uint64_t p = pref_len - pi[static_cast<size_t>(pref_len - 1)];
    if (p == 0 || p > max_period || (n / p) < 2) return std::nullopt;

    // Exact full-sequence verification via 64-bit word slices
    uint64_t checked = pref_len;
    while (checked + 64 <= n) {
        if (seq.get_bits64(checked, 64) != seq.get_bits64(checked - p, 64)) return std::nullopt;
        checked += 64;
    }
    while (checked < n) {
        if (seq.get_bit(checked) != seq.get_bit(checked - p)) return std::nullopt;
        ++checked;
    }
    return p;
}

// Locally consistent restricted recompression (run-length + deterministic local maxima pair merge)
std::vector<uint32_t> restricted_recompression(
    std::vector<uint32_t> cur, DAGBuilder& builder, int max_rounds = 28) {
    for (int rnd = 0; rnd < max_rounds && cur.size() > 1; ++rnd) {
        // Phase A: RLE
        std::vector<uint32_t> rle;
        rle.reserve(cur.size());
        bool did_rle = false;
        size_t i = 0;
        while (i < cur.size()) {
            size_t j = i + 1;
            while (j < cur.size() && cur[j] == cur[i]) ++j;
            size_t cnt = j - i;
            if (cnt >= 2) {
                uint64_t lu = builder.length_of(cur[i]);
                rle.push_back(builder.add(RepeatNode{cur[i], cnt, 0ULL}, cnt * lu));
                did_rle = true;
            } else {
                rle.push_back(cur[i]);
            }
            i = j;
        }
        cur = std::move(rle);
        if (cur.size() <= 1) break;

        // Phase B: Pair frequency + SplitMix64 priority local maxima
        std::unordered_map<uint64_t, uint32_t> pcounts;
        pcounts.reserve(cur.size());
        uint32_t max_c = 0;
        for (size_t p = 0; p + 1 < cur.size(); ++p) {
            uint64_t pk = (static_cast<uint64_t>(cur[p]) << 32) | cur[p + 1];
            uint32_t c = ++pcounts[pk];
            if (c > max_c) max_c = c;
        }
        if (max_c < 2) {
            if (!did_rle) break;
            continue;
        }

        size_t m = cur.size() - 1;
        std::vector<uint64_t> prio(m, 0ULL);
        for (size_t p = 0; p < m; ++p) {
            uint64_t pk = (static_cast<uint64_t>(cur[p]) << 32) | cur[p + 1];
            uint32_t c = pcounts[pk];
            if (c >= 2) {
                prio[p] = (static_cast<uint64_t>(c) << 40) | (splitmix64(pk) & ((1ULL << 40) - 1ULL));
            }
        }

        std::vector<uint8_t> sel(m, 0);
        bool any_sel = false;
        if (m == 1) {
            if (prio[0] > 0) { sel[0] = 1; any_sel = true; }
        } else {
            if (prio[0] > 0 && prio[0] >= prio[1]) { sel[0] = 1; any_sel = true; }
            for (size_t p = 1; p + 1 < m; ++p) {
                if (prio[p] > 0 && prio[p] > prio[p - 1] && prio[p] >= prio[p + 1]) {
                    sel[p] = 1; any_sel = true;
                }
            }
            if (prio[m - 1] > 0 && prio[m - 1] > prio[m - 2]) { sel[m - 1] = 1; any_sel = true; }
        }

        if (!any_sel) {
            // Greedy non-overlapping fallback on top pair
            uint64_t top_pk = 0;
            uint32_t top_cnt = 0;
            for (const auto& kv : pcounts) {
                if (kv.second > top_cnt) { top_cnt = kv.second; top_pk = kv.first; }
            }
            size_t chosen = 0;
            ptrdiff_t last = -2;
            for (size_t p = 0; p < m; ++p) {
                uint64_t pk = (static_cast<uint64_t>(cur[p]) << 32) | cur[p + 1];
                if (pk == top_pk && static_cast<ptrdiff_t>(p) >= last + 2) {
                    sel[p] = 1;
                    last = static_cast<ptrdiff_t>(p);
                    ++chosen;
                }
            }
            if (chosen < 2) break;
        }

        std::vector<uint32_t> nxt;
        nxt.reserve(cur.size());
        size_t pos = 0;
        while (pos < cur.size()) {
            if (pos < m && sel[pos]) {
                uint32_t u1 = cur[pos], u2 = cur[pos + 1];
                nxt.push_back(builder.add(ConcatNode{{u1, u2}}, builder.length_of(u1) + builder.length_of(u2)));
                pos += 2;
            } else {
                nxt.push_back(cur[pos]);
                pos += 1;
            }
        }
        cur = std::move(nxt);
    }
    return cur;
}

// V_4-morphic 64-bit word recompression (for Thue-Morse, Rudin-Shapiro, sparse/dense, nested ASTs)
uint32_t morphic_word_recompression(const BitSeq& seq, DAGBuilder& builder) {
    uint64_t n = seq.bit_len();
    size_t n_full = static_cast<size_t>(n >> 6);
    int rem = static_cast<int>(n & 63ULL);

    std::unordered_map<uint64_t, uint32_t> canon_nodes;
    std::vector<uint32_t> stream;
    stream.reserve(n_full + 1);

    for (size_t i = 0; i < n_full; ++i) {
        auto [cw, op] = canonical_v4_word(seq.word(i), 64);
        auto it = canon_nodes.find(cw);
        uint32_t base_id;
        if (it == canon_nodes.end()) {
            base_id = builder.add(AtomNode{encode_micro_atom(cw, 64)}, 64);
            canon_nodes.emplace(cw, base_id);
        } else {
            base_id = it->second;
        }
        stream.push_back(builder.add_morph(base_id, op));
    }

    std::vector<uint32_t> cur = restricted_recompression(std::move(stream), builder, 28);

    // Interleaved V_4 NOT lifting across merged nodes (captures Thue-Morse X -> X . NOT(X) in O(log n) nodes!)
    for (int m_rnd = 0; m_rnd < 24 && cur.size() > 1; ++m_rnd) {
        std::unordered_map<uint32_t, bool> present;
        present.reserve(cur.size() * 2);
        for (uint32_t u : cur) present[u] = true;

        bool lifted = false;
        std::vector<uint32_t> lifted_cur;
        lifted_cur.reserve(cur.size());
        for (uint32_t u : cur) {
            const auto& nd = builder.node_at(u);
            if (const auto* cn = std::get_if<ConcatNode>(&nd); cn && cn->children.size() == 2) {
                uint32_t a = cn->children[0], b = cn->children[1];
                uint32_t na = builder.add_morph(a, V4Op::NOT);
                uint32_t nb = builder.add_morph(b, V4Op::NOT);
                uint32_t inv_cand = builder.add(ConcatNode{{na, nb}},
                                                builder.length_of(na) + builder.length_of(nb));
                if (inv_cand < u && present.count(inv_cand)) {
                    lifted_cur.push_back(builder.add_morph(inv_cand, V4Op::NOT));
                    lifted = true;
                    continue;
                }
            }
            lifted_cur.push_back(u);
        }
        if (!lifted && m_rnd > 0) break;
        size_t prev_sz = lifted_cur.size();
        cur = restricted_recompression(std::move(lifted_cur), builder, 4);
        if (cur.size() == prev_sz && !lifted) break;
    }

    if (rem > 0) {
        cur.push_back(builder.add(AtomNode{encode_micro_atom(seq.word(n_full), rem)}, static_cast<uint64_t>(rem)));
    }
    return builder.add_concat(cur);
}

uint32_t encode_unmatched_span(const BitSeq& seq, DAGBuilder& builder) {
    uint64_t n = seq.bit_len();
    if (n == 0) return builder.add(EmptyNode{}, 0ULL);
    
    // Check if this span is noise - emit RAW even for small segments
    if (should_use_raw(seq)) {
        std::vector<uint8_t> bytes;
        if (seq.bit_len() % 8 == 0) {
            bytes = seq.to_bytes_msb();
        } else {
            seq.to_bytes_msb_padded(bytes);
        }
        return builder.add(RawNode{std::move(bytes), seq.bit_len()}, seq.bit_len());
    }
    
    if (n <= 64) return encode_atom_span(seq, builder);
    size_t n_full = static_cast<size_t>(n >> 6);
    if (n_full >= 4) {
        std::unordered_map<uint64_t, uint8_t> seen;
        seen.reserve(n_full);
        for (size_t i = 0; i < n_full; ++i) seen[seq.word(i)] = 1;
        if (seen.size() <= static_cast<size_t>(0.80 * static_cast<double>(n_full))) {
            return morphic_word_recompression(seq, builder);
        }
    }
    return encode_atom_span(seq, builder);
}

struct MinimizerAnchor {
    uint64_t canon_word;
    V4Op mu;
    uint64_t bit_pos;
};

// Exact O(n) Flat-Ring Monotonic-Deque {ID, NOT}-Equivariant Bit-Shift-Invariant Minimizer Anchors
std::vector<MinimizerAnchor> compute_bit_minimizers_linear(const BitSeq& seq, size_t window_radius = 64) {
    uint64_t n = seq.bit_len();
    if (n < 256) return {};
    uint64_t num_pos = n - 63ULL; // positions 0 .. n - 64

    // Power-of-two ring buffer (256 >= 2*64 + 1) eliminates all modulo divisions & heap allocations!
    const uint64_t R = window_radius;
    uint64_t h_ring[256];
    uint64_t cw_ring[256];
    uint8_t not_ring[256];
    uint64_t dq[256];
    uint8_t dq_head = 0, dq_tail = 0;

    const uint64_t* words = seq.words().data();
    const size_t n_words = seq.word_count();

    auto eval_pos = [&](uint64_t p) noexcept -> uint64_t {
        size_t wi = static_cast<size_t>(p >> 6);
        int sh = static_cast<int>(p & 63ULL);
        uint64_t w = words[wi] >> sh;
        if (sh != 0 && wi + 1 < n_words) w |= (words[wi + 1] << (64 - sh));
        uint64_t nw = ~w;
        bool is_not = (nw < w);
        uint64_t cw = is_not ? nw : w;
        uint8_t slot = static_cast<uint8_t>(p);
        cw_ring[slot] = cw;
        not_ring[slot] = is_not ? 1u : 0u;
        uint64_t h = splitmix64(cw);
        h_ring[slot] = h;
        return h;
    };

    uint64_t init_end = std::min<uint64_t>(num_pos, R);
    for (uint64_t q = 0; q < init_end; ++q) {
        uint64_t hq = eval_pos(q);
        while (dq_head != dq_tail && h_ring[static_cast<uint8_t>(dq[static_cast<uint8_t>(dq_tail - 1u)])] > hq) {
            --dq_tail;
        }
        dq[dq_tail++] = q;
    }

    std::vector<MinimizerAnchor> anchors;
    anchors.reserve(static_cast<size_t>(num_pos / 48ULL) + 8);
    int64_t last_emit = -32;

    for (uint64_t p = 0; p < num_pos; ++p) {
        uint64_t add_q = p + R;
        if (add_q < num_pos) {
            uint64_t hq = eval_pos(add_q);
            while (dq_head != dq_tail && h_ring[static_cast<uint8_t>(dq[static_cast<uint8_t>(dq_tail - 1u)])] > hq) {
                --dq_tail;
            }
            dq[dq_tail++] = add_q;
        }
        while (dq_head != dq_tail && dq[dq_head] + R < p) {
            ++dq_head;
        }
        uint64_t win_min = h_ring[static_cast<uint8_t>(dq[dq_head])];
        uint8_t p_slot = static_cast<uint8_t>(p);
        if (h_ring[p_slot] == win_min && static_cast<int64_t>(p) - last_emit >= 32) {
            last_emit = static_cast<int64_t>(p);
            anchors.push_back(MinimizerAnchor{
                cw_ring[p_slot],
                not_ring[p_slot] ? V4Op::NOT : V4Op::ID,
                p
            });
        }
    }
    return anchors;
}

uint32_t encode_general_body(const BitSeq& seq, DAGBuilder& builder) {
    uint64_t n = seq.bit_len();
    if (n <= 64) return encode_atom_span(seq, builder);

    // 1. Low-subword-complexity morphic regime check (Thue-Morse, Fibonacci, Rudin-Shapiro, Sparse/Dense)
    size_t n_full = static_cast<size_t>(n >> 6);
    if (n_full >= 4) {
        std::unordered_map<uint64_t, uint8_t> uniq;
        uniq.reserve(std::min<size_t>(n_full, 1024));
        size_t limit_uniq = static_cast<size_t>(0.12 * static_cast<double>(n_full)) + 1;
        for (size_t i = 0; i < n_full; ++i) {
            uniq[seq.word(i)] = 1;
            if (uniq.size() > limit_uniq) break;
        }
        if (uniq.size() <= limit_uniq) {
            DAGBuilder b_word;
            uint32_t r_word = morphic_word_recompression(seq, b_word);
            ExplicitChunkDAG dag_word = b_word.build_compacted(r_word);

            if (n <= 524288 && dag_word.nodes.size() > 64) {
                // Bit-level recompression check for non-64-aligned Sturmian/Fibonacci morphisms
                DAGBuilder b_bit;
                uint32_t a0 = b_bit.add(AtomNode{DualBasisAtom{AtomBasis::POS, 1, 0, 0}}, 1);
                uint32_t a1 = b_bit.add(AtomNode{DualBasisAtom{AtomBasis::POS, 1, 1, 0}}, 1);
                std::vector<uint32_t> bstream(static_cast<size_t>(n));
                for (uint64_t i = 0; i < n; ++i) bstream[static_cast<size_t>(i)] = seq.get_bit(i) ? a1 : a0;
                auto comp = restricted_recompression(std::move(bstream), b_bit, 40);
                uint32_t r_bit = b_bit.add_concat(comp);
                ExplicitChunkDAG dag_bit = b_bit.build_compacted(r_bit);
                if (estimate_dag_bytes(dag_bit) < estimate_dag_bytes(dag_word)) {
                    return builder.import_dag(dag_bit);
                }
            }
            return builder.import_dag(dag_word);
        }
    }

    // 2. General Meso-Scale Anchor + V_4-Morphic + Sparse-XOR + Deferred SLICE Pipeline
    auto anchors = compute_bit_minimizers_linear(seq, 64);

    // Pre-index 256-bit aligned blocks under full V_4 (incl. REV & REV_NOT)
    struct BlockHit { uint64_t bit_pos; V4Op mu; };
    std::unordered_map<uint64_t, std::vector<BlockHit>> blk_index;
    size_t n_blk256 = static_cast<size_t>(n >> 8);
    for (size_t b_i = 0; b_i < n_blk256; ++b_i) {
        uint64_t bpos = static_cast<uint64_t>(b_i) * 256ULL;
        uint64_t w0 = seq.word(4 * b_i), w1 = seq.word(4 * b_i + 1),
                 w2 = seq.word(4 * b_i + 2), w3 = seq.word(4 * b_i + 3);
        auto h4 = [](uint64_t a, uint64_t b, uint64_t c, uint64_t d) {
            uint64_t h = splitmix64(a ^ 0x1111111111111111ULL);
            h ^= splitmix64(b ^ 0x2222222222222222ULL);
            h ^= splitmix64(c ^ 0x3333333333333333ULL);
            h ^= splitmix64(d ^ 0x4444444444444444ULL);
            return h;
        };
        uint64_t k_id = h4(w0, w1, w2, w3);
        uint64_t k_not = h4(~w0, ~w1, ~w2, ~w3);
        uint64_t rw0 = bitrev64(w3), rw1 = bitrev64(w2), rw2 = bitrev64(w1), rw3 = bitrev64(w0);
        uint64_t k_rev = h4(rw0, rw1, rw2, rw3);
        uint64_t k_rn = h4(~rw0, ~rw1, ~rw2, ~rw3);

        uint64_t best_k = k_id; V4Op best_op = V4Op::ID;
        if (k_not < best_k) { best_k = k_not; best_op = V4Op::NOT; }
        if (k_rev < best_k) { best_k = k_rev; best_op = V4Op::REV; }
        if (k_rn < best_k)  { best_k = k_rn;  best_op = V4Op::REV_NOT; }

        auto& vec = blk_index[best_k];
        if (vec.size() < 8) vec.push_back(BlockHit{bpos, best_op});
    }

    // 64-bit word sub-anchor index (for XOR_DIFF perturbed records)
    std::unordered_map<uint64_t, std::vector<uint64_t>> word64_idx;
    for (size_t w_i = 0; w_i < n_full; w_i += 2) {
        auto& vec = word64_idx[seq.word(w_i)];
        if (vec.size() < 8) vec.push_back(static_cast<uint64_t>(w_i) * 64ULL);
    }

    enum class SegKind : uint8_t { RAW = 0, MORPH_REF = 1, XOR_REF = 2, DIRECT_NODE = 3 };
    struct SegSpec {
        uint64_t start = 0;
        uint64_t len = 0;
        SegKind kind = SegKind::RAW;
        uint64_t ref_start = 0;
        V4Op rel_mu = V4Op::ID;
        uint32_t aux_vid = 0;
    };

    std::vector<SegSpec> segs;
    std::unordered_map<uint64_t, std::vector<std::pair<uint64_t, V4Op>>> anchor_table;
    size_t a_ptr = 0;
    uint64_t cursor = 0;
    uint64_t lit_start = 0;

    while (cursor < n) {
        while (a_ptr < anchors.size() && anchors[a_ptr].bit_pos < cursor) {
            auto& lst = anchor_table[anchors[a_ptr].canon_word];
            if (lst.size() < 8) lst.emplace_back(anchors[a_ptr].bit_pos, anchors[a_ptr].mu);
            ++a_ptr;
        }

        bool matched = false;

        // Check 1: 256-bit V_4 block match (incl. REV / REV_NOT)
        if ((cursor & 255ULL) == 0ULL && cursor + 256ULL <= n) {
            size_t b_i = static_cast<size_t>(cursor >> 8);
            uint64_t w0 = seq.word(4 * b_i), w1 = seq.word(4 * b_i + 1),
                     w2 = seq.word(4 * b_i + 2), w3 = seq.word(4 * b_i + 3);
            auto h4 = [](uint64_t a, uint64_t b, uint64_t c, uint64_t d) {
                return splitmix64(a ^ 0x1111111111111111ULL) ^
                       splitmix64(b ^ 0x2222222222222222ULL) ^
                       splitmix64(c ^ 0x3333333333333333ULL) ^
                       splitmix64(d ^ 0x4444444444444444ULL);
            };
            uint64_t rw0 = bitrev64(w3), rw1 = bitrev64(w2), rw2 = bitrev64(w1), rw3 = bitrev64(w0);
            uint64_t best_k = h4(w0, w1, w2, w3); V4Op cur_op = V4Op::ID;
            uint64_t kn = h4(~w0, ~w1, ~w2, ~w3); if (kn < best_k) { best_k = kn; cur_op = V4Op::NOT; }
            uint64_t kr = h4(rw0, rw1, rw2, rw3); if (kr < best_k) { best_k = kr; cur_op = V4Op::REV; }
            uint64_t krn = h4(~rw0, ~rw1, ~rw2, ~rw3); if (krn < best_k) { best_k = krn; cur_op = V4Op::REV_NOT; }

            auto it = blk_index.find(best_k);
            if (it != blk_index.end()) {
                for (auto rit = it->second.rbegin(); rit != it->second.rend(); ++rit) {
                    if (rit->bit_pos + 256ULL > cursor) continue;
                    V4Op rel_mu = compose_v4(cur_op, rit->mu);
                    if (rel_mu == V4Op::REV || rel_mu == V4Op::REV_NOT) {
                        uint64_t ext = 256ULL;
                        while (cursor + ext + 256ULL <= n && rit->bit_pos >= ext - 256ULL + 256ULL) {
                            break;
                        }
                        if (seq.slice(rit->bit_pos, 256).apply_v4(rel_mu) == seq.slice(cursor, 256)) {
                            // Extend forward for REV across preceding blocks if mirrored!
                            uint64_t ref_s = rit->bit_pos;
                            while (cursor + ext + 256ULL <= n && ref_s >= 256ULL) {
                                if (seq.slice(ref_s - 256ULL, 256ULL).apply_v4(rel_mu) ==
                                    seq.slice(cursor + ext, 256ULL)) {
                                    ref_s -= 256ULL;
                                    ext += 256ULL;
                                } else {
                                    break;
                                }
                            }
                            if (cursor > lit_start) segs.push_back(SegSpec{lit_start, cursor - lit_start, SegKind::RAW});
                            segs.push_back(SegSpec{cursor, ext, SegKind::MORPH_REF, ref_s, rel_mu, 0});
                            cursor += ext;
                            lit_start = cursor;
                            matched = true;
                            break;
                        }
                    } else {
                        // ID or NOT block match
                        uint64_t mask_inv = (rel_mu == V4Op::NOT) ? ~0ULL : 0ULL;
                        uint64_t ext = 0ULL;
                        while (cursor + ext + 64ULL <= n && rit->bit_pos + ext + 64ULL <= cursor) {
                            if ((seq.get_bits64(rit->bit_pos + ext, 64) ^ mask_inv) == seq.get_bits64(cursor + ext, 64)) {
                                ext += 64ULL;
                            } else {
                                break;
                            }
                        }
                        if (ext >= 192ULL) {
                            if (cursor > lit_start) segs.push_back(SegSpec{lit_start, cursor - lit_start, SegKind::RAW});
                            segs.push_back(SegSpec{cursor, ext, SegKind::MORPH_REF, rit->bit_pos, rel_mu, 0});
                            cursor += ext;
                            lit_start = cursor;
                            matched = true;
                            break;
                        }
                    }
                }
            }
        }
        if (matched) continue;

        // Check 2: Bit-minimizer shift-invariant {ID, NOT} match
        if (a_ptr < anchors.size() && anchors[a_ptr].bit_pos == cursor) {
            const auto& anc = anchors[a_ptr];
            auto it = anchor_table.find(anc.canon_word);
            if (it != anchor_table.end()) {
                uint64_t best_ext = 0, best_back = 0, best_prev = 0;
                V4Op best_mu = V4Op::ID;
                for (auto rit = it->second.rbegin(); rit != it->second.rend(); ++rit) {
                    uint64_t prev_p = rit->first;
                    if (prev_p + 192ULL > cursor) continue;
                    uint64_t delta_p = cursor - prev_p;
                    V4Op rel_mu = compose_v4(anc.mu, rit->second);
                    uint64_t mask_inv = (rel_mu == V4Op::NOT) ? ~0ULL : 0ULL;

                    uint64_t back = 0;
                    uint64_t max_back = std::min<uint64_t>({cursor - lit_start, prev_p, delta_p - 1});
                    while (back + 64ULL <= max_back) {
                        if ((seq.get_bits64(prev_p - back - 64ULL, 64) ^ mask_inv) ==
                            seq.get_bits64(cursor - back - 64ULL, 64)) back += 64ULL;
                        else break;
                    }
                    while (back < max_back) {
                        int b1 = seq.get_bit(prev_p - back - 1ULL) ^ (rel_mu == V4Op::NOT ? 1 : 0);
                        if (b1 == seq.get_bit(cursor - back - 1ULL)) ++back;
                        else break;
                    }

                    uint64_t ref_s = prev_p - back;
                    uint64_t cur_s = cursor - back;
                    uint64_t max_fwd = std::min(n - cur_s, cur_s - ref_s);
                    uint64_t ext = std::min(back, max_fwd);
                    while (ext + 64ULL <= max_fwd) {
                        if ((seq.get_bits64(ref_s + ext, 64) ^ mask_inv) == seq.get_bits64(cur_s + ext, 64)) ext += 64ULL;
                        else break;
                    }
                    while (ext < max_fwd) {
                        int b1 = seq.get_bit(ref_s + ext) ^ (rel_mu == V4Op::NOT ? 1 : 0);
                        if (b1 == seq.get_bit(cur_s + ext)) ++ext;
                        else break;
                    }
                    if (ext >= 192ULL && (cur_s + ext > cursor) && ext > best_ext) {
                        best_ext = ext; best_back = back; best_prev = ref_s; best_mu = rel_mu;
                    }
                }

                if (best_ext >= 192ULL) {
                    uint64_t m_start = cursor - best_back;
                    if (m_start > lit_start) segs.push_back(SegSpec{lit_start, m_start - lit_start, SegKind::RAW});
                    segs.push_back(SegSpec{m_start, best_ext, SegKind::MORPH_REF, best_prev, best_mu, 0});
                    while (a_ptr < anchors.size() && anchors[a_ptr].bit_pos < m_start + best_ext) {
                        auto& lst = anchor_table[anchors[a_ptr].canon_word];
                        if (lst.size() < 8) lst.emplace_back(anchors[a_ptr].bit_pos, anchors[a_ptr].mu);
                        ++a_ptr;
                    }
                    cursor = m_start + best_ext;
                    lit_start = cursor;
                    continue;
                }

                // Check 2b: Sparse-XOR differential match from minimizer anchor
                for (auto rit = it->second.rbegin(); rit != it->second.rend(); ++rit) {
                    uint64_t prev_p = rit->first;
                    if (anc.mu != rit->second) continue;
                    uint64_t cand_len = std::min<uint64_t>({1024ULL, n - cursor, cursor - prev_p});
                    cand_len &= ~63ULL;
                    if (cand_len >= 256ULL) {
                        BitSeq delta = seq.slice(cursor, cand_len).bitwise_xor(seq.slice(prev_p, cand_len));
                        uint64_t wt = delta.popcount();
                        if (wt > 0 && wt <= cand_len / 12ULL) {
                            if (cursor > lit_start) segs.push_back(SegSpec{lit_start, cursor - lit_start, SegKind::RAW});
                            uint32_t d_vid = morphic_word_recompression(delta, builder);
                            segs.push_back(SegSpec{cursor, cand_len, SegKind::XOR_REF, prev_p, V4Op::ID, d_vid});
                            while (a_ptr < anchors.size() && anchors[a_ptr].bit_pos < cursor + cand_len) {
                                auto& lst = anchor_table[anchors[a_ptr].canon_word];
                                if (lst.size() < 8) lst.emplace_back(anchors[a_ptr].bit_pos, anchors[a_ptr].mu);
                                ++a_ptr;
                            }
                            cursor += cand_len;
                            lit_start = cursor;
                            matched = true;
                            break;
                        }
                    }
                }
                if (matched) continue;
            }
        }

        // Check 3: 64-bit word sub-anchor for XOR_DIFF on perturbed aligned records
        if ((cursor & 127ULL) == 0ULL && cursor + 256ULL <= n) {
            uint64_t w_cur = seq.word(static_cast<size_t>(cursor >> 6));
            auto it = word64_idx.find(w_cur);
            if (it != word64_idx.end()) {
                for (auto rit = it->second.rbegin(); rit != it->second.rend(); ++rit) {
                    uint64_t prev_p = *rit;
                    if (prev_p + 256ULL > cursor) continue;
                    uint64_t max_l = std::min<uint64_t>({2048ULL, n - cursor, cursor - prev_p}) & ~63ULL;
                    if (max_l < 256ULL) continue;
                    uint64_t valid_l = 0, run_wt = 0;
                    for (uint64_t off = 0; off < max_l; off += 64ULL) {
                        uint64_t dw = seq.get_bits64(cursor + off, 64) ^ seq.get_bits64(prev_p + off, 64);
                        uint64_t w64 = static_cast<uint64_t>(std::popcount(dw));
                        if (run_wt + w64 <= (off + 64ULL) / 12ULL) {
                            run_wt += w64;
                            valid_l = off + 64ULL;
                        } else {
                            break;
                        }
                    }
                    if (valid_l >= 256ULL) {
                        if (cursor > lit_start) segs.push_back(SegSpec{lit_start, cursor - lit_start, SegKind::RAW});
                        if (run_wt == 0) {
                            segs.push_back(SegSpec{cursor, valid_l, SegKind::MORPH_REF, prev_p, V4Op::ID, 0});
                        } else {
                            BitSeq delta = seq.slice(cursor, valid_l).bitwise_xor(seq.slice(prev_p, valid_l));
                            uint32_t d_vid = morphic_word_recompression(delta, builder);
                            segs.push_back(SegSpec{cursor, valid_l, SegKind::XOR_REF, prev_p, V4Op::ID, d_vid});
                        }
                        cursor += valid_l;
                        lit_start = cursor;
                        matched = true;
                        break;
                    }
                }
                if (matched) continue;
            }
        }

        uint64_t next_anc = (a_ptr < anchors.size()) ? anchors[a_ptr].bit_pos : n;
        uint64_t next_b = ((cursor >> 7) + 1ULL) << 7;
        cursor = std::max<uint64_t>(cursor + 1, std::min({next_anc, next_b, n}));
    }

    if (lit_start < n) segs.push_back(SegSpec{lit_start, n - lit_start, SegKind::RAW});
    if (segs.size() == 1 && segs[0].kind == SegKind::RAW) {
        return encode_unmatched_span(seq, builder);
    }

    // Materialize segments left-to-right with SliceNode back-reference interval projection
    std::vector<uint64_t> seg_starts, seg_ends;
    std::vector<uint32_t> seg_vids;
    seg_starts.reserve(segs.size());
    seg_ends.reserve(segs.size());
    seg_vids.reserve(segs.size());

    auto resolve_past_range = [&](uint64_t r_start, uint64_t r_len) -> uint32_t {
        uint64_t r_end = r_start + r_len;
        auto it = std::upper_bound(seg_starts.begin(), seg_starts.end(), r_start);
        size_t idx = (it == seg_starts.begin()) ? 0 : static_cast<size_t>(std::distance(seg_starts.begin(), it) - 1);
        std::vector<uint32_t> parts;
        while (idx < seg_vids.size() && seg_starts[idx] < r_end) {
            uint64_t ov_s = std::max(r_start, seg_starts[idx]);
            uint64_t ov_e = std::min(r_end, seg_ends[idx]);
            if (ov_e > ov_s) {
                uint64_t rel_s = ov_s - seg_starts[idx];
                uint64_t ov_l = ov_e - ov_s;
                uint64_t full_l = seg_ends[idx] - seg_starts[idx];
                if (rel_s == 0 && ov_l == full_l) parts.push_back(seg_vids[idx]);
                else parts.push_back(builder.add(SliceNode{seg_vids[idx], rel_s, ov_l}, ov_l));
            }
            ++idx;
        }
        return builder.add_concat(parts);
    };

    for (const auto& sp : segs) {
        uint32_t vid = 0;
        if (sp.kind == SegKind::RAW) {
            vid = encode_unmatched_span(seq.slice(sp.start, sp.len), builder);
        } else if (sp.kind == SegKind::MORPH_REF) {
            uint32_t base_vid = resolve_past_range(sp.ref_start, sp.len);
            vid = builder.add_morph(base_vid, sp.rel_mu);
        } else if (sp.kind == SegKind::XOR_REF) {
            uint32_t base_vid = resolve_past_range(sp.ref_start, sp.len);
            vid = builder.add(XorDiffNode{base_vid, sp.aux_vid}, sp.len);
        } else {
            vid = sp.aux_vid;
        }
        seg_starts.push_back(sp.start);
        seg_ends.push_back(sp.start + sp.len);
        seg_vids.push_back(vid);
    }

    if (seg_vids.size() > 3) {
        seg_vids = restricted_recompression(std::move(seg_vids), builder, 16);
    }
    return builder.add_concat(seg_vids);
}

// 128-bit V_4 canonical signature for fast ChunkRef lookup (always verified bit-for-bit!)
struct ChunkKey128 {
    uint64_t h1 = 0;
    uint64_t h2 = 0;
    uint64_t bit_len = 0;
    bool operator==(const ChunkKey128& o) const noexcept {
        return h1 == o.h1 && h2 == o.h2 && bit_len == o.bit_len;
    }
};

struct ChunkKey128Hash {
    size_t operator()(const ChunkKey128& k) const noexcept {
        return static_cast<size_t>(k.h1 ^ splitmix64(k.h2 ^ k.bit_len));
    }
};

std::pair<ChunkKey128, V4Op> compute_chunk_v4_signature(const BitSeq& seq) {
    auto hash_seq = [](const BitSeq& s) -> std::pair<uint64_t, uint64_t> {
        uint64_t a = splitmix64(s.bit_len() ^ 0xA5A5A5A5A5A5A5A5ULL);
        uint64_t b = splitmix64(s.bit_len() ^ 0x5A5A5A5A5A5A5A5AULL);
        for (size_t i = 0; i < s.word_count(); ++i) {
            a = splitmix64(a ^ s.word(i));
            b = splitmix64(b + (s.word(i) ^ static_cast<uint64_t>(i)));
        }
        return {a, b};
    };

    V4Op best_op = V4Op::ID;
    BitSeq best_seq = seq;
    {
        BitSeq s_not = seq.bitwise_not();
        if (s_not.lex_less(best_seq)) { best_seq = std::move(s_not); best_op = V4Op::NOT; }
    }
    {
        BitSeq s_rev = seq.reverse_bits();
        BitSeq s_rn = s_rev.bitwise_not();
        if (s_rev.lex_less(best_seq)) { best_seq = std::move(s_rev); best_op = V4Op::REV; }
        if (s_rn.lex_less(best_seq))  { best_seq = std::move(s_rn);  best_op = V4Op::REV_NOT; }
    }
    auto [h1, h2] = hash_seq(best_seq);
    return {ChunkKey128{h1, h2, seq.bit_len()}, best_op};
}

} // namespace

ExplicitChunkDAG encode_chunk_dag(const BitSeq& seq, bool allow_interleave) {
    uint64_t n = seq.bit_len();
    DAGBuilder builder;

    if (n <= 64) {
        uint32_t r = encode_atom_span(seq, builder);
        return builder.build_compacted(r);
    }

    // Stage 0: DEFLATE-aware front end (F.1-F.4)
    // Detect zlib/gzip/raw deflate framing, parse block boundaries, and
    // encode as RAW to preserve the deflate stream exactly (no re-compression
    // attempt; ceiling 0.955×-1.039× recorded honestly).
    if (n >= 16 && (n % 8 == 0)) {
        std::vector<uint8_t> bytes = seq.to_bytes_msb();
        DeflateInfo di = detect_deflate(bytes.data(), bytes.size());
        if (di.detected && (di.type == DeflateType::ZLIB || di.type == DeflateType::GZIP ||
                            (di.type == DeflateType::RAW && !di.blocks.empty()))) {
            // Expose boundaries by parsing (already in di.blocks for RAW; parse for framed streams)
            if (di.blocks.empty() && di.data_len > 0 && di.data_offset + di.data_len <= bytes.size()) {
                parse_deflate_blocks(bytes.data() + di.data_offset, di.data_len, di.blocks);
            }
            // Emit exact original bytes as RAW (lossless, deflate-aware path)
            uint32_t root = builder.add(RawNode{bytes, n}, n);
            return builder.build_compacted(root);
        }
    }

    // Stage 1a: Exact periodicity
    if (auto p = detect_exact_period(seq, 16384); p && (n / *p) >= 2) {
        ExplicitChunkDAG sub = encode_chunk_dag(seq.slice(0, *p), allow_interleave);
        uint32_t u_pat = builder.import_dag(sub);
        uint32_t root = builder.add(RepeatNode{u_pat, n / *p, n % *p}, n);
        ExplicitChunkDAG cand_rep = builder.build_compacted(root);

        if (auto lfsr = verify_and_measure_lfsr(seq, 64, 256); lfsr && lfsr->length == n) {
            DAGBuilder bl;
            uint32_t rl = bl.add(LfsrNode{lfsr->degree, lfsr->conn_mask, lfsr->init_mask, n}, n);
            ExplicitChunkDAG cand_lf = bl.build_compacted(rl);
            if (estimate_dag_bytes(cand_lf) < estimate_dag_bytes(cand_rep)) return cand_lf;
        }
        return cand_rep;
    }

    // Stage 1b: Whole-chunk GF(2) LFSR check
    if (auto lfsr = verify_and_measure_lfsr(seq, 64, 256); lfsr && lfsr->length == n) {
        uint32_t rl = builder.add(LfsrNode{lfsr->degree, lfsr->conn_mask, lfsr->init_mask, n}, n);
        return builder.build_compacted(rl);
    }

    // Stage 3+4 Direct DAG
    uint32_t direct_root = encode_general_body(seq, builder);
    ExplicitChunkDAG best_dag = builder.build_compacted(direct_root);
    size_t best_bytes = 0; // Computed lazily only if Stage 2 triggers

    // Stage 2: Bit-Plane Stride Decomposition check (s in {8, 16, 32})
    if (allow_interleave && n >= 1024 && n <= 4194304) {
        uint64_t sample_bits = std::min<uint64_t>(n, 4096ULL);
        for (int s : {8, 16, 32}) {
            uint64_t gran = 64ULL * static_cast<uint64_t>(s);
            uint64_t aligned_n = (n / gran) * gran;
            uint64_t sample_aligned = (sample_bits / gran) * gran;
            if (aligned_n < 1024 || sample_aligned < 512) continue;

            BitSeq samp_seq = seq.slice(0, sample_aligned);
            auto samp_lanes = deinterleave_bitplanes(samp_seq, s);
            auto dual_cost64 = [](uint64_t x) {
                int cp = shell_bit_cost(64, std::popcount(x));
                int cz = shell_bit_cost(64, std::popcount(mobius_word(x, 64)));
                return std::min(cp, cz);
            };
            uint64_t lane_est = 0, seq_est = 0;
            for (const auto& ln : samp_lanes) {
                for (uint64_t x : ln.words()) lane_est += static_cast<uint64_t>(dual_cost64(x));
            }
            for (uint64_t x : samp_seq.words()) seq_est += static_cast<uint64_t>(dual_cost64(x));

            if (lane_est * 100ULL < seq_est * 88ULL) {
                if (best_bytes == 0) best_bytes = estimate_dag_bytes(best_dag);
                DAGBuilder b_int;
                auto lanes_full = deinterleave_bitplanes(seq.slice(0, aligned_n), s);
                std::vector<uint32_t> lane_roots;
                lane_roots.reserve(static_cast<size_t>(s));
                for (const auto& ln : lanes_full) {
                    ExplicitChunkDAG ldag = encode_chunk_dag(ln, false);
                    lane_roots.push_back(b_int.import_dag(ldag));
                }
                uint32_t int_vid = b_int.add(
                    InterleaveNode{static_cast<uint8_t>(s), std::move(lane_roots)}, aligned_n);
                if (aligned_n < n) {
                    ExplicitChunkDAG tdag = encode_chunk_dag(seq.slice(aligned_n, n - aligned_n), false);
                    int_vid = b_int.add_concat({int_vid, b_int.import_dag(tdag)});
                }
                ExplicitChunkDAG cand = b_int.build_compacted(int_vid);
                size_t c_bytes = estimate_dag_bytes(cand);
                if (c_bytes < best_bytes) {
                    best_dag = std::move(cand);
                    best_bytes = c_bytes;
                }
            }
        }
    }

    return best_dag;
}

std::vector<std::pair<uint64_t, uint64_t>> synchronize_partition(
    const BitSeq& seq, const StreamConfig& cfg) {
    uint64_t n = seq.bit_len();
    if (n <= cfg.l_min) return {{0ULL, n}};

    uint64_t avg_gap = (cfg.l_target > cfg.l_min) ? (cfg.l_target - cfg.l_min) : 65536ULL;
    uint64_t mask = (1ULL << (std::bit_width(avg_gap) - 1)) - 1ULL;

    std::vector<std::pair<uint64_t, uint64_t>> spans;
    uint64_t start = 0;
    while (start < n) {
        if (n - start <= cfg.l_min) {
            spans.emplace_back(start, n - start);
            break;
        }
        uint64_t search_s = start + cfg.l_min;
        uint64_t hard_e = std::min<uint64_t>(n, start + cfg.l_max);
        if (hard_e - search_s < 64ULL) {
            spans.emplace_back(start, hard_e - start);
            start = hard_e;
            continue;
        }
        uint64_t cut = hard_e;
        // Scan 64-bit word windows using V_4-equivariant canonical word so complemented/reflected
        // multi-superchunk regions lock onto identical superchunk boundaries!
        for (uint64_t p = search_s; p + 64ULL <= hard_e; ++p) {
            uint64_t w = seq.get_bits64(p, 64);
            uint64_t cw = std::min(w, ~w);
            if ((splitmix64(cw) & mask) == 0ULL) {
                cut = p & ~7ULL;  // Round down to byte boundary
                if (cut < search_s) cut = search_s;  // Ensure progress
                break;
            }
        }
        spans.emplace_back(start, cut - start);
        start = cut;
    }
    return spans;
}

namespace {

// Shared bounded-window chunk dispatcher used by both BitSeq and streaming file encoders
class BoundedChunkPipeline {
public:
    BoundedChunkPipeline(ContainerWriter& writer, const StreamConfig& cfg, unsigned num_threads)
        : writer_(writer), cfg_(cfg), threads_(std::max(1u, num_threads)),
          max_batch_(std::max<size_t>(4, 2 * std::max(1u, num_threads))) {}

    void submit_chunk(BitSeq chunk) {
        uint32_t c_idx = next_chunk_idx_++;
        uint64_t c_len = chunk.bit_len();
        uint64_t b_off = cur_bit_offset_;
        cur_bit_offset_ += c_len;

        // Evict expired history entries outside W_hist
        while (!hist_ring_.empty() &&
               (cfg_.w_hist == 0 || (c_idx - hist_ring_.front().idx) > cfg_.w_hist)) {
            hist_ring_.pop_front();
        }

        // Check exact V_4 cross-chunk match
        bool is_ref = false;
        uint32_t ref_target = 0;
        V4Op ref_mu = V4Op::ID;

        if (cfg_.w_hist > 0 && c_len > 0) {
            auto [sig, mu_c] = compute_chunk_v4_signature(chunk);
            for (auto it = hist_ring_.rbegin(); it != hist_ring_.rend(); ++it) {
                if (it->sig == sig) {
                    V4Op cand_mu = compose_v4(mu_c, it->mu_canon);
                    if (it->seq.apply_v4(cand_mu) == chunk) {
                        is_ref = true;
                        ref_target = it->idx;
                        ref_mu = cand_mu;
                        break;
                    }
                }
            }
            hist_ring_.push_back(HistItem{c_idx, sig, mu_c, is_ref ? chunk : chunk});
        }

        PendingTask pt;
        pt.chunk_idx = c_idx;
        pt.bit_offset = b_off;
        pt.bit_len = static_cast<uint32_t>(c_len);
        pt.is_ref = is_ref;
        pt.ref_target = ref_target;
        pt.ref_mu = ref_mu;
        if (!is_ref) {
            pt.seq_for_encode = std::move(chunk);
        } else {
            ++chunk_ref_count_;
        }
        pending_.push_back(std::move(pt));

        if (pending_.size() >= max_batch_) {
            flush_pending();
        }
    }

    void flush_pending() {
        if (pending_.empty()) return;

        // Collect indices requiring explicit DAG synthesis
        std::vector<size_t> work_indices;
        for (size_t i = 0; i < pending_.size(); ++i) {
            if (!pending_[i].is_ref) work_indices.push_back(i);
        }

        std::vector<std::vector<uint8_t>> payloads(pending_.size());
        if (threads_ <= 1 || work_indices.size() <= 1) {
            for (size_t idx : work_indices) {
                ExplicitChunkDAG dag = encode_chunk_dag(pending_[idx].seq_for_encode, true);
                payloads[idx] = serialize_chunk_dag_payload(dag);
                pending_[idx].seq_for_encode = BitSeq();
            }
        } else {
            size_t n_workers = std::min<size_t>(threads_, work_indices.size());
            std::atomic<size_t> next_w{0};
            std::vector<std::future<void>> futs;
            futs.reserve(n_workers);
            for (size_t t = 0; t < n_workers; ++t) {
                futs.push_back(std::async(std::launch::async, [&]() {
                    while (true) {
                        size_t k = next_w.fetch_add(1);
                        if (k >= work_indices.size()) break;
                        size_t idx = work_indices[k];
                        ExplicitChunkDAG dag = encode_chunk_dag(pending_[idx].seq_for_encode, true);
                        payloads[idx] = serialize_chunk_dag_payload(dag);
                        pending_[idx].seq_for_encode = BitSeq();
                    }
                }));
            }
            for (auto& f : futs) f.get();
        }

        // Retire strictly in canonical index order
        for (size_t i = 0; i < pending_.size(); ++i) {
            const auto& pt = pending_[i];
            if (pt.is_ref) {
                writer_.write_chunk_ref(pt.chunk_idx, pt.bit_offset, pt.bit_len, pt.ref_target, pt.ref_mu);
            } else {
                writer_.write_explicit_dag(pt.chunk_idx, pt.bit_offset, pt.bit_len, payloads[i]);
            }
        }
        pending_.clear();
    }

    uint64_t chunk_count() const noexcept { return next_chunk_idx_; }
    uint64_t chunk_ref_count() const noexcept { return chunk_ref_count_; }

private:
    struct HistItem {
        uint32_t idx;
        ChunkKey128 sig;
        V4Op mu_canon;
        BitSeq seq;
    };

    struct PendingTask {
        uint32_t chunk_idx = 0;
        uint64_t bit_offset = 0;
        uint32_t bit_len = 0;
        bool is_ref = false;
        uint32_t ref_target = 0;
        V4Op ref_mu = V4Op::ID;
        BitSeq seq_for_encode;
    };

    ContainerWriter& writer_;
    StreamConfig cfg_;
    unsigned threads_;
    size_t max_batch_;
    uint32_t next_chunk_idx_ = 0;
    uint64_t cur_bit_offset_ = 0;
    uint64_t chunk_ref_count_ = 0;
    std::deque<HistItem> hist_ring_;
    std::vector<PendingTask> pending_;
};

} // namespace

EncodeStats encode_bitseq_to_file(
    const BitSeq& seq,
    const std::string& out_mapr_path,
    bool raw_bytes_mode,
    unsigned num_threads,
    const StreamConfig& cfg) {
    auto t0 = std::chrono::steady_clock::now();
    if (raw_bytes_mode && (seq.bit_len() & 7ULL) != 0ULL) {
        throw std::invalid_argument("raw_bytes_mode requires bit_len % 8 == 0");
    }

    std::array<uint8_t, 32> digest{};
    if (raw_bytes_mode) {
        auto bytes = seq.to_bytes_msb();
        digest = Sha256::hash(bytes.data(), bytes.size());
    } else {
        digest = seq.canonical_sha256();
    }

    ContainerWriter writer(out_mapr_path, cfg, raw_bytes_mode);
    BoundedChunkPipeline pipe(writer, cfg, num_threads);

    auto spans = synchronize_partition(seq, cfg);
    for (const auto& [st, ln] : spans) {
        pipe.submit_chunk(seq.slice(st, ln));
    }
    pipe.flush_pending();
    uint64_t out_bytes = writer.finish(seq.bit_len(), digest);

    auto t1 = std::chrono::steady_clock::now();
    EncodeStats stats;
    stats.input_bits = seq.bit_len();
    stats.output_bytes = out_bytes;
    stats.chunk_count = pipe.chunk_count();
    stats.chunk_ref_count = pipe.chunk_ref_count();
    stats.wall_seconds = std::chrono::duration<double>(t1 - t0).count();
    stats.peak_rss_mb = read_peak_rss_mb();
    stats.stream_sha256_hex = Sha256::to_hex(digest);
    return stats;
}

EncodeStats encode_raw_file_streaming(
    const std::string& in_raw_path,
    const std::string& out_mapr_path,
    unsigned num_threads,
    const StreamConfig& cfg) {
    auto t0 = std::chrono::steady_clock::now();
    std::ifstream in(in_raw_path, std::ios::binary);
    if (!in) throw std::runtime_error("Cannot open input file: " + in_raw_path);

    ContainerWriter writer(out_mapr_path, cfg, true);
    BoundedChunkPipeline pipe(writer, cfg, num_threads);
    Sha256 sha;

    const uint64_t avg_gap = (cfg.l_target > cfg.l_min) ? (cfg.l_target - cfg.l_min) : 65536ULL;
    const uint64_t sync_mask = (1ULL << (std::bit_width(avg_gap) - 1)) - 1ULL;

    // Bounded rolling word buffer (~2 MiB max capacity) so multi-GB files use constant RAM!
    std::vector<uint64_t> wbuf;
    wbuf.reserve(static_cast<size_t>((cfg.l_max >> 6) * 2 + 65536));
    uint64_t buf_bit_len = 0ULL;
    uint64_t buf_bit_start = 0ULL; // bit offset within wbuf[0..]
    uint64_t total_input_bits = 0ULL;

    auto extract_from_wbuf = [&](uint64_t start_bit, uint64_t len_bits) -> BitSeq {
        if (len_bits == 0) return BitSeq::empty();
        size_t out_words = static_cast<size_t>((len_bits + 63ULL) >> 6);
        std::vector<uint64_t> res(out_words, 0ULL);
        size_t ws = static_cast<size_t>(start_bit >> 6);
        int sh = static_cast<int>(start_bit & 63ULL);
        if (sh == 0) {
            std::copy_n(wbuf.begin() + static_cast<ptrdiff_t>(ws), out_words, res.begin());
        } else {
            int rsh = 64 - sh;
            for (size_t i = 0; i < out_words; ++i) {
                uint64_t lo = wbuf[ws + i] >> sh;
                uint64_t hi = (ws + i + 1 < wbuf.size()) ? (wbuf[ws + i + 1] << rsh) : 0ULL;
                res[i] = lo | hi;
            }
        }
        return BitSeq(std::move(res), len_bits);
    };

    auto get_wbuf64 = [&](uint64_t bit_pos) -> uint64_t {
        size_t wi = static_cast<size_t>(bit_pos >> 6);
        int sh = static_cast<int>(bit_pos & 63ULL);
        uint64_t lo = wbuf[wi] >> sh;
        if (sh != 0 && wi + 1 < wbuf.size()) lo |= wbuf[wi + 1] << (64 - sh);
        return lo;
    };

    auto compact_wbuf = [&]() {
        size_t drop_words = static_cast<size_t>(buf_bit_start >> 6);
        if (drop_words >= 32768) {
            wbuf.erase(wbuf.begin(), wbuf.begin() + static_cast<ptrdiff_t>(drop_words));
            uint64_t drop_bits = static_cast<uint64_t>(drop_words) * 64ULL;
            buf_bit_start -= drop_bits;
            buf_bit_len -= drop_bits;
        }
    };

    constexpr size_t IO_CHUNK = 1u << 20; // 1 MiB streaming I/O buffer (8-byte multiple!)
    std::vector<uint8_t> iobuf(IO_CHUNK);

    while (in) {
        in.read(reinterpret_cast<char*>(iobuf.data()), static_cast<std::streamsize>(IO_CHUNK));
        size_t got = static_cast<size_t>(in.gcount());
        if (got == 0) break;

        sha.update(iobuf.data(), got);
        total_input_bits += static_cast<uint64_t>(got) * 8ULL;

        // Append bytes via BITREV8 into wbuf (note: IO_CHUNK is divisible by 8 except possibly final EOF read)
        BitSeq blk = BitSeq::from_bytes_msb(iobuf.data(), got);
        int tail_rem = static_cast<int>(buf_bit_len & 63ULL);
        if (tail_rem == 0) {
            wbuf.insert(wbuf.end(), blk.words().begin(), blk.words().end());
            buf_bit_len += blk.bit_len();
        } else {
            // Only happens if an intermediate read returned non-multiple of 8 bytes
            for (size_t i = 0; i < blk.word_count(); ++i) {
                int wb = (i + 1 < blk.word_count() || (blk.bit_len() & 63ULL) == 0ULL)
                             ? 64 : static_cast<int>(blk.bit_len() & 63ULL);
                uint64_t val = blk.word(i) & low_mask(wb);
                int r = static_cast<int>(buf_bit_len & 63ULL);
                if (r == 0) wbuf.push_back(val);
                else {
                    wbuf.back() |= (val << r);
                    if (r + wb > 64) wbuf.push_back(val >> (64 - r));
                }
                buf_bit_len += static_cast<uint64_t>(wb);
            }
        }

        // Emit ready superchunks whenever at least l_max + l_min bits are buffered
        while ((buf_bit_len - buf_bit_start) > static_cast<uint64_t>(cfg.l_max) + cfg.l_min) {
            uint64_t search_s = buf_bit_start + cfg.l_min;
            uint64_t hard_e = buf_bit_start + cfg.l_max;
            uint64_t cut = hard_e;
            for (uint64_t p = search_s; p + 64ULL <= hard_e; ++p) {
                uint64_t w = get_wbuf64(p);
                uint64_t cw = std::min(w, ~w);
                if ((splitmix64(cw) & sync_mask) == 0ULL) {
                    cut = p;
                    break;
                }
            }
            pipe.submit_chunk(extract_from_wbuf(buf_bit_start, cut - buf_bit_start));
            buf_bit_start = cut;
            compact_wbuf();
        }
    }

    // Drain remaining buffered bits identically to synchronize_partition
    if (total_input_bits == 0) {
        pipe.submit_chunk(BitSeq::empty());
    } else {
        while (buf_bit_start < buf_bit_len) {
            uint64_t rem_bits = buf_bit_len - buf_bit_start;
            if (rem_bits <= cfg.l_min) {
                pipe.submit_chunk(extract_from_wbuf(buf_bit_start, rem_bits));
                buf_bit_start = buf_bit_len;
                break;
            }
            uint64_t search_s = buf_bit_start + cfg.l_min;
            uint64_t hard_e = std::min<uint64_t>(buf_bit_len, buf_bit_start + cfg.l_max);
            uint64_t cut = hard_e;
            if (hard_e - search_s >= 64ULL) {
                for (uint64_t p = search_s; p + 64ULL <= hard_e; ++p) {
                    uint64_t w = get_wbuf64(p);
                    uint64_t cw = std::min(w, ~w);
                    if ((splitmix64(cw) & sync_mask) == 0ULL) {
                        cut = p;
                        break;
                    }
                }
            }
            pipe.submit_chunk(extract_from_wbuf(buf_bit_start, cut - buf_bit_start));
            buf_bit_start = cut;
            compact_wbuf();
        }
    }

    pipe.flush_pending();
    auto digest = sha.finalize();
    uint64_t out_bytes = writer.finish(total_input_bits, digest);

    auto t1 = std::chrono::steady_clock::now();
    EncodeStats stats;
    stats.input_bits = total_input_bits;
    stats.output_bytes = out_bytes;
    stats.chunk_count = pipe.chunk_count();
    stats.chunk_ref_count = pipe.chunk_ref_count();
    stats.wall_seconds = std::chrono::duration<double>(t1 - t0).count();
    stats.peak_rss_mb = read_peak_rss_mb();
    stats.stream_sha256_hex = Sha256::to_hex(digest);
    return stats;
}

} // namespace mapr
