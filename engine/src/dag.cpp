#include "mapr/dag.hpp"
#include <algorithm>
#include <functional>
#include <set>
#include <stdexcept>

namespace mapr {

namespace {

bool validate_atom(const DualBasisAtom& a, std::string& err) {
    if (a.b < 1 || a.b > 64) {
        err = "Atom b out of [1,64]";
        return false;
    }
    if (a.w > a.b) {
        err = "Atom w > b";
        return false;
    }
    if (a.beta == AtomBasis::ZHEG && !is_dyadic_atom_len(a.b)) {
        err = "ZHEG basis requires dyadic b in {1,2,4,8,16,32,64}";
        return false;
    }
    if (a.rho >= binom64(a.b, a.w)) {
        err = "Atom rho >= C(b,w)";
        return false;
    }
    return true;
}

} // namespace

ValidationResult validate_chunk_dag(const ExplicitChunkDAG& dag, uint64_t expected_bit_len) {
    ValidationResult res;
    size_t m = dag.nodes.size();
    if (m == 0) {
        res.error = "ExplicitChunkDAG has 0 nodes";
        return res;
    }
    if (dag.root >= m) {
        res.error = "root index out of bounds";
        return res;
    }
    // Bounded intermediate static-length cap preventing Repeat+Slice / Interleave bombs (DEF-001)
    const uint64_t max_inter_bits = std::max<uint64_t>(4ULL * expected_bit_len + 4096ULL, 67108864ULL);
    res.node_lengths.assign(m, 0ULL);

    for (size_t v = 0; v < m; ++v) {
        const auto& nd = dag.nodes[v];
        if (std::holds_alternative<EmptyNode>(nd)) {
            res.node_lengths[v] = 0ULL;
        } else if (const auto* an = std::get_if<AtomNode>(&nd)) {
            if (!validate_atom(an->atom, res.error)) return res;
            res.node_lengths[v] = an->atom.b;
        } else if (const auto* asn = std::get_if<AtomSpanNode>(&nd)) {
            if (asn->atoms.empty()) {
                res.error = "AtomSpanNode empty";
                return res;
            }
            uint64_t sum = 0ULL;
            for (const auto& a : asn->atoms) {
                if (!validate_atom(a, res.error)) return res;
                sum += a.b;
                if (sum > max_inter_bits) {
                    res.error = "AtomSpanNode intermediate length exceeds safety cap";
                    return res;
                }
            }
            res.node_lengths[v] = sum;
        } else if (const auto* cn = std::get_if<ConcatNode>(&nd)) {
            if (cn->children.size() < 2) {
                res.error = "ConcatNode degree < 2";
                return res;
            }
            uint64_t sum = 0ULL;
            for (uint32_t u : cn->children) {
                if (u >= v) {
                    res.error = "Topological cycle/forward edge in ConcatNode";
                    return res;
                }
                if (res.node_lengths[u] > max_inter_bits - sum) {
                    res.error = "ConcatNode intermediate length exceeds safety cap";
                    return res;
                }
                sum += res.node_lengths[u];
            }
            res.node_lengths[v] = sum;
        } else if (const auto* rn = std::get_if<RepeatNode>(&nd)) {
            if (rn->child >= v) {
                res.error = "Topological violation in RepeatNode";
                return res;
            }
            uint64_t clen = res.node_lengths[rn->child];
            if (clen == 0 || rn->q < 1 || rn->r >= clen) {
                res.error = "Invalid RepeatNode domain parameters";
                return res;
            }
            if (rn->q > (max_inter_bits - rn->r) / clen) {
                res.error = "RepeatNode intermediate length exceeds safety cap";
                return res;
            }
            res.node_lengths[v] = rn->q * clen + rn->r;
        } else if (const auto* sn = std::get_if<SliceNode>(&nd)) {
            if (sn->child >= v) {
                res.error = "Topological violation in SliceNode";
                return res;
            }
            uint64_t clen = res.node_lengths[sn->child];
            if (sn->length == 0 || sn->start > clen || sn->length > clen - sn->start) {
                res.error = "SliceNode out of bounds";
                return res;
            }
            res.node_lengths[v] = sn->length;
        } else if (const auto* mn = std::get_if<MorphNode>(&nd)) {
            if (mn->child >= v) {
                res.error = "Topological violation in MorphNode";
                return res;
            }
            if (static_cast<uint8_t>(mn->mu) > 3u) {
                res.error = "Invalid V4Op in MorphNode";
                return res;
            }
            res.node_lengths[v] = res.node_lengths[mn->child];
        } else if (const auto* xn = std::get_if<XorDiffNode>(&nd)) {
            if (xn->base >= v || xn->delta >= v) {
                res.error = "Topological violation in XorDiffNode";
                return res;
            }
            uint64_t bl = res.node_lengths[xn->base];
            uint64_t dl = res.node_lengths[xn->delta];
            if (bl == 0 || bl != dl) {
                res.error = "XorDiffNode base/delta length mismatch";
                return res;
            }
            res.node_lengths[v] = bl;
        } else if (const auto* in = std::get_if<InterleaveNode>(&nd)) {
            if ((in->stride != 8 && in->stride != 16 && in->stride != 32 && in->stride != 64) ||
                in->lanes.size() != in->stride) {
                res.error = "Invalid InterleaveNode stride/lane count";
                return res;
            }
            for (uint32_t u : in->lanes) {
                if (u >= v) {
                    res.error = "Topological violation in InterleaveNode";
                    return res;
                }
            }
            uint64_t l0 = res.node_lengths[in->lanes[0]];
            if (l0 == 0) {
                res.error = "Zero-length lane in InterleaveNode";
                return res;
            }
            for (uint32_t u : in->lanes) {
                if (res.node_lengths[u] != l0) {
                    res.error = "InterleaveNode unequal lane lengths";
                    return res;
                }
            }
            if (l0 > max_inter_bits / static_cast<uint64_t>(in->stride)) {
                res.error = "InterleaveNode intermediate length exceeds safety cap";
                return res;
            }
            res.node_lengths[v] = static_cast<uint64_t>(in->stride) * l0;
        } else if (const auto* ln = std::get_if<LfsrNode>(&nd)) {
            if (ln->degree < 1 || ln->degree > 64) {
                res.error = "LfsrNode degree out of [1,64]";
                return res;
            }
            uint64_t mL = low_mask(ln->degree);
            if (ln->conn_mask == 0ULL || (ln->conn_mask & ~mL) != 0ULL || (ln->init_mask & ~mL) != 0ULL) {
                res.error = "LfsrNode mask out of bounds";
                return res;
            }
            if (ln->length < static_cast<uint64_t>(2 * ln->degree + 1) || ln->length > max_inter_bits) {
                res.error = "LfsrNode length out of valid bounds";
                return res;
            }
            res.node_lengths[v] = ln->length;
        } else if (const auto* rn = std::get_if<RawNode>(&nd)) {
            if (rn->bit_len == 0) {
                res.error = "RawNode zero length";
                return res;
            }
            res.node_lengths[v] = rn->bit_len;
        } else if (std::holds_alternative<DedupRefNode>(nd)) {
            // Length cannot be determined without global index context
            res.error = "DedupRefNode requires external index resolution";
            return res;
        } else if (std::holds_alternative<DeflateHintNode>(nd)) {
            res.error = "DeflateHintNode not directly evaluable";
            return res;
        }
    }

    if (res.node_lengths[dag.root] != expected_bit_len) {
        res.error = "Root static length != expected superchunk bit_len";
        return res;
    }
    res.valid = true;
    return res;
}

BitSeq evaluate_chunk_dag(const ExplicitChunkDAG& dag, uint64_t expected_bit_len) {
    auto val = validate_chunk_dag(dag, expected_bit_len);
    if (!val.valid) {
        throw std::runtime_error("Invalid chunk DAG: " + val.error);
    }
    size_t m = dag.nodes.size();

    // Reachability & reference counting so dead/consumed buffers free immediately
    std::vector<uint8_t> reachable(m, 0);
    reachable[dag.root] = 1;
    auto visit_children = [&](size_t v, auto&& fn) {
        const auto& nd = dag.nodes[v];
        if (const auto* cn = std::get_if<ConcatNode>(&nd)) {
            for (uint32_t u : cn->children) fn(u);
        } else if (const auto* rn = std::get_if<RepeatNode>(&nd)) {
            fn(rn->child);
        } else if (const auto* sn = std::get_if<SliceNode>(&nd)) {
            fn(sn->child);
        } else if (const auto* mn = std::get_if<MorphNode>(&nd)) {
            fn(mn->child);
        } else if (const auto* xn = std::get_if<XorDiffNode>(&nd)) {
            fn(xn->base); fn(xn->delta);
        } else if (const auto* in = std::get_if<InterleaveNode>(&nd)) {
            for (uint32_t u : in->lanes) fn(u);
        }
    };

    for (size_t v = m; v-- > 0;) {
        if (!reachable[v]) continue;
        visit_children(v, [&](uint32_t u) { reachable[u] = 1; });
    }

    std::vector<uint32_t> ref_rem(m, 0);
    ref_rem[dag.root] = 1;
    for (size_t v = 0; v < m; ++v) {
        if (!reachable[v]) continue;
        visit_children(v, [&](uint32_t u) { ++ref_rem[u]; });
    }

    std::vector<BitSeq> vals(m);
    auto consume = [&](uint32_t u) {
        if (--ref_rem[u] == 0) {
            vals[u] = BitSeq();
        }
    };

    for (size_t v = 0; v < m; ++v) {
        if (!reachable[v]) continue;
        const auto& nd = dag.nodes[v];
        if (std::holds_alternative<EmptyNode>(nd)) {
            vals[v] = BitSeq::empty();
        } else if (const auto* an = std::get_if<AtomNode>(&nd)) {
            vals[v] = BitSeq::from_word(decode_micro_atom(an->atom), an->atom.b);
        } else if (const auto* asn = std::get_if<AtomSpanNode>(&nd)) {
            BitSeqAppender app(val.node_lengths[v]);
            for (const auto& a : asn->atoms) {
                app.append_word(decode_micro_atom(a), a.b);
            }
            vals[v] = app.finish();
        } else if (const auto* cn = std::get_if<ConcatNode>(&nd)) {
            BitSeqAppender app(val.node_lengths[v]);
            for (uint32_t u : cn->children) {
                app.append_seq(vals[u]);
            }
            vals[v] = app.finish();
            for (uint32_t u : cn->children) consume(u);
        } else if (const auto* rn = std::get_if<RepeatNode>(&nd)) {
            vals[v] = vals[rn->child].repeat(rn->q, rn->r);
            consume(rn->child);
        } else if (const auto* sn = std::get_if<SliceNode>(&nd)) {
            vals[v] = vals[sn->child].slice(sn->start, sn->length);
            consume(sn->child);
        } else if (const auto* mn = std::get_if<MorphNode>(&nd)) {
            vals[v] = vals[mn->child].apply_v4(mn->mu);
            consume(mn->child);
        } else if (const auto* xn = std::get_if<XorDiffNode>(&nd)) {
            vals[v] = vals[xn->base].bitwise_xor(vals[xn->delta]);
            consume(xn->base);
            consume(xn->delta);
        } else if (const auto* in = std::get_if<InterleaveNode>(&nd)) {
            std::vector<BitSeq> lanes;
            lanes.reserve(in->stride);
            for (uint32_t u : in->lanes) lanes.push_back(vals[u]);
            vals[v] = interleave_bitplanes(lanes, in->stride);
            for (uint32_t u : in->lanes) consume(u);
        } else if (const auto* ln = std::get_if<LfsrNode>(&nd)) {
            vals[v] = evaluate_lfsr(ln->degree, ln->conn_mask, ln->init_mask, ln->length);
        } else if (const auto* rn = std::get_if<RawNode>(&nd)) {
            vals[v] = BitSeq::from_bytes_msb(rn->bytes.data(), rn->bytes.size()).slice(0, rn->bit_len);
        }
    }

    BitSeq out = std::move(vals[dag.root]);
    if (out.bit_len() != expected_bit_len) {
        throw std::runtime_error("Decoded length mismatch");
    }
    return out;
}

void InspectionSummary::add_chunk_ref(uint64_t chunk_bit_len, V4Op mu) {
    ++chunk_count;
    ++chunk_ref_count;
    total_bits += chunk_bit_len;
    accounted_bits += chunk_bit_len;
    node_counts["CHUNK_REF"] += 1;
    std::string key = "CHUNK_REF";
    if (mu == V4Op::NOT) key = "CHUNK_REF_NOT";
    else if (mu == V4Op::REV) key = "CHUNK_REF_REV";
    else if (mu == V4Op::REV_NOT) key = "CHUNK_REF_REV_NOT";
    mechanism_bits[key] += chunk_bit_len;
}

void InspectionSummary::add_chunk_dag(const ExplicitChunkDAG& dag, uint64_t chunk_bit_len) {
    auto val = validate_chunk_dag(dag, chunk_bit_len);
    if (!val.valid) throw std::runtime_error("Inspect invalid DAG: " + val.error);

    ++chunk_count;
    total_bits += chunk_bit_len;
    size_t m = dag.nodes.size();

    // Compute exact reachability from dag.root so unreachable dead nodes are excluded (DEF-004)
    std::vector<uint8_t> reachable(m, 0u);
    if (dag.root < m) reachable[dag.root] = 1u;
    for (size_t idx = m; idx > 0; --idx) {
        size_t v = idx - 1;
        if (!reachable[v]) continue;
        const auto& nd = dag.nodes[v];
        if (const auto* cn = std::get_if<ConcatNode>(&nd)) {
            for (uint32_t u : cn->children) reachable[u] = 1u;
        } else if (const auto* rn = std::get_if<RepeatNode>(&nd)) {
            reachable[rn->child] = 1u;
        } else if (const auto* sn = std::get_if<SliceNode>(&nd)) {
            reachable[sn->child] = 1u;
        } else if (const auto* mn = std::get_if<MorphNode>(&nd)) {
            reachable[mn->child] = 1u;
        } else if (const auto* xn = std::get_if<XorDiffNode>(&nd)) {
            reachable[xn->base] = 1u;
            reachable[xn->delta] = 1u;
        } else if (const auto* in = std::get_if<InterleaveNode>(&nd)) {
            for (uint32_t u : in->lanes) reachable[u] = 1u;
        }
        // RawNode/DedupRefNode/DeflateHintNode are leaves (no children)
    }

    std::vector<uint32_t> depth(m, 0);
    for (size_t v = 0; v < m; ++v) {
        if (!reachable[v]) continue;
        ++total_dag_nodes;
        const auto& nd = dag.nodes[v];
        if (std::holds_alternative<EmptyNode>(nd)) {
            node_counts["EmptyNode"]++;
        } else if (const auto* an = std::get_if<AtomNode>(&nd)) {
            node_counts["AtomNode"]++;
            total_micro_atoms++;
            if (an->atom.beta == AtomBasis::POS) pos_atoms++; else zheg_atoms++;
        } else if (const auto* asn = std::get_if<AtomSpanNode>(&nd)) {
            node_counts["AtomSpanNode"]++;
            total_micro_atoms += asn->atoms.size();
            for (const auto& a : asn->atoms) {
                if (a.beta == AtomBasis::POS) pos_atoms++; else zheg_atoms++;
            }
        } else if (const auto* cn = std::get_if<ConcatNode>(&nd)) {
            node_counts["ConcatNode"]++;
            total_dag_edges += cn->children.size();
            uint32_t md = 0;
            for (uint32_t u : cn->children) md = std::max(md, depth[u]);
            depth[v] = md + 1;
        } else if (const auto* rn = std::get_if<RepeatNode>(&nd)) {
            node_counts["RepeatNode"]++;
            total_dag_edges += 1;
            depth[v] = depth[rn->child] + 1;
        } else if (const auto* sn = std::get_if<SliceNode>(&nd)) {
            node_counts["SliceNode"]++;
            total_dag_edges += 1;
            depth[v] = depth[sn->child] + 1;
        } else if (const auto* mn = std::get_if<MorphNode>(&nd)) {
            node_counts["MorphNode"]++;
            total_dag_edges += 1;
            depth[v] = depth[mn->child] + 1;
        } else if (const auto* xn = std::get_if<XorDiffNode>(&nd)) {
            node_counts["XorDiffNode"]++;
            total_dag_edges += 2;
            depth[v] = std::max(depth[xn->base], depth[xn->delta]) + 1;
        } else if (const auto* in = std::get_if<InterleaveNode>(&nd)) {
            node_counts["InterleaveNode"]++;
            total_dag_edges += in->lanes.size();
            uint32_t md = 0;
            for (uint32_t u : in->lanes) md = std::max(md, depth[u]);
            depth[v] = md + 1;
        } else if (std::holds_alternative<LfsrNode>(nd)) {
            node_counts["LfsrNode"]++;
        } else if (std::holds_alternative<RawNode>(nd)) {
            node_counts["RawNode"]++;
        } else if (std::holds_alternative<DedupRefNode>(nd)) {
            node_counts["DedupRefNode"]++;
        } else if (std::holds_alternative<DeflateHintNode>(nd)) {
            node_counts["DeflateHintNode"]++;
        }
        max_dag_depth = std::max(max_dag_depth, depth[v] + 1);
    }

    // Exact interval-clamped top-down bit-accountability attribution (DEF-004 fix)
    std::vector<uint64_t> claimed(m, 0ULL);
    std::function<void(size_t, uint64_t)> walk_quota = [&](size_t v, uint64_t quota) {
        if (quota == 0ULL) return;
        const auto& nd = dag.nodes[v];
        if (const auto* an = std::get_if<AtomNode>(&nd)) {
            mechanism_bits[an->atom.beta == AtomBasis::POS ? "ATOM_POS" : "ATOM_ZHEG"] += quota;
            accounted_bits += quota;
        } else if (const auto* asn = std::get_if<AtomSpanNode>(&nd)) {
            uint64_t rem = quota;
            for (const auto& a : asn->atoms) {
                uint64_t take = std::min<uint64_t>(rem, a.b);
                mechanism_bits[a.beta == AtomBasis::POS ? "ATOM_POS" : "ATOM_ZHEG"] += take;
                accounted_bits += take;
                rem -= take;
                if (rem == 0ULL) break;
            }
        } else if (std::holds_alternative<LfsrNode>(nd)) {
            mechanism_bits["LFSR"] += quota;
            accounted_bits += quota;
        } else if (std::holds_alternative<RawNode>(nd)) {
            mechanism_bits["RAW"] += quota;
            accounted_bits += quota;
        } else if (std::holds_alternative<DedupRefNode>(nd)) {
            mechanism_bits["DEDUP_REF"] += quota;
            accounted_bits += quota;
        } else if (std::holds_alternative<DeflateHintNode>(nd)) {
            mechanism_bits["DEFLATE_HINT"] += quota;
            accounted_bits += quota;
        } else if (const auto* cn = std::get_if<ConcatNode>(&nd)) {
            uint64_t rem = quota;
            for (uint32_t u : cn->children) {
                uint64_t take = std::min<uint64_t>(rem, val.node_lengths[u]);
                uint64_t avail = (val.node_lengths[u] > claimed[u]) ? (val.node_lengths[u] - claimed[u]) : 0ULL;
                uint64_t first = std::min<uint64_t>(take, avail);
                uint64_t shared = take - first;
                claimed[u] += first;
                if (first > 0ULL) walk_quota(u, first);
                if (shared > 0ULL) {
                    mechanism_bits["DAG_SHARED_REUSE"] += shared;
                    accounted_bits += shared;
                }
                rem -= take;
                if (rem == 0ULL) break;
            }
        } else if (const auto* rn = std::get_if<RepeatNode>(&nd)) {
            size_t u = rn->child;
            uint64_t motif = std::min<uint64_t>(quota, val.node_lengths[u]);
            uint64_t avail = (val.node_lengths[u] > claimed[u]) ? (val.node_lengths[u] - claimed[u]) : 0ULL;
            uint64_t first = std::min<uint64_t>(motif, avail);
            claimed[u] += first;
            if (first > 0ULL) walk_quota(u, first);
            if (quota > first) {
                mechanism_bits["REPEAT_EXTENSION"] += (quota - first);
                accounted_bits += (quota - first);
            }
        } else if (const auto* sn = std::get_if<SliceNode>(&nd)) {
            size_t u = sn->child;
            uint64_t avail = (val.node_lengths[u] > claimed[u]) ? (val.node_lengths[u] - claimed[u]) : 0ULL;
            uint64_t first = std::min<uint64_t>(quota, avail);
            uint64_t shared = quota - first;
            claimed[u] += first;
            if (first > 0ULL) walk_quota(u, first);
            if (shared > 0ULL) {
                mechanism_bits["SLICE_PROJECTION"] += shared;
                accounted_bits += shared;
            }
        } else if (const auto* mn = std::get_if<MorphNode>(&nd)) {
            size_t u = mn->child;
            uint64_t avail = (val.node_lengths[u] > claimed[u]) ? (val.node_lengths[u] - claimed[u]) : 0ULL;
            uint64_t first = std::min<uint64_t>(quota, avail);
            uint64_t shared = quota - first;
            claimed[u] += first;
            if (first > 0ULL) walk_quota(u, first);
            if (shared > 0ULL) {
                std::string k = "MORPH_ID";
                if (mn->mu == V4Op::NOT) k = "MORPH_NOT";
                else if (mn->mu == V4Op::REV) k = "MORPH_REV";
                else if (mn->mu == V4Op::REV_NOT) k = "MORPH_REV_NOT";
                mechanism_bits[k] += shared;
                accounted_bits += shared;
            }
        } else if (const auto* xn = std::get_if<XorDiffNode>(&nd)) {
            size_t u = xn->base;
            uint64_t avail = (val.node_lengths[u] > claimed[u]) ? (val.node_lengths[u] - claimed[u]) : 0ULL;
            uint64_t first = std::min<uint64_t>(quota, avail);
            uint64_t shared = quota - first;
            claimed[u] += first;
            if (first > 0ULL) walk_quota(u, first);
            if (shared > 0ULL) {
                mechanism_bits["XOR_DIFF"] += shared;
                accounted_bits += shared;
            }
        } else if (const auto* in = std::get_if<InterleaveNode>(&nd)) {
            uint64_t rem = quota;
            for (uint32_t u : in->lanes) {
                uint64_t take = std::min<uint64_t>(rem, val.node_lengths[u]);
                uint64_t avail = (val.node_lengths[u] > claimed[u]) ? (val.node_lengths[u] - claimed[u]) : 0ULL;
                uint64_t first = std::min<uint64_t>(take, avail);
                uint64_t shared = take - first;
                claimed[u] += first;
                if (first > 0ULL) walk_quota(u, first);
                if (shared > 0ULL) {
                    mechanism_bits["DAG_SHARED_REUSE"] += shared;
                    accounted_bits += shared;
                }
                rem -= take;
                if (rem == 0ULL) break;
            }
        }
    };
    claimed[dag.root] = chunk_bit_len;
    walk_quota(dag.root, chunk_bit_len);
}

} // namespace mapr
