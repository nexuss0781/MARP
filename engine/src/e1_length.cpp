#include "mapr/e1_length.hpp"
#include <vector>

namespace mapr {

// ============================================================================
// length_of implementation (Math-SPECS Part B)
// ============================================================================

Result<LengthResult> length_of(const TermView& term) noexcept {
    size_t N = term.node_count();
    LengthResult res;
    res.memo.resize(N);

    for (NodeId id = 0; id < N; ++id) {
        switch (term.node_kind(id)) {
            case NodeKind::Empty:
                res.memo[id] = BigInt::zero();
                break;

            case NodeKind::Atom:
                res.memo[id] = BigInt(term.atom_size(id));
                break;

            case NodeKind::Zero:
                res.memo[id] = term.zero_count(id);
                break;

            case NodeKind::Concat: {
                BigInt sum = BigInt::zero();
                for (NodeId c : term.concat_children(id)) {
                    auto r = sum.add(res.memo[c]);
                    if (!r.ok()) return r.error();
                    sum = std::move(r.value());
                }
                res.memo[id] = std::move(sum);
                break;
            }

            case NodeKind::Repeat: {
                const BigInt& L = res.memo[term.repeat_child(id)];
                const BigInt& q = term.repeat_q(id);
                const BigInt& r = term.repeat_r(id);
                if (q.is_zero() && !r.is_zero()) return ErrCode::Invalid;
                if (!q.is_zero()) {
                    int c = r.compare(L);
                    if (c >= 0) return ErrCode::Invalid; // r >= L
                }
                auto mq = q.mul(L);
                if (!mq.ok()) return mq.error();
                auto mqr = mq.value().add(r);
                if (!mqr.ok()) return mqr.error();
                res.memo[id] = std::move(mqr.value());
                break;
            }

            case NodeKind::Slice: {
                const BigInt& L = res.memo[term.slice_child(id)];
                const BigInt& s = term.slice_start(id);
                const BigInt& l = term.slice_len(id);
                if (s.compare(L) > 0) return ErrCode::Invalid;
                auto sp = s.add(l);
                if (!sp.ok()) return sp.error();
                if (sp.value().compare(L) > 0) return ErrCode::Invalid;
                res.memo[id] = l;
                break;
            }

            case NodeKind::Morph:
                res.memo[id] = res.memo[term.morph_child(id)];
                break;

            case NodeKind::Xor: {
                const BigInt& a = res.memo[term.xor_a(id)];
                const BigInt& b = res.memo[term.xor_b(id)];
                if (a.compare(b) != 0) return ErrCode::Invalid;
                res.memo[id] = a;
                break;
            }

            case NodeKind::Interleave: {
                const auto& children = term.interleave_children(id);
                uint32_t stride = term.interleave_stride(id);
                if (stride == 0) return ErrCode::Invalid;
                if (children.size() < 2) return ErrCode::Invalid;
                const BigInt& L0 = res.memo[children[0]];
                for (size_t i = 1; i < children.size(); ++i) {
                    if (res.memo[children[i]].compare(L0) != 0) return ErrCode::Invalid;
                }
                // Check L0 % stride == 0
                auto dm = L0.divmod_scalar(stride);
                if (!dm.ok()) return dm.error();
                if (dm.value().second != 0) return ErrCode::Invalid;

                BigInt k(children.size());
                auto mk = k.mul(L0);
                if (!mk.ok()) return mk.error();
                res.memo[id] = std::move(mk.value());
                break;
            }

            case NodeKind::Lfsr:
                res.memo[id] = term.lfsr_n(id);
                break;

            case NodeKind::Affine:
                res.memo[id] = term.affine_n(id);
                break;

            case NodeKind::Predictor:
                res.memo[id] = res.memo[term.predictor_residual(id)];
                break;
        }
    }
    res.length = std::move(res.memo[N - 1]); // root is the last node (topological order)
    return res;
}

} // namespace mapr