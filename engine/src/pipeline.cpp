#include "mapr/pipeline.hpp"
#include "mapr/encoder.hpp"
#include "mapr/bitio.hpp"

#include <algorithm>

namespace mapr {

void BoundedChunkPipeline::submit_chunk(BitSeq chunk) {
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
        pt.seq_for_encode = ::std::move(chunk);
    } else {
        ++chunk_ref_count_;
    }
    pending_.push_back(::std::move(pt));

    if (pending_.size() >= max_batch_) {
        flush_pending();
    }
}

void BoundedChunkPipeline::flush_pending() {
    if (pending_.empty()) return;

    // Collect indices requiring explicit DAG synthesis
    ::std::vector<size_t> work_indices;
    for (size_t i = 0; i < pending_.size(); ++i) {
        if (!pending_[i].is_ref) work_indices.push_back(i);
    }

    ::std::vector<::std::vector<uint8_t>> payloads(pending_.size());
    if (threads_ <= 1 || work_indices.size() <= 1) {
        for (size_t idx : work_indices) {
            ExplicitChunkDAG dag = encode_chunk_dag(pending_[idx].seq_for_encode, true);
            payloads[idx] = serialize_chunk_dag_payload(dag);
            pending_[idx].seq_for_encode = BitSeq();
        }
    } else {
        size_t n_workers = ::std::min<size_t>(threads_, work_indices.size());
        ::std::atomic<size_t> next_w{0};
        ::std::vector<::std::future<void>> futs;
        futs.reserve(n_workers);
        for (size_t t = 0; t < n_workers; ++t) {
            futs.push_back(::std::async(::std::launch::async, [&]() {
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

} // namespace mapr