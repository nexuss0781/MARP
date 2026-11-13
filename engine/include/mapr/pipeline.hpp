#pragma once

#include "mapr/bitseq.hpp"
#include "mapr/container.hpp"
#include "mapr/dag.hpp"
#include "mapr/encoder.hpp"
#include "mapr/pipeline_helpers.hpp"
#include "mapr/profile.hpp"
#include "mapr/simd/dispatch.hpp"
#include "mapr/thread_pool.hpp"

#include <atomic>
#include <deque>
#include <future>
#include <memory>
#include <vector>

namespace mapr {

// Forward declarations
struct HistItem {
    uint32_t idx;
    ChunkKey128 sig;
    V4Op mu_canon;
    BitSeq seq; // for V_4 verify on match
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

// Shared bounded-window chunk dispatcher used by both BitSeq and streaming file encoders
class BoundedChunkPipeline {
public:
    BoundedChunkPipeline(ContainerWriter& writer, const StreamConfig& cfg, unsigned num_threads)
        : writer_(writer), cfg_(cfg), threads_(::std::max(1u, num_threads)),
          max_batch_(::std::max<size_t>(4, 2 * ::std::max(1u, num_threads))) {}

    void submit_chunk(BitSeq chunk);
    void flush_pending();
    uint64_t chunk_count() const { return next_chunk_idx_; }
    uint64_t chunk_ref_count() const { return chunk_ref_count_; }

private:
    ContainerWriter& writer_;
    StreamConfig cfg_;
    unsigned threads_;
    size_t max_batch_;

    ::std::deque<HistItem> hist_ring_;
    ::std::vector<PendingTask> pending_;
    uint32_t next_chunk_idx_ = 0;
    uint64_t cur_bit_offset_ = 0;
    uint64_t chunk_ref_count_ = 0;
};

} // namespace mapr