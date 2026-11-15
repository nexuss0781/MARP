// MARP v2 — E2 ALGEBRA — C05 EVAL implementation.
//
// Traceability:
//   SPECS/COMPONENTS/e2-algebra/SPECS.md §5.3–5.5, §6–11
//   SPECS/COMPONENTS-V2.md (C05 EVAL)
//   SPECS/SPECS-V2.md §3.3–3.8, §8.2–8.3, §9.1, §12.11
//
// Authority boundary:
//   Pure E1 + E2(C03) dependencies only.  No E3–E7, wire, container, harness,
//   CLI, file I/O, thread, time, floating-point, or mutable global state.

#include "mapr/e2/e2_eval.hpp"

#include <memory>
#include <string_view>
#include <utility>

namespace marp::v2 {
namespace {

Status to_eval_status(mapr::ErrCode code) noexcept {
    return code == mapr::ErrCode::Limit ? Code::Limit : Code::Invalid;
}

}  // namespace

// ---------------------------------------------------------------------------
// PredictorCheckpoint validation & capture (§5.5)
// ---------------------------------------------------------------------------

Status validate_predictor_checkpoint(const Ir& ir, const PredictorCheckpoint& cp,
                                     const EvalLimits& limits) {
    auto plan = detail::build_eval_plan(ir, limits, true, ir.root);
    if (!plan.ok()) return plan.code();
    return detail::validate_checkpoint_against_plan(plan.value(), cp);
}

Result<PredictorCheckpoint> capture_predictor_checkpoint(const Ir& ir, u32 predictor_node,
                                                         const BigInt& target_offset,
                                                         const PredictorCheckpoint* from,
                                                         const EvalLimits& limits,
                                                         EvalStats* stats) {
    if (stats != nullptr) *stats = EvalStats{};
    auto plan = detail::build_eval_plan(ir, limits, true, ir.root);
    if (!plan.ok()) return plan.code();
    return detail::capture_checkpoint_with_plan(plan.value(), predictor_node, target_offset,
                                                from, stats);
}

// ---------------------------------------------------------------------------
// Incremental SHA-256 streaming sink (parent §9.1(4), E2-I9)
// ---------------------------------------------------------------------------

HashingSink::HashingSink(Sink* downstream) noexcept : downstream_(downstream) {}

Status HashingSink::write(std::span<const u8> chunk) {
    if (finished_) return Code::Invalid;
    const std::string_view view(reinterpret_cast<const char*>(chunk.data()), chunk.size());
    const mapr::ErrCode err = hasher_.update(view);
    if (err != mapr::ErrCode::Ok) return to_eval_status(err);
    auto next = bytes_.add(BigInt(static_cast<u64>(chunk.size())));
    if (!next.ok()) return to_eval_status(next.error());
    bytes_ = std::move(next.value());
    if (downstream_ != nullptr) {
        const Status dst = downstream_->write(chunk);
        if (!dst.ok()) return dst;
    }
    return Status{};
}

Result<StreamDigest> HashingSink::finish() {
    if (finished_) return Code::Invalid;
    auto digest = hasher_.finish();
    if (!digest.ok()) return to_eval_status(digest.error()).code();
    finished_ = true;
    StreamDigest out;
    out.sha256 = digest.value();
    out.bytes = bytes_;
    return out;
}

Result<StreamDigest> eval_stream_digest(const Ir& ir, const EvalLimits& limits,
                                        EvalStats* stats, Sink* downstream) {
    return eval_node_stream_digest(ir, ir.root, limits, stats, downstream);
}

Result<StreamDigest> eval_node_stream_digest(const Ir& ir, u32 node,
                                             const EvalLimits& limits,
                                             EvalStats* stats, Sink* downstream) {
    HashingSink sink(downstream);
    const Status st = eval_node_stream_ex(ir, node, sink, limits, stats);
    if (!st.ok()) return st.code();
    return sink.finish();
}

Result<StreamDigest> eval_range_digest(const Ir& ir, const BigInt& start,
                                       const BigInt& length, const EvalLimits& limits,
                                       std::span<const PredictorCheckpoint> checkpoints,
                                       EvalStats* stats, Sink* downstream) {
    HashingSink sink(downstream);
    const Status st = eval_range_ex(ir, start, length, sink, limits, checkpoints, stats);
    if (!st.ok()) return st.code();
    return sink.finish();
}

// ---------------------------------------------------------------------------
// Extended evaluation entry points
// ---------------------------------------------------------------------------

Status eval_node_stream_ex(const Ir& ir, u32 node, Sink& sink,
                           const EvalLimits& limits, EvalStats* stats) {
    if (stats != nullptr) *stats = EvalStats{};
    auto plan = detail::build_eval_plan(ir, limits, true, node);
    if (!plan.ok()) return plan.code();
    const BigInt& total = plan.value().lengths[node];
    return detail::stream_range_to_sink(plan.value(), node, BigInt::zero(), total, sink, {},
                                        stats);
}

Status eval_stream_ex(const Ir& ir, Sink& sink, const EvalLimits& limits,
                      EvalStats* stats) {
    return eval_node_stream_ex(ir, ir.root, sink, limits, stats);
}

Status eval_range_ex(const Ir& ir, const BigInt& start, const BigInt& length,
                     Sink& sink, const EvalLimits& limits,
                     std::span<const PredictorCheckpoint> checkpoints,
                     EvalStats* stats) {
    if (stats != nullptr) *stats = EvalStats{};
    auto plan = detail::build_eval_plan(ir, limits, true, ir.root);
    if (!plan.ok()) return plan.code();
    return detail::stream_range_to_sink(plan.value(), ir.root, start, length, sink,
                                        checkpoints, stats);
}

Result<std::size_t> read_range_ex(const Ir& ir, u32 node, const BigInt& start,
                                  std::span<u8> out, const EvalLimits& limits,
                                  std::span<const PredictorCheckpoint> checkpoints,
                                  EvalStats* stats) {
    if (stats != nullptr) *stats = EvalStats{};
    auto plan = detail::build_eval_plan(ir, limits, true, node);
    if (!plan.ok()) return plan.code();
    const Status st = detail::eval_range_with_plan(plan.value(), node, start, out, nullptr,
                                                   checkpoints, stats);
    if (!st.ok()) return st.code();
    return out.size();
}

// ---------------------------------------------------------------------------
// PreparedEval — reusable validated, immutable, thread-safe plan
// ---------------------------------------------------------------------------

struct PreparedEval::Impl {
    detail::EvalPlanData plan;
};

PreparedEval::PreparedEval() noexcept = default;
PreparedEval::PreparedEval(std::unique_ptr<Impl> impl) noexcept : impl_(std::move(impl)) {}
PreparedEval::~PreparedEval() = default;
PreparedEval::PreparedEval(PreparedEval&&) noexcept = default;
PreparedEval& PreparedEval::operator=(PreparedEval&&) noexcept = default;

Result<PreparedEval> PreparedEval::prepare(const Ir& ir, const EvalLimits& limits) {
    auto plan = detail::build_eval_plan(ir, limits, true, ir.root);
    if (!plan.ok()) return plan.code();
    auto impl = std::make_unique<Impl>();
    impl->plan = std::move(plan.value());
    return PreparedEval(std::move(impl));
}

const Ir& PreparedEval::ir() const noexcept { return *impl_->plan.ir; }
const EvalLimits& PreparedEval::limits() const noexcept { return impl_->plan.limits; }

Result<BigInt> PreparedEval::node_length(u32 node) const {
    if (!impl_ || node >= impl_->plan.lengths.size()) return Code::Invalid;
    return impl_->plan.lengths[node];
}

const BigInt& PreparedEval::total_length() const noexcept {
    return impl_->plan.lengths[impl_->plan.ir->root];
}

Result<std::size_t> PreparedEval::read_range(
    u32 node, const BigInt& start, std::span<u8> out,
    std::span<const PredictorCheckpoint> checkpoints, EvalStats* stats) const {
    if (stats != nullptr) *stats = EvalStats{};
    if (!impl_) return Code::Invalid;
    const Status st = detail::eval_range_with_plan(impl_->plan, node, start, out, nullptr,
                                                   checkpoints, stats);
    if (!st.ok()) return st.code();
    return out.size();
}

Status PreparedEval::eval_node_stream(u32 node, Sink& sink, EvalStats* stats) const {
    if (stats != nullptr) *stats = EvalStats{};
    if (!impl_ || node >= impl_->plan.lengths.size()) return Code::Invalid;
    const BigInt& total = impl_->plan.lengths[node];
    return detail::stream_range_to_sink(impl_->plan, node, BigInt::zero(), total, sink, {},
                                        stats);
}

Status PreparedEval::eval_stream(Sink& sink, EvalStats* stats) const {
    if (!impl_) return Code::Invalid;
    return eval_node_stream(impl_->plan.ir->root, sink, stats);
}

Status PreparedEval::eval_range(const BigInt& start, const BigInt& length, Sink& sink,
                                std::span<const PredictorCheckpoint> checkpoints,
                                EvalStats* stats) const {
    if (stats != nullptr) *stats = EvalStats{};
    if (!impl_) return Code::Invalid;
    return detail::stream_range_to_sink(impl_->plan, impl_->plan.ir->root, start, length, sink,
                                        checkpoints, stats);
}

Result<PredictorCheckpoint> PreparedEval::capture_checkpoint(
    u32 predictor_node, const BigInt& target_offset, const PredictorCheckpoint* from,
    EvalStats* stats) const {
    if (stats != nullptr) *stats = EvalStats{};
    if (!impl_) return Code::Invalid;
    return detail::capture_checkpoint_with_plan(impl_->plan, predictor_node, target_offset,
                                                from, stats);
}

}  // namespace marp::v2
