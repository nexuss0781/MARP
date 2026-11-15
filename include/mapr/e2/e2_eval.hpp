// MARP v2 — E2 ALGEBRA — C05 EVAL
//
// Full streaming evaluation, indexed range evaluation, incremental SHA-256
// streaming, predictor checkpoints, prepared evaluation plans, and resource /
// work accounting.
//
// Normative sources:
//   SPECS/SPECS-V2.md                      §3.3–3.6, §8.2–8.3
//   SPECS/COMPONENTS/e2-algebra/SPECS.md   §4.9–4.11, §5.3–5.5, §6 (E2-I2,
//                                          E2-I8, E2-I9, E2-I12), §7 (O5.1–O5.3),
//                                          §8, §9, §11
//   SPECS/COMPONENTS-V2.md                 §4 C05
//
// Scope discipline (E2 §10, C05 prompt §3.8):
//   * evaluation semantics and execution only — no term rewriting (C04),
//     no standalone DAG builder policy (C06), no wire encode/decode (E3),
//     no discovery/selection (E4–E6), no CLI/MAU/certificate (E7);
//   * no file, path, media-type, environment, or mutable global state access;
//   * C++20 only; E1 `BigInt` is the only length/offset arithmetic provider.
//
// Error model (E2 §9): every fallible operation returns `Result<T>` /
// `Status`; nothing throws past the API boundary and nothing terminates the
// process.  `Invalid` is a contract or bounds violation; `Limit` is a resource
// or policy bound (W7 depth, §8.3 output cap, §5.5 predictor prefix/window
// policy, scratch/work caps).
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <vector>

#include "mapr/e1_sha256.hpp"
#include "mapr/e2/e2_term.hpp"

namespace marp::v2 {

// ---------------------------------------------------------------------------
// Resource bounds and execution telemetry (E2 §5.3–5.5, §11, O5.1–O5.3)
// ---------------------------------------------------------------------------

constexpr std::size_t kDefaultMaxScratchBytes = 64ull << 20;       // 64 MiB
constexpr std::size_t kDefaultPredictorWindowCap = 16ull << 20;    // 16 MiB

struct EvalLimits {
    Limits wf{};                                                   // W1, W7, §8.3 2^63 cap
    std::size_t block_bytes = kEvalBlock;                          // fixed streaming chunk size
    std::size_t max_scratch_bytes = kDefaultMaxScratchBytes;       // heap scratch cap
    std::size_t max_predictor_window = kDefaultPredictorWindowCap; // stride ring cap
    BigInt predictor_prefix_max = predictor_prefix_limit();        // §5.5 2^28 default
    u64 max_work_bytes = 0;                                        // 0 = unlimited
};

struct EvalStats {
    u64 frames_pushed = 0;
    u32 peak_stack_depth = 0;
    std::size_t peak_scratch_bytes = 0;       // peak temporary scratch + ring bytes
    u64 subterms_touched = 0;                 // child subterm range dispatches
    u64 concat_children_skipped = 0;          // non-intersecting Concat children skipped
    u64 lfsr_jumps = 0;                       // GF(2) jump-ahead invocations
    u64 lfsr_gf2_mul_ops = 0;                 // 64x64 GF(2) matrix compositions executed
    u64 lfsr_byte_steps = 0;                  // bytes emitted from LFSR state
    u64 predictor_prefix_bytes = 0;           // residual prefix bytes discarded
    u64 predictor_emitted_bytes = 0;          // reconstructed predictor bytes emitted
    u64 sink_writes = 0;                      // Sink::write invocations
};

// ---------------------------------------------------------------------------
// Predictor checkpoints (E2 §5.5)
// ---------------------------------------------------------------------------

// Exact predictor state at `offset` within `⟦node⟧` (`0 <= offset <= ℓ(node)`).
// Derived from a prior evaluation so range reads past `2^28` can restore state
// without re-scanning from 0.  No gate requires checkpoints; when supplied,
// they are validated before use and produce exact bytes.
struct PredictorCheckpoint {
    u32 node = 0;                  // Predictor node id in the Ir
    BigInt offset;                 // Exact byte offset i in ⟦node⟧
    u8 prev1 = 0;                  // out[i-1] for pid 0, 1, 2 (0 when i == 0)
    u8 prev2 = 0;                  // out[i-2] for pid 2 (0 when i < 2)
    std::vector<u8> window;        // ring[0..param) for pid 3, 4 when 0 < param < ℓ(node) and i > 0
};

// Validates that `cp` is structurally sound for `ir` (`WF(ir)` already checked
// or checked here).
Status validate_predictor_checkpoint(const Ir& ir, const PredictorCheckpoint& cp,
                                     const EvalLimits& limits = {});

// Evaluates `node` (must be `Kind::Predictor`) up to `target_offset` using an
// optional earlier checkpoint `from` (`nullptr` starts at 0) and returns the
// exact state at `target_offset` without materialising output.
Result<PredictorCheckpoint> capture_predictor_checkpoint(
    const Ir& ir, u32 predictor_node, const BigInt& target_offset,
    const PredictorCheckpoint* from = nullptr, const EvalLimits& limits = {},
    EvalStats* stats = nullptr);

// ---------------------------------------------------------------------------
// Incremental SHA-256 streaming sink (E2 §5.3)
// ---------------------------------------------------------------------------

struct StreamDigest {
    BigInt bytes;
    std::array<u8, 32> sha256{};
};

// Incremental SHA-256 sink that optionally forwards every chunk to a
// downstream `Sink` (`downstream == nullptr` hashes and counts bytes with zero
// output materialisation).
class HashingSink final : public Sink {
public:
    explicit HashingSink(Sink* downstream = nullptr) noexcept;

    Status write(std::span<const u8> bytes) override;
    Result<StreamDigest> finish();

    const BigInt& bytes_written() const noexcept { return bytes_; }

private:
    Sink* downstream_ = nullptr;
    mapr::Sha256 hasher_{};
    BigInt bytes_{};
    bool finished_ = false;
};

Result<StreamDigest> eval_stream_digest(const Ir& ir,
                                        const EvalLimits& limits = {},
                                        EvalStats* stats = nullptr,
                                        Sink* downstream = nullptr);
Result<StreamDigest> eval_node_stream_digest(const Ir& ir, u32 node,
                                             const EvalLimits& limits = {},
                                             EvalStats* stats = nullptr,
                                             Sink* downstream = nullptr);
Result<StreamDigest> eval_range_digest(
    const Ir& ir, const BigInt& start, const BigInt& length,
    const EvalLimits& limits = {},
    std::span<const PredictorCheckpoint> checkpoints = {},
    EvalStats* stats = nullptr, Sink* downstream = nullptr);

// ---------------------------------------------------------------------------
// Extended one-shot evaluation entry points
// ---------------------------------------------------------------------------

Status eval_stream_ex(const Ir& ir, Sink& sink, const EvalLimits& limits = {},
                      EvalStats* stats = nullptr);
Status eval_node_stream_ex(const Ir& ir, u32 node, Sink& sink,
                           const EvalLimits& limits = {}, EvalStats* stats = nullptr);
Status eval_range_ex(const Ir& ir, const BigInt& start, const BigInt& length,
                     Sink& sink, const EvalLimits& limits = {},
                     std::span<const PredictorCheckpoint> checkpoints = {},
                     EvalStats* stats = nullptr);
Result<std::size_t> read_range_ex(
    const Ir& ir, u32 node, const BigInt& start, std::span<u8> out,
    const EvalLimits& limits = {},
    std::span<const PredictorCheckpoint> checkpoints = {},
    EvalStats* stats = nullptr);

// ---------------------------------------------------------------------------
// PreparedEval — pre-validated, immutable, reentrant evaluation plan
// ---------------------------------------------------------------------------

// Validates `WF(ir)`, recomputes exact structural lengths, and builds `O(log k)`
// cumulative offset tables for wide `Concat` nodes once, allowing repeated
// range/stream queries without repeating `O(|nodes|)` validation.
//
// Thread-safety / reentrancy (E2-I12): all query methods are `const` and touch
// no mutable shared state; concurrent calls on the same `PreparedEval` (and its
// underlying `const Ir&`) are completely independent.
class PreparedEval {
public:
    static Result<PreparedEval> prepare(const Ir& ir, const EvalLimits& limits = {});

    PreparedEval() noexcept;
    ~PreparedEval();
    PreparedEval(PreparedEval&&) noexcept;
    PreparedEval& operator=(PreparedEval&&) noexcept;
    PreparedEval(const PreparedEval&) = delete;
    PreparedEval& operator=(const PreparedEval&) = delete;

    const Ir& ir() const noexcept;
    const EvalLimits& limits() const noexcept;
    Result<BigInt> node_length(u32 node) const;
    const BigInt& total_length() const noexcept;

    Result<std::size_t> read_range(
        u32 node, const BigInt& start, std::span<u8> out,
        std::span<const PredictorCheckpoint> checkpoints = {},
        EvalStats* stats = nullptr) const;

    Status eval_stream(Sink& sink, EvalStats* stats = nullptr) const;
    Status eval_node_stream(u32 node, Sink& sink, EvalStats* stats = nullptr) const;

    Status eval_range(
        const BigInt& start, const BigInt& length, Sink& sink,
        std::span<const PredictorCheckpoint> checkpoints = {},
        EvalStats* stats = nullptr) const;

    Result<PredictorCheckpoint> capture_checkpoint(
        u32 predictor_node, const BigInt& target_offset,
        const PredictorCheckpoint* from = nullptr,
        EvalStats* stats = nullptr) const;

private:
    struct Impl;
    explicit PreparedEval(std::unique_ptr<Impl> impl) noexcept;
    std::unique_ptr<Impl> impl_;
};

// ---------------------------------------------------------------------------
// Internal shared evaluation core (`e2_term.cpp` <-> `e2_eval.cpp`)
// ---------------------------------------------------------------------------
namespace detail {

struct EvalPlanData {
    const Ir* ir = nullptr;
    EvalLimits limits{};
    std::vector<BigInt> lengths;
    // For Concat nodes with args.size() >= kConcatBinarySearchMinArgs,
    // `concat_cum[node_id]` holds `args.size() + 1` cumulative lengths
    // `[0, len(c0), len(c0)+len(c1), ...]`.  Empty for all other nodes.
    std::vector<std::vector<BigInt>> concat_cum;
};

struct StreamSession;

Result<EvalPlanData> build_eval_plan(const Ir& ir, const EvalLimits& limits,
                                     bool full_wf, u32 subterm_root);

Status validate_checkpoint_against_plan(const EvalPlanData& plan,
                                        const PredictorCheckpoint& cp);

std::unique_ptr<StreamSession> make_stream_session(
    const EvalPlanData& plan,
    std::span<const PredictorCheckpoint> checkpoints,
    Status& out_status);

// Evaluates `[start, start + out.size())` of `node_id` using explicit stack and
// `session` state (pass `session == nullptr` to create a call-local session).
Status eval_range_with_plan(
    const EvalPlanData& plan, u32 node_id, const BigInt& start, std::span<u8> out,
    StreamSession* session, std::span<const PredictorCheckpoint> checkpoints,
    EvalStats* stats);

Status stream_range_to_sink(
    const EvalPlanData& plan, u32 node_id, const BigInt& start, const BigInt& length,
    Sink& sink, std::span<const PredictorCheckpoint> checkpoints, EvalStats* stats);

Result<PredictorCheckpoint> capture_checkpoint_with_plan(
    const EvalPlanData& plan, u32 predictor_node, const BigInt& target_offset,
    const PredictorCheckpoint* from, EvalStats* stats);

}  // namespace detail

}  // namespace marp::v2
