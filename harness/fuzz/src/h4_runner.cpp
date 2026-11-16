// MARP v2 — H4 FUZZ — campaign runner.
//
// One mutant is executed as:
//
//   validate(Source)            the verify path (E3 §5.1, all 11 stages)
//   decode(Source, Arena)       the decode path
//   encode(decode(...))         the canonicality check of a decode success
//
// and classified as exactly one of
//
//   valid             both surfaces accepted and the decoded `Ir` re-encodes to
//                     the mutant byte-for-byte (a genuinely canonical wire);
//   accepted_invalid  one surface accepted what the other rejected, or an
//                     accepted mutant is not a canonical wire;
//   rejected          both surfaces rejected it.
//
// A mutant that exceeds the per-mutant time bound is a timeout; a worker
// process that dies abnormally is a crash.  Both are measured, never assumed.
//
// §12.8 asks for a bounded campaign, so the index space is split into
// contiguous shards only for *execution*; the mutation a given index receives
// is a pure function of (campaign seed, index) and is therefore identical at
// any worker count.

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include <signal.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#include "h4_alloc_guard.hpp"
#include "h4_mutate.hpp"
#include "h4_support.hpp"
#include "marp/harness/h4_fuzz.hpp"
#include "mapr/e3/e3_wire.hpp"

namespace marp::harness {
namespace {

namespace fs = std::filesystem;
using namespace marp::v2;  // NOLINT
using h4::Mutation;

constexpr std::size_t kMaxTrackedSeeds = 64;
constexpr std::size_t kStageSlots = 13;  // Stage::None .. Stage::Eval + 1

std::size_t stage_slot(Stage stage) noexcept {
    const auto index = static_cast<std::size_t>(stage);
    return index < kStageSlots ? index : kStageSlots - 1;
}

// E3 `Source` over a seed's bytes with a sparse, bounded edit map.  Reading
// never copies the seed; only the bytes a mutation actually changed come from
// the edit map.  `size_` may be smaller than the seed (truncation).
class PatchedSource final : public Source {
public:
    PatchedSource(const std::vector<std::uint8_t>& base,
                  const std::map<std::size_t, std::uint8_t>& changes,
                  std::size_t size) noexcept
        : base_(base), changes_(changes), size_(size) {}

    u64 size() const noexcept override { return static_cast<u64>(size_); }

    bool read(u64 offset, std::span<u8> dst) const override {
        const u64 n = static_cast<u64>(dst.size());
        if (offset > static_cast<u64>(size_) || n > static_cast<u64>(size_) - offset) {
            return false;
        }
        const std::size_t at = static_cast<std::size_t>(offset);
        const std::size_t count = dst.size();
        const std::size_t from_base = at < base_.size() ? base_.size() - at : 0;
        const std::size_t copied = std::min(count, from_base);
        if (copied > 0) {
            std::memcpy(dst.data(), base_.data() + at, copied);
        }
        if (copied < count) {
            std::memset(dst.data() + copied, 0, count - copied);
        }
        auto it = changes_.lower_bound(at);
        const std::size_t end = at + count;
        for (; it != changes_.end() && it->first < end; ++it) {
            dst[it->first - at] = it->second;
        }
        return true;
    }

private:
    const std::vector<std::uint8_t>& base_;
    const std::map<std::size_t, std::uint8_t>& changes_;
    std::size_t size_;
};

bool source_matches(const Source& source, const std::vector<std::uint8_t>& bytes) {
    if (source.size() != static_cast<u64>(bytes.size())) return false;
    std::array<std::uint8_t, 8192> buffer{};
    u64 offset = 0;
    while (offset < source.size()) {
        const std::size_t n = static_cast<std::size_t>(
            std::min<u64>(static_cast<u64>(buffer.size()), source.size() - offset));
        if (!source.read(offset, std::span<u8>(buffer.data(), n))) return false;
        if (std::memcmp(buffer.data(), bytes.data() + offset, n) != 0) return false;
        offset += static_cast<u64>(n);
    }
    return true;
}

enum class FailureKind : std::uint64_t {
    None = 0,
    VerifyAcceptedDecodeRejected = 1,
    DecodeAcceptedVerifyRejected = 2,
    NonCanonicalAccepted = 3,
    AllocationBudget = 4,
    Timeout = 5,
    Crash = 6,
};

const char* failure_kind_name(FailureKind kind) noexcept {
    switch (kind) {
        case FailureKind::None: return "none";
        case FailureKind::VerifyAcceptedDecodeRejected: return "verify-accepted-decode-rejected";
        case FailureKind::DecodeAcceptedVerifyRejected: return "decode-accepted-verify-rejected";
        case FailureKind::NonCanonicalAccepted: return "non-canonical-accepted";
        case FailureKind::AllocationBudget: return "allocation-budget-exceeded";
        case FailureKind::Timeout: return "timeout";
        case FailureKind::Crash: return "crash";
    }
    return "unknown";
}

struct OneOutcome {
    bool verified = false;
    bool decoded = false;
    bool accepted_invalid = false;
    bool valid = false;
    bool fixpoint_mismatch = false;
    bool alloc_violation = false;
    Stage validate_stage = Stage::None;
    Stage decode_stage = Stage::None;
    MutationClass cls = MutationClass::BitFlip;
    std::size_t seed_index = 0;
    bool touched_header = false;
    bool touched_index = false;
    bool touched_trailer = false;
    bool touched_body = false;
    u64 peak_alloc = 0;
    u64 elapsed_us = 0;
    FailureKind failure = FailureKind::None;
};

OneOutcome run_one(const std::vector<SeedInfo>& seeds, const FuzzConfig& config, u64 index) {
    OneOutcome outcome;
    const std::size_t seed_index = static_cast<std::size_t>(index % static_cast<u64>(seeds.size()));
    const MutationClass cls =
        static_cast<MutationClass>((index / static_cast<u64>(seeds.size())) % 4ull);
    const SeedInfo& seed = seeds[seed_index];
    outcome.seed_index = seed_index;
    outcome.cls = cls;

    const Mutation mutation =
        h4::plan_mutation(seed, seed_index, cls, index, config.seed);
    outcome.touched_header = mutation.touched_header;
    outcome.touched_index = mutation.touched_index;
    outcome.touched_trailer = mutation.touched_trailer;
    outcome.touched_body = mutation.touched_body;

    const std::size_t mutant_size = mutation.size;
    const u64 budget = static_cast<u64>(mutant_size) + config.alloc_budget_bytes;

    // A repaired mutant needs its whole image (the CRCs cover it).  Everything
    // else is served virtually, so a 3 MiB seed costs no per-mutant copy.
    std::vector<std::uint8_t> repaired;
    PatchedSource patched(seed.wire, mutation.changes, mutant_size);
    std::optional<SpanSource> span_source;
    Source* source = &patched;
    if (mutation.repair_outer_crcs) {
        repaired = h4::materialize(seed.wire, mutation);
        span_source.emplace(std::span<const u8>(repaired.data(), repaired.size()));
        source = &span_source.value();
    }

    const auto started = std::chrono::steady_clock::now();
    h4::alloc_guard::begin(static_cast<std::size_t>(budget));
    {
        WireLimits limits;
        const WireResult<Validation> validated = validate(*source, limits);
        outcome.verified = validated.ok();
        if (!validated.ok()) outcome.validate_stage = validated.error().stage;

        HeapArena arena(limits.arena_capacity_bytes);
        WireResult<Ir> decoded = decode(*source, arena, limits);
        outcome.decoded = decoded.ok();
        if (!decoded.ok()) outcome.decode_stage = decoded.error().stage;

        if (outcome.verified && decoded.ok()) {
            if (config.verify_fixpoint) {
                const WireResult<std::vector<u8>> reencoded = encode(decoded.value(), limits);
                if (!reencoded.ok() || !source_matches(*source, reencoded.value())) {
                    outcome.accepted_invalid = true;
                    outcome.fixpoint_mismatch = true;
                    outcome.failure = FailureKind::NonCanonicalAccepted;
                } else {
                    outcome.valid = true;
                }
            } else {
                outcome.valid = true;
            }
        } else if (outcome.verified != outcome.decoded) {
            // One surface accepted a container the other rejected.  Whichever
            // direction it goes, "accepted invalid" is exactly this case.
            outcome.accepted_invalid = true;

        outcome.failure = outcome.verified ? FailureKind::VerifyAcceptedDecodeRejected
                                               : FailureKind::DecodeAcceptedVerifyRejected;
        }
    }
    outcome.peak_alloc = static_cast<u64>(h4::alloc_guard::peak_bytes());
    outcome.alloc_violation = h4::alloc_guard::violated();
    h4::alloc_guard::end();
    outcome.elapsed_us = static_cast<u64>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - started)
            .count());
    if (outcome.alloc_violation) {
        outcome.failure = FailureKind::AllocationBudget;
    } else if (outcome.elapsed_us > static_cast<u64>(config.per_mutant_timeout_ms) * 1000ull) {
        // The mutant returned, but outside its budget: a timeout whether or not
        // it eventually produced a verdict.
        outcome.failure = FailureKind::Timeout;
    }
    return outcome;
}

// ---------------------------------------------------------------------------
// Shared per-shard counters (process-shared; each shard writes only its slot)
// ---------------------------------------------------------------------------

void atomic_max(std::atomic<u64>& target, u64 value) noexcept {
    u64 current = target.load(std::memory_order_relaxed);
    while (current < value &&
           !target.compare_exchange_weak(current, value, std::memory_order_relaxed)) {
    }
}

struct ShardCounters {
    std::atomic<u64> current{0};  // index + 1 of the mutant being processed
    std::atomic<u64> done{0};
    std::atomic<u64> processed{0};
    std::atomic<u64> accepted_invalid{0};
    std::atomic<u64> valid{0};
    std::atomic<u64> rejected{0};
    std::atomic<u64> timeouts{0};
    std::atomic<u64> alloc_violations{0};
    std::atomic<u64> verified{0};
    std::atomic<u64> decode_accepted{0};
    std::atomic<u64> fixpoint_checked{0};
    std::atomic<u64> fixpoint_mismatch{0};
    std::atomic<u64> peak_alloc{0};
    std::atomic<u64> slowest_us{0};
    std::atomic<u64> by_class[4];
    std::atomic<u64> by_seed[kMaxTrackedSeeds];
    std::atomic<u64> validate_stage[kStageSlots];
    std::atomic<u64> decode_stage[kStageSlots];
    std::atomic<u64> region_header{0};
    std::atomic<u64> region_index{0};
    std::atomic<u64> region_trailer{0};
    std::atomic<u64> region_body{0};
    std::atomic<u64> first_failure_index{0};  // index + 1; 0 = none yet
    std::atomic<u64> first_failure_kind{0};
};

void note_failure(ShardCounters& counters, u64 index, FailureKind kind) noexcept {
    u64 expected = 0;
    if (counters.first_failure_index.compare_exchange_strong(
            expected, index + 1ull, std::memory_order_relaxed)) {
        counters.first_failure_kind.store(static_cast<u64>(kind), std::memory_order_relaxed);
    }
}

void record_outcome(ShardCounters& counters, u64 index, const OneOutcome& outcome) {
    counters.processed.fetch_add(1, std::memory_order_relaxed);
    counters.by_class[static_cast<std::size_t>(outcome.cls)].fetch_add(1, std::memory_order_relaxed);
    if (outcome.seed_index < kMaxTrackedSeeds) {
        counters.by_seed[outcome.seed_index].fetch_add(1, std::memory_order_relaxed);
    }
    if (outcome.touched_header) counters.region_header.fetch_add(1, std::memory_order_relaxed);
    if (outcome.touched_index) counters.region_index.fetch_add(1, std::memory_order_relaxed);
    if (outcome.touched_trailer) counters.region_trailer.fetch_add(1, std::memory_order_relaxed);
    if (outcome.touched_body) counters.region_body.fetch_add(1, std::memory_order_relaxed);
    if (outcome.verified) counters.verified.fetch_add(1, std::memory_order_relaxed);
    if (outcome.decoded) counters.decode_accepted.fetch_add(1, std::memory_order_relaxed);
    if (outcome.verified && outcome.decoded && !outcome.fixpoint_mismatch) {
        counters.fixpoint_checked.fetch_add(1, std::memory_order_relaxed);
    }
    if (outcome.fixpoint_mismatch) counters.fixpoint_mismatch.fetch_add(1, std::memory_order_relaxed);
    if (!outcome.verified) {
        counters.validate_stage[stage_slot(outcome.validate_stage)].fetch_add(
            1, std::memory_order_relaxed);
    }
    if (!outcome.decoded) {
        counters.decode_stage[stage_slot(outcome.decode_stage)].fetch_add(
            1, std::memory_order_relaxed);
    }
    if (outcome.accepted_invalid) {
        counters.accepted_invalid.fetch_add(1, std::memory_order_relaxed);
        note_failure(counters, index, outcome.failure);
    } else if (outcome.valid) {
        counters.valid.fetch_add(1, std::memory_order_relaxed);
    } else {
        counters.rejected.fetch_add(1, std::memory_order_relaxed);
    }
    if (outcome.alloc_violation) {
        counters.alloc_violations.fetch_add(1, std::memory_order_relaxed);
        note_failure(counters, index, FailureKind::AllocationBudget);
    }
    if (outcome.failure == FailureKind::Timeout) {
        counters.timeouts.fetch_add(1, std::memory_order_relaxed);
        note_failure(counters, index, FailureKind::Timeout);
    }
    atomic_max(counters.peak_alloc, outcome.peak_alloc);
    atomic_max(counters.slowest_us, outcome.elapsed_us);
}

void run_range(const std::vector<SeedInfo>& seeds, const FuzzConfig& config, u64 begin, u64 end,
               ShardCounters& counters) {
    for (u64 index = begin; index < end; ++index) {
        counters.current.store(index + 1ull, std::memory_order_relaxed);
        const OneOutcome outcome = run_one(seeds, config, index);
        record_outcome(counters, index, outcome);
    }
    counters.done.store(1, std::memory_order_relaxed);
}

// ---------------------------------------------------------------------------
// Aggregation
// ---------------------------------------------------------------------------

FuzzReport aggregate(const std::vector<ShardCounters*>& shards, u64 mutants) {
    FuzzReport report;
    report.counts.total = mutants;
    report.tally.by_seed.assign(kMaxTrackedSeeds, 0);
    u64 processed = 0;
    for (const ShardCounters* counters : shards) {
        report.counts.accepted_invalid += counters->accepted_invalid.load();
        report.counts.valid += counters->valid.load();
        report.counts.timeouts += counters->timeouts.load();
        report.tally.rejected += counters->rejected.load();
        report.tally.verified += counters->verified.load();
        report.tally.decode_accepted += counters->decode_accepted.load();
        report.tally.fixpoint_checked += counters->fixpoint_checked.load();
        report.tally.fixpoint_mismatch += counters->fixpoint_mismatch.load();
        report.tally.alloc_violations += counters->alloc_violations.load();
        report.tally.peak_alloc_bytes =
            std::max(report.tally.peak_alloc_bytes, counters->peak_alloc.load());
        report.tally.slowest_us =
            std::max(report.tally.slowest_us, counters->slowest_us.load());
        report.tally.region_header += counters->region_header.load();
        report.tally.region_index += counters->region_index.load();
        report.tally.region_trailer += counters->region_trailer.load();
        report.tally.region_body += counters->region_body.load();
        for (std::size_t i = 0; i < 4; ++i) {
            report.tally.by_class[i] += counters->by_class[i].load();
        }
        for (std::size_t i = 0; i < kMaxTrackedSeeds; ++i) {
            report.tally.by_seed[i] += counters->by_seed[i].load();
        }
        for (std::size_t i = 0; i < kStageSlots; ++i) {
            report.tally.validate_stage[i] += counters->validate_stage[i].load();
            report.tally.decode_stage[i] += counters->decode_stage[i].load();
        }
        processed += counters->processed.load();
        const u64 failure_index = counters->first_failure_index.load();
        if (failure_index != 0 &&
            (report.tally.first_failure_index == 0 ||
             failure_index - 1ull < report.tally.first_failure_index)) {
            report.tally.first_failure_index = failure_index - 1ull;
            report.tally.first_failure_kind =
                failure_kind_name(static_cast<FailureKind>(counters->first_failure_kind.load()));
        }
    }
    if (!report.tally.first_failure_kind.empty() && report.tally.first_failure_kind != "none") {
        report.tally.first_failure = report.tally.first_failure_kind + " at mutant " +
                                     std::to_string(report.tally.first_failure_index);
    }
    report.tally.processed = processed;
    report.completed = processed == mutants && report.counts.timeouts == 0 &&
                       report.counts.crashes == 0;
    return report;
}

// ---------------------------------------------------------------------------
// Process-shared counters
// ---------------------------------------------------------------------------

class SharedArena {
public:
    explicit SharedArena(std::size_t count) : count_(count) {
        const std::size_t bytes = sizeof(ShardCounters) * count;
        void* memory = ::mmap(nullptr, bytes, PROT_READ | PROT_WRITE,
                              MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        if (memory == MAP_FAILED) {
            pointer_ = nullptr;
            return;
        }
        pointer_ = memory;
        auto* raw = static_cast<unsigned char*>(pointer_);
        for (std::size_t i = 0; i < count; ++i) {
            new (raw + i * sizeof(ShardCounters)) ShardCounters();
        }
    }
    ~SharedArena() {
        if (pointer_ != nullptr) {
            ::munmap(pointer_, sizeof(ShardCounters) * count_);
        }
    }
    SharedArena(const SharedArena&) = delete;
    SharedArena& operator=(const SharedArena&) = delete;

    bool ok() const noexcept { return pointer_ != nullptr; }
    ShardCounters& at(std::size_t index) {
        return *reinterpret_cast<ShardCounters*>(
            static_cast<unsigned char*>(pointer_) + index * sizeof(ShardCounters));
    }

private:
    void* pointer_ = nullptr;
    std::size_t count_ = 0;
};

FuzzReport run_forked(const std::vector<SeedInfo>& seeds, const FuzzConfig& config) {
    const u64 mutants = config.mutants;
    std::size_t shard_count = static_cast<std::size_t>(config.workers);
    if (shard_count == 0) shard_count = 1;
    if (static_cast<u64>(shard_count) > mutants) shard_count = static_cast<std::size_t>(mutants);
    SharedArena shared(shard_count);
    if (!shared.ok()) {
        FuzzReport report;
        report.counts.total = mutants;
        report.failure = "shared counter allocation failed";
        return report;
    }

    std::vector<pid_t> pids(shard_count, 0);
    std::vector<bool> alive(shard_count, false);
    for (std::size_t shard = 0; shard < shard_count; ++shard) {
        const u64 begin = static_cast<u64>(shard) * mutants / static_cast<u64>(shard_count);
        const u64 end = static_cast<u64>(shard + 1) * mutants / static_cast<u64>(shard_count);
        const pid_t pid = ::fork();
        if (pid == 0) {
            // Child: run the shard, write only its own counters, leave without
            // running the parent's destructors or the sanitizer's leak check.
            run_range(seeds, config, begin, end, shared.at(shard));
            ::_exit(0);
        }
        if (pid < 0) {
            // A fork failure is not a reason to run unsupervised: stop here and
            // report it, because the crash/timeout accounting depends on
            // process isolation.
            for (std::size_t live = 0; live < shard; ++live) {
                if (alive[live]) ::kill(pids[live], SIGKILL);
            }
            for (std::size_t live = 0; live < shard; ++live) {
                if (!alive[live]) continue;
                int status = 0;
                while (::waitpid(pids[live], &status, 0) < 0 && errno == EINTR) {
                }
            }
            FuzzReport failed;
            failed.counts.total = mutants;
            failed.failure = "fork failed for shard " + std::to_string(shard);
            return failed;
        }
        pids[shard] = pid;
        alive[shard] = true;
    }

    const u64 timeout_us = static_cast<u64>(config.per_mutant_timeout_ms) * 1000ull;
    const u64 total_timeout_us = static_cast<u64>(config.total_timeout_ms) * 1000ull;
    const auto started = std::chrono::steady_clock::now();
    std::vector<u64> last_progress(shard_count, 0);
    std::vector<u64> last_change_us(shard_count, 0);
    std::string abort_reason;
    u64 crash_shard = 0;
    u64 crash_index = 0;
    bool aborted = false;

    auto kill_alive = [&]() {
        for (std::size_t shard = 0; shard < shard_count; ++shard) {
            if (alive[shard]) {
                ::kill(pids[shard], SIGKILL);
            }
        }
        for (std::size_t shard = 0; shard < shard_count; ++shard) {
            if (!alive[shard]) continue;
            int status = 0;
            while (::waitpid(pids[shard], &status, 0) < 0 && errno == EINTR) {
            }
            alive[shard] = false;
        }
    };

    for (;;) {
        const u64 now_us = static_cast<u64>(
            std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - started)
                .count());
        bool any_alive = false;
        for (std::size_t shard = 0; shard < shard_count; ++shard) {
            if (!alive[shard]) continue;
            any_alive = true;
            if (shared.at(shard).done.load(std::memory_order_relaxed) != 0) continue;
            const u64 progress = shared.at(shard).current.load(std::memory_order_relaxed);
            if (progress != last_progress[shard]) {
                last_progress[shard] = progress;
                last_change_us[shard] = now_us;
            } else if (progress != 0 && now_us > last_change_us[shard] &&
                       now_us - last_change_us[shard] > timeout_us) {
                aborted = true;
                abort_reason = "timeout at mutant " +
                               std::to_string(progress - 1ull) + " (shard " +
                               std::to_string(shard) + ")";
                shared.at(shard).timeouts.fetch_add(1);
                note_failure(shared.at(shard), progress - 1ull, FailureKind::Timeout);
            }
        }
        for (;;) {
            int status = 0;
            const pid_t reaped = ::waitpid(-1, &status, WNOHANG);
            if (reaped <= 0) break;
            for (std::size_t shard = 0; shard < shard_count; ++shard) {
                if (pids[shard] != reaped || !alive[shard]) continue;
                alive[shard] = false;
                const bool exited_ok = WIFEXITED(status) && WEXITSTATUS(status) == 0;
                if (!exited_ok) {
                    aborted = true;
                    crash_shard = static_cast<u64>(shard);
                    const u64 progress =
                        shared.at(shard).current.load(std::memory_order_relaxed);
                    crash_index = progress > 0 ? progress - 1ull : 0;
                    abort_reason = "crash (worker death) at mutant " +
                                   std::to_string(crash_index) + " (shard " +
                                   std::to_string(shard) + ")";
                    shared.at(shard).done.store(0);
                }
            }
        }
        if (!any_alive) break;
        if (aborted) {
            kill_alive();
            break;
        }
        if (now_us > total_timeout_us) {
            aborted = true;
            abort_reason = "campaign exceeded its total time bound of " +
                           std::to_string(config.total_timeout_ms) + " ms";
            break;
        }
        ::usleep(20'000);
    }
    if (aborted) {
        kill_alive();
    }

    std::vector<ShardCounters*> pointers;
    pointers.reserve(shard_count);
    for (std::size_t shard = 0; shard < shard_count; ++shard) {
        pointers.push_back(&shared.at(shard));
    }
    FuzzReport report = aggregate(pointers, mutants);

    if (aborted) {
        report.completed = false;
        if (abort_reason.rfind("crash", 0) == 0) {
            report.counts.crashes += 1;
            report.tally.first_failure = abort_reason;
            report.tally.first_failure_kind = failure_kind_name(FailureKind::Crash);
            report.tally.first_failure_index = crash_index;
            (void)crash_shard;
        } else {
            report.tally.first_failure = abort_reason;
            report.tally.first_failure_kind = failure_kind_name(FailureKind::Timeout);
        }
        report.failure = abort_reason;
    }

    // Every mutant must be accounted for: a clean campaign's verdicts equal the
    // campaign size.  (A crash loses the rest of its shard, which is precisely
    // why a crash is a hard failure.)
    if (!report.completed || report.tally.processed != mutants) {
        report.completed = false;
        if (report.failure.empty()) {
            report.failure = "accounting mismatch: " + std::to_string(report.tally.processed) +
                             " of " + std::to_string(mutants) + " mutants reached a verdict";
        }
    }
    return report;
}

FuzzReport run_in_process(const std::vector<SeedInfo>& seeds, const FuzzConfig& config) {
    ShardCounters counters;
    run_range(seeds, config, 0, config.mutants, counters);
    FuzzReport report = aggregate({&counters}, config.mutants);
    if (report.tally.processed != config.mutants) {
        report.completed = false;
        report.failure = "accounting mismatch: " + std::to_string(report.tally.processed) +
                         " of " + std::to_string(config.mutants) + " mutants reached a verdict";
    }
    return report;
}

}  // namespace

// ---------------------------------------------------------------------------
// Public surface
// ---------------------------------------------------------------------------

bool targets_met(const FuzzCounts& counts) noexcept {
    return counts.total == 100'000ull && counts.accepted_invalid == 0 && counts.crashes == 0 &&
           counts.timeouts == 0;
}

bool FuzzTally::clean() const noexcept {
    return first_failure.empty() && alloc_violations == 0 && fixpoint_mismatch == 0;
}

bool FuzzReport::targets_met() const noexcept {
    return marp::harness::targets_met(counts) && completed && tally.processed == counts.total;
}

FuzzReport run_fuzz(const std::vector<SeedInfo>& seeds, const FuzzConfig& config) {
    FuzzReport report;
    report.counts.total = config.mutants;
    if (seeds.empty()) {
        report.failure = "no seeds";
        return report;
    }
    if (seeds.size() > kMaxTrackedSeeds) {
        report.failure = "more seeds than the tally can track";
        return report;
    }
    if (config.mutants == 0) {
        report.failure = "campaign size is zero";
        return report;
    }
    if (config.fork_workers && config.workers > 1) {
        return run_forked(seeds, config);
    }
    return run_in_process(seeds, config);
}

FuzzCounts fuzz(const std::filesystem::path& seeds, u64 mutants, u64 seed) {
    const std::vector<SeedInfo> loaded = load_seeds(seeds);
    FuzzConfig config;
    config.mutants = mutants;
    config.seed = seed;
    config.workers = 1;
    config.fork_workers = false;
    return run_fuzz(loaded, config).counts;
}

std::vector<SeedInfo> load_seeds(const std::filesystem::path& dir) {
    std::vector<SeedInfo> seeds;
    std::error_code error;
    if (!fs::is_directory(dir, error)) return seeds;
    std::vector<fs::path> paths;
    for (const auto& entry : fs::directory_iterator(dir, error)) {
        if (!entry.is_regular_file()) continue;
        if (entry.path().extension() != ".wire") continue;
        paths.push_back(entry.path());
    }
    if (error) return seeds;
    std::sort(paths.begin(), paths.end());
    for (const fs::path& path : paths) {
        SeedInfo seed;
        if (!h4::read_file(path, seed.wire)) continue;
        seed.id = path.stem().string();
        seed.sha256 = h4::sha256_hex(seed.wire);
        if (seed.wire.size() >= static_cast<std::size_t>(kWireMinContainerBytes)) {
            const std::uint32_t flags = static_cast<std::uint32_t>(seed.wire[kHdrOffFlags]) |
                                        (static_cast<std::uint32_t>(seed.wire[kHdrOffFlags + 1]) << 8) |
                                        (static_cast<std::uint32_t>(seed.wire[kHdrOffFlags + 2]) << 16) |
                                        (static_cast<std::uint32_t>(seed.wire[kHdrOffFlags + 3]) << 24);
            seed.index_present = (flags & kWireFlagIndexPresent) != 0;
        }
        seed.large = seed.wire.size() > 65536;
        seed.source = "seed-dir";
        seeds.push_back(std::move(seed));
    }
    return seeds;
}

}  // namespace marp::harness
