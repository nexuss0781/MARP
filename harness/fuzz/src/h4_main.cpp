// MARP v2 — H4 FUZZ — command line driver.
//
// The driver never measures anything itself: it builds/verifies the E3 seeds,
// runs the worker-count determinism campaign, runs the authoritative campaign,
// and asks the evidence writer to render what was measured.  `RESULT: PASS` is
// printed only when the §12.8 targets hold, the prerequisite E3-G evidence is
// green, the determinism comparison is exact, and every mutant reached a
// verdict.

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <filesystem>
#include <string>
#include <vector>

#include "h4_evidence.hpp"
#include "h4_seeds.hpp"
#include "h4_selftest.hpp"
#include "h4_support.hpp"
#include "h4_alloc_guard.hpp"
#include "marp/harness/h4_fuzz.hpp"

namespace fs = std::filesystem;
using marp::harness::FuzzConfig;
using marp::harness::FuzzReport;
using marp::harness::SeedInfo;

namespace {

void usage(const char* program) {
    std::fprintf(stderr,
                 "usage: %s [--root DIR] [--seed-dir DIR] [--mutants N] [--seed U64]\n"
                 "          [--workers N] [--per-mutant-timeout-ms N]\n"
                 "          [--alloc-budget-bytes N] [--dry-run-mutants N]\n"
                 "          [--no-fork] [--no-prereq] [--write-evidence]\n"
                 "          [--print-seeds] [--self-test] [--help]\n",
                 program);
}

bool parse_u64(const char* text, std::uint64_t& value) {
    if (text == nullptr || *text == '\0') return false;
    char* end = nullptr;
    const unsigned long long parsed = std::strtoull(text, &end, 0);
    if (end == text || *end != '\0') return false;
    value = static_cast<std::uint64_t>(parsed);
    return true;
}

bool same_tally(const FuzzReport& a, const FuzzReport& b) {
    if (a.completed != b.completed) return false;
    if (a.counts.total != b.counts.total || a.counts.accepted_invalid != b.counts.accepted_invalid ||
        a.counts.crashes != b.counts.crashes || a.counts.timeouts != b.counts.timeouts ||
        a.counts.valid != b.counts.valid) {
        return false;
    }
    if (a.tally.processed != b.tally.processed || a.tally.rejected != b.tally.rejected ||
        a.tally.verified != b.tally.verified ||
        a.tally.decode_accepted != b.tally.decode_accepted ||
        a.tally.fixpoint_checked != b.tally.fixpoint_checked ||
        a.tally.fixpoint_mismatch != b.tally.fixpoint_mismatch ||
        a.tally.alloc_violations != b.tally.alloc_violations ||
        a.tally.peak_alloc_bytes != b.tally.peak_alloc_bytes ||
        a.tally.region_header != b.tally.region_header ||
        a.tally.region_index != b.tally.region_index ||
        a.tally.region_trailer != b.tally.region_trailer ||
        a.tally.region_body != b.tally.region_body ||
        a.tally.first_failure_index != b.tally.first_failure_index ||
        a.tally.first_failure_kind != b.tally.first_failure_kind) {
        return false;
    }
    for (std::size_t i = 0; i < 4; ++i) {
        if (a.tally.by_class[i] != b.tally.by_class[i]) return false;
    }
    for (std::size_t i = 0; i < 13; ++i) {
        if (a.tally.validate_stage[i] != b.tally.validate_stage[i]) return false;
        if (a.tally.decode_stage[i] != b.tally.decode_stage[i]) return false;
    }
    for (std::size_t i = 0; i < a.tally.by_seed.size() && i < b.tally.by_seed.size(); ++i) {
        if (a.tally.by_seed[i] != b.tally.by_seed[i]) return false;
    }
    return true;
}

bool campaign_clean(const FuzzReport& report, std::uint64_t want_total) {
    return report.completed && report.counts.total == want_total &&
           report.counts.accepted_invalid == 0 && report.counts.crashes == 0 &&
           report.counts.timeouts == 0 && report.tally.processed == want_total &&
           report.tally.alloc_violations == 0 && report.tally.fixpoint_mismatch == 0;
}

void print_campaign(const char* label, const FuzzReport& report) {
    std::printf("  %s: total=%llu valid=%llu accepted_invalid=%llu crashes=%llu timeouts=%llu"
                " rejected=%llu processed=%llu\n",
                label, static_cast<unsigned long long>(report.counts.total),
                static_cast<unsigned long long>(report.counts.valid),
                static_cast<unsigned long long>(report.counts.accepted_invalid),
                static_cast<unsigned long long>(report.counts.crashes),
                static_cast<unsigned long long>(report.counts.timeouts),
                static_cast<unsigned long long>(report.tally.rejected),
                static_cast<unsigned long long>(report.tally.processed));
    std::printf("  %s: class mix bitflip=%llu truncation=%llu fieldswap=%llu"
                " lengthcorruption=%llu\n",
                label, static_cast<unsigned long long>(report.tally.by_class[0]),
                static_cast<unsigned long long>(report.tally.by_class[1]),
                static_cast<unsigned long long>(report.tally.by_class[2]),
                static_cast<unsigned long long>(report.tally.by_class[3]));
    if (!report.tally.first_failure.empty()) {
        std::printf("  %s: first failure: %s\n", label, report.tally.first_failure.c_str());
    }
    if (!report.failure.empty()) {
        std::printf("  %s: failure: %s\n", label, report.failure.c_str());
    }
}

}  // namespace

int main(int argc, char** argv) {
    fs::path root = "..";
    fs::path seed_dir;
    std::uint64_t mutant_count = 100'000;
    std::uint64_t campaign_seed = 0x4834'4655'5A5Aull;
    std::uint64_t dry_mutants = 3'000;
    FuzzConfig config;
    bool require_prereq = true;
    bool fork_workers = true;
    bool write_evidence_flag = false;
    bool print_seeds = false;
    bool self_test = false;

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        auto next = [&](std::uint64_t& value) {
            return i + 1 < argc && parse_u64(argv[++i], value);
        };
        try {
            if (arg == "--root" && i + 1 < argc) {
                root = argv[++i];
            } else if (arg == "--seed-dir" && i + 1 < argc) {
                seed_dir = argv[++i];
            } else if (arg == "--mutants") {
                if (!next(mutant_count)) throw std::invalid_argument("bad --mutants");
                config.mutants = mutant_count;
            } else if (arg == "--seed") {
                if (!next(campaign_seed)) throw std::invalid_argument("bad --seed");
                config.seed = campaign_seed;
            } else if (arg == "--dry-run-mutants") {
                if (!next(dry_mutants)) throw std::invalid_argument("bad --dry-run-mutants");
            } else if (arg == "--workers") {
                std::uint64_t workers = 0;
                if (!next(workers) || workers == 0 || workers > 256) {
                    throw std::invalid_argument("bad --workers");
                }
                config.workers = static_cast<unsigned>(workers);
            } else if (arg == "--per-mutant-timeout-ms") {
                std::uint64_t value = 0;
                if (!next(value) || value == 0) throw std::invalid_argument("bad timeout");
                config.per_mutant_timeout_ms = static_cast<unsigned long>(value);
            } else if (arg == "--alloc-budget-bytes") {
                std::uint64_t value = 0;
                if (!next(value)) throw std::invalid_argument("bad alloc budget");
                config.alloc_budget_bytes = value;
            } else if (arg == "--no-fork") {
                fork_workers = false;
            } else if (arg == "--no-prereq") {
                require_prereq = false;
            } else if (arg == "--write-evidence") {
                write_evidence_flag = true;
            } else if (arg == "--print-seeds") {
                print_seeds = true;
            } else if (arg == "--self-test") {
                self_test = true;
            } else if (arg == "--help") {
                usage(argv[0]);
                return 0;
            } else {
                std::fprintf(stderr, "unknown option: %s\n", arg.c_str());
                usage(argv[0]);
                return 1;
            }
        } catch (const std::exception& error) {
            std::fprintf(stderr, "%s\n", error.what());
            return 1;
        }
    }

    if (seed_dir.empty()) seed_dir = root / "engine" / "obj" / "h4" / "seeds";
    config.mutants = mutant_count;
    config.seed = campaign_seed;
    config.fork_workers = fork_workers && config.workers > 1;

    if (self_test) {
        return marp::harness::h4::run_self_test(root, seed_dir);
    }

    const marp::harness::h4::Prereq prereq = marp::harness::h4::check_prerequisite(root);
    if (require_prereq && !prereq.ok) {
        std::fprintf(stderr, "BLOCKED: %s\n", prereq.failure.c_str());
        std::fprintf(stderr,
                     "H4 is blocked on E3-G: no campaign result may be claimed without green"
                     " E3-G gate evidence.\n");
        return 4;
    }
    std::printf("E3-G prerequisite: %s (gate sha256=%s, rows=%zu, fail=%zu, blocked=%zu)\n",
                prereq.ok ? "PASS" : "NOT CHECKED", prereq.gate_sha256.c_str(), prereq.gate_rows,
                prereq.gate_fail, prereq.gate_blocked);

    const marp::harness::h4::SeedBuild build = marp::harness::h4::build_seeds(root);
    if (!build.ok) {
        std::fprintf(stderr, "FAIL: %s\n", build.failure.c_str());
        return 1;
    }
    std::printf("seeds: %zu canonical E3-G wires, set sha256=%s\n", build.seeds.size(),
                marp::harness::h4::seeds_sha256_set(build.seeds).c_str());
    if (print_seeds) {
        std::fputs(marp::harness::h4::seeds_manifest(build.seeds).c_str(), stdout);
        return 0;
    }
    std::string why;
    if (!marp::harness::h4::write_seed_dir(seed_dir, build.seeds, why)) {
        std::fprintf(stderr, "FAIL: %s\n", why.c_str());
        return 1;
    }

    // ---- worker-count determinism on a bounded dry run -------------------
    FuzzConfig dry_one = config;
    dry_one.mutants = dry_mutants;
    dry_one.workers = 1;
    dry_one.fork_workers = false;
    const FuzzReport dry_at_one = marp::harness::run_fuzz(build.seeds, dry_one);
    FuzzConfig dry_many = config;
    dry_many.mutants = dry_mutants;
    const FuzzReport dry_at_many = marp::harness::run_fuzz(build.seeds, dry_many);
    const bool determinism_equal = same_tally(dry_at_one, dry_at_many);
    std::printf("determinism: dry run %llu mutants, workers 1 vs %u -> %s\n",
                static_cast<unsigned long long>(dry_mutants), config.workers,
                determinism_equal ? "identical" : "DIFFERS");
    print_campaign("workers=1", dry_at_one);
    print_campaign("workers>1", dry_at_many);

    // ---- authoritative campaign -----------------------------------------
    const FuzzReport campaign = marp::harness::run_fuzz(build.seeds, config);
    std::printf("campaign: %llu mutants, workers=%u, timeout=%lu ms, alloc budget=%llu bytes\n",
                static_cast<unsigned long long>(config.mutants), config.workers,
                config.per_mutant_timeout_ms,
                static_cast<unsigned long long>(config.alloc_budget_bytes));
    print_campaign("campaign", campaign);
    std::printf("campaign: stages distinct=%zu, regions header=%llu index=%llu trailer=%llu"
                " body=%llu, fixpoint checked=%llu mismatch=%llu, peak alloc=%llu\n",
                static_cast<std::size_t>([&campaign]() {
                    std::size_t covered = 0;
                    for (std::size_t i = 1; i < 13; ++i) {
                        if (campaign.tally.validate_stage[i] > 0) ++covered;
                    }
                    return covered;
                }()),
                static_cast<unsigned long long>(campaign.tally.region_header),
                static_cast<unsigned long long>(campaign.tally.region_index),
                static_cast<unsigned long long>(campaign.tally.region_trailer),
                static_cast<unsigned long long>(campaign.tally.region_body),
                static_cast<unsigned long long>(campaign.tally.fixpoint_checked),
                static_cast<unsigned long long>(campaign.tally.fixpoint_mismatch),
                static_cast<unsigned long long>(campaign.tally.peak_alloc_bytes));

    if (write_evidence_flag) {
        marp::harness::h4::EvidenceInput input;
        input.prereq = &prereq;
        input.seeds = &build;
        input.campaign = &campaign;
        input.workers_one = &dry_at_one;
        input.workers_many = &dry_at_many;
        input.config = &config;
        input.dry_mutants = dry_mutants;
        input.determinism_equal = determinism_equal;
        input.alloc_guard_enabled = marp::harness::h4::alloc_guard::enabled();
        std::error_code error;
        const fs::path relative = fs::relative(seed_dir, root, error);
        input.seed_dir = error ? seed_dir.generic_string() : relative.generic_string();
        if (!marp::harness::h4::write_evidence(root, input, why)) {
            std::fprintf(stderr, "FAIL: %s\n", why.c_str());
            return 1;
        }
        std::printf("evidence: specs_and_reports/v2/gates/H4-FUZZ.tsv, "
                    "logs/H4-FUZZ.log, corpus/H4/*, evidence/H4/*\n");
    }

    const bool clean = campaign_clean(campaign, config.mutants);
    const bool verdict = clean && prereq.ok && determinism_equal;
    std::printf("RESULT: %s\n", verdict ? "PASS" : "FAIL");
    if (!verdict) {
        if (!campaign.completed) std::fprintf(stderr, "campaign did not complete: %s\n",
                                              campaign.failure.c_str());
        if (campaign.counts.accepted_invalid != 0)
            std::fprintf(stderr, "accepted_invalid=%llu\n",
                         static_cast<unsigned long long>(campaign.counts.accepted_invalid));
        if (campaign.counts.crashes != 0)
            std::fprintf(stderr, "crashes=%llu\n",
                         static_cast<unsigned long long>(campaign.counts.crashes));
        if (campaign.counts.timeouts != 0)
            std::fprintf(stderr, "timeouts=%llu\n",
                         static_cast<unsigned long long>(campaign.counts.timeouts));
        if (!prereq.ok) std::fprintf(stderr, "prerequisite: %s\n", prereq.failure.c_str());
        if (!determinism_equal) std::fprintf(stderr, "worker-count determinism differs\n");
        return 1;
    }
    return 0;
}
