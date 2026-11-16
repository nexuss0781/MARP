// MARP v2 — H4 FUZZ — deterministic self-checks.

#include "h4_selftest.hpp"

#include <array>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <string>
#include <vector>

#include "h4_evidence.hpp"
#include "h4_mutate.hpp"
#include "h4_seeds.hpp"
#include "h4_support.hpp"
#include "marp/harness/h4_fuzz.hpp"

namespace marp::harness::h4 {
namespace {

namespace fs = std::filesystem;

std::size_t g_failures = 0;

void check(bool condition, const std::string& what) {
    std::printf("%s %s\n", condition ? "PASS" : "FAIL", what.c_str());
    if (!condition) ++g_failures;
}

bool same_plan(const Mutation& a, const Mutation& b) {
    if (a.size != b.size || a.repair_outer_crcs != b.repair_outer_crcs || a.changes != b.changes) {
        return false;
    }
    return a.touched_header == b.touched_header && a.touched_index == b.touched_index &&
           a.touched_trailer == b.touched_trailer && a.touched_body == b.touched_body;
}

bool same_tally(const FuzzReport& a, const FuzzReport& b) {
    if (a.counts.total != b.counts.total || a.counts.accepted_invalid != b.counts.accepted_invalid ||
        a.counts.crashes != b.counts.crashes || a.counts.timeouts != b.counts.timeouts ||
        a.counts.valid != b.counts.valid || a.completed != b.completed ||
        a.tally.processed != b.tally.processed || a.tally.rejected != b.tally.rejected ||
        a.tally.verified != b.tally.verified || a.tally.decode_accepted != b.tally.decode_accepted ||
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
    if (a.tally.by_seed.size() != b.tally.by_seed.size()) return false;
    for (std::size_t i = 0; i < a.tally.by_seed.size(); ++i) {
        if (a.tally.by_seed[i] != b.tally.by_seed[i]) return false;
    }
    return true;
}

std::vector<std::string> split_tabs(const std::string& line) {
    std::vector<std::string> fields;
    std::size_t start = 0;
    for (std::size_t i = 0; i <= line.size(); ++i) {
        if (i == line.size() || line[i] == '\t') {
            fields.push_back(line.substr(start, i - start));
            start = i + 1;
        }
    }
    return fields;
}

bool gate_verdict_is_pass(const std::string& tsv) {
    std::size_t start = 0;
    while (start < tsv.size()) {
        const std::size_t end = tsv.find('\n', start);
        const std::string line = tsv.substr(start, end == std::string::npos ? std::string::npos
                                                                           : end - start);
        if (line.rfind("h4.verdict\t", 0) == 0) {
            const std::vector<std::string> fields = split_tabs(line);
            return fields.size() == 8 && fields[6] == "PASS";
        }
        if (end == std::string::npos) break;
        start = end + 1;
    }
    return false;
}

}  // namespace

int run_self_test(const fs::path& root, const fs::path& seed_dir) {
    g_failures = 0;
    std::printf("# H4 FUZZ self-test\n");

    const Prereq prereq = check_prerequisite(root);
    check(prereq.ok, "E3-G prerequisite evidence is green" +
                        (prereq.ok ? std::string() : ": " + prereq.failure));
    check(prereq.gate_rows > 0 && prereq.gate_fail == 0 && prereq.gate_blocked == 0,
          "E3-G gate evidence carries no FAIL/BLOCKED row");

    const SeedBuild build = build_seeds(root);
    check(build.ok, "E3 seeds regenerate their committed E3-G identities" +
                        (build.ok ? std::string() : ": " + build.failure));
    check(build.seeds.size() == 15, "seed catalog is complete (15 seeds)");
    std::size_t large = 0;
    std::size_t index_present = 0;
    for (const SeedInfo& seed : build.seeds) {
        if (seed.large) ++large;
        if (seed.index_present) ++index_present;
    }
    check(large == 3, "three large seeds are present");
    check(index_present >= 2, "large index-bearing seeds are present");

    // ---- seed directory round trip ----------------------------------------
    std::string why;
    const bool wrote = write_seed_dir(seed_dir, build.seeds, why);
    check(wrote, "seed directory is written" + (wrote ? std::string() : ": " + why));
    const std::vector<SeedInfo> reloaded = load_seeds(seed_dir);
    bool roundtrip = reloaded.size() == build.seeds.size();
    for (std::size_t i = 0; roundtrip && i < reloaded.size(); ++i) {
        roundtrip = reloaded[i].id == build.seeds[i].id &&
                    reloaded[i].sha256 == build.seeds[i].sha256 &&
                    reloaded[i].wire == build.seeds[i].wire &&
                    reloaded[i].index_present == build.seeds[i].index_present &&
                    reloaded[i].large == build.seeds[i].large;
    }
    check(roundtrip, "seeds survive a directory round trip byte-identically");

    // ---- mutation planning ------------------------------------------------
    const u64 campaign_seed = 0x4834'4655'5A5Aull;
    std::array<std::size_t, 4> class_seen{};
    std::size_t header = 0;
    std::size_t index = 0;
    std::size_t trailer = 0;
    std::size_t body = 0;
    bool deterministic = true;
    bool bounds_ok = true;
    bool classes_change = true;
    for (u64 i = 0; i < 6000; ++i) {
        const std::size_t seed_index = static_cast<std::size_t>(i % build.seeds.size());
        const auto cls = static_cast<MutationClass>((i / build.seeds.size()) % 4ull);
        const SeedInfo& seed = build.seeds[seed_index];
        const Mutation a = plan_mutation(seed, seed_index, cls, i, campaign_seed);
        const Mutation b = plan_mutation(seed, seed_index, cls, i, campaign_seed);
        deterministic = deterministic && same_plan(a, b);
        class_seen[static_cast<std::size_t>(cls)] += 1;
        if (a.touched_header) ++header;
        if (a.touched_index) ++index;
        if (a.touched_trailer) ++trailer;
        if (a.touched_body) ++body;
        if (a.size > seed.wire.size()) {
            bounds_ok = false;
            std::printf("  debug: size %zu > seed %zu (seed %s class %s)\n", a.size,
                        seed.wire.size(), seed.id.c_str(), mutation_class_name(cls));
        }
        for (const auto& [offset, value] : a.changes) {
            (void)value;
            if (offset >= seed.wire.size()) {
                bounds_ok = false;
                std::printf("  debug: offset %zu >= seed %zu (seed %s class %s)\n", offset,
                            seed.wire.size(), seed.id.c_str(), mutation_class_name(cls));
            }
        }
        const bool changed = !a.changes.empty() || a.size != seed.wire.size();
        classes_change = classes_change && changed;
        if (cls == MutationClass::Truncation) {
            if (!(a.size < seed.wire.size())) {
                std::printf("  debug: truncation size %zu not below %zu (seed %s)\n", a.size,
                            seed.wire.size(), seed.id.c_str());
            }
            bounds_ok = bounds_ok && a.size < seed.wire.size();
        }
        const std::vector<std::uint8_t> materialized = materialize(seed.wire, a);
        if (materialized.size() != a.size) {
            bounds_ok = false;
            std::printf("  debug: materialized %zu != %zu\n", materialized.size(), a.size);
        }
        // A repaired mutant has its two outer CRC fields overwritten *after*
        // the planned edits, so byte equality holds only for unrepaired plans.
        if (!a.repair_outer_crcs) {
            for (const auto& [offset, value] : a.changes) {
                if (offset < materialized.size() && materialized[offset] != value) {
                    bounds_ok = false;
                }
            }
        }
        const std::vector<std::uint8_t> again = materialize(seed.wire, a);
        deterministic = deterministic && again == materialized;
    }
    check(deterministic, "mutation planning and materialisation are deterministic");
    check(bounds_ok, "mutation sizes and offsets stay inside the seed");
    check(classes_change, "every planned mutant actually changes the container");
    for (std::size_t i = 0; i < 4; ++i) {
        check(class_seen[i] > 0,
              std::string("mutation class ") +
                  mutation_class_name(static_cast<MutationClass>(i)) + " is produced");
    }
    check(header > 0 && index > 0 && trailer > 0 && body > 0,
          "header, index, trailer and body regions are all mutated");

    // ---- runner determinism across worker counts -------------------------
    FuzzConfig config;
    config.mutants = 600;
    config.seed = campaign_seed;
    config.workers = 1;
    config.fork_workers = false;
    const FuzzReport run_a = run_fuzz(build.seeds, config);
    const FuzzReport run_b = run_fuzz(build.seeds, config);
    check(run_a.completed && run_b.completed, "in-process campaigns complete");
    check(same_tally(run_a, run_b), "repeated campaigns produce identical tallies");
    check(run_a.counts.accepted_invalid == 0 && run_a.counts.crashes == 0 &&
              run_a.counts.timeouts == 0,
          "self-test campaign has zero accepted-invalid, crashes and timeouts");
    config.workers = 4;
    config.fork_workers = true;
    const FuzzReport run_fork = run_fuzz(build.seeds, config);
    check(run_fork.completed, "forked campaign completes");
    check(same_tally(run_a, run_fork),
          "worker count does not change a single count or tally");

    // ---- the target predicate can fail -----------------------------------
    FuzzCounts clean{100'000, 0, 0, 0, 1};
    check(targets_met(clean), "target predicate accepts a clean 100,000-mutant campaign");
    FuzzCounts injected_invalid{100'000, 1, 0, 0, 1};
    FuzzCounts injected_crash{100'000, 0, 1, 0, 1};
    FuzzCounts injected_timeout{100'000, 0, 0, 1, 1};
    FuzzCounts short_campaign{99'999, 0, 0, 0, 1};
    check(!targets_met(injected_invalid), "target predicate rejects accepted_invalid=1");
    check(!targets_met(injected_crash), "target predicate rejects crashes=1");
    check(!targets_met(injected_timeout), "target predicate rejects timeouts=1");
    check(!targets_met(short_campaign), "target predicate rejects a short campaign");

    // ---- evidence determinism and honest FAIL ----------------------------
    FuzzReport measured = run_a;
    measured.counts.total = 100'000;
    measured.tally.processed = 100'000;
    FuzzConfig evidence_config = config;
    evidence_config.mutants = 100'000;
    EvidenceInput input;
    input.prereq = &prereq;
    input.seeds = &build;
    input.campaign = &measured;
    input.workers_one = &run_a;
    input.workers_many = &run_fork;
    input.config = &evidence_config;
    input.dry_mutants = run_a.counts.total;
    input.determinism_equal = true;
    input.alloc_guard_enabled = false;
    input.seed_dir = "engine/obj/h4/seeds";
    const EvidenceText evidence_a = render_evidence(input);
    const EvidenceText evidence_b = render_evidence(input);
    check(evidence_a.gate_tsv == evidence_b.gate_tsv && evidence_a.log == evidence_b.log &&
              evidence_a.counts_tsv == evidence_b.counts_tsv &&
              evidence_a.seeds_tsv == evidence_b.seeds_tsv,
          "evidence rendering is deterministic");
    check(gate_verdict_is_pass(evidence_a.gate_tsv),
          "a clean measurement renders h4.verdict PASS");
    FuzzReport broken = measured;
    broken.counts.accepted_invalid = 1;
    EvidenceInput broken_input = input;
    broken_input.campaign = &broken;
    const EvidenceText evidence_broken = render_evidence(broken_input);
    check(!gate_verdict_is_pass(evidence_broken.gate_tsv),
          "an accepted-invalid measurement renders h4.verdict FAIL");

    std::printf("%s %zu self-test failure(s)\n", g_failures == 0 ? "PASS" : "FAIL", g_failures);
    return g_failures == 0 ? 0 : 1;
}

}  // namespace marp::harness::h4
