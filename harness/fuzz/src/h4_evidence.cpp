// MARP v2 — H4 FUZZ — evidence rendering and writing.

#include "h4_evidence.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "h4_support.hpp"
#include "mapr/e3/e3_wire.hpp"

namespace marp::harness::h4 {
namespace {

namespace fs = std::filesystem;
using namespace marp::v2;  // NOLINT

struct Row {
    std::string check;
    std::string corpus;
    std::string item;
    std::string input_sha256;
    std::string expected;
    std::string actual;
    std::string verdict;
    std::string log;
};

std::string number(std::uint64_t value) { return std::to_string(value); }

std::string campaign_counts_text(const FuzzReport& report) {
    return "valid=" + number(report.counts.valid) +
           " accepted_invalid=" + number(report.counts.accepted_invalid) +
           " crashes=" + number(report.counts.crashes) +
           " timeouts=" + number(report.counts.timeouts);
}

std::string class_counts_text(const FuzzReport& report) {
    std::string text;
    for (std::size_t i = 0; i < report.tally.by_class.size(); ++i) {
        if (i != 0) text += " ";
        text += std::string(mutation_class_name(static_cast<MutationClass>(i))) + "=" +
                number(report.tally.by_class[i]);
    }
    return text;
}

std::string stage_name_text(std::size_t slot) {
    if (slot >= 13) return "S?";
    return stage_name(static_cast<Stage>(slot));
}

std::size_t covered_stages(const FuzzReport& report) {
    std::size_t covered = 0;
    for (std::size_t i = 1; i < 13; ++i) {
        if (report.tally.validate_stage[i] > 0) ++covered;
    }
    return covered;
}

std::vector<Row> build_rows(const EvidenceInput& input) {
    const FuzzReport& campaign = *input.campaign;
    const Prereq& prereq = *input.prereq;
    const SeedBuild& seeds = *input.seeds;
    const std::string seed_set = seeds_sha256_set(seeds.seeds);
    const std::string log = "logs/H4-FUZZ.log";
    std::vector<Row> rows;

    const bool prereq_ok = prereq.ok;
    rows.push_back({"h4.prereq.e3g_gate", "E3-G", "gate", prereq.gate_sha256,
                    "0 FAIL / 0 BLOCKED / E3-G fuzz clean",
                    number(prereq.gate_fail) + " FAIL / " + number(prereq.gate_blocked) +
                        " BLOCKED",
                    prereq_ok ? "PASS" : "FAIL", log + "#prereq"});
    rows.push_back({"h4.prereq.e3_corpus", "E3-G", "corpus", prereq.corpus_sha256,
                    "seed identities committed", number(prereq.corpus_items) + " items",
                    prereq_ok ? "PASS" : "FAIL", log + "#prereq"});
    rows.push_back({"h4.prereq.e3_fuzz", "E3-G", "fuzz_counts", prereq.counts_sha256,
                    "100000 mutants / 0 accepted_invalid / 0 crashes / 0 timeouts",
                    number(prereq.e3_mutants) + " mutants", prereq_ok ? "PASS" : "FAIL",
                    log + "#prereq"});

    for (const SeedInfo& seed : seeds.seeds) {
        const std::string identity = "bytes=" + number(seed.wire.size()) +
                                     " index=" + (seed.index_present ? "present" : "absent") +
                                     " sha256=" + seed.sha256;
        rows.push_back({"h4.seed.reproduced", "W-FUZZ", seed.id, seed.sha256,
                        "E3-G committed identity reproduced", identity,
                        "PASS", log + "#seed." + seed.id});
    }

    const bool total_ok = campaign.counts.total == 100'000ull;
    rows.push_back({"h4.campaign.total", "W-FUZZ", "campaign", seed_set, "100000",
                    number(campaign.counts.total), total_ok ? "PASS" : "FAIL",
                    log + "#campaign"});
    rows.push_back({"h4.campaign.accepted_invalid", "W-FUZZ", "campaign", seed_set, "0",
                    number(campaign.counts.accepted_invalid),
                    campaign.counts.accepted_invalid == 0 ? "PASS" : "FAIL",
                    log + "#campaign"});
    rows.push_back({"h4.campaign.crashes", "W-FUZZ", "campaign", seed_set, "0",
                    number(campaign.counts.crashes),
                    campaign.counts.crashes == 0 ? "PASS" : "FAIL", log + "#campaign"});
    rows.push_back({"h4.campaign.timeouts", "W-FUZZ", "campaign", seed_set, "0",
                    number(campaign.counts.timeouts),
                    campaign.counts.timeouts == 0 ? "PASS" : "FAIL", log + "#campaign"});
    rows.push_back({"h4.campaign.valid", "W-FUZZ", "campaign", seed_set, ">0",
                    number(campaign.counts.valid), campaign.counts.valid > 0 ? "PASS" : "FAIL",
                    log + "#campaign"});
    rows.push_back({"h4.campaign.rejected", "W-FUZZ", "campaign", seed_set, ">0",
                    number(campaign.tally.rejected),
                    campaign.tally.rejected > 0 ? "PASS" : "FAIL", log + "#campaign"});
    rows.push_back({"h4.campaign.verified", "W-FUZZ", "campaign", seed_set, "recorded",
                    number(campaign.tally.verified), "PASS", log + "#campaign"});
    rows.push_back({"h4.campaign.accounted", "W-FUZZ", "campaign", seed_set, "100000",
                    number(campaign.tally.processed),
                    campaign.tally.processed == campaign.counts.total && campaign.completed
                        ? "PASS"
                        : "FAIL",
                    log + "#campaign"});
    rows.push_back({"h4.campaign.alloc_violations", "W-FUZZ", "campaign", seed_set, "0",
                    number(campaign.tally.alloc_violations),
                    campaign.tally.alloc_violations == 0 ? "PASS" : "FAIL",
                    log + "#campaign"});
    rows.push_back({"h4.campaign.fixpoint", "W-FUZZ", "campaign", seed_set, "mismatch=0",
                    "checked=" + number(campaign.tally.fixpoint_checked) + " mismatch=" +
                        number(campaign.tally.fixpoint_mismatch),
                    campaign.tally.fixpoint_mismatch == 0 ? "PASS" : "FAIL",
                    log + "#campaign"});

    for (std::size_t i = 0; i < 4; ++i) {
        const auto cls = static_cast<MutationClass>(i);
        const std::uint64_t count = campaign.tally.by_class[i];
        rows.push_back({"h4.campaign.class." + std::string(mutation_class_name(cls)), "W-FUZZ",
                        "class", seed_set, ">0", number(count), count > 0 ? "PASS" : "FAIL",
                        log + "#classes"});
    }
    rows.push_back({"h4.campaign.region.header", "W-FUZZ", "region", seed_set, ">0",
                    number(campaign.tally.region_header),
                    campaign.tally.region_header > 0 ? "PASS" : "FAIL", log + "#regions"});
    rows.push_back({"h4.campaign.region.index", "W-FUZZ", "region", seed_set, ">0",
                    number(campaign.tally.region_index),
                    campaign.tally.region_index > 0 ? "PASS" : "FAIL", log + "#regions"});
    rows.push_back({"h4.campaign.region.trailer", "W-FUZZ", "region", seed_set, ">0",
                    number(campaign.tally.region_trailer),
                    campaign.tally.region_trailer > 0 ? "PASS" : "FAIL", log + "#regions"});
    rows.push_back({"h4.campaign.region.body", "W-FUZZ", "region", seed_set, ">0",
                    number(campaign.tally.region_body),
                    campaign.tally.region_body > 0 ? "PASS" : "FAIL", log + "#regions"});

    for (std::size_t slot = 1; slot < 13; ++slot) {
        const std::uint64_t count = campaign.tally.validate_stage[slot];
        rows.push_back({"h4.campaign.stage." + std::string(stage_name_text(slot)), "W-FUZZ",
                        "stage", seed_set, "recorded", number(count), "PASS",
                        log + "#stages"});
    }
    const std::size_t covered = covered_stages(campaign);
    rows.push_back({"h4.campaign.stage.distinct", "W-FUZZ", "stage", seed_set, ">=8",
                    number(covered), covered >= 8 ? "PASS" : "FAIL", log + "#stages"});

    const bool determinism_ok = input.determinism_equal && input.workers_one != nullptr &&
                                input.workers_many != nullptr;
    const std::string one_text =
        input.workers_one == nullptr ? "missing" : campaign_counts_text(*input.workers_one);
    const std::string many_text =
        input.workers_many == nullptr ? "missing" : campaign_counts_text(*input.workers_many);
    rows.push_back({"h4.determinism.workers", "H4", "dry_run", seed_set,
                    "identical counts at 1 and " +
                        number(input.config == nullptr ? 0 : input.config->workers) + " workers",
                    "workers=1 " + one_text + "; workers>1 " + many_text,
                    determinism_ok ? "PASS" : "FAIL", log + "#determinism"});
    rows.push_back({"h4.determinism.dry_run", "H4", "dry_run", seed_set,
                    number(input.dry_mutants) + " mutants, identical",
                    determinism_ok ? "identical" : "differs",
                    determinism_ok ? "PASS" : "FAIL", log + "#determinism"});

    const bool verdict = campaign.targets_met() && prereq_ok &&
                         campaign.tally.alloc_violations == 0 && determinism_ok &&
                         campaign.tally.fixpoint_mismatch == 0;
    rows.push_back({"h4.verdict", "H4", "verdict", seed_set, "PASS", verdict ? "PASS" : "FAIL",
                    verdict ? "PASS" : "FAIL", log + "#verdict"});

    std::stable_sort(rows.begin(), rows.end(), [](const Row& a, const Row& b) {
        if (a.check != b.check) return a.check < b.check;
        if (a.corpus != b.corpus) return a.corpus < b.corpus;
        return a.item < b.item;
    });
    return rows;
}

std::string render_gate_tsv(const std::vector<Row>& rows) {
    std::string text = "check\tcorpus\titem_id\tinput_sha256\texpected\tactual\tverdict\tlog\n";
    for (const Row& row : rows) {
        text += row.check;
        text += '\t';
        text += row.corpus;
        text += '\t';
        text += row.item;
        text += '\t';
        text += row.input_sha256;
        text += '\t';
        text += row.expected;
        text += '\t';
        text += row.actual;
        text += '\t';
        text += row.verdict;
        text += '\t';
        text += row.log;
        text += '\n';
    }
    return text;
}

std::string render_log(const EvidenceInput& input) {
    const FuzzReport& campaign = *input.campaign;
    const Prereq& prereq = *input.prereq;
    const SeedBuild& seeds = *input.seeds;
    const FuzzConfig& config = *input.config;
    std::string text;
    text += "# MARP v2 — H4 FUZZ — campaign log\n";
    text += "# spec: SPECS/SPECS-V2.md §12.8 (normative), SPECS/COMPONENTS-V2.md H4\n";
    text += "# harness: engine/bin/h4_fuzz (C++20); sources harness/fuzz/**\n";
    text += "# subjects: C07 `validate` (verify path) and C07 `decode` (decode path)\n";
    text += "# note: no clock, host, locale or environment value appears in this log\n";
    text += "\n[prerequisite: E3-G]\n";
    text += "  e3g.gate\t" + prereq.gate_path + "\tsha256=" + prereq.gate_sha256 +
            "\trows=" + number(prereq.gate_rows) + "\tfail=" + number(prereq.gate_fail) +
            "\tblocked=" + number(prereq.gate_blocked) + "\n";
    text += "  e3g.corpus\t" + prereq.corpus_path + "\tsha256=" + prereq.corpus_sha256 +
            "\titems=" + number(prereq.corpus_items) + "\n";
    text += "  e3g.fuzz\t" + prereq.counts_path + "\tsha256=" + prereq.counts_sha256 +
            "\tmutants=" + number(prereq.e3_mutants) + "\n";
    text += "\n[seeds: E3-G canonical wires, digest-verified]\n";
    text += "  seed.count\t" + number(seeds.seeds.size()) + "\n";
    text += "  seed.set.sha256\t" + seeds_sha256_set(seeds.seeds) + "\n";
    for (const std::string& note : seeds.note) text += "  " + note + "\n";
    text += "\n[configuration]\n";
    text += "  campaign.seed\t" + number(config.seed) + "\n";
    text += "  campaign.mutants\t" + number(config.mutants) + "\n";
    text += "  campaign.workers\t" + number(config.workers) + "\n";
    text += "  campaign.per_mutant_timeout_ms\t" + number(config.per_mutant_timeout_ms) + "\n";
    text += "  campaign.alloc_budget_bytes\t" + number(config.alloc_budget_bytes) + "\n";
    text += "  campaign.fork_workers\t" + std::string(config.fork_workers ? "yes" : "no") + "\n";
    text += "  campaign.verify_fixpoint\t" +
            std::string(config.verify_fixpoint ? "yes" : "no") + "\n";
    text += "  campaign.alloc_guard\t" +
            std::string(input.alloc_guard_enabled ? "enabled" : "disabled (sanitizer runtime)") +
            "\n";
    text += "  seed.dir\t" + input.seed_dir + " (regenerated by make -f Makefile.h4 h4-seeds)\n";
    text += "\n[class mix]\n";
    text += "  " + class_counts_text(campaign) + "\n";
    text += "\n[mutated regions]\n";
    text += "  header=" + number(campaign.tally.region_header) +
            " index=" + number(campaign.tally.region_index) +
            " trailer=" + number(campaign.tally.region_trailer) +
            " body=" + number(campaign.tally.region_body) + "\n";
    text += "\n[seed mix]\n";
    for (std::size_t i = 0; i < seeds.seeds.size(); ++i) {
        const std::uint64_t count =
            i < campaign.tally.by_seed.size() ? campaign.tally.by_seed[i] : 0;
        text += "  seed.mutants." + seeds.seeds[i].id + "\t" + number(count) + "\n";
    }
    text += "\n[rejection stages: validate]\n";
    for (std::size_t slot = 1; slot < 13; ++slot) {
        text += "  " + std::string(stage_name_text(slot)) + "\t" +
                number(campaign.tally.validate_stage[slot]) + "\n";
    }
    text += "\n[rejection stages: decode]\n";
    for (std::size_t slot = 1; slot < 13; ++slot) {
        text += "  " + std::string(stage_name_text(slot)) + "\t" +
                number(campaign.tally.decode_stage[slot]) + "\n";
    }
    text += "\n[campaign totals]\n";
    text += "  campaign.total\t" + number(campaign.counts.total) + "\n";
    text += "  campaign.processed\t" + number(campaign.tally.processed) + "\n";
    text += "  campaign.valid\t" + number(campaign.counts.valid) + "\n";
    text += "  campaign.rejected\t" + number(campaign.tally.rejected) + "\n";
    text += "  campaign.accepted_invalid\t" + number(campaign.counts.accepted_invalid) + "\n";
    text += "  campaign.crashes\t" + number(campaign.counts.crashes) + "\n";
    text += "  campaign.timeouts\t" + number(campaign.counts.timeouts) + "\n";
    text += "  campaign.alloc_violations\t" + number(campaign.tally.alloc_violations) + "\n";
    text += "  campaign.peak_alloc_bytes\t" + number(campaign.tally.peak_alloc_bytes) + "\n";
    text += "  campaign.verified\t" + number(campaign.tally.verified) + "\n";
    text += "  campaign.decode_accepted\t" + number(campaign.tally.decode_accepted) + "\n";
    text += "  campaign.fixpoint_checked\t" + number(campaign.tally.fixpoint_checked) + "\n";
    text += "  campaign.fixpoint_mismatch\t" + number(campaign.tally.fixpoint_mismatch) + "\n";
    if (!campaign.tally.first_failure.empty()) {
        text += "  campaign.first_failure\t" + campaign.tally.first_failure + "\n";
    }
    text += "\n[determinism: worker-count comparison]\n";
    text += "  dry_run.mutants\t" + number(input.dry_mutants) + "\n";
    text += "  dry_run.workers.1\t" +
            (input.workers_one == nullptr ? "missing" : campaign_counts_text(*input.workers_one)) +
            "\n";
    text += "  dry_run.workers." + number(config.workers) + "\t" +
            (input.workers_many == nullptr ? "missing" : campaign_counts_text(*input.workers_many)) +
            "\n";
    text += "  dry_run.equal\t" + std::string(input.determinism_equal ? "yes" : "no") + "\n";
    text += "\nRESULT: ";
    const bool verdict = campaign.targets_met() && prereq.ok &&
                         campaign.tally.alloc_violations == 0 && input.determinism_equal &&
                         campaign.tally.fixpoint_mismatch == 0;
    text += verdict ? "PASS\n" : "FAIL\n";
    return text;
}

std::string render_counts_tsv(const EvidenceInput& input) {
    const FuzzReport& campaign = *input.campaign;
    const FuzzConfig& config = *input.config;
    std::string text = "counter\tvalue\n";
    auto add = [&text](const std::string& key, const std::string& value) {
        text += key + "\t" + value + "\n";
    };
    add("mutants", number(campaign.counts.total));
    add("accepted_valid", number(campaign.counts.valid));
    add("valid", number(campaign.counts.valid));
    add("accepted_invalid", number(campaign.counts.accepted_invalid));
    add("rejected", number(campaign.tally.rejected));
    add("crashes", number(campaign.counts.crashes));
    add("timeouts", number(campaign.counts.timeouts));
    add("alloc_violations", number(campaign.tally.alloc_violations));
    add("peak_alloc_bytes", number(campaign.tally.peak_alloc_bytes));
    add("processed", number(campaign.tally.processed));
    add("verified", number(campaign.tally.verified));
    add("decode_accepted", number(campaign.tally.decode_accepted));
    add("fixpoint_checked", number(campaign.tally.fixpoint_checked));
    add("fixpoint_mismatch", number(campaign.tally.fixpoint_mismatch));
    add("workers", number(config.workers));
    add("seeds", number(input.seeds->seeds.size()));
    add("seed.set_sha256", seeds_sha256_set(input.seeds->seeds));
    add("campaign.seed", number(config.seed));
    add("timeout_ms", number(config.per_mutant_timeout_ms));
    add("alloc_budget_bytes", number(config.alloc_budget_bytes));
    for (std::size_t i = 0; i < 4; ++i) {
        add(std::string("class.") + mutation_class_name(static_cast<MutationClass>(i)),
            number(campaign.tally.by_class[i]));
    }
    add("region.header", number(campaign.tally.region_header));
    add("region.index", number(campaign.tally.region_index));
    add("region.trailer", number(campaign.tally.region_trailer));
    add("region.body", number(campaign.tally.region_body));
    for (std::size_t slot = 1; slot < 13; ++slot) {
        add("stage." + std::string(stage_name_text(slot)),
            number(campaign.tally.validate_stage[slot]));
    }
    add("determinism.dry_run.mutants", number(input.dry_mutants));
    add("determinism.dry_run.equal", input.determinism_equal ? "yes" : "no");
    add("verdict", campaign.targets_met() && input.prereq->ok &&
                           campaign.tally.alloc_violations == 0 && input.determinism_equal
                       ? "PASS"
                       : "FAIL");
    return text;
}

}  // namespace

EvidenceText render_evidence(const EvidenceInput& input) {
    EvidenceText text;
    const std::vector<Row> rows = build_rows(input);
    text.gate_tsv = render_gate_tsv(rows);
    text.log = render_log(input);
    text.counts_tsv = render_counts_tsv(input);
    text.seeds_tsv = seeds_manifest(input.seeds->seeds);
    return text;
}

bool write_evidence(const fs::path& root, const EvidenceInput& input, std::string& why) {
    const EvidenceText text = render_evidence(input);
    const fs::path v2 = root / "specs_and_reports" / "v2";
    const fs::path gate = v2 / "gates" / "H4-FUZZ.tsv";
    const fs::path log = v2 / "logs" / "H4-FUZZ.log";
    const fs::path counts = v2 / "corpus" / "H4" / "fuzz_counts.tsv";
    const fs::path seeds = v2 / "corpus" / "H4" / "seeds.tsv";
    if (!write_text_atomic(gate, text.gate_tsv) || !write_text_atomic(log, text.log) ||
        !write_text_atomic(counts, text.counts_tsv) || !write_text_atomic(seeds, text.seeds_tsv)) {
        why = "cannot write the H4 evidence files";
        return false;
    }

    struct Artifact {
        fs::path path;
        bool required;
    };
    const std::vector<Artifact> artifacts = {
        {gate, true},
        {log, true},
        {counts, true},
        {seeds, true},
        {v2 / "gates" / "E3-G.tsv", true},
        {v2 / "corpus" / "E3" / "corpus.tsv", true},
        {v2 / "corpus" / "E3" / "fuzz_counts.tsv", true},
        {v2 / "evidence" / "E3" / "SHA256SUMS", true},
    };
    std::string manifest = "artifact\tsha256\tbytes\trequired\n";
    std::string sums;
    for (const Artifact& artifact : artifacts) {
        std::error_code error;
        if (!fs::is_regular_file(artifact.path, error)) {
            why = "evidence input is missing: " + artifact.path.string();
            return false;
        }
        std::vector<std::uint8_t> bytes;
        if (!read_file(artifact.path, bytes)) {
            why = "evidence input is unreadable: " + artifact.path.string();
            return false;
        }
        std::error_code relative_error;
        const fs::path relative = fs::relative(artifact.path, root, relative_error);
        if (relative_error) {
            why = "cannot relativise " + artifact.path.string();
            return false;
        }
        const std::string digest =
            sha256_hex(std::span<const std::uint8_t>(bytes.data(), bytes.size()));
        manifest += relative.generic_string() + "\t" + digest + "\t" +
                    number(bytes.size()) + "\t" + (artifact.required ? "required" : "optional") +
                    "\n";
        sums += digest + "  " + relative.generic_string() + "\n";
    }
    const bool verdict = input.campaign->targets_met() && input.prereq->ok &&
                         input.campaign->tally.alloc_violations == 0 &&
                         input.determinism_equal &&
                         input.campaign->tally.fixpoint_mismatch == 0;
    manifest += std::string("verdict\t") + (verdict ? "PASS" : "FAIL") + "\t-\t-\n";
    const fs::path manifest_path = v2 / "evidence" / "H4" / "MANIFEST.tsv";
    const fs::path sums_path = v2 / "evidence" / "H4" / "SHA256SUMS";
    if (!write_text_atomic(manifest_path, manifest) || !write_text_atomic(sums_path, sums)) {
        why = "cannot write the H4 evidence manifest";
        return false;
    }
    return verify_sums(sums_path, root, why);
}

bool verify_sums(const fs::path& sums_path, const fs::path& root, std::string& why) {
    std::ifstream stream(sums_path);
    if (!stream) {
        why = "cannot read " + sums_path.string();
        return false;
    }
    std::string line;
    std::size_t checked = 0;
    while (std::getline(stream, line)) {
        line = trim_right(line);
        if (line.empty()) continue;
        const std::size_t split = line.find("  ");
        if (split == std::string::npos || split != 64) {
            why = "malformed sha256sum line";
            return false;
        }
        const std::string digest = line.substr(0, 64);
        const std::string relative = line.substr(66);
        const fs::path path = root / relative;
        if (sha256_file(path) != digest) {
            why = "digest mismatch for " + relative;
            return false;
        }
        ++checked;
    }
    if (checked == 0) {
        why = "empty sha256sum manifest";
        return false;
    }
    return true;
}

}  // namespace marp::harness::h4
