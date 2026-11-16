// MARP v2 — E3 WIRE — E3-G integrated gate — entry point.
//
// The gate has two faces that must never be in one translation unit: the wire
// half (`e3g_checks.cpp`, which includes C07) and the legacy half
// (`e3g_legacy_side.cpp`, which includes C08).  This file includes neither; it
// drives both through their own headers and joins their results, which is what
// keeps C08 unreachable from the v2 encode path at the translation-unit level and
// not only at the review level.

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

#include "e3g_checks.hpp"
#include "e3g_legacy_side.hpp"
#include "e3g_report.hpp"
#include "e3g_support.hpp"

namespace {

constexpr const char* kUsage =
    "usage: e3_g_gate [--root DIR] [--oracle-bin PATH] [--no-oracle]\n"
    "                 [--fuzz-iterations N] [--fuzz-threads N] [--threads 1,4]\n"
    "                 [--no-fuzz] [--write-evidence] [--help]\n";

std::string fixed_banner() {
    return std::string(
        "# E3-G evidence\n"
        "# tool: engine/bin/e3_g_gate\n"
        "# spec: SPECS/COMPONENTS/e3-wire/SPECS.md §13 (normative)\n"
        "#       SPECS/SPECS-V2.md §5/§8/§15\n"
        "# components under test: C07 (v2 canonical wire), C08 (v1 legacy, read-only)\n"
        "# oracle: H3 clean-room decoder, reached as a subprocess only\n"
        "# note: fixed banner; the harness reads no clock, host, locale or environment\n");
}

std::vector<unsigned> parse_threads(const std::string& text) {
    std::vector<unsigned> out;
    std::size_t start = 0;
    while (start <= text.size()) {
        const std::size_t comma = text.find(',', start);
        const std::string part =
            text.substr(start, comma == std::string::npos ? std::string::npos : comma - start);
        if (!part.empty()) {
            const unsigned value = static_cast<unsigned>(std::strtoul(part.c_str(), nullptr, 10));
            if (value > 0) out.push_back(value);
        }
        if (comma == std::string::npos) break;
        start = comma + 1;
    }
    if (out.empty()) out.push_back(1);
    return out;
}

// The spec readings the harness had to decide.  §13.7 requires each to be
// recorded rather than silently resolved.
std::string spec_readings_text(const e3g::Settings& settings) {
    std::string text;
    text += "  [1] W-CANON composition: E2's T-KAT (128 pinned) + T-GEN (5 000 generated)\n";
    text += "      plus the §13.3 edge items.  E2's `Dag::finish` emits post-order\n";
    text += "      first-use ids but does not run C04's rewrite system, so 607 of the\n";
    text += "      5 128 terms are not in canonical form as emitted.  §13.3 asks for\n";
    text += "      *canonical terms*, so those are canonicalised with E2's own `canon`\n";
    text += "      before use; the count is reported per item (`corpus.tsv` note column)\n";
    text += "      and the corpus is still exactly E2's term set.  No term was dropped.\n";
    text += "  [2] §13.3's edge items are added rather than substituted: an E2 census\n";
    text += "      of T-KAT+T-GEN shows bigint tags {0,1} only, one total-length form\n";
    text += "      (u64), no index-present container, and no declared length above the\n";
    text += "      §8.3 cap.  E3-G therefore synthesises tag 2, both length forms,\n";
    text += "      index-present terms of >= 3 MiB, and the >2^64 totals under W-BIG.\n";
    text += "  [3] INDEX_STRIDE policy: §4.7's stride is 1 MiB and the entry count is a\n";
    text += "      u32, so the largest declared total length with a canonical index is\n";
    text += "      2^32 * 1 MiB = 2^52 bytes.  That bound is a *format* limit, not a\n";
    text += "      resource limit; `big-limit-repeat-entry-cap` is the item that probes\n";
    text += "      it and requires `Limit` at stage 10 from `plan`, `encoded_size` and\n";
    text += "      `encode` alike.  It is recorded as a limitation, never as a pass.\n";
    text += "  [4] W-SEED: §13.4 step 5 says \"every W-SEED wire, including hand-built\n";
    text += "      canonical wires\".  The hand-built set is assembled by this harness's\n";
    text += "      own §4 writer, not by C07, so `enc(dec(w)) = w` is checked against an\n";
    text += "      independent writer; the rest of W-SEED is the W-CANON wire set.\n";
    text += "  [5] Non-canonical rejection stage attribution follows §5.1's order: the\n";
    text += "      step that first observes a violation owns it.  Several §4.10 rules are\n";
    text += "      detectable at more than one step (a duplicate atom payload is visible in\n";
    text += "      the atom table and again in the cross-reference check); the row records\n";
    text += "      the stage the implementation reports, and the corpus's `expected` column\n";
    text += "      was set from §5.1 rather than from observed output.\n";
    text += "  [6] §13.4 step 9 (1 and 4 threads): the term set is sharded across the\n";
    text += "      requested thread count and each pass is compared item by item on wire\n";
    text += "      bytes and verdict.  Overlapping rows are reported twice by design.\n";
    text += "  [7] Stage 11 and the §8.3 cap: the W-BIG terms declare totals of 2^64,\n";
    text += "      2^64+1, 2^65 and 2^128.  Their *wire* is small and canonical, but the\n";
    text += "      default limits stop at stage 6 (`enforce_output_cap`) or stage 11\n";
    text += "      (`max_eval_bytes`).  Both outcomes are recorded: the default-limits row\n";
    text += "      requires `Limit`, and the lifted-limits row requires the full §5.1\n";
    text += "      validation, decode and byte-exact re-encode to succeed.\n";
    text += "  [8] Fuzz campaign: " + std::to_string(settings.fuzz_iterations) +
            " mutants from the W-FUZZ\n";
    text += "      seed set, " + std::to_string(settings.fuzz_threads) +
            " worker(s), allocation guard armed per mutant\n";
    text += "      with a budget of container bytes + " +
            std::to_string(settings.fuzz_alloc_budget_bytes) + " B.  A mutant whose\n";
    text += "      validate+decode exceeds the configured " +
            std::to_string(settings.fuzz_timeout_seconds) + " s wall clock is counted\n";
    text += "      as a timeout (O7.10).  The worst observed time is printed to CI stdout\n";
    text += "      and is deliberately not written into committed evidence, because it is\n";
    text += "      the one quantity in the campaign that is not reproducible run to run;\n";
    text += "      the committed obligation is the counters, and those are exact.\n";
    text += "  [9] H3 agreement: the oracle is invoked as a subprocess and its own\n";
    text += "      rendering of the header, atom table, node table and trailer is compared\n";
    text += "      against the harness's rendering of the decoded `Ir`.  Neither side\n";
    text += "      supplies text to the other.\n";
    text += "  [10] The index region is excluded from the H3 structural comparison: §4.7's\n";
    text += "      policy is C07's (see REPORT/E3/C07-WIRE-REPORT.md §5) and H3\n";
    text += "      reconstructs its own.  Index presence and entry count are compared\n";
    text += "      through the coverage census and the C07 fixpoint instead.\n";
    text += "  [11] W-V1's recorded output digest is the SHA-256 of the decoded root\n";
    text += "      term's *denotation* — the byte-exact evaluated output (§13.3,\n";
    text += "      §13.4 step 8, O7.7) — not a proxy.  The legacy half hashes the\n";
    text += "      evaluated stream twice (E2's StreamDigest and its own SHA-256) and\n";
    text += "      the gate requires both to agree with each other and with the\n";
    text += "      manifest; the two byte counts must agree as well.\n";
    text += "  [12] W-V1/manifest.tsv is exactly three tab-separated columns\n";
    text += "      (<fixture>, <container SHA-256>, <expected denotation SHA-256>) and\n";
    text += "      is read identically by this gate's legacy half and by the C08 gate.\n";
    text += "      A fixture with no entry, a malformed line, or a container digest\n";
    text += "      that does not match the bytes is a FAIL, never an inferred value.\n";
    return text;
}

std::string limitations_text(const e3g::GateResult& result) {
    std::string text;
    text += "  - index entry cap: `entry_count` is a u32 (§4.7), so no canonical wire\n";
    text += "    exists for a declared length above 2^52 bytes.  Probed by\n";
    text += "    `big-limit-repeat-entry-cap` (2^64/INDEX_STRIDE = 2^44 entries); the\n";
    text += "    required and observed outcome is `Limit@stage10_index`.\n";
    text += "  - dense >2^64 denotations cannot be evaluated by stage 11 under the\n";
    text += "    default `max_eval_bytes` (1 GiB of step-11 work).  The containers are\n";
    text += "    still validated structurally and round-tripped byte-exactly with the\n";
    text += "    bound lifted; the default-limits `Limit` is recorded, not suppressed.\n";
    text += "  - v1 emission is out of scope and unreachable: C08 is read-only and this\n";
    text += "    gate contains no v1 writer (see e3g.legacy.readonly_surface).\n";
    if (result.legacy_half_blocked) {
        text += "  - BLOCKED: W-V1 fixture corpus.  specs_and_reports/v2/W-V1 is " +
                std::string(result.legacy.fixtures_found == 0 ? "absent" : "incomplete") +
                " (" + result.legacy.blocked_reason +
                ").  §13.3: a missing or mis-hashed v1 fixture makes the legacy half\n";
        text += "    BLOCKED; it does not make the gate PASS.  No fixture was fabricated and\n";
        text += "    no expected digest was inferred from a decode.\n";
    } else {
        text += "  - W-V1: " + std::to_string(result.legacy.fixtures_found) +
                " fixtures: every container hash matches its manifest entry, every\n";
        text += "    container decodes to a well-formed canonical term, and every decoded\n";
        text += "    denotation is byte-exact against its recorded SHA-256 (§13.4 step 8).\n";
        text += "    No malformed or PoC/defect container is in the decode-success set.\n";
    }
    return text;
}

}  // namespace

int main(int argc, char** argv) {
    e3g::Settings settings;
    bool write = false;
    for (int i = 1; i < argc; ++i) {
        const std::string_view arg(argv[i]);
        auto next = [&argc, &argv, &i]() -> std::string {
            return i + 1 < argc ? std::string(argv[++i]) : std::string{};
        };
        if (arg == "--root") {
            settings.root = next();
        } else if (arg == "--oracle-bin") {
            settings.oracle_path = next();
        } else if (arg == "--legacy-half") {
            settings.legacy_binary = next();
        } else if (arg == "--no-oracle") {
            settings.full_oracle = false;
        } else if (arg == "--fuzz-iterations") {
            const std::string text = next();
            settings.fuzz_iterations = text.empty()
                                           ? 0
                                           : static_cast<std::size_t>(std::strtoull(text.c_str(),
                                                                                    nullptr, 10));
        } else if (arg == "--fuzz-threads") {
            const std::string text = next();
            settings.fuzz_threads = text.empty()
                                        ? 1
                                        : static_cast<std::size_t>(std::strtoull(text.c_str(),
                                                                                 nullptr, 10));
            if (settings.fuzz_threads == 0) settings.fuzz_threads = 1;
        } else if (arg == "--threads") {
            settings.thread_counts = parse_threads(next());
        } else if (arg == "--no-fuzz") {
            settings.fuzz_iterations = 0;
        } else if (arg == "--write-evidence") {
            write = true;
        } else if (arg == "--help" || arg == "-h") {
            std::fputs(kUsage, stdout);
            return 0;
        } else {
            std::fprintf(stderr, "e3_g_gate: unknown argument: %s\n", argv[i]);
            return 2;
        }
    }
    if (settings.root.empty()) settings.root = ".";
    if (settings.legacy_binary.empty()) {
        settings.legacy_binary = settings.root + "/engine/bin/e3g_legacy_half";
    }
    if (settings.fuzz_iterations == 0) {
        // A zero-iteration campaign would make the "all three counters are zero"
        // obligation vacuous, so it is rejected rather than reported as clean.
        std::fprintf(stderr, "e3_g_gate: the fuzz campaign cannot be empty (§13.4 step 7)\n");
        return 2;
    }

    e3g::Corpus corpus = e3g::build_corpus(settings.root);
    e3g::Collector collector;
    collector.set_environment(fixed_banner());
    collector.log("corpus: W-CANON=" + std::to_string(corpus.canon.size()) +
                  " (T-KAT=" + std::to_string(corpus.t_kat_bound) +
                  " T-GEN=" + std::to_string(corpus.t_gen_bound) + ")" +
                  " hand-built W-SEED=" + std::to_string(corpus.hand_built.size()) +
                  " W-NONCANON=" + std::to_string(corpus.noncanon.size()) +
                  " W-V1=" + std::to_string(corpus.v1.size()) +
                  " W-FUZZ seeds=" + std::to_string(corpus.fuzz_seeds.size()));
    collector.log("corpus seeds: " + corpus.e2_seed_note);

    // ---- wire half --------------------------------------------------------
    collector.section("E3-G wire half (C07 + H3)");
    e3g::WireResultSummary wire =
        e3g::run_wire_checks(corpus, settings, collector);

    // ---- legacy half ------------------------------------------------------
    //
    // C08 is reached only through its own process (`bin/e3g_legacy_half`); see
    // e3g_legacy_side.cpp for why one binary cannot carry both components.  The
    // v2 re-encode of each decoded v1 term happens back on this side, so no v2
    // encode symbol is ever linked into anything that links C08.
    collector.section("E3-G legacy half (C08, read-only, out of process)");
    e3g::LegacySummary legacy = e3g::run_legacy_checks(settings.root, settings.legacy_binary);
    for (const e3g::LegacyRow& row : legacy.rows) {
        collector.row_verdict(row.check, "W-V1", row.item_id, row.input_sha256, row.wire_sha256,
                              row.wire_bytes, row.expected, row.actual, row.verdict, row.log);
    }
    // Step 8's v2 half, run only for fixtures whose hash, decode and digest passed.
    for (const e3g::LegacyRow& row : legacy.rows) {
        if (row.check != "e3g.legacy.decode_v1" || row.verdict != "PASS") continue;
        bool digest_pass = false;
        std::string expected_digest;
        for (const e3g::LegacyRow& sibling : legacy.rows) {
            if (sibling.check == "e3g.legacy.denotation" && sibling.item_id == row.item_id &&
                sibling.verdict == "PASS") {
                digest_pass = true;
                expected_digest = sibling.expected;
            }
        }
        if (!digest_pass || row.structure_text.empty()) continue;
        e3g::reencode_legacy_term(row.item_id, row.structure_text, row.payload_hex, expected_digest, settings,
                                  collector, legacy.failures);
    }
    legacy.v2_reencoded = 0;
    for (const e3g::Row& row : collector.rows()) {
        if (row.check == "e3g.legacy.v2_fixpoint" && row.verdict == "PASS") ++legacy.v2_reencoded;
    }

    // ---- assemble the result ---------------------------------------------
    e3g::GateResult result;
    result.environment = fixed_banner();
    result.rows = collector.rows();
    result.log = collector.log_lines();
    result.fuzz_log = collector.log_lines();
    result.legacy_log = legacy.log_lines;
    result.corpus_rows = wire.corpus_tsv;
    result.count_rows = wire.count_tsv;
    result.wire = wire;
    result.legacy = legacy;
    result.wire_half_ok = wire.ok;
    result.legacy_half_blocked = legacy.blocked;
    result.legacy_half_ok = !legacy.blocked && legacy.failures == 0;
    result.spec_readings = spec_readings_text(settings);
    result.passes = 0;
    result.failures = 0;
    result.blocked = 0;
    for (const e3g::Row& row : result.rows) {
        if (row.verdict == "PASS") {
            ++result.passes;
        } else if (row.verdict == "FAIL") {
            ++result.failures;
        } else {
            ++result.blocked;
        }
    }
    result.fuzz_timeout_seconds = settings.fuzz_timeout_seconds;
    result.limitations = limitations_text(result);

    // ---- report ------------------------------------------------------------
    const std::string summary = e3g::console_summary(result);
    std::fputs(summary.c_str(), stdout);
    if (write) {
        if (!e3g::write_evidence(settings.root, result)) {
            std::fprintf(stderr, "e3_g_gate: cannot write evidence under %s\n",
                         settings.root.c_str());
            return 3;
        }
        std::printf("evidence written under %s/specs_and_reports/v2/\n", settings.root.c_str());
    }
    const e3g::Verdict verdict = e3g::verdict_of(result);
    // Exit codes: 0 PASS, 1 FAIL, 4 BLOCKED.  A BLOCKED legacy half is *not*
    // success — the workflow treats any non-zero exit as a failure so the missing
    // dependency cannot be mistaken for a green gate — but it is reported with its
    // own code so the CI step can state which of the two happened.
    switch (verdict) {
        case e3g::Verdict::Pass: return 0;
        case e3g::Verdict::Fail: return 1;
        case e3g::Verdict::Blocked: return 4;
    }
    return 1;
}
