// MARP v2 — E3 WIRE — E3-G integrated gate — evidence writer (§13.5).
//
// Writes exactly the artefacts §13.5 names, plus the self-referential manifest in
// `evidence/E3/`.  The writer is the only code that touches these paths, it never
// reads them back, and it never edits a measured value: a row arrives here already
// measured by `e3g_checks.cpp` / `e3g_legacy_side.cpp`.
#pragma once

#include <string>
#include <vector>

#include "e3g_checks.hpp"
#include "e3g_legacy_side.hpp"
#include "e3g_support.hpp"

namespace e3g {

// Everything the gate measured, in the order it was measured.
struct GateResult {
    std::string environment;          // fixed banner, machine independent
    std::vector<Row> rows;            // all PASS/FAIL/BLOCKED rows
    std::vector<std::string> log;     // E3-G.log body
    std::vector<std::string> fuzz_log;
    std::vector<std::string> legacy_log;
    std::vector<std::string> corpus_rows;   // corpus/E3/corpus.tsv body
    std::vector<std::string> count_rows;    // corpus/E3/fuzz_counts.tsv body
    WireResultSummary wire;
    LegacySummary legacy;
    unsigned fuzz_timeout_seconds = 10;   // the per-mutant budget actually configured
    std::string spec_readings;        // recorded interpretations (§13.7)
    std::string limitations;          // format limits and BLOCKED items
    std::size_t passes = 0;
    std::size_t failures = 0;
    std::size_t blocked = 0;
    bool wire_half_ok = false;
    bool legacy_half_blocked = false;
    bool legacy_half_ok = false;
};

// The gate's verdict, from the rows themselves.
enum class Verdict { Pass, Blocked, Fail };

Verdict verdict_of(const GateResult& result);

// Paths, relative to the repository root.
struct EvidencePaths {
    std::string gate_tsv = "specs_and_reports/v2/gates/E3-G.tsv";
    std::string log = "specs_and_reports/v2/logs/E3-G.log";
    std::string fuzz_log = "specs_and_reports/v2/logs/E3-G-fuzz.log";
    std::string legacy_log = "specs_and_reports/v2/logs/E3-G-legacy.log";
    std::string corpus = "specs_and_reports/v2/corpus/E3/corpus.tsv";
    std::string counts = "specs_and_reports/v2/corpus/E3/fuzz_counts.tsv";
    std::string evidence_dir = "specs_and_reports/v2/evidence/E3";
};

const EvidencePaths& evidence_paths();

// Writes every §13.5 artefact under `root`, plus
// `evidence/E3/SHA256SUMS` and `evidence/E3/MANIFEST.tsv`.  Returns false on any
// I/O failure.
bool write_evidence(const std::string& root, const GateResult& result);

// Renders the console summary the CI job prints and the log's tail.
std::string console_summary(const GateResult& result);

}  // namespace e3g
