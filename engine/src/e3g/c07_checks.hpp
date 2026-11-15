// MARP v2 — C07 WIRE — the gate checks of §13.4, C07-scoped.
//
// The C07 gate proves the v2 wire obligations of E3 §13.4 steps 2–6, 9, 10 for
// a C07 corpus, the §5.1 stage-and-code contract for the `W-NONCANON` set, the
// `encoded_size` exactness of O7.1, the determinism obligations of O7.9, and the
// isolation obligations of §11.  It does not run the 100k fuzz campaign, the
// `W-V1` legacy set, or the full E3-G corpus — those are E3-G (with C08).
#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include "c07_report.hpp"

namespace c07 {

struct Settings {
    std::string root = "..";          // repository root (evidence paths are relative)
    std::string oracle_bin;           // H3 oracle binary, empty when unavailable
    bool run_oracle = true;
    bool run_threads = true;
    bool run_fuzz = true;
    std::size_t fuzz_iterations = 20000;
};

class Gate {
public:
    explicit Gate(Settings settings);

    void set_environment(std::string text) { environment_ = std::move(text); }
    const std::string& environment() const { return environment_; }

    int run();
    bool write_evidence();

    const std::vector<Row>& rows() const { return rows_; }
    std::size_t failures() const { return failures_; }
    std::size_t passes() const { return passes_; }

private:
    Settings settings_;
    std::string environment_;
    std::vector<Row> rows_;
    std::vector<std::string> log_lines_;
    std::size_t failures_ = 0;
    std::size_t passes_ = 0;
};

int run_main(int argc, char** argv);

}  // namespace c07
