// MARP v2 — C07 WIRE — evidence rows and log lines.
//
// The harness never asserts: every obligation becomes one TSV row with exact
// expected/actual values and a PASS/FAIL verdict, plus a log line.  A run with
// any non-PASS row exits non-zero, and the evidence files are written only by
// this harness.
#pragma once

#include <cstddef>
#include <string>
#include <vector>

namespace c07 {

struct Row {
    std::string check;
    std::string corpus;
    std::string item_id;
    std::string input_sha256;
    std::string wire_sha256;
    std::string wire_bytes;
    std::string expected;
    std::string actual;
    std::string verdict;
    std::string log;
};

class Collector {
public:
    void row(const std::string& check, const std::string& corpus, const std::string& item_id,
             const std::string& input_sha256, const std::string& wire_sha256,
             const std::string& wire_bytes, const std::string& expected,
             const std::string& actual, bool pass, const std::string& log_ref);

    // A row whose verdict is not PASS/FAIL (e.g. BLOCKED).  Used only where the
    // spec itself defines a non-PASS, non-FAIL state.
    void row_verdict(const std::string& check, const std::string& corpus,
                     const std::string& item_id, const std::string& input_sha256,
                     const std::string& wire_sha256, const std::string& wire_bytes,
                     const std::string& expected, const std::string& actual,
                     const std::string& verdict, const std::string& log_ref);

    void log(const std::string& line);
    void section(const std::string& name);

    const std::vector<Row>& rows() const { return rows_; }
    const std::vector<std::string>& log_lines() const { return log_lines_; }
    std::size_t passes() const { return passes_; }
    std::size_t failures() const { return failures_; }
    std::size_t count_verdict(const std::string& verdict) const;

    void set_environment(std::string text) { environment_ = std::move(text); }
    const std::string& environment() const { return environment_; }

private:
    std::vector<Row> rows_;
    std::vector<std::string> log_lines_;
    std::string environment_;
    std::size_t passes_ = 0;
    std::size_t failures_ = 0;
    std::size_t section_rows_ = 0;
};

}  // namespace c07
