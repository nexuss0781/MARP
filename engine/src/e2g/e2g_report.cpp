// MARP v2 — E2-G integrated ALGEBRA gate — evidence row implementation.

#include "e2g_report.hpp"

#include <utility>

namespace e2g {

void Collector::row(const std::string& check, const std::string& corpus,
                    const std::string& item_id, const std::string& input_sha256,
                    const std::string& expected, const std::string& actual, bool pass,
                    const std::string& log_ref) {
    Row r;
    r.check = check;
    r.corpus = corpus;
    r.item_id = item_id;
    r.input_sha256 = input_sha256;
    r.expected = expected;
    r.actual = actual;
    r.verdict = pass ? "PASS" : "FAIL";
    r.log = log_ref;
    rows_.push_back(std::move(r));
    if (pass) {
        ++passes_;
    } else {
        ++failures_;
    }
    ++section_rows_;
}

void Collector::row_verdict(const std::string& check, const std::string& corpus,
                            const std::string& item_id, const std::string& input_sha256,
                            const std::string& expected, const std::string& actual,
                            const std::string& verdict, const std::string& log_ref) {
    Row r;
    r.check = check;
    r.corpus = corpus;
    r.item_id = item_id;
    r.input_sha256 = input_sha256;
    r.expected = expected;
    r.actual = actual;
    r.verdict = verdict;
    r.log = log_ref;
    rows_.push_back(std::move(r));
    ++section_rows_;
}

void Collector::log(const std::string& line) { log_lines_.push_back(line); }

void Collector::section(const std::string& name) {
    log_lines_.push_back("[" + name + "] cumulative pass=" + std::to_string(passes_) +
                         " fail=" + std::to_string(failures_) +
                         " rows=" + std::to_string(section_rows_));
    section_rows_ = 0;
}

std::size_t Collector::count_verdict(const std::string& verdict) const {
    std::size_t n = 0;
    for (const Row& r : rows_) {
        if (r.verdict == verdict) ++n;
    }
    return n;
}

}  // namespace e2g
