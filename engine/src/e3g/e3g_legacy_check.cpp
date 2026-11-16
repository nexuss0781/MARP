// MARP v2 — E3 WIRE — E3-G integrated gate — legacy (W-V1) half, gate side.
//
// Runs `bin/e3g_legacy_half` and turns its stdout into §13.5 rows.  This file
// includes neither `mapr/e3/e3_wire.hpp` nor `mapr/e3/e3_legacy.hpp`: the legacy
// boundary is crossed exactly once, by a process, and its result arrives as text.

#include "e3g_support.hpp"
#include "e3g_legacy_side.hpp"

#include <array>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace e3g {
namespace {

namespace fs = std::filesystem;

std::vector<std::string> split_tabs(const std::string& line) {
    std::vector<std::string> cols;
    std::size_t start = 0;
    for (;;) {
        const std::size_t tab = line.find('\t', start);
        cols.push_back(line.substr(start, tab == std::string::npos ? std::string::npos
                                                                  : tab - start));
        if (tab == std::string::npos) break;
        start = tab + 1u;
    }
    return cols;
}

bool executable(const std::string& path) {
    std::error_code ec;
    return fs::exists(path, ec) && !fs::is_directory(path, ec) &&
           (fs::status(path, ec).permissions() & fs::perms::owner_exec) != fs::perms::none;
}

// Captures stdout of `command`.  Returns the text and sets `code` to the exit
// status.  A process that cannot be started yields an empty capture and code -1.
std::string run_capture(const std::string& command, int& code) {
    code = -1;
    FILE* pipe = ::popen(command.c_str(), "r");
    if (pipe == nullptr) return {};
    std::string text;
    std::array<char, 4096> buffer{};
    std::size_t got = 0;
    while ((got = std::fread(buffer.data(), 1, buffer.size(), pipe)) > 0) {
        text.append(buffer.data(), got);
    }
    const int status = ::pclose(pipe);
    code = (status == -1) ? -1 : (status / 256);
    return text;
}

std::string shell_quote(const std::string& text) {
    std::string out = "'";
    for (const char c : text) {
        if (c == '\'') {
            out += "'\\''";
        } else {
            out += c;
        }
    }
    out += "'";
    return out;
}

}  // namespace

LegacySummary run_legacy_checks(const std::string& root, const std::string& binary_arg) {
    LegacySummary summary;
    summary.root = root;
    // Resolved against `--root` exactly as `--oracle-bin` is, so the two external
    // helpers cannot disagree about what a relative path means.  Before this they
    // did: with `--root ..` the oracle was looked up under the root while the legacy
    // half was looked up under the working directory, so one spelling worked for one
    // binary and not the other.
    const std::string binary = resolve_path(root, binary_arg);
    summary.binary = binary;
    summary.binary_available = executable(binary);

    summary.log_lines.push_back("legacy half binary: " + binary);
    if (!summary.binary_available) {
        // §13.3: a missing W-V1 dependency blocks the legacy half; it never passes.
        summary.blocked = true;
        summary.blocked_reason = "legacy_half_binary_absent";
        LegacyRow row;
        row.check = "e3g.legacy.half";
        row.item_id = "W-V1";
        row.input_sha256 = "-";
        row.wire_sha256 = "-";
        row.wire_bytes = "-";
        row.expected = "bin/e3g_legacy_half present and runnable";
        row.actual = "absent: " + binary;
        row.verdict = "BLOCKED";
        row.log = "logs/E3-G-legacy.log#binary";
        summary.rows.push_back(row);
        return summary;
    }

    int code = -1;
    const std::string output = run_capture(shell_quote(binary) + " " + shell_quote(root) + " 2>&1",
                                           code);
    summary.ran = code >= 0;
    summary.exit_code = code;
    std::vector<std::string> lines;
    {
        std::size_t start = 0;
        while (start <= output.size()) {
            const std::size_t nl = output.find('\n', start);
            const std::string part =
                output.substr(start, nl == std::string::npos ? std::string::npos : nl - start);
            if (!part.empty()) lines.push_back(part);
            if (nl == std::string::npos) break;
            start = nl + 1u;
        }
    }
    for (const std::string& line : lines) {
        summary.raw.push_back(line);
        const std::vector<std::string> cols = split_tabs(line);
        if (cols.empty()) continue;
        const std::string& tag = cols[0];
        if (tag == "fixtures" && cols.size() >= 2) {
            summary.fixtures_found = static_cast<std::size_t>(std::strtoull(cols[1].c_str(),
                                                                            nullptr, 10));
        } else if (tag == "surface" && cols.size() >= 2) {
            summary.surface = cols[1];
        } else if (tag == "fixture" && cols.size() >= 4) {
            LegacyRow row;
            row.check = "e3g.legacy.hash_input";
            row.item_id = cols[1];
            row.input_sha256 = cols[2];
            row.wire_sha256 = cols[2];
            row.wire_bytes = cols[3];
            row.expected = "container SHA-256";
            row.actual = cols[2];
            row.verdict = "PASS";
            row.log = "logs/E3-G-legacy.log#" + cols[1];
            summary.rows.push_back(row);
        } else if (tag == "hash" && cols.size() >= 4) {
            ++summary.fixtures_hashed;
            LegacyRow row;
            row.check = "e3g.legacy.hash";
            row.item_id = cols[1];
            row.input_sha256 = cols[3];
            row.wire_sha256 = cols[3];
            row.wire_bytes = "-";
            row.expected = cols[1] + " present in W-V1/manifest.tsv with a matching SHA-256";
            row.actual = "manifest=" + cols[2];
            row.verdict = cols[2] == "match" ? "PASS" : "FAIL";
            row.log = "logs/E3-G-legacy.log#" + cols[1];
            summary.rows.push_back(row);
            if (cols[2] != "match") {
                ++summary.failures;
                summary.blocked = true;
                if (summary.blocked_reason.empty()) {
                    summary.blocked_reason = cols[2] == "absent" ? "unhashed_w_v1_fixture"
                                                                : "mis_hashed_w_v1_fixture";
                }
            }
        } else if (tag == "decode" && cols.size() >= 3) {
            LegacyRow row;
            row.check = "e3g.legacy.decode_v1";
            row.item_id = cols[1];
            row.input_sha256 = "-";
            row.wire_sha256 = "-";
            row.wire_bytes = "-";
            row.expected = "decode_v1=Ok";
            row.actual = "decode_v1=" + cols[2];
            row.verdict = cols[2] == "Ok" ? "PASS" : "FAIL";
            row.log = "logs/E3-G-legacy.log#" + cols[1];
            summary.rows.push_back(row);
            if (cols[2] != "Ok") {
                ++summary.failures;
                summary.log_lines.push_back("  " + cols[1] + ": decode_v1=" + cols[2]);
                continue;
            }
            ++summary.decode_ok;
            ++summary.fixtures_verified;
            if (cols.size() < 6) continue;

            // Step 8a: the recorded output digest against the harness's own.
            LegacyRow digest;
            digest.check = "e3g.legacy.denotation";
            digest.item_id = cols[1];
            digest.input_sha256 = "-";
            digest.wire_sha256 = "-";
            digest.wire_bytes = "-";
            digest.expected = cols[3];
            digest.actual = cols[4];
            digest.verdict = (!cols[3].empty() && cols[3] == cols[4]) ? "PASS" : "FAIL";
            digest.log = "logs/E3-G-legacy.log#" + cols[1];
            summary.rows.push_back(digest);
            if (digest.verdict == "PASS") ++summary.digest_ok; else ++summary.failures;

            // Step 8b: the decoded term must be a legal v2 encode input.
            LegacyRow canon;
            canon.check = "e3g.legacy.term_canonical";
            canon.item_id = cols[1];
            canon.input_sha256 = "-";
            canon.wire_sha256 = "-";
            canon.wire_bytes = "-";
            canon.expected = "check_canonical(ir)=Ok";
            canon.actual = cols[5];
            canon.verdict = cols[5] == "Ok" ? "PASS" : "FAIL";
            canon.log = "logs/E3-G-legacy.log#" + cols[1];
            summary.rows.push_back(canon);
            if (canon.verdict == "PASS") ++summary.canonical_ok; else ++summary.failures;

            if (cols.size() >= 7) summary.structure_sha.push_back(cols[6]);
        } else if (tag == "structure" && cols.size() >= 3) {
            // Attach the rendering to the fixture's decode row so the caller can
            // hand the term to the v2 side once its hash and digest have passed.
            for (LegacyRow& row : summary.rows) {
                if (row.check == "e3g.legacy.decode_v1" && row.item_id == cols[1]) {
                    // cols[0] is the tag and cols[1] the fixture name; the record is
                    // everything after them, tabs included.
                    std::string record;
                    for (std::size_t i = 2; i < cols.size(); ++i) {
                        if (i != 2) record += '\t';
                        record += cols[i];
                    }
                    if (!row.structure_text.empty()) row.structure_text += "\n";
                    row.structure_text += record;
                    break;
                }
            }
        } else if (tag == "payload" && cols.size() >= 4) {
            for (LegacyRow& row : summary.rows) {
                if (row.check == "e3g.legacy.decode_v1" && row.item_id == cols[1]) {
                    row.payload_hex.push_back(cols[3]);
                    ++summary.payloads_received;
                    break;
                }
            }
        } else if (tag == "fail" && cols.size() >= 3) {
            ++summary.failures;
            summary.log_lines.push_back("  " + cols[1] + ": " + cols[2]);
        } else if (tag == "dir" && cols.size() >= 2) {
            summary.log_lines.push_back("W-V1 directory: " + cols[1]);
        }
    }

    if (summary.fixtures_found == 0 && summary.blocked_reason.empty()) {
        summary.blocked = true;
        summary.blocked_reason = "missing_w_v1_corpus";
    }

    // The half's own row: it must have run, and its surface must be the read-only
    // one C08 declares.
    {
        LegacyRow row;
        row.check = "e3g.legacy.half";
        row.item_id = "W-V1";
        row.input_sha256 = "-";
        row.wire_sha256 = "-";
        row.wire_bytes = "-";
        row.expected = "exit 0";
        row.actual = "exit " + std::to_string(summary.exit_code);
        row.verdict = summary.exit_code == 0 ? "PASS" : "FAIL";
        row.log = "logs/E3-G-legacy.log#half";
        summary.rows.push_back(row);
        if (summary.exit_code != 0) ++summary.failures;
    }
    {
        LegacyRow row;
        row.check = "e3g.legacy.readonly_surface";
        row.item_id = "W-V1";
        row.input_sha256 = "-";
        row.wire_sha256 = "-";
        row.wire_bytes = "-";
        row.expected = "decode_v1/looks_like_v1 only (no v1 emitter)";
        row.actual = summary.surface.empty() ? "absent" : summary.surface;
        row.verdict = summary.surface == "C08 read-only: decode_v1, looks_like_v1" ? "PASS"
                                                                                   : "FAIL";
        row.log = "logs/E3-G-legacy.log#readonly";
        summary.rows.push_back(row);
        if (row.verdict != "PASS") ++summary.failures;
    }
    {
        LegacyRow row;
        row.check = "e3g.legacy.w_v1_corpus";
        row.item_id = "W-V1";
        row.input_sha256 = "-";
        row.wire_sha256 = "-";
        row.wire_bytes = std::to_string(summary.fixtures_found);
        row.expected = "every fixture hash-certified, decoded, and byte-exact against its "
                       "recorded output SHA-256";
        if (summary.blocked) {
            row.actual = "blocked:reason=" + summary.blocked_reason + ";gates=E3-G";
            row.verdict = "BLOCKED";
        } else {
            row.actual = "verified=" + std::to_string(summary.fixtures_verified) +
                         " decode_ok=" + std::to_string(summary.decode_ok) +
                         " digest_ok=" + std::to_string(summary.digest_ok) +
                         " canonical_ok=" + std::to_string(summary.canonical_ok);
            row.verdict = (summary.failures == 0 &&
                           summary.fixtures_verified == summary.fixtures_found &&
                           summary.digest_ok == summary.fixtures_found)
                              ? "PASS"
                              : "FAIL";
        }
        row.log = "logs/E3-G-legacy.log#w_v1_corpus";
        summary.rows.push_back(row);
        if (row.verdict == "FAIL") ++summary.failures;
    }
    summary.log_lines.push_back("fixtures=" + std::to_string(summary.fixtures_found) +
                                " hashed=" + std::to_string(summary.fixtures_hashed) +
                                " verified=" + std::to_string(summary.fixtures_verified) +
                                " decode_ok=" + std::to_string(summary.decode_ok) +
                                " digest_ok=" + std::to_string(summary.digest_ok) +
                                " canonical_ok=" + std::to_string(summary.canonical_ok));
    if (summary.blocked) {
        summary.log_lines.push_back("BLOCKED: " + summary.blocked_reason);
    }
    return summary;
}

}  // namespace e3g
