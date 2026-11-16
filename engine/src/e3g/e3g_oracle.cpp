// MARP v2 — E3 WIRE — E3-G integrated gate — independent H3 oracle adapter.
//
// Harness-only: this translation unit names a child process and a temporary
// file.  Nothing under `include/mapr/e3` or `engine/src/e3` does (E3 §11).

#include "e3g_oracle.hpp"

#include <array>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <string>
#include <utility>
#include <vector>

#if defined(_WIN32)
#define E3G_POPEN _popen
#define E3G_PCLOSE _pclose
#else
#include <sys/stat.h>
#include <unistd.h>
#define E3G_POPEN popen
#define E3G_PCLOSE pclose
#endif

namespace e3g {
namespace {

std::string shell_quote(const std::string& text) {
    std::string quoted = "'";
    for (const char c : text) {
        if (c == '\'') {
            quoted += "'\\''";
        } else {
            quoted.push_back(c);
        }
    }
    quoted.push_back('\'');
    return quoted;
}

// Runs `command` and returns stdout+stderr.  `exit_code` receives the status.
std::string run_command(const std::string& command, int& exit_code) {
    std::string output;
    FILE* pipe = E3G_POPEN(command.c_str(), "r");
    if (pipe == nullptr) {
        exit_code = -1;
        return output;
    }
    std::array<char, 4096> buffer{};
    while (std::fgets(buffer.data(), static_cast<int>(buffer.size()), pipe) != nullptr) {
        output += buffer.data();
    }
    const int status = E3G_PCLOSE(pipe);
    exit_code = status;
    return output;
}

std::vector<std::string> split_tabs(const std::string& line) {
    std::vector<std::string> columns;
    std::size_t start = 0;
    for (;;) {
        const std::size_t tab = line.find('\t', start);
        columns.push_back(line.substr(start, tab == std::string::npos ? std::string::npos
                                                                    : tab - start));
        if (tab == std::string::npos) break;
        start = tab + 1;
    }
    return columns;
}

// Parses the `inspect` TSV documented in harness/oracle/src/decode.cpp
// (`write_inspect_tsv`).
// The oracle's own structural key, in the same line shape the harness uses for
// its `Ir`.  Only fields the oracle derived from the bytes appear, and none of
// them is copied from the harness: the comparison in `e3g_checks.cpp` is between
// two independent decoders' renderings of one container.
void build_key(OracleOutcome& out) {
    if (out.total_length.empty()) return;
    std::string text;
    text += "header\t" + out.version_major + "\t" + out.version_minor + "\ttotal=" +
            out.total_length + "\t" + out.header_bytes + "\n";
    for (std::size_t i = 0; i < out.atoms.size(); ++i) {
        const std::vector<std::string> cols = split_tabs(out.atoms[i]);  // klass, len, sha
        if (cols.size() < 3) {
            out.key_text = "unparsable-atom";
            return;
        }
        text += "atom\t" + std::to_string(i) + "\t" + cols[0] + "\t" + cols[1] + "\t" +
                cols[2] + "\n";
    }
    for (std::size_t i = 0; i < out.nodes.size(); ++i) {
        const std::vector<std::string> cols = split_tabs(out.nodes[i]);
        if (cols.size() < 6) {
            out.key_text = "unparsable-node";
            return;
        }
        text += "node\t" + std::to_string(i) + "\t" + cols[0] + "\t" + cols[1] + "\t" +
                cols[2] + "\t" + cols[3] + "\t" + cols[4] + "\t" + cols[5] + "\n";
    }
    text += "trailer\troot=" + out.trailer_root_id + "\tatoms=" + out.trailer_atom_count +
            "\tnodes=" + out.trailer_node_count + "\n";
    out.key_text = std::move(text);
}

void parse_inspect(OracleOutcome& out, const std::string& text) {
    std::size_t start = 0;
    while (start <= text.size()) {
        const std::size_t end = text.find('\n', start);
        const std::string line =
            text.substr(start, end == std::string::npos ? std::string::npos : end - start);
        if (!line.empty()) {
            const std::vector<std::string> c = split_tabs(line);
            const std::string& tag = c[0];
            if (tag == "header" && c.size() >= 12) {
                out.file_bytes = "";  // `header` does not carry it; trailer does
                out.version_major = c[1];
                out.version_minor = c[2];
                out.flags = c[3];
                out.header_bytes = c[4];
                out.total_length = c[5];
                out.total_length_big_len = c[6];
                out.atom_offset = c[7];
                out.node_offset = c[8];
                out.index_offset = c[9];
                out.trailer_offset = c[10];
                out.file_crc32 = c[11];
            } else if (tag == "atom" && c.size() >= 5) {
                out.atoms.push_back(c[2] + "\t" + c[3] + "\t" + c[4]);
            } else if (tag == "node" && c.size() >= 8) {
                // node <id> <kind> <kind_name> <argc> <args> <params> <len>  (8 columns)
                out.nodes.push_back(c[2] + "\t" + c[3] + "\t" + c[4] + "\t" + c[5] + "\t" + c[6] +
                                "\t" + c[7]);
            } else if (tag == "index" && c.size() >= 5) {
                out.index.push_back(c[2] + "\t" + c[3] + "\t" + c[4]);
            } else if (tag == "trailer" && c.size() >= 6) {
                out.trailer_file_bytes = c[1];
                out.trailer_root_id = c[2];
                out.trailer_atom_count = c[3];
                out.trailer_node_count = c[4];
                out.trailer_crc32 = c[5];
            }
        }
        if (end == std::string::npos) break;
        start = end + 1;
    }
    build_key(out);
}

}  // namespace

std::string write_temp_file(const std::vector<u8>& bytes, const char* tag) {
    std::string pattern = std::string("/tmp/e3g-") + tag + "-XXXXXX";
    std::vector<char> writable(pattern.begin(), pattern.end());
    writable.push_back('\0');
#if defined(_WIN32)
    return {};
#else
    const int fd = mkstemp(writable.data());
    if (fd < 0) return {};
    close(fd);
    std::ofstream out(writable.data(), std::ios::binary | std::ios::trunc);
    if (!out) return {};
    if (!bytes.empty()) {
        out.write(reinterpret_cast<const char*>(bytes.data()),
                  static_cast<std::streamsize>(bytes.size()));
    }
    if (!out) return {};
    return std::string(writable.data());
#endif
}

void remove_temp_file(const std::string& path) {
#if !defined(_WIN32)
    if (!path.empty()) std::remove(path.c_str());
#else
    (void)path;
#endif
}

bool oracle_available(const std::string& oracle_path) {
    if (oracle_path.empty()) return false;
#if defined(_WIN32)
    std::ifstream probe(oracle_path, std::ios::binary);
    return static_cast<bool>(probe);
#else
    struct stat info {};
    if (stat(oracle_path.c_str(), &info) != 0) return false;
    if ((info.st_mode & S_IXUSR) == 0) return false;
    return S_ISREG(info.st_mode);
#endif
}

OracleOutcome oracle_inspect(const std::string& oracle_path, const std::vector<u8>& wire) {
    OracleOutcome result;
    result.available = oracle_available(oracle_path);
    if (!result.available) {
        result.error = "oracle binary missing";
        return result;
    }
    const std::string path = write_temp_file(wire, "inspect");
    if (path.empty()) {
        result.error = "cannot write temporary file";
        return result;
    }
    const std::string command =
        shell_quote(oracle_path) + " inspect " + shell_quote(path) + " 2>&1";
    result.raw = run_command(command, result.exit_code);
    result.ran = true;
    parse_inspect(result, result.raw);
    remove_temp_file(path);
    return result;
}

OracleOutcome oracle_decode(const std::string& oracle_path, const std::vector<u8>& wire) {
    OracleOutcome result;
    result.available = oracle_available(oracle_path);
    if (!result.available) {
        result.error = "oracle binary missing";
        return result;
    }
    const std::string in_path = write_temp_file(wire, "decode-in");
    if (in_path.empty()) {
        result.error = "cannot write temporary file";
        return result;
    }
    const std::string out_path = write_temp_file({}, "decode-out");
    if (out_path.empty()) {
        remove_temp_file(in_path);
        result.error = "cannot write temporary file";
        return result;
    }
    const std::string command = shell_quote(oracle_path) + " decode " + shell_quote(in_path) + " " +
                                shell_quote(out_path) + " 2>&1";
    result.raw = run_command(command, result.exit_code);
    result.ran = true;
    std::vector<u8> decoded;
    if (result.exit_code == 0 && read_file_bytes(out_path, decoded)) {
        result.output_sha256 = sha_of_bytes(decoded);
        result.total_length = std::to_string(decoded.size());
    }
    remove_temp_file(in_path);
    remove_temp_file(out_path);
    return result;
}

OracleOutcome oracle_verify(const std::string& oracle_path, const std::vector<u8>& wire,
                            const std::string& expect_sha256) {
    OracleOutcome result;
    result.available = oracle_available(oracle_path);
    if (!result.available) {
        result.error = "oracle binary missing";
        return result;
    }
    const std::string path = write_temp_file(wire, "verify");
    if (path.empty()) {
        result.error = "cannot write temporary file";
        return result;
    }
    std::string command = shell_quote(oracle_path) + " verify " + shell_quote(path);
    if (!expect_sha256.empty()) command += " --sha256 " + expect_sha256;
    command += " 2>&1";
    result.raw = run_command(command, result.exit_code);
    result.ran = true;
    remove_temp_file(path);
    return result;
}

}  // namespace e3g
