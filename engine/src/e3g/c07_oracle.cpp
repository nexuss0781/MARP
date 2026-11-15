// MARP v2 — C07 WIRE — H3 oracle cross-check through a separate process.
//
// This translation unit is part of the *harness*, not of the component: it may
// name another process, a temporary file, and a stdout parser.  Nothing under
// `include/mapr/e3` or `engine/src/e3` does any of that (E3 §11).

#include "c07_oracle.hpp"

#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <utility>
#include <vector>

#if defined(_WIN32)
#define C07_POPEN _popen
#define C07_PCLOSE _pclose
#else
#include <sys/stat.h>
#include <unistd.h>
#define C07_POPEN popen
#define C07_PCLOSE pclose
#endif

namespace c07 {
namespace {

// Extracts `key\tvalue` from the oracle's tab-separated stdout.
std::string field(const std::string& text, const std::string& key) {
    const std::string needle = key + "\t";
    std::size_t pos = 0;
    while ((pos = text.find(needle, pos)) != std::string::npos) {
        const bool at_line_start = (pos == 0) || (text[pos - 1] == '\n');
        if (at_line_start) {
            const std::size_t start = pos + needle.size();
            const std::size_t end = text.find('\n', start);
            return text.substr(start, end == std::string::npos ? std::string::npos : end - start);
        }
        pos += needle.size();
    }
    return {};
}

std::string run(const std::string& command) {
    std::string output;
    FILE* pipe = C07_POPEN(command.c_str(), "r");
    if (pipe == nullptr) return output;
    std::array<char, 4096> buffer{};
    while (std::fgets(buffer.data(), static_cast<int>(buffer.size()), pipe) != nullptr) {
        output += buffer.data();
    }
    C07_PCLOSE(pipe);
    return output;
}

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

}  // namespace

bool write_temp_file(const std::vector<std::uint8_t>& bytes, std::string& path) {
    std::string pattern = "/tmp/c07-oracle-XXXXXX";
    std::vector<char> writable(pattern.begin(), pattern.end());
    writable.push_back('\0');
    const int fd = mkstemp(writable.data());
    if (fd < 0) return false;
    close(fd);
    path.assign(writable.data());
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) return false;
    out.write(reinterpret_cast<const char*>(bytes.data()),
              static_cast<std::streamsize>(bytes.size()));
    if (!out) return false;
    return true;
}

OracleResult oracle_inspect(const std::string& oracle_path,
                            const std::vector<std::uint8_t>& wire, bool want_digest) {
    OracleResult result;
    {
        std::ifstream probe(oracle_path, std::ios::binary);
        result.available = static_cast<bool>(probe);
    }
    if (!result.available) return result;

    std::string path;
    if (!write_temp_file(wire, path)) return result;

    const std::string quoted_bin = shell_quote(oracle_path);
    const std::string quoted_file = shell_quote(path);

    // `inspect` prints the structure (header, one line per node, trailer); it is
    // the only command that reports the declared total length.
    result.raw = run(quoted_bin + " inspect " + quoted_file + " 2>&1");
    result.exit_code =
        std::system((quoted_bin + " inspect " + quoted_file + " >/dev/null 2>&1").c_str());
    result.ran = true;
    result.total_length = field(result.raw, "total_length");
    if (result.total_length.empty()) {
        // `inspect`'s header line puts total_length in a positional column; take
        // the sixth tab-separated field of the `header` line instead.
        const std::size_t at = result.raw.find("header\t");
        if (at != std::string::npos) {
            const std::size_t end_line = result.raw.find('\n', at);
            const std::string line = result.raw.substr(at, end_line == std::string::npos
                                                              ? std::string::npos
                                                              : end_line - at);
            std::size_t start_field = 0;
            unsigned index = 0;
            for (;;) {
                const std::size_t tab = line.find('\t', start_field);
                const std::string value = line.substr(
                    start_field, tab == std::string::npos ? std::string::npos : tab - start_field);
                if (index == 5u) {  // 0:header 1:major 2:minor 3:flags 4:header_bytes 5:total
                    result.total_length = value;
                    break;
                }
                if (tab == std::string::npos) break;
                start_field = tab + 1;
                ++index;
            }
        }
    }
#if !defined(_WIN32)
    std::remove(path.c_str());
#endif
    if (!want_digest) return result;

    // `verify` evaluates the whole denotation and exits 0 iff it agrees with the
    // declared length; there is no `--info` flag, so the digest itself is not
    // reported back.  Acceptance is the cross-check C07 uses here.
    std::string verify_path;
    if (!write_temp_file(wire, verify_path)) return result;
    const std::string quoted_verify = shell_quote(verify_path);
    result.raw += run(quoted_bin + " verify " + quoted_verify + " 2>&1");
    const int verify_code =
        std::system((quoted_bin + " verify " + quoted_verify + " >/dev/null 2>&1").c_str());
    if (verify_code != 0) result.exit_code = verify_code;
    const std::string digest = field(result.raw, "output_sha256");
    if (!digest.empty()) result.output_sha256 = digest;
#if !defined(_WIN32)
    std::remove(verify_path.c_str());
#endif
    return result;
}

}  // namespace c07
