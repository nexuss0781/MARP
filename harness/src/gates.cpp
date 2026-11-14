#include "marp/harness/gates.hpp"
#include <mapr/e1_sha256.hpp>
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <thread>
#include <unistd.h>

namespace marp::harness {

namespace fs = std::filesystem;

namespace {

std::string run_capture(const char* command) {
    std::string out;
    FILE* pipe = popen(command, "r");
    if (pipe == nullptr) return out;
    char buffer[512];
    while (std::fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        out += buffer;
    }
    pclose(pipe);
    while (!out.empty() && (out.back() == '\n' || out.back() == '\r')) {
        out.pop_back();
    }
    return out;
}

std::string utc_timestamp() {
    const auto now = std::chrono::system_clock::now();
    const std::time_t now_c = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
    gmtime_r(&now_c, &tm);
    char buffer[64];
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buffer;
}

std::string hex_of(const std::array<uint8_t, 32>& digest) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (uint8_t byte : digest) {
        oss << std::setw(2) << static_cast<int>(byte);
    }
    return oss.str();
}

void hash_tree(const fs::path& root, const fs::path& dir,
               std::vector<fs::path>& files) {
    std::error_code ec;
    if (!fs::is_directory(root / dir, ec)) return;
    for (const auto& entry : fs::recursive_directory_iterator(root / dir, ec)) {
        if (ec) break;
        if (!entry.is_regular_file()) continue;
        const fs::path ext = entry.path().extension();
        if (ext != ".cpp" && ext != ".hpp") continue;
        files.push_back(entry.path());
    }
}

std::string tree_sha256(const fs::path& root, const std::vector<fs::path>& dirs) {
    std::vector<fs::path> files;
    for (const auto& dir : dirs) hash_tree(root, dir, files);
    std::sort(files.begin(), files.end());
    std::string manifest;
    for (const auto& file : files) {
        std::error_code ec;
        const fs::path rel = fs::relative(file, root, ec);
        manifest += (ec ? file.string() : rel.generic_string());
        manifest += ' ';
        manifest += sha256_file_hex(file);
        manifest += '\n';
    }
    return sha256_hex(manifest);
}

} // namespace

bool write_row(const fs::path& tsv_path, const Row& row) {
    std::error_code ec;
    fs::create_directories(tsv_path.parent_path(), ec);

    const bool is_first = !fs::exists(tsv_path) || fs::file_size(tsv_path) == 0;

    std::ofstream ofs(tsv_path, std::ios::app);
    if (!ofs) return false;

    if (is_first) {
        ofs << "gate\tfixture\tinput_bytes\twire_bytes\tratio_num\tratio_den\t"
               "sha_match\tverdict\tlog\n";
    }

    ofs << row.gate << '\t'
        << row.fixture << '\t'
        << row.input_bytes.to_decimal() << '\t'
        << row.wire_bytes.to_decimal() << '\t'
        << row.ratio_num << '\t'
        << row.ratio_den << '\t'
        << (row.sha_match ? "true" : "false") << '\t'
        << row.verdict << '\t'
        << row.log << '\n';

    return static_cast<bool>(ofs);
}

bool write_evidence_tsv(const fs::path& tsv_path, std::vector<EvidenceRow> rows) {
    std::error_code ec;
    fs::create_directories(tsv_path.parent_path(), ec);

    for (const auto& row : rows) {
        if (row.verdict != "PASS" && row.verdict != "FAIL" && row.verdict != "BLOCKED") {
            return false;
        }
        const std::string* fields[] = {&row.check, &row.corpus, &row.item_id,
                                       &row.input_sha256, &row.expected,
                                       &row.actual, &row.verdict, &row.log};
        for (const std::string* field : fields) {
            if (field->find('\t') != std::string::npos ||
                field->find('\n') != std::string::npos ||
                field->find('\r') != std::string::npos) {
                return false;
            }
        }
    }

    std::stable_sort(rows.begin(), rows.end(),
                     [](const EvidenceRow& a, const EvidenceRow& b) {
                         if (a.check != b.check) return a.check < b.check;
                         if (a.corpus != b.corpus) return a.corpus < b.corpus;
                         return a.item_id < b.item_id;
                     });

    fs::path temp = tsv_path;
    temp += ".tmp";

    {
        std::ofstream ofs(temp, std::ios::trunc);
        if (!ofs) return false;
        ofs << "check\tcorpus\titem_id\tinput_sha256\texpected\tactual\tverdict\tlog\n";
        for (const auto& row : rows) {
            ofs << row.check << '\t'
                << row.corpus << '\t'
                << row.item_id << '\t'
                << row.input_sha256 << '\t'
                << row.expected << '\t'
                << row.actual << '\t'
                << row.verdict << '\t'
                << row.log << '\n';
        }
        ofs.flush();
        if (!ofs) return false;
    }

    fs::rename(temp, tsv_path, ec);
    if (ec) {
        fs::remove(temp, ec);
        return false;
    }
    return true;
}

std::vector<EvidenceRow> read_evidence_tsv(const fs::path& tsv_path) {
    std::vector<EvidenceRow> rows;
    std::ifstream ifs(tsv_path);
    if (!ifs) return rows;

    std::string line;
    std::getline(ifs, line); // header
    while (std::getline(ifs, line)) {
        if (line.empty()) continue;
        std::istringstream iss(line);
        EvidenceRow row;
        std::getline(iss, row.check, '\t');
        std::getline(iss, row.corpus, '\t');
        std::getline(iss, row.item_id, '\t');
        std::getline(iss, row.input_sha256, '\t');
        std::getline(iss, row.expected, '\t');
        std::getline(iss, row.actual, '\t');
        std::getline(iss, row.verdict, '\t');
        std::getline(iss, row.log);
        if (!row.check.empty()) rows.push_back(std::move(row));
    }
    return rows;
}

std::string sha256_hex(std::string_view data) {
    auto digest = mapr::Sha256::hash(data);
    if (!digest.ok()) return "";
    return hex_of(digest.value());
}

std::string sha256_file_hex(const fs::path& path) {
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) return "";
    mapr::Sha256 ctx;
    std::string buffer(64 * 1024, '\0');
    while (ifs) {
        ifs.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        const std::streamsize got = ifs.gcount();
        if (got > 0) {
            const auto err = ctx.update(std::string_view(
                buffer.data(), static_cast<size_t>(got)));
            if (err != mapr::ErrCode::Ok) return "";
        }
    }
    auto digest = ctx.finish();
    if (!digest.ok()) return "";
    return hex_of(digest.value());
}

int render(const fs::path& tsv_dir, const fs::path& out) {
    std::error_code ec;
    std::vector<fs::path> tsv_files;
    if (fs::is_directory(tsv_dir, ec)) {
        for (const auto& entry : fs::directory_iterator(tsv_dir, ec)) {
            if (ec) break;
            if (entry.is_regular_file() && entry.path().extension() == ".tsv") {
                tsv_files.push_back(entry.path());
            }
        }
    }
    std::sort(tsv_files.begin(), tsv_files.end());
    if (tsv_files.empty()) return 1;

    bool any_fail = false;
    std::vector<std::vector<EvidenceRow>> by_file;
    by_file.reserve(tsv_files.size());
    for (const auto& tsv : tsv_files) {
        by_file.push_back(read_evidence_tsv(tsv));
        for (const auto& row : by_file.back()) {
            if (row.verdict != "PASS") any_fail = true;
        }
    }

    // A failed render must never overwrite the acceptance record. Write the
    // failure to a sidecar instead and return nonzero.
    fs::path target = out;
    if (any_fail) {
        target = out.parent_path() /
                 (out.stem().string() + ".FAIL" + out.extension().string());
    }

    fs::create_directories(target.parent_path(), ec);
    std::ofstream ofs(target, std::ios::trunc);
    if (!ofs) return 1;

    ofs << "# ACCEPTANCE REPORT\n\n";
    ofs << "Generated: " << utc_timestamp() << "\n\n";

    for (size_t i = 0; i < tsv_files.size(); ++i) {
        ofs << "## " << tsv_files[i].filename().string() << "\n\n";
        ofs << "| Check | Corpus | Item | Input SHA-256 | Expected | Actual | Verdict | Log |\n";
        ofs << "|-------|--------|------|---------------|----------|--------|---------|-----|\n";
        for (const auto& row : by_file[i]) {
            ofs << "| " << row.check << " | " << row.corpus << " | " << row.item_id
                << " | " << row.input_sha256 << " | " << row.expected << " | "
                << row.actual << " | " << row.verdict << " | " << row.log << " |\n";
        }
        ofs << "\n";
    }

    ofs << "RESULT: " << (any_fail ? "FAIL" : "PASS") << "\n";
    return any_fail ? 1 : 0;
}

bool all_rows_pass(const fs::path& tsv_dir) {
    std::error_code ec;
    bool saw_row = false;
    if (!fs::is_directory(tsv_dir, ec)) return false;
    for (const auto& entry : fs::directory_iterator(tsv_dir, ec)) {
        if (ec) return false;
        if (!entry.is_regular_file() || entry.path().extension() != ".tsv") continue;
        for (const auto& row : read_evidence_tsv(entry.path())) {
            saw_row = true;
            if (row.verdict != "PASS") return false;
        }
    }
    return saw_row;
}

int verify_evidence(const fs::path& manifest_path) {
    std::ifstream ifs(manifest_path);
    if (!ifs) return 1;

    fs::path root = manifest_path.parent_path();
    while (!root.empty() && !fs::exists(root / "specs_and_reports")) {
        const fs::path parent = root.parent_path();
        if (parent == root) break;
        root = parent;
    }
    if (root.empty()) root = manifest_path.parent_path();

    bool saw_entry = false;
    std::string line;
    while (std::getline(ifs, line)) {
        if (line.empty()) continue;
        const std::size_t sep = line.find("  ");
        if (sep == std::string::npos) return 1;
        const std::string expected = line.substr(0, sep);
        const std::string rel = line.substr(sep + 2);
        if (rel.empty()) return 1;

        const fs::path file = root / rel;
        const std::string actual = sha256_file_hex(file);
        if (actual.empty() || actual != expected) return 1;
        saw_entry = true;
    }
    return saw_entry ? 0 : 1;
}

EnvRecord capture_env_record() {
    return capture_env_record(fs::path("."));
}

EnvRecord capture_env_record(const fs::path& root) {
    EnvRecord env;
    env.date_utc = utc_timestamp();

    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == 0) {
        hostname[sizeof(hostname) - 1] = '\0';
        env.host = hostname;
    }

    env.kernel = run_capture("uname -r");
    env.nproc = static_cast<int>(std::thread::hardware_concurrency());

    const std::string mem = run_capture("grep MemTotal /proc/meminfo | awk '{print $2}'");
    env.mem_total_kib = std::strtol(mem.c_str(), nullptr, 10);

    env.disk = run_capture("df -h . | tail -1 | awk '{print $4}'");
    env.compiler = run_capture("g++ --version | head -1");
    env.make = run_capture("make --version | head -1");

    env.engine_sha256 = tree_sha256(root, {"engine/src", "include/mapr"});
    env.test_sha256 = tree_sha256(root, {"tests", "harness/tests", "harness/src", "harness/include"});

    const fs::path corpus = root / "specs_and_reports" / "v2" / "corpus" / "E1" / "corpus.tsv";
    const std::string corpus_sha = sha256_file_hex(corpus);
    env.fixture_manifest_sha256 = corpus_sha.empty() ? "N/A" : corpus_sha;

    return env;
}

} // namespace marp::harness
