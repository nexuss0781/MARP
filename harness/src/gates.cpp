#include "marp/harness/gates.hpp"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <algorithm>
#include <filesystem>
#include <thread>
#include <mutex>

namespace marp::harness {

namespace fs = std::filesystem;

bool write_row(const fs::path& tsv_path, const Row& row) {
    // Ensure parent directory exists
    fs::create_directories(tsv_path.parent_path());
    
    // Check if file exists and is empty (for header)
    bool is_first = !fs::exists(tsv_path) || fs::file_size(tsv_path) == 0;
    
    // Open target file in append mode
    std::ofstream ofs(tsv_path, std::ios::app);
    if (!ofs) return false;
    
    // Write header if first row
    if (is_first) {
        ofs << "gate\tfixture\tinput_bytes\twire_bytes\tratio_num\tratio_den\tsha_match\tverdict\tlog\n";
    }
    
    // Write row
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

EnvRecord capture_env_record() {
    EnvRecord env;
    
    // Date UTC
    auto now = std::chrono::system_clock::now();
    auto now_c = std::chrono::system_clock::to_time_t(now);
    std::tm tm = *std::gmtime(&now_c);
    char buf[64];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
    env.date_utc = buf;
    
    // Host
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == 0) {
        env.host = hostname;
    }
    
    // Kernel
    FILE* fp = popen("uname -r", "r");
    if (fp) {
        char kernel[256];
        if (fgets(kernel, sizeof(kernel), fp)) {
            env.kernel = kernel;
            if (!env.kernel.empty() && env.kernel.back() == '\n') env.kernel.pop_back();
        }
        pclose(fp);
    }
    
    // nproc
    env.nproc = std::thread::hardware_concurrency();
    
    // Memory
    fp = popen("grep MemTotal /proc/meminfo | awk '{print $2}'", "r");
    if (fp) {
        char mem[64];
        if (fgets(mem, sizeof(mem), fp)) {
            env.mem_total_kib = std::strtol(mem, nullptr, 10);
        }
        pclose(fp);
    }
    
    // Disk
    fp = popen("df -h . | tail -1 | awk '{print $4}'", "r");
    if (fp) {
        char disk[64];
        if (fgets(disk, sizeof(disk), fp)) {
            env.disk = disk;
            if (!env.disk.empty() && env.disk.back() == '\n') env.disk.pop_back();
        }
        pclose(fp);
    }
    
    // Compiler
    fp = popen("g++ --version | head -1", "r");
    if (fp) {
        char comp[256];
        if (fgets(comp, sizeof(comp), fp)) {
            env.compiler = comp;
            if (!env.compiler.empty() && env.compiler.back() == '\n') env.compiler.pop_back();
        }
        pclose(fp);
    }
    
    // Make
    fp = popen("make --version | head -1", "r");
    if (fp) {
        char mk[256];
        if (fgets(mk, sizeof(mk), fp)) {
            env.make = mk;
            if (!env.make.empty() && env.make.back() == '\n') env.make.pop_back();
        }
        pclose(fp);
    }
    
    // Engine SHA256
    fp = popen("find ../engine -type f -name '*.cpp' -o -name '*.hpp' | sort | xargs sha256sum | sha256sum | awk '{print $1}'", "r");
    if (fp) {
        char sha[65];
        if (fgets(sha, sizeof(sha), fp)) {
            env.engine_sha256 = sha;
            if (!env.engine_sha256.empty() && env.engine_sha256.back() == '\n') env.engine_sha256.pop_back();
        }
        pclose(fp);
    }
    
    // Test SHA256
    fp = popen("find ../tests -type f -name '*.cpp' | sort | xargs sha256sum | sha256sum | awk '{print $1}'", "r");
    if (fp) {
        char sha[65];
        if (fgets(sha, sizeof(sha), fp)) {
            env.test_sha256 = sha;
            if (!env.test_sha256.empty() && env.test_sha256.back() == '\n') env.test_sha256.pop_back();
        }
        pclose(fp);
    }
    
    // Fixture manifest SHA256 (placeholder for now)
    env.fixture_manifest_sha256 = "N/A";
    
    return env;
}

int render(const fs::path& tsv_dir, const fs::path& out) {
    // Read all TSV files in the directory
    std::vector<fs::path> tsv_files;
    for (const auto& entry : fs::directory_iterator(tsv_dir)) {
        if (entry.path().extension() == ".tsv") {
            tsv_files.push_back(entry.path());
        }
    }
    
    if (tsv_files.empty()) {
        return 1;
    }
    
    std::ofstream ofs(out);
    if (!ofs) return 1;
    
    ofs << "# ACCEPTANCE REPORT\n\n";
    ofs << "Generated: " << capture_env_record().date_utc << "\n\n";
    
    for (const auto& tsv : tsv_files) {
        std::ifstream ifs(tsv);
        if (!ifs) continue;
        
        ofs << "## " << tsv.filename().string() << "\n\n";
        ofs << "| Gate | Fixture | Input Bytes | Wire Bytes | Ratio Num | Ratio Den | SHA Match | Verdict | Log |\n";
        ofs << "|------|---------|-------------|------------|-----------|-----------|-----------|---------|-----|\n";
        
        std::string line;
        bool first = true;
        while (std::getline(ifs, line)) {
            if (first) { first = false; continue; } // Skip header
            if (line.empty()) continue;
            
            std::istringstream iss(line);
            std::string gate, fixture, input_bytes, wire_bytes, ratio_num, ratio_den, sha_match, verdict, log;
            std::getline(iss, gate, '\t');
            std::getline(iss, fixture, '\t');
            std::getline(iss, input_bytes, '\t');
            std::getline(iss, wire_bytes, '\t');
            std::getline(iss, ratio_num, '\t');
            std::getline(iss, ratio_den, '\t');
            std::getline(iss, sha_match, '\t');
            std::getline(iss, verdict, '\t');
            std::getline(iss, log);
            
            ofs << "| " << gate << " | " << fixture << " | " << input_bytes 
                << " | " << wire_bytes << " | " << ratio_num << " | " << ratio_den
                << " | " << sha_match << " | " << verdict << " | " << log << " |\n";
        }
        ofs << "\n";
    }
    
    return 0;
}

int verify_evidence(const fs::path& manifest_path) {
    std::ifstream ifs(manifest_path);
    if (!ifs) return 1;
    
    std::string line;
    while (std::getline(ifs, line)) {
        if (line.empty()) continue;
        std::istringstream iss(line);
        std::string expected_sha, filename;
        iss >> expected_sha >> filename;
        
        fs::path file_path = manifest_path.parent_path() / filename;
        if (!fs::exists(file_path)) {
            return 1;
        }
        
        // Compute SHA256
        std::string cmd = "sha256sum " + file_path.string() + " | awk '{print $1}'";
        FILE* fp = popen(cmd.c_str(), "r");
        if (!fp) return 1;
        
        char actual_sha[65];
        if (!fgets(actual_sha, sizeof(actual_sha), fp)) {
            pclose(fp);
            return 1;
        }
        pclose(fp);
        
        std::string actual(actual_sha);
        if (!actual.empty() && actual.back() == '\n') actual.pop_back();
        
        if (actual != expected_sha) {
            return 1;
        }
    }
    
    return 0;
}

int run_gate(std::string_view gate_id, const fs::path& root) {
    // This is a stub - actual implementation in e0_selftest.cpp and e1_gate.cpp
    (void)gate_id;
    (void)root;
    return 1;
}

} // namespace marp::harness