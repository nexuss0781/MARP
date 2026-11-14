#include "marp/harness/e0_selftest.hpp"
#include "marp/harness/e1_gate.hpp"
#include "marp/harness/gates.hpp"
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <string>

namespace fs = std::filesystem;

namespace {

void print_usage(const char* program) {
    std::cerr << "Usage: " << program << " [options]\n";
    std::cerr << "Options:\n";
    std::cerr << "  --gate E0-G|E1-G    Run the specified gate\n";
    std::cerr << "  --root <path>       Repository root (default: .)\n";
    std::cerr << "  --threads <n>       Worker count for E1-G (default: 1)\n";
    std::cerr << "  --self-test         Run the E0-G false-gate self-test\n";
    std::cerr << "  --render            Render ACCEPTANCE.md from gate TSVs\n";
    std::cerr << "  --verify-evidence   Verify the SHA256SUMS evidence manifest\n";
    std::cerr << "  --help              Show this help\n";
}

std::string join_command_line(int argc, char** argv) {
    std::string line;
    for (int i = 0; i < argc; ++i) {
        if (i != 0) line.push_back(' ');
        line += argv[i];
    }
    return line;
}

bool parse_positive_int(const char* text, int& value) {
    char* end = nullptr;
    const long parsed = std::strtol(text, &end, 10);
    if (end == text || *end != '\0' || parsed <= 0 || parsed > 1024) return false;
    value = static_cast<int>(parsed);
    return true;
}

} // namespace

int main(int argc, char** argv) {
    std::string gate;
    fs::path root = ".";
    int threads = 1;
    bool self_test = false;
    bool render_report = false;
    bool verify = false;
    const std::string command_line = join_command_line(argc, argv);

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--gate" && i + 1 < argc) {
            gate = argv[++i];
        } else if (arg == "--root" && i + 1 < argc) {
            root = argv[++i];
        } else if (arg == "--threads" && i + 1 < argc) {
            if (!parse_positive_int(argv[++i], threads)) {
                std::cerr << "Invalid --threads value\n";
                return 1;
            }
        } else if (arg == "--self-test") {
            self_test = true;
        } else if (arg == "--render") {
            render_report = true;
        } else if (arg == "--verify-evidence") {
            verify = true;
        } else if (arg == "--help") {
            print_usage(argv[0]);
            return 0;
        } else {
            std::cerr << "Unknown option: " << arg << "\n";
            print_usage(argv[0]);
            return 1;
        }
    }

    const fs::path v2 = root / "specs_and_reports" / "v2";

    if (verify) {
        const fs::path manifest = v2 / "evidence" / "E1" / "SHA256SUMS";
        if (!fs::exists(manifest)) {
            std::cout << "Evidence verification: no manifest yet (skipped)\n";
            return 0;
        }
        const int result = marp::harness::verify_evidence(manifest);
        if (result == 0) {
            std::cout << "Evidence verification: PASS\n";
        } else {
            std::cerr << "Evidence verification: FAIL\n";
        }
        return result;
    }

    if (render_report) {
        const int result = marp::harness::render(v2 / "gates", v2 / "ACCEPTANCE.md");
        if (result == 0) {
            std::cout << "Rendered " << (v2 / "ACCEPTANCE.md") << "\n";
        } else {
            std::cerr << "Render found a non-PASS verdict; ACCEPTANCE.md left untouched\n";
        }
        return result;
    }

    if (self_test || gate == "E0-G") {
        return marp::harness::run_e0_selftest(root, command_line);
    }

    if (gate == "E1-G") {
        return marp::harness::run_e1_gate(root, threads, command_line);
    }

    if (gate.empty()) {
        std::cerr << "Error: --gate is required\n";
        print_usage(argv[0]);
        return 1;
    }

    std::cerr << "Unknown gate: " << gate << "\n";
    return 1;
}
