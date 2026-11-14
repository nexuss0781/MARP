#include "marp/harness/gates.hpp"
#include "marp/harness/e1_gate.hpp"
#include "marp/harness/e0_selftest.hpp"
#include <iostream>
#include <string>
#include <filesystem>
#include <cstdlib>

namespace fs = std::filesystem;

void print_usage(const char* prog) {
    std::cerr << "Usage: " << prog << " [options]\n";
    std::cerr << "Options:\n";
    std::cerr << "  --gate E0-G|E1-G    Run specified gate\n";
    std::cerr << "  --root <path>       Repository root path\n";
    std::cerr << "  --threads <1|4>     Number of threads (default: 1)\n";
    std::cerr << "  --self-test         Run E0-G false-gate check\n";
    std::cerr << "  --render            Render ACCEPTANCE.md from TSVs\n";
    std::cerr << "  --verify-evidence   Verify SHA256SUMS manifest\n";
    std::cerr << "  --help              Show this help\n";
}

int main(int argc, char** argv) {
    std::string gate;
    fs::path root = ".";
    int threads = 1;
    bool self_test = false;
    bool render = false;
    bool verify = false;
    
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--gate" && i + 1 < argc) {
            gate = argv[++i];
        } else if (arg == "--root" && i + 1 < argc) {
            root = argv[++i];
        } else if (arg == "--threads" && i + 1 < argc) {
            threads = std::atoi(argv[++i]);
        } else if (arg == "--self-test") {
            self_test = true;
        } else if (arg == "--render") {
            render = true;
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
    
    if (verify) {
        fs::path manifest = root / "specs_and_reports" / "v2" / "evidence" / "E1" / "SHA256SUMS";
        int result = marp::harness::verify_evidence(manifest);
        if (result == 0) {
            std::cout << "Evidence verification: PASS\n";
        } else {
            std::cerr << "Evidence verification: FAIL\n";
        }
        return result;
    }
    
    if (render) {
        fs::path tsv_dir = root / "specs_and_reports" / "v2" / "gates";
        fs::path out = root / "specs_and_reports" / "v2" / "ACCEPTANCE.md";
        int result = marp::harness::render(tsv_dir, out);
        if (result == 0) {
            std::cout << "Rendered: " << out << "\n";
        } else {
            std::cerr << "Render failed\n";
        }
        return result;
    }
    
    if (gate.empty()) {
        std::cerr << "Error: --gate is required\n";
        print_usage(argv[0]);
        return 1;
    }
    
    if (gate == "E0-G") {
        if (self_test) {
            return marp::harness::run_e0_selftest(root);
        }
        // Run full E0-G (which is just the self-test for now)
        return marp::harness::run_e0_selftest(root);
    } else if (gate == "E1-G") {
        return marp::harness::run_e1_gate(root, threads);
    } else {
        std::cerr << "Unknown gate: " << gate << "\n";
        return 1;
    }
}