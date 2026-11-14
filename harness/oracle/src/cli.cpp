#include "marp/oracle/oracle.hpp"

#include <filesystem>
#include <iostream>
#include <string>
#include <string_view>

namespace {

int usage_error(std::string_view msg) {
    std::cerr << "error\t2\tusage\tnone\t" << msg << '\n';
    std::cerr << "usage:\n"
              << "  mapr_oracle decode  <wire> <out> [--info]\n"
              << "  mapr_oracle verify  <wire> [--sha256 <hex>] [--structure-only]\n"
              << "  mapr_oracle range   <wire> <start> <len> <out>\n"
              << "  mapr_oracle inspect <wire>\n";
    return static_cast<int>(marp::oracle::ErrorCode::Usage);
}

void report_diag(const marp::oracle::Diagnostic& diag) {
    std::cerr << "error\t" << diag.code << '\t'
              << marp::oracle::error_name(diag.code) << '\t'
              << marp::oracle::stage_name(diag.stage) << '\t'
              << diag.message << '\n';
}

void print_info(const marp::oracle::Info& info) {
    std::cout << "file_bytes\t" << info.file_bytes << '\n'
              << "node_count\t" << info.node_count << '\n'
              << "atom_count\t" << info.atom_count << '\n'
              << "root_id\t" << info.root_id << '\n'
              << "total_length\t" << info.total_length << '\n'
              << "output_sha256\t" << info.output_sha256 << '\n'
              << "has_index\t" << (info.has_index ? 1 : 0) << '\n';
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        return usage_error("missing command");
    }

    const std::string_view cmd(argv[1]);

    if (cmd == "decode") {
        if (argc != 4 && argc != 5) {
            return usage_error("decode requires <wire> <out> [--info]");
        }
        bool show_info = false;
        if (argc == 5) {
            if (std::string_view(argv[4]) != "--info") {
                return usage_error("unknown flag for decode");
            }
            show_info = true;
        }
        marp::oracle::Info info;
        marp::oracle::Diagnostic diag;
        const int rc = marp::oracle::decode_file(
            std::filesystem::path(argv[2]),
            std::filesystem::path(argv[3]),
            &info,
            &diag);
        if (rc != 0) {
            report_diag(diag);
            return rc;
        }
        if (show_info) {
            print_info(info);
        }
        return 0;
    }

    if (cmd == "verify") {
        if (argc < 3) {
            return usage_error("verify requires <wire> [--sha256 <hex>] [--structure-only]");
        }
        const std::filesystem::path wire(argv[2]);
        std::string expect_sha;
        bool has_sha = false;
        bool structure_only = false;

        for (int i = 3; i < argc; ++i) {
            const std::string_view arg(argv[i]);
            if (arg == "--structure-only") {
                structure_only = true;
            } else if (arg == "--sha256") {
                if (i + 1 >= argc) {
                    return usage_error("--sha256 requires a 64-character hex argument");
                }
                expect_sha = argv[++i];
                has_sha = true;
            } else {
                return usage_error("unknown flag for verify");
            }
        }
        if (has_sha && structure_only) {
            return usage_error("--sha256 cannot be combined with --structure-only");
        }

        marp::oracle::Info info;
        marp::oracle::Diagnostic diag;
        const int rc = marp::oracle::verify_file(wire, expect_sha, structure_only, &info, &diag);
        if (rc != 0) {
            report_diag(diag);
            return rc;
        }
        return 0;
    }

    if (cmd == "range") {
        if (argc != 6) {
            return usage_error("range requires <wire> <start> <len> <out>");
        }
        marp::oracle::Diagnostic diag;
        const int rc = marp::oracle::decode_range(
            std::filesystem::path(argv[2]),
            std::string(argv[3]),
            std::string(argv[4]),
            std::filesystem::path(argv[5]),
            &diag);
        if (rc != 0) {
            report_diag(diag);
            return rc;
        }
        return 0;
    }

    if (cmd == "inspect") {
        if (argc != 3) {
            return usage_error("inspect requires <wire>");
        }
        marp::oracle::Diagnostic diag;
        const int rc = marp::oracle::inspect_file(
            std::filesystem::path(argv[2]),
            std::cout,
            &diag);
        if (rc != 0) {
            report_diag(diag);
            return rc;
        }
        return 0;
    }

    return usage_error("unknown command");
}
