#include "mapr/common.hpp"
#include "mapr/container.hpp"
#include "mapr/crypto.hpp"
#include "mapr/decoder.hpp"
#include "mapr/encoder.hpp"

#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace {

using namespace mapr;

BitSeq read_bitseq_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) throw std::runtime_error("Cannot open .bitseq input: " + path);
    uint8_t hdr[8];
    in.read(reinterpret_cast<char*>(hdr), 8);
    if (in.gcount() != 8) throw std::runtime_error("Invalid .bitseq header");
    uint64_t n = read_be64(hdr);
    size_t n_bytes = static_cast<size_t>((n + 7ULL) >> 3);
    std::vector<uint8_t> raw(n_bytes);
    if (n_bytes > 0) {
        in.read(reinterpret_cast<char*>(raw.data()), static_cast<std::streamsize>(n_bytes));
        if (static_cast<size_t>(in.gcount()) != n_bytes) {
            throw std::runtime_error("Truncated .bitseq payload");
        }
    }
    return BitSeq::from_bytes_msb(raw.data(), raw.size()).slice(0, n);
}

void write_bitseq_file(const std::string& path, const BitSeq& seq) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) throw std::runtime_error("Cannot open .bitseq output: " + path);
    uint8_t hdr[8];
    write_be64(hdr, seq.bit_len());
    out.write(reinterpret_cast<const char*>(hdr), 8);
    if (seq.bit_len() > 0) {
        std::vector<uint8_t> padded;
        seq.to_bytes_msb_padded(padded);
        out.write(reinterpret_cast<const char*>(padded.data()), static_cast<std::streamsize>(padded.size()));
    }
    if (!out) throw std::runtime_error("Failed writing .bitseq output");
}

void print_usage() {
    std::cerr
        << "Universal Patterned Binary Representation Engine (MAPR v1.0.1 C++20)\n"
        << "Usage:\n"
        << "  mapr encode  --input <in> --output <out.mapr> [--bitseq] [--threads N] [--metrics-out <m.json>]\n"
        << "  mapr decode  --input <in.mapr> --output <out> [--bitseq] [--threads N] [--metrics-out <m.json>]\n"
        << "  mapr inspect --input <in.mapr> [--json-out <i.json>]\n"
        << "  mapr verify  --input <in.mapr>\n";
}

std::string format_inspect_json(const FullInspectReport& rep) {
    std::ostringstream os;
    os << std::fixed << std::setprecision(6);
    os << "{\n"
       << "  \"valid\": true,\n"
       << "  \"format_version\": \"" << rep.meta.version_major << "." << rep.meta.version_minor << "\",\n"
       << "  \"container_bytes\": " << rep.file_size << ",\n"
       << "  \"total_bits\": " << rep.meta.total_bits << ",\n"
       << "  \"accounted_bits\": " << rep.summary.accounted_bits << ",\n"
       << "  \"bit_accountability_ratio\": "
       << (rep.meta.total_bits == 0 ? 1.0 : static_cast<double>(rep.summary.accounted_bits) / static_cast<double>(rep.meta.total_bits)) << ",\n"
       << "  \"stream_sha256\": \"" << Sha256::to_hex(rep.meta.stream_sha256) << "\",\n"
       << "  \"chunk_count\": " << rep.summary.chunk_count << ",\n"
       << "  \"chunk_ref_count\": " << rep.summary.chunk_ref_count << ",\n"
       << "  \"total_dag_nodes\": " << rep.summary.total_dag_nodes << ",\n"
       << "  \"total_dag_edges\": " << rep.summary.total_dag_edges << ",\n"
       << "  \"total_micro_atoms\": " << rep.summary.total_micro_atoms << ",\n"
       << "  \"pos_atoms\": " << rep.summary.pos_atoms << ",\n"
       << "  \"zheg_atoms\": " << rep.summary.zheg_atoms << ",\n"
       << "  \"max_dag_depth\": " << rep.summary.max_dag_depth << ",\n"
       << "  \"node_counts\": {";
    bool first = true;
    for (const auto& [k, v] : rep.summary.node_counts) {
        if (!first) os << ",";
        first = false;
        os << "\n    \"" << k << "\": " << v;
    }
    os << "\n  },\n  \"mechanism_bits\": {";
    first = true;
    for (const auto& [k, v] : rep.summary.mechanism_bits) {
        if (!first) os << ",";
        first = false;
        os << "\n    \"" << k << "\": " << v;
    }
    os << "\n  }\n}\n";
    return os.str();
}

} // namespace

int main(int argc, char** argv) {
    try {
        if (argc < 2) {
            print_usage();
            return 1;
        }
        std::string cmd = argv[1];
        std::string input_path, output_path, metrics_out, inline_bitstring;
        bool bitseq_mode = false;
        bool has_inline_bitstring = false;
        bool out_bitstring_stdout = false;
        unsigned threads = std::max(1u, std::thread::hardware_concurrency());

        for (int i = 2; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--input" && i + 1 < argc) input_path = argv[++i];
            else if (arg == "--output" && i + 1 < argc) output_path = argv[++i];
            else if ((arg == "--metrics-out" || arg == "--json-out") && i + 1 < argc) metrics_out = argv[++i];
            else if (arg == "--threads" && i + 1 < argc) threads = static_cast<unsigned>(std::stoul(argv[++i]));
            else if (arg == "--bitstring" && i + 1 < argc) { inline_bitstring = argv[++i]; has_inline_bitstring = true; }
            else if (arg == "--out-bitstring") out_bitstring_stdout = true;
            else if (arg == "--bitseq") bitseq_mode = true;
            else if (arg == "--raw-bytes") bitseq_mode = false;
            else throw std::invalid_argument("Unknown or incomplete CLI flag: " + arg);
        }

        if (cmd == "encode") {
            if ((!has_inline_bitstring && input_path.empty()) || output_path.empty()) {
                throw std::invalid_argument("encode requires (--input or --bitstring) and --output");
            }
            EncodeStats st;
            if (has_inline_bitstring) {
                BitSeq seq = BitSeq::from_bitstring(inline_bitstring);
                st = encode_bitseq_to_file(seq, output_path, false, threads);
            } else if (bitseq_mode) {
                BitSeq seq = read_bitseq_file(input_path);
                st = encode_bitseq_to_file(seq, output_path, false, threads);
            } else {
                st = encode_raw_file_streaming(input_path, output_path, threads);
            }
            if (!metrics_out.empty()) {
                FullInspectReport irep = inspect_mapr_container(output_path);
                std::ofstream mf(metrics_out);
                mf << std::fixed << std::setprecision(6)
                   << "{\n"
                   << "  \"input_bits\": " << st.input_bits << ",\n"
                   << "  \"output_bytes\": " << st.output_bytes << ",\n"
                   << "  \"chunk_count\": " << st.chunk_count << ",\n"
                   << "  \"chunk_ref_count\": " << st.chunk_ref_count << ",\n"
                   << "  \"encode_time_sec\": " << st.wall_seconds << ",\n"
                   << "  \"encode_peak_rss_mb\": " << st.peak_rss_mb << ",\n"
                   << "  \"stream_sha256\": \"" << st.stream_sha256_hex << "\",\n"
                   << "  \"inspection\": " << format_inspect_json(irep)
                   << "}\n";
            }
            return 0;
        } else if (cmd == "decode") {
            if (input_path.empty() || (!out_bitstring_stdout && output_path.empty())) {
                throw std::invalid_argument("decode requires --input and (--output or --out-bitstring)");
            }
            DecodeStats st;
            if (out_bitstring_stdout) {
                auto [seq, dst] = decode_mapr_to_bitseq(input_path, threads);
                std::cout << seq.to_bitstring() << "\n";
                st = dst;
            } else if (bitseq_mode) {
                auto [seq, dst] = decode_mapr_to_bitseq(input_path, threads);
                write_bitseq_file(output_path, seq);
                st = dst;
            } else {
                st = decode_mapr_to_raw_file(input_path, output_path, threads);
            }
            if (!metrics_out.empty()) {
                std::ofstream mf(metrics_out);
                mf << std::fixed << std::setprecision(6)
                   << "{\n"
                   << "  \"output_bits\": " << st.output_bits << ",\n"
                   << "  \"output_bytes\": " << st.output_bytes << ",\n"
                   << "  \"chunk_count\": " << st.chunk_count << ",\n"
                   << "  \"decode_time_sec\": " << st.wall_seconds << ",\n"
                   << "  \"decode_peak_rss_mb\": " << st.peak_rss_mb << ",\n"
                   << "  \"stream_sha256\": \"" << st.stream_sha256_hex << "\",\n"
                   << "  \"sha256_verified\": " << (st.sha256_verified ? "true" : "false") << "\n"
                   << "}\n";
            }
            return 0;
        } else if (cmd == "inspect") {
            if (input_path.empty()) throw std::invalid_argument("inspect requires --input");
            auto rep = inspect_mapr_container(input_path);
            std::string js = format_inspect_json(rep);
            if (!metrics_out.empty()) {
                std::ofstream mf(metrics_out);
                mf << js;
            } else {
                std::cout << js;
            }
            return 0;
        } else if (cmd == "verify") {
            if (input_path.empty()) throw std::invalid_argument("verify requires --input");
            auto [seq, st] = decode_mapr_to_bitseq(input_path, threads);
            auto rep = inspect_mapr_container(input_path);
            std::cout << "VERIFIED OK: bits=" << st.output_bits
                      << " chunks=" << st.chunk_count
                      << " accounted=" << rep.summary.accounted_bits
                      << " sha256=" << st.stream_sha256_hex << "\n";
            return 0;
        } else {
            print_usage();
            return 1;
        }
    } catch (const std::exception& ex) {
        std::cerr << "MAPR ERROR: " << ex.what() << "\n";
        return 2;
    }
}
