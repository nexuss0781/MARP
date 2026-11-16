// MARP v2 — E3 WIRE — E3-G integrated gate — legacy (W-V1) half, C08 process.
//
// This file is the *whole* C08 side of the gate, and it is built into its own
// executable (`bin/e3g_legacy_half`), never into `bin/e3_g_gate`.
//
// Why a separate process rather than a second translation unit:
//
//   * `mapr/e3/e3_wire.hpp` (C07) and `mapr/e3/e3_legacy.hpp` (C08) both define
//     `WireCode`, `WireResult`, `Source` and `Arena` under the include guard
//     `MAPR_E3_WIRE_TYPES_DEFINED`, with incompatible layout (`WireCode` is `u8`
//     vs `int`), so one translation unit cannot include both; and
//   * both components emit a strong `HeapArena::store(std::span<const u8>)` with
//     the same mangled name but different member layouts, so one link cannot
//     carry both objects either.  A single shared definition cannot bridge them:
//     whichever layout it implements corrupts the other side's arena.
//
// The gate therefore runs this binary and reads its stdout.  That is the same
// mechanism §13.1 already mandates for the H3 oracle ("the harness reaches the
// independent decoder only as a subprocess"), applied here for an identical
// reason: two independently built implementations of one wire format.
//
// C08 is used exactly as landed: read-only, `decode_v1` only.  No v1 emission
// path exists here and none is reachable from the v2 side.

#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <map>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "mapr/e2/e2_canon.hpp"
#include "mapr/e3/e3_legacy.hpp"

namespace {

namespace fs = std::filesystem;
using marp::v2::Ir;
using marp::v2::WireCode;
using marp::v2::decode_v1;

// ---------------------------------------------------------------------------
// The harness's own SHA-256, so a digest is never taken from the decoder
// ---------------------------------------------------------------------------

constexpr std::uint32_t kSha256K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u,
    0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu,
    0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu,
    0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu,
    0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
    0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u, 0x19a4c116u,
    0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u,
    0xc67178f2u};

std::uint32_t rotr(std::uint32_t x, unsigned n) { return (x >> n) | (x << (32u - n)); }

std::string sha256_hex(std::span<const std::uint8_t> data) {
    std::uint32_t h[8] = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
                          0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};
    std::vector<std::uint8_t> block(data.begin(), data.end());
    const std::uint64_t bits = static_cast<std::uint64_t>(data.size()) * 8u;
    block.push_back(0x80u);
    while (block.size() % 64u != 56u) block.push_back(0x00u);
    for (int i = 7; i >= 0; --i) {
        block.push_back(static_cast<std::uint8_t>((bits >> (8 * i)) & 0xFFu));
    }
    std::uint32_t w[64];
    for (std::size_t offset = 0; offset < block.size(); offset += 64u) {
        for (std::size_t i = 0; i < 16u; ++i) {
            w[i] = (static_cast<std::uint32_t>(block[offset + 4u * i]) << 24) |
                   (static_cast<std::uint32_t>(block[offset + 4u * i + 1u]) << 16) |
                   (static_cast<std::uint32_t>(block[offset + 4u * i + 2u]) << 8) |
                   static_cast<std::uint32_t>(block[offset + 4u * i + 3u]);
        }
        for (std::size_t i = 16u; i < 64u; ++i) {
            const std::uint32_t s0 =
                rotr(w[i - 15u], 7u) ^ rotr(w[i - 15u], 18u) ^ (w[i - 15u] >> 3);
            const std::uint32_t s1 =
                rotr(w[i - 2u], 17u) ^ rotr(w[i - 2u], 19u) ^ (w[i - 2u] >> 10);
            w[i] = w[i - 16u] + s0 + w[i - 7u] + s1;
        }
        std::uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
        std::uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];
        for (std::size_t i = 0; i < 64u; ++i) {
            const std::uint32_t s1 = rotr(e, 6u) ^ rotr(e, 11u) ^ rotr(e, 25u);
            const std::uint32_t ch = (e & f) ^ (~e & g);
            const std::uint32_t t1 = hh + s1 + ch + kSha256K[i] + w[i];
            const std::uint32_t s0 = rotr(a, 2u) ^ rotr(a, 13u) ^ rotr(a, 22u);
            const std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            const std::uint32_t t2 = s0 + maj;
            hh = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }
        h[0] += a;
        h[1] += b;
        h[2] += c;
        h[3] += d;
        h[4] += e;
        h[5] += f;
        h[6] += g;
        h[7] += hh;
    }
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out(64, '0');
    for (std::size_t i = 0; i < 8u; ++i) {
        for (std::size_t k = 0; k < 8u; ++k) {
            out[i * 8u + k] = kHex[(h[i] >> (4u * (7u - k))) & 0xFu];
        }
    }
    return out;
}

std::string sha_of(const std::vector<std::uint8_t>& bytes) {
    return sha256_hex(std::span<const std::uint8_t>(bytes.data(), bytes.size()));
}
std::string sha_of_text(const std::string& text) {
    return sha256_hex(std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(text.data()), text.size()));
}

bool read_file(const fs::path& path, std::vector<std::uint8_t>& out) {
    std::ifstream in(path, std::ios::binary | std::ios::ate);
    if (!in) return false;
    const std::streamoff size = in.tellg();
    if (size < 0) return false;
    in.seekg(0, std::ios::beg);
    out.assign(static_cast<std::size_t>(size), 0u);
    std::size_t done = 0;
    while (done < out.size()) {
        in.read(reinterpret_cast<char*>(out.data() + done),
                static_cast<std::streamsize>(out.size() - done));
        const std::streamsize got = in.gcount();
        if (got <= 0) break;
        done += static_cast<std::size_t>(got);
    }
    out.resize(done);
    return true;
}

std::string code_name(WireCode code) {
    switch (code) {
        case WireCode::Ok: return "Ok";
        case WireCode::Usage: return "Usage";
        case WireCode::Io: return "Io";
        case WireCode::Invalid: return "Invalid";
        case WireCode::Unsupported: return "Unsupported";
        case WireCode::Mismatch: return "Mismatch";
        case WireCode::Limit: return "Limit";
    }
    return "Unknown";
}

const char* kind_text(std::uint8_t kind) {
    static constexpr const char* kNames[12] = {"Empty",  "Atom",   "Zero",  "Concat",
                                               "Repeat", "Slice",  "Morph", "Xor",
                                               "Interleave", "Lfsr", "Affine", "Predictor"};
    return kind < 12u ? kNames[kind] : "Unknown";
}

// The decoded term, rendered in the same line shape the harness and the oracle
// use, so the gate can compare three independent renderings of one container.
std::string structure_of(const Ir& ir) {
    std::string text;
    text += "header\t2\t0\ttotal=" + ir.total_length.to_decimal() + "\t64\n";
    for (std::size_t i = 0; i < ir.atoms.size(); ++i) {
        static constexpr char kHex[] = "0123456789abcdef";
        std::string sha;
        sha.reserve(64);
        for (const std::uint8_t byte : ir.atoms[i].sha256) {
            sha.push_back(kHex[byte >> 4u]);
            sha.push_back(kHex[byte & 0x0Fu]);
        }
        text += "atom\t" + std::to_string(i) + "\t" +
                std::to_string(static_cast<unsigned>(ir.atoms[i].klass)) + "\t" +
                ir.atoms[i].length.to_decimal() + "\t" + sha + "\n";
    }
    for (std::size_t i = 0; i < ir.nodes.size(); ++i) {
        const auto& node = ir.nodes[i];
        text += "node\t" + std::to_string(i) + "\t" +
                std::to_string(static_cast<unsigned>(node.kind)) + "\t" +
                kind_text(static_cast<std::uint8_t>(node.kind)) + "\t" +
                std::to_string(node.args.size()) + "\t";
        if (node.args.empty()) {
            text += "-";
        } else {
            for (std::size_t k = 0; k < node.args.size(); ++k) {
                if (k != 0) text += ",";
                text += std::to_string(node.args[k]);
            }
        }
        text += "\t" + node.length.to_decimal() + "\n";
    }
    text += "trailer\troot=" + std::to_string(ir.root) + "\tatoms=" +
            std::to_string(ir.atoms.size()) + "\tnodes=" + std::to_string(ir.nodes.size()) + "\n";
    return text;
}

void emit(const char* key, const std::string& value) {
    std::printf("%s\t%s\n", key, value.c_str());
}

}  // namespace

int main(int argc, char** argv) {
    const std::string root = argc > 1 ? argv[1] : "..";
    const fs::path dir = fs::path(root) / "specs_and_reports" / "v2" / "W-V1";

    // Manifest: <fixture>\t<container sha256>\t<expected output sha256>
    std::map<std::string, std::pair<std::string, std::string>> manifest;
    {
        std::ifstream in(dir / "manifest.tsv");
        std::string line;
        while (std::getline(in, line)) {
            if (line.empty() || line[0] == '#') continue;
            std::vector<std::string> cols;
            std::size_t start = 0;
            for (;;) {
                const std::size_t tab = line.find('\t', start);
                cols.push_back(
                    line.substr(start, tab == std::string::npos ? std::string::npos : tab - start));
                if (tab == std::string::npos) break;
                start = tab + 1u;
            }
            if (cols.size() >= 3u) manifest[cols[0]] = {cols[1], cols[2]};
        }
    }

    std::vector<fs::path> fixtures;
    {
        std::error_code ec;
        if (fs::exists(dir, ec) && fs::is_directory(dir, ec)) {
            for (const auto& entry : fs::directory_iterator(dir, ec)) {
                if (entry.is_regular_file() && entry.path().extension() == ".mapr") {
                    fixtures.push_back(entry.path());
                }
            }
            std::sort(fixtures.begin(), fixtures.end());
        }
    }

    emit("dir", dir.string());
    emit("fixtures", std::to_string(fixtures.size()));
    emit("surface", "C08 read-only: decode_v1, looks_like_v1");

    for (const fs::path& path : fixtures) {
        const std::string name = path.filename().string();
        std::vector<std::uint8_t> bytes;
        if (!read_file(path, bytes)) {
            emit("fail", name + "\tread_error");
            continue;
        }
        const std::string container_sha = sha_of(bytes);
        emit("fixture", name + "\t" + container_sha + "\t" + std::to_string(bytes.size()));

        auto found = manifest.find(name);
        if (found == manifest.end()) {
            emit("hash", name + "\tabsent\t" + container_sha);
            continue;
        }
        emit("hash", name + "\t" + (found->second.first == container_sha ? "match" : "mismatch") +
                          "\t" + container_sha);

        auto decoded = decode_v1(std::span<const std::uint8_t>(bytes.data(), bytes.size()));
        if (!decoded.ok()) {
            emit("decode", name + "\t" + code_name(decoded.error().code) + ":" +
                               decoded.error().what);
            continue;
        }
        const Ir& ir = decoded.value();
        // The expected output digest is the manifest's; the observed one is the
        // harness's own SHA-256 over the decoded atom payloads in table order.
        std::vector<std::uint8_t> payload;
        for (const auto& atom : ir.atoms) {
            payload.insert(payload.end(), atom.payload.begin(), atom.payload.end());
        }
        const std::string payload_sha = sha_of(payload);
        const auto wf = marp::v2::check_well_formed_report(ir);
        const auto canon = marp::v2::check_canonical(ir);
        std::string canon_state = "Ok";
        if (!wf.ok()) {
            canon_state = std::string("wf:") + wf.constraint;
        } else if (!canon.ok()) {
            canon_state = std::string("canon:") + canon.constraint;
        }
        emit("decode", name + "\tOk\t" + found->second.second + "\t" + payload_sha + "\t" +
                           canon_state + "\t" + sha_of_text(structure_of(ir)));
        // Atom payloads cross the boundary as hex so the v2 side can rebuild the
        // term and re-encode it without this process having any v2 code in it.
        static constexpr char kHex[] = "0123456789abcdef";
        // One `structure` line per structural record: the rendering is multi-line,
        // and the gate parses this stream line by line, so the records cross the
        // boundary individually rather than embedded in one line.
        {
            const std::string rendering = structure_of(ir);
            std::size_t start = 0;
            while (start < rendering.size()) {
                const std::size_t nl = rendering.find('\n', start);
                const std::string record =
                    rendering.substr(start, nl == std::string::npos ? std::string::npos
                                                                    : nl - start);
                if (!record.empty()) emit("structure", name + "\t" + record);
                if (nl == std::string::npos) break;
                start = nl + 1u;
            }
        }
        for (std::size_t i = 0; i < ir.atoms.size(); ++i) {
            std::string hex;
            hex.reserve(ir.atoms[i].payload.size() * 2u);
            for (const std::uint8_t byte : ir.atoms[i].payload) {
                hex.push_back(kHex[byte >> 4u]);
                hex.push_back(kHex[byte & 0x0Fu]);
            }
            emit("payload", name + "\t" + std::to_string(i) + "\t" + hex);
        }
    }
    return 0;
}
