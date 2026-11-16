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
// mechanism §13.1 already mandates for the H3 oracle (\"the harness reaches the
// independent decoder only as a subprocess\"), applied here for an identical
// reason: two independently built implementations of one wire format.
//
// C08 is used exactly as landed: read-only, `decode_v1` only.  No v1 emission
// path exists here and none is reachable from the v2 side.
//
// ---------------------------------------------------------------------------
// What the expected output digest means (§13.3, §13.4 step 8, O7.7)
// ---------------------------------------------------------------------------
//
// W-V1's recorded digest is the SHA-256 of the fixture's **denotation**: the
// byte-exact output of evaluating the decoded root term (`eval_stream_digest`,
// E2's C05 evaluator).  It is *not* the concatenation of the atom-table
// payloads: for a legacy container whose root is a `Repeat`/`Slice`/`Morph`
// over its atoms — or any DAG with more than one node — those two byte strings
// differ, and only the denotation is the term's output.  This process therefore
// hashes the evaluated stream, with two independent hashers, and reports both:
// E2's own `StreamDigest` and this harness's streaming SHA-256 fed by a
// downstream `Sink`.  A disagreement between the two is a gate failure, never a
// silently chosen value.
//
// ---------------------------------------------------------------------------
// stdout protocol (one record per line, tab separated)
// ---------------------------------------------------------------------------
//
//   dir          <path>
//   fixtures     <count>
//   surface      C08 read-only: decode_v1, looks_like_v1
//   fixture      <name> <container_sha256> <bytes> <looks_like_v1>
//   hash         <name> <match|absent|mismatch> <container_sha256>
//   decode       <name> <Ok|Code:what>
//   denotation   <name> <expected_sha256> <observed_sha256> <bytes> <e2_sha256>
//   term         <name> <well_formed_state> <canonical_state>
//   structure    <name> <one structural_key record>
//   payload      <name> <atom_index> <lowercase hex>
//   fail         <name> <reason>
//
// `manifest.tsv` is read as exactly three tab-separated columns:
// `<filename.mapr>\t<container SHA-256>\t<denotation SHA-256>`.  A line that does
// not have that shape is reported as a `fail` record rather than interpreted
// loosely; this file and the C08 gate agree on the format.

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "mapr/e2/e2_canon.hpp"
#include "mapr/e2/e2_eval.hpp"
#include "mapr/e3/e3_legacy.hpp"

namespace {

namespace fs = std::filesystem;
using marp::v2::EvalLimits;
using marp::v2::Ir;
using marp::v2::Kind;
using marp::v2::Node;
using marp::v2::Sink;
using marp::v2::Status;
using marp::v2::WireCode;
using marp::v2::decode_v1;
using marp::v2::eval_stream_digest;

// ---------------------------------------------------------------------------
// The harness's own SHA-256, so a digest is never taken from the decoder.
// Streaming, because a denotation is produced block by block and may be far
// larger than one buffer.
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

class Sha256Hasher {
public:
    void update(std::span<const std::uint8_t> data) {
        total_bytes_ += data.size();
        while (!data.empty()) {
            const std::size_t take = std::min(data.size(), buffer_.size() - buffered_);
            std::memcpy(buffer_.data() + buffered_, data.data(), take);
            buffered_ += take;
            data = data.subspan(take);
            if (buffered_ == buffer_.size()) {
                process_block(buffer_.data());
                buffered_ = 0;
            }
        }
    }

    // Finalises and returns the lowercase hex digest.  Safe to call once; a
    // second call returns the same digest without re-absorbing the padding.
    std::string hex() {
        if (!finished_) {
            const std::uint64_t bits = total_bytes_ * 8u;
            std::vector<std::uint8_t> tail(buffer_.begin(),
                                           buffer_.begin() + static_cast<std::ptrdiff_t>(buffered_));
            tail.push_back(0x80u);
            while (tail.size() % 64u != 56u) tail.push_back(0x00u);
            for (int i = 7; i >= 0; --i) {
                tail.push_back(static_cast<std::uint8_t>((bits >> (8 * i)) & 0xFFu));
            }
            for (std::size_t offset = 0; offset < tail.size(); offset += 64u) {
                process_block(tail.data() + offset);
            }
            finished_ = true;
        }
        static constexpr char kHex[] = "0123456789abcdef";
        std::string out(64, '0');
        for (std::size_t i = 0; i < 8u; ++i) {
            for (std::size_t k = 0; k < 8u; ++k) {
                out[i * 8u + k] = kHex[(h_[i] >> (4u * (7u - k))) & 0xFu];
            }
        }
        return out;
    }

private:
    void process_block(const std::uint8_t* p) {
        std::uint32_t w[64];
        for (std::size_t i = 0; i < 16u; ++i) {
            w[i] = (static_cast<std::uint32_t>(p[4u * i]) << 24) |
                   (static_cast<std::uint32_t>(p[4u * i + 1u]) << 16) |
                   (static_cast<std::uint32_t>(p[4u * i + 2u]) << 8) |
                   static_cast<std::uint32_t>(p[4u * i + 3u]);
        }
        for (std::size_t i = 16u; i < 64u; ++i) {
            const std::uint32_t s0 =
                rotr(w[i - 15u], 7u) ^ rotr(w[i - 15u], 18u) ^ (w[i - 15u] >> 3);
            const std::uint32_t s1 =
                rotr(w[i - 2u], 17u) ^ rotr(w[i - 2u], 19u) ^ (w[i - 2u] >> 10);
            w[i] = w[i - 16u] + s0 + w[i - 7u] + s1;
        }
        std::uint32_t a = h_[0], b = h_[1], c = h_[2], d = h_[3];
        std::uint32_t e = h_[4], f = h_[5], g = h_[6], hh = h_[7];
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
        h_[0] += a;
        h_[1] += b;
        h_[2] += c;
        h_[3] += d;
        h_[4] += e;
        h_[5] += f;
        h_[6] += g;
        h_[7] += hh;
    }

    std::uint32_t h_[8] = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
                           0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};
    std::array<std::uint8_t, 64> buffer_{};
    std::size_t buffered_ = 0;
    std::uint64_t total_bytes_ = 0;
    bool finished_ = false;
};

std::string sha256_hex(std::span<const std::uint8_t> data) {
    Sha256Hasher hasher;
    hasher.update(data);
    return hasher.hex();
}

std::string sha_of(const std::vector<std::uint8_t>& bytes) {
    return sha256_hex(std::span<const std::uint8_t>(bytes.data(), bytes.size()));
}
// A `Sink` that only hashes: the denotation is never materialised, so a large
// legacy container costs one block of memory, not its output length.
class DenotationSink final : public Sink {
public:
    Status write(std::span<const marp::v2::u8> bytes) override {
        hasher_.update(bytes);
        bytes_ += bytes.size();
        return Status{};
    }

    std::string hex() { return hasher_.hex(); }

    std::uint64_t bytes() const { return bytes_; }

private:
    Sha256Hasher hasher_{};
    std::uint64_t bytes_ = 0;
};

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

// §4.6 kind-specific parameters, rendered exactly as `params_text` in
// `e3g_support.cpp` and H3's `format_node_params` render them.  It is
// duplicated here because this translation unit may not include the gate's
// support header (it carries C07's `e3_wire.hpp`, which collides with C08's
// header); the two renderings are cross-checked by the gate, which parses this
// text back into an `Ir` and re-encodes it.
std::string params_text(const Node& node) {
    switch (node.kind) {
        case Kind::Empty:
            return "-";
        case Kind::Atom:
            return "atom=" + node.a.to_decimal();
        case Kind::Zero:
            return "n=" + node.a.to_decimal();
        case Kind::Concat:
            return "-";
        case Kind::Repeat:
            return "q=" + node.a.to_decimal() + ",r=" + node.b.to_decimal();
        case Kind::Slice:
            return "start=" + node.a.to_decimal() + ",len=" + node.b.to_decimal();
        case Kind::Morph:
            return "morph=" + std::to_string(static_cast<unsigned>(node.morph)) +
                   ",k=" + std::to_string(static_cast<unsigned>(node.morph_k));
        case Kind::Xor:
            return "-";
        case Kind::Interleave:
            return "stride=" + std::to_string(node.a.to_u64_checked().value_or(0));
        case Kind::Lfsr: {
            static constexpr char kHex[] = "0123456789abcdef";
            auto hex64 = [&](marp::v2::u64 v) {
                std::string out(16, '0');
                for (int i = 15; i >= 0; --i) {
                    out[static_cast<std::size_t>(i)] = kHex[v & 0x0Fu];
                    v >>= 4;
                }
                return out;
            };
            return "conn=0x" + hex64(node.lfsr_conn) + ",init=0x" + hex64(node.lfsr_init) +
                   ",n=" + node.a.to_decimal();
        }
        case Kind::Affine:
            return "start=" + std::to_string(static_cast<unsigned>(node.affine_start)) +
                   ",step=" + std::to_string(static_cast<unsigned>(node.affine_step)) +
                   ",n=" + node.a.to_decimal();
        case Kind::Predictor:
            return "pid=" + std::to_string(static_cast<unsigned>(node.predictor_id)) +
                   ",param=" + std::to_string(node.predictor_param);
    }
    return "-";
}

// The decoded term, rendered in exactly the line shape `structural_key` emits
// (the gate parses this back and re-encodes it as v2, §13.4 step 8), so the
// term crosses the process boundary as text plus its atom payloads.
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
        text += "\t" + params_text(node) + "\t" + node.length.to_decimal() + "\n";
    }
    text += "trailer\troot=" + std::to_string(ir.root) + "\tatoms=" +
            std::to_string(ir.atoms.size()) + "\tnodes=" + std::to_string(ir.nodes.size()) + "\n";
    return text;
}

std::vector<std::string> split_tabs(const std::string& line) {
    std::vector<std::string> cols;
    std::size_t start = 0;
    for (;;) {
        const std::size_t tab = line.find('\t', start);
        cols.push_back(
            line.substr(start, tab == std::string::npos ? std::string::npos : tab - start));
        if (tab == std::string::npos) break;
        start = tab + 1u;
    }
    return cols;
}

bool is_lower_hex_sha256(const std::string& text) {
    if (text.size() != 64u) return false;
    for (const char c : text) {
        const bool digit = c >= '0' && c <= '9';
        const bool lower = c >= 'a' && c <= 'f';
        if (!digit && !lower) return false;
    }
    return true;
}

void emit(const char* key, const std::string& value) {
    std::printf("%s\t%s\n", key, value.c_str());
}

}  // namespace

int main(int argc, char** argv) {
    const std::string root = argc > 1 ? argv[1] : "..";
    const fs::path dir = fs::path(root) / "specs_and_reports" / "v2" / "W-V1";

    // Manifest: <fixture>\t<container sha256>\t<expected denotation sha256>.
    std::map<std::string, std::pair<std::string, std::string>> manifest;
    std::vector<std::string> manifest_problems;
    {
        std::ifstream in(dir / "manifest.tsv");
        std::string line;
        std::size_t line_no = 0;
        while (std::getline(in, line)) {
            ++line_no;
            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (line.empty() || line[0] == '#') continue;
            const std::vector<std::string> cols = split_tabs(line);
            const std::string where = "manifest.tsv line " + std::to_string(line_no);
            if (cols.size() != 3u) {
                manifest_problems.push_back(where + ": expected 3 tab-separated columns, got " +
                                            std::to_string(cols.size()));
                continue;
            }
            if (!is_lower_hex_sha256(cols[1]) || !is_lower_hex_sha256(cols[2])) {
                manifest_problems.push_back(where + ": digests must be 64 lowercase hex digits");
                continue;
            }
            if (!manifest.emplace(cols[0], std::make_pair(cols[1], cols[2])).second) {
                manifest_problems.push_back(where + ": duplicate entry for " + cols[0]);
            }
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
    for (const std::string& problem : manifest_problems) {
        emit("fail", "manifest.tsv\t" + problem);
    }

    for (const fs::path& path : fixtures) {
        const std::string name = path.filename().string();
        std::vector<std::uint8_t> bytes;
        if (!read_file(path, bytes)) {
            emit("fail", name + "\tread_error");
            continue;
        }
        const std::string container_sha = sha_of(bytes);
        const bool probe =
            marp::v2::looks_like_v1(std::span<const std::uint8_t>(bytes.data(), bytes.size()));
        emit("fixture", name + "\t" + container_sha + "\t" + std::to_string(bytes.size()) + "\t" +
                            (probe ? "1" : "0"));

        auto found = manifest.find(name);
        if (found == manifest.end()) {
            emit("hash", name + "\tabsent\t" + container_sha);
            continue;
        }
        emit("hash", name + "\t" + (found->second.first == container_sha ? "match" : "mismatch") +
                          "\t" + container_sha);
        if (found->second.first != container_sha) continue;

        auto decoded = decode_v1(std::span<const std::uint8_t>(bytes.data(), bytes.size()));
        if (!decoded.ok()) {
            emit("decode", name + "\t" + code_name(decoded.error().code) + ":" +
                               decoded.error().what);
            continue;
        }
        const Ir& ir = decoded.value();
        emit("decode", name + "\tOk");

        // §13.4 step 8: byte-exact denotation against the recorded digest.  The
        // denotation is the evaluated root — the same bytes E2's C05 evaluator
        // produces — hashed twice, by E2 and by this harness's own SHA-256.
        DenotationSink sink;
        auto digest = eval_stream_digest(ir, EvalLimits{}, nullptr, &sink);
        if (!digest.ok()) {
            emit("fail", name + "\teval=" + marp::v2::code_name(digest.code()));
        } else {
            const std::string observed = sink.hex();
            std::string e2_digest;
            {
                static constexpr char kHex[] = "0123456789abcdef";
                e2_digest.reserve(64);
                for (const std::uint8_t byte : digest.value().sha256) {
                    e2_digest.push_back(kHex[byte >> 4u]);
                    e2_digest.push_back(kHex[byte & 0x0Fu]);
                }
            }
            emit("denotation", name + "\t" + found->second.second + "\t" + observed + "\t" +
                                   std::to_string(sink.bytes()) + "\t" + e2_digest);
            // The two hashers and the two byte counts must agree; a boundary that
            // dropped or duplicated a block would otherwise go unnoticed.
            if (digest.value().bytes.to_decimal() != std::to_string(sink.bytes())) {
                emit("fail", name + "\tdenotation_byte_count=" +
                                 digest.value().bytes.to_decimal() + " sink=" +
                                 std::to_string(sink.bytes()));
            }
        }

        const auto wf = marp::v2::check_well_formed_report(ir);
        const auto canon = marp::v2::check_canonical(ir);
        std::string wf_state = "Ok";
        if (!wf.ok()) wf_state = std::string("wf:") + wf.constraint;
        std::string canon_state = "Ok";
        if (!canon.ok()) canon_state = std::string("canon:") + canon.constraint;
        emit("term", name + "\t" + wf_state + "\t" + canon_state);

        // One `structure` record per structural line: the gate parses the stream
        // line by line, so the rendering crosses individually rather than
        // embedded in one line.
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
        // Atom payloads cross the boundary as hex so the v2 side can rebuild the
        // term and re-encode it without this process having any v2 code in it.
        static constexpr char kHex[] = "0123456789abcdef";
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
