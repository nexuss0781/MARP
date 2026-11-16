// MARP v2 — E3 WIRE — E3-G integrated gate — shared harness support.
//
// Harness-only: never linked into C07 (`e3_wire*.cpp`) or C08 (`e3_legacy.cpp`).

#include "e3g_support.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <map>
#include <set>
#include <utility>

#include "mapr/e1_crc32.hpp"
#include "mapr/e1_sha256.hpp"

namespace e3g {
namespace {

constexpr char kHexDigits[] = "0123456789abcdef";

}  // namespace

std::string hex_bytes(const u8* data, std::size_t size) {
    std::string out;
    out.reserve(size * 2);
    for (std::size_t i = 0; i < size; ++i) {
        out.push_back(kHexDigits[(data[i] >> 4) & 0x0Fu]);
        out.push_back(kHexDigits[data[i] & 0x0Fu]);
    }
    return out;
}

std::string sha256_hex(std::span<const u8> bytes) {
    auto digest = mapr::Sha256::hash(
        std::string_view(reinterpret_cast<const char*>(bytes.data()), bytes.size()));
    if (!digest.ok()) return std::string(64, '0');
    return hex_array(digest.value());
}

std::string sha256_hex(std::string_view text) {
    return sha256_hex(std::span<const u8>(
        reinterpret_cast<const u8*>(text.data()), text.size()));
}

std::string sha_of_bytes(const std::vector<u8>& bytes) {
    return sha256_hex(std::span<const u8>(bytes.data(), bytes.size()));
}

std::string sha_of_text(const std::string& text) { return sha256_hex(std::string_view(text)); }

std::string sha_of_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return "missing";
    std::string text;
    std::array<char, 65536> chunk{};
    while (in) {
        in.read(chunk.data(), static_cast<std::streamsize>(chunk.size()));
        const std::streamsize got = in.gcount();
        if (got > 0) text.append(chunk.data(), static_cast<std::size_t>(got));
    }
    return sha_of_text(text);
}

std::string resolve_path(const std::string& root, const std::string& path) {
    if (path.empty() || path.front() == '/') return path;
    if (root.empty() || root == ".") return path;
    if (!root.empty() && root.back() == '/') return root + path;
    return root + "/" + path;
}

std::vector<std::string> split_lines(const std::string& text) {
    std::vector<std::string> lines;
    std::size_t start = 0;
    while (start <= text.size()) {
        const std::size_t nl = text.find('\n', start);
        if (nl == std::string::npos) {
            if (start < text.size()) lines.push_back(text.substr(start));
            break;
        }
        lines.push_back(text.substr(start, nl - start));
        start = nl + 1;
    }
    return lines;
}

bool file_exists(const std::string& path) {
    std::ifstream probe(path, std::ios::binary);
    return static_cast<bool>(probe);
}

bool read_file_bytes(const std::string& path, std::vector<u8>& out) {
    std::ifstream in(path, std::ios::binary | std::ios::ate);
    if (!in) return false;
    const std::streamoff size = in.tellg();
    if (size < 0) return false;
    out.resize(static_cast<std::size_t>(size));
    in.seekg(0, std::ios::beg);
    if (!out.empty() &&
        !in.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(out.size()))) {
        return false;
    }
    return true;
}

bool write_file_bytes(const std::string& path, std::span<const u8> bytes) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) return false;
    if (!bytes.empty()) {
        out.write(reinterpret_cast<const char*>(bytes.data()),
                  static_cast<std::streamsize>(bytes.size()));
    }
    return static_cast<bool>(out);
}

// ---------------------------------------------------------------------------
// Structural description / comparison
// ---------------------------------------------------------------------------

std::string describe_ir(const Ir& ir) {
    std::string text;
    text += "ir|root=" + std::to_string(ir.root) + "|total=" + ir.total_length.to_decimal() +
            "|atoms=" + std::to_string(ir.atoms.size()) + "|nodes=" +
            std::to_string(ir.nodes.size()) + "\n";
    for (std::size_t i = 0; i < ir.atoms.size(); ++i) {
        const Atom& atom = ir.atoms[i];
        text += "A" + std::to_string(i) + "|klass=" + std::to_string(static_cast<unsigned>(atom.klass)) +
                "|flags=" + std::to_string(static_cast<unsigned>(atom.flags)) +
                "|len=" + atom.length.to_decimal() + "|sha=" + hex_array(atom.sha256) +
                "|payload=" + std::to_string(atom.payload.size()) + "\n";
    }
    for (std::size_t i = 0; i < ir.nodes.size(); ++i) {
        const Node& node = ir.nodes[i];
        text += "N" + std::to_string(i) + "|kind=" + std::to_string(static_cast<unsigned>(node.kind)) +
                "|flags=" + std::to_string(static_cast<unsigned>(node.flags)) + "|args=";
        for (std::size_t k = 0; k < node.args.size(); ++k) {
            if (k != 0) text += ",";
            text += std::to_string(node.args[k]);
        }
        text += "|a=" + node.a.to_decimal() + "|b=" + node.b.to_decimal() +
                "|morph=" + std::to_string(static_cast<unsigned>(node.morph)) + "/" +
                std::to_string(static_cast<unsigned>(node.morph_k)) +
                "|lfsr=" + std::to_string(node.lfsr_conn) + "/" + std::to_string(node.lfsr_init) +
                "|affine=" + std::to_string(static_cast<unsigned>(node.affine_start)) + "/" +
                std::to_string(static_cast<unsigned>(node.affine_step)) +
                "|pred=" + std::to_string(static_cast<unsigned>(node.predictor_id)) + "/" +
                std::to_string(node.predictor_param) + "|len=" + node.length.to_decimal() + "\n";
    }
    return text;
}

const char* kind_text(Kind kind) {
    switch (kind) {
        case Kind::Empty: return "Empty";
        case Kind::Atom: return "Atom";
        case Kind::Zero: return "Zero";
        case Kind::Concat: return "Concat";
        case Kind::Repeat: return "Repeat";
        case Kind::Slice: return "Slice";
        case Kind::Morph: return "Morph";
        case Kind::Xor: return "Xor";
        case Kind::Interleave: return "Interleave";
        case Kind::Lfsr: return "Lfsr";
        case Kind::Affine: return "Affine";
        case Kind::Predictor: return "Predictor";
    }
    return "Unknown";
}

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
            return "morph=" + std::to_string(static_cast<unsigned>(node.morph)) + ",k=" +
                   std::to_string(static_cast<unsigned>(node.morph_k));
        case Kind::Xor:
            return "-";
        case Kind::Interleave:
            return "stride=" + std::to_string(node.a.to_u64_checked().value_or(0));
        case Kind::Lfsr: {
            static constexpr char kHex[] = "0123456789abcdef";
            auto hex64 = [&](u64 v) {
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
            return "start=" + std::to_string(static_cast<unsigned>(node.affine_start)) + ",step=" +
                   std::to_string(static_cast<unsigned>(node.affine_step)) +
                   ",n=" + node.a.to_decimal();
        case Kind::Predictor:
            return "pid=" + std::to_string(static_cast<unsigned>(node.predictor_id)) +
                   ",param=" + std::to_string(node.predictor_param);
    }
    return "-";
}

std::string structural_key(const Ir& ir) {
    // Mirrors the H3 `inspect` TSV line for line (harness/oracle/src/decode.cpp,
    // `write_inspect_tsv`): the header's version-2 fields, the atom table, the node
    // table with H3's parameter rendering, and the trailer's structural counts.
    // Excluded on purpose: region offsets, `file_crc32`, `index_offset` and
    // `trailer_crc32` — those are container bookkeeping the oracle recomputes from
    // the bytes, not properties of the term.  The index region is excluded because
    // the index policy is C07's (REPORT/E3/C07-WIRE-REPORT.md §5) and H3's index
    // is its own reconstruction; the index *presence* is compared instead, through
    // `Coverage` and through the canonical-wire fixpoint of step 4.
    std::string text;
    text += "header\t2\t0\ttotal=" + ir.total_length.to_decimal() + "\t64\n";
    for (std::size_t i = 0; i < ir.atoms.size(); ++i) {
        const Atom& atom = ir.atoms[i];
        text += "atom\t" + std::to_string(i) + "\t" +
                std::to_string(static_cast<unsigned>(atom.klass)) + "\t" +
                atom.length.to_decimal() + "\t" + hex_array(atom.sha256) + "\n";
    }
    for (std::size_t i = 0; i < ir.nodes.size(); ++i) {
        const Node& node = ir.nodes[i];
        text += "node\t" + std::to_string(i) + "\t" +
                std::to_string(static_cast<unsigned>(node.kind)) + "\t" + kind_text(node.kind) +
                "\t" + std::to_string(node.args.size()) + "\t";
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
            std::to_string(ir.atoms.size()) + "\tnodes=" + std::to_string(ir.nodes.size()) +
            "\n";
    return text;
}

bool same_ir(const Ir& a, const Ir& b, std::string& why) {
    if (a.atoms.size() != b.atoms.size()) {
        why = "atom count " + std::to_string(a.atoms.size()) + "!=" + std::to_string(b.atoms.size());
        return false;
    }
    if (a.nodes.size() != b.nodes.size()) {
        why = "node count " + std::to_string(a.nodes.size()) + "!=" + std::to_string(b.nodes.size());
        return false;
    }
    for (std::size_t i = 0; i < a.atoms.size(); ++i) {
        const Atom& x = a.atoms[i];
        const Atom& y = b.atoms[i];
        if (x.klass != y.klass) {
            why = "atom " + std::to_string(i) + " klass";
            return false;
        }
        if (x.flags != y.flags) {
            why = "atom " + std::to_string(i) + " flags";
            return false;
        }
        if (x.length != y.length) {
            why = "atom " + std::to_string(i) + " length";
            return false;
        }
        if (x.sha256 != y.sha256) {
            why = "atom " + std::to_string(i) + " sha256";
            return false;
        }
        if (x.payload.size() != y.payload.size()) {
            why = "atom " + std::to_string(i) + " payload size";
            return false;
        }
        if (!x.payload.empty() &&
            std::memcmp(x.payload.data(), y.payload.data(), x.payload.size()) != 0) {
            why = "atom " + std::to_string(i) + " payload";
            return false;
        }
    }
    for (std::size_t i = 0; i < a.nodes.size(); ++i) {
        const Node& x = a.nodes[i];
        const Node& y = b.nodes[i];
        if (x.kind != y.kind || x.flags != y.flags || x.args != y.args || x.a != y.a ||
            x.b != y.b || x.morph != y.morph || x.morph_k != y.morph_k ||
            x.lfsr_conn != y.lfsr_conn || x.lfsr_init != y.lfsr_init ||
            x.affine_start != y.affine_start || x.affine_step != y.affine_step ||
            x.predictor_id != y.predictor_id || x.predictor_param != y.predictor_param ||
            x.length != y.length) {
            why = "node " + std::to_string(i);
            return false;
        }
    }
    if (a.root != b.root) {
        why = "root id";
        return false;
    }
    if (a.total_length != b.total_length) {
        why = "total length";
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Collector
// ---------------------------------------------------------------------------

void Collector::row(const std::string& check, const std::string& corpus,
                    const std::string& item_id, const std::string& input_sha256,
                    const std::string& wire_sha256, const std::string& wire_bytes,
                    const std::string& expected, const std::string& actual, bool pass,
                    const std::string& log_ref) {
    Row r;
    r.check = check;
    r.corpus = corpus;
    r.item_id = item_id;
    r.input_sha256 = input_sha256;
    r.wire_sha256 = wire_sha256;
    r.wire_bytes = wire_bytes;
    r.expected = expected;
    r.actual = actual;
    r.verdict = pass ? "PASS" : "FAIL";
    r.log = log_ref;
    rows_.push_back(std::move(r));
    if (pass) {
        ++passes_;
    } else {
        ++failures_;
    }
    ++section_rows_;
}

void Collector::row_verdict(const std::string& check, const std::string& corpus,
                            const std::string& item_id, const std::string& input_sha256,
                            const std::string& wire_sha256, const std::string& wire_bytes,
                            const std::string& expected, const std::string& actual,
                            const std::string& verdict, const std::string& log_ref) {
    Row r;
    r.check = check;
    r.corpus = corpus;
    r.item_id = item_id;
    r.input_sha256 = input_sha256;
    r.wire_sha256 = wire_sha256;
    r.wire_bytes = wire_bytes;
    r.expected = expected;
    r.actual = actual;
    r.verdict = verdict;
    r.log = log_ref;
    rows_.push_back(std::move(r));
    ++section_rows_;
}

void Collector::log(const std::string& line) { log_lines_.push_back(line); }

void Collector::section(const std::string& name) {
    log_lines_.push_back("[" + name + "] cumulative pass=" + std::to_string(passes_) +
                         " fail=" + std::to_string(failures_) +
                         " blocked=" + std::to_string(count_verdict("BLOCKED")) +
                         " rows=" + std::to_string(section_rows_));
    section_rows_ = 0;
}

void Collector::merge(const Collector& other) {
    rows_.insert(rows_.end(), other.rows_.begin(), other.rows_.end());
    log_lines_.insert(log_lines_.end(), other.log_lines_.begin(), other.log_lines_.end());
    passes_ += other.passes_;
    failures_ += other.failures_;
    section_rows_ += other.section_rows_;
    if (environment_.empty()) environment_ = other.environment_;
}

std::size_t Collector::count_verdict(const std::string& verdict) const {
    std::size_t n = 0;
    for (const Row& r : rows_) {
        if (r.verdict == verdict) ++n;
    }
    return n;
}

// ---------------------------------------------------------------------------
// Container field helpers
// ---------------------------------------------------------------------------

u16 load16_at(const std::vector<u8>& wire, std::size_t at) {
    return static_cast<u16>(static_cast<u16>(wire[at]) |
                            (static_cast<u16>(wire[at + 1]) << 8));
}

u32 load32_at(const std::vector<u8>& wire, std::size_t at) {
    return static_cast<u32>(wire[at]) | (static_cast<u32>(wire[at + 1]) << 8) |
           (static_cast<u32>(wire[at + 2]) << 16) | (static_cast<u32>(wire[at + 3]) << 24);
}

u64 load64_at(const std::vector<u8>& wire, std::size_t at) {
    return static_cast<u64>(load32_at(wire, at)) |
           (static_cast<u64>(load32_at(wire, at + 4)) << 32);
}

void put16_at(std::vector<u8>& wire, std::size_t at, u16 v) {
    wire[at + 0] = static_cast<u8>(v & 0xFFu);
    wire[at + 1] = static_cast<u8>((v >> 8) & 0xFFu);
}

void put32_at(std::vector<u8>& wire, std::size_t at, u32 v) {
    wire[at + 0] = static_cast<u8>(v & 0xFFu);
    wire[at + 1] = static_cast<u8>((v >> 8) & 0xFFu);
    wire[at + 2] = static_cast<u8>((v >> 16) & 0xFFu);
    wire[at + 3] = static_cast<u8>((v >> 24) & 0xFFu);
}

void put64_at(std::vector<u8>& wire, std::size_t at, u64 v) {
    put32_at(wire, at, static_cast<u32>(v & 0xFFFFFFFFull));
    put32_at(wire, at + 4, static_cast<u32>(v >> 32));
}

void repair_outer_crcs(std::vector<u8>& wire) {
    if (wire.size() < static_cast<std::size_t>(kWireMinContainerBytes)) return;
    const std::size_t trailer_offset = wire.size() - static_cast<std::size_t>(kWireTrailerBytes);
    put32_at(wire, kHdrOffFileCrc32, 0u);
    const u32 file_crc = mapr::crc32(std::string_view(
        reinterpret_cast<const char*>(wire.data()), trailer_offset));
    put32_at(wire, kHdrOffFileCrc32, file_crc);

    std::array<u8, 32> buffer{};
    std::memcpy(buffer.data(), wire.data() + trailer_offset, 28);
    buffer[28] = static_cast<u8>(file_crc & 0xFFu);
    buffer[29] = static_cast<u8>((file_crc >> 8) & 0xFFu);
    buffer[30] = static_cast<u8>((file_crc >> 16) & 0xFFu);
    buffer[31] = static_cast<u8>((file_crc >> 24) & 0xFFu);
    const u32 trailer_crc =
        mapr::crc32(std::string_view(reinterpret_cast<const char*>(buffer.data()), buffer.size()));
    put32_at(wire, trailer_offset + kTrlOffTrailerCrc32, trailer_crc);
}

bool read_uvarint_at(const std::vector<u8>& wire, std::size_t& pos, u64& value) {
    value = 0;
    unsigned shift = 0;
    for (unsigned i = 0; i < 10; ++i) {
        if (pos >= wire.size()) return false;
        const u8 byte = wire[pos++];
        value |= static_cast<u64>(byte & 0x7Fu) << shift;
        if ((byte & 0x80u) == 0) return true;
        shift += 7;
    }
    return false;
}

std::string code_and_stage(const WireError& error) {
    return std::string(wire_code_name(error.code)) + "@" + stage_name(error.stage);
}

}  // namespace e3g

namespace e3g {
namespace {

bool parse_bigint_text(const std::string& text, BigInt& out) {
    auto parsed = BigInt::from_decimal(text);
    if (!parsed.ok()) return false;
    out = parsed.value();
    return true;
}

bool parse_u64_text(const std::string& text, u64& out) {
    if (text.empty()) return false;
    for (const char c : text) {
        if (c < '0' || c > '9') return false;
    }
    out = std::strtoull(text.c_str(), nullptr, 10);
    return true;
}

bool hex_to_digest(const std::string& text, std::array<u8, 32>& out) {
    if (text.size() != 64u) return false;
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (std::size_t i = 0; i < 32u; ++i) {
        const int high = nibble(text[2u * i]);
        const int low = nibble(text[2u * i + 1u]);
        if (high < 0 || low < 0) return false;
        out[i] = static_cast<u8>((high << 4) | low);
    }
    return true;
}

std::vector<std::string> split_on(const std::string& text, char sep) {
    std::vector<std::string> parts;
    std::size_t start = 0;
    for (;;) {
        const std::size_t at = text.find(sep, start);
        parts.push_back(text.substr(start, at == std::string::npos ? std::string::npos : at - start));
        if (at == std::string::npos) break;
        start = at + 1;
    }
    return parts;
}

}  // namespace

bool parse_structural_key(const std::string& text, Ir& out, std::string& why) {
    out = Ir{};
    out.total_length = BigInt(0);
    std::vector<Node> nodes;
    u32 root = 0;
    bool saw_header = false;
    for (const std::string& line : split_lines(text)) {
        if (line.rfind("header\t", 0) == 0) {
            const std::vector<std::string> cols = split_on(line, '\t');
            if (cols.size() < 5 || cols[1] != "2") {
                why = "unexpected header rendering";
                return false;
            }
            const std::string& total = cols[3];
            if (total.rfind("total=", 0) != 0) {
                why = "header total_length field missing";
                return false;
            }
            if (!parse_bigint_text(total.substr(6), out.total_length)) {
                why = "unparsable total_length";
                return false;
            }
            saw_header = true;
        } else if (line.rfind("atom\t", 0) == 0) {
            const std::vector<std::string> cols = split_on(line, '\t');
            if (cols.size() < 5) {
                why = "unparsable atom record";
                return false;
            }
            Atom atom;
            atom.klass = static_cast<u8>(std::strtoul(cols[2].c_str(), nullptr, 10));
            if (!parse_bigint_text(cols[3], atom.length)) {
                why = "unparsable atom length";
                return false;
            }
            if (!hex_to_digest(cols[4], atom.sha256)) {
                why = "unparsable atom digest";
                return false;
            }
            out.atoms.push_back(std::move(atom));
        } else if (line.rfind("node\t", 0) == 0) {
            const std::vector<std::string> cols = split_on(line, '\t');
            // The rendering is exactly eight fields:
            //   <tag> <id> <kind> <kind_name> <argc> <args> <params> <len>
            // `args` is field 5 and `argc` field 4.  Reading `args` at field 4
            // (the argc slot) silently produced `args = [argc]` for every node with
            // children, which is why the earlier fixtures — single-Atom terms, whose
            // argc is 0 and whose args field is `-` — could not expose it.  A
            // multi-node legacy container does: a `Concat` root then parses as a
            // self-referential node and the encoder rejects it as unreachable.
            if (cols.size() != 8u) {
                why = "node record must have 8 fields";
                return false;
            }
            const std::string argc_field = cols[4];
            const std::string args_field = cols[5];
            const std::string params_field = cols[6];
            const std::string length_field = cols[7];
            Node node;
            node.kind = static_cast<Kind>(std::strtoul(cols[2].c_str(), nullptr, 10));
            // E2 §4.2 field map: `Atom` carries its atom id in `a`, not in `args`
            // (its argc is 0).  H3's rendering prints it in the params column and
            // `-` in the args column, so the two columns are read by kind, not
            // positionally.
            u64 declared_argc = 0;
            if (!parse_u64_text(argc_field, declared_argc)) {
                why = "unparsable node argc";
                return false;
            }
            if (node.kind != Kind::Atom && args_field != "-") {
                for (const std::string& arg : split_on(args_field, ',')) {
                    u64 value = 0;
                    if (!parse_u64_text(arg, value)) {
                        why = "unparsable node argument";
                        return false;
                    }
                    node.args.push_back(static_cast<u32>(value));
                }
            }
            if (node.args.size() != static_cast<std::size_t>(declared_argc)) {
                why = "node argc does not match the argument list";
                return false;
            }
            // Key=value pairs into a map first: `start`/`len` mean different slots
            // for Slice than `start`/`step` do for Affine, so the kind decides.
            std::vector<std::pair<std::string, std::string>> fields;
            for (const std::string& field : split_on(params_field, ',')) {
                const std::size_t eq = field.find('=');
                if (eq == std::string::npos) continue;
                fields.emplace_back(field.substr(0, eq), field.substr(eq + 1));
            }
            auto get = [&fields](const char* key) -> std::optional<std::string> {
                for (const auto& [k, v] : fields) {
                    if (k == key) return v;
                }
                return std::nullopt;
            };
            auto take_bigint = [&](const char* key, BigInt& slot) -> bool {
                const auto value = get(key);
                if (!value.has_value()) return true;
                return parse_bigint_text(*value, slot);
            };
            auto take_u64 = [&](const char* key, u64& slot, int base) -> bool {
                const auto value = get(key);
                if (!value.has_value()) return true;
                if (base == 10 && !parse_u64_text(*value, slot)) return false;
                slot = std::strtoull(value->c_str(), nullptr, base);
                return true;
            };
            switch (node.kind) {
                case Kind::Atom:
                case Kind::Zero:
                case Kind::Lfsr:
                case Kind::Affine:
                    if (!take_bigint("atom", node.a)) return false;
                    if (!take_bigint("n", node.a)) return false;
                    break;
                case Kind::Repeat:
                    if (!take_bigint("q", node.a)) return false;
                    if (!take_bigint("r", node.b)) return false;
                    break;
                case Kind::Slice:
                    if (!take_bigint("start", node.a)) return false;
                    if (!take_bigint("len", node.b)) return false;
                    break;
                case Kind::Interleave: {
                    if (!take_bigint("stride", node.a)) return false;
                    break;
                }
                default:
                    break;
            }
            if (node.kind == Kind::Morph) {
                u64 morph = 0;
                u64 k = 0;
                if (!take_u64("morph", morph, 10)) return false;
                if (!take_u64("k", k, 10)) return false;
                node.morph = static_cast<u8>(morph);
                node.morph_k = static_cast<u8>(k);
            } else if (node.kind == Kind::Lfsr) {
                if (!take_u64("conn", node.lfsr_conn, 16)) return false;
                if (!take_u64("init", node.lfsr_init, 16)) return false;
            } else if (node.kind == Kind::Affine) {
                u64 start_byte = 0;
                u64 step_byte = 0;
                if (!take_u64("start", start_byte, 10)) return false;
                if (!take_u64("step", step_byte, 10)) return false;
                node.affine_start = static_cast<u8>(start_byte);
                node.affine_step = static_cast<u8>(step_byte);
                if (!take_bigint("n", node.a)) return false;
            } else if (node.kind == Kind::Predictor) {
                u64 pid = 0;
                u64 param = 0;
                if (!take_u64("pid", pid, 10)) return false;
                if (!take_u64("param", param, 10)) return false;
                node.predictor_id = static_cast<u8>(pid);
                node.predictor_param = static_cast<u32>(param);
            }
            // The rendering is positional: <kind> <argc> <args> <params> <len>, and a
            // node with no parameters renders an empty params field.  The length is
            // therefore the last column and the params the one before it, whatever
            // the splitter did with an empty run of tabs.
            if (!parse_bigint_text(length_field, node.length)) {
                why = "unparsable node length";
                return false;
            }
            nodes.push_back(std::move(node));
        } else if (line.rfind("trailer\t", 0) == 0) {
            for (const std::string& field : split_on(line, '\t')) {
                const std::size_t eq = field.find('=');
                if (eq == std::string::npos) continue;
                if (field.substr(0, eq) == "root") {
                    u64 value = 0;
                    if (!parse_u64_text(field.substr(eq + 1), value)) {
                        why = "unparsable root id";
                        return false;
                    }
                    root = static_cast<u32>(value);
                }
            }
        }
    }
    if (!saw_header || nodes.empty()) {
        why = "rendering lacks a header or a node table";
        return false;
    }
    out.nodes = std::move(nodes);
    out.root = root;
    return true;
}

}  // namespace e3g
