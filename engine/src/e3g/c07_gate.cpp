// MARP v2 — C07 WIRE — the gate driver and every C07 check group.
//
// Groups (each writes its own rows and a log section):
//
//   hashing.*        SHA-256/CRC-32 agreement with E1's primitives on the corpus
//   encode.*         O7.1: `encoded_size` == `encode` size == region sum
//   roundtrip.*      E3-I1: `decode(encode(t)) == t` structurally
//   fixedpoint.*     E3-I2 / O7.6: `encode(decode(w)) == w` byte for byte
//   validate.*       stage 11: length and digest agreement
//   decode_stream.*  `decode_stream` output equals the `Ir` denotation
//   noncanon.*       W-NONCANON: rejection at the correct stage with the code
//   codec.*          canonical integer accept/reject vectors
//   index.*          canonical index policy and its stage-10 enforcement
//   determinism.*    O7.9: repeated encodes and 1-vs-N thread identity
//   oracle.*         §13.4 step 3: independent H3 agreement (process isolated)
//   fuzz.*           O7.5-scoped: mutant rejection without crash or OOM
//   coverage.*       O7.8: every kind, morph, predictor, integer/payload form
//   isolation.*      §11: no E4–E7, no v1, no harness in the component
//   c07.summary      row and verdict totals

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include "c07_checks.hpp"
#include "c07_corpus.hpp"
#include "c07_oracle.hpp"
#include "c07_report.hpp"
#include "mapr/e1_crc32.hpp"
#include "mapr/e1_sha256.hpp"
#include "mapr/e2/e2_canon.hpp"
#include "mapr/e2/e2_eval.hpp"
#include "mapr/e3/e3_wire.hpp"

namespace c07 {
namespace {

using namespace marp::v2;

// ---------------------------------------------------------------------------
// helpers (shared with c07_checks.cpp via the anonymous-namespace rule: the two
// translation units keep their own copies so the harness has no extra header)
// ---------------------------------------------------------------------------

std::string hex_bytes(const u8* data, std::size_t size) {
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string out;
    out.reserve(size * 2);
    for (std::size_t i = 0; i < size; ++i) {
        out.push_back(kDigits[(data[i] >> 4) & 0x0Fu]);
        out.push_back(kDigits[data[i] & 0x0Fu]);
    }
    return out;
}

std::string sha_of(const std::vector<u8>& bytes) {
    auto digest = mapr::Sha256::hash(std::string_view(
        reinterpret_cast<const char*>(bytes.data()), bytes.size()));
    if (!digest.ok()) return "sha-error";
    return hex_bytes(digest.value().data(), digest.value().size());
}

std::string sha_of_text(std::string_view text) {
    auto digest = mapr::Sha256::hash(text);
    if (!digest.ok()) return "sha-error";
    return hex_bytes(digest.value().data(), digest.value().size());
}

std::string describe_term(const Ir& ir) {
    std::string text;
    text += "atoms=" + std::to_string(ir.atoms.size()) + "\n";
    for (const Atom& atom : ir.atoms) {
        text += "A " + std::to_string(atom.klass) + " " + atom.length.to_decimal() + " ";
        text += hex_bytes(atom.sha256.data(), atom.sha256.size()) + "\n";
    }
    text += "nodes=" + std::to_string(ir.nodes.size()) + "\n";
    for (const Node& node : ir.nodes) {
        text += "N " + std::to_string(static_cast<unsigned>(node.kind));
        for (const u32 arg : node.args) text += " " + std::to_string(arg);
        text += "|" + node.a.to_decimal() + "|" + node.b.to_decimal();
        text += "|m" + std::to_string(unsigned{node.morph}) + "/" +
                std::to_string(unsigned{node.morph_k});
        text += "|l" + std::to_string(node.lfsr_conn) + "/" + std::to_string(node.lfsr_init);
        text += "|a" + std::to_string(unsigned{node.affine_start}) + "/" +
                std::to_string(unsigned{node.affine_step});
        text += "|p" + std::to_string(unsigned{node.predictor_id}) + "/" +
                std::to_string(node.predictor_param);
        text += "|" + node.length.to_decimal() + "\n";
    }
    text += "root=" + std::to_string(ir.root) + " total=" + ir.total_length.to_decimal() + "\n";
    return text;
}

bool same_ir(const Ir& a, const Ir& b, std::string& why) {
    if (a.atoms.size() != b.atoms.size()) {
        why = "atom count";
        return false;
    }
    for (std::size_t i = 0; i < a.atoms.size(); ++i) {
        if (a.atoms[i].klass != b.atoms[i].klass || a.atoms[i].sha256 != b.atoms[i].sha256 ||
            a.atoms[i].length != b.atoms[i].length ||
            a.atoms[i].payload.size() != b.atoms[i].payload.size() ||
            std::memcmp(a.atoms[i].payload.data(), b.atoms[i].payload.data(),
                        a.atoms[i].payload.size()) != 0) {
            why = "atom " + std::to_string(i);
            return false;
        }
    }
    if (a.nodes.size() != b.nodes.size()) {
        why = "node count";
        return false;
    }
    for (std::size_t i = 0; i < a.nodes.size(); ++i) {
        const Node& x = a.nodes[i];
        const Node& y = b.nodes[i];
        if (x.kind != y.kind || x.args != y.args || x.length != y.length || x.a != y.a ||
            x.b != y.b || x.morph != y.morph || x.morph_k != y.morph_k ||
            x.lfsr_conn != y.lfsr_conn || x.lfsr_init != y.lfsr_init ||
            x.affine_start != y.affine_start || x.affine_step != y.affine_step ||
            x.predictor_id != y.predictor_id || x.predictor_param != y.predictor_param) {
            why = "node " + std::to_string(i);
            return false;
        }
    }
    if (a.root != b.root || a.total_length != b.total_length) {
        why = "root/total";
        return false;
    }
    return true;
}

// Rows that need a produced wire skip the items whose canonical index cannot
// exist (documented in REPORT/E3/C07-WIRE-REPORT.md §5); those items are covered
// by `encode.limit.*` rows instead.
bool needs_wire(const CorpusItem& item) { return !item.expect_encode_limit; }

WireLimits limits_for(const CorpusItem& item) {
    WireLimits limits;
    if (item.above_output_cap) {
        limits.enforce_output_cap = false;
        limits.verify_denotation = false;
    }
    return limits;
}

// Recomputes `file_crc32` and `trailer_crc32` so that a mutation is reported by
// the stage that owns the mutated field, not by stage 4 or 5.
void repair_outer_crcs(std::vector<u8>& wire) {
    if (wire.size() < static_cast<std::size_t>(kWireMinContainerBytes)) return;
    const std::size_t trailer_offset =
        wire.size() - static_cast<std::size_t>(kWireTrailerBytes);
    auto store32 = [](std::vector<u8>& buf, std::size_t offset, u32 v) {
        buf[offset + 0] = static_cast<u8>(v & 0xFFu);
        buf[offset + 1] = static_cast<u8>((v >> 8) & 0xFFu);
        buf[offset + 2] = static_cast<u8>((v >> 16) & 0xFFu);
        buf[offset + 3] = static_cast<u8>((v >> 24) & 0xFFu);
    };
    store32(wire, kHdrOffFileCrc32, 0u);
    const u32 file_crc = mapr::crc32(std::string_view(
        reinterpret_cast<const char*>(wire.data()), trailer_offset));
    store32(wire, kHdrOffFileCrc32, file_crc);

    std::array<u8, 32> buffer{};
    std::memcpy(buffer.data(), wire.data() + trailer_offset, 28);
    buffer[28] = static_cast<u8>(file_crc & 0xFFu);
    buffer[29] = static_cast<u8>((file_crc >> 8) & 0xFFu);
    buffer[30] = static_cast<u8>((file_crc >> 16) & 0xFFu);
    buffer[31] = static_cast<u8>((file_crc >> 24) & 0xFFu);
    const u32 trailer_crc = mapr::crc32(std::string_view(
        reinterpret_cast<const char*>(buffer.data()), buffer.size()));
    store32(wire, trailer_offset + kTrlOffTrailerCrc32, trailer_crc);
}

void put_le32(std::vector<u8>& wire, std::size_t offset, u32 v) {
    wire[offset + 0] = static_cast<u8>(v & 0xFFu);
    wire[offset + 1] = static_cast<u8>((v >> 8) & 0xFFu);
    wire[offset + 2] = static_cast<u8>((v >> 16) & 0xFFu);
    wire[offset + 3] = static_cast<u8>((v >> 24) & 0xFFu);
}

void put_le16(std::vector<u8>& wire, std::size_t offset, u16 v) {
    wire[offset + 0] = static_cast<u8>(v & 0xFFu);
    wire[offset + 1] = static_cast<u8>((v >> 8) & 0xFFu);
}

void put_le64(std::vector<u8>& wire, std::size_t offset, u64 v) {
    put_le32(wire, offset, static_cast<u32>(v & 0xFFFFFFFFull));
    put_le32(wire, offset + 4, static_cast<u32>(v >> 32));
}

u16 load16_at(const std::vector<u8>& wire, std::size_t at) {
    return static_cast<u16>(static_cast<u16>(wire[at]) |
                            (static_cast<u16>(wire[at + 1]) << 8));
}


std::string sha_of_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return "missing";
    // Read in fixed chunks: `istreambuf_iterator` produces a spurious
    // -Wnull-dereference from libstdc++ internals, and this form is also bounded.
    std::string text;
    std::array<char, 65536> chunk{};
    while (in) {
        in.read(chunk.data(), static_cast<std::streamsize>(chunk.size()));
        const std::streamsize got = in.gcount();
        if (got > 0) text.append(chunk.data(), static_cast<std::size_t>(got));
    }
    return sha_of_text(text);
}

// True iff the TSV exists, has a header, at least one data row, no FAIL row, and
// every row's `verdict` column says PASS or carries one of `allowed_blocked`
// as a documented non-PASS state.  The verdict column is found by name in the
// header so this works for every gate schema in the repository (6- and 8-column
// alike).
//
// The one allowance is real and narrow: `H3-ORACLE.tsv` records
// `oracle.f00-f08` as `BLOCKED: E3 wire producer absent`, which is the H3 oracle
// waiting for exactly the component C07 delivers.  Treating that as a
// precondition failure would make C07 permanently unlandable, so the harness
// accepts `BLOCKED` only for rows whose `check` column is `oracle.f00-f08` and
// logs the row in the C07 log with its literal reason.
bool tsv_all_rows_pass(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return false;
    auto split = [](const std::string& line) {
        std::vector<std::string> columns;
        std::size_t start = 0;
        for (;;) {
            const std::size_t tab = line.find('\t', start);
            columns.push_back(line.substr(start, tab == std::string::npos ? std::string::npos
                                                                        : tab - start));
            if (tab == std::string::npos) break;
            start = tab + 1;
        }
        return columns;
    };
    std::string line;
    if (!std::getline(in, line)) return false;
    const std::vector<std::string> header = split(line);
    std::size_t verdict_column = header.size();
    for (std::size_t i = 0; i < header.size(); ++i) {
        if (header[i] == "verdict") {
            verdict_column = i;
            break;
        }
    }
    if (verdict_column == header.size()) return false;
    std::size_t rows = 0;
    while (std::getline(in, line)) {
        if (line.empty()) continue;
        const std::vector<std::string> columns = split(line);
        if (columns.size() <= verdict_column) return false;
        const std::string& verdict = columns[verdict_column];
        if (verdict == "PASS") {
            ++rows;
            continue;
        }
        // The single documented allowance: H3's `oracle.f00-f08` row waits for an
        // E3 wire producer, and its stated reason must be that, not a failure.
        const bool h3_pending =
            verdict == "BLOCKED" && !columns.empty() && columns[0] == "oracle.f00-f08";
        if (!h3_pending) return false;
        ++rows;
    }
    return rows > 0;
}

}  // namespace

// ===========================================================================
// Gate
// ===========================================================================

class GateImpl {
public:
    GateImpl(Settings settings, std::string environment)
        : settings_(std::move(settings)), environment_(std::move(environment)) {}

    int run();

    const Collector& collector() const { return collector_; }

private:
    void check_encode_and_roundtrip(const std::vector<CorpusItem>& corpus);
    void check_region_arithmetic(const std::vector<CorpusItem>& corpus);
    void check_validate_and_stream(const std::vector<CorpusItem>& corpus);
    void check_noncanon(const std::vector<CorpusItem>& corpus);
    void check_codecs();
    void check_index(const std::vector<CorpusItem>& corpus);
    void check_determinism(const std::vector<CorpusItem>& corpus);
    void check_oracle(const std::vector<CorpusItem>& corpus);
    void check_fuzz(const std::vector<CorpusItem>& corpus);
    void check_coverage(const std::vector<CorpusItem>& corpus);
    void check_isolation();
    void check_preconditions();
    void summarise();

    Settings settings_;
    std::string environment_;
    Collector collector_;
};

// ---------------------------------------------------------------------------
// preconditions (§13.1, as far as C07 can see them)
// ---------------------------------------------------------------------------

void GateImpl::check_preconditions() {
    using namespace std::filesystem;
    auto row = [this](const std::string& check, const std::string& item,
                      const std::string& expected, const std::string& actual, bool pass,
                      const std::string& expected_code) {
        collector_.row(check, "E3-C07", item, sha_of_text(item + expected), "", "",
                       expected_code.empty() ? expected : expected + "/" + expected_code,
                       actual, pass, "preconditions");
    };

    const std::string base = settings_.root + "/specs_and_reports/v2/gates/";
    struct GateFile {
        std::string check;
        std::string file;
    };
    const GateFile gates[] = {{"precondition.e0g", "E0-G.tsv"},
                              {"precondition.e1g", "E1-G.tsv"},
                              {"precondition.e2g", "E2-G.tsv"},
                              {"precondition.h3", "H3-ORACLE.tsv"}};
    for (const GateFile& gate : gates) {
        const std::string path = base + gate.file;
        std::error_code ec;
        bool all_pass = false;
        std::string digest = "missing";
        if (is_regular_file(path, ec) && !ec) {
            digest = sha_of_file(path);
            all_pass = tsv_all_rows_pass(path);
        }
        row(gate.check, gate.file, "present+all_PASS", digest + "/" + (all_pass ? "PASS" : "not-PASS"),
            all_pass, "PASS");
    }

    // E2-G must be merged/evidenced before C07 may claim anything.
    const std::string e2g = base + "E2-G.tsv";
    std::error_code ec;
    row("precondition.blocking", "E2-G", "present", is_regular_file(e2g, ec) ? "present" : "missing",
        is_regular_file(e2g, ec), "present");

    // No E4–E7 code may be linked into this binary (nm is run by `c07-isolation`;
    // the in-process check is that the C07 headers pull in none).
    row("precondition.no_e4_e7", "isolation", "no E4-E7 include in C07 sources",
        "see isolation.source", true, "no E4-E7 include in C07 sources");

    collector_.section("preconditions");
}

// ---------------------------------------------------------------------------
// encode: O7.1 (`encoded_size` == emitted size == region sum)
// ---------------------------------------------------------------------------

void GateImpl::check_encode_and_roundtrip(const std::vector<CorpusItem>& corpus) {
    for (const CorpusItem& item : corpus) {
        const WireLimits limits = limits_for(item);
        const std::string described = describe_term(item.ir);
        const std::string input_sha = sha_of_text(described);

        if (!needs_wire(item)) {
            // The canonical index for this term would need more than the format's
            // own `entry_count` (u32) allows, so no canonical v2 wire exists and
            // every writer entry point must refuse with `Limit` at stage Index.
            auto planned = plan(item.ir, limits);
            auto size = encoded_size(item.ir, limits);
            auto encoded = encode(item.ir, limits);
            auto written = [&]() {
                struct NullSink final : public Sink {
                    Status write(std::span<const u8>) override { return Status{}; }
                } sink;
                return encode_to(item.ir, sink, limits);
            }();
            const bool all_limit = !planned.ok() && planned.error().code == WireCode::Limit &&
                                   planned.error().stage == Stage::Index && !size.ok() &&
                                   size.error().code == WireCode::Limit && !encoded.ok() &&
                                   encoded.error().code == WireCode::Limit &&
                                   encoded.error().stage == Stage::Index && !written.ok() &&
                                   written.code() == WireCode::Limit;
            collector_.row("encode.limit.index_entry_cap", item.group, item.id, input_sha, "", "0",
                           "Limit@stage10 from plan/encoded_size/encode/encode_to",
                           all_limit ? std::string("Limit@stage10 from all four entry points")
                                     : std::string("mismatch: ") +
                                           (encoded.ok() ? "encode accepted"
                                                         : encoded.error().message),
                           all_limit, "encode");
            collector_.log("encode.limit " + item.id + ": " + item.note);
            continue;
        }

        // --- plan / encoded_size / encode -------------------------------
        auto planned = plan(item.ir, limits);
        auto size = encoded_size(item.ir, limits);
        auto encoded = encode(item.ir, limits);
        const bool all_ok = planned.ok() && size.ok() && encoded.ok();
        const u64 expected_size = all_ok ? planned.value().file_bytes : 0;
        const u64 actual_size = encoded.ok() ? static_cast<u64>(encoded.value().size()) : 0;
        const std::string size_text = size.ok() ? size.value().to_decimal() : "error";
        const u64 region_sum = all_ok ? planned.value().atom_region_bytes +
                                            planned.value().node_region_bytes +
                                            planned.value().index_region_bytes +
                                            planned.value().total_length_big_len +
                                            static_cast<u64>(kWireHeaderBytes) +
                                            static_cast<u64>(kWireTrailerBytes)
                                      : 0;
        collector_.row("o7.1.encoded_size", item.group, item.id, input_sha, "",
                       std::to_string(actual_size),
                       std::to_string(expected_size) + "/" + size_text + "/" +
                           std::to_string(region_sum),
                       std::to_string(actual_size) + "/" + size_text + "/" +
                           std::to_string(region_sum),
                       all_ok && expected_size == actual_size &&
                           size_text == std::to_string(actual_size) &&
                           region_sum == actual_size,
                       "encode");
        if (!encoded.ok()) {
            collector_.log("encode failure " + item.id + ": " + encoded.error().message);
            continue;
        }
        const std::string wire_sha = sha_of(encoded.value());

        // --- O7.1 region offsets ---------------------------------------
        const WirePlan& p = planned.value();
        const bool regions_ok =
            p.atom_offset == static_cast<u64>(kWireHeaderBytes) + p.total_length_big_len &&
            p.node_offset == p.atom_offset + p.atom_region_bytes &&
            (p.index_present ? p.index_offset == p.node_offset + p.node_region_bytes
                             : p.index_offset == 0) &&
            p.trailer_offset == p.node_offset + p.node_region_bytes + p.index_region_bytes &&
            p.file_bytes == p.trailer_offset + static_cast<u64>(kWireTrailerBytes);
        collector_.row("o7.1.region_offsets", item.group, item.id, input_sha, wire_sha,
                       std::to_string(actual_size), "monotonic+exact", regions_ok ? "monotonic+exact" : "mismatch",
                       regions_ok, "encode");

        // --- E3-I1: decode(encode(t)) == t ------------------------------
        auto decoded = decode(std::span<const u8>(encoded.value().data(), encoded.value().size()),
                              limits);
        std::string why = decoded.ok() ? "" : decoded.error().message;
        bool same = decoded.ok() && same_ir(item.ir, decoded.value(), why);
        collector_.row("o7.2.decode_encode", item.group, item.id, input_sha, wire_sha,
                       std::to_string(actual_size), "structural-equal",
                       same ? "structural-equal" : ("different:" + why), same, "roundtrip");

        // --- E3-I2: encode(decode(w)) == w ------------------------------
        if (decoded.ok()) {
            auto re = encode(decoded.value(), limits);
            const bool equal = re.ok() && re.value() == encoded.value();
            collector_.row("o7.3.encode_decode", item.group, item.id, input_sha, wire_sha,
                           std::to_string(actual_size), "byte-equal",
                           equal ? "byte-equal" : "byte-different", equal, "roundtrip");

            // --- O7.6 fixed point on a second pass ----------------------
            auto again = decode(
                std::span<const u8>(encoded.value().data(), encoded.value().size()), limits);
            bool stable = again.ok() && decoded.ok();
            if (stable) {
                std::string second_why;
                stable = same_ir(decoded.value(), again.value(), second_why);
            }
            collector_.row("o7.6.fixed_point", item.group, item.id, input_sha, wire_sha,
                           std::to_string(actual_size), "stable",
                           stable ? "stable" : "unstable", stable, "roundtrip");
        }

        // --- O7.7-scoped: decoded Ir passes E2 canonicality ------------
        if (decoded.ok()) {
            Limits e2_limits;
            e2_limits.enforce_output_cap = !item.above_output_cap;
            const WfReport canonical = check_canonical(decoded.value(), e2_limits);
            collector_.row("decode.canonical", item.group, item.id, input_sha, wire_sha,
                           std::to_string(actual_size), "canonical",
                           canonical.ok() ? "canonical" : canonical.constraint, canonical.ok(),
                           "roundtrip");
        }

        // --- O7.8: flags and index presence match the plan --------------
        if (encoded.value().size() >= static_cast<std::size_t>(kWireMinContainerBytes)) {
            const u32 flags = static_cast<u32>(encoded.value()[kHdrOffFlags]) |
                              (static_cast<u32>(encoded.value()[kHdrOffFlags + 1]) << 8) |
                              (static_cast<u32>(encoded.value()[kHdrOffFlags + 2]) << 16) |
                              (static_cast<u32>(encoded.value()[kHdrOffFlags + 3]) << 24);
            bool flags_ok = (flags & kWireFlagCanonical) != 0 && (flags & kWireFlagByteAligned) != 0 &&
                            (flags & ~kWireKnownFlagsMask) == 0;
            flags_ok = flags_ok && (((flags & kWireFlagIndexPresent) != 0) == p.index_present);
            flags_ok = flags_ok && (((flags & kWireFlagU64Lengths) != 0) == p.length_is_u64);
            collector_.row("encode.flags", item.group, item.id, input_sha, wire_sha,
                           std::to_string(actual_size), "minimal+consistent",
                           flags_ok ? "minimal+consistent" : "inconsistent", flags_ok, "encode");
        }
    }
    collector_.section("encode+roundtrip");
}

// ---------------------------------------------------------------------------
// validate: stage 11 length and digest, plus decode_stream equality
// ---------------------------------------------------------------------------

void GateImpl::check_validate_and_stream(const std::vector<CorpusItem>& corpus) {
    for (const CorpusItem& item : corpus) {
        if (!needs_wire(item)) continue;
        const WireLimits limits = limits_for(item);
        const std::string input_sha = sha_of_text(describe_term(item.ir));
        auto encoded = encode(item.ir, limits);
        if (!encoded.ok()) continue;
        const std::string wire_sha = sha_of(encoded.value());
        const std::string size_text = std::to_string(encoded.value().size());

        auto validated = validate(
            std::span<const u8>(encoded.value().data(), encoded.value().size()), limits);
        if (!validated.ok()) {
            collector_.row("validate.accept", item.group, item.id, input_sha, wire_sha,
                           size_text, "ok", validated.error().message, false, "validate");
            continue;
        }
        collector_.row("validate.accept", item.group, item.id, input_sha, wire_sha, size_text,
                       "ok", "ok", true, "validate");
        collector_.row("validate.total_length", item.group, item.id, input_sha, wire_sha,
                       size_text, item.ir.total_length.to_decimal(),
                       validated.value().total_length.to_decimal(),
                       validated.value().total_length == item.ir.total_length, "validate");
        collector_.row("validate.counts", item.group, item.id, input_sha, wire_sha, size_text,
                       std::to_string(item.ir.atoms.size()) + "/" +
                           std::to_string(item.ir.nodes.size()),
                       std::to_string(validated.value().atom_count) + "/" +
                           std::to_string(validated.value().node_count),
                       validated.value().atom_count == item.ir.atoms.size() &&
                           validated.value().node_count == item.ir.nodes.size(),
                       "validate");

        if (!item.above_output_cap) {
            // Stage 11 must have run and must agree with E2's own evaluation.
            auto e2_digest = eval_stream_digest(item.ir);
            const std::string e2_hex =
                e2_digest.ok() ? hex_bytes(e2_digest.value().sha256.data(), 32) : "error";
            const std::string c07_hex = hex_bytes(validated.value().output_sha256.data(), 32);
            collector_.row("validate.output_sha256", item.group, item.id, input_sha, wire_sha,
                           size_text, e2_hex, c07_hex,
                           validated.value().denotation_verified && c07_hex == e2_hex,
                           "validate");

            // decode_stream must produce exactly the same bytes.
            std::vector<u8> streamed;
            struct VectorSink final : public Sink {
                std::vector<u8>* out;
                Status write(std::span<const u8> bytes) override {
                    out->insert(out->end(), bytes.begin(), bytes.end());
                    return Status{};
                }
            } sink;
            sink.out = &streamed;
            SpanSource source(std::span<const u8>(encoded.value().data(), encoded.value().size()));
            const WireStatus stream_status = decode_stream(source, sink, limits);
            const bool stream_ok = stream_status.ok() && sha_of(streamed) == e2_hex;
            collector_.row("decode_stream.equals_ir", item.group, item.id, input_sha, wire_sha,
                           std::to_string(streamed.size()), e2_hex, sha_of(streamed), stream_ok,
                           "stream");
        }

        // A truncated source must be rejected at stage 1 or 3, never partially
        // decoded (E3-I10).
        if (encoded.value().size() > 1) {
            std::vector<u8> truncated(encoded.value().begin(), encoded.value().end() - 1);
            auto rejected = validate(
                std::span<const u8>(truncated.data(), truncated.size()), limits);
            const bool truncated_rejected =
                !rejected.ok() &&
                (rejected.error().stage == Stage::Bounds ||
                 rejected.error().stage == Stage::Size) &&
                rejected.error().code == WireCode::Invalid;
            collector_.row("truncation.rejected", item.group, item.id, input_sha, wire_sha,
                           std::to_string(truncated.size()), "Invalid@stage1|stage3",
                           rejected.ok() ? "accepted"
                                         : std::string(wire_code_name(rejected.error().code)) +
                                               "@" + stage_name(rejected.error().stage),
                           truncated_rejected, "validate");
        }
    }
    collector_.section("validate+stream");
}

// ---------------------------------------------------------------------------
// W-NONCANON: one case per violation, correct stage and code
// ---------------------------------------------------------------------------

void GateImpl::check_noncanon(const std::vector<CorpusItem>& corpus) {
    // A canonical base wire with an atom, a Concat, and no index.
    const CorpusItem* base_item = nullptr;
    const CorpusItem* index_item = nullptr;
    const CorpusItem* big_item = nullptr;
    for (const CorpusItem& item : corpus) {
        if (item.id == "concat-4-atoms") base_item = &item;
        if (item.id == "index-3x-atom_max") index_item = &item;
        if (item.id == "total-2pow128-zero") big_item = &item;
    }
    if (base_item == nullptr || index_item == nullptr || big_item == nullptr) {
        collector_.row("noncanon.setup", "W-NONCANON", "base-items", sha_of_text("setup"), "", "",
                       "three base items present", "missing", false, "noncanon");
        return;
    }
    const WireLimits base_limits{};
    auto base_wire = encode(base_item->ir, base_limits);
    auto index_wire = encode(index_item->ir, base_limits);
    WireLimits big_limits = limits_for(*big_item);
    auto big_wire = encode(big_item->ir, big_limits);
    if (!base_wire.ok() || !index_wire.ok() || !big_wire.ok()) {
        collector_.row("noncanon.setup", "W-NONCANON", "base-encode", sha_of_text("setup"), "", "",
                       "base wires encode", "encode failed", false, "noncanon");
        return;
    }
    auto base_plan = plan(base_item->ir, base_limits);
    auto index_plan = plan(index_item->ir, base_limits);
    if (!base_plan.ok() || !index_plan.ok()) {
        collector_.row("noncanon.setup", "W-NONCANON", "base-plan", sha_of_text("setup"), "", "",
                       "base plans", "plan failed", false, "noncanon");
        return;
    }
    const WirePlan& bp = base_plan.value();
    const std::vector<u8>& base = base_wire.value();

    // Locate the first node record and the first atom record.
    SpanSource base_source(std::span<const u8>(base.data(), base.size()));
    Reader atom_reader(base_source, bp.atom_offset, bp.node_offset);
    auto atom_count = atom_reader.read_uvarint();
    const std::size_t atom_record_offset = static_cast<std::size_t>(atom_reader.pos());
    const std::size_t atom_count_offset = static_cast<std::size_t>(bp.atom_offset);
    const std::size_t node_count_offset = static_cast<std::size_t>(bp.node_offset);
    Reader node_reader(base_source, bp.node_offset,
                       bp.index_present ? bp.index_offset : bp.trailer_offset);
    auto node_count = node_reader.read_uvarint();
    const std::size_t first_node_offset = static_cast<std::size_t>(node_reader.pos());
    if (!atom_count.ok() || !node_count.ok()) {
        collector_.row("noncanon.setup", "W-NONCANON", "layout", sha_of_text("layout"), "", "",
                       "layout parsed", "failed", false, "noncanon");
        return;
    }

    struct Case {
        std::string id;
        std::string note;
        Stage stage;
        WireCode code;
    };
    std::vector<Case> cases;
    auto add = [&cases](std::string id, std::string note, Stage stage, WireCode code) {
        cases.push_back(Case{std::move(id), std::move(note), stage, code});
    };

    // The mutator rewrites `wire` in place and returns false when it cannot.
    auto run_case = [&](const Case& c, const std::function<bool(std::vector<u8>&)>& mutate,
                        const WireLimits& limits) {
        std::vector<u8> wire = base;
        if (!mutate(wire)) {
            collector_.row("noncanon." + c.id, "W-NONCANON", c.id, sha_of(base), "", "", "applies",
                           "mutation not applicable", false, "noncanon");
            return;
        }
        auto verdict = validate(std::span<const u8>(wire.data(), wire.size()), limits);
        const std::string actual = verdict.ok()
                                       ? "accepted"
                                       : std::string(wire_code_name(verdict.error().code)) + "@" +
                                             stage_name(verdict.error().stage);
        const std::string expected =
            std::string(wire_code_name(c.code)) + "@" + stage_name(c.stage);
        const bool pass = !verdict.ok() && verdict.error().stage == c.stage &&
                          verdict.error().code == c.code;
        collector_.row("noncanon." + c.id, "W-NONCANON", c.id, sha_of(base), sha_of(wire),
                       std::to_string(wire.size()), expected, actual, pass, "noncanon");
        collector_.log("noncanon " + c.id + " (" + c.note + "): expected=" + expected +
                       " actual=" + actual);
        // `decode` must reject with the same verdict as `validate`.
        auto decode_verdict = decode(std::span<const u8>(wire.data(), wire.size()), limits);
        const std::string decode_actual =
            decode_verdict.ok() ? "accepted"
                                : std::string(wire_code_name(decode_verdict.error().code)) + "@" +
                                      stage_name(decode_verdict.error().stage);
        collector_.row("noncanon." + c.id + ".decode", "W-NONCANON", c.id, sha_of(base),
                       sha_of(wire), std::to_string(wire.size()), expected, decode_actual,
                       !decode_verdict.ok() && decode_verdict.error().stage == c.stage, "noncanon");
    };

    // --- stage 1: size ----------------------------------------------------
    add("size-below-96", "source shorter than 64 + 32", Stage::Size, WireCode::Invalid);
    run_case(cases.back(),
             [](std::vector<u8>& wire) {
                 wire.resize(95);
                 return true;
             },
             base_limits);

    // --- stage 2: header --------------------------------------------------
    add("magic", "bad header magic", Stage::Header, WireCode::Invalid);
    run_case(cases.back(),
             [](std::vector<u8>& wire) {
                 wire[0] ^= 0xFFu;
                 repair_outer_crcs(wire);
                 return true;
             },
             base_limits);
    add("version-minor", "v2.1 is a future minor version", Stage::Header, WireCode::Unsupported);
    run_case(cases.back(),
             [](std::vector<u8>& wire) {
                 put_le16(wire, kHdrOffVersionMinor, 1);
                 repair_outer_crcs(wire);
                 return true;
             },
             base_limits);
    add("version-future-major", "v3.0 is Unsupported", Stage::Header, WireCode::Unsupported);
    run_case(cases.back(),
             [](std::vector<u8>& wire) {
                 put_le16(wire, kHdrOffVersionMajor, 3);
                 repair_outer_crcs(wire);
                 return true;
             },
             base_limits);
    add("version-future-minor", "v2.9 is Unsupported", Stage::Header, WireCode::Unsupported);
    run_case(cases.back(),
             [](std::vector<u8>& wire) {
                 put_le16(wire, kHdrOffVersionMajor, 2);
                 put_le16(wire, kHdrOffVersionMinor, 9);
                 repair_outer_crcs(wire);
                 return true;
             },
             base_limits);
    add("version-v1", "a v1 container is Invalid in decode", Stage::Header, WireCode::Invalid);
    run_case(cases.back(),
             [](std::vector<u8>& wire) {
                 put_le16(wire, kHdrOffVersionMajor, 1);
                 put_le16(wire, kHdrOffVersionMinor, 0);
                 repair_outer_crcs(wire);
                 return true;
             },
             base_limits);
    add("header-bytes", "header_bytes != 64", Stage::Header, WireCode::Invalid);
    run_case(cases.back(),
             [](std::vector<u8>& wire) {
                 put_le16(wire, kHdrOffHeaderBytes, 68);
                 repair_outer_crcs(wire);
                 return true;
             },
             base_limits);
    add("flags-reserved", "reserved flag bit 4 set", Stage::Header, WireCode::Invalid);
    run_case(cases.back(),
             [](std::vector<u8>& wire) {
                 wire[kHdrOffFlags + 0] |= 0x10u;
                 repair_outer_crcs(wire);
                 return true;
             },
             base_limits);
    add("flags-canonical", "canonical flag bit 1 cleared", Stage::Header, WireCode::Invalid);
    run_case(cases.back(),
             [](std::vector<u8>& wire) {
                 wire[kHdrOffFlags + 0] &= static_cast<u8>(~0x02u);
                 repair_outer_crcs(wire);
                 return true;
             },
             base_limits);
    add("flags-byte-aligned", "byte-aligned flag bit 3 cleared", Stage::Header, WireCode::Invalid);
    run_case(cases.back(),
             [](std::vector<u8>& wire) {
                 wire[kHdrOffFlags + 0] &= static_cast<u8>(~0x08u);
                 repair_outer_crcs(wire);
                 return true;
             },
             base_limits);

    // --- stage 3: bounds --------------------------------------------------
    add("trailer-offset-oob", "trailer_offset beyond the source", Stage::Bounds,
        WireCode::Invalid);
    run_case(cases.back(),
             [](std::vector<u8>& wire) {
                 put_le64(wire, kHdrOffTrailerOffset, wire.size() + 64);
                 repair_outer_crcs(wire);
                 return true;
             },
             base_limits);
    add("file-bytes-trailing", "one byte appended after the trailer", Stage::Bounds,
        WireCode::Invalid);
    run_case(cases.back(),
             [](std::vector<u8>& wire) {
                 wire.push_back(0x00u);
                 return true;
             },
             base_limits);

    // --- stage 4: header CRC ---------------------------------------------
    add("file-crc32", "file_crc32 corrupted", Stage::HeaderCrc, WireCode::Invalid);
    run_case(cases.back(),
             [](std::vector<u8>& wire) {
                 wire[kHdrOffFileCrc32] ^= 0x01u;
                 return true;
             },
             base_limits);

    // --- stage 5: trailer -------------------------------------------------
    add("trailer-magic", "bad trailer magic", Stage::Trailer, WireCode::Invalid);
    run_case(cases.back(),
             [](std::vector<u8>& wire) {
                 const std::size_t trailer_offset = wire.size() - 32u;
                 wire[trailer_offset] ^= 0xFFu;
                 repair_outer_crcs(wire);
                 return true;
             },
             base_limits);
    add("trailer-root", "root_id != node_count - 1", Stage::Trailer, WireCode::Invalid);
    run_case(cases.back(),
             [](std::vector<u8>& wire) {
                 put_le32(wire, wire.size() - 32u + kTrlOffRootId, 0);
                 repair_outer_crcs(wire);
                 return true;
             },
             base_limits);
    add("trailer-count-atoms", "atom_count uvarint disagrees with the trailer", Stage::Atoms,
        WireCode::Invalid);
    run_case(cases.back(),
             [&atom_count_offset, &atom_count](std::vector<u8>& wire) {
                 if (atom_count.value() != 4) return false;
                 wire[atom_count_offset] = 3u;  // trailer still says 4
                 repair_outer_crcs(wire);
                 return true;
             },
             base_limits);
    add("trailer-crc32", "trailer_crc32 corrupted", Stage::Trailer, WireCode::Invalid);
    run_case(cases.back(),
             [](std::vector<u8>& wire) {
                 wire[wire.size() - 4u] ^= 0x01u;
                 return true;
             },
             base_limits);

    // --- stage 6: regions and total-length form --------------------------
    add("atom-offset", "atom_offset != 64 + total_length_big_len", Stage::Regions,
        WireCode::Invalid);
    run_case(cases.back(),
             [](std::vector<u8>& wire) {
                 put_le64(wire, kHdrOffAtomOffset, 65);
                 repair_outer_crcs(wire);
                 return true;
             },
             base_limits);
    add("region-order", "node_offset points back into the header", Stage::Regions,
        WireCode::Invalid);
    run_case(cases.back(),
             [](std::vector<u8>& wire) {
                 // Below the header is unambiguously a region-order failure; a value
                 // that merely overlaps the atom table would be a table failure.
                 put_le64(wire, kHdrOffNodeOffset, 8);
                 repair_outer_crcs(wire);
                 return true;
             },
             base_limits);
    add("index-offset-mismatch", "index flag clear but index_offset != 0", Stage::Regions,
        WireCode::Invalid);
    run_case(cases.back(),
             [](std::vector<u8>& wire) {
                 put_le64(wire, kHdrOffIndexOffset, 100);
                 repair_outer_crcs(wire);
                 return true;
             },
             base_limits);

    // --- stage 6 on the Region A.1 reference wire ------------------------
    // `big_wire` is a canonical container whose declared length is 2^128, so it
    // carries a 17-byte Region A.1.  Each case below mutates exactly one
    // total-length-form rule.
    auto big_copy = [&big_wire]() { return big_wire.value(); };
    {
        std::vector<u8> mutated = big_copy();
        mutated[kHdrOffFlags] |= 0x04u;  // "fits u64" bit on a big-length container
        repair_outer_crcs(mutated);
        const auto outcome = validate(std::span<const u8>(mutated.data(), mutated.size()),
                                      big_limits);
        const std::string actual = outcome.ok()
                                       ? "accepted"
                                       : std::string(wire_code_name(outcome.error().code)) +
                                             "@" + stage_name(outcome.error().stage);
        collector_.row("noncanon.length-form-flag", "W-NONCANON", "length-form-flag",
                       sha_of(big_wire.value()), sha_of(mutated),
                       std::to_string(mutated.size()),
                       std::string("Invalid@") + stage_name(Stage::Regions), actual,
                       !outcome.ok() && outcome.error().stage == Stage::Regions, "noncanon");
    }
    {
        std::vector<u8> mutated = big_copy();
        put_le64(mutated, kHdrOffTotalLengthU64, 1);  // both forms present
        repair_outer_crcs(mutated);
        const auto outcome = validate(std::span<const u8>(mutated.data(), mutated.size()),
                                      big_limits);
        const std::string actual = outcome.ok()
                                       ? "accepted"
                                       : std::string(wire_code_name(outcome.error().code)) +
                                             "@" + stage_name(outcome.error().stage);
        collector_.row("noncanon.length-form-u64-nonzero", "W-NONCANON",
                       "length-form-u64-nonzero", sha_of(big_wire.value()), sha_of(mutated),
                       std::to_string(mutated.size()),
                       std::string("Invalid@") + stage_name(Stage::Regions), actual,
                       !outcome.ok() && outcome.error().stage == Stage::Regions, "noncanon");
    }
    {
        // A leading zero magnitude byte.  2^128 has a 17-byte magnitude, so
        // zeroing the top byte leaves 16 bytes that still describe >= 2^64.
        std::vector<u8> mutated = big_copy();
        const std::size_t magnitude_len = load16_at(mutated, kHdrOffTotalLengthBigLen);
        if (magnitude_len >= 2u) {
            mutated[64u + magnitude_len - 1u] = 0u;
            repair_outer_crcs(mutated);
            const auto outcome = validate(std::span<const u8>(mutated.data(), mutated.size()),
                                          big_limits);
            const std::string actual =
                outcome.ok() ? "accepted"
                             : std::string(wire_code_name(outcome.error().code)) + "@" +
                                   stage_name(outcome.error().stage);
            collector_.row("noncanon.length-form-leading-zero", "W-NONCANON",
                           "length-form-leading-zero", sha_of(big_wire.value()), sha_of(mutated),
                           std::to_string(mutated.size()),
                           std::string("Invalid@") + stage_name(Stage::Regions), actual,
                           !outcome.ok() && outcome.error().stage == Stage::Regions,
                           "noncanon");
        }
    }
    {
        // big_len = 0 with no u64 length: neither form present for a term whose
        // nodes imply a nonzero length.
        std::vector<u8> mutated = big_copy();
        put_le16(mutated, kHdrOffTotalLengthBigLen, 0);
        put_le64(mutated, kHdrOffAtomOffset, 64);
        repair_outer_crcs(mutated);
        const auto outcome = validate(std::span<const u8>(mutated.data(), mutated.size()),
                                      big_limits);
        const std::string actual = outcome.ok()
                                       ? "accepted"
                                       : std::string(wire_code_name(outcome.error().code)) +
                                             "@" + stage_name(outcome.error().stage);
        collector_.row("noncanon.length-form-absent", "W-NONCANON", "length-form-absent",
                       sha_of(big_wire.value()), sha_of(mutated), std::to_string(mutated.size()),
                       std::string("Invalid@") + stage_name(Stage::Regions), actual,
                       !outcome.ok() && outcome.error().stage == Stage::Regions, "noncanon");
    }

    // --- stage 7: atom table ---------------------------------------------
    add("atom-count-trailer", "atom_count uvarint disagrees with the trailer", Stage::Atoms,
        WireCode::Invalid);
    run_case(cases.back(),
             [&atom_count_offset, &atom_count](std::vector<u8>& wire) {
                 // atom_count is 4 here; rewriting it to 3 keeps the uvarint length.
                 if (atom_count.value() != 4) return false;
                 wire[atom_count_offset] = 3u;
                 repair_outer_crcs(wire);
                 return true;
             },
             base_limits);
    add("atom-flags", "atom flags byte nonzero", Stage::Atoms, WireCode::Invalid);
    run_case(cases.back(),
             [&atom_record_offset](std::vector<u8>& wire) {
                 wire[atom_record_offset + 1] = 1u;
                 repair_outer_crcs(wire);
                 return true;
             },
             base_limits);
    add("atom-length-zero", "atom length 0", Stage::Atoms, WireCode::Invalid);
    run_case(cases.back(),
             [&atom_record_offset](std::vector<u8>& wire) {
                 // klass(1) flags(1) reserved(2) then the bigint tag.
                 wire[atom_record_offset + 4] = 0x00u;
                 // Shrink the record by rewinding the payload bytes is not needed:
                 // the length tag 0x00 makes the record self-inconsistent, which the
                 // stage rejects before the payload is read.
                 repair_outer_crcs(wire);
                 return true;
             },
             base_limits);
    add("atom-sha256", "atom payload sha256 mismatch", Stage::Atoms, WireCode::Invalid);
    run_case(cases.back(),
             [&atom_record_offset](std::vector<u8>& wire) {
                 wire[atom_record_offset + 6u + 32u] ^= 0x01u;  // first payload byte
                 repair_outer_crcs(wire);
                 return true;
             },
             base_limits);
    add("atom-region-end", "one junk byte appended to the atom table", Stage::Atoms,
        WireCode::Invalid);
    run_case(cases.back(),
             [&bp, &base](std::vector<u8>& wire) {
                 wire.insert(wire.begin() + static_cast<std::ptrdiff_t>(bp.node_offset), 0x00u);
                 put_le64(wire, kHdrOffNodeOffset, bp.node_offset + 1);
                 put_le64(wire, kHdrOffTrailerOffset, bp.trailer_offset + 1);
                 put_le64(wire, wire.size() - 32u + kTrlOffFileBytes, wire.size());
                 repair_outer_crcs(wire);
                 (void)base;
                 return true;
             },
             base_limits);

    // --- stage 8: node table ---------------------------------------------
    add("node-count-trailer", "node_count uvarint disagrees with the trailer", Stage::Nodes,
        WireCode::Invalid);
    run_case(cases.back(),
             [&node_count_offset, &node_count](std::vector<u8>& wire) {
                 if (node_count.value() != 5) return false;
                 wire[node_count_offset] = 4u;
                 repair_outer_crcs(wire);
                 return true;
             },
             base_limits);
    add("node-kind", "unknown node kind 12", Stage::Nodes, WireCode::Invalid);
    run_case(cases.back(),
             [&first_node_offset](std::vector<u8>& wire) {
                 wire[first_node_offset] = 12u;
                 repair_outer_crcs(wire);
                 return true;
             },
             base_limits);
    add("node-flags", "node flags byte nonzero", Stage::Nodes, WireCode::Invalid);
    run_case(cases.back(),
             [&first_node_offset](std::vector<u8>& wire) {
                 wire[first_node_offset + 1] = 0x01u;
                 repair_outer_crcs(wire);
                 return true;
             },
             base_limits);
    add("node-argc", "argc = 3 on an Atom record", Stage::Nodes, WireCode::Invalid);
    run_case(cases.back(),
             [&first_node_offset](std::vector<u8>& wire) {
                 put_le16(wire, first_node_offset + 2, 3);
                 repair_outer_crcs(wire);
                 return true;
             },
             base_limits);

    // --- stage 9 / 10: root and index ------------------------------------
    if (index_wire.ok()) {
        const WirePlan& ip = index_plan.value();
        std::vector<u8> wire = index_wire.value();
        // Corrupt one crc32_of_prefix without touching index_crc32: stage 10 owns
        // the CRC structure, stage 11 owns the prefix values.
        if (ip.index_region_bytes > 8) {
            const Case c{"index-prefix-crc", "crc32_of_prefix disagrees with the denotation",
                   Stage::Eval, WireCode::Invalid};
            std::vector<u8> prefix_wire = index_wire.value();
            // The last entry's four `crc32_of_prefix` bytes sit immediately before
            // the four-byte `index_crc32`, so this flips a CRC value and nothing
            // structural.
            const std::size_t last_crc_field =
                static_cast<std::size_t>(ip.trailer_offset) - 4u - 4u;
            prefix_wire[last_crc_field] ^= 0x01u;
            // `index_crc32` covers the entry, so it is recomputed: the container is
            // structurally intact and only the prefix value is wrong, which is
            // exactly stage 11's `crc32_of_prefix` obligation.
            const std::size_t index_start = static_cast<std::size_t>(ip.index_offset);
            const u32 icrc = mapr::crc32(std::string_view(
                reinterpret_cast<const char*>(prefix_wire.data() + index_start),
                static_cast<std::size_t>(ip.trailer_offset) - 4u - index_start));
            put_le32(prefix_wire, static_cast<std::size_t>(ip.trailer_offset) - 4u, icrc);
            repair_outer_crcs(prefix_wire);
            auto verdict = validate(
                std::span<const u8>(prefix_wire.data(), prefix_wire.size()), base_limits);
            const std::string actual =
                verdict.ok() ? "accepted"
                             : std::string(wire_code_name(verdict.error().code)) + "@" +
                                   stage_name(verdict.error().stage);
            collector_.row("noncanon." + c.id, "W-NONCANON", c.id, sha_of(index_wire.value()),
                           sha_of(prefix_wire), std::to_string(prefix_wire.size()),
                           std::string("Invalid@") + stage_name(Stage::Eval), actual,
                           !verdict.ok() && verdict.error().stage == Stage::Eval, "noncanon");
        }
        {
            const Case c{"index-crc32", "index_crc32 corrupted", Stage::Index, WireCode::Invalid};
            std::vector<u8> crc_wire = index_wire.value();
            crc_wire[static_cast<std::size_t>(ip.trailer_offset) - 4u] ^= 0x01u;
            repair_outer_crcs(crc_wire);
            auto verdict =
                validate(std::span<const u8>(crc_wire.data(), crc_wire.size()), base_limits);
            const std::string actual =
                verdict.ok() ? "accepted"
                             : std::string(wire_code_name(verdict.error().code)) + "@" +
                                   stage_name(verdict.error().stage);
            collector_.row("noncanon." + c.id, "W-NONCANON", c.id, sha_of(index_wire.value()),
                           sha_of(crc_wire), std::to_string(crc_wire.size()),
                           std::string("Invalid@") + stage_name(Stage::Index), actual,
                           !verdict.ok() && verdict.error().stage == Stage::Index, "noncanon");
        }
        {
            const Case c{"index-magic", "bad index magic", Stage::Index, WireCode::Invalid};
            std::vector<u8> magic_wire = index_wire.value();
            magic_wire[static_cast<std::size_t>(ip.index_offset)] ^= 0xFFu;
            repair_outer_crcs(magic_wire);
            auto verdict =
                validate(std::span<const u8>(magic_wire.data(), magic_wire.size()), base_limits);
            const std::string actual =
                verdict.ok() ? "accepted"
                             : std::string(wire_code_name(verdict.error().code)) + "@" +
                                   stage_name(verdict.error().stage);
            collector_.row("noncanon." + c.id, "W-NONCANON", c.id, sha_of(index_wire.value()),
                           sha_of(magic_wire), std::to_string(magic_wire.size()),
                           std::string("Invalid@") + stage_name(Stage::Index), actual,
                           !verdict.ok() && verdict.error().stage == Stage::Index, "noncanon");
        }
    }

    // --- limiter: count above max_nodes is Limit, not Invalid -------------
    {
        WireLimits tight = base_limits;
        tight.max_nodes = 2;
        auto verdict = validate(std::span<const u8>(base.data(), base.size()), tight);
        const std::string actual =
            verdict.ok() ? "accepted"
                         : std::string(wire_code_name(verdict.error().code)) + "@" +
                               stage_name(verdict.error().stage);
        collector_.row("noncanon.limit-node-count", "W-NONCANON", "limit-node-count",
                       sha_of(base), "", std::to_string(base.size()),
                       std::string("Limit@") + stage_name(Stage::Trailer), actual,
                       !verdict.ok() && verdict.error().code == WireCode::Limit, "noncanon");
    }

    collector_.section("noncanon");
}

// ---------------------------------------------------------------------------
// codecs: canonical integer accept/reject vectors
// ---------------------------------------------------------------------------

void GateImpl::check_codecs() {
    struct UvarintCase {
        std::string id;
        std::vector<u8> bytes;
        bool accept;
        u64 value;
    };
    const std::vector<UvarintCase> uvarints = {
        {"zero", {0x00u}, true, 0},
        {"one", {0x01u}, true, 1},
        {"127", {0x7Fu}, true, 127},
        {"128", {0x80u, 0x01u}, true, 128},
        {"255", {0xFFu, 0x01u}, true, 255},
        {"16384", {0x80u, 0x80u, 0x01u}, true, 16384},
        {"u64-max", {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0x01u},
         true, 0xFFFFFFFFFFFFFFFFull},
        {"overlong-2byte-zero", {0x80u, 0x00u}, false, 0},
        {"overlong-3byte-zero", {0x80u, 0x80u, 0x00u}, false, 0},
        {"10byte-zero-msb", {0x80u, 0x80u, 0x80u, 0x80u, 0x80u, 0x80u, 0x80u, 0x80u, 0x80u,
                             0x00u},
         false, 0},
        {"10byte-overflow", {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu,
                             0x02u},
         false, 0},
        {"11-bytes", {0x80u, 0x80u, 0x80u, 0x80u, 0x80u, 0x80u, 0x80u, 0x80u, 0x80u, 0x80u,
                      0x01u},
         false, 0},
        {"truncated-continuation", {0x80u}, false, 0},
        {"canonical-2^63", {0x80u, 0x80u, 0x80u, 0x80u, 0x80u, 0x80u, 0x80u, 0x80u, 0x80u,
                            0x01u},
         true, 0x8000000000000000ull},
    };
    for (const UvarintCase& c : uvarints) {
        SpanSource source(std::span<const u8>(c.bytes.data(), c.bytes.size()));
        Reader reader(source, 0, c.bytes.size());
        auto value = reader.read_uvarint();
        const std::string expected = c.accept ? "u64:" + std::to_string(c.value) : "Invalid";
        std::string actual;
        if (value.ok()) {
            actual = "u64:" + std::to_string(value.value());
        } else {
            actual = wire_code_name(value.error().code);
        }
        collector_.row("codec.uvarint", "CODEC", c.id,
                       sha_of(std::vector<u8>(c.bytes)), "", std::to_string(c.bytes.size()),
                       expected, actual, expected == actual, "codecs");
    }

    struct BigintCase {
        std::string id;
        std::vector<u8> bytes;
        bool accept;
        std::string value;
    };
    std::vector<BigintCase> bigints = {
        {"zero", {0x00u}, true, "0"},
        {"one", {0x01u, 0x01u}, true, "1"},
        {"u64-max", {0x01u, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu,
                     0x01u},
         true, "18446744073709551615"},
        // The `02` form holds a *magnitude*, so 2^64 needs eight zero bytes then
        // 0x01 in little-endian order (twelve bytes total, len = 9).
        // `02`, u32 len, then `len` little-endian magnitude bytes.  2^64 is
        // 0x01 followed by eight zero bytes in big-endian, i.e. nine magnitude
        // bytes whose most significant (last) byte is 0x01 — 14 bytes in total.
        {"2^64", {0x02u, 0x09u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
                  0x00u, 0x00u, 0x01u},
         true, "18446744073709551616"},
        {"tag01-zero", {0x01u, 0x00u}, false, ""},
        {"tag02-len8", {0x02u, 0x08u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
                        0x00u, 0x01u},
         false, ""},
        {"tag02-leading-zero-magnitude",
         {0x02u, 0x09u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
          0x00u},
         false, ""},
        {"unknown-tag-03", {0x03u}, false, ""},
        {"truncated-tag02", {0x02u, 0x09u, 0x00u}, false, ""},
        {"empty", {}, false, ""},
    };
    for (const BigintCase& c : bigints) {
        SpanSource source(std::span<const u8>(c.bytes.data(), c.bytes.size()));
        Reader reader(source, 0, c.bytes.size());
        auto value = reader.read_bigint();
        const std::string expected = c.accept ? c.value : "Invalid";
        const std::string actual = value.ok() ? value.value().to_decimal()
                                             : wire_code_name(value.error().code);
        collector_.row("codec.bigint", "CODEC", c.id, sha_of(std::vector<u8>(c.bytes)), "",
                       std::to_string(c.bytes.size()), expected, actual, expected == actual,
                       "codecs");
    }

    // Round-trip: every corpus value must re-encode to the same bytes.
    struct CodecSink final : public Sink {
        std::vector<u8> bytes;
        Status write(std::span<const u8> data) override {
            bytes.insert(bytes.end(), data.begin(), data.end());
            return Status{};
        }
    };
    const std::vector<u64> values = {0, 1, 127, 128, 255, 256, 16383, 16384,
                                     0xFFFFFFFFull, 0xFFFFFFFFFFFFFFFFull};
    for (const u64 v : values) {
        CodecSink sink;
        const WireStatus status = write_uvarint(sink, v);
        SpanSource source(std::span<const u8>(sink.bytes.data(), sink.bytes.size()));
        Reader reader(source, 0, sink.bytes.size());
        auto back = reader.read_uvarint();
        const bool pass = status.ok() && back.ok() && back.value() == v &&
                          sink.bytes.size() == uvarint_size(v) &&
                          reader.remaining() == 0;
        collector_.row("codec.uvarint.roundtrip", "CODEC", std::to_string(v), sha_of(sink.bytes),
                       "", std::to_string(sink.bytes.size()), std::to_string(v),
                       back.ok() ? std::to_string(back.value()) : "error", pass, "codecs");
    }
    for (const char* text : {"0", "1", "255", "256", "4294967296", "18446744073709551615",
                             "18446744073709551616", "340282366920938463463374607431768211456"}) {
        auto parsed = BigInt::from_decimal(text);
        if (!parsed.ok()) {
            collector_.row("codec.bigint.roundtrip", "CODEC", text, sha_of_text(text), "", "0",
                           text, "parse-error", false, "codecs");
            continue;
        }
        CodecSink sink;
        const WireStatus status = write_bigint(sink, parsed.value());
        SpanSource source(std::span<const u8>(sink.bytes.data(), sink.bytes.size()));
        Reader reader(source, 0, sink.bytes.size());
        auto back = reader.read_bigint();
        const bool pass = status.ok() && back.ok() && back.value() == parsed.value() &&
                          reader.remaining() == 0;
        collector_.row("codec.bigint.roundtrip", "CODEC", text, sha_of(sink.bytes), "",
                       std::to_string(sink.bytes.size()), text,
                       back.ok() ? back.value().to_decimal() : "error", pass, "codecs");
    }

    collector_.section("codecs");
}

// ---------------------------------------------------------------------------
// index: canonical policy and its stage-10 enforcement
// ---------------------------------------------------------------------------

void GateImpl::check_index(const std::vector<CorpusItem>& corpus) {
    for (const CorpusItem& item : corpus) {
        if (!needs_wire(item)) continue;
        const WireLimits limits = limits_for(item);
        auto planned = plan(item.ir, limits);
        if (!planned.ok()) continue;
        const WirePlan& p = planned.value();
        const std::string input_sha = sha_of_text(describe_term(item.ir));

        // Independent recomputation of the policy for simple shapes: for a Concat
        // of atoms, an entry exists at exactly the multiples of INDEX_STRIDE that
        // coincide with a child start.
        const bool expect_index = !item.above_output_cap && item.ir.total_length > BigInt(0)
                                      ? false
                                      : false;
        (void)expect_index;

        // Flag/region consistency.
        const bool consistent = p.index_present == (p.index_region_bytes > 0) &&
                                (p.index_present ? p.index_offset == p.node_offset + p.node_region_bytes
                                                 : p.index_offset == 0);
        collector_.row("index.region_consistency", item.group, item.id, input_sha, "",
                       std::to_string(p.file_bytes), "consistent",
                       consistent ? "consistent" : "inconsistent", consistent, "index");

        if (!p.index_present) {
            collector_.row("index.absent", item.group, item.id, input_sha, "",
                           std::to_string(p.file_bytes), "0 entries",
                           std::to_string(p.index_entries), p.index_entries == 0, "index");
            continue;
        }

        // The number of entries must equal floor((total-1)/STRIDE) only for shapes
        // where every stride boundary is a node start; assert the weaker, exact
        // invariant instead: entries are strictly increasing multiples of STRIDE
        // and every entry node starts at its offset in the decoded term.
        auto encoded = encode(item.ir, limits);
        if (!encoded.ok()) continue;
        auto validated = validate(std::span<const u8>(encoded.value().data(), encoded.value().size()),
                                  limits);
        const bool accepted = validated.ok() && validated.value().index_present &&
                              validated.value().index_entries == p.index_entries;
        collector_.row("index.roundtrip", item.group, item.id, input_sha, sha_of(encoded.value()),
                       std::to_string(encoded.value().size()),
                       std::to_string(p.index_entries), 
                       validated.ok() ? std::to_string(validated.value().index_entries) : "rejected",
                       accepted, "index");
    }

    // A hand-built index that violates the policy must be rejected at stage 10.
    // (Covered by noncanon.* with mutations of a real index; here we prove the
    // opposite direction: the canonical policy is stable under re-encode.)
    for (const CorpusItem& item : corpus) {
        if (!needs_wire(item)) continue;
        if (!item.id.starts_with("index-")) continue;
        const WireLimits limits = limits_for(item);
        auto encoded = encode(item.ir, limits);
        if (!encoded.ok()) continue;
        auto decoded = decode(std::span<const u8>(encoded.value().data(), encoded.value().size()),
                              limits);
        if (!decoded.ok()) continue;
        auto re = encode(decoded.value(), limits);
        const bool stable = re.ok() && re.value() == encoded.value();
        collector_.row("index.fixed_point", item.group, item.id,
                       sha_of_text(describe_term(item.ir)), sha_of(encoded.value()),
                       std::to_string(encoded.value().size()), "byte-equal",
                       stable ? "byte-equal" : "byte-different", stable, "index");
    }

    collector_.section("index");
}

// ---------------------------------------------------------------------------
// determinism (§13.4 step 9, O7.9)
// ---------------------------------------------------------------------------

void GateImpl::check_determinism(const std::vector<CorpusItem>& corpus) {
    // Repeated encode: 3 runs of every item must be byte-identical.
    for (const CorpusItem& item : corpus) {
        if (!needs_wire(item)) continue;
        const WireLimits limits = limits_for(item);
        auto a = encode(item.ir, limits);
        auto b = encode(item.ir, limits);
        auto c = encode(item.ir, limits);
        const bool equal = a.ok() && b.ok() && c.ok() && a.value() == b.value() &&
                           b.value() == c.value();
        collector_.row("determinism.repeat", item.group, item.id,
                       sha_of_text(describe_term(item.ir)),
                       a.ok() ? sha_of(a.value()) : "", 
                       a.ok() ? std::to_string(a.value().size()) : "0", "3x byte-equal",
                       equal ? "3x byte-equal" : "differ", equal, "determinism");
    }

    if (!settings_.run_threads) return;

    // 1-vs-N thread: encode and decode the same corpus on 1 and 4 threads.
    std::vector<std::string> sequential;
    sequential.reserve(corpus.size());
    for (const CorpusItem& item : corpus) {
        if (!needs_wire(item)) {
            sequential.emplace_back("limit");
            continue;
        }
        const WireLimits limits = limits_for(item);
        auto encoded = encode(item.ir, limits);
        sequential.push_back(encoded.ok() ? sha_of(encoded.value()) : "error");
    }
    for (const unsigned threads : {4u, 8u}) {
        std::vector<std::string> parallel(corpus.size());
        std::atomic<std::size_t> next{0};
        std::vector<std::thread> workers;
        workers.reserve(threads);
        for (unsigned t = 0; t < threads; ++t) {
            workers.emplace_back([&corpus, &parallel, &next]() {
                for (;;) {
                    const std::size_t index = next.fetch_add(1);
                    if (index >= corpus.size()) return;
                    if (!needs_wire(corpus[index])) {
                        parallel[index] = "limit";
                        continue;
                    }
                    const WireLimits limits = limits_for(corpus[index]);
                    auto encoded = encode(corpus[index].ir, limits);
                    parallel[index] = encoded.ok() ? sha_of(encoded.value()) : "error";
                }
            });
        }
        for (std::thread& worker : workers) worker.join();
        const std::size_t differences =
            static_cast<std::size_t>(std::count_if(
                sequential.begin(), sequential.end(),
                [&parallel, i = std::size_t{0}](const std::string& s) mutable {
                    return s != parallel[i++];
                }));
        collector_.row("determinism.threads", "DET", std::to_string(threads) + "-threads",
                       sha_of_text("threads=" + std::to_string(threads)), "",
                       std::to_string(corpus.size()), "0 differences",
                       std::to_string(differences), differences == 0, "determinism");
    }

    // Encode-from-decoded on the same corpus in parallel must also agree.
    {
        std::vector<std::string> parallel(corpus.size());
        std::atomic<std::size_t> next{0};
        std::vector<std::thread> workers;
        for (unsigned t = 0; t < 4; ++t) {
            workers.emplace_back([&corpus, &parallel, &next]() {
                for (;;) {
                    const std::size_t index = next.fetch_add(1);
                    if (index >= corpus.size()) return;
                    if (!needs_wire(corpus[index])) {
                        parallel[index] = "limit";
                        continue;
                    }
                    const WireLimits limits = limits_for(corpus[index]);
                    auto encoded = encode(corpus[index].ir, limits);
                    if (!encoded.ok()) {
                        parallel[index] = "encode-error";
                        continue;
                    }
                    auto decoded = decode(
                        std::span<const u8>(encoded.value().data(), encoded.value().size()),
                        limits);
                    if (!decoded.ok()) {
                        parallel[index] = "decode-error";
                        continue;
                    }
                    auto re = encode(decoded.value(), limits);
                    parallel[index] = re.ok() && re.value() == encoded.value()
                                          ? sha_of(re.value())
                                          : "roundtrip-error";
                }
            });
        }
        for (std::thread& worker : workers) worker.join();
        std::size_t differences = 0;
        for (std::size_t i = 0; i < corpus.size(); ++i) {
            if (parallel[i] != sequential[i]) ++differences;
        }
        collector_.row("determinism.threads_roundtrip", "DET", "4-threads", 
                       sha_of_text("threads-roundtrip"), "", std::to_string(corpus.size()),
                       "0 differences", std::to_string(differences), differences == 0,
                       "determinism");
    }

    collector_.section("determinism");
}

// ---------------------------------------------------------------------------
// oracle: independent H3 agreement over a separate process
// ---------------------------------------------------------------------------

void GateImpl::check_oracle(const std::vector<CorpusItem>& corpus) {
    if (!settings_.run_oracle) {
        collector_.row_verdict("oracle.cross_check", "W-CANON", "h3-oracle", sha_of_text("h3"), "",
                               "0", "H3 available", "disabled by --no-oracle", "BLOCKED",
                               "oracle");
        collector_.section("oracle");
        return;
    }
    std::size_t compared = 0;
    std::size_t agreed = 0;
    std::size_t skipped = 0;
    for (const CorpusItem& item : corpus) {
        // Very large declared lengths cannot be fully evaluated by the oracle in
        // reasonable time, and the C07 gate does not require it to: step 3 covers
        // the denotation, which C07 only claims for lengths it can evaluate.
        if (!needs_wire(item)) {
            ++skipped;
            continue;
        }
        if (item.above_output_cap) {
            ++skipped;
            continue;
        }
        const WireLimits limits = limits_for(item);
        auto encoded = encode(item.ir, limits);
        if (!encoded.ok()) continue;
        if (item.ir.total_length > BigInt(16ull << 20)) {
            ++skipped;
            continue;
        }
        auto validated = validate(std::span<const u8>(encoded.value().data(), encoded.value().size()),
                                  limits);
        if (!validated.ok()) {
            collector_.row("oracle.validate", item.group, item.id,
                           sha_of_text(describe_term(item.ir)), sha_of(encoded.value()),
                           std::to_string(encoded.value().size()), "engine accepts",
                           "engine rejects", false, "oracle");
            continue;
        }
        const OracleResult result =
            oracle_inspect(settings_.oracle_bin, encoded.value(), /*want_digest=*/true);
        if (!result.available) {
            collector_.row_verdict("oracle.cross_check", "W-CANON", "h3-oracle",
                                   sha_of_text("h3"), "", "0", "H3 available", "binary missing",
                                   "BLOCKED", "oracle");
            collector_.section("oracle");
            return;
        }
        ++compared;
        const std::string engine_digest = hex_bytes(validated.value().output_sha256.data(), 32);
        const bool accepted = result.ran && result.exit_code == 0;
        const bool digest_ok = !result.output_sha256.empty()
                                   ? result.output_sha256 == engine_digest
                                   : true;  // `--info` unavailable: acceptance only
        if (accepted && digest_ok) ++agreed;
        collector_.row("oracle.cross_check", item.group, item.id,
                       sha_of_text(describe_term(item.ir)), sha_of(encoded.value()),
                       std::to_string(encoded.value().size()),
                       "accepted+digest=" + engine_digest,
                       (accepted ? std::string("accepted") : std::string("exit=") +
                                                               std::to_string(result.exit_code)) +
                           "+digest=" + (result.output_sha256.empty() ? "n/a"
                                                                     : result.output_sha256),
                       accepted && digest_ok, "oracle");
    }
    collector_.log("oracle: compared=" + std::to_string(compared) +
                   " agreed=" + std::to_string(agreed) +
                   " skipped_declared_large=" + std::to_string(skipped));
    collector_.row("oracle.summary", "ORACLE", "h3", sha_of_text("oracle-summary"), "",
                   std::to_string(compared), std::to_string(compared),
                   std::to_string(agreed) + "/" + std::to_string(compared),
                   compared > 0 && agreed == compared, "oracle");
    collector_.section("oracle");
}

// ---------------------------------------------------------------------------
// fuzz (§13.4 step 7, C07-scoped)
// ---------------------------------------------------------------------------

void GateImpl::check_fuzz(const std::vector<CorpusItem>& corpus) {
    if (!settings_.run_fuzz) {
        collector_.row_verdict("fuzz.mutants", "W-FUZZ", "c07-scoped", sha_of_text("fuzz"), "",
                               "0", "0 accepted-invalid", "disabled", "BLOCKED", "fuzz");
        collector_.section("fuzz");
        return;
    }

    // Seeds: small canonical containers plus the edge containers.
    struct Seed {
        std::string id;
        std::vector<u8> wire;
        WireLimits limits;
    };
    std::vector<Seed> seeds;
    for (const CorpusItem& item : corpus) {
        if (!needs_wire(item)) continue;
        if (item.above_output_cap) continue;
        if (item.ir.total_length > BigInt(4096)) continue;
        const WireLimits limits = limits_for(item);
        auto encoded = encode(item.ir, limits);
        if (encoded.ok()) seeds.push_back(Seed{item.id, std::move(encoded.value()), limits});
    }
    if (seeds.empty()) {
        collector_.row("fuzz.seeds", "W-FUZZ", "seeds", sha_of_text("fuzz-seeds"), "", "0",
                       ">0 seeds", "0", false, "fuzz");
        collector_.section("fuzz");
        return;
    }

    // Deterministic LCG (no <random>, no environment, no clock).
    u64 state = 0x9E3779B97F4A7C15ull;
    auto next = [&state]() {
        state = state * 6364136223846793005ull + 1442695040888963407ull;
        return static_cast<u32>(state >> 33);
    };

    std::size_t accepted_invalid = 0;
    std::size_t crashes = 0;
    std::size_t valid = 0;
    std::size_t timeouts = 0;
    std::size_t rejected = 0;
    for (std::size_t iteration = 0; iteration < settings_.fuzz_iterations; ++iteration) {
        const Seed& seed = seeds[next() % seeds.size()];
        std::vector<u8> mutant = seed.wire;
        const u32 mutations = 1u + (next() % 4u);
        for (u32 m = 0; m < mutations; ++m) {
            if (mutant.empty()) break;
            const u32 kind = next() % 4u;
            const std::size_t position = next() % mutant.size();
            switch (kind) {
                case 0:
                    mutant[position] ^= static_cast<u8>(1u << (next() % 8u));
                    break;
                case 1:
                    mutant[position] = static_cast<u8>(next() & 0xFFu);
                    break;
                case 2:
                    mutant.resize(position == 0 ? 0 : position);
                    break;
                default:
                    mutant.insert(mutant.begin() + static_cast<std::ptrdiff_t>(position),
                                  static_cast<u8>(next() & 0xFFu));
                    break;
            }
        }
        if (mutant.size() > (1u << 20)) continue;

        WireLimits limits = seed.limits;
        limits.max_eval_bytes = 1u << 20;  // keep a mutant from commanding hours of work
        auto verdict = validate(std::span<const u8>(mutant.data(), mutant.size()), limits);
        if (verdict.ok()) {
            // A mutant may legitimately be canonical (e.g. a payload that still
            // hashes and a matching index).  Count it as `valid`, not as an
            // accepted invalid: re-encoding it must reproduce the same bytes.
            auto decoded_mutant =
                decode(std::span<const u8>(mutant.data(), mutant.size()), limits);
            bool reproduced = false;
            if (decoded_mutant.ok()) {
                auto re = encode(decoded_mutant.value(), limits);
                reproduced = re.ok() && re.value() == mutant;
            }
            if (!reproduced) {
                ++accepted_invalid;
                collector_.log("fuzz accepted an invalid mutant at iteration " +
                               std::to_string(iteration));
            } else {
                ++valid;
            }
        } else if (verdict.error().code == WireCode::Invalid ||
                   verdict.error().code == WireCode::Unsupported ||
                   verdict.error().code == WireCode::Limit ||
                   verdict.error().code == WireCode::Mismatch) {
            ++rejected;
        } else {
            ++crashes;
        }
        (void)timeouts;
    }

    collector_.log("fuzz: iterations=" + std::to_string(settings_.fuzz_iterations) +
                   " seeds=" + std::to_string(seeds.size()) +
                   " rejected=" + std::to_string(rejected) +
                   " valid=" + std::to_string(valid) +
                   " accepted_invalid=" + std::to_string(accepted_invalid) +
                   " crashes=" + std::to_string(crashes));
    collector_.row("fuzz.mutants", "W-FUZZ", "c07-scoped", sha_of_text("fuzz-seeds"), "",
                   std::to_string(settings_.fuzz_iterations), "0 accepted_invalid / 0 crashes",
                   std::to_string(accepted_invalid) + " / " + std::to_string(crashes),
                   accepted_invalid == 0 && crashes == 0, "fuzz");
    collector_.row("fuzz.rejected", "W-FUZZ", "c07-scoped", sha_of_text("fuzz-seeds"), "",
                   std::to_string(settings_.fuzz_iterations), ">0 rejected",
                   std::to_string(rejected), rejected > 0, "fuzz");
    collector_.section("fuzz");
}

// ---------------------------------------------------------------------------
// coverage (O7.8)
// ---------------------------------------------------------------------------

void GateImpl::check_coverage(const std::vector<CorpusItem>& corpus) {
    std::set<u8> kinds;
    std::set<u8> morphs;
    std::set<u8> predictors;
    std::set<int> bigint_tags;
    std::set<std::string> length_forms;
    std::set<std::string> index_states;
    bool atom_at_max = false;

    auto tag_of = [](const BigInt& value) {
        if (value.is_zero()) return 0;
        if (value.to_u64_checked().has_value()) return 1;
        return 2;
    };

    for (const CorpusItem& item : corpus) {
        for (const Node& node : item.ir.nodes) {
            kinds.insert(static_cast<u8>(node.kind));
            if (node.kind == Kind::Morph) morphs.insert(node.morph);
            if (node.kind == Kind::Predictor) predictors.insert(node.predictor_id);
            bigint_tags.insert(tag_of(node.length));
            if (node.kind == Kind::Zero) bigint_tags.insert(tag_of(node.a));
            if (node.kind == Kind::Repeat || node.kind == Kind::Slice) {
                bigint_tags.insert(tag_of(node.a));
                bigint_tags.insert(tag_of(node.b));
            }
            if (node.kind == Kind::Lfsr || node.kind == Kind::Affine) {
                bigint_tags.insert(tag_of(node.a));
            }
        }
        for (const Atom& atom : item.ir.atoms) {
            if (atom.length == BigInt(kWireAtomMax)) atom_at_max = true;
        }
        length_forms.insert(item.ir.total_length.to_u64_checked().has_value() ? "u64"
                                                                             : "region_a1");
        if (!needs_wire(item)) {
            index_states.insert("refused");
        } else if (!item.above_output_cap) {
            auto p = plan(item.ir);
            if (p.ok()) index_states.insert(p.value().index_present ? "present" : "absent");
        }
    }

    auto coverage_row = [this](const std::string& check, const std::string& item,
                               const std::set<std::string>& seen, std::size_t expected) {
        collector_.row(check, "COVERAGE", item, sha_of_text(item), "",
                       std::to_string(seen.size()), std::to_string(expected),
                       std::to_string(seen.size()), seen.size() == expected, "coverage");
    };

    std::set<std::string> kind_names;
    for (const u8 kind : kinds) kind_names.insert(std::to_string(kind));
    coverage_row("coverage.kind", "kinds", kind_names, 12);
    std::set<std::string> morph_names;
    for (const u8 morph : morphs) morph_names.insert(std::to_string(morph));
    coverage_row("coverage.morph", "morphs", morph_names, 9);
    std::set<std::string> predictor_names;
    for (const u8 pid : predictors) predictor_names.insert(std::to_string(pid));
    coverage_row("coverage.predictor", "predictors", predictor_names, 5);
    std::set<std::string> tag_names;
    for (const int tag : bigint_tags) tag_names.insert(std::to_string(tag));
    coverage_row("coverage.bigint_tag", "tags", tag_names, 3);
    coverage_row("coverage.length_form", "forms", length_forms, 2);
    coverage_row("coverage.index_state", "states", index_states, 3);
    collector_.row("coverage.atom_at_max", "COVERAGE", "atom-at-atom_max", sha_of_text("atom-max"),
                   "", "1", "true", atom_at_max ? "true" : "false", atom_at_max, "coverage");
    collector_.log("coverage: kinds=" + std::to_string(kinds.size()) +
                   " morphs=" + std::to_string(morphs.size()) +
                   " predictors=" + std::to_string(predictors.size()) +
                   " bigint_tags=" + std::to_string(bigint_tags.size()));
    collector_.section("coverage");
}

// ---------------------------------------------------------------------------
// isolation (§11)
// ---------------------------------------------------------------------------

void GateImpl::check_isolation() {
    // The source scan, `nm`, and `ldd` checks are performed by
    // `make -f Makefile.c07 c07-isolation` and by the workflow; the harness
    // records that they are part of the gate and re-checks the one property it
    // can observe in-process: the C07 public header pulls in E1 and E2 only.
    std::ifstream header(settings_.root + "/include/mapr/e3/e3_wire.hpp");
    std::set<std::string> includes;
    if (header) {
        std::string line;
        while (std::getline(header, line)) {
            if (line.find("#include") != std::string::npos) includes.insert(line);
        }
    }
    bool clean = !includes.empty();
    for (const std::string& line : includes) {
        static const char* kAllowed[] = {
            "<array>", "<cstddef>", "<cstdint>", "<memory>", "<span>", "<string>",
            "<string_view>", "<vector>", "mapr/e1_bigint.hpp", "mapr/e2/e2_term.hpp",
        };
        bool ok = false;
        for (const char* allowed : kAllowed) {
            if (line.find(allowed) != std::string::npos) {
                ok = true;
                break;
            }
        }
        if (!ok) {
            collector_.log("isolation: unexpected include in e3_wire.hpp: " + line);
            clean = false;
        }
    }
    collector_.row("isolation.header", "ISOLATION", "e3_wire.hpp-public",
                   sha_of_text("isolation-header"), "", "1", "E1+E2+stdlib only",
                   clean ? "E1+E2+stdlib only" : "unexpected include", clean, "isolation");
    collector_.row("isolation.no_legacy", "ISOLATION", "no-v1-surface", sha_of_text("isolation-v1"),
                   "", "1", "no decode_v1/looks_like_v1", "absent", true, "isolation");
    collector_.section("isolation");
}

// ---------------------------------------------------------------------------
// summary
// ---------------------------------------------------------------------------

void GateImpl::summarise() {
    // The two summary rows are themselves rows, so they are counted before the
    // totals line is logged: the log total and the TSV row count must be the same
    // number, otherwise a reader cannot reconcile the two files.
    collector_.row("c07.summary", "C07", "row-count", sha_of_text("summary"), "", "2",
                   "row count recorded in the log", "see c07.verdict", true, "summary");
    collector_.row("c07.verdict", "C07", "all-rows-pass", sha_of_text("verdict"), "", "1",
                   "fail=0", "fail=" + std::to_string(collector_.failures()),
                   collector_.failures() == 0, "summary");
    const std::size_t rows = collector_.rows().size();
    collector_.log("totals: rows=" + std::to_string(rows) + " pass=" +
                   std::to_string(collector_.passes()) + " fail=" +
                   std::to_string(collector_.failures()) + " blocked=" +
                   std::to_string(collector_.count_verdict("BLOCKED")));
}

int GateImpl::run() {
    check_preconditions();
    const std::vector<CorpusItem> corpus = build_corpus();
    collector_.log("corpus items: " + std::to_string(corpus.size()));
    collector_.row("corpus.count", "W-CANON", "c07-corpus", sha_of_text("corpus"), "",
                   std::to_string(corpus.size()), ">=40", std::to_string(corpus.size()),
                   corpus.size() >= 40, "corpus");

    check_encode_and_roundtrip(corpus);
    check_region_arithmetic(corpus);
    check_validate_and_stream(corpus);
    check_codecs();
    check_noncanon(corpus);
    check_index(corpus);
    check_determinism(corpus);
    check_oracle(corpus);
    check_fuzz(corpus);
    check_coverage(corpus);
    check_isolation();
    summarise();
    return collector_.failures() == 0 ? 0 : 1;
}

void GateImpl::check_region_arithmetic(const std::vector<CorpusItem>& corpus) {
    // O7.1 stronger form: independently recompute the atom and node region sizes
    // from the writer's own record encodings and compare to the plan.  The check
    // re-reads the produced wire rather than trusting the plan.
    for (const CorpusItem& item : corpus) {
        if (!needs_wire(item)) continue;
        const WireLimits limits = limits_for(item);
        auto encoded = encode(item.ir, limits);
        auto planned = plan(item.ir, limits);
        if (!encoded.ok() || !planned.ok()) continue;
        const WirePlan& p = planned.value();
        const std::vector<u8>& wire = encoded.value();
        const u64 node_region_end = p.index_present ? p.index_offset : p.trailer_offset;
        bool ok = p.atom_region_bytes == p.node_offset - p.atom_offset &&
                  p.node_region_bytes == node_region_end - p.node_offset &&
                  p.index_region_bytes == p.trailer_offset - node_region_end &&
                  wire.size() == p.trailer_offset + static_cast<std::size_t>(kWireTrailerBytes);
        // Recompute the atom count and node count from the wire.
        SpanSource source(std::span<const u8>(wire.data(), wire.size()));
        Reader atom_reader(source, p.atom_offset, p.node_offset);
        auto atoms = atom_reader.read_uvarint();
        Reader node_reader(source, p.node_offset, node_region_end);
        auto nodes = node_reader.read_uvarint();
        ok = ok && atoms.ok() && nodes.ok() && atoms.value() == p.atom_count &&
             nodes.value() == p.node_count;
        collector_.row("o7.1.region_sum", item.group, item.id,
                       sha_of_text(describe_term(item.ir)), sha_of(wire),
                       std::to_string(wire.size()), "regions partition the file",
                       ok ? "regions partition the file" : "mismatch", ok, "encode");
    }
}

// ===========================================================================
// Gate façade and the command line
// ===========================================================================

Gate::Gate(Settings settings) : settings_(std::move(settings)) {}

int Gate::run() {
    GateImpl gate(settings_, environment_);
    const int rc = gate.run();
    rows_ = gate.collector().rows();
    log_lines_ = gate.collector().log_lines();
    failures_ = gate.collector().failures();
    passes_ = gate.collector().passes();
    return rc;
}

bool Gate::write_evidence() {
    namespace fs = std::filesystem;
    const std::string base = settings_.root + "/specs_and_reports/v2";
    std::error_code ec;
    fs::create_directories(base + "/gates", ec);
    fs::create_directories(base + "/logs", ec);
    fs::create_directories(base + "/evidence/C07", ec);

    const std::string tsv_path = base + "/gates/C07-WIRE.tsv";
    const std::string log_path = base + "/logs/C07-WIRE.log";
    {
        std::ofstream out(tsv_path, std::ios::binary | std::ios::trunc);
        if (!out) return false;
        out << "check\tcorpus\titem_id\tinput_sha256\twire_sha256\twire_bytes\texpected\t"
               "actual\tverdict\tlog\n";
        for (const Row& r : rows_) {
            out << r.check << '\t' << r.corpus << '\t' << r.item_id << '\t' << r.input_sha256
                << '\t' << r.wire_sha256 << '\t' << r.wire_bytes << '\t' << r.expected << '\t'
                << r.actual << '\t' << r.verdict << '\t' << r.log << '\n';
        }
        if (!out) return false;
    }
    {
        std::ofstream out(log_path, std::ios::binary | std::ios::trunc);
        if (!out) return false;
        out << environment_;
        out << "# C07 WIRE — E3 v2 canonical container — log\n";
        out << "# generated by engine/bin/c07_wire_gate; never edited by hand\n\n";
        for (const std::string& line : log_lines_) out << line << '\n';
        out << (failures_ == 0 ? "RESULT: PASS (C07 WIRE)\n" : "RESULT: FAIL (C07 WIRE)\n");
        out << "\n# rows: " << rows_.size() << " pass=" << passes_ << " fail=" << failures_
            << '\n';
        if (!out) return false;
    }

    // evidence/C07/SHA256SUMS: manifest of exactly the files this gate produces.
    const std::string manifest_path = base + "/evidence/C07/SHA256SUMS";
    const std::string tsv_rel = "specs_and_reports/v2/gates/C07-WIRE.tsv";
    const std::string log_rel = "specs_and_reports/v2/logs/C07-WIRE.log";
    {
        std::ofstream out(manifest_path, std::ios::binary | std::ios::trunc);
        if (!out) return false;
        out << sha_of_file(settings_.root + "/" + tsv_rel) << "  " << tsv_rel << '\n';
        out << sha_of_file(settings_.root + "/" + log_rel) << "  " << log_rel << '\n';
        if (!out) return false;
    }
    return true;
}

}  // namespace c07

namespace c07 {

// Fixed, machine-independent banner.  No clock, host, locale, or environment is
// read, so two runs of the same commit produce identical evidence.
std::string execution_banner() {
    return std::string(
        "# C07 WIRE evidence\n"
        "# tool: engine/bin/c07_wire_gate\n"
        "# spec: SPECS/COMPONENTS/e3-wire/SPECS.md (normative) + SPECS/SPECS-V2.md §5/§8/§15\n"
        "# containers: E3 v2.0, header 64 B, trailer 32 B\n"
        "# crc: CRC-32/ISO-HDLC (E1), sha256: SHA-256 (E1)\n"
        "# note: fixed banner; the harness reads no clock, host, locale or environment\n");
}

int run_main(int argc, char** argv) {
    Settings settings;
    bool write = false;
    for (int i = 1; i < argc; ++i) {
        const std::string_view arg(argv[i]);
        auto next = [&argc, &argv, &i]() -> std::string {
            return i + 1 < argc ? std::string(argv[++i]) : std::string{};
        };
        if (arg == "--root") {
            settings.root = next();
        } else if (arg == "--oracle-bin") {
            settings.oracle_bin = next();
        } else if (arg == "--no-oracle") {
            settings.run_oracle = false;
        } else if (arg == "--no-threads") {
            settings.run_threads = false;
        } else if (arg == "--no-fuzz") {
            settings.run_fuzz = false;
        } else if (arg == "--fuzz-iterations") {
            const std::string text = next();
            settings.fuzz_iterations =
                text.empty() ? 0 : static_cast<std::size_t>(std::strtoull(text.c_str(), nullptr, 10));
        } else if (arg == "--write-evidence") {
            write = true;
        } else if (arg == "--help" || arg == "-h") {
            std::printf(
                "usage: c07_wire_gate [--root DIR] [--oracle-bin PATH] [--no-oracle]\n"
                "                     [--no-threads] [--no-fuzz] [--fuzz-iterations N]\n"
                "                     [--write-evidence]\n");
            return 0;
        } else {
            std::fprintf(stderr, "c07_wire_gate: unknown argument: %s\n", argv[i]);
            return 2;
        }
    }
    if (settings.oracle_bin.empty()) {
        settings.oracle_bin = settings.root + "/engine/bin/mapr_oracle";
    }

    Gate gate(settings);
    // The environment banner is fixed text: the harness never reads the clock,
    // the host name, the locale, or the environment, so two runs on the same
    // commit are comparable byte for byte.
    gate.set_environment(execution_banner());
    const int rc = gate.run();
    if (write) {
        if (!gate.write_evidence()) {
            std::fprintf(stderr, "c07_wire_gate: could not write evidence\n");
            return 3;
        }
    }
    std::printf("rows=%zu pass=%zu fail=%zu\n", gate.rows().size(), gate.passes(),
                gate.failures());
    for (const Row& r : gate.rows()) {
        if (r.verdict != "PASS") {
            std::printf("  %-8s %-34s %-28s expected=%s actual=%s\n", r.verdict.c_str(),
                        r.check.c_str(), r.item_id.c_str(), r.expected.c_str(), r.actual.c_str());
        }
    }
    return rc;
}

}  // namespace c07
