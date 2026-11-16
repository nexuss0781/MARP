// MARP v2 — H3 ORACLE — F00–F08 cross-check wire producer.
//
// This tool is the *E3 side* of the H3 `oracle.f00-f08` cross-check.  It is the
// only place in the H3 evidence path that touches the engine: it
//
//   1. takes the pinned F00–F08 fixtures from H1 FIXTURES
//      (`harness/src/fixtures.cpp`, the normative §12.3 generators),
//   2. re-identifies every fixture against the committed H1 manifest
//      (`specs_and_reports/v2/fixtures.tsv`) by streaming the generator and
//      re-hashing it (so a drifted generator cannot silently pass),
//   3. constructs the canonical E2 term that denotes the fixture bytes
//      (via the C03 `Builder`, which recomputes every length from structure),
//   4. canonicalises it with C04 `canon` and requires `check_canonical`,
//   5. emits the unique canonical v2 wire with C07 `encode` (and checks that a
//      second encode is byte-identical and that `encoded_size` agrees),
//   6. runs the full C07 §5.1 validation (stages 1–11) so that the engine's own
//      evaluation must reproduce the H1 fixture digest and length, and
//   7. writes the wire files plus a deterministic manifest for the clean-room
//      H3 oracle, which independently decodes/verifies them.
//
// It never claims anything about the oracle: all *decoding* evidence for
// `oracle.f00-f08` comes from `harness/oracle/**`.  Nothing under
// `harness/oracle/` includes or links this file, and `bin/mapr_oracle` is
// untouched by it.
//
// Usage:
//   bin/h3_f00f08_producer [--root <repo>] [--out <dir>] [--skip-identify]
//
// Outputs (all deterministic; no clock, host, or absolute path ever enters the
// manifest, so the committed evidence is host-independent):
//   <out>/wires/F00.wire … F08.wire
//   <out>/f00-f08-manifest.tsv
//   <out>/f00-f08-producer.log
//
// C++20 only.  No third-party dependency.  No Python.

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "mapr/e1_sha256.hpp"
#include "mapr/e2/e2_canon.hpp"
#include "mapr/e2/e2_term.hpp"
#include "mapr/e3/e3_wire.hpp"
#include "marp/harness/fixtures.hpp"

#include "e2/c03_build.hpp"

namespace {

namespace fs = std::filesystem;

using mapr::BigInt;
using namespace marp::v2;  // NOLINT
using marp::harness::GenerateOptions;
using marp::harness::ManifestRow;

constexpr const char* kManifestName = "f00-f08-manifest.tsv";
constexpr const char* kLogName = "f00-f08-producer.log";

// The order and set of the cross-check fixtures is fixed by SPECS-V2 §12.3 and
// the H3 work item: F00–F08, in id order.
constexpr std::array<const char*, 9> kFixtureIds = {
    "F00", "F01", "F02", "F03", "F04", "F05", "F06", "F07", "F08"};

// Fixtures whose wire contains an atom taken from the H1 generator.
constexpr std::uint64_t kBlockBytes = 64 * 1024;  // F03/F04/F08 pinned block

std::string sha256_hex(std::span<const std::uint8_t> bytes) {
    return marp::harness::sha256_hex(bytes);
}

std::string hex_u64(std::uint64_t value) {
    std::ostringstream oss;
    oss << "0x" << std::hex << std::nouppercase << value;
    return oss.str();
}

// ---------------------------------------------------------------------------
// Fixture → canonical E2 term
// ---------------------------------------------------------------------------
//
// Each fixture has a *pinned* structure in SPECS-V2 §12.3 and in the H1
// generators.  The canonical term is built directly from that structure — this
// is not a discovery or selection step (E4–E6 are out of scope): the term is a
// function of the fixture id alone.
//
// Decision (recorded in REPORT/HARNESS/H3-ORACLE-REPORT.md §11.4): F03/F04/F08
// are repeated 64 KiB blocks.  F08's *generator* nests leaf/copy/group repeats
// inside that block, but the block is one pinned atom in the fixture stream, so
// the canonical term that denotes the fixture is `Repeat(Atom(64 KiB), 16384)`
// exactly as for F03.  The nested structure is byte-level, and a term that
// encoded it as nested repeats would not be the canonical representative of
// the denotation under E2 §4.7.
struct FixtureTerm {
    Ir ir;
    std::string shape;
};

std::string node_shape(const Ir& ir, u32 node_id) {
    const Node& n = ir.nodes[node_id];
    const std::string len = n.length.to_decimal();
    switch (n.kind) {
        case Kind::Empty:
            return "empty";
        case Kind::Atom: {
            const BigInt atom_id = n.a;
            const auto id = atom_id.to_u64_checked();
            const std::string atom_len = id.has_value() && id.value() < ir.atoms.size()
                                             ? ir.atoms[static_cast<std::size_t>(id.value())].length.to_decimal()
                                             : std::string("?");
            return "atom(n=" + atom_len + ")";
        }
        case Kind::Zero:
            return "zero(n=" + n.a.to_decimal() + ")";
        case Kind::Repeat:
            return "repeat(" + node_shape(ir, n.args.at(0)) + ",q=" + n.a.to_decimal() +
                   ",r=" + n.b.to_decimal() + ")";
        case Kind::Affine:
            return "affine(n=" + n.a.to_decimal() + ",start=" + std::to_string(n.affine_start) +
                   ",step=" + std::to_string(n.affine_step) + ")";
        case Kind::Lfsr:
            return "lfsr(n=" + n.a.to_decimal() + ",conn=" + hex_u64(n.lfsr_conn) +
                   ",init=" + hex_u64(n.lfsr_init) + ")";
        default:
            return std::string(kind_name(n.kind)) + "(n=" + len + ")";
    }
}

FixtureTerm build_term(std::string_view id, const GenerateOptions& options) {
    c03::Builder b;
    u32 root = 0;

    if (id == "F00") {
        root = b.empty();
    } else if (id == "F01") {
        // SPECS-V2 §12.3 F01: exactly one byte, 0xA5.
        root = b.atom_node(b.add_atom({0xA5}));
    } else if (id == "F02") {
        // 1 GiB of zeros -> the canonical `Zero` node.
        root = b.zero(BigInt(std::uint64_t{1073741824}));
    } else if (id == "F03") {
        // 1 GiB = 64 KiB text block × 16384.
        const auto block = marp::harness::read_range("F03", BigInt(0), kBlockBytes, options);
        root = b.repeat(b.atom_node(b.add_atom(block)), std::uint64_t{16384}, std::uint64_t{0});
    } else if (id == "F04") {
        // 4 GiB = 64 KiB tile × 65536.
        const auto block = marp::harness::read_range("F04", BigInt(0), kBlockBytes, options);
        root = b.repeat(b.atom_node(b.add_atom(block)), std::uint64_t{65536}, std::uint64_t{0});
    } else if (id == "F05") {
        // 256 MiB, affine: byte i = (11 + 3·i) mod 256.
        root = b.affine(11, 3, BigInt(std::uint64_t{268435456}));
    } else if (id == "F06") {
        // 1 GiB counter, affine with step 1.
        root = b.affine(0, 1, BigInt(std::uint64_t{1073741824}));
    } else if (id == "F07") {
        // 1 GiB spec-lfsr, MSB-first packing (§3.5 pinned constants).
        root = b.lfsr(0xD800000000000000ull, 0x4D41525048314637ull,
                      BigInt(std::uint64_t{1073741824}));
    } else if (id == "F08") {
        // 1 GiB = 64 KiB grammar block × 16384.
        const auto block = marp::harness::read_range("F08", BigInt(0), kBlockBytes, options);
        root = b.repeat(b.atom_node(b.add_atom(block)), std::uint64_t{16384}, std::uint64_t{0});
    } else {
        throw std::invalid_argument("unsupported fixture id: " + std::string(id));
    }

    Ir ir = b.finish(root);
    const WfReport wf = check_well_formed_report(ir);
    if (!wf.ok()) {
        throw std::runtime_error(std::string(id) + ": term is not well formed: " + wf.constraint +
                                 " " + wf.message);
    }
    const auto canon = marp::v2::canon(ir);
    if (!canon.ok()) {
        throw std::runtime_error(std::string(id) + ": canon() failed with code " +
                                 std::to_string(static_cast<int>(canon.code())));
    }
    FixtureTerm out;
    out.ir = canon.value();
    const WfReport cc = check_canonical(out.ir);
    if (!cc.ok()) {
        throw std::runtime_error(std::string(id) + ": term is not canonical: " + cc.constraint +
                                 " " + cc.message);
    }
    out.shape = node_shape(out.ir, out.ir.root);
    return out;
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

bool write_bytes_atomic(const fs::path& path, std::span<const std::uint8_t> bytes) {
    const fs::path tmp = path.string() + ".tmp";
    {
        std::ofstream ofs(tmp, std::ios::binary | std::ios::trunc);
        if (!ofs.is_open()) return false;
        if (!bytes.empty()) {
            ofs.write(reinterpret_cast<const char*>(bytes.data()),
                      static_cast<std::streamsize>(bytes.size()));
        }
        ofs.flush();
        if (!ofs.good()) return false;
    }
    std::error_code ec;
    fs::rename(tmp, path, ec);
    return !ec;
}

bool write_text_atomic(const fs::path& path, std::string_view text) {
    const fs::path tmp = path.string() + ".tmp";
    {
        std::ofstream ofs(tmp, std::ios::binary | std::ios::trunc);
        if (!ofs.is_open()) return false;
        ofs << text;
        ofs.flush();
        if (!ofs.good()) return false;
    }
    std::error_code ec;
    fs::rename(tmp, path, ec);
    return !ec;
}

const ManifestRow* find_row(const std::vector<ManifestRow>& rows, std::string_view id) {
    for (const auto& row : rows) {
        if (row.fixture == id) return &row;
    }
    return nullptr;
}

void usage(const char* program) {
    std::cerr << "usage: " << program << " [--root <repo>] [--out <dir>] [--skip-identify]\n"
              << "  --root <repo>       repository root holding specs_and_reports/v2/fixtures.tsv\n"
              << "                      (default: ..)\n"
              << "  --out <dir>         output directory (default: build/h3-crosscheck)\n"
              << "  --skip-identify     do not recompute the fixture digests from the H3/H1\n"
              << "                      generator (only the pinned manifest is consulted)\n";
}

}  // namespace

int main(int argc, char** argv) {
    fs::path root = "..";
    fs::path out_dir = "build/h3-crosscheck";
    bool identify_fixtures = true;

    for (int i = 1; i < argc; ++i) {
        const std::string_view arg(argv[i]);
        if (arg == "--root" && i + 1 < argc) {
            root = argv[++i];
        } else if (arg == "--out" && i + 1 < argc) {
            out_dir = argv[++i];
        } else if (arg == "--skip-identify") {
            identify_fixtures = false;
        } else if (arg == "--help") {
            usage(argv[0]);
            return 0;
        } else {
            std::cerr << "error: unknown argument: " << arg << '\n';
            usage(argv[0]);
            return 2;
        }
    }

    const auto manifest_path = root / "specs_and_reports" / "v2" / "fixtures.tsv";
    if (!fs::exists(manifest_path)) {
        std::cerr << "error: H1 fixture manifest missing: " << manifest_path << '\n';
        return 1;
    }

    std::vector<ManifestRow> h1_rows;
    try {
        h1_rows = marp::harness::read_manifest(manifest_path);
    } catch (const std::exception& ex) {
        std::cerr << "error: cannot read H1 fixture manifest: " << ex.what() << '\n';
        return 1;
    }

    const auto wires_dir = out_dir / "wires";
    std::error_code ec;
    fs::create_directories(wires_dir, ec);
    if (ec) {
        std::cerr << "error: cannot create " << wires_dir << ": " << ec.message() << '\n';
        return 1;
    }

    GenerateOptions options;
    options.root = root;

    const std::string header =
        "fixture\tfixture_bytes\tfixture_sha256\tir_nodes\tir_atoms\twire_bytes\t"
        "wire_sha256\tengine_output_sha256\tengine_total_length\tir_shape\twire_path\n";
    std::string manifest = header;
    std::vector<std::string> log_lines;

    std::uint64_t total_wire_bytes = 0;
    std::uint64_t total_fixture_bytes = 0;
    int failures = 0;

    for (const char* raw_id : kFixtureIds) {
        const std::string id(raw_id);
        const auto started = std::chrono::steady_clock::now();
        try {
            const ManifestRow* h1 = find_row(h1_rows, id);
            if (h1 == nullptr) {
                throw std::runtime_error("missing row in " + manifest_path.string());
            }
            if (h1->mode != "generated") {
                throw std::runtime_error("expected mode=generated, got " + h1->mode);
            }

            // 1) Fixture identity.  `identify()` streams the H1 generator and
            //    re-hashes it; the committed manifest row must agree exactly.
            std::string fixture_sha = h1->sha256;
            std::string fixture_bytes = h1->bytes;
            if (identify_fixtures) {
                const marp::harness::Fixture fx = marp::harness::identify(id, options);
                const std::string live_sha = marp::harness::digest_hex(fx.sha256);
                const std::string live_bytes = fx.bytes.to_decimal();
                if (live_sha != h1->sha256 || live_bytes != h1->bytes) {
                    throw std::runtime_error("H1 generator disagrees with committed manifest: "
                                             "live=" + live_bytes + "/" + live_sha +
                                             " manifest=" + h1->bytes + "/" + h1->sha256);
                }
                fixture_sha = live_sha;
                fixture_bytes = live_bytes;
            }

            // 2) Canonical term for the fixture.
            const FixtureTerm term = build_term(id, options);

            // 3) C07 encode: unique canonical wire, identical on a second run.
            WireLimits limits;
            // Stage 11 must actually run for F04 (4 GiB), so the work bound is
            // raised well past the default 1 GiB.  This is a resource bound, not
            // a format constant; the wire bytes do not depend on it.
            limits.max_eval_bytes = std::uint64_t{1} << 42;

            const auto encoded = encode(term.ir, limits);
            if (!encoded.ok()) {
                throw std::runtime_error("encode() rejected the canonical term: " +
                                         encoded.error().message);
            }
            const std::vector<std::uint8_t>& wire = encoded.value();
            const auto planned = encoded_size(term.ir, limits);
            if (!planned.ok() ||
                planned.value().to_decimal() != std::to_string(wire.size())) {
                throw std::runtime_error("encoded_size() disagrees with encode()");
            }
            const auto encoded_again = encode(term.ir, limits);
            if (!encoded_again.ok() || encoded_again.value() != wire) {
                throw std::runtime_error("encode() is not deterministic");
            }

            const auto wire_path = wires_dir / (id + ".wire");
            if (!write_bytes_atomic(wire_path, std::span<const std::uint8_t>(wire.data(), wire.size()))) {
                throw std::runtime_error("cannot write " + wire_path.string());
            }
            const std::string wire_sha = sha256_hex(std::span<const std::uint8_t>(wire.data(), wire.size()));

            // 4) Full §5.1 validation: the engine's own evaluation of the wire
            //    must reproduce the H1 fixture digest and length.  This is the
            //    engine half of the cross-check; the oracle half is H3.
            const auto validation =
                validate(std::span<const std::uint8_t>(wire.data(), wire.size()), limits);
            if (!validation.ok()) {
                throw std::runtime_error(std::string("validate() failed at ") +
                                         stage_name(validation.error().stage) + " / " +
                                         validation.error().check + ": " +
                                         validation.error().message);
            }
            const std::string engine_sha = marp::harness::digest_hex(validation.value().output_sha256);
            const std::string engine_total = validation.value().total_length.to_decimal();
            if (engine_sha != fixture_sha) {
                throw std::runtime_error("engine output digest " + engine_sha +
                                         " != H1 fixture digest " + fixture_sha);
            }
            if (engine_total != fixture_bytes) {
                throw std::runtime_error("engine output length " + engine_total +
                                         " != H1 fixture length " + fixture_bytes);
            }
            if (validation.value().node_count != term.ir.nodes.size() ||
                validation.value().atom_count != term.ir.atoms.size()) {
                throw std::runtime_error("validated container counts disagree with the canonical term");
            }
            if (validation.value().root_id + 1 != term.ir.nodes.size()) {
                throw std::runtime_error("validated root id is not the last node");
            }

            total_wire_bytes += static_cast<std::uint64_t>(wire.size());
            total_fixture_bytes += std::stoull(fixture_bytes);

            manifest += id;
            manifest += '\t' + fixture_bytes;
            manifest += '\t' + fixture_sha;
            manifest += '\t' + std::to_string(term.ir.nodes.size());
            manifest += '\t' + std::to_string(term.ir.atoms.size());
            manifest += '\t' + std::to_string(wire.size());
            manifest += '\t' + wire_sha;
            manifest += '\t' + engine_sha;
            manifest += '\t' + engine_total;
            manifest += '\t' + term.shape;
            manifest += "\twires/" + id + ".wire\n";

            log_lines.push_back(id + ": fixture_bytes=" + fixture_bytes +
                                " fixture_sha256=" + fixture_sha +
                                " ir_nodes=" + std::to_string(term.ir.nodes.size()) +
                                " ir_atoms=" + std::to_string(term.ir.atoms.size()) +
                                " wire_bytes=" + std::to_string(wire.size()) +
                                " wire_sha256=" + wire_sha +
                                " engine_output_sha256=" + engine_sha + " term=" + term.shape +
                                " result=PASS");

            const auto finished = std::chrono::steady_clock::now();
            const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(finished - started);
            std::cout << "PASS " << id << " fixture=" << fixture_bytes << "B wire="
                      << wire.size() << "B term=" << term.shape << " ("
                      << ms.count() << " ms)\n";
        } catch (const std::exception& ex) {
            ++failures;
            std::cout << "FAIL " << id << ": " << ex.what() << '\n';
            log_lines.push_back(id + ": result=FAIL reason=" + ex.what());
        }
    }

    if (!write_text_atomic(out_dir / kManifestName, manifest)) {
        std::cerr << "error: cannot write " << (out_dir / kManifestName) << '\n';
        return 1;
    }

    std::string log;
    log += "H3 ORACLE F00-F08 wire producer (E3 C07 encode + §5.1 validate)\n";
    log += "manifest: " + manifest_path.string() + "\n";
    log += "identify_fixtures: " + std::string(identify_fixtures ? "yes" : "no") + "\n";
    for (const auto& line : log_lines) log += line + '\n';
    log += "totals: fixtures=" + std::to_string(kFixtureIds.size()) +
           " pass=" + std::to_string(kFixtureIds.size() - static_cast<std::size_t>(failures)) +
           " fail=" + std::to_string(failures) +
           " fixture_bytes=" + std::to_string(total_fixture_bytes) +
           " wire_bytes=" + std::to_string(total_wire_bytes) + "\n";
    log += "RESULT: " + std::string(failures == 0 ? "PASS" : "FAIL") + "\n";
    if (!write_text_atomic(out_dir / kLogName, log)) {
        std::cerr << "error: cannot write " << (out_dir / kLogName) << '\n';
        return 1;
    }

    std::cout << "manifest: " << (out_dir / kManifestName) << "\n"
              << "totals: fixtures=" << kFixtureIds.size() << " fail=" << failures
              << " wire_bytes=" << total_wire_bytes << "\n"
              << "RESULT: " << (failures == 0 ? "PASS" : "FAIL") << '\n';
    return failures == 0 ? 0 : 1;
}
