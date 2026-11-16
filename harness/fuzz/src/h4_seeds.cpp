// MARP v2 — H4 FUZZ — E3-G prerequisite and seed provenance.
//
// The E3-G corpus builder is consumed through its own header
// (`engine/src/e3g/e3g_corpus.hpp`) rather than re-derived: H4 must mutate the
// *E3* wires, not a second opinion about them.

#include "h4_seeds.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <map>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "e3g_corpus.hpp"
#include "e3g_support.hpp"
#include "h4_support.hpp"
#include "mapr/e3/e3_wire.hpp"

namespace marp::harness::h4 {
namespace {

namespace fs = std::filesystem;
using namespace marp::v2;  // NOLINT

std::vector<std::string> split_tabs(const std::string& line) {
    std::vector<std::string> fields;
    std::size_t start = 0;
    for (std::size_t i = 0; i <= line.size(); ++i) {
        if (i == line.size() || line[i] == '\t') {
            fields.push_back(line.substr(start, i - start));
            start = i + 1;
        }
    }
    return fields;
}

std::vector<std::string> read_lines(const fs::path& path, bool& ok) {
    std::vector<std::string> lines;
    std::ifstream stream(path);
    ok = static_cast<bool>(stream);
    if (!ok) return lines;
    std::string line;
    while (std::getline(stream, line)) {
        lines.push_back(trim_right(std::move(line)));
    }
    return lines;
}

struct CatalogEntry {
    const char* id;
};

// Twelve small canonical wires (every shape family at least once, plus the
// 1 KiB body) and three large containers whose header/index/trailer are what
// the campaign targets.  Two of the large seeds carry a canonical seek index
// (4 MiB and 5 MiB declared lengths), so index-field corruption is exercised on
// a real index and not a fabricated one.
constexpr CatalogEntry kCatalog[] = {
    {"tkat-empty"},        {"tkat-atom1"},      {"tkat-atom16"},   {"tkat-zero0"},
    {"tkat-zero5"},        {"tkat-concat2"},    {"tkat-repeat35"}, {"tkat-slicemid"},
    {"tkat-xor"},          {"tkat-ilv-s1"},     {"tkat-lfsr0"},    {"tkat-atom1023"},
    {"tkat-atom-max"},     {"edge-index-repeat-5x1mib"}, {"edge-atom-max-plus-one"},
};

std::uint32_t load_u32(const std::vector<std::uint8_t>& bytes, std::size_t offset) {
    return static_cast<std::uint32_t>(bytes[offset]) |
           (static_cast<std::uint32_t>(bytes[offset + 1]) << 8) |
           (static_cast<std::uint32_t>(bytes[offset + 2]) << 16) |
           (static_cast<std::uint32_t>(bytes[offset + 3]) << 24);
}

const e3g::CanonItem* find_item(const e3g::Corpus& corpus, const std::string& id) {
    for (const e3g::CanonItem& item : corpus.canon) {
        if (item.id == id) return &item;
    }
    return nullptr;
}

}  // namespace

Prereq check_prerequisite(const fs::path& root) {
    Prereq prereq;
    const fs::path v2 = root / "specs_and_reports" / "v2";
    prereq.gate_path = "specs_and_reports/v2/gates/E3-G.tsv";
    prereq.corpus_path = "specs_and_reports/v2/corpus/E3/corpus.tsv";
    prereq.counts_path = "specs_and_reports/v2/corpus/E3/fuzz_counts.tsv";

    const fs::path gate = v2 / "gates" / "E3-G.tsv";
    const fs::path corpus = v2 / "corpus" / "E3" / "corpus.tsv";
    const fs::path counts = v2 / "corpus" / "E3" / "fuzz_counts.tsv";
    if (!fs::is_regular_file(gate)) {
        prereq.failure = "E3-G gate evidence is missing: " + prereq.gate_path;
        return prereq;
    }
    if (!fs::is_regular_file(corpus)) {
        prereq.failure = "E3-G corpus manifest is missing: " + prereq.corpus_path;
        return prereq;
    }
    if (!fs::is_regular_file(counts)) {
        prereq.failure = "E3-G fuzz counters are missing: " + prereq.counts_path;
        return prereq;
    }
    prereq.gate_sha256 = sha256_file(gate);
    prereq.corpus_sha256 = sha256_file(corpus);
    prereq.counts_sha256 = sha256_file(counts);

    bool ok = false;
    const std::vector<std::string> lines = read_lines(gate, ok);
    if (!ok) {
        prereq.failure = "E3-G gate evidence cannot be read";
        return prereq;
    }
    if (lines.empty()) {
        prereq.failure = "E3-G gate evidence is empty";
        return prereq;
    }
    const std::size_t verdict_column = 8;
    bool fuzz_zero = false;
    bool crashes_zero = false;
    bool timeouts_zero = false;
    bool fuzz_seen = false;
    for (std::size_t i = 1; i < lines.size(); ++i) {
        if (lines[i].empty()) continue;
        const std::vector<std::string> fields = split_tabs(lines[i]);
        if (fields.size() < 10) {
            prereq.failure = "E3-G gate evidence has a malformed row";
            return prereq;
        }
        ++prereq.gate_rows;
        if (fields[verdict_column] == "FAIL") ++prereq.gate_fail;
        if (fields[verdict_column] == "BLOCKED") ++prereq.gate_blocked;
        if (fields[0] == "e3g.fuzz.accepted_invalid" && fields[verdict_column] == "PASS" &&
            fields[7] == "0") {
            fuzz_zero = true;
            fuzz_seen = true;
        }
        if (fields[0] == "e3g.fuzz.crashes" && fields[verdict_column] == "PASS" &&
            fields[7] == "0") {
            crashes_zero = true;
        }
        if (fields[0] == "e3g.fuzz.timeouts" && fields[verdict_column] == "PASS" &&
            fields[7] == "0") {
            timeouts_zero = true;
        }
    }
    if (prereq.gate_fail != 0 || prereq.gate_blocked != 0) {
        prereq.failure = "E3-G gate evidence is not green (" +
                         std::to_string(prereq.gate_fail) + " FAIL, " +
                         std::to_string(prereq.gate_blocked) + " BLOCKED)";
        return prereq;
    }
    if (!fuzz_seen || !fuzz_zero || !crashes_zero || !timeouts_zero) {
        prereq.failure =
            "E3-G gate evidence lacks a clean fuzz record (accepted_invalid/crashes/timeouts)";
        return prereq;
    }
    prereq.gate_verdict = "PASS";

    const std::vector<std::string> corpus_lines = read_lines(corpus, ok);
    if (!ok || corpus_lines.size() < 2) {
        prereq.failure = "E3-G corpus manifest is empty or unreadable";
        return prereq;
    }
    prereq.corpus_items = corpus_lines.size() - 1;

    const std::vector<std::string> count_lines = read_lines(counts, ok);
    if (!ok) {
        prereq.failure = "E3-G fuzz counters cannot be read";
        return prereq;
    }
    bool mutants_seen = false;
    for (std::size_t i = 1; i < count_lines.size(); ++i) {
        const std::vector<std::string> fields = split_tabs(count_lines[i]);
        if (fields.size() < 2) continue;
        if (fields[0] == "mutants") {
            prereq.e3_mutants = std::stoull(fields[1]);
            mutants_seen = true;
        } else if ((fields[0] == "accepted_invalid" || fields[0] == "crashes" ||
                    fields[0] == "timeouts") &&
                   fields[1] != "0") {
            prereq.failure = "E3-G fuzz counters record a non-zero " + fields[0];
            return prereq;
        }
    }
    if (!mutants_seen || prereq.e3_mutants != 100'000ull) {
        prereq.failure = "E3-G fuzz counters do not record 100000 mutants";
        return prereq;
    }
    prereq.ok = true;
    return prereq;
}

SeedBuild build_seeds(const fs::path& root) {
    SeedBuild build;
    const fs::path corpus_path = root / "specs_and_reports" / "v2" / "corpus" / "E3" / "corpus.tsv";
    bool ok = false;
    const std::vector<std::string> lines = read_lines(corpus_path, ok);
    if (!ok) {
        build.failure = "E3-G corpus manifest is unreadable";
        return build;
    }
    struct Identity {
        std::string sha256;
        std::uint64_t bytes = 0;
    };
    std::map<std::string, Identity> identities;
    for (std::size_t i = 1; i < lines.size(); ++i) {
        if (lines[i].empty()) continue;
        const std::vector<std::string> fields = split_tabs(lines[i]);
        if (fields.size() < 8) continue;
        Identity identity;
        identity.sha256 = fields[5];
        identity.bytes = std::stoull(fields[6]);
        identities[fields[1]] = identity;
    }

    const e3g::Corpus corpus = e3g::build_corpus(root.string());
    for (const CatalogEntry& entry : kCatalog) {
        const std::string id = entry.id;
        const e3g::CanonItem* item = find_item(corpus, id);
        if (item == nullptr) {
            build.failure = "seed " + id + " is absent from the E3-G corpus";
            return build;
        }
        const auto identity = identities.find(id);
        if (identity == identities.end()) {
            build.failure = "seed " + id + " has no committed E3-G identity";
            return build;
        }
        if (item->expect_encode_limit) {
            build.failure = "seed " + id + " is a documented limit case, not a valid wire";
            return build;
        }
        WireLimits limits;
        if (item->needs_limit_lift) {
            limits.enforce_output_cap = false;
            limits.verify_denotation = false;
        }
        const WireResult<std::vector<std::uint8_t>> encoded = encode(item->ir, limits);
        if (!encoded.ok()) {
            build.failure = "seed " + id + " does not encode";
            return build;
        }
        SeedInfo seed;
        seed.id = id;
        seed.e3_item = id;
        seed.source = "E3-G:" + item->group;
        seed.wire = encoded.value();
        seed.sha256 = sha256_hex(std::span<const std::uint8_t>(seed.wire.data(), seed.wire.size()));
        if (seed.wire.size() != identity->second.bytes || seed.sha256 != identity->second.sha256) {
            build.failure = "seed " + id + " does not reproduce its committed E3-G identity";
            return build;
        }
        const WireResult<Validation> validated =
            validate(std::span<const std::uint8_t>(seed.wire.data(), seed.wire.size()), limits);
        if (!validated.ok()) {
            build.failure = "seed " + id + " is not a valid container (validate rejected it)";
            return build;
        }
        const WireResult<Ir> decoded =
            decode(std::span<const std::uint8_t>(seed.wire.data(), seed.wire.size()), limits);
        if (!decoded.ok()) {
            build.failure = "seed " + id + " is not a valid container (decode rejected it)";
            return build;
        }
        if (seed.wire.size() >= static_cast<std::size_t>(kWireMinContainerBytes)) {
            seed.index_present =
                (load_u32(seed.wire, kHdrOffFlags) & kWireFlagIndexPresent) != 0;
        }
        seed.large = seed.wire.size() > 65536;
        build.note.push_back("seed " + seed.id + " source=" + seed.source + " bytes=" +
                             std::to_string(seed.wire.size()) + " sha256=" + seed.sha256 +
                             " index=" + (seed.index_present ? "present" : "absent") +
                             " role=" + (seed.large ? "large-header-index" : "small"));
        build.seeds.push_back(std::move(seed));
    }
    if (build.seeds.size() != std::size(kCatalog)) {
        build.failure = "seed catalog is incomplete";
        return build;
    }
    // Seed order is the campaign's seed-index order; it must be the same order
    // `load_seeds` produces from the seed directory (file name order).
    std::sort(build.seeds.begin(), build.seeds.end(),
              [](const SeedInfo& a, const SeedInfo& b) { return a.id < b.id; });
    std::sort(build.note.begin(), build.note.end());
    build.ok = true;
    return build;
}

bool write_seed_dir(const fs::path& dir, const std::vector<SeedInfo>& seeds, std::string& why) {
    std::error_code error;
    fs::create_directories(dir, error);
    if (error) {
        why = "cannot create seed directory " + dir.string();
        return false;
    }
    for (const SeedInfo& seed : seeds) {
        const fs::path path = dir / (seed.id + ".wire");
        if (!write_file_atomic(
                path, std::span<const std::uint8_t>(seed.wire.data(), seed.wire.size()))) {
            why = "cannot write seed " + path.string();
            return false;
        }
    }
    if (!write_text_atomic(dir / "manifest.tsv", seeds_manifest(seeds))) {
        why = "cannot write the seed manifest";
        return false;
    }
    return true;
}

std::string seeds_manifest(const std::vector<SeedInfo>& seeds) {
    std::string text =
        "seed\te3_item\tsource\tbytes\tsha256\tindex\trole\n";
    for (const SeedInfo& seed : seeds) {
        text += seed.id;
        text += '\t';
        text += seed.e3_item;
        text += '\t';
        text += seed.source;
        text += '\t';
        text += std::to_string(seed.wire.size());
        text += '\t';
        text += seed.sha256;
        text += '\t';
        text += seed.index_present ? "present" : "absent";
        text += '\t';
        text += seed.large ? "large-header-index" : "small";
        text += '\n';
    }
    return text;
}

std::string seeds_sha256_set(const std::vector<SeedInfo>& seeds) {
    std::string text;
    for (const SeedInfo& seed : seeds) {
        text += seed.sha256;
        text += ' ';
        text += seed.id;
        text += '\n';
    }
    return sha256_hex(text);
}

std::string sha256sum_line(const fs::path& path, const fs::path& relative_to) {
    std::error_code error;
    const fs::path relative = fs::relative(path, relative_to, error);
    const fs::path shown = error ? path : relative;
    return sha256_file(path) + "  " + shown.generic_string() + "\n";
}

}  // namespace marp::harness::h4
