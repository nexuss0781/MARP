#include "marp/harness/fixtures.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <span>
#include <string>
#include <vector>

namespace marp::harness {
namespace fs = std::filesystem;

namespace {

GenerateOptions test_options() {
    GenerateOptions options;
    options.root = fs::current_path();
    options.allow_blocked = true;
    return options;
}

std::vector<std::uint8_t> read_prefix(std::string_view id, std::size_t len,
                                      const GenerateOptions& options) {
    auto stream = open_stream(id, options);
    std::vector<std::uint8_t> out(len);
    std::size_t done = 0;
    while (done < out.size()) {
        const std::size_t got = stream->read(std::span<std::uint8_t>(out).subspan(done));
        if (got == 0) break;
        done += got;
    }
    out.resize(done);
    return out;
}

std::vector<std::uint8_t> read_all(std::string_view id, const GenerateOptions& options) {
    auto stream = open_stream(id, options);
    std::vector<std::uint8_t> out;
    std::array<std::uint8_t, 64 * 1024> buffer{};
    while (true) {
        const std::size_t got = stream->read(std::span<std::uint8_t>(buffer));
        if (got == 0) break;
        out.insert(out.end(), buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(got));
    }
    return out;
}

fs::path scratch_root() {
    const fs::path root = fs::temp_directory_path() / "marp_h1_fixtures_test";
    fs::remove_all(root);
    fs::create_directories(root);
    return root;
}

} // namespace

TEST(FixturesTest, CatalogueOrderAndExactSizes) {
    const auto options = test_options();
    const auto specs = catalogue(options);
    const auto ids = catalogue_ids();
    ASSERT_EQ(specs.size(), ids.size());
    ASSERT_EQ(specs.size(), 31u);
    for (std::size_t i = 0; i < specs.size(); ++i) {
        EXPECT_EQ(specs[i].id, ids[i]);
    }
    EXPECT_EQ(specs[23].id, "F13");
    EXPECT_EQ(specs[23].bytes.to_decimal(), "1099511627776");
    EXPECT_EQ(specs[24].id, "F14");
    EXPECT_EQ(specs[24].bytes.to_decimal(), "1125899906842624");
    EXPECT_EQ(specs[25].id, "F15");
    EXPECT_EQ(specs[25].bytes.to_decimal(), "4294967296");
    BigInt sum;
    for (std::size_t i = 26; i < 31; ++i) {
        EXPECT_EQ(specs[i].id, "F15.seg" + std::to_string(i - 26));
        auto result = sum.add(specs[i].bytes);
        ASSERT_TRUE(result.ok());
        sum = std::move(result).value();
    }
    EXPECT_EQ(sum, specs[25].bytes);
}

TEST(FixturesTest, GeneratedPrefixesAreRewindable) {
    const auto options = test_options();
    const std::vector<std::string> ids = {
        "F00", "F01", "F02", "F03", "F04", "F05", "F06", "F07", "F08",
        "F09", "F09.0", "F09.9", "F10", "F15", "F15.seg4"
    };
    for (const auto& id : ids) {
        auto stream = open_stream(id, options);
        std::array<std::uint8_t, 4096> first{};
        std::array<std::uint8_t, 4096> second{};
        const std::size_t n1 = stream->read(std::span<std::uint8_t>(first));
        stream->rewind();
        const std::size_t n2 = stream->read(std::span<std::uint8_t>(second));
        EXPECT_EQ(n1, n2) << id;
        EXPECT_TRUE(std::equal(first.begin(), first.begin() + static_cast<std::ptrdiff_t>(n1),
                               second.begin())) << id;
    }
}

TEST(FixturesTest, SmallLiteralAndEmpty) {
    const auto options = test_options();
    EXPECT_TRUE(read_prefix("F00", 16, options).empty());
    const auto one = read_prefix("F01", 16, options);
    ASSERT_EQ(one.size(), 1u);
    EXPECT_EQ(one[0], 0xA5);
}

TEST(FixturesTest, F09AggregateIsMemberConcatenation) {
    const auto options = test_options();
    std::vector<std::uint8_t> expected;
    for (int member = 0; member < 10; ++member) {
        const auto bytes = read_all("F09." + std::to_string(member), options);
        ASSERT_EQ(bytes.size(), 100u * 1024u);
        expected.insert(expected.end(), bytes.begin(), bytes.end());
    }
    const auto aggregate = read_all("F09", options);
    EXPECT_EQ(aggregate, expected);
}

TEST(FixturesTest, VirtualEndRangesAndNoMaterialisation) {
    const auto options = test_options();
    BigInt offset13;
    {
        auto result = BigInt::from_decimal("1099511627776");
        ASSERT_TRUE(result.ok());
        offset13 = std::move(result).value();
        auto sub = offset13.sub(BigInt(64));
        ASSERT_TRUE(sub.ok());
        offset13 = std::move(sub).value();
    }
    const auto zero = read_range("F13", offset13, 64, options);
    EXPECT_TRUE(std::all_of(zero.begin(), zero.end(), [](std::uint8_t b) { return b == 0; }));

    BigInt offset14;
    {
        auto result = BigInt::from_decimal("1125899906842624");
        ASSERT_TRUE(result.ok());
        offset14 = std::move(result).value();
        auto sub = offset14.sub(BigInt(64));
        ASSERT_TRUE(sub.ok());
        offset14 = std::move(sub).value();
    }
    const auto repeat = read_range("F14", offset14, 64, options);
    const std::uint64_t start = 1125899906842624ULL - 64ULL;
    for (std::size_t i = 0; i < repeat.size(); ++i) {
        const std::uint64_t pos = start + static_cast<std::uint64_t>(i);
        const std::uint8_t expected = static_cast<std::uint8_t>(
            ((pos * 13ULL) ^ (pos >> 8) ^ 0x5AULL) & 0xFFULL);
        EXPECT_EQ(repeat[i], expected);
    }
    EXPECT_THROW(materialize("F13", fs::temp_directory_path() / "marp_h1_virtual", options),
                 std::invalid_argument);
    EXPECT_THROW(materialize("F14", fs::temp_directory_path() / "marp_h1_virtual", options),
                 std::invalid_argument);
    EXPECT_THROW(read_range("F13", BigInt::from_decimal("1099511627777").value(), 1, options),
                 std::out_of_range);
}

TEST(FixturesTest, RangeRequiresZeroOrRepeatAndMatchesSequential) {
    const auto options = test_options();
    EXPECT_THROW(read_range("F05", BigInt::zero(), 16, options), std::invalid_argument);
    EXPECT_THROW(read_range("F10", BigInt::zero(), 16, options), std::invalid_argument);
    const auto range = read_range("F03", BigInt(65535), 128, options);
    const auto prefix = read_prefix("F03", 65535 + 128, options);
    ASSERT_EQ(prefix.size(), 65535u + 128u);
    EXPECT_TRUE(std::equal(range.begin(), range.end(), prefix.begin() + 65535));
}

TEST(FixturesTest, SuppliedBytesAreOpaqueAndMissingIsBlocked) {
    const fs::path root = scratch_root();
    const fs::path supplied = root / "opaque-input";
    const std::vector<std::uint8_t> bytes{0x00, 0x01, 0x02, 0xFF, 0x7F};
    {
        std::ofstream out(supplied, std::ios::binary);
        out.write(reinterpret_cast<const char*>(bytes.data()),
                  static_cast<std::streamsize>(bytes.size()));
    }
    GenerateOptions options = test_options();
    options.root = root;
    options.real = supplied;
    const auto fixture = identify("F11", options);
    EXPECT_EQ(fixture.bytes.to_decimal(), "5");
    EXPECT_EQ(digest_hex(fixture.sha256), sha256_hex(std::span<const std::uint8_t>(bytes)));
    EXPECT_FALSE(fixture.path.empty());
    EXPECT_EQ(read_all("F11", options), bytes);

    const auto blocked = identify("F12", options);
    EXPECT_EQ(blocked.bytes.to_decimal(), "0");
    EXPECT_TRUE(blocked.path.empty());
    const std::array<std::uint8_t, 32> zero_digest{};
    EXPECT_EQ(blocked.sha256, zero_digest);
    EXPECT_EQ(affected_gates(), "V2-G1,V2-G6,V2-G7,V2-G14");
    fs::remove_all(root);
}

TEST(FixturesTest, MaterializeSmallGeneratedFixtures) {
    const fs::path root = scratch_root();
    GenerateOptions options = test_options();
    options.root = root;
    const auto empty = materialize("F00", root / "F00", options);
    EXPECT_EQ(empty.logical_bytes, 0u);
    EXPECT_EQ(fs::file_size(root / "F00"), 0u);
    const auto one = materialize("F01", root / "F01", options);
    EXPECT_EQ(one.logical_bytes, 1u);
    EXPECT_EQ(fs::file_size(root / "F01"), 1u);
    EXPECT_EQ(sha256_file_hex(root / "F01"), digest_hex(one.fixture.sha256));
    EXPECT_THROW(materialize("F11", root / "F11", options), std::invalid_argument);
    fs::remove_all(root);
}

TEST(FixturesTest, ManifestWriterRejectsBadOrderAndEvidenceSumsVerify) {
    const fs::path root = scratch_root();
    GenerateOptions options = test_options();
    options.root = root;
    options.manifest = root / "specs_and_reports" / "v2" / "fixtures.tsv";
    std::vector<ManifestRow> rows;
    for (const auto& spec : catalogue(options)) {
        ManifestRow row;
        row.fixture = spec.id;
        row.bytes = spec.bytes.to_decimal();
        row.params = spec.params;
        row.path = "-";
        row.gates = "-";
        if (spec.mode == FixtureMode::Virtual) {
            row.mode = "virtual";
            row.sha256 = "-";
        } else if (spec.mode == FixtureMode::Supplied) {
            row.mode = "blocked";
            row.bytes = "0";
            row.sha256 = "-";
            row.params = "source=supplied;option=--real;reason=missing_path;requested=-";
            row.gates = affected_gates();
        } else {
            row.mode = "generated";
            row.sha256 = std::string(64, '0');
        }
        rows.push_back(row);
    }
    write_manifest(options.manifest, rows);
    EXPECT_EQ(read_manifest(options.manifest).size(), rows.size());
    std::swap(rows[0], rows[1]);
    EXPECT_THROW(write_manifest(options.manifest, rows), std::runtime_error);
    std::swap(rows[0], rows[1]);

    EvidenceContext context;
    context.root = root;
    context.manifest = options.manifest;
    context.command_line = "fixtures_test";
    FixtureEvidenceRow row;
    row.check = "fixtures.catalog";
    row.corpus = "FIXTURES";
    row.item_id = "manifest";
    row.input_sha256 = sha256_file_hex(options.manifest);
    row.expected = "31";
    row.actual = "31";
    row.verdict = "PASS";
    row.log = "logs/H1-FIXTURES.log#fixtures.catalog:manifest";
    upsert_evidence(context, {row}, {});
    EXPECT_EQ(verify_evidence_sums(root), 0);
    {
        std::ofstream out(options.manifest, std::ios::app);
        out << "tamper\n";
    }
    EXPECT_NE(verify_evidence_sums(root), 0);
    fs::remove_all(root);
}

} // namespace marp::harness
