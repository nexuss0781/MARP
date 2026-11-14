#pragma once

#include <mapr/e1_bigint.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace marp::harness {

using BigInt = mapr::BigInt;

struct Fixture {
    std::string id;
    BigInt bytes;
    std::array<std::uint8_t, 32> sha256{}; // all-zero for virtual/blocked
    std::string path;                      // empty unless materialised/supplied
};

enum class FixtureMode { Generated, Supplied, Virtual, Blocked };

struct FixtureSpec {
    std::string id;
    FixtureMode mode = FixtureMode::Generated;
    BigInt bytes;
    std::string params; // pinned constants, compact k=v;k=v
};

class FixtureStream {
public:
    virtual ~FixtureStream() = default;
    virtual std::size_t read(std::span<std::uint8_t> out) = 0;
    virtual void rewind() = 0;
    virtual bool supports_range() const { return false; }
    virtual void read_range(const BigInt& offset, std::span<std::uint8_t> out);
};

// One manifest row. `bytes` is kept as canonical decimal text so the TSV
// contract cannot accidentally introduce a floating-point conversion.
struct ManifestRow {
    std::string fixture;
    std::string mode;
    std::string bytes;
    std::string sha256;
    std::string params;
    std::string path;
    std::string gates;
};

// Same eight columns as H2 evidence, without linking the H2 implementation.
struct FixtureEvidenceRow {
    std::string check;
    std::string corpus;
    std::string item_id;
    std::string input_sha256;
    std::string expected;
    std::string actual;
    std::string verdict; // PASS, FAIL, or BLOCKED
    std::string log;

    bool operator==(const FixtureEvidenceRow& other) const = default;
};

struct GenerateOptions {
    std::filesystem::path root{"."};
    std::filesystem::path out;
    std::filesystem::path manifest;
    std::filesystem::path real;
    std::filesystem::path coded;
    bool allow_blocked = false;
    bool evidence = false;
    bool determinism = false;
    std::string command_line;
    std::string ci_run_id;
    std::string ci_run_url;
    std::string commit;
    std::string runner_os;
};

struct EvidenceContext {
    std::filesystem::path root{"."};
    std::filesystem::path manifest;
    std::string command_line;
    std::string ci_run_id;
    std::string ci_run_url;
    std::string commit;
    std::string runner_os;
};

struct MaterializeResult {
    Fixture fixture;
    std::uint64_t logical_bytes = 0;
    std::uint64_t allocated_bytes = 0;
    bool sparse = false;
};

// Minimum normative surface. This overload writes only the manifest and
// returns nonzero when F11/F12 are blocked.
int generate(const std::filesystem::path& out,
             const std::filesystem::path& manifest);
int generate(const GenerateOptions& options);
int verify(const GenerateOptions& options);

std::vector<FixtureSpec> catalogue(const GenerateOptions& options);
std::vector<std::string> catalogue_ids();
std::unique_ptr<FixtureStream> open_stream(std::string_view id,
                                           const GenerateOptions& options);
Fixture identify(std::string_view id, const GenerateOptions& options);
MaterializeResult materialize(std::string_view id,
                              const std::filesystem::path& to,
                              const GenerateOptions& options);
std::vector<std::uint8_t> read_range(std::string_view id,
                                     const BigInt& offset, std::size_t len,
                                     const GenerateOptions& options);

std::string mode_name(FixtureMode mode);
std::string digest_hex(const std::array<std::uint8_t, 32>& digest);
std::string sha256_hex(std::span<const std::uint8_t> bytes);
std::string sha256_file_hex(const std::filesystem::path& path);
std::string affected_gates();

void write_manifest(const std::filesystem::path& path,
                    const std::vector<ManifestRow>& rows);
std::vector<ManifestRow> read_manifest(const std::filesystem::path& path);
std::string manifest_text(const std::vector<ManifestRow>& rows);

void upsert_evidence(const EvidenceContext& context,
                     const std::vector<FixtureEvidenceRow>& rows,
                     const std::vector<std::string>& log_lines);
void record_check(const EvidenceContext& context, std::string check,
                  std::string item_id, std::string expected,
                  std::string actual, std::string input_sha256,
                  std::string verdict);
void record_small(const EvidenceContext& context, std::string_view id,
                  const std::filesystem::path& file,
                  std::string_view external_sha256);
void record_sparse(const EvidenceContext& context,
                   const MaterializeResult& result);
int verify_evidence_sums(const std::filesystem::path& root);

} // namespace marp::harness
