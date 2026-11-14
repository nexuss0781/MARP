#pragma once

#include <array>
#include <cstdint>
#include <filesystem>
#include <iosfwd>
#include <span>
#include <string>
#include <vector>

namespace marp::oracle {

enum class ErrorCode : int {
    Ok = 0,
    Usage = 2,
    Io = 3,
    Invalid = 4,
    Unsupported = 5,
    Mismatch = 6,
    Limit = 7,
};

enum class ValidationStage : std::uint8_t {
    None = 0,
    Size = 1,
    Header = 2,
    Bounds = 3,
    HeaderCrc = 4,
    Trailer = 5,
    Regions = 6,
    Atoms = 7,
    Nodes = 8,
    Root = 9,
    Index = 10,
    Eval = 11,
};

const char* stage_name(ValidationStage stage) noexcept;
const char* error_name(int code) noexcept;

struct Limits {
    std::uint64_t max_container_bytes = (1ULL << 63);
    std::uint32_t max_atoms = (1U << 24);
    std::uint32_t max_nodes = (1U << 24);
    std::uint32_t max_depth = (1U << 16);
    std::uint64_t max_output_bytes = (1ULL << 63);
    std::uint64_t max_range_expansion_ratio = (1ULL << 20);
    std::uint64_t max_predictor_prefix = (1ULL << 28);
    std::uint64_t max_predictor_stride_buf = (64ULL << 20);
};

struct Info {
    std::uint64_t file_bytes = 0;
    std::uint32_t node_count = 0;
    std::uint32_t atom_count = 0;
    std::uint32_t root_id = 0;
    std::string total_length;       // exact decimal
    std::string output_sha256;      // lowercase hex (empty if structure_only)
    bool has_index = false;
};

struct Diagnostic {
    int code = 0;
    ValidationStage stage = ValidationStage::None;
    std::string message;
};

// Normative minimum surface (§6.1)
int decode_file(const std::filesystem::path& wire,
                const std::filesystem::path& out,
                Info* info = nullptr);

int verify_file(const std::filesystem::path& wire,
                const std::string& expect_sha256_hex,
                bool structure_only = false);

int decode_range(const std::filesystem::path& wire,
                 const std::string& start_decimal,
                 const std::string& len_decimal,
                 const std::filesystem::path& out);

int inspect_file(const std::filesystem::path& wire, std::ostream& out);

// Diagnostic and custom-limit overloads
int decode_file(const std::filesystem::path& wire,
                const std::filesystem::path& out,
                Info* info,
                Diagnostic* diag,
                const Limits& limits = Limits{});

int verify_file(const std::filesystem::path& wire,
                const std::string& expect_sha256_hex,
                bool structure_only,
                Info* info,
                Diagnostic* diag,
                const Limits& limits = Limits{});

int decode_range(const std::filesystem::path& wire,
                 const std::string& start_decimal,
                 const std::string& len_decimal,
                 const std::filesystem::path& out,
                 Diagnostic* diag,
                 const Limits& limits = Limits{});

int inspect_file(const std::filesystem::path& wire,
                 std::ostream& out,
                 Diagnostic* diag,
                 const Limits& limits = Limits{});

// In-memory span operations (for clean-room unit testing without temp files)
int validate_bytes(std::span<const std::uint8_t> wire,
                   bool structure_only,
                   Info* info = nullptr,
                   Diagnostic* diag = nullptr,
                   const Limits& limits = Limits{});

int verify_bytes(std::span<const std::uint8_t> wire,
                 const std::string& expect_sha256_hex,
                 bool structure_only,
                 Info* info = nullptr,
                 Diagnostic* diag = nullptr,
                 const Limits& limits = Limits{});

int decode_bytes(std::span<const std::uint8_t> wire,
                 std::vector<std::uint8_t>& out,
                 Info* info = nullptr,
                 Diagnostic* diag = nullptr,
                 const Limits& limits = Limits{});

int decode_range_bytes(std::span<const std::uint8_t> wire,
                       const std::string& start_decimal,
                       const std::string& len_decimal,
                       std::vector<std::uint8_t>& out,
                       Diagnostic* diag = nullptr,
                       const Limits& limits = Limits{});

int inspect_bytes(std::span<const std::uint8_t> wire,
                  std::ostream& out,
                  Diagnostic* diag = nullptr,
                  const Limits& limits = Limits{});

// Clean-room self-testable cryptographic/checksum primitives
std::array<std::uint8_t, 32> sha256_bytes(std::span<const std::uint8_t> data);
std::string sha256_hex(std::span<const std::uint8_t> data);
std::uint32_t crc32_bytes(std::span<const std::uint8_t> data);

} // namespace marp::oracle
