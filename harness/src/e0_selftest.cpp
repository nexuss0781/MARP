#include "marp/harness/e0_selftest.hpp"
#include "marp/harness/gates.hpp"
#include <mapr/e1_crc32.hpp>
#include <mapr/e1_sha256.hpp>
#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace marp::harness {

namespace fs = std::filesystem;

// MARP-H0 envelope format:
//   magic  8 bytes "MARP-H0\0"
//   length u32 LE
//   crc32  u32 LE (standard CRC-32 of the payload)
//   payload length bytes

namespace {

constexpr std::array<uint8_t, 8> kMarpH0Magic = {'M', 'A', 'R', 'P', '-', 'H', '0', '\0'};

struct Envelope {
    std::array<uint8_t, 8> magic = kMarpH0Magic;
    uint32_t length = 0;
    uint32_t crc32 = 0;
    std::vector<uint8_t> payload;
};

void write_u32_le(std::vector<uint8_t>& buffer, uint32_t value) {
    buffer.push_back(static_cast<uint8_t>(value & 0xFFu));
    buffer.push_back(static_cast<uint8_t>((value >> 8) & 0xFFu));
    buffer.push_back(static_cast<uint8_t>((value >> 16) & 0xFFu));
    buffer.push_back(static_cast<uint8_t>((value >> 24) & 0xFFu));
}

uint32_t read_u32_le(const uint8_t* bytes) {
    return static_cast<uint32_t>(bytes[0]) |
           (static_cast<uint32_t>(bytes[1]) << 8) |
           (static_cast<uint32_t>(bytes[2]) << 16) |
           (static_cast<uint32_t>(bytes[3]) << 24);
}

std::string_view byte_view(const std::vector<uint8_t>& bytes) {
    if (bytes.empty()) return {};
    return std::string_view(reinterpret_cast<const char*>(bytes.data()), bytes.size());
}

Envelope make_valid_envelope(const std::vector<uint8_t>& payload) {
    Envelope envelope;
    envelope.length = static_cast<uint32_t>(payload.size());
    envelope.crc32 = mapr::crc32(byte_view(payload));
    envelope.payload = payload;
    return envelope;
}

std::vector<uint8_t> serialize_envelope(const Envelope& envelope) {
    std::vector<uint8_t> buffer;
    buffer.insert(buffer.end(), envelope.magic.begin(), envelope.magic.end());
    write_u32_le(buffer, envelope.length);
    write_u32_le(buffer, envelope.crc32);
    buffer.insert(buffer.end(), envelope.payload.begin(), envelope.payload.end());
    return buffer;
}

bool verify_envelope(const std::vector<uint8_t>& data) {
    if (data.size() < 16) return false;
    for (size_t i = 0; i < kMarpH0Magic.size(); ++i) {
        if (data[i] != kMarpH0Magic[i]) return false;
    }
    const uint32_t length = read_u32_le(data.data() + 8);
    const uint32_t expected_crc = read_u32_le(data.data() + 12);
    if (static_cast<uint64_t>(length) + 16u != data.size()) return false;

    const std::string_view payload(
        reinterpret_cast<const char*>(data.data() + 16), static_cast<size_t>(length));
    return mapr::crc32(payload) == expected_crc;
}


EvidenceRow make_row(const std::string& check, const std::string& corpus,
                     const std::string& item, const std::string& input_sha,
                     const std::string& expected, const std::string& actual,
                     bool pass) {
    EvidenceRow row;
    row.check = check;
    row.corpus = corpus;
    row.item_id = item;
    row.input_sha256 = input_sha;
    row.expected = expected;
    row.actual = actual;
    row.verdict = pass ? "PASS" : "FAIL";
    row.log = "logs/E0-G.log#" + check;
    return row;
}

bool file_contains(const fs::path& path, std::string_view needle) {
    std::ifstream ifs(path);
    if (!ifs) return false;
    std::ostringstream oss;
    oss << ifs.rdbuf();
    return oss.str().find(needle) != std::string::npos;
}

} // namespace

int run_e0_selftest(const fs::path& root, std::string_view command_line) {
    const fs::path v2 = root / "specs_and_reports" / "v2";
    const fs::path tsv_path = v2 / "gates" / "E0-G.tsv";
    const fs::path log_path = v2 / "logs" / "E0-G.log";
    const fs::path acceptance_path = v2 / "ACCEPTANCE.md";

    std::error_code ec;
    fs::create_directories(tsv_path.parent_path(), ec);
    fs::create_directories(log_path.parent_path(), ec);

    std::ofstream log_file(log_path, std::ios::trunc);
    if (!log_file) return 1;
    const EnvRecord env = capture_env_record(root);
    log_file << "date_utc: " << env.date_utc << '\n';
    log_file << "host: " << env.host << '\n';
    log_file << "kernel: " << env.kernel << '\n';
    log_file << "nproc: " << env.nproc << '\n';
    log_file << "mem_total_kib: " << env.mem_total_kib << '\n';
    log_file << "disk: " << env.disk << '\n';
    log_file << "compiler: " << env.compiler << '\n';
    log_file << "make: " << env.make << '\n';
    log_file << "engine_sha256: " << env.engine_sha256 << '\n';
    log_file << "test_sha256: " << env.test_sha256 << '\n';
    log_file << "fixture_manifest_sha256: " << env.fixture_manifest_sha256 << '\n';
    log_file << "command_line: " << command_line << '\n';

    std::vector<EvidenceRow> rows;
    bool all_checks = true;

    // 1. A valid MARP-H0 envelope is accepted.
    const std::vector<uint8_t> payload = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', '!'};
    const Envelope valid = make_valid_envelope(payload);
    const std::vector<uint8_t> serialized = serialize_envelope(valid);
    const bool accepted = verify_envelope(serialized);
    rows.push_back(make_row("envelope.valid", "MARP-H0", "valid",
                            sha256_hex(byte_view(serialized)), "accepted",
                            accepted ? "accepted" : "rejected", accepted));
    log_file << "envelope.valid: accepted=" << (accepted ? "YES" : "NO") << '\n';
    all_checks = all_checks && accepted;

    // 2. A deliberately corrupted envelope is rejected.
    std::vector<uint8_t> corrupted = serialized;
    corrupted[16] ^= 0x01u;
    const bool rejected = !verify_envelope(corrupted);
    rows.push_back(make_row("envelope.corrupted", "MARP-H0", "payload-bit-flip",
                            sha256_hex(byte_view(corrupted)), "rejected",
                            rejected ? "rejected" : "accepted", rejected));
    log_file << "envelope.corrupted: rejected=" << (rejected ? "YES" : "NO") << '\n';
    all_checks = all_checks && rejected;

    // 3. A deliberately false gate row must render FAIL. The false row lives in
    //    a scratch TSV; E0-G.tsv itself contains only PASS verdicts.
    const fs::path scratch_dir = fs::temp_directory_path() / "marp_e0_scratch";
    fs::remove_all(scratch_dir, ec);
    fs::create_directories(scratch_dir, ec);
    const fs::path scratch_tsv = scratch_dir / "E0-G.tsv";
    const fs::path scratch_md = scratch_dir / "ACCEPTANCE.md";

    std::vector<EvidenceRow> false_rows;
    false_rows.push_back(make_row("envelope.valid", "MARP-H0", "false-row",
                                  sha256_hex("false-row"), "PASS", "FAIL", false));
    bool false_written = write_evidence_tsv(scratch_tsv, false_rows);

    const bool acceptance_existed = fs::exists(acceptance_path);
    const std::string acceptance_before =
        acceptance_existed ? sha256_file_hex(acceptance_path) : "";

    const int false_render = false_written ? render(scratch_dir, scratch_md) : 1;
    const fs::path scratch_fail = scratch_dir / "ACCEPTANCE.FAIL.md";
    const bool false_rendered =
        false_render != 0 && fs::exists(scratch_fail) &&
        file_contains(scratch_fail, "RESULT: FAIL");

    const bool acceptance_untouched =
        fs::exists(acceptance_path) == acceptance_existed &&
        (!acceptance_existed || sha256_file_hex(acceptance_path) == acceptance_before);
    const bool false_gate_ok = false_written && false_rendered && acceptance_untouched;

    rows.push_back(make_row("false.gate", "MARP-H0", "scratch-tsv",
                            sha256_hex("false-row-rendered"),
                            "RESULT: FAIL",
                            false_rendered ? "RESULT: FAIL" : "not rendered",
                            false_gate_ok));
    log_file << "false.gate: written=" << (false_written ? "YES" : "NO")
             << " rendered=" << (false_rendered ? "YES" : "NO")
             << " acceptance_untouched=" << (acceptance_untouched ? "YES" : "NO") << '\n';
    all_checks = all_checks && false_gate_ok;

    fs::remove_all(scratch_dir, ec);

    // Only PASS verdicts may appear in the committed E0-G evidence.
    if (!write_evidence_tsv(tsv_path, rows)) all_checks = false;

    const std::vector<EvidenceRow> read_back = read_evidence_tsv(tsv_path);
    if (read_back.size() != rows.size()) all_checks = false;
    for (const auto& row : read_back) {
        if (row.verdict != "PASS") all_checks = false;
    }

    const int exit_code = all_checks ? 0 : 1;
    log_file << "RESULT: " << (all_checks ? "PASS" : "FAIL") << '\n';
    log_file << "exit_code: " << exit_code << '\n';
    log_file.close();
    return exit_code;
}

} // namespace marp::harness
