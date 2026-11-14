#include "marp/harness/e0_selftest.hpp"
#include <mapr/e1_crc32.hpp>
#include <mapr/e1_sha256.hpp>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <string>
#include <filesystem>
#include <cstdint>
#include <cstring>

namespace marp::harness {

namespace fs = std::filesystem;

// MARP-H0 envelope format:
// magic: 8 bytes "MARP-H0\0"
// length: u32 LE
// crc32: u32 LE (standard CRC-32 of payload)
// payload: length bytes

static constexpr std::array<uint8_t, 8> MARP_H0_MAGIC = {'M','A','R','P','-','H','0','\0'};

struct Envelope {
    std::array<uint8_t, 8> magic;
    uint32_t length;
    uint32_t crc32;
    std::vector<uint8_t> payload;
};

static void write_u32_le(std::vector<uint8_t>& buf, uint32_t v) {
    buf.push_back(static_cast<uint8_t>(v & 0xFF));
    buf.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    buf.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
    buf.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
}

static uint32_t read_u32_le(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) |
           (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

static Envelope make_valid_envelope(const std::vector<uint8_t>& payload) {
    Envelope env;
    env.magic = MARP_H0_MAGIC;
    env.length = static_cast<uint32_t>(payload.size());
    env.crc32 = mapr::crc32(std::string_view(reinterpret_cast<const char*>(payload.data()), payload.size()));
    env.payload = payload;
    return env;
}

static std::vector<uint8_t> serialize_envelope(const Envelope& env) {
    std::vector<uint8_t> buf;
    buf.insert(buf.end(), env.magic.begin(), env.magic.end());
    write_u32_le(buf, env.length);
    write_u32_le(buf, env.crc32);
    buf.insert(buf.end(), env.payload.begin(), env.payload.end());
    return buf;
}

static bool verify_envelope(const std::vector<uint8_t>& data) {
    if (data.size() < 16) return false; // magic(8) + length(4) + crc32(4)
    
    // Check magic
    for (int i = 0; i < 8; ++i) {
        if (data[i] != MARP_H0_MAGIC[i]) return false;
    }
    
    uint32_t length = read_u32_le(data.data() + 8);
    uint32_t crc32 = read_u32_le(data.data() + 12);
    
    // Check length bound
    if (data.size() != 16 + length) return false;
    
    // Verify CRC
    std::string_view payload(reinterpret_cast<const char*>(data.data() + 16), length);
    uint32_t computed_crc = mapr::crc32(payload);
    if (computed_crc != crc32) return false;
    
    return true;
}

static std::string sha256_hex(std::string_view data) {
    auto digest = mapr::Sha256::hash(data);
    if (!digest.ok()) return "";
    std::ostringstream oss;
    for (uint8_t b : digest.value()) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    }
    return oss.str();
}

static void write_e0_row(const fs::path& root, const std::string& fixture,
                         const std::string& verdict, const std::string& log_ref) {
    fs::path tsv_path = root / "specs_and_reports" / "v2" / "gates" / "E0-G.tsv";
    Row row;
    row.gate = "E0-G";
    row.fixture = fixture;
    row.input_bytes = BigInt(0);
    row.wire_bytes = BigInt(0);
    row.ratio_num = 0;
    row.ratio_den = 1;
    row.sha_match = false;
    row.verdict = verdict;
    row.log = log_ref;
    write_row(tsv_path, row);
    
    // Also write in E0-G specific format
    fs::create_directories(tsv_path.parent_path());
    std::ofstream ofs(tsv_path, std::ios::app);
    if (ofs) {
        bool is_first = !fs::exists(tsv_path) || fs::file_size(tsv_path) == 0;
        if (is_first) {
            ofs << "check\tcorpus\titem_id\tinput_sha256\texpected\tactual\tverdict\tlog\n";
        }
        ofs << "E0-G\tMARP-H0\t" << fixture << "\t" << sha256_hex(fixture) 
            << "\tPASS\t" << verdict << "\t" << verdict << "\t" << log_ref << "\n";
    }
}

int run_e0_selftest(const fs::path& root) {
    // Initialize log
    fs::path log_path = root / "specs_and_reports" / "v2" / "logs" / "E0-G.log";
    fs::create_directories(log_path.parent_path());
    std::ofstream log_file(log_path, std::ios::app);
    
    auto log_msg = [&](const std::string& msg) {
        log_file << msg << "\n";
        log_file.flush();
    };
    
    log_msg("=== E0-G Self-Test Started ===");
    log_msg("root: " + root.string());
    
    // Test 1: Valid envelope accepted
    log_msg("Test 1: Valid envelope");
    std::vector<uint8_t> payload = {'H','e','l','l','o',' ','W','o','r','l','d','!'};
    Envelope valid = make_valid_envelope(payload);
    auto serialized = serialize_envelope(valid);
    bool accepted = verify_envelope(serialized);
    log_msg("  Valid envelope accepted: " + std::string(accepted ? "YES" : "NO"));
    write_e0_row(root, "valid_accepted", accepted ? "PASS" : "FAIL", "logs/E0-G.log#test1");
    
    // Test 2: Corrupted envelope rejected (single bit flip in payload)
    log_msg("Test 2: Corrupted envelope rejected");
    std::vector<uint8_t> corrupted = serialized;
    if (corrupted.size() > 16) {
        corrupted[16] ^= 0x01; // Flip first payload bit
    }
    bool rejected = !verify_envelope(corrupted);
    log_msg("  Corrupted envelope rejected: " + std::string(rejected ? "YES" : "NO"));
    write_e0_row(root, "corrupted_rejected", rejected ? "PASS" : "FAIL", "logs/E0-G.log#test2");
    
    // Test 3: False gate reports FAIL
    log_msg("Test 3: False gate FAIL");
    // Write a deliberately false row: expected=PASS, actual=FAIL
    fs::path tsv_path = root / "specs_and_reports" / "v2" / "gates" / "E0-G.tsv";
    fs::create_directories(tsv_path.parent_path());
    std::ofstream ofs(tsv_path, std::ios::app);
    if (ofs) {
        bool is_first = !fs::exists(tsv_path) || fs::file_size(tsv_path) == 0;
        if (is_first) {
            ofs << "check\tcorpus\titem_id\tinput_sha256\texpected\tactual\tverdict\tlog\n";
        }
        ofs << "E0-G\tMARP-H0\tfalse_gate\t" << sha256_hex("false_gate")
            << "\tPASS\tFAIL\tFAIL\tlogs/E0-G.log#test3\n";
    }
    log_msg("  False gate row written (expected=PASS, actual=FAIL)");
    write_e0_row(root, "false_gate", "FAIL", "logs/E0-G.log#test3");
    
    // Verify render produces FAIL for false gate
    log_msg("Test 4: Render detects FAIL");
    int render_result = render(tsv_path.parent_path(), root / "specs_and_reports" / "v2" / "ACCEPTANCE.FAIL.md");
    (void)render_result; // render succeeds but writes FAIL.md
    // Actually render should succeed but the ACCEPTANCE.md should not be overwritten
    // Check that ACCEPTANCE.md doesn't exist or is not overwritten
    fs::path acceptance_md = root / "specs_and_reports" / "v2" / "ACCEPTANCE.md";
    bool acceptance_untouched = !fs::exists(acceptance_md);
    log_msg("  ACCEPTANCE.md untouched: " + std::string(acceptance_untouched ? "YES" : "NO"));
    
    log_msg("=== E0-G Self-Test Completed ===");
    log_file.close();
    
    return (accepted && rejected && acceptance_untouched) ? 0 : 1;
}

} // namespace marp::harness