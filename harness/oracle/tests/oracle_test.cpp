#include "marp/oracle/oracle.hpp"
#include "wire_builder.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <bit>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <string_view>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

namespace {

using namespace marp::oracle;
using namespace marp::oracle::test_wire;

struct EvidenceRow {
    std::string check;
    std::string corpus;
    std::string item_id;
    std::string input_sha256;
    std::string expected;
    std::string actual;
    std::string verdict; // PASS, FAIL, or BLOCKED
    std::string log;
};

struct EvidenceCollector {
    std::vector<EvidenceRow> rows;
    std::vector<std::string> log_lines;
    std::filesystem::path evidence_root;
    std::filesystem::path oracle_bin;
    bool write_evidence = false;
    bool nm_verified_by_ci = false;
    std::string command_line;
    // F00-F08 cross-check inputs.  `cross_check_dir` holds the wires and the
    // manifest emitted by the E3 side (`bin/h3_f00f08_producer`); this binary
    // only ever reads them as opaque bytes.  Empty means "not supplied".
    std::filesystem::path cross_check_dir;
    std::filesystem::path repo_root{".."};
    std::string cross_check_only;  // optional comma list, e.g. "F00,F01"

    void add_row(std::string check,
                 std::string corpus,
                 std::string item_id,
                 std::string input_sha,
                 std::string expected,
                 std::string actual,
                 std::string verdict,
                 std::string log_ref) {
        rows.push_back(EvidenceRow{
            std::move(check),
            std::move(corpus),
            std::move(item_id),
            std::move(input_sha),
            std::move(expected),
            std::move(actual),
            std::move(verdict),
            std::move(log_ref)});
    }

    void add_log(std::string line) {
        log_lines.push_back(std::move(line));
    }
};

EvidenceCollector& collector() {
    static EvidenceCollector c;
    return c;
}

std::string sha256_of_string(std::string_view s) {
    return sha256_hex(std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(s.data()), s.size()));
}

std::string sha256_of_file(const std::filesystem::path& p) {
    std::ifstream ifs(p, std::ios::binary);
    if (!ifs.is_open()) {
        return "";
    }
    std::vector<std::uint8_t> data(
        (std::istreambuf_iterator<char>(ifs)),
        std::istreambuf_iterator<char>());
    return sha256_hex(data);
}

bool write_bytes_file(const std::filesystem::path& p, std::span<const std::uint8_t> data) {
    std::ofstream ofs(p, std::ios::binary | std::ios::trunc);
    if (!ofs.is_open()) {
        return false;
    }
    if (!data.empty()) {
        ofs.write(reinterpret_cast<const char*>(data.data()),
                  static_cast<std::streamsize>(data.size()));
    }
    ofs.flush();
    return ofs.good();
}

std::vector<std::uint8_t> read_bytes_file(const std::filesystem::path& p) {
    std::ifstream ifs(p, std::ios::binary);
    return std::vector<std::uint8_t>(
        (std::istreambuf_iterator<char>(ifs)),
        std::istreambuf_iterator<char>());
}

int run_process_capture(const std::vector<std::string>& args,
                        std::string& stdout_str,
                        std::string& stderr_str) {
    stdout_str.clear();
    stderr_str.clear();
    int out_pipe[2] = {-1, -1};
    int err_pipe[2] = {-1, -1};
    if (pipe(out_pipe) != 0 || pipe(err_pipe) != 0) {
        return -1;
    }

    const pid_t pid = fork();
    if (pid < 0) {
        close(out_pipe[0]); close(out_pipe[1]);
        close(err_pipe[0]); close(err_pipe[1]);
        return -1;
    }
    if (pid == 0) {
        dup2(out_pipe[1], STDOUT_FILENO);
        dup2(err_pipe[1], STDERR_FILENO);
        close(out_pipe[0]); close(out_pipe[1]);
        close(err_pipe[0]); close(err_pipe[1]);

        std::vector<char*> argv_c;
        argv_c.reserve(args.size() + 1);
        for (const auto& a : args) {
            argv_c.push_back(const_cast<char*>(a.c_str()));
        }
        argv_c.push_back(nullptr);
        execv(argv_c[0], argv_c.data());
        _exit(127);
    }

    close(out_pipe[1]);
    close(err_pipe[1]);

    char buf[4096];
    ssize_t n = 0;
    while ((n = read(out_pipe[0], buf, sizeof(buf))) > 0) {
        stdout_str.append(buf, static_cast<std::size_t>(n));
    }
    while ((n = read(err_pipe[0], buf, sizeof(buf))) > 0) {
        stderr_str.append(buf, static_cast<std::size_t>(n));
    }
    close(out_pipe[0]);
    close(err_pipe[0]);

    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        return -1;
    }
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    return -1;
}

// Reference bit-by-bit LFSR generator for independent test cross-check
std::vector<std::uint8_t> ref_lfsr(std::uint64_t conn, std::uint64_t init, std::size_t n) {
    std::vector<std::uint8_t> out(n, 0);
    std::uint64_t st = init;
    for (std::size_t i = 0; i < n; ++i) {
        std::uint8_t byte = 0;
        for (int bit = 7; bit >= 0; --bit) {
            const std::uint64_t fb = static_cast<std::uint64_t>(std::popcount(st & conn) & 1);
            st = (st >> 1) | (fb << 63);
            byte = static_cast<std::uint8_t>(byte | static_cast<std::uint8_t>(fb << bit));
        }
        out[i] = byte;
    }
    return out;
}

std::uint8_t ref_bitrev8(std::uint8_t b) {
    std::uint8_t r = 0;
    for (int i = 0; i < 8; ++i) {
        r = static_cast<std::uint8_t>((r << 1) | ((b >> i) & 1U));
    }
    return r;
}

// Build a canonical 3-MiB Concat container with valid 2-entry seek index
std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>> make_indexed_3mib_wire(bool with_index) {
    constexpr std::size_t k1MiB = 1048576;
    std::vector<std::uint8_t> a0(k1MiB), a1(k1MiB), a2(k1MiB);
    for (std::size_t i = 0; i < k1MiB; ++i) {
        a0[i] = static_cast<std::uint8_t>((i * 37U + 1U) & 0xFFU);
        a1[i] = static_cast<std::uint8_t>((i * 73U + 2U) & 0xFFU);
        a2[i] = static_cast<std::uint8_t>((i * 113U + 3U) & 0xFFU);
    }

    std::vector<std::uint8_t> expected;
    expected.reserve(3 * k1MiB);
    expected.insert(expected.end(), a0.begin(), a0.end());
    expected.insert(expected.end(), a1.begin(), a1.end());
    expected.insert(expected.end(), a2.begin(), a2.end());

    ContainerSpec s;
    s.total_length = std::to_string(3 * k1MiB);
    s.atoms.push_back(AtomSpec{1, a0});
    s.atoms.push_back(AtomSpec{2, a1});
    s.atoms.push_back(AtomSpec{3, a2});

    NodeSpec n0; n0.kind = 1; n0.atom_id = 0; n0.length = std::to_string(k1MiB);
    NodeSpec n1; n1.kind = 1; n1.atom_id = 1; n1.length = std::to_string(k1MiB);
    NodeSpec n2; n2.kind = 1; n2.atom_id = 2; n2.length = std::to_string(k1MiB);
    NodeSpec n3; n3.kind = 3; n3.args = {0, 1, 2}; n3.length = std::to_string(3 * k1MiB);
    s.nodes = {n0, n1, n2, n3};

    if (with_index) {
        const std::uint32_t crc1 = crc32_bytes(std::span<const std::uint8_t>(expected.data(), k1MiB));
        const std::uint32_t crc2 = crc32_bytes(std::span<const std::uint8_t>(expected.data(), 2 * k1MiB));
        s.index_entries.push_back(IndexEntrySpec{std::to_string(k1MiB), 1U, crc1});
        s.index_entries.push_back(IndexEntrySpec{std::to_string(2 * k1MiB), 2U, crc2});
    }

    return {build_wire(s), expected};
}

// =========================================================================
// 1. Published SHA-256 and CRC-32 self-vectors
// =========================================================================
TEST(OracleDigestVectors, PublishedSha256AndCrc32) {
    bool all_ok = true;

    // FIPS 180-4 SHA-256 KATs
    const std::string sha_empty = sha256_of_string("");
    EXPECT_EQ(sha_empty, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    all_ok &= (sha_empty == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    const std::string sha_abc = sha256_of_string("abc");
    EXPECT_EQ(sha_abc, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    all_ok &= (sha_abc == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    const std::string sha_448 = sha256_of_string(
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
    EXPECT_EQ(sha_448, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    all_ok &= (sha_448 == "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");

    const std::vector<std::uint8_t> million_a(1000000, static_cast<std::uint8_t>('a'));
    const std::string sha_1m = sha256_hex(million_a);
    EXPECT_EQ(sha_1m, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
    all_ok &= (sha_1m == "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");

    // IEEE 802.3 CRC-32 KATs
    const std::uint32_t crc_empty = crc32_bytes({});
    EXPECT_EQ(crc_empty, 0x00000000U);
    all_ok &= (crc_empty == 0x00000000U);

    const std::string check_str = "123456789";
    const std::uint32_t crc_check = crc32_bytes(std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(check_str.data()), check_str.size()));
    EXPECT_EQ(crc_check, 0xCBF43926U);
    all_ok &= (crc_check == 0xCBF43926U);

    const std::array<std::uint8_t, 32> zeros{};
    const std::uint32_t crc_z32 = crc32_bytes(zeros);
    EXPECT_EQ(crc_z32, 0x190A55ADU);
    all_ok &= (crc_z32 == 0x190A55ADU);

    std::array<std::uint8_t, 32> ones{};
    ones.fill(0xFFU);
    const std::uint32_t crc_ff32 = crc32_bytes(ones);
    EXPECT_EQ(crc_ff32, 0xFF6CAB0BU);
    all_ok &= (crc_ff32 == 0xFF6CAB0BU);

    collector().add_row(
        "digest.vectors", "ORACLE", "sha256-crc32-kat",
        sha_abc, "8/8 published KATs match", all_ok ? "8/8 published KATs match" : "mismatch",
        all_ok ? "PASS" : "FAIL", "logs/H3-ORACLE.log#digest.vectors");
    collector().add_log("digest.vectors: sha256_kats=4 crc32_kats=4 status=" +
                        std::string(all_ok ? "PASS" : "FAIL"));
}

// =========================================================================
// 2. Pinned hand-assembled hex vectors + Header/Stage-order validation
// =========================================================================
TEST(OracleWireHeader, PinnedHexAndHeaderValidation) {
    // Hand-assembled canonical Empty wire (103 bytes) per SPECS-V2 §5 & E3 §4:
    // Header (64 B):
    //   0..7:   89 4D 41 50 52 32 0D 0A ("\x89MAPR2\r\n")
    //   8..9:   02 00 (major=2)
    //  10..11:  00 00 (minor=0)
    //  12..15:  0E 00 00 00 (flags = canonical(2)|u64len(4)|byte_aligned(8) = 0x0E)
    //  16..17:  40 00 (header_bytes=64)
    //  18..25:  00..00 (total_length_u64=0)
    //  26..27:  00 00 (total_length_big_len=0)
    //  28..35:  40 00..00 (atom_offset=64)
    //  36..43:  41 00..00 (node_offset=65)
    //  44..51:  00..00 (index_offset=0)
    //  52..59:  47 00..00 (trailer_offset=71)
    //  60..63:  file_crc32 (computed over bytes 0..70 with 60..63 zeroed)
    // Atom table [64..65): 00 (atom_count=0)
    // Node table [65..71): 01 (node_count=1) 00(Empty) 00(flags) 00 00(argc=0) 00(len=0)
    // Trailer [71..103):
    //  71..78:  54 52 4C 52 32 0D 0A 1A ("TRLR2\r\n\x1a")
    //  79..86:  67 00..00 (file_bytes=103)
    //  87..90:  00 00 00 00 (root_id=0)
    //  91..94:  00 00 00 00 (atom_count=0)
    //  95..98:  01 00 00 00 (node_count=1)
    //  99..102: trailer_crc32
    std::vector<std::uint8_t> pinned_empty = {
        0x89, 0x4D, 0x41, 0x50, 0x52, 0x32, 0x0D, 0x0A,
        0x02, 0x00, 0x00, 0x00, 0x0E, 0x00, 0x00, 0x00,
        0x40, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x47, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        // Atom table (1 byte)
        0x00,
        // Node table (6 bytes)
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        // Trailer (32 bytes)
        0x54, 0x52, 0x4C, 0x52, 0x32, 0x0D, 0x0A, 0x1A,
        0x67, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };
    ASSERT_EQ(pinned_empty.size(), 103U);
    const std::uint32_t fcrc = crc32_bytes(std::span<const std::uint8_t>(pinned_empty.data(), 71));
    write_le32_at(pinned_empty, 60, fcrc);
    std::array<std::uint8_t, 32> tcrc_in{};
    std::memcpy(tcrc_in.data(), pinned_empty.data() + 71, 28);
    tcrc_in[28] = static_cast<std::uint8_t>(fcrc & 0xFFU);
    tcrc_in[29] = static_cast<std::uint8_t>((fcrc >> 8) & 0xFFU);
    tcrc_in[30] = static_cast<std::uint8_t>((fcrc >> 16) & 0xFFU);
    tcrc_in[31] = static_cast<std::uint8_t>((fcrc >> 24) & 0xFFU);
    const std::uint32_t tcrc = crc32_bytes(tcrc_in);
    write_le32_at(pinned_empty, 99, tcrc);

    // Must match test-only builder byte-for-byte
    const auto built_empty = make_empty_wire();
    ASSERT_EQ(pinned_empty, built_empty);

    // Decode pinned vector
    std::vector<std::uint8_t> decoded;
    Info info;
    Diagnostic diag;
    ASSERT_EQ(decode_bytes(pinned_empty, decoded, &info, &diag), 0);
    EXPECT_TRUE(decoded.empty());
    EXPECT_EQ(info.file_bytes, 103ULL);
    EXPECT_EQ(info.node_count, 1U);
    EXPECT_EQ(info.atom_count, 0U);
    EXPECT_EQ(info.root_id, 0U);
    EXPECT_EQ(info.total_length, "0");
    EXPECT_EQ(info.output_sha256,
              "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    EXPECT_FALSE(info.has_index);

    // Pinned 1-byte atom (0xA5)
    const std::array<std::uint8_t, 1> one_byte = {0xA5U};
    const auto one_wire = make_atom_wire(one_byte, 0);
    ASSERT_EQ(decode_bytes(one_wire, decoded, &info, &diag), 0);
    ASSERT_EQ(decoded.size(), 1U);
    EXPECT_EQ(decoded[0], 0xA5U);

    // Hand-assembled pinned hex vector for Zero(2^64) with Region A.1 + BigInt tag 0x02 (139 bytes)
    {
        std::vector<std::uint8_t> pinned_z64 = {
            // Header (64 B): flags=0x0A (canonical|byte_aligned, bit2=0 big total_len)
            0x89, 0x4D, 0x41, 0x50, 0x52, 0x32, 0x0D, 0x0A,
            0x02, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00,
            0x40, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // total_length_u64 = 0
            0x09, 0x00,                                     // total_length_big_len = 9
            0x49, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // atom_offset = 73
            0x4A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // node_offset = 74
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // index_offset = 0
            0x6B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // trailer_offset = 107
            0x00, 0x00, 0x00, 0x00,                         // file_crc32 placeholder
            // Region A.1 (9 B): 2^64 in LE
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            // Region B (1 B): atom_count = 0
            0x00,
            // Region C (33 B): node_count=1, kind=Zero(2), flags=0, argc=0, n=2^64, len=2^64
            0x01, 0x02, 0x00, 0x00, 0x00,
            0x02, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x02, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            // Region E: Trailer (32 B)
            0x54, 0x52, 0x4C, 0x52, 0x32, 0x0D, 0x0A, 0x1A,
            0x8B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // file_bytes = 139
            0x00, 0x00, 0x00, 0x00,                         // root_id = 0
            0x00, 0x00, 0x00, 0x00,                         // atom_count = 0
            0x01, 0x00, 0x00, 0x00,                         // node_count = 1
            0x00, 0x00, 0x00, 0x00                          // trailer_crc32 placeholder
        };
        ASSERT_EQ(pinned_z64.size(), 139U);
        recompute_outer_crcs(pinned_z64);
        ASSERT_EQ(pinned_z64, make_zero_wire("18446744073709551616"));
        Info zi;
        Diagnostic zd;
        ASSERT_EQ(validate_bytes(pinned_z64, true, &zi, &zd), 0) << zd.message;
        EXPECT_EQ(zi.total_length, "18446744073709551616");
        std::vector<std::uint8_t> ztail;
        ASSERT_EQ(decode_range_bytes(pinned_z64, "18446744073709551600", "16", ztail, &zd), 0);
        EXPECT_EQ(ztail, std::vector<std::uint8_t>(16, 0x00U));
        EXPECT_EQ(validate_bytes(pinned_z64, false, nullptr, &zd), 7);
    }

    int checks_passed = 0;
    int checks_total = 0;
    auto expect_reject = [&](const std::vector<std::uint8_t>& w,
                             int expected_code,
                             ValidationStage expected_stage) {
        ++checks_total;
        Diagnostic d;
        const int rc = validate_bytes(w, false, nullptr, &d);
        EXPECT_EQ(rc, expected_code) << "stage=" << stage_name(d.stage) << " msg=" << d.message;
        EXPECT_EQ(d.stage, expected_stage) << "msg=" << d.message;
        if (rc == expected_code && d.stage == expected_stage) {
            ++checks_passed;
        }
    };

    // Stage 1: Size < 96
    expect_reject({}, 4, ValidationStage::Size);
    expect_reject(std::vector<std::uint8_t>(95, 0), 4, ValidationStage::Size);

    // Stage 2: Header magic, version, header_bytes, flags
    {
        auto w = pinned_empty;
        w[0] = 0x00; // bad magic (plus corrupt trailer to prove Stage 2 stops first)
        w[71] = 0x00;
        expect_reject(w, 4, ValidationStage::Header);
    }
    {
        // v1 magic must be rejected as Invalid (4)
        auto w = pinned_empty;
        const char v1m[8] = {'M','A','P','R','\x01','\x00','\x00','\x00'};
        std::memcpy(w.data(), v1m, 8);
        expect_reject(w, 4, ValidationStage::Header);
    }
    {
        // version_major = 1 -> Invalid (4)
        auto w = pinned_empty;
        write_le16_at(w, 8, 1U);
        recompute_outer_crcs(w);
        expect_reject(w, 4, ValidationStage::Header);
    }
    {
        // version_minor = 1 (2.1 future) -> Unsupported (5)
        auto w = pinned_empty;
        write_le16_at(w, 10, 1U);
        recompute_outer_crcs(w);
        expect_reject(w, 5, ValidationStage::Header);
    }
    {
        // version_major = 3 (3.0 future) -> Unsupported (5)
        auto w = pinned_empty;
        write_le16_at(w, 8, 3U);
        recompute_outer_crcs(w);
        expect_reject(w, 5, ValidationStage::Header);
    }
    {
        // header_bytes != 64
        auto w = pinned_empty;
        write_le16_at(w, 16, 65U);
        recompute_outer_crcs(w);
        expect_reject(w, 4, ValidationStage::Header);
    }
    {
        // reserved flag bit 4 set
        auto w = pinned_empty;
        write_le32_at(w, 12, 0x1EU);
        recompute_outer_crcs(w);
        expect_reject(w, 4, ValidationStage::Header);
    }
    {
        // canonical bit 1 clear
        auto w = pinned_empty;
        write_le32_at(w, 12, 0x0CU);
        recompute_outer_crcs(w);
        expect_reject(w, 4, ValidationStage::Header);
    }
    {
        // byte-aligned bit 3 clear
        auto w = pinned_empty;
        write_le32_at(w, 12, 0x06U);
        recompute_outer_crcs(w);
        expect_reject(w, 4, ValidationStage::Header);
    }

    // Stage 3: Bounds (trailer_offset and file_bytes)
    {
        auto w = pinned_empty;
        write_le64_at(w, 52, 70ULL); // wrong trailer_offset
        expect_reject(w, 4, ValidationStage::Bounds);
    }
    {
        auto w = pinned_empty;
        write_le64_at(w, 52, 0xFFFFFFFFFFFFFFF0ULL); // overflow guard
        expect_reject(w, 4, ValidationStage::Bounds);
    }
    {
        auto w = pinned_empty;
        write_le64_at(w, 79, 104ULL); // wrong trailer.file_bytes
        expect_reject(w, 4, ValidationStage::Bounds);
    }

    // Stage 4: Header CRC (without recomputing CRC, plus bad trailer magic to prove Stage 4 runs before Stage 5)
    {
        auto w = pinned_empty;
        w[64] ^= 0x01U;
        w[71] ^= 0xFFU;
        expect_reject(w, 4, ValidationStage::HeaderCrc);
    }

    // Stage 6: Regions & total_length canonicality
    {
        // Flag bit 2 set (u64 len) but big_len = 9
        auto w = pinned_empty;
        write_le16_at(w, 26, 9U);
        recompute_outer_crcs(w);
        expect_reject(w, 4, ValidationStage::Regions);
    }
    {
        // Flag bit 2 clear (big len) but big_len = 8 (fits in u64!)
        std::vector<std::uint8_t> mag(8, 0xFFU);
        std::vector<std::uint8_t> atom_bin = {0x00};
        std::vector<std::uint8_t> node_bin = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00};
        auto w = assemble_raw("0", atom_bin, node_bin, {}, 0, 1, 0);
        // Inject 8-byte Region A.1 manually
        w.insert(w.begin() + 64, mag.begin(), mag.end());
        write_le32_at(w, 12, 0x0AU); // bit 2 clear
        write_le64_at(w, 18, 0ULL);
        write_le16_at(w, 26, 8U);
        write_le64_at(w, 28, 72ULL);
        write_le64_at(w, 36, 73ULL);
        write_le64_at(w, 52, 79ULL);
        write_le64_at(w, 79 + 8, w.size());
        recompute_outer_crcs(w);
        expect_reject(w, 4, ValidationStage::Regions);
    }
    {
        // Region A.1 with leading zero MSB (10 bytes, last byte 0x00)
        auto w = make_zero_wire("18446744073709551616"); // 2^64 (9 bytes in A.1)
        w.insert(w.begin() + 64 + 9, 0x00U); // now 10 bytes, MSB == 0
        write_le16_at(w, 26, 10U);
        write_le64_at(w, 28, read_le64_at(w, 28) + 1);
        write_le64_at(w, 36, read_le64_at(w, 36) + 1);
        write_le64_at(w, 52, read_le64_at(w, 52) + 1);
        write_le64_at(w, w.size() - 32 + 8, w.size());
        recompute_outer_crcs(w);
        expect_reject(w, 4, ValidationStage::Regions);
    }
    {
        // atom_offset != 64 + big_len
        auto w = pinned_empty;
        write_le64_at(w, 28, 65ULL);
        recompute_outer_crcs(w);
        expect_reject(w, 4, ValidationStage::Regions);
    }
    {
        // node_offset < atom_offset
        auto w = pinned_empty;
        write_le64_at(w, 36, 63ULL);
        recompute_outer_crcs(w);
        expect_reject(w, 4, ValidationStage::Regions);
    }
    {
        // index flag clear but index_offset != 0
        auto w = pinned_empty;
        write_le64_at(w, 44, 70ULL);
        recompute_outer_crcs(w);
        expect_reject(w, 4, ValidationStage::Regions);
    }
    {
        // index flag set but index_offset == 0
        auto w = pinned_empty;
        write_le32_at(w, 12, 0x0FU);
        recompute_outer_crcs(w);
        expect_reject(w, 4, ValidationStage::Regions);
    }

    const bool ok = (checks_passed == checks_total);
    collector().add_row(
        "wire.header", "ORACLE", "stages-1-2-3-4-6-pinned",
        sha256_hex(pinned_empty),
        std::to_string(checks_total) + "/" + std::to_string(checks_total) + " passed",
        std::to_string(checks_passed) + "/" + std::to_string(checks_total) + " passed",
        ok ? "PASS" : "FAIL", "logs/H3-ORACLE.log#wire.header");
    collector().add_log("wire.header: passed=" + std::to_string(checks_passed) +
                        "/" + std::to_string(checks_total));
}

// =========================================================================
// 3. Canonical integer codecs (uvarint & bigint, E3 §4.9)
// =========================================================================
TEST(OracleWireBigInt, CanonicalAndNonCanonicalIntegers) {
    int passed = 0;
    int total = 0;

    // Valid canonical bigints: tag 0 (0), tag 1 (1, 127, 128, 2^63-1, 2^63, 2^64-1),
    // tag 2 (2^64, 2^128) — verified via structure_only on Zero(n)
    const std::vector<std::string> valid_lens = {
        "0", "1", "127", "128", "16383", "16384",
        "9223372036854775807",        // 2^63 - 1
        "9223372036854775808",        // 2^63
        "18446744073709551615",       // 2^64 - 1
        "18446744073709551616",       // 2^64 (Region A.1 + tag 0x02 len=9)
        "340282366920938463463374607431768211456" // 2^128 (tag 0x02 len=17)
    };
    for (const auto& dec : valid_lens) {
        ++total;
        const auto w = make_zero_wire(dec);
        Info info;
        Diagnostic d;
        const int rc = validate_bytes(w, true, &info, &d);
        EXPECT_EQ(rc, 0) << "dec=" << dec << " msg=" << d.message;
        EXPECT_EQ(info.total_length, dec);
        if (rc == 0 && info.total_length == dec) {
            ++passed;
        }
    }

    auto make_node_with_raw_zero_n = [](const std::vector<std::uint8_t>& raw_n_bigint,
                                        std::string_view total_dec) {
        std::vector<std::uint8_t> atom_bin = {0x00};
        std::vector<std::uint8_t> node_bin;
        put_uvarint(node_bin, 1U);
        put_u8(node_bin, 2U); // Zero
        put_u8(node_bin, 0U);
        put_le16(node_bin, 0U);
        node_bin.insert(node_bin.end(), raw_n_bigint.begin(), raw_n_bigint.end());
        put_bigint_dec(node_bin, total_dec);
        return assemble_raw(total_dec, atom_bin, node_bin, {}, 0, 1, 0);
    };

    auto expect_bad_node = [&](const std::vector<std::uint8_t>& w, const char* label) {
        ++total;
        Diagnostic d;
        const int rc = validate_bytes(w, true, nullptr, &d);
        EXPECT_EQ(rc, 4) << label << " got rc=" << rc << " stage=" << stage_name(d.stage);
        EXPECT_EQ(d.stage, ValidationStage::Nodes) << label;
        if (rc == 4 && d.stage == ValidationStage::Nodes) {
            ++passed;
        }
    };

    // Non-canonical bigints per E3 §4.9:
    // 1) Tag 0x01 with v = 0 (must use 0x00)
    expect_bad_node(make_node_with_raw_zero_n({0x01, 0x00}, "0"), "tag1_zero");
    // 2) Tag 0x01 with overlong uvarint (1 encoded as 81 00)
    expect_bad_node(make_node_with_raw_zero_n({0x01, 0x81, 0x00}, "1"), "tag1_overlong_uvarint");
    // 3) Tag 0x01 with 10-byte uvarint ending in 0x00
    expect_bad_node(make_node_with_raw_zero_n(
        {0x01, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00}, "0"), "uvarint_10b_zero");
    // 4) Tag 0x01 with 10-byte uvarint overflow (10th byte = 0x02)
    expect_bad_node(make_node_with_raw_zero_n(
        {0x01, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02}, "0"), "uvarint_10b_overflow");
    // 5) Tag 0x01 with 11-byte uvarint
    expect_bad_node(make_node_with_raw_zero_n(
        {0x01, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x81, 0x01}, "0"), "uvarint_11b");
    // 6) Tag 0x02 with len = 0
    expect_bad_node(make_node_with_raw_zero_n({0x02, 0x00, 0x00, 0x00, 0x00}, "0"), "tag2_len0");
    // 7) Tag 0x02 with len = 1 (value < 2^64)
    expect_bad_node(make_node_with_raw_zero_n({0x02, 0x01, 0x00, 0x00, 0x00, 0x05}, "5"), "tag2_len1");
    // 8) Tag 0x02 with len = 8 (value = 2^64 - 1 < 2^64)
    expect_bad_node(make_node_with_raw_zero_n(
        {0x02, 0x08, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
        "18446744073709551615"), "tag2_len8");
    // 9) Tag 0x02 with len = 9 and leading-zero MSB (all zeros)
    expect_bad_node(make_node_with_raw_zero_n(
        {0x02, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
        "0"), "tag2_len9_zero_msb");
    // 10) Tag 0x02 with len = 10 and trailing 0x00 MSB
    expect_bad_node(make_node_with_raw_zero_n(
        {0x02, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00},
        "18446744073709551616"), "tag2_len10_zero_msb");
    // 11) Tag 0x02 with absurd len = 0xFFFFFFFF (no huge allocation!)
    expect_bad_node(make_node_with_raw_zero_n(
        {0x02, 0xFF, 0xFF, 0xFF, 0xFF, 0x01}, "1"), "tag2_absurd_len");
    // 12) Unknown tag 0x03
    expect_bad_node(make_node_with_raw_zero_n({0x03, 0x01}, "1"), "tag3_unknown");

    // Non-canonical uvarint in atom_count (80 00 = overlong 0)
    {
        ++total;
        std::vector<std::uint8_t> atom_bin = {0x80, 0x00};
        std::vector<std::uint8_t> node_bin = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00};
        auto w = assemble_raw("0", atom_bin, node_bin, {}, 0, 1, 0);
        Diagnostic d;
        const int rc = validate_bytes(w, true, nullptr, &d);
        EXPECT_EQ(rc, 4);
        EXPECT_EQ(d.stage, ValidationStage::Atoms);
        if (rc == 4 && d.stage == ValidationStage::Atoms) ++passed;
    }

    const bool ok = (passed == total);
    collector().add_row(
        "wire.bigint", "ORACLE", "canonical-uvarint-bigint",
        sha256_of_string("wire.bigint"),
        std::to_string(total) + "/" + std::to_string(total) + " passed",
        std::to_string(passed) + "/" + std::to_string(total) + " passed",
        ok ? "PASS" : "FAIL", "logs/H3-ORACLE.log#wire.bigint");
    collector().add_log("wire.bigint: passed=" + std::to_string(passed) +
                        "/" + std::to_string(total));
}

// =========================================================================
// 4. Atom table validation (Stage 7 + first-use / dedup / ATOM_MAX)
// =========================================================================
TEST(OracleWireAtoms, AtomTableValidation) {
    int passed = 0;
    int total = 0;

    // Valid: atom at exact ATOM_MAX (1 MiB) and non-zero advisory klass
    {
        ++total;
        std::vector<std::uint8_t> big_atom(1048576);
        for (std::size_t i = 0; i < big_atom.size(); ++i) {
            big_atom[i] = static_cast<std::uint8_t>((i * 17U) & 0xFFU);
        }
        const auto w = make_atom_wire(big_atom, 7U);
        std::vector<std::uint8_t> out;
        Diagnostic d;
        const int rc = decode_bytes(w, out, nullptr, &d);
        EXPECT_EQ(rc, 0) << d.message;
        EXPECT_EQ(out, big_atom);
        if (rc == 0 && out == big_atom) ++passed;
    }

    auto expect_stage = [&](const std::vector<std::uint8_t>& w, ValidationStage st, const char* lbl) {
        ++total;
        Diagnostic d;
        const int rc = validate_bytes(w, true, nullptr, &d);
        EXPECT_EQ(rc, 4) << lbl << " msg=" << d.message;
        EXPECT_EQ(d.stage, st) << lbl << " got " << stage_name(d.stage);
        if (rc == 4 && d.stage == st) ++passed;
    };

    // Atom count mismatch vs trailer
    {
        auto w = make_empty_wire();
        write_le32_at(w, w.size() - 32 + 20, 1U); // trailer atom_count=1, region has 0
        recompute_outer_crcs(w);
        expect_stage(w, ValidationStage::Atoms, "atom_count_mismatch");
    }
    // Nonzero atom flags
    {
        const std::array<std::uint8_t, 2> p = {1, 2};
        auto w = make_atom_wire(p);
        w[64 + 1 + 1] = 0x01U; // atom_count(1) + klass(1) + flags
        recompute_outer_crcs(w);
        expect_stage(w, ValidationStage::Atoms, "atom_nonzero_flags");
    }
    // Nonzero atom reserved
    {
        const std::array<std::uint8_t, 2> p = {1, 2};
        auto w = make_atom_wire(p);
        w[64 + 1 + 2] = 0x01U; // reserved
        recompute_outer_crcs(w);
        expect_stage(w, ValidationStage::Atoms, "atom_nonzero_reserved");
    }
    // Zero-length atom (invalid per E3 §4.5)
    {
        ContainerSpec s;
        s.total_length = "0";
        s.atoms.push_back(AtomSpec{0, {}});
        NodeSpec n; n.kind = 1; n.atom_id = 0; n.length = "0";
        s.nodes.push_back(n);
        expect_stage(build_wire(s), ValidationStage::Atoms, "atom_zero_length");
    }
    // Atom > ATOM_MAX (1 MiB + 1)
    {
        std::vector<std::uint8_t> over(1048577, 0x42U);
        expect_stage(make_atom_wire(over), ValidationStage::Atoms, "atom_over_max");
    }
    // Bad payload SHA-256
    {
        const std::array<std::uint8_t, 4> p = {10, 20, 30, 40};
        auto w = make_atom_wire(p);
        // Corrupt last byte of payload and recompute outer CRCs (so Stage 4 passes, Stage 7 catches SHA mismatch!)
        const std::size_t node_off = static_cast<std::size_t>(read_le64_at(w, 36));
        w[node_off - 1] ^= 0xFFU;
        recompute_outer_crcs(w);
        expect_stage(w, ValidationStage::Atoms, "atom_bad_sha256");
    }
    // Duplicate atom payloads
    {
        ContainerSpec s;
        s.total_length = "6";
        s.atoms.push_back(AtomSpec{0, {1, 2, 3}});
        s.atoms.push_back(AtomSpec{0, {1, 2, 3}});
        NodeSpec n0; n0.kind = 1; n0.atom_id = 0; n0.length = "3";
        NodeSpec n1; n1.kind = 1; n1.atom_id = 1; n1.length = "3";
        NodeSpec n2; n2.kind = 3; n2.args = {0, 1}; n2.length = "6";
        s.nodes = {n0, n1, n2};
        expect_stage(build_wire(s), ValidationStage::Atoms, "atom_duplicate");
    }
    // Trailing garbage byte in atom region
    {
        std::vector<std::uint8_t> atom_bin = {0x00, 0xFF};
        std::vector<std::uint8_t> node_bin = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00};
        auto w = assemble_raw("0", atom_bin, node_bin, {}, 0, 1, 0);
        expect_stage(w, ValidationStage::Atoms, "atom_trailing_bytes");
    }
    // Wrong atom first-use order (Atom(1) used before Atom(0))
    {
        ContainerSpec s;
        s.total_length = "4";
        s.atoms.push_back(AtomSpec{0, {1, 2}});
        s.atoms.push_back(AtomSpec{0, {3, 4}});
        NodeSpec n0; n0.kind = 1; n0.atom_id = 1; n0.length = "2";
        NodeSpec n1; n1.kind = 1; n1.atom_id = 0; n1.length = "2";
        NodeSpec n2; n2.kind = 3; n2.args = {0, 1}; n2.length = "4";
        s.nodes = {n0, n1, n2};
        expect_stage(build_wire(s), ValidationStage::Nodes, "atom_wrong_first_use");
    }
    // Unused atom record
    {
        ContainerSpec s;
        s.total_length = "2";
        s.atoms.push_back(AtomSpec{0, {1, 2}});
        s.atoms.push_back(AtomSpec{0, {3, 4}});
        NodeSpec n0; n0.kind = 1; n0.atom_id = 0; n0.length = "2";
        s.nodes = {n0};
        expect_stage(build_wire(s), ValidationStage::Nodes, "atom_unused");
    }

    const bool ok = (passed == total);
    collector().add_row(
        "wire.atoms", "ORACLE", "atom-table-rules",
        sha256_of_string("wire.atoms"),
        std::to_string(total) + "/" + std::to_string(total) + " passed",
        std::to_string(passed) + "/" + std::to_string(total) + " passed",
        ok ? "PASS" : "FAIL", "logs/H3-ORACLE.log#wire.atoms");
    collector().add_log("wire.atoms: passed=" + std::to_string(passed) +
                        "/" + std::to_string(total));
}

// =========================================================================
// 5. Node table validation (Stage 8) + Trailer/Root validation (Stages 5 & 9)
// =========================================================================
TEST(OracleWireNodesAndTrailer, NodeRulesAndTrailerRoot) {
    int node_passed = 0, node_total = 0;
    auto expect_bad_node = [&](const std::vector<std::uint8_t>& w, const char* lbl) {
        ++node_total;
        Diagnostic d;
        const int rc = validate_bytes(w, true, nullptr, &d);
        EXPECT_EQ(rc, 4) << lbl << " msg=" << d.message;
        EXPECT_EQ(d.stage, ValidationStage::Nodes) << lbl << " got " << stage_name(d.stage);
        if (rc == 4 && d.stage == ValidationStage::Nodes) ++node_passed;
    };

    // Unknown kind 12
    {
        std::vector<std::uint8_t> atom_bin = {0x00};
        std::vector<std::uint8_t> node_bin = {0x01, 12, 0, 0, 0, 0};
        expect_bad_node(assemble_raw("0", atom_bin, node_bin, {}, 0, 1, 0), "unknown_kind");
    }
    // Nonzero node flags
    {
        auto w = make_empty_wire();
        w[65 + 2] = 0x01U;
        recompute_outer_crcs(w);
        expect_bad_node(w, "node_nonzero_flags");
    }
    // Wrong argc for every node kind (0..11)
    {
        ContainerSpec base;
        base.total_length = "2";
        base.atoms = {{0, {1, 2}}};
        NodeSpec a0; a0.kind = 1; a0.atom_id = 0; a0.length = "2";
        // Concat with 1 child
        {
            ContainerSpec s = base;
            NodeSpec n1; n1.kind = 3; n1.args = {0}; n1.length = "2";
            s.nodes = {a0, n1};
            expect_bad_node(build_wire(s), "concat_argc_1");
        }
        // Empty with 1 child
        {
            ContainerSpec s = base;
            NodeSpec n1; n1.kind = 0; n1.args = {0}; n1.length = "0";
            s.nodes = {a0, n1};
            expect_bad_node(build_wire(s), "empty_argc_1");
        }
        // Atom with 1 child
        {
            ContainerSpec s = base;
            NodeSpec n1; n1.kind = 1; n1.args = {0}; n1.atom_id = 0; n1.length = "2";
            s.nodes = {a0, n1};
            expect_bad_node(build_wire(s), "atom_argc_1");
        }
        // Zero with 1 child
        {
            ContainerSpec s = base;
            NodeSpec n1; n1.kind = 2; n1.args = {0}; n1.param_a = "2"; n1.length = "2";
            s.nodes = {a0, n1};
            expect_bad_node(build_wire(s), "zero_argc_1");
        }
        // Repeat with 0 children
        {
            ContainerSpec s; s.total_length = "0";
            NodeSpec n0; n0.kind = 4; n0.param_a = "0"; n0.param_b = "0"; n0.length = "0";
            s.nodes = {n0};
            expect_bad_node(build_wire(s), "repeat_argc_0");
        }
        // Slice with 2 children
        {
            ContainerSpec s = base;
            NodeSpec n1; n1.kind = 5; n1.args = {0, 0}; n1.param_a = "0"; n1.param_b = "2"; n1.length = "2";
            s.nodes = {a0, n1};
            expect_bad_node(build_wire(s), "slice_argc_2");
        }
        // Morph with 0 children
        {
            ContainerSpec s; s.total_length = "0";
            NodeSpec n0; n0.kind = 6; n0.morph = 2; n0.morph_k = 0; n0.length = "0";
            s.nodes = {n0};
            expect_bad_node(build_wire(s), "morph_argc_0");
        }
        // Xor with 1 child
        {
            ContainerSpec s = base;
            NodeSpec n1; n1.kind = 7; n1.args = {0}; n1.length = "2";
            s.nodes = {a0, n1};
            expect_bad_node(build_wire(s), "xor_argc_1");
        }
        // Interleave with 0 children
        {
            ContainerSpec s; s.total_length = "0";
            NodeSpec n0; n0.kind = 8; n0.stride = 1; n0.length = "0";
            s.nodes = {n0};
            expect_bad_node(build_wire(s), "interleave_argc_0");
        }
        // Lfsr with 1 child
        {
            ContainerSpec s = base;
            NodeSpec n1; n1.kind = 9; n1.args = {0}; n1.lfsr_conn = 1; n1.lfsr_init = 1; n1.param_a = "2"; n1.length = "2";
            s.nodes = {a0, n1};
            expect_bad_node(build_wire(s), "lfsr_argc_1");
        }
        // Affine with 1 child
        {
            ContainerSpec s = base;
            NodeSpec n1; n1.kind = 10; n1.args = {0}; n1.affine_start = 0; n1.affine_step = 1; n1.param_a = "2"; n1.length = "2";
            s.nodes = {a0, n1};
            expect_bad_node(build_wire(s), "affine_argc_1");
        }
        // Predictor with 0 children
        {
            ContainerSpec s; s.total_length = "0";
            NodeSpec n0; n0.kind = 11; n0.predictor_id = 0; n0.predictor_param = 0; n0.length = "0";
            s.nodes = {n0};
            expect_bad_node(build_wire(s), "predictor_argc_0");
        }
    }
    // Arg >= current id (self reference)
    {
        ContainerSpec s;
        s.total_length = "0";
        NodeSpec n0; n0.kind = 6; n0.args = {0}; n0.morph = 2; n0.morph_k = 0; n0.length = "0";
        s.nodes = {n0};
        expect_bad_node(build_wire(s), "arg_ge_id");
    }
    // Repeat q=0, r=1 invalid
    {
        ContainerSpec s;
        s.total_length = "1";
        s.atoms.push_back(AtomSpec{0, {1, 2}});
        NodeSpec n0; n0.kind = 1; n0.atom_id = 0; n0.length = "2";
        NodeSpec n1; n1.kind = 4; n1.args = {0}; n1.param_a = "0"; n1.param_b = "1"; n1.length = "1";
        s.nodes = {n0, n1};
        expect_bad_node(build_wire(s), "repeat_q0_r1");
    }
    // Repeat q=2, r=len(child) invalid
    {
        ContainerSpec s;
        s.total_length = "6";
        s.atoms.push_back(AtomSpec{0, {1, 2}});
        NodeSpec n0; n0.kind = 1; n0.atom_id = 0; n0.length = "2";
        NodeSpec n1; n1.kind = 4; n1.args = {0}; n1.param_a = "2"; n1.param_b = "2"; n1.length = "6";
        s.nodes = {n0, n1};
        expect_bad_node(build_wire(s), "repeat_r_ge_child");
    }
    // Slice start + len > child_len
    {
        ContainerSpec s;
        s.total_length = "2";
        s.atoms.push_back(AtomSpec{0, {1, 2, 3}});
        NodeSpec n0; n0.kind = 1; n0.atom_id = 0; n0.length = "3";
        NodeSpec n1; n1.kind = 5; n1.args = {0}; n1.param_a = "2"; n1.param_b = "2"; n1.length = "2";
        s.nodes = {n0, n1};
        expect_bad_node(build_wire(s), "slice_oob");
    }
    // Morph bad id 0 & 10, bad k, bad SWAP16/32/64 multiple
    {
        ContainerSpec s;
        s.total_length = "3";
        s.atoms.push_back(AtomSpec{0, {1, 2, 3}});
        NodeSpec n0; n0.kind = 1; n0.atom_id = 0; n0.length = "3";
        NodeSpec n1; n1.kind = 6; n1.args = {0}; n1.morph = 0; n1.morph_k = 0; n1.length = "3";
        s.nodes = {n0, n1};
        expect_bad_node(build_wire(s), "morph_id_0");
        s.nodes[1].morph = 10;
        expect_bad_node(build_wire(s), "morph_id_10");
        s.nodes[1].morph = 2; s.nodes[1].morph_k = 1;
        expect_bad_node(build_wire(s), "morph_invert_k1");
        s.nodes[1].morph = 6; s.nodes[1].morph_k = 0;
        expect_bad_node(build_wire(s), "morph_rotl_k0");
        s.nodes[1].morph = 7; s.nodes[1].morph_k = 8;
        expect_bad_node(build_wire(s), "morph_rotr_k8");
        s.nodes[1].morph = 3; s.nodes[1].morph_k = 0;
        expect_bad_node(build_wire(s), "morph_swap16_odd");
        s.nodes[1].morph = 4; s.nodes[1].morph_k = 0;
        expect_bad_node(build_wire(s), "morph_swap32_not4");
        s.nodes[1].morph = 5; s.nodes[1].morph_k = 0;
        expect_bad_node(build_wire(s), "morph_swap64_not8");
    }
    // Xor unequal lengths
    {
        ContainerSpec s;
        s.total_length = "2";
        s.atoms.push_back(AtomSpec{0, {1, 2}});
        s.atoms.push_back(AtomSpec{0, {1, 2, 3}});
        NodeSpec n0; n0.kind = 1; n0.atom_id = 0; n0.length = "2";
        NodeSpec n1; n1.kind = 1; n1.atom_id = 1; n1.length = "3";
        NodeSpec n2; n2.kind = 7; n2.args = {0, 1}; n2.length = "2";
        s.nodes = {n0, n1, n2};
        expect_bad_node(build_wire(s), "xor_unequal");
    }
    // Interleave stride=0, unequal lengths, L%stride!=0
    {
        ContainerSpec s;
        s.total_length = "6";
        s.atoms.push_back(AtomSpec{0, {1, 2, 3}});
        s.atoms.push_back(AtomSpec{0, {4, 5, 6}});
        NodeSpec n0; n0.kind = 1; n0.atom_id = 0; n0.length = "3";
        NodeSpec n1; n1.kind = 1; n1.atom_id = 1; n1.length = "3";
        NodeSpec n2; n2.kind = 8; n2.args = {0, 1}; n2.stride = 0; n2.length = "6";
        s.nodes = {n0, n1, n2};
        expect_bad_node(build_wire(s), "interleave_stride0");
        s.nodes[2].stride = 2; // 3 % 2 != 0
        expect_bad_node(build_wire(s), "interleave_not_multiple");
    }
    // LFSR conn == 0
    {
        ContainerSpec s;
        s.total_length = "4";
        NodeSpec n0; n0.kind = 9; n0.lfsr_conn = 0; n0.lfsr_init = 1; n0.param_a = "4"; n0.length = "4";
        s.nodes = {n0};
        expect_bad_node(build_wire(s), "lfsr_conn0");
    }
    // Predictor unknown pid=5, stride param=0, non-stride param=1
    {
        ContainerSpec s;
        s.total_length = "4";
        s.atoms.push_back(AtomSpec{0, {1, 2, 3, 4}});
        NodeSpec n0; n0.kind = 1; n0.atom_id = 0; n0.length = "4";
        NodeSpec n1; n1.kind = 11; n1.args = {0}; n1.predictor_id = 5; n1.predictor_param = 0; n1.length = "4";
        s.nodes = {n0, n1};
        expect_bad_node(build_wire(s), "pred_pid5");
        s.nodes[1].predictor_id = 3; s.nodes[1].predictor_param = 0;
        expect_bad_node(build_wire(s), "pred_stride_param0");
        s.nodes[1].predictor_id = 0; s.nodes[1].predictor_param = 1;
        expect_bad_node(build_wire(s), "pred_delta_param1");
    }
    // Declared node length != recomputed length
    {
        ContainerSpec s;
        s.total_length = "5";
        NodeSpec n0; n0.kind = 2; n0.param_a = "4"; n0.length = "5";
        s.nodes = {n0};
        expect_bad_node(build_wire(s), "node_len_mismatch");
    }
    // Duplicate identical node
    {
        ContainerSpec s;
        s.total_length = "4";
        NodeSpec n0; n0.kind = 2; n0.param_a = "2"; n0.length = "2";
        NodeSpec n1; n1.kind = 2; n1.param_a = "2"; n1.length = "2";
        NodeSpec n2; n2.kind = 3; n2.args = {0, 1}; n2.length = "4";
        s.nodes = {n0, n1, n2};
        expect_bad_node(build_wire(s), "duplicate_node");
    }
    // Non-post-order first-use (Concat(1, 0))
    {
        ContainerSpec s;
        s.total_length = "5";
        NodeSpec n0; n0.kind = 2; n0.param_a = "2"; n0.length = "2";
        NodeSpec n1; n1.kind = 2; n1.param_a = "3"; n1.length = "3";
        NodeSpec n2; n2.kind = 3; n2.args = {1, 0}; n2.length = "5";
        s.nodes = {n0, n1, n2};
        expect_bad_node(build_wire(s), "non_postorder");
    }
    // Unused node
    {
        ContainerSpec s;
        s.total_length = "3";
        NodeSpec n0; n0.kind = 2; n0.param_a = "2"; n0.length = "2";
        NodeSpec n1; n1.kind = 2; n1.param_a = "3"; n1.length = "3";
        s.nodes = {n0, n1};
        expect_bad_node(build_wire(s), "unused_node");
    }

    const bool nodes_ok = (node_passed == node_total);
    collector().add_row(
        "wire.nodes", "ORACLE", "node-table-rules",
        sha256_of_string("wire.nodes"),
        std::to_string(node_total) + "/" + std::to_string(node_total) + " passed",
        std::to_string(node_passed) + "/" + std::to_string(node_total) + " passed",
        nodes_ok ? "PASS" : "FAIL", "logs/H3-ORACLE.log#wire.nodes");
    collector().add_log("wire.nodes: passed=" + std::to_string(node_passed) +
                        "/" + std::to_string(node_total));

    // Trailer (Stage 5) & Root (Stage 9)
    int trl_passed = 0, trl_total = 0;
    auto expect_trl = [&](const std::vector<std::uint8_t>& w, ValidationStage st, const char* lbl) {
        ++trl_total;
        Diagnostic d;
        const int rc = validate_bytes(w, true, nullptr, &d);
        EXPECT_EQ(rc, 4) << lbl << " msg=" << d.message;
        EXPECT_EQ(d.stage, st) << lbl << " got " << stage_name(d.stage);
        if (rc == 4 && d.stage == st) ++trl_passed;
    };

    // Bad trailer magic (Stage 5)
    {
        auto w = make_empty_wire();
        w[w.size() - 32] ^= 0x01U;
        recompute_outer_crcs(w);
        expect_trl(w, ValidationStage::Trailer, "bad_trailer_magic");
    }
    // Bad trailer CRC (Stage 5)
    {
        auto w = make_empty_wire();
        w.back() ^= 0x01U;
        expect_trl(w, ValidationStage::Trailer, "bad_trailer_crc");
    }
    // Trailer node_count = 0 (Stage 5)
    {
        auto w = make_empty_wire();
        write_le32_at(w, w.size() - 32 + 24, 0U);
        recompute_outer_crcs(w);
        expect_trl(w, ValidationStage::Trailer, "trailer_node_count_0");
    }
    // Trailer root_id != node_count - 1 (Stage 9)
    {
        ContainerSpec s;
        s.total_length = "2";
        s.atoms.push_back(AtomSpec{0, {0x11, 0x22}});
        NodeSpec n0; n0.kind = 1; n0.atom_id = 0; n0.length = "2";
        NodeSpec n1; n1.kind = 6; n1.args = {0}; n1.morph = 2; n1.morph_k = 0; n1.length = "2";
        s.nodes = {n0, n1};
        auto w = build_wire(s);
        write_le32_at(w, w.size() - 32 + 16, 0U); // root_id=0 instead of 1
        recompute_outer_crcs(w);
        expect_trl(w, ValidationStage::Root, "root_not_last");
    }
    // Root node length != header total_length (Stage 9)
    {
        auto w = make_zero_wire("10");
        write_le64_at(w, 18, 11ULL); // header claims 11, root Zero(10) has 10
        recompute_outer_crcs(w);
        expect_trl(w, ValidationStage::Root, "root_len_mismatch_total");
    }

    const bool trl_ok = (trl_passed == trl_total);
    collector().add_row(
        "wire.trailer", "ORACLE", "stages-5-9-trailer-root",
        sha256_of_string("wire.trailer"),
        std::to_string(trl_total) + "/" + std::to_string(trl_total) + " passed",
        std::to_string(trl_passed) + "/" + std::to_string(trl_total) + " passed",
        trl_ok ? "PASS" : "FAIL", "logs/H3-ORACLE.log#wire.trailer");
    collector().add_log("wire.trailer: passed=" + std::to_string(trl_passed) +
                        "/" + std::to_string(trl_total));
}

// =========================================================================
// 6. Seek Index validation (Stage 10 & Stage 11 prefix CRC)
// =========================================================================
TEST(OracleWireIndex, SeekIndexAcceptAndReject) {
    int passed = 0, total = 0;

    auto [w_idx, expected] = make_indexed_3mib_wire(true);
    auto [w_noidx, expected2] = make_indexed_3mib_wire(false);
    ASSERT_EQ(expected, expected2);

    // Valid indexed and unindexed wires decode identically
    {
        ++total;
        std::vector<std::uint8_t> d1, d2;
        Info i1, i2;
        Diagnostic diag1, diag2;
        const int r1 = decode_bytes(w_idx, d1, &i1, &diag1);
        const int r2 = decode_bytes(w_noidx, d2, &i2, &diag2);
        EXPECT_EQ(r1, 0) << diag1.message;
        EXPECT_EQ(r2, 0) << diag2.message;
        EXPECT_TRUE(i1.has_index);
        EXPECT_FALSE(i2.has_index);
        EXPECT_EQ(d1, expected);
        EXPECT_EQ(d1, d2);
        EXPECT_EQ(i1.output_sha256, i2.output_sha256);
        if (r1 == 0 && r2 == 0 && i1.has_index && !i2.has_index && d1 == expected && d1 == d2) {
            ++passed;
        }
    }

    const std::size_t idx_off = static_cast<std::size_t>(read_le64_at(w_idx, 44));
    const std::size_t trl_off = static_cast<std::size_t>(read_le64_at(w_idx, 52));

    auto expect_idx_err = [&](std::vector<std::uint8_t> w,
                              bool struct_only,
                              ValidationStage st,
                              const char* lbl) {
        ++total;
        Diagnostic d;
        const int rc = validate_bytes(w, struct_only, nullptr, &d);
        EXPECT_EQ(rc, 4) << lbl << " msg=" << d.message;
        EXPECT_EQ(d.stage, st) << lbl << " got " << stage_name(d.stage);
        if (rc == 4 && d.stage == st) ++passed;
    };

    // Bad index magic (Stage 10)
    {
        auto w = w_idx;
        w[idx_off] ^= 0x01U;
        recompute_outer_crcs(w);
        expect_idx_err(w, true, ValidationStage::Index, "bad_index_magic");
    }
    // Bad index_crc32 (Stage 10)
    {
        auto w = w_idx;
        w[trl_off - 1] ^= 0x01U;
        recompute_outer_crcs(w);
        expect_idx_err(w, true, ValidationStage::Index, "bad_index_crc");
    }
    // Empty index (entry_count == 0) is non-canonical (Stage 10)
    {
        std::vector<std::uint8_t> empty_idx;
        empty_idx.insert(empty_idx.end(), kIdxMagic.begin(), kIdxMagic.end());
        put_le32(empty_idx, 0U);
        put_le32(empty_idx, crc32_bytes(empty_idx));
        auto w = assemble_raw("0", {0x00}, {0x01, 0x00, 0x00, 0x00, 0x00, 0x00}, empty_idx, 0, 1, 0);
        expect_idx_err(w, true, ValidationStage::Index, "empty_index");
    }
    // Unsorted index entries (2 MiB before 1 MiB) (Stage 10)
    {
        constexpr std::size_t k1MiB = 1048576;
        const auto atoms_bin = std::vector<std::uint8_t>(
            w_idx.begin() + 64, w_idx.begin() + static_cast<std::ptrdiff_t>(read_le64_at(w_idx, 36)));
        const auto nodes_bin = std::vector<std::uint8_t>(
            w_idx.begin() + static_cast<std::ptrdiff_t>(read_le64_at(w_idx, 36)),
            w_idx.begin() + static_cast<std::ptrdiff_t>(idx_off));
        const auto bad_idx = encode_index({
            {std::to_string(2 * k1MiB), 2U, 0U},
            {std::to_string(k1MiB), 1U, 0U}
        });
        auto w = assemble_raw(std::to_string(3 * k1MiB), atoms_bin, nodes_bin, bad_idx, 3, 4, 3);
        expect_idx_err(w, true, ValidationStage::Index, "unsorted_index");
    }
    // Non-multiple of INDEX_STRIDE (Stage 10)
    {
        constexpr std::size_t k1MiB = 1048576;
        const auto atoms_bin = std::vector<std::uint8_t>(
            w_idx.begin() + 64, w_idx.begin() + static_cast<std::ptrdiff_t>(read_le64_at(w_idx, 36)));
        const auto nodes_bin = std::vector<std::uint8_t>(
            w_idx.begin() + static_cast<std::ptrdiff_t>(read_le64_at(w_idx, 36)),
            w_idx.begin() + static_cast<std::ptrdiff_t>(idx_off));
        const auto bad_idx = encode_index({{std::to_string(k1MiB + 1), 1U, 0U}});
        auto w = assemble_raw(std::to_string(3 * k1MiB), atoms_bin, nodes_bin, bad_idx, 3, 4, 3);
        expect_idx_err(w, true, ValidationStage::Index, "non_stride_index");
    }
    // Wrong node_id at 1 MiB (claims node 2 instead of node 1) (Stage 10)
    {
        constexpr std::size_t k1MiB = 1048576;
        const auto atoms_bin = std::vector<std::uint8_t>(
            w_idx.begin() + 64, w_idx.begin() + static_cast<std::ptrdiff_t>(read_le64_at(w_idx, 36)));
        const auto nodes_bin = std::vector<std::uint8_t>(
            w_idx.begin() + static_cast<std::ptrdiff_t>(read_le64_at(w_idx, 36)),
            w_idx.begin() + static_cast<std::ptrdiff_t>(idx_off));
        const auto bad_idx = encode_index({{std::to_string(k1MiB), 2U, 0U}});
        auto w = assemble_raw(std::to_string(3 * k1MiB), atoms_bin, nodes_bin, bad_idx, 3, 4, 3);
        expect_idx_err(w, true, ValidationStage::Index, "wrong_index_node_id");
    }
    // Bad crc32_of_prefix: passes Stage 10 structure-only, rejected at Stage 11 full eval!
    {
        constexpr std::size_t k1MiB = 1048576;
        const auto atoms_bin = std::vector<std::uint8_t>(
            w_idx.begin() + 64, w_idx.begin() + static_cast<std::ptrdiff_t>(read_le64_at(w_idx, 36)));
        const auto nodes_bin = std::vector<std::uint8_t>(
            w_idx.begin() + static_cast<std::ptrdiff_t>(read_le64_at(w_idx, 36)),
            w_idx.begin() + static_cast<std::ptrdiff_t>(idx_off));
        const auto bad_idx = encode_index({
            {std::to_string(k1MiB), 1U, 0xDEADBEEFU},
            {std::to_string(2 * k1MiB), 2U, 0xCAFEBABEU}
        });
        auto w = assemble_raw(std::to_string(3 * k1MiB), atoms_bin, nodes_bin, bad_idx, 3, 4, 3);
        expect_idx_err(w, false, ValidationStage::Eval, "bad_prefix_crc");
    }

    const bool ok = (passed == total);
    collector().add_row(
        "wire.index", "ORACLE", "seek-index-3mib",
        sha256_hex(w_idx),
        std::to_string(total) + "/" + std::to_string(total) + " passed",
        std::to_string(passed) + "/" + std::to_string(total) + " passed",
        ok ? "PASS" : "FAIL", "logs/H3-ORACLE.log#wire.index");
    collector().add_log("wire.index: passed=" + std::to_string(passed) +
                        "/" + std::to_string(total));
}

// =========================================================================
// 7. Systematic Mutation Rejection Matrix
// =========================================================================
TEST(OracleWireMutations, SystematicMutationSweep) {
    // Seed container with Atom, Morph, Repeat, Concat
    ContainerSpec s;
    s.total_length = "14";
    s.atoms.push_back(AtomSpec{4, {'A','B','C','D'}});
    NodeSpec n0; n0.kind = 1; n0.atom_id = 0; n0.length = "4";
    NodeSpec n1; n1.kind = 6; n1.args = {0}; n1.morph = 2; n1.morph_k = 0; n1.length = "4";
    NodeSpec n2; n2.kind = 4; n2.args = {1}; n2.param_a = "2"; n2.param_b = "2"; n2.length = "10";
    NodeSpec n3; n3.kind = 3; n3.args = {0, 2}; n3.length = "14";
    s.nodes = {n0, n1, n2, n3};
    const auto base = build_wire(s);

    Diagnostic d0;
    ASSERT_EQ(validate_bytes(base, false, nullptr, &d0), 0) << d0.message;

    int mutants = 0;
    int rejected = 0;

    // 1) Flip EVERY single byte position in the container (100% coverage of every byte!)
    for (std::size_t pos = 0; pos < base.size(); ++pos) {
        auto m = base;
        m[pos] ^= 0x80U;
        ++mutants;
        if (validate_bytes(m, false) != 0) {
            ++rejected;
        }
    }

    // 2) Truncate to every length 0 .. base.size() - 1
    for (std::size_t len = 0; len < base.size(); ++len) {
        std::vector<std::uint8_t> m(base.begin(), base.begin() + static_cast<std::ptrdiff_t>(len));
        ++mutants;
        if (validate_bytes(m, false) != 0) {
            ++rejected;
        }
    }

    // 3) Append trailing bytes
    for (std::size_t extra : {1U, 4U, 32U}) {
        auto m = base;
        m.insert(m.end(), extra, 0x00U);
        ++mutants;
        if (validate_bytes(m, false) != 0) {
            ++rejected;
        }
    }

    EXPECT_EQ(rejected, mutants);
    const bool ok = (rejected == mutants);
    collector().add_row(
        "wire.mutations", "ORACLE", "exhaustive-byte-flip-and-trunc",
        sha256_hex(base),
        std::to_string(mutants) + " rejected / 0 accepted",
        std::to_string(rejected) + " rejected / " + std::to_string(mutants - rejected) + " accepted",
        ok ? "PASS" : "FAIL", "logs/H3-ORACLE.log#wire.mutations");
    collector().add_log("wire.mutations: total=" + std::to_string(mutants) +
                        " rejected=" + std::to_string(rejected) +
                        " accepted_invalid=" + std::to_string(mutants - rejected));
}

// =========================================================================
// 8. Exact Evaluation of All 12 Node Kinds
// =========================================================================
TEST(OracleEvalKinds, AllTwelveNodeKindsExact) {
    int passed = 0, total = 0;
    auto check_eval = [&](const ContainerSpec& s, const std::vector<std::uint8_t>& exp, const char* lbl) {
        ++total;
        const auto w = build_wire(s);
        std::vector<std::uint8_t> got;
        Diagnostic d;
        const int rc = decode_bytes(w, got, nullptr, &d);
        EXPECT_EQ(rc, 0) << lbl << " msg=" << d.message;
        EXPECT_EQ(got, exp) << lbl;
        if (rc == 0 && got == exp) ++passed;
    };

    // Kind 0: Empty
    {
        ContainerSpec s; s.total_length = "0";
        NodeSpec n; n.kind = 0; n.length = "0";
        s.nodes = {n};
        check_eval(s, {}, "Empty");
    }
    // Kind 1: Atom
    {
        ContainerSpec s; s.total_length = "5";
        s.atoms = {{0, {'h','e','l','l','o'}}};
        NodeSpec n; n.kind = 1; n.atom_id = 0; n.length = "5";
        s.nodes = {n};
        check_eval(s, {'h','e','l','l','o'}, "Atom");
    }
    // Kind 2: Zero
    {
        ContainerSpec s; s.total_length = "7";
        NodeSpec n; n.kind = 2; n.param_a = "7"; n.length = "7";
        s.nodes = {n};
        check_eval(s, std::vector<std::uint8_t>(7, 0x00U), "Zero");
    }
    // Kind 3: Concat
    {
        ContainerSpec s; s.total_length = "6";
        s.atoms = {{0, {1, 2}}, {0, {3, 4, 5}}};
        NodeSpec n0; n0.kind = 1; n0.atom_id = 0; n0.length = "2";
        NodeSpec n1; n1.kind = 2; n1.param_a = "1"; n1.length = "1";
        NodeSpec n2; n2.kind = 1; n2.atom_id = 1; n2.length = "3";
        NodeSpec n3; n3.kind = 3; n3.args = {0, 1, 2}; n3.length = "6";
        s.nodes = {n0, n1, n2, n3};
        check_eval(s, {1, 2, 0, 3, 4, 5}, "Concat");
    }
    // Kind 4: Repeat (q=3, r=2)
    {
        ContainerSpec s; s.total_length = "11";
        s.atoms = {{0, {0xA, 0xB, 0xC}}};
        NodeSpec n0; n0.kind = 1; n0.atom_id = 0; n0.length = "3";
        NodeSpec n1; n1.kind = 4; n1.args = {0}; n1.param_a = "3"; n1.param_b = "2"; n1.length = "11";
        s.nodes = {n0, n1};
        check_eval(s, {0xA,0xB,0xC, 0xA,0xB,0xC, 0xA,0xB,0xC, 0xA,0xB}, "Repeat");
    }
    // Kind 5: Slice
    {
        ContainerSpec s; s.total_length = "3";
        s.atoms = {{0, {10, 20, 30, 40, 50}}};
        NodeSpec n0; n0.kind = 1; n0.atom_id = 0; n0.length = "5";
        NodeSpec n1; n1.kind = 5; n1.args = {0}; n1.param_a = "1"; n1.param_b = "3"; n1.length = "3";
        s.nodes = {n0, n1};
        check_eval(s, {20, 30, 40}, "Slice");
    }
    // Kind 6: Morph (INVERT8)
    {
        ContainerSpec s; s.total_length = "3";
        s.atoms = {{0, {0x00, 0x55, 0xFF}}};
        NodeSpec n0; n0.kind = 1; n0.atom_id = 0; n0.length = "3";
        NodeSpec n1; n1.kind = 6; n1.args = {0}; n1.morph = 2; n1.morph_k = 0; n1.length = "3";
        s.nodes = {n0, n1};
        check_eval(s, {0xFF, 0xAA, 0x00}, "Morph");
    }
    // Kind 7: Xor
    {
        ContainerSpec s; s.total_length = "4";
        s.atoms = {{0, {0x12, 0x34, 0x56, 0x78}}, {0, {0xFF, 0x0F, 0xF0, 0xAA}}};
        NodeSpec n0; n0.kind = 1; n0.atom_id = 0; n0.length = "4";
        NodeSpec n1; n1.kind = 1; n1.atom_id = 1; n1.length = "4";
        NodeSpec n2; n2.kind = 7; n2.args = {0, 1}; n2.length = "4";
        s.nodes = {n0, n1, n2};
        check_eval(s, {0xED, 0x3B, 0xA6, 0xD2}, "Xor");
    }
    // Kind 8: Interleave (stride 1, 2, 3)
    {
        ContainerSpec s; s.total_length = "12";
        s.atoms = {{0, {1, 2, 3, 4}}, {0, {11, 12, 13, 14}}, {0, {21, 22, 23, 24}}};
        NodeSpec n0; n0.kind = 1; n0.atom_id = 0; n0.length = "4";
        NodeSpec n1; n1.kind = 1; n1.atom_id = 1; n1.length = "4";
        NodeSpec n2; n2.kind = 1; n2.atom_id = 2; n2.length = "4";
        NodeSpec n3; n3.kind = 8; n3.args = {0, 1, 2}; n3.stride = 2; n3.length = "12";
        s.nodes = {n0, n1, n2, n3};
        check_eval(s, {1,2, 11,12, 21,22, 3,4, 13,14, 23,24}, "Interleave_s2");
    }
    // Kind 9: Lfsr
    {
        const std::uint64_t conn = 0xD800000000000000ULL;
        const std::uint64_t init = 0x0123456789ABCDEFULL;
        ContainerSpec s; s.total_length = "16";
        NodeSpec n; n.kind = 9; n.lfsr_conn = conn; n.lfsr_init = init; n.param_a = "16"; n.length = "16";
        s.nodes = {n};
        check_eval(s, ref_lfsr(conn, init, 16), "Lfsr");
    }
    // Kind 10: Affine (wrap mod 256)
    {
        ContainerSpec s; s.total_length = "6";
        NodeSpec n; n.kind = 10; n.affine_start = 250; n.affine_step = 3; n.param_a = "6"; n.length = "6";
        s.nodes = {n};
        check_eval(s, {250, 253, 0, 3, 6, 9}, "Affine");
    }
    // Kind 11: Predictor (DELTA8)
    {
        ContainerSpec s; s.total_length = "5";
        s.atoms = {{0, {10, 5, 250, 1, 255}}};
        NodeSpec n0; n0.kind = 1; n0.atom_id = 0; n0.length = "5";
        NodeSpec n1; n1.kind = 11; n1.args = {0}; n1.predictor_id = 0; n1.predictor_param = 0; n1.length = "5";
        s.nodes = {n0, n1};
        check_eval(s, {10, 15, 9, 10, 9}, "Predictor");
    }
    // Shared DAG diamond: Concat(A, Xor(A, Morph(A)))
    {
        ContainerSpec s; s.total_length = "8";
        s.atoms = {{0, {0x01, 0x23, 0x45, 0x67}}};
        NodeSpec n0; n0.kind = 1; n0.atom_id = 0; n0.length = "4";
        NodeSpec n1; n1.kind = 6; n1.args = {0}; n1.morph = 2; n1.morph_k = 0; n1.length = "4";
        NodeSpec n2; n2.kind = 7; n2.args = {0, 1}; n2.length = "4";
        NodeSpec n3; n3.kind = 3; n3.args = {0, 2}; n3.length = "8";
        s.nodes = {n0, n1, n2, n3};
        check_eval(s, {0x01, 0x23, 0x45, 0x67, 0xFF, 0xFF, 0xFF, 0xFF}, "SharedDAG");
    }

    const bool ok = (passed == total);
    collector().add_row(
        "eval.kinds", "ORACLE", "all-12-node-kinds",
        sha256_of_string("eval.kinds"),
        std::to_string(total) + "/" + std::to_string(total) + " exact",
        std::to_string(passed) + "/" + std::to_string(total) + " exact",
        ok ? "PASS" : "FAIL", "logs/H3-ORACLE.log#eval.kinds");
    collector().add_log("eval.kinds: passed=" + std::to_string(passed) +
                        "/" + std::to_string(total));
}

// =========================================================================
// 9. All 9 Morphisms (full + unaligned range + involution/composition)
// =========================================================================
TEST(OracleEvalMorph, AllNineMorphismsExact) {
    const std::vector<std::uint8_t> input = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE
    };
    int passed = 0, total = 0;

    auto verify_morph = [&](std::uint8_t m, std::uint8_t k,
                            const std::vector<std::uint8_t>& exp,
                            bool is_involution) {
        ++total;
        ContainerSpec s;
        s.total_length = std::to_string(input.size());
        s.atoms = {{0, input}};
        NodeSpec n0; n0.kind = 1; n0.atom_id = 0; n0.length = s.total_length;
        NodeSpec n1; n1.kind = 6; n1.args = {0}; n1.morph = m; n1.morph_k = k; n1.length = s.total_length;
        s.nodes = {n0, n1};
        const auto w = build_wire(s);

        std::vector<std::uint8_t> got;
        ASSERT_EQ(decode_bytes(w, got), 0);
        bool ok_case = (got == exp);
        EXPECT_EQ(got, exp) << "morph=" << int(m) << " k=" << int(k);

        // Verify unaligned range slices across all offsets/lengths
        for (std::size_t st = 0; st < input.size(); ++st) {
            for (std::size_t ln : {std::size_t(0), std::size_t(1), std::size_t(3), std::size_t(5), input.size() - st}) {
                if (st + ln > input.size()) continue;
                std::vector<std::uint8_t> r_got;
                const int rrc = decode_range_bytes(w, std::to_string(st), std::to_string(ln), r_got);
                const std::vector<std::uint8_t> r_exp(
                    exp.begin() + static_cast<std::ptrdiff_t>(st),
                    exp.begin() + static_cast<std::ptrdiff_t>(st + ln));
                EXPECT_EQ(rrc, 0);
                EXPECT_EQ(r_got, r_exp);
                if (rrc != 0 || r_got != r_exp) ok_case = false;
            }
        }

        // Check involution m(m(x)) == x
        if (is_involution) {
            ContainerSpec s2;
            s2.total_length = std::to_string(input.size());
            s2.atoms = {{0, input}};
            NodeSpec a0; a0.kind = 1; a0.atom_id = 0; a0.length = s2.total_length;
            NodeSpec a1; a1.kind = 6; a1.args = {0}; a1.morph = m; a1.morph_k = 0; a1.length = s2.total_length;
            NodeSpec a2; a2.kind = 6; a2.args = {1}; a2.morph = m; a2.morph_k = 0; a2.length = s2.total_length;
            s2.nodes = {a0, a1, a2};
            std::vector<std::uint8_t> inv_out;
            const int irc = decode_bytes(build_wire(s2), inv_out);
            EXPECT_EQ(irc, 0);
            EXPECT_EQ(inv_out, input);
            if (irc != 0 || inv_out != input) ok_case = false;
        }
        if (ok_case) ++passed;
    };

    // 1: BIT_REVERSE8
    {
        std::vector<std::uint8_t> exp(input.size());
        for (std::size_t i = 0; i < input.size(); ++i) exp[i] = ref_bitrev8(input[i]);
        verify_morph(1, 0, exp, true);
    }
    // 2: INVERT8
    {
        std::vector<std::uint8_t> exp(input.size());
        for (std::size_t i = 0; i < input.size(); ++i) exp[i] = static_cast<std::uint8_t>(~input[i]);
        verify_morph(2, 0, exp, true);
    }
    // 3: SWAP16
    {
        std::vector<std::uint8_t> exp = input;
        for (std::size_t i = 0; i < exp.size(); i += 2) std::swap(exp[i], exp[i + 1]);
        verify_morph(3, 0, exp, true);
    }
    // 4: SWAP32
    {
        std::vector<std::uint8_t> exp = input;
        for (std::size_t i = 0; i < exp.size(); i += 4) std::reverse(exp.begin() + static_cast<std::ptrdiff_t>(i), exp.begin() + static_cast<std::ptrdiff_t>(i + 4));
        verify_morph(4, 0, exp, true);
    }
    // 5: SWAP64
    {
        std::vector<std::uint8_t> exp = input;
        for (std::size_t i = 0; i < exp.size(); i += 8) std::reverse(exp.begin() + static_cast<std::ptrdiff_t>(i), exp.begin() + static_cast<std::ptrdiff_t>(i + 8));
        verify_morph(5, 0, exp, true);
    }
    // 6: ROTL8 (k=1..7)
    for (std::uint8_t k = 1; k <= 7; ++k) {
        std::vector<std::uint8_t> exp(input.size());
        for (std::size_t i = 0; i < input.size(); ++i) {
            exp[i] = static_cast<std::uint8_t>((input[i] << k) | (input[i] >> (8U - k)));
        }
        verify_morph(6, k, exp, false);
    }
    // 7: ROTR8 (k=1..7)
    for (std::uint8_t k = 1; k <= 7; ++k) {
        std::vector<std::uint8_t> exp(input.size());
        for (std::size_t i = 0; i < input.size(); ++i) {
            exp[i] = static_cast<std::uint8_t>((input[i] >> k) | (input[i] << (8U - k)));
        }
        verify_morph(7, k, exp, false);
    }
    // 8: REVERSE_BYTES
    {
        std::vector<std::uint8_t> exp(input.rbegin(), input.rend());
        verify_morph(8, 0, exp, true);
    }
    // 9: REVERSE_BITS
    {
        std::vector<std::uint8_t> exp(input.rbegin(), input.rend());
        for (auto& b : exp) b = ref_bitrev8(b);
        verify_morph(9, 0, exp, true);
    }

    const bool ok = (passed == total);
    collector().add_row(
        "eval.morph", "ORACLE", "all-9-morphs-all-k",
        sha256_hex(input),
        std::to_string(total) + "/" + std::to_string(total) + " exact",
        std::to_string(passed) + "/" + std::to_string(total) + " exact",
        ok ? "PASS" : "FAIL", "logs/H3-ORACLE.log#eval.morph");
    collector().add_log("eval.morph: passed=" + std::to_string(passed) +
                        "/" + std::to_string(total));
}

// =========================================================================
// 10. All 5 Predictors (full + range + edge lengths)
// =========================================================================
TEST(OracleEvalPredictor, AllFivePredictorsExact) {
    int passed = 0, total = 0;

    auto test_pred = [&](std::uint8_t pid,
                         std::uint32_t param,
                         const std::vector<std::uint8_t>& residual,
                         const std::vector<std::uint8_t>& expected,
                         const char* lbl) {
        ++total;
        ContainerSpec s;
        s.total_length = std::to_string(residual.size());
        NodeSpec n0;
        if (residual.empty()) {
            n0.kind = 0; // Empty
            n0.length = "0";
        } else {
            s.atoms = {{0, residual}};
            n0.kind = 1; n0.atom_id = 0; n0.length = s.total_length;
        }
        NodeSpec n1;
        n1.kind = 11; n1.args = {0}; n1.predictor_id = pid; n1.predictor_param = param;
        n1.length = s.total_length;
        s.nodes = {n0, n1};
        const auto w = build_wire(s);

        std::vector<std::uint8_t> got;
        Diagnostic d;
        const int rc = decode_bytes(w, got, nullptr, &d);
        bool ok_case = (rc == 0 && got == expected);
        EXPECT_EQ(rc, 0) << lbl << " msg=" << d.message;
        EXPECT_EQ(got, expected) << lbl;

        // Check range decodes across predictor state
        for (std::size_t st = 0; st <= residual.size(); st += std::max<std::size_t>(1, residual.size() / 4)) {
            const std::size_t ln = std::min<std::size_t>(5, residual.size() - st);
            std::vector<std::uint8_t> rg;
            const int rrc = decode_range_bytes(w, std::to_string(st), std::to_string(ln), rg);
            const std::vector<std::uint8_t> re(
                expected.begin() + static_cast<std::ptrdiff_t>(st),
                expected.begin() + static_cast<std::ptrdiff_t>(st + ln));
            EXPECT_EQ(rrc, 0) << lbl;
            EXPECT_EQ(rg, re) << lbl;
            if (rrc != 0 || rg != re) ok_case = false;
        }
        if (ok_case) ++passed;
    };

    // 0: DELTA8
    test_pred(0, 0, {10, 20, 230, 5, 255}, {10, 30, 4, 9, 8}, "DELTA8");
    test_pred(0, 0, {}, {}, "DELTA8_empty");
    test_pred(0, 0, {0x42}, {0x42}, "DELTA8_len1");

    // 1: XOR8
    test_pred(1, 0, {0xAA, 0x55, 0x0F, 0xF0}, {0xAA, 0xFF, 0xF0, 0x00}, "XOR8");

    // 2: LINEAR2 (literal SPECS-V2 §3.6 & E2 §4.11: out[0]=r[0], out[1]=r[1], out[i]=(2*out[i-1]-out[i-2]) mod 256)
    test_pred(2, 0, {10, 15, 0, 0, 0, 0}, {10, 15, 20, 25, 30, 35}, "LINEAR2_ramp");
    test_pred(2, 0, {250, 254, 99, 88}, {250, 254, 2, 6}, "LINEAR2_wrap_literal");
    test_pred(2, 0, {7}, {7}, "LINEAR2_len1");

    // 3: STRIDE_XOR (param = 1, 3, and param > len fast pass-through)
    test_pred(3, 1, {0x12, 0x34, 0x56}, {0x12, 0x26, 0x70}, "STRIDE_XOR_1");
    test_pred(3, 3, {1, 2, 3, 0x10, 0x20, 0x30, 0x01, 0x02, 0x03},
              {1, 2, 3, 0x11, 0x22, 0x33, 0x10, 0x20, 0x30}, "STRIDE_XOR_3");
    test_pred(3, 1000000000U, {9, 8, 7, 6}, {9, 8, 7, 6}, "STRIDE_XOR_huge_param_short_len");

    // 4: STRIDE_DELTA (param = 1, 3, and param > len)
    test_pred(4, 1, {10, 20, 30}, {10, 30, 60}, "STRIDE_DELTA_1");
    test_pred(4, 3, {1, 2, 250, 10, 20, 10, 5, 5, 5},
              {1, 2, 250, 11, 22, 4, 16, 27, 9}, "STRIDE_DELTA_3");
    test_pred(4, 1000000000U, {4, 3, 2, 1}, {4, 3, 2, 1}, "STRIDE_DELTA_huge_param_short_len");

    // Multi-chunk (> 64 KiB = 100,000 bytes) streaming test for ALL 5 predictors + mid-range check
    {
        constexpr std::size_t kBigN = 100000;
        std::vector<std::uint8_t> res(kBigN);
        for (std::size_t i = 0; i < kBigN; ++i) {
            res[i] = static_cast<std::uint8_t>((i * 31U + 7U) & 0xFFU);
        }
        for (std::uint8_t pid = 0; pid <= 4; ++pid) {
            const std::uint32_t param = (pid >= 3U) ? 7U : 0U;
            std::vector<std::uint8_t> exp(kBigN);
            for (std::size_t i = 0; i < kBigN; ++i) {
                if (pid == 0U) {
                    exp[i] = (i == 0) ? res[0] : static_cast<std::uint8_t>(exp[i - 1] + res[i]);
                } else if (pid == 1U) {
                    exp[i] = (i == 0) ? res[0] : static_cast<std::uint8_t>(exp[i - 1] ^ res[i]);
                } else if (pid == 2U) {
                    if (i < 2) exp[i] = res[i];
                    else exp[i] = static_cast<std::uint8_t>(2U * exp[i - 1] - exp[i - 2]);
                } else if (pid == 3U) {
                    exp[i] = (i < param) ? res[i] : static_cast<std::uint8_t>(exp[i - param] ^ res[i]);
                } else {
                    exp[i] = (i < param) ? res[i] : static_cast<std::uint8_t>(exp[i - param] + res[i]);
                }
            }
            ++total;
            ContainerSpec s;
            s.total_length = std::to_string(kBigN);
            s.atoms = {{0, res}};
            NodeSpec n0; n0.kind = 1; n0.atom_id = 0; n0.length = s.total_length;
            NodeSpec n1; n1.kind = 11; n1.args = {0}; n1.predictor_id = pid; n1.predictor_param = param; n1.length = s.total_length;
            s.nodes = {n0, n1};
            const auto w = build_wire(s);

            std::vector<std::uint8_t> got;
            const int rc = decode_bytes(w, got);
            std::vector<std::uint8_t> rg;
            const int rrc = decode_range_bytes(w, "70003", "513", rg);
            const std::vector<std::uint8_t> re(exp.begin() + 70003, exp.begin() + 70003 + 513);
            EXPECT_EQ(rc, 0);
            EXPECT_EQ(got, exp);
            EXPECT_EQ(rrc, 0);
            EXPECT_EQ(rg, re);
            if (rc == 0 && got == exp && rrc == 0 && rg == re) ++passed;
        }
    }

    const bool ok = (passed == total);
    collector().add_row(
        "eval.predictor", "ORACLE", "all-5-predictors",
        sha256_of_string("eval.predictor"),
        std::to_string(total) + "/" + std::to_string(total) + " exact",
        std::to_string(passed) + "/" + std::to_string(total) + " exact",
        ok ? "PASS" : "FAIL", "logs/H3-ORACLE.log#eval.predictor");
    collector().add_log("eval.predictor: passed=" + std::to_string(passed) +
                        "/" + std::to_string(total));
}

// =========================================================================
// 11. LFSR and GF(2) Jump-Ahead (small exact + large virtual offsets)
// =========================================================================
TEST(OracleEvalLfsr, LfsrExactAndJumpAhead) {
    int passed = 0, total = 0;

    const std::array<std::pair<std::uint64_t, std::uint64_t>, 4> pairs = {{
        {0xD800000000000000ULL, 0x0000000000000001ULL},
        {0x800000000000000DULL, 0xFEDCBA9876543210ULL},
        {0xFFFFFFFFFFFFFFFFULL, 0xA5A5A5A55A5A5A5AULL},
        {0x0000000000000001ULL, 0x8000000000000001ULL}
    }};

    for (const auto& [conn, init] : pairs) {
        const std::size_t full_len = 5000;
        const auto ref = ref_lfsr(conn, init, full_len);

        ContainerSpec s;
        s.total_length = std::to_string(full_len);
        NodeSpec n;
        n.kind = 9; n.lfsr_conn = conn; n.lfsr_init = init; n.param_a = s.total_length; n.length = s.total_length;
        s.nodes = {n};
        const auto w = build_wire(s);

        ++total;
        std::vector<std::uint8_t> got;
        const int rc = decode_bytes(w, got);
        bool ok_pair = (rc == 0 && got == ref);
        EXPECT_EQ(rc, 0);
        EXPECT_EQ(got, ref);

        // Verify jump-ahead range decode against bit-by-bit reference at varied offsets
        for (std::size_t off : {std::size_t(0), std::size_t(1), std::size_t(7),
                                std::size_t(8), std::size_t(63), std::size_t(64),
                                std::size_t(65), std::size_t(513), std::size_t(4936)}) {
            const std::size_t ln = std::min<std::size_t>(64, full_len - off);
            std::vector<std::uint8_t> rg;
            const int rrc = decode_range_bytes(w, std::to_string(off), std::to_string(ln), rg);
            const std::vector<std::uint8_t> re(
                ref.begin() + static_cast<std::ptrdiff_t>(off),
                ref.begin() + static_cast<std::ptrdiff_t>(off + ln));
            EXPECT_EQ(rrc, 0);
            EXPECT_EQ(rg, re);
            if (rrc != 0 || rg != re) ok_pair = false;
        }
        if (ok_pair) ++passed;
    }

    // Virtual 2^50 and 2^70 LFSR jump-ahead (constant-time, zero materialisation!)
    // Use known-period tap conn=0x0000000000000001ULL (pure 64-bit rotation: bit 0 feeds bit 63 => period = 64 bits = 8 bytes!)
    {
        ++total;
        const std::uint64_t conn = 0x0000000000000001ULL;
        const std::uint64_t init = 0x0123456789ABCDEFULL;
        // Period is exactly 8 bytes, so offset 2^70 - 64 (multiple of 8) MUST match offset 0!
        const auto ref64 = ref_lfsr(conn, init, 64);
        const std::string len_2_70 = "1180591620717411303424"; // 2^70
        const std::string off_end  = "1180591620717411303360"; // 2^70 - 64 (divisible by 8!)

        ContainerSpec s;
        s.total_length = len_2_70;
        NodeSpec n; n.kind = 9; n.lfsr_conn = conn; n.lfsr_init = init; n.param_a = len_2_70; n.length = len_2_70;
        s.nodes = {n};
        const auto w = build_wire(s);

        std::vector<std::uint8_t> tail;
        Diagnostic d;
        const int rc = decode_range_bytes(w, off_end, "64", tail, &d);
        EXPECT_EQ(rc, 0) << d.message;
        EXPECT_EQ(tail, ref64);
        if (rc == 0 && tail == ref64) ++passed;
    }

    const bool ok = (passed == total);
    collector().add_row(
        "eval.lfsr", "ORACLE", "lfsr-kats-and-2p70-jump",
        sha256_of_string("eval.lfsr"),
        std::to_string(total) + "/" + std::to_string(total) + " exact",
        std::to_string(passed) + "/" + std::to_string(total) + " exact",
        ok ? "PASS" : "FAIL", "logs/H3-ORACLE.log#eval.lfsr");
    collector().add_log("eval.lfsr: passed=" + std::to_string(passed) +
                        "/" + std::to_string(total));
}

// =========================================================================
// 12. Range decode (virtual 2^40, 2^50, 2^70, complex trees, OOB rejection)
// =========================================================================
TEST(OracleEvalRange, RangeDecodeAndVirtualTails) {
    int passed = 0, total = 0;

    // 1) Virtual Zero(2^70) end-range decode
    {
        ++total;
        const std::string len_2_70 = "1180591620717411303424"; // 2^70
        const std::string start_tail = "1180591620717411303360"; // 2^70 - 64
        const auto w = make_zero_wire(len_2_70);
        std::vector<std::uint8_t> out;
        Diagnostic d;
        const int rc = decode_range_bytes(w, start_tail, "64", out, &d);
        const std::vector<std::uint8_t> exp(64, 0x00U);
        EXPECT_EQ(rc, 0) << d.message;
        EXPECT_EQ(out, exp);
        if (rc == 0 && out == exp) ++passed;
    }

    // 2) Virtual Affine(start=7, step=13, n=2^70) end-range decode
    // 2^70 mod 256 == 0, so (2^70 - 8) mod 256 == 248!
    {
        ++total;
        const std::string len_2_70 = "1180591620717411303424";
        const std::string start_tail = "1180591620717411303416"; // 2^70 - 8
        ContainerSpec s;
        s.total_length = len_2_70;
        NodeSpec n;
        n.kind = 10; n.affine_start = 7; n.affine_step = 13; n.param_a = len_2_70; n.length = len_2_70;
        s.nodes = {n};
        const auto w = build_wire(s);

        std::vector<std::uint8_t> out;
        Diagnostic d;
        const int rc = decode_range_bytes(w, start_tail, "8", out, &d);
        std::vector<std::uint8_t> exp(8);
        for (std::size_t i = 0; i < 8; ++i) {
            exp[i] = static_cast<std::uint8_t>((7U + (248U + i) * 13U) & 0xFFU);
        }
        EXPECT_EQ(rc, 0) << d.message;
        EXPECT_EQ(out, exp);
        if (rc == 0 && out == exp) ++passed;
    }

    // 3) Virtual Concat(Zero(2^50), Atom("TAIL_MARK")) end-range crossing boundary!
    {
        ++total;
        const std::string z_len = "1125899906842624"; // 2^50
        const std::string tot_len = "1125899906842633"; // 2^50 + 9
        const std::string start_cross = "1125899906842620"; // 2^50 - 4
        const std::vector<std::uint8_t> tag = {'T','A','I','L','_','M','A','R','K'};

        ContainerSpec s;
        s.total_length = tot_len;
        s.atoms = {{4, tag}};
        NodeSpec n0; n0.kind = 2; n0.param_a = z_len; n0.length = z_len;
        NodeSpec n1; n1.kind = 1; n1.atom_id = 0; n1.length = "9";
        NodeSpec n2; n2.kind = 3; n2.args = {0, 1}; n2.length = tot_len;
        s.nodes = {n0, n1, n2};
        const auto w = build_wire(s);

        std::vector<std::uint8_t> out;
        Diagnostic d;
        const int rc = decode_range_bytes(w, start_cross, "13", out, &d);
        const std::vector<std::uint8_t> exp = {0, 0, 0, 0, 'T','A','I','L','_','M','A','R','K'};
        EXPECT_EQ(rc, 0) << d.message;
        EXPECT_EQ(out, exp);
        if (rc == 0 && out == exp) ++passed;
    }

    // 4) Virtual Repeat(Atom("ABCDE"), q=2^64, r=3) end-range decode
    // (5 * 2^64 + 3) = 92233720368547758083; last 8 bytes = "ABCDEABC"
    {
        ++total;
        const std::string q_str = "18446744073709551616"; // 2^64
        const std::string tot_str = "92233720368547758083"; // 5 * 2^64 + 3
        const std::string start_str = "92233720368547758075"; // tot - 8
        ContainerSpec s;
        s.total_length = tot_str;
        s.atoms = {{4, {'A','B','C','D','E'}}};
        NodeSpec n0; n0.kind = 1; n0.atom_id = 0; n0.length = "5";
        NodeSpec n1; n1.kind = 4; n1.args = {0}; n1.param_a = q_str; n1.param_b = "3"; n1.length = tot_str;
        s.nodes = {n0, n1};
        const auto w = build_wire(s);

        std::vector<std::uint8_t> out;
        Diagnostic d;
        const int rc = decode_range_bytes(w, start_str, "8", out, &d);
        const std::vector<std::uint8_t> exp = {'A','B','C','D','E','A','B','C'};
        EXPECT_EQ(rc, 0) << d.message;
        EXPECT_EQ(out, exp);
        if (rc == 0 && out == exp) ++passed;
    }

    // 5) Huge 2^70 virtual Affine(start=1, step=7) wrapped in Morph(REVERSE_BYTES = 8)
    {
        ++total;
        const std::string len70 = "1180591620717411303424";
        ContainerSpec s;
        s.total_length = len70;
        NodeSpec n0; n0.kind = 10; n0.affine_start = 1U; n0.affine_step = 7U; n0.param_a = len70; n0.length = len70;
        NodeSpec n1; n1.kind = 6; n1.args = {0}; n1.morph = 8U; n1.morph_k = 0U; n1.length = len70;
        s.nodes = {n0, n1};
        const auto w = build_wire(s);

        std::vector<std::uint8_t> got;
        Diagnostic d;
        const int r = decode_range_bytes(w, "0", "16", got, &d);
        std::vector<std::uint8_t> exp(16);
        for (std::size_t i = 0; i < 16; ++i) {
            const std::uint8_t pos_mod = static_cast<std::uint8_t>((255U - i) & 0xFFU);
            exp[i] = static_cast<std::uint8_t>((1U + 7U * pos_mod) & 0xFFU);
        }
        EXPECT_EQ(r, 0) << d.message;
        EXPECT_EQ(got, exp);
        if (r == 0 && got == exp) ++passed;
    }

    // 6) Interleave with argc = 1 (allowed by E3 §4.6) and multi-child unaligned range decode
    {
        ++total;
        ContainerSpec s1;
        s1.total_length = "6";
        s1.atoms = {{0, {1, 2, 3, 4, 5, 6}}};
        NodeSpec a0; a0.kind = 1; a0.atom_id = 0; a0.length = "6";
        NodeSpec il1; il1.kind = 8; il1.args = {0}; il1.stride = 2; il1.length = "6";
        s1.nodes = {a0, il1};
        std::vector<std::uint8_t> g1;
        const int r1 = decode_bytes(build_wire(s1), g1);
        const std::vector<std::uint8_t> e1 = {1, 2, 3, 4, 5, 6};

        ContainerSpec s3;
        s3.total_length = "27";
        s3.atoms = {
            {0, {10, 11, 12, 13, 14, 15, 16, 17, 18}},
            {1, {20, 21, 22, 23, 24, 25, 26, 27, 28}},
            {2, {30, 31, 32, 33, 34, 35, 36, 37, 38}},
        };
        NodeSpec c0; c0.kind = 1; c0.atom_id = 0; c0.length = "9";
        NodeSpec c1; c1.kind = 1; c1.atom_id = 1; c1.length = "9";
        NodeSpec c2; c2.kind = 1; c2.atom_id = 2; c2.length = "9";
        NodeSpec il3; il3.kind = 8; il3.args = {0, 1, 2}; il3.stride = 3; il3.length = "27";
        s3.nodes = {c0, c1, c2, il3};
        const auto w3 = build_wire(s3);
        std::vector<std::uint8_t> full3;
        const int r3 = decode_bytes(w3, full3);
        bool all_sub_ok = (r1 == 0 && g1 == e1 && r3 == 0 && full3.size() == 27U);
        for (std::size_t st = 0; st < 27 && all_sub_ok; st += 2) {
            for (std::size_t ln = 1; st + ln <= 27 && all_sub_ok; ln += 3) {
                std::vector<std::uint8_t> sub;
                if (decode_range_bytes(w3, std::to_string(st), std::to_string(ln), sub) != 0 ||
                    !std::equal(sub.begin(), sub.end(), full3.begin() + static_cast<std::ptrdiff_t>(st))) {
                    all_sub_ok = false;
                }
            }
        }
        EXPECT_TRUE(all_sub_ok);
        if (all_sub_ok) ++passed;
    }

    // 7) Out-of-bounds range rejected with Invalid (4); bad decimal rejected with Usage (2)
    {
        ++total;
        const auto w = make_zero_wire("100");
        std::vector<std::uint8_t> out;
        const int r1 = decode_range_bytes(w, "95", "6", out);
        const int r2 = decode_range_bytes(w, "101", "0", out);
        const int r3 = decode_range_bytes(w, "-1", "5", out);
        const int r4 = decode_range_bytes(w, "abc", "5", out);
        EXPECT_EQ(r1, 4);
        EXPECT_EQ(r2, 4);
        EXPECT_EQ(r3, 2);
        EXPECT_EQ(r4, 2);
        if (r1 == 4 && r2 == 4 && r3 == 2 && r4 == 2) ++passed;
    }

    const bool ok = (passed == total);
    collector().add_row(
        "eval.range", "ORACLE", "virtual-2p50-2p70-and-bounds",
        sha256_of_string("eval.range"),
        std::to_string(total) + "/" + std::to_string(total) + " exact",
        std::to_string(passed) + "/" + std::to_string(total) + " exact",
        ok ? "PASS" : "FAIL", "logs/H3-ORACLE.log#eval.range");
    collector().add_log("eval.range: passed=" + std::to_string(passed) +
                        "/" + std::to_string(total));
}

// =========================================================================
// 13. Resource Limits & Safety (No OOM, No Crash, Explicit Stack)
// =========================================================================
TEST(OracleResourceLimits, LimitsAndAllocationSafety) {
    int passed = 0, total = 0;

    // 1) Large-length container Zero(2^70): structure-only PASS, end-range PASS, full verify LIMIT (7)
    {
        ++total;
        const std::string len_2_70 = "1180591620717411303424";
        const auto w = make_zero_wire(len_2_70);
        Diagnostic d1, d2;
        const int r_struct = validate_bytes(w, true, nullptr, &d1);
        const int r_full = validate_bytes(w, false, nullptr, &d2);
        EXPECT_EQ(r_struct, 0) << d1.message;
        EXPECT_EQ(r_full, 7) << d2.message;
        EXPECT_EQ(d2.stage, ValidationStage::Eval);
        if (r_struct == 0 && r_full == 7 && d2.stage == ValidationStage::Eval) ++passed;
    }

    // 2) Range expansion ratio limit (> 2^20 * file_bytes -> Limit 7)
    {
        ++total;
        const std::string len_2_70 = "1180591620717411303424";
        const auto w = make_zero_wire(len_2_70);
        std::vector<std::uint8_t> out;
        Diagnostic d;
        const int r_exp = decode_range_bytes(w, "0", "1073741824", out, &d); // 1 GiB from ~120 B wire
        EXPECT_EQ(r_exp, 7) << d.message;
        if (r_exp == 7) ++passed;
    }

    // 3) Absurd trailer counts (0xFFFFFFFF) rejected at Stage 5 as Limit (7) without allocating
    {
        ++total;
        auto w = make_empty_wire();
        write_le32_at(w, w.size() - 32 + 20, 0xFFFFFFFFU); // atom_count
        recompute_outer_crcs(w);
        Diagnostic d;
        const int r1 = validate_bytes(w, true, nullptr, &d);
        EXPECT_EQ(r1, 7);
        EXPECT_EQ(d.stage, ValidationStage::Trailer);

        auto w2 = make_empty_wire();
        write_le32_at(w2, w2.size() - 32 + 24, 0xFFFFFFFFU); // node_count
        recompute_outer_crcs(w2);
        Diagnostic d2;
        const int r2 = validate_bytes(w2, true, nullptr, &d2);
        EXPECT_EQ(r2, 7);
        EXPECT_EQ(d2.stage, ValidationStage::Trailer);
        if (r1 == 7 && r2 == 7) ++passed;
    }

    // 4) In-limit but impossible counts (atom_count=1000000 in 100B file) rejected at Stage 7/8 as Invalid (4) without allocating
    {
        ++total;
        std::vector<std::uint8_t> atom_bin;
        put_uvarint(atom_bin, 1000000ULL);
        std::vector<std::uint8_t> node_bin = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00};
        auto w = assemble_raw("0", atom_bin, node_bin, {}, 1000000U, 1U, 0U);
        Diagnostic d;
        const int r1 = validate_bytes(w, true, nullptr, &d);
        EXPECT_EQ(r1, 4);
        EXPECT_EQ(d.stage, ValidationStage::Atoms);

        std::vector<std::uint8_t> nbin;
        put_uvarint(nbin, 1000000ULL);
        auto w2 = assemble_raw("0", {0x00}, nbin, {}, 0U, 1000000U, 999999U);
        Diagnostic d2;
        const int r2 = validate_bytes(w2, true, nullptr, &d2);
        EXPECT_EQ(r2, 4);
        EXPECT_EQ(d2.stage, ValidationStage::Nodes);
        if (r1 == 4 && r2 == 4) ++passed;
    }

    // 5) Deep DAG: explicit stack handles depth 5000 cleanly; depth 65537 (> 2^16 default) returns Limit (7)
    {
        ++total;
        auto make_deep_morph_wire = [](std::uint32_t count) {
            std::vector<std::uint8_t> atom_bin = encode_atoms({AtomSpec{0, {0xAA, 0x55}}});
            std::vector<std::uint8_t> node_bin;
            node_bin.reserve(count * 12ULL + 16ULL);
            put_uvarint(node_bin, count);
            // Node 0: Atom(0), len=2
            put_u8(node_bin, 1U); put_u8(node_bin, 0U); put_le16(node_bin, 0U);
            put_uvarint(node_bin, 0U); put_bigint_u64(node_bin, 2U);
            // Nodes 1..count-1: Morph(i-1, INVERT8, 0), len=2
            for (std::uint32_t i = 1; i < count; ++i) {
                put_u8(node_bin, 6U); put_u8(node_bin, 0U); put_le16(node_bin, 1U);
                put_uvarint(node_bin, i - 1U);
                put_u8(node_bin, 2U); put_u8(node_bin, 0U);
                put_bigint_u64(node_bin, 2U);
            }
            return assemble_raw("2", atom_bin, node_bin, {}, 1U, count, count - 1U);
        };

        // Depth 5000: decodes cleanly with zero stack overflow!
        const auto w5k = make_deep_morph_wire(5000U);
        std::vector<std::uint8_t> out;
        Diagnostic d_ok;
        const int r_ok = decode_bytes(w5k, out, nullptr, &d_ok);
        // 4999 inversions (odd) -> ~{0xAA, 0x55} = {0x55, 0xAA}
        const std::vector<std::uint8_t> exp = {0x55, 0xAA};
        EXPECT_EQ(r_ok, 0) << d_ok.message;
        EXPECT_EQ(out, exp);

        // Depth 65537 (> default max_depth = 2^16 = 65536): returns Limit (7) at Stage 8!
        const auto w_over = make_deep_morph_wire(65537U);
        Diagnostic d_lim;
        const int r_lim = validate_bytes(w_over, true, nullptr, &d_lim);
        EXPECT_EQ(r_lim, 7) << d_lim.message;
        EXPECT_EQ(d_lim.stage, ValidationStage::Nodes);

        if (r_ok == 0 && out == exp && r_lim == 7 && d_lim.stage == ValidationStage::Nodes) {
            ++passed;
        }
    }

    // 6) Predictor range start > max_predictor_prefix (2^28) returns Limit (7)
    {
        ++total;
        const std::string big_len = "300000000"; // > 2^28
        ContainerSpec s;
        s.total_length = big_len;
        NodeSpec n0; n0.kind = 2; n0.param_a = big_len; n0.length = big_len;
        NodeSpec n1; n1.kind = 11; n1.args = {0}; n1.predictor_id = 0; n1.predictor_param = 0; n1.length = big_len;
        s.nodes = {n0, n1};
        const auto w = build_wire(s);
        std::vector<std::uint8_t> out;
        Diagnostic d;
        const int r_lim = decode_range_bytes(w, "270000000", "16", out, &d);
        EXPECT_EQ(r_lim, 7) << d.message;
        if (r_lim == 7) ++passed;
    }

    const bool ok = (passed == total);
    collector().add_row(
        "resource.limits", "ORACLE", "limits-oom-depth-expansion",
        sha256_of_string("resource.limits"),
        std::to_string(total) + "/" + std::to_string(total) + " safe",
        std::to_string(passed) + "/" + std::to_string(total) + " safe",
        ok ? "PASS" : "FAIL", "logs/H3-ORACLE.log#resource.limits");
    collector().add_log("resource.limits: passed=" + std::to_string(passed) +
                        "/" + std::to_string(total));
}

// =========================================================================
// 13b. Observable Stage-Order Precedence (E3 §5.1 steps 1..11)
// =========================================================================
TEST(OracleStageOrder, AdjacentStagePrecedenceAllEleven) {
    int passed = 0, total = 0;

    auto check_stage = [&](const std::vector<std::uint8_t>& w,
                           bool structure_only,
                           int exp_rc,
                           ValidationStage exp_stage,
                           const char* label) {
        ++total;
        Diagnostic d;
        const int rc = validate_bytes(w, structure_only, nullptr, &d);
        EXPECT_EQ(rc, exp_rc) << label << " msg=" << d.message;
        EXPECT_EQ(d.stage, exp_stage) << label << " got " << stage_name(d.stage);
        if (rc == exp_rc && d.stage == exp_stage) ++passed;
    };

    // 1 < 2: Size (<96) beats bad header magic
    {
        std::vector<std::uint8_t> w(64, 0xFFU);
        check_stage(w, true, 4, ValidationStage::Size, "1_beats_2");
    }
    // 2 < 3: Bad header magic beats wrong trailer_offset
    {
        auto w = make_empty_wire();
        w[0] ^= 0x01U;
        write_le64_at(w, 52, 0ULL);
        check_stage(w, true, 4, ValidationStage::Header, "2_beats_3");
    }
    // 3 < 4: Wrong trailer_offset beats bad file_crc32
    {
        auto w = make_empty_wire();
        write_le64_at(w, 52, 70ULL);
        w[60] ^= 0xFFU;
        check_stage(w, true, 4, ValidationStage::Bounds, "3_beats_4");
    }
    // 4 < 5: Bad file_crc32 beats bad trailer magic
    {
        auto w = make_empty_wire();
        w[60] ^= 0xFFU;
        w[w.size() - 32] ^= 0xFFU;
        check_stage(w, true, 4, ValidationStage::HeaderCrc, "4_beats_5");
    }
    // 5 < 6: Bad trailer magic beats bad region offset order
    {
        auto w = make_empty_wire();
        write_le64_at(w, 28, 12ULL); // bad atom_offset
        w[w.size() - 32] ^= 0xFFU;   // bad trailer magic
        recompute_outer_crcs(w);
        check_stage(w, true, 4, ValidationStage::Trailer, "5_beats_6");
    }
    // 6 < 7: Non-monotonic regions beats corrupt atom table
    {
        auto w = make_empty_wire();
        write_le64_at(w, 28, 66ULL); // atom_offset > node_offset (65)
        w[64] = 0xFFU;               // corrupt atom_count too
        recompute_outer_crcs(w);
        check_stage(w, true, 4, ValidationStage::Regions, "6_beats_7");
    }
    // 7 < 8: Corrupt atom table beats corrupt node table
    {
        auto w = assemble_raw("0", {0x02}, {0x01, 0xFF, 0x00, 0x00, 0x00, 0x00}, {}, 2U, 1U, 0U);
        check_stage(w, true, 4, ValidationStage::Atoms, "7_beats_8");
    }
    // 8 < 9: Bad node kind beats root_id != node_count - 1
    {
        auto w = assemble_raw("0", {0x00}, {0x01, 0x7F, 0x00, 0x00, 0x00, 0x00}, {}, 0U, 1U, 99U);
        check_stage(w, true, 4, ValidationStage::Nodes, "8_beats_9");
    }
    // 9 < 10: Root length mismatch beats bad seek index magic
    {
        auto [w, _] = make_indexed_3mib_wire(true);
        const std::size_t idx_off = static_cast<std::size_t>(read_le64_at(w, 44));
        write_le64_at(w, 18, 999ULL); // Stage 9 root length mismatch
        w[idx_off] ^= 0x01U;          // Stage 10 bad index magic
        recompute_outer_crcs(w);
        check_stage(w, true, 4, ValidationStage::Root, "9_beats_10");
    }
    // 10 < 11: Bad index CRC beats bad index prefix CRC (Stage 11)
    {
        auto [w, _] = make_indexed_3mib_wire(true);
        const std::size_t idx_off = static_cast<std::size_t>(read_le64_at(w, 44));
        const std::size_t trl_off = static_cast<std::size_t>(read_le64_at(w, 52));
        w[idx_off + 12] ^= 0x01U; // corrupt entry prefix CRC (Stage 11)
        w[trl_off - 1] ^= 0x01U;  // corrupt index_crc32 (Stage 10)
        recompute_outer_crcs(w);
        check_stage(w, false, 4, ValidationStage::Index, "10_beats_11");
    }
    // 11 alone: Valid index CRC but wrong entry prefix CRC fails at Stage 11
    {
        auto [w, _] = make_indexed_3mib_wire(true);
        const std::size_t idx_off = static_cast<std::size_t>(read_le64_at(w, 44));
        const std::size_t trl_off = static_cast<std::size_t>(read_le64_at(w, 52));
        w[trl_off - 5] ^= 0x01U; // flip prefix CRC of last entry
        const std::uint32_t new_icrc = crc32_bytes(std::span<const std::uint8_t>(
            w.data() + idx_off, trl_off - idx_off - 4));
        write_le32_at(w, trl_off - 4, new_icrc);
        recompute_outer_crcs(w);
        check_stage(w, false, 4, ValidationStage::Eval, "11_eval_prefix_crc");
    }

    EXPECT_EQ(passed, total);
    collector().add_row(
        "wire.stage_order", "ORACLE", "stages-1-to-11-precedence",
        sha256_of_string("wire.stage_order"),
        std::to_string(total) + "/" + std::to_string(total) + " ordered",
        std::to_string(passed) + "/" + std::to_string(total) + " ordered",
        (passed == total) ? "PASS" : "FAIL", "logs/H3-ORACLE.log#wire.stage_order");
    collector().add_log("wire.stage_order: passed=" + std::to_string(passed) +
                        "/" + std::to_string(total));
}

// =========================================================================
// 14. CLI Smoke Matrix & Determinism (invokes bin/mapr_oracle if supplied)
// =========================================================================
TEST(OracleCliAndDeterminism, CliSmokeAndDeterminism) {
    const auto tmp_dir = std::filesystem::temp_directory_path() /
                         ("marp_h3_oracle_test_" + std::to_string(getpid()));
    std::error_code ec;
    std::filesystem::remove_all(tmp_dir, ec);
    std::filesystem::create_directories(tmp_dir, ec);

    // Build test wires: small complex DAG, large 2^70 virtual wire, future-version wire, invalid wire
    ContainerSpec s;
    s.total_length = "10";
    s.atoms = {{4, {'M','A','R','P','!'}}};
    NodeSpec n0; n0.kind = 1; n0.atom_id = 0; n0.length = "5";
    NodeSpec n1; n1.kind = 4; n1.args = {0}; n1.param_a = "2"; n1.param_b = "0"; n1.length = "10";
    s.nodes = {n0, n1};
    const auto small_wire = build_wire(s);
    const std::vector<std::uint8_t> small_exp = {'M','A','R','P','!','M','A','R','P','!'};
    const std::string small_sha = sha256_hex(small_exp);

    const std::string len_2_70 = "1180591620717411303424";
    const std::string off_2_70_m16 = "1180591620717411303408";
    const auto large_wire = make_zero_wire(len_2_70);

    auto future_wire = make_empty_wire();
    write_le16_at(future_wire, 8, 3U);
    recompute_outer_crcs(future_wire);

    auto bad_wire = small_wire;
    bad_wire[64] ^= 0xFFU;

    const auto f_small = tmp_dir / "small.mapr";
    const auto f_large = tmp_dir / "large.mapr";
    const auto f_future = tmp_dir / "future.mapr";
    const auto f_bad = tmp_dir / "bad.mapr";
    const auto f_out1 = tmp_dir / "out1.bin";
    const auto f_out2 = tmp_dir / "out2.bin";
    const auto f_rng = tmp_dir / "range.bin";

    ASSERT_TRUE(write_bytes_file(f_small, small_wire));
    ASSERT_TRUE(write_bytes_file(f_large, large_wire));
    ASSERT_TRUE(write_bytes_file(f_future, future_wire));
    ASSERT_TRUE(write_bytes_file(f_bad, bad_wire));

    // Library-level determinism check (always runs)
    Info info1, info2;
    ASSERT_EQ(decode_file(f_small, f_out1, &info1), 0);
    ASSERT_EQ(decode_file(f_small, f_out2, &info2), 0);
    const auto d1 = read_bytes_file(f_out1);
    const auto d2 = read_bytes_file(f_out2);
    EXPECT_EQ(d1, small_exp);
    EXPECT_EQ(d1, d2);
    EXPECT_EQ(info1.output_sha256, small_sha);
    EXPECT_EQ(info1.output_sha256, info2.output_sha256);

    std::ostringstream ins1, ins2;
    ASSERT_EQ(inspect_file(f_small, ins1), 0);
    ASSERT_EQ(inspect_file(f_small, ins2), 0);
    EXPECT_EQ(ins1.str(), ins2.str());
    EXPECT_NE(ins1.str().find("header\t2\t0\t"), std::string::npos);
    EXPECT_NE(ins1.str().find("atom\t0\t4\t5\t"), std::string::npos);
    EXPECT_NE(ins1.str().find("node\t1\t4\tRepeat\t"), std::string::npos);
    EXPECT_NE(ins1.str().find("trailer\t"), std::string::npos);

    // Library verify_file check
    EXPECT_EQ(verify_file(f_small, small_sha, false), 0);
    EXPECT_EQ(verify_file(f_small, std::string(64, '0'), false), 6);
    EXPECT_EQ(verify_file(f_large, "", true), 0);
    EXPECT_EQ(verify_file(f_large, "", false), 7);
    EXPECT_EQ(decode_range(f_large, off_2_70_m16, "16", f_rng), 0);
    EXPECT_EQ(read_bytes_file(f_rng), std::vector<std::uint8_t>(16, 0x00U));

    // Failed decode_file / decode_range must NOT leave a partial output file behind
    const auto f_should_not_exist = tmp_dir / "no_leftover.bin";
    EXPECT_EQ(decode_file(f_bad, f_should_not_exist), 4);
    EXPECT_FALSE(std::filesystem::exists(f_should_not_exist));
    EXPECT_EQ(decode_range(f_bad, "0", "4", f_should_not_exist), 4);
    EXPECT_FALSE(std::filesystem::exists(f_should_not_exist));

    bool det_ok = (d1 == small_exp && d1 == d2 && ins1.str() == ins2.str() &&
                   info1.output_sha256 == small_sha &&
                   !std::filesystem::exists(f_should_not_exist));

    // If CLI binary path was supplied, run full CLI smoke matrix + CLI determinism!
    if (!collector().oracle_bin.empty() && std::filesystem::exists(collector().oracle_bin)) {
        const std::string bin = collector().oracle_bin.string();
        std::string out_s, err_s;

        // 1) decode --info twice -> identical stdout & file bytes
        const auto c_out1 = tmp_dir / "cli_out1.bin";
        const auto c_out2 = tmp_dir / "cli_out2.bin";
        std::string out_s2, err_s2;
        const int rc_d1 = run_process_capture({bin, "decode", f_small.string(), c_out1.string(), "--info"}, out_s, err_s);
        const int rc_d2 = run_process_capture({bin, "decode", f_small.string(), c_out2.string(), "--info"}, out_s2, err_s2);
        EXPECT_EQ(rc_d1, 0) << err_s;
        EXPECT_EQ(rc_d2, 0) << err_s2;
        EXPECT_EQ(out_s, out_s2);
        EXPECT_EQ(read_bytes_file(c_out1), small_exp);
        EXPECT_EQ(read_bytes_file(c_out2), small_exp);
        det_ok &= (rc_d1 == 0 && rc_d2 == 0 && out_s == out_s2 && read_bytes_file(c_out1) == small_exp);

        // 2) verify valid, verify --sha256 ok, verify --sha256 mismatch (6)
        EXPECT_EQ(run_process_capture({bin, "verify", f_small.string()}, out_s, err_s), 0);
        EXPECT_EQ(run_process_capture({bin, "verify", f_small.string(), "--sha256", small_sha}, out_s, err_s), 0);
        EXPECT_EQ(run_process_capture({bin, "verify", f_small.string(), "--sha256", std::string(64, 'f')}, out_s, err_s), 6);

        // 3) verify large --structure-only (0), verify large full (7), range large tail (0)
        EXPECT_EQ(run_process_capture({bin, "verify", f_large.string(), "--structure-only"}, out_s, err_s), 0);
        EXPECT_EQ(run_process_capture({bin, "verify", f_large.string()}, out_s, err_s), 7);
        const auto c_rng = tmp_dir / "cli_rng.bin";
        EXPECT_EQ(run_process_capture({bin, "range", f_large.string(), off_2_70_m16, "16", c_rng.string()}, out_s, err_s), 0);
        EXPECT_EQ(read_bytes_file(c_rng), std::vector<std::uint8_t>(16, 0x00U));

        // 4) inspect deterministic TSV
        std::string i_s1, i_s2;
        EXPECT_EQ(run_process_capture({bin, "inspect", f_small.string()}, i_s1, err_s), 0);
        EXPECT_EQ(run_process_capture({bin, "inspect", f_small.string()}, i_s2, err_s), 0);
        EXPECT_EQ(i_s1, i_s2);
        det_ok &= (i_s1 == i_s2 && i_s1 == ins1.str());

        // 5) Error exit codes: invalid (4), unsupported (5), I/O (3), usage (2)
        EXPECT_EQ(run_process_capture({bin, "verify", f_bad.string()}, out_s, err_s), 4);
        EXPECT_EQ(run_process_capture({bin, "verify", f_future.string()}, out_s, err_s), 5);
        EXPECT_EQ(run_process_capture({bin, "verify", (tmp_dir / "nonexistent.mapr").string()}, out_s, err_s), 3);
        EXPECT_EQ(run_process_capture({bin, "bogus-cmd"}, out_s, err_s), 2);
        EXPECT_EQ(run_process_capture({bin, "verify", f_small.string(), "--structure-only", "--sha256", small_sha}, out_s, err_s), 2);
    }

    std::filesystem::remove_all(tmp_dir, ec);

    collector().add_row(
        "determinism", "ORACLE", "repeat-decode-and-inspect",
        sha256_hex(small_wire),
        small_sha, det_ok ? small_sha : "mismatch",
        det_ok ? "PASS" : "FAIL", "logs/H3-ORACLE.log#determinism");
    collector().add_log("determinism: cli_bin=" +
                        (collector().oracle_bin.empty() ? std::string("none") : collector().oracle_bin.string()) +
                        " status=" + std::string(det_ok ? "PASS" : "FAIL"));
}

// =========================================================================
// 16. F00-F08 cross-check: E3-emitted v2 wires decoded by the clean-room oracle
// =========================================================================
//
// The wires are produced by the *E3 side* (`harness/crosscheck/f00f08_producer.cpp`,
// built by `make -f Makefile.h3 h3-crosscheck`) and handed to this binary as
// opaque files plus a deterministic manifest.  Nothing below includes, links,
// or re-implements any engine/E3 code: every wire is parsed, validated and
// evaluated here, from the bytes on disk, by `marp::oracle`.
//
// Independence of the *expected* value is the whole point: the digests come
// from the committed H1 fixture manifest (`specs_and_reports/v2/fixtures.tsv`,
// written by H1 FIXTURES from the §12.3 generators), never from the wire's own
// trailer or from anything the producer claims.  A wire that merely agrees with
// itself therefore cannot pass.

struct CrossCheckManifestRow {
    std::string id;
    std::string fixture_bytes;
    std::string fixture_sha256;
    std::string ir_nodes;
    std::string ir_atoms;
    std::string wire_bytes;
    std::string wire_sha256;
    std::string wire_path;
};

bool read_tsv_rows(const std::filesystem::path& path,
                   std::vector<std::vector<std::string>>& rows) {
    std::ifstream ifs(path);
    if (!ifs.is_open()) return false;
    std::string line;
    bool first = true;
    while (std::getline(ifs, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (first) {
            first = false;
            continue;  // header
        }
        if (line.empty()) continue;
        std::vector<std::string> columns;
        std::size_t start = 0;
        for (;;) {
            const std::size_t tab = line.find('\t', start);
            columns.push_back(line.substr(start, tab == std::string::npos
                                                     ? std::string::npos
                                                     : tab - start));
            if (tab == std::string::npos) break;
            start = tab + 1;
        }
        rows.push_back(std::move(columns));
    }
    return !rows.empty();
}

std::vector<std::string> split_csv(const std::string& text) {
    std::vector<std::string> parts;
    std::size_t start = 0;
    for (;;) {
        const std::size_t comma = text.find(',', start);
        std::string part = text.substr(start, comma == std::string::npos
                                                  ? std::string::npos
                                                  : comma - start);
        if (!part.empty()) parts.push_back(std::move(part));
        if (comma == std::string::npos) break;
        start = comma + 1;
    }
    return parts;
}

TEST(OracleF00F08CrossCheck, E3WiresReproduceFixtureBytes) {
    auto& col = collector();
    const std::array<const char*, 9> canonical_order = {
        "F00", "F01", "F02", "F03", "F04", "F05", "F06", "F07", "F08"};

    if (col.cross_check_dir.empty()) {
        GTEST_SKIP() << "no --cross-check-dir supplied; the authoritative run is "
                        "`make -f Makefile.h3 h3-test-cross`";
        return;
    }

    const auto manifest_path = col.cross_check_dir / "f00-f08-manifest.tsv";
    const auto fixtures_manifest = col.repo_root / "specs_and_reports" / "v2" / "fixtures.tsv";

    std::vector<std::string> wanted;
    if (col.cross_check_only.empty()) {
        for (const char* id : canonical_order) wanted.emplace_back(id);
    } else {
        wanted = split_csv(col.cross_check_only);
    }

    std::size_t passed = 0;
    std::size_t total = 0;
    std::size_t engine_agree = 0;
    std::uint64_t wire_bytes_total = 0;
    std::string identity_text;      // feed for the evidence row's input_sha256
    std::string setup_failure;

    std::vector<std::vector<std::string>> h1_rows;
    std::vector<std::vector<std::string>> manifest_rows;
    if (!std::filesystem::exists(manifest_path)) {
        setup_failure = "producer manifest missing: " + manifest_path.string();
    } else if (!read_tsv_rows(manifest_path, manifest_rows)) {
        setup_failure = "unreadable or empty producer manifest: " + manifest_path.string();
    } else if (!std::filesystem::exists(fixtures_manifest)) {
        setup_failure = "H1 fixture manifest missing: " + fixtures_manifest.string();
    } else if (!read_tsv_rows(fixtures_manifest, h1_rows)) {
        setup_failure = "unreadable H1 fixture manifest: " + fixtures_manifest.string();
    }

    for (const std::string& id : wanted) {
        ++total;
        std::string why;
        bool ok = setup_failure.empty();
        if (!ok) why = setup_failure;

        const std::vector<std::string>* h1_row = nullptr;
        const std::vector<std::string>* manifest_row = nullptr;
        for (const auto& row : h1_rows) {
            if (!row.empty() && row[0] == id) h1_row = &row;
        }
        for (const auto& row : manifest_rows) {
            if (!row.empty() && row[0] == id) manifest_row = &row;
        }

        if (ok && h1_row == nullptr) {
            ok = false;
            why = "no row for " + id + " in the H1 fixture manifest";
        }
        if (ok && manifest_row == nullptr) {
            ok = false;
            why = "no row for " + id + " in the producer manifest";
        }
        if (ok && (h1_row->size() < 4 || manifest_row->size() < 11)) {
            ok = false;
            why = "malformed manifest row for " + id;
        }
        if (ok && ((*h1_row)[1] != "generated")) {
            ok = false;
            why = "H1 row for " + id + " is not a generated fixture";
        }

        CrossCheckManifestRow row;
        if (ok) {
            row.id = id;
            row.fixture_bytes = (*h1_row)[2];
            row.fixture_sha256 = (*h1_row)[3];
            row.ir_nodes = (*manifest_row)[3];
            row.ir_atoms = (*manifest_row)[4];
            row.wire_bytes = (*manifest_row)[5];
            row.wire_sha256 = (*manifest_row)[6];
            row.wire_path = (*manifest_row)[10];

            // The producer must agree with H1 on the fixture identity.  This is a
            // claim in the manifest; the oracle checks it, it does not trust it.
            if ((*manifest_row)[1] != row.fixture_bytes) {
                ok = false;
                why = "producer fixture_bytes " + (*manifest_row)[1] + " != H1 " + row.fixture_bytes;
            } else if ((*manifest_row)[2] != row.fixture_sha256) {
                ok = false;
                why = "producer fixture_sha256 " + (*manifest_row)[2] + " != H1 " + row.fixture_sha256;
            } else if ((*manifest_row)[7] != row.fixture_sha256 ||
                       (*manifest_row)[8] != row.fixture_bytes) {
                ok = false;
                why = "producer engine claim does not reproduce the H1 fixture identity";
            }
        }

        std::vector<std::uint8_t> wire;
        if (ok) {
            const auto wire_path = col.cross_check_dir / row.wire_path;
            if (!std::filesystem::exists(wire_path)) {
                ok = false;
                why = "wire file missing: " + wire_path.string();
            } else {
                wire = read_bytes_file(wire_path);
                if (wire.empty()) {
                    ok = false;
                    why = "wire file is empty";
                } else if (std::to_string(wire.size()) != row.wire_bytes) {
                    ok = false;
                    why = "wire size " + std::to_string(wire.size()) +
                          " != manifest " + row.wire_bytes;
                } else if (sha256_hex(std::span<const std::uint8_t>(wire.data(), wire.size())) !=
                           row.wire_sha256) {
                    ok = false;
                    why = "wire SHA-256 disagrees with the manifest";
                }
            }
        }

        Info info;
        Diagnostic diag;
        if (ok) {
            // Full E3 §5.1 stages 1-11, performed here, by the oracle.  The
            // expected digest is H1's, so stage 11 must reproduce it exactly.
            const int rc = verify_bytes(std::span<const std::uint8_t>(wire.data(), wire.size()),
                                        row.fixture_sha256, /*structure_only=*/false, &info,
                                        &diag);
            if (rc != 0) {
                ok = false;
                why = "oracle verify failed: code " + std::to_string(rc) + " at " +
                      stage_name(diag.stage) + ": " + diag.message;
            } else if (info.output_sha256 != row.fixture_sha256) {
                ok = false;
                why = "oracle output SHA-256 " + info.output_sha256 + " != H1 " + row.fixture_sha256;
            } else if (info.total_length != row.fixture_bytes) {
                ok = false;
                why = "oracle total_length " + info.total_length + " != H1 " + row.fixture_bytes;
            } else if (std::to_string(info.file_bytes) != row.wire_bytes) {
                ok = false;
                why = "oracle file_bytes disagrees with the manifest";
            } else if (std::to_string(info.node_count) != row.ir_nodes ||
                       std::to_string(info.atom_count) != row.ir_atoms) {
                ok = false;
                why = "oracle node/atom counts disagree with the canonical term";
            }
        }

        // Structural re-validation (stages 1-10 only) must also accept the wire.
        if (ok) {
            Info struct_info;
            Diagnostic struct_diag;
            const int rc_struct = validate_bytes(
                std::span<const std::uint8_t>(wire.data(), wire.size()), /*structure_only=*/true,
                &struct_info, &struct_diag);
            if (rc_struct != 0) {
                ok = false;
                why = "oracle structural validation failed: code " + std::to_string(rc_struct) +
                      " at " + stage_name(struct_diag.stage) + ": " + struct_diag.message;
            }
        }

        // F00/F01 additionally get a literal byte-for-byte comparison, because
        // for those two the exact bytes are pinned by §12.3 and are tiny.
        std::string literal_note = "not-applicable";
        if (ok && (id == "F00" || id == "F01")) {
            std::vector<std::uint8_t> decoded;
            Diagnostic decode_diag;
            const int rc_decode = decode_bytes(
                std::span<const std::uint8_t>(wire.data(), wire.size()), decoded, nullptr,
                &decode_diag);
            const std::vector<std::uint8_t> expected_bytes =
                id == "F00" ? std::vector<std::uint8_t>{} : std::vector<std::uint8_t>{0xA5U};
            if (rc_decode != 0) {
                ok = false;
                why = "oracle decode failed: code " + std::to_string(rc_decode) + " at " +
                      stage_name(decode_diag.stage) + ": " + decode_diag.message;
            } else if (decoded != expected_bytes) {
                ok = false;
                why = "decoded bytes differ from the §12.3 literal";
            } else {
                literal_note = "equal";
            }
        }

        if (ok) {
            ++passed;
            ++engine_agree;
            wire_bytes_total += static_cast<std::uint64_t>(wire.size());
            identity_text += id + '\t' + row.fixture_bytes + '\t' + row.fixture_sha256 + '\t' +
                             std::to_string(wire.size()) + '\t' + row.wire_sha256 + '\n';
        }

        col.add_log("oracle.f00-f08: " + id +
                    " fixture_bytes=" + (row.fixture_bytes.empty() ? "?" : row.fixture_bytes) +
                    " fixture_sha256=" + (row.fixture_sha256.empty() ? "?" : row.fixture_sha256) +
                    " wire_bytes=" + std::to_string(wire.size()) +
                    " wire_sha256=" +
                    (wire.empty() ? std::string("?")
                                  : sha256_hex(std::span<const std::uint8_t>(wire.data(), wire.size()))) +
                    " oracle_output_sha256=" + (info.output_sha256.empty() ? "?" : info.output_sha256) +
                    " oracle_total_length=" + (info.total_length.empty() ? "?" : info.total_length) +
                    " nodes=" + std::to_string(info.node_count) +
                    " atoms=" + std::to_string(info.atom_count) +
                    " index=" + std::string(info.has_index ? "present" : "absent") +
                    " literal_bytes=" + literal_note +
                    " result=" + (ok ? "PASS" : "FAIL") +
                    (ok ? std::string() : " reason=" + why));
        EXPECT_TRUE(ok) << id << ": " << why;
    }

    const bool all_ok = setup_failure.empty() && passed == total && total > 0;
    const std::string expected_text =
        std::to_string(total) + "/" + std::to_string(total) +
        " byte-exact (sha256(out)==sha256(in))";
    const std::string actual_text =
        std::to_string(passed) + "/" + std::to_string(total) + " byte-exact; wire_bytes=" +
        std::to_string(wire_bytes_total) + "; engine_vs_oracle=" + std::to_string(engine_agree) +
        "/" + std::to_string(total) + " digests agree";

    col.add_row("oracle.f00-f08", "ORACLE", "f00-f08-cross-check",
                sha256_of_string(identity_text), expected_text, actual_text,
                all_ok ? "PASS" : "FAIL", "logs/H3-ORACLE.log#oracle.f00-f08");
    col.add_log("oracle.f00-f08: cross_check_dir=" + col.cross_check_dir.string() +
                " fixtures=" + std::to_string(total) + " passed=" + std::to_string(passed) +
                " wire_bytes=" + std::to_string(wire_bytes_total) +
                " expected_sha256_source=" + fixtures_manifest.string() +
                " result=" + (all_ok ? "PASS" : "FAIL") +
                (setup_failure.empty() ? std::string() : " reason=" + setup_failure));
    EXPECT_TRUE(all_ok) << setup_failure;
}

// =========================================================================
// Evidence writing helpers (clean-room C++20, matching H2 8-col TSV format)
// =========================================================================

bool check_source_independence(const std::filesystem::path& repo_root,
                               std::string& detail,
                               std::string& src_tree_sha256) {
    const auto oracle_dir = repo_root / "harness" / "oracle";
    if (!std::filesystem::exists(oracle_dir)) {
        detail = "harness/oracle directory not found";
        src_tree_sha256 = sha256_of_string("missing");
        return false;
    }
    std::vector<std::filesystem::path> files;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(
             oracle_dir, std::filesystem::directory_options::follow_directory_symlink)) {
        if (entry.is_regular_file()) {
            files.push_back(entry.path());
        }
    }
    std::sort(files.begin(), files.end());

    std::string manifest_text;
    int files_scanned = 0;
    for (const auto& p : files) {
        std::error_code rel_ec;
        const auto rel = std::filesystem::relative(p, oracle_dir, rel_ec).generic_string();
        manifest_text += rel;
        manifest_text += ':';
        manifest_text += sha256_of_file(p);
        manifest_text += '\n';

        std::ifstream ifs(p);
        std::string line;
        int lineno = 0;
        while (std::getline(ifs, line)) {
            ++lineno;
            const auto pos = line.find("#include");
            if (pos == std::string::npos) continue;
            // Ignore comment lines mentioning #include
            const auto slash = line.find("//");
            if (slash != std::string::npos && slash < pos) continue;
            if (line.find("mapr/", pos) != std::string::npos ||
                line.find("marp/harness/", pos) != std::string::npos) {
                detail = "forbidden include in " + rel + ":" + std::to_string(lineno);
                src_tree_sha256 = sha256_of_string(manifest_text);
                return false;
            }
        }
        ++files_scanned;
    }
    src_tree_sha256 = sha256_of_string(manifest_text);
    detail = "0 forbidden includes across " + std::to_string(files_scanned) + " oracle files";
    return files_scanned >= 7;
}

std::string utc_now_iso() {
    const std::time_t now = std::time(nullptr);
    std::tm g{};
    gmtime_r(&now, &g);
    char buf[80];
    std::snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02dZ",
                  g.tm_year + 1900, g.tm_mon + 1, g.tm_mday,
                  g.tm_hour, g.tm_min, g.tm_sec);
    return std::string(buf);
}

int write_h3_evidence() {
    auto& col = collector();
    const auto root = col.evidence_root;

    // 1) Independence check row (uses deterministic source-tree digest so TSV is host-independent)
    std::string inc_detail;
    std::string src_tree_sha;
    const bool src_indep = check_source_independence(root, inc_detail, src_tree_sha);
    const bool full_indep = src_indep && col.nm_verified_by_ci;
    const std::string bin_sha = (!col.oracle_bin.empty() && std::filesystem::exists(col.oracle_bin))
                                    ? sha256_of_file(col.oracle_bin)
                                    : sha256_of_string("no-oracle-bin");
    col.add_row(
        "independence", "ORACLE", "grep-and-nm-clean-room",
        src_tree_sha,
        "0 engine includes, 0 engine symbols",
        inc_detail + (col.nm_verified_by_ci ? "; nm_clean=YES" : "; nm_clean=NOT_RUN"),
        full_indep ? "PASS" : "FAIL",
        "logs/H3-ORACLE.log#independence");
    col.add_log("independence: " + inc_detail +
                " src_tree_sha256=" + src_tree_sha +
                " nm_verified_by_ci=" + std::string(col.nm_verified_by_ci ? "YES" : "NO"));

    // 2) oracle.f00-f08 is emitted by `OracleF00F08CrossCheck` from measured
    //    values only.  If that test did not run (no cross-check data), no PASS
    //    may be recorded: write an explicit FAIL row rather than a stale or
    //    hand-written verdict.
    {
        bool have_cross_check_row = false;
        for (const auto& r : col.rows) {
            if (r.check == "oracle.f00-f08") have_cross_check_row = true;
        }
        if (!have_cross_check_row) {
            col.add_row("oracle.f00-f08", "ORACLE", "f00-f08-cross-check",
                        sha256_of_string("cross-check-absent"),
                        "byte-exact reproduction of E3 F00-F08 wires",
                        "FAIL: cross-check data absent (no --cross-check-dir)",
                        "FAIL", "logs/H3-ORACLE.log#oracle.f00-f08");
            col.add_log("oracle.f00-f08: FAIL (cross-check data absent; run "
                        "`make -f Makefile.h3 h3-test-cross`)");
        }
    }

    // Sort rows deterministically by (check, corpus, item_id)
    std::sort(col.rows.begin(), col.rows.end(), [](const EvidenceRow& a, const EvidenceRow& b) {
        if (a.check != b.check) return a.check < b.check;
        if (a.corpus != b.corpus) return a.corpus < b.corpus;
        return a.item_id < b.item_id;
    });

    int n_pass = 0, n_fail = 0, n_blocked = 0;
    for (const auto& r : col.rows) {
        if (r.verdict == "PASS") ++n_pass;
        else if (r.verdict == "FAIL") ++n_fail;
        else if (r.verdict == "BLOCKED") ++n_blocked;
    }

    const auto gates_dir = root / "specs_and_reports" / "v2" / "gates";
    const auto logs_dir  = root / "specs_and_reports" / "v2" / "logs";
    const auto ev_dir    = root / "specs_and_reports" / "v2" / "evidence" / "H3";
    std::error_code ec;
    std::filesystem::create_directories(gates_dir, ec);
    std::filesystem::create_directories(logs_dir, ec);
    std::filesystem::create_directories(ev_dir, ec);

    const auto tsv_path = gates_dir / "H3-ORACLE.tsv";
    const auto tsv_tmp  = gates_dir / "H3-ORACLE.tsv.tmp";
    {
        std::ofstream ofs(tsv_tmp, std::ios::binary | std::ios::trunc);
        if (!ofs.is_open()) {
            std::cerr << "failed to write " << tsv_tmp << '\n';
            return 1;
        }
        ofs << "check\tcorpus\titem_id\tinput_sha256\texpected\tactual\tverdict\tlog\n";
        for (const auto& r : col.rows) {
            ofs << r.check << '\t'
                << r.corpus << '\t'
                << r.item_id << '\t'
                << r.input_sha256 << '\t'
                << r.expected << '\t'
                << r.actual << '\t'
                << r.verdict << '\t'
                << r.log << '\n';
        }
        ofs.flush();
        if (!ofs.good()) return 1;
    }
    std::filesystem::rename(tsv_tmp, tsv_path, ec);
    if (ec) return 1;

    const auto log_path = logs_dir / "H3-ORACLE.log";
    const auto log_tmp  = logs_dir / "H3-ORACLE.log.tmp";
    {
        struct utsname u{};
        uname(&u);
        std::ofstream ofs(log_tmp, std::ios::binary | std::ios::trunc);
        if (!ofs.is_open()) return 1;
        ofs << "date_utc: " << utc_now_iso() << '\n'
            << "host: " << u.nodename << '\n'
            << "kernel: " << u.release << '\n'
            << "nproc: " << sysconf(_SC_NPROCESSORS_ONLN) << '\n'
            << "compiler: " << __VERSION__ << '\n'
            << "oracle_bin_sha256: " << bin_sha << '\n'
            << "command_line: " << col.command_line << '\n';
        for (const auto& line : col.log_lines) {
            ofs << line << '\n';
        }
        ofs << "totals: total=" << col.rows.size()
            << " pass=" << n_pass
            << " fail=" << n_fail
            << " blocked=" << n_blocked << '\n';
        if (n_fail > 0) {
            ofs << "RESULT: FAIL\n";
        } else if (n_blocked > 0) {
            ofs << "RESULT: BLOCKED (all implemented H3 oracle checks PASS; oracle.f00-f08 BLOCKED awaiting E3)\n";
        } else {
            ofs << "RESULT: PASS\n";
        }
        ofs << "exit_code: " << (n_fail == 0 ? 0 : 1) << '\n';
        ofs.flush();
        if (!ofs.good()) return 1;
    }
    std::filesystem::rename(log_tmp, log_path, ec);
    if (ec) return 1;

    // Publish the E3-side F00-F08 manifest as committed H3 evidence.  It is
    // harness-written (copied from the producer output), never hand-edited, and
    // it is hash-pinned by SHA256SUMS below.  CI regenerates it from the same
    // deterministic producer, so a drifted or hand-edited copy shows up as a
    // TSV/SHA256SUMS mismatch.
    const auto fixture_evidence = ev_dir / "f00-f08-manifest.tsv";
    bool have_fixture_evidence = false;
    if (!col.cross_check_dir.empty()) {
        const auto produced = col.cross_check_dir / "f00-f08-manifest.tsv";
        if (std::filesystem::exists(produced)) {
            std::error_code copy_ec;
            std::filesystem::copy_file(produced, fixture_evidence,
                                       std::filesystem::copy_options::overwrite_existing, copy_ec);
            if (copy_ec) {
                std::cerr << "failed to publish " << fixture_evidence << ": " << copy_ec.message()
                          << '\n';
                return 1;
            }
            have_fixture_evidence = true;
        }
    }

    // Write SHA256SUMS manifest covering H3-ORACLE.tsv, H3-ORACLE.log and the
    // F00-F08 fixture/wire identity manifest when it is present.
    const auto manifest_path = ev_dir / "SHA256SUMS";
    const auto manifest_tmp  = ev_dir / "SHA256SUMS.tmp";
    {
        const std::string tsv_sha = sha256_of_file(tsv_path);
        const std::string log_sha = sha256_of_file(log_path);
        std::ofstream ofs(manifest_tmp, std::ios::binary | std::ios::trunc);
        if (!ofs.is_open()) return 1;
        ofs << tsv_sha << "  specs_and_reports/v2/gates/H3-ORACLE.tsv\n";
        ofs << log_sha << "  specs_and_reports/v2/logs/H3-ORACLE.log\n";
        if (have_fixture_evidence) {
            ofs << sha256_of_file(fixture_evidence)
                << "  specs_and_reports/v2/evidence/H3/f00-f08-manifest.tsv\n";
        }
        ofs.flush();
        if (!ofs.good()) return 1;
    }
    std::filesystem::rename(manifest_tmp, manifest_path, ec);
    if (ec) return 1;

    return (n_fail == 0) ? 0 : 1;
}

} // namespace

int main(int argc, char** argv) {
    auto& col = collector();
    {
        std::ostringstream cmd;
        for (int i = 0; i < argc; ++i) {
            if (i > 0) cmd << ' ';
            cmd << argv[i];
        }
        col.command_line = cmd.str();
    }

    // Filter custom harness flags before passing remaining args to GoogleTest
    std::vector<char*> gtest_argv;
    gtest_argv.push_back(argv[0]);
    for (int i = 1; i < argc; ++i) {
        const std::string_view arg(argv[i]);
        if (arg == "--write-evidence" && i + 1 < argc) {
            col.write_evidence = true;
            col.evidence_root = argv[++i];
        } else if (arg == "--oracle-bin" && i + 1 < argc) {
            col.oracle_bin = argv[++i];
        } else if (arg == "--nm-verified") {
            col.nm_verified_by_ci = true;
        } else if (arg == "--cross-check-dir" && i + 1 < argc) {
            col.cross_check_dir = argv[++i];
        } else if (arg == "--cross-check-only" && i + 1 < argc) {
            col.cross_check_only = argv[++i];
        } else if (arg == "--repo-root" && i + 1 < argc) {
            col.repo_root = argv[++i];
        } else {
            gtest_argv.push_back(argv[i]);
        }
    }
    // Refuse to write evidence that cannot state the `oracle.f00-f08` verdict
    // from measured values.  The cross-check is the whole point of this row, so
    // an evidence run without it is a hard usage error, not a silent BLOCKED.
    if (col.write_evidence && col.cross_check_dir.empty()) {
        std::cerr << "error: --write-evidence requires --cross-check-dir <dir> "
                     "(run `make -f Makefile.h3 h3-test-cross` or the producer first)\n";
        return 2;
    }

    int gtest_argc = static_cast<int>(gtest_argv.size());
    ::testing::InitGoogleTest(&gtest_argc, gtest_argv.data());

    const int gtest_rc = RUN_ALL_TESTS();
    if (col.write_evidence) {
        const int ev_rc = write_h3_evidence();
        if (gtest_rc != 0 || ev_rc != 0) {
            return 1;
        }
    }
    return gtest_rc;
}
