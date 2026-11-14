#include "marp/harness/gates.hpp"
#include "marp/harness/e1_oracle.hpp"
#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace marp::harness {

namespace fs = std::filesystem;

TEST(HarnessGates, GenericRowWriteAndRead) {
    const fs::path tmpdir = fs::temp_directory_path() / "marp_harness_test";
    fs::remove_all(tmpdir);
    fs::create_directories(tmpdir);

    const fs::path tsv = tmpdir / "generic.tsv";

    Row row;
    row.gate = "TEST";
    row.fixture = "fixture1";
    row.input_bytes = BigInt(100);
    row.wire_bytes = BigInt(200);
    row.ratio_num = 1;
    row.ratio_den = 2;
    row.sha_match = true;
    row.verdict = "PASS";
    row.log = "logs/test.log";

    EXPECT_TRUE(write_row(tsv, row));
    EXPECT_TRUE(fs::exists(tsv));

    std::ifstream ifs(tsv);
    std::string header;
    std::string line;
    std::getline(ifs, header);
    std::getline(ifs, line);
    EXPECT_NE(line.find("TEST"), std::string::npos);
    EXPECT_NE(line.find("fixture1"), std::string::npos);
    EXPECT_NE(line.find("PASS"), std::string::npos);

    fs::remove_all(tmpdir);
}

TEST(HarnessGates, EvidenceTsvWriteReadAndSort) {
    const fs::path tmpdir = fs::temp_directory_path() / "marp_harness_evidence";
    fs::remove_all(tmpdir);
    fs::create_directories(tmpdir);
    const fs::path tsv = tmpdir / "E1-G.tsv";

    EvidenceRow b;
    b.check = "arith.add";
    b.corpus = "A-ARITH";
    b.item_id = "00002";
    b.input_sha256 = "bb";
    b.expected = "e";
    b.actual = "e";
    b.verdict = "PASS";
    b.log = "logs/E1-G.log#arith.add/00002";

    EvidenceRow a = b;
    a.item_id = "00001";
    a.input_sha256 = "aa";

    EvidenceRow c;
    c.check = "conv.dec";
    c.corpus = "S-DEC";
    c.item_id = "00000";
    c.input_sha256 = "cc";
    c.expected = "e";
    c.actual = "e";
    c.verdict = "PASS";
    c.log = "logs/E1-G.log#conv.dec/00000";

    ASSERT_TRUE(write_evidence_tsv(tsv, {b, c, a}));
    const std::vector<EvidenceRow> rows = read_evidence_tsv(tsv);
    ASSERT_EQ(rows.size(), 3u);
    EXPECT_EQ(rows[0].check, "arith.add");
    EXPECT_EQ(rows[0].item_id, "00001");
    EXPECT_EQ(rows[1].check, "arith.add");
    EXPECT_EQ(rows[1].item_id, "00002");
    EXPECT_EQ(rows[2].check, "conv.dec");

    fs::remove_all(tmpdir);
}

TEST(HarnessGates, EvidenceTsvRejectsBadVerdictAndTabs) {
    const fs::path tmpdir = fs::temp_directory_path() / "marp_harness_bad";
    fs::remove_all(tmpdir);
    fs::create_directories(tmpdir);
    const fs::path tsv = tmpdir / "bad.tsv";

    EvidenceRow row;
    row.check = "x";
    row.corpus = "y";
    row.item_id = "z";
    row.input_sha256 = "h";
    row.expected = "e";
    row.actual = "a";
    row.verdict = "MAYBE";
    row.log = "logs/x";
    EXPECT_FALSE(write_evidence_tsv(tsv, {row}));

    row.verdict = "PASS";
    row.expected = "bad\tvalue";
    EXPECT_FALSE(write_evidence_tsv(tsv, {row}));

    fs::remove_all(tmpdir);
}

TEST(HarnessGates, RenderAndAllRowsPass) {
    const fs::path tmpdir = fs::temp_directory_path() / "marp_harness_render";
    fs::remove_all(tmpdir);
    fs::create_directories(tmpdir);

    const fs::path tsv_dir = tmpdir / "gates";
    fs::create_directories(tsv_dir);
    const fs::path tsv = tsv_dir / "E1-G.tsv";

    EvidenceRow row;
    row.check = "arith.add";
    row.corpus = "A-ARITH";
    row.item_id = "all";
    row.input_sha256 = sha256_hex("arith.add");
    row.expected = "10";
    row.actual = "10";
    row.verdict = "PASS";
    row.log = "logs/E1-G.log#arith.add";
    ASSERT_TRUE(write_evidence_tsv(tsv, {row}));
    EXPECT_TRUE(all_rows_pass(tsv_dir));

    const fs::path out = tmpdir / "ACCEPTANCE.md";
    EXPECT_EQ(render(tsv_dir, out), 0);
    ASSERT_TRUE(fs::exists(out));
    std::ifstream ifs(out);
    std::stringstream ss;
    ss << ifs.rdbuf();
    EXPECT_NE(ss.str().find("RESULT: PASS"), std::string::npos);

    row.actual = "9";
    row.verdict = "FAIL";
    ASSERT_TRUE(write_evidence_tsv(tsv, {row}));
    EXPECT_FALSE(all_rows_pass(tsv_dir));

    const fs::path out2 = tmpdir / "ACCEPTANCE2.md";
    EXPECT_NE(render(tsv_dir, out2), 0);
    EXPECT_FALSE(fs::exists(out2));
    EXPECT_TRUE(fs::exists(tmpdir / "ACCEPTANCE2.FAIL.md"));

    fs::remove_all(tmpdir);
}

TEST(HarnessGates, VerifyEvidenceManifest) {
    const fs::path tmpdir = fs::temp_directory_path() / "marp_harness_manifest";
    fs::remove_all(tmpdir);
    const fs::path root = tmpdir;
    const fs::path gates_dir = root / "specs_and_reports" / "v2" / "gates";
    const fs::path evidence_dir = root / "specs_and_reports" / "v2" / "evidence" / "E1";
    fs::create_directories(gates_dir);
    fs::create_directories(evidence_dir);

    const fs::path tsv = gates_dir / "E1-G.tsv";
    EvidenceRow row;
    row.check = "arith.add";
    row.corpus = "A-ARITH";
    row.item_id = "all";
    row.input_sha256 = "aa";
    row.expected = "1";
    row.actual = "1";
    row.verdict = "PASS";
    row.log = "logs/E1-G.log#arith.add";
    ASSERT_TRUE(write_evidence_tsv(tsv, {row}));

    const std::string rel = "specs_and_reports/v2/gates/E1-G.tsv";
    const fs::path manifest = evidence_dir / "SHA256SUMS";
    {
        std::ofstream ofs(manifest);
        ofs << sha256_file_hex(root / rel) << "  " << rel << '\n';
    }
    EXPECT_EQ(verify_evidence(manifest), 0);

    {
        std::ofstream ofs(manifest, std::ios::trunc);
        ofs << "00" << sha256_file_hex(root / rel).substr(2) << "  " << rel << '\n';
    }
    EXPECT_NE(verify_evidence(manifest), 0);

    fs::remove_all(tmpdir);
}

TEST(HarnessGates, EnvRecord) {
    const EnvRecord env = capture_env_record(fs::current_path());
    EXPECT_FALSE(env.date_utc.empty());
    EXPECT_FALSE(env.compiler.empty());
}

} // namespace marp::harness
