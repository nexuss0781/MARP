#include "marp/harness/gates.hpp"
#include "marp/harness/e1_oracle.hpp"
#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>
#include <sstream>

namespace marp::harness {

namespace fs = std::filesystem;

TEST(HarnessGates, RowWriteAndRead) {
    fs::path tmpdir = fs::temp_directory_path() / "marp_harness_test";
    fs::remove_all(tmpdir);
    fs::create_directories(tmpdir);
    
    fs::path tsv = tmpdir / "test.tsv";
    
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
    
    // Read back
    std::ifstream ifs(tsv);
    std::string line;
    std::getline(ifs, line); // header
    std::getline(ifs, line); // data
    
    EXPECT_NE(line.find("TEST"), std::string::npos);
    EXPECT_NE(line.find("fixture1"), std::string::npos);
    EXPECT_NE(line.find("100"), std::string::npos);
    EXPECT_NE(line.find("200"), std::string::npos);
    EXPECT_NE(line.find("PASS"), std::string::npos);
    
    // Append second row
    Row row2 = row;
    row2.fixture = "fixture2";
    row2.verdict = "FAIL";
    EXPECT_TRUE(write_row(tsv, row2));
    
    ifs.close();
    ifs.open(tsv);
    std::getline(ifs, line); // header
    std::getline(ifs, line); // row1
    std::getline(ifs, line); // row2
    EXPECT_NE(line.find("fixture2"), std::string::npos);
    EXPECT_NE(line.find("FAIL"), std::string::npos);
    
    fs::remove_all(tmpdir);
}

TEST(HarnessGates, AtomicWrite) {
    fs::path tmpdir = fs::temp_directory_path() / "marp_harness_test2";
    fs::remove_all(tmpdir);
    fs::create_directories(tmpdir);
    
    fs::path tsv = tmpdir / "atomic.tsv";
    
    Row row;
    row.gate = "ATOMIC";
    row.fixture = "test";
    row.verdict = "PASS";
    
    // Write multiple rows rapidly
    for (int i = 0; i < 100; ++i) {
        row.fixture = "test" + std::to_string(i);
        EXPECT_TRUE(write_row(tsv, row));
    }
    
    // Verify all rows present
    std::ifstream ifs(tsv);
    std::string line;
    std::getline(ifs, line); // header
    int count = 0;
    while (std::getline(ifs, line)) {
        if (!line.empty()) count++;
    }
    EXPECT_EQ(count, 100);
    
    fs::remove_all(tmpdir);
}

TEST(HarnessGates, Render) {
    fs::path tmpdir = fs::temp_directory_path() / "marp_harness_test3";
    fs::remove_all(tmpdir);
    fs::create_directories(tmpdir);
    
    fs::path tsv_dir = tmpdir / "gates";
    fs::create_directories(tsv_dir);
    
    fs::path tsv = tsv_dir / "E1-G.tsv";
    Row row;
    row.gate = "E1-G";
    row.fixture = "arith.add";
    row.verdict = "PASS";
    write_row(tsv, row);
    
    row.fixture = "arith.mul";
    row.verdict = "PASS";
    write_row(tsv, row);
    
    fs::path out = tmpdir / "ACCEPTANCE.md";
    int result = render(tsv_dir, out);
    EXPECT_EQ(result, 0);
    EXPECT_TRUE(fs::exists(out));
    
    std::ifstream ifs(out);
    ASSERT_TRUE(ifs.is_open());
    std::stringstream ss;
    ss << ifs.rdbuf();
    std::string content = ss.str();
    EXPECT_NE(content.find("arith.add"), std::string::npos);
    EXPECT_NE(content.find("arith.mul"), std::string::npos);
    EXPECT_NE(content.find("PASS"), std::string::npos);
    
    fs::remove_all(tmpdir);
}

TEST(HarnessGates, EnvRecord) {
    EnvRecord env = capture_env_record();
    EXPECT_FALSE(env.date_utc.empty());
    EXPECT_FALSE(env.host.empty());
    EXPECT_GT(env.nproc, 0);
    EXPECT_GT(env.mem_total_kib, 0);
    EXPECT_FALSE(env.compiler.empty());
}

TEST(HarnessGates, FalseGateDetected) {
    fs::path tmpdir = fs::temp_directory_path() / "marp_harness_test4";
    fs::remove_all(tmpdir);
    fs::create_directories(tmpdir);
    
    fs::path tsv_dir = tmpdir / "gates";
    fs::create_directories(tsv_dir);
    fs::path tsv = tsv_dir / "E0-G.tsv";
    
    // Write a false gate row
    std::ofstream ofs(tsv);
    ofs << "check\tcorpus\titem_id\tinput_sha256\texpected\tactual\tverdict\tlog\n";
    ofs << "E0-G\tMARP-H0\tfalse_gate\tabc\tPASS\tFAIL\tFAIL\tlogs/E0-G.log\n";
    ofs.close();
    
    fs::path out_fail = tmpdir / "ACCEPTANCE.FAIL.md";
    fs::path out_ok = tmpdir / "ACCEPTANCE.md";
    
    // Render should create FAIL version
    int result = render(tsv_dir, out_fail);
    EXPECT_EQ(result, 0);
    EXPECT_TRUE(fs::exists(out_fail));
    
    // ACCEPTANCE.md should not be created/overwritten
    EXPECT_FALSE(fs::exists(out_ok));
    
    fs::remove_all(tmpdir);
}

} // namespace marp::harness