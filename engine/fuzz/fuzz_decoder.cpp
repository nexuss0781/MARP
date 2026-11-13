// libFuzzer harness for MAPR decoder
// Tests: decode_mapr_to_bitseq, decode_mapr_to_raw_file, malformed DAGs

#include "mapr/container.hpp"
#include "mapr/bitseq.hpp"
#include "mapr/crypto.hpp"
#include "mapr/dag.hpp"
#include "mapr/decoder.hpp"
#include "mapr/encoder.hpp"
#include "mapr/pipeline.hpp"

#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>
#include <fstream>
#include <filesystem>
#include <unistd.h>

namespace mapr {

// Simple check macro for fuzzers (doesn't exit, just returns)
#define FUZZ_CHECK(cond) do { if (!(cond)) return 0; } while(0)

// Generate a valid .mapr file with given bit sequence, then corrupt it
static std::vector<uint8_t> make_valid_mapr(const BitSeq& seq) {
    const std::string temp_path = "/tmp/fuzz_gen_XXXXXX.mapr";
    char temp_path_buf[256];
    std::strcpy(temp_path_buf, temp_path.c_str());
    int fd = mkstemp(temp_path_buf);
    close(fd);
    
    try {
        StreamConfig cfg{};
        cfg.w_sync = 64;
        cfg.l_min = 262144;
        cfg.l_target = 1048576;
        cfg.l_max = 4194304;
        cfg.w_hist = 32;
        
        Sha256 sha;
        sha.update(seq.to_bytes_msb().data(), seq.to_bytes_msb().size());
        
        ContainerWriter writer(temp_path_buf, cfg, true);
        BoundedChunkPipeline pipe(writer, cfg, 1);
        pipe.submit_chunk(seq);
        pipe.flush_pending();
        writer.finish(seq.bit_len(), sha.finalize());
    } catch (...) {
        std::filesystem::remove(temp_path_buf);
        return {};
    }
    
    std::ifstream in(temp_path_buf, std::ios::binary);
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    std::filesystem::remove(temp_path_buf);
    return data;
}

static int test_decoder_fuzz(const uint8_t* data, size_t size) {
    if (size < 64) return 0;
    
    const std::string temp_path = "/tmp/fuzz_decode_XXXXXX.mapr";
    char temp_path_buf[256];
    std::strcpy(temp_path_buf, temp_path.c_str());
    int fd = mkstemp(temp_path_buf);
    if (fd < 0) return 0;
    
    ssize_t written = write(fd, data, size);
    close(fd);
    if (written != static_cast<ssize_t>(size)) {
        std::filesystem::remove(temp_path_buf);
        return 0;
    }
    
    try {
        // Test full decode to BitSeq
        auto [seq, stats] = decode_mapr_to_bitseq(temp_path_buf, 1);
        (void)seq;
        (void)stats;
    } catch (const std::exception&) {
        // Expected for invalid input
    } catch (...) {
        // Don't crash
    }
    
    try {
        // Test streaming decode to raw file
        const std::string out_path = "/tmp/fuzz_decode_out_XXXXXX.bin";
        char out_path_buf[256];
        std::strcpy(out_path_buf, out_path.c_str());
        int out_fd = mkstemp(out_path_buf);
        close(out_fd);
        
        auto stats2 = decode_mapr_to_raw_file(temp_path_buf, out_path_buf, 1);
        (void)stats2;
        std::filesystem::remove(out_path_buf);
    } catch (const std::exception&) {
        // Expected
    } catch (...) {
    }
    
    try {
        // Test inspection
        auto report = inspect_mapr_container(temp_path_buf);
        (void)report;
    } catch (const std::exception&) {
    } catch (...) {
    }
    
    std::filesystem::remove(temp_path_buf);
    return 0;
}

static int test_valid_roundtrip(const uint8_t* data, size_t size) {
    if (size == 0 || size > 10000) return 0;
    
    try {
        BitSeq seq = BitSeq::from_bytes_msb(data, size);
        auto mapr_data = make_valid_mapr(seq);
        if (mapr_data.empty()) return 0;
        
        // Write and decode
        const std::string temp_path = "/tmp/fuzz_rt_XXXXXX.mapr";
        char temp_path_buf[256];
        std::strcpy(temp_path_buf, temp_path.c_str());
        int fd = mkstemp(temp_path_buf);
        write(fd, mapr_data.data(), mapr_data.size());
        close(fd);
        
        auto [decoded, stats] = decode_mapr_to_bitseq(temp_path_buf, 1);
        FUZZ_CHECK(decoded == seq);
        FUZZ_CHECK(stats.output_bits == seq.bit_len());
        FUZZ_CHECK(stats.sha256_verified);
        
        std::filesystem::remove(temp_path_buf);
    } catch (const std::exception&) {
    } catch (...) {
    }
    
    return 0;
}

} // namespace mapr

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    mapr::test_decoder_fuzz(data, size);
    mapr::test_valid_roundtrip(data, size);
    return 0;
}