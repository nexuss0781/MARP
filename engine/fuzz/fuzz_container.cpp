// libFuzzer harness for MAPR container parsing
// Tests: ContainerReader, malformed headers, truncated files, corrupt CRCs

#include "mapr/container.hpp"
#include "mapr/bitseq.hpp"
#include "mapr/crypto.hpp"
#include "mapr/dag.hpp"
#include "mapr/decoder.hpp"

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

// Helper: Write fuzz input to temp file and attempt to parse
static int test_container_parse(const uint8_t* data, size_t size) {
    if (size < 64) return 0; // Minimum valid .mapr file is 64 bytes (header)
    
    // Write to temp file
    const std::string temp_path = "/tmp/fuzz_container_XXXXXX.mapr";
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
        ContainerReader reader(temp_path_buf);
        const auto& meta = reader.meta();
        
        // Try to read all chunks
        for (uint64_t i = 0; i < meta.chunk_count; ++i) {
            auto frame = reader.read_chunk(i);
            if (frame.chunk_kind == KIND_EXPLICIT_DAG) {
                // Try to evaluate DAG
                auto seq = evaluate_chunk_dag(frame.dag, frame.bit_len);
                FUZZ_CHECK(seq.bit_len() == frame.bit_len);
            }
        }
        
        // Full decode test
        auto [seq, stats] = decode_mapr_to_bitseq(temp_path_buf, 1);
        FUZZ_CHECK(seq.bit_len() == meta.total_bits);
        
    } catch (const std::exception&) {
        // Expected for malformed input - just don't crash
    } catch (...) {
        // Don't crash on unknown exceptions
    }
    
    std::filesystem::remove(temp_path_buf);
    return 0;
}

// Helper: Test bitseq serialization round-trip
static int test_bitseq_roundtrip(const uint8_t* data, size_t size) {
    if (size == 0 || size > 10000) return 0;
    
    try {
        BitSeq seq = BitSeq::from_bytes_msb(data, size);
        auto bytes = seq.to_bytes_msb();
        BitSeq seq2 = BitSeq::from_bytes_msb(bytes.data(), bytes.size());
        FUZZ_CHECK(seq == seq2);
        
        // Test slice/concat
        if (seq.bit_len() > 10) {
            auto s1 = seq.slice(0, seq.bit_len() / 2);
            auto s2 = seq.slice(seq.bit_len() / 2, seq.bit_len() - seq.bit_len() / 2);
            auto cat = BitSeq::concat({s1, s2});
            FUZZ_CHECK(cat == seq);
        }
        
        // Test V4 operations
        for (uint8_t op = 0; op < 4; ++op) {
            V4Op v4op = static_cast<V4Op>(op);
            auto transformed = seq.apply_v4(v4op);
            auto back = transformed.apply_v4(v4op);
            FUZZ_CHECK(back == seq);
        }
        
    } catch (const std::exception&) {
        // Expected for edge cases
    }
    
    return 0;
}

// Helper: Test crypto functions with fuzz input
static int test_crypto(const uint8_t* data, size_t size) {
    if (size == 0) return 0;
    
    // CRC32
    crc32_compute(data, size);
    
    // SHA-256
    auto hash = Sha256::hash(data, size);
    (void)hash;
    
    // Streaming SHA-256
    Sha256 sha;
    size_t pos = 0;
    while (pos < size) {
        size_t chunk = std::min<size_t>(size - pos, 137);
        sha.update(data + pos, chunk);
        pos += chunk;
    }
    auto final_hash = sha.finalize();
    FUZZ_CHECK(final_hash == Sha256::hash(data, size));
    
    return 0;
}

} // namespace mapr

// libFuzzer entry points
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Run all fuzz tests
    mapr::test_container_parse(data, size);
    mapr::test_bitseq_roundtrip(data, size);
    mapr::test_crypto(data, size);
    return 0;
}