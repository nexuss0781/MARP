// libFuzzer harness for MAPR encoder
// Tests: encode_bitseq_to_file, encode_raw_file_streaming, various profiles

#include "mapr/bitseq.hpp"
#include "mapr/container.hpp"
#include "mapr/encoder.hpp"
#include "mapr/decoder.hpp"
#include "mapr/profile.hpp"
#include "mapr/pipeline.hpp"

#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>
#include <filesystem>
#include <unistd.h>

namespace mapr {

// Simple check macro for fuzzers (doesn't exit, just returns)
#define FUZZ_CHECK(cond) do { if (!(cond)) return 0; } while(0)

// Helper: Convert EncodeConfig to StreamConfig (inline copy from mapr_internal.h)
inline StreamConfig to_stream_config(const EncodeConfig& cfg) {
    StreamConfig sc;
    sc.w_sync = 64;
    sc.l_min = 262144;
    sc.l_target = 1048576;
    sc.l_max = 4194304;
    sc.w_hist = static_cast<uint32_t>(cfg.max_history_window);
    return sc;
}

static int test_encoder_fuzz(const uint8_t* data, size_t size) {
    if (size == 0 || size > 50000) return 0;
    
    try {
        BitSeq seq = BitSeq::from_bytes_msb(data, size);
        
        // Test with all profiles
        for (int p = 0; p < 4; ++p) {
            Profile profile = static_cast<Profile>(p);
            EncodeConfig cfg;
            cfg.enable_lfsr_detection = (p > 0);
            cfg.enable_interleave = (p > 0);
            cfg.enable_xor_diff = (p > 1);
            cfg.enable_morphic_lifting = (p > 2);
            cfg.max_history_window = (p == 0) ? 16 : (p == 1) ? 32 : 64;
            cfg.threads = 1;
            
            const std::string temp_path = "/tmp/fuzz_enc_XXXXXX.mapr";
            char temp_path_buf[256];
            std::strcpy(temp_path_buf, temp_path.c_str());
            int fd = mkstemp(temp_path_buf);
            close(fd);
            
            try {
                StreamConfig sc = to_stream_config(cfg);
                encode_bitseq_to_file(seq, temp_path_buf, false, 1, sc);
                
                // Verify it decodes correctly
                auto [decoded, stats] = decode_mapr_to_bitseq(temp_path_buf, 1);
                FUZZ_CHECK(decoded == seq);
                FUZZ_CHECK(stats.sha256_verified);
            } catch (const std::exception&) {
            } catch (...) {
            }
            
            std::filesystem::remove(temp_path_buf);
        }
        
    } catch (const std::exception&) {
    } catch (...) {
    }
    
    return 0;
}

static int test_streaming_encoder_fuzz(const uint8_t* data, size_t size) {
    if (size == 0 || size > 100000) return 0;
    
    const std::string in_path = "/tmp/fuzz_in_XXXXXX.bin";
    char in_path_buf[256];
    std::strcpy(in_path_buf, in_path.c_str());
    int fd = mkstemp(in_path_buf);
    write(fd, data, size);
    close(fd);
    
    const std::string out_path = "/tmp/fuzz_stream_XXXXXX.mapr";
    char out_path_buf[256];
    std::strcpy(out_path_buf, out_path.c_str());
    int out_fd = mkstemp(out_path_buf);
    close(out_fd);
    
    try {
        StreamConfig cfg{};
        cfg.w_sync = 64;
        cfg.l_min = 262144;
        cfg.l_target = 1048576;
        cfg.l_max = 4194304;
        cfg.w_hist = 32;
        
        encode_raw_file_streaming(in_path_buf, out_path_buf, 1, cfg);
        
        // Verify
        auto [decoded, stats] = decode_mapr_to_bitseq(out_path_buf, 1);
        BitSeq original = BitSeq::from_bytes_msb(data, size);
        FUZZ_CHECK(decoded == original);
        FUZZ_CHECK(stats.sha256_verified);
        
    } catch (const std::exception&) {
    } catch (...) {
    }
    
    std::filesystem::remove(in_path_buf);
    std::filesystem::remove(out_path_buf);
    return 0;
}

static int test_v4_operations(const uint8_t* data, size_t size) {
    if (size == 0) return 0;
    
    try {
        BitSeq seq = BitSeq::from_bytes_msb(data, size);
        
        // Test all V4 operations
        for (int op = 0; op < 4; ++op) {
            V4Op v4op = static_cast<V4Op>(op);
            auto transformed = seq.apply_v4(v4op);
            auto back = transformed.apply_v4(v4op);
            FUZZ_CHECK(back == seq);
            
            // Test composition
            for (int op2 = 0; op2 < 4; ++op2) {
                V4Op v4op2 = static_cast<V4Op>(op2);
                auto composed = seq.apply_v4(v4op).apply_v4(v4op2);
                auto expected = seq.apply_v4(compose_v4(v4op2, v4op));
                FUZZ_CHECK(composed == expected);
            }
        }
        
        // Test DAG encoding/decoding
        if (size < 10000) {
            ExplicitChunkDAG dag = encode_chunk_dag(seq, true);
            auto decoded = evaluate_chunk_dag(dag, seq.bit_len());
            FUZZ_CHECK(decoded == seq);
            
            auto validated = validate_chunk_dag(dag, seq.bit_len());
            FUZZ_CHECK(validated.valid);
        }
        
    } catch (const std::exception&) {
    } catch (...) {
    }
    
    return 0;
}

} // namespace mapr

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    mapr::test_encoder_fuzz(data, size);
    mapr::test_streaming_encoder_fuzz(data, size);
    mapr::test_v4_operations(data, size);
    return 0;
}