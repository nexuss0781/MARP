#include "mapr/mapr.h"
#include "mapr/mapr_internal.h"

#include <cstring>
#include <cstdlib>
#include <cstdio>

extern "C" {

// ──────────────────────────────────────────────────────────────
// Encoder (One-shot)
// ──────────────────────────────────────────────────────────────

mapr_result_t mapr_encoder_create(const mapr_encode_config_t* cfg, mapr_encoder_t* out_enc) {
    if (!cfg || !out_enc) return MAPR_ERR_INVALID_ARG;

    // Convert C config to internal config
    mapr::Profile profile = static_cast<mapr::Profile>(cfg->profile);
    mapr::HardwareCaps hw = mapr::probe_hardware();
    mapr::EncodeConfig ecfg = mapr::select_config(profile, hw, 0, cfg->time_budget_sec);

    // Override with explicit settings
    ecfg.raw_bytes_mode = cfg->raw_bytes_mode;
    ecfg.compute_sha256 = cfg->compute_sha256;
    if (cfg->threads > 0) ecfg.threads = cfg->threads;
    if (cfg->max_memory_mb > 0) ecfg.max_memory_mb = cfg->max_memory_mb;

    try {
        *out_enc = new mapr_encoder_s(ecfg);
        return MAPR_OK;
    } catch (...) {
        return MAPR_ERR_MEMORY;
    }
}

mapr_result_t mapr_encoder_encode_file(mapr_encoder_t enc, const char* input_path, const char* output_path) {
    if (!enc || !input_path || !output_path) return MAPR_ERR_INVALID_ARG;

    try {
        mapr::StreamConfig sc = to_stream_config(enc->config);
        mapr::EncodeStats stats = mapr::encode_raw_file_streaming(input_path, output_path,
                                                      static_cast<unsigned>(enc->config.threads), sc);
        (void)stats;
        return MAPR_OK;
    } catch (const std::exception& e) {
        return MAPR_ERR_IO;
    }
}

mapr_result_t mapr_encoder_encode_buffer(mapr_encoder_t enc, const uint8_t* input, size_t input_bytes,
                                         uint8_t** output, size_t* output_bytes) {
    (void)output; (void)output_bytes;
    if (!enc || !input) return MAPR_ERR_INVALID_ARG;

    try {
        mapr::BitSeq seq = mapr::BitSeq::from_bytes_msb(input, input_bytes);
        if (enc->config.raw_bytes_mode && (seq.bit_len() & 7)) {
            return MAPR_ERR_INVALID_ARG;
        }
        // TODO: implement buffer encoding directly
        return MAPR_ERR_UNSUPPORTED;
    } catch (const std::exception& e) {
        return MAPR_ERR_IO;
    }
}

mapr_result_t mapr_encoder_destroy(mapr_encoder_t enc) {
    if (!enc) return MAPR_OK;
    delete enc;
    return MAPR_OK;
}

// ──────────────────────────────────────────────────────────────
// Decoder (One-shot)
// ──────────────────────────────────────────────────────────────

mapr_result_t mapr_decoder_create(const mapr_decode_config_t* cfg, mapr_decoder_t* out_dec) {
    if (!cfg || !out_dec) return MAPR_ERR_INVALID_ARG;

    int threads = cfg->threads > 0 ? cfg->threads : static_cast<int>(std::thread::hardware_concurrency());

    try {
        *out_dec = new mapr_decoder_s(threads, cfg->verify_sha256);
        return MAPR_OK;
    } catch (...) {
        return MAPR_ERR_MEMORY;
    }
}

mapr_result_t mapr_decoder_decode_file(mapr_decoder_t dec, const char* input_path, const char* output_path) {
    if (!dec || !input_path || !output_path) return MAPR_ERR_INVALID_ARG;

    try {
        mapr::DecodeStats stats = mapr::decode_mapr_to_raw_file(input_path, output_path,
                                                     static_cast<unsigned>(dec->config.threads));
        if (dec->config.verify_sha256 && !stats.sha256_verified) {
            return MAPR_ERR_VERIFY_FAILED;
        }
        return MAPR_OK;
    } catch (const std::exception& e) {
        return MAPR_ERR_IO;
    }
}

mapr_result_t mapr_decoder_decode_buffer(mapr_decoder_t dec, const uint8_t* input, size_t input_bytes,
                                         uint8_t** output, size_t* output_bytes) {
    (void)dec; (void)input; (void)input_bytes; (void)output; (void)output_bytes;
    return MAPR_ERR_UNSUPPORTED;
}

mapr_result_t mapr_decoder_destroy(mapr_decoder_t dec) {
    if (!dec) return MAPR_OK;
    delete dec;
    return MAPR_OK;
}

// ──────────────────────────────────────────────────────────────
// Streaming Encoder
// ──────────────────────────────────────────────────────────────

mapr_result_t mapr_stream_encoder_create(const mapr_encode_config_t* cfg, mapr_stream_encoder_t* out_enc) {
    if (!cfg || !out_enc) return MAPR_ERR_INVALID_ARG;

    try {
        // Get hardware caps for profile selection
        mapr::HardwareCaps hw = mapr::probe_hardware();
        
        // Create EncodeConfig from profile using the profile system
        mapr::EncodeConfig ecfg = mapr::select_config(
            static_cast<mapr::Profile>(cfg->profile),
            hw,
            0, // file_bits unknown for streaming
            cfg->time_budget_sec
        );
        
        // Apply user overrides
        ecfg.threads = cfg->threads;
        ecfg.max_memory_mb = cfg->max_memory_mb;
        ecfg.raw_bytes_mode = cfg->raw_bytes_mode;
        ecfg.compute_sha256 = cfg->compute_sha256;
        // Note: metrics_json_out not in EncodeConfig, would need separate handling

        auto* enc = new mapr_stream_encoder_s(ecfg);
        // Initialize writer with memory buffer
        enc->output_buffer = std::make_unique<std::vector<uint8_t>>();
        enc->writer = std::make_unique<mapr::ContainerWriter>(
            *enc->output_buffer,
            enc->stream_config,
            true // raw_bytes_mode
        );
        enc->pipeline = std::make_unique<mapr::BoundedChunkPipeline>(
            *enc->writer, enc->stream_config, static_cast<unsigned>(ecfg.threads)
        );
        // Compute sync mask
        const uint64_t avg_gap = (enc->stream_config.l_target > enc->stream_config.l_min)
            ? (enc->stream_config.l_target - enc->stream_config.l_min) : 65536ULL;
        enc->sync_mask = (1ULL << (std::bit_width(avg_gap) - 1)) - 1ULL;

        *out_enc = enc;
        return MAPR_OK;
    } catch (const std::exception& e) {
        return MAPR_ERR_MEMORY;
    } catch (...) {
        return MAPR_ERR_MEMORY;
    }
}

mapr_result_t mapr_stream_encoder_write(mapr_stream_encoder_t enc, const uint8_t* data, size_t bytes) {
    if (!enc || !data) return MAPR_ERR_INVALID_ARG;
    if (enc->finished) return MAPR_ERR_INVALID_ARG;
    if (bytes == 0) return MAPR_OK;

    try {
        // Update SHA
        enc->sha.update(data, bytes);
        enc->total_input_bits += static_cast<uint64_t>(bytes) * 8ULL;

        // Convert bytes to bit sequence (BITREV8 into wbuf)
        mapr::BitSeq blk = mapr::BitSeq::from_bytes_msb(data, bytes);

        // Append to wbuf (same logic as encode_raw_file_streaming)
        int tail_rem = static_cast<int>(enc->buf_bit_len & 63ULL);
        if (tail_rem == 0) {
            enc->wbuf.insert(enc->wbuf.end(), blk.words().begin(), blk.words().end());
            enc->buf_bit_len += blk.bit_len();
        } else {
            for (size_t i = 0; i < blk.word_count(); ++i) {
                int wb = (i + 1 < blk.word_count() || (blk.bit_len() & 63ULL) == 0ULL)
                         ? 64 : static_cast<int>(blk.bit_len() & 63ULL);
                uint64_t val = blk.word(i) & mapr::low_mask(wb);
                int r = static_cast<int>(enc->buf_bit_len & 63ULL);
                if (r == 0) enc->wbuf.push_back(val);
                else {
                    enc->wbuf.back() |= (val << r);
                    if (r + wb > 64) enc->wbuf.push_back(val >> (64 - r));
                }
                enc->buf_bit_len += static_cast<uint64_t>(wb);
            }
        }

        // Emit ready superchunks whenever at least l_max + l_min bits are buffered
        while ((enc->buf_bit_len - enc->buf_bit_start) > static_cast<uint64_t>(enc->stream_config.l_max) + enc->stream_config.l_min) {
            uint64_t search_s = enc->buf_bit_start + enc->stream_config.l_min;
            uint64_t hard_e = enc->buf_bit_start + enc->stream_config.l_max;
            uint64_t cut = hard_e;
            for (uint64_t p = search_s; p + 64ULL <= hard_e; ++p) {
                // Get word at bit position p
                size_t wi = static_cast<size_t>(p >> 6);
                int sh = static_cast<int>(p & 63ULL);
                uint64_t w = enc->wbuf[wi] >> sh;
                if (sh != 0 && wi + 1 < enc->wbuf.size()) w |= enc->wbuf[wi + 1] << (64 - sh);

                uint64_t cw = std::min(w, ~w);
                if ((mapr::splitmix64(cw) & enc->sync_mask) == 0ULL) {
                    cut = p;
                    break;
                }
            }
            // Extract and submit chunk
            uint64_t chunk_len = cut - enc->buf_bit_start;
            size_t out_words = static_cast<size_t>((chunk_len + 63ULL) >> 6);
            std::vector<uint64_t> res(out_words, 0ULL);
            size_t ws = static_cast<size_t>(enc->buf_bit_start >> 6);
            int sh = static_cast<int>(enc->buf_bit_start & 63ULL);
            if (sh == 0) {
                std::copy_n(enc->wbuf.begin() + static_cast<ptrdiff_t>(ws), out_words, res.begin());
            } else {
                int rsh = 64 - sh;
                for (size_t i = 0; i < out_words; ++i) {
                    uint64_t lo = enc->wbuf[ws + i] >> sh;
                    uint64_t hi = (ws + i + 1 < enc->wbuf.size()) ? (enc->wbuf[ws + i + 1] << rsh) : 0ULL;
                    res[i] = lo | hi;
                }
            }
            mapr::BitSeq chunk_seq(std::move(res), chunk_len);
            enc->pipeline->submit_chunk(std::move(chunk_seq));
            enc->buf_bit_start = cut;
            // Compact buffer
            size_t drop_words = static_cast<size_t>(enc->buf_bit_start >> 6);
            if (drop_words >= 32768) {
                enc->wbuf.erase(enc->wbuf.begin(), enc->wbuf.begin() + static_cast<ptrdiff_t>(drop_words));
                uint64_t drop_bits = static_cast<uint64_t>(drop_words) * 64ULL;
                enc->buf_bit_start -= drop_bits;
                enc->buf_bit_len -= drop_bits;
            }
        }
        return MAPR_OK;
    } catch (const std::exception& e) {
        return MAPR_ERR_IO;
    } catch (...) {
        return MAPR_ERR_IO;
    }
}

mapr_result_t mapr_stream_encoder_finish(mapr_stream_encoder_t enc, uint8_t** output, size_t* output_bytes) {
    if (!enc || !output || !output_bytes) return MAPR_ERR_INVALID_ARG;
    if (enc->finished) return MAPR_ERR_INVALID_ARG;

    try {
        // Drain remaining buffered bits
        if (enc->total_input_bits == 0) {
            enc->pipeline->submit_chunk(mapr::BitSeq::empty());
        } else {
            while (enc->buf_bit_start < enc->buf_bit_len) {
                uint64_t rem_bits = enc->buf_bit_len - enc->buf_bit_start;
                if (rem_bits <= enc->stream_config.l_min) {
                    // Extract remaining
                    size_t out_words = static_cast<size_t>((rem_bits + 63ULL) >> 6);
                    std::vector<uint64_t> res(out_words, 0ULL);
                    size_t ws = static_cast<size_t>(enc->buf_bit_start >> 6);
                    int sh = static_cast<int>(enc->buf_bit_start & 63ULL);
                    if (sh == 0) {
                        std::copy_n(enc->wbuf.begin() + static_cast<ptrdiff_t>(ws), out_words, res.begin());
                    } else {
                        int rsh = 64 - sh;
                        for (size_t i = 0; i < out_words; ++i) {
                            uint64_t lo = enc->wbuf[ws + i] >> sh;
                            uint64_t hi = (ws + i + 1 < enc->wbuf.size()) ? (enc->wbuf[ws + i + 1] << rsh) : 0ULL;
                            res[i] = lo | hi;
                        }
                    }
                    mapr::BitSeq chunk_seq(std::move(res), rem_bits);
                    enc->pipeline->submit_chunk(std::move(chunk_seq));
                    enc->buf_bit_start = enc->buf_bit_len;
                    break;
                }
                uint64_t search_s = enc->buf_bit_start + enc->stream_config.l_min;
                uint64_t hard_e = std::min<uint64_t>(enc->buf_bit_len, enc->buf_bit_start + enc->stream_config.l_max);
                uint64_t cut = hard_e;
                if (hard_e - search_s >= 64ULL) {
                    for (uint64_t p = search_s; p + 64ULL <= hard_e; ++p) {
                        size_t wi = static_cast<size_t>(p >> 6);
                        int sh = static_cast<int>(p & 63ULL);
                        uint64_t w = enc->wbuf[wi] >> sh;
                        if (sh != 0 && wi + 1 < enc->wbuf.size()) w |= enc->wbuf[wi + 1] << (64 - sh);
                        uint64_t cw = std::min(w, ~w);
                        if ((mapr::splitmix64(cw) & enc->sync_mask) == 0ULL) {
                            cut = p;
                            break;
                        }
                    }
                }
                uint64_t chunk_len = cut - enc->buf_bit_start;
                size_t out_words = static_cast<size_t>((chunk_len + 63ULL) >> 6);
                std::vector<uint64_t> res(out_words, 0ULL);
                size_t ws = static_cast<size_t>(enc->buf_bit_start >> 6);
                int sh = static_cast<int>(enc->buf_bit_start & 63ULL);
                if (sh == 0) {
                    std::copy_n(enc->wbuf.begin() + static_cast<ptrdiff_t>(ws), out_words, res.begin());
                } else {
                    int rsh = 64 - sh;
                    for (size_t i = 0; i < out_words; ++i) {
                        uint64_t lo = enc->wbuf[ws + i] >> sh;
                        uint64_t hi = (ws + i + 1 < enc->wbuf.size()) ? (enc->wbuf[ws + i + 1] << rsh) : 0ULL;
                        res[i] = lo | hi;
                    }
                }
                mapr::BitSeq chunk_seq(std::move(res), chunk_len);
                enc->pipeline->submit_chunk(std::move(chunk_seq));
                enc->buf_bit_start = cut;
                // Compact buffer
                size_t drop_words = static_cast<size_t>(enc->buf_bit_start >> 6);
                if (drop_words >= 32768) {
                    enc->wbuf.erase(enc->wbuf.begin(), enc->wbuf.begin() + static_cast<ptrdiff_t>(drop_words));
                    uint64_t drop_bits = static_cast<uint64_t>(drop_words) * 64ULL;
                    enc->buf_bit_start -= drop_bits;
                    enc->buf_bit_len -= drop_bits;
                }
            }
        }

        enc->pipeline->flush_pending();
        auto digest = enc->sha.finalize();
        enc->writer->finish(enc->total_input_bits, digest);

        // Move output buffer to caller
        *output_bytes = enc->output_buffer->size();
        *output = static_cast<uint8_t*>(malloc(*output_bytes));
        if (!*output) return MAPR_ERR_MEMORY;
        std::memcpy(*output, enc->output_buffer->data(), *output_bytes);

        enc->finished = true;
        return MAPR_OK;
    } catch (const std::exception& e) {
        return MAPR_ERR_IO;
    } catch (...) {
        return MAPR_ERR_IO;
    }
}

mapr_result_t mapr_stream_encoder_destroy(mapr_stream_encoder_t enc) {
    if (!enc) return MAPR_OK;
    delete enc;
    return MAPR_OK;
}

// ──────────────────────────────────────────────────────────────
// Inspection & Verification
// ──────────────────────────────────────────────────────────────

mapr_result_t mapr_inspect_file(const char* path, mapr_inspect_result_t* out) {
    if (!path || !out) return MAPR_ERR_INVALID_ARG;

    try {
        mapr::FullInspectReport rep = mapr::inspect_mapr_container(path);
        out->total_bits = rep.meta.total_bits;
        out->chunk_count = rep.summary.chunk_count;
        out->accounted_bits = rep.summary.accounted_bits;
        out->container_bytes = rep.file_size;
        out->valid = true;
        out->compression_ratio = rep.meta.total_bits > 0
            ? static_cast<double>(rep.meta.total_bits) / (static_cast<double>(rep.file_size) * 8.0)
            : 1.0;
        // SHA256 hex
        for (size_t i = 0; i < 32; ++i) {
            std::sprintf(out->stream_sha256 + i * 2, "%02x", rep.meta.stream_sha256[i]);
        }
        out->stream_sha256[64] = '\0';
        return MAPR_OK;
    } catch (const std::exception& e) {
        return MAPR_ERR_CORRUPT;
    }
}

mapr_result_t mapr_verify_file(const char* path) {
    if (!path) return MAPR_ERR_INVALID_ARG;

    try {
        auto [seq, st] = mapr::decode_mapr_to_bitseq(path, 1);
        (void)seq;
        auto rep = mapr::inspect_mapr_container(path);
        (void)rep;
        if (!st.sha256_verified) return MAPR_ERR_VERIFY_FAILED;
        return MAPR_OK;
    } catch (const std::exception& e) {
        return MAPR_ERR_CORRUPT;
    }
}

// ──────────────────────────────────────────────────────────────
// Memory Management
// ──────────────────────────────────────────────────────────────

void mapr_free(void* ptr) {
    std::free(ptr);
}

// ──────────────────────────────────────────────────────────────
// Version
// ──────────────────────────────────────────────────────────────

const char* mapr_version_string(void) {
    return MAPR_VERSION_STRING;
}

void mapr_version(int* major, int* minor, int* patch) {
    if (major) *major = MAPR_VERSION_MAJOR;
    if (minor) *minor = MAPR_VERSION_MINOR;
    if (patch) *patch = MAPR_VERSION_PATCH;
}

} // extern "C"