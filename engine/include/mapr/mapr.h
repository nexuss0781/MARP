#ifndef MAPR_H
#define MAPR_H

/**
 * MAPR — Multi-Scale Algebraic & Compositional Pattern Representation
 * C API — Stable ABI, single-header
 * Version: 1.0.1
 */

#include <cstdint>
#include <cstddef>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32) || defined(__CYGWIN__)
#  ifdef MAPR_BUILD_DLL
#    define MAPR_API __declspec(dllexport)
#  else
#    define MAPR_API __declspec(dllimport)
#  endif
#else
#  define MAPR_API __attribute__((visibility("default")))
#endif

/* ────────────────────────────────────────────────────────────── */
/* Version                                                         */
/* ────────────────────────────────────────────────────────────── */
#define MAPR_VERSION_MAJOR 1
#define MAPR_VERSION_MINOR 0
#define MAPR_VERSION_PATCH 1
#define MAPR_VERSION_STRING "1.0.1"

/* ────────────────────────────────────────────────────────────── */
/* Opaque Types                                                    */
/* ────────────────────────────────────────────────────────────── */
typedef struct mapr_encoder_s*        mapr_encoder_t;
typedef struct mapr_decoder_s*        mapr_decoder_t;
typedef struct mapr_stream_encoder_s* mapr_stream_encoder_t;
typedef struct mapr_stream_decoder_s* mapr_stream_decoder_t;
typedef struct mapr_hw_caps_s*        mapr_hw_caps_handle_t;

/* ────────────────────────────────────────────────────────────── */
/* Result Codes                                                    */
/* ────────────────────────────────────────────────────────────── */
typedef enum {
    MAPR_OK                        = 0,
    MAPR_ERR_INVALID_ARG           = -1,
    MAPR_ERR_IO                    = -2,
    MAPR_ERR_CORRUPT               = -3,
    MAPR_ERR_VERIFY_FAILED         = -4,
    MAPR_ERR_MEMORY                = -5,
    MAPR_ERR_UNSUPPORTED           = -6,
    MAPR_ERR_TIMEOUT               = -7,
    MAPR_ERR_PROFILE               = -8,
} mapr_result_t;

/* ────────────────────────────────────────────────────────────── */
/* Profile Presets                                                 */
/* ────────────────────────────────────────────────────────────── */
typedef enum {
    MAPR_PROFILE_FAST       = 0,  // Disable LFSR/interleave/XOR-diff, minimal history
    MAPR_PROFILE_BALANCED   = 1,  // Default: all features, adaptive threads
    MAPR_PROFILE_THOROUGH   = 2,  // Max compression, full analysis
    MAPR_PROFILE_MAX        = 3,  // Exhaustive search, no time limit
} mapr_profile_t;

/* ────────────────────────────────────────────────────────────── */
/* Encoder Configuration                                           */
/* ────────────────────────────────────────────────────────────── */
typedef struct {
    mapr_profile_t profile;           // Encoding profile preset
    int            threads;           // 0 = auto (all physical cores)
    size_t         max_memory_mb;     // 0 = auto (25% available RAM)
    bool           raw_bytes_mode;    // true = byte-aligned input (zip, etc.)
    bool           compute_sha256;    // true = verify on decode
    double         time_budget_sec;   // 0 = no limit
    const char*    metrics_json_out;  // Optional path for metrics JSON
} mapr_encode_config_t;

/* ────────────────────────────────────────────────────────────── */
/* Decoder Configuration                                           */
/* ────────────────────────────────────────────────────────────── */
typedef struct {
    int            threads;           // 0 = auto
    size_t         max_memory_mb;     // 0 = auto
    bool           verify_sha256;     // true = verify on decode
    const char*    metrics_json_out;  // Optional path for metrics JSON
} mapr_decode_config_t;

/* ────────────────────────────────────────────────────────────── */
/* Hardware Capabilities                                           */
/* ────────────────────────────────────────────────────────────── */
typedef struct {
    int            physical_cores;
    int            logical_cores;
    size_t         l1_cache_kb;
    size_t         l2_cache_kb;
    size_t         l3_cache_kb;
    bool           has_avx2;
    bool           has_avx512f;
    bool           has_avx512vl;
    bool           has_avx512bw;
    bool           has_avx512dq;
    bool           has_avx512vbmi;
    bool           has_neon;
    bool           has_sve;
    bool           has_bmi2;
    bool           has_popcnt;
    bool           has_lzcnt;
    bool           has_crc32;
    bool           has_sha_ext;
    size_t         total_ram_mb;
    size_t         available_ram_mb;
    float          thermal_headroom;  // 0.0-1.0 (mobile), 1.0 = unknown/desktop
} mapr_hw_caps_t;

/* ────────────────────────────────────────────────────────────── */
/* Inspection Result                                               */
/* ────────────────────────────────────────────────────────────── */
typedef struct {
    uint64_t       total_bits;
    uint64_t       chunk_count;
    uint64_t       accounted_bits;
    char           stream_sha256[65]; // hex string + null
    bool           valid;
    double         compression_ratio; // input_bits / output_bits * 8
    uint64_t       container_bytes;
} mapr_inspect_result_t;

/* ────────────────────────────────────────────────────────────── */
/* Encode/Decode Statistics                                        */
/* ────────────────────────────────────────────────────────────── */
typedef struct {
    uint64_t       input_bits;
    uint64_t       output_bytes;
    uint64_t       chunk_count;
    uint64_t       chunk_ref_count;
    double         wall_seconds;
    double         peak_rss_mb;
    char           stream_sha256_hex[65];
} mapr_encode_stats_t;

typedef struct {
    uint64_t       output_bits;
    uint64_t       output_bytes;
    uint64_t       chunk_count;
    double         wall_seconds;
    double         peak_rss_mb;
    char           stream_sha256_hex[65];
    bool           sha256_verified;
} mapr_decode_stats_t;

/* ────────────────────────────────────────────────────────────── */
/* Hardware Probe                                                  */
/* ────────────────────────────────────────────────────────────── */
/**
 * Probe hardware capabilities. Call once at startup.
 * Results are cached; safe to call multiple times.
 * @param out_caps  Output handle (allocated internally, must be freed with mapr_free_hw_caps)
 * @return MAPR_OK on success
 */
MAPR_API mapr_result_t mapr_probe_hardware(mapr_hw_caps_handle_t* out_caps);

/**
 * Free hardware capabilities handle returned by mapr_probe_hardware.
 * @param caps  Handle to free
 * @return MAPR_OK on success
 */
MAPR_API mapr_result_t mapr_free_hw_caps(mapr_hw_caps_handle_t caps);

/* ────────────────────────────────────────────────────────────── */
/* Encoder (One-shot)                                              */
/* ────────────────────────────────────────────────────────────── */
/**
 * Create encoder with configuration.
 * @param cfg       Configuration (copied internally, can be freed after)
 * @param out_enc   Output encoder handle
 * @return MAPR_OK on success
 */
MAPR_API mapr_result_t mapr_encoder_create(const mapr_encode_config_t* cfg, mapr_encoder_t* out_enc);

/**
 * Encode file to .mapr container.
 * @param enc           Encoder handle
 * @param input_path    Path to input file
 * @param output_path   Path to output .mapr file
 * @return MAPR_OK on success
 */
MAPR_API mapr_result_t mapr_encoder_encode_file(mapr_encoder_t enc, const char* input_path, const char* output_path);

/**
 * Encode buffer to .mapr container.
 * @param enc           Encoder handle
 * @param input         Input buffer
 * @param input_bytes   Input buffer size
 * @param output        Output buffer (allocated via malloc, caller must free with mapr_free)
 * @param output_bytes  Output buffer size
 * @return MAPR_OK on success
 */
MAPR_API mapr_result_t mapr_encoder_encode_buffer(mapr_encoder_t enc, const uint8_t* input, size_t input_bytes, uint8_t** output, size_t* output_bytes);

/**
 * Destroy encoder.
 * @param enc   Encoder handle (set to NULL after)
 * @return MAPR_OK on success
 */
MAPR_API mapr_result_t mapr_encoder_destroy(mapr_encoder_t enc);

/* ────────────────────────────────────────────────────────────── */
/* Decoder (One-shot)                                              */
/* ────────────────────────────────────────────────────────────── */
MAPR_API mapr_result_t mapr_decoder_create(const mapr_decode_config_t* cfg, mapr_decoder_t* out_dec);
MAPR_API mapr_result_t mapr_decoder_decode_file(mapr_decoder_t dec, const char* input_path, const char* output_path);
MAPR_API mapr_result_t mapr_decoder_decode_buffer(mapr_decoder_t dec, const uint8_t* input, size_t input_bytes, uint8_t** output, size_t* output_bytes);
MAPR_API mapr_result_t mapr_decoder_destroy(mapr_decoder_t dec);

/* ────────────────────────────────────────────────────────────── */
/* Streaming Encoder (for huge files / pipes)                      */
/* ────────────────────────────────────────────────────────────── */
/**
 * Create streaming encoder.
 * @param cfg           Configuration
 * @param out_enc       Output stream encoder handle
 * @return MAPR_OK on success
 */
MAPR_API mapr_result_t mapr_stream_encoder_create(const mapr_encode_config_t* cfg, mapr_stream_encoder_t* out_enc);

/**
 * Write data to streaming encoder.
 * @param enc       Stream encoder handle
 * @param data      Input data
 * @param bytes     Input data size
 * @return MAPR_OK on success
 */
MAPR_API mapr_result_t mapr_stream_encoder_write(mapr_stream_encoder_t enc, const uint8_t* data, size_t bytes);

/**
 * Finish streaming encoder and get output.
 * @param enc           Stream encoder handle
 * @param output        Output buffer (allocated via malloc, caller must free with mapr_free)
 * @param output_bytes  Output buffer size
 * @return MAPR_OK on success
 */
MAPR_API mapr_result_t mapr_stream_encoder_finish(mapr_stream_encoder_t enc, uint8_t** output, size_t* output_bytes);

/**
 * Destroy stream encoder (call after finish or on error).
 * @param enc   Stream encoder handle
 * @return MAPR_OK on success
 */
MAPR_API mapr_result_t mapr_stream_encoder_destroy(mapr_stream_encoder_t enc);

/* ────────────────────────────────────────────────────────────── */
/* Inspection & Verification                                       */
/* ────────────────────────────────────────────────────────────── */
MAPR_API mapr_result_t mapr_inspect_file(const char* path, mapr_inspect_result_t* out);
MAPR_API mapr_result_t mapr_verify_file(const char* path);

/* ────────────────────────────────────────────────────────────── */
/* Memory Management                                               */
/* ────────────────────────────────────────────────────────────── */
/**
 * Free buffer allocated by mapr_encoder_encode_buffer or mapr_stream_encoder_finish.
 * @param ptr   Pointer returned by encode functions
 */
MAPR_API void mapr_free(void* ptr);

/* ────────────────────────────────────────────────────────────── */
/* Version Query                                                   */
/* ────────────────────────────────────────────────────────────── */
MAPR_API const char* mapr_version_string(void);
MAPR_API void mapr_version(int* major, int* minor, int* patch);

#ifdef __cplusplus
}
#endif

#endif // MAPR_H