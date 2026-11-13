// =====================================================================
//  MARP  ::  Stage 2  ::  Noise Detector  ::  noise_detector.hpp
//
//  Entropy estimation to decide when to emit RAW opcode instead of
//  structural atoms. Removes the ~4% noise expansion.
// =====================================================================

#pragma once

#include <cstddef>
#include <cstdint>
#include "mapr/bitseq.hpp"

namespace mapr {

struct NoiseProfile {
    double entropy_order0 = 0.0;      // bits per byte
    double entropy_order1 = 0.0;      // bits per byte  
    double lz_match_ratio = 0.0;      // estimated compressibility
    bool is_noise = false;            // true if RAW should be used
    double estimated_compressed_ratio = 1.0;  // estimated output/input ratio
};

NoiseProfile analyze_noise(const BitSeq& seq);

bool should_use_raw(const BitSeq& seq);

} // namespace mapr