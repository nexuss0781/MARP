#include "oracle_internal.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace marp::oracle::detail {

namespace {

int fail_eval(Diagnostic* diag, ErrorCode code, std::string msg) {
    const int c = static_cast<int>(code);
    if (diag != nullptr) {
        diag->code = c;
        diag->stage = ValidationStage::Eval;
        diag->message = std::move(msg);
    }
    return c;
}

inline std::uint8_t bit_reverse8(std::uint8_t b) noexcept {
    b = static_cast<std::uint8_t>(((b & 0xF0U) >> 4) | ((b & 0x0FU) << 4));
    b = static_cast<std::uint8_t>(((b & 0xCCU) >> 2) | ((b & 0x33U) << 2));
    b = static_cast<std::uint8_t>(((b & 0xAAU) >> 1) | ((b & 0x55U) << 1));
    return b;
}

inline std::uint8_t rotl8(std::uint8_t b, std::uint8_t k) noexcept {
    return static_cast<std::uint8_t>((b << k) | (b >> (8U - k)));
}

inline std::uint8_t rotr8(std::uint8_t b, std::uint8_t k) noexcept {
    return static_cast<std::uint8_t>((b >> k) | (b << (8U - k)));
}

// 64x64 GF(2) matrix represented by rows: (M * v)[i] = parity(row[i] & v)
struct Gf2Mat64 {
    std::array<std::uint64_t, 64> row{};
};

Gf2Mat64 gf2_identity() noexcept {
    Gf2Mat64 m;
    for (unsigned i = 0; i < 64; ++i) {
        m.row[i] = 1ULL << i;
    }
    return m;
}

Gf2Mat64 gf2_mul(const Gf2Mat64& a, const Gf2Mat64& b) noexcept {
    Gf2Mat64 c;
    for (unsigned i = 0; i < 64; ++i) {
        std::uint64_t mask = a.row[i];
        std::uint64_t acc = 0;
        while (mask != 0ULL) {
            const unsigned k = static_cast<unsigned>(std::countr_zero(mask));
            acc ^= b.row[k];
            mask &= (mask - 1ULL);
        }
        c.row[i] = acc;
    }
    return c;
}

std::uint64_t gf2_apply(const Gf2Mat64& m, std::uint64_t v) noexcept {
    std::uint64_t out = 0;
    for (unsigned i = 0; i < 64; ++i) {
        if ((std::popcount(m.row[i] & v) & 1) != 0) {
            out |= (1ULL << i);
        }
    }
    return out;
}

}  // namespace

// Compute LFSR state after advancing `byte_offset * 8` bit steps in O(log byte_offset)
std::uint64_t lfsr_jump_bytes(std::uint64_t conn,
                              std::uint64_t init,
                              const BigInt& byte_offset) noexcept {
    if (byte_offset.is_zero()) {
        return init;
    }
    // Single-bit transition matrix T:
    // next_state[j] = state[j+1] for 0 <= j < 63
    // next_state[63] = parity(state & conn)
    Gf2Mat64 t1;
    for (unsigned j = 0; j < 63; ++j) {
        t1.row[j] = 1ULL << (j + 1U);
    }
    t1.row[63] = conn;

    // 1 byte = 8 bit transitions: T^8
    const Gf2Mat64 t2 = gf2_mul(t1, t1);
    const Gf2Mat64 t4 = gf2_mul(t2, t2);
    Gf2Mat64 base = gf2_mul(t4, t4);

    Gf2Mat64 acc = gf2_identity();
    const std::size_t bits = byte_offset.bit_length();
    for (std::size_t b = 0; b < bits; ++b) {
        if (byte_offset.get_bit(b)) {
            acc = gf2_mul(base, acc);
        }
        if (b + 1 < bits) {
            base = gf2_mul(base, base);
        }
    }
    return gf2_apply(acc, init);
}

void lfsr_emit(std::uint64_t conn,
               std::uint64_t& state,
               std::span<std::uint8_t> out) noexcept {
    for (std::size_t i = 0; i < out.size(); ++i) {
        std::uint8_t byte = 0;
        for (int bit_pos = 7; bit_pos >= 0; --bit_pos) {
            const std::uint64_t fb =
                static_cast<std::uint64_t>(std::popcount(state & conn) & 1);
            state = (state >> 1) | (fb << 63);
            byte = static_cast<std::uint8_t>(byte | static_cast<std::uint8_t>(fb << bit_pos));
        }
        out[i] = byte;
    }
}

struct EvalFrame {
    std::uint32_t node_id = 0;
    BigInt start;
    std::uint8_t* dst = nullptr;
    std::size_t len = 0;
    std::uint8_t phase = 0;

    std::size_t aux_idx = 0;
    std::size_t aux_done = 0;
    BigInt aux_pos;
    std::vector<std::uint8_t> scratch;

    // Predictor state (used only for NodeKind::Predictor)
    std::uint64_t pred_pos = 0;
    std::uint64_t pred_start = 0;
    std::uint64_t pred_end = 0;
    std::uint8_t pred_prev1 = 0;
    std::uint8_t pred_prev2 = 0;
    std::vector<std::uint8_t> pred_ring;
    std::size_t pred_ring_pos = 0;
};

constexpr std::size_t kMaxTotalScratchBytes = 128ULL << 20; // 128 MiB safety cap

// Explicit-stack iterative evaluator (zero C++ call-stack recursion)
int eval_node_range_iterative(const ParsedContainer& c,
                              const ByteSource& src,
                              std::uint32_t start_node,
                              const BigInt& start_offset,
                              std::span<std::uint8_t> out,
                              const Limits& limits,
                              Diagnostic* diag) {
    if (out.empty()) {
        return 0;
    }

    std::vector<EvalFrame> stack;
    stack.reserve(64);
    {
        EvalFrame root_frame;
        root_frame.node_id = start_node;
        root_frame.start = start_offset;
        root_frame.dst = out.data();
        root_frame.len = out.size();
        stack.push_back(std::move(root_frame));
    }

    std::size_t scratch_bytes = 0;
    auto pop_frame = [&]() {
        const EvalFrame& top = stack.back();
        scratch_bytes -= (top.scratch.size() + top.pred_ring.size());
        stack.pop_back();
    };

    while (!stack.empty()) {
        EvalFrame& cur = stack.back();
        if (cur.len == 0) {
            pop_frame();
            continue;
        }
        const NodeRecord& n = c.nodes[cur.node_id];

        switch (n.kind) {
            case NodeKind::Empty: {
                pop_frame();
                break;
            }

            case NodeKind::Atom: {
                const AtomRecord& atom = c.atoms[n.atom_id];
                const std::uint64_t off = cur.start.to_u64();
                if (!src.read_at(atom.payload_offset + off,
                                 std::span<std::uint8_t>(cur.dst, cur.len))) {
                    return fail_eval(diag, ErrorCode::Io, "failed reading atom payload");
                }
                pop_frame();
                break;
            }

            case NodeKind::Zero: {
                std::memset(cur.dst, 0, cur.len);
                pop_frame();
                break;
            }

            case NodeKind::Affine: {
                const std::uint64_t rem = BigInt::mod_u64(cur.start, 256ULL);
                std::uint8_t val = static_cast<std::uint8_t>(
                    (static_cast<std::uint64_t>(n.affine_start) +
                     rem * static_cast<std::uint64_t>(n.affine_step)) & 0xFFULL);
                for (std::size_t i = 0; i < cur.len; ++i) {
                    cur.dst[i] = val;
                    val = static_cast<std::uint8_t>(val + n.affine_step);
                }
                pop_frame();
                break;
            }

            case NodeKind::Lfsr: {
                std::uint64_t state = lfsr_jump_bytes(n.lfsr_conn, n.lfsr_init, cur.start);
                lfsr_emit(n.lfsr_conn, state, std::span<std::uint8_t>(cur.dst, cur.len));
                pop_frame();
                break;
            }

            case NodeKind::Slice: {
                // Tail call: replace frame in-place (zero stack growth)
                cur.start = BigInt::add(n.param_a, cur.start);
                cur.node_id = n.args[0];
                cur.phase = 0;
                break;
            }

            case NodeKind::Morph: {
                const bool is_block = (n.morph == 3U || n.morph == 4U || n.morph == 5U);
                if (!is_block) {
                    if (cur.phase == 0U) {
                        BigInt child_start = cur.start;
                        if (n.morph == 8U || n.morph == 9U) {
                            const BigInt end_off = BigInt::add_u64(cur.start, cur.len);
                            child_start = BigInt::sub(n.length, end_off);
                        }
                        cur.phase = 1U;
                        EvalFrame child;
                        child.node_id = n.args[0];
                        child.start = std::move(child_start);
                        child.dst = cur.dst;
                        child.len = cur.len;
                        stack.push_back(std::move(child));
                    } else {
                        switch (n.morph) {
                            case 1U: // BIT_REVERSE8
                                for (std::size_t i = 0; i < cur.len; ++i) {
                                    cur.dst[i] = bit_reverse8(cur.dst[i]);
                                }
                                break;
                            case 2U: // INVERT8
                                for (std::size_t i = 0; i < cur.len; ++i) {
                                    cur.dst[i] = static_cast<std::uint8_t>(~cur.dst[i]);
                                }
                                break;
                            case 6U: // ROTL8
                                for (std::size_t i = 0; i < cur.len; ++i) {
                                    cur.dst[i] = rotl8(cur.dst[i], n.morph_k);
                                }
                                break;
                            case 7U: // ROTR8
                                for (std::size_t i = 0; i < cur.len; ++i) {
                                    cur.dst[i] = rotr8(cur.dst[i], n.morph_k);
                                }
                                break;
                            case 8U: // REVERSE_BYTES
                                std::reverse(cur.dst, cur.dst + cur.len);
                                break;
                            case 9U: // REVERSE_BITS = REVERSE_BYTES o BIT_REVERSE8
                                std::reverse(cur.dst, cur.dst + cur.len);
                                for (std::size_t i = 0; i < cur.len; ++i) {
                                    cur.dst[i] = bit_reverse8(cur.dst[i]);
                                }
                                break;
                            default:
                                break;
                        }
                        pop_frame();
                    }
                } else {
                    const std::size_t blk_sz = (n.morph == 3U) ? 2U : (n.morph == 4U ? 4U : 8U);
                    if (cur.phase == 0U) {
                        const std::uint64_t lead = BigInt::mod_u64(cur.start, blk_sz);
                        const BigInt aligned_start = BigInt::sub(cur.start, BigInt(lead));
                        const std::size_t span_len = static_cast<std::size_t>(lead) + cur.len;
                        const std::size_t rem = span_len % blk_sz;
                        const std::size_t trail = (rem == 0U) ? 0U : (blk_sz - rem);
                        const std::size_t aligned_len = span_len + trail;

                        if (scratch_bytes + aligned_len > kMaxTotalScratchBytes) {
                            return fail_eval(diag, ErrorCode::Limit,
                                             "evaluator scratch memory limit exceeded");
                        }
                        cur.aux_idx = static_cast<std::size_t>(lead);
                        cur.scratch.resize(aligned_len);
                        scratch_bytes += aligned_len;
                        cur.phase = 1U;

                        EvalFrame child;
                        child.node_id = n.args[0];
                        child.start = aligned_start;
                        child.dst = cur.scratch.data();
                        child.len = aligned_len;
                        stack.push_back(std::move(child));
                    } else {
                        for (std::size_t pos = 0; pos < cur.scratch.size(); pos += blk_sz) {
                            std::reverse(cur.scratch.data() + pos,
                                         cur.scratch.data() + pos + blk_sz);
                        }
                        std::memcpy(cur.dst, cur.scratch.data() + cur.aux_idx, cur.len);
                        pop_frame();
                    }
                }
                break;
            }

            case NodeKind::Xor: {
                if (cur.phase == 0U) {
                    cur.phase = 1U;
                    EvalFrame child;
                    child.node_id = n.args[0];
                    child.start = cur.start;
                    child.dst = cur.dst;
                    child.len = cur.len;
                    stack.push_back(std::move(child));
                } else if (cur.phase == 1U) {
                    if (scratch_bytes + cur.len > kMaxTotalScratchBytes) {
                        return fail_eval(diag, ErrorCode::Limit,
                                         "evaluator scratch memory limit exceeded");
                    }
                    cur.scratch.resize(cur.len);
                    scratch_bytes += cur.len;
                    cur.phase = 2U;

                    EvalFrame child;
                    child.node_id = n.args[1];
                    child.start = cur.start;
                    child.dst = cur.scratch.data();
                    child.len = cur.len;
                    stack.push_back(std::move(child));
                } else {
                    for (std::size_t i = 0; i < cur.len; ++i) {
                        cur.dst[i] ^= cur.scratch[i];
                    }
                    pop_frame();
                }
                break;
            }

            case NodeKind::Concat: {
                if (cur.phase == 0U) {
                    BigInt cum;
                    std::size_t idx = 0;
                    while (idx < n.args.size()) {
                        const BigInt& clen = c.nodes[n.args[idx]].length;
                        const BigInt next_cum = BigInt::add(cum, clen);
                        if (next_cum > cur.start) {
                            break;
                        }
                        cum = next_cum;
                        ++idx;
                    }
                    cur.aux_idx = idx;
                    cur.aux_pos = std::move(cum);
                    cur.aux_done = 0;
                    cur.phase = 1U;
                }
                if (cur.aux_done >= cur.len) {
                    pop_frame();
                    break;
                }
                while (cur.aux_idx < n.args.size() &&
                       c.nodes[n.args[cur.aux_idx]].length.is_zero()) {
                    ++cur.aux_idx;
                }
                if (cur.aux_idx >= n.args.size()) {
                    return fail_eval(diag, ErrorCode::Mismatch,
                                     "Concat exhausted children before filling range");
                }
                const std::uint32_t child_id = n.args[cur.aux_idx];
                const BigInt& clen = c.nodes[child_id].length;
                const BigInt cur_abs = BigInt::add_u64(cur.start, cur.aux_done);
                const BigInt child_off = BigInt::sub(cur_abs, cur.aux_pos);
                const BigInt child_avail = BigInt::sub(clen, child_off);
                const std::size_t need = cur.len - cur.aux_done;
                const std::size_t take =
                    (child_avail.fits_u64() && child_avail.to_u64() < need)
                        ? static_cast<std::size_t>(child_avail.to_u64())
                        : need;

                std::uint8_t* dst_slice = cur.dst + cur.aux_done;
                cur.aux_done += take;
                if (BigInt::add_u64(child_off, take) == clen) {
                    cur.aux_pos = BigInt::add(cur.aux_pos, clen);
                    ++cur.aux_idx;
                }

                EvalFrame child;
                child.node_id = child_id;
                child.start = child_off;
                child.dst = dst_slice;
                child.len = take;
                stack.push_back(std::move(child));
                break;
            }

            case NodeKind::Repeat: {
                if (cur.phase == 0U) {
                    cur.aux_pos = cur.start;
                    cur.aux_done = 0;
                    cur.phase = 1U;
                }
                if (cur.aux_done >= cur.len) {
                    pop_frame();
                    break;
                }
                const std::uint32_t child_id = n.args[0];
                const BigInt& clen = c.nodes[child_id].length;

                // Fast periodic copy once one full period is already materialised in cur.dst
                if (clen.fits_u64()) {
                    const std::uint64_t period = clen.to_u64();
                    if (period > 0ULL && static_cast<std::uint64_t>(cur.aux_done) >= period) {
                        const std::size_t p = static_cast<std::size_t>(period);
                        while (cur.aux_done < cur.len) {
                            const std::size_t copy_n = std::min(p, cur.len - cur.aux_done);
                            std::memcpy(cur.dst + cur.aux_done,
                                        cur.dst + cur.aux_done - p,
                                        copy_n);
                            cur.aux_done += copy_n;
                        }
                        pop_frame();
                        break;
                    }
                }

                auto [q_unused, rem] = BigInt::divmod(cur.aux_pos, clen);
                (void)q_unused;
                const BigInt avail = BigInt::sub(clen, rem);
                const std::size_t need = cur.len - cur.aux_done;
                const std::size_t take =
                    (avail.fits_u64() && avail.to_u64() < need)
                        ? static_cast<std::size_t>(avail.to_u64())
                        : need;

                std::uint8_t* dst_slice = cur.dst + cur.aux_done;
                cur.aux_pos = BigInt::add_u64(cur.aux_pos, take);
                cur.aux_done += take;

                EvalFrame child;
                child.node_id = child_id;
                child.start = std::move(rem);
                child.dst = dst_slice;
                child.len = take;
                stack.push_back(std::move(child));
                break;
            }

            case NodeKind::Interleave: {
                if (cur.phase == 0U) {
                    cur.aux_pos = cur.start;
                    cur.aux_done = 0;
                    cur.phase = 1U;
                }
                if (cur.aux_done >= cur.len) {
                    pop_frame();
                    break;
                }
                const std::uint64_t k = static_cast<std::uint64_t>(n.args.size());
                const std::uint64_t stride = n.stride;
                const BigInt super_stride = BigInt::mul_u64(BigInt(k), stride);
                auto [blk, rem_big] = BigInt::divmod(cur.aux_pos, super_stride);
                const std::uint64_t rem = rem_big.to_u64();
                const std::size_t cidx = static_cast<std::size_t>(rem / stride);
                const std::uint64_t in_blk = rem % stride;
                const std::uint64_t avail = stride - in_blk;
                const std::size_t need = cur.len - cur.aux_done;
                const std::size_t take =
                    static_cast<std::size_t>(std::min<std::uint64_t>(avail, need));

                BigInt child_off = BigInt::add_u64(BigInt::mul_u64(blk, stride), in_blk);
                std::uint8_t* dst_slice = cur.dst + cur.aux_done;
                cur.aux_pos = BigInt::add_u64(cur.aux_pos, take);
                cur.aux_done += take;

                EvalFrame child;
                child.node_id = n.args[cidx];
                child.start = std::move(child_off);
                child.dst = dst_slice;
                child.len = take;
                stack.push_back(std::move(child));
                break;
            }

            case NodeKind::Predictor: {
                if (cur.phase == 0U) {
                    // For STRIDE_XOR/STRIDE_DELTA, if entire range lies in [0, param),
                    // out[i] = r[i] directly — zero prefix scan, zero ring buffer!
                    if (n.predictor_id >= 3U &&
                        BigInt::add_u64(cur.start, cur.len) <= BigInt(n.predictor_param)) {
                        cur.node_id = n.args[0];
                        cur.phase = 0U;
                        break;
                    }

                    if (!cur.start.fits_u64() || cur.start.to_u64() > limits.max_predictor_prefix) {
                        return fail_eval(diag, ErrorCode::Limit,
                                         "predictor range start exceeds max_predictor_prefix");
                    }
                    cur.pred_start = cur.start.to_u64();
                    cur.pred_end = cur.pred_start + static_cast<std::uint64_t>(cur.len);
                    cur.pred_pos = 0ULL;
                    cur.pred_prev1 = 0U;
                    cur.pred_prev2 = 0U;

                    if (n.predictor_id >= 3U) {
                        if (n.predictor_param > limits.max_predictor_stride_buf) {
                            return fail_eval(diag, ErrorCode::Limit,
                                             "predictor stride exceeds max_predictor_stride_buf");
                        }
                        if (scratch_bytes + n.predictor_param > kMaxTotalScratchBytes) {
                            return fail_eval(diag, ErrorCode::Limit,
                                             "evaluator scratch memory limit exceeded");
                        }
                        cur.pred_ring.assign(n.predictor_param, 0U);
                        scratch_bytes += cur.pred_ring.size();
                        cur.pred_ring_pos = 0;
                    }

                    constexpr std::size_t kPredChunk = 16384;
                    const std::size_t buf_sz = static_cast<std::size_t>(
                        std::min<std::uint64_t>(kPredChunk, cur.pred_end));
                    if (scratch_bytes + buf_sz > kMaxTotalScratchBytes) {
                        return fail_eval(diag, ErrorCode::Limit,
                                         "evaluator scratch memory limit exceeded");
                    }
                    cur.scratch.resize(buf_sz);
                    scratch_bytes += buf_sz;
                    cur.phase = 1U;
                }

                if (cur.phase == 1U) {
                    if (cur.pred_pos >= cur.pred_end) {
                        pop_frame();
                        break;
                    }
                    const std::size_t step = static_cast<std::size_t>(
                        std::min<std::uint64_t>(cur.scratch.size(), cur.pred_end - cur.pred_pos));
                    cur.aux_idx = step;
                    cur.phase = 2U;

                    EvalFrame child;
                    child.node_id = n.args[0];
                    child.start = BigInt(cur.pred_pos);
                    child.dst = cur.scratch.data();
                    child.len = step;
                    stack.push_back(std::move(child));
                } else {
                    const std::size_t step = cur.aux_idx;
                    for (std::size_t j = 0; j < step; ++j) {
                        const std::uint64_t idx = cur.pred_pos + j;
                        const std::uint8_t r = cur.scratch[j];
                        std::uint8_t out_b = 0;
                        switch (n.predictor_id) {
                            case 0U: // DELTA8: out[0]=r[0]; out[i]=(out[i-1]+r[i]) mod 256
                                out_b = (idx == 0ULL)
                                            ? r
                                            : static_cast<std::uint8_t>(cur.pred_prev1 + r);
                                cur.pred_prev1 = out_b;
                                break;
                            case 1U: // XOR8: out[0]=r[0]; out[i]=out[i-1] XOR r[i]
                                out_b = (idx == 0ULL)
                                            ? r
                                            : static_cast<std::uint8_t>(cur.pred_prev1 ^ r);
                                cur.pred_prev1 = out_b;
                                break;
                            case 2U: // LINEAR2 (literal SPECS-V2 §3.6 & E2 §4.11):
                                     // out[0]=r[0], out[1]=r[1]; out[i]=(2*out[i-1]-out[i-2]) mod 256
                                if (idx == 0ULL) {
                                    out_b = r;
                                    cur.pred_prev1 = out_b;
                                } else if (idx == 1ULL) {
                                    out_b = r;
                                    cur.pred_prev2 = cur.pred_prev1;
                                    cur.pred_prev1 = out_b;
                                } else {
                                    out_b = static_cast<std::uint8_t>(
                                        (2U * static_cast<unsigned>(cur.pred_prev1) -
                                         static_cast<unsigned>(cur.pred_prev2)) & 0xFFU);
                                    cur.pred_prev2 = cur.pred_prev1;
                                    cur.pred_prev1 = out_b;
                                }
                                break;
                            case 3U: // STRIDE_XOR
                                if (idx < n.predictor_param) {
                                    out_b = r;
                                } else {
                                    out_b = static_cast<std::uint8_t>(
                                        cur.pred_ring[cur.pred_ring_pos] ^ r);
                                }
                                cur.pred_ring[cur.pred_ring_pos] = out_b;
                                if (++cur.pred_ring_pos == cur.pred_ring.size()) {
                                    cur.pred_ring_pos = 0;
                                }
                                break;
                            case 4U: // STRIDE_DELTA
                                if (idx < n.predictor_param) {
                                    out_b = r;
                                } else {
                                    out_b = static_cast<std::uint8_t>(
                                        cur.pred_ring[cur.pred_ring_pos] + r);
                                }
                                cur.pred_ring[cur.pred_ring_pos] = out_b;
                                if (++cur.pred_ring_pos == cur.pred_ring.size()) {
                                    cur.pred_ring_pos = 0;
                                }
                                break;
                            default:
                                break;
                        }
                        if (idx >= cur.pred_start) {
                            cur.dst[idx - cur.pred_start] = out_b;
                        }
                    }
                    cur.pred_pos += step;
                    cur.phase = 1U;
                }
                break;
            }
        }
    }

    return 0;
}

std::size_t choose_chunk_size(std::uint32_t root_depth) noexcept {
    if (root_depth > 4096U) {
        return 4096U;
    }
    if (root_depth > 256U) {
        return 16384U;
    }
    return 65536U;
}

int eval_full_stream(const ParsedContainer& c,
                     const ByteSource& src,
                     const ChunkSink& sink,
                     std::array<std::uint8_t, 32>& out_sha256,
                     const Limits& limits,
                     Diagnostic* diag) {
    if (!c.total_length.fits_u64() || c.total_length.to_u64() > limits.max_output_bytes) {
        return fail_eval(diag, ErrorCode::Limit,
                         "declared total_length exceeds max_output_bytes");
    }

    const std::uint64_t total = c.total_length.to_u64();
    const std::uint32_t root = c.trailer.root_id;
    const std::size_t chunk_sz = choose_chunk_size(c.nodes[root].depth);
    std::vector<std::uint8_t> buf(chunk_sz);

    Sha256 sha;
    Crc32 prefix_crc;
    std::size_t next_idx = 0;
    std::uint64_t emitted = 0;

    // Fast O(N) streaming path when root is a Predictor (avoids quadratic prefix rescans)
    const NodeRecord& rnode = c.nodes[root];
    const bool root_is_predictor = (rnode.kind == NodeKind::Predictor);
    std::uint8_t p_prev1 = 0;
    std::uint8_t p_prev2 = 0;
    std::vector<std::uint8_t> p_ring;
    std::size_t p_ring_pos = 0;
    if (root_is_predictor && rnode.predictor_id >= 3U && total > rnode.predictor_param) {
        if (rnode.predictor_param > limits.max_predictor_stride_buf) {
            return fail_eval(diag, ErrorCode::Limit,
                             "predictor stride exceeds max_predictor_stride_buf");
        }
        p_ring.assign(rnode.predictor_param, 0U);
    }

    while (emitted < total) {
        std::uint64_t take_u64 = std::min<std::uint64_t>(buf.size(), total - emitted);
        if (c.has_index && next_idx < c.index_entries.size()) {
            const BigInt& idx_off = c.index_entries[next_idx].output_offset;
            if (idx_off.fits_u64()) {
                const std::uint64_t target = idx_off.to_u64();
                if (target > emitted && emitted + take_u64 > target) {
                    take_u64 = target - emitted;
                }
            }
        }

        const std::size_t take = static_cast<std::size_t>(take_u64);
        std::span<std::uint8_t> slice(buf.data(), take);

        if (root_is_predictor) {
            const int rc = eval_node_range_iterative(
                c, src, rnode.args[0], BigInt(emitted), slice, limits, diag);
            if (rc != 0) {
                return rc;
            }
            for (std::size_t j = 0; j < take; ++j) {
                const std::uint64_t idx = emitted + j;
                const std::uint8_t r = slice[j];
                std::uint8_t out_b = r;
                switch (rnode.predictor_id) {
                    case 0U:
                        out_b = (idx == 0ULL) ? r : static_cast<std::uint8_t>(p_prev1 + r);
                        p_prev1 = out_b;
                        break;
                    case 1U:
                        out_b = (idx == 0ULL) ? r : static_cast<std::uint8_t>(p_prev1 ^ r);
                        p_prev1 = out_b;
                        break;
                    case 2U:
                        if (idx == 0ULL) {
                            out_b = r;
                            p_prev1 = out_b;
                        } else if (idx == 1ULL) {
                            out_b = r;
                            p_prev2 = p_prev1;
                            p_prev1 = out_b;
                        } else {
                            out_b = static_cast<std::uint8_t>(
                                (2U * static_cast<unsigned>(p_prev1) -
                                 static_cast<unsigned>(p_prev2)) & 0xFFU);
                            p_prev2 = p_prev1;
                            p_prev1 = out_b;
                        }
                        break;
                    case 3U:
                        if (!p_ring.empty()) {
                            out_b = (idx < rnode.predictor_param)
                                        ? r
                                        : static_cast<std::uint8_t>(p_ring[p_ring_pos] ^ r);
                            p_ring[p_ring_pos] = out_b;
                            if (++p_ring_pos == p_ring.size()) p_ring_pos = 0;
                        }
                        break;
                    case 4U:
                        if (!p_ring.empty()) {
                            out_b = (idx < rnode.predictor_param)
                                        ? r
                                        : static_cast<std::uint8_t>(p_ring[p_ring_pos] + r);
                            p_ring[p_ring_pos] = out_b;
                            if (++p_ring_pos == p_ring.size()) p_ring_pos = 0;
                        }
                        break;
                    default:
                        break;
                }
                slice[j] = out_b;
            }
        } else {
            const int rc = eval_node_range_iterative(
                c, src, root, BigInt(emitted), slice, limits, diag);
            if (rc != 0) {
                return rc;
            }
        }

        sha.update(slice);
        if (c.has_index) {
            prefix_crc.update(slice);
        }

        const int sink_rc = sink(slice);
        if (sink_rc != 0) {
            return fail_eval(diag, static_cast<ErrorCode>(sink_rc), "output sink error");
        }

        emitted += take_u64;

        if (c.has_index && next_idx < c.index_entries.size()) {
            const BigInt& idx_off = c.index_entries[next_idx].output_offset;
            if (idx_off == BigInt(emitted)) {
                if (prefix_crc.value() != c.index_entries[next_idx].crc32_of_prefix) {
                    return fail_eval(diag, ErrorCode::Invalid,
                                     "seek index crc32_of_prefix mismatch during evaluation");
                }
                ++next_idx;
            }
        }
    }

    if (BigInt(emitted) != c.total_length) {
        return fail_eval(diag, ErrorCode::Mismatch,
                         "evaluated byte count != declared total_length");
    }
    if (c.has_index && next_idx != c.index_entries.size()) {
        return fail_eval(diag, ErrorCode::Invalid,
                         "unverified seek index entries remaining after full evaluation");
    }

    out_sha256 = sha.finalize();
    return 0;
}

int eval_range_stream(const ParsedContainer& c,
                      const ByteSource& src,
                      const BigInt& start,
                      const BigInt& len,
                      const ChunkSink& sink,
                      const Limits& limits,
                      Diagnostic* diag) {
    if (start > c.total_length || BigInt::add(start, len) > c.total_length) {
        return fail_eval(diag, ErrorCode::Invalid,
                         "requested range exceeds declared total_length");
    }
    if (!len.fits_u64() || len.to_u64() > limits.max_output_bytes) {
        return fail_eval(diag, ErrorCode::Limit,
                         "requested range length exceeds max_output_bytes");
    }
    const BigInt max_expanded =
        BigInt::mul_u64(BigInt(src.size()), limits.max_range_expansion_ratio);
    if (len > max_expanded) {
        return fail_eval(diag, ErrorCode::Limit,
                         "requested range exceeds max_range_expansion_ratio");
    }

    const std::uint64_t total_len = len.to_u64();
    if (total_len == 0ULL) {
        return 0;
    }

    const std::uint32_t root = c.trailer.root_id;
    const std::size_t chunk_sz = choose_chunk_size(c.nodes[root].depth);
    std::vector<std::uint8_t> buf(static_cast<std::size_t>(
        std::min<std::uint64_t>(chunk_sz, total_len)));

    std::uint64_t done = 0;
    while (done < total_len) {
        const std::size_t take = static_cast<std::size_t>(
            std::min<std::uint64_t>(buf.size(), total_len - done));
        std::span<std::uint8_t> slice(buf.data(), take);
        const int rc = eval_node_range_iterative(
            c, src, root, BigInt::add_u64(start, done), slice, limits, diag);
        if (rc != 0) {
            return rc;
        }
        const int sink_rc = sink(slice);
        if (sink_rc != 0) {
            return fail_eval(diag, static_cast<ErrorCode>(sink_rc), "output sink error");
        }
        done += take;
    }
    return 0;
}

} // namespace marp::oracle::detail

// ---------------------------------------------------------------------------
// Structural length recomputation (E2-G gate support)
// ---------------------------------------------------------------------------

namespace marp::oracle::detail {

BigInt oracle_node_length(const ParsedContainer& c, std::uint32_t node, bool& ok) {
    ok = true;
    if (node >= c.nodes.size()) {
        ok = false;
        return BigInt();
    }
    std::vector<BigInt> lengths(c.nodes.size());
    std::vector<char> known(c.nodes.size(), 0);
    for (std::size_t i = 0; i < c.nodes.size(); ++i) {
        const NodeRecord& n = c.nodes[i];
        BigInt out;
        bool node_ok = true;
        switch (n.kind) {
            case NodeKind::Empty:
                out = BigInt();
                break;
            case NodeKind::Atom:
                if (n.atom_id >= c.atoms.size()) node_ok = false;
                else out = BigInt(c.atoms[n.atom_id].length);
                break;
            case NodeKind::Zero:
            case NodeKind::Lfsr:
            case NodeKind::Affine:
                out = n.param_a;
                break;
            case NodeKind::Slice:
                out = n.param_b;
                break;
            case NodeKind::Concat:
                for (const std::uint32_t arg : n.args) {
                    if (arg >= i || known[arg] == 0) { node_ok = false; break; }
                    out = BigInt::add(out, lengths[arg]);
                }
                break;
            case NodeKind::Repeat:
                if (n.args.size() != 1 || n.args[0] >= i || known[n.args[0]] == 0) {
                    node_ok = false;
                } else {
                    out = BigInt::add(BigInt::mul(n.param_a, lengths[n.args[0]]), n.param_b);
                }
                break;
            case NodeKind::Morph:
            case NodeKind::Xor:
            case NodeKind::Predictor:
                if (n.args.empty() || n.args[0] >= i || known[n.args[0]] == 0) node_ok = false;
                else out = lengths[n.args[0]];
                break;
            case NodeKind::Interleave:
                if (n.args.empty() || n.args[0] >= i || known[n.args[0]] == 0) node_ok = false;
                else out = BigInt::mul_u64(lengths[n.args[0]],
                                           static_cast<std::uint64_t>(n.args.size()));
                break;
            default:
                node_ok = false;
                break;
        }
        lengths[i] = out;
        known[i] = node_ok ? 1 : 0;
    }
    if (known[node] == 0) {
        ok = false;
        return BigInt();
    }
    return lengths[node];
}

} // namespace marp::oracle::detail
