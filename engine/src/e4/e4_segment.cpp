// MARP v2 — E4 MEASURE — C10 SEGMENT (implementation).
//
// Three pure passes, none of which may consult anything but the bytes and the
// constants in `e4_segment.hpp`:
//
//   1. `scan_boundaries(source, L, T)` — §4.5 gear scan for one target.
//   2. `scan_change_points(source, L)` — §4.5 window scan of order-0 entropy and
//      zero fraction at the finest scale.
//   3. `segment_impl(...)` — §4.6 top-down tree over the boundary sets.
//
// Memory and I/O shape:
//   * every scan is streaming in fixed blocks (`kBlockBytes`), so a per-scale
//     pass costs O(1) memory plus the boundary vector;
//   * the change-point scan keeps one 2·W sliding window and reads L + W bytes,
//     not L·(2W/hop): each hop reads only the bytes that entered the window;
//   * the tree is built from the boundary vectors alone, never from the bytes,
//     so building it can be sharded across threads without touching the source.
//
// Parallelism (S5, E4-I3): the only work that runs concurrently is (a) the
// read-only per-scale scans and (b) the per-child subtree construction.  In both
// cases every unit of work writes its own result slot and the merge is a serial
// ordered concatenation — there is no shared accumulator, no reduction, and no
// iteration over an unordered container, so no value can depend on completion
// order.  The first error reported is the one of the lowest job index, so even a
// failing run reports the same code at every worker count.
//
// `Source::read` is `const` and re-readable (E4 §4.1, E4-I11).  `segment()` is
// the normative entry point and always reads serially; only
// `segment_parallel(..., threads > 1, ...)` asks for concurrent read-only
// access, which is the §11 statement that "all parallel work is read-only".

#include "mapr/e4/e4_segment.hpp"

#include <algorithm>
#include <atomic>
#include <cstring>
#include <limits>
#include <optional>
#include <string>
#include <thread>
#include <utility>

#include "mapr/e1_gear.hpp"

namespace marp::v2 {

namespace {

// One streaming block.  A constant, not a function of L (E4 §11).
constexpr std::size_t kBlockBytes = 64u * 1024u;

// E4 §4.2 requires a 128-bit intermediate for the fixed-point sums.  It is spelled
// through `__extension__` because the project builds with `-pedantic -Werror`;
// the type is the one the specification names, not a fixed-width substitute that
// would silently narrow a sum.
#if !defined(__SIZEOF_INT128__)
#error "C10 SEGMENT requires a 128-bit unsigned intermediate (MARP2-E4 §4.2)"
#endif
__extension__ typedef unsigned __int128 u128;

// ---------------------------------------------------------------------------
// Block reader
// ---------------------------------------------------------------------------

// Streams `[off, off + count)` in fixed blocks, calling `fn(block, block_offset)`
// for each.  `fn` returns false to stop early (a cap was reached).  A short or
// failed read is `Io`; nothing is ever silently zero-filled.
template <typename Fn>
[[nodiscard]] MeasureCode for_each_block(Source& source, u64 off, u64 count, Fn&& fn) {
    std::array<u8, kBlockBytes> block{};
    u64 pos = off;
    u64 left = count;
    while (left > 0u) {
        const std::size_t want = static_cast<std::size_t>(std::min<u64>(left, kBlockBytes));
        const std::span<u8> dst(block.data(), want);
        const MeasureCode rc = source.read(BigInt(pos), dst);
        if (rc != MeasureCode::Ok) return MeasureCode::Io;
        if (!fn(std::span<const u8>(block.data(), want), pos)) return MeasureCode::Ok;
        pos += static_cast<u64>(want);
        left -= static_cast<u64>(want);
    }
    return MeasureCode::Ok;
}

// Reads the whole source as a `u64` length.  A length that cannot be addressed
// by a `u64` offset is `Invalid`: this implementation's positions are `u64`
// (widened into `BigInt` for the tree), and returning a truncated boundary set
// for a longer input would be a false measurement rather than a limitation.
[[nodiscard]] MeasureResult<u64> source_length(Source& source) {
    const std::optional<u64> length = source.size().to_u64_checked();
    if (!length.has_value()) return MeasureCode::Invalid;
    return *length;
}

[[nodiscard]] constexpr bool power_of_two(u64 v) noexcept {
    return v != 0u && (v & (v - 1u)) == 0u;
}

// ---------------------------------------------------------------------------
// Boundary scan (§4.5)
// ---------------------------------------------------------------------------

// `B_T` for one target over `[0, L)`.  The gear state resets to 0 at every cut,
// forced or content-defined, exactly as §4.5 specifies.
//
// A cut is recorded only when `i + 1 < L`: §4.5 emits `L` unconditionally at the
// end, so a cut at `L` and that final `L` would be the same position twice, and
// `B_T` is strictly increasing.  The reset still happens at such a cut, which
// leaves the final `L` unaffected.
[[nodiscard]] MeasureResult<std::vector<u64>> scan_boundaries(Source& source, u64 length,
                                                              u64 target) {
    if (!power_of_two(target) || target < 4u) return MeasureCode::Invalid;

    const u64 mask = target - 1u;
    const u64 min_chunk = target / 4u;
    const u64 max_chunk = target * 4u;
    const std::array<u64, 256>& table = mapr::gear_table();

    std::vector<u64> out;
    out.reserve(static_cast<std::size_t>(
                    std::min<u64>(length / std::max<u64>(min_chunk, 1u), kMaxBoundaries)) +
                2u);
    out.push_back(0u);

    // `B_T` is a *set* that "always contains 0 and L, is strictly increasing"
    // (§4.5).  For the empty input `{0, L}` is `{0, 0}`, which as a set is
    // `{0}` — the only reading under which both sentences hold, and the one that
    // lets the empty input keep its single `[0, 0)` leaf (S3).
    if (length == 0u) {
        out.pop_back();
        out.push_back(0u);
        return out;
    }

    u64 start = 0u;
    u64 h = 0u;
    bool capped = false;

    const MeasureCode rc = for_each_block(source, 0u, length,
                                          [&](std::span<const u8> bytes, u64 base) {
        for (std::size_t j = 0; j < bytes.size(); ++j) {
            const u64 i = base + static_cast<u64>(j);
            h = (h << 1u) + table[bytes[j]];  // mod 2^64 by unsigned wrap
            const u64 len = i + 1u - start;
            const bool content_cut = len >= min_chunk && (h & mask) == 0u;
            const bool forced_cut = len >= max_chunk;
            if (!content_cut && !forced_cut) continue;
            const u64 cut = i + 1u;
            if (cut < length) {
                if (out.size() >= kMaxBoundaries) {
                    capped = true;
                    return false;
                }
                out.push_back(cut);
                start = cut;
            }
            h = 0u;
        }
        return true;
    });
    if (capped) return MeasureCode::Limit;
    if (rc != MeasureCode::Ok) return MeasureCode::Io;

    out.push_back(length);
    return out;
}

// ---------------------------------------------------------------------------
// Change points (§4.5)
// ---------------------------------------------------------------------------

// An interior window boundary `i` (with `W` bytes on both sides) is a change
// point when `dH0 >= 2^24` or `dZ >= 2^22`, comparing `[i-W, i)` against
// `[i, i+W)`.  Candidates are inserted in increasing offset order up to the cap
// `L/2048 + 16`, then deduplicated within 2048 bytes keeping the smaller offset.
// The cap is the specified behaviour, not an error: §4.5 defines truncation at
// the cap as "keep the first ones in increasing offset order".
[[nodiscard]] MeasureResult<std::vector<u64>> scan_change_points(Source& source, u64 length) {
    std::vector<u64> candidates;
    if (length < 2u * kChangeWindow) return candidates;  // no i has W on both sides

    const u64 cap = length / kChangeHop + kChangeCapSlack;
    candidates.reserve(static_cast<std::size_t>(std::min<u64>(cap, kMaxBoundaries)));

    const u64 window = kChangeWindow;
    const u64 hop = kChangeHop;
    const u64 span = 2u * window;

    std::vector<u8> buf(static_cast<std::size_t>(span));
    u64 buf_start = 0u;
    u64 buf_len = 0u;  // valid bytes at buf[0, buf_len) starting at buf_start

    std::array<u64, 256> left_counts{};
    std::array<u64, 256> right_counts{};

    for (u64 i = window; i + window <= length; i += hop) {
        const u64 want = i - window;
        const u64 need_end = want + span;

        // Slide the window: keep the overlap, read only what entered.
        if (buf_len != 0u && want >= buf_start && want < buf_start + buf_len) {
            const u64 shift = want - buf_start;
            std::memmove(buf.data(), buf.data() + static_cast<std::size_t>(shift),
                         static_cast<std::size_t>(buf_len - shift));
            buf_len -= shift;
            buf_start = want;
        } else {
            buf_len = 0u;
            buf_start = want;
        }
        if (buf_start + buf_len < need_end) {
            const u64 tail_start = buf_start + buf_len;
            const MeasureCode rc =
                for_each_block(source, tail_start, need_end - tail_start,
                               [&](std::span<const u8> bytes, u64 base) {
                                   const std::size_t at = static_cast<std::size_t>(base - buf_start);
                                   std::memcpy(buf.data() + at, bytes.data(), bytes.size());
                                   return true;
                               });
            if (rc != MeasureCode::Ok) return MeasureCode::Io;
            buf_len = need_end - buf_start;
        }

        left_counts.fill(0u);
        right_counts.fill(0u);
        const std::span<const u8> left(buf.data(), static_cast<std::size_t>(window));
        const std::span<const u8> right(buf.data() + window, static_cast<std::size_t>(window));
        for (const u8 b : left) ++left_counts[b];
        for (const u8 b : right) ++right_counts[b];

        const u64 h0_left = h0_q24_from_counts(left_counts);
        const u64 h0_right = h0_q24_from_counts(right_counts);
        const u64 z_left = zero_frac_q24(left);
        const u64 z_right = zero_frac_q24(right);
        const u64 d_h0 = h0_left > h0_right ? h0_left - h0_right : h0_right - h0_left;
        const u64 d_z = z_left > z_right ? z_left - z_right : z_right - z_left;

        if (d_h0 >= kChangeEntropyQ24 || d_z >= kChangeZeroFracQ24) {
            if (candidates.size() >= cap) break;  // cap reached: stop inserting
            candidates.push_back(i);
        }
    }

    // Dedup within 2048 bytes, keeping the smaller offset.  `candidates` is
    // ascending, so the smaller offset is the earlier one: a candidate is
    // dropped when it lies within 2048 bytes of the last kept candidate.
    std::vector<u64> kept;
    kept.reserve(candidates.size());
    for (const u64 offset : candidates) {
        if (!kept.empty() && offset - kept.back() < kChangeDedupBytes) continue;
        kept.push_back(offset);
    }
    return kept;
}

}  // namespace

// ---------------------------------------------------------------------------
// Fixed point (E4 §4.2)
// ---------------------------------------------------------------------------

u64 ilog2_q24(u64 x) noexcept {
    if (x < 2u) return 0u;
    // Integer part: floor(log2(x)).  24 further bits come from squaring the
    // mantissa into [1, 4) and comparing against 2, all in a 128-bit
    // intermediate: no `std::log2`, no floating point.
    const unsigned msb = static_cast<unsigned>(63u - static_cast<unsigned>(__builtin_clzll(x)));
    // m = y · 2^62 with y = x / 2^msb in [1, 2).  For msb == 63 (x >= 2^63)
    // the scale is a right shift by one, not a left shift by `62 - msb`:
    // writing `x << (62 - msb)` there would be a shift by 2^32-1, which is
    // undefined behaviour and is caught by the sanitizer build.
    u128 m = (msb <= 62u) ? (static_cast<u128>(x) << (62u - msb))
                          : (static_cast<u128>(x) >> 1u);
    u64 fraction = 0u;
    for (unsigned bit = 0; bit < 24u; ++bit) {
        m = (m * m) >> 62u;  // y <- y^2, still scaled by 2^62
        fraction <<= 1u;
        if (m >= (static_cast<u128>(1) << 63u)) {
            m >>= 1u;  // renormalise y^2 into [1, 2)
            fraction |= 1u;
        }
    }
    return (static_cast<u64>(msb) << 24u) + fraction;
}

u64 h0_q24_from_counts(std::span<const u64, 256> counts) noexcept {
    u64 n = 0u;
    for (const u64 c : counts) {
        if (c == 0u) continue;
        if (n > std::numeric_limits<u64>::max() - c) return 0u;  // unreachable for u64 ranges
        n += c;
    }
    if (n == 0u) return 0u;

    // ( N·ilog2(N) − Σ n_i·ilog2(n_i) ) / N, all products in 128 bits; the single
    // division is the final floor, so no partial rounding can enter.
    u128 total = static_cast<u128>(n) * static_cast<u128>(ilog2_q24(n));
    for (const u64 c : counts) {
        if (c == 0u) continue;
        total -= static_cast<u128>(c) * static_cast<u128>(ilog2_q24(c));
    }
    return static_cast<u64>(total / static_cast<u128>(n));
}

u64 h0_q24(std::span<const u8> bytes) noexcept {
    std::array<u64, 256> counts{};
    for (const u8 b : bytes) ++counts[b];
    return h0_q24_from_counts(counts);
}

u64 zero_frac_q24(std::span<const u8> bytes) noexcept {
    if (bytes.empty()) return 0u;
    u64 zeros = 0u;
    for (const u8 b : bytes) {
        if (b == 0x00u) ++zeros;
    }
    const u128 scaled = static_cast<u128>(zeros) << 24u;
    return static_cast<u64>(scaled / static_cast<u128>(bytes.size()));
}

// ---------------------------------------------------------------------------
// Effort (E4 §4.10)
// ---------------------------------------------------------------------------

MeasureResult<ScaleLevels> active_scales(u8 effort) noexcept {
    if (!effort_in_domain(static_cast<u32>(effort))) return MeasureCode::Invalid;
    ScaleLevels result{};
    if (effort <= 2u) {
        // {64 B, 4 KiB, 256 KiB} = kScales[0], kScales[3], kScales[6].
        result.levels[0] = 0u;
        result.levels[1] = 3u;
        result.levels[2] = 6u;
        result.count = 3u;
        return result;
    }
    for (u32 k = 0; k < kScaleCount; ++k) {
        result.levels[k] = static_cast<u8>(k);
    }
    result.count = kScaleCount;
    return result;
}

// ---------------------------------------------------------------------------
// Boundary sets (E4 §4.5, §5.2)
// ---------------------------------------------------------------------------

MeasureResult<std::vector<u64>> boundaries_for_scale(Source& source, u64 target) {
    if (!power_of_two(target) || target < 4u) return MeasureCode::Invalid;
    const MeasureResult<u64> length = source_length(source);
    if (!length.ok()) return length.code();
    return scan_boundaries(source, length.value(), target);
}

MeasureResult<std::vector<u64>> change_points(Source& source) {
    const MeasureResult<u64> length = source_length(source);
    if (!length.ok()) return length.code();
    return scan_change_points(source, length.value());
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

std::string boundaries_text(std::span<const u64> boundaries) {
    std::string out;
    out.reserve(boundaries.size() * 8u + 16u);
    out += std::to_string(boundaries.size());
    out += ':';
    for (std::size_t i = 0; i < boundaries.size(); ++i) {
        if (i != 0u) out += ',';
        out += std::to_string(boundaries[i]);
    }
    return out;
}

std::string tree_text(std::span<const Segment> nodes) {
    std::string out;
    out.reserve(nodes.size() * 24u);
    for (std::size_t i = 0; i < nodes.size(); ++i) {
        if (i != 0u) out += ';';
        out += nodes[i].begin.to_decimal();
        out += '-';
        out += nodes[i].end.to_decimal();
        out += "@d";
        out += std::to_string(nodes[i].depth);
        out += "k";
        out += std::to_string(static_cast<unsigned>(nodes[i].level));
    }
    return out;
}

// ---------------------------------------------------------------------------
// Segment tree (E4 §4.6)
// ---------------------------------------------------------------------------

namespace {

// The per-scale boundary sets the tree is built from.
struct Levels {
    std::array<std::vector<u64>, kScaleCount> boundaries{};
    std::array<u8, kScaleCount> order{};  // ascending level of the j-th active set
    std::array<u8, kScaleCount> index_of{};  // level -> j, or kScaleCount if inactive
    u32 count = 0;

    [[nodiscard]] u8 level_at(u32 j) const noexcept { return order[j]; }

    void set(u32 j, u8 level, std::vector<u64> set) {
        order[j] = level;
        boundaries[level] = std::move(set);
    }
    void finish() {
        index_of.fill(static_cast<u8>(kScaleCount));
        for (u32 j = 0; j < count; ++j) index_of[order[j]] = static_cast<u8>(j);
    }
};

// Children of `[a, b)` at the next finer active level:
//   * no boundary strictly inside  -> one child with the same interval;
//   * otherwise                    -> consecutive pairs of {a} ∪ inner ∪ {b}.
void children_of(u64 a, u64 b, const std::vector<u64>& finer,
                 std::vector<std::pair<u64, u64>>& out) {
    out.clear();
    if (a >= b) {
        // Degenerate interval (only the empty input): {a, b} == {a}, so the node
        // keeps its interval as its single child.
        out.emplace_back(a, b);
        return;
    }
    const auto first = std::upper_bound(finer.begin(), finer.end(), a);
    const auto last = std::lower_bound(finer.begin(), finer.end(), b);
    if (first == last) {
        out.emplace_back(a, b);
        return;
    }
    u64 prev = a;
    for (auto it = first; it != last; ++it) {
        out.emplace_back(prev, *it);
        prev = *it;
    }
    out.emplace_back(prev, b);
}

// Pre-order emission of the subtree rooted at (a, b, level k = order[j], depth d).
// Recursion depth is bounded by the number of active scales (E4 §11), so `j` is
// always a valid index.
[[nodiscard]] MeasureResult<void> emit_subtree(const Levels& levels, u32 j, u64 a, u64 b, u32 depth,
                                               std::vector<Segment>& out, u64 node_budget) {
    if (out.size() >= node_budget) return MeasureCode::Limit;
    out.push_back(Segment{BigInt(a), BigInt(b), depth, levels.level_at(j)});
    if (j == 0u) return MeasureStatus{};  // k == 0: leaf

    const std::vector<u64>& finer = levels.boundaries[levels.level_at(j - 1u)];
    std::vector<std::pair<u64, u64>> children;
    children_of(a, b, finer, children);
    for (const auto& [x, y] : children) {
        const MeasureResult<void> rc =
            emit_subtree(levels, j - 1u, x, y, depth + 1u, out, node_budget);
        if (!rc.ok()) return rc;
    }
    return MeasureStatus{};
}

// Serial builder: the reference order every parallel build must reproduce.
[[nodiscard]] MeasureResult<std::vector<Segment>> build_tree(const Levels& levels, u64 length) {
    std::vector<Segment> out;
    out.reserve(static_cast<std::size_t>(std::min<u64>(length / 4u + 16u, 1ull << 20)));
    const MeasureResult<void> rc = emit_subtree(levels, levels.count - 1u, 0u, length, 0u, out,
                                                kMaxTreeNodes);
    if (!rc.ok()) return rc.code();
    return out;
}

// Sharded builder: the root's children are independent subtrees, so each is built
// into its own vector and the parts are concatenated in child order (ascending
// begin offset, §5.4).  Completion order cannot reach the output.
//
// The root itself is emitted first: `segment()`'s tree is always rooted at
// `[0, L)`, depth 0, at the coarsest active level.
[[nodiscard]] MeasureResult<std::vector<Segment>> build_tree_sharded(const Levels& levels,
                                                                    u64 length, u32 threads) {
    const u32 top = levels.count - 1u;
    std::vector<Segment> out;
    out.push_back(Segment{BigInt(0u), BigInt(length), 0u, levels.level_at(top)});
    if (top == 0u) return out;

    std::vector<std::pair<u64, u64>> roots;
    children_of(0u, length, levels.boundaries[levels.level_at(top - 1u)], roots);

    const std::size_t n = roots.size();
    std::vector<std::vector<Segment>> parts(n);
    std::vector<MeasureCode> codes(n, MeasureCode::Ok);

    std::atomic<std::size_t> next{0};
    auto worker = [&]() {
        for (;;) {
            const std::size_t idx = next.fetch_add(1u, std::memory_order_relaxed);
            if (idx >= n) return;
            const auto& [x, y] = roots[idx];
            const MeasureResult<void> rc =
                emit_subtree(levels, top - 1u, x, y, 1u, parts[idx], kMaxTreeNodes);
            codes[idx] = rc.ok() ? MeasureCode::Ok : rc.code();
        }
    };

    if (threads <= 1u || n <= 1u) {
        worker();
    } else {
        const std::size_t fanout = std::min<std::size_t>(threads, n);
        std::vector<std::thread> pool;
        pool.reserve(fanout);
        for (std::size_t t = 0; t < fanout; ++t) pool.emplace_back(worker);
        for (std::thread& t : pool) t.join();
    }

    // Lowest job index wins, so the reported code is schedule-independent.
    u64 total = 1u;
    for (std::size_t i = 0; i < n; ++i) {
        if (codes[i] != MeasureCode::Ok) return codes[i];
        total += static_cast<u64>(parts[i].size());
    }
    if (total > kMaxTreeNodes) return MeasureCode::Limit;
    out.reserve(static_cast<std::size_t>(total));
    for (std::vector<Segment>& part : parts) {
        for (Segment& node : part) out.push_back(std::move(node));
    }
    return out;
}

// S1/S2/S3 as an internal contract: a tree that violates the spec is `Invalid`,
// never a returned value.  This is the §9 "boundary set not monotone -> Invalid
// (internal contract)" row applied to the whole tree.
//
// The stored order is pre-order from the coarsest level with a single child when
// a level has no finer boundary, so a node's children are the contiguous run of
// following nodes at `depth + 1`; each child's own subtree is skipped by depth.
[[nodiscard]] bool tree_is_sound(const Levels& levels, std::span<const Segment> tree, u64 length) {
    if (tree.empty()) return false;
    if (tree.front().begin != BigInt(0u) || tree.front().end != BigInt(length)) return false;
    if (tree.front().depth != 0u) return false;
    // A single node is the §4.4 "single leaf" tree for `L <= 64`, and it is the
    // finest level; any larger tree is rooted at the coarsest active level.
    if (tree.size() == 1u) {
        if (tree.front().level != 0u) return false;
    } else if (tree.front().level != levels.level_at(levels.count - 1u)) {
        return false;
    }

    // Leaves: level 0, ascending, contiguous, covering [0, L).
    u64 expect = 0u;
    bool saw_leaf = false;
    for (const Segment& node : tree) {
        if (node.level != 0u) continue;
        const std::optional<u64> b = node.begin.to_u64_checked();
        const std::optional<u64> e = node.end.to_u64_checked();
        if (!b.has_value() || !e.has_value()) return false;
        if (*b != expect) return false;                       // gap or overlap (S1)
        if (*b > *e) return false;                            // not an interval
        if (*b == *e && length != 0u) return false;           // S3: only empty input is zero-length
        expect = *e;
        saw_leaf = true;
    }
    if (!saw_leaf || expect != length) return false;

    // S2/S3 by reconstruction over every internal node.
    for (std::size_t i = 0; i < tree.size(); ++i) {
        const Segment& parent = tree[i];
        const std::optional<u64> pb = parent.begin.to_u64_checked();
        const std::optional<u64> pe = parent.end.to_u64_checked();
        if (!pb.has_value() || !pe.has_value()) return false;
        if (*pb > *pe) return false;
        if (*pb == *pe && length != 0u) return false;
        if (parent.level >= kScaleCount) return false;
        const u8 j = levels.index_of[parent.level];
        if (static_cast<u32>(j) >= levels.count) return false;  // level not active at this effort

        u64 cursor = *pb;
        bool any_child = false;
        std::size_t k = i + 1u;
        while (k < tree.size() && tree[k].depth == parent.depth + 1u) {
            const Segment& child = tree[k];
            const std::optional<u64> cb = child.begin.to_u64_checked();
            const std::optional<u64> ce = child.end.to_u64_checked();
            if (!cb.has_value() || !ce.has_value()) return false;
            if (*cb != cursor) return false;          // children do not tile the parent
            if (*ce > *pe) return false;              // child outside the parent
            if (j == 0u) return false;                // a leaf may not have children
            if (child.level != levels.level_at(j - 1u)) return false;  // wrong next level
            cursor = *ce;
            any_child = true;
            std::size_t skip = k + 1u;                // skip this child's subtree
            while (skip < tree.size() && tree[skip].depth > child.depth) ++skip;
            k = skip;
        }
        if (j == 0u) continue;
        if (!any_child) return false;                 // every internal node has >= 1 child
        if (cursor != *pe) return false;              // S2: union of children == parent
    }
    return true;
}

[[nodiscard]] std::vector<Segment> leaves_of(std::span<const Segment> tree) {
    std::vector<Segment> leaves;
    for (const Segment& node : tree) {
        if (node.level == 0u) leaves.push_back(node);
    }
    return leaves;
}

// §4.5: change points are added to `B_64` before dedup, so the finest set is the
// union of the gear boundaries and the change points.  Both inputs are ascending
// and internally deduplicated; the result must still be strictly increasing and
// keep 0 and L, otherwise the internal contract failed (`Invalid`).
[[nodiscard]] MeasureResult<std::vector<u64>> union_boundaries(const std::vector<u64>& base,
                                                             const std::vector<u64>& extra,
                                                             u64 length) {
    std::vector<u64> out;
    out.reserve(base.size() + extra.size());
    std::size_t i = 0u;
    std::size_t j = 0u;
    while (i < base.size() || j < extra.size()) {
        const bool take_base =
            j >= extra.size() || (i < base.size() && base[i] <= extra[j]);
        const u64 value = take_base ? base[i] : extra[j];
        if (out.empty() || value > out.back()) out.push_back(value);
        if (take_base) {
            ++i;
        } else {
            ++j;
        }
    }
    if (out.empty() || out.front() != 0u || out.back() != length) return MeasureCode::Invalid;
    return out;
}

// The whole of `segment()`, after the effort check.
[[nodiscard]] MeasureResult<std::vector<Segment>> segment_impl(Source& source,
                                                              const Provenance& prov,
                                                              const Policy& policy, u32 threads,
                                                              std::vector<Segment>* tree_out) {
    if (!effort_in_domain(static_cast<u32>(policy.effort))) return MeasureCode::Invalid;

    const MeasureResult<u64> length_result = source_length(source);
    if (!length_result.ok()) return length_result.code();
    const u64 length = length_result.value();

    // §5.2 precondition: the provenance must be the identity of *these* bytes.
    // The re-verification is one streaming pass; a mismatch is reported before
    // any boundary is computed, so no row can describe unverified bytes.
    const MeasureStatus matches = provenance_matches(source, prov, policy);
    if (!matches.ok()) return matches.code();

    const MeasureResult<ScaleLevels> active = active_scales(policy.effort);
    if (!active.ok()) return active.code();
    const ScaleLevels levels_active = active.value();

    Levels levels;
    levels.count = levels_active.count;

    if (length <= kSingleLeafMax) {
        // §4.4, read literally: "For L <= 64, both boundary sets are {0, L} and
        // the tree is a single leaf."  A single node, not the eleven-node chain
        // §4.6 would produce from eleven identical boundary sets, because the
        // text names the tree as well as the sets.  The node is the leaf, so it
        // is at level 0 (the finest) and depth 0 (the root).
        std::vector<Segment> only{Segment{BigInt(0u), BigInt(length), 0u, 0u}};
        if (tree_out != nullptr) *tree_out = only;
        return only;
    }
    {
        // One read-only pass per active scale; each job writes its own slot and
        // the merge is a serial ordered concatenation.
        std::vector<std::vector<u64>> results(levels_active.count);
        std::vector<MeasureCode> codes(levels_active.count, MeasureCode::Ok);

        std::atomic<std::size_t> next{0};
        const std::size_t jobs = levels_active.count;
        auto worker = [&]() {
            for (;;) {
                const std::size_t idx = next.fetch_add(1u, std::memory_order_relaxed);
                if (idx >= jobs) return;
                const u8 k = levels_active.levels[idx];
                const MeasureResult<std::vector<u64>> got =
                    scan_boundaries(source, length, kScales[k]);
                if (!got.ok()) {
                    codes[idx] = got.code();
                    continue;
                }
                results[idx] = got.value();
            }
        };
        if (threads <= 1u || jobs <= 1u) {
            worker();
        } else {
            const std::size_t fanout = std::min<std::size_t>(threads, jobs);
            std::vector<std::thread> pool;
            pool.reserve(fanout);
            for (std::size_t t = 0; t < fanout; ++t) pool.emplace_back(worker);
            for (std::thread& t : pool) t.join();
        }
        for (std::size_t idx = 0; idx < jobs; ++idx) {
            if (codes[idx] != MeasureCode::Ok) return codes[idx];
        }

        // Change points belong to the finest scale, level 0, which every effort
        // includes; the detector is skipped only if that were ever false, and
        // then no boundary could claim to be a change point either.
        if (levels_active.levels[0] == 0u) {
            const MeasureResult<std::vector<u64>> changes = scan_change_points(source, length);
            if (!changes.ok()) return changes.code();
            const MeasureResult<std::vector<u64>> merged =
                union_boundaries(results[0], changes.value(), length);
            if (!merged.ok()) return merged.code();
            results[0] = merged.value();
        }

        for (u32 j = 0; j < levels_active.count; ++j) {
            const u8 k = levels_active.levels[j];
            levels.set(j, k, std::move(results[j]));
        }
    }
    levels.finish();

    MeasureResult<std::vector<Segment>> built =
        threads <= 1u ? build_tree(levels, length) : build_tree_sharded(levels, length, threads);
    if (!built.ok()) return built.code();
    std::vector<Segment> tree = std::move(built.value());

    if (!tree_is_sound(levels, tree, length)) return MeasureCode::Invalid;

    std::vector<Segment> leaves = leaves_of(tree);
    if (tree_out != nullptr) *tree_out = std::move(tree);
    return leaves;
}

}  // namespace

MeasureResult<std::vector<Segment>> segment(Source& source, const Provenance& prov,
                                            const Policy& policy, std::vector<Segment>* tree) {
    return segment_impl(source, prov, policy, 1u, tree);
}

MeasureResult<std::vector<Segment>> segment_parallel(Source& source, const Provenance& prov,
                                                     const Policy& policy, u32 threads,
                                                     std::vector<Segment>* tree) {
    return segment_impl(source, prov, policy, threads, tree);
}

}  // namespace marp::v2
