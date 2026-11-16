// MARP v2 — H4 FUZZ — mutation planning.
//
// Four classes, as §12.8 requires, and no fifth:
//   BitFlip           bit flips (single-site, multi-site, random runs)
//   Truncation        prefix cuts at every interesting boundary (below the
//                     minimum container, the header boundary, the trailer, the
//                     index, the last byte)
//   FieldSwap         field swaps (8-byte header offsets, trailer counts and
//                     root id, version fields, index/trailer magic, byte runs)
//   LengthCorruption  length/count/offset corruption (header lengths, region
//                     offsets, flags, trailer counts and file size, root id,
//                     index entry count, version)
//
// The plan is a bounded edit map, not a byte copy, so a 3 MiB seed costs a few
// dozen planned bytes unless the mutant actually needs the whole image (a CRC
// repair).  That is what keeps 100,000 mutants in bounded time without
// skipping the large-container classes.

#include "h4_mutate.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <string_view>

#include "mapr/e3/e3_wire.hpp"
#include "mapr/e1_crc32.hpp"

namespace marp::harness::h4 {
namespace {

using namespace marp::v2;  // NOLINT

constexpr std::size_t kHeader = static_cast<std::size_t>(kWireHeaderBytes);
constexpr std::size_t kTrailer = static_cast<std::size_t>(kWireTrailerBytes);

u16 load16(const std::vector<u8>& b, std::size_t off) noexcept {
    return static_cast<u16>(static_cast<u16>(b[off]) |
                            static_cast<u16>(static_cast<u16>(b[off + 1]) << 8));
}

u32 load32(const std::vector<u8>& b, std::size_t off) noexcept {
    return static_cast<u32>(load16(b, off)) |
           (static_cast<u32>(load16(b, off + 2)) << 16);
}

u64 load64(const std::vector<u8>& b, std::size_t off) noexcept {
    return static_cast<u64>(load32(b, off)) |
           (static_cast<u64>(load32(b, off + 4)) << 32);
}

struct Range {
    std::size_t begin = 0;
    std::size_t end = 0;
    bool empty() const noexcept { return end <= begin; }
    std::size_t length() const noexcept { return end > begin ? end - begin : 0; }
};

void mark_touched(Mutation& m, const SeedLayout& layout, std::size_t off,
                  std::size_t len) {
    const std::size_t end = off + len;
    if (off < kHeader) m.touched_header = true;
    if (off >= layout.trailer_offset || end >= layout.trailer_offset) m.touched_trailer = true;
    if (layout.index_present && end > layout.index_offset && off < layout.trailer_offset) {
        m.touched_index = true;
    }
    if (end > kHeader && off < layout.trailer_offset) m.touched_body = true;
}

void put_byte(Mutation& m, const SeedLayout& layout, std::size_t off, u8 value) {
    m.changes[off] = value;
    mark_touched(m, layout, off, 1);
}

void put16(Mutation& m, const SeedLayout& layout, std::size_t off, u16 value) {
    for (std::size_t i = 0; i < 2; ++i) {
        put_byte(m, layout, off + i, static_cast<u8>((value >> (8u * i)) & 0xFFu));
    }
}

void put32(Mutation& m, const SeedLayout& layout, std::size_t off, u32 value) {
    for (std::size_t i = 0; i < 4; ++i) {
        put_byte(m, layout, off + i, static_cast<u8>((value >> (8u * i)) & 0xFFu));
    }
}

void put64(Mutation& m, const SeedLayout& layout, std::size_t off, u64 value) {
    for (std::size_t i = 0; i < 8; ++i) {
        put_byte(m, layout, off + i, static_cast<u8>((value >> (8u * i)) & 0xFFu));
    }
}

void swap_runs(Mutation& m, const SeedLayout& layout, const std::vector<u8>& base,
               std::size_t a, std::size_t b, std::size_t len) {
    if (a + len > layout.size || b + len > layout.size) return;
    if (a + len > b && b + len > a) return;  // overlapping runs are not swapped
    for (std::size_t i = 0; i < len; ++i) {
        put_byte(m, layout, a + i, base[b + i]);
        put_byte(m, layout, b + i, base[a + i]);
    }
}

void flip_bit(Mutation& m, const SeedLayout& layout, const std::vector<u8>& base,
              std::size_t off, unsigned bit_index) {
    const u8 current = m.changes.count(off) != 0 ? m.changes[off] : base[off];
    const u8 mask = static_cast<u8>(1u << (bit_index & 7u));
    put_byte(m, layout, off, static_cast<u8>(current ^ mask));
}

Range pick_large_range(SplitMix64& rng, const SeedInfo& seed, const SeedLayout& layout) {
    // large seeds: header, trailer and (when present) index only.
    std::array<Range, 3> ranges{};
    std::size_t count = 0;
    ranges[count++] = Range{0, std::min(kHeader, layout.size)};
    ranges[count++] = Range{layout.trailer_offset, layout.size};
    if (layout.index_present && layout.index_offset > 0 &&
        layout.index_offset < layout.trailer_offset) {
        ranges[count++] = Range{layout.index_offset, layout.trailer_offset};
    }
    const std::size_t pick = rng.below(count);
    Range chosen = ranges[pick];
    if (chosen.empty()) chosen = Range{0, layout.size};  // degenerate seed
    (void)seed;
    return chosen;
}

std::size_t pick_offset(SplitMix64& rng, const SeedInfo& seed, const SeedLayout& layout) {
    if (!seed.large) return rng.below(layout.size);
    const Range r = pick_large_range(rng, seed, layout);
    const std::size_t len = r.length();
    return r.begin + (len == 0 ? 0 : rng.below(len));
}

// ---- class 0: bit flips ----------------------------------------------------
void plan_bit_flips(Mutation& m, SplitMix64& rng, const SeedInfo& seed,
                    const SeedLayout& layout) {
    const std::vector<u8>& base = seed.wire;
    const std::size_t ops = 1 + rng.below(seed.large ? 3 : 4);
    for (std::size_t op = 0; op < ops; ++op) {
        if (!seed.large && rng.below(4) == 0) {
            // a contiguous run overwritten with random bytes
            const std::size_t at = rng.below(layout.size);
            const std::size_t capped = std::min<std::size_t>(16, layout.size - at);
            const std::size_t len = 1 + rng.below(capped);
            for (std::size_t i = 0; i < len; ++i) {
                put_byte(m, layout, at + i, static_cast<u8>(rng.next() & 0xFFu));
            }
        } else if (!seed.large && rng.below(5) == 0) {
            // byte-level XOR at one offset
            const std::size_t at = rng.below(layout.size);
            const u8 current = m.changes.count(at) != 0 ? m.changes[at] : base[at];
            put_byte(m, layout, at, static_cast<u8>(current ^ static_cast<u8>(rng.next())));
        } else {
            const std::size_t at = pick_offset(rng, seed, layout);
            flip_bit(m, layout, base, at, static_cast<unsigned>(rng.below(8)));
        }
    }
}

// ---- class 1: truncation ---------------------------------------------------
void plan_truncation(Mutation& m, SplitMix64& rng, const SeedInfo& seed,
                     const SeedLayout& layout) {
    const std::size_t size = layout.size;
    const std::size_t mode = rng.below(8);
    std::size_t target = 0;
    switch (mode) {
        case 0: target = rng.below(size); break;
        case 1: target = rng.below(std::min<std::size_t>(64, size)); break;
        case 2: target = kHeader - 1 + rng.below(4); break;   // 63..66
        case 3: target = 95 + rng.below(3); break;            // 95..97
        case 4: target = size / 2; break;
        case 5: target = size - 1; break;
        case 6: target = layout.trailer_offset; break;
        default: target = layout.index_present ? layout.index_offset : size / 3; break;
    }
    if (size == 0) target = 0;
    if (target >= size) target = size > 0 ? size - 1 : 0;
    m.size = target;
    // A truncation attacks the container bounds: every region boundary is part
    // of the mutation, whether or not a byte below the cut changed.
    m.touched_header = true;
    m.touched_trailer = true;
    if (layout.index_present && target > layout.index_offset) m.touched_index = true;
    if (target > kHeader && layout.trailer_offset > target) m.touched_body = true;
    (void)seed;
}

// ---- class 2: field swaps --------------------------------------------------
void plan_field_swaps(Mutation& m, SplitMix64& rng, const SeedInfo& seed,
                      const SeedLayout& layout) {
    const std::vector<u8>& base = seed.wire;
    const std::size_t modes = seed.large ? 4 : 6;
    switch (rng.below(modes)) {
        case 0: {  // swap two 8-byte header region offsets
            const std::size_t fields[4] = {
                kHdrOffAtomOffset, kHdrOffNodeOffset, kHdrOffIndexOffset,
                kHdrOffTrailerOffset};
            const std::size_t i = rng.below(4);
            std::size_t j = rng.below(4);
            if (j == i) j = (j + 1) % 4;
            swap_runs(m, layout, base, fields[i], fields[j], 8);
            break;
        }
        case 1: {  // swap the two trailer u32 counts
            const std::size_t tr = layout.trailer_offset;
            swap_runs(m, layout, base, tr + kTrlOffAtomCount, tr + kTrlOffNodeCount, 4);
            break;
        }
        case 2: {  // swap trailer root id with the atom count
            const std::size_t tr = layout.trailer_offset;
            swap_runs(m, layout, base, tr + kTrlOffRootId, tr + kTrlOffAtomCount, 4);
            break;
        }
        case 3: {  // swap version major/minor
            swap_runs(m, layout, base, kHdrOffVersionMajor, kHdrOffVersionMinor, 2);
            break;
        }
        case 4: {  // swap header_bytes with the bigint length width
            swap_runs(m, layout, base, kHdrOffHeaderBytes, kHdrOffTotalLengthBigLen, 2);
            break;
        }
        default: {  // swap two equal-length runs inside the body
            const std::size_t body_begin = kHeader;
            const std::size_t body_end = layout.trailer_offset;
            const std::size_t span = body_end > body_begin ? body_end - body_begin : 0;
            if (span < 4) {
                swap_runs(m, layout, base, 0, kHeader, std::min<std::size_t>(4, layout.size / 2));
                break;
            }
            // First half and second half are disjoint by construction, so the
            // swap always changes bytes.
            const std::size_t half = span / 2;
            const std::size_t len = 1 + rng.below(std::min<std::size_t>(16, half));
            const std::size_t a = body_begin + rng.below(half - len + 1);
            const std::size_t b = body_begin + half + rng.below(half - len + 1);
            swap_runs(m, layout, base, a, b, len);
            break;
        }
    }
}

// ---- class 3: length / count / offset corruption ---------------------------
void plan_length_corruption(Mutation& m, SplitMix64& rng, const SeedInfo& seed,
                            const SeedLayout& layout) {
    const std::vector<u8>& base = seed.wire;
    const std::size_t tr = layout.trailer_offset;
    std::size_t modes[9] = {0, 1, 2, 3, 4, 5, 6, 7, 8};
    std::size_t mode_count = 9;
    if (seed.large) {
        const std::size_t large_modes[6] = {0, 1, 4, 5, 6, 7};
        for (std::size_t i = 0; i < 6; ++i) modes[i] = large_modes[i];
        mode_count = 6;
    }
    std::size_t mode = modes[rng.below(mode_count)];
    if (mode == 7 && !layout.index_present) mode = 0;
    const u64 random64 = rng.next();
    const u32 random32 = static_cast<u32>(random64);
    switch (mode) {
        case 0: {  // header region offset
            const std::size_t fields[4] = {
                kHdrOffAtomOffset, kHdrOffNodeOffset, kHdrOffIndexOffset,
                kHdrOffTrailerOffset};
            const std::size_t field = fields[rng.below(4)];
            const u64 original = load64(base, field);
            u64 value = 0;
            switch (rng.below(6)) {
                case 0: value = 0; break;
                case 1: value = static_cast<u64>(layout.size); break;
                case 2: value = static_cast<u64>(layout.size) + 1; break;
                case 3: value = original + 1 + (random64 & 0x3Fu); break;
                case 4: value = ~0ull; break;
                default: value = random64; break;
            }
            put64(m, layout, field, value);
            break;
        }
        case 1: {  // total length (u64 form)
            const u64 original = load64(base, kHdrOffTotalLengthU64);
            u64 value = 0;
            switch (rng.below(6)) {
                case 0: value = 0; break;
                case 1: value = 1; break;
                case 2: value = original + 1; break;
                case 3: value = original > 0 ? original - 1 : 0; break;
                case 4: value = ~0ull; break;
                default: value = random64; break;
            }
            put64(m, layout, kHdrOffTotalLengthU64, value);
            break;
        }
        case 2: {  // flags
            put32(m, layout, kHdrOffFlags, random32);
            break;
        }
        case 3: {  // header_bytes / bigint length width
            const std::size_t field =
                rng.below(2) == 0 ? kHdrOffHeaderBytes : kHdrOffTotalLengthBigLen;
            static const u16 values[] = {0u, 63u, 65u, 0xFFFFu, 1u};
            put16(m, layout, field, values[rng.below(5)]);
            break;
        }
        case 4: {  // trailer file_bytes
            const u64 original = load64(base, tr + kTrlOffFileBytes);
            u64 value = 0;
            switch (rng.below(5)) {
                case 0: value = static_cast<u64>(layout.size); break;
                case 1: value = static_cast<u64>(layout.size) + 1; break;
                case 2: value = original > 0 ? original - 1 : 0; break;
                case 3: value = 0; break;
                default: value = random64; break;
            }
            put64(m, layout, tr + kTrlOffFileBytes, value);
            break;
        }
        case 5: {  // trailer atom/node counts
            const std::size_t field = rng.below(2) == 0 ? tr + kTrlOffAtomCount
                                                        : tr + kTrlOffNodeCount;
            const u32 original = load32(base, field);
            u32 value = 0;
            switch (rng.below(5)) {
                case 0: value = 0; break;
                case 1: value = original + 1; break;
                case 2: value = original > 0 ? original - 1 : 0; break;
                case 3: value = 0xFFFFFFFFu; break;
                default: value = random32; break;
            }
            put32(m, layout, field, value);
            break;
        }
        case 6: {  // trailer root id
            const u32 original = load32(base, tr + kTrlOffRootId);
            u32 value = 0;
            switch (rng.below(5)) {
                case 0: value = 0; break;
                case 1: value = original + 1; break;
                case 2: value = original > 0 ? original - 1 : 0; break;
                case 3: value = 0xFFFFFFFFu; break;
                default: value = random32; break;
            }
            put32(m, layout, tr + kTrlOffRootId, value);
            break;
        }
        case 7: {  // index entry count / magic
            if (rng.below(3) == 0) {
                // one byte of the index magic
                put16(m, layout, layout.index_offset,
                      static_cast<u16>(random32 & 0xFFFFu));
            } else {
                // magic(8) + u32 entry_count (E3 §4.7)
                const u32 original = load32(base, layout.index_offset + 8);
                u32 value = 0;
                switch (rng.below(5)) {
                    case 0: value = 0; break;
                    case 1: value = original + 1; break;
                    case 2: value = original > 0 ? original - 1 : 0; break;
                    case 3: value = 0xFFFFFFFFu; break;
                    default: value = random32; break;
                }
                put32(m, layout, layout.index_offset + 8, value);
            }
            break;
        }
        default: {  // version fields
            const std::size_t field =
                rng.below(2) == 0 ? kHdrOffVersionMajor : kHdrOffVersionMinor;
            static const u16 values[] = {0u, 1u, 3u, 0xFFFFu};
            put16(m, layout, field, values[rng.below(4)]);
            break;
        }
    }
}

void put32_at(std::vector<u8>& wire, std::size_t at, u32 value) {
    for (std::size_t i = 0; i < 4; ++i) {
        wire[at + i] = static_cast<u8>((value >> (8u * i)) & 0xFFu);
    }
}

void repair_outer_crcs(std::vector<u8>& wire) {
    const std::size_t trailer_offset = wire.size() - kTrailer;
    put32_at(wire, kHdrOffFileCrc32, 0u);
    const u32 file_crc = mapr::crc32(std::string_view(
        reinterpret_cast<const char*>(wire.data()), trailer_offset));
    put32_at(wire, kHdrOffFileCrc32, file_crc);
    std::array<u8, 32> buffer{};
    std::memcpy(buffer.data(), wire.data() + trailer_offset, 28);
    buffer[28] = static_cast<u8>(file_crc & 0xFFu);
    buffer[29] = static_cast<u8>((file_crc >> 8) & 0xFFu);
    buffer[30] = static_cast<u8>((file_crc >> 16) & 0xFFu);
    buffer[31] = static_cast<u8>((file_crc >> 24) & 0xFFu);
    const u32 trailer_crc =
        mapr::crc32(std::string_view(reinterpret_cast<const char*>(buffer.data()), buffer.size()));
    put32_at(wire, trailer_offset + kTrlOffTrailerCrc32, trailer_crc);
}

}  // namespace

SeedLayout layout_of(const SeedInfo& seed) {
    SeedLayout layout;
    layout.size = seed.wire.size();
    if (layout.size >= kTrailer) layout.trailer_offset = layout.size - kTrailer;
    if (layout.size >= kHeader) {
        const u32 flags = load32(seed.wire, kHdrOffFlags);
        layout.index_present = (flags & kWireFlagIndexPresent) != 0;
        if (layout.index_present) {
            const u64 offset = load64(seed.wire, kHdrOffIndexOffset);
            if (offset >= kHeader && offset < layout.trailer_offset) {
                layout.index_offset = static_cast<std::size_t>(offset);
            } else {
                // A valid seed always satisfies the bound; if it does not, the
                // index cannot be targeted and the mutation falls back.
                layout.index_present = false;
            }
        }
    }
    return layout;
}

Mutation plan_mutation(const SeedInfo& seed, std::size_t seed_index, MutationClass cls,
                       u64 index, u64 campaign_seed) {
    Mutation m;
    m.cls = cls;
    m.seed_index = seed_index;
    const SeedLayout layout = layout_of(seed);
    m.size = layout.size;

    // Independent stream per mutant: the plan cannot depend on how shards were
    // split, which worker ran it, or what ran before it.
    const u64 mixed = campaign_seed ^ (index + 1ull) * 0x9E3779B97F4A7C15ull;
    SplitMix64 rng(mixed == 0 ? 0xA5A5A5A5A5A5A5A5ull : mixed);

    if (layout.size == 0) return m;
    switch (cls) {
        case MutationClass::BitFlip: plan_bit_flips(m, rng, seed, layout); break;
        case MutationClass::Truncation: plan_truncation(m, rng, seed, layout); break;
        case MutationClass::FieldSwap: plan_field_swaps(m, rng, seed, layout); break;
        case MutationClass::LengthCorruption:
            plan_length_corruption(m, rng, seed, layout);
            break;
    }

    // Half of the mutants keep the stale outer CRCs, half are repaired.  A
    // repaired mutant is rejected (if at all) by the stage that owns its
    // defect; a stale one is also legitimate input, so both families run.
    m.repair_outer_crcs = (rng.next() & 1ull) != 0;
    if (m.size < static_cast<std::size_t>(kWireMinContainerBytes)) {
        m.repair_outer_crcs = false;
    }
    return m;
}

std::vector<u8> materialize(const std::vector<u8>& base, const Mutation& mutation) {
    std::vector<u8> out;
    const std::size_t keep = std::min(base.size(), mutation.size);
    out.assign(base.begin(), base.begin() + static_cast<std::ptrdiff_t>(keep));
    out.resize(mutation.size, 0u);
    for (const auto& [offset, value] : mutation.changes) {
        if (offset < out.size()) out[offset] = value;
    }
    if (mutation.repair_outer_crcs && out.size() >= static_cast<std::size_t>(kWireMinContainerBytes)) {
        repair_outer_crcs(out);
    }
    return out;
}

}  // namespace marp::harness::h4

namespace marp::harness {

const char* mutation_class_name(MutationClass cls) noexcept {
    switch (cls) {
        case MutationClass::BitFlip: return "bitflip";
        case MutationClass::Truncation: return "truncation";
        case MutationClass::FieldSwap: return "fieldswap";
        case MutationClass::LengthCorruption: return "lengthcorruption";
    }
    return "unknown";
}

}  // namespace marp::harness
