// MARP v2 — E3 WIRE — C07 WIRE — part 2 of 3.
//
// The staged reader and validator of §5.1 (parent §5.9), and `validate`,
// `decode`, `decode_stream`.
//
// Validation runs the eleven stages in order and stops at the first failure:
//
//   1  source size >= 96                          Size
//   2  magic, version, header_bytes, flags        Header
//   3  trailer_offset / file_bytes bounds         Bounds
//   4  file_crc32                                 HeaderCrc
//   5  trailer magic, counts, root, CRC           Trailer
//   6  region monotonicity, atom_offset,
//      total-length canonicality                 Regions
//   7  atom table                                 Atoms
//   8  node table (+ E2 canonical shape)          Nodes
//   9  root id == node_count-1                    Root
//   10 seek index                                 Index
//   11 full evaluation                            Eval
//
// No stage allocates from a count or offset it has not already bounded against
// the region that must contain it (E3-I4, §5.1); every region reader is built
// from validated absolute offsets; and every count is divided by the minimum
// possible record size before a vector is sized.

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "e3_wire_internal.hpp"
#include "mapr/e1_crc32.hpp"
#include "mapr/e1_sha256.hpp"
#include "mapr/e2/e2_canon.hpp"
#include "mapr/e2/e2_eval.hpp"
#include "mapr/e3/e3_wire.hpp"

namespace marp::v2::detail {
namespace {

// ---------------------------------------------------------------------------
// Record layout constants used for pre-allocation bounds (§5.1, E3-I4)
// ---------------------------------------------------------------------------

// Minimum atom record: klass(1) + flags(1) + reserved(2) + length bigint(1) +
// sha256(32) + payload(1) = 38 bytes.
constexpr u64 kMinAtomRecordBytes = 38;
// Minimum node record: kind(1) + flags(1) + argc(2) + length bigint(1) = 5.
constexpr u64 kMinNodeRecordBytes = 5;
// Minimum index entry: offset bigint(1) + node_id uvarint(1) + prefix crc(4) = 6.
constexpr u64 kMinIndexEntryBytes = 6;

// Every E2 constraint identifier that can still fire at this point describes a
// node record (W1/W3/W4/W6/W7/W8) or the root record (W2/W5), so stage 8 owns
// all of them: the header and trailer stages already decided flags, counts, and
// the root id.
constexpr Stage kNodeConstraintStage = Stage::Nodes;

// Structural identity of a node record: kind, the parameters the kind owns, and
// the child ids.  `length` is recomputed (W6) and `flags` must be 0, so neither
// is part of identity.  Two equal keys in one table cannot both be canonical
// (E2 §4.7 rule 12).
std::string node_key(const Node& node) {
    std::string key;
    key.push_back(static_cast<char>(static_cast<u8>(node.kind)));
    auto put_bigint = [&key](const BigInt& value) {
        key.push_back('|');
        key += value.to_decimal();
    };
    auto put_u64 = [&key](u64 value) {
        for (unsigned shift = 0; shift < 64u; shift += 8u) {
            key.push_back(static_cast<char>((value >> shift) & 0xFFu));
        }
    };
    switch (node.kind) {
        case Kind::Empty:
        case Kind::Concat:
        case Kind::Xor:
            break;
        case Kind::Atom:
        case Kind::Zero:
        case Kind::Interleave:
        case Kind::Affine:
            put_bigint(node.a);
            break;
        case Kind::Repeat:
        case Kind::Slice:
            put_bigint(node.a);
            put_bigint(node.b);
            break;
        case Kind::Morph:
            key.push_back(static_cast<char>(node.morph));
            key.push_back(static_cast<char>(node.morph_k));
            break;
        case Kind::Predictor:
            key.push_back(static_cast<char>(node.predictor_id));
            put_u64(node.predictor_param);
            break;
        case Kind::Lfsr:
            put_u64(node.lfsr_conn);
            put_u64(node.lfsr_init);
            put_bigint(node.a);
            break;
    }
    if (node.kind == Kind::Affine) {
        key.push_back(static_cast<char>(node.affine_start));
        key.push_back(static_cast<char>(node.affine_step));
    }
    for (const u32 arg : node.args) {
        key.push_back(':');
        key += std::to_string(arg);
    }
    return key;
}

// The validation context shared by every stage.
struct Ctx {
    Source& source;
    const WireLimits& limits;
    ParsedWire& out;
};

// ---------------------------------------------------------------------------
// Stage 2 body: the 64-byte header (§4.2, §4.3)
// ---------------------------------------------------------------------------

WireError read_header(Ctx& ctx) {
    std::array<u8, kWireHeaderBytes> header{};
    if (!ctx.source.read(0, header)) {
        return err(WireCode::Invalid, Stage::Header, kStageMagic, "cannot read the header");
    }
    if (!std::equal(kHeaderMagic.begin(), kHeaderMagic.end(), header.begin())) {
        return err(WireCode::Invalid, Stage::Header, kStageMagic, "bad header magic");
    }

    ParsedWire& w = ctx.out;
    w.version_major = load_le16(header.data() + kHdrOffVersionMajor);
    w.version_minor = load_le16(header.data() + kHdrOffVersionMinor);
    w.flags = load_le32(header.data() + kHdrOffFlags);
    w.header_bytes = load_le16(header.data() + kHdrOffHeaderBytes);
    w.total_length_u64 = load_le64(header.data() + kHdrOffTotalLengthU64);
    w.total_length_big_len = load_le16(header.data() + kHdrOffTotalLengthBigLen);
    w.atom_offset = load_le64(header.data() + kHdrOffAtomOffset);
    w.node_offset = load_le64(header.data() + kHdrOffNodeOffset);
    w.index_offset = load_le64(header.data() + kHdrOffIndexOffset);
    w.trailer_offset = load_le64(header.data() + kHdrOffTrailerOffset);
    w.file_crc32 = load_le32(header.data() + kHdrOffFileCrc32);

    // A future major, or the same major with a future minor, is `Unsupported`;
    // anything else that is not exactly 2.0 is `Invalid` (E3 §5.2).
    if (w.version_major > kWireVersionMajor ||
        (w.version_major == kWireVersionMajor && w.version_minor > kWireVersionMinor)) {
        return err(WireCode::Unsupported, Stage::Header, kStageVersionFuture,
                   "unsupported future wire version");
    }
    if (w.version_major != kWireVersionMajor || w.version_minor != kWireVersionMinor) {
        return err(WireCode::Invalid, Stage::Header, kStageVersion,
                   "not a v2.0 container");
    }
    if (w.header_bytes != kWireHeaderBytes) {
        return err(WireCode::Invalid, Stage::Header, kStageHeaderBytes, "header_bytes != 64");
    }
    if ((w.flags & ~kWireKnownFlagsMask) != 0u) {
        return err(WireCode::Invalid, Stage::Header, kStageFlagsReserved,
                   "reserved flag bits (4..31) must be zero");
    }
    if ((w.flags & kWireFlagCanonical) == 0u) {
        return err(WireCode::Invalid, Stage::Header, kStageFlagsCanonical,
                   "canonical flag (bit 1) must be 1");
    }
    if ((w.flags & kWireFlagByteAligned) == 0u) {
        return err(WireCode::Invalid, Stage::Header, kStageFlagsByteAligned,
                   "byte-aligned flag (bit 3) must be 1");
    }
    w.index_present = (w.flags & kWireFlagIndexPresent) != 0u;
    w.length_is_u64 = (w.flags & kWireFlagU64Lengths) != 0u;
    return WireError{};
}

// ---------------------------------------------------------------------------
// Stage 3 body: trailer_offset / file_bytes bounds (§5.1 step 3)
// ---------------------------------------------------------------------------

WireError check_bounds(Ctx& ctx) {
    ParsedWire& w = ctx.out;
    const u64 size = ctx.source.size();
    if (size > ctx.limits.max_container_bytes) {
        return err(WireCode::Limit, Stage::Bounds, "S3.container-limit",
                   "container exceeds max_container_bytes");
    }
    if (w.trailer_offset > size ||
        size - w.trailer_offset < static_cast<u64>(kWireTrailerBytes)) {
        return err(WireCode::Invalid, Stage::Bounds, kStageTrailerBound,
                   "trailer_offset + 32 exceeds the source size");
    }

    std::array<u8, kWireTrailerBytes> trailer{};
    if (!ctx.source.read(w.trailer_offset, trailer)) {
        return err(WireCode::Invalid, Stage::Bounds, kStageTrailerBound,
                   "cannot read the trailer");
    }
    w.file_bytes = load_le64(trailer.data() + kTrlOffFileBytes);
    if (w.file_bytes != size) {
        return err(WireCode::Invalid, Stage::Bounds, kStageTrailerBound,
                   "trailer file_bytes != source size");
    }
    // Nothing may follow the trailer (§4.8: file_bytes == trailer_offset + 32).
    if (w.trailer_offset != size - static_cast<u64>(kWireTrailerBytes)) {
        return err(WireCode::Invalid, Stage::Bounds, kStageTrailerBound,
                   "trailing bytes after the trailer region");
    }
    return WireError{};
}

// ---------------------------------------------------------------------------
// Stage 4 body: file_crc32 (§4.2)
// ---------------------------------------------------------------------------

WireError check_file_crc(Ctx& ctx) {
    const ParsedWire& w = ctx.out;
    const u64 end = w.trailer_offset;
    mapr::Crc32 crc;
    std::array<u8, 1u << 16> buffer{};
    u64 pos = 0;
    while (pos < end) {
        const u64 take = std::min<u64>(static_cast<u64>(buffer.size()), end - pos);
        if (!ctx.source.read(pos, std::span<u8>(buffer.data(), static_cast<std::size_t>(take)))) {
            return err(WireCode::Invalid, Stage::HeaderCrc, kStageFileCrc,
                       "source shorter than the header CRC range");
        }
        if (pos <= kHdrOffFileCrc32 && kHdrOffFileCrc32 + 4u <= pos + take) {
            // Zero the `file_crc32` field inside the buffer window.
            const std::size_t offset = static_cast<std::size_t>(kHdrOffFileCrc32 - pos);
            buffer[offset] = 0u;
            buffer[offset + 1] = 0u;
            buffer[offset + 2] = 0u;
            buffer[offset + 3] = 0u;
        }
        crc.update(std::string_view(reinterpret_cast<const char*>(buffer.data()),
                                    static_cast<std::size_t>(take)));
        pos += take;
    }
    if (crc.finish() != w.file_crc32) {
        return err(WireCode::Invalid, Stage::HeaderCrc, kStageFileCrc, "file_crc32 mismatch");
    }
    return WireError{};
}

// ---------------------------------------------------------------------------
// Stage 5 body: trailer magic, counts, root, CRC (§4.8)
// ---------------------------------------------------------------------------

WireError check_trailer(Ctx& ctx) {
    ParsedWire& w = ctx.out;
    std::array<u8, kWireTrailerBytes> trailer{};
    if (!ctx.source.read(w.trailer_offset, trailer)) {
        return err(WireCode::Invalid, Stage::Trailer, kStageTrailerMagic,
                   "cannot read the trailer");
    }
    if (!std::equal(kTrailerMagic.begin(), kTrailerMagic.end(), trailer.begin())) {
        return err(WireCode::Invalid, Stage::Trailer, kStageTrailerMagic, "bad trailer magic");
    }
    w.root_id = load_le32(trailer.data() + kTrlOffRootId);
    w.atom_count = load_le32(trailer.data() + kTrlOffAtomCount);
    w.node_count = load_le32(trailer.data() + kTrlOffNodeCount);
    w.trailer_crc32 = load_le32(trailer.data() + kTrlOffTrailerCrc32);

    if (w.node_count == 0u) {
        return err(WireCode::Invalid, Stage::Trailer, kStageTrailerCounts,
                   "node_count == 0 is not a container");
    }
    if (w.node_count > ctx.limits.max_nodes) {
        return err(WireCode::Limit, Stage::Trailer, "S5.node-limit",
                   "node_count exceeds max_nodes");
    }
    if (w.atom_count > ctx.limits.max_atoms) {
        return err(WireCode::Limit, Stage::Trailer, "S5.atom-limit",
                   "atom_count exceeds max_atoms");
    }
    if (w.root_id != w.node_count - 1u) {
        return err(WireCode::Invalid, Stage::Trailer, kStageTrailerRoot,
                   "root_id must equal node_count - 1");
    }

    // trailer_crc32 = CRC32(trailer[0..28) || LE32(file_crc32)).
    std::array<u8, 32> buffer{};
    std::memcpy(buffer.data(), trailer.data(), 28);
    store_le32(std::span<u8>(buffer.data() + 28, 4), w.file_crc32);
    const u32 computed = mapr::crc32(std::string_view(
        reinterpret_cast<const char*>(buffer.data()), buffer.size()));
    if (computed != w.trailer_crc32) {
        return err(WireCode::Invalid, Stage::Trailer, kStageTrailerCrc, "trailer_crc32 mismatch");
    }
    return WireError{};
}

// ---------------------------------------------------------------------------
// Stage 6 body: region monotonicity and the total-length form (§4.4, §4.7)
// ---------------------------------------------------------------------------

WireError check_regions(Ctx& ctx) {
    ParsedWire& w = ctx.out;
    const u64 header_bytes = static_cast<u64>(kWireHeaderBytes);
    const u64 trailer_offset = w.trailer_offset;

    // The trailer may legitimately begin right after the header plus the
    // minimal atom/node tables (an `Empty` container is 103 bytes), so the only
    // structural floor is `trailer_offset >= 64 + total_length_big_len`, which
    // the atom_offset checks below enforce.
    if (trailer_offset < header_bytes) {
        return err(WireCode::Invalid, Stage::Regions, kStageRegionOrder,
                   "trailer_offset lies inside the header");
    }

    // --- total-length form (§4.4) ------------------------------------------
    if (w.length_is_u64) {
        if (w.total_length_big_len != 0u) {
            return err(WireCode::Invalid, Stage::Regions, kStageLengthForm,
                       "u64 length form with total_length_big_len != 0");
        }
        w.total_length = BigInt(w.total_length_u64);
    } else {
        if (w.total_length_u64 != 0u) {
            return err(WireCode::Invalid, Stage::Regions, kStageLengthForm,
                       "big length form with a nonzero total_length_u64");
        }
        if (w.total_length_big_len < 9u) {
            return err(WireCode::Invalid, Stage::Regions, kStageLengthForm,
                       "big length form with a magnitude that would fit u64");
        }
        if (header_bytes + w.total_length_big_len > trailer_offset) {
            return err(WireCode::Invalid, Stage::Regions, kStageLengthForm,
                       "Region A.1 exceeds the container");
        }
        std::vector<u8> magnitude(static_cast<std::size_t>(w.total_length_big_len));
        if (!ctx.source.read(header_bytes, magnitude)) {
            return err(WireCode::Invalid, Stage::Regions, kStageLengthForm,
                       "cannot read Region A.1");
        }
        if (magnitude.back() == 0u) {
            return err(WireCode::Invalid, Stage::Regions, kStageLengthForm,
                       "Region A.1 magnitude has a leading zero byte");
        }
        auto parsed = BigInt::from_le_bytes(std::string_view(
            reinterpret_cast<const char*>(magnitude.data()), magnitude.size()));
        if (!parsed.ok()) {
            return err(WireCode::Invalid, Stage::Regions, kStageLengthForm,
                       "Region A.1 magnitude rejected");
        }
        w.total_length = std::move(parsed.value());
    }

    // --- the §8.3 output cap ----------------------------------------------
    if (ctx.limits.enforce_output_cap) {
        if (w.total_length > ctx.limits.max_output_bytes) {
            return err(WireCode::Limit, Stage::Regions, kStageOutputCap,
                       "declared total length exceeds the output cap");
        }
    }

    // --- region offsets ----------------------------------------------------
    if (w.atom_offset != header_bytes + static_cast<u64>(w.total_length_big_len)) {
        return err(WireCode::Invalid, Stage::Regions, kStageAtomOffset,
                   "atom_offset != 64 + total_length_big_len");
    }
    if (w.atom_offset > w.node_offset || w.node_offset > trailer_offset) {
        return err(WireCode::Invalid, Stage::Regions, kStageRegionOrder,
                   "non-monotonic region offsets");
    }
    if (w.index_present) {
        if (w.index_offset <= w.node_offset || w.index_offset > trailer_offset) {
            return err(WireCode::Invalid, Stage::Regions, kStageIndexOffset,
                       "index present but index_offset is not the node-table end");
        }
    } else if (w.index_offset != 0u) {
        return err(WireCode::Invalid, Stage::Regions, kStageIndexOffset,
                   "index absent but index_offset != 0");
    }
    return WireError{};
}

// ---------------------------------------------------------------------------
// Stage 7 body: atom table (§4.5)
// ---------------------------------------------------------------------------

WireError read_atoms(Ctx& ctx, std::vector<u64>& payload_offsets) {
    ParsedWire& w = ctx.out;
    Reader reader(ctx.source, w.atom_offset, w.node_offset);

    WireResult<u64> count = reader.read_uvarint();
    if (!count.ok()) {
        return err(WireCode::Invalid, Stage::Atoms, kStageAtomCount,
                   "invalid or non-canonical atom_count");
    }
    if (count.value() > 0xFFFFFFFFull) {
        return err(WireCode::Invalid, Stage::Atoms, kStageAtomCount,
                   "atom_count exceeds the u32 trailer field");
    }
    if (count.value() > static_cast<u64>(ctx.limits.max_atoms)) {
        return err(WireCode::Limit, Stage::Atoms, kStageAtomCount,
                   "atom_count exceeds max_atoms");
    }
    if (count.value() != static_cast<u64>(w.atom_count)) {
        return err(WireCode::Invalid, Stage::Atoms, kStageAtomCountTrailer,
                   "atom_count disagrees with the trailer");
    }
    // Bound the count by the region capacity before allocating (E3-I4).
    if (count.value() > reader.remaining() / kMinAtomRecordBytes) {
        return err(WireCode::Invalid, Stage::Atoms, kStageAtomCount,
                   "atom_count exceeds the atom-region capacity");
    }

    const std::size_t atoms = static_cast<std::size_t>(count.value());
    w.ir.atoms.reserve(atoms);
    payload_offsets.assign(atoms, 0);

    // Duplicate detection by (length, sha256), confirmed by exact bytes.
    std::map<std::pair<u64, std::array<u8, 32>>, std::vector<std::size_t>> seen;
    std::array<u8, 1u << 16> hash_buffer{};

    for (std::size_t index = 0; index < atoms; ++index) {
        Atom atom;
        u8 flags = 0;
        u16 reserved = 0;
        if (!reader.read_u8(atom.klass) || !reader.read_u8(flags) || !reader.read_u16(reserved)) {
            return err(WireCode::Invalid, Stage::Atoms, kStageAtomRegion,
                       "truncated atom record header");
        }
        if (flags != 0u || reserved != 0u) {
            return err(WireCode::Invalid, Stage::Atoms, kStageAtomFlags,
                       "atom flags and reserved field must be 0");
        }
        WireResult<BigInt> length = reader.read_bigint();
        if (!length.ok()) {
            return err(WireCode::Invalid, Stage::Atoms, kStageAtomLength,
                       "invalid or non-canonical atom length");
        }
        const std::optional<u64> length_u64 = length.value().to_u64_checked();
        if (!length_u64.has_value() || *length_u64 == 0u || *length_u64 > kWireAtomMax) {
            return err(WireCode::Invalid, Stage::Atoms, kStageAtomLength,
                       "atom length must be 1..ATOM_MAX");
        }
        atom.length = length.value();
        if (!reader.read_exact(atom.sha256)) {
            return err(WireCode::Invalid, Stage::Atoms, kStageAtomRegion,
                       "truncated atom sha256");
        }
        if (*length_u64 > reader.remaining()) {
            return err(WireCode::Invalid, Stage::Atoms, kStageAtomRegion,
                       "atom payload exceeds the atom region");
        }
        payload_offsets[index] = reader.pos();

        // Stream the payload: verify SHA-256 and retain the bytes.  Retention
        // is needed because (a) E2's well-formedness pass checks that every atom
        // record agrees with its payload size and (b) `decode` must return a
        // self-contained `Ir`.  The vector is sized from a `length` that was
        // already bounded by `ATOM_MAX` and by the atom region, so no allocation
        // is sized from an unvalidated count (E3-I4).
        std::vector<u8> payload(static_cast<std::size_t>(*length_u64));
        mapr::Sha256 hasher;
        u64 hashed = 0;
        while (hashed < *length_u64) {
            const u64 take = std::min<u64>(static_cast<u64>(hash_buffer.size()),
                                           *length_u64 - hashed);
            if (!reader.read_exact(
                    std::span<u8>(hash_buffer.data(), static_cast<std::size_t>(take)))) {
                return err(WireCode::Invalid, Stage::Atoms, kStageAtomRegion,
                           "truncated atom payload");
            }
            hasher.update(std::string_view(reinterpret_cast<const char*>(hash_buffer.data()),
                                           static_cast<std::size_t>(take)));
            std::memcpy(payload.data() + static_cast<std::size_t>(hashed),
                        hash_buffer.data(), static_cast<std::size_t>(take));
            hashed += take;
        }
        auto digest = hasher.finish();
        if (!digest.ok()) {
            return err(WireCode::Limit, Stage::Atoms, kStageAtomSha, "atom digest overflow");
        }
        if (digest.value() != atom.sha256) {
            return err(WireCode::Invalid, Stage::Atoms, kStageAtomSha,
                       "atom payload SHA-256 mismatch");
        }

        // Exact-byte duplicate check (a SHA-256 collision never merges records).
        auto& bucket = seen[{*length_u64, atom.sha256}];
        for (const std::size_t previous : bucket) {
            bool equal = true;
            std::array<u8, 1u << 12> a{};
            std::array<u8, 1u << 12> b{};
            u64 done = 0;
            while (done < *length_u64 && equal) {
                const u64 take = std::min<u64>(static_cast<u64>(a.size()), *length_u64 - done);
                if (!ctx.source.read(payload_offsets[previous] + done,
                                     std::span<u8>(a.data(), static_cast<std::size_t>(take))) ||
                    !ctx.source.read(payload_offsets[index] + done,
                                     std::span<u8>(b.data(), static_cast<std::size_t>(take)))) {
                    return err(WireCode::Invalid, Stage::Atoms, kStageAtomRegion,
                               "cannot re-read an atom payload");
                }
                if (std::memcmp(a.data(), b.data(), static_cast<std::size_t>(take)) != 0) {
                    equal = false;
                }
                done += take;
            }
            if (equal) {
                return err(WireCode::Invalid, Stage::Atoms, kStageAtomDup,
                           "duplicate atom payload in the atom table");
            }
        }
        bucket.push_back(index);
        w.retained_payloads.push_back(std::move(payload));
        atom.payload = std::span<const u8>(w.retained_payloads.back().data(),
                                          w.retained_payloads.back().size());
        w.ir.atoms.push_back(std::move(atom));
    }

    if (reader.remaining() != 0u) {
        return err(WireCode::Invalid, Stage::Atoms, kStageAtomRegion,
                   "unconsumed bytes at the end of the atom table");
    }
    return WireError{};
}

// ---------------------------------------------------------------------------
// Stage 7 tail: atom first-use order and reference (§4.5, §4.10 rules 3, 5)
// ---------------------------------------------------------------------------

// Canonical atom order is "first use in post-order traversal of the canonical
// term": atom record `i` is the payload of the `i`-th distinct atom met by the
// traversal, and every atom record is referenced.  E2's canonical shape covers
// dedup and the `ATOM_MAX` bound; the traversal order is a wire rule because it
// is what makes the wire unique.
//
// E3-G integration fix (see REPORT/E3/E3-GATE-REPORT.md §6.2): the traversal
// must visit every *node* once, not once per occurrence.  E2 canonical form is
// hash-consed (C12: no two structurally identical node records), so the same
// `Atom` node is legitimately shared by several parents — `Interleave(a, a)`
// in E2's own T-GEN corpus is the minimal witness.  Re-walking a shared node
// made this check reject the wire C07 itself had just produced for 200 of the
// 5 128 canonical T-KAT/T-GEN terms, breaking E3-I1.  H3's independent reader
// (harness/oracle/src/decode.cpp, stage 8) already models first use this way.
// Only the *first* visit of an Atom node claims the next atom id, so a genuine
// violation (an atom record used by two distinct Atom nodes, or an out-of-order
// table) is still rejected with the same code and stage.
WireError check_atom_order(const Ir& ir) {
    const std::size_t atoms = ir.atoms.size();
    if (atoms == 0) return WireError{};
    std::vector<u8> used(atoms, 0);
    // One visit per node: a hash-consed node is entered once, from whichever
    // parent reaches it first in post-order.
    std::vector<u8> entered(ir.nodes.size(), 0);
    std::size_t expected = 0;

    struct Frame {
        u32 node;
        std::size_t next_arg;
    };
    std::vector<Frame> stack;
    stack.push_back(Frame{ir.root, 0});
    entered[ir.root] = 1;
    while (!stack.empty()) {
        Frame& top = stack.back();
        const Node& node = ir.nodes[top.node];
        if (top.next_arg < node.args.size()) {
            const u32 child = node.args[top.next_arg++];
            if (child < entered.size() && entered[child] == 0) {
                entered[child] = 1;
                stack.push_back(Frame{child, 0});
            }
            continue;
        }
        // Post-order visit: an Atom node's payload is appended on first use.
        if (node.kind == Kind::Atom) {
            const std::size_t atom_id = as_index(node.a);
            if (atom_id >= atoms) {
                return err(WireCode::Invalid, Stage::Atoms, kStageAtomOrder,
                           "Atom node references an out-of-range atom id");
            }
            if (used[atom_id] == 0) {
                used[atom_id] = 1;
                if (atom_id != expected) {
                    return err(WireCode::Invalid, Stage::Atoms, kStageAtomOrder,
                               "atom table is not in canonical first-use order");
                }
                ++expected;
            } else {
                // A second *distinct* Atom node claiming the same record.  The
                // same node reached twice is a shared subterm, not a violation.
                return err(WireCode::Invalid, Stage::Atoms, kStageAtomOrder,
                           "the same atom record is referenced by two Atom nodes"
                           " (canonical terms have one Atom node per payload)");
            }
        }
        stack.pop_back();
    }
    if (expected != atoms) {
        return err(WireCode::Invalid, Stage::Atoms, kStageAtomUnused,
                   "an atom record is never referenced");
    }
    return WireError{};
}

// ---------------------------------------------------------------------------
// Stage 8 body: node table (§4.6)
// ---------------------------------------------------------------------------

WireError read_nodes(Ctx& ctx) {
    ParsedWire& w = ctx.out;
    Reader reader(ctx.source, w.node_offset,
                  w.index_present ? w.index_offset : w.trailer_offset);

    WireResult<u64> count = reader.read_uvarint();
    if (!count.ok()) {
        return err(WireCode::Invalid, Stage::Nodes, kStageNodeCount,
                   "invalid or non-canonical node_count");
    }
    if (count.value() > 0xFFFFFFFFull) {
        return err(WireCode::Invalid, Stage::Nodes, kStageNodeCount,
                   "node_count exceeds the u32 trailer field");
    }
    if (count.value() > static_cast<u64>(ctx.limits.max_nodes)) {
        return err(WireCode::Limit, Stage::Nodes, kStageNodeCount,
                   "node_count exceeds max_nodes");
    }
    if (count.value() != static_cast<u64>(w.node_count)) {
        return err(WireCode::Invalid, Stage::Nodes, kStageNodeCountTrailer,
                   "node_count disagrees with the trailer");
    }
    if (count.value() > reader.remaining() / kMinNodeRecordBytes) {
        return err(WireCode::Invalid, Stage::Nodes, kStageNodeCount,
                   "node_count exceeds the node-region capacity");
    }

    const std::size_t nodes = static_cast<std::size_t>(count.value());
    w.ir.nodes.reserve(nodes);

    for (std::size_t id = 0; id < nodes; ++id) {
        Node node;
        u8 kind_raw = 0;
        u8 flags = 0;
        u16 argc = 0;
        if (!reader.read_u8(kind_raw) || !reader.read_u8(flags) || !reader.read_u16(argc)) {
            return err(WireCode::Invalid, Stage::Nodes, kStageNodeRegion,
                       "truncated node record header");
        }
        if (!kind_domain(static_cast<Kind>(kind_raw))) {
            return err(WireCode::Invalid, Stage::Nodes, kStageNodeKind, "unknown node kind");
        }
        if (flags != 0u) {
            return err(WireCode::Invalid, Stage::Nodes, kStageNodeFlags,
                       "node flags must be 0");
        }
        node.kind = static_cast<Kind>(kind_raw);

        // Exact argc per kind (§4.6).
        bool argc_ok = false;
        switch (node.kind) {
            case Kind::Empty:
            case Kind::Atom:
            case Kind::Zero:
            case Kind::Lfsr:
            case Kind::Affine:
                argc_ok = (argc == 0u);
                break;
            case Kind::Repeat:
            case Kind::Slice:
            case Kind::Morph:
            case Kind::Predictor:
                argc_ok = (argc == 1u);
                break;
            case Kind::Xor:
                argc_ok = (argc == 2u);
                break;
            case Kind::Concat:
                argc_ok = (argc >= 2u);
                break;
            case Kind::Interleave:
                argc_ok = (argc >= 1u);
                break;
        }
        if (!argc_ok) {
            return err(WireCode::Invalid, Stage::Nodes, kStageNodeArgc,
                       "argc does not match the node kind");
        }
        if (static_cast<u64>(argc) > reader.remaining()) {
            return err(WireCode::Invalid, Stage::Nodes, kStageNodeArg,
                       "argc exceeds the remaining node region");
        }

        node.args.reserve(argc);
        for (u16 a = 0; a < argc; ++a) {
            WireResult<u64> arg = reader.read_uvarint();
            if (!arg.ok()) {
                return err(WireCode::Invalid, Stage::Nodes, kStageNodeArg,
                           "invalid or non-canonical node argument");
            }
            if (arg.value() >= static_cast<u64>(id)) {
                return err(WireCode::Invalid, Stage::Nodes, kStageNodeArg,
                           "node argument is not smaller than its own id");
            }
            node.args.push_back(static_cast<u32>(arg.value()));
        }

        // --- kind-specific params (§4.6) -----------------------------------
        switch (node.kind) {
            case Kind::Empty:
            case Kind::Concat:
            case Kind::Xor:
                break;
            case Kind::Atom: {
                WireResult<u64> atom_id = reader.read_uvarint();
                if (!atom_id.ok()) {
                    return err(WireCode::Invalid, Stage::Nodes, kStageNodeParams,
                               "invalid Atom atom_id");
                }
                if (atom_id.value() >= static_cast<u64>(w.ir.atoms.size())) {
                    return err(WireCode::Invalid, Stage::Nodes, kStageNodeParams,
                               "Atom atom_id out of range");
                }
                node.a = BigInt(atom_id.value());
                break;
            }
            case Kind::Zero: {
                WireResult<BigInt> n = reader.read_bigint();
                if (!n.ok()) {
                    return err(WireCode::Invalid, Stage::Nodes, kStageNodeParams,
                               "invalid Zero n");
                }
                node.a = std::move(n.value());
                break;
            }
            case Kind::Repeat:
            case Kind::Slice: {
                WireResult<BigInt> a = reader.read_bigint();
                if (!a.ok()) {
                    return err(WireCode::Invalid, Stage::Nodes, kStageNodeParams,
                               "invalid Repeat/Slice first parameter");
                }
                WireResult<BigInt> b = reader.read_bigint();
                if (!b.ok()) {
                    return err(WireCode::Invalid, Stage::Nodes, kStageNodeParams,
                               "invalid Repeat/Slice second parameter");
                }
                node.a = std::move(a.value());
                node.b = std::move(b.value());
                break;
            }
            case Kind::Morph: {
                if (!reader.read_u8(node.morph) || !reader.read_u8(node.morph_k)) {
                    return err(WireCode::Invalid, Stage::Nodes, kStageNodeParams,
                               "truncated Morph parameters");
                }
                break;
            }
            case Kind::Interleave: {
                u32 stride = 0;
                if (!reader.read_u32(stride)) {
                    return err(WireCode::Invalid, Stage::Nodes, kStageNodeParams,
                               "truncated Interleave stride");
                }
                node.a = BigInt(stride);
                break;
            }
            case Kind::Lfsr: {
                if (!reader.read_u64(node.lfsr_conn) || !reader.read_u64(node.lfsr_init)) {
                    return err(WireCode::Invalid, Stage::Nodes, kStageNodeParams,
                               "truncated Lfsr parameters");
                }
                WireResult<BigInt> n = reader.read_bigint();
                if (!n.ok()) {
                    return err(WireCode::Invalid, Stage::Nodes, kStageNodeParams,
                               "invalid Lfsr n");
                }
                node.a = std::move(n.value());
                break;
            }
            case Kind::Affine: {
                if (!reader.read_u8(node.affine_start) || !reader.read_u8(node.affine_step)) {
                    return err(WireCode::Invalid, Stage::Nodes, kStageNodeParams,
                               "truncated Affine parameters");
                }
                WireResult<BigInt> n = reader.read_bigint();
                if (!n.ok()) {
                    return err(WireCode::Invalid, Stage::Nodes, kStageNodeParams,
                               "invalid Affine n");
                }
                node.a = std::move(n.value());
                break;
            }
            case Kind::Predictor: {
                if (!reader.read_u8(node.predictor_id) || !reader.read_u32(node.predictor_param)) {
                    return err(WireCode::Invalid, Stage::Nodes, kStageNodeParams,
                               "truncated Predictor parameters");
                }
                break;
            }
        }

        WireResult<BigInt> length = reader.read_bigint();
        if (!length.ok()) {
            return err(WireCode::Invalid, Stage::Nodes, kStageNodeLength,
                       "invalid or non-canonical node length");
        }
        node.length = std::move(length.value());
        w.ir.nodes.push_back(std::move(node));
    }

    if (reader.remaining() != 0u) {
        return err(WireCode::Invalid, Stage::Nodes, kStageNodeRegion,
                   "unconsumed bytes at the end of the node table");
    }
    return WireError{};
}

// Stage 8 tail (wire level): post-order first-use node order, no unused record,
// and the structural-dedup rule that makes the wire unique (§4.6, §4.10 rule 4).
WireError check_node_order(const Ir& ir) {
    // Iterative post-order traversal from the root; every finished node must be
    // the next dense id, which simultaneously proves reachability and order.
    std::vector<u8> state(ir.nodes.size(), 0);  // 0 new, 1 active, 2 done
    struct Frame {
        u32 node;
        std::size_t next_arg;
    };
    std::vector<Frame> stack;
    stack.push_back(Frame{ir.root, 0});
    state[ir.root] = 1;
    u32 expected = 0;
    while (!stack.empty()) {
        Frame& top = stack.back();
        const Node& node = ir.nodes[top.node];
        if (top.next_arg < node.args.size()) {
            const u32 child = node.args[top.next_arg++];
            if (state[child] == 1) {
                return err(WireCode::Invalid, Stage::Nodes, kStageNodeArg,
                           "node graph contains a cycle");
            }
            if (state[child] == 0) {
                state[child] = 1;
                stack.push_back(Frame{child, 0});
            }
            continue;
        }
        const u32 finished = top.node;
        state[finished] = 2;
        stack.pop_back();
        if (finished != expected) {
            return err(WireCode::Invalid, Stage::Nodes, kStageNodePostOrder,
                       "node table is not in canonical post-order first-use order");
        }
        ++expected;
    }
    if (expected != static_cast<u32>(ir.nodes.size())) {
        return err(WireCode::Invalid, Stage::Nodes, kStageNodeUnused,
                   "an unreachable/unused node record is present");
    }

    // Structural dedup: two records with identical kind, params, and child ids
    // cannot both be canonical (E2 §4.7 rule 12 / §4.10 rule 4).
    std::vector<std::string> keys;
    keys.reserve(ir.nodes.size());
    for (const Node& node : ir.nodes) keys.push_back(node_key(node));
    std::vector<u32> order(ir.nodes.size());
    for (std::size_t i = 0; i < order.size(); ++i) order[i] = static_cast<u32>(i);
    std::sort(order.begin(), order.end(), [&](u32 a, u32 b) { return keys[a] < keys[b]; });
    for (std::size_t i = 1; i < order.size(); ++i) {
        if (keys[order[i]] == keys[order[i - 1]]) {
            return err(WireCode::Invalid, Stage::Nodes, kStageNodeCanon,
                       "two structurally identical node records (not hash-consed)");
        }
    }
    return WireError{};
}

// ---------------------------------------------------------------------------
// Stage 8 tail: E2's authority over lengths, shape, and canonicality (§6.2)
// ---------------------------------------------------------------------------

WireError check_node_structure(Ctx& ctx) {
    ParsedWire& w = ctx.out;
    w.ir.root = w.root_id;
    w.ir.total_length = w.total_length;

    // E2 recomputes every length from structure and enforces W1–W8 (counts,
    // flags, root, reachability, arg range, length equality, depth, kind
    // constraints) in its fixed order, reporting the first failing constraint.
    Limits e2_limits;
    e2_limits.max_nodes = ctx.limits.max_nodes;
    e2_limits.max_atoms = ctx.limits.max_atoms;
    e2_limits.max_depth = ctx.limits.max_depth;
    e2_limits.enforce_output_cap = false;  // enforced at stage 6 for stage stability

    const WfReport wf = check_well_formed_report(w.ir, e2_limits);
    if (!wf.ok()) {
        const WireCode code =
            wf.code == Code::Limit ? WireCode::Limit : WireCode::Invalid;
        return err(code, kNodeConstraintStage, wf.constraint, wf.message);
    }
    if (ctx.limits.enforce_canonical_shape) {
        const WfReport canonical = check_canonical(w.ir, e2_limits);
        if (!canonical.ok()) {
            const WireCode code =
                canonical.code == Code::Limit ? WireCode::Limit : WireCode::Invalid;
            return err(code, Stage::Nodes, kStageNodeCanon, canonical.constraint);
        }
    }
    w.structure_loaded = true;
    return WireError{};
}

}  // namespace
}  // namespace marp::v2::detail

namespace marp::v2::detail {

// ---------------------------------------------------------------------------
// Stage 10 body: the seek index (§4.7)
// ---------------------------------------------------------------------------

WireError parse_index_region(Source& source, const WireLimits& limits, ParsedWire& parsed) {
    parsed.index_entries.clear();
    if (!parsed.index_present) {
        parsed.canonical_index = IndexPolicy{};
        return WireError{};
    }
    const u64 start = parsed.index_offset;
    const u64 end = parsed.trailer_offset;
    if (end - start < 16u) {
        return err(WireCode::Invalid, Stage::Index, kStageIndexCount,
                   "index region is smaller than magic + count + CRC");
    }

    mapr::Crc32 crc;
    {
        std::array<u8, 1u << 16> buffer{};
        u64 pos = start;
        const u64 crc_end = end - 4u;  // the trailing u32 is the CRC itself
        while (pos < crc_end) {
            const u64 take = std::min<u64>(static_cast<u64>(buffer.size()), crc_end - pos);
            if (!source.read(pos, std::span<u8>(buffer.data(), static_cast<std::size_t>(take)))) {
                return err(WireCode::Invalid, Stage::Index, kStageIndexCrc,
                           "cannot read the index region");
            }
            crc.update(std::string_view(reinterpret_cast<const char*>(buffer.data()),
                                        static_cast<std::size_t>(take)));
            pos += take;
        }
    }
    std::array<u8, 4> stored_crc{};
    if (!source.read(end - 4u, stored_crc)) {
        return err(WireCode::Invalid, Stage::Index, kStageIndexCrc,
                   "cannot read index_crc32");
    }
    if (crc.finish() != load_le32(stored_crc.data())) {
        return err(WireCode::Invalid, Stage::Index, kStageIndexCrc, "index_crc32 mismatch");
    }

    Reader reader(source, start, end - 4u);
    std::array<u8, 8> magic{};
    if (!reader.read_exact(magic)) {
        return err(WireCode::Invalid, Stage::Index, kStageIndexMagic, "truncated index magic");
    }
    if (!std::equal(kIndexMagic.begin(), kIndexMagic.end(), magic.begin())) {
        return err(WireCode::Invalid, Stage::Index, kStageIndexMagic, "bad index magic");
    }
    u32 entry_count = 0;
    if (!reader.read_u32(entry_count)) {
        return err(WireCode::Invalid, Stage::Index, kStageIndexCount, "truncated entry_count");
    }
    if (entry_count == 0u) {
        return err(WireCode::Invalid, Stage::Index, kStageIndexCount,
                   "an empty index region is non-canonical");
    }
    if (entry_count > limits.max_index_entries) {
        return err(WireCode::Limit, Stage::Index, kStageIndexCount,
                   "index entry_count exceeds the limit");
    }
    if (static_cast<u64>(entry_count) > reader.remaining() / kMinIndexEntryBytes) {
        return err(WireCode::Invalid, Stage::Index, kStageIndexCount,
                   "index entry_count exceeds the region capacity");
    }

    parsed.index_entries.reserve(entry_count);
    for (u32 i = 0; i < entry_count; ++i) {
        IndexEntryC07 entry;
        WireResult<BigInt> offset = reader.read_bigint();
        if (!offset.ok()) {
            return err(WireCode::Invalid, Stage::Index, kStageIndexOrder,
                       "invalid or non-canonical index output_offset");
        }
        const std::optional<u64> offset_u64 = offset.value().to_u64_checked();
        if (!offset_u64.has_value() || *offset_u64 == 0u) {
            return err(WireCode::Invalid, Stage::Index, kStageIndexOrder,
                       "index output_offset must be a positive u64");
        }
        if (*offset_u64 % kWireIndexStride != 0u) {
            return err(WireCode::Invalid, Stage::Index, kStageIndexOrder,
                       "index output_offset is not a multiple of INDEX_STRIDE");
        }
        if (!parsed.index_entries.empty() &&
            *offset_u64 <= parsed.index_entries.back().output_offset) {
            return err(WireCode::Invalid, Stage::Index, kStageIndexOrder,
                       "index entries are not strictly increasing");
        }
        WireResult<u64> node_id = reader.read_uvarint();
        if (!node_id.ok()) {
            return err(WireCode::Invalid, Stage::Index, kStageIndexNodeId,
                       "invalid index node_id");
        }
        if (node_id.value() >= static_cast<u64>(parsed.ir.nodes.size())) {
            return err(WireCode::Invalid, Stage::Index, kStageIndexNodeId,
                       "index node_id out of range");
        }
        if (!reader.read_u32(entry.crc32_of_prefix)) {
            return err(WireCode::Invalid, Stage::Index, kStageIndexCount,
                       "truncated index crc32_of_prefix");
        }
        entry.output_offset = *offset_u64;
        entry.node_id = static_cast<u32>(node_id.value());
        parsed.index_entries.push_back(entry);
    }
    if (reader.remaining() != 0u) {
        return err(WireCode::Invalid, Stage::Index, kStageIndexCount,
                   "unconsumed bytes at the end of the index region");
    }

    // The index must equal the canonical policy output (§4.10 rule 6).
    WireError policy_error = compute_index_policy(parsed.ir, limits, parsed.canonical_index);
    if (!policy_error.ok()) return policy_error;
    return validate_index_entries(parsed.canonical_index, parsed.index_entries);
}

// ---------------------------------------------------------------------------
// Stage 11: full evaluation (§5.1 step 11)
// ---------------------------------------------------------------------------

WireResult<StreamDigest> evaluate_structure(const ParsedWire& parsed, const WireLimits& limits) {
    if (parsed.total_length > BigInt(limits.max_eval_bytes)) {
        return err(WireCode::Limit, Stage::Eval, "S11.work-bound",
                   "declared total length exceeds the evaluation work bound");
    }
    EvalLimits eval_limits;
    eval_limits.wf.max_nodes = limits.max_nodes;
    eval_limits.wf.max_atoms = limits.max_atoms;
    eval_limits.wf.max_depth = limits.max_depth;
    eval_limits.wf.enforce_output_cap = false;
    auto digest = eval_stream_digest(parsed.ir, eval_limits);
    if (!digest.ok()) {
        return err(digest.code() == Code::Limit ? WireCode::Limit : WireCode::Mismatch,
                   Stage::Eval, kStageEvalDigest, "evaluation failed");
    }
    if (digest.value().bytes != parsed.total_length) {
        return err(WireCode::Mismatch, Stage::Eval, kStageEvalLength,
                   "output length disagrees with the declared total length");
    }
    return digest.value();
}

// Stage 11 index check: every `crc32_of_prefix` must match the actual prefix.
WireError verify_index_prefixes(const ParsedWire& parsed, const WireLimits& limits) {
    if (!parsed.index_present || parsed.index_entries.empty()) return WireError{};
    IndexPolicy expected;
    expected.entries = parsed.index_entries;
    WireError prefix_error = fill_prefix_crcs(parsed.ir, limits, expected);
    if (!prefix_error.ok()) return prefix_error;
    for (std::size_t i = 0; i < expected.entries.size(); ++i) {
        if (expected.entries[i].crc32_of_prefix != parsed.index_entries[i].crc32_of_prefix) {
            return err(WireCode::Invalid, Stage::Eval, kStageEvalPrefix,
                       "index crc32_of_prefix disagrees with the denotation");
        }
    }
    return WireError{};
}

// ---------------------------------------------------------------------------
// The staged driver (§5.1)
// ---------------------------------------------------------------------------

WireError run_validation(Source& source, const WireLimits& limits, ParsedWire& out) {
    out = ParsedWire{};
    Ctx ctx{source, limits, out};

    // 1. minimum container size
    if (source.size() < kWireMinContainerBytes) {
        return err(WireCode::Invalid, Stage::Size, kStageSize,
                   "source is smaller than 64 + 32 bytes");
    }
    if (source.size() > limits.max_container_bytes) {
        return err(WireCode::Limit, Stage::Size, kStageSize,
                   "source exceeds max_container_bytes");
    }

    // 2-6
    if (WireError e = read_header(ctx); !e.ok()) return e;
    if (WireError e = check_bounds(ctx); !e.ok()) return e;
    if (WireError e = check_file_crc(ctx); !e.ok()) return e;
    if (WireError e = check_trailer(ctx); !e.ok()) return e;
    if (WireError e = check_regions(ctx); !e.ok()) return e;

    // 7-8
    std::vector<u64> payload_offsets;
    if (WireError e = read_atoms(ctx, payload_offsets); !e.ok()) return e;
    if (WireError e = read_nodes(ctx); !e.ok()) return e;
    if (WireError e = check_node_structure(ctx); !e.ok()) return e;
    if (limits.enforce_wire_canonicality) {
        if (WireError e = check_atom_order(out.ir); !e.ok()) return e;
        if (WireError e = check_node_order(out.ir); !e.ok()) return e;
    }

    // 9. root id equals node_count - 1 (already true from the trailer; re-checked
    // against the parsed table so a disagreement cannot survive stage 5).
    if (out.root_id != static_cast<u32>(out.ir.nodes.size() - 1)) {
        return err(WireCode::Invalid, Stage::Root, kStageRoot,
                   "root id disagrees with the node table");
    }

    // 10. seek index
    if (WireError e = parse_index_region(source, limits, out); !e.ok()) return e;

    // 11. full evaluation
    if (limits.verify_denotation) {
        WireResult<StreamDigest> digest = evaluate_structure(out, limits);
        if (!digest.ok()) return digest.error();
        out.output_sha256 = digest.value().sha256;
        out.denotation_verified = true;
        if (WireError e = verify_index_prefixes(out, limits); !e.ok()) return e;
    }
    return WireError{};
}

}  // namespace marp::v2::detail

namespace marp::v2 {

WireResult<Validation> validate(Source& source, const WireLimits& limits) {
    detail::ParsedWire parsed;
    const WireError e = detail::run_validation(source, limits, parsed);
    if (!e.ok()) return e;
    // The payload storage was only needed while E2 checked the records.
    parsed.retained_payloads.clear();
    parsed.retained_payloads.shrink_to_fit();
    for (Atom& atom : parsed.ir.atoms) atom.payload = std::span<const u8>();

    Validation v;
    v.total_length = parsed.total_length;
    v.output_sha256 = parsed.output_sha256;
    v.atom_count = parsed.atom_count;
    v.node_count = parsed.node_count;
    v.root_id = parsed.root_id;
    v.index_present = parsed.index_present;
    v.index_entries = static_cast<u32>(parsed.index_entries.size());
    v.denotation_verified = parsed.denotation_verified;
    v.flags = static_cast<u8>(parsed.flags);
    return v;
}

WireResult<Validation> validate(std::span<const u8> wire, const WireLimits& limits) {
    SpanSource source(wire);
    return validate(source, limits);
}

WireResult<Ir> decode(Source& source, Arena& arena, const WireLimits& limits) {
    detail::ParsedWire parsed;
    const WireError e = detail::run_validation(source, limits, parsed);
    if (!e.ok()) return e;

    // Rehome every payload into the caller's arena.  `decode` owns the
    // container's payload storage only until it returns, so the arena is the
    // storage that outlives the `Ir` (E3 §6.4).  A failed `store` is `Limit`.
    WireResult<std::span<const u8>> owner = arena.store(std::span<const u8>());
    if (!owner.ok()) return owner.error();
    for (Atom& atom : parsed.ir.atoms) {
        WireResult<std::span<const u8>> stored = arena.store(atom.payload);
        if (!stored.ok()) return stored.error();
        atom.payload = stored.value();
    }
    return std::move(parsed.ir);
}

WireResult<Ir> decode(std::span<const u8> wire, const WireLimits& limits) {
    SpanSource source(wire);
    HeapArena arena(limits.arena_capacity_bytes);
    WireResult<Ir> decoded = decode(source, arena, limits);
    if (!decoded.ok()) return decoded.error();
    // Keep the arena alive for as long as the `Ir` (C04's `Atom::owner`
    // convention): the views stay valid through the handle below.
    Ir ir = std::move(decoded.value());
    for (Atom& atom : ir.atoms) atom.owner = arena.owner();
    return ir;
}

WireStatus decode_stream(Source& source, Sink& sink, const WireLimits& limits) {
    detail::ParsedWire parsed;
    const WireError e = detail::run_validation(source, limits, parsed);
    if (!e.ok()) return e;
    if (parsed.total_length > BigInt(limits.max_stream_bytes)) {
        return detail::err(WireCode::Limit, Stage::Eval, "S11.stream-bound",
                           "declared total length exceeds the stream bound");
    }
    EvalLimits eval_limits;
    eval_limits.wf.max_nodes = limits.max_nodes;
    eval_limits.wf.max_atoms = limits.max_atoms;
    eval_limits.wf.max_depth = limits.max_depth;
    eval_limits.wf.enforce_output_cap = false;
    const Status status = eval_stream_ex(parsed.ir, sink, eval_limits);
    if (!status.ok()) {
        return detail::err(status.code() == Code::Limit ? WireCode::Limit : WireCode::Mismatch,
                           Stage::Eval, kStageEvalDigest, "stream evaluation failed");
    }
    return WireStatus{};
}

}  // namespace marp::v2
