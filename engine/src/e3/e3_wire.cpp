// MARP v2 — E3 WIRE — C07 WIRE — part 1 of 3.
//
//   * format constants and stage names
//   * `SpanSource`, `HeapArena`, `Reader`, and the canonical integer codecs
//   * the encode plan (§6.1, O7.1) and the writer entry points
//
// The staged reader/validator lives in `e3_wire_read.cpp`; the seek-index
// policy and the wire assembler live in `e3_wire_index.cpp`.  The three units
// are one component: the split is a file-size split, not an architecture split.
//
// Independence (E3 §11, §13.1): this component includes E1 and E2 only.  It
// includes no E4–E7 header, no v1/legacy code, and no harness header, and it
// never consults the environment, the clock, the thread count, or file names.

#include "mapr/e3/e3_wire.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "e3_wire_internal.hpp"
#include "mapr/e1_crc32.hpp"
#include "mapr/e1_sha256.hpp"
#include "mapr/e2/e2_canon.hpp"

namespace marp::v2 {

// ===========================================================================
// Format constants
// ===========================================================================

const std::array<u8, 8> kHeaderMagic = {0x89u, 0x4Du, 0x41u, 0x50u, 0x52u, 0x32u, 0x0Du, 0x0Au};
const std::array<u8, 8> kIndexMagic = {0x49u, 0x4Eu, 0x44u, 0x58u, 0x32u, 0x0Du, 0x0Au, 0x1Au};
const std::array<u8, 8> kTrailerMagic = {0x54u, 0x52u, 0x4Cu, 0x52u, 0x32u, 0x0Du, 0x0Au, 0x1Au};

const char* wire_code_name(WireCode code) noexcept {
    switch (code) {
        case WireCode::Ok: return "Ok";
        case WireCode::Invalid: return "Invalid";
        case WireCode::Unsupported: return "Unsupported";
        case WireCode::Limit: return "Limit";
        case WireCode::Mismatch: return "Mismatch";
    }
    return "?";
}

const char* stage_name(Stage stage) noexcept {
    switch (stage) {
        case Stage::None: return "none";
        case Stage::Size: return "stage1_size";
        case Stage::Header: return "stage2_header";
        case Stage::Bounds: return "stage3_bounds";
        case Stage::HeaderCrc: return "stage4_header_crc";
        case Stage::Trailer: return "stage5_trailer";
        case Stage::Regions: return "stage6_regions";
        case Stage::Atoms: return "stage7_atoms";
        case Stage::Nodes: return "stage8_nodes";
        case Stage::Root: return "stage9_root";
        case Stage::Index: return "stage10_index";
        case Stage::Eval: return "stage11_eval";
    }
    return "unknown";
}

// ===========================================================================
// Internal helpers (declared in e3_wire_internal.hpp)
// ===========================================================================

namespace detail {

WireError err(WireCode code, Stage stage, const char* check, std::string message) {
    return WireError{code, stage, check, std::move(message)};
}

std::vector<u8> bigint_magnitude(const BigInt& value) {
    std::vector<u8> le = value.to_le_bytes();
    while (!le.empty() && le.back() == 0) le.pop_back();
    return le;
}

WireResult<std::size_t> bigint_size_impl(const BigInt& value) {
    if (value.is_zero()) return std::size_t{1};
    const std::optional<u64> small = value.to_u64_checked();
    if (small.has_value()) return std::size_t{1} + detail::uvarint_len(*small);
    const std::vector<u8> magnitude = bigint_magnitude(value);
    if (magnitude.size() < 9u) {
        return err(WireCode::Invalid, Stage::None, "U.bigint",
                   "value >= 2^64 with a magnitude shorter than 9 bytes");
    }
    if (magnitude.size() > 0xFFFFFFFFull) {
        return err(WireCode::Limit, Stage::None, "U.bigint", "magnitude exceeds the u32 length");
    }
    return std::size_t{5} + magnitude.size();
}

void append_uvarint(std::vector<u8>& out, u64 value) {
    while (value >= 0x80ull) {
        out.push_back(static_cast<u8>((value & 0x7Full) | 0x80ull));
        value >>= 7;
    }
    out.push_back(static_cast<u8>(value & 0x7Full));
}

void append_bigint(std::vector<u8>& out, const BigInt& value) {
    if (value.is_zero()) {
        out.push_back(0x00u);
        return;
    }
    const std::optional<u64> small = value.to_u64_checked();
    if (small.has_value()) {
        out.push_back(0x01u);
        append_uvarint(out, *small);
        return;
    }
    const std::vector<u8> magnitude = bigint_magnitude(value);
    out.push_back(0x02u);
    append_le32(out, static_cast<u32>(magnitude.size()));
    out.insert(out.end(), magnitude.begin(), magnitude.end());
}

void append_le16(std::vector<u8>& out, u16 v) { store_le16(std::span<u8>(out.insert(out.end(), 2, 0u), 2), v); }
void append_le32(std::vector<u8>& out, u32 v) { store_le32(std::span<u8>(out.insert(out.end(), 4, 0u), 4), v); }
void append_le64(std::vector<u8>& out, u64 v) { store_le64(std::span<u8>(out.insert(out.end(), 8, 0u), 8), v); }

void patch_le32(std::vector<u8>& buf, std::size_t offset, u32 v) {
    store_le32(std::span<u8>(buf.data() + offset, 4), v);
}

bool atom_length_ok(const Atom& atom) noexcept {
    const std::optional<u64> declared = atom.length.to_u64_checked();
    if (!declared.has_value() || *declared == 0 || *declared > kWireAtomMax) return false;
    return atom.payload.size() == static_cast<std::size_t>(*declared);
}

}  // namespace detail

// ===========================================================================
// Sources, arena, reader (§9)
// ===========================================================================

bool SpanSource::read(u64 offset, std::span<u8> dst) const {
    if (offset > static_cast<u64>(data_.size())) return false;
    if (static_cast<u64>(dst.size()) > static_cast<u64>(data_.size()) - offset) return false;
    if (!dst.empty()) {
        std::memcpy(dst.data(), data_.data() + static_cast<std::size_t>(offset), dst.size());
    }
    return true;
}

HeapArena::HeapArena(u64 capacity) : capacity_(capacity) {
    owner_ = std::make_shared<std::vector<std::vector<u8>>>();
}

WireResult<std::span<const u8>> HeapArena::store(std::span<const u8> bytes) {
    const u64 n = static_cast<u64>(bytes.size());
    if (n > capacity_ || used_ > capacity_ - n) {
        return detail::err(WireCode::Limit, Stage::None, "A1.arena-capacity",
                           "arena capacity exceeded");
    }
    auto* blocks = static_cast<std::vector<std::vector<u8>>*>(owner_.get());
    blocks->emplace_back(bytes.begin(), bytes.end());
    used_ += n;
    const std::vector<u8>& block = blocks->back();
    return std::span<const u8>(block.data(), block.size());
}

Reader::Reader(const Source& src, u64 start, u64 end) noexcept
    : src_(src), pos_(start), end_(end < start ? start : end) {}

bool Reader::read_exact(std::span<u8> dst) {
    const u64 n = static_cast<u64>(dst.size());
    if (n > remaining()) return false;
    if (!src_.read(pos_, dst)) return false;
    pos_ += n;
    return true;
}

bool Reader::skip(u64 n) noexcept {
    if (n > remaining()) return false;
    pos_ += n;
    return true;
}

bool Reader::read_u8(u8& out) {
    std::array<u8, 1> b{};
    if (!read_exact(b)) return false;
    out = b[0];
    return true;
}

bool Reader::read_u16(u16& out) {
    std::array<u8, 2> b{};
    if (!read_exact(b)) return false;
    out = detail::load_le16(b.data());
    return true;
}

bool Reader::read_u32(u32& out) {
    std::array<u8, 4> b{};
    if (!read_exact(b)) return false;
    out = detail::load_le32(b.data());
    return true;
}

bool Reader::read_u64(u64& out) {
    std::array<u8, 8> b{};
    if (!read_exact(b)) return false;
    out = detail::load_le64(b.data());
    return true;
}

// Canonical uvarint (§4.9): at most 10 bytes; the last byte of a multi-byte
// encoding MUST NOT be 0x00; a 10th byte MUST be 0x01 (0x00 would be a
// redundant zero group, >= 0x02 would overflow u64).
WireResult<u64> Reader::read_uvarint() {
    u64 value = 0;
    for (unsigned index = 0; index < 10; ++index) {
        u8 byte = 0;
        if (!read_u8(byte)) {
            return detail::err(WireCode::Invalid, Stage::None, "U.uvarint", "truncated uvarint");
        }
        const bool more = (byte & 0x80u) != 0u;
        const u8 low = static_cast<u8>(byte & 0x7Fu);
        if (index == 9u) {
            if (more || low != 0x01u) {
                return detail::err(WireCode::Invalid, Stage::None, "U.uvarint",
                                   "non-canonical or overflowing 10-byte uvarint");
            }
            value |= (1ull << 63);
            return value;
        }
        if (!more && index > 0u && low == 0u) {
            return detail::err(WireCode::Invalid, Stage::None, "U.uvarint",
                               "redundant trailing zero group in uvarint");
        }
        value |= static_cast<u64>(low) << (index * 7u);
        if (!more) return value;
    }
    return detail::err(WireCode::Invalid, Stage::None, "U.uvarint", "uvarint longer than 10 bytes");
}

// Canonical tagged bigint (§4.9):
//   0x00                -> 0
//   0x01 <uvarint v>    -> 1 <= v <= 2^64-1   (v == 0 non-canonical)
//   0x02 <u32 len> ...  -> value >= 2^64, len >= 9, last magnitude byte != 0
WireResult<BigInt> Reader::read_bigint() {
    u8 tag = 0;
    if (!read_u8(tag)) {
        return detail::err(WireCode::Invalid, Stage::None, "U.bigint", "truncated bigint tag");
    }
    if (tag == 0x00u) return BigInt{};
    if (tag == 0x01u) {
        WireResult<u64> value = read_uvarint();
        if (!value.ok()) {
            return detail::err(WireCode::Invalid, Stage::None, "U.bigint",
                               "invalid uvarint in tag-0x01 bigint");
        }
        if (value.value() == 0) {
            return detail::err(WireCode::Invalid, Stage::None, "U.bigint",
                               "tag 0x01 with v == 0 is non-canonical");
        }
        return BigInt(value.value());
    }
    if (tag == 0x02u) {
        u32 len = 0;
        if (!read_u32(len)) {
            return detail::err(WireCode::Invalid, Stage::None, "U.bigint",
                               "truncated bigint length");
        }
        if (len < 9u) {
            return detail::err(WireCode::Invalid, Stage::None, "U.bigint",
                               "tag 0x02 with len < 9 is non-canonical");
        }
        if (static_cast<u64>(len) > remaining()) {
            return detail::err(WireCode::Invalid, Stage::None, "U.bigint",
                               "bigint magnitude exceeds the region");
        }
        std::vector<u8> magnitude(static_cast<std::size_t>(len));
        if (!read_exact(magnitude)) {
            return detail::err(WireCode::Invalid, Stage::None, "U.bigint",
                               "truncated bigint magnitude");
        }
        if (magnitude.back() == 0u) {
            return detail::err(WireCode::Invalid, Stage::None, "U.bigint",
                               "leading zero byte in bigint magnitude");
        }
        const std::string_view bytes(reinterpret_cast<const char*>(magnitude.data()),
                                     magnitude.size());
        auto parsed = BigInt::from_le_bytes(bytes);
        if (!parsed.ok()) {
            return detail::err(WireCode::Invalid, Stage::None, "U.bigint",
                               "bigint magnitude rejected");
        }
        return parsed.value();
    }
    return detail::err(WireCode::Invalid, Stage::None, "U.bigint", "unknown bigint tag");
}

// ===========================================================================
// Codec surface (§9)
// ===========================================================================

std::size_t uvarint_size(u64 value) noexcept { return detail::uvarint_len(value); }

WireResult<std::size_t> bigint_size(const BigInt& value) noexcept {
    return detail::bigint_size_impl(value);
}

WireStatus write_uvarint(Sink& sink, u64 value) {
    std::array<u8, 10> buf{};
    std::size_t n = 0;
    while (value >= 0x80ull) {
        buf[n++] = static_cast<u8>((value & 0x7Full) | 0x80ull);
        value >>= 7;
    }
    buf[n++] = static_cast<u8>(value & 0x7Full);
    const Status status = sink.write(std::span<const u8>(buf.data(), n));
    if (!status.ok()) {
        return detail::err(WireCode::Limit, Stage::None, "U.sink", "sink rejected a write");
    }
    return WireStatus{};
}

WireStatus write_bigint(Sink& sink, const BigInt& value) {
    std::vector<u8> buf;
    buf.reserve(16);
    detail::append_bigint(buf, value);
    const Status status = sink.write(std::span<const u8>(buf.data(), buf.size()));
    if (!status.ok()) {
        return detail::err(WireCode::Limit, Stage::None, "U.sink", "sink rejected a write");
    }
    return WireStatus{};
}

WireResult<u64> read_uvarint(Reader& reader) { return reader.read_uvarint(); }
WireResult<BigInt> read_bigint(Reader& reader) { return reader.read_bigint(); }

// ===========================================================================
// Encode plan (§6.1, O7.1)
// ===========================================================================

namespace detail {
namespace {

// Exact region sizes of the atom and node tables, computed from the canonical
// `Ir` exactly as the writer writes them.
WireError measure_tables(const Ir& ir, const WireLimits& limits, u64& atom_region,
                         u64& node_region) {
    atom_region = 0;
    node_region = 0;

    if (ir.atoms.size() > static_cast<std::size_t>(limits.max_atoms)) {
        return err(WireCode::Limit, Stage::Atoms, "E.atoms", "atom count exceeds the limit");
    }
    if (ir.nodes.size() > static_cast<std::size_t>(limits.max_nodes)) {
        return err(WireCode::Limit, Stage::Nodes, "E.nodes", "node count exceeds the limit");
    }
    if (ir.nodes.empty()) {
        return err(WireCode::Invalid, Stage::Nodes, "E.nodes", "an Ir has at least one node");
    }

    // --- atoms -------------------------------------------------------------
    u64 atom_bytes = uvarint_len(static_cast<u64>(ir.atoms.size()));
    for (const Atom& atom : ir.atoms) {
        if (atom.flags != 0) {
            return err(WireCode::Invalid, Stage::Atoms, kStageAtomFlags, "atom flags must be 0");
        }
        if (!atom_length_ok(atom)) {
            return err(WireCode::Invalid, Stage::Atoms, kStageAtomLength,
                       "atom length must be 1..ATOM_MAX and equal its payload size");
        }
        WireResult<std::size_t> len_bytes = bigint_size_impl(atom.length);
        if (!len_bytes.ok()) return len_bytes.error();
        // u8 klass, u8 flags, u16 reserved, bigint length, u8[32] sha256, payload
        atom_bytes += 1 + 1 + 2 + static_cast<u64>(len_bytes.value()) + 32 + atom.payload.size();
    }
    atom_region = atom_bytes;

    // --- nodes -------------------------------------------------------------
    u64 node_bytes = uvarint_len(static_cast<u64>(ir.nodes.size()));
    for (const Node& node : ir.nodes) {
        if (!kind_domain(node.kind)) {
            return err(WireCode::Invalid, Stage::Nodes, kStageNodeKind, "unknown node kind");
        }
        if (node.flags != 0) {
            return err(WireCode::Invalid, Stage::Nodes, kStageNodeFlags, "node flags must be 0");
        }
        if (node.args.size() > 0xFFFFu) {
            return err(WireCode::Unsupported, Stage::Nodes, kStageNodeArgc,
                       "argc exceeds the u16 wire field");
        }
        node_bytes += 1 + 1 + 2;  // kind, flags, argc
        for (const u32 arg : node.args) node_bytes += uvarint_len(arg);
        switch (node.kind) {
            case Kind::Empty:
            case Kind::Concat:
            case Kind::Xor:
                break;
            case Kind::Atom: {
                const std::size_t atom_id = as_index(node.a);
                if (atom_id >= ir.atoms.size()) {
                    return err(WireCode::Invalid, Stage::Nodes, kStageNodeParams,
                               "Atom atom id out of range");
                }
                node_bytes += uvarint_len(static_cast<u64>(atom_id));
                break;
            }
            case Kind::Zero: {
                WireResult<std::size_t> n = bigint_size_impl(node.a);
                if (!n.ok()) return n.error();
                node_bytes += static_cast<u64>(n.value());
                break;
            }
            case Kind::Repeat:
            case Kind::Slice: {
                WireResult<std::size_t> a = bigint_size_impl(node.a);
                if (!a.ok()) return a.error();
                WireResult<std::size_t> b = bigint_size_impl(node.b);
                if (!b.ok()) return b.error();
                node_bytes += static_cast<u64>(a.value()) + static_cast<u64>(b.value());
                break;
            }
            case Kind::Morph:
                node_bytes += 2;  // u8 morph, u8 k
                break;
            case Kind::Interleave: {
                const std::optional<u64> stride = node.a.to_u64_checked();
                if (!stride.has_value() || *stride > 0xFFFFFFFFull) {
                    return err(WireCode::Invalid, Stage::Nodes, kStageNodeParams,
                               "Interleave stride does not fit u32");
                }
                node_bytes += 4;
                break;
            }
            case Kind::Lfsr: {
                WireResult<std::size_t> n = bigint_size_impl(node.a);
                if (!n.ok()) return n.error();
                node_bytes += 8 + 8 + static_cast<u64>(n.value());
                break;
            }
            case Kind::Affine: {
                WireResult<std::size_t> n = bigint_size_impl(node.a);
                if (!n.ok()) return n.error();
                node_bytes += 1 + 1 + static_cast<u64>(n.value());
                break;
            }
            case Kind::Predictor:
                node_bytes += 1 + 4;  // u8 pid, u32 param
                break;
        }
        WireResult<std::size_t> length_bytes = bigint_size_impl(node.length);
        if (!length_bytes.ok()) return length_bytes.error();
        node_bytes += static_cast<u64>(length_bytes.value());
    }
    node_region = node_bytes;
    return WireError{};
}

}  // namespace
}  // namespace detail

WireResult<WirePlan> plan(const Ir& ir, const WireLimits& limits) {
    // E3 §12: exceeding a *declared* limit is `Limit`, never `Invalid`.  E2's
    // `check_canonical` folds the count limits into its W1 check and reports them
    // as `Invalid`, so C07 checks its own limits first and only then asks E2
    // about canonical shape.  This ordering is what makes the code class right.
    if (ir.atoms.size() > static_cast<std::size_t>(limits.max_atoms)) {
        return detail::err(WireCode::Limit, Stage::Atoms, "E.atoms",
                           "atom count exceeds max_atoms");
    }
    if (ir.nodes.size() > static_cast<std::size_t>(limits.max_nodes)) {
        return detail::err(WireCode::Limit, Stage::Nodes, "E.nodes",
                           "node count exceeds max_nodes");
    }

    // Contract (E3 §6.1): encode requires a canonical `Ir`; E2 is the authority.
    // The §8.3 output cap is enforced by C07 below (stable stage attribution), so
    // E2's copy is not consulted here; a caller that disables the cap can
    // exercise the Region A.1 form for a declared length above 2^64.
    Limits e2_limits;
    e2_limits.max_nodes = limits.max_nodes;
    e2_limits.max_atoms = limits.max_atoms;
    e2_limits.max_depth = limits.max_depth;
    e2_limits.enforce_output_cap = false;
    const WfReport canonical = check_canonical(ir, e2_limits);
    if (!canonical.ok()) {
        return detail::err(canonical.code == Code::Limit ? WireCode::Limit : WireCode::Invalid,
                           Stage::Nodes, kStageNodeCanon, canonical.constraint);
    }

    u64 atom_region = 0;
    u64 node_region = 0;
    const WireError table_error = detail::measure_tables(ir, limits, atom_region, node_region);
    if (!table_error.ok()) return table_error;

    WirePlan p;
    p.atom_count = static_cast<u32>(ir.atoms.size());
    p.node_count = static_cast<u32>(ir.nodes.size());
    p.atom_region_bytes = atom_region;
    p.node_region_bytes = node_region;

    // --- canonical total-length form (§4.4) --------------------------------
    const std::optional<u64> small = ir.total_length.to_u64_checked();
    p.length_is_u64 = small.has_value();
    if (!small.has_value()) {
        const std::vector<u8> magnitude = detail::bigint_magnitude(ir.total_length);
        if (magnitude.size() < 9u) {
            return detail::err(WireCode::Invalid, Stage::Regions, kStageLengthForm,
                               "value >= 2^64 with a magnitude shorter than 9 bytes");
        }
        if (magnitude.size() > 0xFFFFull) {
            return detail::err(WireCode::Unsupported, Stage::Regions, kStageLengthCap,
                               "total-length magnitude exceeds the u16 field");
        }
        p.total_length_big_len = static_cast<u64>(magnitude.size());
    }

    // --- canonical index policy (§4.7) -------------------------------------
    detail::IndexPolicy policy;
    const WireError index_error = detail::compute_index_policy(ir, limits, policy);
    if (!index_error.ok()) return index_error;
    WireResult<u64> index_bytes = detail::index_region_size(policy);
    if (!index_bytes.ok()) return index_bytes.error();
    p.index_present = !policy.entries.empty();
    p.index_entries = static_cast<u32>(policy.entries.size());
    p.index_region_bytes = index_bytes.value();

    // --- region arithmetic --------------------------------------------------
    p.atom_offset = static_cast<u64>(kWireHeaderBytes) + p.total_length_big_len;
    p.node_offset = p.atom_offset + atom_region;
    const u64 node_end = p.node_offset + node_region;
    p.index_offset = p.index_present ? node_end : 0;
    p.trailer_offset = node_end + p.index_region_bytes;
    if (p.trailer_offset > std::numeric_limits<u64>::max() - static_cast<u64>(kWireTrailerBytes)) {
        return detail::err(WireCode::Limit, Stage::Regions, kStageRegionOrder,
                           "container size overflows u64");
    }
    p.file_bytes = p.trailer_offset + static_cast<u64>(kWireTrailerBytes);

    if (p.atom_offset > p.node_offset || p.node_offset > node_end || node_end > p.trailer_offset) {
        return detail::err(WireCode::Limit, Stage::Regions, kStageRegionOrder,
                           "non-monotonic region offsets");
    }
    if (limits.enforce_output_cap && ir.total_length > limits.max_output_bytes) {
        return detail::err(WireCode::Limit, Stage::Regions, kStageOutputCap,
                           "declared total length exceeds the output cap");
    }
    if (p.file_bytes > limits.max_container_bytes) {
        return detail::err(WireCode::Limit, Stage::Regions, "E.container",
                           "container exceeds the limit");
    }
    return p;
}

WireResult<BigInt> encoded_size(const Ir& ir, const WireLimits& limits) {
    WireResult<WirePlan> p = plan(ir, limits);
    if (!p.ok()) return p.error();
    return BigInt(p.value().file_bytes);
}

WireStatus encode_to(const Ir& ir, Sink& sink, const WireLimits& limits) {
    WireResult<WirePlan> p = plan(ir, limits);
    if (!p.ok()) return p.error();
    return detail::write_wire(ir, p.value(), limits, sink);
}

WireResult<std::vector<u8>> encode(const Ir& ir, const WireLimits& limits) {
    WireResult<WirePlan> p = plan(ir, limits);
    if (!p.ok()) return p.error();
    std::vector<u8> out;
    out.reserve(static_cast<std::size_t>(p.value().file_bytes));
    const WireError e = detail::append_wire(ir, p.value(), limits, out);
    if (!e.ok()) return e;
    if (static_cast<u64>(out.size()) != p.value().file_bytes) {
        return detail::err(WireCode::Invalid, Stage::Regions, "E.size",
                           "writer emitted a size different from the plan");
    }
    return out;
}

}  // namespace marp::v2
