// MARP v2 — E3 WIRE — C07 WIRE — part 3 of 3.
//
//   * the canonical seek-index policy (§4.7)
//   * the index region writer and validator
//   * the single wire assembler used by `encode_to` / `encode` (§4.1–4.8)
//
// Canonical index policy.  E3 §4.7 makes the index *canonical*: an entry exists
// for output offset `s` iff `s > 0`, `s % INDEX_STRIDE == 0`, and at least one
// node *starts* at `s`; the entry's `node_id` is the smallest node id whose
// output starts there.  "Node n starts at s" is read in the only way that makes
// the rule a total function of the term (REPORT/E3/C07-WIRE-REPORT.md §5):
//
//   there is an occurrence of `n` in the unfolding of the denotation whose first
//   emitted byte is output offset `s`.
//
// Children of a node therefore start at deterministically translated offsets:
//
//   Concat        child k starts at parent_start + len(child 0) + … + len(child k-1)
//   Repeat        child starts at parent_start + i·len(child), i = 0 … q-1
//   Xor           both operands start at parent_start
//   Interleave    every child starts at parent_start
//   Morph         child starts at parent_start
//   Predictor     residual starts at parent_start
//   Slice(c, a, l) child starts at parent_start iff a == 0 (a > 0 hides its byte 0)
//   Empty / Atom / Zero / Lfsr / Affine   leaves
//
// This is exactly the descendant walk an independent reader performs when it
// asks "which nodes begin at offset s", so the writer and the reader agree by
// construction rather than by coincidence.  The walk is bounded by
// `WireLimits::max_index_occurrences`; a term that would need more is `Limit`
// (see the report's limitations section for why that bound is not a format
// constant).

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <map>
#include <string>
#include <utility>
#include <vector>

#include "e3_wire_internal.hpp"
#include "mapr/e1_crc32.hpp"
#include "mapr/e1_sha256.hpp"
#include "mapr/e2/e2_term.hpp"

namespace marp::v2::detail {
namespace {

// Exact offset arithmetic with an explicit overflow/limit signal.
enum class Arith { Ok, TooLarge };

Arith add_offset(const BigInt& base, const BigInt& delta, BigInt& out) {
    auto sum = base.add(delta);
    if (!sum.ok()) return Arith::TooLarge;
    out = std::move(sum.value());
    return Arith::Ok;
}

Arith mul_offset(const BigInt& a, const BigInt& b, BigInt& out) {
    auto product = a.mul(b);
    if (!product.ok()) return Arith::TooLarge;
    out = std::move(product.value());
    return Arith::Ok;
}

struct Occurrence {
    u32 node = 0;
    BigInt start;
};

}  // namespace

// ---------------------------------------------------------------------------
// Canonical policy (§4.7)
// ---------------------------------------------------------------------------

WireError compute_index_policy(const Ir& ir, const WireLimits& limits, IndexPolicy& out) {
    out = IndexPolicy{};
    const std::size_t n = ir.nodes.size();
    if (n == 0) return WireError{};
    const BigInt stride = BigInt(kWireIndexStride);
    const BigInt zero{};

    // Per-node dedupe of known occurrence starts (small sets in practice).
    std::vector<std::vector<BigInt>> seen(n);

    struct Pending {
        u32 node;
        BigInt start;
    };
    std::vector<Pending> frontier;
    frontier.push_back(Pending{ir.root, BigInt{}});
    seen[ir.root].push_back(BigInt{});

    // Map from offset (decimal form) to the smallest node id starting there.
    std::map<std::string, std::pair<BigInt, u32>> candidates;
    u64 visits = 0;

    while (!frontier.empty()) {
        const Pending current = std::move(frontier.back());
        frontier.pop_back();
        ++visits;
        if (visits > limits.max_index_occurrences) {
            return err(WireCode::Limit, Stage::Index, kStageIndexPolicy,
                       "canonical index needs more node occurrences than the limit");
        }

        // Is `current.start` an entry offset?
        if (!current.start.is_zero()) {
            auto division = current.start.divmod(stride);
            if (!division.ok()) {
                return err(WireCode::Limit, Stage::Index, kStageIndexPolicy,
                           "index offset division failed");
            }
            if (division.value().second.is_zero()) {
                const std::string key = current.start.to_decimal();
                auto it = candidates.find(key);
                if (it == candidates.end()) {
                    candidates.emplace(key, std::make_pair(current.start, current.node));
                    if (candidates.size() > static_cast<std::size_t>(limits.max_index_entries)) {
                        return err(WireCode::Limit, Stage::Index, kStageIndexPolicy,
                                   "canonical index needs more entries than the limit");
                    }
                } else if (current.node < it->second.second) {
                    it->second.second = current.node;
                }
            }
        }

        const Node& node = ir.nodes[current.node];
        auto descend = [&](u32 child, const BigInt& start) -> WireError {
            for (const BigInt& known : seen[child]) {
                if (known == start) return WireError{};  // already visited
            }
            seen[child].push_back(start);
            frontier.push_back(Pending{child, start});
            return WireError{};
        };

        switch (node.kind) {
            case Kind::Empty:
            case Kind::Atom:
            case Kind::Zero:
            case Kind::Lfsr:
            case Kind::Affine:
                break;
            case Kind::Concat: {
                BigInt cumulative = zero;
                for (const u32 child : node.args) {
                    BigInt child_start;
                    if (add_offset(current.start, cumulative, child_start) != Arith::Ok) {
                        return err(WireCode::Limit, Stage::Index, kStageIndexPolicy,
                                   "concat offset overflow");
                    }
                    const WireError e = descend(child, child_start);
                    if (!e.ok()) return e;
                    BigInt next;
                    if (add_offset(cumulative, ir.nodes[child].length, next) != Arith::Ok) {
                        return err(WireCode::Limit, Stage::Index, kStageIndexPolicy,
                                   "concat cumulative overflow");
                    }
                    cumulative = std::move(next);
                }
                break;
            }
            case Kind::Xor:
            case Kind::Interleave: {
                for (const u32 child : node.args) {
                    const WireError e = descend(child, current.start);
                    if (!e.ok()) return e;
                }
                break;
            }
            case Kind::Morph:
            case Kind::Predictor: {
                if (!node.args.empty()) {
                    const WireError e = descend(node.args[0], current.start);
                    if (!e.ok()) return e;
                }
                break;
            }
            case Kind::Repeat: {
                if (node.args.empty()) break;
                const u32 child = node.args[0];
                const BigInt& child_len = ir.nodes[child].length;
                const BigInt& q = node.a;
                if (child_len.is_zero()) {
                    const WireError e = descend(child, current.start);
                    if (!e.ok()) return e;
                    break;
                }
                // `q` may be astronomical (2^60 in the Region A.1 corpus), so this
                // walk must never iterate once per repetition.
                //
                // Repetition `i` places the child at `start + i*child_len`.  Two
                // families of index entries can arise there:
                //   (a) the child start itself is a stride multiple;
                //   (b) a boundary *inside* the child is a stride multiple.
                // A child with no internal boundaries (`boundary_free`) has none of
                // (b), so only the `i` of family (a) need visiting; they form the
                // arithmetic progression `i = 0, P, 2P, ...` with
                // `P = INDEX_STRIDE / gcd(child_len, INDEX_STRIDE)`.
                const bool boundary_free =  // leaf shapes only
                    ir.nodes[child].kind == Kind::Empty ||
                    ir.nodes[child].kind == Kind::Atom ||
                    ir.nodes[child].kind == Kind::Zero ||
                    ir.nodes[child].kind == Kind::Lfsr ||
                    ir.nodes[child].kind == Kind::Affine;
                const std::optional<u64> q_small = q.to_u64_checked();
                const bool iterate_all =
                    q_small.has_value() && *q_small <= (1ull << 20);

                // P = stride / gcd(child_len, stride)
                BigInt period = kWireIndexStride > 0 ? BigInt(kWireIndexStride) : BigInt(1);
                if (boundary_free || !iterate_all) {
                    auto gcd = gcd_bigint(child_len, BigInt(kWireIndexStride));
                    if (!gcd.ok() || gcd.value().is_zero()) {
                        return err(WireCode::Limit, Stage::Index, kStageIndexPolicy,
                                   "repeat index period is undefined");
                    }
                    auto quotient = BigInt(kWireIndexStride).divmod(gcd.value());
                    if (!quotient.ok()) {
                        return err(WireCode::Limit, Stage::Index, kStageIndexPolicy,
                                   "repeat index period overflow");
                    }
                    period = std::move(quotient.value().first);
                    if (period.is_zero()) period = BigInt(1);
                }

                if (!iterate_all && !boundary_free) {
                    // Family (b) means one visit per repetition; that is beyond any
                    // useful budget for a non-atomic child.
                    return err(WireCode::Limit, Stage::Index, kStageIndexPolicy,
                               "canonical index for a non-atomic Repeat above the "
                               "occurrence budget is not computable");
                }
                if (!iterate_all) {
                    // Family (a) alone already needs `q/P` occurrences and therefore
                    // at least `q/P` entries: reject before doing the work.
                    auto needed = q.divmod(period);
                    if (!needed.ok() ||
                        needed.value().first > BigInt(limits.max_index_entries)) {
                        return err(WireCode::Limit, Stage::Index, kStageIndexPolicy,
                                   "canonical index needs more entries than the limit");
                    }
                }

                BigInt i = zero;
                while (i < q) {
                    BigInt delta;
                    if (mul_offset(i, child_len, delta) != Arith::Ok) {
                        return err(WireCode::Limit, Stage::Index, kStageIndexPolicy,
                                   "repeat offset overflow");
                    }
                    BigInt child_start;
                    if (add_offset(current.start, delta, child_start) != Arith::Ok) {
                        return err(WireCode::Limit, Stage::Index, kStageIndexPolicy,
                                   "repeat offset overflow");
                    }
                    const WireError e = descend(child, child_start);
                    if (!e.ok()) return e;
                    if (visits + frontier.size() > limits.max_index_occurrences) {
                        return err(WireCode::Limit, Stage::Index, kStageIndexPolicy,
                                   "canonical index needs more node occurrences than the limit");
                    }
                    auto next = iterate_all ? i.add(BigInt(1)) : i.add(period);
                    if (!next.ok()) {
                        return err(WireCode::Limit, Stage::Index, kStageIndexPolicy,
                                   "repeat counter overflow");
                    }
                    i = std::move(next.value());
                }
                break;
            }
            case Kind::Slice: {
                if (!node.args.empty() && node.a.is_zero()) {
                    const WireError e = descend(node.args[0], current.start);
                    if (!e.ok()) return e;
                }
                break;
            }
        }
    }

    out.occurrences = visits;
    out.entries.reserve(candidates.size());
    // `std::map<std::string,...>` order is lexicographic, not numeric: sort by
    // value with E1's exact comparison instead.
    std::vector<std::pair<BigInt, u32>> ordered;
    ordered.reserve(candidates.size());
    for (const auto& [key, value] : candidates) {
        (void)key;
        ordered.push_back(value);
    }
    std::sort(ordered.begin(), ordered.end(),
              [](const std::pair<BigInt, u32>& a, const std::pair<BigInt, u32>& b) {
                  return a.first < b.first;
              });
    for (const auto& [offset, id] : ordered) {
        IndexEntryC07 entry;
        const std::optional<u64> offset_u64 = offset.to_u64_checked();
        if (!offset_u64.has_value()) {
            return err(WireCode::Unsupported, Stage::Index, kStageIndexPolicy,
                       "a canonical index offset does not fit u64");
        }
        entry.output_offset = *offset_u64;
        entry.node_id = id;
        entry.crc32_of_prefix = 0;  // filled from the denotation by the writer
        out.entries.push_back(entry);
    }
    return WireError{};
}

WireResult<u64> index_region_size(const IndexPolicy& policy) {
    if (policy.entries.empty()) return u64{0};
    // magic(8) + u32 entry_count + entries + u32 index_crc32
    u64 bytes = 8 + 4 + 4;
    for (const IndexEntryC07& entry : policy.entries) {
        WireResult<std::size_t> offset_bytes = bigint_size_impl(entry.output_offset);
        if (!offset_bytes.ok()) return offset_bytes.error();
        bytes += static_cast<u64>(offset_bytes.value());
        bytes += uvarint_len(entry.node_id);
        bytes += 4;  // crc32_of_prefix
    }
    return bytes;
}

void append_index_region(std::vector<u8>& out, const IndexPolicy& policy) {
    const std::size_t start = out.size();
    out.insert(out.end(), kIndexMagic.begin(), kIndexMagic.end());
    append_le32(out, static_cast<u32>(policy.entries.size()));
    for (const IndexEntryC07& entry : policy.entries) {
        append_bigint(out, entry.output_offset);
        append_uvarint(out, entry.node_id);
        append_le32(out, entry.crc32_of_prefix);
    }
    // index_crc32 = CRC-32 over every index byte before the field.
    const std::string_view covered(reinterpret_cast<const char*>(out.data() + start),
                                   out.size() - start);
    append_le32(out, mapr::crc32(covered));
}

// ---------------------------------------------------------------------------
// Prefix CRC-32 of the denotation (§4.7 `crc32_of_prefix`)
// ---------------------------------------------------------------------------

WireError fill_prefix_crcs(const Ir& ir, const WireLimits& limits, IndexPolicy& policy) {
    if (policy.entries.empty()) return WireError{};
    if (policy.entries.back().output_offset > limits.max_eval_bytes) {
        return err(WireCode::Limit, Stage::Index, kStageEvalPrefix,
                   "index prefix evaluation exceeds the work bound");
    }

    TermCursor cursor(ir, ir.root);
    std::vector<u8> block(static_cast<std::size_t>(kEvalBlock));
    BigInt offset{};
    u32 crc = 0;  // finalized CRC-32 of the empty string
    std::size_t next = 0;
    while (next < policy.entries.size()) {
        const BigInt& want = policy.entries[next].output_offset;
        if (offset == want) {
            policy.entries[next].crc32_of_prefix = crc;
            ++next;
            continue;
        }
        auto gap = want.sub(offset);
        if (!gap.ok()) {
            return err(WireCode::Mismatch, Stage::Eval, kStageEvalLength,
                       "index offsets are not increasing");
        }
        std::optional<u64> gap_u64 = gap.value().to_u64_checked();
        const u64 take_u64 = gap_u64.has_value()
                                 ? std::min<u64>(*gap_u64, static_cast<u64>(block.size()))
                                 : static_cast<u64>(block.size());
        const std::size_t take = static_cast<std::size_t>(take_u64);
        auto read = cursor.read(std::span<u8>(block.data(), take));
        if (!read.ok()) {
            return err(read.code() == Code::Limit ? WireCode::Limit : WireCode::Mismatch,
                       Stage::Eval, kStageEvalLength,
                       "denotation rejected while computing an index prefix");
        }
        if (read.value() != take) {
            return err(WireCode::Mismatch, Stage::Eval, kStageEvalLength,
                       "denotation shorter than a declared index offset");
        }
        crc = mapr::crc32_incremental(
            std::string_view(reinterpret_cast<const char*>(block.data()), take), crc);
        auto advanced = offset.add(BigInt(static_cast<u64>(take)));
        if (!advanced.ok()) {
            return err(WireCode::Limit, Stage::Eval, kStageEvalLength, "offset overflow");
        }
        offset = std::move(advanced.value());
    }
    return WireError{};
}

// ---------------------------------------------------------------------------
// Index validation (§5.1 step 10)
// ---------------------------------------------------------------------------

WireError validate_index_entries(const IndexPolicy& canonical,
                                 const std::vector<IndexEntryC07>& parsed) {
    if (parsed.size() != canonical.entries.size()) {
        return err(WireCode::Invalid, Stage::Index, kStageIndexPolicy,
                   "index entry set disagrees with the canonical policy");
    }
    for (std::size_t i = 0; i < parsed.size(); ++i) {
        if (parsed[i].output_offset != canonical.entries[i].output_offset) {
            return err(WireCode::Invalid, Stage::Index, kStageIndexPolicy,
                       "index output_offset set disagrees with the canonical policy");
        }
        if (parsed[i].node_id != canonical.entries[i].node_id) {
            return err(WireCode::Invalid, Stage::Index, kStageIndexNodeId,
                       "index node_id is not the smallest node starting at that offset");
        }
    }
    return WireError{};
}

// ---------------------------------------------------------------------------
// Wire assembler (§4.1–4.8)
// ---------------------------------------------------------------------------

namespace {

void append_atom_record(std::vector<u8>& out, const Atom& atom,
                        const std::array<u8, 32>& digest) {
    out.push_back(atom.klass);
    out.push_back(0u);      // flags
    append_le16(out, 0u);   // reserved
    append_bigint(out, atom.length);
    out.insert(out.end(), digest.begin(), digest.end());
    out.insert(out.end(), atom.payload.begin(), atom.payload.end());
}

void append_node_record(std::vector<u8>& out, const Node& node) {
    out.push_back(static_cast<u8>(node.kind));
    out.push_back(0u);  // flags
    append_le16(out, static_cast<u16>(node.args.size()));
    for (const u32 arg : node.args) append_uvarint(out, arg);
    switch (node.kind) {
        case Kind::Empty:
        case Kind::Concat:
        case Kind::Xor:
            break;
        case Kind::Atom:
            append_uvarint(out, static_cast<u64>(as_index(node.a)));
            break;
        case Kind::Zero:
            append_bigint(out, node.a);
            break;
        case Kind::Repeat:
        case Kind::Slice:
            append_bigint(out, node.a);
            append_bigint(out, node.b);
            break;
        case Kind::Morph:
            out.push_back(node.morph);
            out.push_back(node.morph_k);
            break;
        case Kind::Interleave:
            append_le32(out, static_cast<u32>(*node.a.to_u64_checked()));
            break;
        case Kind::Lfsr:
            append_le64(out, node.lfsr_conn);
            append_le64(out, node.lfsr_init);
            append_bigint(out, node.a);
            break;
        case Kind::Affine:
            out.push_back(node.affine_start);
            out.push_back(node.affine_step);
            append_bigint(out, node.a);
            break;
        case Kind::Predictor:
            out.push_back(node.predictor_id);
            append_le32(out, node.predictor_param);
            break;
    }
    append_bigint(out, node.length);
}

}  // namespace

WireError append_wire(const Ir& ir, const WirePlan& p, const WireLimits& limits,
                      std::vector<u8>& out) {
    out.clear();
    out.reserve(static_cast<std::size_t>(p.file_bytes));

    // --- Region A: header, patched after the CRCs are known ------------------
    out.resize(static_cast<std::size_t>(kWireHeaderBytes), 0u);

    // --- Region A.1: total-length magnitude (§4.4) --------------------------
    if (!p.length_is_u64) {
        const std::vector<u8> magnitude = bigint_magnitude(ir.total_length);
        if (magnitude.size() != p.total_length_big_len) {
            return err(WireCode::Invalid, Stage::Regions, kStageLengthForm,
                       "total-length magnitude disagrees with the plan");
        }
        out.insert(out.end(), magnitude.begin(), magnitude.end());
    }

    // --- Region B: atom table (§4.5) ---------------------------------------
    append_uvarint(out, static_cast<u64>(ir.atoms.size()));
    for (const Atom& atom : ir.atoms) {
        const std::string_view payload(reinterpret_cast<const char*>(atom.payload.data()),
                                       atom.payload.size());
        auto digest = mapr::Sha256::hash(payload);
        if (!digest.ok()) {
            return err(WireCode::Limit, Stage::Atoms, kStageAtomSha, "atom digest overflow");
        }
        if (digest.value() != atom.sha256) {
            return err(WireCode::Invalid, Stage::Atoms, kStageAtomSha,
                       "atom record sha256 disagrees with its payload");
        }
        append_atom_record(out, atom, digest.value());
    }

    // --- Region C: node table (§4.6) ---------------------------------------
    append_uvarint(out, static_cast<u64>(ir.nodes.size()));
    for (const Node& node : ir.nodes) append_node_record(out, node);

    // --- Region D: seek index (§4.7) ---------------------------------------
    IndexPolicy policy;
    WireError policy_error = compute_index_policy(ir, limits, policy);
    if (!policy_error.ok()) return policy_error;
    if (policy.entries.size() != static_cast<std::size_t>(p.index_entries) ||
        policy.entries.empty() == p.index_present) {
        return err(WireCode::Invalid, Stage::Index, kStageIndexPolicy,
                   "index policy disagrees with the plan");
    }
    if (p.index_present) {
        policy_error = fill_prefix_crcs(ir, limits, policy);
        if (!policy_error.ok()) return policy_error;
        append_index_region(out, policy);
    }

    // --- Region E: trailer (§4.8) ------------------------------------------
    const std::size_t trailer_offset = out.size();
    if (static_cast<u64>(trailer_offset) != p.trailer_offset) {
        return err(WireCode::Invalid, Stage::Regions, kStageRegionOrder,
                   "assembled regions disagree with the plan");
    }
    out.insert(out.end(), kTrailerMagic.begin(), kTrailerMagic.end());
    append_le64(out, p.file_bytes);
    append_le32(out, p.node_count - 1u);  // root id is the last record
    append_le32(out, p.atom_count);
    append_le32(out, p.node_count);
    append_le32(out, 0u);  // trailer_crc32 placeholder

    // --- header -------------------------------------------------------------
    u32 flags = kWireFlagCanonical | kWireFlagByteAligned;
    if (p.index_present) flags |= kWireFlagIndexPresent;
    if (p.length_is_u64) flags |= kWireFlagU64Lengths;

    std::memcpy(out.data(), kHeaderMagic.data(), kHeaderMagic.size());
    store_le16(std::span<u8>(out.data() + kHdrOffVersionMajor, 2), kWireVersionMajor);
    store_le16(std::span<u8>(out.data() + kHdrOffVersionMinor, 2), kWireVersionMinor);
    store_le32(std::span<u8>(out.data() + kHdrOffFlags, 4), flags);
    store_le16(std::span<u8>(out.data() + kHdrOffHeaderBytes, 2), kWireHeaderBytes);
    const std::optional<u64> small = ir.total_length.to_u64_checked();
    store_le64(std::span<u8>(out.data() + kHdrOffTotalLengthU64, 8), small.value_or(0));
    store_le16(std::span<u8>(out.data() + kHdrOffTotalLengthBigLen, 2),
               static_cast<u16>(p.total_length_big_len));
    store_le64(std::span<u8>(out.data() + kHdrOffAtomOffset, 8), p.atom_offset);
    store_le64(std::span<u8>(out.data() + kHdrOffNodeOffset, 8), p.node_offset);
    store_le64(std::span<u8>(out.data() + kHdrOffIndexOffset, 8), p.index_offset);
    store_le64(std::span<u8>(out.data() + kHdrOffTrailerOffset, 8), p.trailer_offset);
    store_le32(std::span<u8>(out.data() + kHdrOffFileCrc32, 4), 0u);

    // file_crc32 = CRC-32 over [0, trailer_offset) with its own field zeroed.
    const std::string_view covered(reinterpret_cast<const char*>(out.data()),
                                   static_cast<std::size_t>(p.trailer_offset));
    const u32 file_crc = mapr::crc32(covered);
    store_le32(std::span<u8>(out.data() + kHdrOffFileCrc32, 4), file_crc);

    // trailer_crc32 = CRC32(trailer[0..28) || LE32(file_crc32)).
    {
        std::array<u8, 32> buffer{};
        std::memcpy(buffer.data(), out.data() + trailer_offset, 28);
        store_le32(std::span<u8>(buffer.data() + 28, 4), file_crc);
        const u32 trailer_crc = mapr::crc32(std::string_view(
            reinterpret_cast<const char*>(buffer.data()), buffer.size()));
        store_le32(std::span<u8>(out.data() + trailer_offset + kTrlOffTrailerCrc32, 4),
                   trailer_crc);
    }

    if (static_cast<u64>(out.size()) != p.file_bytes) {
        return err(WireCode::Invalid, Stage::Regions, "E.size",
                   "assembled size disagrees with the plan");
    }
    return WireError{};
}

WireStatus write_wire(const Ir& ir, const WirePlan& p, const WireLimits& limits, Sink& sink) {
    std::vector<u8> buffer;
    if (p.file_bytes > (1ull << 34)) {
        return err(WireCode::Limit, Stage::Regions, "E.container",
                   "encode_to buffer above 16 GiB is not supported");
    }
    const WireError e = append_wire(ir, p, limits, buffer);
    if (!e.ok()) return e;
    const Status status = sink.write(std::span<const u8>(buffer.data(), buffer.size()));
    if (!status.ok()) {
        return err(WireCode::Limit, Stage::None, "E.sink", "sink rejected the wire write");
    }
    return WireStatus{};
}

}  // namespace marp::v2::detail
