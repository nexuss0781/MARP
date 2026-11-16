// MARP v2 — E3 WIRE — E3-G integrated gate — corpus construction (§13.3).
//
// Harness-only.  The E2 corpus is consumed through its own headers
// (`src/e2g/e2g_corpus.hpp`), never re-derived, so W-CANON is exactly E2's
// `T-KAT` + `T-GEN` set and the identities in `corpus.tsv` are reproducible.

#include "e3g_corpus.hpp"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "e2g_corpus.hpp"
#include "e2g_terms.hpp"
#include "mapr/e1_crc32.hpp"
#include "mapr/e1_sha256.hpp"
#include "mapr/e2/e2_canon.hpp"
#include "mapr/e2/e2_dag.hpp"

namespace e3g {
namespace {

constexpr std::size_t kAtomMax = static_cast<std::size_t>(kWireAtomMax);

BigInt pow2(unsigned bits) {
    auto value = BigInt(1).shl(bits);
    return value.ok() ? value.value() : BigInt{};
}

std::array<u8, 32> digest_of(std::span<const u8> bytes) {
    auto digest = mapr::Sha256::hash(
        std::string_view(reinterpret_cast<const char*>(bytes.data()), bytes.size()));
    std::array<u8, 32> out{};
    if (digest.ok()) std::memcpy(out.data(), digest.value().data(), out.size());
    return out;
}

// Builds an `Ir` through E2's `Dag` and certifies it with E2's own predicates.
bool finish_dag(Dag& dag, u32 root, Ir& out, std::string& why) {
    auto finished = std::move(dag).finish(root);
    if (!finished.ok()) {
        why = std::string("Dag::finish returned ") + code_name(finished.code());
        return false;
    }
    out = std::move(finished.value());
    return true;
}

// A directly built `Ir` (bypassing `Dag::finish`'s output cap) that E2 still
// certifies as well-formed and canonical under `enforce_output_cap = false`.
bool certify_direct(Ir ir, bool above_cap, Ir& out, std::string& why) {
    Limits limits;
    limits.enforce_output_cap = !above_cap;
    const WfReport wf = check_well_formed_report(ir, limits);
    if (!wf.ok()) {
        why = std::string("direct Ir is not well-formed: ") + wf.constraint + " " + wf.message;
        return false;
    }
    const WfReport canonical = check_canonical(ir, limits);
    if (!canonical.ok()) {
        why = std::string("direct Ir is not canonical: ") + canonical.constraint + " " +
              canonical.message;
        return false;
    }
    out = std::move(ir);
    return true;
}

Ir direct_zero(const BigInt& n) {
    Ir ir;
    Node node;
    node.kind = Kind::Zero;
    node.a = n;
    node.length = n;
    ir.nodes.push_back(std::move(node));
    ir.root = 0;
    ir.total_length = ir.nodes[0].length;
    return ir;
}

Ir direct_lfsr(u64 conn, u64 init, const BigInt& n) {
    Ir ir;
    Node node;
    node.kind = Kind::Lfsr;
    node.lfsr_conn = conn;
    node.lfsr_init = init;
    node.a = n;
    node.length = n;
    ir.nodes.push_back(std::move(node));
    ir.root = 0;
    ir.total_length = ir.nodes[0].length;
    return ir;
}

Ir direct_repeat_atom(std::size_t atom_bytes, u8 seed, const BigInt& q, const BigInt& r) {
    auto owner = std::make_shared<std::vector<std::vector<u8>>>();
    owner->push_back(payload(atom_bytes, seed));
    Ir ir;
    Atom atom;
    atom.klass = 9;
    atom.length = BigInt(static_cast<u64>(atom_bytes));
    atom.payload = std::span<const u8>(owner->back().data(), owner->back().size());
    atom.owner = owner;
    atom.sha256 = digest_of(atom.payload);
    ir.atoms.push_back(std::move(atom));

    Node child;
    child.kind = Kind::Atom;
    child.a = BigInt(0);
    child.length = BigInt(static_cast<u64>(atom_bytes));
    ir.nodes.push_back(std::move(child));

    Node repeat;
    repeat.kind = Kind::Repeat;
    repeat.args = {0};
    repeat.a = q;
    repeat.b = r;
    auto product = q.mul(BigInt(static_cast<u64>(atom_bytes)));
    repeat.length = product.ok() ? product.value() : BigInt{};
    if (product.ok() && r != BigInt{}) {
        auto sum = repeat.length.add(r);
        if (sum.ok()) repeat.length = sum.value();
    }
    ir.nodes.push_back(std::move(repeat));
    ir.root = 1;
    ir.total_length = ir.nodes[1].length;
    return ir;
}

// ---------------------------------------------------------------------------
// The harness's own canonical container writer
// ---------------------------------------------------------------------------

void put_uvarint(std::vector<u8>& out, u64 value) {
    while (value >= 0x80ull) {
        out.push_back(static_cast<u8>((value & 0x7Full) | 0x80ull));
        value >>= 7;
    }
    out.push_back(static_cast<u8>(value));
}

void put_le16(std::vector<u8>& out, u16 v) {
    out.push_back(static_cast<u8>(v & 0xFFu));
    out.push_back(static_cast<u8>((v >> 8) & 0xFFu));
}

void put_le32(std::vector<u8>& out, u32 v) {
    out.push_back(static_cast<u8>(v & 0xFFu));
    out.push_back(static_cast<u8>((v >> 8) & 0xFFu));
    out.push_back(static_cast<u8>((v >> 16) & 0xFFu));
    out.push_back(static_cast<u8>((v >> 24) & 0xFFu));
}

void put_le64(std::vector<u8>& out, u64 v) {
    put_le32(out, static_cast<u32>(v & 0xFFFFFFFFull));
    put_le32(out, static_cast<u32>(v >> 32));
}

// Canonical bigint (§4.9) from decimal text: tag 0 for zero, tag 1 for a value
// that fits u64, tag 2 with a >= 9-byte little-endian magnitude beyond that.
bool put_bigint(std::vector<u8>& out, const std::string& decimal, std::string& why) {
    auto parsed = BigInt::from_decimal(decimal);
    if (!parsed.ok()) {
        why = "bad decimal '" + decimal + "'";
        return false;
    }
    const BigInt& value = parsed.value();
    if (value.is_zero()) {
        out.push_back(0x00u);
        return true;
    }
    const std::optional<u64> small = value.to_u64_checked();
    if (small.has_value()) {
        out.push_back(0x01u);
        put_uvarint(out, *small);
        return true;
    }
    std::vector<u8> magnitude = value.to_le_bytes();
    while (!magnitude.empty() && magnitude.back() == 0u) magnitude.pop_back();
    if (magnitude.size() < 9u) {
        why = "magnitude below 9 bytes for a value >= 2^64";
        return false;
    }
    out.push_back(0x02u);
    put_le32(out, static_cast<u32>(magnitude.size()));
    out.insert(out.end(), magnitude.begin(), magnitude.end());
    return true;
}

// A decimal field, or the raw bytes when the case deliberately overrides it.
bool put_raw_or_bigint(std::vector<u8>& out, const std::vector<u8>& raw,
                       const std::string& decimal, std::string& why) {
    if (!raw.empty()) {
        out.insert(out.end(), raw.begin(), raw.end());
        return true;
    }
    return put_bigint(out, decimal, why);
}

std::vector<u8> decimal_to_le(const std::string& decimal) {
    auto parsed = BigInt::from_decimal(decimal);
    if (!parsed.ok()) return {};
    std::vector<u8> magnitude = parsed.value().to_le_bytes();
    while (!magnitude.empty() && magnitude.back() == 0u) magnitude.pop_back();
    return magnitude;
}

}  // namespace

std::vector<u8> payload(std::size_t size, u8 seed) {
    std::vector<u8> bytes(size);
    u8 state = seed;
    for (std::size_t i = 0; i < size; ++i) {
        state = static_cast<u8>(state * 167u + 13u);
        bytes[i] = static_cast<u8>(state ^ static_cast<u8>(i * 31u));
    }
    return bytes;
}

std::vector<u8> assemble_container(const HandContainer& container, std::string& why) {
    why.clear();
    const std::vector<u8> total_le = decimal_to_le(container.total_length);
    auto total_parsed = BigInt::from_decimal(container.total_length);
    if (!total_parsed.ok()) {
        why = "bad total_length";
        return {};
    }
    const bool fits_u64 = total_parsed.value().to_u64_checked().has_value();
    u64 total_u64 = 0;
    if (fits_u64) total_u64 = *total_parsed.value().to_u64_checked();
    if (!fits_u64 && total_le.size() < 9u) {
        why = "Region A.1 magnitude below 9 bytes";
        return {};
    }
    if (total_le.size() > 65535u) {
        why = "Region A.1 magnitude above u16";
        return {};
    }

    // Region B: atom table.
    std::vector<u8> atoms;
    put_uvarint(atoms, static_cast<u64>(container.atoms.size()));
    for (const HandAtom& atom : container.atoms) {
        atoms.push_back(atom.klass);
        atoms.push_back(0u);  // flags
        put_le16(atoms, 0u);  // reserved
        if (!put_bigint(atoms, std::to_string(atom.payload_bytes.size()), why)) return {};
        const std::array<u8, 32> sha = digest_of(
            std::span<const u8>(atom.payload_bytes.data(), atom.payload_bytes.size()));
        atoms.insert(atoms.end(), sha.begin(), sha.end());
        atoms.insert(atoms.end(), atom.payload_bytes.begin(), atom.payload_bytes.end());
    }

    // Region C: node table.
    std::vector<u8> nodes;
    put_uvarint(nodes, static_cast<u64>(container.nodes.size()));
    for (const HandNode& node : container.nodes) {
        nodes.push_back(node.kind);
        nodes.push_back(0u);  // flags
        put_le16(nodes, static_cast<u16>(node.args.size()));
        for (const u32 arg : node.args) put_uvarint(nodes, arg);
        switch (node.kind) {
            case 0:  // Empty
                break;
            case 1:  // Atom
                put_uvarint(nodes, static_cast<u64>(std::stoul(node.param_a)));
                break;
            case 2:  // Zero
                if (!put_raw_or_bigint(nodes, node.raw_param_a, node.param_a, why)) return {};
                break;
            case 3:  // Concat
                break;
            case 4:  // Repeat
            case 5:  // Slice
                if (!put_raw_or_bigint(nodes, node.raw_param_a, node.param_a, why)) return {};
                if (!put_raw_or_bigint(nodes, node.raw_param_b, node.param_b, why)) return {};
                break;
            case 6:  // Morph
                nodes.push_back(node.morph);
                nodes.push_back(node.morph_k);
                break;
            case 7:  // Xor
                break;
            case 8:  // Interleave
                put_le32(nodes, node.stride);
                break;
            case 9:  // Lfsr
                put_le64(nodes, node.lfsr_conn);
                put_le64(nodes, node.lfsr_init);
                if (!put_bigint(nodes, node.param_a, why)) return {};
                break;
            case 10:  // Affine
                nodes.push_back(node.affine_start);
                nodes.push_back(node.affine_step);
                if (!put_bigint(nodes, node.param_a, why)) return {};
                break;
            case 11:  // Predictor
                nodes.push_back(node.predictor_id);
                put_le32(nodes, node.predictor_param);
                break;
            default:
                why = "unsupported kind in the hand-built writer";
                return {};
        }
        if (!put_raw_or_bigint(nodes, node.raw_length, node.length, why)) return {};
    }

    // Layout (§4.1–4.2).  No index region: the hand-built seeds never reach a
    // stride boundary, which the assembler asserts rather than assumes.
    auto total_big = BigInt::from_decimal(container.total_length);
    if (total_big.ok()) {
        auto boundaries = total_big.value().divmod(BigInt(kWireIndexStride));
        if (boundaries.ok() && !boundaries.value().first.is_zero()) {
            why = "hand-built writer does not model a seek index";
            return {};
        }
    }
    // §4.2: atom_offset = 64 + total_length_big_len.  Region A.1 is present only
    // for the big form, so a u64-form container starts its atom table at 64.
    const u64 big_len = fits_u64 ? 0u : static_cast<u64>(total_le.size());
    const u64 atom_offset = static_cast<u64>(kWireHeaderBytes) + big_len;
    const u64 node_offset = atom_offset + atoms.size();
    const u64 trailer_offset = node_offset + nodes.size();
    const u64 file_bytes = trailer_offset + static_cast<u64>(kWireTrailerBytes);

    u32 flags = kWireFlagCanonical | kWireFlagByteAligned;
    if (fits_u64) flags |= kWireFlagU64Lengths;

    std::vector<u8> wire;
    wire.reserve(static_cast<std::size_t>(file_bytes));
    wire.insert(wire.end(), kHeaderMagic.begin(), kHeaderMagic.end());
    put_le16(wire, kWireVersionMajor);
    put_le16(wire, kWireVersionMinor);
    put_le32(wire, flags);
    put_le16(wire, kWireHeaderBytes);
    put_le64(wire, total_u64);
    put_le16(wire, static_cast<u16>(big_len));
    put_le64(wire, atom_offset);
    put_le64(wire, node_offset);
    put_le64(wire, 0u);  // index_offset: absent
    put_le64(wire, trailer_offset);
    put_le32(wire, 0u);  // file_crc32 placeholder
    if (!fits_u64) wire.insert(wire.end(), total_le.begin(), total_le.end());
    wire.insert(wire.end(), atoms.begin(), atoms.end());
    wire.insert(wire.end(), nodes.begin(), nodes.end());

    wire.insert(wire.end(), kTrailerMagic.begin(), kTrailerMagic.end());
    put_le64(wire, file_bytes);
    put_le32(wire, container.nodes.empty() ? 0u
                                           : static_cast<u32>(container.nodes.size() - 1u));
    put_le32(wire, static_cast<u32>(container.atoms.size()));
    put_le32(wire, static_cast<u32>(container.nodes.size()));
    put_le32(wire, 0u);  // trailer_crc32 placeholder
    repair_outer_crcs(wire);
    return wire;
}

// ---------------------------------------------------------------------------
// Corpus
// ---------------------------------------------------------------------------

Corpus build_corpus(const std::string& root) {
    Corpus corpus;
    corpus.e2_seed_note =
        "T-KAT seed=0, T-GEN seed=0xE2A15EED0001 (E2 CorpusSeeds), atom seed=0xE2A15EED0002";

    // ---------------- W-CANON: E2's T-KAT + T-GEN -------------------------
    {
        e2g::Corpus e2 = e2g::build_corpus();
        for (const e2g::CorpusTerm& term : e2.terms) {
            if (term.corpus != "T-KAT" && term.corpus != "T-GEN") continue;
            e2g::BindResult bound = e2g::bind(term.desc);
            if (!bound.ok) continue;
            CanonItem item;
            item.id = term.id;
            item.group = "W-CANON";
            item.origin = term.corpus;
            item.ir = std::move(bound.ir);
            item.note = term.corpus == "T-KAT" ? "E2 pinned term" : "E2 generated term";
            if (term.corpus == "T-KAT") ++corpus.t_kat_bound; else ++corpus.t_gen_bound;
            // E2's own canonical form is the authority on whether a term is
            // canonical (E2 §4.7).  `Dag::finish` emits post-order first-use ids
            // but does not run the C04 rewrite system, so a few generated shapes
            // are not in canonical form; §13.3's corpus is *canonical terms*, so
            // those are canonicalised with E2's own `canon` before use.  The
            // count is recorded so the decision is visible in the evidence.
            const WfReport canonical = check_canonical(item.ir);
            if (!canonical.ok()) {
                CanonReport report;
                auto rewritten = canon(item.ir, report);
                if (!rewritten.ok()) continue;
                const WfReport again = check_canonical(rewritten.value());
                if (!again.ok()) continue;
                item.ir = std::move(rewritten.value());
                item.canonicalised = true;
                item.canonical_report = canonical.constraint;
            }
            corpus.canon.push_back(std::move(item));
        }
    }

    // ---------------- W-CANON edge cases (§13.3) --------------------------
    auto push_edge = [&corpus](std::string id, std::string group, Ir ir, bool above_cap,
                               std::string note) {
        CanonItem item;
        item.id = std::move(id);
        item.group = std::move(group);
        item.origin = "edge";
        item.ir = std::move(ir);
        item.above_output_cap = above_cap;
        item.note = std::move(note);
        corpus.canon.push_back(std::move(item));
    };
    std::string why;

    // Empty and one byte.
    {
        Dag dag;
        auto id = dag.add_node(Node{});
        Ir ir;
        if (finish_dag(dag, id.value(), ir, why)) {
            push_edge("edge-empty", "W-CANON-EDGE", std::move(ir), false, "Empty, length 0");
        }
    }
    {
        Dag dag;
        const std::vector<u8> bytes = payload(1, 0xA5);
        auto atom_id = dag.add_atom(std::span<const u8>(bytes.data(), bytes.size()), 1);
        Node node;
        node.kind = Kind::Atom;
        node.a = BigInt(atom_id.value());
        auto id = dag.add_node(std::move(node));
        Ir ir;
        if (finish_dag(dag, id.value(), ir, why)) {
            push_edge("edge-atom-1", "W-CANON-EDGE", std::move(ir), false,
                      "one byte: a single 1-byte Atom");
        }
    }
    // Atom exactly ATOM_MAX.
    {
        Dag dag;
        const std::vector<u8> bytes = payload(kAtomMax, 0x5A);
        auto atom_id = dag.add_atom(std::span<const u8>(bytes.data(), bytes.size()), 200);
        Node node;
        node.kind = Kind::Atom;
        node.a = BigInt(atom_id.value());
        auto id = dag.add_node(std::move(node));
        Ir ir;
        if (finish_dag(dag, id.value(), ir, why)) {
            push_edge("edge-atom-max", "W-CANON-EDGE", std::move(ir), false,
                      "atom length == ATOM_MAX (1 MiB)");
        }
    }
    // ATOM_MAX + 1 split into two atoms.
    {
        Dag dag;
        const std::vector<u8> bytes = payload(kAtomMax + 1, 0x5B);
        auto first = dag.add_atom(std::span<const u8>(bytes.data(), kAtomMax), 11);
        auto second = dag.add_atom(std::span<const u8>(bytes.data() + kAtomMax, 1), 12);
        Node a;
        a.kind = Kind::Atom;
        a.a = BigInt(first.value());
        auto ai = dag.add_node(std::move(a));
        Node b;
        b.kind = Kind::Atom;
        b.a = BigInt(second.value());
        auto bi = dag.add_node(std::move(b));
        Node concat;
        concat.kind = Kind::Concat;
        concat.args = {ai.value(), bi.value()};
        auto id = dag.add_node(std::move(concat));
        Ir ir;
        if (finish_dag(dag, id.value(), ir, why)) {
            push_edge("edge-atom-max-plus-one", "W-CANON-EDGE", std::move(ir), false,
                      "ATOM_MAX + 1 split into two atom records");
        }
    }
    // Zero(1), Zero(2^32), Zero(2^40) and the index-absent / index-present shapes.
    for (const auto& spec : std::vector<std::pair<std::string, BigInt>>{
             {"edge-zero-1", BigInt(1)},
             {"edge-zero-2pow32", pow2(32)},
             {"edge-zero-2pow40", pow2(40)}}) {
        Ir ir = direct_zero(spec.second);
        Ir certified;
        if (certify_direct(std::move(ir), false, certified, why)) {
            push_edge(spec.first, "W-CANON-EDGE", std::move(certified), false,
                      "Zero(" + spec.second.to_decimal() + ") in the u64 length form");
        }
    }
    // Lfsr(2^40).
    {
        Ir ir = direct_lfsr(0xD800000000000000ull, 0x4D41525048314637ull, pow2(40));
        Ir certified;
        if (certify_direct(std::move(ir), false, certified, why)) {
            push_edge("edge-lfsr-2pow40", "W-CANON-EDGE", std::move(certified), false,
                      "Lfsr(conn, init, 2^40) in the u64 length form");
        }
    }
    // Index present: three 1 MiB atoms.
    {
        Dag dag;
        std::vector<u32> args;
        for (u32 i = 0; i < 3; ++i) {
            const std::vector<u8> bytes = payload(kAtomMax, static_cast<u8>(0x90 + i));
            auto atom_id = dag.add_atom(std::span<const u8>(bytes.data(), bytes.size()),
                                        static_cast<u8>(i));
            Node atom;
            atom.kind = Kind::Atom;
            atom.a = BigInt(atom_id.value());
            args.push_back(dag.add_node(std::move(atom)).value());
        }
        Node concat;
        concat.kind = Kind::Concat;
        concat.args = args;
        auto id = dag.add_node(std::move(concat));
        Ir ir;
        if (finish_dag(dag, id.value(), ir, why)) {
            push_edge("edge-index-3x-atom-max", "W-CANON-EDGE", std::move(ir), false,
                      "index present: 3 MiB, entries at 1 MiB and 2 MiB");
        }
    }
    // Index present over a Repeat.
    {
        Dag dag;
        const std::vector<u8> bytes = payload(static_cast<std::size_t>(1u << 20), 0xE1);
        auto atom_id = dag.add_atom(std::span<const u8>(bytes.data(), bytes.size()), 0);
        Node atom;
        atom.kind = Kind::Atom;
        atom.a = BigInt(atom_id.value());
        auto ai = dag.add_node(std::move(atom));
        Node repeat;
        repeat.kind = Kind::Repeat;
        repeat.args = {ai.value()};
        repeat.a = BigInt(5u);
        repeat.b = BigInt(0u);
        auto id = dag.add_node(std::move(repeat));
        Ir ir;
        if (finish_dag(dag, id.value(), ir, why)) {
            push_edge("edge-index-repeat-5x1mib", "W-CANON-EDGE", std::move(ir), false,
                      "index present: Repeat(1 MiB atom, 5, 0)");
        }
    }
    // Index absent: just under the stride.
    {
        Ir ir = direct_zero(BigInt((1ull << 20) - 1));
        Ir certified;
        if (certify_direct(std::move(ir), false, certified, why)) {
            push_edge("edge-index-absent-just-under", "W-CANON-EDGE", std::move(certified), false,
                      "index absent: total length just below INDEX_STRIDE");
        }
    }

    // ---------------- Region A.1 totals and the one encodability limit -----
    auto push_big = [&corpus](std::string id, Ir ir, bool expect_limit, std::string note) {
        Ir certified;
        std::string why_local;
        if (!certify_direct(std::move(ir), true, certified, why_local)) return;
        CanonItem item;
        item.id = std::move(id);
        item.group = "W-BIG";
        item.origin = "edge";
        item.ir = std::move(certified);
        item.above_output_cap = true;
        item.needs_limit_lift = true;
        item.expect_encode_limit = expect_limit;
        item.note = std::move(note);
        corpus.canon.push_back(std::move(item));
    };
    push_big("big-total-2pow64", direct_zero(pow2(64)), false,
             "Region A.1: total_length = 2^64 exactly");
    {
        auto plus_one = pow2(64).add(BigInt(1));
        push_big("big-total-2pow64-plus-one", direct_zero(plus_one.ok() ? plus_one.value() : BigInt{}),
                 false, "Region A.1: total_length = 2^64 + 1");
    }
    push_big("big-total-2pow128", direct_zero(pow2(128)), false,
             "Region A.1: total_length = 2^128 (Region A.1 = 17 bytes)");
    {
        auto n = pow2(64).sub(BigInt(1));
        Ir ir = direct_zero(n.ok() ? n.value() : BigInt{});
        Ir certified;
        if (certify_direct(std::move(ir), false, certified, why)) {
            push_edge("big-total-2pow64-minus-one", "W-BIG", std::move(certified), false,
                      "u64 form boundary: total_length = 2^64 - 1");
        }
    }
    push_big("big-total-lfsr-2pow65",
             direct_lfsr(0x8000000000000001ull, 0xDEADBEEFull, pow2(65)), false,
             "Region A.1 via Lfsr(conn, init, 2^65)");
    push_big("big-limit-repeat-entry-cap",
             direct_repeat_atom(static_cast<std::size_t>(1u << 20), 0x77,
                                pow2(44), BigInt(0)),
             true,
             "no canonical wire: 2^64/INDEX_STRIDE entries exceed the u32 entry_count");

    // ---------------- W-SEED hand-built canonical wires -------------------
    // Each is assembled by the harness's own writer and must be byte-identical
    // to what C07 produces for the equivalent term (checked in step 6), so they
    // are a genuine cross-check between two writers of the same format.
    auto push_hand = [&corpus](std::string id, HandContainer container, std::string& failure) {
        std::string reason;
        std::vector<u8> wire = assemble_container(container, reason);
        if (wire.empty()) {
            failure = reason;
            return false;
        }
        corpus.hand_built.push_back(SeedWire{std::move(id), "hand-built", std::move(wire)});
        return true;
    };
    {
        // bigint tag 0: Empty.
        HandContainer c;
        c.total_length = "0";
        HandNode n;
        n.kind = 0;
        n.length = "0";
        c.nodes.push_back(n);
        push_hand("seed-bigint-tag0-empty", c, why);
    }
    {
        // bigint tag 1: a 3-byte Atom.
        HandContainer c;
        c.total_length = "3";
        HandAtom a;
        a.klass = 7;
        a.payload_bytes = {0x01u, 0x02u, 0x03u};
        c.atoms.push_back(a);
        HandNode n;
        n.kind = 1;
        n.param_a = "0";
        n.length = "3";
        c.nodes.push_back(n);
        push_hand("seed-bigint-tag1-atom3", c, why);
    }
    {
        // bigint tag 2: Zero(2^64) with a 9-byte Region A.1.
        HandContainer c;
        c.total_length = pow2(64).to_decimal();
        HandNode n;
        n.kind = 2;
        n.param_a = pow2(64).to_decimal();
        n.length = pow2(64).to_decimal();
        c.nodes.push_back(n);
        push_hand("seed-bigint-tag2-region-a1", c, why);
    }
    {
        // bigint tag 2 in a *node parameter* (not only in the total length): a
        // Repeat whose quotient is 2^64.  The declared total is 2^64, so the
        // container also carries Region A.1; the parameter and the total-length
        // magnitude are two independent tag-2 sites, which is the point.
        HandContainer c;
        c.total_length = pow2(64).to_decimal();
        HandAtom a;
        a.klass = 3;
        a.payload_bytes = {0x11u};
        c.atoms.push_back(a);
        HandNode atom;
        atom.kind = 1;
        atom.param_a = "0";
        atom.length = "1";
        c.nodes.push_back(atom);
        HandNode rep;
        rep.kind = 4;
        rep.args = {0};
        rep.param_a = pow2(64).to_decimal();  // tag 2, u64-exceeding quotient
        rep.param_b = "0";
        rep.length = pow2(64).to_decimal();
        c.nodes.push_back(rep);
        push_hand("seed-bigint-tag2-param-repeat", c, why);
    }
    {
        // Every kind leaf at a small size, exercising the params.
        HandContainer c;
        c.total_length = "16";
        HandNode lfsr;
        lfsr.kind = 9;
        lfsr.lfsr_conn = 0xD800000000000000ull;
        lfsr.lfsr_init = 0x0123456789ABCDEFull;
        lfsr.param_a = "16";
        lfsr.length = "16";
        c.nodes.push_back(lfsr);
        push_hand("seed-lfsr-16", c, why);
    }
    {
        HandContainer c;
        c.total_length = "8";
        HandNode affine;
        affine.kind = 10;
        affine.affine_start = 3;
        affine.affine_step = 5;
        affine.param_a = "8";
        affine.length = "8";
        c.nodes.push_back(affine);
        push_hand("seed-affine-8", c, why);
    }
    {
        HandContainer c;
        c.total_length = "32";
        HandAtom a;
        a.klass = 2;
        a.payload_bytes = payload(16, 0x11);
        c.atoms.push_back(a);
        HandAtom b;
        b.klass = 3;
        b.payload_bytes = payload(16, 0x12);
        c.atoms.push_back(b);
        HandNode na;
        na.kind = 1;
        na.param_a = "0";
        na.length = "16";
        c.nodes.push_back(na);
        HandNode nb;
        nb.kind = 1;
        nb.param_a = "1";
        nb.length = "16";
        c.nodes.push_back(nb);
        // E2 W8: every child of an Interleave has the same length, a multiple of
        // the stride; E2 §4.7 C9 additionally requires argc >= 2.
        HandNode inter;
        inter.kind = 8;
        inter.args = {0, 1};
        inter.stride = 4;
        inter.length = "32";
        c.nodes.push_back(inter);
        push_hand("seed-interleave-stride4", c, why);
    }
    {
        HandContainer c;
        c.total_length = "8";
        HandAtom a;
        a.klass = 4;
        a.payload_bytes = payload(8, 0x22);
        c.atoms.push_back(a);
        HandNode atom;
        atom.kind = 1;
        atom.param_a = "0";
        atom.length = "8";
        c.nodes.push_back(atom);
        HandNode pred;
        pred.kind = 11;
        pred.args = {0};
        pred.predictor_id = 2;
        pred.predictor_param = 0;
        pred.length = "8";
        c.nodes.push_back(pred);
        push_hand("seed-predictor-2", c, why);
    }
    {
        HandContainer c;
        c.total_length = "8";
        HandAtom a;
        a.klass = 5;
        a.payload_bytes = payload(8, 0x33);
        c.atoms.push_back(a);
        HandNode atom;
        atom.kind = 1;
        atom.param_a = "0";
        atom.length = "8";
        c.nodes.push_back(atom);
        HandNode morph;
        morph.kind = 6;
        morph.args = {0};
        morph.morph = 6;
        morph.morph_k = 3;
        morph.length = "8";
        c.nodes.push_back(morph);
        push_hand("seed-morph-rotl3", c, why);
    }
    {
        HandContainer c;
        c.total_length = "12";
        HandAtom a;
        a.klass = 6;
        a.payload_bytes = payload(4, 0x44);
        c.atoms.push_back(a);
        HandNode na;
        na.kind = 1;
        na.param_a = "0";
        na.length = "4";
        c.nodes.push_back(na);
        // E2 §4.7 C3: adjacent atoms that would fit in one ATOM_MAX record must be
        // merged, so the second child is a derived node, not a second atom.
        HandNode zero;
        zero.kind = 2;
        zero.param_a = "4";
        zero.length = "4";
        c.nodes.push_back(zero);
        HandNode concat;
        concat.kind = 3;
        concat.args = {0, 1};
        concat.length = "8";
        c.nodes.push_back(concat);
        HandNode slice;
        slice.kind = 5;
        slice.args = {2};
        slice.param_a = "2";
        slice.param_b = "4";
        slice.length = "4";
        c.nodes.push_back(slice);
        // E2 W8.repeat requires q >= 1 => r < len(child): 2*4 + 2 = 10.
        HandNode rep;
        rep.kind = 4;
        rep.args = {3};
        rep.param_a = "2";
        rep.param_b = "2";
        rep.length = "10";
        c.nodes.push_back(rep);
        c.total_length = "10";
        push_hand("seed-repeat-slice-concat", c, why);
    }

    // ---------------- W-NONCANON (§4.10, §5.1, §13.3) --------------------
    // One container per violation.  Each starts from a real canonical wire and
    // applies exactly one documented mutation; outer CRCs are repaired unless the
    // case is about a CRC, so the rejection is attributed to the stage that owns
    // the mutated field.
    auto base_wire_of = [&corpus](const std::string& id, std::vector<u8>& out) {
        for (const CanonItem& item : corpus.canon) {
            if (item.id != id || item.expect_encode_limit) continue;
            WireLimits limits;
            limits.enforce_output_cap = !item.above_output_cap;
            auto encoded = encode(item.ir, limits);
            if (!encoded.ok()) return false;
            out = std::move(encoded.value());
            return true;
        }
        return false;
    };

    std::vector<u8> base;       // edge-atom-1: 1 atom, 1 node
    std::vector<u8> concat;     // edge-atom-max-plus-one: 2 atoms, 3 nodes
    std::vector<u8> indexed;    // edge-index-3x-atom-max: index present
    std::vector<u8> region_a1;  // big-total-2pow128
    const bool have_base = base_wire_of("edge-atom-1", base);
    const bool have_concat = base_wire_of("edge-atom-max-plus-one", concat);
    const bool have_indexed = base_wire_of("edge-index-3x-atom-max", indexed);
    const bool have_big = base_wire_of("big-total-2pow128", region_a1);

    auto add_case = [&corpus](std::string id, std::string violation, std::vector<u8> wire,
                              Stage stage, WireCode code, std::string note) {
        NonCanonItem item;
        item.id = std::move(id);
        item.violation = std::move(violation);
        item.wire = std::move(wire);
        item.stage = stage;
        item.code = code;
        item.note = std::move(note);
        corpus.noncanon.push_back(std::move(item));
    };

    // Locates the first node record of a wire (after the node_count uvarint).
    auto first_node_offset = [](const std::vector<u8>& wire, std::size_t& offset) {
        const u64 node_offset = load64_at(wire, kHdrOffNodeOffset);
        std::size_t pos = static_cast<std::size_t>(node_offset);
        u64 count = 0;
        if (!read_uvarint_at(wire, pos, count)) return false;
        offset = pos;
        return true;
    };
    auto first_atom_offset = [](const std::vector<u8>& wire, std::size_t& offset) {
        const u64 atom_offset = load64_at(wire, kHdrOffAtomOffset);
        std::size_t pos = static_cast<std::size_t>(atom_offset);
        u64 count = 0;
        if (!read_uvarint_at(wire, pos, count)) return false;
        offset = pos;
        return true;
    };

    if (have_base) {
        {   // §5.1 stage 1: source shorter than 96 bytes.
            std::vector<u8> w = base;
            w.resize(static_cast<std::size_t>(kWireMinContainerBytes) - 1u);
            add_case("noncanon-size-below-96", "§5.1 step 1 (source size)", std::move(w),
                     Stage::Size, WireCode::Invalid, "96-byte minimum");
        }
        {   // §5.1 stage 2: magic.
            std::vector<u8> w = base;
            w[0] ^= 0xFFu;
            repair_outer_crcs(w);
            add_case("noncanon-magic", "§4.2 magic", std::move(w), Stage::Header,
                     WireCode::Invalid, "bad header magic");
        }
        {   // §5.1 stage 2 / §5.2: future minor version is Unsupported.
            std::vector<u8> w = base;
            put16_at(w, kHdrOffVersionMinor, 1u);
            repair_outer_crcs(w);
            add_case("noncanon-version-minor-future", "§5.2 future minor version", std::move(w),
                     Stage::Header, WireCode::Unsupported, "v2.1");
        }
        {   // §5.1 stage 2: future major version.
            std::vector<u8> w = base;
            put16_at(w, kHdrOffVersionMajor, 3u);
            repair_outer_crcs(w);
            add_case("noncanon-version-major-future", "§5.2 future major version", std::move(w),
                     Stage::Header, WireCode::Unsupported, "v3.0");
        }
        {   // §5.2: a v1 container is Invalid in `decode`.
            std::vector<u8> w = base;
            put16_at(w, kHdrOffVersionMajor, 1u);
            put16_at(w, kHdrOffVersionMinor, 0u);
            repair_outer_crcs(w);
            add_case("noncanon-version-v1", "§5.2 v1 container in a v2 reader", std::move(w),
                     Stage::Header, WireCode::Invalid, "v1.0");
        }
        {   // §4.2 header_bytes.
            std::vector<u8> w = base;
            put16_at(w, kHdrOffHeaderBytes, 68u);
            repair_outer_crcs(w);
            add_case("noncanon-header-bytes", "§4.2 header_bytes", std::move(w), Stage::Header,
                     WireCode::Invalid, "header_bytes != 64");
        }
        {   // §4.3 reserved flag bit.
            std::vector<u8> w = base;
            const u32 flags = load32_at(w, kHdrOffFlags) | (1u << 5);
            put32_at(w, kHdrOffFlags, flags);
            repair_outer_crcs(w);
            add_case("noncanon-flags-reserved", "§4.3 reserved flag bit 5", std::move(w),
                     Stage::Header, WireCode::Invalid, "reserved bits MUST be 0");
        }
        {   // §4.3 bit 1 must be 1.
            std::vector<u8> w = base;
            put32_at(w, kHdrOffFlags, load32_at(w, kHdrOffFlags) & ~static_cast<u32>(kWireFlagCanonical));
            repair_outer_crcs(w);
            add_case("noncanon-flags-canonical-clear", "§4.3 bit 1 (canonical) MUST be 1",
                     std::move(w), Stage::Header, WireCode::Invalid, "bit 1 clear");
        }
        {   // §4.3 bit 3 must be 1.
            std::vector<u8> w = base;
            put32_at(w, kHdrOffFlags,
                     load32_at(w, kHdrOffFlags) & ~static_cast<u32>(kWireFlagByteAligned));
            repair_outer_crcs(w);
            add_case("noncanon-flags-byte-aligned-clear", "§4.3 bit 3 (byte-aligned) MUST be 1",
                     std::move(w), Stage::Header, WireCode::Invalid, "bit 3 clear");
        }
        {   // §5.1 step 3: trailer_offset out of bounds.
            std::vector<u8> w = base;
            put64_at(w, kHdrOffTrailerOffset, w.size());
            repair_outer_crcs(w);
            add_case("noncanon-trailer-bounds", "§5.1 step 3 (trailer_offset bounds)", std::move(w),
                     Stage::Bounds, WireCode::Invalid, "trailer_offset past the source");
        }
        {   // §5.1 step 4: file_crc32.
            std::vector<u8> w = base;
            w[kHdrOffFileCrc32] ^= 0x01u;
            add_case("noncanon-file-crc32", "§5.1 step 4 (file_crc32)", std::move(w),
                     Stage::HeaderCrc, WireCode::Invalid, "corrupted header CRC");
        }
        {   // §5.1 step 5: trailer magic.
            std::vector<u8> w = base;
            w[w.size() - static_cast<std::size_t>(kWireTrailerBytes)] ^= 0xFFu;
            repair_outer_crcs(w);
            add_case("noncanon-trailer-magic", "§4.8 trailer magic", std::move(w), Stage::Trailer,
                     WireCode::Invalid, "bad trailer magic");
        }
        {   // §5.1 step 5: trailer counts.
            std::vector<u8> w = base;
            put32_at(w, w.size() - static_cast<std::size_t>(kWireTrailerBytes) + kTrlOffAtomCount,
                     3u);
            repair_outer_crcs(w);
            add_case("noncanon-trailer-count-atoms", "§4.8 trailer atom_count", std::move(w),
                     Stage::Atoms, WireCode::Invalid,
                     "atom_count disagrees with the table (stage 7 owns the count)");
        }
        {   // §5.1 step 5: trailer_crc32.
            std::vector<u8> w = base;
            w[w.size() - 4u] ^= 0x01u;
            add_case("noncanon-trailer-crc32", "§4.8 trailer_crc32", std::move(w), Stage::Trailer,
                     WireCode::Invalid, "corrupted trailer CRC");
        }
        {   // §4.2 / §5.1 step 6: atom_offset must be 64 + total_length_big_len.
            std::vector<u8> w = base;
            put64_at(w, kHdrOffAtomOffset, 65u);
            repair_outer_crcs(w);
            add_case("noncanon-atom-offset", "§4.2 atom_offset", std::move(w), Stage::Regions,
                     WireCode::Invalid, "atom_offset != 64");
        }
        {   // §5.1 step 6: non-monotonic regions.
            std::vector<u8> w = base;
            put64_at(w, kHdrOffNodeOffset, 8u);
            repair_outer_crcs(w);
            add_case("noncanon-region-order", "§5.1 step 6 (region monotonicity)", std::move(w),
                     Stage::Regions, WireCode::Invalid, "node_offset inside the header");
        }
        {   // §4.7 index flag clear but index_offset nonzero.
            std::vector<u8> w = base;
            put64_at(w, kHdrOffIndexOffset, 100u);
            repair_outer_crcs(w);
            add_case("noncanon-index-offset-without-flag", "§4.7 index_offset vs flag", std::move(w),
                     Stage::Regions, WireCode::Invalid, "index present but flag clear");
        }
        {   // §4.9 overlong uvarint in the atom count.
            std::vector<u8> w = base;
            const std::size_t at = static_cast<std::size_t>(load64_at(w, kHdrOffAtomOffset));
            // 0x80 0x80 0x00 encodes 0 with two redundant continuation groups.
            w[at] = 0x80u;
            w.insert(w.begin() + static_cast<std::ptrdiff_t>(at + 1), 0x80u);
            w.insert(w.begin() + static_cast<std::ptrdiff_t>(at + 2), 0x00u);
            put64_at(w, kHdrOffNodeOffset, load64_at(w, kHdrOffNodeOffset) + 2u);
            put64_at(w, kHdrOffTrailerOffset, load64_at(w, kHdrOffTrailerOffset) + 2u);
            put64_at(w, w.size() - static_cast<std::size_t>(kWireTrailerBytes) + kTrlOffFileBytes,
                     w.size());
            repair_outer_crcs(w);
            add_case("noncanon-uvarint-overlong", "§4.9 redundant uvarint", std::move(w),
                     Stage::Atoms, WireCode::Invalid, "atom_count with a redundant zero group");
        }
        std::size_t atom_at = 0;
        if (first_atom_offset(base, atom_at)) {
            {   // §4.5 atom flags MUST be 0.
                std::vector<u8> w = base;
                w[atom_at + 1] = 0x01u;
                repair_outer_crcs(w);
                add_case("noncanon-atom-flags", "§4.5 atom flags MUST be 0", std::move(w),
                         Stage::Atoms, WireCode::Invalid, "atom flags byte nonzero");
            }
            {   // §4.5 atom length must be in [1, ATOM_MAX].
                std::vector<u8> w = base;
                w[atom_at + 4] = 0x00u;  // bigint tag 0 => length 0
                repair_outer_crcs(w);
                add_case("noncanon-atom-length-zero", "§4.5 atom length 1..ATOM_MAX", std::move(w),
                         Stage::Atoms, WireCode::Invalid, "atom length 0");
            }
            {   // §4.5 atom sha256 must match the payload.
                std::vector<u8> w = base;
                // klass(1) flags(1) reserved(2) bigint(2) => sha256 starts at +6.
                w[atom_at + 6u + 32u] ^= 0x01u;
                repair_outer_crcs(w);
                add_case("noncanon-atom-sha256", "§4.5 atom sha256 of the payload", std::move(w),
                         Stage::Atoms, WireCode::Invalid, "payload digest mismatch");
            }
            {   // §4.9 non-canonical bigint tag 1 with value 0.
                std::vector<u8> w = base;
                // tag 0x01 with v = 0 (2 bytes) replaced by 0x00 (1 byte) leaves a
                // stray byte; instead rewrite the tag to 0x02 with len 0, which is
                // a canonicality violation at the same stage.
                w[atom_at + 4] = 0x02u;
                repair_outer_crcs(w);
                add_case("noncanon-bigint-tag02-len0", "§4.9 bigint tag 0x02 with len 0",
                         std::move(w), Stage::Atoms, WireCode::Invalid,
                         "tag 0x02 must have len >= 9");
            }
        }
        std::size_t node_at = 0;
        if (first_node_offset(base, node_at)) {
            {   // §4.6 unknown kind.
                std::vector<u8> w = base;
                w[node_at] = 12u;
                repair_outer_crcs(w);
                add_case("noncanon-node-kind", "§4.6 kind domain 0..11", std::move(w),
                         Stage::Nodes, WireCode::Invalid, "kind 12");
            }
            {   // §4.6 node flags MUST be 0.
                std::vector<u8> w = base;
                w[node_at + 1] = 0x01u;
                repair_outer_crcs(w);
                add_case("noncanon-node-flags", "§4.6 node flags MUST be 0", std::move(w),
                         Stage::Nodes, WireCode::Invalid, "node flags byte nonzero");
            }
            {   // §4.6 argc for an Atom record.
                std::vector<u8> w = base;
                put16_at(w, node_at + 2u, 1u);
                repair_outer_crcs(w);
                add_case("noncanon-node-argc", "§4.6 argc per kind", std::move(w), Stage::Nodes,
                         WireCode::Invalid, "argc = 1 on an Atom record");
            }
        }
    }
    if (have_concat) {
        std::size_t node_at = 0;
        if (first_node_offset(concat, node_at)) {
            // §4.6 arg >= current record index (the first node's sole child is
            // itself).  Node 0 is an Atom in this base, so target node 2 (Concat).
            std::size_t pos = node_at;
            // Skip record 0: kind(1) flags(1) argc(2) params atom(1) length(1).
            pos += 1 + 1 + 2 + 1 + 1;
            // Skip record 1 the same way.
            pos += 1 + 1 + 2 + 1 + 1;
            if (pos + 4 < concat.size() && concat[pos] == static_cast<u8>(Kind::Concat)) {
                std::vector<u8> w = concat;
                // Concat args start at pos + 4; point the first arg at the record
                // itself (id 2), which violates `arg < id`.
                w[pos + 4] = 2u;
                repair_outer_crcs(w);
                add_case("noncanon-node-arg-forward", "§4.6 arg MUST be < current record index",
                         std::move(w), Stage::Nodes, WireCode::Invalid, "arg == current id");
            }
        }
        // §4.10 rule 3 / §4.5: two atom records with the same payload.  Built by
        // duplicating the second atom record's payload into the first.
        std::size_t atom_at = 0;
        if (first_atom_offset(concat, atom_at)) {
            std::vector<u8> w = concat;
            // Atom 1 is 1 byte; the payload sits at the very end of the atom table.
            const u64 node_offset = load64_at(w, kHdrOffNodeOffset);
            w[static_cast<std::size_t>(node_offset) - 1u] = w[atom_at + 6u + 32u];
            // Recompute the second atom's sha256 by rebuilding the wire instead:
            // the mutation above changes a payload without its digest, which stage
            // 7 already rejects.  Use the dedicated duplicate builder below.
            (void)w;
        }
    }
    if (have_indexed) {
        const u64 index_offset = load64_at(indexed, kHdrOffIndexOffset);
        const u64 trailer_offset = load64_at(indexed, kHdrOffTrailerOffset);
        if (index_offset != 0 && trailer_offset > index_offset + 8u) {
            {   // §4.7 index magic.
                std::vector<u8> w = indexed;
                w[static_cast<std::size_t>(index_offset)] ^= 0xFFu;
                repair_outer_crcs(w);
                add_case("noncanon-index-magic", "§4.7 index magic", std::move(w), Stage::Index,
                         WireCode::Invalid, "bad INDX2 magic");
            }
            {   // §4.7 index_crc32.
                std::vector<u8> w = indexed;
                w[static_cast<std::size_t>(trailer_offset) - 4u] ^= 0x01u;
                repair_outer_crcs(w);
                add_case("noncanon-index-crc32", "§4.7 index_crc32", std::move(w), Stage::Index,
                         WireCode::Invalid, "corrupted index CRC");
            }
            {   // §5.1 step 11: a prefix CRC that disagrees with the denotation.
                std::vector<u8> w = indexed;
                const std::size_t last_crc_field =
                    static_cast<std::size_t>(trailer_offset) - 4u - 4u;
                w[last_crc_field] ^= 0x01u;
                // Recompute index_crc32 so the container stays structurally intact:
                // only the stated prefix value is wrong.
                const u32 icrc = mapr::crc32(std::string_view(
                    reinterpret_cast<const char*>(w.data() + static_cast<std::size_t>(index_offset)),
                    static_cast<std::size_t>(trailer_offset) - 4u -
                        static_cast<std::size_t>(index_offset)));
                put32_at(w, static_cast<std::size_t>(trailer_offset) - 4u, icrc);
                repair_outer_crcs(w);
                add_case("noncanon-index-prefix-crc32", "§5.1 step 11 (index prefix CRC)",
                         std::move(w), Stage::Eval, WireCode::Invalid,
                         "crc32_of_prefix disagrees with the denotation");
            }
            {   // §4.7 an empty index region is non-canonical: clear the flag and
                // drop the region by moving trailer_offset onto index_offset.
                std::vector<u8> w = indexed;
                put64_at(w, kHdrOffTrailerOffset, index_offset);
                put64_at(w, kHdrOffIndexOffset, 0u);
                put32_at(w, kHdrOffFlags,
                         load32_at(w, kHdrOffFlags) & ~static_cast<u32>(kWireFlagIndexPresent));
                w.resize(static_cast<std::size_t>(index_offset) +
                         static_cast<std::size_t>(kWireTrailerBytes));
                put64_at(w, w.size() - static_cast<std::size_t>(kWireTrailerBytes) + kTrlOffFileBytes,
                         w.size());
                repair_outer_crcs(w);
                add_case("noncanon-index-flag-cleared-with-region",
                         "§4.7 the index region is not reachable from the trailer", std::move(w),
                         Stage::Trailer, WireCode::Invalid,
                         "trailer_offset was moved, so the trailer no longer matches");
            }
        }
    }
    if (have_big) {
        // §4.4 "fits u64" flag on a container that carries Region A.1.
        {
            std::vector<u8> w = region_a1;
            put32_at(w, kHdrOffFlags, load32_at(w, kHdrOffFlags) | kWireFlagU64Lengths);
            repair_outer_crcs(w);
            add_case("noncanon-length-form-flag", "§4.3 bit 2 vs §4.4 big form", std::move(w),
                     Stage::Regions, WireCode::Invalid, "u64 flag set with a big length");
        }
        {   // §4.4 both forms present.
            std::vector<u8> w = region_a1;
            put64_at(w, kHdrOffTotalLengthU64, 1u);
            repair_outer_crcs(w);
            add_case("noncanon-length-form-both", "§4.4 both total-length forms", std::move(w),
                     Stage::Regions, WireCode::Invalid, "total_length_u64 nonzero with big_len");
        }
        {   // §4.4 leading zero magnitude byte.
            std::vector<u8> w = region_a1;
            const std::size_t magnitude_len = load16_at(w, kHdrOffTotalLengthBigLen);
            if (magnitude_len >= 2u) {
                w[static_cast<std::size_t>(kWireHeaderBytes) + magnitude_len - 1u] = 0u;
                repair_outer_crcs(w);
                add_case("noncanon-length-form-leading-zero", "§4.4 leading zero magnitude",
                         std::move(w), Stage::Regions, WireCode::Invalid,
                         "top magnitude byte zero");
            }
        }
        {   // §4.4 big_len = 0 with no u64 length: neither form present.
            std::vector<u8> w = region_a1;
            put16_at(w, kHdrOffTotalLengthBigLen, 0u);
            put64_at(w, kHdrOffAtomOffset, static_cast<u64>(kWireHeaderBytes));
            repair_outer_crcs(w);
            add_case("noncanon-length-form-absent", "§4.4 neither total-length form",
                     std::move(w), Stage::Regions, WireCode::Invalid,
                     "declared total is implied but not recorded");
        }
    }
    // §4.5 duplicate atom payload: built directly so the digest is consistent.
    {
        HandContainer c;
        c.total_length = "2";
        HandAtom a;
        a.klass = 1;
        a.payload_bytes = {0xAAu};
        HandAtom b;
        b.klass = 2;
        b.payload_bytes = {0xAAu};  // same payload, second record
        c.atoms.push_back(a);
        c.atoms.push_back(b);
        HandNode n0;
        n0.kind = 1;
        n0.param_a = "0";
        n0.length = "1";
        c.nodes.push_back(n0);
        HandNode n1;
        n1.kind = 1;
        n1.param_a = "1";
        n1.length = "1";
        c.nodes.push_back(n1);
        HandNode cat;
        cat.kind = 3;
        cat.args = {0, 1};
        cat.length = "2";
        c.nodes.push_back(cat);
        std::string reason;
        std::vector<u8> w = assemble_container(c, reason);
        if (!w.empty()) {
            add_case("noncanon-atom-duplicate-payload", "§4.5 duplicate payload MUST NOT appear",
                     std::move(w), Stage::Atoms, WireCode::Invalid, "two records, one payload");
        }
    }
    // §4.10 rule 4 / §4.5: an unused atom record.
    {
        HandContainer c;
        c.total_length = "1";
        HandAtom a;
        a.klass = 1;
        a.payload_bytes = {0x01u};
        HandAtom b;
        b.klass = 2;
        b.payload_bytes = {0x02u};  // never referenced
        c.atoms.push_back(a);
        c.atoms.push_back(b);
        HandNode n;
        n.kind = 1;
        n.param_a = "0";
        n.length = "1";
        c.nodes.push_back(n);
        std::string reason;
        std::vector<u8> w = assemble_container(c, reason);
        if (!w.empty()) {
            add_case("noncanon-atom-unused", "§4.10 rule 3 / §4.5 every atom MUST be referenced",
                     std::move(w), Stage::Nodes, WireCode::Invalid,
                     "unreferenced atom record (detected by the cross-reference check)");
        }
    }
    // §4.5 wrong atom order: two atoms referenced in the opposite order.
    {
        HandContainer c;
        c.total_length = "2";
        HandAtom a;
        a.klass = 1;
        a.payload_bytes = {0x11u};
        HandAtom b;
        b.klass = 2;
        b.payload_bytes = {0x22u};
        c.atoms.push_back(a);
        c.atoms.push_back(b);
        HandNode n0;
        n0.kind = 1;
        n0.param_a = "1";  // first use is atom 1, not atom 0
        n0.length = "1";
        c.nodes.push_back(n0);
        HandNode n1;
        n1.kind = 1;
        n1.param_a = "0";
        n1.length = "1";
        c.nodes.push_back(n1);
        HandNode cat;
        cat.kind = 3;
        cat.args = {0, 1};
        cat.length = "2";
        c.nodes.push_back(cat);
        std::string reason;
        std::vector<u8> w = assemble_container(c, reason);
        if (!w.empty()) {
            add_case("noncanon-atom-order", "§4.5 first-use order", std::move(w), Stage::Nodes,
                     WireCode::Invalid, "atom 1 used before atom 0 (cross-reference check)");
        }
    }
    // §4.6 unused node record.
    {
        HandContainer c;
        c.total_length = "1";
        HandAtom a;
        a.klass = 1;
        a.payload_bytes = {0x31u};
        c.atoms.push_back(a);
        HandNode leaf;
        leaf.kind = 2;
        leaf.param_a = "1";
        leaf.length = "1";
        c.nodes.push_back(leaf);
        HandNode unused;
        unused.kind = 2;
        unused.param_a = "1";
        unused.length = "1";
        c.nodes.push_back(unused);
        HandNode root_node;
        root_node.kind = 3;
        root_node.args = {0};
        root_node.length = "1";
        c.nodes.push_back(root_node);
        std::string reason;
        std::vector<u8> w = assemble_container(c, reason);
        if (!w.empty()) {
            add_case("noncanon-node-unused", "§4.10 rule 4 (no unused record)", std::move(w),
                     Stage::Nodes, WireCode::Invalid, "node 1 is unreachable");
        }
    }
    // §4.6 root not last.
    {
        HandContainer c;
        c.total_length = "1";
        HandNode leaf;
        leaf.kind = 2;
        leaf.param_a = "1";
        leaf.length = "1";
        c.nodes.push_back(leaf);
        HandNode extra;
        extra.kind = 2;
        extra.param_a = "2";
        extra.length = "2";
        c.nodes.push_back(extra);
        std::string reason;
        std::vector<u8> w = assemble_container(c, reason);
        if (!w.empty()) {
            // root_id is nodes.size()-1 == 1 (the second record), so the wire is
            // canonical as written; instead inflate the trailer's record count so
            // the stated root is not the last record.
            put32_at(w, w.size() - static_cast<std::size_t>(kWireTrailerBytes) + kTrlOffNodeCount, 3u);
            repair_outer_crcs(w);
            add_case("noncanon-root-not-last", "§4.6 root is the last record", std::move(w),
                     Stage::Trailer, WireCode::Invalid,
                     "node_count 3 with two records (trailer stage owns the count)");
        }
    }
    // §4.6 length-field mismatch.
    {
        HandContainer c;
        c.total_length = "4";
        HandNode leaf;
        leaf.kind = 2;
        leaf.param_a = "4";
        leaf.length = "5";  // disagrees with Zero(4)
        c.nodes.push_back(leaf);
        std::string reason;
        std::vector<u8> w = assemble_container(c, reason);
        if (!w.empty()) {
            add_case("noncanon-length-field", "§4.6 length MUST equal §3.7 recomputation",
                     std::move(w), Stage::Nodes, WireCode::Invalid, "Zero(4) with length 5");
        }
    }
    // §4.6 morph k out of range.
    {
        HandContainer c;
        c.total_length = "1";
        HandAtom a;
        a.klass = 1;
        a.payload_bytes = {0x41u};
        c.atoms.push_back(a);
        HandNode atom;
        atom.kind = 1;
        atom.param_a = "0";
        atom.length = "1";
        c.nodes.push_back(atom);
        HandNode morph;
        morph.kind = 6;
        morph.args = {0};
        morph.morph = 6;      // Rotl8 requires 1 <= k <= 7
        morph.morph_k = 8;    // out of range
        morph.length = "1";
        c.nodes.push_back(morph);
        std::string reason;
        std::vector<u8> w = assemble_container(c, reason);
        if (!w.empty()) {
            add_case("noncanon-morph-k", "§4.6 / E2 W8.morph k range", std::move(w), Stage::Nodes,
                     WireCode::Invalid, "Rotl8 with k = 8");
        }
    }
    // §4.6 predictor param.
    {
        HandContainer c;
        c.total_length = "8";
        HandAtom a;
        a.klass = 1;
        a.payload_bytes = payload(8, 0x51);
        c.atoms.push_back(a);
        HandNode atom;
        atom.kind = 1;
        atom.param_a = "0";
        atom.length = "8";
        c.nodes.push_back(atom);
        // E2 §4.11: pid must be in the closed catalogue and pid >= 3 needs
        // param >= 1.  pid 3 with param 0 violates the parameter rule exactly.
        HandNode pred;
        pred.kind = 11;
        pred.args = {0};
        pred.predictor_id = 3;      // STRIDE_XOR
        pred.predictor_param = 0;   // violates param >= 1
        pred.length = "8";
        c.nodes.push_back(pred);
        std::string reason;
        std::vector<u8> w = assemble_container(c, reason);
        if (!w.empty()) {
            add_case("noncanon-predictor-param", "§4.6 / E2 W8.predictor", std::move(w),
                     Stage::Nodes, WireCode::Invalid, "pid 3 (STRIDE_XOR) with param 0");
        }
    }
    // §4.6 Lfsr conn = 0.
    {
        HandContainer c;
        c.total_length = "8";
        HandNode lfsr;
        lfsr.kind = 9;
        lfsr.lfsr_conn = 0;  // rejected by E2 W8.lfsr
        lfsr.lfsr_init = 1;
        lfsr.param_a = "8";
        lfsr.length = "8";
        c.nodes.push_back(lfsr);
        std::string reason;
        std::vector<u8> w = assemble_container(c, reason);
        if (!w.empty()) {
            add_case("noncanon-lfsr-conn-zero", "§4.6 / E2 W8.lfsr conn != 0", std::move(w),
                     Stage::Nodes, WireCode::Invalid, "Lfsr conn = 0");
        }
    }
    // §4.6 Slice bounds: start + len > child length.
    {
        HandContainer c;
        c.total_length = "8";
        HandNode zero;
        zero.kind = 2;
        zero.param_a = "8";
        zero.length = "8";
        c.nodes.push_back(zero);
        HandNode slice;
        slice.kind = 5;
        slice.args = {0};
        slice.param_a = "4";
        slice.param_b = "8";  // 4 + 8 > 8
        slice.length = "8";
        c.nodes.push_back(slice);
        std::string reason;
        std::vector<u8> w = assemble_container(c, reason);
        if (!w.empty()) {
            add_case("noncanon-slice-bounds", "§4.6 / E2 W8.slice bounds", std::move(w),
                     Stage::Nodes, WireCode::Invalid, "Slice(Zero(8), 4, 8)");
        }
    }
    // §4.9: a bigint whose uvarint is not the shortest encoding of its value.
    {
        HandContainer c;
        c.total_length = "1";
        HandNode zero;
        zero.kind = 2;
        zero.param_a = "1";
        zero.raw_length = {0x01u, 0x81u, 0x00u};  // tag 1, then 1 as 0x81 0x00
        zero.length = "1";
        c.nodes.push_back(zero);
        std::string reason;
        std::vector<u8> w = assemble_container(c, reason);
        if (!w.empty()) {
            add_case("noncanon-bigint-overlong-uvarint",
                     "§4.9 tag 0x01 with a redundant uvarint group", std::move(w),
                     Stage::Nodes, WireCode::Invalid, "0x81 0x00 is not the shortest form of 1");
        }
    }
    // §4.9: tag 0x02 on a value that fits u64 (so it must have been tag 0x01).
    {
        HandContainer c;
        c.total_length = "1";
        HandNode zero;
        zero.kind = 2;
        zero.param_a = "1";
        zero.raw_length = {0x02u, 0x08u, 0x00u, 0x00u, 0x00u,
                           0x00u, 0x00u, 0x00u, 0x00u, 0x01u};
        zero.length = "1";
        c.nodes.push_back(zero);
        std::string reason;
        std::vector<u8> w = assemble_container(c, reason);
        if (!w.empty()) {
            add_case("noncanon-bigint-tag02-below-u64", "§4.9 tag 0x02 below 2^64",
                     std::move(w), Stage::Nodes, WireCode::Invalid,
                     "a 9-byte magnitude for the value 1");
        }
    }
    // §4.9: tag 0x02 with a magnitude shorter than the 9 bytes §4.9 requires.
    {
        HandContainer c;
        c.total_length = "1";
        HandNode zero;
        zero.kind = 2;
        zero.param_a = "1";
        zero.raw_length = {0x02u, 0x01u, 0x01u};  // tag 2, len 1, magnitude 1
        zero.length = "1";
        c.nodes.push_back(zero);
        std::string reason;
        std::vector<u8> w = assemble_container(c, reason);
        if (!w.empty()) {
            add_case("noncanon-bigint-tag02-short", "§4.9 tag 0x02 requires len >= 9",
                     std::move(w), Stage::Nodes, WireCode::Invalid, "tag 2 with len 1");
        }
    }
    // §4.9: tag 0x01 carrying the value zero, which must be tag 0x00.
    {
        HandContainer c;
        c.total_length = "1";
        HandNode zero;
        zero.kind = 2;
        zero.param_a = "1";
        zero.raw_length = {0x01u, 0x00u};  // tag 1 with v = 0
        zero.length = "1";
        c.nodes.push_back(zero);
        std::string reason;
        std::vector<u8> w = assemble_container(c, reason);
        if (!w.empty()) {
            add_case("noncanon-bigint-tag01-zero", "§4.9 tag 0x01 v = 0 must be tag 0x00",
                     std::move(w), Stage::Nodes, WireCode::Invalid, "tag 1 with v = 0");
        }
    }
    // §5.1 step 11: the declared total length disagrees with the denotation.
    {
        HandContainer c;
        c.total_length = "4";
        HandNode zero;
        zero.kind = 2;
        zero.param_a = "5";
        zero.length = "5";
        c.nodes.push_back(zero);
        std::string reason;
        std::vector<u8> w = assemble_container(c, reason);
        if (!w.empty()) {
            // Rewrite total_length to 4 while Zero(5) still denotes 5 bytes: node 0's
            // stored length equals its recomputation, so the first disagreement is
            // the declared total.
            put64_at(w, kHdrOffTotalLengthU64, 4u);
            repair_outer_crcs(w);
            add_case("noncanon-total-length-mismatch", "§5.1 step 11 (declared length)",
                     std::move(w), Stage::Nodes, WireCode::Invalid,
                     "total_length 4 with a 5-byte denotation (root-length check)");
        }
    }
    // §5.2: a declared limit exceeded is Limit, not Invalid.
    if (have_base) {
        // Covered in the gate (it needs a modified WireLimits), not here; the
        // corpus keeps only wire-level violations so every entry is a container.
    }

    // ---------------- W-V1: the pinned legacy corpus ----------------------
    {
        const std::string dir = root + "/specs_and_reports/v2/W-V1";
        // manifest.tsv: <name>\t<sha256>\t<output_sha256>  (the output digest is
        // optional; C08's own gate reads the same file with a 2-column form).
        std::map<std::string, std::pair<std::string, std::string>> manifest;
        {
            std::ifstream in(dir + "/manifest.tsv", std::ios::binary);
            std::string line;
            while (std::getline(in, line)) {
                if (line.empty() || line[0] == '#') continue;
                std::vector<std::string> cols;
                std::size_t start = 0;
                for (;;) {
                    const std::size_t tab = line.find('\t', start);
                    cols.push_back(line.substr(start, tab == std::string::npos
                                                          ? std::string::npos
                                                          : tab - start));
                    if (tab == std::string::npos) break;
                    start = tab + 1;
                }
                if (cols.size() >= 2) {
                    manifest[cols[0]] = {cols[1], cols.size() >= 3 ? cols[2] : std::string{}};
                }
            }
        }
        // Enumerate *.mapr fixtures in name order.
        std::vector<std::string> names;
        {
            std::error_code ec;
            std::filesystem::directory_iterator it(dir, ec);
            if (!ec) {
                for (const auto& entry : it) {
                    if (!entry.is_regular_file()) continue;
                    if (entry.path().extension() != ".mapr") continue;
                    names.push_back(entry.path().filename().string());
                }
            }
            std::sort(names.begin(), names.end());
        }
        for (const std::string& name : names) {
            V1Fixture fixture;
            fixture.name = name;
            if (!read_file_bytes(dir + "/" + name, fixture.bytes)) continue;
            fixture.sha256_actual = sha_of_bytes(fixture.bytes);
            const auto found = manifest.find(name);
            if (found != manifest.end()) {
                fixture.recorded_sha256 = found->second.first;
                fixture.expected_sha256 = found->second.second;
                fixture.hash_matches = fixture.recorded_sha256 == fixture.sha256_actual;
            }
            corpus.v1.push_back(std::move(fixture));
        }
    }

    // ---------------- W-FUZZ: eight small valid seeds ---------------------
    // §13.3: empty, 1, 2, 16, 256, 4096, 65536 bytes plus the header/trailer/
    // index fields of a large virtual container.
    for (const std::size_t size : {std::size_t{0}, std::size_t{1}, std::size_t{2},
                                   std::size_t{16}, std::size_t{256}, std::size_t{4096},
                                   std::size_t{65536}}) {
        HandContainer c;
        if (size == 0) {
            c.total_length = "0";
            HandNode n;
            n.kind = 0;
            n.length = "0";
            c.nodes.push_back(n);
        } else {
            c.total_length = std::to_string(size);
            HandAtom a;
            a.klass = 1;
            a.payload_bytes = payload(size, 0x60);
            c.atoms.push_back(a);
            HandNode n;
            n.kind = 1;
            n.param_a = "0";
            n.length = std::to_string(size);
            c.nodes.push_back(n);
        }
        std::string reason;
        std::vector<u8> wire = assemble_container(c, reason);
        if (!wire.empty()) {
            corpus.fuzz_seeds.push_back(std::move(wire));
            corpus.fuzz_seed_ids.push_back("fuzz-atom-" + std::to_string(size));
        }
    }
    // The large virtual container: a declared length of 2^40 with a 1 MiB atom
    // repeated, so header, atom table, node table and trailer are all present
    // while the denotation is never materialised.
    {
        HandContainer c;
        c.total_length = pow2(40).to_decimal();
        HandAtom a;
        a.klass = 1;
        a.payload_bytes = payload(static_cast<std::size_t>(1u << 20), 0x63);
        c.atoms.push_back(a);
        HandNode atom;
        atom.kind = 1;
        atom.param_a = "0";
        atom.length = std::to_string(kAtomMax);
        c.nodes.push_back(atom);
        HandNode rep;
        rep.kind = 4;
        rep.args = {0};
        rep.param_a = pow2(20).to_decimal();  // 2^20 * 2^20 = 2^40
        rep.param_b = "0";
        rep.length = pow2(40).to_decimal();
        c.nodes.push_back(rep);
        std::string reason;
        std::vector<u8> wire = assemble_container(c, reason);
        if (!wire.empty()) {
            corpus.fuzz_seeds.push_back(std::move(wire));
            corpus.fuzz_seed_ids.push_back("fuzz-virtual-2pow40");
        }
    }
    // ---- the limit boundary, derived once from C07's own constants ----------
    //
    // Two independent limits can stop §13.4's steps 2–4 for a term that *is* a
    // canonical wire: the §8.3 output cap on the declared length, and stage 11's
    // evaluation work bound.  Both are policy, not format, so a term beyond either
    // is still round-tripped — with the bound lifted — and the default-limits
    // outcome is recorded as its own row.  Deriving the flag here (instead of
    // hand-marking items) keeps the corpus and the gate consistent by construction.
    const BigInt work_bound(kC07DefaultMaxEvalBytes);
    for (CanonItem& item : corpus.canon) {
        if (item.expect_encode_limit) continue;
        if (item.ir.total_length.compare(work_bound) > 0) item.needs_limit_lift = true;
        if (item.ir.total_length.compare(marp::v2::max_output_bytes()) > 0) {
            item.above_output_cap = true;
            item.needs_limit_lift = true;
        }
    }
    return corpus;
}

}  // namespace e3g
