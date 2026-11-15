// MARP v2 — C07 WIRE — corpus construction.
//
// Every term is canonical by construction and is re-validated by E2's
// `check_canonical` before it enters the corpus, so a corpus defect shows up as
// a harness failure rather than as a false PASS.

#include "c07_corpus.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "mapr/e1_sha256.hpp"
#include "mapr/e2/e2_canon.hpp"
#include "mapr/e2/e2_dag.hpp"

namespace c07 {
namespace {

using namespace marp::v2;

constexpr std::size_t kAtomMax = static_cast<std::size_t>(kWireAtomMax);

std::shared_ptr<std::vector<std::vector<u8>>> make_owner() {
    return std::make_shared<std::vector<std::vector<u8>>>();
}

// `Atom::sha256` is part of the record C07 writes, so a hand-built Ir must fill
// it exactly as `Dag::add_atom` does.  C07 will *reject* a stale hash rather than
// silently recompute it (encode never normalises), so this helper is the corpus'
// one place that computes it.
std::array<u8, 32> payload_sha(std::span<const u8> bytes) {
    auto digest = mapr::Sha256::hash(std::string_view(
        reinterpret_cast<const char*>(bytes.data()), bytes.size()));
    std::array<u8, 32> out{};
    if (digest.ok()) std::memcpy(out.data(), digest.value().data(), out.size());
    return out;
}

// A finished `Ir` created through E2's `Dag` builder.
bool finish_dag(Dag& dag, u32 root, Ir& out, std::string& why) {
    auto finished = std::move(dag).finish(root);
    if (!finished.ok()) {
        why = "Dag::finish returned ";
        why += code_name(finished.code());
        return false;
    }
    out = std::move(finished.value());
    return true;
}

// A directly constructed `Ir` (bypasses `Dag::finish`'s output cap) that E2 still
// certifies as canonical under `enforce_output_cap = false`.
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
    auto owner = make_owner();
    owner->push_back(payload(atom_bytes, seed));
    Ir ir;
    Atom atom;
    atom.klass = 9;
    atom.length = BigInt(static_cast<u64>(atom_bytes));
    atom.payload = std::span<const u8>(owner->back().data(), owner->back().size());
    atom.owner = owner;
    atom.sha256 = payload_sha(atom.payload);
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
// Corpus
// ---------------------------------------------------------------------------

std::vector<CorpusItem> build_corpus() {
    std::vector<CorpusItem> items;
    std::string why;

    auto push = [&items](std::string id, std::string group, Ir ir, bool above_cap,
                         std::string note) {
        CorpusItem item;
        item.id = std::move(id);
        item.group = std::move(group);
        item.ir = std::move(ir);
        item.above_output_cap = above_cap;
        item.note = std::move(note);
        items.push_back(std::move(item));
    };

    // --- Empty and the smallest atoms --------------------------------------
    {
        Dag dag;
        auto id = dag.add_node(Node{});
        Ir ir;
        if (finish_dag(dag, id.value(), ir, why)) {
            push("empty", "W-CANON", std::move(ir), false, "Empty, length 0");
        }
    }
    for (const std::size_t size : {1u, 2u, 3u, 16u, 255u, 256u, 4096u}) {
        Dag dag;
        const std::vector<u8> bytes = payload(size, static_cast<u8>(size));
        auto atom_id = dag.add_atom(std::span<const u8>(bytes.data(), bytes.size()),
                                    static_cast<u8>(size & 0x7Fu));
        Node node;
        node.kind = Kind::Atom;
        node.a = BigInt(atom_id.value());
        auto id = dag.add_node(std::move(node));
        Ir ir;
        if (finish_dag(dag, id.value(), ir, why)) {
            push("atom-" + std::to_string(size), "W-CANON", std::move(ir), false,
                 "single Atom, klass = size & 0x7f");
        }
    }

    // --- Atom exactly ATOM_MAX (the format boundary) -----------------------
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
            push("atom-atom_max", "W-EDGE", std::move(ir), false,
                 "atom length == ATOM_MAX (1 MiB)");
        }
    }
    // --- ATOM_MAX + 1 split into two atoms ---------------------------------
    {
        Dag dag;
        const std::vector<u8> bytes = payload(kAtomMax + 1, 0x5B);
        auto first = dag.add_atom(std::span<const u8>(bytes.data(), kAtomMax), 11);
        auto second = dag.add_atom(
            std::span<const u8>(bytes.data() + kAtomMax, 1), 12);
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
            push("atom-atom_max_plus_one", "W-EDGE", std::move(ir), false,
                 "ATOM_MAX + 1 split into two atom records");
        }
    }

    // --- Zero at several sizes --------------------------------------------
    for (const u64 n : {0ull, 1ull, 2ull, 255ull, 256ull, 65535ull, 65536ull, 1ull << 20}) {
        Dag dag;
        Node node;
        node.kind = Kind::Zero;
        node.a = BigInt(n);
        auto id = dag.add_node(std::move(node));
        Ir ir;
        if (finish_dag(dag, id.value(), ir, why)) {
            push("zero-" + std::to_string(n), "W-CANON", std::move(ir), false,
                 "Zero(n)");
        }
    }

    // --- Affine ------------------------------------------------------------
    for (const u8 step : {u8{1}, u8{7}, u8{255}}) {
        Dag dag;
        Node node;
        node.kind = Kind::Affine;
        node.affine_start = static_cast<u8>(step * 3u);
        node.affine_step = step;
        node.a = BigInt(1024u);
        auto id = dag.add_node(std::move(node));
        Ir ir;
        if (finish_dag(dag, id.value(), ir, why)) {
            push("affine-" + std::to_string(step), "W-CANON", std::move(ir), false,
                 "Affine(start, step != 0, 1024)");
        }
    }

    // --- LFSR (all with conn != 0) ----------------------------------------
    for (const u64 conn : {1ull, 0x8000000000000000ull, 0x8000000000000001ull,
                           0xD800000000000000ull}) {
        Dag dag;
        Node node;
        node.kind = Kind::Lfsr;
        node.lfsr_conn = conn;
        node.lfsr_init = 0x0123456789ABCDEFull;
        node.a = BigInt(512u);
        auto id = dag.add_node(std::move(node));
        Ir ir;
        if (finish_dag(dag, id.value(), ir, why)) {
            char name[48];
            std::snprintf(name, sizeof(name), "lfsr-%016llx",
                          static_cast<unsigned long long>(conn));
            push(name, "W-CANON", std::move(ir), false, "Lfsr(conn, init, 512)");
        }
    }

    // --- Morphs: every id in the closed catalogue --------------------------
    struct MorphCase {
        u8 morph;
        u8 k;
        std::size_t length;
    };
    const MorphCase morph_cases[] = {
        {1, 0, 64}, {2, 0, 64}, {3, 0, 64}, {4, 0, 64}, {5, 0, 64},
        {6, 1, 64}, {6, 3, 64}, {6, 7, 64}, {7, 1, 64}, {7, 5, 64},
        {8, 0, 64}, {9, 0, 64},
    };
    for (const MorphCase& c : morph_cases) {
        Dag dag;
        const std::vector<u8> bytes = payload(c.length, static_cast<u8>(c.morph));
        auto atom_id = dag.add_atom(std::span<const u8>(bytes.data(), bytes.size()), 0);
        Node atom;
        atom.kind = Kind::Atom;
        atom.a = BigInt(atom_id.value());
        auto ai = dag.add_node(std::move(atom));
        Node morph;
        morph.kind = Kind::Morph;
        morph.args = {ai.value()};
        morph.morph = c.morph;
        morph.morph_k = c.k;
        auto id = dag.add_node(std::move(morph));
        Ir ir;
        if (finish_dag(dag, id.value(), ir, why)) {
            char name[48];
            std::snprintf(name, sizeof(name), "morph-%u-k%u", unsigned{c.morph},
                          unsigned{c.k});
            push(name, "W-CANON", std::move(ir), false, "Morph over a 64-byte Atom");
        }
    }

    // --- Predictors: every id 0..4 ---------------------------------------
    for (const u32 pid : {0u, 1u, 2u, 3u, 4u}) {
        for (const u32 param : {0u, 1u, 3u}) {
            if (pid >= 3u && param == 0u) continue;
            if (pid < 3u && param != 0u) continue;
            Dag dag;
            const std::vector<u8> bytes = payload(48, static_cast<u8>(pid + 1u));
            auto atom_id = dag.add_atom(std::span<const u8>(bytes.data(), bytes.size()), 0);
            Node atom;
            atom.kind = Kind::Atom;
            atom.a = BigInt(atom_id.value());
            auto ai = dag.add_node(std::move(atom));
            Node pred;
            pred.kind = Kind::Predictor;
            pred.args = {ai.value()};
            pred.predictor_id = static_cast<u8>(pid);
            pred.predictor_param = param;
            auto id = dag.add_node(std::move(pred));
            Ir ir;
            if (finish_dag(dag, id.value(), ir, why)) {
                push("predictor-" + std::to_string(pid) + "-" + std::to_string(param),
                     "W-CANON", std::move(ir), false, "Predictor(pid, param, residual)");
            }
        }
    }

    // --- Slice / Repeat / Xor / Interleave / Concat ------------------------
    {
        Dag dag;
        const std::vector<u8> bytes = payload(1024, 0x77);
        auto atom_id = dag.add_atom(std::span<const u8>(bytes.data(), bytes.size()), 4);
        Node atom;
        atom.kind = Kind::Atom;
        atom.a = BigInt(atom_id.value());
        auto ai = dag.add_node(std::move(atom));
        Node slice;
        slice.kind = Kind::Slice;
        slice.args = {ai.value()};
        slice.a = BigInt(100u);
        slice.b = BigInt(500u);
        auto id = dag.add_node(std::move(slice));
        Ir ir;
        if (finish_dag(dag, id.value(), ir, why)) {
            push("slice-mid", "W-CANON", std::move(ir), false, "Slice(atom, 100, 500)");
        }
    }
    {
        Dag dag;
        const std::vector<u8> bytes = payload(64, 0x21);
        auto atom_id = dag.add_atom(std::span<const u8>(bytes.data(), bytes.size()), 4);
        Node atom;
        atom.kind = Kind::Atom;
        atom.a = BigInt(atom_id.value());
        auto ai = dag.add_node(std::move(atom));
        Node slice;
        slice.kind = Kind::Slice;
        slice.args = {ai.value()};
        slice.a = BigInt(0u);
        slice.b = BigInt(32u);
        auto id = dag.add_node(std::move(slice));
        Ir ir;
        if (finish_dag(dag, id.value(), ir, why)) {
            push("slice-from-zero", "W-CANON", std::move(ir), false,
                 "Slice(atom, 0, 32): the canonical Repeat remainder shape");
        }
    }
    {
        Dag dag;
        const std::vector<u8> bytes = payload(64, 0x31);
        auto atom_id = dag.add_atom(std::span<const u8>(bytes.data(), bytes.size()), 4);
        Node atom;
        atom.kind = Kind::Atom;
        atom.a = BigInt(atom_id.value());
        auto ai = dag.add_node(std::move(atom));
        Node repeat;
        repeat.kind = Kind::Repeat;
        repeat.args = {ai.value()};
        repeat.a = BigInt(3u);
        repeat.b = BigInt(9u);
        auto id = dag.add_node(std::move(repeat));
        Ir ir;
        if (finish_dag(dag, id.value(), ir, why)) {
            push("repeat-q3-r9", "W-CANON", std::move(ir), false, "Repeat(atom, 3, 9)");
        }
    }
    {
        // Two distinct atoms XORed with distinct payloads (Xor(x,x) is folded by
        // E2 C8).  700 KiB each keeps every per-child shape out of C3's reach.
        Dag dag;
        const std::vector<u8> a_bytes = payload(700u * 1024u, 0x41);
        const std::vector<u8> b_bytes = payload(700u * 1024u, 0x42);
        auto a_id = dag.add_atom(std::span<const u8>(a_bytes.data(), a_bytes.size()), 1);
        auto b_id = dag.add_atom(std::span<const u8>(b_bytes.data(), b_bytes.size()), 2);
        Node a;
        a.kind = Kind::Atom;
        a.a = BigInt(a_id.value());
        auto ai = dag.add_node(std::move(a));
        Node b;
        b.kind = Kind::Atom;
        b.a = BigInt(b_id.value());
        auto bi = dag.add_node(std::move(b));
        Node x;
        x.kind = Kind::Xor;
        x.args = {ai.value(), bi.value()};
        auto id = dag.add_node(std::move(x));
        Ir ir;
        if (finish_dag(dag, id.value(), ir, why)) {
            // E2 C8 orders Xor operands by `canonical_key`; `canon` is the
            // authority for that order, so the corpus asks it rather than
            // re-deriving the key order here.
            auto canonical = canon(ir);
            if (!canonical.ok()) {
                std::fprintf(stderr, "corpus: canon(xor-two-atoms) failed: %s\n",
                             marp::v2::code_name(canonical.code()));
            } else {
                push("xor-two-atoms", "W-CANON", std::move(canonical.value()), false,
                     "Xor(atom, atom)");
            }
        }
    }
    {
        // Interleave with argc = 2 and stride dividing the child length.
        Dag dag;
        const std::vector<u8> a_bytes = payload(128, 0x51);
        const std::vector<u8> b_bytes = payload(128, 0x52);
        auto a_id = dag.add_atom(std::span<const u8>(a_bytes.data(), a_bytes.size()), 1);
        auto b_id = dag.add_atom(std::span<const u8>(b_bytes.data(), b_bytes.size()), 2);
        Node a;
        a.kind = Kind::Atom;
        a.a = BigInt(a_id.value());
        auto ai = dag.add_node(std::move(a));
        Node b;
        b.kind = Kind::Atom;
        b.a = BigInt(b_id.value());
        auto bi = dag.add_node(std::move(b));
        Node il;
        il.kind = Kind::Interleave;
        il.args = {ai.value(), bi.value()};
        il.a = BigInt(16u);
        auto id = dag.add_node(std::move(il));
        Ir ir;
        if (finish_dag(dag, id.value(), ir, why)) {
            push("interleave-2-s16", "W-CANON", std::move(ir), false,
                 "Interleave(atom, atom, stride 16)");
        }
    }
    {
        // A wide Concat over four distinct atoms.
        Dag dag;
        std::vector<u32> args;
        // Every adjacent Atom pair in a Concat must exceed ATOM_MAX (E2 C3), so
        // each child is 700 KiB.
        for (u32 i = 0; i < 4; ++i) {
            const std::vector<u8> bytes =
                payload((700u * 1024u) + i, static_cast<u8>(0x60 + i));
            auto atom_id = dag.add_atom(std::span<const u8>(bytes.data(), bytes.size()), 0);
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
            push("concat-4-atoms", "W-CANON", std::move(ir), false, "Concat of four Atoms");
        }
    }

    // --- Index-present terms (>= 3 MiB declared output) --------------------
    {
        // Three 1 MiB atoms: canonical index offsets 1 MiB and 2 MiB.
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
            push("index-3x-atom_max", "W-EDGE", std::move(ir), false,
                 "index present: two entries at 1 MiB and 2 MiB");
        }
    }
    {
        // Zero(4 MiB): entries at 1, 2, 3 MiB, all pointing at node 0.
        Dag dag;
        Node node;
        node.kind = Kind::Zero;
        node.a = BigInt(4ull << 20);
        auto id = dag.add_node(std::move(node));
        Ir ir;
        if (finish_dag(dag, id.value(), ir, why)) {
            push("index-zero-4mib", "W-EDGE", std::move(ir), false,
                 "index present: three entries, same node id");
        }
    }
    {
        // Just under the stride: no index entries at all.
        Dag dag;
        Node node;
        node.kind = Kind::Zero;
        node.a = BigInt((1ull << 20) - 1);
        auto id = dag.add_node(std::move(node));
        Ir ir;
        if (finish_dag(dag, id.value(), ir, why)) {
            push("index-absent-just-under", "W-EDGE", std::move(ir), false,
                 "index absent: total length just below INDEX_STRIDE");
        }
    }
    {
        // Exactly the stride but no node starts at it (a single Slice consumes it).
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
            push("index-repeat-5x1mib", "W-EDGE", std::move(ir), false,
                 "index present: Repeat(1 MiB atom, 5, 0) starts children at every MiB");
        }
    }

    // --- Declared lengths above 2^64: Region A.1 wire form -----------------
    {
        Ir ir = direct_zero(BigInt(1).shl(64).value());
        Ir certified;
        if (certify_direct(std::move(ir), true, certified, why)) {
            push("total-2pow64-zero", "W-BIG", std::move(certified), true,
                 "Region A.1: total_length = 2^64 exactly");
        }
    }
    {
        auto plus_one = BigInt(1).shl(64).value().add(BigInt(1));
        Ir ir = direct_zero(plus_one.ok() ? plus_one.value() : BigInt{});
        Ir certified;
        if (certify_direct(std::move(ir), true, certified, why)) {
            push("total-2pow64-plus-one-zero", "W-BIG", std::move(certified), true,
                 "Region A.1: total_length = 2^64 + 1");
        }
    }
    {
        auto huge = BigInt(1).shl(128).value();
        Ir ir = direct_zero(huge);
        Ir certified;
        if (certify_direct(std::move(ir), true, certified, why)) {
            push("total-2pow128-zero", "W-BIG", std::move(certified), true,
                 "Region A.1: total_length = 2^128 (Region A.1 = 17 bytes)");
        }
    }
    {
        // Repeat(atom, q, r) with a large-but-computable q, above 2^64 without
        // materialising any byte.  `16 * 2^59` repetitions would need
        // 2^59 / INDEX_STRIDE index entries, which is far beyond the documented
        // entry budget (see REPORT/E3/C07-WIRE-REPORT.md §5), so the corpus uses
        // a q whose entry count stays inside it.
        auto q = BigInt(1).shl(59).value();
        Ir ir = direct_repeat_atom(16, 0x33, q, BigInt(7));
        Ir certified;
        if (certify_direct(std::move(ir), true, certified, why)) {
            CorpusItem item;
            item.id = "limit-repeat-16x2pow59";
            item.group = "W-BIG";
            item.ir = std::move(certified);
            item.above_output_cap = true;
            item.expect_encode_limit = true;
            item.note =
                "Region A.1 Repeat; canonical index exceeds the u32 entry_count bound";
            items.push_back(std::move(item));
        }
    }
    {
        // A 1 MiB-atom Repeat above 2^64: the canonical index needs exactly
        // 2^64/INDEX_STRIDE entries, which is `Unsupported` by the documented
        // entry budget.  This is the one shape where C07 refuses to encode a
        // canonical Ir; reported as a Limit row by the harness.
        auto q = BigInt(1).shl(44).value();  // 2^44 * 2^20 = 2^64
        Ir ir = direct_repeat_atom(static_cast<std::size_t>(1u << 20), 0x77, q, BigInt(0));
        Ir certified;
        if (certify_direct(std::move(ir), true, certified, why)) {
            CorpusItem item;
            item.id = "limit-repeat-entry-budget";
            item.group = "W-BIG";
            item.ir = std::move(certified);
            item.above_output_cap = true;
            item.expect_encode_limit = true;
            item.note = "canonical index entry count exceeds the u32 entry_count bound";
            items.push_back(std::move(item));
        }
    }
    {
        Ir ir = direct_lfsr(0x8000000000000001ull, 0xDEADBEEFull, BigInt(1).shl(65).value());
        Ir certified;
        if (certify_direct(std::move(ir), true, certified, why)) {
            push("total-lfsr-2pow65", "W-BIG", std::move(certified), true,
                 "Region A.1 via Lfsr(conn, init, 2^65)");
        }
    }
    {
        // Exactly 2^64 - 1 must use the u64 form, not Region A.1.
        auto n = BigInt(1).shl(64).value().sub(BigInt(1));
        Ir ir = direct_zero(n.ok() ? n.value() : BigInt{});
        Ir certified;
        if (certify_direct(std::move(ir), false, certified, why)) {
            push("total-2pow64-minus-one-zero", "W-BIG", std::move(certified), false,
                 "u64 form boundary: total_length = 2^64 - 1");
        }
    }

    return items;
}

}  // namespace c07
