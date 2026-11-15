// MARP v2 — E2 ALGEBRA — C05 EVAL evidence harness.
//
// Produces:
//   specs_and_reports/v2/gates/C05-EVAL.tsv
//   specs_and_reports/v2/logs/C05-EVAL.log
//   specs_and_reports/v2/evidence/C05/SHA256SUMS
// when invoked with `--root <repo> --write-evidence`.
//
// Never asserts: every obligation (O5.1, O5.2, O5.3, WF enforcement, W7
// explicit-stack execution, C04 canon coherence, determinism, concurrency, and
// source-level isolation) is evaluated and recorded as a TSV row with exact
// expected/actual values and a PASS/FAIL verdict.

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#include "c03_build.hpp"
#include "c03_reference.hpp"
#include "mapr/e1_sha256.hpp"
#include "mapr/e2/e2_canon.hpp"
#include "mapr/e2/e2_eval.hpp"
#include "mapr/e2/e2_term.hpp"

namespace c05 {

using namespace marp::v2;  // NOLINT
using c03::Builder;
using c03::pattern;

std::string hex_bytes(std::span<const u8> bytes) {
    std::string out;
    out.reserve(bytes.size() * 2u);
    for (const u8 byte : bytes) {
        char buf[3];
        std::snprintf(buf, sizeof(buf), "%02x", static_cast<unsigned>(byte));
        out += buf;
    }
    return out;
}

std::string hex_array(const std::array<u8, 32>& digest) {
    return hex_bytes(std::span<const u8>(digest.data(), digest.size()));
}

std::string sha_hex(std::span<const u8> bytes) {
    auto digest = mapr::Sha256::hash(
        std::string_view(reinterpret_cast<const char*>(bytes.data()), bytes.size()));
    return digest.ok() ? hex_array(digest.value()) : std::string(64, '0');
}

std::string sha_text(const std::string& text) {
    return sha_hex(std::span<const u8>(reinterpret_cast<const u8*>(text.data()), text.size()));
}

BigInt pow2(u32 k) {
    auto r = BigInt(1).shl(k);
    return r.ok() ? r.value() : BigInt::zero();
}

std::size_t read_rss_kib() {
    std::ifstream in("/proc/self/status");
    std::string line;
    while (std::getline(in, line)) {
        if (line.rfind("VmRSS:", 0) == 0) {
            unsigned long kib = 0;
            if (std::sscanf(line.c_str() + 6, "%lu", &kib) == 1) {
                return static_cast<std::size_t>(kib);
            }
        }
    }
    return 0;
}

std::string code_str(Code c) { return std::string(code_name(c)); }

std::string describe(const Ir& ir) {
    if (ir.nodes.empty()) return "empty-ir";
    if (ir.nodes.size() > 4096u || ir.root >= ir.nodes.size()) {
        std::string text = "summary|nodes=" + std::to_string(ir.nodes.size());
        text += "|atoms=" + std::to_string(ir.atoms.size());
        text += "|len=" + ir.total_length.to_decimal();
        for (const Atom& atom : ir.atoms) text += ":" + hex_array(atom.sha256);
        return text;
    }
    std::string text = structural_key(ir, ir.root);
    text += "|len=" + ir.total_length.to_decimal();
    text += "|nodes=" + std::to_string(ir.nodes.size());
    text += "|atoms=" + std::to_string(ir.atoms.size());
    for (const Atom& atom : ir.atoms) text += ":" + hex_array(atom.sha256);
    return text;
}

struct VecSink final : Sink {
    std::vector<u8> bytes;
    std::size_t calls = 0;
    Code fail_code = Code::Ok;
    std::size_t fail_at = 0;

    Status write(std::span<const u8> chunk) override {
        ++calls;
        if (fail_at != 0 && calls == fail_at) return fail_code;
        bytes.insert(bytes.end(), chunk.begin(), chunk.end());
        return Status{};
    }
};

struct Row {
    std::string check;
    std::string corpus;
    std::string item_id;
    std::string input_sha256;
    std::string expected;
    std::string actual;
    std::string verdict;
    std::string log;
};

struct CorpusItem {
    std::string id;
    std::string corpus;
    Ir ir;
};

class Gate {
public:
    explicit Gate(std::string root) : root_(std::move(root)) {}

    int run();
    bool write_evidence();
    void set_environment(const std::string& env) { environment_ = env; }

private:
    std::string root_;
    std::string environment_;
    std::vector<CorpusItem> corpus_;
    std::vector<std::unique_ptr<Builder>> corpus_builders_;
    std::vector<Row> rows_;
    std::vector<std::string> log_lines_;
    std::size_t passes_ = 0;
    std::size_t failures_ = 0;
    std::array<std::size_t, kKindCount> kind_hits_{};
    std::array<std::size_t, kMorphCount + 1u> morph_hits_{};
    std::array<std::size_t, kPredictorCount> predictor_hits_{};

    void log(const std::string& line) { log_lines_.push_back(line); }

    void section(const std::string& name) {
        log("[" + name + "] cumulative pass=" + std::to_string(passes_) +
            " fail=" + std::to_string(failures_));
    }

    void record_hits(const Ir& ir) {
        for (const Node& n : ir.nodes) {
            const auto k = static_cast<std::size_t>(n.kind);
            if (k < kKindCount) ++kind_hits_[k];
            if (n.kind == Kind::Morph && n.morph >= 1 && n.morph <= kMorphCount) {
                ++morph_hits_[n.morph];
            }
            if (n.kind == Kind::Predictor && n.predictor_id < kPredictorCount) {
                ++predictor_hits_[n.predictor_id];
            }
        }
    }

    void row(std::string check, std::string corpus, std::string item_id,
             std::string input_sha, std::string expected, std::string actual,
             bool pass, std::string note) {
        if (pass) ++passes_;
        else {
            ++failures_;
            log("FAIL " + check + " " + item_id + " expected=" + expected +
                " actual=" + actual);
        }
        rows_.push_back(Row{std::move(check), std::move(corpus), std::move(item_id),
                            std::move(input_sha), std::move(expected), std::move(actual),
                            pass ? "PASS" : "FAIL", std::move(note)});
    }

    Builder& new_corpus_builder() {
        corpus_builders_.push_back(std::make_unique<Builder>());
        return *corpus_builders_.back();
    }

    void add_item(std::string id, std::string grp, Ir ir) {
        record_hits(ir);
        corpus_.push_back(CorpusItem{std::move(id), std::move(grp), std::move(ir)});
    }

    void build_corpus();
    void run_o51_corpus();
    void run_o52_virtual_and_jump();
    void run_o52_predictor_policy_and_checkpoints();
    void run_o53_bounded_memory_and_depth();
    void run_wf_and_limits();
    void run_canon_coherence();
    void run_determinism_and_concurrency();
    void run_source_independence();
    void run_coverage();
};

void Gate::build_corpus() {
    // 1. Empty & Zero & Atom
    {
        Builder& b = new_corpus_builder();
        add_item("e-empty", "O5.1-KIND", b.finish(b.empty()));
    }
    {
        Builder& b = new_corpus_builder();
        add_item("e-zero-0", "O5.1-KIND", b.finish(b.zero(BigInt::zero())));
    }
    {
        Builder& b = new_corpus_builder();
        add_item("e-zero-29", "O5.1-KIND", b.finish(b.zero(BigInt(29))));
    }
    {
        Builder& b = new_corpus_builder();
        add_item("e-atom-1", "O5.1-KIND", b.finish(b.atom_node(b.add_atom({0x7Bu}))));
    }
    {
        Builder& b = new_corpus_builder();
        add_item("e-atom-37", "O5.1-KIND", b.finish(b.atom_node(b.add_atom(pattern(37, 13)))));
    }

    // 2. Concat (small + wide binary-search >= 8 children + Empty-interspersed)
    {
        Builder& b = new_corpus_builder();
        const u32 a = b.atom_node(b.add_atom(pattern(11, 3)));
        const u32 z = b.zero(BigInt(7));
        const u32 c = b.affine(9, 23, BigInt(15));
        add_item("e-concat-3", "O5.1-KIND", b.finish(b.concat({a, z, c})));
    }
    {
        Builder& b = new_corpus_builder();
        std::vector<u32> kids;
        kids.push_back(b.empty());
        for (u32 i = 0; i < 12; ++i) {
            kids.push_back(b.atom_node(
                b.add_atom(pattern(4u + (i % 5u), static_cast<u8>(i * 19u + 1u)))));
            if (i % 4u == 1u) kids.push_back(b.empty());
        }
        add_item("e-concat-wide", "O5.1-KIND", b.finish(b.concat(kids)));
    }

    // 3. Repeat (q=0,r=0; q>0,r=0; q>0,r>0)
    {
        Builder& b = new_corpus_builder();
        const u32 c = b.atom_node(b.add_atom(pattern(9, 7)));
        add_item("e-repeat-0-0", "O5.1-KIND", b.finish(b.repeat(c, BigInt::zero(), BigInt::zero())));
    }
    {
        Builder& b = new_corpus_builder();
        const u32 c = b.atom_node(b.add_atom(pattern(11, 17)));
        add_item("e-repeat-3-6", "O5.1-KIND", b.finish(b.repeat(c, BigInt(3), BigInt(6))));
    }

    // 4. Slice (interior, full, zero-length, nested)
    {
        Builder& b = new_corpus_builder();
        const u32 base = b.lfsr(0x80200003ull, 0x12345678ull, BigInt(64));
        const u32 s1 = b.slice(base, BigInt(7), BigInt(45));
        const u32 s2 = b.slice(s1, BigInt(5), BigInt(29));
        add_item("e-slice-nested", "O5.1-KIND", b.finish(s2));
    }

    // 5. All 9 Morphisms (byte-local 1,2,6,7; block 3,4,5; mirrored 8,9)
    for (u8 m : {u8{1}, u8{2}, u8{3}, u8{4}, u8{5}, u8{6}, u8{7}, u8{8}, u8{9}}) {
        Builder& b = new_corpus_builder();
        const std::size_t n = (m >= 3 && m <= 5) ? 32u : 29u;
        const u8 k = (m == 6 || m == 7) ? 3u : 0u;
        const u32 child =
            b.atom_node(b.add_atom(pattern(n, static_cast<u8>(m * 31u + 5u))));
        add_item("e-morph-" + std::to_string(m), "O5.1-MORPH",
                 b.finish(b.morph(child, m, k)));
    }

    // 6. Xor & Interleave & Lfsr & Affine
    {
        Builder& b = new_corpus_builder();
        const u32 x = b.lfsr(0xD0080004ull, 0xCAFEBABEull, BigInt(35));
        const u32 y = b.affine(17, 59, BigInt(35));
        add_item("e-xor", "O5.1-KIND", b.finish(b.xor_node(x, y)));
    }
    {
        Builder& b = new_corpus_builder();
        const u32 c0 = b.atom_node(b.add_atom(pattern(15, 11)));
        const u32 c1 = b.affine(3, 41, BigInt(15));
        const u32 c2 = b.lfsr(0x80200003ull, 7ull, BigInt(15));
        add_item("e-interleave-3x3", "O5.1-KIND",
                 b.finish(b.interleave({c0, c1, c2}, 3u)));
    }
    {
        Builder& b = new_corpus_builder();
        add_item("e-lfsr-37", "O5.1-KIND",
                 b.finish(b.lfsr(0x800000000000000Dull, 0x0102030405060708ull, BigInt(37))));
    }
    {
        Builder& b = new_corpus_builder();
        add_item("e-affine-41", "O5.1-KIND", b.finish(b.affine(250, 13, BigInt(41))));
    }

    // 7. All 5 Predictors (DELTA8, XOR8, LINEAR2, STRIDE_DELTA, STRIDE_XOR) + short residuals
    {
        Builder& b = new_corpus_builder();
        add_item("e-pred-0", "O5.1-PRED",
                 b.finish(b.predictor(0, 0, b.atom_node(b.add_atom(pattern(33, 21))))));
    }
    {
        Builder& b = new_corpus_builder();
        add_item("e-pred-1", "O5.1-PRED",
                 b.finish(b.predictor(1, 0, b.atom_node(b.add_atom(pattern(33, 22))))));
    }
    {
        Builder& b = new_corpus_builder();
        add_item("e-pred-2", "O5.1-PRED",
                 b.finish(b.predictor(2, 0, b.atom_node(b.add_atom(pattern(33, 23))))));
    }
    {
        Builder& b = new_corpus_builder();
        add_item("e-pred-2-len1", "O5.1-PRED",
                 b.finish(b.predictor(2, 0, b.atom_node(b.add_atom({0xABu})))));
    }
    {
        Builder& b = new_corpus_builder();
        add_item("e-pred-2-len2", "O5.1-PRED",
                 b.finish(b.predictor(2, 0, b.atom_node(b.add_atom({0xABu, 0xCDu})))));
    }
    {
        Builder& b = new_corpus_builder();
        add_item("e-pred-3-s7", "O5.1-PRED",
                 b.finish(b.predictor(3, 7, b.atom_node(b.add_atom(pattern(35, 24))))));
    }
    {
        Builder& b = new_corpus_builder();
        add_item("e-pred-4-s5", "O5.1-PRED",
                 b.finish(b.predictor(4, 5, b.atom_node(b.add_atom(pattern(35, 25))))));
    }
    {
        Builder& b = new_corpus_builder();
        add_item("e-pred-4-short", "O5.1-PRED",
                 b.finish(b.predictor(4, 64, b.atom_node(b.add_atom(pattern(12, 26))))));
    }

    // 8. Deeply composed multi-operator DAGs
    {
        Builder& b = new_corpus_builder();
        const u32 lf = b.lfsr(0x80200003ull, 0x778899AAull, BigInt(24));
        const u32 p2 = b.predictor(2, 0, lf);
        const u32 sw = b.morph(p2, 5, 0);  // SWAP64 (24 divisible by 8)
        const u32 rv = b.morph(sw, 9, 0);  // REVERSE_BITS
        const u32 af = b.affine(11, 29, BigInt(24));
        const u32 il = b.interleave({rv, af}, 4u);  // 48 bytes
        const u32 rp = b.repeat(il, BigInt(1), BigInt(16));  // 64 bytes
        const u32 sl = b.slice(rp, BigInt(5), BigInt(48));
        add_item("e-composite-all", "O5.1-DAG", b.finish(sl));
    }
    {
        Builder& b = new_corpus_builder();
        u32 cur = b.atom_node(b.add_atom(pattern(32, 99)));
        for (u32 i = 0; i < 8; ++i) {
            const u32 rot = b.morph(cur, 6, static_cast<u8>((i % 7u) + 1u));
            cur = b.xor_node(cur, rot);
        }
        add_item("e-shared-xor-dag", "O5.1-DAG", b.finish(cur));
    }
}

void Gate::run_o51_corpus() {
    for (const CorpusItem& item : corpus_) {
        const std::string in_sha = sha_text(describe(item.ir));

        // 1. Full stream vs independent c03ref::ref_denote
        std::vector<u8> ref_bytes;
        const bool ref_ok = c03ref::ref_denote(item.ir, item.ir.root, ref_bytes, 1u << 20);
        VecSink full;
        const Status st = eval_stream(item.ir, full);
        const std::string exp_hex = ref_ok ? sha_hex(ref_bytes) : "ERR";
        const std::string act_hex = st.ok() ? sha_hex(full.bytes) : code_str(st.code());
        row("o5.1.stream_vs_ref", item.corpus, item.id, in_sha, exp_hex, act_hex,
            ref_ok && st.ok() && full.bytes == ref_bytes, item.id);

        if (!ref_ok || !st.ok()) continue;
        const std::vector<u8>& truth = full.bytes;
        const std::size_t n = truth.size();

        // 2. Exhaustive subrange equivalence: read_range & eval_range == eval_stream[s..s+l)
        std::size_t pairs_checked = 0;
        std::size_t pairs_ok = 0;
        for (std::size_t s = 0; s <= n; ++s) {
            for (std::size_t l = 0; s + l <= n; ++l) {
                ++pairs_checked;
                std::vector<u8> buf(l, 0x5Au);
                auto r = read_range(item.ir, item.ir.root, BigInt(static_cast<u64>(s)), buf);
                bool ok = r.ok() && r.value() == l &&
                          std::equal(buf.begin(), buf.end(),
                                     truth.begin() + static_cast<std::ptrdiff_t>(s));
                if (ok && ((s + l) % 11u == 0u || n <= 8u)) {
                    VecSink rsink;
                    const Status rst = eval_range(item.ir, BigInt(static_cast<u64>(s)),
                                                  BigInt(static_cast<u64>(l)), rsink);
                    ok = rst.ok() && rsink.bytes == buf;
                }
                if (ok) ++pairs_ok;
            }
        }
        row("o5.1.subranges", item.corpus, item.id, in_sha,
            std::to_string(pairs_checked) + "/" + std::to_string(pairs_checked),
            std::to_string(pairs_ok) + "/" + std::to_string(pairs_checked),
            pairs_ok == pairs_checked, "pairs=" + std::to_string(pairs_checked));

        // 3. Monotone TermCursor with irregular chunk sizes (E2-I8)
        TermCursor cur(item.ir, item.ir.root);
        std::vector<u8> cur_bytes;
        std::size_t chunk_sz = 1;
        bool cur_ok = true;
        while (!cur.at_end()) {
            std::vector<u8> tmp(chunk_sz);
            auto rd = cur.read(tmp);
            if (!rd.ok() || rd.value() == 0) {
                cur_ok = false;
                break;
            }
            cur_bytes.insert(cur_bytes.end(), tmp.begin(),
                             tmp.begin() + static_cast<std::ptrdiff_t>(rd.value()));
            chunk_sz = (chunk_sz * 5u + 3u) % 19u + 1u;
        }
        const std::string cur_hex = cur_ok ? sha_hex(cur_bytes) : "CURSOR_ERR";
        row("o5.1.cursor", item.corpus, item.id, in_sha, exp_hex, cur_hex,
            cur_ok && cur.at_end() && cur.remaining().is_zero() && cur_bytes == truth,
            item.id);

        // 4. Block-buffer invariance: tiny prime block_bytes=13 vs default 64 KiB (E2-I8)
        EvalLimits small_blk;
        small_blk.block_bytes = 13;
        auto d13 = eval_stream_digest(item.ir, small_blk);
        auto d64k = eval_stream_digest(item.ir);
        const std::string d13_hex = d13.ok() ? hex_array(d13.value().sha256) : "ERR";
        const std::string d64_hex = d64k.ok() ? hex_array(d64k.value().sha256) : "ERR";
        row("o5.1.block_invariance", item.corpus, item.id, in_sha, d64_hex, d13_hex,
            d13.ok() && d64k.ok() && d13.value().sha256 == d64k.value().sha256 &&
                d64_hex == exp_hex,
            "blk13_vs_64k");
    }
    section("o5.1_corpus");
}

void Gate::run_o52_virtual_and_jump() {
    // 1. LFSR O(log offset) jump-ahead at 2^60 + 999999 & adjacent concatenation
    {
        Builder b;
        constexpr u64 kConn = 0xD80000000000000Dull;
        constexpr u64 kInit = 0xFEDCBA9876543210ull;
        const Ir ir = b.finish(b.lfsr(kConn, kInit, pow2(62)));
        const std::string in_sha = sha_text(describe(ir));

        const BigInt far = pow2(60).add(BigInt(999999)).value();
        std::array<u8, 128> span128{};
        EvalStats stats{};
        const auto r = read_range_ex(ir, ir.root, far, span128, EvalLimits{}, {}, &stats);
        std::array<u8, 64> lo{}, hi{};
        const auto rlo = read_range(ir, ir.root, far, lo);
        const auto rhi = read_range(ir, ir.root, far.add(BigInt(64)).value(), hi);

        std::array<u8, 128> direct{};
        const Status dst = lfsr_read_range(kConn, kInit, far, direct);

        const bool split_ok = r.ok() && rlo.ok() && rhi.ok() && dst.ok() &&
                              span128 == direct &&
                              std::equal(lo.begin(), lo.end(), span128.begin()) &&
                              std::equal(hi.begin(), hi.end(), span128.begin() + 64);
        row("o5.2.lfsr_jump_exact", "O5.2-VIRT", "lfsr-2pow60", in_sha,
            sha_hex(direct), r.ok() ? sha_hex(span128) : code_str(r.code()), split_ok,
            "muls=" + std::to_string(stats.lfsr_gf2_mul_ops));

        const bool log_bound = stats.lfsr_jumps == 1u && stats.lfsr_gf2_mul_ops <= 130u;
        row("o5.2.lfsr_log_bound", "O5.2-VIRT", "lfsr-2pow60-ops", in_sha,
            "jumps=1,muls<=130",
            "jumps=" + std::to_string(stats.lfsr_jumps) + ",muls=" +
                std::to_string(stats.lfsr_gf2_mul_ops),
            log_bound, "O(log_offset)");
    }

    // 2. Slice over 2^70-byte LFSR at child offset 2^65 + 137 (> 2^64, M2-I2!)
    {
        Builder b;
        constexpr u64 kConn = 0x800000000000001Bull;
        constexpr u64 kInit = 0x0123456789ABCDEFull;
        const BigInt slice_off = pow2(65).add(BigInt(137)).value();
        const u32 lf = b.lfsr(kConn, kInit, pow2(70));
        const Ir ir = b.finish(b.slice(lf, slice_off, BigInt(64)));
        const std::string in_sha = sha_text(describe(ir));

        std::array<u8, 32> got{};
        const auto r = read_range(ir, ir.root, BigInt(19), got);
        std::array<u8, 32> expected{};
        const Status dst = lfsr_read_range(kConn, kInit, slice_off.add(BigInt(19)).value(),
                                           expected);
        row("o5.2.above_2pow64_slice", "O5.2-VIRT", "slice-at-2pow65+156", in_sha,
            sha_hex(expected), r.ok() ? sha_hex(got) : code_str(r.code()),
            r.ok() && dst.ok() && got == expected, "child_len=2^70");
    }

    // 3. Wide Concat (256 children): disjoint sibling skipping via binary search
    {
        Builder b;
        std::vector<u32> kids;
        std::vector<u8> full;
        for (u32 i = 0; i < 256; ++i) {
            auto bytes = pattern(9u + (i % 7u), static_cast<u8>(i * 29u + 3u));
            full.insert(full.end(), bytes.begin(), bytes.end());
            kids.push_back(b.atom_node(b.add_atom(bytes)));
        }
        const Ir ir = b.finish(b.concat(kids));
        const std::string in_sha = sha_text(describe(ir));
        const std::size_t mid = full.size() / 2u;
        std::array<u8, 24> got{};
        EvalStats stats{};
        const auto r =
            read_range_ex(ir, ir.root, BigInt(static_cast<u64>(mid)), got, EvalLimits{}, {}, &stats);
        const std::span<const u8> exp_span(full.data() + mid, 24u);
        const bool ok = r.ok() &&
                        std::equal(got.begin(), got.end(), exp_span.begin()) &&
                        stats.concat_children_skipped >= 252u;
        row("o5.2.concat_skip", "O5.2-VIRT", "concat-256-kids", in_sha,
            "match+skipped>=252",
            (r.ok() ? std::string("match") : code_str(r.code())) + "+skipped=" +
                std::to_string(stats.concat_children_skipped),
            ok, "touched=" + std::to_string(stats.subterms_touched));
    }

    // 4. Virtual Morph SWAP64 & REVERSE_BITS with zero heap scratch
    {
        Builder b;
        constexpr u64 kConn = 0xD008000000000005ull;
        constexpr u64 kInit = 0xCAFEBABE12345678ull;
        const BigInt n = pow2(40);
        const u32 lf = b.lfsr(kConn, kInit, n);
        const u32 sw = b.morph(lf, 5, 0);  // SWAP64
        const u32 rv = b.morph(sw, 9, 0);  // REVERSE_BITS
        const Ir ir = b.finish(rv);
        const std::string in_sha = sha_text(describe(ir));

        const BigInt start = pow2(39).add(BigInt(3)).value();
        std::array<u8, 29> got{};
        EvalStats stats{};
        const auto r = read_range_ex(ir, ir.root, start, got, EvalLimits{}, {}, &stats);

        // Independent computation on the enclosing 8-byte aligned window of `lf`.
        const BigInt rev_from = n.sub(start).value().sub(BigInt(29)).value();
        const u32 rem = rev_from.divmod_scalar(8).value().second;
        const BigInt aligned_from = rev_from.sub(BigInt(rem)).value();
        std::array<u8, 40> raw{};
        const Status lst = lfsr_read_range(kConn, kInit, aligned_from, raw);
        (void)apply_morph_to_buffer(5, 0, raw);
        std::array<u8, 29> expected{};
        std::memcpy(expected.data(), raw.data() + rem, 29u);
        std::reverse(expected.begin(), expected.end());
        for (u8& byte : expected) byte = bit_reverse8(byte);

        row("o5.2.virtual_morph_zero_scratch", "O5.2-VIRT", "swap64+revbits-2pow40",
            in_sha, sha_hex(expected) + "|scratch=0",
            (r.ok() ? sha_hex(got) : code_str(r.code())) + "|scratch=" +
                std::to_string(stats.peak_scratch_bytes),
            r.ok() && lst.ok() && got == expected && stats.peak_scratch_bytes == 0u,
            "2^40_virtual_morph");
    }
    section("o5.2_virtual_and_jump");
}

void Gate::run_o52_predictor_policy_and_checkpoints() {
    // 1. Default 2^28 prefix limit & out-of-bounds precedence
    {
        Builder b;
        const BigInt len = pow2(30);
        const Ir ir = b.finish(b.predictor(0, 0, b.zero(len)));
        const std::string in_sha = sha_text(describe(ir));
        std::array<u8, 8> buf{};

        const BigInt over = predictor_prefix_limit().add(BigInt(1)).value();
        const auto r_lim = read_range(ir, ir.root, over, buf);
        row("o5.2.pred_prefix_limit", "O5.2-PRED", "start-2pow28+1", in_sha,
            "Limit", code_str(r_lim.code()), r_lim.code() == Code::Limit, "no_checkpoint");

        const auto r_oob = read_range(ir, ir.root, len.add(BigInt(1)).value(), {});
        row("o5.2.pred_oob_precedence", "O5.2-PRED", "start-past-len", in_sha,
            "Invalid", code_str(r_oob.code()), r_oob.code() == Code::Invalid,
            "bounds_before_prefix");
    }

    // 2. Stride window > 16 MiB policy
    {
        Builder b;
        constexpr u32 kStride = (16u << 20) + 128u;
        const Ir ir =
            b.finish(b.predictor(3, kStride, b.affine(5, 9, BigInt(kStride + 1024ull))));
        const std::string in_sha = sha_text(describe(ir));
        std::array<u8, 16> buf{};
        const auto r_in = read_range(ir, ir.root, BigInt(64), buf);
        const auto r_over = read_range(ir, ir.root, BigInt(kStride), buf);
        row("o5.2.pred_window_limit", "O5.2-PRED", "stride-over-16mib", in_sha,
            "inside=Ok,past=Limit",
            "inside=" + code_str(r_in.code()) + ",past=" + code_str(r_over.code()),
            r_in.ok() && r_over.code() == Code::Limit, "16MiB_window_cap");
    }

    // 3. Checkpoints across all 5 predictor IDs: capture, chain, and random access
    for (u8 pid = 0; pid < kPredictorCount; ++pid) {
        const u32 param = (pid == 3) ? 13u : (pid == 4 ? 19u : 0u);
        Builder b;
        const u32 res = b.lfsr(0x80200003ull, 0xABC000ull + pid, BigInt(4000));
        const u32 pred = b.predictor(pid, param, res);
        const Ir ir = b.finish(pred);
        const std::string in_sha = sha_text(describe(ir));

        VecSink full;
        (void)eval_stream(ir, full);

        EvalLimits lim;
        lim.predictor_prefix_max = BigInt(900);
        lim.block_bytes = 251;

        auto cp1 = capture_predictor_checkpoint(ir, pred, BigInt(900), nullptr, lim);
        auto cp2 = cp1.ok()
                       ? capture_predictor_checkpoint(ir, pred, BigInt(1800), &cp1.value(), lim)
                       : Result<PredictorCheckpoint>(cp1.code());
        auto cp3 = cp2.ok()
                       ? capture_predictor_checkpoint(ir, pred, BigInt(2700), &cp2.value(), lim)
                       : Result<PredictorCheckpoint>(cp2.code());

        bool ok = false;
        std::string act = "ERR";
        const std::span<const u8> exp_span(full.bytes.data() + 3100, 64u);
        if (cp3.ok()) {
            const std::array<PredictorCheckpoint, 3> cps = {cp1.value(), cp2.value(),
                                                            cp3.value()};
            std::array<u8, 64> got{};
            EvalStats stats{};
            auto r = read_range_ex(ir, pred, BigInt(3100), got, lim, cps, &stats);
            if (r.ok()) {
                act = sha_hex(got);
                ok = std::equal(got.begin(), got.end(), exp_span.begin()) &&
                     stats.predictor_prefix_bytes == 400u;
            } else {
                act = code_str(r.code());
            }
        }
        row("o5.2.pred_checkpoint_chain", "O5.2-PRED",
            "pred-" + std::to_string(pid) + "-chain", in_sha, sha_hex(exp_span), act, ok,
            "prefix_scan=400");
    }

    // 4. Sequential streaming across 20x predictor_prefix_max with 0 prefix re-scan
    {
        Builder b;
        const u32 res = b.lfsr(0x80200003ull, 0x55AA55AAull, BigInt(10000));
        const u32 p = b.predictor(4, 29, res);
        const u32 cat = b.concat({p, b.xor_node(p, b.morph(p, 2, 0))});
        const Ir ir = b.finish(cat);
        const std::string in_sha = sha_text(describe(ir));

        EvalLimits lim;
        lim.block_bytes = 197;
        lim.predictor_prefix_max = BigInt(500);
        EvalStats stats{};
        const auto dig = eval_stream_digest(ir, lim, &stats);
        const auto baseline = eval_stream_digest(ir);
        const bool ok = dig.ok() && baseline.ok() &&
                        dig.value().sha256 == baseline.value().sha256 &&
                        stats.predictor_prefix_bytes == 0u;
        row("o5.2.pred_stream_rolling", "O5.2-PRED", "dag-shared-pred-stream", in_sha,
            (baseline.ok() ? hex_array(baseline.value().sha256) : "ERR") + "|prefix=0",
            (dig.ok() ? hex_array(dig.value().sha256) : code_str(dig.code())) + "|prefix=" +
                std::to_string(stats.predictor_prefix_bytes),
            ok, "O(N)_rolling_session");
    }
    section("o5.2_predictor");
}

void Gate::run_o53_bounded_memory_and_depth() {
    // 1. O5.3: 64 MiB composite stream hashed incrementally with <= 128 KiB scratch
    //    and <= 16 MiB process RSS delta!
    {
        Builder b;
        constexpr u64 kHalf = 32ull << 20;  // 32 MiB
        const u32 lf = b.lfsr(0x800000000000000Dull, 0xA5A5A5A55A5A5A5Aull, BigInt(kHalf));
        const u32 af = b.affine(17, 29, BigInt(kHalf));
        const u32 sw = b.morph(b.xor_node(lf, af), 5, 0);
        const u32 pr = b.predictor(3, 64, af);
        const Ir ir = b.finish(b.concat({sw, pr}));  // 64 MiB
        const std::string in_sha = sha_text(describe(ir));

        const std::size_t rss_before = read_rss_kib();
        EvalStats stats{};
        const auto dig = eval_stream_digest(ir, EvalLimits{}, &stats);
        const std::size_t rss_after = read_rss_kib();
        const std::size_t rss_delta_kib =
            (rss_after > rss_before) ? (rss_after - rss_before) : 0u;

        log("o5.3_64mib_stream: bytes=" +
            (dig.ok() ? dig.value().bytes.to_decimal() : std::string("ERR")) +
            " sha256=" + (dig.ok() ? hex_array(dig.value().sha256) : std::string("ERR")) +
            " peak_scratch_bytes=" + std::to_string(stats.peak_scratch_bytes) +
            " rss_before_kib=" + std::to_string(rss_before) +
            " rss_after_kib=" + std::to_string(rss_after) +
            " rss_delta_kib=" + std::to_string(rss_delta_kib));

        const bool scratch_ok =
            dig.ok() && dig.value().bytes == BigInt(64ull << 20) &&
            stats.peak_scratch_bytes <= 131072u;
        row("o5.3.scratch_bound_64mib", "O5.3-MEM", "composite-64mib", in_sha,
            "bytes=67108864,peak_scratch<=131072",
            "bytes=" + (dig.ok() ? dig.value().bytes.to_decimal() : std::string("ERR")) +
                ",peak_scratch=" + std::to_string(stats.peak_scratch_bytes),
            scratch_ok, "scratch=" + std::to_string(stats.peak_scratch_bytes));

        const bool rss_ok = dig.ok() && rss_delta_kib <= 16u * 1024u;
        row("o5.3.rss_delta_64mib", "O5.3-MEM", "composite-64mib-rss", in_sha,
            "rss_delta<=16384KiB",
            rss_ok ? "rss_delta<=16384KiB" : ("rss_delta=" + std::to_string(rss_delta_kib) + "KiB"),
            rss_ok, "64MiB_stream_incremental_sha256");
    }

    // 2. W7 maximum legal depth (65,536) on explicit heap stack + 65,537 Limit rejection
    {
        Builder b;
        const std::vector<u8> payload = {0x10u, 0x20u, 0x30u, 0x40u, 0x50u, 0x60u, 0x70u, 0x80u};
        u32 cur = b.atom_node(b.add_atom(payload));
        for (u32 i = 1; i < kMaxDepthSpec; ++i) cur = b.morph(cur, 2, 0);
        const Ir ir = b.finish(cur);
        const std::string in_sha = sha_text(describe(ir));

        EvalStats stats{};
        VecSink sink;
        const Status st = eval_stream_ex(ir, sink, EvalLimits{}, &stats);
        std::vector<u8> expected(payload.size());
        for (std::size_t i = 0; i < payload.size(); ++i) {
            expected[i] = static_cast<u8>(~payload[i]);
        }
        const bool ok = st.ok() && sink.bytes == expected &&
                        stats.peak_stack_depth == kMaxDepthSpec &&
                        stats.peak_scratch_bytes == 0u;
        row("o5.3.w7_depth_65536", "O5.3-STACK", "explicit-stack-65536", in_sha,
            sha_hex(expected) + "|depth=65536",
            (st.ok() ? sha_hex(sink.bytes) : code_str(st.code())) + "|depth=" +
                std::to_string(stats.peak_stack_depth),
            ok, "zero_call_stack_recursion");

        Builder b2;
        u32 n = b2.atom_node(b2.add_atom(payload));
        for (u32 i = 1; i <= kMaxDepthSpec; ++i) n = b2.morph(n, 1, 0);
        const Ir over = b2.finish(n);
        VecSink s2;
        const Status st_over = eval_stream(over, s2);
        row("o5.3.w7_depth_65537_limit", "O5.3-STACK", "explicit-stack-65537",
            sha_text(describe(over)), "Limit", code_str(st_over.code()),
            st_over.code() == Code::Limit, "W7_exceeded");
    }
    section("o5.3_memory_and_stack");
}

void Gate::run_wf_and_limits() {
    auto check_bad = [&](const std::string& id, const Ir& bad, Code expected) {
        VecSink s1, s2;
        std::array<u8, 1> b{};
        const Code c1 = eval_stream(bad, s1).code();
        const Code c2 = eval_range(bad, BigInt::zero(), BigInt::zero(), s2).code();
        const Code c3 = read_range(bad, bad.root, BigInt::zero(), {}).code();
        TermCursor cur(bad, bad.root);
        const Code c4 = cur.read(b).code();
        const Code c5 = PreparedEval::prepare(bad).code();
        const bool all_match =
            (c1 == expected && c2 == expected && c3 == expected && c4 == expected &&
             c5 == expected);
        row("c05.wf_guard", "C05-BAD", id, sha_text(describe(bad)), code_str(expected),
            all_match ? code_str(expected) : "MISMATCH", all_match, id);
    };

    {
        Builder b;
        (void)b.atom_node(b.add_atom(pattern(4, 1)));
        check_bad("bad-w2-unreachable", b.finish(b.zero(BigInt(8))), Code::Invalid);
    }
    {
        Builder b;
        Ir ir = b.finish(b.morph(b.zero(BigInt(8)), 1, 0));
        ir.nodes[1].args[0] = 1;
        check_bad("bad-w3-cycle", ir, Code::Invalid);
    }
    {
        Builder b;
        Ir ir = b.finish(b.zero(BigInt(8)));
        ir.nodes[0].flags = 2;
        check_bad("bad-w4-flags", ir, Code::Invalid);
    }
    {
        Builder b;
        check_bad("bad-w5-empty-atom", b.finish(b.atom_node(b.add_atom({}))), Code::Invalid);
    }
    {
        Builder b;
        Ir ir = b.finish(b.zero(BigInt(8)));
        ir.nodes[0].length = BigInt(9);
        check_bad("bad-w6-tampered-length", ir, Code::Invalid);
    }
    {
        Builder b;
        check_bad("bad-s1-output-cap",
                  b.finish(b.zero(pow2(63).add(BigInt(1)).value())), Code::Limit);
    }
    section("c05_wf_guards");
}

void Gate::run_canon_coherence() {
    Builder b;
    const u32 a1 = b.atom_node(b.add_atom(pattern(16, 7)));
    const u32 a2 = b.atom_node(b.add_atom(pattern(16, 11)));
    const u32 cat_atoms = b.concat({a1, b.empty(), a2});
    const u32 rot_id = b.morph(b.morph(cat_atoms, 6, 6), 6, 2);
    const u32 swap_id = b.morph(b.morph(rot_id, 4, 0), 4, 0);
    const u32 z_xor = b.xor_node(a1, a1);
    const u32 aff0 = b.affine(0x3Cu, 0u, BigInt(16));
    const u32 il1 = b.interleave({aff0}, 8u);
    const u32 root =
        b.slice(b.concat({swap_id, z_xor, b.zero(BigInt(8)), il1}), BigInt(5), BigInt(58));
    const Ir raw = b.finish(root);
    const std::string in_sha = sha_text(describe(raw));

    const auto can = canon(raw);
    const auto d_raw = eval_stream_digest(raw);
    const auto d_can = can.ok() ? eval_stream_digest(can.value())
                                : Result<StreamDigest>(can.code());

    bool ranges_ok = can.ok();
    if (can.ok()) {
        for (u64 s = 0; s <= 58; s += 6) {
            for (u64 l = 0; s + l <= 58; l += 9) {
                std::vector<u8> r1(static_cast<std::size_t>(l));
                std::vector<u8> r2(static_cast<std::size_t>(l));
                if (!read_range(raw, raw.root, BigInt(s), r1).ok() ||
                    !read_range(can.value(), can.value().root, BigInt(s), r2).ok() ||
                    r1 != r2) {
                    ranges_ok = false;
                }
            }
        }
    }

    const std::string exp = d_raw.ok() ? hex_array(d_raw.value().sha256) : "ERR";
    const std::string act = d_can.ok() ? hex_array(d_can.value().sha256) : "ERR";
    row("c05.canon_coherence", "C05-E2I4", "canon-preserves-eval-and-ranges", in_sha,
        exp, act, d_raw.ok() && d_can.ok() && exp == act && ranges_ok, "E2-I4");
    section("c05_canon_coherence");
}

void Gate::run_determinism_and_concurrency() {
    Builder b;
    const u32 lf = b.lfsr(0x80200003ull, 0x9988776655443322ull, BigInt(2048));
    const u32 pr = b.predictor(4, 17, lf);
    const u32 sw = b.morph(pr, 5, 0);
    const Ir ir = b.finish(b.repeat(sw, BigInt(2), BigInt(96)));
    const std::string in_sha = sha_text(describe(ir));

    auto prep = PreparedEval::prepare(ir);
    const auto baseline = eval_stream_digest(ir);
    const std::string exp = baseline.ok() ? hex_array(baseline.value().sha256) : "ERR";

    // Repeated runs + 4 concurrent threads sharing one const PreparedEval (E2-I2, E2-I12).
    constexpr std::size_t kThreads = 4;
    std::array<std::string, kThreads> thread_hex{};
    if (prep.ok()) {
        std::vector<std::thread> pool;
        for (std::size_t t = 0; t < kThreads; ++t) {
            pool.emplace_back([&, t]() {
                HashingSink hs;
                if (!prep.value().eval_stream(hs).ok()) {
                    thread_hex[t] = "ERR";
                    return;
                }
                auto d = hs.finish();
                thread_hex[t] = d.ok() ? hex_array(d.value().sha256) : "ERR";
            });
        }
        for (std::thread& th : pool) th.join();
    }
    bool all_eq = prep.ok() && baseline.ok();
    for (std::size_t t = 0; t < kThreads; ++t) {
        if (thread_hex[t] != exp) all_eq = false;
    }
    row("c05.determinism_concurrency", "C05", "4-thread-prepared-eval", in_sha, exp,
        all_eq ? exp : "MISMATCH", all_eq, "E2-I2+E2-I12");
    section("c05_determinism");
}

void Gate::run_source_independence() {
    namespace fs = std::filesystem;
    const std::vector<std::string> dirs = {
        root_ + "/include/mapr/e2",
        root_ + "/engine/src/e2",
    };
    const std::vector<std::string> forbidden = {
        "wire",       "container", "harness",   "cli",       "mau",
        "certificate","discovery", "rewrite",   "selection", "e3",
        "e4",         "e5",        "e6",        "e7",
    };
    std::vector<std::string> files;
    for (const std::string& dir : dirs) {
        std::error_code ec;
        for (auto it = fs::recursive_directory_iterator(dir, ec);
             !ec && it != fs::recursive_directory_iterator(); ++it) {
            if (!it->is_regular_file()) continue;
            const std::string ext = it->path().extension().string();
            if (ext == ".hpp" || ext == ".h" || ext == ".cpp") {
                files.push_back(it->path().string());
            }
        }
    }
    std::sort(files.begin(), files.end());

    std::size_t bad = 0;
    std::string digest_acc;
    for (const std::string& file : files) {
        std::ifstream in(file);
        std::string line;
        while (std::getline(in, line)) {
            digest_acc += line;
            digest_acc.push_back('\n');
            if (line.find("#include") == std::string::npos) continue;
            for (const std::string& tok : forbidden) {
                if (line.find(tok) != std::string::npos) {
                    ++bad;
                    log("forbidden include in " + file + ": " + line);
                }
            }
        }
    }
    row("independence", "C05", "source-scan", sha_text(digest_acc), "0 forbidden includes",
        std::to_string(bad) + " forbidden includes across " + std::to_string(files.size()) +
            " files",
        bad == 0 && !files.empty(), "source-scan");
    section("independence");
}

void Gate::run_coverage() {
    std::size_t kinds = 0;
    for (std::size_t i = 0; i < kKindCount; ++i) {
        if (kind_hits_[i] > 0) ++kinds;
    }
    row("coverage.kind", "C05", "all-12-kinds", sha_text("kinds"), "12/12",
        std::to_string(kinds) + "/12", kinds == kKindCount, "all-12-kinds");

    std::size_t morphs = 0;
    for (std::size_t i = 1; i <= kMorphCount; ++i) {
        if (morph_hits_[i] > 0) ++morphs;
    }
    row("coverage.morph", "C05", "all-9-morphs", sha_text("morphs"), "9/9",
        std::to_string(morphs) + "/9", morphs == kMorphCount, "all-9-morphs");

    std::size_t predictors = 0;
    for (std::size_t i = 0; i < kPredictorCount; ++i) {
        if (predictor_hits_[i] > 0) ++predictors;
    }
    row("coverage.predictor", "C05", "all-5-predictors", sha_text("predictors"), "5/5",
        std::to_string(predictors) + "/5", predictors == kPredictorCount,
        "all-5-predictors");
    section("coverage");
}

int Gate::run() {
    build_corpus();
    run_o51_corpus();
    run_o52_virtual_and_jump();
    run_o52_predictor_policy_and_checkpoints();
    run_o53_bounded_memory_and_depth();
    run_wf_and_limits();
    run_canon_coherence();
    run_determinism_and_concurrency();
    run_source_independence();
    run_coverage();

    const std::size_t checks = passes_ + failures_;
    log("totals: checks=" + std::to_string(checks) + " pass=" + std::to_string(passes_) +
        " fail=" + std::to_string(failures_));
    log(failures_ == 0 ? std::string("RESULT: PASS (C05 EVAL)")
                       : std::string("RESULT: FAIL (C05 EVAL)"));
    row("c05.summary", "C05", "all-checks", sha_text("summary"),
        std::to_string(checks) + " checks all PASS",
        "pass=" + std::to_string(passes_) + " fail=" + std::to_string(failures_),
        failures_ == 0, "summary");
    return failures_ == 0 ? 0 : 1;
}

bool Gate::write_evidence() {
    namespace fs = std::filesystem;
    const std::string gate_dir = root_ + "/specs_and_reports/v2/gates";
    const std::string log_dir = root_ + "/specs_and_reports/v2/logs";
    const std::string evidence_dir = root_ + "/specs_and_reports/v2/evidence/C05";
    std::error_code ec;
    fs::create_directories(gate_dir, ec);
    fs::create_directories(log_dir, ec);
    fs::create_directories(evidence_dir, ec);

    const std::string tsv_path = gate_dir + "/C05-EVAL.tsv";
    const std::string log_path = log_dir + "/C05-EVAL.log";

    std::string tsv = "check\tcorpus\titem_id\tinput_sha256\texpected\tactual\tverdict\tlog\n";
    for (const Row& r : rows_) {
        tsv += r.check + "\t" + r.corpus + "\t" + r.item_id + "\t" + r.input_sha256 + "\t" +
               r.expected + "\t" + r.actual + "\t" + r.verdict + "\t" + r.log + "\n";
    }
    {
        std::ofstream out(tsv_path, std::ios::binary | std::ios::trunc);
        if (!out) return false;
        out.write(tsv.data(), static_cast<std::streamsize>(tsv.size()));
    }

    std::string log_text = environment_;
    for (const std::string& line : log_lines_) log_text += line + "\n";
    {
        std::ofstream out(log_path, std::ios::binary | std::ios::trunc);
        if (!out) return false;
        out.write(log_text.data(), static_cast<std::streamsize>(log_text.size()));
    }

    const std::string tsv_sha =
        sha_hex(std::span<const u8>(reinterpret_cast<const u8*>(tsv.data()), tsv.size()));
    const std::string log_sha = sha_hex(
        std::span<const u8>(reinterpret_cast<const u8*>(log_text.data()), log_text.size()));
    std::string sums;
    sums += tsv_sha + "  specs_and_reports/v2/gates/C05-EVAL.tsv\n";
    sums += log_sha + "  specs_and_reports/v2/logs/C05-EVAL.log\n";
    {
        std::ofstream out(evidence_dir + "/SHA256SUMS", std::ios::binary | std::ios::trunc);
        if (!out) return false;
        out.write(sums.data(), static_cast<std::streamsize>(sums.size()));
    }
    return true;
}

std::string environment_record(const std::string& root, const char* command_line) {
    std::string text;
    text += "tool: C05-EVAL evidence harness\n";
    text += "root: " + root + "\n";
    text += "command_line: " + std::string(command_line) + "\n";
    text += "compiler: " __VERSION__ "\n";
    text += "std: c++20 (build flags in engine/Makefile.c05)\n";
    return text;
}

int main(int argc, char** argv) {
    std::string root = ".";
    bool write_evidence = false;
    std::string command_line;
    for (int i = 0; i < argc; ++i) {
        if (i != 0) command_line.push_back(' ');
        command_line.append(argv[i]);
    }
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--root" && i + 1 < argc) {
            root = argv[++i];
        } else if (arg == "--write-evidence") {
            write_evidence = true;
        } else if (arg == "--help") {
            std::printf("usage: e2_c05_gate [--root PATH] [--write-evidence]\n");
            return 0;
        } else {
            std::fprintf(stderr, "unknown argument: %s\n", arg.c_str());
            return 2;
        }
    }
    Gate gate(root);
    gate.set_environment(environment_record(root, command_line.c_str()));
    const int rc = gate.run();
    if (!write_evidence) return rc;
    if (!gate.write_evidence()) {
        std::fprintf(stderr, "failed to write evidence\n");
        return 1;
    }
    return rc;
}

}  // namespace c05

int main(int argc, char** argv) { return c05::main(argc, argv); }
