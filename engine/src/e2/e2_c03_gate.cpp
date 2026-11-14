// C03 TERM — evidence harness.
//
// Builds the C03 corpus, runs every C03 obligation through the engine, compares
// against the independent reference implementation in c03_reference.hpp, and
// writes the evidence set:
//
//   specs_and_reports/v2/gates/C03-TERM.tsv
//   specs_and_reports/v2/logs/C03-TERM.log
//   specs_and_reports/v2/evidence/E2/SHA256SUMS
//
// Every measured value in the TSV is produced here; nothing is hand-edited.
// The TSV is environment-independent (no compiler, host, time, or path data),
// so a CI re-run must reproduce it byte for byte.  The log carries the
// environment record and is not byte-compared across machines.

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "c03_build.hpp"
#include "c03_reference.hpp"
#include "mapr/e1_sha256.hpp"
#include "mapr/e2/e2_term.hpp"

namespace {

using namespace marp::v2;  // NOLINT
using c03::Builder;
using c03::pattern;

constexpr u64 kMaterialiseCap = 1u << 20;

std::string hex_bytes(std::span<const u8> bytes) {
    static const char* digits = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (u8 byte : bytes) {
        out.push_back(digits[byte >> 4]);
        out.push_back(digits[byte & 0x0Fu]);
    }
    return out;
}

std::string hex_array(const std::array<u8, 32>& digest) {
    return hex_bytes(std::span<const u8>(digest.data(), digest.size()));
}

std::string sha_hex(std::span<const u8> bytes) {
    auto digest = mapr::Sha256::hash(std::string_view(
        reinterpret_cast<const char*>(bytes.data()), bytes.size()));
    return digest.ok() ? hex_array(digest.value()) : std::string("sha-error");
}

std::string sha_text(const std::string& text) {
    return sha_hex(std::span<const u8>(reinterpret_cast<const u8*>(text.data()), text.size()));
}

std::string describe(const Ir& ir) {
    // Deep/wide terms are described structurally without the exponential
    // pre-order key; the description only has to be deterministic, not minimal.
    if (ir.nodes.size() > 4096) {
        std::string text = "summary|nodes=" + std::to_string(ir.nodes.size());
        text += "|atoms=" + std::to_string(ir.atoms.size());
        text += "|len=" + ir.total_length.to_decimal();
        text += "|rootkind=" + std::string(kind_name(ir.nodes[ir.root].kind));
        std::array<std::size_t, kKindCount> histogram{};
        for (const Node& node : ir.nodes) {
            histogram[static_cast<std::size_t>(node.kind)] += 1;
        }
        for (std::size_t i = 0; i < kKindCount; ++i) {
            text += "|k" + std::to_string(i) + "=" + std::to_string(histogram[i]);
        }
        for (const Atom& atom : ir.atoms) text += ":" + hex_array(atom.sha256);
        return text;
    }
    std::string text = structural_key(ir, ir.root);
    text += "|len=";
    text += ir.total_length.to_decimal();
    text += "|nodes=" + std::to_string(ir.nodes.size());
    text += "|atoms=" + std::to_string(ir.atoms.size());
    for (const Atom& atom : ir.atoms) text += ":" + hex_array(atom.sha256);
    return text;
}

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

struct TermItem {
    std::string id;
    std::string corpus;
    std::unique_ptr<Builder> builder;
    Ir ir;
    bool materialisable = true;
};

struct BadCase {
    std::string id;
    std::string constraint;
    Code code = Code::Invalid;
    Limits limits{};
    std::function<Ir(Builder&)> build;
};

class Gate {
public:
    explicit Gate(std::string root) : root_(std::move(root)) {}

    int run();
    bool write_evidence();
    void set_environment(std::string text) { environment_ = std::move(text); }
    bool failed() const { return failures_ != 0; }

private:
    // --- evidence plumbing -------------------------------------------------
    void row(const std::string& check, const std::string& corpus, const std::string& id,
             const std::string& input_sha, const std::string& expected,
             const std::string& actual, bool pass, const std::string& log_ref);
    void log(const std::string& line) { log_lines_.push_back(line); }
    void section(const std::string& name, std::size_t pass, std::size_t total,
                 const std::string& extra = std::string());

    // --- corpus ------------------------------------------------------------
    void build_corpus();
    void build_bad_corpus();
    void add_term(const std::string& id, const std::string& corpus, bool materialisable,
                  const std::function<u32(Builder&)>& build);

    // --- checks ------------------------------------------------------------
    void run_wf_accept();
    void run_wf_reject();
    void run_denotation_and_length();
    void run_ranges();
    void run_big_terms();
    void run_morphs();
    void run_predictors();
    void run_lfsr();
    void run_stream_and_cursor();
    void run_stored_length_trust();
    void run_depth_limits();
    void run_determinism();
    void run_source_independence();
    void run_coverage();

    std::string root_;
    std::string environment_;
    std::vector<Row> rows_;
    std::vector<std::string> log_lines_;
    std::vector<TermItem> terms_;
    std::vector<std::unique_ptr<Builder>> bad_builders_;
    std::vector<BadCase> bad_cases_;
    std::size_t failures_ = 0;
    std::size_t passes_ = 0;
    std::array<std::size_t, kKindCount> kind_hits_{};
    std::array<std::size_t, kMorphCount + 1> morph_hits_{};
    std::array<std::size_t, kPredictorCount> predictor_hits_{};
};

void Gate::row(const std::string& check, const std::string& corpus, const std::string& id,
               const std::string& input_sha, const std::string& expected,
               const std::string& actual, bool pass, const std::string& log_ref) {
    Row r;
    r.check = check;
    r.corpus = corpus;
    r.item_id = id;
    r.input_sha256 = input_sha;
    r.expected = expected;
    r.actual = actual;
    r.verdict = pass ? "PASS" : "FAIL";
    r.log = log_ref;
    rows_.push_back(std::move(r));
    if (pass) {
        ++passes_;
    } else {
        ++failures_;
    }
}

void Gate::section(const std::string& name, std::size_t pass, std::size_t total,
                   const std::string& extra) {
    log(name + ": passed=" + std::to_string(pass) + "/" + std::to_string(total) +
        (extra.empty() ? std::string() : " " + extra));
}

void Gate::add_term(const std::string& id, const std::string& corpus, bool materialisable,
                    const std::function<u32(Builder&)>& build) {
    auto builder = std::make_unique<Builder>();
    const u32 root = build(*builder);
    Ir ir = builder->finish(root);
    kind_hits_[static_cast<std::size_t>(ir.nodes[root].kind)] += 1;
    terms_.push_back(TermItem{id, corpus, std::move(builder), ir, materialisable});
}

// ---------------------------------------------------------------------------
// Corpus
// ---------------------------------------------------------------------------

void Gate::build_corpus() {
    // --- one term per node kind, all pinned -------------------------------
    add_term("t-empty", "T-KAT", true, [](Builder& b) { return b.empty(); });
    add_term("t-atom1", "T-KAT", true,
             [](Builder& b) { return b.atom_node(b.add_atom({0xA5})); });
    add_term("t-atom16", "T-KAT", true, [](Builder& b) {
        return b.atom_node(b.add_atom(pattern(16, 3)));
    });
    add_term("t-atom32", "T-KAT", true, [](Builder& b) {
        return b.atom_node(b.add_atom(pattern(32, 9)));
    });
    add_term("t-zero0", "T-KAT", true, [](Builder& b) { return b.zero(0); });
    add_term("t-zero5", "T-KAT", true, [](Builder& b) { return b.zero(5); });
    add_term("t-concat2", "T-KAT", true, [](Builder& b) {
        return b.concat({b.atom_node(b.add_atom(pattern(16, 4))), b.zero(4)});
    });
    add_term("t-concat3", "T-KAT", true, [](Builder& b) {
        return b.concat({b.atom_node(b.add_atom(pattern(16, 5))),
                         b.atom_node(b.add_atom(pattern(31, 6))), b.zero(3)});
    });
    add_term("t-repeat-0-0", "T-KAT", true, [](Builder& b) {
        return b.repeat(b.atom_node(b.add_atom(pattern(16, 7))), 0, 0);
    });
    add_term("t-repeat-3-5", "T-KAT", true, [](Builder& b) {
        return b.repeat(b.atom_node(b.add_atom(pattern(16, 8))), 3, 5);
    });
    add_term("t-slice", "T-KAT", true, [](Builder& b) {
        return b.slice(b.atom_node(b.add_atom(pattern(31, 11))), 5, 9);
    });
    add_term("t-slice-full", "T-KAT", true, [](Builder& b) {
        return b.slice(b.atom_node(b.add_atom(pattern(16, 12))), 0, 16);
    });
    add_term("t-slice-empty", "T-KAT", true, [](Builder& b) {
        return b.slice(b.atom_node(b.add_atom(pattern(16, 13))), 16, 0);
    });
    // --- every morph id with valid k -------------------------------------
    for (u8 morph = 1; morph <= 9; ++morph) {
        const u8 k = (morph == 6 || morph == 7) ? 3 : 0;
        add_term("t-morph" + std::to_string(morph), "T-KAT", true,
                 [morph, k](Builder& b) {
                     return b.morph(b.atom_node(b.add_atom(pattern(32, morph))), morph, k);
                 });
    }
    add_term("t-xor", "T-KAT", true, [](Builder& b) {
        return b.xor_node(b.atom_node(b.add_atom(pattern(16, 20))),
                          b.atom_node(b.add_atom(pattern(16, 21))));
    });
    add_term("t-interleave-2-1", "T-KAT", true, [](Builder& b) {
        return b.interleave({b.atom_node(b.add_atom(pattern(8, 30))),
                             b.atom_node(b.add_atom(pattern(8, 31)))},
                            1);
    });
    add_term("t-interleave-2-2", "T-KAT", true, [](Builder& b) {
        return b.interleave({b.atom_node(b.add_atom(pattern(8, 32))),
                             b.atom_node(b.add_atom(pattern(8, 33)))},
                            2);
    });
    add_term("t-interleave-2-3-stride", "T-KAT", true, [](Builder& b) {
        return b.interleave({b.atom_node(b.add_atom(pattern(9, 34))),
                             b.atom_node(b.add_atom(pattern(9, 35)))},
                            3);
    });
    add_term("t-interleave-3-2", "T-KAT", true, [](Builder& b) {
        return b.interleave({b.atom_node(b.add_atom(pattern(8, 36))),
                             b.atom_node(b.add_atom(pattern(8, 37))),
                             b.atom_node(b.add_atom(pattern(8, 38)))},
                            2);
    });
    add_term("t-lfsr-a", "T-KAT", true, [](Builder& b) {
        return b.lfsr(0x80200003ull, 0x1ull, 17);
    });
    add_term("t-lfsr-b", "T-KAT", true, [](Builder& b) {
        return b.lfsr(0xD0080004ull, 0xDEADBEEFCAFEF00Dull, 64);
    });
    add_term("t-affine", "T-KAT", true, [](Builder& b) { return b.affine(3, 5, 40); });
    add_term("t-affine-wrap", "T-KAT", true, [](Builder& b) { return b.affine(250, 7, 300); });
    // --- every predictor id, including param edges -----------------------
    add_term("t-pred-0", "T-KAT", true, [](Builder& b) {
        return b.predictor(0, 0, b.atom_node(b.add_atom(pattern(32, 40))));
    });
    add_term("t-pred-1", "T-KAT", true, [](Builder& b) {
        return b.predictor(1, 0, b.atom_node(b.add_atom(pattern(32, 41))));
    });
    add_term("t-pred-2", "T-KAT", true, [](Builder& b) {
        return b.predictor(2, 0, b.atom_node(b.add_atom(pattern(32, 42))));
    });
    add_term("t-pred-3-p1", "T-KAT", true, [](Builder& b) {
        return b.predictor(3, 1, b.atom_node(b.add_atom(pattern(32, 43))));
    });
    add_term("t-pred-3-p5", "T-KAT", true, [](Builder& b) {
        return b.predictor(3, 5, b.atom_node(b.add_atom(pattern(32, 44))));
    });
    add_term("t-pred-4-p3", "T-KAT", true, [](Builder& b) {
        return b.predictor(4, 3, b.atom_node(b.add_atom(pattern(32, 45))));
    });
    add_term("t-pred-4-p64", "T-KAT", true, [](Builder& b) {
        return b.predictor(4, 64, b.atom_node(b.add_atom(pattern(32, 46))));
    });
    add_term("t-pred-1-n1", "T-KAT", true, [](Builder& b) {
        return b.predictor(1, 0, b.atom_node(b.add_atom({7})));
    });
    add_term("t-pred-2-n1", "T-KAT", true, [](Builder& b) {
        return b.predictor(2, 0, b.atom_node(b.add_atom({7})));
    });
    add_term("t-pred-2-n2", "T-KAT", true, [](Builder& b) {
        return b.predictor(2, 0, b.atom_node(b.add_atom({7, 200})));
    });
    // --- compositions ------------------------------------------------------
    add_term("t-nest-xor-slice-repeat", "T-KAT", true, [](Builder& b) {
        u32 rep = b.repeat(b.atom_node(b.add_atom(pattern(16, 50))), 3, 5);
        u32 sl = b.slice(rep, 7, 20);
        u32 other = b.atom_node(b.add_atom(pattern(20, 51)));
        return b.xor_node(sl, other);
    });
    add_term("t-nest-interleave-morph-lfsr", "T-KAT", true, [](Builder& b) {
        u32 m = b.morph(b.atom_node(b.add_atom(pattern(8, 52))), 6, 3);
        u32 l = b.lfsr(0x80000005ull, 0x1234ull, 8);
        return b.interleave({m, l}, 1);
    });
    add_term("t-nest-predictor-concat", "T-KAT", true, [](Builder& b) {
        u32 cat = b.concat({b.atom_node(b.add_atom(pattern(16, 53))), b.zero(16)});
        return b.predictor(4, 3, cat);
    });
    add_term("t-nest-morph-slice-xor", "T-KAT", true, [](Builder& b) {
        u32 x = b.xor_node(b.atom_node(b.add_atom(pattern(16, 54))),
                           b.atom_node(b.add_atom(pattern(16, 55))));
        u32 sl = b.slice(x, 2, 10);
        return b.morph(sl, 8, 0);
    });
    add_term("t-nest-repeat-concat-morph9", "T-KAT", true, [](Builder& b) {
        u32 cat = b.concat({b.atom_node(b.add_atom(pattern(8, 56))),
                            b.morph(b.atom_node(b.add_atom(pattern(8, 57))), 9, 0)});
        return b.repeat(cat, 2, 3);
    });
    add_term("t-deep-morph-chain", "T-KAT", true, [](Builder& b) {
        u32 node = b.atom_node(b.add_atom(pattern(8, 58)));
        for (int i = 0; i < 64; ++i) node = b.morph(node, 2, 0);
        return node;
    });
    // --- virtual terms (never materialised) -------------------------------
    add_term("t-big-repeat", "T-BIG", false, [](Builder& b) {
        auto q = BigInt(1).shl(60).value();
        return b.repeat(b.atom_node(b.add_atom(pattern(4, 60))), q, BigInt(3));
    });
    add_term("t-big-zero", "T-BIG", false, [](Builder& b) {
        return b.zero(BigInt(1).shl(62).value().add(BigInt(1)).value());
    });
    add_term("t-big-slice", "T-BIG", false, [](Builder& b) {
        auto z = b.zero(BigInt(1).shl(62).value().add(BigInt(5)).value());
        auto start = BigInt(1).shl(40).value().add(BigInt(7)).value();
        return b.slice(z, start, BigInt(100));
    });
    add_term("t-big-affine", "T-BIG", false, [](Builder& b) {
        auto n = BigInt(1).shl(40).value();
        u32 aff = b.affine(17, 0, n);
        auto start = BigInt(1).shl(39).value();
        return b.slice(aff, start, BigInt(64));
    });
    add_term("t-big-lfsr", "T-BIG", false, [](Builder& b) {
        auto n = BigInt(1).shl(40).value();
        u32 l = b.lfsr(0x80200003ull, 0x1ull, n);
        auto start = BigInt(1).shl(32).value().add(BigInt(5)).value();
        return b.slice(l, start, BigInt(64));
    });
}

void Gate::build_bad_corpus() {
    auto add = [&](const std::string& id, const std::string& constraint, Code code,
                   Limits limits, std::function<Ir(Builder&)> build) {
        BadCase c;
        c.id = id;
        c.constraint = constraint;
        c.code = code;
        c.limits = limits;
        c.build = std::move(build);
        bad_cases_.push_back(std::move(c));
    };

    const Limits tight_nodes{2, kMaxRecordsSpec, kMaxDepthSpec, true};

    add("bad-counts-nodes", kC_counts, Code::Invalid, tight_nodes, [](Builder& b) {
        return b.finish(b.concat({b.atom_node(b.add_atom(pattern(4, 1))), b.zero(1),
                                  b.zero(2), b.zero(3)}));
    });
    add("bad-atom-flags", kC_atom_flags, Code::Invalid, Limits{}, [](Builder& b) {
        u32 a = b.add_atom(pattern(4, 2));
        b.atom(a).flags = 1;
        return b.finish(b.atom_node(a));
    });
    add("bad-node-flags", kC_node_flags, Code::Invalid, Limits{}, [](Builder& b) {
        u32 a = b.add_atom(pattern(4, 3));
        u32 n = b.atom_node(a);
        b.node(n).flags = 1;
        return b.finish(n);
    });
    add("bad-atom-payload-length", kC_atom_payload, Code::Invalid, Limits{}, [](Builder& b) {
        u32 a = b.add_atom(pattern(4, 4));
        b.atom(a).length = BigInt(5);
        return b.finish(b.atom_node(a));
    });
    add("bad-root", kC_root, Code::Invalid, Limits{}, [](Builder& b) {
        u32 a = b.add_atom(pattern(4, 5));
        (void)b.atom_node(a);
        Ir ir = b.ir();
        ir.root = 9;
        return ir;
    });
    add("bad-no-nodes", kC_root, Code::Invalid, Limits{}, [](Builder&) { return Ir{}; });
    add("bad-unreachable-node", kC_reachable, Code::Invalid, Limits{}, [](Builder& b) {
        u32 root = b.atom_node(b.add_atom(pattern(4, 6)));
        (void)b.zero(3);  // appended after the root, never referenced
        return b.finish(root);
    });
    add("bad-unused-atom", kC_atom_unused, Code::Invalid, Limits{}, [](Builder& b) {
        u32 used = b.add_atom(pattern(4, 7));
        (void)b.add_atom(pattern(4, 8));
        return b.finish(b.atom_node(used));
    });
    add("bad-arg-range", kC_arg_range, Code::Invalid, Limits{}, [](Builder& b) {
        u32 z = b.zero(4);
        u32 cat = b.concat({z, z});
        b.node(cat).args[1] = 99;
        return b.finish(cat);
    });
    add("bad-arg-order", kC_arg_order, Code::Invalid, Limits{}, [](Builder& b) {
        u32 z = b.zero(4);
        u32 cat = b.concat({z, z});
        b.node(cat).args[0] = cat;
        return b.finish(cat);
    });
    add("bad-total-length", kC_total_length, Code::Invalid, Limits{}, [](Builder& b) {
        u32 z = b.zero(4);
        return b.finish_with_total(z, BigInt(5));
    });
    add("bad-stored-length-atom", kC_length, Code::Invalid, Limits{}, [](Builder& b) {
        u32 n = b.atom_node(b.add_atom(pattern(4, 9)));
        b.node(n).length = BigInt(5);
        return b.finish_with_total(n, BigInt(5));
    });
    add("bad-stored-length-zero", kC_length, Code::Invalid, Limits{}, [](Builder& b) {
        u32 n = b.zero(4);
        b.node(n).length = BigInt(3);
        return b.finish_with_total(n, BigInt(3));
    });
    add("bad-stored-length-concat", kC_length, Code::Invalid, Limits{}, [](Builder& b) {
        u32 cat = b.concat({b.zero(4), b.zero(5)});
        b.node(cat).length = BigInt(10);
        return b.finish_with_total(cat, BigInt(10));
    });
    add("bad-stored-length-repeat", kC_length, Code::Invalid, Limits{}, [](Builder& b) {
        u32 rep = b.repeat(b.zero(4), 3, 0);
        b.node(rep).length = BigInt(11);
        return b.finish_with_total(rep, BigInt(11));
    });
    add("bad-stored-length-slice", kC_length, Code::Invalid, Limits{}, [](Builder& b) {
        u32 z = b.zero(16);
        u32 sl = b.slice(z, 2, 4);
        b.node(sl).length = BigInt(5);
        return b.finish_with_total(sl, BigInt(5));
    });
    add("bad-stored-length-morph", kC_length, Code::Invalid, Limits{}, [](Builder& b) {
        u32 m = b.morph(b.zero(8), 2, 0);
        b.node(m).length = BigInt(9);
        return b.finish_with_total(m, BigInt(9));
    });
    add("bad-stored-length-xor", kC_length, Code::Invalid, Limits{}, [](Builder& b) {
        u32 x = b.xor_node(b.zero(8), b.zero(8));
        b.node(x).length = BigInt(7);
        return b.finish_with_total(x, BigInt(7));
    });
    add("bad-stored-length-interleave", kC_length, Code::Invalid, Limits{}, [](Builder& b) {
        u32 i = b.interleave({b.zero(4), b.zero(4)}, 2);
        b.node(i).length = BigInt(9);
        return b.finish_with_total(i, BigInt(9));
    });
    add("bad-stored-length-lfsr", kC_length, Code::Invalid, Limits{}, [](Builder& b) {
        u32 l = b.lfsr(0x80000001ull, 1, 8);
        b.node(l).length = BigInt(7);
        return b.finish_with_total(l, BigInt(7));
    });
    add("bad-stored-length-affine", kC_length, Code::Invalid, Limits{}, [](Builder& b) {
        u32 a = b.affine(1, 1, 8);
        b.node(a).length = BigInt(9);
        return b.finish_with_total(a, BigInt(9));
    });
    add("bad-stored-length-predictor", kC_length, Code::Invalid, Limits{}, [](Builder& b) {
        u32 p = b.predictor(1, 0, b.zero(8));
        b.node(p).length = BigInt(7);
        return b.finish_with_total(p, BigInt(7));
    });
    add("bad-depth", kC_depth, Code::Limit, Limits{}, [](Builder& b) {
        u32 node = b.atom_node(b.add_atom(pattern(1, 10)));
        for (u32 i = 0; i < kMaxDepthSpec; ++i) node = b.morph(node, 2, 0);
        return b.finish(node);
    });
    add("bad-output-cap", kC_output_cap, Code::Limit, Limits{}, [](Builder& b) {
        return b.finish(b.zero(BigInt(1).shl(63).value().add(BigInt(1)).value()));
    });

    // --- argc per kind -----------------------------------------------------
    auto argc_case = [](const std::string& id, std::function<void(Builder&, u32)> mutate) {
        BadCase c;
        c.id = id;
        c.constraint = kC_argc;
        c.code = Code::Invalid;
        c.build = [mutate](Builder& b) {
            u32 z = b.zero(2);
            u32 w = b.zero(3);
            u32 root = b.concat({z, w});
            mutate(b, root);
            return b.finish_with_total(root, b.node(root).length);
        };
        return c;
    };
    add("bad-argc-empty", kC_argc, Code::Invalid, Limits{}, [](Builder& b) {
        u32 a = b.atom_node(b.add_atom(pattern(2, 11)));
        u32 e = b.empty();
        b.node(e).args = {a};
        return b.finish(e);
    });
    add("bad-argc-atom", kC_argc, Code::Invalid, Limits{}, [](Builder& b) {
        u32 n0 = b.atom_node(b.add_atom(pattern(2, 12)));
        u32 bad = b.atom_node(b.add_atom(pattern(3, 13)));
        b.node(bad).args = {n0};
        return b.finish(bad);
    });
    add("bad-argc-zero", kC_argc, Code::Invalid, Limits{}, [](Builder& b) {
        u32 z = b.zero(2);
        u32 y = b.zero(3);
        b.node(y).args = {z};
        return b.finish(y);
    });
    add("bad-argc-concat", kC_argc, Code::Invalid, Limits{}, [](Builder& b) {
        u32 z = b.zero(2);
        u32 bad = b.concat({z});       // argc 1
        u32 root = b.concat({bad, z}); // keeps z reachable
        (void)root;
        return b.finish(root);
    });
    add("bad-argc-repeat", kC_argc, Code::Invalid, Limits{}, [](Builder& b) {
        u32 z = b.zero(2);
        u32 w = b.zero(3);
        u32 rep = b.repeat(z, 1, 0);
        b.node(rep).args = {z, w};
        return b.finish(rep);
    });
    add("bad-argc-slice", kC_argc, Code::Invalid, Limits{}, [](Builder& b) {
        u32 z = b.zero(4);
        u32 sl = b.slice(z, 1, 2);
        b.node(sl).args.clear();
        return b.finish(b.concat({sl, z}));
    });
    add("bad-argc-morph", kC_argc, Code::Invalid, Limits{}, [](Builder& b) {
        u32 z = b.zero(4);
        u32 m = b.morph(z, 2, 0);
        b.node(m).args.clear();
        return b.finish(b.concat({m, z}));
    });
    add("bad-argc-xor", kC_argc, Code::Invalid, Limits{}, [](Builder& b) {
        u32 z = b.zero(4);
        u32 x = b.xor_node(z, z);
        b.node(x).args = {z};
        return b.finish(x);
    });
    add("bad-argc-interleave", kC_argc, Code::Invalid, Limits{}, [](Builder& b) {
        u32 z = b.zero(4);
        u32 w = b.zero(4);
        u32 i = b.interleave({z, w}, 2);
        b.node(i).args.clear();
        return b.finish(b.concat({i, z, w}));
    });
    add("bad-argc-lfsr", kC_argc, Code::Invalid, Limits{}, [](Builder& b) {
        u32 z = b.zero(4);
        u32 l = b.lfsr(0x80000001ull, 1, 4);
        b.node(l).args = {z};
        return b.finish(l);
    });
    add("bad-argc-affine", kC_argc, Code::Invalid, Limits{}, [](Builder& b) {
        u32 z = b.zero(4);
        u32 a = b.affine(1, 1, 4);
        b.node(a).args = {z};
        return b.finish(a);
    });
    add("bad-argc-predictor", kC_argc, Code::Invalid, Limits{}, [](Builder& b) {
        u32 z = b.zero(4);
        u32 p = b.predictor(1, 0, z);
        b.node(p).args.clear();
        return b.finish(b.concat({p, z}));
    });
    (void)argc_case;

    // --- kind-specific constraints -----------------------------------------
    add("bad-atom-id", kC_atom_id, Code::Invalid, Limits{}, [](Builder& b) {
        const u32 atom = b.add_atom(pattern(4, 20));
        const u32 good = b.atom_node(atom);
        const u32 bad = b.atom_node(atom);
        b.node(bad).a = BigInt(5);
        return b.finish(b.concat({good, bad}));
    });
    add("bad-atom-zero-length", kC_atom_len, Code::Invalid, Limits{}, [](Builder& b) {
        u32 a = b.add_atom(std::span<const u8>());
        return b.finish(b.atom_node(a));
    });
    add("bad-repeat-q0-r7", kC_repeat, Code::Invalid, Limits{}, [](Builder& b) {
        return b.finish(b.repeat(b.atom_node(b.add_atom(pattern(16, 14))), 0, 7));
    });
    add("bad-repeat-q0-r5", kC_repeat, Code::Invalid, Limits{}, [](Builder& b) {
        u32 z = b.zero(4);
        u32 rep = b.repeat(z, 0, 0);
        b.node(rep).b = BigInt(5);
        b.node(rep).length = BigInt(5);
        return b.finish_with_total(rep, BigInt(5));
    });
    add("bad-repeat-r-eq-len", kC_repeat, Code::Invalid, Limits{}, [](Builder& b) {
        u32 z = b.zero(4);
        u32 rep = b.repeat(z, 2, 0);
        b.node(rep).b = BigInt(4);
        b.node(rep).length = BigInt(12);
        return b.finish_with_total(rep, BigInt(12));
    });
    add("bad-slice-start-past-end", kC_slice, Code::Invalid, Limits{}, [](Builder& b) {
        u32 z = b.zero(4);
        u32 sl = b.slice(z, 0, 0);
        b.node(sl).a = BigInt(5);
        b.node(sl).b = BigInt(0);
        b.node(sl).length = BigInt(0);
        return b.finish(sl);
    });
    add("bad-slice-overrun", kC_slice, Code::Invalid, Limits{}, [](Builder& b) {
        u32 z = b.zero(4);
        u32 sl = b.slice(z, 0, 0);
        b.node(sl).a = BigInt(2);
        b.node(sl).b = BigInt(3);
        b.node(sl).length = BigInt(3);
        return b.finish_with_total(sl, BigInt(3));
    });
    add("bad-morph-id0", kC_morph, Code::Invalid, Limits{}, [](Builder& b) {
        u32 m = b.morph(b.zero(8), 2, 0);
        b.node(m).morph = 0;
        return b.finish(m);
    });
    add("bad-morph-id10", kC_morph, Code::Invalid, Limits{}, [](Builder& b) {
        u32 m = b.morph(b.zero(8), 2, 0);
        b.node(m).morph = 10;
        return b.finish(m);
    });
    add("bad-morph-k-bitrev", kC_morph, Code::Invalid, Limits{}, [](Builder& b) {
        u32 m = b.morph(b.zero(8), 1, 0);
        b.node(m).morph_k = 1;
        return b.finish(m);
    });
    add("bad-morph-rotl-k0", kC_morph, Code::Invalid, Limits{}, [](Builder& b) {
        u32 m = b.morph(b.zero(8), 6, 3);
        b.node(m).morph_k = 0;
        return b.finish(m);
    });
    add("bad-morph-rotl-k8", kC_morph, Code::Invalid, Limits{}, [](Builder& b) {
        u32 m = b.morph(b.zero(8), 6, 3);
        b.node(m).morph_k = 8;
        return b.finish(m);
    });
    add("bad-morph-rotr-k0", kC_morph, Code::Invalid, Limits{}, [](Builder& b) {
        u32 m = b.morph(b.zero(8), 7, 3);
        b.node(m).morph_k = 0;
        return b.finish(m);
    });
    add("bad-morph-swap16-odd", kC_morph, Code::Invalid, Limits{}, [](Builder& b) {
        return b.finish(b.morph(b.zero(5), 3, 0));
    });
    add("bad-morph-swap32-mod4", kC_morph, Code::Invalid, Limits{}, [](Builder& b) {
        return b.finish(b.morph(b.zero(6), 4, 0));
    });
    add("bad-morph-swap64-mod8", kC_morph, Code::Invalid, Limits{}, [](Builder& b) {
        return b.finish(b.morph(b.zero(12), 5, 0));
    });
    add("bad-xor-length", kC_xor, Code::Invalid, Limits{}, [](Builder& b) {
        return b.finish(b.xor_node(b.zero(4), b.zero(5)));
    });
    add("bad-interleave-length", kC_interleave, Code::Invalid, Limits{}, [](Builder& b) {
        return b.finish(b.interleave({b.zero(8), b.zero(9)}, 1));
    });
    add("bad-interleave-stride0", kC_interleave, Code::Invalid, Limits{}, [](Builder& b) {
        return b.finish(b.interleave({b.zero(8), b.zero(8)}, 0));
    });
    add("bad-interleave-mod", kC_interleave, Code::Invalid, Limits{}, [](Builder& b) {
        return b.finish(b.interleave({b.zero(10), b.zero(10)}, 3));
    });
    add("bad-interleave-stride-big", kC_interleave, Code::Invalid, Limits{}, [](Builder& b) {
        u32 i = b.interleave({b.zero(8), b.zero(8)}, 1);
        b.node(i).a = BigInt(1).shl(40).value();
        return b.finish(i);
    });
    add("bad-lfsr-conn0", kC_lfsr, Code::Invalid, Limits{}, [](Builder& b) {
        u32 l = b.lfsr(0x80000001ull, 1, 8);
        b.node(l).lfsr_conn = 0;
        return b.finish(l);
    });
    add("bad-predictor-pid5", kC_predictor, Code::Invalid, Limits{}, [](Builder& b) {
        u32 p = b.predictor(1, 0, b.zero(8));
        b.node(p).predictor_id = 5;
        return b.finish(p);
    });
    add("bad-predictor-p3-param0", kC_predictor, Code::Invalid, Limits{}, [](Builder& b) {
        u32 p = b.predictor(3, 2, b.zero(8));
        b.node(p).predictor_param = 0;
        return b.finish(p);
    });
    add("bad-predictor-p4-param0", kC_predictor, Code::Invalid, Limits{}, [](Builder& b) {
        u32 p = b.predictor(4, 2, b.zero(8));
        b.node(p).predictor_param = 0;
        return b.finish(p);
    });
}

// ---------------------------------------------------------------------------
// Checks
// ---------------------------------------------------------------------------

void Gate::run_wf_accept() {
    std::size_t pass = 0;
    for (const TermItem& item : terms_) {
        const WfReport report = check_well_formed_report(item.ir);
        const std::string actual = report.ok()
                                       ? std::string("Ok")
                                       : std::string(code_name(report.code)) + ":" +
                                             report.constraint;
        row("wf.accept", item.corpus, item.id, sha_text(describe(item.ir)), "Ok", actual,
            report.ok(), item.id);
        if (report.ok()) ++pass;
        log("wf.accept " + item.id + ": " + actual + " nodes=" +
            std::to_string(item.ir.nodes.size()) + " len=" +
            item.ir.total_length.to_decimal());
    }
    section("wf.accept", pass, terms_.size());
}

void Gate::run_wf_reject() {
    std::size_t pass = 0;
    for (const BadCase& bad : bad_cases_) {
        auto builder = std::make_unique<Builder>();
        Ir ir = bad.build(*builder);
        const WfReport report = check_well_formed_report(ir, bad.limits);
        const std::string expected =
            std::string(code_name(bad.code)) + ":" + bad.constraint;
        const std::string actual = report.ok()
                                       ? std::string("Ok")
                                       : std::string(code_name(report.code)) + ":" +
                                             report.constraint;
        const bool ok = (actual == expected);
        row("wf.reject", "T-BAD", bad.id, sha_text(describe(ir)), expected, actual, ok,
            bad.id);
        if (ok) ++pass;
        log("wf.reject " + bad.id + ": expected " + expected + " actual " + actual +
            (report.message.empty() ? std::string() : " (" + report.message + ")"));
        bad_builders_.push_back(std::move(builder));
    }
    section("wf.reject", pass, bad_cases_.size());
}

void Gate::run_denotation_and_length() {
    std::size_t pass = 0;
    std::size_t total = 0;
    for (const TermItem& item : terms_) {
        if (!item.materialisable) continue;
        ++total;
        std::vector<u8> reference;
        const bool ref_ok = c03ref::ref_denote(item.ir, item.ir.root, reference,
                                               kMaterialiseCap);
        auto engine = denote_node(item.ir, item.ir.root, kMaterialiseCap);
        const std::string expected = ref_ok ? sha_hex(reference) : "reference-error";
        const std::string actual =
            engine.ok() ? sha_hex(engine.value()) : std::string(code_name(engine.code()));
        const bool ok = ref_ok && engine.ok() && engine.value() == reference;
        row("denotation", item.corpus, item.id, sha_text(describe(item.ir)), expected,
            actual, ok, item.id);
        if (ok) ++pass;
        log("denotation " + item.id + ": expected=" + expected + " actual=" + actual +
            " bytes=" + std::to_string(engine.ok() ? engine.value().size() : 0));

        // |⟦t⟧| == ℓ(t): recomputed length, reference length and denotation size.
        auto lengths = recompute_lengths_checked(item.ir);
        BigInt ref_len;
        const bool ref_len_ok = c03ref::ref_length(item.ir, item.ir.root, ref_len);
        std::string length_actual = "recompute-error";
        bool length_ok = false;
        if (lengths.ok() && ref_len_ok) {
            length_actual = lengths.value()[item.ir.root].to_decimal();
            length_ok = length_actual == ref_len.to_decimal() &&
                        ref_len.compare(BigInt(static_cast<u64>(reference.size()))) == 0 &&
                        lengths.value()[item.ir.root].compare(
                            BigInt(static_cast<u64>(reference.size()))) == 0;
        }
        row("length", item.corpus, item.id, sha_text(describe(item.ir)), ref_len.to_decimal(),
            length_actual, length_ok, item.id);
        if (length_ok) ++pass;
        log("length " + item.id + ": reference=" + ref_len.to_decimal() +
            " engine=" + length_actual + " denotation=" +
            std::to_string(reference.size()));
        ++total;
    }
    section("denotation+length", pass, total, "(denotation and length rows)");
}

void Gate::run_ranges() {
    std::size_t pass = 0;
    std::size_t total = 0;
    for (const TermItem& item : terms_) {
        if (!item.materialisable) continue;
        std::vector<u8> full;
        if (!c03ref::ref_denote(item.ir, item.ir.root, full, kMaterialiseCap)) continue;
        const std::size_t n = full.size();

        struct Range {
            std::size_t start;
            std::size_t len;
            std::string tag;
        };
        std::vector<Range> ranges;
        ranges.push_back({0, 0, "r0"});
        ranges.push_back({0, n >= 1 ? 1u : 0u, "r1"});
        if (n >= 1) ranges.push_back({n - 1, 1, "r2"});
        ranges.push_back({n / 2, std::min<std::size_t>(4096, n - n / 2), "r3"});
        ranges.push_back({0, n, "r4"});
        // eight deterministic pseudo-random ranges
        u64 seed = 0x9E3779B97F4A7C15ull;
        for (int i = 0; i < 8; ++i) {
            seed = seed * 6364136223846793005ull + 1442695040888963407ull;
            const std::size_t start = (n == 0) ? 0 : static_cast<std::size_t>(seed % n);
            const std::size_t max_len = n - start;
            const std::size_t len = (max_len == 0)
                                        ? 0
                                        : static_cast<std::size_t>((seed >> 17) % (max_len + 1));
            ranges.push_back({start, len, "g" + std::to_string(i)});
        }
        for (const Range& r : ranges) {
            ++total;
            std::vector<u8> out(r.len, 0xEE);
            auto result = read_range(item.ir, item.ir.root, BigInt(static_cast<u64>(r.start)),
                                     out);
            const std::vector<u8> expected_bytes(
                full.begin() + static_cast<std::ptrdiff_t>(r.start),
                full.begin() + static_cast<std::ptrdiff_t>(r.start + r.len));
            const std::string expected = sha_hex(expected_bytes);
            const std::string actual = result.ok() ? sha_hex(out)
                                                   : std::string(code_name(result.code()));
            const bool ok = result.ok() && out == expected_bytes &&
                            result.value() == r.len;
            row("range", item.corpus, item.id + "#" + r.tag, sha_text(describe(item.ir)),
                expected, actual, ok, item.id + "#" + r.tag);
            if (ok) ++pass;
            else {
                log("range FAIL " + item.id + "#" + r.tag + " start=" +
                    std::to_string(r.start) + " len=" + std::to_string(r.len) +
                    " expected=" + expected + " actual=" + actual);
            }
        }
    }
    section("range", pass, total);
}

void Gate::run_big_terms() {
    std::size_t pass = 0;
    std::size_t total = 0;
    for (const TermItem& item : terms_) {
        if (item.materialisable) continue;
        const Node& root = item.ir.nodes[item.ir.root];
        auto lengths = recompute_lengths_checked(item.ir);
        BigInt ref_len;
        const bool ref_ok = c03ref::ref_length(item.ir, item.ir.root, ref_len);
        ++total;
        const bool len_ok = lengths.ok() && ref_ok &&
                            lengths.value()[item.ir.root].compare(ref_len) == 0;
        row("length.big", item.corpus, item.id, sha_text(describe(item.ir)),
            ref_len.to_decimal(),
            lengths.ok() ? lengths.value()[item.ir.root].to_decimal()
                         : std::string(code_name(lengths.code())),
            len_ok, item.id);
        if (len_ok) ++pass;
        log("length.big " + item.id + ": reference=" + ref_len.to_decimal() + " engine=" +
            (lengths.ok() ? lengths.value()[item.ir.root].to_decimal()
                          : std::string(code_name(lengths.code()))));

        // Sampled ranges at offsets above 2^32, checked analytically.
        const std::size_t count = 64;
        std::optional<u64> len_u64;
        if (lengths.ok()) {
            len_u64 = lengths.value()[item.ir.root].to_u64_checked();
        }
        std::vector<u64> starts;
        const u64 candidates[] = {0, 1, (u64{1} << 32), (u64{1} << 32) + 1, (u64{1} << 39)};
        for (u64 candidate : candidates) {
            if (len_u64.has_value() &&
                candidate + count <= len_u64.value()) {
                starts.push_back(candidate);
            }
        }
        if (len_u64.has_value() && len_u64.value() > count) {
            starts.push_back(len_u64.value() - count);
        }
        for (u64 start : starts) {
            ++total;
            std::vector<u8> out(count, 0xEE);
            auto result = read_range(item.ir, item.ir.root, BigInt(start), out);
            std::vector<u8> expected(count, 0);
            bool expected_ok = true;
            if (root.kind == Kind::Lfsr) {
                u64 state = 0;
                expected_ok = c03ref::ref_lfsr_state_at_bits(root.lfsr_conn, root.lfsr_init,
                                                             start * 8, state) &&
                              c03ref::ref_lfsr_from_state(root.lfsr_conn, state, count,
                                                          expected);
            } else if (root.kind == Kind::Affine) {
                for (std::size_t i = 0; i < count; ++i) {
                    const unsigned v = static_cast<unsigned>(root.affine_start) +
                                       static_cast<unsigned>((start + i) % 256) *
                                           static_cast<unsigned>(root.affine_step);
                    expected[i] = static_cast<u8>(v & 0xFFu);
                }
            } else if (root.kind == Kind::Slice) {
                // Slice(Zero|Affine|Lfsr, s, l): the child offset is s + start.
                const Node& child = item.ir.nodes[root.args[0]];
                const BigInt child_offset = root.a.add(BigInt(start)).value();
                auto off_u64 = child_offset.to_u64_checked();
                if (!off_u64.has_value()) {
                    expected_ok = false;
                } else if (child.kind == Kind::Zero) {
                    expected.assign(count, 0);
                } else if (child.kind == Kind::Affine) {
                    for (std::size_t i = 0; i < count; ++i) {
                        const unsigned v = static_cast<unsigned>(child.affine_start) +
                                           static_cast<unsigned>((*off_u64 + i) % 256) *
                                               static_cast<unsigned>(child.affine_step);
                        expected[i] = static_cast<u8>(v & 0xFFu);
                    }
                } else if (child.kind == Kind::Lfsr) {
                    u64 state = 0;
                    expected_ok = c03ref::ref_lfsr_state_at_bits(
                                      child.lfsr_conn, child.lfsr_init, *off_u64 * 8, state) &&
                                  c03ref::ref_lfsr_from_state(child.lfsr_conn, state, count,
                                                              expected);
                } else {
                    expected_ok = false;
                }
            } else if (root.kind == Kind::Repeat) {
                // Repeat(atom(p), q, r): byte at offset s is payload[s mod p].
                const Node& child = item.ir.nodes[root.args[0]];
                const Atom& atom = item.ir.atoms[static_cast<std::size_t>(
                    child.a.to_u64_checked().value())];
                const std::size_t p = atom.payload.size();
                for (std::size_t i = 0; i < count; ++i) {
                    expected[i] = atom.payload[static_cast<std::size_t>(
                        (start + i) % static_cast<u64>(p))];
                }
            } else if (root.kind == Kind::Zero) {
                expected.assign(count, 0);
            } else {
                expected_ok = false;
            }
            const std::string expected_sha = expected_ok ? sha_hex(expected) : "reference-error";
            const std::string actual = result.ok() ? sha_hex(out)
                                                   : std::string(code_name(result.code()));
            const bool ok = expected_ok && result.ok() && out == expected;
            row("range.big", item.corpus, item.id + "#" + std::to_string(start),
                sha_text(describe(item.ir)), expected_sha, actual, ok,
                item.id + "#" + std::to_string(start));
            if (ok) ++pass;
            else {
                log("range.big FAIL " + item.id + " start=" + std::to_string(start) +
                    " expected=" + expected_sha + " actual=" + actual);
            }
        }
        // Range calls above the declared length must be rejected.
        ++total;
        {
            std::vector<u8> out(4, 0);
            auto beyond = read_range(item.ir, item.ir.root,
                                     ref_len.add(BigInt(1)).value(), out);
            const bool ok = !beyond.ok();
            row("range.beyond", item.corpus, item.id, sha_text(describe(item.ir)), "Invalid",
                beyond.ok() ? "Ok" : std::string(code_name(beyond.code())), ok, item.id);
            if (ok) ++pass;
        }
    }
    section("big terms (length + range)", pass, total);
}

void Gate::run_morphs() {
    std::size_t pass = 0;
    std::size_t total = 0;
    const std::vector<u8> input = pattern(64, 77);

    auto kat = [&](u8 morph, u8 k) {
        ++total;
        std::vector<u8> engine = input;
        std::vector<u8> reference = input;
        const Status engine_st = apply_morph_to_buffer(morph, k, engine);
        const bool ref_ok = c03ref::ref_morph(morph, k, reference);
        const std::string id = std::string("morph") + std::to_string(morph) + "-k" +
                               std::to_string(k);
        const std::string expected = ref_ok ? sha_hex(reference) : "reference-error";
        const std::string actual =
            engine_st.ok() ? sha_hex(engine) : std::string(code_name(engine_st.code()));
        const bool ok = ref_ok && engine_st.ok() && engine == reference;
        row("morph.kat", "M-KAT", id, sha_hex(input), expected, actual, ok, id);
        if (ok) ++pass;
        else log("morph.kat FAIL " + id + " expected=" + expected + " actual=" + actual);
        morph_hits_[morph] += 1;
    };

    for (u8 morph = 1; morph <= 9; ++morph) {
        if (morph == 6 || morph == 7) {
            for (u8 k = 1; k <= 7; ++k) kat(morph, k);
        } else {
            kat(morph, 0);
        }
    }

    // Involutions: m(m(x)) = x.  §3.4 declares 1,2,3,4,5,8,9 involutive.
    for (u8 morph : {u8{1}, u8{2}, u8{3}, u8{4}, u8{5}, u8{8}, u8{9}}) {
        ++total;
        std::vector<u8> bytes = input;
        const Status first = apply_morph_to_buffer(morph, 0, bytes);
        const Status second = apply_morph_to_buffer(morph, 0, bytes);
        const bool ok = first.ok() && second.ok() && bytes == input;
        const std::string id = std::string("morph") + std::to_string(morph) + "-involution";
        row("morph.involution", "M-KAT", id, sha_hex(input), sha_hex(input),
            ok ? sha_hex(bytes) : "mismatch", ok, id);
        if (ok) ++pass;
        else log("morph.involution FAIL " + id);
    }

    // Rotation composition: ROTL(a) then ROTL(b) == ROTL((a+b) mod 8).
    for (u8 a = 1; a <= 7; ++a) {
        for (u8 b = 1; b <= 7; ++b) {
            ++total;
            std::vector<u8> bytes = input;
            const Status f = apply_morph_to_buffer(6, a, bytes);
            const Status s = apply_morph_to_buffer(6, b, bytes);
            std::vector<u8> expected_bytes = input;
            const u8 sum = static_cast<u8>((a + b) % 8);
            const Status e = (sum == 0) ? Status{} : apply_morph_to_buffer(6, sum, expected_bytes);
            const bool ok = f.ok() && s.ok() && e.ok() && bytes == expected_bytes;
            const std::string id = "rotl" + std::to_string(a) + "+" + std::to_string(b);
            row("morph.compose", "M-KAT", id, sha_hex(input), sha_hex(expected_bytes),
                ok ? sha_hex(bytes) : "mismatch", ok, id);
            if (ok) ++pass;
            else log("morph.compose FAIL " + id);
        }
    }

    // Closed catalogue rejections.
    struct Reject {
        u8 morph;
        u8 k;
        std::size_t len;
        const char* tag;
    };
    const Reject rejects[] = {
        {0, 0, 8, "morph0"},    {10, 0, 8, "morph10"},  {1, 1, 8, "bitrev-k1"},
        {2, 3, 8, "invert-k3"}, {3, 0, 5, "swap16-odd"}, {4, 0, 6, "swap32-mod4"},
        {5, 0, 12, "swap64-mod8"}, {6, 0, 8, "rotl-k0"}, {6, 8, 8, "rotl-k8"},
        {7, 0, 8, "rotr-k0"},   {7, 8, 8, "rotr-k8"},    {8, 1, 8, "reverse-bytes-k1"},
    };
    for (const Reject& r : rejects) {
        ++total;
        std::vector<u8> bytes(r.len, 0x5A);
        const Status st = apply_morph_to_buffer(r.morph, r.k, bytes);
        const std::string id = r.tag;
        row("morph.reject", "M-KAT", id, sha_hex(std::span<const u8>(bytes)), "Invalid",
            st.ok() ? "Ok" : std::string(code_name(st.code())), !st.ok(), id);
        if (!st.ok()) ++pass;
        else log("morph.reject FAIL " + id);
    }
    // apply_morph_byte is byte-local only; checked form rejects the rest.
    for (u8 morph : {u8{1}, u8{2}, u8{6}, u8{7}}) {
        ++total;
        const u8 in = 0x96;
        auto engine = apply_morph_byte_checked(morph, morph == 6 || morph == 7 ? 3 : 0, in);
        std::vector<u8> buf{in};
        const bool ref_ok = c03ref::ref_morph(morph, morph == 6 || morph == 7 ? 3 : 0, buf);
        const bool ok = engine.ok() && ref_ok && buf[0] == engine.value();
        const std::string id = "byte-" + std::to_string(morph);
        row("morph.byte", "M-KAT", id, sha_hex(std::span<const u8>(&in, 1)),
            ref_ok ? hex_bytes(std::span<const u8>(buf.data(), 1)) : "reference-error",
            engine.ok() ? hex_bytes(std::span<const u8>(&engine.value(), 1))
                        : std::string(code_name(engine.code())),
            ok, id);
        if (ok) ++pass;
        else log("morph.byte FAIL " + id);
    }
    for (u8 morph : {u8{3}, u8{4}, u8{5}, u8{8}, u8{9}, u8{0}, u8{12}}) {
        ++total;
        const u8 in = 0x11;
        auto engine = apply_morph_byte_checked(morph, 0, in);
        const std::string id = "byte-nonlocal-" + std::to_string(morph);
        row("morph.byte", "M-KAT", id, sha_hex(std::span<const u8>(&in, 1)), "Invalid",
            engine.ok() ? "Ok" : std::string(code_name(engine.code())), !engine.ok(), id);
        if (!engine.ok()) ++pass;
        else log("morph.byte FAIL " + id);
    }
    section("morph", pass, total);
}

void Gate::run_predictors() {
    std::size_t pass = 0;
    std::size_t total = 0;
    const std::vector<u8> residual = pattern(64, 91);

    struct Case {
        u8 pid;
        u32 param;
        const char* tag;
    };
    const Case cases[] = {
        {0, 0, "pred0"},      {1, 0, "pred1"},      {2, 0, "pred2"},
        {3, 1, "pred3-p1"},   {3, 2, "pred3-p2"},   {3, 5, "pred3-p5"},
        {3, 64, "pred3-p64"}, {3, 65, "pred3-p65"}, {4, 1, "pred4-p1"},
        {4, 3, "pred4-p3"},   {4, 7, "pred4-p7"},   {4, 64, "pred4-p64"},
        {4, 2000, "pred4-p2000"},
    };
    for (const Case& c : cases) {
        ++total;
        std::vector<u8> engine(residual.size(), 0);
        std::vector<u8> reference;
        const Status st = apply_predictor_to_buffer(c.pid, c.param, residual, engine);
        const bool ref_ok = c03ref::ref_predictor(c.pid, c.param, residual, reference);
        const std::string id = c.tag;
        const std::string expected = ref_ok ? sha_hex(reference) : "reference-error";
        const std::string actual =
            st.ok() ? sha_hex(engine) : std::string(code_name(st.code()));
        const bool ok = ref_ok && st.ok() && engine == reference;
        row("predictor.kat", "M-KAT", id, sha_hex(residual), expected, actual, ok, id);
        if (ok) ++pass;
        else log("predictor.kat FAIL " + id + " expected=" + expected + " actual=" + actual);
        predictor_hits_[c.pid] += 1;
    }

    // Short residuals: reconstruction must match the §4.11 seeding rules.
    for (std::size_t n = 0; n <= 4; ++n) {
        for (u8 pid = 0; pid <= 2; ++pid) {
            ++total;
            std::vector<u8> small(residual.begin(),
                                  residual.begin() + static_cast<std::ptrdiff_t>(n));
            std::vector<u8> engine(n, 0);
            std::vector<u8> reference;
            const Status st = apply_predictor_to_buffer(pid, 0, small, engine);
            const bool ref_ok = c03ref::ref_predictor(pid, 0, small, reference);
            const std::string id = "pred" + std::to_string(pid) + "-n" + std::to_string(n);
            const bool ok = st.ok() && ref_ok && engine == reference;
            row("predictor.short", "M-KAT", id, sha_hex(small),
                ref_ok ? sha_hex(reference) : "reference-error",
                st.ok() ? sha_hex(engine) : std::string(code_name(st.code())), ok, id);
            if (ok) ++pass;
            else log("predictor.short FAIL " + id);
        }
    }

    // Closed catalogue rejections and the step primitive.
    struct Reject {
        u8 pid;
        u32 param;
        const char* tag;
    };
    const Reject rejects[] = {{5, 0, "pid5"}, {9, 1, "pid9"}, {3, 0, "p3-param0"},
                              {4, 0, "p4-param0"}};
    for (const Reject& r : rejects) {
        ++total;
        std::vector<u8> out(residual.size(), 0);
        const Status st = apply_predictor_to_buffer(r.pid, r.param, residual, out);
        const std::string id = r.tag;
        row("predictor.reject", "M-KAT", id, sha_hex(residual), "Invalid",
            st.ok() ? "Ok" : std::string(code_name(st.code())), !st.ok(), id);
        if (!st.ok()) ++pass;
        else log("predictor.reject FAIL " + id);
    }
    {
        ++total;
        auto step = apply_predictor_step_checked(0, 0, 3, 250, 0);
        const bool ok = step.ok() && step.value() == 253;
        row("predictor.step", "M-KAT", "delta8-wrap", "n/a", "253",
            step.ok() ? std::to_string(step.value()) : std::string(code_name(step.code())), ok,
            "delta8-wrap");
        if (ok) ++pass;
        else log("predictor.step FAIL delta8-wrap");
    }
    {
        ++total;
        // pid 2 follows the literal §4.11 formula: residual bytes are unused at
        // i >= 2, which is the inherited H3 §7 defect recorded in the report.
        auto step = apply_predictor_step_checked(2, 0, 99, 10, 4);
        const bool ok = step.ok() && step.value() == 16;
        row("predictor.step", "M-KAT", "linear2-literal", "n/a", "16",
            step.ok() ? std::to_string(step.value()) : std::string(code_name(step.code())), ok,
            "linear2-literal");
        if (ok) ++pass;
        else log("predictor.step FAIL linear2-literal");
    }
    {
        ++total;
        auto step = apply_predictor_step_checked(3, 4, 1, 0, 0);
        const bool ok = step.ok() && step.value() == 1;
        row("predictor.step", "M-KAT", "stride-xor-seed", "n/a", "1",
            step.ok() ? std::to_string(step.value()) : std::string(code_name(step.code())), ok,
            "stride-xor-seed");
        if (ok) ++pass;
        else log("predictor.step FAIL stride-xor-seed");
    }
    section("predictor", pass, total);
}

void Gate::run_lfsr() {
    std::size_t pass = 0;
    std::size_t total = 0;
    struct Pair {
        u64 conn;
        u64 init;
    };
    const Pair pairs[] = {
        {0x80200003ull, 0x1ull},
        {0xD0080004ull, 0xDEADBEEFCAFEF00Dull},
        {0x8000000000000001ull, 0ull},
        {0xFFFFFFFFFFFFFFFFull, 0xFFFFFFFFFFFFFFFFull},
        {0x1ull, 0x8000000000000000ull},
        {0x80000005ull, 0x1234ull},
    };
    const std::size_t lengths[] = {1, 7, 8, 9, 64, 65, 129};
    for (const Pair& p : pairs) {
        for (std::size_t len : lengths) {
            ++total;
            std::vector<u8> engine(len, 0);
            const Status st = lfsr_read_range(p.conn, p.init, BigInt::zero(), engine);
            std::vector<u8> reference;
            const bool ref_ok = c03ref::ref_lfsr_bytes(p.conn, p.init, len, reference);
            const std::string id = "lfsr-" + std::to_string(p.conn) + "-" +
                                   std::to_string(p.init) + "-n" + std::to_string(len);
            const bool ok = st.ok() && ref_ok && engine == reference;
            row("lfsr.kat", "L-KAT", id, sha_text(id),
                ref_ok ? sha_hex(reference) : "reference-error",
                st.ok() ? sha_hex(engine) : std::string(code_name(st.code())), ok, id);
            if (ok) ++pass;
            else log("lfsr.kat FAIL " + id);
        }
    }

    // Bit order: the first emitted bit is the MSB of byte 0 (§3.5).
    {
        ++total;
        const u64 conn = 0x80200003ull;
        u64 state = 0x1ull;
        std::vector<u8> bytes(1, 0);
        const Status st = lfsr_read_range(conn, 0x1ull, BigInt::zero(), bytes);
        // Manual, spec-literal simulation of the same eight steps.
        unsigned expected_byte = 0;
        for (unsigned i = 0; i < 8; ++i) {
            const u64 bit = static_cast<u64>(__builtin_parityll(state & conn));
            state = (state >> 1) | (bit << 63);
            expected_byte = (expected_byte << 1) | static_cast<unsigned>(bit);
        }
        const bool ok = st.ok() && bytes[0] == static_cast<u8>(expected_byte);
        row("lfsr.bitorder", "L-KAT", "first-bit-is-msb", sha_text("bitorder"), "msb-first",
            ok ? "msb-first" : "mismatch", ok, "first-bit-is-msb");
        if (ok) ++pass;
        else log("lfsr.bitorder FAIL");
    }

    // Jump-ahead against independent row-oriented GF(2) exponentiation.
    const std::vector<u64> offsets = {1ull,
                                      2ull,
                                      3ull,
                                      255ull,
                                      256ull,
                                      1ull << 20,
                                      1ull << 32,
                                      1ull << 40,
                                      1ull << 50};
    for (const Pair& p : pairs) {
        for (u64 offset : offsets) {
            ++total;
            auto engine_state = lfsr_state_at_byte_offset(p.conn, p.init, BigInt(offset));
            u64 reference_state = 0;
            const bool ref_ok = c03ref::ref_lfsr_state_at_bits(p.conn, p.init, offset * 8,
                                                               reference_state);
            std::vector<u8> engine_bytes(64, 0);
            const Status st = lfsr_read_range(p.conn, p.init, BigInt(offset), engine_bytes);
            std::vector<u8> reference_bytes;
            const bool ref_bytes_ok =
                ref_ok && c03ref::ref_lfsr_from_state(p.conn, reference_state, 64,
                                                      reference_bytes);
            const bool ok = engine_state.ok() && ref_ok && st.ok() && ref_bytes_ok &&
                            engine_state.value() == reference_state &&
                            engine_bytes == reference_bytes;
            const std::string id = "lfsr-jump-" + std::to_string(p.conn) + "-" +
                                   std::to_string(p.init) + "-off" + std::to_string(offset);
            row("lfsr.jump", "L-KAT", id, sha_text(id),
                ref_ok ? std::to_string(reference_state) : "reference-error",
                engine_state.ok() ? std::to_string(engine_state.value()) : "error", ok, id);
            if (ok) ++pass;
            else {
                log("lfsr.jump FAIL " + id + " engine_state=" +
                    (engine_state.ok() ? std::to_string(engine_state.value()) : "error") +
                    " ref_state=" + std::to_string(reference_state));
            }
        }
    }

    // conn == 0 is invalid for every entry point.
    {
        ++total;
        std::vector<u8> out(4, 0);
        const Status st = lfsr_read_range(0, 1, BigInt::zero(), out);
        const Status wf = check_lfsr_conn(0);
        const bool ok = !st.ok() && !wf.ok() && st.code() == Code::Invalid;
        row("lfsr.reject", "L-KAT", "conn0", sha_text("conn0"), "Invalid",
            st.ok() ? "Ok" : std::string(code_name(st.code())), ok, "conn0");
        if (ok) ++pass;
        else log("lfsr.reject FAIL conn0");
    }
    section("lfsr", pass, total);
}

namespace {
class VectorSink : public Sink {
public:
    Status write(std::span<const u8> bytes) override {
        data.insert(data.end(), bytes.begin(), bytes.end());
        return Status{};
    }
    std::vector<u8> data;
};

class FailingSink : public Sink {
public:
    Status write(std::span<const u8>) override { return Code::Invalid; }
};
}  // namespace

void Gate::run_stream_and_cursor() {
    std::size_t pass = 0;
    std::size_t total = 0;
    for (const TermItem& item : terms_) {
        if (!item.materialisable) continue;
        std::vector<u8> reference;
        if (!c03ref::ref_denote(item.ir, item.ir.root, reference, kMaterialiseCap)) continue;

        ++total;
        VectorSink sink;
        const Status st = eval_stream(item.ir, sink);
        const bool ok = st.ok() && sink.data == reference;
        row("eval.stream", item.corpus, item.id, sha_text(describe(item.ir)),
            sha_hex(reference), st.ok() ? sha_hex(sink.data) : std::string(code_name(st.code())),
            ok, item.id);
        if (ok) ++pass;
        else log("eval.stream FAIL " + item.id);

        ++total;
        VectorSink range_sink;
        const Status rst = eval_range(item.ir, BigInt::zero(),
                                      BigInt(static_cast<u64>(reference.size())), range_sink);
        const bool rok = rst.ok() && range_sink.data == reference;
        row("eval.range-all", item.corpus, item.id, sha_text(describe(item.ir)),
            sha_hex(reference),
            rst.ok() ? sha_hex(range_sink.data) : std::string(code_name(rst.code())), rok,
            item.id);
        if (rok) ++pass;
        else log("eval.range-all FAIL " + item.id);

        // TermCursor with deliberately awkward chunk sizes.
        ++total;
        TermCursor cursor(item.ir, item.ir.root);
        std::vector<u8> collected;
        const std::size_t chunks[] = {1, 3, 7, 2, 13, 5, 11, 17, 19, 23};
        std::size_t index = 0;
        bool cursor_ok = true;
        for (;;) {
            const std::size_t want = chunks[index % 10];
            std::vector<u8> buffer(want, 0);
            auto count = cursor.read(buffer);
            if (!count.ok()) {
                cursor_ok = false;
                break;
            }
            if (count.value() == 0) break;
            if (count.value() > want) {
                cursor_ok = false;
                break;
            }
            collected.insert(collected.end(), buffer.begin(),
                             buffer.begin() + static_cast<std::ptrdiff_t>(count.value()));
            ++index;
            if (index > 100000) {
                cursor_ok = false;
                break;
            }
        }
        cursor_ok = cursor_ok && cursor.at_end() && collected == reference;
        row("eval.cursor", item.corpus, item.id, sha_text(describe(item.ir)),
            sha_hex(reference), cursor_ok ? sha_hex(collected) : "mismatch", cursor_ok,
            item.id);
        if (cursor_ok) ++pass;
        else log("eval.cursor FAIL " + item.id);

        // A sink that refuses is propagated, not swallowed.
        ++total;
        FailingSink failing;
        const Status fst = eval_stream(item.ir, failing);
        const bool fok = reference.empty() ? fst.ok() : !fst.ok();
        row("eval.sink-error", item.corpus, item.id, sha_text(describe(item.ir)), "Invalid",
            fst.ok() ? "Ok" : std::string(code_name(fst.code())), fok, item.id);
        if (fok) ++pass;
        else log("eval.sink-error FAIL " + item.id);
    }
    section("evaluation (stream/cursor/sink)", pass, total);
}

void Gate::run_stored_length_trust() {
    std::size_t pass = 0;
    std::size_t total = 0;
    // Every well-formed corpus term, with one stored length corrupted, must be
    // rejected: validation recomputes lengths and never trusts the stored value.
    for (const TermItem& item : terms_) {
        if (!item.materialisable) continue;
        ++total;
        Ir copy = item.ir;
        const u32 root = copy.root;
        copy.nodes[root].length = copy.nodes[root].length.add(BigInt(1)).value();
        copy.total_length = copy.nodes[root].length;  // W5 stays consistent; W6 must fail
        const WfReport report = check_well_formed_report(copy);
        const bool ok = !report.ok() && std::string(report.constraint) == kC_length;
        row("length.stored", item.corpus, item.id, sha_text(describe(item.ir)),
            std::string("Invalid:") + kC_length,
            report.ok() ? std::string("Ok")
                        : std::string(code_name(report.code)) + ":" + report.constraint,
            ok, item.id);
        if (ok) ++pass;
        else log("length.stored FAIL " + item.id + " reported " + report.constraint);
    }
    // Intermediate (non-root) length corruption.
    {
        ++total;
        Builder b;
        u32 a = b.atom_node(b.add_atom(pattern(8, 3)));
        u32 cat = b.concat({a, b.zero(4)});
        Ir ir = b.finish(cat);
        ir.nodes[a].length = BigInt(9);
        const WfReport report = check_well_formed_report(ir);
        const bool ok = !report.ok() && std::string(report.constraint) == kC_length &&
                        report.node == a;
        row("length.stored", "T-BAD", "intermediate-atom", sha_text(describe(ir)),
            std::string("Invalid:") + kC_length,
            report.ok() ? std::string("Ok")
                        : std::string(code_name(report.code)) + ":" + report.constraint,
            ok, "intermediate-atom");
        if (ok) ++pass;
        else log("length.stored FAIL intermediate-atom");
    }
    section("length.stored", pass, total);
}

void Gate::run_depth_limits() {
    std::size_t pass = 0;
    std::size_t total = 0;

    // Depth exactly 2^16 is admissible (E2 §4.3 W7, §9).
    {
        ++total;
        Builder b;
        u32 node = b.atom_node(b.add_atom(pattern(1, 4)));
        for (u32 i = 0; i + 1 < kMaxDepthSpec; ++i) node = b.morph(node, 2, 0);
        Ir ir = b.finish(node);
        const WfReport report = check_well_formed_report(ir);
        const bool ok = report.ok();
        row("wf.limit", "T-BAD", "depth-65536-ok", sha_text(describe(ir)), "Ok",
            report.ok() ? "Ok" : std::string(code_name(report.code)) + ":" + report.constraint,
            ok, "depth-65536-ok");
        if (ok) ++pass;
        else log("wf.limit FAIL depth-65536-ok " + std::string(report.constraint));
    }
    // A tight record-count limit must be reported as Invalid (W1), not Limit.
    {
        ++total;
        Builder b;
        Ir ir = b.finish(b.concat({b.zero(1), b.zero(2), b.zero(3)}));
        const Limits limits{2, kMaxRecordsSpec, kMaxDepthSpec, true};
        const WfReport report = check_well_formed_report(ir, limits);
        const bool ok = !report.ok() && report.code == Code::Invalid &&
                        std::string(report.constraint) == kC_counts;
        row("wf.limit", "T-BAD", "counts", sha_text(describe(ir)),
            std::string("Invalid:") + kC_counts,
            report.ok() ? "Ok" : std::string(code_name(report.code)) + ":" + report.constraint,
            ok, "counts");
        if (ok) ++pass;
        else log("wf.limit FAIL counts");
    }
    // Output above 2^63 is Limit (§8.3).
    {
        ++total;
        Builder b;
        u32 z = b.zero(BigInt(1).shl(63).value().add(BigInt(2)).value());
        Ir ir = b.finish(z);
        const WfReport report = check_well_formed_report(ir);
        const bool ok = !report.ok() && report.code == Code::Limit &&
                        std::string(report.constraint) == kC_output_cap;
        row("wf.limit", "T-BAD", "output-cap", sha_text(describe(ir)),
            std::string("Limit:") + kC_output_cap,
            report.ok() ? "Ok" : std::string(code_name(report.code)) + ":" + report.constraint,
            ok, "output-cap");
        if (ok) ++pass;
        else log("wf.limit FAIL output-cap");
    }
    // Range beyond the predictor prefix policy is Limit, not a wrong answer.
    {
        ++total;
        Builder b;
        // Virtual residual: Zero(2^30) is legal and cheap; a predictor range at
        // an offset above the §5.5 policy limit must report Limit, not bytes.
        u32 z = b.zero(u64{1} << 30);
        u32 p = b.predictor(1, 0, z);
        Ir ir = b.finish(p);
        const BigInt offset = BigInt(1).shl(28).value().add(BigInt(1)).value();
        std::vector<u8> out(4, 0);
        auto result = read_range(ir, p, offset, out);
        const bool ok = !result.ok() && result.code() == Code::Limit;
        row("range.limit", "T-BAD", "predictor-prefix-policy", sha_text("predictor-policy"),
            "Limit", result.ok() ? "Ok" : std::string(code_name(result.code())), ok,
            "predictor-prefix-policy");
        if (ok) ++pass;
        else log("range.limit FAIL predictor-prefix-policy");
        // The same term within the policy window is exact (zeros).
        ++total;
        std::vector<u8> near(8, 0xEE);
        auto in_window = read_range(ir, p, BigInt(1024), near);
        const bool near_ok = in_window.ok();
        bool zeros = true;
        for (u8 v : near) zeros = zeros && v == 0;
        row("range.limit", "T-BAD", "predictor-prefix-in-window",
            sha_text("predictor-policy-in-window"), "Ok+zeros",
            in_window.ok() ? (zeros ? "Ok+zeros" : "Ok+nonzero") : "error", near_ok && zeros,
            "predictor-prefix-in-window");
        if (near_ok && zeros) ++pass;
        else log("range.limit FAIL predictor-prefix-in-window");
    }
    section("limits", pass, total);
}

void Gate::run_determinism() {
    std::size_t pass = 0;
    std::size_t total = 0;
    auto digest_all = [this]() {
        std::string aggregate;
        for (const TermItem& item : terms_) {
            const WfReport report = check_well_formed_report(item.ir);
            aggregate += item.id + ":" + (report.ok() ? "ok" : report.constraint) + ";";
            auto lengths = recompute_lengths_checked(item.ir);
            if (lengths.ok()) aggregate += lengths.value()[item.ir.root].to_decimal();
            aggregate += ";";
            auto bytes = denote_node(item.ir, item.ir.root, 4096);
            if (bytes.ok()) aggregate += sha_hex(bytes.value());
            aggregate += "|";
        }
        std::vector<u8> engine(64, 0);
        (void)lfsr_read_range(0xD0080004ull, 0xDEADBEEFCAFEF00Dull, BigInt(1000), engine);
        aggregate += sha_hex(engine);
        return sha_text(aggregate);
    };
    const std::string first = digest_all();
    const std::string second = digest_all();
    ++total;
    row("determinism", "C03", "repeat-run", sha_text("determinism"), first, second,
        first == second, "repeat-run");
    if (first == second) ++pass;
    else log("determinism FAIL first=" + first + " second=" + second);

    // Two independently constructed but structurally identical terms must
    // produce identical evidence relevant values (construction-order purity).
    ++total;
    {
        Builder b1;
        u32 r1 = b1.concat({b1.atom_node(b1.add_atom(pattern(8, 6))), b1.zero(8)});
        Ir ir1 = b1.finish(r1);
        Builder b2;
        u32 z2 = b2.zero(8);
        u32 a2 = b2.atom_node(b2.add_atom(pattern(8, 6)));
        u32 r2 = b2.concat({a2, z2});
        Ir ir2 = b2.finish(r2);
        auto bytes1 = denote_node(ir1, ir1.root, 4096);
        auto bytes2 = denote_node(ir2, ir2.root, 4096);
        const bool ok = bytes1.ok() && bytes2.ok() && bytes1.value() == bytes2.value();
        row("determinism", "C03", "construction-order", sha_text("construction-order"),
            bytes1.ok() ? sha_hex(bytes1.value()) : "error",
            bytes2.ok() ? sha_hex(bytes2.value()) : "error", ok, "construction-order");
        if (ok) ++pass;
        else log("determinism FAIL construction-order");
    }
    section("determinism", pass, total);
}

void Gate::run_source_independence() {
    std::size_t pass = 0;
    std::size_t total = 0;
    ++total;
    const std::array<std::string, 2> dirs = {"include/mapr/e2", "engine/src/e2"};
    const std::array<std::string, 10> forbidden = {
        "mapr/e3", "mapr/e4",  "mapr/e5",      "mapr/e6",      "mapr/e7",
        "marp/harness", "mapr/container", "mapr/encoder", "mapr/decoder", "mapr/dag"};
    std::vector<std::string> files;
    for (const std::string& dir : dirs) {
        const std::string path = root_ + "/" + dir;
        std::error_code ec;
        if (!std::filesystem::is_directory(path, ec)) continue;
        for (const auto& entry : std::filesystem::directory_iterator(path, ec)) {
            if (!entry.is_regular_file()) continue;
            const std::string name = entry.path().filename().string();
            const bool source = (name.size() > 2 && name.substr(name.size() - 2) == ".h") ||
                                (name.size() > 4 && name.substr(name.size() - 4) == ".hpp") ||
                                (name.size() > 4 && name.substr(name.size() - 4) == ".cpp");
            if (source) files.push_back(path + "/" + name);
        }
    }
    std::sort(files.begin(), files.end());
    std::size_t violations = 0;
    std::string listing;
    for (const std::string& path : files) {
        std::ifstream in(path);
        std::string line;
        while (std::getline(in, line)) {
            if (line.find("#include") == std::string::npos) continue;
            for (const std::string& bad : forbidden) {
                if (line.find(bad) != std::string::npos) {
                    ++violations;
                    listing += path + ":" + line + ";";
                }
            }
        }
    }
    const std::string digest = sha_text(listing + "files=" + std::to_string(files.size()));
    const bool ok = violations == 0 && files.size() >= 4;
    row("independence", "C03", "source-scan", digest, "0 forbidden includes",
        std::to_string(violations) + " forbidden includes across " +
            std::to_string(files.size()) + " files",
        ok, "source-scan");
    if (ok) ++pass;
    log("independence: files=" + std::to_string(files.size()) +
        " violations=" + std::to_string(violations) + " tree_sha256=" + digest);
    section("independence", pass, total);
}

void Gate::run_coverage() {
    // Every node kind, morph id and predictor id must be exercised.  The
    // counters are populated by corpus construction and by the KAT loops.
    std::size_t kinds = 0;
    std::string missing;
    for (std::size_t i = 0; i < kKindCount; ++i) {
        if (kind_hits_[i] > 0) {
            ++kinds;
        } else {
            missing += std::to_string(i) + ",";
        }
    }
    row("coverage.kind", "C03", "all-12-kinds", sha_text("kinds"), "12/12",
        std::to_string(kinds) + "/12", kinds == kKindCount, "all-12-kinds");
    if (kinds != kKindCount) log("coverage.kind MISSING " + missing);
    std::size_t morphs = 0;
    for (std::size_t i = 1; i <= kMorphCount; ++i) {
        if (morph_hits_[i] > 0) ++morphs;
    }
    row("coverage.morph", "C03", "all-9-morphs", sha_text("morphs"), "9/9",
        std::to_string(morphs) + "/9", morphs == kMorphCount, "all-9-morphs");
    std::size_t predictors = 0;
    for (std::size_t i = 0; i < kPredictorCount; ++i) {
        if (predictor_hits_[i] > 0) ++predictors;
    }
    row("coverage.predictor", "C03", "all-5-predictors", sha_text("predictors"), "5/5",
        std::to_string(predictors) + "/5", predictors == kPredictorCount,
        "all-5-predictors");
    section("coverage", (kinds == kKindCount ? 1u : 0u) + (morphs == kMorphCount ? 1u : 0u) +
                            (predictors == kPredictorCount ? 1u : 0u),
            3);
}

// ---------------------------------------------------------------------------

int Gate::run() {
    build_corpus();
    build_bad_corpus();

    run_wf_accept();
    run_wf_reject();
    run_denotation_and_length();
    run_ranges();
    run_big_terms();
    run_morphs();
    run_predictors();
    run_lfsr();
    run_stream_and_cursor();
    run_stored_length_trust();
    run_depth_limits();
    run_determinism();
    run_source_independence();
    run_coverage();

    const std::size_t checks = passes_ + failures_;
    log("totals: checks=" + std::to_string(checks) + " pass=" + std::to_string(passes_) +
        " fail=" + std::to_string(failures_));
    log(failures_ == 0 ? std::string("RESULT: PASS (C03 TERM)")
                       : std::string("RESULT: FAIL (C03 TERM)"));
    row("c03.summary", "C03", "all-checks", sha_text("summary"),
        std::to_string(checks) + " checks all PASS",
        "pass=" + std::to_string(passes_) + " fail=" + std::to_string(failures_),
        failures_ == 0, "summary");
    return failures_ == 0 ? 0 : 1;
}

bool Gate::write_evidence() {
    namespace fs = std::filesystem;
    const std::string gate_dir = root_ + "/specs_and_reports/v2/gates";
    const std::string log_dir = root_ + "/specs_and_reports/v2/logs";
    const std::string evidence_dir = root_ + "/specs_and_reports/v2/evidence/E2";
    std::error_code ec;
    fs::create_directories(gate_dir, ec);
    fs::create_directories(log_dir, ec);
    fs::create_directories(evidence_dir, ec);

    const std::string tsv_path = gate_dir + "/C03-TERM.tsv";
    const std::string log_path = log_dir + "/C03-TERM.log";

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

    const std::string tsv_sha = sha_hex(
        std::span<const u8>(reinterpret_cast<const u8*>(tsv.data()), tsv.size()));
    const std::string log_sha = sha_hex(
        std::span<const u8>(reinterpret_cast<const u8*>(log_text.data()), log_text.size()));
    std::string sums;
    sums += tsv_sha + "  specs_and_reports/v2/gates/C03-TERM.tsv\n";
    sums += log_sha + "  specs_and_reports/v2/logs/C03-TERM.log\n";
    {
        std::ofstream out(evidence_dir + "/SHA256SUMS", std::ios::binary | std::ios::trunc);
        if (!out) return false;
        out.write(sums.data(), static_cast<std::streamsize>(sums.size()));
    }
    return true;
}

std::string environment_record(const std::string& root, const char* command_line) {
    std::string text;
    text += "tool: C03-TERM evidence harness\n";
    text += "root: " + root + "\n";
    text += "command_line: " + std::string(command_line) + "\n";
    text += "compiler: " __VERSION__ "\n";
    text += "std: c++20 (build flags in engine/Makefile.e2)\n";
    return text;
}

}  // namespace

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
            std::printf("usage: e2_c03_gate [--root PATH] [--write-evidence]\n");
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
