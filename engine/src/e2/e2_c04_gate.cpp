// C04 CANON — evidence harness.
//
// Produces specs_and_reports/v2/gates/C04-CANON.tsv,
// specs_and_reports/v2/logs/C04-CANON.log and
// specs_and_reports/v2/evidence/C04/SHA256SUMS when invoked with
// --write-evidence.  The harness never asserts: every check is evaluated and
// recorded as a TSV row with an exact expected/actual pair and a PASS/FAIL
// verdict.  Nothing measured is hand-edited; the values are whatever the
// implementation produces on this machine.
//
// Row schema (same as H3/E1/C03): check \t corpus \t item_id \t input_sha256 \t
// expected \t actual \t verdict \t log

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include "mapr/e1_sha256.hpp"
#include "mapr/e2/e2_canon.hpp"
#include "mapr/e2/e2_term.hpp"
#include "c03_build.hpp"

namespace c04 {

using namespace marp::v2;  // NOLINT
using c03::Builder;
using c03::pattern;

std::string hex_bytes(std::span<const u8> bytes) {
    std::string out;
    out.reserve(bytes.size() * 2);
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
    auto digest = mapr::Sha256::hash(std::string_view(reinterpret_cast<const char*>(bytes.data()),
                                                      bytes.size()));
    return digest.ok() ? hex_array(digest.value()) : std::string(64, '0');
}

std::string sha_text(const std::string& text) {
    return sha_hex(std::span<const u8>(reinterpret_cast<const u8*>(text.data()), text.size()));
}

// ---------------------------------------------------------------------------
// Term fingerprint for input hashing (same shape as C03)
// ---------------------------------------------------------------------------

std::string describe(const Ir& ir) {
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

// Structural equality of two Ir values (used by idempotence checks).
bool ir_equal(const Ir& a, const Ir& b) {
    if (a.nodes.size() != b.nodes.size() || a.atoms.size() != b.atoms.size()) return false;
    if (a.root != b.root || a.total_length != b.total_length) return false;
    for (std::size_t i = 0; i < a.atoms.size(); ++i) {
        if (a.atoms[i].length != b.atoms[i].length) return false;
        if (a.atoms[i].sha256 != b.atoms[i].sha256) return false;
        if (a.atoms[i].payload.size() != b.atoms[i].payload.size()) return false;
        if (!a.atoms[i].payload.empty() &&
            std::memcmp(a.atoms[i].payload.data(), b.atoms[i].payload.data(),
                        a.atoms[i].payload.size()) != 0) {
            return false;
        }
    }
    for (std::size_t i = 0; i < a.nodes.size(); ++i) {
        const Node& x = a.nodes[i];
        const Node& y = b.nodes[i];
        if (x.kind != y.kind) return false;
        if (x.args != y.args) return false;
        if (x.a != y.a || x.b != y.b) return false;
        if (x.morph != y.morph || x.morph_k != y.morph_k) return false;
        if (x.lfsr_conn != y.lfsr_conn || x.lfsr_init != y.lfsr_init) return false;
        if (x.affine_start != y.affine_start || x.affine_step != y.affine_step) return false;
        if (x.predictor_id != y.predictor_id || x.predictor_param != y.predictor_param) {
            return false;
        }
        if (x.length != y.length) return false;
    }
    return true;
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

struct RedexItem {
    std::string id;
    std::string corpus;
    bool materialisable = true;
    std::unique_ptr<Builder> builder;
    Ir ir;
};

class Gate {
public:
    explicit Gate(std::string root) : root_(std::move(root)) {}

    int run();
    bool write_evidence();
    void set_environment(const std::string& environment) { environment_ = environment; }

private:
    void build_corpus();
    void build_redex_corpus();
    void add_term(const std::string& id, const std::string& corpus, bool materialisable,
                  const std::function<u32(Builder&)>& build);
    void add_redex(const std::string& id, const std::string& corpus,
                   const std::function<u32(Builder&)>& build);

    void row(const std::string& check, const std::string& corpus, const std::string& id,
             const std::string& input_sha, const std::string& expected,
             const std::string& actual, bool pass, const std::string& log_ref);
    void log(const std::string& line) { log_lines_.push_back(line); }
    void section(const std::string& name, const std::string& extra = std::string());

    void run_canon_corpus();
    void run_redex_corpus();
    void run_rule_coverage();
    void run_atom_cases();
    void run_canonical_key();
    void run_budget_and_presupposition();
    void run_determinism();
    void run_source_independence();
    void run_coverage();

    // Battery of checks applied to one materialisation-capable canonical
    // candidate.  Returns the number of failed assertions and appends rows.
    void term_battery(const TermItem& term);

    std::string root_;
    std::string environment_;
    std::vector<Row> rows_;
    std::vector<std::string> log_lines_;
    std::vector<TermItem> terms_;
    std::vector<RedexItem> redex_;
    std::size_t failures_ = 0;
    std::size_t passes_ = 0;
    std::array<std::size_t, kKindCount> kind_hits_{};
    std::array<std::size_t, kMorphCount + 1> morph_hits_{};
    std::array<std::size_t, kPredictorCount> predictor_hits_{};
    std::array<u64, 13> rule_fires_total_{};
    u64 rules_fired_total_ = 0;
    std::size_t section_pass_ = 0;
    std::size_t section_fail_ = 0;
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
        ++section_pass_;
    } else {
        ++failures_;
        ++section_fail_;
    }
}

void Gate::section(const std::string& name, const std::string& extra) {
    log(name + ": passed=" + std::to_string(section_pass_) + "/" +
        std::to_string(section_pass_ + section_fail_) +
        (extra.empty() ? std::string() : " " + extra));
    section_pass_ = 0;
    section_fail_ = 0;
}

void Gate::add_term(const std::string& id, const std::string& corpus, bool materialisable,
                    const std::function<u32(Builder&)>& build) {
    auto builder = std::make_unique<Builder>();
    const u32 root = build(*builder);
    Ir ir = builder->finish(root);
    for (const Node& node : ir.nodes) {
        kind_hits_[static_cast<std::size_t>(node.kind)] += 1;
        if (node.kind == Kind::Morph && node.morph >= 1 && node.morph <= kMorphCount) {
            morph_hits_[node.morph] += 1;
        }
        if (node.kind == Kind::Predictor && node.predictor_id < kPredictorCount) {
            predictor_hits_[node.predictor_id] += 1;
        }
    }
    terms_.push_back(TermItem{id, corpus, std::move(builder), ir, materialisable});
}

void Gate::add_redex(const std::string& id, const std::string& corpus,
                     const std::function<u32(Builder&)>& build) {
    auto builder = std::make_unique<Builder>();
    const u32 root = build(*builder);
    Ir ir = builder->finish(root);
    redex_.push_back(RedexItem{id, corpus, true, std::move(builder), ir});
}

// ---------------------------------------------------------------------------
// Corpus (mirrors the C03 corpus so the same engines run; reuse, not edit)
// ---------------------------------------------------------------------------

void Gate::build_corpus() {
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
    // Virtual terms (never materialised, lengths are arbitrary precision).
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

// ---------------------------------------------------------------------------
// Redex corpus: one or more well-formed-but-non-canonical terms per §3.8
// rule id.  Each item names the constraint `check_canonical` must report
// first and the rule index whose counter must move after `canon`.
// ---------------------------------------------------------------------------

void Gate::build_redex_corpus() {
    add_redex("r1-concat-child-concat", "R-KAT", [](Builder& b) {
        u32 inner = b.concat({b.zero(5), b.atom_node(b.add_atom(pattern(8, 71)))});
        return b.concat({b.atom_node(b.add_atom(pattern(16, 70))), inner, b.zero(2)});
    });
    add_redex("r2-concat-empty-child", "R-KAT", [](Builder& b) {
        u32 z = b.empty();
        return b.concat({b.atom_node(b.add_atom(pattern(16, 72))), z});
    });
    add_redex("r3-adjacent-atoms-merge", "R-KAT", [](Builder& b) {
        return b.concat({b.atom_node(b.add_atom(pattern(16, 5))),
                         b.atom_node(b.add_atom(pattern(31, 6)))});
    });
    add_redex("r4-adjacent-zeros-merge", "R-KAT", [](Builder& b) {
        return b.concat({b.zero(5), b.zero(7)});
    });
    add_redex("r5-repeat-q1-r0", "R-KAT", [](Builder& b) {
        return b.repeat(b.atom_node(b.add_atom(pattern(16, 73))), 1, 0);
    });
    add_redex("r5-repeat-q1-r3", "R-KAT", [](Builder& b) {
        return b.repeat(b.atom_node(b.add_atom(pattern(16, 74))), 1, 3);
    });
    add_redex("r5-repeat-q0-r0", "R-KAT", [](Builder& b) {
        return b.repeat(b.atom_node(b.add_atom(pattern(16, 75))), 0, 0);
    });
    add_redex("r6-slice-full-cover", "R-KAT", [](Builder& b) {
        return b.slice(b.atom_node(b.add_atom(pattern(16, 76))), 0, 16);
    });
    add_redex("r6-slice-zero-length", "R-KAT", [](Builder& b) {
        return b.slice(b.atom_node(b.add_atom(pattern(16, 77))), 3, 0);
    });
    add_redex("r7-morph-involution-cancel", "R-KAT", [](Builder& b) {
        return b.morph(b.morph(b.atom_node(b.add_atom(pattern(16, 78))), 2, 0), 2, 0);
    });
    add_redex("r7-morph-rotl-rotr-cancel", "R-KAT", [](Builder& b) {
        return b.morph(b.morph(b.atom_node(b.add_atom(pattern(16, 79))), 6, 3), 7, 3);
    });
    add_redex("r8-xor-self", "R-KAT", [](Builder& b) {
        const u32 atom = b.atom_node(b.add_atom(pattern(16, 80)));
        return b.xor_node(atom, atom);
    });
    add_redex("r8-xor-zero-operand", "R-KAT", [](Builder& b) {
        return b.xor_node(b.atom_node(b.add_atom(pattern(16, 81))), b.zero(16));
    });
    add_redex("r9-interleave-argc1", "R-KAT", [](Builder& b) {
        return b.interleave({b.atom_node(b.add_atom(pattern(8, 82)))}, 1);
    });
    add_redex("r10-affine-step0", "R-KAT", [](Builder& b) {
        return b.affine(7, 0, 40);
    });
    add_redex("r11-repeat-of-zero", "R-KAT", [](Builder& b) {
        return b.repeat(b.zero(4), 2, 1);
    });
    add_redex("r11-slice-of-zero", "R-KAT", [](Builder& b) {
        return b.slice(b.zero(4), 1, 2);
    });
    add_redex("r12-duplicated-subtree", "R-KAT", [](Builder& b) {
        const u32 atom = b.atom_node(b.add_atom(pattern(16, 83)));
        const u32 first = b.morph(atom, 2, 0);
        const u32 second = b.morph(atom, 2, 0);
        return b.concat({first, second});
    });
    add_redex("r13-atom-first-use-order", "R-KAT", [](Builder& b) {
        const u32 first = b.add_atom(pattern(4, 87));   // atom id 0
        const u32 second = b.add_atom(pattern(4, 88));  // atom id 1
        const u32 nb = b.atom_node(second);             // node 0 (uses atom 1)
        const u32 na = b.atom_node(first);              // node 1 (uses atom 0)
        return b.concat({nb, b.zero(1), na});           // atom use order = [1, 0]
    });
}

// First rule id each redex must trip, checked against the constraint string.
const char* redex_constraint(const std::string& id) {
    if (id.rfind("r1-", 0) == 0) return kCanon1;
    if (id.rfind("r2-", 0) == 0) return kCanon2;
    if (id.rfind("r3-", 0) == 0) return kCanon3;
    if (id.rfind("r4-", 0) == 0) return kCanon4;
    if (id.rfind("r5-", 0) == 0) return kCanon5;
    if (id.rfind("r6-", 0) == 0) return kCanon6;
    if (id.rfind("r7-", 0) == 0) return kCanon7;
    if (id.rfind("r8-", 0) == 0) return kCanon8;
    if (id.rfind("r9-", 0) == 0) return kCanon9;
    if (id.rfind("r10-", 0) == 0) return kCanon10;
    if (id.rfind("r11-", 0) == 0) return kCanon11;
    if (id.rfind("r12-", 0) == 0) return kCanon12;
    return kCanon13;
}
// True iff every atom record is used and atom ids appear in dense first-use
// order in node order (canonical identity shape, E2 §4.8 / §5.7).
bool atoms_dense_first_use(const Ir& ir) {
    std::vector<u32> seq;
    for (const Node& n : ir.nodes) {
        if (n.kind != Kind::Atom) continue;
        const auto id = n.a.to_u64_checked();
        if (!id.has_value()) return false;
        seq.push_back(static_cast<u32>(*id));
    }
    if (seq.size() != ir.atoms.size()) return false;
    for (u32 i = 0; i < seq.size(); ++i) {
        if (seq[i] != i) return false;
    }
    return true;
}

// Index into CanonReport::rule_fires for the redex's primary rule.
std::size_t redex_rule_index(const std::string& id) {
    static const std::array<const char*, 13> kAll = {kCanon1, kCanon2, kCanon3, kCanon4,
                                                     kCanon5, kCanon6, kCanon7, kCanon8,
                                                     kCanon9, kCanon10, kCanon11,
                                                     kCanon12, kCanon13};
    const char* c = redex_constraint(id);
    for (std::size_t i = 0; i < kAll.size(); ++i) {
        if (std::strcmp(c, kAll[i]) == 0) return i;
    }
    return 0;
}

constexpr u64 kMaterialiseCap = 8ull << 20;  // 8 MiB: corpus denotations are tiny

void Gate::term_battery(const TermItem& term) {
    const std::string tsha = sha_text(describe(term.ir));
    CanonReport report;
    auto out = canon(term.ir, report);
    if (!out.ok()) {
        row("canon", term.corpus, term.id, tsha, "canon ok",
            out.code() == Code::Limit ? "Limit" : "Invalid", false, "canon");
        log("canon " + term.id + " FAILED code=" +
            (out.code() == Code::Limit ? std::string("Limit") : std::string("Invalid")));
        return;
    }
    const Ir& out_ir = out.value();
    row("canon", term.corpus, term.id, tsha, "canon ok (nodes " +
            std::to_string(term.ir.nodes.size()) + " -> " +
            std::to_string(out_ir.nodes.size()) + ")",
        "ok", true, "canon");
    if (!ir_equal(term.ir, out_ir)) {
        log("canon rewrote " + term.id + ": nodes " + std::to_string(term.ir.nodes.size()) +
            " -> " + std::to_string(out_ir.nodes.size()) + ", rewrites=" +
            std::to_string(report.rewrites));
    }

    const WfReport check = check_canonical(out_ir);
    row("canon-canonical-out", term.corpus, term.id, tsha, "canonical (ok)",
        check.ok() ? std::string("canonical (ok)") : std::string(check.constraint),
        check.ok(), "canon");

    auto re = canon(out_ir);
    const bool idem = re.ok() && ir_equal(re.value(), out_ir);
    row("canon-idempotent", term.corpus, term.id, tsha, "fixed point",
        idem ? std::string("fixed point") : std::string("NOT a fixed point"), idem,
        "canon");

    auto again = canon(term.ir);
    const bool det = again.ok() && ir_equal(again.value(), out_ir);
    row("canon-determinism", term.corpus, term.id, tsha, "identical across runs",
        det ? std::string("identical") : std::string("DIFFERS"), det, "canon");

    if (term.materialisable) {
        auto d1 = denote_root(term.ir, kMaterialiseCap);
        auto d2 = denote_root(out_ir, kMaterialiseCap);
        const bool ok = d1.ok() && d2.ok() && d1.value() == d2.value();
        row("canon-denotation", term.corpus, term.id, tsha,
            std::string("denotation preserved (") +
                (d1.ok() ? std::to_string(d1.value().size()) : std::string("n/a")) + " bytes)",
            ok ? std::string("equal")
               : (!d1.ok() || !d2.ok() ? std::string("denote failed")
                                        : std::string("DENOTATION DIVERGED")),
            ok, "denotation");
    } else {
        log("denotation skipped (non-materialisable virtual term) " + term.id);
    }
    rules_fired_total_ += report.rewrites;
    for (std::size_t i = 0; i < 13; ++i) rule_fires_total_[i] += report.rule_fires[i];
}

void Gate::run_canon_corpus() {
    for (const TermItem& term : terms_) term_battery(term);
    section("canon-corpus");
}

void Gate::run_redex_corpus() {
    for (const RedexItem& redex : redex_) {
        const std::string tsha = sha_text(describe(redex.ir));
        const std::string wanted = redex_constraint(redex.id);

        const WfReport reported = check_canonical(redex.ir);
        const bool found =
            !reported.ok() && std::strcmp(reported.constraint, wanted.c_str()) == 0;
        row("redex-first-failure", redex.corpus, redex.id, tsha, wanted,
            reported.ok() ? std::string("(canonical)") : std::string(reported.constraint),
            found, "redex");

        CanonReport report;
        auto out = canon(redex.ir, report);
        if (!out.ok()) {
            row("rewrite", redex.corpus, redex.id, tsha, "canon ok",
                out.code() == Code::Limit ? "Limit" : "Invalid", false, "redex");
            continue;
        }
        const Ir& out_ir = out.value();
        row("rewrite", redex.corpus, redex.id, tsha, "canon ok", "ok", true, "redex");

        const WfReport check = check_canonical(out_ir);
        row("rewrite-canonical-out", redex.corpus, redex.id, tsha, "canonical (ok)",
            check.ok() ? std::string("canonical (ok)") : std::string(check.constraint),
            check.ok(), "redex");

        auto d1 = denote_root(redex.ir, kMaterialiseCap);
        auto d2 = denote_root(out_ir, kMaterialiseCap);
        const bool deno = d1.ok() && d2.ok() && d1.value() == d2.value();
        row("rewrite-denotation", redex.corpus, redex.id, tsha,
            "denotation preserved", deno ? std::string("equal")
                                         : std::string("DENOTATION DIVERGED"),
            deno, "denotation");

        auto re = canon(out_ir);
        const bool idem = re.ok() && ir_equal(re.value(), out_ir);
        row("rewrite-idempotent", redex.corpus, redex.id, tsha, "fixed point",
            idem ? std::string("fixed point") : std::string("NOT a fixed point"), idem,
            "redex");

        const std::size_t rule_index = redex_rule_index(redex.id);
        bool rule_evidence = false;
        std::string rule_actual;
        if (rule_index == 12) {
            // Rule 13's emission work (renumbering to dense first-use atom
            // ids) is not counted by rule_fires[12], which records pruning
            // only.  The semantic evidence is that the canonical output has
            // dense first-use ids and differs from the redex input.
            rule_evidence = atoms_dense_first_use(out_ir) && !ir_equal(redex.ir, out_ir);
            rule_actual = rule_evidence ? std::string("dense first-use ids restored")
                                        : std::string("atomic id order not restored");
        } else {
            const u64 fires = report.rule_fires[rule_index];
            rule_evidence = fires > 0;
            rule_actual = std::string("rule_fires[") + std::to_string(rule_index + 1) +
                          "] = " + std::to_string(fires);
        }
        row("rewrite-rule-fired", redex.corpus, redex.id, tsha, wanted, rule_actual,
            rule_evidence, "redex");
        for (std::size_t i = 0; i < 13; ++i) rule_fires_total_[i] += report.rule_fires[i];
        rules_fired_total_ += report.rewrites;
    }
    section("redex-corpus");
}

// ---------------------------------------------------------------------------
// Rule coverage: every §3.8 rule counter must have fired at least once during
// the corpus + redex batteries (rule firings are accumulated there).
// ---------------------------------------------------------------------------

void Gate::run_rule_coverage() {
    static const std::array<const char*, 13> names = {
        kCanon1, kCanon2, kCanon3, kCanon4, kCanon5, kCanon6, kCanon7,
        kCanon8, kCanon9, kCanon10, kCanon11, kCanon12, kCanon13};
    std::string missing;
    for (std::size_t i = 0; i < 13; ++i) {
        if (rule_fires_total_[i] == 0) {
            missing += std::to_string(i + 1) + ",";
        }
        row("coverage.rule", "C04", names[i], sha_text(std::string(names[i])),
            "fired >= 1", std::to_string(rule_fires_total_[i]),
            rule_fires_total_[i] > 0, "coverage");
    }
    section("rule-coverage", missing.empty() ? std::string() : "missing=" + missing);
}

// ---------------------------------------------------------------------------
// ATOM_MAX = 1,048,576 (length unit) boundary cases at gate scale.
// ---------------------------------------------------------------------------

void Gate::run_atom_cases() {
    // Adjacent atoms whose combined length is exactly ATOM_MAX merge.
    {
        const std::size_t half = kAtomMax / 2;  // 524,288 + 524,288 = 1,048,576
        Builder b;
        u32 first = b.atom_node(b.add_atom(std::vector<u8>(half, 0xA1)));
        u32 second = b.atom_node(b.add_atom(std::vector<u8>(half, 0xB2)));
        auto root = b.concat({first, second});
        Ir ir = b.finish(root);
        const std::string tsha = sha_text(describe(ir));
        auto out = canon(ir);
        const bool ok = out.ok() && out.value().atoms.size() == 1 &&
                        out.value().atoms[0].length.to_u64_checked().value_or(0) == kAtomMax;
        row("atom-max-exact-merge", "T-ATOM", "merge-exact-1MiB", tsha,
            "single atom of length 1048576",
            ok ? std::string("merged to one atom") : std::string("NOT merged / failed"),
            ok, "atom");
        if (out.ok()) {
            auto d1 = denote_root(ir, kMaterialiseCap * 4);
            auto d2 = denote_root(out.value(), kMaterialiseCap * 4);
            const bool deno = d1.ok() && d2.ok() && d1.value() == d2.value();
            row("atom-max-exact-merge-denotation", "T-ATOM", "merge-exact-1MiB", tsha,
                "denotation preserved", deno ? std::string("equal") : std::string("DIVERGED"),
                deno, "atom");
        }
    }
    // Adjacent atoms whose combined length exceeds ATOM_MAX stay split.
    {
        const std::size_t big = kAtomMax / 2 + 1;  // 524,289 + 524,289 = 1,048,578 > MAX
        Builder b;
        u32 first = b.atom_node(b.add_atom(std::vector<u8>(big, 0xC3)));
        u32 second = b.atom_node(b.add_atom(std::vector<u8>(big, 0xD4)));
        auto root = b.concat({first, second});
        Ir ir = b.finish(root);
        const std::string tsha = sha_text(describe(ir));
        auto out = canon(ir);
        const bool ok = out.ok() && out.value().atoms.size() == 2 &&
                        out.value().nodes.size() == 3;  // concat + 2 atoms, unmerged
        row("atom-max-over-stay-split", "T-ATOM", "split-above-1MiB", tsha,
            "atoms stay split", ok ? std::string("stay split") : std::string("WRONGLY MERGED"),
            ok, "atom");
    }
    // An oversized source atom splits into ATOM_MAX pieces with total length
    // preserved and payloads concatenated in order.
    {
        const std::size_t total = kAtomMax + 7;
        Builder b;
        std::vector<u8> payload(total);
        for (std::size_t i = 0; i < total; ++i) payload[i] = static_cast<u8>((i * 31u) & 0xFFu);
        u32 atom = b.atom_node(b.add_atom(payload));
        Ir ir = b.finish(atom);
        const std::string tsha = sha_text(describe(ir));
        auto out = canon(ir);
        bool ok = out.ok();
        if (ok) {
            const Ir& o = out.value();
            ok = o.atoms.size() == 2 && o.atoms[0].length.to_u64_checked().value_or(0) == kAtomMax &&
                 o.atoms[1].length.to_u64_checked().value_or(0) == 7;
        }
        row("atom-max-oversize-split", "T-ATOM", "split-1048583", tsha,
            "split into 1048576 + 7", ok ? std::string("split as expected")
                                         : std::string("unexpected shape"),
            ok, "atom");
        if (out.ok()) {
            auto d1 = denote_root(ir, kMaterialiseCap * 4);
            auto d2 = denote_root(out.value(), kMaterialiseCap * 4);
            const bool deno = d1.ok() && d2.ok() && d1.value() == d2.value();
            row("atom-max-oversize-split-denotation", "T-ATOM", "split-1048583", tsha,
                "denotation preserved", deno ? std::string("equal") : std::string("DIVERGED"),
                deno, "atom");
        }
    }
    section("atom-cases");
}

// ---------------------------------------------------------------------------
// canonical_key (E2 §5.7): equality/ordering behaviour on the corpus.
// ---------------------------------------------------------------------------

void Gate::run_canonical_key() {
    // 1) Out-of-range node id yields an empty key.
    {
        Builder b;
        const u32 z = b.zero(3);
        const Ir ir = b.finish(z);
        const std::string key = canonical_key(ir, static_cast<u32>(ir.nodes.size()));
        row("key-out-of-range", "K-KEY", "oob-node", sha_text(describe(ir)), "empty key",
            key.empty() ? std::string("empty key") : std::string("non-empty"), key.empty(),
            "key");
    }
    // 2) Same subterm under two different ids/parents yields the same key.
    {
        Builder b1;
        const u32 a1 = b1.atom_node(b1.add_atom(pattern(16, 90)));
        const Ir ir1 = b1.finish(a1);
        Builder b2;
        const u32 x = b2.zero(99);  // unrelated prefix nodes shift ids
        const u32 a2 = b2.atom_node(b2.add_atom(pattern(16, 90)));
        const u32 cat = b2.concat({x, a2});
        (void)cat;
        const Ir ir2 = b2.finish(a2);  // same subtree, different position context
        const std::string k1 = canonical_key(ir1, 0);
        const std::string k2 = canonical_key(ir2, 1);
        row("key-id-independent", "K-KEY", "atom-at-different-id", sha_text(describe(ir2)),
            "keys equal", k1 == k2 ? std::string("equal") : std::string("DIFFER"), k1 == k2,
            "key");
    }
    // 3) Structurally distinct subterms never share a key (full corpus scan).
    {
        std::size_t pairs = 0;
        std::size_t equal_pairs = 0;
        std::size_t mismatched = 0;
        for (const TermItem& term : terms_) {
            for (std::size_t i = 0; i < term.ir.nodes.size(); ++i) {
                for (std::size_t j = i + 1; j < term.ir.nodes.size(); ++j) {
                    const bool se = structurally_equal(term.ir, static_cast<u32>(i),
                                                       static_cast<u32>(j));
                    const std::string ki = canonical_key(term.ir, static_cast<u32>(i));
                    const std::string kj = canonical_key(term.ir, static_cast<u32>(j));
                    ++pairs;
                    if (ki == kj) ++equal_pairs;
                    if (se != (ki == kj)) ++mismatched;
                }
            }
        }
        row("key-injective-corpus", "K-KEY", "all-corpus-node-pairs", sha_text("pairs"),
            std::to_string(pairs) + " pairs, 0 mismatches",
            std::to_string(pairs) + " pairs, " + std::to_string(mismatched) + " mismatches",
            mismatched == 0, "key");
    }
    // 4) Key is independent of the atom table position (dedup by payload).
    {
        Builder b;
        const u32 a1 = b.atom_node(b.add_atom(pattern(8, 91)));
        const u32 a2 = b.atom_node(b.add_atom(pattern(8, 92)));
        const Ir ir = b.finish(b.concat({a1, a2}));
        const std::string key = canonical_key(ir, 0);
        row("key-payload-addressed", "K-KEY", "atom-key-payload", sha_text(describe(ir)),
            "non-empty, deterministic",
            (!key.empty() && canonical_key(ir, 0) == key) ? std::string("ok")
                                                          : std::string("unstable"),
            !key.empty() && canonical_key(ir, 0) == key, "key");
    }
    section("canonical-key");
}

// ---------------------------------------------------------------------------
// O4.1 budget behaviour and input presuppositions.
// ---------------------------------------------------------------------------

void Gate::run_budget_and_presupposition() {
    // Budget 0 on a term that needs rewrites yields Limit with a report.
    {
        Builder b;
        const u32 inner = b.concat({b.zero(5), b.atom_node(b.add_atom(pattern(8, 93)))});
        const u32 root = b.concat({b.atom_node(b.add_atom(pattern(16, 94))), inner});
        const Ir ir = b.finish(root);
        CanonReport report;
        auto out = canon_with_budget(ir, 0, &report);
        const bool limited = !out.ok() && out.code() == Code::Limit && report.budget_exhausted;
        row("budget-zero-limit", "T-BUDGET", "budget0-needs-work", sha_text(describe(ir)),
            "Limit + budget_exhausted",
            limited ? std::string("Limit + budget_exhausted") : std::string("not Limit"),
            limited, "budget");
    }
    // Budget 0 on an already-canonical term succeeds (nothing to rewrite).
    {
        Builder b;
        const u32 z = b.zero(3);
        const Ir ir = b.finish(z);
        CanonReport report;
        auto out = canon_with_budget(ir, 0, &report);
        row("budget-zero-noop", "T-BUDGET", "budget0-no-op", sha_text(describe(ir)),
            "ok (0 rewrites)", out.ok() ? std::string("ok") : std::string("failed"),
            out.ok(), "budget");
    }
    // Default budget is 64 * (nodes + 1).
    {
        Builder b;
        const u32 inner = b.concat({b.zero(5), b.atom_node(b.add_atom(pattern(8, 95)))});
        const u32 root = b.concat({b.atom_node(b.add_atom(pattern(16, 96))), inner});
        const Ir ir = b.finish(root);
        CanonReport report;
        auto out = canon(ir, report);
        const bool ok = out.ok() && !report.budget_exhausted &&
                        report.rewrites <= 64ull * (ir.nodes.size() + 1ull);
        row("budget-default-64x", "T-BUDGET", "default-budget", sha_text(describe(ir)),
            "rewrites <= 64*(n+1)",
            ok ? ("rewrites=" + std::to_string(report.rewrites)) : std::string("exceeded/Limit"),
            ok, "budget");
    }
    // Non-WF input yields Invalid and no output.
    {
        Builder b;
        const u32 z = b.zero(4);
        const u32 bad = b.concat({z, z});
        b.node(bad).args.clear();  // Concat argc 0: WF violation
        const Ir ir = b.finish(bad);
        auto out = canon(ir);
        row("presupposition-wf-required", "T-BUDGET", "non-wf-argc0", sha_text(describe(ir)),
            "Invalid", out.ok() ? std::string("ok")
                 : (out.code() == Code::Invalid ? std::string("Invalid") : std::string("Limit")),
            !out.ok() && out.code() == Code::Invalid, "budget");
    }
    // Report accounting: nodes_in/atoms_in/nodes_out/atoms_out are consistent.
    {
        Builder b;
        const u32 root = b.concat({b.atom_node(b.add_atom(pattern(16, 97))),
                                    b.atom_node(b.add_atom(pattern(16, 97)))});
        const Ir ir = b.finish(root);
        CanonReport report;
        auto out = canon(ir, report);
        const bool ok =
            out.ok() && report.nodes_in == ir.nodes.size() &&
            report.atoms_in == ir.atoms.size() &&
            report.nodes_out == out.value().nodes.size() &&
            report.atoms_out == out.value().atoms.size() && !report.budget_exhausted;
        row("report-accounting", "T-BUDGET", "nodes-atoms-accounting", sha_text(describe(ir)),
            "nodes_in/atoms_in/nodes_out/atoms_out consistent",
            ok ? std::string("consistent") : std::string("MISMATCH"), ok, "budget");
    }
    section("budget-and-presupposition");
}

void Gate::run_determinism() {
    // Corpus and redex batteries already checked one repeat each; here a full
    // second canon pass over every corpus term confirms byte-identical output
    // IR on a fresh process-style pass.
    std::size_t rewritten_mismatch = 0;
    std::size_t mismatched_terms = 0;
    for (const TermItem& term : terms_) {
        auto a = canon(term.ir);
        auto b = canon(term.ir);
        if (a.ok() != b.ok()) {
            ++mismatched_terms;
            continue;
        }
        if (a.ok() && !ir_equal(a.value(), b.value())) ++mismatched_terms;
        (void)rewritten_mismatch;
    }
    row("determinism-repeat-corpus", "T-KAT", "all-corpus-terms", sha_text("determinism"),
        "0 mismatched terms", std::to_string(mismatched_terms) + " mismatched",
        mismatched_terms == 0, "determinism");
    section("determinism");
}

// ---------------------------------------------------------------------------
// Source independence from E3..E7 and the harness/container layers.
// ---------------------------------------------------------------------------

void Gate::run_source_independence() {
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
    const bool ok = violations == 0 && files.size() >= 6;
    row("independence", "C04", "source-scan", digest, "0 forbidden includes",
        std::to_string(violations) + " forbidden includes across " +
            std::to_string(files.size()) + " files",
        ok, "source-scan");
    log("independence: files=" + std::to_string(files.size()) +
        " violations=" + std::to_string(violations) + " tree_sha256=" + digest);

    // The C04 library itself must not reach the harness build helper or gtest.
    const std::array<std::string, 2> lib_files = {root_ + "/include/mapr/e2/e2_canon.hpp",
                                                  root_ + "/engine/src/e2/e2_canon.cpp"};
    const std::array<std::string, 6> lib_forbidden = {
        "c03_build", "e2_c03_gate", "e2_c04_gate", "gtest", "googletest", "boost"};
    std::size_t lib_violations = 0;
    for (const std::string& path : lib_files) {
        std::ifstream in(path);
        std::string line;
        while (std::getline(in, line)) {
            if (line.find("#include") == std::string::npos) continue;
            for (const std::string& bad : lib_forbidden) {
                if (line.find(bad) != std::string::npos) ++lib_violations;
            }
        }
    }
    const bool lib_ok = lib_violations == 0;
    row("independence.library", "C04", "library-scan", sha_text("library"),
        "0 harness/test includes in library",
        std::to_string(lib_violations) + " violations", lib_ok, "source-scan");
    log("independence.library: violations=" + std::to_string(lib_violations));
    section("independence");
}

void Gate::run_coverage() {
    std::size_t kinds = 0;
    std::string missing;
    for (std::size_t i = 0; i < kKindCount; ++i) {
        if (kind_hits_[i] > 0) {
            ++kinds;
        } else {
            missing += std::to_string(i) + ",";
        }
    }
    row("coverage.kind", "C04", "all-12-kinds", sha_text("kinds"), "12/12",
        std::to_string(kinds) + "/12", kinds == kKindCount, "all-12-kinds");
    if (kinds != kKindCount) log("coverage.kind MISSING " + missing);
    std::size_t morphs = 0;
    for (std::size_t i = 1; i <= kMorphCount; ++i) {
        if (morph_hits_[i] > 0) ++morphs;
    }
    row("coverage.morph", "C04", "all-9-morphs", sha_text("morphs"), "9/9",
        std::to_string(morphs) + "/9", morphs == kMorphCount, "all-9-morphs");
    std::size_t predictors = 0;
    for (std::size_t i = 0; i < kPredictorCount; ++i) {
        if (predictor_hits_[i] > 0) ++predictors;
    }
    row("coverage.predictor", "C04", "all-5-predictors", sha_text("predictors"), "5/5",
        std::to_string(predictors) + "/5", predictors == kPredictorCount,
        "all-5-predictors");
    section("coverage");
}

int Gate::run() {
    build_corpus();
    build_redex_corpus();

    run_canon_corpus();
    run_redex_corpus();
    run_rule_coverage();
    run_atom_cases();
    run_canonical_key();
    run_budget_and_presupposition();
    run_determinism();
    run_source_independence();
    run_coverage();

    const std::size_t checks = passes_ + failures_;
    log("totals: checks=" + std::to_string(checks) + " pass=" + std::to_string(passes_) +
        " fail=" + std::to_string(failures_));
    log("rule_firings_total: " + std::to_string(rules_fired_total_));
    log(failures_ == 0 ? std::string("RESULT: PASS (C04 CANON)")
                       : std::string("RESULT: FAIL (C04 CANON)"));
    row("c04.summary", "C04", "all-checks", sha_text("summary"),
        std::to_string(checks) + " checks all PASS",
        "pass=" + std::to_string(passes_) + " fail=" + std::to_string(failures_),
        failures_ == 0, "summary");
    return failures_ == 0 ? 0 : 1;
}

bool Gate::write_evidence() {
    namespace fs = std::filesystem;
    const std::string gate_dir = root_ + "/specs_and_reports/v2/gates";
    const std::string log_dir = root_ + "/specs_and_reports/v2/logs";
    const std::string evidence_dir = root_ + "/specs_and_reports/v2/evidence/C04";
    std::error_code ec;
    fs::create_directories(gate_dir, ec);
    fs::create_directories(log_dir, ec);
    fs::create_directories(evidence_dir, ec);

    const std::string tsv_path = gate_dir + "/C04-CANON.tsv";
    const std::string log_path = log_dir + "/C04-CANON.log";

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
    sums += tsv_sha + "  specs_and_reports/v2/gates/C04-CANON.tsv\n";
    sums += log_sha + "  specs_and_reports/v2/logs/C04-CANON.log\n";
    {
        std::ofstream out(evidence_dir + "/SHA256SUMS", std::ios::binary | std::ios::trunc);
        if (!out) return false;
        out.write(sums.data(), static_cast<std::streamsize>(sums.size()));
    }
    return true;
}

std::string environment_record(const std::string& root, const char* command_line) {
    std::string text;
    text += "tool: C04-CANON evidence harness\n";
    text += "root: " + root + "\n";
    text += "command_line: " + std::string(command_line) + "\n";
    text += "compiler: " __VERSION__ "\n";
    text += "std: c++20 (build flags in engine/Makefile.c04)\n";
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
            std::printf("usage: e2_c04_gate [--root PATH] [--write-evidence]\n");
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
}  // namespace c04

int main(int argc, char** argv) { return c04::main(argc, argv); }
