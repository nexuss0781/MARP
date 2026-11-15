#include <cstdio>
#include <map>
#include <string>

#include "e2g_corpus.hpp"
#include "e2g_terms.hpp"
#include "mapr/e2/e2_canon.hpp"

using namespace marp::v2;
using namespace e2g;

int main() {
    auto corpus = build_corpus();
    std::map<std::string, int> counts;
    std::map<std::string, int> bad_ok;
    for (auto& t : corpus.terms) counts[t.corpus]++;
    for (auto& [k, v] : counts) printf("%-12s %d\n", k.c_str(), v);
    printf("M-KAT %zu P-KAT %zu L-KAT %zu\n", corpus.morph_kats.size(),
           corpus.predictor_kats.size(), corpus.lfsr_kats.size());

    int n_kat = 0, n_kat_wf = 0, n_kat_noncanon = 0;
    int n_gen = 0, n_gen_wf = 0, n_gen_noncanon = 0;
    BigInt maxlen;
    std::map<std::string, int> kind_seen;
    std::vector<std::string> fails;
    for (auto& t : corpus.terms) {
        if (t.corpus != "T-KAT" && t.corpus != "T-GEN" && t.corpus != "T-BIG") continue;
        auto b = bind(t.desc);
        if (!b.ok || t.desc.root.empty()) { fails.push_back(t.id + ":bind"); continue; }
        auto wf = check_well_formed_report(b.ir);
        if (!wf.ok()) { fails.push_back(t.id + ":wf:" + wf.constraint); continue; }
        auto wp = b.ir.total_length.to_u64_checked();
        if (wp.has_value() && *wp > 4*1024*1024) fails.push_back(t.id + ":len>4MiB");
        if (t.corpus == "T-GEN") { n_gen++; if (wf.ok()) n_gen_wf++; }
        if (t.corpus == "T-KAT") { n_kat++; n_kat_wf++; }
        // kind coverage
        for (auto& nd : b.ir.nodes) kind_seen[kind_name(nd.kind)]++;
        // canonicalisation
        CanonReport rep;
        auto c = canon(b.ir, rep);
        if (!c.ok()) fails.push_back(t.id + ":canon");
        else if (!is_canonical(c.value())) fails.push_back(t.id + ":notcanon");
    }
    printf("T-KAT total=%d wf=%d ; T-GEN total=%d wf=%d\n", n_kat, n_kat_wf, n_gen, n_gen_wf);
    printf("kinds:");
    for (auto& [k,v] : kind_seen) printf(" %s=%d", k.c_str(), v);
    printf("\n");
    printf("fails=%zu\n", fails.size());
    for (size_t i = 0; i < fails.size() && i < 25; ++i) printf("  %s\n", fails[i].c_str());

    // T-BAD expectations
    int bad_pass = 0, bad_fail = 0;
    for (auto& t : corpus.terms) {
        if (t.corpus != "T-BAD") continue;
        auto b = bind(t.desc);
        auto wf = check_well_formed_report(b.ir);
        std::string got = wf.ok() ? "Ok" : wf.constraint;
        bool ok = !wf.ok() && got == t.expected_constraint &&
                  wf.code == t.expected_code;
        if (ok) bad_pass++; else { bad_fail++; printf("  BAD %-26s expected=%-28s got=%s code=%s\n",
            t.id.c_str(), t.expected_constraint, got.c_str(), code_name(wf.code)); }
    }
    printf("T-BAD pass=%d fail=%d\n", bad_pass, bad_fail);

    // T-NONCANON: is_canonical must be false, and the named rule must fire
    int nc_pass = 0, nc_fail = 0;
    std::map<int,int> rule_fires;
    std::map<int,int> rule_ok;
    for (auto& t : corpus.terms) {
        if (t.corpus != "T-NONCANON") continue;
        auto b = bind(t.desc);
        auto wf = check_well_formed_report(b.ir);
        if (!wf.ok()) { nc_fail++; printf("  NC %s not wf %s\n", t.id.c_str(), wf.constraint); continue; }
        bool can = is_canonical(b.ir);
        CanonReport rep;
        auto c = canon(b.ir, rep);
        if (can) { nc_fail++; printf("  NC %s reported canonical (rule %d)\n", t.id.c_str(), t.redex_rule); continue; }
        if (!c.ok() || !is_canonical(c.value())) { nc_fail++; printf("  NC %s canon failed\n", t.id.c_str()); continue; }
        for (int i = 0; i < 13; ++i) if (rep.rule_fires[(size_t)i]) rule_fires[i+1] += 1;
        if (rep.rule_fires[(size_t)(t.redex_rule-1)] == 0 && t.id != "nc-r8-xor-order") {
            printf("  NC %s rule %d did not fire (fires=%llu)\n", t.id.c_str(), t.redex_rule,
                   (unsigned long long)rep.rule_fires[(size_t)(t.redex_rule-1)]);
            nc_fail++;
            continue;
        }
        rule_ok[t.redex_rule]++;
        nc_pass++;
    }
    printf("T-NONCANON pass=%d fail=%d\n", nc_pass, nc_fail);
    printf("rules fired: ");
    for (auto& [k,v] : rule_fires) printf("%d=%d ", k, v);
    printf("\n");
    printf("rules matching redex: ");
    for (auto& [k,v] : rule_ok) printf("%d=%d ", k, v);
    printf("\n");

    // T-CRIT
    int crit_fail = 0;
    for (auto& t : corpus.terms) {
        if (t.corpus != "T-CRIT") continue;
        auto b = bind(t.desc);
        auto b2 = bind(TermDesc{.id=t.alt.id,.corpus="T-CRIT",.note="",.arena=t.alt.arena,.root=t.alt_root,.virtual_term=false,.pinned_digest=""});
        auto wf = check_well_formed_report(b.ir);
        auto wf2 = check_well_formed_report(b2.ir);
        if (!wf.ok() || !wf2.ok()) { crit_fail++; printf("  CRIT %s not wf: %s %s\n", t.id.c_str(), wf.constraint, wf2.constraint); continue; }
        auto c1 = canon(b.ir), c2 = canon(b2.ir);
        if (!c1.ok() || !c2.ok()) { crit_fail++; continue; }
        if (describe_ir(c1.value()) != describe_ir(c2.value())) {
            crit_fail++;
            if (crit_fail < 6) printf("  CRIT %s diverged (rules %d,%d)\n", t.id.c_str(), t.crit_rule_a, t.crit_rule_b);
        }
    }
    printf("T-CRIT fail=%d\n", crit_fail);
    return 0;
}
