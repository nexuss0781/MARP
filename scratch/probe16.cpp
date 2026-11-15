#include <cstdio>
#include <map>
#include "e2g_corpus.hpp"
#include "e2g_terms.hpp"
#include "mapr/e2/e2_canon.hpp"
using namespace e2g;
using namespace marp::v2;
int main(){
    Corpus c = build_corpus();
    std::map<std::string,int> counts;
    for (auto& t : c.terms) counts[t.corpus]++;
    for (auto& [k,v] : counts) printf("%-12s %5d\n", k.c_str(), v);
    printf("M-KAT %zu  P-KAT %zu  L-KAT %zu\n", c.morph_kats.size(), c.predictor_kats.size(), c.lfsr_kats.size());
    // T-BAD: bind + wf
    for (auto& t : c.terms) {
        if (t.corpus != "T-BAD") continue;
        auto b = bind(t.desc);
        Ir ir = b.ir;
        if (std::string(t.id)=="bad-root") { auto r2 = bind_with(t.desc, "missing-root", std::nullopt); ir = r2.ir; }
        if (std::string(t.id)=="bad-total-length") { ir.total_length = ir.nodes[ir.root].length.add(BigInt(1)).value(); }
        auto wf = check_well_formed_report(ir);
        const char* got = wf.ok() ? "Ok" : wf.constraint;
        const bool ok = !wf.ok() && std::string(got)==t.expected_constraint && wf.code==t.expected_code;
        if (!ok) printf("  BAD %-28s expected=%s/%s got=%s/%s bind=%d\n", t.id.c_str(),
                        wf.ok()?"?":code_name(t.expected_code), t.expected_constraint, code_name(wf.code), got, (int)b.ok);
    }
    // T-NONCANON redex firing
    std::map<int,int> fired, declared;
    for (auto& t : c.terms) {
        if (t.corpus != "T-NONCANON") continue;
        declared[t.redex_rule]++;
        auto b = bind(t.desc);
        if (!b.ok) { printf("  NC BIND %s: %s\n", t.id.c_str(), b.error.c_str()); continue; }
        CanonReport rep; auto r = canon(b.ir, rep);
        if (!r.ok()) { printf("  NC CANON %s: %s\n", t.id.c_str(), code_name(r.code())); continue; }
        if (t.redex_rule>=1 && t.redex_rule<=13 && rep.rule_fires[t.redex_rule-1]>0) fired[t.redex_rule]++;
        else printf("  NC NOFIRE %-30s rule=%d\n", t.id.c_str(), t.redex_rule);
    }
    printf("rule: declared/fired\n");
    for (int r=1;r<=13;++r) printf("  %2d: %2d/%2d %s\n", r, declared[r], fired[r], fired[r]==0?"<<< MISSING":"");
    return 0;
}
