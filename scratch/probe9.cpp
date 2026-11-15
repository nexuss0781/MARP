#include <cstdio>
#include <map>
#include "e2g_corpus.hpp"
#include "e2g_terms.hpp"
#include "mapr/e2/e2_canon.hpp"
using namespace e2g;
using namespace marp::v2;
int main() {
    Corpus c = build_corpus();
    std::map<int,int> declared;
    for (auto& t : c.terms) if (t.corpus=="T-NONCANON") {
        declared[t.redex_rule]++;
        auto b = bind(t.desc);
        if (!b.ok) { printf("%-32s rule=%d BIND FAIL %s\n", t.id.c_str(), t.redex_rule, b.error.c_str()); continue; }
        auto wf = check_well_formed_report(b.ir);
        CanonReport rep; auto r = canon(b.ir, rep);
        if (!wf.ok() || !r.ok()) { printf("%-32s rule=%d wf=%s canon=%s\n", t.id.c_str(), t.redex_rule,
            wf.ok()?"Ok":wf.constraint, r.ok()?"ok":code_name(r.code())); continue; }
        const bool fired = t.redex_rule>=1 && t.redex_rule<=13 && rep.rule_fires[t.redex_rule-1]>0;
        printf("%-32s rule=%2d fired=%d fires[", t.id.c_str(), t.redex_rule, (int)fired);
        for (int i=0;i<13;++i) if (rep.rule_fires[i]) printf("%d ", i+1);
        printf("]\n");
    }
    printf("declared: ");
    for (auto& [r,n] : declared) printf("%d:%d ", r, n);
    printf("\n");
    return 0;
}
