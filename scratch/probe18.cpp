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
    for (auto& t : c.terms) {
        if (t.corpus != "T-NONCANON") continue;
        auto b = bind(t.desc);
        if (!b.ok) { printf("NC BIND %s\n", t.id.c_str()); continue; }
        CanonReport rep; auto r = canon(b.ir, rep);
        if (!r.ok()) { printf("NC CANON %-32s %s\n", t.id.c_str(), code_name(r.code())); continue; }
        const bool fired = t.redex_rule>=1 && t.redex_rule<=13 && rep.rule_fires[t.redex_rule-1]>0;
        if (!fired) printf("NC NOFIRE %-32s rule=%d\n", t.id.c_str(), t.redex_rule);
        if (is_canonical(b.ir)) printf("NC ISCANON %s\n", t.id.c_str());
        if (!is_canonical(r.value())) printf("NC OUTNOTCANON %s\n", t.id.c_str());
    }
    return 0;
}
