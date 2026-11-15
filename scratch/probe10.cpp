#include <cstdio>
#include <map>
#include <string>
#include "e2g_corpus.hpp"
#include "e2g_terms.hpp"
#include "mapr/e2/e2_canon.hpp"
using namespace e2g;
using namespace marp::v2;
int main() {
    Corpus c = build_corpus();
    std::map<std::string, std::array<int,6>> per_family; // [a, b, wf_fail, fired_fail, join_fail, ok]
    for (auto& t : c.terms) {
        if (t.corpus != "T-CRIT") continue;
        const std::string fam = t.desc.note.substr(0, t.desc.note.find('/'));
        auto& st = per_family[fam];
        st[0] = t.crit_rule_a; st[1] = t.crit_rule_b;
        auto a = bind(t.desc);
        TermDesc alt = t.alt; alt.id = t.id + "-alt"; alt.root = t.alt_root;
        auto b = bind(alt);
        if (!a.ok || !b.ok) { st[2]++; continue; }
        auto wa = check_well_formed_report(a.ir), wb = check_well_formed_report(b.ir);
        if (!wa.ok() || !wb.ok()) { st[2]++; continue; }
        CanonReport ra, rb;
        auto ca = canon(a.ir, ra), cb = canon(b.ir, rb);
        if (!ca.ok() || !cb.ok()) { st[2]++; continue; }
        const bool fired = ra.rule_fires[t.crit_rule_a-1] > 0 && ra.rule_fires[t.crit_rule_b-1] > 0;
        const bool join = canonical_key(ca.value(), ca.value().root) == canonical_key(cb.value(), cb.value().root);
        if (!fired) st[3]++;
        if (!join) st[4]++;
        if (fired && join) st[5]++;
        if (!join || !fired) {
            printf("  %-28s rules=%2d/%2d fired=%d join=%d  A=", fam.c_str(), t.crit_rule_a, t.crit_rule_b, (int)fired, (int)join);
            for (int i=0;i<13;++i) if (ra.rule_fires[i]) printf("%d ", i+1);
            printf(" B=");
            for (int i=0;i<13;++i) if (rb.rule_fires[i]) printf("%d ", i+1);
            printf("\n");
        }
    }
    printf("\n%-30s %5s %5s %5s %5s %5s\n", "family", "rA", "rB", "wfF", "firF", "joinF");
    int tot_wf=0, tot_f=0, tot_j=0;
    for (auto& [name, st] : per_family) {
        if (st[2]||st[3]||st[4])
            printf("%-30s %5d %5d %5d %5d %5d\n", name.c_str(), st[0], st[1], st[2], st[3], st[4]);
        tot_wf+=st[2]; tot_f+=st[3]; tot_j+=st[4];
    }
    printf("TOTALS wf_fail=%d fired_fail=%d join_fail=%d\n", tot_wf, tot_f, tot_j);
    return 0;
}
