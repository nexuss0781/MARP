#include <cstdio>
#include <map>
#include "e2g_corpus.hpp"
#include "e2g_terms.hpp"
#include "mapr/e2/e2_canon.hpp"
using namespace e2g;
using namespace marp::v2;
int main(){
    Corpus c = build_corpus();
    std::map<std::string,int> joinfail;
    for (auto& t : c.terms) {
        if (t.corpus != "T-CRIT") continue;
        const std::string fam = t.desc.note.substr(0, t.desc.note.find('/'));
        auto a = bind(t.desc);
        TermDesc alt = t.alt; alt.id=t.id+"-alt"; alt.root=t.alt_root;
        auto b = bind(alt);
        if (!a.ok||!b.ok) continue;
        auto wa=check_well_formed_report(a.ir), wb=check_well_formed_report(b.ir);
        if(!wa.ok()||!wb.ok()) continue;
        auto ca = canon(a.ir), cb = canon(b.ir);
        if(!ca.ok()||!cb.ok()) continue;
        if (canonical_key(ca.value(),ca.value().root)!=canonical_key(cb.value(),cb.value().root)) {
            if (joinfail[fam]++ == 0) {
                printf("%s: A nodes=%zu B nodes=%zu\n", fam.c_str(), a.ir.nodes.size(), b.ir.nodes.size());
                printf("  A=%s\n", describe_ir(ca.value()).substr(0,220).c_str());
                printf("  B=%s\n", describe_ir(cb.value()).substr(0,220).c_str());
            }
        }
    }
    for (auto& [k,v] : joinfail) printf("%-28s join_fail=%d\n", k.c_str(), v);
    return 0;
}
