#include <cstdio>
#include <functional>
#include <string>
#include "e2g_terms.hpp"
#include "mapr/e2/e2_canon.hpp"
using namespace e2g;
using namespace marp::v2;
void one(const char* label, const std::function<std::string(DescArena&)>& f) {
    DescArena a; auto root = f(a);
    TermDesc d; d.id=label; d.corpus="p"; d.arena=a; d.root=root;
    auto b = bind(d);
    if (!b.ok) { printf("%-52s BIND %s\n", label, b.error.c_str()); return; }
    auto wf = check_well_formed_report(b.ir);
    if (!wf.ok()) { printf("%-52s WF %s\n", label, wf.constraint); return; }
    CanonReport rep; auto c = canon(b.ir, rep);
    printf("%-52s rew=%2llu fires=[", label, (unsigned long long)rep.rewrites);
    for (int i=0;i<13;++i) if (rep.rule_fires[i]) printf("%d ", i+1);
    printf("]\n");
}
int main(){
    // 6 vs 11: outer Slice-of-Slice above Slice-of-Zero
    one("slice(slice(zero8,1,6),1,4)", [](DescArena& a){ return a.slice(a.slice(a.zero(8),1,6),1,4); });
    one("slice(slice(repeat(zero4,2,0),1,6),1,4)", [](DescArena& a){
        return a.slice(a.slice(a.repeat(a.zero(4),2,0),1,6),1,4); });
    // 7 vs 9: rule 7 pending where rule 9 fires (morph outside a 1-child ilv)
    one("morph(ilv1([morph(morph(x))]))", [](DescArena& a){
        auto x=a.atom_node(a.atom_bytes("x",8,1));
        return a.morph(a.interleave({a.morph(a.morph(x,2,0),2,0)},1),2,0); });
    one("ilv1([morph(morph(x))]) root", [](DescArena& a){
        auto x=a.atom_node(a.atom_bytes("x",8,1));
        return a.interleave({a.morph(a.morph(x,2,0),2,0)},1); });
    return 0;
}
