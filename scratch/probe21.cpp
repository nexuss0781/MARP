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
    if (!b.ok) { printf("%-40s BIND %s\n", label, b.error.c_str()); return; }
    auto wf = check_well_formed_report(b.ir);
    if (!wf.ok()) { printf("%-40s WF %s\n", label, wf.constraint); return; }
    CanonReport rep; auto c = canon(b.ir, rep);
    printf("%-40s n=%2zu rew=%2llu fires=[", label, b.ir.nodes.size(), (unsigned long long)rep.rewrites);
    for (int i=0;i<13;++i) if (rep.rule_fires[i]) printf("%d ", i+1);
    printf("]\n");
}
int main(){
    one("ilv1([invert(invert(x))],1)", [](DescArena& a){
        auto x=a.atom_node(a.atom_bytes("x",8,15));
        return a.interleave({a.morph(a.morph(x,2,0),2,0)}, 1); });
    one("ilv1([invert(invert(x))],2)", [](DescArena& a){
        auto x=a.atom_node(a.atom_bytes("x",8,15));
        return a.interleave({a.morph(a.morph(x,2,0),2,0)}, 2); });
    one("ilv2([invert(invert(x)),y],2)", [](DescArena& a){
        auto x=a.atom_node(a.atom_bytes("x",8,15)); auto y=a.atom_node(a.atom_bytes("y",8,16));
        return a.interleave({a.morph(a.morph(x,2,0),2,0), y}, 2); });
    one("slice(slice(c,1,200),2,8)", [](DescArena& a){
        auto c=a.atom_node(a.atom_bytes("x",256,12));
        return a.slice(a.slice(c,1,200),2,8); });
    one("concat(zero2,zero3,x,x2)", [](DescArena& a){
        auto x=a.atom_node(a.atom_bytes("x",4,11)); auto y=a.atom_node(a.atom_bytes("y",4,12));
        return a.concat({a.zero(2),a.zero(3),x,y}); });
    // interleave with 1 child, stride dividing length, and a morph chain outside
    one("morph(ilv1([x],2))", [](DescArena& a){
        auto x=a.atom_node(a.atom_bytes("x",8,17));
        return a.morph(a.interleave({x},2), 2, 0); });
    return 0;
}
