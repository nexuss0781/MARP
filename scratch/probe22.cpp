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
    if (!b.ok) { printf("%-46s BIND %s\n", label, b.error.c_str()); return; }
    auto wf = check_well_formed_report(b.ir);
    if (!wf.ok()) { printf("%-46s WF %s\n", label, wf.constraint); return; }
    CanonReport rep; auto c = canon(b.ir, rep);
    printf("%-46s nodes=%2zu rew=%2llu fires=[", label, b.ir.nodes.size(), (unsigned long long)rep.rewrites);
    for (int i=0;i<13;++i) if (rep.rule_fires[i]) printf("%d ", i+1);
    printf("] root_kind=%s\n", kind_name(b.ir.nodes[b.ir.root].kind));
}
int main(){
    one("concat(x, concat(y,z))", [](DescArena& a){
        auto x=a.atom_node(a.atom_bytes("x",4,1)); auto y=a.atom_node(a.atom_bytes("y",4,2)); auto z=a.atom_node(a.atom_bytes("z",4,3));
        return a.concat({x, a.concat({y,z})}); });
    one("concat(concat(x,y), z)", [](DescArena& a){
        auto x=a.atom_node(a.atom_bytes("x",4,1)); auto y=a.atom_node(a.atom_bytes("y",4,2)); auto z=a.atom_node(a.atom_bytes("z",4,3));
        return a.concat({a.concat({x,y}), z}); });
    one("concat(x, concat(y,z), w)", [](DescArena& a){
        auto x=a.atom_node(a.atom_bytes("x",4,1)); auto y=a.atom_node(a.atom_bytes("y",4,2)); auto z=a.atom_node(a.atom_bytes("z",4,3));
        auto w=a.atom_node(a.atom_bytes("w",4,4));
        return a.concat({x, a.concat({y,z}), w}); });
    one("concat(zero2, concat(zero3,zero4))", [](DescArena& a){
        return a.concat({a.zero(2), a.concat({a.zero(3), a.zero(4)})}); });
    one("ilv1([morph(morph(x))],1)", [](DescArena& a){
        auto x=a.atom_node(a.atom_bytes("x",8,15));
        return a.interleave({a.morph(a.morph(x,2,0),2,0)}, 1); });
    return 0;
}
