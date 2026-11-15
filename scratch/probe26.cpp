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
    if (!b.ok) { printf("%-48s BIND %s\n", label, b.error.c_str()); return; }
    auto wf = check_well_formed_report(b.ir);
    if (!wf.ok()) { printf("%-48s WF %s\n", label, wf.constraint); return; }
    CanonReport rep; auto c = canon(b.ir, rep);
    printf("%-48s rew=%2llu fires=[", label, (unsigned long long)rep.rewrites);
    for (int i=0;i<13;++i) if (rep.rule_fires[i]) printf("%d ", i+1);
    printf("]\n");
}
int main(){
    // rule 1 reachable: Repeat(atom,1,r) normalises into a Concat child
    one("concat(x, repeat(atom8,1,3))", [](DescArena& a){
        auto x=a.atom_node(a.atom_bytes("x",4,1));
        auto c=a.atom_node(a.atom_bytes("c",8,2));
        return a.concat({x, a.repeat(c,1,3)}); });
    one("concat(repeat(atom8,1,3), x)", [](DescArena& a){
        auto x=a.atom_node(a.atom_bytes("x",4,1));
        auto c=a.atom_node(a.atom_bytes("c",8,2));
        return a.concat({a.repeat(c,1,3), x}); });
    one("concat(repeat(atom8,1,3), repeat(atom8,1,5))", [](DescArena& a){
        auto c=a.atom_node(a.atom_bytes("c",8,2)); auto d=a.atom_node(a.atom_bytes("d",8,3));
        return a.concat({a.repeat(c,1,1), a.repeat(d,1,2)}); });
    // rule 6 + 11 overlap: nested slices above repeat-of-zero
    one("slice(slice(repeat(zero4,2,0),0,4),1,2)", [](DescArena& a){
        return a.slice(a.slice(a.repeat(a.zero(4),2,0),0,4),1,2); });
    one("slice(slice(repeat(zero4,2,0),1,4),1,2)", [](DescArena& a){
        return a.slice(a.slice(a.repeat(a.zero(4),2,0),1,4),1,2); });
    // rule 3 + 4 in one concat with an intervening Repeat
    one("concat(x, repeat(c,1,2), zero3, zero4)", [](DescArena& a){
        auto x=a.atom_node(a.atom_bytes("x",4,1)); auto c=a.atom_node(a.atom_bytes("c",8,2));
        return a.concat({x, a.repeat(c,1,2), a.zero(3), a.zero(4)}); });
    return 0;
}
