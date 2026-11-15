#include <cstdio>
#include <string>
#include "e2g_terms.hpp"
#include "mapr/e2/e2_canon.hpp"
using namespace e2g;
using namespace marp::v2;
void one(const char* label, const std::string& root, DescArena& a) {
    TermDesc d; d.id=label; d.corpus="p"; d.arena=a; d.root=root;
    auto b = bind(d);
    if (!b.ok) { printf("%-36s BIND FAIL %s\n", label, b.error.c_str()); return; }
    auto wf = check_well_formed_report(b.ir);
    if (!wf.ok()) { printf("%-36s WF FAIL %s\n", label, wf.constraint); return; }
    CanonReport rep; auto c = canon(b.ir, rep);
    printf("%-36s rewrites=%llu fires=[", label, (unsigned long long)rep.rewrites);
    for (int i=0;i<13;++i) if (rep.rule_fires[i]) printf("%d ", i+1);
    printf("]\n");
}
int main(){
    { // c = xor(atom, atom), c cancel
        DescArena a;
        auto x=a.atom_node(a.atom_bytes("x",8,1)); auto y=a.atom_node(a.atom_bytes("y",8,2));
        auto c=a.xor_node(x,y);
        one("xor(c, c) both cancel", a.xor_node(c,c), a);
    }
    { // c = xor(atom, atom) inside a concat, cancel at two spots
        DescArena a;
        auto x=a.atom_node(a.atom_bytes("x",8,1)); auto y=a.atom_node(a.atom_bytes("y",8,2));
        auto c=a.xor_node(x,y);
        one("concat(xor(c,c),xor(c,c))", a.concat({a.xor_node(c,c), a.xor_node(c,c)}), a);
    }
    { // repeat(atom,1,3) then slice: what rule 5 first does
        DescArena a; auto c=a.atom_node(a.atom_bytes("x",16,3));
        one("repeat(atom,1,3) alone", a.repeat(c,1,3), a);
        one("slice(repeat(atom,1,3),1,2)", a.slice(a.repeat(c,1,3),1,2), a);
    }
    { // rule 5 then rule 6: nested slice on a Repeat
        DescArena a; auto c=a.atom_node(a.atom_bytes("x",16,3));
        auto r=a.repeat(c,1,3);
        one("slice(slice(repeat(r,1,3),1,2),0,1)", a.slice(a.slice(r,1,2),0,1), a);
    }
    { // rule 7 chain rotl3.rotr3 then rotl3
        DescArena a; auto c=a.atom_node(a.atom_bytes("x",8,4));
        auto chain = a.morph(a.morph(c,6,3),7,3);
        one("rotl3.rotr3", chain, a);
        one("rotl3.rotl3", a.morph(a.morph(c,6,3),6,3), a);
        one("rotl3.rotr3.morph2", a.morph(chain, 2, 0), a);
    }
    { // rule 11 candidates
        DescArena a;
        one("repeat(repeat(zero,2,0),2,0)", a.repeat(a.repeat(a.zero(4),2,0),2,0), a);
        one("slice(repeat(zero,2,0),0,3)", a.slice(a.repeat(a.zero(4),2,0),0,3), a);
        one("repeat(zero,2,1)", a.repeat(a.zero(4),2,1), a);
        one("repeat(zero,0,0)", a.repeat(a.zero(4),0,0), a);
    }
    return 0;
}
