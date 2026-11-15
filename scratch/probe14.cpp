#include <cstdio>
#include <functional>
#include <string>
#include <vector>
#include "e2g_terms.hpp"
#include "mapr/e2/e2_canon.hpp"
using namespace e2g;
using namespace marp::v2;
struct T { const char* name; std::function<std::string(DescArena&)> a, b; };
int main(){
    std::vector<T> ts = {
      {"r1|r3 concat(atom,[atom,atom])", 
       [](DescArena& a){ auto x=a.atom_node(a.atom_bytes("x",8,1)); auto y=a.atom_node(a.atom_bytes("y",8,2)); auto z=a.atom_node(a.atom_bytes("z",8,3));
                         return a.concat({x, a.concat({y,z})}); },
       [](DescArena& a){ auto x=a.atom_node(a.atom_bytes("x",8,1)); auto y=a.atom_node(a.atom_bytes("y",8,2)); auto z=a.atom_node(a.atom_bytes("z",8,3));
                         return a.concat({x, y, z}); }},
      {"r1|r4 concat(zero,[zero,zero])",
       [](DescArena& a){ return a.concat({a.zero(4), a.concat({a.zero(5), a.zero(6)})}); },
       [](DescArena& a){ return a.concat({a.zero(4), a.zero(5), a.zero(6)}); }},
      {"r1|r2 concat(empty,[zero,zero])",
       [](DescArena& a){ return a.concat({a.empty(), a.concat({a.zero(5), a.zero(6)})}); },
       [](DescArena& a){ return a.concat({a.zero(5), a.zero(6)}); }},
      {"r5|r6 repeat-then-slice",
       [](DescArena& a){ auto c=a.atom_node(a.atom_bytes("x",16,11)); return a.slice(a.repeat(c,1,3),1,2); },
       [](DescArena& a){ auto c=a.atom_node(a.atom_bytes("x",16,11)); return a.slice(a.slice(c,1,2),0,2); }},
      {"r6|r6 slice-assoc atom",
       [](DescArena& a){ auto c=a.atom_node(a.atom_bytes("x",32,12)); return a.slice(a.slice(c,2,20),3,6); },
       [](DescArena& a){ auto c=a.atom_node(a.atom_bytes("x",32,12)); return a.slice(c,5,6); }},
      {"r6|r6 slice-of-repeat-slice",
       [](DescArena& a){ auto c=a.atom_node(a.atom_bytes("x",32,12)); return a.slice(a.slice(c,2,20),1,10); },
       [](DescArena& a){ auto c=a.atom_node(a.atom_bytes("x",32,12)); return a.slice(a.repeat(a.slice(c,2,20),1,0),1,10); }},
      {"r11|r6 slice(concat(zero,zero))",
       [](DescArena& a){ return a.slice(a.concat({a.zero(8), a.zero(9)}), 2, 4); },
       [](DescArena& a){ return a.concat({a.slice(a.zero(8),2,4), a.zero(0)}); }},
      {"r8|r8 xor(c,c) with c=xor(a,b)",
       [](DescArena& a){ auto x=a.atom_node(a.atom_bytes("x",8,4)); auto y=a.atom_node(a.atom_bytes("y",8,5)); auto c=a.xor_node(x,y);
                         return a.xor_node(c,c); },
       [](DescArena& a){ return a.zero(8); }},
      {"r8|r12 xor(c,c') duplicates",
       [](DescArena& a){ auto p=a.atom_bytes("p",8,90); auto q=a.atom_bytes("q",8,90);
                         return a.xor_node(a.atom_node(p), a.atom_node(q)); },
       [](DescArena& a){ auto p=a.atom_node(a.atom_bytes("p",8,90)); return a.zero(8); }},
      {"r7|r7 rot chain",
       [](DescArena& a){ auto c=a.atom_node(a.atom_bytes("x",8,6)); return a.morph(a.morph(c,6,3),7,3); },
       [](DescArena& a){ auto c=a.atom_node(a.atom_bytes("x",8,6)); return a.morph(a.morph(a.morph(c,6,3),7,3),6,0); }},
      {"r10|r10 affine step0 x2",
       [](DescArena& a){ return a.xor_node(a.affine(7,0,16), a.affine(7,0,16)); },
       [](DescArena& a){ return a.zero(16); }},
      {"r11|r11 repeat(zero) nested-ish",
       [](DescArena& a){ return a.repeat(a.zero(4),2,1); },
       [](DescArena& a){ return a.concat({a.repeat(a.zero(4),1,0), a.slice(a.zero(4),0,1)}); }},
      {"r3|r4 atoms+zeros same order",
       [](DescArena& a){ auto x=a.atom_node(a.atom_bytes("x",8,7)); auto y=a.atom_node(a.atom_bytes("y",8,8));
                         return a.concat({x, y, a.zero(3)}); },
       [](DescArena& a){ auto x=a.atom_node(a.atom_bytes("x",8,7)); auto y=a.atom_node(a.atom_bytes("y",8,8));
                         return a.concat({x, y, a.zero(3)}); }},
      {"r2|r2 empties x2",
       [](DescArena& a){ auto c=a.atom_node(a.atom_bytes("x",8,9)); return a.concat({c, a.concat({a.empty(), a.empty()})}); },
       [](DescArena& a){ auto c=a.atom_node(a.atom_bytes("x",8,9)); return a.concat({c, a.empty()}); }},
    };
    for (auto& t : ts) {
        DescArena a1; auto r1 = t.a(a1); TermDesc d1; d1.id="A"; d1.arena=a1; d1.root=r1;
        DescArena a2; auto r2 = t.b(a2); TermDesc d2; d2.id="B"; d2.arena=a2; d2.root=r2;
        auto b1=bind(d1), b2=bind(d2);
        if (!b1.ok||!b2.ok) { printf("%-34s BIND %s | %s\n", t.name, b1.ok?"ok":b1.error.c_str(), b2.ok?"ok":b2.error.c_str()); continue; }
        auto w1=check_well_formed_report(b1.ir), w2=check_well_formed_report(b2.ir);
        if (!w1.ok()||!w2.ok()) { printf("%-34s WF %s | %s\n", t.name, w1.ok()?"Ok":w1.constraint, w2.ok()?"Ok":w2.constraint); continue; }
        CanonReport c1,c2; auto k1=canon(b1.ir,c1), k2=canon(b2.ir,c2);
        bool join = k1.ok()&&k2.ok()&& canonical_key(k1.value(),k1.value().root)==canonical_key(k2.value(),k2.value().root);
        printf("%-34s %-7s A=[", t.name, join?"JOIN":"DIVERGE");
        for(int i=0;i<13;++i) if(c1.rule_fires[i]) printf("%d ",i+1);
        printf("] B=[");
        for(int i=0;i<13;++i) if(c2.rule_fires[i]) printf("%d ",i+1);
        printf("]\n");
    }
    return 0;
}
