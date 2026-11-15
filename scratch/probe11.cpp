#include <cstdio>
#include <functional>
#include <string>
#include <vector>
#include "e2g_terms.hpp"
#include "mapr/e2/e2_canon.hpp"
using namespace e2g;
using namespace marp::v2;

struct Tmpl { const char* name; int a, b; std::function<std::string(DescArena&, int)> build_a;
              std::function<std::string(DescArena&, int)> build_b; };

int main() {
    const int p = 3;  // parameter
    std::vector<Tmpl> t = {
      {"r1|r3 concat-assoc-atom", 1, 3,
       [](DescArena& a, int p){ auto x=a.atom_node(a.atom_bytes("x",4+p,1)); auto y=a.atom_node(a.atom_bytes("y",4+p,2));
                                auto z=a.atom_node(a.atom_bytes("z",4+p,3));
                                return a.concat({a.concat({x,y}), z}); },
       [](DescArena& a, int p){ auto x=a.atom_node(a.atom_bytes("x",4+p,1)); auto y=a.atom_node(a.atom_bytes("y",4+p,2));
                                auto z=a.atom_node(a.atom_bytes("z",4+p,3));
                                return a.concat({x, a.concat({y,z})}); }},
      {"r1|r4 concat-assoc-zero", 1, 4,
       [](DescArena& a, int p){ return a.concat({a.concat({a.zero(u64(2+p)), a.zero(u64(3+p))}), a.zero(u64(4+p))}); },
       [](DescArena& a, int p){ return a.concat({a.zero(u64(2+p)), a.concat({a.zero(u64(3+p)), a.zero(u64(4+p))})}); }},
      {"r2|r4 empty-zero-partition", 2, 4,
       [](DescArena& a, int p){ return a.concat({a.empty(), a.zero(u64(2+p)), a.zero(u64(3+p))}); },
       [](DescArena& a, int p){ return a.concat({a.zero(u64(2+p)), a.concat({a.empty(), a.zero(u64(3+p))})}); }},
      {"r3|r4 atoms-then-zeros", 3, 4,
       [](DescArena& a, int p){ return a.concat({a.atom_node(a.atom_bytes("x",4+p,11)),
                                                 a.atom_node(a.atom_bytes("y",4+p,12)),
                                                 a.zero(u64(5+p))}); },
       [](DescArena& a, int p){ return a.concat({a.atom_node(a.atom_bytes("x",4+p,11)),
                                                 a.atom_node(a.atom_bytes("y",4+p,12)),
                                                 a.zero(u64(2+p)), a.zero(u64(3+p))}); }},
      {"r5|r6 repeat-then-slice", 5, 6,
       [](DescArena& a, int p){ auto c=a.atom_node(a.atom_bytes("x",16,11));
                                return a.slice(a.repeat(c,1,u64(3+p)), 1, u64(2+p)); },
       [](DescArena& a, int p){ auto c=a.atom_node(a.atom_bytes("x",16,11));
                                return a.slice(a.concat({c, a.slice(c,0,u64(3+p))}), 1, u64(2+p)); }},
      {"r6|r6 slice-assoc", 6, 6,
       [](DescArena& a, int p){ auto c=a.atom_node(a.atom_bytes("x",32,12));
                                return a.slice(a.slice(c, u64(1+p), u64(20+p)), u64(2+p), u64(6+p)); },
       [](DescArena& a, int p){ auto c=a.atom_node(a.atom_bytes("x",32,12));
                                return a.slice(c, u64(3+2*p), u64(6+p)); }},
      {"r7|r7 identity-layer", 7, 7,
       [](DescArena& a, int p){ auto c=a.atom_node(a.atom_bytes("x",8+p,13));
                                return a.morph(a.morph(c,2,0),2,0); },
       [](DescArena& a, int p){ auto c=a.atom_node(a.atom_bytes("x",8+p,13));
                                return a.morph(a.morph(a.morph(a.morph(c,2,0),2,0),2,0),2,0); }},
      {"r8|r8 xor-zero-twice", 8, 8,
       [](DescArena& a, int p){ auto c=a.atom_node(a.atom_bytes("x",8+p,14));
                                return a.xor_node(a.xor_node(c, a.zero(u64(8+p))), a.zero(u64(8+p))); },
       [](DescArena& a, int p){ auto c=a.atom_node(a.atom_bytes("x",8+p,14));
                                return a.xor_node(c, a.zero(u64(8+p))); }},
      {"r9|r7 interleave-morph", 9, 7,
       [](DescArena& a, int p){ auto c=a.atom_node(a.atom_bytes("x",8+p,15));
                                return a.interleave({a.morph(a.morph(c,2,0),2,0),
                                                     a.atom_node(a.atom_bytes("y",8+p,16))},3); },
       [](DescArena& a, int p){ auto c=a.atom_node(a.atom_bytes("x",8+p,15));
                                return a.interleave({c, a.atom_node(a.atom_bytes("y",8+p,16))},3); }},
      {"r10|r10 affine-zero-step", 10, 10,
       [](DescArena& a, int p){ return a.morph(a.affine(7,0,u64(16+p)),2,0); },
       [](DescArena& a, int p){ return a.morph(a.affine(7,0,u64(16+p)),2,0); }},
      {"r11|r11 zero-repeat-vs-zero", 11, 11,
       [](DescArena& a, int p){ return a.repeat(a.zero(u64(4+p)), 2, u64(1+p)); },
       [](DescArena& a, int p){ return a.repeat(a.zero(u64(4+p)), 2, u64(1+p)); }},
      {"r12|r12 duplicate-atoms", 12, 12,
       [](DescArena& a, int p){ auto x=a.atom_bytes("x",4+p,16); auto x2=a.atom_bytes("x2",4+p,16);
                                return a.concat({a.atom_node(x), a.atom_node(x2)}); },
       [](DescArena& a, int p){ auto x=a.atom_bytes("x",4+p,16);
                                return a.concat({a.atom_node(x), a.atom_node(x)}); }},
      {"r13|r3 atom-order-atoms", 13, 3,
       [](DescArena& a, int p){ auto x=a.atom_bytes("x",4+p,17); auto y=a.atom_bytes("y",4+p,18);
                                return a.concat({a.atom_node(x), a.atom_node(y)}); },
       [](DescArena& a, int p){ auto x=a.atom_bytes("x",4+p,17); auto y=a.atom_bytes("y",4+p,18);
                                return a.concat({a.atom_node(x), a.atom_node(y)}); }},
      {"r6|r11 slice-of-zero-repeat", 6, 11,
       [](DescArena& a, int p){ return a.slice(a.repeat(a.zero(u64(8+p)),3,0), u64(2+p), u64(4+p)); },
       [](DescArena& a, int p){ return a.slice(a.zero(u64(24+3*p)), u64(2+p), u64(4+p)); }},
      {"r8|r11 xor-with-zero-repeat", 8, 11,
       [](DescArena& a, int p){ return a.xor_node(a.repeat(a.zero(u64(4+p)),2,0), a.zero(u64(8+2*p))); },
       [](DescArena& a, int p){ return a.zero(u64(8+2*p)); }},
      {"r2|r12 empty-and-duplicate", 2, 12,
       [](DescArena& a, int p){ auto x=a.atom_bytes("x",4+p,19); auto x2=a.atom_bytes("x2",4+p,19);
                                return a.concat({a.empty(), a.atom_node(x), a.atom_node(x2)}); },
       [](DescArena& a, int p){ auto x=a.atom_bytes("x",4+p,19);
                                return a.concat({a.atom_node(x)}); }},
    };
    for (auto& tm : t) {
        DescArena a1; const std::string r1 = tm.build_a(a1, p);
        TermDesc d1; d1.id="A"; d1.arena=a1; d1.root=r1;
        DescArena a2; const std::string r2 = tm.build_b(a2, p);
        TermDesc d2; d2.id="B"; d2.arena=a2; d2.root=r2;
        auto b1 = bind(d1), b2 = bind(d2);
        if (!b1.ok || !b2.ok) { printf("%-30s BIND FAIL a=%s b=%s\n", tm.name, b1.ok?"ok":b1.error.c_str(), b2.ok?"ok":b2.error.c_str()); continue; }
        auto w1 = check_well_formed_report(b1.ir), w2 = check_well_formed_report(b2.ir);
        if (!w1.ok() || !w2.ok()) { printf("%-30s WF FAIL a=%s b=%s\n", tm.name, w1.ok()?"Ok":w1.constraint, w2.ok()?"Ok":w2.constraint); continue; }
        CanonReport c1, c2;
        auto k1 = canon(b1.ir, c1), k2 = canon(b2.ir, c2);
        if (!k1.ok() || !k2.ok()) { printf("%-30s CANON FAIL\n", tm.name); continue; }
        const bool join = canonical_key(k1.value(), k1.value().root) == canonical_key(k2.value(), k2.value().root);
        printf("%-30s %s  firedA=[", tm.name, join?"JOIN":"DIVERGE");
        for (int i=0;i<13;++i) if (c1.rule_fires[i]) printf("%d ", i+1);
        printf("] firedB=[");
        for (int i=0;i<13;++i) if (c2.rule_fires[i]) printf("%d ", i+1);
        printf("]\n");
    }
    return 0;
}
