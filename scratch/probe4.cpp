#include <cstdio>
#include <string>
#include "e2g_corpus.hpp"
#include "mapr/e2/e2_canon.hpp"
using namespace marp::v2;
using namespace e2g;

void show(const char* label, const Ir& ir) {
    CanonReport rep;
    auto c = canon(ir, rep);
    printf("%-22s canonic_in=%d rules=[", label, (int)is_canonical(ir));
    for (int i=0;i<13;++i) printf("%llu%s",(unsigned long long)rep.rule_fires[(size_t)i], i==12?"":",");
    printf("]\n");
    if (c.ok()) for (auto& n : c.value().nodes) {
        printf("     %-10s a=%-4s b=%-4s args=", kind_name(n.kind),
               n.a.to_decimal().c_str(), n.b.to_decimal().c_str());
        for (auto a : n.args) printf("%u,", a);
        printf("\n");
    }
}

int main() {
    // replicate C04's r1 redex exactly
    {
        c03::Builder b;
        u32 inner = b.concat({b.zero(5), b.atom_node(b.add_atom(c03::pattern(8,71)))});
        u32 root = b.concat({b.atom_node(b.add_atom(c03::pattern(16,70))), inner, b.zero(2)});
        Ir ir = b.finish(root);
        show("c04-r1", ir);
    }
    // my nc-r1 variant
    {
        DescArena a;
        const std::string inner = a.concat({a.zero(3), a.zero(5)});
        const std::string mid = a.repeat(inner, 1, 2);
        const std::string outer = a.concat({mid, a.zero(2)});
        const std::string rep = a.repeat(outer, 1, 3);
        auto bd = bind(TermDesc{.id="x",.corpus="T-NONCANON",.note="",.arena=a,.root=rep,.virtual_term=false,.pinned_digest=""});
        show("mine", bd.ir);
    }
    // plain nested concat built by Builder
    {
        c03::Builder b;
        u32 inner = b.concat({b.zero(3), b.zero(5)});
        u32 root = b.concat({inner, b.zero(2), b.zero(4)});
        Ir ir = b.finish(root);
        show("plain-nested", ir);
    }
    // check_canonical constraint identity for the plain nested case
    {
        c03::Builder b;
        u32 inner = b.concat({b.zero(3), b.zero(5)});
        u32 root = b.concat({inner, b.zero(2), b.zero(4)});
        Ir ir = b.finish(root);
        auto rep = check_canonical(ir);
        printf("check_canonical constraint=%s code=%s\n", rep.constraint, code_name(rep.code));
    }
    return 0;
}
