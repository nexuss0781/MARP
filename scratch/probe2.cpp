#include <cstdio>
#include <string>
#include <vector>

#include "c03_build.hpp"
#include "mapr/e2/e2_canon.hpp"
#include "mapr/e2/e2_eval.hpp"
#include "mapr/e2/e2_term.hpp"

using namespace marp::v2;
using c03::Builder;
using c03::pattern;

static void report(const char* label, Builder& b, u32 root) {
    Ir ir = b.finish(root);
    CanonReport rep;
    auto c = canon(ir, rep);
    printf("%-28s wf=%d canon=%d nodes=%zu canonic_in=%d", label,
           (int)check_well_formed(ir).ok(), (int)c.ok(), c.ok() ? c.value().nodes.size() : 0u,
           (int)is_canonical(ir));
    printf(" rules=[");
    for (int i = 0; i < 13; ++i) printf("%llu%s", (unsigned long long)rep.rule_fires[i], i==12?"":",");
    printf("]\n");
    if (c.ok()) {
        for (auto& n : c.value().nodes) printf("      %s a=%s b=%s\n", kind_name(n.kind),
            n.a.to_decimal().c_str(), n.b.to_decimal().c_str());
    }
}

int main() {
    {
        Builder b; u32 a = b.atom_node(b.add_atom(pattern(8,1)));
        report("xor(x,x)", b, b.xor_node(a,a));
    }
    {
        Builder b; u32 a = b.atom_node(b.add_atom(pattern(8,1)));
        report("xor(x,zero)", b, b.xor_node(a,b.zero(8)));
    }
    {
        Builder b; u32 a = b.atom_node(b.add_atom(pattern(8,1)));
        report("interleave-1", b, b.interleave({a}, 2));
    }
    {
        Builder b;
        report("affine-step0", b, b.affine(3,0,16));
    }
    {
        Builder b; u32 z = b.zero(8);
        report("repeat(zero,2,0)", b, b.repeat(z,2,0));
    }
    {
        Builder b; u32 a = b.atom_node(b.add_atom(pattern(4,1)));
        u32 c = b.atom_node(b.add_atom(pattern(4,2)));
        report("concat(a4,c4)", b, b.concat({a,c}));
    }
    {
        Builder b; u32 z1=b.zero(3); u32 z2=b.zero(5);
        report("concat(z3,z5)", b, b.concat({z1,z2}));
    }
    {
        Builder b; u32 a = b.atom_node(b.add_atom(pattern(8,1)));
        report("morph(inv,inv)", b, b.morph(b.morph(a,2,0),2,0));
    }
    {
        Builder b; u32 a = b.atom_node(b.add_atom(pattern(8,1)));
        report("rotl(a,3)∘rotl(a,2)", b, b.morph(b.morph(a,6,3),6,2));
    }
    {
        Builder b; u32 a = b.atom_node(b.add_atom(pattern(8,1)));
        report("slice(slice)", b, b.slice(b.slice(a,2,4),1,2));
    }
    {
        Builder b; u32 a = b.atom_node(b.add_atom(pattern(8,1)));
        report("concat(x,x)", b, b.concat({a,a}));
    }
    {
        Builder b; u32 a = b.atom_node(b.add_atom(pattern(8,1)));
        report("concat(empty,a)", b, b.concat({b.empty(), a}));
    }
    {
        Builder b; u32 a = b.atom_node(b.add_atom(pattern(8,1)));
        report("repeat(a,1,3)", b, b.repeat(a,1,3));
    }
    {
        Builder b; u32 a = b.atom_node(b.add_atom(pattern(8,1)));
        report("repeat(a,0,3)", b, b.repeat(a,0,3));
    }
    {
        Builder b; u32 a = b.atom_node(b.add_atom(pattern(8,1)));
        report("morph(revbits)", b, b.morph(a,9,0));
    }
    {
        Builder b; u32 a = b.atom_node(b.add_atom(pattern(8,1)));
        report("morph(inv)", b, b.morph(a,2,0));
    }
    {
        Builder b; u32 a = b.atom_node(b.add_atom(pattern(8,1)));
        report("slice(a,0,8)", b, b.slice(a,0,8));
    }
    return 0;
}
