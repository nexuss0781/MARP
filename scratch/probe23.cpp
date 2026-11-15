#include <cstdio>
#include "e2g_corpus.hpp"
#include "e2g_terms.hpp"
#include "mapr/e2/e2_canon.hpp"
using namespace e2g;
using namespace marp::v2;
int main(){
    DescArena a;
    auto x=a.atom_node(a.atom_bytes("x",4,1)); auto y=a.atom_node(a.atom_bytes("y",4,2)); auto z=a.atom_node(a.atom_bytes("z",4,3));
    const std::string root = a.concat({x, a.concat({y,z})});
    TermDesc d; d.id="t"; d.corpus="p"; d.arena=a; d.root=root;
    auto b = bind(d);
    printf("nodes=%zu root=%u\n", b.ir.nodes.size(), b.ir.root);
    for (size_t i=0;i<b.ir.nodes.size();++i) {
        printf("  n%zu %s args=[", i, kind_name(b.ir.nodes[i].kind));
        for (auto k : b.ir.nodes[i].args) printf("%u ", k);
        printf("] len=%s\n", b.ir.nodes[i].length.to_decimal().c_str());
    }
    CanonReport rep;
    auto c = canon(b.ir, rep);
    printf("canon ok=%d nodes=%zu fires:", (int)c.ok(), c.ok()?c.value().nodes.size():0);
    for (int i=0;i<13;++i) if (rep.rule_fires[i]) printf(" %d=%llu", i+1, (unsigned long long)rep.rule_fires[i]);
    printf("\n");
    return 0;
}
