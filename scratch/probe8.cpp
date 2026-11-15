#include <cstdio>
#include "e2g_terms.hpp"
using namespace e2g;
int main(){
    DescArena a;
    printf("after ctor nodes=%zu atoms=%zu\n", a.node_count(), a.atom_count());
    const std::string p = a.atom_bytes("p", 8, 90);
    printf("after atom nodes=%zu atoms=%zu\n", a.node_count(), a.atom_count());
    const std::string root = a.atom_node(p);
    printf("after atom_node nodes=%zu atoms=%zu root=%s\n", a.node_count(), a.atom_count(), root.c_str());
    TermDesc d; d.id="x"; d.arena = a; d.root = root;
    printf("desc nodes=%zu atoms=%zu root=%s\n", d.arena.node_count(), d.arena.atom_count(), d.root.c_str());
    auto b = bind(d);
    printf("bind ok=%d err=%s nodes=%zu\n", (int)b.ok, b.error.c_str(), b.ir.nodes.size());
    return 0;
}
