#include <cstdio>
#include <string>
#include "e2g_terms.hpp"
#include "mapr/e2/e2_canon.hpp"
#include "mapr/e2/e2_dag.hpp"
using namespace e2g;
using namespace marp::v2;
int main() {
    DescArena arena;
    const std::string a = arena.atom_node(arena.atom_bytes("p", 4, 1));
    const std::string b = arena.atom_node(arena.atom_bytes("q", 4, 2));
    const std::string c = arena.atom_node(arena.atom_bytes("r", 4, 3));
    const std::string root = arena.concat({a,b,c});
    TermDesc desc; desc.id="t"; desc.corpus="T"; desc.arena=arena; desc.root=root;
    auto bound = bind(desc);
    printf("bind ok=%d err=%s root=%u nodes=%zu\n", (int)bound.ok, bound.error.c_str(), bound.ir.root, bound.ir.nodes.size());
    auto can = canon(bound.ir);
    printf("canon ok=%d root=%u nodes=%zu\n", (int)can.ok(), can.ok()?can.value().root:0, can.ok()?can.value().nodes.size():0);
    if (can.ok()) printf("  desc(canon)  = %s\n", describe_ir(can.value()).c_str());
    printf("  desc(bound) = %s\n", describe_ir(bound.ir).c_str());
    auto replay = replay_dag(desc, 12345);
    printf("replay ok=%d err=%s\n", (int)replay.ok, replay.error.c_str());
    if (replay.ok) printf("  desc(replay) = %s\n", describe_ir(replay.ir).c_str());
    return 0;
}
