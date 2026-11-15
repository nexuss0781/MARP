#include <cstdio>
#include <string>
#include "e2g_terms.hpp"
#include "mapr/e2/e2_canon.hpp"
#include "mapr/e2/e2_dag.hpp"

using namespace e2g;
using namespace marp::v2;

int main() {
    // 1) rule 12: an Ir with two structurally identical subterms
    {
        Ir ir;
        Atom a;
        static std::vector<u8> payload{1,2,3,4};
        a.length = BigInt(4);
        a.payload = std::span<const u8>(payload.data(), payload.size());
        ir.atoms.push_back(a);
        // node0: atom ; node1: atom (duplicate of node0) ; node2: concat(node0,node1)
        for (int i = 0; i < 2; ++i) {
            Node n; n.kind = Kind::Atom; n.a = BigInt(0); n.length = BigInt(4);
            ir.nodes.push_back(n);
        }
        Node c; c.kind = Kind::Concat; c.args = {0, 1}; c.length = BigInt(8);
        ir.nodes.push_back(c);
        ir.root = 2; ir.total_length = BigInt(8);
        printf("dup-atoms wf=%d is_canonical=%d\n", (int)check_well_formed_report(ir).ok(), (int)is_canonical(ir));
        CanonReport rep;
        auto out = canon(ir, rep);
        printf("  canon ok=%d rewrites=%llu fires12=%llu nodes_out=%zu\n", (int)out.ok(),
               (unsigned long long)rep.rewrites, (unsigned long long)rep.rule_fires[11],
               out.ok()? out.value().nodes.size():0);
        for (int i=0;i<13;++i) if (rep.rule_fires[i]) printf("   rule %d: %llu\n", i+1, (unsigned long long)rep.rule_fires[i]);
    }
    // 2) dag order: tkat-concat3
    {
        DescArena arena;
        const std::string a = arena.atom_node(arena.atom_bytes("p", 4, 1));
        const std::string b = arena.atom_node(arena.atom_bytes("q", 4, 2));
        const std::string c = arena.atom_node(arena.atom_bytes("r", 4, 3));
        TermDesc desc; desc.id="t"; desc.corpus="T"; desc.arena=arena;
        desc.root = arena.concat({a,b,c});
        auto bound = bind(desc);
        printf("bind ok=%d\n", (int)bound.ok);
        auto can = canon(bound.ir);
        printf("canon ok=%d\n", (int)can.ok());
        printf("describe_ir(canon): %s\n", describe_ir(can.value()).c_str());
        auto replay = replay_dag(desc, 12345);
        printf("replay ok=%d err=%s\n", (int)replay.ok, replay.error.c_str());
        if (replay.ok) printf("describe_ir(replay): %s\n", describe_ir(replay.ir).c_str());
        printf("describe_ir(bound): %s\n", describe_ir(bound.ir).c_str());
    }
    return 0;
}
