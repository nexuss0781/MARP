#include <cstdio>
#include "mapr/e2/e2_term.hpp"
using namespace marp::v2;
static Ir base() {
    static std::vector<u8> payload{1,2,3,4};
    Ir ir; Atom a; a.length = BigInt(4); a.payload = std::span<const u8>(payload.data(), payload.size());
    ir.atoms.push_back(a);
    Node n; n.kind = Kind::Atom; n.a = BigInt(0); n.length = BigInt(4);
    ir.nodes.push_back(n); ir.root = 0; ir.total_length = BigInt(4);
    return ir;
}
int main(){
    { Ir ir = base(); ir.nodes[0].args.push_back(0);   // Atom with 1 arg -> W8.argc
      auto w = check_well_formed_report(ir); printf("atom+arg: %s/%s node=%u msg=%s\n", code_name(w.code), w.constraint, w.node, w.message.c_str()); }
    { Ir ir = base(); ir.nodes[0].args.push_back(5);   // out-of-range arg on Atom
      auto w = check_well_formed_report(ir); printf("atom+arg5: %s/%s\n", code_name(w.code), w.constraint); }
    { Ir ir = base(); Node c; c.kind=Kind::Concat; c.args={0,99}; c.length=BigInt(4); ir.nodes.push_back(c); ir.root=1; ir.total_length=BigInt(4);
      auto w = check_well_formed_report(ir); printf("concat arg99: %s/%s\n", code_name(w.code), w.constraint); }
    { Ir ir = base(); Node c; c.kind=Kind::Concat; c.args={99,0}; c.length=BigInt(4); ir.nodes.push_back(c); ir.root=1; ir.total_length=BigInt(4);
      auto w = check_well_formed_report(ir); printf("concat arg99 first: %s/%s\n", code_name(w.code), w.constraint); }
    { Ir ir = base(); ir.nodes[0].a = BigInt(5);       // atom id out of range
      auto w = check_well_formed_report(ir); printf("atom id 5: %s/%s\n", code_name(w.code), w.constraint); }
    { Ir ir = base(); ir.nodes[0].kind = static_cast<Kind>(12);
      auto w = check_well_formed_report(ir); printf("kind 12: %s/%s\n", code_name(w.code), w.constraint); }
    { Ir ir = base(); ir.nodes[0].args.push_back(0); ir.nodes[0].args.push_back(0);
      auto w = check_well_formed_report(ir); printf("atom 2 args: %s/%s\n", code_name(w.code), w.constraint); }
    return 0;
}
