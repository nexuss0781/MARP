#include <cstdio>
#include <string>
#include "e2g_terms.hpp"
using namespace e2g;
using namespace marp::v2;
int main(){
  TermDesc d;
  d.id = "probe-atom-id"; d.corpus = "PROBE";
  const std::string p = d.arena.atom_bytes("p", 4, 20);
  const std::string q = d.arena.atom_bytes("q", 4, 21);
  const std::string pn = d.arena.atom_node(p);
  const std::string qn = d.arena.atom_node(q);
  const std::string qn2 = d.arena.atom_node(q);
  DescNode cn; cn.kind = Kind::Concat; cn.kids = {pn, qn, qn2};
  d.root = d.arena.node(std::move(cn));
  auto r = bind(d);
  fprintf(stderr, "bind_ok=%d err=%s atoms=%zu nodes=%zu root=%u\n", (int)r.ok, r.error.c_str(),
          r.ir.atoms.size(), r.ir.nodes.size(), r.ir.root);
  for (size_t i = 0; i < r.ir.nodes.size(); ++i)
      fprintf(stderr, "  node %zu kind=%d a=%s len=%s nargs=%zu\n", i, (int)r.ir.nodes[i].kind,
              r.ir.nodes[i].a.to_decimal().c_str(), r.ir.nodes[i].length.to_decimal().c_str(),
              r.ir.nodes[i].args.size());
  if (!r.ok) return 1;
  const u32 atom_node = r.ir.nodes[r.ir.root].args[1];  // atom 1, also used by args[2]
  fprintf(stderr, "patching node %u atom-id -> %zu\n", atom_node, r.ir.atoms.size() + 2);
  r.ir.nodes[atom_node].a = BigInt((u64)r.ir.atoms.size()).add(BigInt(2)).value();
  const WfReport w = check_well_formed_report(r.ir, Limits{});
  fprintf(stderr, "wf ok=%d constraint=%s msg=%s\n", (int)w.ok(), w.constraint, w.message.c_str());
  return 0;
}
