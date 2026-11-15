#include <cstdio>
#include "e2g_terms.hpp"
#include "mapr/e2/e2_canon.hpp"
using namespace e2g;
using namespace marp::v2;
int main(){
    DescArena a;
    auto c=a.atom_node(a.atom_bytes("x",256,12));
    const std::string root = a.slice(a.slice(a.slice(c,1,200),2,8),2,4);
    TermDesc d; d.id="t"; d.corpus="p"; d.arena=a; d.root=root;
    auto b = bind(d);
    auto wf = check_well_formed_report(b.ir);
    printf("bind=%d wf=%s nodes=%zu\n", (int)b.ok, wf.ok()?"Ok":wf.constraint, b.ir.nodes.size());
    if (wf.ok()) { CanonReport rep; auto r = canon(b.ir, rep);
      printf("canon=%d rew=%llu fires:", (int)r.ok(), (unsigned long long)rep.rewrites);
      for(int i=0;i<13;++i) if(rep.rule_fires[i]) printf(" %d", i+1);
      printf("\n  %s\n", r.ok()?describe_ir(r.value()).c_str():"");
    }
    return 0;
}
