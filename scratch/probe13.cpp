#include <cstdio>
#include <functional>
#include <string>
#include "e2g_terms.hpp"
#include "mapr/e2/e2_canon.hpp"
using namespace e2g;
using namespace marp::v2;
void probe(const char* label, const std::function<std::string(DescArena&)>& build) {
    DescArena a; const std::string root = build(a);
    TermDesc d; d.id=label; d.corpus="probe"; d.arena=a; d.root=root;
    auto b = bind(d);
    if (!b.ok) { printf("%-34s BIND FAIL %s\n", label, b.error.c_str()); return; }
    const WfReport wf = check_well_formed_report(b.ir);
    CanonReport rep; auto c = canon(b.ir, rep);
    printf("%-34s wf=%-12s canon_in=%d rewrites=%llu fires=[", label, wf.ok()?"Ok":wf.constraint,
           (int)is_canonical(b.ir), (unsigned long long)rep.rewrites);
    for (int i=0;i<13;++i) if (rep.rule_fires[i]) printf("%d ", i+1);
    printf("] out_canon=%d\n", c.ok()?(int)is_canonical(c.value()):-1);
}
int main(){
    probe("r12 dup payloads, slice-covered", [](DescArena& a) {
        const std::string p = a.atom_bytes("p", 8, 90);
        const std::string q = a.atom_bytes("p-dup", 8, 90);
        return a.concat({a.slice(a.morph(a.atom_node(p), 1, 0), 0, 8),
                         a.slice(a.morph(a.atom_node(q), 1, 0), 0, 8)});
    });
    probe("r12 dup payloads, xor", [](DescArena& a) {
        const std::string p = a.atom_bytes("p", 8, 90);
        const std::string q = a.atom_bytes("p-dup", 8, 90);
        return a.xor_node(a.atom_node(p), a.atom_node(q));
    });
    probe("r12 dup payloads, nested", [](DescArena& a) {
        const std::string p = a.atom_bytes("p", 8, 90);
        const std::string q = a.atom_bytes("p-dup", 8, 90);
        const std::string r = a.atom_bytes("r", 8, 91);
        return a.concat({a.atom_node(p), a.zero(3), a.atom_node(q), a.atom_node(r)});
    });
    probe("r7 rotl3.rotr3 on atom", [](DescArena& a) {
        return a.morph(a.morph(a.atom_node(a.atom_bytes("x", 8, 92)), 6, 3), 7, 3);
    });
    probe("r2 empty-concat-single", [](DescArena& a) { return a.concat({a.empty()}); });
    probe("r2 empty-concat-two", [](DescArena& a) { return a.concat({a.empty(), a.empty()}); });
    return 0;
}
