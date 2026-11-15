#include <cstdio>
#include <functional>
#include <string>
#include "e2g_terms.hpp"
#include "mapr/e2/e2_canon.hpp"
using namespace e2g;
using namespace marp::v2;

void probe(const char* label, const std::function<std::string(DescArena&)>& build) {
    DescArena a;
    const std::string root = build(a);
    TermDesc d; d.id = label; d.corpus = "probe"; d.arena = a; d.root = root;
    auto b = bind(d);
    if (!b.ok) { printf("%-32s bind failed: %s\n", label, b.error.c_str()); return; }
    const WfReport wf = check_well_formed_report(b.ir);
    printf("%-32s wf=%-14s canon_in=%d ", label, wf.ok()?"Ok":wf.constraint, (int)is_canonical(b.ir));
    CanonReport rep; auto c = canon(b.ir, rep);
    if (!c.ok()) { printf("canon failed %s\n", code_name(c.code())); return; }
    printf("rewrites=%llu fires=[", (unsigned long long)rep.rewrites);
    for (int i=0;i<13;++i) if (rep.rule_fires[i]) printf("%d:%llu ", i+1,(unsigned long long)rep.rule_fires[i]);
    printf("] out_canonical=%d\n", (int)is_canonical(c.value()));
}

int main() {
    probe("r12-duplicate-atom", [](DescArena& a) {
        const std::string p = a.atom_bytes("p", 8, 90);
        const std::string q = a.atom_bytes("p-dup", 8, 90);
        return a.concat({a.slice(a.morph(a.atom_node(p), 1, 0), 0, 8),
                         a.slice(a.morph(a.atom_node(q), 1, 0), 0, 8)});
    });
    probe("r12-mixed-atoms", [](DescArena& a) {
        const std::string p = a.atom_bytes("p", 8, 90);
        const std::string q = a.atom_bytes("p-dup", 8, 90);
        return a.concat({a.atom_node(p), a.atom_node(q)});
    });
    probe("r11-repeat-zero-q3", [](DescArena& a) { return a.repeat(a.zero(8), 3, 0); });
    probe("r11-repeat-zero-q1-r3", [](DescArena& a) { return a.repeat(a.zero(8), 1, 3); });
    probe("r11-repeat-zero-q0-r5", [](DescArena& a) { return a.repeat(a.zero(8), 0, 5); });
    probe("r11-repeat-zero-q2-r2", [](DescArena& a) { return a.repeat(a.zero(8), 2, 2); });
    probe("r13-atom-order", [](DescArena& a) {
        const std::string first = a.atom_bytes("first", 8, 60);
        const std::string second = a.atom_bytes("second", 8, 61);
        return a.concat({a.atom_node(second), a.atom_node(first)});
    });
    return 0;
}
