#include <cstdio>
#include <functional>
#include <string>
#include "e2g_terms.hpp"
#include "mapr/e2/e2_canon.hpp"
using namespace e2g;
using namespace marp::v2;
void one(const char* label, const std::function<std::string(DescArena&)>& f) {
    DescArena a; auto root = f(a);
    TermDesc d; d.id=label; d.corpus="p"; d.arena=a; d.root=root;
    auto b = bind(d);
    if (!b.ok) { printf("%-56s BIND %s\n", label, b.error.c_str()); return; }
    auto wf = check_well_formed_report(b.ir);
    if (!wf.ok()) { printf("%-56s WF %s\n", label, wf.constraint); return; }
    CanonReport rep; auto c = canon(b.ir, rep);
    printf("%-56s rew=%2llu fires=[", label, (unsigned long long)rep.rewrites);
    for (int i=0;i<13;++i) if (rep.rule_fires[i]) printf("%d ", i+1);
    printf("]\n");
}
int main(){
    // Slice-of-Slice whose child is a Slice-of-Zero: rules 6 and 11 overlap
    one("slice(slice(slice(zero64,1,40),0,30),0,20)", [](DescArena& a){
        return a.slice(a.slice(a.slice(a.zero(64),1,40),0,30),0,20); });
    one("slice(slice(slice(zero64,2,40),1,30),1,20)", [](DescArena& a){
        return a.slice(a.slice(a.slice(a.zero(64),2,40),1,30),1,20); });
    // Member B: rule 6 applied on the outer pair, rule 11 pending inside
    one("slice(slice(zero64,3,20),0,20)", [](DescArena& a){
        return a.slice(a.slice(a.zero(64),3,20),0,20); });
    // Rule 6 & 11 with a Repeat-of-Zero child
    one("slice(slice(repeat(zero8,4,0),1,20),1,10)", [](DescArena& a){
        return a.slice(a.slice(a.repeat(a.zero(8),2,0),1,20),1,10); });
    return 0;
}
