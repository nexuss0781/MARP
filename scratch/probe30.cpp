#include <cstdio>
#include <functional>
#include <string>
#include "e2g_terms.hpp"
#include "mapr/e2/e2_canon.hpp"
using namespace e2g;
using namespace marp::v2;
void pair(const char* label, const std::function<std::string(DescArena&)>& fa,
          const std::function<std::string(DescArena&)>& fb) {
    DescArena a1; auto r1 = fa(a1); TermDesc d1; d1.id="A"; d1.arena=a1; d1.root=r1;
    DescArena a2; auto r2 = fb(a2); TermDesc d2; d2.id="B"; d2.arena=a2; d2.root=r2;
    auto b1=bind(d1), b2=bind(d2);
    if(!b1.ok||!b2.ok){printf("%-46s BIND\n",label);return;}
    auto w1=check_well_formed_report(b1.ir), w2=check_well_formed_report(b2.ir);
    if(!w1.ok()||!w2.ok()){printf("%-46s WF %s/%s\n",label,w1.ok()?"Ok":w1.constraint,w2.ok()?"Ok":w2.constraint);return;}
    CanonReport c1,c2; auto k1=canon(b1.ir,c1), k2=canon(b2.ir,c2);
    bool join = canonical_key(k1.value(),k1.value().root)==canonical_key(k2.value(),k2.value().root);
    printf("%-46s %-7s A=[", label, join?"JOIN":"DIVERGE");
    for(int i=0;i<13;++i) if(c1.rule_fires[i]) printf("%d ",i+1);
    printf("] rew=%llu  B=[", (unsigned long long)c1.rewrites);
    for(int i=0;i<13;++i) if(c2.rule_fires[i]) printf("%d ",i+1);
    printf("] rew=%llu\n", (unsigned long long)c2.rewrites);
}
int main(){
    pair("6/11 A=slice(slice(zero64,3,20),0,20)",
         [](DescArena& a){ return a.slice(a.slice(a.zero(64),3,20),0,20); },
         [](DescArena& a){ return a.slice(a.zero(20),0,20); });
    return 0;
}
