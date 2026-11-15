#include <cstdio>
#include <string>
#include "e2g_corpus.hpp"
#include "e2g_terms.hpp"
#include "mapr/e2/e2_canon.hpp"
using namespace e2g;
using namespace marp::v2;
int main(){
    // does the raw generator of T-NONCANON nc-r12 produce rule 12?
    const std::string text = R"(r12)";
    // Build via corpus
    Corpus c = build_corpus();
    for (auto& t : c.terms) {
        if (t.corpus != "T-NONCANON") continue;
        if (t.id.find("r12") == std::string::npos) continue;
        auto b = bind(t.desc);
        printf("%s bind=%d\n", t.id.c_str(), (int)b.ok);
        if (!b.ok) continue;
        auto wf = check_well_formed_report(b.ir);
        printf("  wf=%s\n", wf.ok()?"Ok":wf.constraint);
        printf("  desc: %s\n", describe_ir(b.ir).substr(0, 400).c_str());
        CanonReport rep; auto r = canon(b.ir, rep);
        printf("  canon=%d rewrites=%llu fires=[", (int)r.ok(), (unsigned long long)rep.rewrites);
        for (int i=0;i<13;++i) if (rep.rule_fires[i]) printf("%d ", i+1);
        printf("]\n");
    }
    return 0;
}
