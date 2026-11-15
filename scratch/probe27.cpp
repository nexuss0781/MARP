#include <cstdio>
#include "e2g_corpus.hpp"
#include "e2g_terms.hpp"
#include "mapr/e2/e2_canon.hpp"
using namespace e2g;
using namespace marp::v2;
int main(){
    Corpus c = build_corpus();
    for (auto& t : c.terms) {
        if (t.id != "nc-gen-88" && t.id != "nc-gen-101" && t.id != "nc-gen-192") continue;
        auto b = bind(t.desc);
        auto wf = check_well_formed_report(b.ir);
        printf("%s rule=%d note=%s wf=%s\n", t.id.c_str(), t.redex_rule, t.desc.note.c_str(), wf.ok()?"Ok":wf.constraint);
        printf("   %s\n", describe_ir(b.ir).substr(0,300).c_str());
    }
    return 0;
}
