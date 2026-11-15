#include <cstdio>
#include <map>
#include "e2g_corpus.hpp"
#include "e2g_terms.hpp"
#include "mapr/e2/e2_canon.hpp"
using namespace e2g;
using namespace marp::v2;
int main(){
    Corpus c = build_corpus();
    std::map<std::string,int> counts;
    for (auto& t : c.terms) counts[t.corpus]++;
    for (auto& [k,v] : counts) printf("%-12s %5d\n", k.c_str(), v);
    printf("M-KAT %zu  P-KAT %zu  L-KAT %zu\n", c.morph_kats.size(), c.predictor_kats.size(), c.lfsr_kats.size());
    for (auto& t : c.terms) {
        if (t.corpus != "T-BAD") continue;
        auto b = bind(t.desc);
        Ir ir = b.ir;
        if (t.id=="bad-root") { auto r2 = bind_with(t.desc, "missing-root", std::nullopt); ir = r2.ir; }
        if (t.id=="bad-total-length") { ir.total_length = ir.nodes[ir.root].length.add(BigInt(1)).value(); }
        Limits lim; if (t.id=="bad-counts-nodes") lim.max_atoms = 1;
        auto wf = check_well_formed_report(ir, lim);
        const bool ok = !wf.ok() && std::string(wf.constraint)==t.expected_constraint && wf.code==t.expected_code;
        printf("%-30s %s/%s %s\n", t.id.c_str(), code_name(wf.code), wf.constraint, ok?"":"<<< MISMATCH expected "+std::string(code_name(t.expected_code))+"/"+t.expected_constraint);
    }
    return 0;
}
