#include <cstdio>
#include <map>
#include "e2g_corpus.hpp"
#include "e2g_terms.hpp"
#include "mapr/e2/e2_canon.hpp"
using namespace e2g;
using namespace marp::v2;
int main(){
    Corpus c = build_corpus();
    std::map<std::string,std::array<int,5>> fam; // wfA, wfB, joinfail, firedfail, n
    std::map<std::string,std::string> why;
    for (auto& t : c.terms) {
        if (t.corpus != "T-CRIT") continue;
        const std::string fam_name = t.desc.note.substr(0, t.desc.note.find('/'));
        auto& f = fam[fam_name]; f[4]++;
        auto a = bind(t.desc);
        TermDesc alt = t.alt; alt.id = t.id+"-alt"; alt.root = t.alt_root;
        auto b = bind(alt);
        if (!a.ok||!b.ok) { f[0]++; why[fam_name] = "bind a="+(a.ok?"ok":a.error)+" b="+(b.ok?"ok":b.error); continue; }
        auto wa = check_well_formed_report(a.ir), wb = check_well_formed_report(b.ir);
        if (!wa.ok()||!wb.ok()) { f[0]++; why[fam_name] = std::string("wf a=")+(wa.ok()?"Ok":wa.constraint)+" b="+(wb.ok()?"Ok":wb.constraint); continue; }
        CanonReport ra, rb; auto ca = canon(a.ir, ra), cb = canon(b.ir, rb);
        if (!ca.ok()||!cb.ok()) { f[1]++; why[fam_name]="canon"; continue; }
        if (canonical_key(ca.value(),ca.value().root)!=canonical_key(cb.value(),cb.value().root)) f[2]++;
        const bool fired = (ra.rule_fires[t.crit_rule_a-1]+rb.rule_fires[t.crit_rule_a-1])>0
                        && (ra.rule_fires[t.crit_rule_b-1]+rb.rule_fires[t.crit_rule_b-1])>0
                        && (ra.rewrites+rb.rewrites)>0;
        if (!( (ra.rule_fires[t.crit_rule_a-1]>0) && (rb.rule_fires[t.crit_rule_b-1]>0) )) { f[3]++; if (why[fam_name].empty()) {
            char buf[200]; snprintf(buf,sizeof buf,"A=[");
            std::string w(buf);
            for(int i=0;i<13;++i) if(ra.rule_fires[i]) w += std::to_string(i+1)+" ";
            w += "] B=[";
            for(int i=0;i<13;++i) if(rb.rule_fires[i]) w += std::to_string(i+1)+" ";
            w += "]" + std::string(" rewA=")+std::to_string(ra.rewrites)+" rewB="+std::to_string(rb.rewrites); why[fam_name] = w; } }
    }
    for (auto& [name, f] : fam)
        printf("%-30s n=%3d wf=%3d canon=%3d join=%3d fired=%3d  %s\n", name.c_str(), f[4], f[0], f[1], f[2], f[3], why[name].c_str());
    return 0;
}
