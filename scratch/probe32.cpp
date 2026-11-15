#include <cstdio>
#include <vector>
#include "e2g_corpus.hpp"
#include "e2g_terms.hpp"
using namespace e2g;
using namespace marp::v2;
int main(int argc, char** argv){
    Corpus c = build_corpus();
    const std::string want = argc > 1 ? argv[1] : "";
    for (auto& t : c.terms) {
        if (t.corpus != "T-BIG" && t.corpus != "T-GEN" && t.corpus != "T-KAT") continue;
        auto b = bind(t.desc);
        if (!b.ok) continue;
        const auto len = b.recomputed[b.ir.root].to_u64_checked();
        if (!len.has_value()) { printf("%s len>u64\n", t.id.c_str()); continue; }
        if (*len > (8ull<<20) && t.corpus != "T-BIG") { printf("%s HUGE len=%llu corpus=%s\n", t.id.c_str(), (unsigned long long)*len, t.corpus.c_str()); }
        if (t.corpus == "T-BIG" && !want.empty() && t.id.find(want) != std::string::npos)
            printf("%s len=%llu nodes=%zu\n", t.id.c_str(), (unsigned long long)*len, b.ir.nodes.size());
    }
    return 0;
}
