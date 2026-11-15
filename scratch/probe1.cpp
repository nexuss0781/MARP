#include <cstdio>
#include <vector>

#include "c03_build.hpp"
#include "mapr/e2/e2_canon.hpp"
#include "mapr/e2/e2_eval.hpp"
#include "mapr/e2/e2_term.hpp"

using namespace marp::v2;
using c03::Builder;
using c03::pattern;

int main() {
    {
        Builder b;
        u32 a0 = b.atom_node(b.add_atom(pattern(600000, 1)));
        u32 a1 = b.atom_node(b.add_atom(pattern(600000, 2)));
        Ir ir = b.finish(b.concat({a0, a1}));
        printf("merge-atoms wf=%d\n", (int)check_well_formed(ir).ok());
        CanonReport rep;
        auto c = canon(ir, rep);
        printf("  canon ok=%d rewrites=%llu nodes=%zu\n", (int)c.ok(),
               (unsigned long long)rep.rewrites, c.ok() ? c.value().nodes.size() : 0u);
    }
    {
        Builder b;
        u32 atom = b.atom_node(b.add_atom(pattern(8, 3)));
        Ir ir = b.finish(b.repeat(atom, 1, 0));
        auto r = canon(ir);
        printf("repeat-1-0 canon ok=%d nodes=%zu\n", (int)r.ok(),
               r.ok() ? r.value().nodes.size() : 0u);
    }
    {
        Builder b;
        u32 atom = b.atom_node(b.add_atom(pattern(8, 4)));
        Ir ir = b.finish(b.repeat(atom, 0, 3));
        auto r = canon(ir);
        printf("repeat-0-3 => nodes=%zu canonical=%d\n", r.ok() ? r.value().nodes.size() : 0u,
               r.ok() ? (int)is_canonical(r.value()) : -1);
        if (r.ok()) {
            for (auto& n : r.value().nodes) printf("   kind=%s\n", kind_name(n.kind));
        }
    }
    {
        Builder b;
        u32 lf = b.lfsr(0x80200003ull, 1ull, BigInt(1).shl(40).value());
        u32 rv = b.morph(lf, 8, 0);
        Ir ir = b.finish(rv);
        std::vector<u8> buf(16);
        EvalStats st{};
        auto r = read_range_ex(ir, ir.root, BigInt(1).shl(39).value(), buf, EvalLimits{}, {}, &st);
        printf("morph8 at 2^39 ok=%d peak_scratch=%zu\n", (int)r.ok(), st.peak_scratch_bytes);
    }
    return 0;
}
