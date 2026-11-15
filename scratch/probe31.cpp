#include <cstdio>
#include <vector>
#include "e2g_terms.hpp"
#include "e2g_oracle.hpp"
using namespace e2g;
using namespace marp::v2;
int main(){
    DescArena a;
    const std::string root = a.empty();
    TermDesc d; d.id="e"; d.corpus="p"; d.arena=a; d.root=root;
    auto b = bind(d);
    auto wf = check_well_formed_report(b.ir);
    printf("bind=%d wf=%s len=%s\n", (int)b.ok, wf.ok()?"Ok":wf.constraint, b.ir.total_length.to_decimal().c_str());
    std::vector<u8> buf;  // empty span
    auto r = read_range(b.ir, b.ir.root, BigInt(0), std::span<u8>(buf));
    printf("read_range(0,0) -> ok=%d bytes=%zu code=%s\n", (int)r.ok(), r.ok()?r.value():0, code_name(r.code()));
    std::array<u8, 1> one{};
    auto r2 = read_range(b.ir, b.ir.root, BigInt(0), std::span<u8>(one));
    printf("read_range(0,1) -> ok=%d code=%s\n", (int)r2.ok(), code_name(r2.code()));
    OracleBinding ob = make_binding(b.ir);
    std::vector<u8> out; std::string err;
    const bool ok = oracle_range(ob, b.ir.root, to_oracle(BigInt(0)), 0, out, err);
    printf("oracle_range(0,0) -> ok=%d bytes=%zu err=%s\n", (int)ok, out.size(), err.c_str());
    std::vector<u8> out2;
    const bool ok2 = oracle_range(ob, b.ir.root, to_oracle(BigInt(0)), 1, out2, err);
    printf("oracle_range(0,1) -> ok=%d bytes=%zu err=%s\n", (int)ok2, out2.size(), err.c_str());
    return 0;
}
