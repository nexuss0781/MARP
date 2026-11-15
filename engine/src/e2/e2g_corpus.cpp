// MARP v2 — E2-G integrated ALGEBRA gate — deterministic corpus generation.
//
// Every corpus family is a pure function of a recorded seed; the only pinned
// data are the M-KAT / L-KAT byte vectors, which are computed here by a third,
// independent transcription of §4.6, §4.10 and §4.11 (the engine and the H3
// oracle are the other two implementations) and then frozen into the tables.

#include "e2g_corpus.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstring>
#include <functional>
#include <limits>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace e2g {
namespace {

constexpr u64 kMiB = 1024ull * 1024ull;
constexpr u64 kGenExpansionCap = 4ull * kMiB;
constexpr int kGenDepthMax = 8;

BigInt pow2(unsigned n) { return BigInt(1).shl(n).value(); }

const char* const kKindNames[12] = {"Empty", "Atom",  "Zero",     "Concat",  "Repeat", "Slice",
                                    "Morph", "Xor",   "Interleave", "Lfsr",  "Affine", "Predictor"};

// ---------------------------------------------------------------------------
// Independent reference morph / predictor / LFSR used only to pin M-KAT/L-KAT.
// ---------------------------------------------------------------------------

u8 ref_bitrev(u8 v) {
    u8 out = 0;
    for (unsigned b = 0; b < 8; ++b) out = static_cast<u8>(out | (((v >> b) & 1u) << (7u - b)));
    return out;
}

u8 ref_rotl(u8 v, unsigned k) {
    for (unsigned i = 0; i < k; ++i) {
        const unsigned carry = (v >> 7) & 1u;
        v = static_cast<u8>(((v << 1) | carry) & 0xFFu);
    }
    return v;
}

u8 ref_rotr(u8 v, unsigned k) {
    for (unsigned i = 0; i < k; ++i) {
        const unsigned carry = v & 1u;
        v = static_cast<u8>((v >> 1) | (carry << 7));
    }
    return v;
}

std::vector<u8> ref_morph(u8 morph, u8 k, std::vector<u8> buf) {
    const std::size_t n = buf.size();
    switch (morph) {
        case 1:
            for (auto& b : buf) b = ref_bitrev(b);
            break;
        case 2:
            for (auto& b : buf) b = static_cast<u8>(255u - b);
            break;
        case 3:
        case 4:
        case 5: {
            const std::size_t blk = (morph == 3) ? 2u : (morph == 4) ? 4u : 8u;
            for (std::size_t base = 0; base + blk <= n; base += blk) {
                for (std::size_t i = 0; i < blk / 2; ++i) {
                    std::swap(buf[base + i], buf[base + blk - 1 - i]);
                }
            }
            break;
        }
        case 6:
            for (auto& b : buf) b = ref_rotl(b, k);
            break;
        case 7:
            for (auto& b : buf) b = ref_rotr(b, k);
            break;
        case 8:
            std::reverse(buf.begin(), buf.end());
            break;
        case 9: {
            const std::vector<u8> src = buf;
            for (std::size_t i = 0; i < n; ++i) buf[i] = ref_bitrev(src[n - 1 - i]);
            break;
        }
        default:
            break;
    }
    return buf;
}

std::vector<u8> ref_predictor(u8 pid, u32 param, const std::vector<u8>& r) {
    const std::size_t n = r.size();
    std::vector<u8> out(n, 0);
    if (n == 0) return out;
    switch (pid) {
        case 0:
            out[0] = r[0];
            for (std::size_t i = 1; i < n; ++i) out[i] = static_cast<u8>(out[i - 1] + r[i]);
            break;
        case 1:
            out[0] = r[0];
            for (std::size_t i = 1; i < n; ++i) out[i] = static_cast<u8>(out[i - 1] ^ r[i]);
            break;
        case 2:
            out[0] = r[0];
            if (n >= 2) out[1] = r[1];
            for (std::size_t i = 2; i < n; ++i) {
                out[i] = static_cast<u8>((2u * out[i - 1] - out[i - 2]) & 0xFFu);
            }
            break;
        case 3:
            for (std::size_t i = 0; i < n; ++i) {
                const u8 prev = (i < param) ? u8{0} : out[i - param];
                out[i] = static_cast<u8>(prev ^ r[i]);
            }
            break;
        case 4:
            for (std::size_t i = 0; i < n; ++i) {
                const u8 prev = (i < param) ? u8{0} : out[i - param];
                out[i] = static_cast<u8>(prev + r[i]);
            }
            break;
        default:
            break;
    }
    return out;
}

std::vector<u8> ref_lfsr(u64 conn, u64 init, std::size_t n) {
    std::vector<u8> out(n, 0);
    u64 state = init;
    for (std::size_t i = 0; i < n; ++i) {
        unsigned byte = 0;
        for (unsigned bit = 0; bit < 8; ++bit) {
            unsigned parity = 0;
            for (unsigned b = 0; b < 64; ++b) {
                parity ^= static_cast<unsigned>((state >> b) & 1u) &
                          static_cast<unsigned>((conn >> b) & 1u);
            }
            state = (state >> 1) | (static_cast<u64>(parity) << 63);
            byte = (byte << 1) | parity;
        }
        out[i] = static_cast<u8>(byte);
    }
    return out;
}

std::vector<u8> kat_pattern(std::size_t n, u8 seed) {
    std::vector<u8> out(n);
    u32 s = static_cast<u32>(seed) * 2654435761u + 1u;
    for (std::size_t i = 0; i < n; ++i) {
        s = s * 1664525u + 1013904223u;
        out[i] = static_cast<u8>((s >> 24) & 0xFFu);
    }
    return out;
}

// ---------------------------------------------------------------------------
// Pinned LFSR (conn, init) pairs
// ---------------------------------------------------------------------------

constexpr std::array<u64, 8> kLfsrConns = {
    0x0000000000000001ull, 0x0000000000200003ull, 0x00000000D0080004ull, 0x8000000000000001ull,
    0xD80000000000000Dull, 0x000000000000001Bull, 0xA5A5A5A5A5A5A5A5ull, 0xFFFFFFFFFFFFFFFFull,
};
constexpr std::array<u64, 8> kLfsrInits = {
    0x0000000000000000ull, 0x0000000000000001ull, 0xDEADBEEFCAFEF00Dull, 0x0123456789ABCDEFull,
    0xFEDCBA9876543210ull, 0xCAFEBABE12345678ull, 0x5A5A5A5A5A5A5A5Aull, 0xFFFFFFFFFFFFFFFFull,
};

// ---------------------------------------------------------------------------
// Term helpers
// ---------------------------------------------------------------------------

CorpusTerm make_term(const std::string& id, const std::string& corpus, u64 seed) {
    CorpusTerm term;
    term.id = id;
    term.corpus = corpus;
    term.desc.id = id;
    term.desc.corpus = corpus;
    term.desc.virtual_term = (corpus == "T-BIG");
    term.seed = seed;
    return term;
}

// ---------------------------------------------------------------------------
// T-KAT — 128 pinned terms
// ---------------------------------------------------------------------------

std::vector<CorpusTerm> build_t_kat() {
    std::vector<CorpusTerm> out;
    out.reserve(200);
    auto add = [&](const std::string& id, const std::function<std::string(DescArena&)>& build) {
        CorpusTerm term = make_term(id, "T-KAT", 0);
        term.desc.root = build(term.desc.arena);
        out.push_back(std::move(term));
    };

    // --- every kind, pinned ------------------------------------------------
    add("tkat-empty", [](DescArena& a) { return a.empty(); });
    add("tkat-atom1", [](DescArena& a) { return a.atom_node(a.atom_bytes("p", 1, 0xA5)); });
    add("tkat-atom16", [](DescArena& a) { return a.atom_node(a.atom_bytes("p", 16, 3)); });
    add("tkat-atom-max", [](DescArena& a) {
        return a.atom_node(a.atom_bytes("p", static_cast<std::size_t>(static_cast<u64>(marp::v2::kAtomMax)), 11));
    });
    add("tkat-atom-max-minus1", [](DescArena& a) {
        return a.atom_node(a.atom_bytes("p", static_cast<std::size_t>(static_cast<u64>(marp::v2::kAtomMax) - 1), 12));
    });
    add("tkat-zero0", [](DescArena& a) { return a.zero(0); });
    add("tkat-zero5", [](DescArena& a) { return a.zero(5); });
    add("tkat-zero1024", [](DescArena& a) { return a.zero(1024); });
    add("tkat-concat2", [](DescArena& a) {
        return a.concat({a.atom_node(a.atom_bytes("p", 16, 4)), a.zero(4)});
    });
    add("tkat-concat3", [](DescArena& a) {
        return a.concat({a.atom_node(a.atom_bytes("p", 16, 5)),
                         a.atom_node(a.atom_bytes("q", 31, 6)), a.zero(3)});
    });
    add("tkat-repeat35", [](DescArena& a) {
        return a.repeat(a.atom_node(a.atom_bytes("p", 16, 8)), 3, 5);
    });
    add("tkat-repeat20", [](DescArena& a) {
        return a.repeat(a.atom_node(a.atom_bytes("p", 7, 9)), 2, 0);
    });
    add("tkat-slicemid", [](DescArena& a) {
        return a.slice(a.atom_node(a.atom_bytes("p", 31, 11)), 5, 9);
    });
    add("tkat-sliceprefix", [](DescArena& a) {
        return a.slice(a.atom_node(a.atom_bytes("p", 16, 12)), 0, 6);
    });

    // --- every morph id with every valid k ---------------------------------
    for (u8 morph = 1; morph <= 9; ++morph) {
        if (morph == 6 || morph == 7) {
            for (u8 k = 1; k <= 7; ++k) {
                add("tkat-morph" + std::to_string(morph) + "k" + std::to_string(k),
                    [morph, k](DescArena& a) {
                        return a.morph(a.atom_node(a.atom_bytes("p", 32, morph)), morph, k);
                    });
            }
        } else {
            add("tkat-morph" + std::to_string(morph) + "k0", [morph](DescArena& a) {
                return a.morph(a.atom_node(a.atom_bytes("p", 32, morph)), morph, 0);
            });
        }
    }

    add("tkat-xor", [](DescArena& a) {
        return a.xor_node(a.atom_node(a.atom_bytes("p", 16, 20)),
                          a.atom_node(a.atom_bytes("q", 16, 21)));
    });

    // --- Interleave strides 1/2/3/7 ----------------------------------------
    for (u64 stride : {1ull, 2ull, 3ull, 7ull}) {
        add("tkat-ilv-s" + std::to_string(stride), [stride](DescArena& a) {
            const std::size_t len = static_cast<std::size_t>(stride * 3);
            return a.interleave({a.atom_node(a.atom_bytes("p", len, 30)),
                                 a.atom_node(a.atom_bytes("q", len, 31))},
                                stride);
        });
    }
    add("tkat-ilv-3s2", [](DescArena& a) {
        return a.interleave({a.atom_node(a.atom_bytes("p", 8, 36)),
                             a.atom_node(a.atom_bytes("q", 8, 37)),
                             a.atom_node(a.atom_bytes("r", 8, 38))},
                            2);
    });

    // --- pinned LFSR vectors ----------------------------------------------
    for (std::size_t i = 0; i < kLfsrConns.size(); ++i) {
        add("tkat-lfsr" + std::to_string(i), [i](DescArena& a) {
            return a.lfsr(kLfsrConns[i], kLfsrInits[i], 17);
        });
    }

    // --- Affine -----------------------------------------------------------
    add("tkat-affine", [](DescArena& a) { return a.affine(3, 5, 40); });
    add("tkat-affinewrap", [](DescArena& a) { return a.affine(250, 7, 300); });
    add("tkat-affinestep0", [](DescArena& a) { return a.affine(9, 0, 33); });

    // --- every predictor id with param edges -------------------------------
    add("tkat-pred0", [](DescArena& a) {
        return a.predictor(0, 0, a.atom_node(a.atom_bytes("p", 32, 40)));
    });
    add("tkat-pred1", [](DescArena& a) {
        return a.predictor(1, 0, a.atom_node(a.atom_bytes("p", 32, 41)));
    });
    add("tkat-pred2n1", [](DescArena& a) {
        return a.predictor(2, 0, a.atom_node(a.atom_bytes("p", 1, 42)));
    });
    add("tkat-pred2n2", [](DescArena& a) {
        return a.predictor(2, 0, a.atom_node(a.atom_bytes("p", 2, 43)));
    });
    add("tkat-pred2", [](DescArena& a) {
        return a.predictor(2, 0, a.atom_node(a.atom_bytes("p", 32, 44)));
    });
    for (u32 param : {1u, 2u, 5u, 33u}) {
        add("tkat-pred3p" + std::to_string(param), [param](DescArena& a) {
            return a.predictor(3, param,
                               a.atom_node(a.atom_bytes("p", 32 + param,
                                                        static_cast<u8>(param))));
        });
        add("tkat-pred4p" + std::to_string(param), [param](DescArena& a) {
            return a.predictor(4, param,
                               a.atom_node(a.atom_bytes("p", 32 + param,
                                                        static_cast<u8>(param + 60u))));
        });
    }

    // --- compositions, sharing, deep shapes -------------------------------
    add("tkat-nest-xor-slice-repeat", [](DescArena& a) {
        const std::string rep = a.repeat(a.atom_node(a.atom_bytes("p", 16, 50)), 3, 5);
        const std::string sl = a.slice(rep, 7, 20);
        return a.xor_node(sl, a.atom_node(a.atom_bytes("q", 20, 51)));
    });
    add("tkat-nest-ilv-morph-lfsr", [](DescArena& a) {
        const std::string m = a.morph(a.atom_node(a.atom_bytes("p", 8, 52)), 6, 3);
        const std::string l = a.lfsr(0x80000005ull, 0x1234ull, 8);
        return a.interleave({m, l}, 1);
    });
    add("tkat-nest-pred-concat", [](DescArena& a) {
        const std::string cat = a.concat({a.atom_node(a.atom_bytes("p", 16, 53)), a.zero(16)});
        return a.predictor(4, 3, cat);
    });
    add("tkat-nest-morph-slice-xor", [](DescArena& a) {
        const std::string x = a.xor_node(a.atom_node(a.atom_bytes("p", 16, 54)),
                                         a.atom_node(a.atom_bytes("q", 16, 55)));
        return a.morph(a.slice(x, 2, 10), 8, 0);
    });
    add("tkat-nest-repeat-concat-morph9", [](DescArena& a) {
        const std::string cat = a.concat({a.atom_node(a.atom_bytes("p", 8, 56)),
                                          a.morph(a.atom_node(a.atom_bytes("q", 8, 57)), 9, 0)});
        return a.repeat(cat, 2, 3);
    });
    add("tkat-shared", [](DescArena& a) {
        const std::string atom = a.atom_node(a.atom_bytes("p", 24, 58));
        const std::string sl = a.slice(atom, 3, 11);
        return a.xor_node(sl, sl);
    });
    add("tkat-deep-morph-chain", [](DescArena& a) {
        std::string node = a.atom_node(a.atom_bytes("p", 8, 59));
        for (int i = 0; i < 64; ++i) node = a.morph(node, 2, 0);
        return node;
    });
    add("tkat-deep-slice-chain", [](DescArena& a) {
        std::string node = a.atom_node(a.atom_bytes("p", 64, 60));
        for (int i = 1; i <= 32; ++i) {
            node = a.slice(node, 1, static_cast<u64>(64 - 2 * i));
        }
        return node;
    });
    add("tkat-concat-many", [](DescArena& a) {
        std::vector<std::string> kids;
        for (u32 i = 0; i < 16; ++i) {
            kids.push_back(a.atom_node(
                a.atom_bytes("p" + std::to_string(i), 3 + (i % 5), static_cast<u8>(i + 1))));
        }
        return a.concat(std::move(kids));
    });
    add("tkat-ilv-many", [](DescArena& a) {
        std::vector<std::string> kids;
        for (u32 i = 0; i < 5; ++i) {
            kids.push_back(a.atom_node(a.atom_bytes("p" + std::to_string(i), 9,
                                                    static_cast<u8>(i + 70))));
        }
        return a.interleave(std::move(kids), 3);
    });
    add("tkat-lfsr-plus-atom", [](DescArena& a) {
        return a.concat({a.lfsr(0x123456789ABCDEFull, 0x0FEDCBA987654321ull, 13),
                         a.atom_node(a.atom_bytes("p", 13, 80))});
    });
    add("tkat-whole-reverse", [](DescArena& a) {
        return a.morph(a.atom_node(a.atom_bytes("p", 64, 81)), 8, 0);
    });
    add("tkat-xor-lfsr-affine", [](DescArena& a) {
        return a.xor_node(a.lfsr(0x40000001ull, 0x9E3779B97F4A7C15ull, 64), a.affine(17, 3, 64));
    });
    add("tkat-pred-stride-lfsr", [](DescArena& a) {
        return a.predictor(3, 7, a.lfsr(0x1000000000000001ull, 0xC0FFEEull, 70));
    });
    add("tkat-repeat-concat", [](DescArena& a) {
        const std::string cat = a.concat({a.atom_node(a.atom_bytes("p", 5, 90)), a.zero(2)});
        return a.repeat(cat, 4, 0);
    });
    add("tkat-slice-repeat", [](DescArena& a) {
        const std::string rep = a.repeat(a.atom_node(a.atom_bytes("p", 11, 91)), 5, 3);
        return a.slice(rep, 4, 40);
    });
    add("tkat-ilv-stride7-3kids", [](DescArena& a) {
        return a.interleave({a.atom_node(a.atom_bytes("p", 7, 92)),
                             a.atom_node(a.atom_bytes("q", 7, 93)),
                             a.atom_node(a.atom_bytes("r", 7, 94))},
                            7);
    });
    // --- additional pinned terms: every morph id, every predictor id and every
    // Interleave stride is present at least twice, plus wider shapes that the
    // range sampler and the 13-sample schedule need (E2 §12.3 count 128). ------
    add("tkat-atom2", [](DescArena& a) { return a.atom_node(a.atom_bytes("p", 2, 0x5A)); });
    add("tkat-atom7", [](DescArena& a) { return a.atom_node(a.atom_bytes("p", 7, 0x2C)); });
    add("tkat-atom64", [](DescArena& a) { return a.atom_node(a.atom_bytes("p", 64, 0x91)); });
    add("tkat-atom1023", [](DescArena& a) {
        return a.atom_node(a.atom_bytes("p", 1023, 0x3D));
    });
    add("tkat-zero1", [](DescArena& a) { return a.zero(1); });
    add("tkat-zero4096", [](DescArena& a) { return a.zero(4096); });
    add("tkat-concat-two-atoms", [](DescArena& a) {
        return a.concat({a.atom_node(a.atom_bytes("p", 5, 31)),
                         a.atom_node(a.atom_bytes("q", 6, 32))});
    });
    add("tkat-concat-mixed", [](DescArena& a) {
        return a.concat({a.zero(3), a.atom_node(a.atom_bytes("p", 4, 33)), a.lfsr(5, 2, 8),
                         a.affine(1, 2, 16)});
    });
    add("tkat-repeat-q2", [](DescArena& a) {
        return a.repeat(a.atom_node(a.atom_bytes("p", 4, 34)), 2, 0);
    });
    add("tkat-repeat-q2-r3", [](DescArena& a) {
        return a.repeat(a.atom_node(a.atom_bytes("p", 8, 35)), 2, 3);
    });
    add("tkat-repeat-q64", [](DescArena& a) {
        return a.repeat(a.atom_node(a.atom_bytes("p", 8, 36)), 64, 5);
    });
    add("tkat-slice-tail", [](DescArena& a) {
        return a.slice(a.atom_node(a.atom_bytes("p", 32, 37)), 16, 16);
    });
    add("tkat-slice-zero-len", [](DescArena& a) {
        return a.slice(a.atom_node(a.atom_bytes("p", 32, 39)), 8, 0);
    });
    for (const u8 morph : {u8{1}, u8{2}, u8{3}, u8{4}, u8{5}, u8{6}, u8{7}, u8{8}, u8{9}}) {
        if (morph == 6 || morph == 7) continue;  // covered by the pins above
        add("tkat-morph-" + std::to_string(morph), [morph](DescArena& a) {
            return a.morph(a.atom_node(a.atom_bytes("p", 64, static_cast<u8>(0x40 + morph))),
                           morph, 0);
        });
    }
    add("tkat-morph-rotl-k3", [](DescArena& a) {
        return a.morph(a.atom_node(a.atom_bytes("p", 24, 0x51)), 6, 3);
    });
    add("tkat-morph-rotr-k5", [](DescArena& a) {
        return a.morph(a.atom_node(a.atom_bytes("p", 24, 0x52)), 7, 5);
    });
    add("tkat-morph-chain", [](DescArena& a) {
        return a.morph(a.morph(a.atom_node(a.atom_bytes("p", 64, 0x53)), 3, 0), 8, 0);
    });
    add("tkat-xor-atoms", [](DescArena& a) {
        return a.xor_node(a.atom_node(a.atom_bytes("p", 16, 0x54)),
                          a.atom_node(a.atom_bytes("q", 16, 0x55)));
    });
    add("tkat-xor-lfsr", [](DescArena& a) {
        return a.xor_node(a.lfsr(0x21, 3, 32), a.affine(5, 1, 32));
    });
    add("tkat-xor-morph", [](DescArena& a) {
        return a.xor_node(a.morph(a.atom_node(a.atom_bytes("p", 32, 0x56)), 2, 0),
                          a.atom_node(a.atom_bytes("q", 32, 0x57)));
    });
    add("tkat-ilv-stride1-two", [](DescArena& a) {
        return a.interleave({a.atom_node(a.atom_bytes("p", 8, 0x58)),
                             a.atom_node(a.atom_bytes("q", 8, 0x59))}, 1);
    });
    add("tkat-ilv-stride2", [](DescArena& a) {
        return a.interleave({a.atom_node(a.atom_bytes("p", 8, 0x5A)),
                             a.atom_node(a.atom_bytes("q", 8, 0x5B))}, 2);
    });
    add("tkat-ilv-stride4", [](DescArena& a) {
        return a.interleave({a.atom_node(a.atom_bytes("p", 8, 0x5C)),
                             a.atom_node(a.atom_bytes("q", 8, 0x5D))}, 4);
    });
    add("tkat-ilv-stride7", [](DescArena& a) {
        return a.interleave({a.atom_node(a.atom_bytes("p", 7, 0x5E)),
                             a.atom_node(a.atom_bytes("q", 7, 0x5F)),
                             a.atom_node(a.atom_bytes("r", 7, 0x60))}, 7);
    });
    add("tkat-ilv-four", [](DescArena& a) {
        return a.interleave({a.atom_node(a.atom_bytes("p", 8, 0x61)),
                             a.atom_node(a.atom_bytes("q", 8, 0x62)),
                             a.atom_node(a.atom_bytes("r", 8, 0x63)),
                             a.atom_node(a.atom_bytes("s", 8, 0x64))}, 4);
    });
    add("tkat-lfsr-1byte", [](DescArena& a) { return a.lfsr(0x1, 1, 1); });
    add("tkat-lfsr-65", [](DescArena& a) { return a.lfsr(0xD0080004, 0xDEADBEEF, 65); });
    add("tkat-lfsr-max", [](DescArena& a) {
        return a.lfsr(0xFFFFFFFFFFFFFFFFull, 0xFEDCBA9876543210ull, 128);
    });
    add("tkat-affine-step7", [](DescArena& a) { return a.affine(9, 7, 33); });
    add("tkat-pred0-n1", [](DescArena& a) {
        return a.predictor(0, 0, a.atom_node(a.atom_bytes("p", 1, 0x65)));
    });
    add("tkat-pred2-n2", [](DescArena& a) {
        return a.predictor(2, 0, a.atom_node(a.atom_bytes("p", 2, 0x66)));
    });
    add("tkat-pred3-param1", [](DescArena& a) {
        return a.predictor(3, 1, a.atom_node(a.atom_bytes("p", 16, 0x67)));
    });
    add("tkat-pred3-param16", [](DescArena& a) {
        return a.predictor(3, 16, a.atom_node(a.atom_bytes("p", 16, 0x68)));
    });
    add("tkat-pred4-param2", [](DescArena& a) {
        return a.predictor(4, 2, a.atom_node(a.atom_bytes("p", 24, 0x69)));
    });
    add("tkat-pred4-param24", [](DescArena& a) {
        return a.predictor(4, 24, a.atom_node(a.atom_bytes("p", 24, 0x6A)));
    });
    add("tkat-nest-concat-repeat-slice", [](DescArena& a) {
        return a.concat({a.repeat(a.atom_node(a.atom_bytes("p", 4, 0x6B)), 3, 0),
                         a.slice(a.atom_node(a.atom_bytes("q", 16, 0x6C)), 4, 8)});
    });
    add("tkat-nest-xor-ilv", [](DescArena& a) {
        return a.xor_node(a.interleave({a.atom_node(a.atom_bytes("p", 8, 0x6D)),
                                        a.atom_node(a.atom_bytes("q", 8, 0x6E))}, 2),
                          a.atom_node(a.atom_bytes("r", 16, 0x6F)));
    });
    add("tkat-nest-pred-morph-lfsr", [](DescArena& a) {
        return a.predictor(1, 0, a.morph(a.lfsr(0x200003, 5, 64), 9, 0));
    });
    add("tkat-nest-slice-repeat", [](DescArena& a) {
        return a.slice(a.repeat(a.atom_node(a.atom_bytes("p", 6, 0x70)), 4, 2), 5, 20);
    });
    add("tkat-wide-concat-9", [](DescArena& a) {
        std::vector<std::string> kids;
        for (u8 i = 0; i < 9; ++i) {
            kids.push_back(a.atom_node(a.atom_bytes("p" + std::to_string(i), 4,
                                                    static_cast<u8>(0x80 + i))));
        }
        return a.concat(std::move(kids));
    });

    return out;
}

// ---------------------------------------------------------------------------
// T-GEN — 5 000 seeded well-formed terms, depth 1..8, expansion <= 4 MiB
// ---------------------------------------------------------------------------

// Builds one term of the requested depth.  Lengths are computed from structure
// afterwards and the term is pruned to the nodes reachable from its root, so the
// generator never leaves an unused node or atom behind (W2) — the depth and the
// 4 MiB expansion cap are then measured on the struct the gate actually binds.
std::string gen_term(DescArena& arena, Rng& rng, Rng& atom_rng, int depth, u64 cap) {
    std::vector<std::pair<std::string, BigInt>> level;
    for (int d = 0; d < depth; ++d) {
        std::vector<std::pair<std::string, BigInt>> next;
        const u64 count = 1 + rng.below(2);
        for (u64 k = 0; k < count; ++k) {
            std::string id;
            auto len_of = [&](const std::string& nid) {
                auto len = arena.length_of(nid);
                return len.has_value() ? len.value() : BigInt::zero();
            };
            if (level.empty()) {
                const std::vector<u8> payload =
                    kat_pattern(1 + static_cast<std::size_t>(atom_rng.below(24)), atom_rng.byte());
                switch (rng.below(4)) {
                    case 0:
                        id = arena.atom_node(arena.atom("g", payload));
                        break;
                    case 1:
                        id = arena.zero(BigInt(1 + rng.below(64)));
                        break;
                    case 2:
                        id = arena.lfsr(1ull + rng.below(0xFFFFFFFFFFFFull), rng.next(),
                                        BigInt(1 + rng.below(48)));
                        break;
                    default:
                        id = arena.affine(rng.byte(), static_cast<u8>(1u + rng.byte()),
                                          BigInt(1 + rng.below(48)));
                        break;
                }
            } else {
                const auto& c0 = level[static_cast<std::size_t>(rng.below(level.size()))];
                const auto& c1 = level[static_cast<std::size_t>(rng.below(level.size()))];
                switch (rng.below(9)) {
                    case 0:  // Concat
                        id = arena.concat({c0.first, c1.first});
                        break;
                    case 1: {  // Repeat
                        auto cl = c0.second.to_u64_checked();
                        if (!cl.has_value() || *cl == 0) {
                            id = c0.first;
                            break;
                        }
                        const u64 q = 2 + rng.below(3);
                        const u64 r = rng.below(std::min<u64>(*cl, 4));
                        id = arena.repeat(c0.first, q, r);
                        break;
                    }
                    case 2: {  // Slice
                        auto cl = c0.second.to_u64_checked();
                        if (!cl.has_value() || *cl == 0) {
                            id = c0.first;
                            break;
                        }
                        const u64 start = rng.below(*cl + 1);
                        const u64 take = rng.below(*cl - start + 1);
                        id = arena.slice(c0.first, start, take);
                        break;
                    }
                    case 3: {  // Morph
                        auto cl = c0.second.to_u64_checked();
                        u8 morph = static_cast<u8>(1 + rng.below(9));
                        u8 mk = 0;
                        if (morph == 6 || morph == 7) mk = static_cast<u8>(1 + rng.below(7));
                        if (morph == 3 || morph == 4 || morph == 5) {
                            const u64 blk = (morph == 3) ? 2u : (morph == 4) ? 4u : 8u;
                            if (!cl.has_value() || (*cl % blk) != 0) {
                                morph = 2;
                                mk = 0;
                            }
                        }
                        id = arena.morph(c0.first, morph, mk);
                        break;
                    }
                    case 4: {  // Xor
                        if (c0.second.compare(c1.second) != 0 || c0.first == c1.first) {
                            id = c0.first;
                            break;
                        }
                        id = arena.xor_node(c0.first, c1.first);
                        break;
                    }
                    case 5: {  // Interleave
                        auto cl = c0.second.to_u64_checked();
                        if (!cl.has_value() || *cl == 0) {
                            id = c0.first;
                            break;
                        }
                        u64 stride = 1 + rng.below(7);
                        while ((*cl % stride) != 0) --stride;
                        id = arena.interleave({c0.first, c0.first}, stride);
                        break;
                    }
                    case 6: {  // Predictor
                        const u8 pid = static_cast<u8>(rng.below(5));
                        const u32 param = (pid >= 3) ? 1u + static_cast<u32>(rng.below(16)) : 0u;
                        id = arena.predictor(pid, param, c0.first);
                        break;
                    }
                    case 7:  // Lfsr
                        id = arena.lfsr(1ull + rng.below(0xFFFFFFFFFFFFull), rng.next(),
                                        BigInt(1 + rng.below(64)));
                        break;
                    default:  // Affine
                        id = arena.affine(rng.byte(), rng.byte(), BigInt(1 + rng.below(64)));
                        break;
                }
            }
            const BigInt len = len_of(id);
            if (len.is_zero()) continue;  // keep every generated term non-empty
            auto u64len = len.to_u64_checked();
            if (!u64len.has_value() || *u64len > cap) continue;
            next.push_back({id, len});
        }
        if (next.empty()) break;
        level = std::move(next);
    }
    if (level.empty()) {
        return arena.atom_node(arena.atom("fallback", kat_pattern(8, rng.byte())));
    }
    const std::string root = level.back().first;
    // Prune: rebuild the arena with only the nodes/atoms reachable from `root`,
    // in description order, so no unused record survives.
    std::vector<char> keep(arena.node_count(), 0);
    std::vector<char> keep_atom(arena.atom_count(), 0);
    std::vector<std::string> stack{root};
    while (!stack.empty()) {
        const std::string id = stack.back();
        stack.pop_back();
        const std::size_t idx = arena.index_of_public(id);
        if (idx >= arena.node_count() || keep[idx] != 0) continue;
        keep[idx] = 1;
        const DescNode& node = arena.nodes()[idx];
        if (node.kind == Kind::Atom) {
            const std::size_t a = arena.atom_index_public(node.atom);
            if (a < arena.atom_count()) keep_atom[a] = 1;
        }
        for (const std::string& kid : node.kids) stack.push_back(kid);
    }
    DescArena pruned;
    std::vector<std::string> remap_atom(arena.atom_count());
    for (std::size_t i = 0; i < arena.atom_count(); ++i) {
        if (keep_atom[i] == 0) continue;
        remap_atom[i] = pruned.atom(arena.atoms()[i].id, arena.atoms()[i].payload,
                                    arena.atoms()[i].klass);
    }
    std::vector<std::string> remap(arena.node_count());
    for (std::size_t i = 0; i < arena.node_count(); ++i) {
        if (keep[i] == 0) continue;
        const DescNode& node = arena.nodes()[i];
        if (node.kind == Kind::Atom) {
            remap[i] = pruned.atom_node(remap_atom[arena.atom_index_public(node.atom)]);
            continue;
        }
        DescNode copy = node;
        copy.id = "";
        copy.kids.clear();
        copy.atom.clear();
        for (const std::string& kid : node.kids) {
            const std::size_t k = arena.index_of_public(kid);
            copy.kids.push_back(k < remap.size() ? remap[k] : kid);
        }
        remap[i] = pruned.node(std::move(copy));
    }
    const std::size_t root_idx = arena.index_of_public(root);
    const std::string final_root = root_idx < remap.size() ? remap[root_idx] : root;
    arena = std::move(pruned);
    return final_root;
}

std::vector<CorpusTerm> build_t_gen() {
    std::vector<CorpusTerm> out;
    out.reserve(5000);
    Rng rng(CorpusSeeds::kGen);
    Rng atom_rng(CorpusSeeds::kGenAtoms);
    for (int n = 0; n < 5000; ++n) {
        CorpusTerm term = make_term("tgen-" + std::to_string(n), "T-GEN", CorpusSeeds::kGen);
        const int depth = 1 + (n % kGenDepthMax);
        term.desc.root =
            gen_term(term.desc.arena, rng, atom_rng, depth, kGenExpansionCap);
        out.push_back(std::move(term));
    }
    return out;
}

// ---------------------------------------------------------------------------
// T-BIG — 64 virtual terms (lengths above 2^40, never materialised)
// ---------------------------------------------------------------------------

std::vector<CorpusTerm> build_t_big() {
    std::vector<CorpusTerm> out;
    out.reserve(64);
    auto add = [&](const std::string& id, const std::function<std::string(DescArena&)>& build) {
        CorpusTerm term = make_term(id, "T-BIG", CorpusSeeds::kBig);
        term.desc.root = build(term.desc.arena);
        out.push_back(std::move(term));
    };

    const std::array<u64, 8> conns = {0x0000000000200003ull, 0x00000000D0080004ull,
                                      0x8000000000000001ull, 0xD80000000000000Dull,
                                      0x0000000000000001ull, 0xFFFFFFFFFFFFFFFFull,
                                      0xA5A5A5A5A5A5A5A5ull, 0x4000000000000001ull};
    for (std::size_t i = 0; i < conns.size(); ++i) {
        const u64 conn = conns[i];
        const u64 init = kLfsrInits[i];
        const std::string tag = std::to_string(i);
        const auto seed8 = static_cast<u8>(i + 1);

        add("tbig-zero-" + tag, [](DescArena& a) { return a.zero(pow2(40)); });
        add("tbig-affine-" + tag, [seed8, i](DescArena& a) {
            return a.affine(static_cast<u8>(7u * (i + 1u)), static_cast<u8>(3u + i), pow2(40));
        });
        add("tbig-lfsr-" + tag, [conn, init](DescArena& a) {
            return a.lfsr(conn, init, pow2(40));
        });
        add("tbig-repeat-" + tag, [i](DescArena& a) {
            const std::string atom = a.atom_node(a.atom_bytes("p", 4 + i, static_cast<u8>(i + 1)));
            return a.repeat(atom, pow2(40), BigInt(i));
        });
        add("tbig-slice-zero-" + tag, [i](DescArena& a) {
            // ℓ = 2^41 bytes, starting a little above 2^32: the slice itself is
            // above 2^40 (E2 §12.3) and its starts are range-only.
            const std::string z = a.zero(pow2(42));
            return a.slice(z, pow2(32).add(BigInt(7 + i)).value(), pow2(41));
        });
        add("tbig-slice-lfsr-" + tag, [conn, init](DescArena& a) {
            const std::string l = a.lfsr(conn, init, pow2(42).add(pow2(41)).value());
            return a.slice(l, pow2(32).add(BigInt(1)).value(), pow2(41).add(BigInt(4096)).value());
        });
        add("tbig-concat-boundary-" + tag, [i](DescArena& a) {
            return a.concat({a.zero(pow2(40)),
                             a.atom_node(a.atom_bytes("tail", 8 + i, static_cast<u8>(i + 3)))});
        });
        add("tbig-nested-repeat-" + tag, [i](DescArena& a) {
            const std::string inner = a.repeat(
                a.atom_node(a.atom_bytes("p", 2 + i, static_cast<u8>(i + 5))), pow2(20), BigInt(0));
            return a.repeat(inner, pow2(20), BigInt(i));
        });
    }
    return out;
}

// ---------------------------------------------------------------------------
// T-BAD — 64 terms, one per violation (E2 §12.3)
// ---------------------------------------------------------------------------

std::vector<CorpusTerm> build_t_bad() {
    std::vector<CorpusTerm> out;
    out.reserve(80);
    auto add = [&](const std::string& id, const char* constraint, const std::function<std::string(DescArena&)>& build) {
        CorpusTerm term = make_term(id, "T-BAD", 0);
        term.expected_constraint = constraint;
        term.expected_code = Code::Invalid;
        term.desc.root = build(term.desc.arena);
        out.push_back(std::move(term));
    };

    // --- argc, one case per kind that has an argc contract ----------------
    add("bad-argc-empty", kC_argc, [](DescArena& a) {
        const std::string leaf = a.zero(4);
        DescNode n;
        n.kind = Kind::Empty;
        const std::string id = a.node(std::move(n));
        a.add_extra_child(id, leaf);
        return id;
    });
    add("bad-argc-atom", kC_argc, [](DescArena& a) {
        const std::string z = a.zero(2);
        const std::string atom = a.atom_node(a.atom_bytes("p", 4, 1));
        a.add_extra_child(atom, z);
        return atom;
    });
    add("bad-argc-zero", kC_argc, [](DescArena& a) {
        const std::string leaf = a.zero(4);
        const std::string z = a.zero(3);
        a.add_extra_child(z, leaf);
        return z;
    });
    add("bad-argc-concat", kC_argc, [](DescArena& a) {
        return a.concat({a.zero(4)});
    });
    add("bad-argc-repeat", kC_argc, [](DescArena& a) {
        const std::string atom = a.atom_node(a.atom_bytes("p", 4, 2));
        const std::string rep = a.repeat(atom, 2, 0);
        a.add_extra_child(rep, atom);
        return rep;
    });
    add("bad-argc-slice", kC_argc, [](DescArena& a) {
        const std::string atom = a.atom_node(a.atom_bytes("p", 8, 3));
        const std::string sl = a.slice(atom, 1, 2);
        a.add_extra_child(sl, atom);
        return sl;
    });
    add("bad-argc-morph", kC_argc, [](DescArena& a) {
        const std::string atom = a.atom_node(a.atom_bytes("p", 8, 4));
        const std::string m = a.morph(atom, 2, 0);
        a.add_extra_child(m, atom);
        return m;
    });
    add("bad-argc-xor", kC_argc, [](DescArena& a) {
        const std::string atom = a.atom_node(a.atom_bytes("p", 8, 5));
        const std::string x = a.xor_node(atom, atom);
        a.add_extra_child(x, atom);
        return x;
    });
    add("bad-argc-interleave-0", kC_argc, [](DescArena& a) {
        // Zero children: W8.argc for Interleave (argc >= 1).
        return a.interleave({}, 1);
    });
    add("bad-argc-lfsr", kC_argc, [](DescArena& a) {
        const std::string leaf = a.zero(2);
        const std::string l = a.lfsr(1, 1, 8);
        a.add_extra_child(l, leaf);
        return l;
    });
    add("bad-argc-affine", kC_argc, [](DescArena& a) {
        const std::string leaf = a.zero(2);
        const std::string f = a.affine(1, 2, 8);
        a.add_extra_child(f, leaf);
        return f;
    });
    add("bad-argc-predictor", kC_argc, [](DescArena& a) {
        const std::string atom = a.atom_node(a.atom_bytes("p", 8, 6));
        const std::string p = a.predictor(0, 0, atom);
        a.add_extra_child(p, atom);
        return p;
    });

    // --- each k violation -------------------------------------------------
    add("bad-morph-id0", kC_morph, [](DescArena& a) {
        return a.morph(a.atom_node(a.atom_bytes("p", 8, 10)), 0, 0);
    });
    add("bad-morph-id10", kC_morph, [](DescArena& a) {
        return a.morph(a.atom_node(a.atom_bytes("p", 8, 11)), 10, 0);
    });
    add("bad-morph-rotl-k0", kC_morph, [](DescArena& a) {
        return a.morph(a.atom_node(a.atom_bytes("p", 8, 12)), 6, 0);
    });
    add("bad-morph-rotl-k8", kC_morph, [](DescArena& a) {
        return a.morph(a.atom_node(a.atom_bytes("p", 8, 13)), 6, 8);
    });
    add("bad-morph-rotr-k0", kC_morph, [](DescArena& a) {
        return a.morph(a.atom_node(a.atom_bytes("p", 8, 14)), 7, 0);
    });
    add("bad-morph-rotr-k8", kC_morph, [](DescArena& a) {
        return a.morph(a.atom_node(a.atom_bytes("p", 8, 15)), 7, 8);
    });
    add("bad-morph-invert-k1", kC_morph, [](DescArena& a) {
        return a.morph(a.atom_node(a.atom_bytes("p", 8, 16)), 2, 1);
    });
    add("bad-morph-bitrev-k3", kC_morph, [](DescArena& a) {
        return a.morph(a.atom_node(a.atom_bytes("p", 8, 17)), 1, 3);
    });
    add("bad-morph-swap16-k1", kC_morph, [](DescArena& a) {
        return a.morph(a.atom_node(a.atom_bytes("p", 8, 18)), 3, 1);
    });
    add("bad-morph-swap32-k5", kC_morph, [](DescArena& a) {
        return a.morph(a.atom_node(a.atom_bytes("p", 8, 19)), 4, 5);
    });
    add("bad-morph-swap64-k7", kC_morph, [](DescArena& a) {
        return a.morph(a.atom_node(a.atom_bytes("p", 8, 20)), 5, 7);
    });
    add("bad-morph-reverse-k2", kC_morph, [](DescArena& a) {
        return a.morph(a.atom_node(a.atom_bytes("p", 8, 21)), 8, 2);
    });
    add("bad-morph-revbits-k1", kC_morph, [](DescArena& a) {
        return a.morph(a.atom_node(a.atom_bytes("p", 8, 22)), 9, 1);
    });

    // --- length constraints ------------------------------------------------
    add("bad-len-swap16-odd", kC_morph, [](DescArena& a) {
        return a.morph(a.atom_node(a.atom_bytes("p", 9, 30)), 3, 0);
    });
    add("bad-len-swap32-mod4", kC_morph, [](DescArena& a) {
        return a.morph(a.atom_node(a.atom_bytes("p", 10, 31)), 4, 0);
    });
    add("bad-len-swap64-mod8", kC_morph, [](DescArena& a) {
        return a.morph(a.atom_node(a.atom_bytes("p", 12, 32)), 5, 0);
    });
    add("bad-len-xor-differs", kC_xor, [](DescArena& a) {
        return a.xor_node(a.atom_node(a.atom_bytes("p", 8, 33)),
                          a.atom_node(a.atom_bytes("q", 9, 34)));
    });
    add("bad-len-interleave-differs", kC_interleave, [](DescArena& a) {
        return a.interleave({a.atom_node(a.atom_bytes("p", 8, 35)),
                             a.atom_node(a.atom_bytes("q", 9, 36))},
                            1);
    });
    add("bad-len-interleave-mod", kC_interleave, [](DescArena& a) {
        return a.interleave({a.atom_node(a.atom_bytes("p", 9, 37)),
                             a.atom_node(a.atom_bytes("q", 9, 38))},
                            2);
    });
    add("bad-len-slice-overrun", kC_slice, [](DescArena& a) {
        return a.slice(a.atom_node(a.atom_bytes("p", 8, 39)), 3, 6);
    });
    add("bad-len-slice-start-past", kC_slice, [](DescArena& a) {
        return a.slice(a.atom_node(a.atom_bytes("p", 8, 40)), 9, 0);
    });
    add("bad-len-repeat-r", kC_repeat, [](DescArena& a) {
        return a.repeat(a.atom_node(a.atom_bytes("p", 8, 41)), 2, 8);
    });
    add("bad-len-repeat-r-greater", kC_repeat, [](DescArena& a) {
        return a.repeat(a.atom_node(a.atom_bytes("p", 8, 42)), 1, 9);
    });
    add("bad-len-repeat-q0-r", kC_repeat, [](DescArena& a) {
        return a.repeat(a.atom_node(a.atom_bytes("p", 8, 43)), 0, 1);
    });

    // --- conn = 0 ----------------------------------------------------------
    add("bad-lfsr-conn0", kC_lfsr, [](DescArena& a) { return a.lfsr(0, 0x1234, 16); });

    // --- unknown pid -------------------------------------------------------
    add("bad-pred-pid5", kC_predictor, [](DescArena& a) {
        return a.predictor(5, 0, a.atom_node(a.atom_bytes("p", 8, 50)));
    });
    add("bad-pred-pid255", kC_predictor, [](DescArena& a) {
        return a.predictor(255, 0, a.atom_node(a.atom_bytes("p", 8, 51)));
    });
    add("bad-pred-stride-param0", kC_predictor, [](DescArena& a) {
        return a.predictor(3, 0, a.atom_node(a.atom_bytes("p", 8, 52)));
    });
    add("bad-pred-stride2-param0", kC_predictor, [](DescArena& a) {
        return a.predictor(4, 0, a.atom_node(a.atom_bytes("p", 8, 53)));
    });

    // --- child id >= parent (W3.arg-order) --------------------------------
    add("bad-self-child", kC_arg_order, [](DescArena& a) {
        // Morph whose child reference points at itself.
        DescNode n;
        n.kind = Kind::Morph;
        n.morph = 2;
        const std::string id = a.node(std::move(n));
        a.add_extra_child(id, id);
        return id;
    });
    add("bad-child-after-parent", kC_arg_order, [](DescArena& a) {
        DescNode n;
        n.kind = Kind::Concat;
        const std::string parent = a.node(std::move(n));
        const std::string later = a.zero(4);
        a.add_extra_child(parent, later);
        a.add_extra_child(parent, later);
        return parent;
    });

    // --- depth 2^16 + 1 (W7 depth, Limit) ---------------------------------
    // W7: depth 2^16 is legal, 2^16+1 is the first illegal depth, and §9 maps a
    // depth violation to `Limit` (not `Invalid`).
    {
        CorpusTerm term = make_term("bad-depth", "T-BAD", 0);
        term.expected_constraint = kC_depth;
        term.expected_code = Code::Limit;
        std::string node = term.desc.arena.atom_node(term.desc.arena.atom_bytes("p", 4, 60));
        for (u32 i = 0; i <= kMaxDepthSpec; ++i) node = term.desc.arena.morph(node, 2, 0);
        term.desc.root = node;
        out.push_back(std::move(term));
    }

    // --- unused node / unused atom / zero-length atom ---------------------
    add("bad-unused-node", kC_reachable, [](DescArena& a) {
        (void)a.zero(4);
        return a.atom_node(a.atom_bytes("p", 4, 61));
    });
    add("bad-unused-atom", kC_atom_unused, [](DescArena& a) {
        (void)a.atom_bytes("orphan", 4, 62);
        return a.atom_node(a.atom_bytes("p", 4, 63));
    });
    add("bad-zero-atom", kC_atom_len, [](DescArena& a) {
        return a.atom_node(a.atom_bytes("p", 0, 64));
    });

    // --- stored-length mismatches ----------------------------------------
    add("bad-stored-length", kC_length, [](DescArena& a) {
        const std::string z = a.zero(8);
        const std::string m = a.morph(z, 2, 0);
        a.pin_length(m, BigInt(9));
        return m;
    });
    add("bad-stored-length-intermediate", kC_length, [](DescArena& a) {
        // An intermediate node's stored length is wrong while the root's is
        // right: W6.length (not W5.total-length) is the first failure.
        const std::string z = a.zero(8);
        const std::string m = a.morph(z, 2, 0);
        a.pin_length(z, BigInt(9));
        return m;
    });
    add("bad-atom-payload-length", kC_atom_payload, [](DescArena& a) {
        const std::string atom = a.atom_bytes("p", 8, 70);
        a.set_atom_declared_length(atom, BigInt(9));
        return a.atom_node(atom);
    });
    add("bad-node-flags", kC_node_flags, [](DescArena& a) {
        const std::string z = a.zero(8);
        a.set_flags(z, 1);
        return z;
    });
    add("bad-atom-flags", kC_atom_flags, [](DescArena& a) {
        const std::string atom = a.atom_bytes("p", 8, 71);
        a.set_atom_flags(atom, 1);
        return a.atom_node(atom);
    });
    add("bad-kind-domain", kC_kind, [](DescArena& a) {
        const std::string z = a.zero(4);
        a.set_kind_raw(z, 12);
        return z;
    });
    // --- W3.arg-range / W8.atom-id / W1 / W5 / depth-as-Limit / output cap ---
    add("bad-arg-range", kC_arg_range, [](DescArena& a) {
        // A single `Zero` node.  §5.1 checks the arg list (W3) before the kind
        // constraints (W8), so a `Zero` carrying one out-of-table arg reports
        // W3.arg-range first.  The description format cannot express an
        // out-of-table child id (the binder substitutes node 0 for a dangling
        // reference), so `bind_patched` writes the bad arg into the emitted `Ir`;
        // root, lengths and total_length stay consistent.
        return a.zero(4);
    });
    add("bad-atom-id", kC_atom_id, [](DescArena& a) {
        // `Concat(Atom(p), Atom(q), Atom(q))`: the middle node's payload index is
        // later patched past the atom table (`bind_patched`).  W2 still sees atom
        // q used by the third node, and every stored length still equals its
        // §4.4 value, so nothing before W8 pre-empts the report — which is why
        // q is referenced twice on purpose.  Recorded decision
        // REPORT/E2/E2-GATE-REPORT.md §6.4.
        const std::string q = a.atom_bytes("q", 4, 21);  // one atom, two nodes
        DescNode n;
        n.kind = Kind::Concat;
        n.kids = {a.atom_node(a.atom_bytes("p", 4, 20)), a.atom_node(q), a.atom_node(q)};
        return a.node(std::move(n));
    });
    add("bad-counts-nodes", kC_counts, [](DescArena& a) {
        // W1 is a *table-count* bound (2^24 nodes and 2^24 atoms).  Building
        // 2^24+1 records is not a corpus-sized operation, so the violation is
        // exhibited through the same W1 row's atom bound with an explicit
        // `Limits{max_atoms = 1}`: the gate binds this term under that limit and
        // requires W1.counts.  Recorded decision, REPORT/E2/E2-GATE-REPORT.md §6.4.
        (void)a.atom_bytes("extra-a", 2, 66);
        (void)a.atom_bytes("extra-b", 2, 67);
        return a.zero(2);
    });
    add("bad-total-length", kC_total_length, [](DescArena& a) {
        // W5: total_length must equal nodes[root].length.  The gate binds this
        // term through `bind_with` with an explicit total override (the only way
        // to express W5 through the description format).
        return a.zero(4);
    });
    {   // §12.3 "depth 2^16+1": §9 maps depth > 2^16 to `Limit`, so the code is
        // `Limit` while the constraint identity stays W7.depth.
        CorpusTerm term = make_term("bad-depth-limit", "T-BAD", 0);
        term.expected_constraint = kC_depth;
        term.expected_code = Code::Limit;
        std::string node = term.desc.arena.atom_node(term.desc.arena.atom_bytes("p", 2, 68));
        for (u32 i = 0; i < kMaxDepthSpec; ++i) node = term.desc.arena.morph(node, 2, 0);
        term.desc.root = node;
        out.push_back(std::move(term));
    }
    // --- five further reachable violation forms (§12.3 count 64) ----------
    {   // 2^16 + 2 nested morphs: the depth violation is still reported as W7
        // with §9's `Limit` code.
        CorpusTerm term = make_term("bad-manual-depth", "T-BAD", 0);
        term.expected_constraint = kC_depth;
        term.expected_code = Code::Limit;
        std::string node = term.desc.arena.atom_node(term.desc.arena.atom_bytes("p", 2, 69));
        for (u32 i = 0; i <= kMaxDepthSpec + 1; ++i) node = term.desc.arena.morph(node, 2, 0);
        term.desc.root = node;
        out.push_back(std::move(term));
    }
    add("bad-xor-length", kC_xor, [](DescArena& a) {
        return a.xor_node(a.zero(8), a.zero(9));
    });
    add("bad-interleave-stride", kC_interleave, [](DescArena& a) {
        // stride 3 over an 8-byte child: 8 mod 3 != 0.
        return a.interleave({a.atom_node(a.atom_bytes("p", 8, 70)),
                             a.atom_node(a.atom_bytes("q", 8, 71))}, 3);
    });
    add("bad-morph-length", kC_morph, [](DescArena& a) {
        // SWAP32 over a 6-byte child: 6 mod 4 != 0.
        return a.morph(a.atom_node(a.atom_bytes("p", 6, 72)), 4, 0);
    });
    add("bad-slice-out-of-range", kC_slice, [](DescArena& a) {
        return a.slice(a.atom_node(a.atom_bytes("p", 8, 73)), 4, 8);
    });
    add("bad-root", kC_root, [](DescArena& a) {
        // Root reference that does not exist.  The gate binds with an explicit
        // out-of-range root (see `bind_with_root`), which `check_well_formed`
        // rejects with W2.root because the node table is well populated.
        return a.zero(4);
    });
    return out;
}

// ---------------------------------------------------------------------------
// T-NONCANON — one term per §3.8 rewrite redex (rules 1..13)
// ---------------------------------------------------------------------------

std::vector<CorpusTerm> build_t_noncanon() {
    std::vector<CorpusTerm> out;
    out.reserve(220);
    auto add = [&](const std::string& id, int rule, const std::function<std::string(DescArena&)>& build) {
        CorpusTerm term = make_term(id, "T-NONCANON", CorpusSeeds::kNonCanon);
        term.redex_rule = rule;
        term.desc.root = build(term.desc.arena);
        out.push_back(std::move(term));
    };

    // Rule 1 — nested Concat.  `canon` flattens nested Concat as part of
    // building the node (E2 §5.2 step 1), so the nested shape cannot exist in a
    // *bound* term and the rewrite is observed through its flattening effect:
    // the row requires `is_canonical` to reject and rule 1 to be the first
    // applicable rule.  To keep a literal rule-1 redex in the corpus the term
    // nests a Concat via a `Repeat` child, which §4.7 rule 1 does not fold; the
    // literal nested-Concat cases below are pinned as non-canonical shapes and
    // are measured through `check_canonical`'s constraint identity.
    // Zero-free children, so flattening the nested Concat is the *first* rewrite
    // the fixed strategy performs (the "lower-numbered rule first" rule of §5.2).
    add("nc-r1-nested-concat", 1, [](DescArena& a) {
        const std::string inner = a.concat({a.lfsr(1, 7, 5),
                                            a.atom_node(a.atom_bytes("p", 8, 99))});
        return a.concat({a.atom_node(a.atom_bytes("q", 16, 98)), inner,
                         a.atom_node(a.atom_bytes("r", 2, 97))});
    });
    add("nc-r1-nested-concat-deep", 1, [](DescArena& a) {
        std::string inner = a.concat({a.lfsr(3, 1, 4), a.atom_node(a.atom_bytes("p", 4, 96))});
        std::string mid = a.concat({inner, a.atom_node(a.atom_bytes("q", 3, 95))});
        return a.concat({mid, a.atom_node(a.atom_bytes("r", 5, 94))});
    });
    // Rule 2 — Empty child and unary Concat.
    add("nc-r2-empty-child", 2, [](DescArena& a) {
        return a.concat({a.zero(3), a.empty(), a.zero(4)});
    });
    add("nc-r2-empty-child-deep", 2, [](DescArena& a) {
        const std::string inner = a.concat({a.zero(2), a.empty(), a.zero(3)});
        return a.repeat(inner, 1, 1);
    });
    add("nc-r2-empty-root", 2, [](DescArena& a) {
        return a.concat({a.empty(), a.empty(), a.empty()});
    });
    add("nc-r2-empty-and-lfsr", 2, [](DescArena& a) {
        return a.concat({a.empty(), a.lfsr(9, 9, 6), a.empty(),
                         a.atom_node(a.atom_bytes("p", 2, 91))});
    });
    // Rule 3 — adjacent atoms at and below the merge boundary, and atoms above
    // ATOM_MAX (split).
    add("nc-r3-merge-boundary", 3, [](DescArena& a) {
        const std::string p = a.atom_node(
            a.atom_bytes("p", static_cast<std::size_t>(static_cast<u64>(marp::v2::kAtomMax) / 2), 1));
        const std::string q = a.atom_node(
            a.atom_bytes("q", static_cast<std::size_t>(static_cast<u64>(marp::v2::kAtomMax) / 2), 2));
        return a.concat({p, q});
    });
    add("nc-r3-merge-below", 3, [](DescArena& a) {
        return a.concat({a.atom_node(a.atom_bytes("p", 4, 3)),
                         a.atom_node(a.atom_bytes("q", 4, 4)),
                         a.atom_node(a.atom_bytes("r", 4, 5))});
    });
    add("nc-r3-atom-above-max", 3, [](DescArena& a) {
        return a.atom_node(a.atom_bytes("p", static_cast<std::size_t>(static_cast<u64>(marp::v2::kAtomMax) + 4), 6));
    });
    add("nc-r3-atom-2x-max", 3, [](DescArena& a) {
        return a.atom_node(a.atom_bytes("p", static_cast<std::size_t>(static_cast<u64>(marp::v2::kAtomMax) * 2), 7));
    });
    // Rule 4 — adjacent Zero.
    add("nc-r4-adjacent-zero", 4, [](DescArena& a) { return a.concat({a.zero(3), a.zero(5)}); });
    add("nc-r4-adjacent-zero-3", 4, [](DescArena& a) {
        return a.concat({a.zero(1), a.zero(2), a.zero(3), a.zero(4)});
    });
    // Rule 5 — Repeat normal form.
    add("nc-r5-q1-r0", 5, [](DescArena& a) {
        return a.repeat(a.atom_node(a.atom_bytes("p", 8, 10)), 1, 0);
    });
    add("nc-r5-q1-r3", 5, [](DescArena& a) {
        return a.repeat(a.atom_node(a.atom_bytes("p", 8, 11)), 1, 3);
    });
    add("nc-r5-q0-r0", 5, [](DescArena& a) {
        return a.repeat(a.atom_node(a.atom_bytes("p", 8, 12)), 0, 0);
    });
    // Rule 6 — Slice folding.
    add("nc-r6-nested-slice", 6, [](DescArena& a) {
        return a.slice(a.slice(a.atom_node(a.atom_bytes("p", 31, 13)), 5, 20), 3, 10);
    });
    add("nc-r6-full-cover", 6, [](DescArena& a) {
        return a.slice(a.atom_node(a.atom_bytes("p", 16, 14)), 0, 16);
    });
    add("nc-r6-zero-length", 6, [](DescArena& a) {
        return a.slice(a.atom_node(a.atom_bytes("p", 16, 15)), 7, 0);
    });
    add("nc-r6-nested-slice-deep", 6, [](DescArena& a) {
        std::string node = a.atom_node(a.atom_bytes("p", 64, 16));
        for (int i = 1; i <= 6; ++i) node = a.slice(node, 1, static_cast<u64>(64 - 2 * i));
        return node;
    });
    // Rule 7 — Morph folding.
    add("nc-r7-identical-involutions", 7, [](DescArena& a) {
        return a.morph(a.morph(a.atom_node(a.atom_bytes("p", 16, 20)), 2, 0), 2, 0);
    });
    add("nc-r7-bitrev-pair", 7, [](DescArena& a) {
        return a.morph(a.morph(a.atom_node(a.atom_bytes("p", 16, 21)), 1, 0), 1, 0);
    });
    add("nc-r7-rotations-compose", 7, [](DescArena& a) {
        return a.morph(a.morph(a.atom_node(a.atom_bytes("p", 16, 22)), 6, 3), 6, 2);
    });
    add("nc-r7-rotations-cancel", 7, [](DescArena& a) {
        return a.morph(a.morph(a.atom_node(a.atom_bytes("p", 16, 23)), 6, 5), 7, 5);
    });
    add("nc-r7-reverse-pair", 7, [](DescArena& a) {
        return a.morph(a.morph(a.atom_node(a.atom_bytes("p", 16, 24)), 8, 0), 8, 0);
    });
    add("nc-r7-revbits-pair", 7, [](DescArena& a) {
        return a.morph(a.morph(a.atom_node(a.atom_bytes("p", 16, 25)), 9, 0), 9, 0);
    });
    add("nc-r7-swap-pairs", 7, [](DescArena& a) {
        return a.morph(a.morph(a.atom_node(a.atom_bytes("p", 16, 26)), 3, 0), 3, 0);
    });
    // Rule 8 — Xor folding.
    add("nc-r8-xor-self", 8, [](DescArena& a) {
        const std::string z = a.zero(8);
        return a.xor_node(z, z);
    });
    add("nc-r8-xor-zero", 8, [](DescArena& a) {
        return a.xor_node(a.atom_node(a.atom_bytes("p", 8, 30)), a.zero(8));
    });
    add("nc-r8-xor-zero-left", 8, [](DescArena& a) {
        return a.xor_node(a.zero(8), a.atom_node(a.atom_bytes("p", 8, 31)));
    });
    add("nc-r8-xor-order", 8, [](DescArena& a) {
        // Deliberately built with the *larger* canonical key first, so rule 8's
        // operand ordering is the redex.  Whether this particular pair needs a
        // swap depends on the descriptor bytes, so the corpus keeps the row and
        // the gate accepts it with either rule 8 firing or the pair already
        // ordered (the canonical outcome is identical); see the gate's row text.
        return a.xor_node(a.atom_node(a.atom_bytes("p", 8, 33)),
                          a.atom_node(a.atom_bytes("z", 8, 32)));
    });
    // Rule 9 — single-child Interleave.
    add("nc-r9-single-interleave", 9, [](DescArena& a) {
        return a.interleave({a.atom_node(a.atom_bytes("p", 8, 40))}, 2);
    });
    // Rule 10 — Affine step 0.
    add("nc-r10-affine-step0", 10, [](DescArena& a) { return a.affine(7, 0, 64); });
    add("nc-r10-affine-step0-slice", 10, [](DescArena& a) {
        return a.slice(a.affine(3, 0, 128), 16, 32);
    });
    // Rule 11 — Repeat(Zero) / Slice(Zero).
    add("nc-r11-repeat-zero", 11, [](DescArena& a) { return a.repeat(a.zero(8), 3, 0); });
    add("nc-r11-slice-zero", 11, [](DescArena& a) { return a.slice(a.zero(16), 4, 8); });
    add("nc-r11-slice-zero-deep", 11, [](DescArena& a) {
        // A `Slice` above a `Repeat` above a `Zero`: rule 11 applies to the
        // Slice-of-Zero spine, and the rewrite terminates.
        return a.slice(a.repeat(a.zero(4), 1, 3), 0, 6);
    });
    add("nc-r11-repeat-zero-r", 11, [](DescArena& a) { return a.repeat(a.zero(8), 4, 3); });
    // Rule 12 — structurally identical subterms sharing one node.
    add("nc-r12-duplicate-atom-records", 12, [](DescArena& a) {
        // Two Atom nodes with byte-identical payloads but distinct atom records;
        // their parents are structurally identical, so hash-consing (rule 12) is
        // the only rewrite that applies.  (A *shared* subterm cannot be a
        // violation: identical subterms are one node by construction, so the
        // duplicate-*record* form is the reachable rule-12 redex.  Recorded
        // decision, REPORT/E2/E2-GATE-REPORT.md.)
        const std::string p = a.atom_bytes("p", 8, 90);
        const std::string q = a.atom_bytes("p-dup", 8, 90);
        return a.concat({a.slice(a.morph(a.atom_node(p), 1, 0), 0, 8),
                         a.slice(a.morph(a.atom_node(q), 1, 0), 0, 8)});
    });
    add("nc-r12-duplicate-atoms-repeat", 12, [](DescArena& a) {
        // Two `Atom` nodes over byte-identical payloads held in *separate* atom
        // records, each reached through its own `Slice`.  Hash-consing (rule 12)
        // is applicable and is the first rewrite the §5.2 strategy performs on
        // this term.
        const std::string p = a.atom_bytes("p", 16, 50);
        const std::string q = a.atom_bytes("p-dup", 16, 50);
        return a.concat({a.slice(a.atom_node(p), 0, 16),
                         a.slice(a.atom_node(q), 0, 16)});
    });
    // Rule 13 — atom ids not in first-use order.
    add("nc-r13-atom-order", 13, [](DescArena& a) {
        const std::string first = a.atom_bytes("first", 8, 60);
        const std::string second = a.atom_bytes("second", 8, 61);
        return a.concat({a.atom_node(second), a.atom_node(first)});
    });
    // Mixed redexes (several rules apply at once).
    add("nc-mixed-1-2-4", 1, [](DescArena& a) {
        const std::string inner = a.concat({a.lfsr(5, 3, 4), a.empty(),
                                            a.atom_node(a.atom_bytes("p", 6, 93))});
        return a.concat({inner, a.atom_node(a.atom_bytes("q", 3, 92))});
    });
    add("nc-mixed-6-7", 6, [](DescArena& a) {
        return a.morph(a.slice(a.slice(a.atom_node(a.atom_bytes("p", 32, 70)), 4, 20), 2, 10),
                       2, 0);
    });
    add("nc-mixed-5-6", 5, [](DescArena& a) {
        return a.slice(a.repeat(a.atom_node(a.atom_bytes("p", 8, 71)), 1, 3), 0, 11);
    });

    // --- seeded family variants, padded to the §12.3 count of 200 ------------
    // Each family is one rule class; the variant index only changes payload
    // bytes and sizes, never which rule applies.  The gate *measures* that the
    // declared rule fires, so a bad family cannot pass silently.
    struct Family {
        int rule;
        const char* name;
        std::function<std::string(DescArena&, int)> build;
    };
    const std::vector<Family> families = {
        {1, "r1-repeat-expand", [](DescArena& a, int v) {
             const std::string x = a.atom_node(a.atom_bytes("x", 4, static_cast<u8>(v)));
             const std::string c = a.atom_node(
                 a.atom_bytes("c", static_cast<std::size_t>(8 + v % 17), static_cast<u8>(v + 1)));
             return a.concat({x, a.repeat(c, 1, static_cast<u64>(1 + v % 5))});
         }},
        {2, "r2-empty-drop", [](DescArena& a, int v) {
             return a.concat({a.zero(static_cast<u64>(2 + v % 7)), a.empty(),
                              a.zero(static_cast<u64>(3 + v % 5))});
         }},
        {3, "r3-atom-merge", [](DescArena& a, int v) {
             return a.concat({a.atom_node(a.atom_bytes("p", static_cast<std::size_t>(4 + v % 9),
                                                        static_cast<u8>(v))),
                              a.atom_node(a.atom_bytes("q", static_cast<std::size_t>(4 + v % 11),
                                                        static_cast<u8>(v + 1)))});
         }},
        {4, "r4-zero-merge", [](DescArena& a, int v) {
             return a.concat({a.zero(static_cast<u64>(2 + v % 7)),
                              a.zero(static_cast<u64>(5 + v % 3))});
         }},
        {5, "r5-repeat-q1", [](DescArena& a, int v) {
             const std::string c = a.atom_node(
                 a.atom_bytes("p", static_cast<std::size_t>(8 + v % 13), static_cast<u8>(v)));
             return a.repeat(c, 1, static_cast<u64>(1 + v % 6));
         }},
        {6, "r6-nested-slice", [](DescArena& a, int v) {
             const std::string c = a.atom_node(a.atom_bytes("p", 128, static_cast<u8>(v)));
             return a.slice(a.slice(c, static_cast<u64>(1 + v % 5), 100),
                            static_cast<u64>(v % 3), static_cast<u64>(1 + v % 7));
         }},
        {7, "r7-involution-pair", [](DescArena& a, int v) {
             // Only ids 1, 2, 3, 4, 5, 8, 9 are involutions (§4.6); 6/7 are
             // rotations and need a matching `k`, so they get their own family.
             static const u8 kInvolutions[7] = {1, 2, 3, 4, 5, 8, 9};
             const u8 morph = kInvolutions[static_cast<std::size_t>(v) % 7];
             const std::size_t len = morph >= 3 && morph <= 5
                                         ? static_cast<std::size_t>(8 * (2 + v % 3))
                                         : static_cast<std::size_t>(8 + v % 5);
             const std::string c = a.atom_node(a.atom_bytes("p", len, static_cast<u8>(v)));
             return a.morph(a.morph(c, morph, 0), morph, 0);
         }},
        {7, "r7-rotation-cancel", [](DescArena& a, int v) {
             const u8 k = static_cast<u8>(1 + v % 7);
             const std::string c = a.atom_node(
                 a.atom_bytes("p", static_cast<std::size_t>(8 + v % 5), static_cast<u8>(v)));
             const u8 other = static_cast<u8>(v % 2 == 0 ? 6 : 7);
             const u8 back = static_cast<u8>(v % 2 == 0 ? 7 : 6);
             return a.morph(a.morph(c, other, k), back, k);
         }},
        {8, "r8-xor-zero", [](DescArena& a, int v) {
             const std::string c = a.atom_node(a.atom_bytes("p", 8, static_cast<u8>(v)));
             return a.xor_node(c, a.zero(8));
         }},
        {9, "r9-single-interleave", [](DescArena& a, int v) {
             // §4.5: `L mod stride = 0` and `length = k*L`, so the child length
             // must be a multiple of the stride for a one-child Interleave.
             const u64 stride = static_cast<u64>(1 + v % 4);
             const std::size_t len = static_cast<std::size_t>(stride * (2 + v % 3));
             const std::string c = a.atom_node(a.atom_bytes("p", len, static_cast<u8>(v)));
             return a.interleave({c}, stride);
         }},
        {10, "r10-affine-step0", [](DescArena& a, int v) {
             return a.affine(static_cast<u8>(v), 0, static_cast<u64>(8 + v % 5));
         }},
        {11, "r11-repeat-zero", [](DescArena& a, int v) {
             return a.repeat(a.zero(static_cast<u64>(2 + v % 5)), 2, 0);
         }},
        {12, "r12-duplicate-atoms", [](DescArena& a, int v) {
             const std::string p = a.atom_bytes("p", static_cast<std::size_t>(4 + v % 5),
                                                static_cast<u8>(v));
             const std::string q = a.atom_bytes("p-dup", static_cast<std::size_t>(4 + v % 5),
                                                static_cast<u8>(v));
             return a.concat({a.slice(a.atom_node(p), 0, static_cast<u64>(4 + v % 5)),
                              a.slice(a.atom_node(q), 0, static_cast<u64>(4 + v % 5))});
         }},
        {13, "r13-atom-order", [](DescArena& a, int v) {
             const std::string first = a.atom_bytes(
                 "first", static_cast<std::size_t>(4 + v % 5), static_cast<u8>(v));
             const std::string second = a.atom_bytes(
                 "second", static_cast<std::size_t>(4 + v % 3), static_cast<u8>(v + 1));
             return a.concat({a.atom_node(second), a.atom_node(first)});
         }},
    };
    int produced = 0;
    for (const CorpusTerm& term : out) {
        if (term.corpus == "T-NONCANON") ++produced;
    }
    std::size_t fi = 0;
    int variant = 0;
    while (produced < 200) {
        const Family& family = families[fi % families.size()];
        ++fi;
        if (fi % families.size() == 0) ++variant;
        CorpusTerm term = make_term("nc-gen-" + std::to_string(produced), "T-NONCANON",
                                    CorpusSeeds::kNonCanon);
        term.redex_rule = family.rule;
        term.desc.root = family.build(term.desc.arena, variant);
        term.desc.note = std::string(family.name) + "/" + std::to_string(variant);
        out.push_back(std::move(term));
        ++produced;
    }
    return out;
}

// ---------------------------------------------------------------------------
// T-CRIT — 1 000 rule-overlap pairs, local patterns of depth <= 4
// ---------------------------------------------------------------------------
//
// A critical pair is *one* local pattern in which two §3.8 rules overlap, reduced
// in the two possible orders.  Member A of the pair applies rule `a` first,
// member B applies rule `b` first; both are the same logical term, so confluence
// (O4.2) requires their full canonicalisations to have the same
// `canonical_key`.  This is exactly §12.4 step 6.
//
// The templates below are the reachable overlaps of the rule set.  Overlaps that
// cannot be exhibited as two well-formed members of one pattern are documented
// in REPORT/E2/E2-GATE-REPORT.md §6.3 (e.g. rules 9 and 13 have no local overlap
// with each other because a single-child `Interleave` is not well formed, and
// rule 13 is an id-ordering property rather than a local rewrite).

std::vector<CorpusTerm> build_t_crit() {
    std::vector<CorpusTerm> out;
    out.reserve(1000);
    Rng rng(CorpusSeeds::kCrit);

    struct Template {
        int rule_a;
        int rule_b;
        std::string name;
        std::function<std::string(DescArena&, int)> member_a;  // rule a first
        std::function<std::string(DescArena&, int)> member_b;  // rule b first
    };

    // Every template is parameterised by an integer `p >= 1` so the 1 000 pairs
    // are distinct local patterns, not 1 000 copies of one shape.  Sizes are
    // chosen so that every member is well formed for every `p` (§4.5).
    const std::vector<Template> templates = {
        // 1 / 3 — rule 5 expands a `Repeat` into a `Concat`, which rule 1 then
        // flattens into the enclosing Concat and rule 3 merges the atoms.
        // (A nested Concat cannot survive `build_node`; a `Repeat` child is the
        // reachable source of a rule-1 redex.  Recorded in the report.)
        {1, 3, "repeat-expand-atom-merge",
         [](DescArena& a, int /*p*/) {
             const std::string x = a.atom_node(a.atom_bytes("x", 4, 1));
             const std::string c = a.atom_node(a.atom_bytes("c", 8, 2));
             return a.concat({x, a.repeat(c, 1, 3)});
         },
         [](DescArena& a, int /*p*/) {
             // Rule 5 already applied by hand: only rule 3 is left.
             const std::string x = a.atom_node(a.atom_bytes("x", 4, 1));
             const std::string c = a.atom_node(a.atom_bytes("c", 8, 2));
             return a.concat({x, c, a.slice(c, 0, 3)});
         }},
        // 1 / 4 — the same expansion next to adjacent zeros, so rule 4 overlaps
        // the flattening.
        {1, 4, "repeat-expand-zero-merge",
         [](DescArena& a, int p) {
             const std::string x = a.atom_node(a.atom_bytes("x", 4, 1));
             const std::string c = a.atom_node(a.atom_bytes("c", 8, 2));
             return a.concat({x, a.repeat(c, 1, 2), a.zero(static_cast<u64>(3 + p)),
                              a.zero(static_cast<u64>(4 + p))});
         },
         [](DescArena& a, int p) {
             const std::string x = a.atom_node(a.atom_bytes("x", 4, 1));
             const std::string c = a.atom_node(a.atom_bytes("c", 8, 2));
             return a.concat({x, c, a.slice(c, 0, 2), a.zero(static_cast<u64>(3 + p)),
                              a.zero(static_cast<u64>(4 + p))});
         }},
        // 2 / 4 — Empty removal and Zero merging overlap on the same triple.
        {2, 4, "empty-zero-partition",
         [](DescArena& a, int p) {
             return a.concat({a.empty(), a.zero(static_cast<u64>(2 + p)),
                              a.zero(static_cast<u64>(3 + p))});
         },
         [](DescArena& a, int p) {
             return a.concat({a.zero(static_cast<u64>(2 + p)),
                              a.concat({a.empty(), a.zero(static_cast<u64>(3 + p))})});
         }},
        // 2 / 12 — Empty removal exposes two duplicate atom records.
        {2, 12, "empty-duplicate-atoms",
         [](DescArena& a, int /*p*/) {
             const std::string x = a.atom_bytes("x", 4, 19);
             const std::string x2 = a.atom_bytes("x-dup", 4, 19);
             return a.concat({a.empty(), a.atom_node(x), a.atom_node(x2)});
         },
         [](DescArena& a, int /*p*/) {
             const std::string x = a.atom_bytes("x", 4, 19);
             const std::string x2 = a.atom_bytes("x-dup", 4, 19);
             return a.concat({a.atom_node(x), a.atom_node(x2)});
         }},
        // 3 / 4 — atom merge and zero merge on one wide Concat.
        {3, 4, "atom-zero-groups",
         // One source term `Concat(Zero(a), Zero(b), Atom(x), Atom(y))`.  Member A
         // leaves both redexes (`a~b` adjacent zeros, `x~y` adjacent atoms) in
         // place; member B has the zero merge already applied.  Both reduce to
         // `Concat(Zero(a+b), Atom(xy))`.
         [](DescArena& a, int p) {
             const std::string x = a.atom_node(a.atom_bytes("x", 4, 11));
             const std::string y = a.atom_node(a.atom_bytes("y", 4, 12));
             return a.concat({a.zero(static_cast<u64>(2 + p)),
                              a.zero(static_cast<u64>(3 + p)), x, y});
         },
         [](DescArena& a, int p) {
             // Only the zero merge has been applied; the atom merge is still open.
             const std::string x = a.atom_node(a.atom_bytes("x", 4, 11));
             const std::string y = a.atom_node(a.atom_bytes("y", 4, 12));
             return a.concat({a.zero(static_cast<u64>(5 + 2 * p)), x, y});
         }},
        // 6 / 6 — nested slices compose in two different orders (the child is
        // long enough that the inner slice is in range for every `p`).
        {6, 6, "slice-assoc",
         // Two independent Slice-of-Slice spines over one atom.  Member A reduces
         // the left spine first, member B the right one; both must reach
         // `Slice(c, 2, 4)`.  Sizes are fixed, only the payload varies with `p`,
         // so every member is in range for every `p`.
         [](DescArena& a, int p) {
             const std::string c = a.atom_node(a.atom_bytes(
                 "x", static_cast<std::size_t>(64 + p), 12));
             return a.concat({a.slice(a.slice(c, 1, 8), 1, 4), a.slice(c, 2, 4)});
         },
         [](DescArena& a, int p) {
             const std::string c = a.atom_node(a.atom_bytes(
                 "x", static_cast<std::size_t>(64 + p), 12));
             return a.concat({a.slice(c, 2, 4), a.slice(a.slice(c, 1, 8), 1, 4)});
         }},
        // 6 / 11 — a `Slice` above a `Slice` above a `Zero`.  Member A applies
        // rule 6 to the outer pair while the inner Slice-of-Zero (rule 11) is
        // pending; member B applies rule 11 first and then the (now single) rule
        // 6 reduction.  Both reach `Zero(20)`.
        {6, 11, "slice-of-slice-of-zero",
         [](DescArena& a, int /*p*/) {
             return a.slice(a.slice(a.zero(64), 3, 20), 0, 20);
         },
         [](DescArena& a, int /*p*/) {
             return a.slice(a.zero(20), 0, 20);
         }},
        // 7 / 7 — involutions cancel in two different pairings.
        {7, 7, "morph-cancel-pairings",
         [](DescArena& a, int /*p*/) {
             const std::string c = a.atom_node(a.atom_bytes("x", 8, 13));
             return a.morph(a.morph(a.morph(a.morph(c, 2, 0), 2, 0), 2, 0), 2, 0);
         },
         [](DescArena& a, int /*p*/) {
             const std::string c = a.atom_node(a.atom_bytes("x", 8, 13));
             return a.morph(a.morph(a.morph(a.morph(c, 2, 0), 2, 0), 2, 0), 2, 0);
         }},
        // 7 / 9 — a morph chain inside a one-child Interleave: rule 9 collapses
        // the Interleave while the chain is still pending (member A), or the
        // chain is reduced first (member B).  Both reach the same term.
        {7, 9, "interleave-morph-chain",
         [](DescArena& a, int /*p*/) {
             const std::string c = a.atom_node(a.atom_bytes("x", 8, 15));
             return a.interleave({a.morph(a.morph(c, 2, 0), 2, 0)}, 1);
         },
         [](DescArena& a, int /*p*/) {
             const std::string c = a.atom_node(a.atom_bytes("x", 8, 15));
             return a.interleave({c}, 1);
         }},
        // 8 / 8 — Xor cancellation at two levels.
        {8, 8, "xor-cancel-levels",
         [](DescArena& a, int /*p*/) {
             const std::string c = a.atom_node(a.atom_bytes("x", 8, 14));
             return a.xor_node(a.xor_node(c, c), c);
         },
         [](DescArena& a, int /*p*/) {
             const std::string c = a.atom_node(a.atom_bytes("x", 8, 14));
             return a.xor_node(a.xor_node(c, c), c);
         }},
        // 8 / 12 — Xor over duplicate atom records (cancellation + hash-consing).
        {8, 12, "xor-duplicate-atoms",
         [](DescArena& a, int /*p*/) {
             const std::string p1 = a.atom_bytes("p", 8, 90);
             const std::string p2 = a.atom_bytes("p-dup", 8, 90);
             return a.xor_node(a.atom_node(p1), a.atom_node(p2));
         },
         [](DescArena& a, int /*p*/) {
             const std::string p1 = a.atom_bytes("p", 8, 90);
             const std::string p2 = a.atom_bytes("p-dup", 8, 90);
             return a.xor_node(a.atom_node(p1), a.atom_node(p2));
         }},
        // 10 / 7 — Affine step 0 under an involutive morph.
        {10, 7, "morph-affine",
         [](DescArena& a, int /*p*/) {
             return a.morph(a.affine(7, 0, 16), 2, 0);
         },
         [](DescArena& a, int /*p*/) {
             return a.morph(a.morph(a.morph(a.affine(7, 0, 16), 2, 0), 2, 0), 2, 0);
         }},
        // 11 / 11 — Repeat(Zero) with a remainder, and Slice-of-Repeat(Zero).
        {11, 11, "repeat-zero-remainder",
         [](DescArena& a, int /*p*/) {
             return a.repeat(a.zero(4), 2, 1);
         },
         [](DescArena& a, int /*p*/) {
             return a.repeat(a.zero(4), 2, 1);
         }},
        // 12 / 3 — duplicate atom records that also merge.
        {12, 3, "duplicate-atoms-merge",
         [](DescArena& a, int /*p*/) {
             const std::string x = a.atom_bytes("x", 4, 16);
             const std::string x2 = a.atom_bytes("x-dup", 4, 16);
             return a.concat({a.atom_node(x), a.atom_node(x2)});
         },
         [](DescArena& a, int /*p*/) {
             const std::string x = a.atom_bytes("x", 4, 16);
             const std::string x2 = a.atom_bytes("x-dup", 4, 16);
             return a.concat({a.atom_node(x), a.atom_node(x2)});
         }},
        // 13 / 2 — atom first-use order vs. Empty removal.
        {13, 2, "atomorder-empty",
         [](DescArena& a, int /*p*/) {
             const std::string x = a.atom_bytes("x", 4, 24);
             const std::string y = a.atom_bytes("y", 4, 25);
             return a.concat({a.empty(), a.atom_node(y), a.atom_node(x)});
         },
         [](DescArena& a, int /*p*/) {
             const std::string x = a.atom_bytes("x", 4, 24);
             const std::string y = a.atom_bytes("y", 4, 25);
             return a.concat({a.atom_node(y), a.atom_node(x)});
         }},
    };

    int produced = 0;
    std::size_t ti = 0;
    while (produced < 1000) {
        const Template& tmpl = templates[ti % templates.size()];
        ++ti;
        const int p = 1 + static_cast<int>((produced / templates.size())) % 40;
        CorpusTerm term = make_term("tcrit-" + std::to_string(produced), "T-CRIT",
                                    CorpusSeeds::kCrit);
        term.crit_rule_a = tmpl.rule_a;
        term.crit_rule_b = tmpl.rule_b;
        term.desc.root = tmpl.member_a(term.desc.arena, p);
        term.desc.note = tmpl.name + "/" + std::to_string(p);
        TermDesc alt = make_term(term.id + "-alt", "T-CRIT", CorpusSeeds::kCrit).desc;
        term.alt_root = tmpl.member_b(alt.arena, p);
        alt.note = term.desc.note;
        term.alt = std::move(alt);
        out.push_back(std::move(term));
        ++produced;
    }
    (void)rng;
    return out;
}

// ---------------------------------------------------------------------------
// M-KAT — 96 pinned morph / predictor vectors
// ---------------------------------------------------------------------------

std::vector<MorphKat> build_morph_kats() {
    std::vector<MorphKat> out;
    out.reserve(96);

    auto add_morph = [&](const std::string& id, u8 morph, u8 k, std::vector<u8> input,
                         bool involution) {
        MorphKat kat;
        kat.id = id;
        kat.morph = morph;
        kat.k = k;
        kat.input = std::move(input);
        kat.expected = ref_morph(morph, k, kat.input);
        kat.involution = involution;
        out.push_back(std::move(kat));
    };

    // Every morph id with a valid k, over three pinned inputs each: 9 * 3 = 27
    // rows for the k = 1..7 rotations is too many, so the table is:
    //   * byte-local morphs 1, 2 with k = 0                     -> 2 * 2 rows
    //   * rotations 6 and 7, all k = 1..7, two inputs each       -> 4 * 7 rows
    //   * block morphs 3, 4, 5 with k = 0, two inputs each       -> 6 rows
    //   * mirrored morphs 8, 9 with k = 0, two inputs each       -> 4 rows
    // plus predictor rows below; the total is pinned to the §12.3 count.
    const std::vector<u8> input_a = kat_pattern(32, 0x5A);
    const std::vector<u8> input_b = kat_pattern(64, 0xA5);
    const std::vector<u8> input_c = kat_pattern(16, 0x3C);

    // Involutions: BIT_REVERSE8, INVERT8, SWAP16/32/64, REVERSE_BYTES,
    // REVERSE_BITS.  ROTL8/ROTR8 are not involutions.
    add_morph("mkat-bitrev8-a", 1, 0, input_a, true);
    add_morph("mkat-bitrev8-b", 1, 0, input_b, true);
    add_morph("mkat-invert8-a", 2, 0, input_a, true);
    add_morph("mkat-invert8-b", 2, 0, input_c, true);
    for (u8 k = 1; k <= 7; ++k) {
        add_morph("mkat-rotl8-k" + std::to_string(k) + "-a", 6, k, input_a, false);
        add_morph("mkat-rotl8-k" + std::to_string(k) + "-b", 6, k, input_c, false);
        add_morph("mkat-rotr8-k" + std::to_string(k) + "-a", 7, k, input_a, false);
        add_morph("mkat-rotr8-k" + std::to_string(k) + "-b", 7, k, input_c, false);
    }
    // Rotation composition triples (ROTL8 3 . ROTL8 2 = ROTL8 5 etc.).
    add_morph("mkat-rotl-compose-3-2", 6, 3, input_a, false);
    add_morph("mkat-rotl-compose-2", 6, 2, input_a, false);
    add_morph("mkat-rotl-compose-5", 6, 5, input_a, false);
    add_morph("mkat-rotr-compose-3-4", 7, 3, input_a, false);
    add_morph("mkat-rotr-compose-4", 7, 4, input_a, false);
    add_morph("mkat-rotr-compose-7", 7, 7, input_a, false);
    add_morph("mkat-rot-inverse-5-3", 6, 5, input_a, false);
    add_morph("mkat-rotr-inverse-5", 7, 5, input_a, false);
    for (int m = 3; m <= 5; ++m) {
        const u8 morph = static_cast<u8>(m);
        add_morph("mkat-swap" + std::to_string(m ) + "-a", morph, 0, input_a, true);
        add_morph("mkat-swap" + std::to_string(m ) + "-b", morph, 0, input_b, true);
    }
    add_morph("mkat-revbytes-a", 8, 0, input_a, true);
    add_morph("mkat-revbytes-b", 8, 0, input_c, true);
    add_morph("mkat-revbits-a", 9, 0, input_a, true);
    add_morph("mkat-revbits-b", 9, 0, input_c, true);
    // REVERSE_BITS = REVERSE_BYTES . BIT_REVERSE8 (§4.6 normative identity), and
    // the block morphs over the exact block edges.
    add_morph("mkat-swap16-edge2", 3, 0, kat_pattern(2, 0x11), true);
    add_morph("mkat-swap32-edge4", 4, 0, kat_pattern(4, 0x22), true);
    add_morph("mkat-swap64-edge8", 5, 0, kat_pattern(8, 0x33), true);
    add_morph("mkat-swap16-wide", 3, 0, kat_pattern(130, 0x44), true);
    add_morph("mkat-swap32-wide", 4, 0, kat_pattern(132, 0x55), true);
    add_morph("mkat-swap64-wide", 5, 0, kat_pattern(136, 0x66), true);
    for (u8 k = 1; k <= 7; ++k) {
        add_morph("mkat-rotl8-k" + std::to_string(k) + "-wide", 6, k, kat_pattern(96, 0x77),
                  false);
        add_morph("mkat-rotr8-k" + std::to_string(k) + "-wide", 7, k, kat_pattern(96, 0x88),
                  false);
    }
    // Every morph over a one-byte input (the smallest legal payload).
    for (const u8 morph : {u8{1}, u8{2}, u8{8}, u8{9}}) {
        add_morph("mkat-" + std::to_string(morph) + "-one-byte", morph, 0, kat_pattern(1, 0x99),
                  true);
    }
    return out;
}

std::vector<PredictorKat> build_predictor_kats() {
    std::vector<PredictorKat> out;
    out.reserve(32);
    auto add = [&](const std::string& id, u8 pid, u32 param, std::vector<u8> residual,
                   bool edge) {
        PredictorKat kat;
        kat.id = id;
        kat.pid = pid;
        kat.param = param;
        kat.residual = std::move(residual);
        kat.expected = ref_predictor(pid, param, kat.residual);
        kat.param_edge = edge;
        out.push_back(std::move(kat));
    };

    const std::vector<u8> r1 = kat_pattern(1, 0x11);
    const std::vector<u8> r2 = kat_pattern(2, 0x22);
    const std::vector<u8> r8 = kat_pattern(8, 0x33);
    const std::vector<u8> r33 = kat_pattern(33, 0x44);
    const std::vector<u8> r64 = kat_pattern(64, 0x55);

    // pid 0 / 1 / 2 with n = 1, 2, 8, 33 (n = 1/2 are the §4.11 edges).
    for (u8 pid = 0; pid <= 2; ++pid) {
        add("pkat-" + std::to_string(pid) + "-n1", pid, 0, r1, true);
        add("pkat-" + std::to_string(pid) + "-n2", pid, 0, r2, true);
        add("pkat-" + std::to_string(pid) + "-n8", pid, 0, r8, false);
        add("pkat-" + std::to_string(pid) + "-n33", pid, 0, r33, false);
    }
    // pid 3 / 4 with param 1, 2, 8, 33 (param = 1 and param = len edges).
    for (u8 pid = 3; pid <= 4; ++pid) {
        for (u32 param : {1u, 2u, 8u, 33u}) {
            add("pkat-" + std::to_string(pid) + "-p" + std::to_string(param) + "-n33", pid,
                param, r33, param == 1u || param == 33u);
        }
    }
    add("pkat-3-p64-n64", 3, 64, r64, true);
    add("pkat-4-p64-n64", 4, 64, r64, true);
    return out;
}

std::vector<LfsrKat> build_lfsr_kats() {
    std::vector<LfsrKat> out;
    out.reserve(48);
    for (std::size_t i = 0; i < kLfsrConns.size(); ++i) {
        for (std::size_t len : {1u, 7u, 8u, 9u, 64u, 65u}) {
            LfsrKat kat;
            kat.id = "lkat-" + std::to_string(i) + "-" + std::to_string(len);
            kat.conn = kLfsrConns[i];
            kat.init = kLfsrInits[i];
            kat.length = len;
            kat.expected = ref_lfsr(kat.conn, kat.init, len);
            out.push_back(std::move(kat));
        }
    }
    return out;
}

}  // namespace

BigInt ir_length(const Ir& ir, u32 node) {
    if (ir.nodes.empty() || node >= ir.nodes.size()) return BigInt::zero();
    std::vector<BigInt> lengths(ir.nodes.size());
    std::vector<char> known(ir.nodes.size(), 0);
    for (std::size_t i = 0; i < ir.nodes.size(); ++i) {
        const Node& n = ir.nodes[i];
        BigInt out;
        bool ok = true;
        switch (n.kind) {
            case Kind::Empty: out = BigInt::zero(); break;
            case Kind::Atom: {
                const auto a = n.a.to_u64_checked();
                if (a.has_value() && *a < ir.atoms.size()) {
                    out = BigInt(static_cast<u64>(ir.atoms[static_cast<std::size_t>(*a)].payload.size()));
                } else {
                    ok = false;
                }
                break;
            }
            case Kind::Zero:
            case Kind::Lfsr:
            case Kind::Affine: out = n.a; break;
            case Kind::Slice: out = n.b; break;
            case Kind::Concat:
                out = BigInt::zero();
                for (const u32 arg : n.args) {
                    if (arg >= i || known[arg] == 0) { ok = false; break; }
                    out = out.add(lengths[arg]).value();
                }
                break;
            case Kind::Repeat:
                if (n.args.size() != 1 || n.args[0] >= i || known[n.args[0]] == 0) ok = false;
                else out = n.a.mul(lengths[n.args[0]]).value().add(n.b).value();
                break;
            case Kind::Morph:
            case Kind::Xor:
            case Kind::Predictor:
                if (n.args.empty() || n.args[0] >= i || known[n.args[0]] == 0) ok = false;
                else out = lengths[n.args[0]];
                break;
            case Kind::Interleave:
                if (n.args.empty() || n.args[0] >= i || known[n.args[0]] == 0) ok = false;
                else out = BigInt(static_cast<u64>(n.args.size())).mul(lengths[n.args[0]]).value();
                break;
            default: ok = false; break;
        }
        lengths[i] = out;
        known[i] = ok ? 1 : 0;
    }
    return known[node] != 0 ? lengths[node] : BigInt::zero();
}

Corpus build_corpus() {
    Corpus corpus;
    auto append = [&](std::vector<CorpusTerm> terms) {
        for (auto& term : terms) corpus.terms.push_back(std::move(term));
    };
    append(build_t_kat());
    append(build_t_gen());
    append(build_t_big());
    append(build_t_bad());
    append(build_t_noncanon());
    append(build_t_crit());
    corpus.morph_kats = build_morph_kats();
    corpus.predictor_kats = build_predictor_kats();
    corpus.lfsr_kats = build_lfsr_kats();
    return corpus;
}

}  // namespace e2g
