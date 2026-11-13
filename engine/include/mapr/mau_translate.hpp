// =====================================================================
//  MARP  ::  Stage 2  ::  MAU Translator  ::  mau_translate.hpp
//
//  MARP IR → MAU bridge Program (exact decimal BigInt parameters)
// =====================================================================

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

// Forward declarations
namespace mapr {
    struct IrProgram;
}

namespace mapr::translate {

// Spec §10 contract (exact decimal BigInt parameters, pure, never guesses)
struct Term {
    uint8_t kind = 0;
    std::vector<uint32_t> args;
    std::string a, b;      // decimal BigInt, exact
    uint64_t u = 0;
};

struct Program {
    std::vector<std::string> atoms;   // opaque literals (bytes)
    std::vector<Term> nodes;          // topological
    uint32_t root = 0;
};

// Spec-compliant entry point
Program fromIr(const mapr::IrProgram& ir);

// Internal/extended API (preserves atom bit_length for lossless round-trip)
struct MauTerm {
    uint8_t kind = 0;
    std::vector<uint32_t> args;
    std::string a, b;
    uint64_t u = 0;
};

struct MauProgram {
    struct Atom { std::string bytes; std::string bit_length; };
    struct Node {
        uint8_t kind = 0;
        std::vector<uint32_t> args;
        std::string a, b;
        uint64_t u = 0;
    };
    std::vector<Atom> atoms;
    std::vector<Node> nodes;
    uint32_t root = 0;
};

MauProgram from_ir(const mapr::IrProgram& ir);
mapr::IrProgram to_ir(const MauProgram& mau);

} // namespace mapr::translate

// Alias for spec namespace spelling
namespace marp { namespace translate = ::mapr::translate; }