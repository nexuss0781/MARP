#pragma once

#include "mapr/bitseq.hpp"
#include "mapr/common.hpp"
#include "mapr/math_core.hpp"
#include <cstdint>
#include <map>
#include <string>
#include <variant>
#include <vector>

namespace mapr {

enum class NodeOp : uint8_t {
    EMPTY = 0,
    ATOM = 1,
    ATOM_SPAN = 2,
    CONCAT = 3,
    REPEAT = 4,
    SLICE = 5,
    MORPH = 6,
    XOR_DIFF = 7,
    INTERLEAVE = 8,
    LFSR = 9,
    // v1.1 extensions (additive only)
    RAW = 10,
    DEDUP_REF = 11,
    DEFLATE_HINT = 12
};

struct EmptyNode {};
struct AtomNode { DualBasisAtom atom; };
struct AtomSpanNode { std::vector<DualBasisAtom> atoms; };
struct ConcatNode { std::vector<uint32_t> children; };
struct RepeatNode { uint32_t child; uint64_t q; uint64_t r; };
struct SliceNode { uint32_t child; uint64_t start; uint64_t length; };
struct MorphNode { uint32_t child; V4Op mu; };
struct XorDiffNode { uint32_t base; uint32_t delta; };
struct InterleaveNode { uint8_t stride; std::vector<uint32_t> lanes; };
struct LfsrNode { uint8_t degree; uint64_t conn_mask; uint64_t init_mask; uint64_t length; };
// v1.1 extensions
struct RawNode { std::vector<uint8_t> bytes; uint64_t bit_len = 0; };
struct DedupRefNode { uint64_t ref_id; };  // global dedup index reference
struct DeflateHintNode { 
    uint8_t cm;  // compression method
    uint8_t flg; // flags
    uint16_t mtime;
    uint8_t xfl;
    uint8_t os;
};

using DAGNode = std::variant<
    EmptyNode,
    AtomNode,
    AtomSpanNode,
    ConcatNode,
    RepeatNode,
    SliceNode,
    MorphNode,
    XorDiffNode,
    InterleaveNode,
    LfsrNode,
    RawNode,
    DedupRefNode,
    DeflateHintNode
>;

struct ExplicitChunkDAG {
    std::vector<DAGNode> nodes;
    uint32_t root = 0;
};

struct ValidationResult {
    bool valid = false;
    std::string error;
    std::vector<uint64_t> node_lengths;
};

ValidationResult validate_chunk_dag(const ExplicitChunkDAG& dag, uint64_t expected_bit_len);

BitSeq evaluate_chunk_dag(const ExplicitChunkDAG& dag, uint64_t expected_bit_len);

struct InspectionSummary {
    uint64_t total_bits = 0;
    uint64_t accounted_bits = 0;
    uint64_t chunk_count = 0;
    uint64_t chunk_ref_count = 0;
    uint64_t total_dag_nodes = 0;
    uint64_t total_dag_edges = 0;
    uint64_t total_micro_atoms = 0;
    uint64_t pos_atoms = 0;
    uint64_t zheg_atoms = 0;
    uint32_t max_dag_depth = 0;
    std::map<std::string, uint64_t> node_counts;
    std::map<std::string, uint64_t> mechanism_bits;

    void add_chunk_dag(const ExplicitChunkDAG& dag, uint64_t chunk_bit_len);
    void add_chunk_ref(uint64_t chunk_bit_len, V4Op mu);
};

} // namespace mapr
