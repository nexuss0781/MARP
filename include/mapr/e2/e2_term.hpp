// MARP v2 — E2 ALGEBRA — C03 TERM
//
// Term grammar, well-formedness, length, denotation, and the closed
// morphism / predictor / LFSR catalogues.
//
// Normative sources:
//   SPECS/SPECS-V2.md            §3.1–3.7, §4, §5.5, §8.2–8.3
//   SPECS/COMPONENTS/e2-algebra/SPECS.md   §4, §5.1, §5.3–5.5, §8, §9
//   SPECS/COMPONENTS-V2.md       §4 C03
//
// Scope discipline (E2 §10, C03 prompt §3.7):
//   * no wire encode/decode (E3), no canonicalisation policy (C04),
//     no discovery/selection (E4–E6), no CLI/MAU/certificate (E7);
//   * no file, path, media-type, environment, or global-state access;
//   * C++20 only, no third-party dependency; E1 `BigInt` is the only
//     arithmetic and `BigInt` is the only length type.
//
// Error model (E2 §9): every fallible operation returns `Result<T>` /
// `Status`; nothing throws past the API boundary and nothing terminates
// the process.  `Invalid` is a contract violation, `Limit` is a resource
// bound (W7 depth, §8.3 output cap, predictor prefix policy).
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "mapr/e1_bigint.hpp"
#include "mapr/e1_types.hpp"

namespace marp::v2 {

using u8 = std::uint8_t;
using u16 = std::uint16_t;
using u32 = std::uint32_t;
using u64 = std::uint64_t;

// E1 is the only arithmetic provider (E2 §4.4: "All arithmetic is E1 BigInt
// arithmetic. No u64 intermediate is permitted.").
using BigInt = mapr::BigInt;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

enum class Code : u8 {
    Ok = 0,
    Invalid = 1,  // contract violation; exact, never approximated
    Limit = 2,    // resource bound (§8.3, W7, predictor prefix policy)
};

const char* code_name(Code code) noexcept;

// `Result<T>` == T | Code.  `Result<void>` is a plain status.
template <typename T>
class Result {
public:
    Result(const T& value) noexcept : value_(value), code_(Code::Ok), has_value_(true) {}   // NOLINT
    Result(T&& value) noexcept : value_(std::move(value)), code_(Code::Ok), has_value_(true) {}  // NOLINT
    Result(Code code) noexcept : value_(), code_(code), has_value_(false) {}                 // NOLINT

    bool ok() const noexcept { return has_value_; }
    Code code() const noexcept { return code_; }
    const T& value() const& noexcept { return value_; }
    T& value() & noexcept { return value_; }
    T&& value() && noexcept { return std::move(value_); }

private:
    T value_{};
    Code code_ = Code::Invalid;
    bool has_value_ = false;
};

template <>
class Result<void> {
public:
    Result() noexcept : code_(Code::Ok) {}
    Result(Code code) noexcept : code_(code) {}  // NOLINT

    bool ok() const noexcept { return code_ == Code::Ok; }
    Code code() const noexcept { return code_; }

private:
    Code code_;
};

using Status = Result<void>;

// ---------------------------------------------------------------------------
// IR (E2 §4.2 / parent §4)
// ---------------------------------------------------------------------------

enum class Kind : u8 {
    Empty = 0,
    Atom = 1,
    Zero = 2,
    Concat = 3,
    Repeat = 4,
    Slice = 5,
    Morph = 6,
    Xor = 7,
    Interleave = 8,
    Lfsr = 9,
    Affine = 10,
    Predictor = 11,
};

constexpr u32 kKindCount = 12u;
constexpr u64 kAtomMax = 1'048'576ull;  // 1 MiB, format constant (E2 §4.7)
constexpr u32 kMaxDepthSpec = 1u << 16; // W7
constexpr u32 kMaxRecordsSpec = 1u << 24;  // W1

const char* kind_name(Kind kind) noexcept;
// Closed kind domain: values 0..11 only.  Anything else is `Invalid`.
bool parse_kind(u8 raw, Kind& out) noexcept;
Status check_kind_domain(u8 raw);

struct Atom {
    u8 klass = 0;                              // advisory (parent §6.9); never affects denotation
    u8 flags = 0;                              // MUST be 0
    BigInt length;                             // payload byte length
    std::array<u8, 32> sha256{};               // SHA-256 of payload
    std::span<const u8> payload;               // view; storage outlives the Ir
    // C04 CANON additive member: when set, keeps the payload storage referenced
    // through `payload` alive for as long as this atom lives.  `canon` returns
    // self-contained Ir values whose atoms always carry this handle (they own
    // their merged/split payload storage); atoms built by other tools leave it
    // nullptr, matching the pre-C04 contract that the caller keeps storage
    // alive.  Existing code is unaffected.
    std::shared_ptr<void> owner;
};

struct Node {
    Kind kind = Kind::Empty;
    u8 flags = 0;                              // MUST be 0
    std::vector<u32> args;                     // absolute ids, strictly < own index
    // Parameter slots, exactly as E2 §4.2 declares them.  Field mapping
    // (documented in REPORT/E2/C03-TERM-REPORT.md §5):
    //   Zero       n        -> a
    //   Repeat     q, r     -> a, b
    //   Slice      start,len-> a, b
    //   Interleave stride   -> a   (u32 range; §4.2 has no dedicated field)
    //   Lfsr       n        -> a   (conn/init in lfsr_conn/lfsr_init)
    //   Affine     n        -> a   (start/step in affine_start/affine_step)
    //   Atom       atom id  -> args[0]
    BigInt a, b;
    u8 morph = 0;
    u8 morph_k = 0;
    u64 lfsr_conn = 0;
    u64 lfsr_init = 0;
    u8 affine_start = 0;
    u8 affine_step = 0;
    u8 predictor_id = 0;
    u32 predictor_param = 0;
    BigInt length;                             // MUST equal the §4.4 recomputation
};

struct Ir {
    std::vector<Atom> atoms;
    std::vector<Node> nodes;
    u32 root = 0;
    BigInt total_length;                       // MUST equal nodes[root].length
};

// `Ir` limits.  Defaults are the normative constants; the struct exists so
// W1/W7/output-cap checks are exercisable without allocating 2^24 records.
struct Limits {
    u32 max_nodes = kMaxRecordsSpec;
    u32 max_atoms = kMaxRecordsSpec;
    u32 max_depth = kMaxDepthSpec;
    bool enforce_output_cap = true;
};

// §8.3 hard output cap: 2^63 bytes.
const BigInt& max_output_bytes();

// Interleave stride lives in `Node::a` (see field mapping above) and must fit
// in u32, matching the wire parameter of parent §5.5.
Result<u32> interleave_stride(const Node& node) noexcept;

// ---------------------------------------------------------------------------
// Well-formedness (E2 §4.3–4.5, §5.1)
// ---------------------------------------------------------------------------

// Constraint identifiers, in the fixed first-failure order of E2 §5.1:
//   counts, flags, root, reachability, args, lengths, depth, kind constraints.
constexpr const char* kC_counts = "W1.counts";
constexpr const char* kC_atom_flags = "W4.atom-flags";
constexpr const char* kC_node_flags = "W4.node-flags";
constexpr const char* kC_kind = "W8.kind-domain";
constexpr const char* kC_atom_payload = "W6.atom-payload-length";
constexpr const char* kC_root = "W2.root";
constexpr const char* kC_reachable = "W2.unreachable-node";
constexpr const char* kC_arg_range = "W3.arg-range";
constexpr const char* kC_atom_unused = "W2.unused-atom";
constexpr const char* kC_total_length = "W5.total-length";
constexpr const char* kC_arg_order = "W3.arg-order";
constexpr const char* kC_length = "W6.length";
constexpr const char* kC_output_cap = "S1.output-cap";
constexpr const char* kC_depth = "W7.depth";
constexpr const char* kC_argc = "W8.argc";
constexpr const char* kC_atom_id = "W8.atom-id";
constexpr const char* kC_atom_len = "W8.atom-length";
constexpr const char* kC_repeat = "W8.repeat";
constexpr const char* kC_slice = "W8.slice";
constexpr const char* kC_morph = "W8.morph";
constexpr const char* kC_xor = "W8.xor";
constexpr const char* kC_interleave = "W8.interleave";
constexpr const char* kC_lfsr = "W8.lfsr";
constexpr const char* kC_predictor = "W8.predictor";

struct WfReport {
    Code code = Code::Ok;
    u32 node = 0;                 // offending node id (or atom id for atom checks)
    const char* constraint = "";  // one of the kC_* identifiers
    std::string message;

    bool ok() const noexcept { return code == Code::Ok; }
};

// Full diagnostic form: reports the first failure in the fixed §5.1 order.
WfReport check_well_formed_report(const Ir& ir);
WfReport check_well_formed_report(const Ir& ir, const Limits& limits);

// Normative predicate.  Ok iff WF(ir).
Status check_well_formed(const Ir& ir);
Status check_well_formed(const Ir& ir, const Limits& limits);

// Atom digests are part of the IR record (§4.2).  WF does not pay O(bytes) to
// re-hash; E3 owns payload/digest verification.  This helper is the explicit
// C03 surface for callers that do want the digest recomputed (used by the C03
// evidence harness).
Status verify_atom_digests(const Ir& ir);

// ---------------------------------------------------------------------------
// Lengths (E2 §4.4)
// ---------------------------------------------------------------------------

// Recomputes every node length bottom-up from structure.  Stored lengths are
// never read.  Returns `Invalid` when a node's arg list cannot produce a
// length (it is then the kind-constraint pass that rejects the term) and
// `Limit` on arithmetic/resource failure.
Result<std::vector<std::optional<BigInt>>> recompute_lengths(const Ir& ir);

// Strict form: `Invalid` if any length is not computable.
Result<std::vector<BigInt>> recompute_lengths_checked(const Ir& ir);

// ---------------------------------------------------------------------------
// Morphisms (E2 §4.6, parent §3.4) — closed catalogue, ids 1..9
// ---------------------------------------------------------------------------

constexpr u8 kMorphCount = 9u;

enum class Morph : u8 {
    BitReverse8 = 1,
    Invert8 = 2,
    Swap16 = 3,
    Swap32 = 4,
    Swap64 = 5,
    Rotl8 = 6,
    Rotr8 = 7,
    ReverseBytes = 8,
    ReverseBits = 9,
};

const char* morph_name(u8 morph) noexcept;
// 1..9 only.
Status check_morph_domain(u8 morph);
// `k` and length constraint jointly, per §4.6 (length in bytes).
Status check_morph_params(u8 morph, u8 k, const BigInt& length);
// Block size for block-local morphs 3/4/5, else 0.
u32 morph_block_size(u8 morph) noexcept;
// True for morphs 1, 2, 6, 7 (byte-local).
bool morph_is_byte_local(u8 morph) noexcept;

// Byte-local primitive of the C03 surface (E2 §8).  Defined for morphs 1, 2,
// 6, 7.  For the block/mirrored morphs 3, 4, 5, 8, 9 a single byte carries no
// meaning; this function returns `in` unchanged and the engine never calls it
// for those ids.  Use `apply_morph_to_buffer` for every morph.
u8 apply_morph_byte(u8 morph, u8 k, u8 in) noexcept;
// Checked form: `Invalid` for non-byte-local morph ids and wrong `k`.
Result<u8> apply_morph_byte_checked(u8 morph, u8 k, u8 in);

// Exact morph application to a whole segment, all nine ids, §4.6 length
// constraints enforced.  `Invalid` on any closed-catalogue violation.
Status apply_morph_to_buffer(u8 morph, u8 k, std::span<u8> buffer);

u8 bit_reverse8(u8 x) noexcept;

// ---------------------------------------------------------------------------
// Predictors (E2 §4.11, parent §3.6) — closed catalogue, pids 0..4
// ---------------------------------------------------------------------------

constexpr u8 kPredictorCount = 5u;

enum class Predictor : u8 {
    Delta8 = 0,
    Xor8 = 1,
    Linear2 = 2,
    StrideXor = 3,
    StrideDelta = 4,
};

const char* predictor_name(u8 pid) noexcept;
Status check_predictor_domain(u8 pid);
Status check_predictor_params(u8 pid, u32 param);

// One step of the predictor recurrence.
//   prev1 = out[i-1] (pid 0,1) / out[i-s] (pid 3,4) / out[i-1] (pid 2)
//   prev2 = out[i-2] (pid 2 only)
// Seeding is the caller's: index 0 is `r[0]` for every pid, index 1 is `r[1]`
// for pid 2, and indices `i < s` are `r[i]` for pid 3/4 (callers pass prev1=0
// there).  pid 2 follows the literal normative formula of §4.11, which ignores
// the residual — see REPORT/E2/C03-TERM-REPORT.md §5 (inherited H3 §7 defect).
u8 apply_predictor_step(u8 pid, u32 param, u8 residual, u8 prev1, u8 prev2) noexcept;
// Checked form: `Invalid` for pid > 4 and for pid in {3,4} with param == 0.
Result<u8> apply_predictor_step_checked(u8 pid, u32 param, u8 residual, u8 prev1, u8 prev2);

// Exact reconstruction of a whole residual buffer; `out.size() == residual.size()`.
Status apply_predictor_to_buffer(u8 pid, u32 param, std::span<const u8> residual,
                                 std::span<u8> out);

// §5.5 policy: the predictor prefix pass is linear in `start`; above this
// offset the range path returns `Limit` unless a checkpoint is supplied
// (checkpoints are C05 scope).
const BigInt& predictor_prefix_limit();

// ---------------------------------------------------------------------------
// LFSR (E2 §4.10, parent §3.5)
// ---------------------------------------------------------------------------

Status check_lfsr_conn(u64 conn);

u64 lfsr_parity(u64 value) noexcept;                 // XOR of set bits
u64 lfsr_step(u64 state, u64 conn) noexcept;         // one bit step
// Emits one byte (8 bit steps) MSB-first, advancing `state`.
u8 lfsr_next_byte(u64& state, u64 conn) noexcept;

// 64x64 GF(2) linear map of the LFSR one-step transition.
struct Gf2Matrix64 {
    std::array<u64, 64> col{};  // col[i] = image of basis vector 2^i
};

Gf2Matrix64 lfsr_step_matrix(u64 conn) noexcept;
u64 gf2_apply(const Gf2Matrix64& map, u64 value) noexcept;
Gf2Matrix64 gf2_compose(const Gf2Matrix64& outer, const Gf2Matrix64& inner) noexcept;
Gf2Matrix64 gf2_power(const Gf2Matrix64& base, const BigInt& exponent);

// State after `8 * byte_offset` bit steps: T^(8·offset)·init in O(log offset).
Result<u64> lfsr_state_at_byte_offset(u64 conn, u64 init, const BigInt& byte_offset);

// Streaming generator with O(log offset) seeking.
class LfsrStream {
public:
    LfsrStream(u64 conn, u64 init);

    Status jump_to_byte_offset(const BigInt& byte_offset);
    u64 state() const noexcept { return state_; }
    u8 next_byte() noexcept;
    Status read(std::span<u8> out) noexcept;

private:
    u64 conn_ = 0;
    u64 init_ = 0;
    u64 state_ = 0;
};

// One-shot range read: bytes [byte_offset, byte_offset + out.size()).
Status lfsr_read_range(u64 conn, u64 init, const BigInt& byte_offset, std::span<u8> out);

// ---------------------------------------------------------------------------
// Denotation (E2 §4.9, §5.3–5.5)
// ---------------------------------------------------------------------------

// E2 output boundary; E3/E7 supply concrete sinks.
class Sink {
public:
    virtual ~Sink() = default;
    virtual Status write(std::span<const u8> bytes) = 0;
};

// ⟦node⟧ written in one fixed order, block buffer of `kEvalBlock` bytes.
Status eval_stream(const Ir& ir, Sink& sink);
Status eval_stream(const Ir& ir, u32 node, Sink& sink);
Status eval_range(const Ir& ir, const BigInt& start, const BigInt& length, Sink& sink);

constexpr std::size_t kEvalBlock = 1u << 16;

// ⟦node⟧[start, start + out.size()) — E2 §5.3/§5.4.
// Preconditions: `check_well_formed(ir)` and `start + out.size() <= ℓ(node)`.
// Returns `Invalid` if the requested range is outside the declared length, and
// never allocates memory proportional to ℓ(node) or to `start`.
Result<std::size_t> read_range(const Ir& ir, u32 node, const BigInt& start,
                               std::span<u8> out);

// Monotone cursor over ⟦node⟧ (E2 §5.3).
class TermCursor {
public:
    TermCursor(const Ir& ir, u32 node);
    ~TermCursor();
    TermCursor(TermCursor&&) noexcept;
    TermCursor& operator=(TermCursor&&) noexcept;
    TermCursor(const TermCursor&) = delete;
    TermCursor& operator=(const TermCursor&) = delete;

    Result<std::size_t> read(std::span<u8> out);
    const BigInt& remaining() const noexcept;
    const BigInt& offset() const noexcept;
    bool at_end() const noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// C03 convenience for harnesses/tests: materialise ⟦node⟧ when it is at most
// `max_bytes` bytes long (`Limit` otherwise).  Not a range primitive.
Result<std::vector<u8>> denote_node(const Ir& ir, u32 node, u64 max_bytes);
Result<std::vector<u8>> denote_root(const Ir& ir, u64 max_bytes);

// ---------------------------------------------------------------------------
// Structural digest helper (deterministic evidence support)
// ---------------------------------------------------------------------------

// Deterministic, id-independent description of the subterm at `node`, in the
// pre-order encoding of E2 §5.7.  Equality/ordering behaviour is normative;
// the exact bytes are not.  (C04/C06 will own the canonical key policy.)
std::string structural_key(const Ir& ir, u32 node);

}  // namespace marp::v2
