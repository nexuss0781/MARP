// MARP v2 — E3 WIRE — E3-G integrated gate — shared harness support.
//
// Evidence-support code for the E3-G harness only.  Nothing here is linked into
// `e3_wire.o`, `e3_wire_read.o`, `e3_wire_index.o` (C07) or `e3_legacy.o` (C08);
// the component has no dependency on this directory in any direction.
//
// Normative sources:
//   SPECS/COMPONENTS/e3-wire/SPECS.md   §13.3 (corpus), §13.4 (procedure),
//                                       §13.5 (evidence), §13.6 (fail conditions)
//   SPECS/SPECS-V2.md                   §5, §8, §15
//
// The harness never asserts and never edits a measured value: every obligation
// becomes one TSV row with an exact expected/actual pair and a PASS/FAIL (or,
// where the spec itself defines one, BLOCKED) verdict.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "mapr/e2/e2_term.hpp"
#include "mapr/e3/e3_wire.hpp"

namespace e3g {

using namespace marp::v2;  // NOLINT

// ---------------------------------------------------------------------------
// Bytes and digests
// ---------------------------------------------------------------------------

std::string hex_bytes(const u8* data, std::size_t size);
inline std::string hex_bytes(std::span<const u8> bytes) {
    return hex_bytes(bytes.data(), bytes.size());
}
inline std::string hex_array(const std::array<u8, 32>& digest) {
    return hex_bytes(digest.data(), digest.size());
}

std::string sha256_hex(std::span<const u8> bytes);
std::string sha256_hex(std::string_view text);
std::string sha_of_bytes(const std::vector<u8>& bytes);
std::string sha_of_text(const std::string& text);
// SHA-256 of a file, or "missing" when it cannot be read.  Fixed chunking so the
// digest does not depend on the standard library's iterator implementation.
std::string sha_of_file(const std::string& path);

// Joins a repository-relative path against `root`; an absolute path is returned
// unchanged.
std::string resolve_path(const std::string& root, const std::string& path);

// Splits on '\n', dropping a trailing empty line.
std::vector<std::string> split_lines(const std::string& text);

bool file_exists(const std::string& path);
bool read_file_bytes(const std::string& path, std::vector<u8>& out);
bool write_file_bytes(const std::string& path, std::span<const u8> bytes);

// ---------------------------------------------------------------------------
// Canonical structural description of an `Ir` (corpus identity + comparison)
// ---------------------------------------------------------------------------

// Deterministic, complete description of an `Ir`: every atom (klass, declared
// length, payload digest), every node (kind, args, params, declared length), the
// root id and the total length.  Used as the `input_sha256` source, so a corpus
// row is bound to the term it names and not to an artefact of construction.
std::string describe_ir(const Ir& ir);

// The same description restricted to the fields an independent reader reports
// (`inspect`), in a stable one-line-per-record form.  See `e3g_oracle.hpp`.
std::string structural_key(const Ir& ir);

// §4.6 kind-specific parameters in the exact textual form the H3 oracle prints
// (`format_node_params`), so a structural comparison is a string comparison of
// two independently written renderings of the same wire.
std::string params_text(const Node& node);

// E2's kind name, spelled as H3's `kind_name` spells it.
const char* kind_text(Kind kind);

// Structural equality over ids, kinds, args, params, lengths, klass and payloads.
bool same_ir(const Ir& a, const Ir& b, std::string& why);

// Rebuilds an `Ir` from a `structural_key` rendering.  It exists for one purpose:
// the legacy half runs as a separate process, so the term C08 decoded has to
// cross the boundary as text before the v2 side can re-encode it (§13.4 step 8).
// A rendering that does not parse yields false and the caller records a FAIL; the
// parser accepts only the exact form `structural_key` emits.
bool parse_structural_key(const std::string& text, Ir& out, std::string& why);

// ---------------------------------------------------------------------------
// Evidence rows
// ---------------------------------------------------------------------------

// The §13.5 column set, in order:
//   check  corpus  item_id  input_sha256  wire_sha256  wire_bytes  expected
//   actual  verdict  log
struct Row {
    std::string check;
    std::string corpus;
    std::string item_id;
    std::string input_sha256;
    std::string wire_sha256;
    std::string wire_bytes;
    std::string expected;
    std::string actual;
    std::string verdict;
    std::string log;
};

class Collector {
public:
    void row(const std::string& check, const std::string& corpus, const std::string& item_id,
             const std::string& input_sha256, const std::string& wire_sha256,
             const std::string& wire_bytes, const std::string& expected,
             const std::string& actual, bool pass, const std::string& log_ref);

    // A row whose verdict is neither PASS nor FAIL.  The spec defines exactly one
    // such state — `BLOCKED` — and only where a hard dependency is absent.
    void row_verdict(const std::string& check, const std::string& corpus,
                     const std::string& item_id, const std::string& input_sha256,
                     const std::string& wire_sha256, const std::string& wire_bytes,
                     const std::string& expected, const std::string& actual,
                     const std::string& verdict, const std::string& log_ref);

    void log(const std::string& line);
    void section(const std::string& name);

    // Appends another collector's rows and log lines in order, so a pass run on
    // several threads can be recorded by one collector in a deterministic
    // shard order (§13.4 step 9).
    void merge(const Collector& other);

    const std::vector<Row>& rows() const { return rows_; }
    const std::vector<std::string>& log_lines() const { return log_lines_; }
    std::size_t passes() const { return passes_; }
    std::size_t failures() const { return failures_; }
    std::size_t count_verdict(const std::string& verdict) const;

    void set_environment(std::string text) { environment_ = std::move(text); }
    const std::string& environment() const { return environment_; }

private:
    std::vector<Row> rows_;
    std::vector<std::string> log_lines_;
    std::string environment_;
    std::size_t passes_ = 0;
    std::size_t failures_ = 0;
    std::size_t section_rows_ = 0;
};

// ---------------------------------------------------------------------------
// Container field access, for the W-NONCANON mutations
// ---------------------------------------------------------------------------

u16 load16_at(const std::vector<u8>& wire, std::size_t at);
u32 load32_at(const std::vector<u8>& wire, std::size_t at);
u64 load64_at(const std::vector<u8>& wire, std::size_t at);
void put16_at(std::vector<u8>& wire, std::size_t at, u16 v);
void put32_at(std::vector<u8>& wire, std::size_t at, u32 v);
void put64_at(std::vector<u8>& wire, std::size_t at, u64 v);

// Recomputes `file_crc32` and `trailer_crc32` so that a mutation is reported by
// the stage that owns the mutated field rather than by stage 4 or 5.
void repair_outer_crcs(std::vector<u8>& wire);

// Reads a canonical uvarint out of `wire` starting at `pos`, advancing `pos`.
// Returns false on a non-canonical or truncated encoding.  Harness-side only:
// it lets a mutation locate a table record without re-deriving the layout.
bool read_uvarint_at(const std::vector<u8>& wire, std::size_t& pos, u64& value);

// Wire-code and stage names, for `expected`/`actual` columns.
std::string code_and_stage(const WireError& error);

// ---------------------------------------------------------------------------
// Allocation guard (O7.10)
// ---------------------------------------------------------------------------
//
// The fuzz campaign must show that no mutant commands an allocation beyond its
// declared container size.  The guard is a process-wide `operator new`/`delete`
// pair (defined in `e3g_alloc_guard.cpp`, linked only into the E3-G gate) that
// tracks outstanding and peak bytes; the campaign arms it per mutant and asks
// for the peak afterwards.  Nothing in C07 or C08 knows it exists.
namespace alloc_guard {

void begin(std::size_t budget_bytes);
void end();
std::size_t peak_bytes();
std::size_t outstanding_bytes();
bool violated();
bool enabled();

}  // namespace alloc_guard

}  // namespace e3g
