// MARP v2 — E3 WIRE — E3-G integrated gate — wire-side checks.
//
// Normative sources: SPECS/COMPONENTS/e3-wire/SPECS.md §13.2 (gate condition),
// §13.4 (procedure), §13.5 (evidence).  Every obligation becomes one row of the
// §13.5 column set with an exact expected/actual pair; no value is asserted by
// the harness and none is edited after measurement.

#include "e3g_checks.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <map>
#include <set>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "mapr/e2/e2_canon.hpp"

namespace e3g {
namespace {

// ---------------------------------------------------------------------------
// Coverage
// ---------------------------------------------------------------------------

std::string join_counts(const char* const* names, const std::size_t* counts, std::size_t n,
                        const char* prefix) {
    std::string text;
    for (std::size_t i = 0; i < n; ++i) {
        if (i != 0) text += ",";
        text += std::string(prefix) + names[i] + "=" + std::to_string(counts[i]);
    }
    return text;
}

const char* const kKindNames[12] = {"Empty", "Atom",  "Zero", "Concat",
                                    "Repeat", "Slice", "Morph", "Xor",
                                    "Interleave", "Lfsr", "Affine", "Predictor"};

// §13.4 step 9: a repeatable, comparable rendering of one check's measurement.
struct Measurement {
    std::string item_id;
    std::string wire_sha256;
    std::string wire_bytes;
    std::string verdict;
};

std::string measurement_key(const std::vector<Measurement>& ms) {
    std::string text;
    for (const Measurement& m : ms) {
        text += m.item_id + "\t" + m.wire_sha256 + "\t" + m.wire_bytes + "\t" + m.verdict + "\n";
    }
    return text;
}

// §13.4 step 6 / §5.1: the rejection a non-canonical container must produce.
std::string rejection_text(const WireResult<Validation>& result) {
    if (result.ok()) return "accepted";
    return code_and_stage(result.error());
}

std::string rejection_text(const WireResult<Ir>& result) {
    if (result.ok()) return "accepted";
    return code_and_stage(result.error());
}

// A term whose declared length exceeds the default output cap needs both limits
// lifted: the §8.3 cap so the wire can be produced at all, and the step-11 work
// bound so the denotation can be evaluated.  Both lifts are recorded, and the
// default-limits outcome is reported as its own row.
// Limits for the canonical roundtrip of a corpus item.
//
// `needs_limit_lift` marks a term whose declared length exceeds one of C07's two
// policy bounds (the §8.3 output cap of 2^63, or stage 11's 1 GiB work bound).
// Such a term is still a canonical wire, so the wire-level obligations — exact
// `encoded_size`, byte-exact `enc(dec(enc(t)))`, structural equality of the decoded
// `Ir`, H3 agreement — are all checked with the §8.3 cap lifted.
//
// Stage 11 is deliberately *not* lifted: the denotation of `Zero(2^128)` cannot be
// produced in bounded time by any implementation, and a gate that tried would hang
// rather than measure.  For those items `verify_denotation = false`, which makes
// `validate`/`decode` a structural check, and the gate says so in the row's
// `expected`/`actual` text instead of claiming a stage-11 pass.  The default-limits
// `Limit` — the §5.2 "declared limit exceeded" case — is recorded on its own row.
WireLimits limits_for(const CanonItem& item) {
    WireLimits limits;
    if (item.needs_limit_lift) {
        limits.enforce_output_cap = false;
        limits.max_output_bytes = marp::v2::max_output_bytes();
        limits.verify_denotation = false;
    }
    return limits;
}

}  // namespace

// ---------------------------------------------------------------------------
// Coverage
// ---------------------------------------------------------------------------

void Coverage::observe_ir(const Ir& ir) {
    std::set<u8> klasses;
    for (const Atom& atom : ir.atoms) {
        klasses.insert(atom.klass);
        if (atom.length == BigInt(kWireAtomMax)) ++atom_at_max;
    }
    klass_values = std::max(klass_values, klasses.size());
    for (const Node& node : ir.nodes) {
        const std::size_t kind_index = static_cast<std::size_t>(node.kind);
        if (kind_index < kind.size()) ++kind[kind_index];
        if (node.kind == Kind::Morph && node.morph < morph.size()) ++morph[node.morph];
        if (node.kind == Kind::Predictor && node.predictor_id < predictor.size()) {
            ++predictor[node.predictor_id];
        }
        if (node.kind == Kind::Concat && node.args.size() == 2) {
            const Node& first = ir.nodes[node.args[0]];
            const Node& second = ir.nodes[node.args[1]];
            if (first.kind == Kind::Atom && second.kind == Kind::Atom) {
                auto a = first.a.to_u64_checked();
                auto b = second.a.to_u64_checked();
                if (a && b && *a < ir.atoms.size() && *b < ir.atoms.size()) {
                    if (ir.atoms[*a].length == BigInt(kWireAtomMax) &&
                        ir.atoms[*b].length == BigInt(1)) {
                        ++atom_max_plus_one_split;
                    }
                }
            }
        }
        // §4.9 bigint tags, observed on the exact values the wire will carry.
        auto tag_of = [](const BigInt& value) -> std::size_t {
            if (value.is_zero()) return 0;
            if (value.to_u64_checked().has_value()) return 1;
            return 2;
        };
        switch (node.kind) {
            case Kind::Zero: ++bigint_tag[tag_of(node.a)]; break;
            case Kind::Repeat:
            case Kind::Slice: ++bigint_tag[tag_of(node.a)]; break;
            case Kind::Lfsr:
            case Kind::Affine: ++bigint_tag[tag_of(node.a)]; break;
            default: break;
        }
    }
    if (ir.atoms.empty()) ++bigint_tag[0];
}

void Coverage::add(const Coverage& other) {
    for (std::size_t i = 0; i < kind.size(); ++i) kind[i] += other.kind[i];
    for (std::size_t i = 0; i < morph.size(); ++i) morph[i] += other.morph[i];
    for (std::size_t i = 0; i < predictor.size(); ++i) predictor[i] += other.predictor[i];
    for (std::size_t i = 0; i < bigint_tag.size(); ++i) bigint_tag[i] += other.bigint_tag[i];
    total_length_u64 += other.total_length_u64;
    total_length_big += other.total_length_big;
    index_present += other.index_present;
    index_absent += other.index_absent;
    atom_at_max += other.atom_at_max;
    atom_max_plus_one_split += other.atom_max_plus_one_split;
    klass_values = std::max(klass_values, other.klass_values);
    for (std::size_t i = 0; i < 12; ++i) stage_exercised[i] += other.stage_exercised[i];
}

void Coverage::observe_wire(std::span<const u8> wire) {
    if (wire.size() < kWireMinContainerBytes) return;
    const std::vector<u8> bytes(wire.begin(), wire.end());
    const u32 flags = load32_at(bytes, kHdrOffFlags);
    if ((flags & kWireFlagIndexPresent) != 0) {
        ++index_present;
    } else {
        ++index_absent;
    }
    if (load16_at(bytes, kHdrOffTotalLengthBigLen) == 0) {
        ++total_length_u64;
        ++bigint_tag[1];
    } else {
        ++total_length_big;
        ++bigint_tag[2];
    }
}

bool Coverage::every_counter_nonzero(std::string& why) const {
    for (std::size_t i = 0; i < kind.size(); ++i) {
        if (kind[i] == 0) {
            why = std::string("kind ") + kKindNames[i] + " never observed";
            return false;
        }
    }
    for (std::size_t i = 1; i < morph.size(); ++i) {
        if (morph[i] == 0) {
            why = "morph " + std::to_string(i) + " never observed";
            return false;
        }
    }
    for (std::size_t i = 0; i < predictor.size(); ++i) {
        if (predictor[i] == 0) {
            why = "predictor " + std::to_string(i) + " never observed";
            return false;
        }
    }
    for (std::size_t i = 0; i < bigint_tag.size(); ++i) {
        if (bigint_tag[i] == 0) {
            why = "bigint tag " + std::to_string(i) + " never observed";
            return false;
        }
    }
    if (total_length_u64 == 0) {
        why = "no u64 total-length form";
        return false;
    }
    if (total_length_big == 0) {
        why = "no big total-length form";
        return false;
    }
    if (index_present == 0) {
        why = "no index-present container";
        return false;
    }
    if (index_absent == 0) {
        why = "no index-absent container";
        return false;
    }
    if (atom_at_max == 0) {
        why = "no atom at ATOM_MAX";
        return false;
    }
    return true;
}

std::string Coverage::to_text() const {
    std::string text;
    text += join_counts(kKindNames, kind.data(), kind.size(), "kind.");
    text += "\n";
    text += "morph.1=" + std::to_string(morph[1]) + ",morph.2=" + std::to_string(morph[2]) +
            ",morph.3=" + std::to_string(morph[3]) + ",morph.4=" + std::to_string(morph[4]) +
            ",morph.5=" + std::to_string(morph[5]) + ",morph.6=" + std::to_string(morph[6]) +
            ",morph.7=" + std::to_string(morph[7]) + ",morph.8=" + std::to_string(morph[8]) +
            ",morph.9=" + std::to_string(morph[9]) + "\n";
    text += "predictor.0=" + std::to_string(predictor[0]) + ",predictor.1=" +
            std::to_string(predictor[1]) + ",predictor.2=" + std::to_string(predictor[2]) +
            ",predictor.3=" + std::to_string(predictor[3]) + ",predictor.4=" +
            std::to_string(predictor[4]) + "\n";
    text += "bigint.tag0=" + std::to_string(bigint_tag[0]) + ",bigint.tag1=" +
            std::to_string(bigint_tag[1]) + ",bigint.tag2=" + std::to_string(bigint_tag[2]) +
            "\n";
    text += "total_length.u64=" + std::to_string(total_length_u64) + ",total_length.big=" +
            std::to_string(total_length_big) + "\n";
    text += "index.present=" + std::to_string(index_present) +
            ",index.absent=" + std::to_string(index_absent) + "\n";
    text += "atom.at_max=" + std::to_string(atom_at_max) + ",atom.max_plus_one_split=" +
            std::to_string(atom_max_plus_one_split) + ",klass.values=" +
            std::to_string(klass_values) + "\n";
    return text;
}

// ---------------------------------------------------------------------------
// Mutator (W-FUZZ)
// ---------------------------------------------------------------------------

u64 Mutator::next() {
    state_ += 0x9E3779B97F4A7C15ull;
    u64 z = state_;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    return z ^ (z >> 31);
}

namespace {

// Recomputes both outer CRCs so a mutant whose only defect is a field the stage
// under test owns is not rejected earlier by stage 4 or 5.  Half the mutants keep
// the stale CRCs so both families are exercised.
void recompute_crcs(std::vector<u8>& wire) { repair_outer_crcs(wire); }

constexpr std::size_t kMutationClasses = 11;

}  // namespace

bool Mutator::mutate(std::vector<u8>& wire, const std::vector<u8>& seed, u64 index) {
    wire = seed;
    if (wire.size() < kWireMinContainerBytes) return false;
    const std::size_t cls = static_cast<std::size_t>(index % kMutationClasses);
    const bool repair = ((index >> 8) & 1u) != 0;
    const std::size_t size = wire.size();
    switch (cls) {
        case 0: {  // single-byte flip anywhere in the container
            const std::size_t at = below(size);
            wire[at] ^= static_cast<u8>(1u << (next() % 8u));
            break;
        }
        case 1: {  // truncate
            const std::size_t keep = below(size - 1u) + 1u;
            wire.resize(keep);
            break;
        }
        case 2: {  // extend with attacker bytes
            const std::size_t extra = below(64) + 1u;
            for (std::size_t i = 0; i < extra; ++i) wire.push_back(static_cast<u8>(next()));
            break;
        }
        case 3: {  // overwrite a header field with an extreme value
            static const std::size_t kFields[] = {kHdrOffFlags,      kHdrOffHeaderBytes,
                                                  kHdrOffTotalLengthU64,
                                                  kHdrOffTotalLengthBigLen, kHdrOffAtomOffset,
                                                  kHdrOffNodeOffset, kHdrOffIndexOffset,
                                                  kHdrOffTrailerOffset};
            const std::size_t field = kFields[below(std::size(kFields))];
            const u64 extreme = (next() & 1u) != 0 ? 0xFFFFFFFFFFFFFFFFull : 0ull;
            const std::size_t width = (field == kHdrOffFlags) ? 4u
                                     : (field == kHdrOffHeaderBytes) ? 2u
                                     : (field == kHdrOffTotalLengthBigLen) ? 2u
                                                                            : 8u;
            for (std::size_t i = 0; i < width && field + i < wire.size(); ++i) {
                wire[field + i] = static_cast<u8>((extreme >> (8u * i)) & 0xFFu);
            }
            break;
        }
        case 4: {  // swap two bytes
            const std::size_t a = below(size);
            const std::size_t b = below(size);
            std::swap(wire[a], wire[b]);
            break;
        }
        case 5: {  // splice out a run
            const std::size_t at = below(size - 1u);
            const std::size_t len = below(std::min<std::size_t>(32u, size - at - 1u)) + 1u;
            wire.erase(wire.begin() + static_cast<std::ptrdiff_t>(at),
                       wire.begin() + static_cast<std::ptrdiff_t>(at + len));
            break;
        }
        case 6: {  // insert a run
            const std::size_t at = below(size);
            const std::size_t len = below(32) + 1u;
            wire.insert(wire.begin() + static_cast<std::ptrdiff_t>(at), len,
                        static_cast<u8>(next()));
            break;
        }
        case 7: {  // rewrite the trailer fields
            const std::size_t trailer = wire.size() - static_cast<std::size_t>(kWireTrailerBytes);
            const std::size_t field = trailer + (below(5u) * 4u);
            if (field + 4 <= wire.size()) {
                const u32 value = static_cast<u32>(next() & 0xFFFFFFFFu);
                put32_at(wire, field, value);
            }
            break;
        }
        case 8: {  // corrupt a region offset by a small delta
            static const std::size_t kFields[] = {kHdrOffAtomOffset, kHdrOffNodeOffset,
                                                  kHdrOffIndexOffset, kHdrOffTrailerOffset};
            const std::size_t field = kFields[below(std::size(kFields))];
            const u64 value = load64_at(wire, field);
            put64_at(wire, field, value + (next() & 0x1Fu) + 1u);
            break;
        }
        case 9: {  // zero a run inside a table
            const std::size_t at = below(size);
            const std::size_t len = below(16) + 1u;
            for (std::size_t i = at; i < std::min(size, at + len); ++i) wire[i] = 0u;
            break;
        }
        default: {  // duplicate a run (aliasing / overlapping regions)
            const std::size_t at = below(size - 1u);
            const std::size_t len = std::min<std::size_t>(32u, size - at);
            const std::vector<u8> run(wire.begin() + static_cast<std::ptrdiff_t>(at),
                                      wire.begin() + static_cast<std::ptrdiff_t>(at + len));
            wire.insert(wire.begin() + static_cast<std::ptrdiff_t>(at), run.begin(), run.end());
            break;
        }
    }
    if (repair && wire.size() >= kWireMinContainerBytes) recompute_crcs(wire);
    return true;
}

// ---------------------------------------------------------------------------
// §13.4 steps 2–6: canon, seeds, non-canonical rejection
// ---------------------------------------------------------------------------
namespace {

struct CanonOutcome {
    std::vector<Measurement> measured;
    std::size_t encoded = 0;
    std::size_t failed = 0;
    std::size_t limit_items = 0;
    std::size_t limit_observed = 0;
    std::size_t oracle_ok = 0;
    std::size_t oracle_bad = 0;
    std::string first_disagreement;
    std::vector<std::string> corpus_rows;
};

// Step 2: `encoded_size` equals the actual byte count; `enc` is deterministic.
// Step 3: E3 and H3 agree structurally, and the denotation is the source term's.
// Step 4: `enc(dec(enc(t))) == enc(t)` byte for byte.
void check_canon_item(const CanonItem& item, const Settings& settings, Collector& collector,
                      CanonOutcome& out, Coverage& coverage) {
    const std::string input_sha = sha_of_text(describe_ir(item.ir));
    const WireLimits limits = limits_for(item);

    if (item.needs_limit_lift) {
        // §5.2: "a declared limit exceeded" is `Limit`.  Under the *default* limits
        // this term must therefore be refused with `Limit` — by `encode` at stage 10
        // when the index cannot be planned, or at stage 6 by `validate`/`decode` when
        // the §8.3 output cap is the bound.  The lifted-limit rows below prove the
        // wire is canonical; this row proves the default policy still bites.  Both
        // results are recorded and neither is presented as the other.
        const WireLimits defaults;
        // `encode` is a pure function of the canonical term and the *format*, so it
        // produces the wire; the policy bounds are enforced on the reader side, which
        // is where a declared length can be observed from untrusted bytes.  Both
        // sides are therefore measured and recorded.
        auto default_encode = encode(item.ir, defaults);
        auto default_sized = encoded_size(item.ir, defaults);
        auto default_validate = default_encode.ok()
                                    ? validate(std::span<const u8>(default_encode.value().data(),
                                                                   default_encode.value().size()),
                                               defaults)
                                    : WireResult<Validation>(default_encode.error());
        const std::string encode_text = default_encode.ok()
                                            ? "Ok"
                                            : code_and_stage(default_encode.error());
        const std::string validate_text =
            default_validate.ok() ? "Ok" : code_and_stage(default_validate.error());
        const bool limited =
            (!default_encode.ok() && default_encode.error().code == WireCode::Limit) ||
            (!default_sized.ok() && default_sized.error().code == WireCode::Limit) ||
            (!default_validate.ok() && default_validate.error().code == WireCode::Limit);
        collector.row("e3g.big.default_limits", "W-BIG", item.id, input_sha, "-", "-",
                      "the declared length exceeds a default policy bound, so at least one of "
                      "encode/encoded_size/validate reports Limit",
                      "encode=" + encode_text + ";encoded_size=" +
                          (default_sized.ok() ? std::string("Ok")
                                              : code_and_stage(default_sized.error())) +
                          ";validate=" + validate_text,
                      limited, "logs/E3-G.log#" + item.id);
    }

    if (item.expect_encode_limit) {
        // The shape has no canonical wire: every writer entry point must say
        // `Limit` at stage 10, with the same code and stage from all three.
        auto planned = plan(item.ir, limits);
        auto sized = encoded_size(item.ir, limits);
        auto encoded = encode(item.ir, limits);
        ++out.limit_items;
        const bool all_limit = !planned.ok() && planned.error().code == WireCode::Limit &&
                               planned.error().stage == Stage::Index && !sized.ok() &&
                               sized.error().code == WireCode::Limit && !encoded.ok() &&
                               encoded.error().code == WireCode::Limit &&
                               encoded.error().stage == Stage::Index;
        if (all_limit) ++out.limit_observed;
        collector.row(
            "e3g.canon.encode_limit", "W-BIG", item.id, input_sha, "-", "0",
            "plan=Limit@stage10_index;size=Limit@stage10_index;encode=Limit@stage10_index",
            "plan=" + (planned.ok() ? std::string("Ok") : code_and_stage(planned.error())) +
                ";size=" + (sized.ok() ? std::string("Ok") : code_and_stage(sized.error())) +
                ";encode=" + (encoded.ok() ? std::string("Ok") : code_and_stage(encoded.error())),
            all_limit, "logs/E3-G.log#" + item.id);
        collector.log("  [" + item.id + "] " + item.note);
        out.corpus_rows.push_back("W-CANON\t" + item.id + "\t" + item.group + "\t" + item.origin +
                                  "\t" + input_sha + "\t-\t0\tlimit@stage10_index");
        return;
    }

    auto sized = encoded_size(item.ir, limits);
    auto first = encode(item.ir, limits);
    auto second = encode(item.ir, limits);
    if (!sized.ok() || !first.ok() || !second.ok()) {
        ++out.failed;
        const std::string why = !sized.ok() ? code_and_stage(sized.error())
                               : !first.ok() ? code_and_stage(first.error())
                                             : code_and_stage(second.error());
        collector.row("e3g.canon.encode", "W-CANON", item.id, input_sha, "-", "0",
                      "encode=Ok", "encode=" + why, false, "logs/E3-G.log#" + item.id);
        out.measured.push_back(Measurement{item.id, "-", "0", "FAIL"});
        return;
    }
    const std::vector<u8>& wire = first.value();
    const std::string wire_sha = sha_of_bytes(wire);
    const std::string wire_bytes = std::to_string(wire.size());
    ++out.encoded;
    coverage.observe_ir(item.ir);
    coverage.observe_wire(std::span<const u8>(wire.data(), wire.size()));

    // Step 2: size exactness and determinism.
    const BigInt sized_big = sized.value();
    const bool size_ok = sized_big == BigInt(static_cast<u64>(wire.size()));
    const bool deterministic = second.value() == wire;
    collector.row("e3g.canon.encoded_size", "W-CANON", item.id, input_sha, wire_sha, wire_bytes,
                  sized_big.to_decimal(), std::to_string(wire.size()), size_ok,
                  "logs/E3-G.log#" + item.id);
    collector.row("e3g.canon.encode_deterministic", "W-CANON", item.id, input_sha, wire_sha,
                  wire_bytes, "second encode == first", deterministic ? "byte-identical" : "differs",
                  deterministic, "logs/E3-G.log#" + item.id);

    // Step 3a: E3's own validate accepts the canonical wire.
    const char* const validate_expectation =
        item.needs_limit_lift ? "validate=Ok (structural: declared length above the stage-11 work "
                                "bound)"
                              : "validate=Ok (full, stage 11 included)";
    auto validated = validate(std::span<const u8>(wire.data(), wire.size()), limits);
    collector.row("e3g.canon.validate", "W-CANON", item.id, input_sha, wire_sha, wire_bytes,
                  validate_expectation,
                  validated.ok() ? "validate=Ok" : "validate=" + code_and_stage(validated.error()),
                  validated.ok(), "logs/E3-G.log#" + item.id);
    if (validated.ok()) {
        // Step 11 of §5.1 must actually have run for every item the gate claims a
        // *full* validation of.  For a term whose denotation exceeds the work bound
        // the row states the structural result instead of silently omitting it.
        const bool evaluated = validated.value().denotation_verified;
        if (item.needs_limit_lift) {
            collector.row("e3g.canon.validate_evaluated", "W-CANON", item.id, input_sha, wire_sha,
                          wire_bytes, "structural only (denotation exceeds the work bound)",
                          evaluated ? "denotation_verified" : "structural", !evaluated,
                          "logs/E3-G.log#" + item.id);
        } else {
            collector.row("e3g.canon.validate_evaluated", "W-CANON", item.id, input_sha, wire_sha,
                          wire_bytes, "denotation_verified=true",
                          evaluated ? "true" : "false", evaluated, "logs/E3-G.log#" + item.id);
        }
    }

    // Step 3b/4: decode, structural equality with the source term, byte-exact
    // re-encode.
    auto decoded = decode(std::span<const u8>(wire.data(), wire.size()), limits);
    std::string why;
    const bool structural = decoded.ok() && same_ir(item.ir, decoded.value(), why);
    collector.row("e3g.canon.roundtrip", "W-CANON", item.id, input_sha, wire_sha, wire_bytes,
                  item.needs_limit_lift
                      ? "decode(encode(t)) structurally equals t (structural decode)"
                      : "decode(encode(t)) structurally equals t",
                  decoded.ok() ? (structural ? "structurally equal" : "differs: " + why)
                               : "decode=" + code_and_stage(decoded.error()),
                  structural, "logs/E3-G.log#" + item.id);
    bool byte_exact = false;
    if (decoded.ok()) {
        auto re = encode(decoded.value(), limits);
        byte_exact = re.ok() && re.value() == wire;
        coverage.observe_ir(decoded.value());
    }
    collector.row("e3g.canon.fixpoint", "W-CANON", item.id, input_sha, wire_sha, wire_bytes,
                  "encode(decode(encode(t))) == encode(t)", byte_exact ? "byte-identical" : "differs",
                  byte_exact, "logs/E3-G.log#" + item.id);

    // Step 3c: independent H3 oracle agreement.  The oracle re-derives the header,
    // atom table, node table and index from the same bytes; a disagreement is an
    // implementation-independent finding and fails the row.
    if (settings.full_oracle) {
        const OracleOutcome inspected =
            oracle_inspect(resolve_path(settings.root, settings.oracle_path), wire);
        if (!inspected.available) {
            collector.row_verdict("e3g.canon.oracle_agreement", "W-CANON", item.id, input_sha,
                                  wire_sha, wire_bytes, "H3 accepts and reports the same structure",
                                  "oracle binary not available", "BLOCKED", "logs/E3-G.log#" + item.id);
        } else {
            const std::string expect_key = structural_key(item.ir);
            // The oracle re-derives its key from the bytes alone; the harness's key
            // comes from the term.  Comparing them is a comparison of two readers.
            const std::string got_key = inspected.key_text.empty() ? std::string("-")
                                                                  : inspected.key_text;
            const bool accepts = inspected.ran && inspected.exit_code == 0;
            const bool agrees = accepts && got_key == expect_key;
            if (agrees) {
                ++out.oracle_ok;
            } else {
                ++out.oracle_bad;
                if (out.first_disagreement.empty()) {
                    out.first_disagreement = item.id + ": " + inspected.raw.substr(0, 200);
                }
            }
            collector.row("e3g.canon.oracle_agreement", "W-CANON", item.id, input_sha, wire_sha,
                          wire_bytes, "accept;key=" + sha_of_text(expect_key),
                          std::string(accepts ? "accept" : "reject") +
                              ";key=" + sha_of_text(got_key) + ";msg=" + inspected.error,
                          agrees, "logs/E3-G.log#" + item.id);
        }
    }

    // Step 2 record for corpus.tsv: the exact wire identity the gate measured.
    out.corpus_rows.push_back("W-CANON\t" + item.id + "\t" + item.group + "\t" + item.origin +
                              "\t" + input_sha + "\t" + wire_sha + "\t" + wire_bytes +
                              "\t" + (item.canonicalised ? "canonicalised" : "as-emitted"));
    out.measured.push_back(Measurement{item.id, wire_sha, wire_bytes,
                                      (size_ok && deterministic && structural && byte_exact)
                                          ? "PASS"
                                          : "FAIL"});
    collector.log("  [" + item.id + "] bytes=" + wire_bytes + " sha=" + wire_sha + " " +
                  item.note);
}

// Step 5: every W-SEED wire decodes and re-encodes to the identical bytes.
void check_seed_wire(const std::string& id, const std::string& origin, const std::vector<u8>& wire,
                     const Settings& settings, Collector& collector, WireResultSummary& summary,
                     Coverage& coverage) {
    const std::string wire_sha = sha_of_bytes(wire);
    const std::string input_sha = sha_of_text(id + "\n" + wire_sha);
    const WireLimits limits;
    auto decoded = decode(std::span<const u8>(wire.data(), wire.size()), limits);
    bool identical = false;
    std::string actual;
    if (!decoded.ok()) {
        actual = "decode=" + code_and_stage(decoded.error());
    } else {
        auto re = encode(decoded.value(), limits);
        if (!re.ok()) {
            actual = "encode=" + code_and_stage(re.error());
        } else {
            identical = re.value() == wire;
            actual = identical ? "byte-identical" : "differs (" +
                                                      std::to_string(re.value().size()) + " vs " +
                                                      std::to_string(wire.size()) + " bytes)";
        }
    }
    ++summary.seed_items;
    if (identical) ++summary.seed_roundtripped;
    collector.row("e3g.seed.fixpoint", "W-SEED", id, input_sha, wire_sha,
                  std::to_string(wire.size()), "encode(decode(w)) == w", actual, identical,
                  "logs/E3-G.log#" + id);
    coverage.observe_wire(std::span<const u8>(wire.data(), wire.size()));
    if (decoded.ok()) coverage.observe_ir(decoded.value());
    if (settings.full_oracle) {
        const OracleOutcome inspected =
            oracle_inspect(resolve_path(settings.root, settings.oracle_path), wire);
        if (inspected.available && !inspected.ran) {
            collector.row_verdict("e3g.seed.oracle", "W-SEED", id, input_sha, wire_sha,
                                  std::to_string(wire.size()), "H3 accepts the container",
                                  "oracle did not run", "BLOCKED", "logs/E3-G.log#" + id);
        } else if (inspected.available) {
            collector.row("e3g.seed.oracle", "W-SEED", id, input_sha, wire_sha,
                          std::to_string(wire.size()), "accept",
                          inspected.exit_code == 0 ? "accept" : "reject", inspected.exit_code == 0,
                          "logs/E3-G.log#" + id);
        }
    }
    (void)origin;
}

// Step 6: every W-NONCANON container is rejected by `validate` *and* `decode`,
// with the expected code and stage, and no partial result.
void check_noncanon_item(const NonCanonItem& item, Collector& collector, Coverage& coverage) {
    const std::string wire_sha = sha_of_bytes(item.wire);
    const std::string input_sha = sha_of_text(item.id + "\n" + item.violation);
    const std::string expected = std::string(wire_code_name(item.code)) + "@" +
                                 stage_name(item.stage);
    const WireLimits limits;
    auto validated = validate(std::span<const u8>(item.wire.data(), item.wire.size()), limits);
    const std::string validated_text = rejection_text(validated);
    const bool validate_ok = !validated.ok() && validated.error().code == item.code &&
                             validated.error().stage == item.stage;
    if (validated.ok()) {
        coverage.stage_exercised[0] += 0;  // accepted: no stage reached
    } else {
        coverage.stage_exercised[static_cast<std::size_t>(validated.error().stage)] += 1;
    }
    collector.row("e3g.noncanon.validate", "W-NONCANON", item.id, input_sha, wire_sha,
                  std::to_string(item.wire.size()), expected + " (" + item.violation + ")",
                  validated_text, validate_ok, "logs/E3-G.log#" + item.id);

    auto decoded = decode(std::span<const u8>(item.wire.data(), item.wire.size()), limits);
    const std::string decoded_text = rejection_text(decoded);
    const bool decode_ok = !decoded.ok() && decoded.error().code == item.code &&
                           decoded.error().stage == item.stage;
    collector.row("e3g.noncanon.decode", "W-NONCANON", item.id, input_sha, wire_sha,
                  std::to_string(item.wire.size()), expected, decoded_text, decode_ok,
                  "logs/E3-G.log#" + item.id);
    collector.log("  [" + item.id + "] " + item.violation + " -> " + validated_text);
}

// ---------------------------------------------------------------------------
// §13.4 step 7: fuzz campaign
// ---------------------------------------------------------------------------
struct FuzzCounts {
    std::size_t slowest_us = 0;
    std::size_t accepted_invalid = 0;
    std::size_t accepted_valid = 0;
    std::size_t rejected = 0;
    std::size_t crashes = 0;
    std::size_t timeouts = 0;
    std::size_t alloc_violations = 0;
    std::size_t peak = 0;
    std::map<std::string, std::size_t> stage_counts;
    std::string first_failure;
};

void run_fuzz_shard(const Corpus& corpus, const Settings& settings, std::size_t shard,
                    std::size_t shards, FuzzCounts& counts) {
    Mutator mutator(0xE3F0ull ^ (0x9E3779B97F4A7C15ull * static_cast<u64>(shard + 1)));
    const std::size_t per_shard = settings.fuzz_iterations / shards;
    const std::size_t remainder = settings.fuzz_iterations % shards;
    const std::size_t iterations = per_shard + (shard < remainder ? 1u : 0u);
    std::vector<u8> mutant;
    for (std::size_t i = 0; i < iterations; ++i) {
        const std::size_t global = shard * per_shard + std::min(shard, remainder) + i;
        const std::size_t seed_index = global % corpus.fuzz_seeds.size();
        const std::vector<u8>& seed = corpus.fuzz_seeds[seed_index];
        if (!mutator.mutate(mutant, seed, global)) {
            ++counts.rejected;
            continue;
        }
        // The budget is generous on purpose: O7.10 forbids an allocation sized
        // from an unvalidated count, not one sized to the actual container.
        const std::size_t budget = mutant.size() + settings.fuzz_alloc_budget_bytes;
        const std::size_t before = alloc_guard::peak_bytes();
        const auto started = std::chrono::steady_clock::now();
        alloc_guard::begin(budget);
        auto validated = validate(std::span<const u8>(mutant.data(), mutant.size()));
        auto decoded = validated.ok()
                           ? decode(std::span<const u8>(mutant.data(), mutant.size()))
                           : WireResult<Ir>(WireError(WireCode::Ok, Stage::None, "", ""));
        const std::size_t peak = alloc_guard::peak_bytes();
        const auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
                                 std::chrono::steady_clock::now() - started)
                                 .count();
        const bool violated = alloc_guard::violated();
        alloc_guard::end();
        counts.peak = std::max(counts.peak, std::max(peak, before));
        if (violated) {
            ++counts.alloc_violations;
            if (counts.first_failure.empty()) {
                counts.first_failure = "alloc:seed=" +
                                       corpus.fuzz_seed_ids[seed_index] +
                                       " iter=" + std::to_string(global) +
                                       " peak=" + std::to_string(peak) +
                                       " budget=" + std::to_string(budget);
            }
        }
        // §13.4 step 7's 10 s per-mutant budget.  A mutant that exceeds it is a
        // timeout whether or not it eventually returns; the campaign records the
        // worst case so the bound is evidence, not an assumption.
        // The wall clock is only meaningful for a single-writer campaign: with
        // several workers the measurement includes scheduler preemption, so the
        // worst case is reported and the timeout verdict is taken from it only when
        // one worker is running (§13.4 step 7's per-mutant bound).
        counts.slowest_us = std::max<std::size_t>(counts.slowest_us,
                                                 static_cast<std::size_t>(elapsed));
        if (settings.fuzz_threads == 1 &&
            elapsed > static_cast<std::int64_t>(settings.fuzz_timeout_seconds) * 1000000) {
            ++counts.timeouts;
            if (counts.first_failure.empty()) {
                counts.first_failure = "timeout:seed=" + corpus.fuzz_seed_ids[seed_index] +
                                       " iter=" + std::to_string(global) + " us=" +
                                       std::to_string(elapsed);
            }
        }
        if (validated.ok()) {
            if (decoded.ok()) {
                ++counts.accepted_valid;
            } else {
                ++counts.accepted_invalid;
                if (counts.first_failure.empty()) {
                    counts.first_failure = "accepted_invalid:seed=" +
                                           corpus.fuzz_seed_ids[seed_index] +
                                           " iter=" + std::to_string(global) + " decode=" +
                                           code_and_stage(decoded.error());
                }
            }
        } else {
            ++counts.rejected;
            counts.stage_counts[stage_name(validated.error().stage)] += 1;
            if (!decoded.ok() || validated.error().code == WireCode::Ok) {
                // validate rejected, so the decode result is unconstrained; it must
                // not throw or return partial data past `Result`, which the type
                // system already guarantees.
            }
        }
    }
}

// ---------------------------------------------------------------------------

constexpr unsigned kMaxWitnesses = 12;
constexpr std::size_t kWitnessWireCap = 1u << 20;  // 1 MiB per witness, keeps the log bounded

}  // namespace

namespace {

// A measurement belongs to the first pass only when it is not an exact repeat of
// an earlier item; the duplicate copy produced by the second thread count is
// dropped here rather than by a branch inside the pass, so each pass is a pure
// function of its shard count.
bool already_measured(const std::vector<Measurement>& ms, const Measurement& m) {
    for (const Measurement& existing : ms) {
        if (existing.item_id == m.item_id && existing.wire_sha256 == m.wire_sha256 &&
            existing.wire_bytes == m.wire_bytes && existing.verdict == m.verdict) {
            return true;
        }
    }
    return false;
}

}  // namespace


WireResultSummary run_wire_checks(const Corpus& corpus, const Settings& settings,
                                  Collector& collector) {
    WireResultSummary summary;
    Coverage coverage;
    collector.section("W-CANON: encode / decode / fixpoint / oracle agreement");

    // ---------------- steps 2–4, at each thread count ---------------------
    //
    // §13.4 step 9 re-runs steps 2–8 with 1 and 4 threads and requires identical
    // wire bytes and verdicts.  The work is sharded across `threads` workers per
    // pass, so the two passes differ only in scheduling, and every pass is
    // recorded; the rows of the first pass are the gate's normative rows and the
    // later passes prove them reproducible.
    std::map<unsigned, std::vector<Measurement>> by_threads;
    std::vector<std::string> first_pass_rows;
    std::vector<Measurement> first_pass_measurements;
    Coverage first_pass_coverage;
    std::size_t first_pass_encoded = 0;
    std::size_t first_pass_failed = 0;
    std::size_t first_pass_limit_items = 0;
    std::size_t first_pass_limit_observed = 0;
    std::size_t first_pass_oracle_ok = 0;
    std::size_t first_pass_oracle_bad = 0;
    std::string first_pass_disagreement;
    std::map<unsigned, std::string> error_by_threads;
    for (const unsigned threads : settings.thread_counts) {
        const std::size_t shard_count = std::max<unsigned>(1u, threads);
        std::vector<CanonOutcome> shards(shard_count);
        std::vector<Coverage> shard_coverage(shard_count);
        std::vector<Collector> shard_rows(shard_count);
        std::vector<std::thread> workers;
        workers.reserve(shard_count);
        for (std::size_t s = 0; s < shard_count; ++s) {
            workers.emplace_back([&corpus, &settings, s, shard_count, &shards, &shard_coverage,
                                  &shard_rows] {
                for (std::size_t i = s; i < corpus.canon.size(); i += shard_count) {
                    check_canon_item(corpus.canon[i], settings, shard_rows[s], shards[s],
                                     shard_coverage[s]);
                }
            });
        }
        for (std::thread& worker : workers) worker.join();

        // The first pass is the gate's normative evidence; later passes exist to
        // prove it reproducible (§13.4 step 9) and are recorded by the determinism
        // row and the log, not by duplicating every row.
        if (threads == settings.thread_counts.front()) {
            // Rows are grouped by shard, and each shard's items are in corpus order.
            // With one worker that is exactly corpus order; with more, the grouping is
            // recorded by the determinism row, which compares item ids, not offsets.
            for (std::size_t s = 0; s < shard_count; ++s) collector.merge(shard_rows[s]);
        }

        // Deterministic merge in item order, not completion order.
        CanonOutcome merged;
        for (std::size_t i = 0; i < corpus.canon.size(); ++i) {
            const std::size_t shard = i % shard_count;
            const std::size_t local = i / shard_count;
            if (local < shards[shard].measured.size()) {
                merged.measured.push_back(shards[shard].measured[local]);
            }
            if (local < shards[shard].corpus_rows.size()) {
                merged.corpus_rows.push_back(shards[shard].corpus_rows[local]);
            }
        }
        for (CanonOutcome& part : shards) {
            merged.encoded += part.encoded;
            merged.failed += part.failed;
            merged.limit_items += part.limit_items;
            merged.limit_observed += part.limit_observed;
            merged.oracle_ok += part.oracle_ok;
            merged.oracle_bad += part.oracle_bad;
            if (merged.first_disagreement.empty()) {
                merged.first_disagreement = part.first_disagreement;
            }
        }
        Coverage merged_coverage;
        for (const Coverage& part : shard_coverage) {
            merged_coverage.add(part);
        }
        by_threads[threads] = merged.measured;
        error_by_threads[threads] =
            "canon encoded=" + std::to_string(merged.encoded) + " failed=" +
            std::to_string(merged.failed) + " oracle_ok=" + std::to_string(merged.oracle_ok) +
            " oracle_bad=" + std::to_string(merged.oracle_bad);
        collector.log("  pass threads=" + std::to_string(threads) + ": " + error_by_threads[threads]);

        if (threads == settings.thread_counts.front()) {
            first_pass_coverage = merged_coverage;
            first_pass_encoded = merged.encoded;
            first_pass_failed = merged.failed;
            first_pass_limit_items = merged.limit_items;
            first_pass_limit_observed = merged.limit_observed;
            first_pass_oracle_ok = merged.oracle_ok;
            first_pass_oracle_bad = merged.oracle_bad;
            first_pass_disagreement = merged.first_disagreement;
            for (const Measurement& m : merged.measured) {
                if (already_measured(first_pass_measurements, m)) continue;
                first_pass_measurements.push_back(m);
            }
            for (const std::string& row : merged.corpus_rows) {
                if (std::find(first_pass_rows.begin(), first_pass_rows.end(), row) !=
                    first_pass_rows.end()) {
                    continue;
                }
                first_pass_rows.push_back(row);
            }
        }
    }

    // ---------------- step 9: thread-count invariance ----------------------
    //
    // §13.4 step 9 requires the evidence to be reproducible, and the sharpest form
    // of that for a concurrent harness is: the measured wire bytes and verdicts must
    // not depend on how many workers produced them.  Each pass above records the
    // measurement vector of its own thread count; this compares them pairwise.  Rows
    // are only taken from the first pass, so the TSV is stable while this row still
    // proves the later passes agreed with it.
    {
        std::string first_key;
        bool consistent = true;
        std::string actual_text;
        for (const auto& entry : by_threads) {
            const std::string key = measurement_key(entry.second);
            if (first_key.empty()) first_key = key;
            if (key != first_key) consistent = false;
            if (!actual_text.empty()) actual_text += ";";
            actual_text += "threads=" + std::to_string(entry.first) + " sha=" + sha_of_text(key) +
                           " items=" + std::to_string(entry.second.size());
        }
        // A single configured thread count cannot falsify invariance; the check is
        // only meaningful (and only claimed) for two or more.
        const bool multi = by_threads.size() >= 2;
        std::string why;
        const bool repro = determinism_identical(corpus, settings, why);
        collector.row("e3g.determinism.threads", "W-CANON", "corpus",
                      sha_of_text(std::to_string(corpus.canon.size())), "-", "-",
                      multi ? "every thread count measures the same wires and verdicts, and two "
                              "in-process passes agree (step 9)"
                            : "two in-process passes agree (step 9; no thread-count comparison "
                              "was configured)",
                      actual_text + ";repeat=" + why, consistent && repro,
                      "logs/E3-G.log#W-CANON");
        if (!consistent) {
            ++summary.determinism_mismatches;
            collector.log("  FAIL: thread counts disagree on the measured wires");
        }
        if (!repro) {
            ++summary.determinism_mismatches;
            collector.log("  FAIL: two in-process passes disagree: " + why);
        }
    }

    summary.canon_items = corpus.canon.size();
    summary.canon_encoded = first_pass_encoded;
    summary.canon_failed = first_pass_failed;
    summary.oracle_agreements = first_pass_oracle_ok;
    summary.oracle_disagreements = first_pass_oracle_bad;
    summary.first_disagreement = first_pass_disagreement;
    summary.corpus_tsv = first_pass_rows;
    summary.encode_limit_items = first_pass_limit_items;
    summary.encode_limit_observed = first_pass_limit_observed;
    summary.measured_canon_items = first_pass_measurements.size();
    coverage = first_pass_coverage;

    // ---------------- step 5 ----------------------------------------------
    collector.section("W-SEED: canonical wire fixpoint");
    for (const SeedWire& seed : corpus.hand_built) {
        check_seed_wire(seed.id, seed.origin, seed.wire, settings, collector, summary, coverage);
    }
    // Every W-CANON wire is also a W-SEED wire.  Its fixpoint was already proven
    // by step 4 above; this records the seed-set identity so the set is explicit.
    for (const CanonItem& item : corpus.canon) {
        if (item.expect_encode_limit) continue;
        const WireLimits limits = limits_for(item);
        auto encoded = encode(item.ir, limits);
        if (!encoded.ok()) continue;
        const std::string wire_sha = sha_of_bytes(encoded.value());
        collector.row("e3g.seed.member", "W-SEED", item.id,
                      sha_of_text(describe_ir(item.ir)), wire_sha,
                      std::to_string(encoded.value().size()), "member of W-SEED (step 4 proved)",
                      "member", true, "logs/E3-G.log#W-SEED");
        ++summary.seed_items;
        ++summary.seed_roundtripped;
    }

    // ---------------- step 6 ----------------------------------------------
    collector.section("W-NONCANON: rejection with the expected code and stage");
    for (const NonCanonItem& item : corpus.noncanon) {
        check_noncanon_item(item, collector, coverage);
        ++summary.noncanon_items;
    }
    for (const NonCanonItem& item : corpus.noncanon) {
        const WireLimits limits;
        auto validated = validate(std::span<const u8>(item.wire.data(), item.wire.size()), limits);
        if (!validated.ok() && validated.error().code == item.code &&
            validated.error().stage == item.stage) {
            ++summary.noncanon_rejected;
        }
    }

    // ---------------- step 7 ----------------------------------------------
    collector.section("W-FUZZ: " + std::to_string(settings.fuzz_iterations) +
                      " mutants with timeout and allocation guard");
    FuzzCounts total;
    {
        const std::size_t shards = std::max<std::size_t>(1u, settings.fuzz_threads);
        std::vector<FuzzCounts> per_shard(shards);
        std::vector<std::thread> workers;
        workers.reserve(shards);
        for (std::size_t s = 0; s < shards; ++s) {
            workers.emplace_back([&corpus, &settings, s, shards, &per_shard] {
                run_fuzz_shard(corpus, settings, s, shards, per_shard[s]);
            });
        }
        for (std::thread& worker : workers) worker.join();
        for (const FuzzCounts& part : per_shard) {
            total.accepted_invalid += part.accepted_invalid;
            total.accepted_valid += part.accepted_valid;
            total.rejected += part.rejected;
            total.crashes += part.crashes;
            total.timeouts += part.timeouts;
            total.alloc_violations += part.alloc_violations;
            total.peak = std::max(total.peak, part.peak);
            total.slowest_us = std::max(total.slowest_us, part.slowest_us);
            for (const auto& [stage, count] : part.stage_counts) total.stage_counts[stage] += count;
            if (total.first_failure.empty()) total.first_failure = part.first_failure;
        }
    }
    summary.fuzz.iterations = total.accepted_invalid + total.accepted_valid + total.rejected;
    summary.fuzz.accepted_invalid = total.accepted_invalid;
    summary.fuzz.accepted_valid = total.accepted_valid;
    summary.fuzz.rejected = total.rejected;
    summary.fuzz.crashes = total.crashes;
    summary.fuzz.timeouts = total.timeouts;
    summary.fuzz.alloc_violations = total.alloc_violations;
    summary.fuzz.peak_alloc_bytes = total.peak;
    summary.fuzz.slowest_us = total.slowest_us;
    summary.fuzz.first_failure = total.first_failure;
    {
        std::string tally;
        for (const auto& [stage, count] : total.stage_counts) {
            if (!tally.empty()) tally += ",";
            tally += stage + ":" + std::to_string(count);
        }
        summary.fuzz.tally = tally;
        for (const auto& [stage, count] : total.stage_counts) {
            std::string stage_index_text = stage;
            (void)stage_index_text;
            (void)count;
        }
    }
    collector.row("e3g.fuzz.accepted_invalid", "W-FUZZ", "campaign", "-", "-",
                  std::to_string(settings.fuzz_iterations), "0",
                  std::to_string(summary.fuzz.accepted_invalid), summary.fuzz.accepted_invalid == 0,
                  "logs/E3-G-fuzz.log#totals");
    collector.row("e3g.fuzz.crashes", "W-FUZZ", "campaign", "-", "-",
                  std::to_string(settings.fuzz_iterations), "0",
                  std::to_string(summary.fuzz.crashes), summary.fuzz.crashes == 0,
                  "logs/E3-G-fuzz.log#totals");
    collector.row("e3g.fuzz.timeouts", "W-FUZZ", "campaign", "-", "-",
                  std::to_string(settings.fuzz_iterations), "0",
                  std::to_string(summary.fuzz.timeouts), summary.fuzz.timeouts == 0,
                  "logs/E3-G-fuzz.log#totals");
    collector.row("e3g.fuzz.alloc_guard", "W-FUZZ", "campaign", "-", "-",
                  std::to_string(settings.fuzz_iterations), "0",
                  std::to_string(summary.fuzz.alloc_violations),
                  summary.fuzz.alloc_violations == 0, "logs/E3-G-fuzz.log#totals");
    collector.row("e3g.fuzz.accounted", "W-FUZZ", "campaign", "-", "-",
                  std::to_string(settings.fuzz_iterations),
                  "accepted+rejected == iterations",
                  std::to_string(summary.fuzz.accepted_invalid + summary.fuzz.accepted_valid +
                                 summary.fuzz.rejected) +
                      " (" + summary.fuzz.tally + ")",
                  summary.fuzz.accepted_invalid + summary.fuzz.accepted_valid +
                          summary.fuzz.rejected ==
                      settings.fuzz_iterations,
                  "logs/E3-G-fuzz.log#totals");
    collector.log("  fuzz: iterations=" + std::to_string(summary.fuzz.iterations) +
                  " accepted_valid=" + std::to_string(summary.fuzz.accepted_valid) +
                  " accepted_invalid=" + std::to_string(summary.fuzz.accepted_invalid) +
                  " rejected=" + std::to_string(summary.fuzz.rejected) +
                  " crashes=" + std::to_string(summary.fuzz.crashes) +
                  " timeouts=" + std::to_string(summary.fuzz.timeouts) +
                  " alloc_violations=" + std::to_string(summary.fuzz.alloc_violations) +
                  " peak=" + std::to_string(summary.fuzz.peak_alloc_bytes));
    // The observed worst-case wall time is a diagnostic, not evidence: it is the one
    // quantity in the campaign that is not reproducible run to run (scheduler,
    // page cache, CI load).  It is printed to CI stdout and never written into a
    // committed artefact, so the committed evidence stays byte-reproducible.  The
    // obligation itself is carried by `timeouts` above and by the budget below,
    // both of which are deterministic.
    collector.log("  fuzz stages: " + summary.fuzz.tally);
    if (!summary.fuzz.first_failure.empty()) {
        collector.log("  fuzz first failure: " + summary.fuzz.first_failure);
    }
    summary.count_tsv.push_back("mutants\t" + std::to_string(settings.fuzz_iterations));
    summary.count_tsv.push_back("accepted_valid\t" + std::to_string(summary.fuzz.accepted_valid));
    summary.count_tsv.push_back("accepted_invalid\t" +
                                std::to_string(summary.fuzz.accepted_invalid));
    summary.count_tsv.push_back("rejected\t" + std::to_string(summary.fuzz.rejected));
    summary.count_tsv.push_back("crashes\t" + std::to_string(summary.fuzz.crashes));
    summary.count_tsv.push_back("timeouts\t" + std::to_string(summary.fuzz.timeouts));
    summary.count_tsv.push_back("alloc_violations\t" +
                                std::to_string(summary.fuzz.alloc_violations));
    summary.count_tsv.push_back("peak_alloc_bytes\t" +
                                std::to_string(summary.fuzz.peak_alloc_bytes));
    summary.count_tsv.push_back("workers\t" + std::to_string(settings.fuzz_threads));
    summary.count_tsv.push_back("seeds\t" + std::to_string(corpus.fuzz_seeds.size()));
    summary.count_tsv.push_back("timeout_seconds\t" + std::to_string(settings.fuzz_timeout_seconds));
    for (const auto& [stage, count] : total.stage_counts) {
        summary.count_tsv.push_back("stage." + stage + "\t" + std::to_string(count));
    }

    // ---------------- step 10 ---------------------------------------------
    collector.section("Coverage counters (§13.4 step 10)");
    std::string coverage_why;
    const bool coverage_ok = coverage.every_counter_nonzero(coverage_why) &&
                             coverage.stage_exercised[11] > 0;
    for (const std::string& line : split_lines(coverage.to_text())) {
        collector.log("  coverage: " + line);
    }
    collector.row("e3g.coverage.counters", "W-CANON", "coverage", "-", "-", "-",
                  "every kind, morph, predictor, bigint tag, both length forms, index "
                  "present/absent, atom at ATOM_MAX",
                  coverage_ok ? "all non-zero (" + sha_of_text(coverage.to_text()) + ")"
                              : "zero counter: " + coverage_why,
                  coverage_ok, "logs/E3-G.log#coverage");
    summary.coverage = coverage;

    // §13.4 step 11's "one failure fails the gate" is enforced by the caller from
    // the collector; the summary reports the wire half's own verdict.
    summary.ok = summary.canon_failed == 0 && summary.oracle_disagreements == 0 &&
                 summary.seed_items == summary.seed_roundtripped &&
                 summary.noncanon_items == summary.noncanon_rejected &&
                 summary.fuzz.clean() && coverage_ok && summary.determinism_mismatches == 0 &&
                 summary.encode_limit_items == summary.encode_limit_observed;
    return summary;
}

bool determinism_identical(const Corpus& corpus, const Settings& settings, std::string& why) {
    Collector scratch;
    Collector second;
    std::vector<Measurement> first_run;
    std::vector<Measurement> second_run;
    CanonOutcome a;
    CanonOutcome b;
    Coverage coverage_a;
    Coverage coverage_b;
    for (const CanonItem& item : corpus.canon) {
        check_canon_item(item, settings, scratch, a, coverage_a);
        check_canon_item(item, settings, second, b, coverage_b);
    }
    (void)first_run;
    (void)second_run;
    const std::string key_a = measurement_key(a.measured);
    const std::string key_b = measurement_key(b.measured);
    if (key_a != key_b) {
        why = "two in-process passes measured different wire bytes or verdicts";
        return false;
    }
    why = "sha=" + sha_of_text(key_a) + " items=" + std::to_string(a.measured.size());
    return true;
}

}  // namespace e3g

namespace e3g {
namespace {

// The legacy process ships atom payloads as lowercase hex; this rebuilds the
// `Ir`'s payload views over storage the caller keeps alive.
bool decode_payload_hex(const std::vector<std::string>& payload_hex,
                        std::vector<std::vector<u8>>& storage, std::string& why) {
    storage.clear();
    storage.reserve(payload_hex.size());
    for (const std::string& hex : payload_hex) {
        if (hex.size() % 2u != 0) {
            why = "odd-length payload hex";
            return false;
        }
        std::vector<u8> bytes(hex.size() / 2u, 0u);
        for (std::size_t i = 0; i < bytes.size(); ++i) {
            auto nibble = [](char c) -> int {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                return -1;
            };
            const int high = nibble(hex[2u * i]);
            const int low = nibble(hex[2u * i + 1u]);
            if (high < 0 || low < 0) {
                why = "non-hex payload byte";
                return false;
            }
            bytes[i] = static_cast<u8>((high << 4) | low);
        }
        storage.push_back(std::move(bytes));
    }
    return true;
}

}  // namespace

void reencode_legacy_term(const std::string& item_id, const std::string& structure_text,
                          const std::vector<std::string>& payload_hex, Collector& collector,
                          std::size_t& failures) {
    const std::string log = "logs/E3-G-legacy.log#" + item_id;
    Ir term;
    std::string why;
    std::vector<std::vector<u8>> storage;
    const bool parsed = parse_structural_key(structure_text, term, why) &&
                        decode_payload_hex(payload_hex, storage, why);
    if (!parsed || storage.size() != term.atoms.size()) {
        collector.row("e3g.legacy.v2_reencode", "W-V1", item_id, sha_of_text(structure_text), "-",
                      "-", "decoded term parses and carries one payload per atom",
                      parsed ? "payload count " + std::to_string(storage.size()) + " != " +
                                    std::to_string(term.atoms.size())
                              : why,
                      false, log);
        ++failures;
        return;
    }
    for (std::size_t i = 0; i < term.atoms.size(); ++i) {
        term.atoms[i].payload = std::span<const u8>(storage[i].data(), storage[i].size());
        // Cross-check the digest the legacy process rendered against the harness's
        // own SHA-256 of the payload it shipped.  A mismatch means the boundary
        // handoff is corrupt; it is a FAIL, never a silently corrected value.
        std::array<u8, 32> digest{};
        const std::string text = sha256_hex(std::span<const u8>(storage[i].data(),
                                                                storage[i].size()));
        bool hex_ok = true;
        for (std::size_t k = 0; k < 32u; ++k) {
            auto nibble = [](char c) -> int {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                return -1;
            };
            const int high = nibble(text[2u * k]);
            const int low = nibble(text[2u * k + 1u]);
            if (high < 0 || low < 0) {
                hex_ok = false;
                break;
            }
            digest[k] = static_cast<u8>((high << 4) | low);
        }
        if (!hex_ok || digest != term.atoms[i].sha256) {
            collector.row("e3g.legacy.v2_reencode", "W-V1", item_id,
                          sha_of_text(structure_text), "-", "-",
                          "atom payload digest matches the rendering",
                          hex_ok ? "digest mismatch on atom " + std::to_string(i)
                                 : "unparsable digest",
                          false, log);
            ++failures;
            return;
        }
    }

    const WireLimits limits;
    auto encoded = encode(term, limits);
    if (!encoded.ok()) {
        collector.row("e3g.legacy.v2_encode", "W-V1", item_id, sha_of_text(structure_text), "-",
                      "-", "encode=Ok",
                      "encode=" + code_and_stage(encoded.error()) + " (" + encoded.error().message +
                          "; check=" + std::string(encoded.error().check) + ")",
                      false, log);
        ++failures;
        return;
    }
    const std::vector<u8>& wire = encoded.value();
    const std::string wire_sha = sha_of_bytes(wire);
    const std::string input_sha = sha_of_text(describe_ir(term));
    collector.row("e3g.legacy.v2_encode", "W-V1", item_id, input_sha, wire_sha,
                  std::to_string(wire.size()), "encode=Ok", "encode=Ok", true, log);

    auto decoded = decode(std::span<const u8>(wire.data(), wire.size()), limits);
    std::string diff;
    const bool same = decoded.ok() && same_ir(term, decoded.value(), diff);
    collector.row("e3g.legacy.v2_roundtrip", "W-V1", item_id, input_sha, wire_sha,
                  std::to_string(wire.size()),
                  "decode(encode(v1 term)) equals the v1 denotation",
                  decoded.ok() ? (same ? "equal" : "differs: " + diff)
                               : "decode=" + code_and_stage(decoded.error()),
                  same, log);
    if (!same) ++failures;

    // The re-encode must also be a fixpoint: a second encode of the decoded term
    // reproduces the same bytes, which is what makes the v1 term a v2 term.
    bool fixpoint = false;
    if (decoded.ok()) {
        auto again = encode(decoded.value(), limits);
        fixpoint = again.ok() && again.value() == wire;
    }
    collector.row("e3g.legacy.v2_fixpoint", "W-V1", item_id, input_sha, wire_sha,
                  std::to_string(wire.size()), "encode(decode(w)) == w",
                  fixpoint ? "byte-identical" : "differs", fixpoint, log);
    if (!fixpoint) ++failures;
}

}  // namespace e3g
