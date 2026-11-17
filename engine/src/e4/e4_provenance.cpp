// MARP v2 — E4 MEASURE — C09 PROVENANCE (implementation).
//
// One streaming pass: the buffer is filled by `Source::read`, then handed to
// E1's `Sha256` and E1's `GearHash` in the same iteration.  The input is never
// materialised, no whole-input buffer exists, and the working set is a single
// fixed 64 KiB block plus two hash states (E4 §11: "Provenance is one streaming
// pass: O(1) memory").
//
// Determinism (E4-I1): the only inputs to the result are the bytes and the
// policy's effort.  There is no global mutable state, no static cache, no
// clock, no locale, no thread, and no hash-map iteration.  The gear table used
// is E1's fixed 256-entry table; the SHA-256 is E1's FIPS 180-4 implementation.

#include "mapr/e4/e4_measure.hpp"

#include <cstring>
#include <string_view>

#include "mapr/e1_gear.hpp"
#include "mapr/e1_sha256.hpp"

namespace marp::v2 {

namespace {

// E4 §11 asks for O(1) working memory; 64 KiB is the same block the project's
// other streaming hashers use and it is a constant, not a function of L.
constexpr std::size_t kBlockBytes = 64u * 1024u;

inline std::string hex_of(std::span<const u8> bytes) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2u);
    for (const u8 b : bytes) {
        out.push_back(kHex[(b >> 4) & 0x0Fu]);
        out.push_back(kHex[b & 0x0Fu]);
    }
    return out;
}

inline std::string u64_hex(u64 value) {
    std::array<u8, 8> be{};
    for (std::size_t i = 0; i < 8u; ++i) {
        be[i] = static_cast<u8>((value >> (8u * (7u - i))) & 0xFFu);  // big-endian text form
    }
    return hex_of(be);
}

}  // namespace

// ---------------------------------------------------------------------------
// SpanSource
// ---------------------------------------------------------------------------

MeasureCode SpanSource::read(const BigInt& off, std::span<u8> dst) const noexcept {
    const std::optional<u64> offset = off.to_u64_checked();
    if (!offset.has_value()) return MeasureCode::Io;
    const u64 start = *offset;
    const u64 length = static_cast<u64>(data_.size());
    if (start > length) return MeasureCode::Io;
    if (static_cast<u64>(dst.size()) > length - start) return MeasureCode::Io;
    if (!dst.empty()) {
        std::memcpy(dst.data(), data_.data() + static_cast<std::size_t>(start), dst.size());
    }
    return MeasureCode::Ok;
}

// ---------------------------------------------------------------------------
// Seed (E4 §4.3)
// ---------------------------------------------------------------------------

MeasureResult<u64> derive_seed(std::span<const u8, 32> digest, u8 effort) noexcept {
    if (!effort_in_domain(static_cast<u32>(effort))) return MeasureCode::Invalid;

    // payload = "MARP2-seed" || LE32(effort) || sha256(x)   (11 + 4 + 32 = 47 B)
    std::array<u8, kSeedDomainLen + 4u + 32u> payload{};
    for (std::size_t i = 0; i < kSeedDomainLen; ++i) {
        payload[i] = static_cast<u8>(kSeedDomain[i]);
    }
    payload[kSeedDomainLen + 0u] = static_cast<u8>(effort & 0xFFu);
    payload[kSeedDomainLen + 1u] = 0u;
    payload[kSeedDomainLen + 2u] = 0u;
    payload[kSeedDomainLen + 3u] = 0u;
    for (std::size_t i = 0; i < 32u; ++i) {
        payload[kSeedDomainLen + 4u + i] = digest[i];
    }

    const auto hashed = mapr::Sha256::hash(std::string_view(
        reinterpret_cast<const char*>(payload.data()), payload.size()));
    if (!hashed.ok()) return MeasureCode::Invalid;

    // seed = LE64(digest[0..8)) — the first eight bytes read as a little-endian
    // integer.  The byte order is fixed by the specification and is independent
    // of host endianness because it is assembled byte by byte.
    const std::array<u8, 32>& d = hashed.value();
    u64 seed = 0;
    for (std::size_t i = 0; i < 8u; ++i) {
        seed |= static_cast<u64>(d[i]) << (8u * i);
    }
    return seed;
}

// ---------------------------------------------------------------------------
// Provenance (E4 §4.3, §5.1)
// ---------------------------------------------------------------------------

MeasureResult<Provenance> provenance(Source& source, const Policy& policy) {
    if (!effort_in_domain(static_cast<u32>(policy.effort))) return MeasureCode::Invalid;

    const BigInt declared = source.size();
    if (declared.compare(BigInt::zero()) < 0) return MeasureCode::Io;  // impossible; contract

    mapr::Sha256 sha;
    mapr::GearHash gear(mapr::GEAR_SEED_DEFAULT);

    std::array<u8, kBlockBytes> block{};
    BigInt pos = BigInt::zero();
    BigInt remaining = declared;

    // The loop condition is the exact remaining byte count, so a source that
    // under-delivers is a short read (`Io`), never a truncated digest.
    while (remaining.compare(BigInt::zero()) > 0) {
        const std::optional<u64> left = remaining.to_u64_checked();
        if (!left.has_value()) return MeasureCode::Io;  // cannot size one block
        std::size_t want = kBlockBytes;
        if (*left < static_cast<u64>(want)) {
            want = static_cast<std::size_t>(*left);
        }

        const std::span<u8> dst(block.data(), want);
        const MeasureCode rc = source.read(pos, dst);
        if (rc != MeasureCode::Ok) return MeasureCode::Io;

        const std::string_view chunk(reinterpret_cast<const char*>(block.data()), want);
        if (sha.update(chunk) != mapr::ErrCode::Ok) return MeasureCode::Invalid;
        gear.update(chunk);

        const BigInt step(static_cast<u64>(want));
        auto next_pos = pos.add(step);
        if (!next_pos.ok()) return MeasureCode::Io;
        auto next_remaining = remaining.sub(step);
        if (!next_remaining.ok()) return MeasureCode::Io;  // cannot happen: want <= remaining
        pos = std::move(next_pos.value());
        remaining = std::move(next_remaining.value());
    }

    const auto digest = sha.finish();
    if (!digest.ok()) return MeasureCode::Invalid;

    Provenance prov;
    prov.length = declared;
    prov.sha256 = digest.value();
    prov.gear = gear.finish();

    const auto seed = derive_seed(prov.sha256, policy.effort);
    if (!seed.ok()) return seed.code();
    prov.seed = seed.value();
    return prov;
}

// ---------------------------------------------------------------------------
// Re-verification (E4 §5.2 precondition, §9 Mismatch)
// ---------------------------------------------------------------------------

MeasureStatus provenance_matches(Source& source, const Provenance& prov, const Policy& policy) {
    const MeasureResult<Provenance> fresh = provenance(source, policy);
    if (!fresh.ok()) return fresh.code();

    const Provenance& other = fresh.value();
    if (other.length != prov.length) return MeasureCode::Mismatch;
    if (!same_digest(other.sha256, prov.sha256)) return MeasureCode::Mismatch;
    if (other.gear != prov.gear) return MeasureCode::Mismatch;
    if (other.seed != prov.seed) return MeasureCode::Mismatch;
    return MeasureStatus{};
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

std::string provenance_text(const Provenance& prov) {
    std::string out;
    out.reserve(64u + 24u + 3u * 24u);
    out += "length=";
    out += prov.length.to_decimal();
    out += ";sha256=";
    out += hex_of(prov.sha256);
    out += ";gear=0x";
    out += u64_hex(prov.gear);
    out += ";seed=0x";
    out += u64_hex(prov.seed);
    return out;
}

}  // namespace marp::v2
