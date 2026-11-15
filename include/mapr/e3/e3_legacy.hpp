#pragma once

#include <mapr/e1_types.hpp>
#include <mapr/e2/e2_term.hpp>

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace marp::v2 {

#ifndef MAPR_E3_WIRE_TYPES_DEFINED
#define MAPR_E3_WIRE_TYPES_DEFINED

// Unified v2 wire / boundary error codes (SPECS-V2 §11.1, COMPONENTS-V2 §3, E3 §10).
// Kept distinct from frozen E2's 3-valued marp::v2::Code so E2 headers remain untouched.
enum class WireCode : int {
    Ok = 0,
    Usage = 2,
    Io = 3,
    Invalid = 4,
    Unsupported = 5,
    Mismatch = 6,
    Limit = 7,
};

[[nodiscard]] constexpr const char* wire_code_name(WireCode c) noexcept {
    switch (c) {
        case WireCode::Ok: return "Ok";
        case WireCode::Usage: return "Usage";
        case WireCode::Io: return "Io";
        case WireCode::Invalid: return "Invalid";
        case WireCode::Unsupported: return "Unsupported";
        case WireCode::Mismatch: return "Mismatch";
        case WireCode::Limit: return "Limit";
    }
    return "Unknown";
}

struct WireErr {
    WireCode code = WireCode::Invalid;
    std::string what{};

    friend bool operator==(const WireErr&, const WireErr&) = default;
};

template <class T>
class WireResult {
public:
    WireResult(T value) : storage_(std::move(value)) {}
    WireResult(WireErr err) : storage_(std::move(err)) {}
    WireResult(WireCode code, std::string what = {})
        : storage_(WireErr{code, std::move(what)}) {}

    [[nodiscard]] bool ok() const noexcept {
        return std::holds_alternative<T>(storage_);
    }
    [[nodiscard]] explicit operator bool() const noexcept { return ok(); }

    [[nodiscard]] WireCode code() const noexcept {
        return ok() ? WireCode::Ok : std::get<WireErr>(storage_).code;
    }

    [[nodiscard]] const WireErr& error() const noexcept {
        return std::get<WireErr>(storage_);
    }

    [[nodiscard]] T& value() & { return std::get<T>(storage_); }
    [[nodiscard]] const T& value() const& { return std::get<T>(storage_); }
    [[nodiscard]] T&& value() && { return std::get<T>(std::move(storage_)); }

private:
    std::variant<T, WireErr> storage_;
};

// Random-access byte source (SPECS/COMPONENTS/e3-wire/SPECS.md §9).
// Implementations MUST NOT perform network access or ambient path lookup inside decode.
struct Source {
    virtual ~Source() = default;

    [[nodiscard]] virtual u64 size() const noexcept = 0;

    // Reads exactly `dst.size()` bytes starting at `offset`.
    // Returns:
    //   - WireCode::Ok      when all requested bytes are copied into `dst`;
    //   - WireCode::Invalid when `offset + dst.size() > size()`;
    //   - WireCode::Io      when the underlying random-access medium fails.
    [[nodiscard]] virtual WireCode read(u64 offset, std::span<u8> dst) = 0;
};

// Zero-copy in-memory Source backed by a caller byte span.
class SpanSource final : public Source {
public:
    constexpr explicit SpanSource(std::span<const u8> bytes) noexcept : bytes_(bytes) {}

    [[nodiscard]] u64 size() const noexcept override {
        return static_cast<u64>(bytes_.size());
    }

    [[nodiscard]] WireCode read(u64 offset, std::span<u8> dst) override;

private:
    std::span<const u8> bytes_;
};

// Stable byte arena for decoded Atom payloads (SPECS/COMPONENTS-V2.md §3 & §5 C08).
// Returned spans remain valid for the lifetime of the Arena.
struct Arena {
    virtual ~Arena() = default;

    [[nodiscard]] virtual WireResult<std::span<const u8>> store(
        std::span<const u8> bytes) = 0;
};

// Bounded heap-backed Arena with stable block addresses and explicit byte cap.
class HeapArena final : public Arena {
public:
    static constexpr std::size_t kDefaultMaxBytes = 256ULL * 1024ULL * 1024ULL;

    explicit HeapArena(std::size_t max_bytes = kDefaultMaxBytes) noexcept
        : max_bytes_(max_bytes) {}

    [[nodiscard]] WireResult<std::span<const u8>> store(
        std::span<const u8> bytes) override;

    [[nodiscard]] std::size_t used_bytes() const noexcept { return used_bytes_; }
    [[nodiscard]] std::size_t max_bytes() const noexcept { return max_bytes_; }

private:
    std::size_t max_bytes_ = kDefaultMaxBytes;
    std::size_t used_bytes_ = 0;
    std::vector<std::vector<u8>> blocks_{};
};

#endif // MAPR_E3_WIRE_TYPES_DEFINED

// Resource caps for C08 read-only legacy v1 decode (E3 §8.3, SPECS.md §2.4).
// Structural / truncation violations always return WireCode::Invalid before any cap check;
// exceeding an explicit resource cap on an otherwise structurally sound header/frame returns Limit.
struct LegacyLimits {
    u64 max_chunks = 1'048'576ULL;
    u64 max_output_bytes = 256ULL * 1024ULL * 1024ULL;
    u64 max_chunk_payload_bytes = 64ULL * 1024ULL * 1024ULL;
    u64 max_dag_nodes_per_chunk = 33'554'448ULL;
    u64 max_eval_working_bytes = 512ULL * 1024ULL * 1024ULL;
};

// C08 LEGACY — magic probe only (SPECS/COMPONENTS/e3-wire/SPECS.md §6.3, §9).
// True iff `src` is at least 8 bytes and begins with the frozen v1 magic
// 89 4D 41 50 52 0D 0A 1A ("\x89MAPR\r\n\x1a"). Never decodes or allocates.
[[nodiscard]] bool looks_like_v1(Source& src) noexcept;
[[nodiscard]] bool looks_like_v1(std::span<const u8> bytes) noexcept;

// C08 LEGACY — read-only decoder for frozen MARP v1.0.1 and v1.1 containers.
// Produces a canonical, well-formed v2 Ir whose byte denotation matches the v1 payload
// bit-for-bit and satisfies trailer SHA-256 verification.
// Unsupported legacy versions or non-representable/external v1 features return Unsupported.
// Atom payloads in the Arena overloads point into `arena` (Atom::owner is empty).
[[nodiscard]] WireResult<Ir> decode_v1(Source& src,
                                       Arena& arena,
                                       const LegacyLimits& limits = {});

// Convenience overload: Atom payloads are owned by Atom::owner inside Ir.
[[nodiscard]] WireResult<Ir> decode_v1(Source& src,
                                       const LegacyLimits& limits = {});

// Span convenience overloads.
[[nodiscard]] WireResult<Ir> decode_v1(std::span<const u8> bytes,
                                       Arena& arena,
                                       const LegacyLimits& limits = {});
[[nodiscard]] WireResult<Ir> decode_v1(std::span<const u8> bytes,
                                       const LegacyLimits& limits = {});

namespace legacy {
using Code = WireCode;
using Err = WireErr;
template <class T>
using Result = WireResult<T>;
using marp::v2::Arena;
using marp::v2::HeapArena;
using marp::v2::LegacyLimits;
using marp::v2::Source;
using marp::v2::SpanSource;
using marp::v2::decode_v1;
using marp::v2::looks_like_v1;
} // namespace legacy

} // namespace marp::v2
