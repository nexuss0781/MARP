// MARP v2 — H4 FUZZ — per-mutant allocation guard (implementation).
//
// Adapted from the same technique E3-G uses for O7.10: every block records its
// payload size and whether it was allocated while the guard was armed, so an
// epoch's accounting cannot be corrupted by the harness's own long-lived
// allocations.  Counters are thread-local; H4 processes one mutant at a time in
// one worker, so a per-mutant peak is not contaminated by another worker's
// allocations and the reported peak is reproducible.
//
// Linked only into `engine/bin/h4_fuzz*`; nothing in E3 links this file.

#include "h4_alloc_guard.hpp"

#include <cstdlib>
#include <new>

namespace marp::harness::h4::alloc_guard {

// Allocation entry points used by the replaced global operators below.  They
// are deliberately not part of the public guard surface.
void* raw_allocate(std::size_t size, std::size_t alignment);
void raw_release(void* pointer) noexcept;

}  // namespace marp::harness::h4::alloc_guard

#if !defined(H4_ALLOC_GUARD_DISABLED)

void* operator new(std::size_t size) {
    return marp::harness::h4::alloc_guard::raw_allocate(size, alignof(std::max_align_t));
}
void* operator new[](std::size_t size) {
    return marp::harness::h4::alloc_guard::raw_allocate(size, alignof(std::max_align_t));
}
void* operator new(std::size_t size, std::align_val_t alignment) {
    return marp::harness::h4::alloc_guard::raw_allocate(size, static_cast<std::size_t>(alignment));
}
void* operator new[](std::size_t size, std::align_val_t alignment) {
    return marp::harness::h4::alloc_guard::raw_allocate(size, static_cast<std::size_t>(alignment));
}
void* operator new(std::size_t size, const std::nothrow_t&) noexcept {
    try {
        return marp::harness::h4::alloc_guard::raw_allocate(size, alignof(std::max_align_t));
    } catch (...) {
        return nullptr;
    }
}
void* operator new[](std::size_t size, const std::nothrow_t&) noexcept {
    try {
        return marp::harness::h4::alloc_guard::raw_allocate(size, alignof(std::max_align_t));
    } catch (...) {
        return nullptr;
    }
}
void* operator new(std::size_t size, std::align_val_t alignment, const std::nothrow_t&) noexcept {
    try {
        return marp::harness::h4::alloc_guard::raw_allocate(size, static_cast<std::size_t>(alignment));
    } catch (...) {
        return nullptr;
    }
}
void* operator new[](std::size_t size, std::align_val_t alignment, const std::nothrow_t&) noexcept {
    try {
        return marp::harness::h4::alloc_guard::raw_allocate(size, static_cast<std::size_t>(alignment));
    } catch (...) {
        return nullptr;
    }
}
void operator delete(void* pointer) noexcept {
    marp::harness::h4::alloc_guard::raw_release(pointer);
}
void operator delete[](void* pointer) noexcept {
    marp::harness::h4::alloc_guard::raw_release(pointer);
}
void operator delete(void* pointer, std::size_t) noexcept {
    marp::harness::h4::alloc_guard::raw_release(pointer);
}
void operator delete[](void* pointer, std::size_t) noexcept {
    marp::harness::h4::alloc_guard::raw_release(pointer);
}
void operator delete(void* pointer, std::align_val_t) noexcept {
    marp::harness::h4::alloc_guard::raw_release(pointer);
}
void operator delete[](void* pointer, std::align_val_t) noexcept {
    marp::harness::h4::alloc_guard::raw_release(pointer);
}
void operator delete(void* pointer, std::size_t, std::align_val_t) noexcept {
    marp::harness::h4::alloc_guard::raw_release(pointer);
}
void operator delete[](void* pointer, std::size_t, std::align_val_t) noexcept {
    marp::harness::h4::alloc_guard::raw_release(pointer);
}

#endif  // !H4_ALLOC_GUARD_DISABLED

namespace marp::harness::h4::alloc_guard {
namespace {

thread_local bool g_enabled = false;
thread_local bool g_violated = false;
thread_local std::size_t g_budget = 0;
thread_local std::size_t g_outstanding = 0;
thread_local std::size_t g_peak = 0;

#if !defined(H4_ALLOC_GUARD_DISABLED)

void account_add(std::size_t bytes) noexcept {
    g_outstanding += bytes;
    if (g_outstanding > g_peak) g_peak = g_outstanding;
    if (g_outstanding > g_budget) g_violated = true;
}

void account_sub(std::size_t bytes) noexcept {
    g_outstanding = g_outstanding > bytes ? g_outstanding - bytes : 0;
}

struct alignas(std::max_align_t) Header {
    std::size_t bytes;
    std::size_t offset;
    std::size_t accounted;
};

#endif  // !H4_ALLOC_GUARD_DISABLED

}  // namespace

#if !defined(H4_ALLOC_GUARD_DISABLED)

void* raw_allocate(std::size_t size, std::size_t alignment) {
    if (alignment < alignof(std::max_align_t)) alignment = alignof(std::max_align_t);
    const std::size_t overhead = sizeof(Header) + alignment;
    if (size > static_cast<std::size_t>(-1) - overhead) throw std::bad_alloc();
    auto* raw = static_cast<unsigned char*>(std::malloc(size + overhead));
    if (raw == nullptr) throw std::bad_alloc();
    const auto raw_address = reinterpret_cast<std::size_t>(raw);
    const std::size_t aligned =
        (raw_address + sizeof(Header) + alignment - 1) / alignment * alignment;
    auto* payload = reinterpret_cast<unsigned char*>(aligned);
    auto* header = reinterpret_cast<Header*>(payload) - 1;
    header->bytes = size;
    header->offset = aligned - raw_address;
    header->accounted = g_enabled ? 1u : 0u;
    if (header->accounted != 0u) account_add(size);
    return payload;
}

void raw_release(void* pointer) noexcept {
    if (pointer == nullptr) return;
    auto* header = static_cast<Header*>(pointer) - 1;
    if (header->accounted != 0u) account_sub(header->bytes);
    auto* raw = static_cast<unsigned char*>(pointer) - header->offset;
    std::free(raw);
}

#else

void* raw_allocate(std::size_t size, std::size_t) {
    void* p = std::malloc(size);
    if (p == nullptr) throw std::bad_alloc();
    return p;
}

void raw_release(void* pointer) noexcept { std::free(pointer); }

#endif  // !H4_ALLOC_GUARD_DISABLED

void begin(std::size_t budget_bytes) noexcept {
    g_enabled = true;
    g_violated = false;
    g_budget = budget_bytes;
    g_outstanding = 0;
    g_peak = 0;
}

void end() noexcept { g_enabled = false; }

std::size_t peak_bytes() noexcept { return g_peak; }
std::size_t outstanding_bytes() noexcept { return g_outstanding; }
bool violated() noexcept { return g_violated; }

bool enabled() noexcept {
#if defined(H4_ALLOC_GUARD_DISABLED)
    return false;
#else
    return true;
#endif
}

}  // namespace marp::harness::h4::alloc_guard
