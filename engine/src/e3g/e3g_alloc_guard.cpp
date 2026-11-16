// MARP v2 — E3 WIRE — E3-G integrated gate — O7.10 allocation guard.
//
// Replaces the global allocation functions so the fuzz campaign can measure the
// peak heap a single mutant commands.  Linked into `bin/e3_g_gate` only: nothing
// in C07 (`e3_wire*.cpp`) or C08 (`e3_legacy.cpp`) refers to this translation
// unit, and `Makefile.c07`, `Makefile.c08`, `Makefile.h3` and `engine/Makefile`
// do not link it, so the replacement exists exactly where the gate needs it.
//
// O7.10 asks that no fuzz mutant cause "an allocation beyond its declared
// container size".  The guard is armed per mutant with a budget, records the peak
// and the outstanding byte count, and `violated()` reports whether the budget was
// ever exceeded.  It never aborts a mutant: a decoder that allocates too much must
// be *measured* to fail the obligation, not to crash the harness.
//
// The counters are `thread_local`: a mutant is processed start to finish by one
// worker, so per-mutant peak accounting must not be contaminated by a concurrent
// worker's allocations.  That also makes the reported peak reproducible, which a
// process-global counter is not (the maximum over concurrently running mutants
// would depend on scheduling).
//
// With `E3G_ALLOC_GUARD_DISABLED` defined (the sanitizer build, whose own runtime
// supplies these symbols) the same accounting API exists but the replacement
// functions are omitted.

#include <cstddef>
#include <cstdlib>
#include <new>

namespace e3g::alloc_guard {
namespace {

thread_local bool g_enabled = false;
thread_local bool g_violated = false;
thread_local std::size_t g_budget = 0;
thread_local std::size_t g_outstanding = 0;
thread_local std::size_t g_peak = 0;

#if !defined(E3G_ALLOC_GUARD_DISABLED)

void account_add(std::size_t bytes) {
    g_outstanding += bytes;
    if (g_outstanding > g_peak) g_peak = g_outstanding;
    if (g_outstanding > g_budget) g_violated = true;
}

void account_sub(std::size_t bytes) {
    g_outstanding = g_outstanding > bytes ? g_outstanding - bytes : 0;
}

// Every block records its payload size, the distance back to the `malloc` base
// (so plain and over-aligned requests are both released exactly) and whether it
// was allocated while the guard was armed.  A block from before `begin()` is
// never credited on release, so an epoch's accounting cannot be corrupted by the
// harness's own long-lived allocations.
struct alignas(std::max_align_t) Header {
    std::size_t bytes;
    std::size_t offset;
    std::size_t accounted;
};

void* allocate(std::size_t size, std::size_t alignment) {
    if (alignment < alignof(std::max_align_t)) alignment = alignof(std::max_align_t);
    const std::size_t overhead = sizeof(Header) + alignment;
    if (size > static_cast<std::size_t>(-1) - overhead) throw std::bad_alloc();
    auto* raw = static_cast<unsigned char*>(std::malloc(size + overhead));
    if (raw == nullptr) throw std::bad_alloc();
    const auto raw_address = reinterpret_cast<std::size_t>(raw);
    const std::size_t first = raw_address + sizeof(Header);
    const std::size_t aligned = (first + alignment - 1) / alignment * alignment;
    auto* payload = reinterpret_cast<unsigned char*>(aligned);
    auto* header = reinterpret_cast<Header*>(payload) - 1;
    header->bytes = size;
    header->offset = aligned - raw_address;
    header->accounted = g_enabled ? 1u : 0u;
    if (header->accounted != 0u) account_add(size);
    return payload;
}

void release(void* pointer) noexcept {
    if (pointer == nullptr) return;
    auto* header = static_cast<Header*>(pointer) - 1;
    const std::size_t bytes = header->bytes;
    const std::size_t accounted = header->accounted;
    auto* raw = static_cast<unsigned char*>(pointer) - header->offset;
    if (accounted != 0u) account_sub(bytes);
    std::free(raw);
}

#endif  // !E3G_ALLOC_GUARD_DISABLED

}  // namespace

void begin(std::size_t budget_bytes) {
    g_budget = budget_bytes;
    g_outstanding = 0;
    g_peak = 0;
    g_violated = false;
    g_enabled = true;
}

// Disarms accounting.  Blocks allocated during the epoch keep their `accounted`
// mark, so releasing them afterwards is still safe (the counter simply floors at
// zero); the next `begin()` re-arms with fresh counters.
void end() { g_enabled = false; }

std::size_t peak_bytes() { return g_peak; }
std::size_t outstanding_bytes() { return g_outstanding; }
bool violated() { return g_violated; }
bool enabled() { return g_enabled; }

}  // namespace e3g::alloc_guard

#if !defined(E3G_ALLOC_GUARD_DISABLED)
namespace e3g::alloc_guard::detail {

void* allocate_bytes(std::size_t size) { return e3g::alloc_guard::allocate(size, 0); }
void release_bytes(void* pointer) noexcept { e3g::alloc_guard::release(pointer); }

}  // namespace e3g::alloc_guard::detail

void* operator new(std::size_t size) { return e3g::alloc_guard::detail::allocate_bytes(size); }
void* operator new[](std::size_t size) { return e3g::alloc_guard::detail::allocate_bytes(size); }
void* operator new(std::size_t size, const std::nothrow_t&) noexcept {
    try {
        return e3g::alloc_guard::detail::allocate_bytes(size);
    } catch (...) {
        return nullptr;
    }
}
void* operator new[](std::size_t size, const std::nothrow_t&) noexcept {
    try {
        return e3g::alloc_guard::detail::allocate_bytes(size);
    } catch (...) {
        return nullptr;
    }
}
void* operator new(std::size_t size, std::align_val_t alignment) {
    return e3g::alloc_guard::allocate(size, static_cast<std::size_t>(alignment));
}
void* operator new[](std::size_t size, std::align_val_t alignment) {
    return e3g::alloc_guard::allocate(size, static_cast<std::size_t>(alignment));
}
void* operator new(std::size_t size, std::align_val_t alignment, const std::nothrow_t&) noexcept {
    try {
        return e3g::alloc_guard::allocate(size, static_cast<std::size_t>(alignment));
    } catch (...) {
        return nullptr;
    }
}
void* operator new[](std::size_t size, std::align_val_t alignment, const std::nothrow_t&) noexcept {
    try {
        return e3g::alloc_guard::allocate(size, static_cast<std::size_t>(alignment));
    } catch (...) {
        return nullptr;
    }
}

void operator delete(void* pointer) noexcept { e3g::alloc_guard::detail::release_bytes(pointer); }
void operator delete[](void* pointer) noexcept {
    e3g::alloc_guard::detail::release_bytes(pointer);
}
void operator delete(void* pointer, std::size_t) noexcept {
    e3g::alloc_guard::detail::release_bytes(pointer);
}
void operator delete[](void* pointer, std::size_t) noexcept {
    e3g::alloc_guard::detail::release_bytes(pointer);
}
void operator delete(void* pointer, const std::nothrow_t&) noexcept {
    e3g::alloc_guard::detail::release_bytes(pointer);
}
void operator delete[](void* pointer, const std::nothrow_t&) noexcept {
    e3g::alloc_guard::detail::release_bytes(pointer);
}
void operator delete(void* pointer, std::align_val_t) noexcept {
    e3g::alloc_guard::detail::release_bytes(pointer);
}
void operator delete[](void* pointer, std::align_val_t) noexcept {
    e3g::alloc_guard::detail::release_bytes(pointer);
}
void operator delete(void* pointer, std::size_t, std::align_val_t) noexcept {
    e3g::alloc_guard::detail::release_bytes(pointer);
}
void operator delete[](void* pointer, std::size_t, std::align_val_t) noexcept {
    e3g::alloc_guard::detail::release_bytes(pointer);
}
void operator delete(void* pointer, std::align_val_t, const std::nothrow_t&) noexcept {
    e3g::alloc_guard::detail::release_bytes(pointer);
}
void operator delete[](void* pointer, std::align_val_t, const std::nothrow_t&) noexcept {
    e3g::alloc_guard::detail::release_bytes(pointer);
}
#endif  // !E3G_ALLOC_GUARD_DISABLED
