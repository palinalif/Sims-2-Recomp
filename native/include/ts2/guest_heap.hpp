#pragma once
#include <cstdint>
#include <map>

namespace ts2 {
class GuestMemory;
struct GuestRegisters;

// Explicit portable service, NOT a reconstruction of Windows heap internals.
// Owns allocation metadata for a caller-provided, exclusively owned committed
// arena. Memory must outlive the heap; caller must exclude stack/image/other
// heaps, concurrent use and remapping. No implicit mappings or process-global
// heap initialization. Handle is an opaque nonzero guest token, not a pointer.
//
// Supported subset: HeapAlloc flags 0 or HEAP_ZERO_MEMORY (8); HeapFree flags 0.
// Invalid handle/unsupported flags throw, exhaustion returns 0, invalid free
// returns false without mutation. Allocations are first-fit, 8-byte aligned;
// zero-size requests own 8 bytes. Zero-fill covers the rounded allocation;
// otherwise bytes are unspecified (currently retained across free/reuse).
// Free coalesces metadata but neither erases nor decommits guest bytes. Checked
// guest accesses remain page-based, NOT allocation-lifetime/use-after-free guards.
// Host metadata allocation exceptions propagate; no SEH/last-error/threads,
// HeapCreate/Destroy/Size or automatic IAT binding is supplied.
class GuestHeap {
public:
    GuestHeap(GuestMemory&, uint32_t handle, uint32_t arena, uint64_t bytes);
    GuestHeap(const GuestHeap&)=delete;
    GuestHeap& operator=(const GuestHeap&)=delete;
    uint32_t allocate(uint32_t handle, uint32_t flags, uint32_t bytes);
    bool release(uint32_t handle, uint32_t flags, uint32_t address);
    // Portable HeapReAlloc subset: flags 0 only, exact live base required.
    // Shrinks/grows in place where possible, otherwise first-fit moves. Keeps
    // min(old requested bytes, new bytes); extension bytes are unspecified.
    // A zero-size request retains an owned 8-byte block (not free). Invalid
    // addresses/exhaustion return 0 without changing ownership or guest bytes.
    // No Windows allocator-address/last-error equivalence is implied.
    uint32_t reallocate(uint32_t handle, uint32_t flags, uint32_t address, uint32_t bytes);
    // Integer-only stdcall12 endpoint: [ESP]=return, +4 handle, +8 flags,
    // +12 size; EAX=result, ESP+=16; all other integer state retained.
    // Validates complete frame/cleanup range before mutating heap/registers.
    // This stronger preservation is our service policy, not observed Windows ABI.
    void invoke_allocate(GuestRegisters&);
    // stdcall16: return, handle, flags, address, size; EAX=result, ESP+=20.
    // Same validation and integer-preservation policy as invoke_allocate.
    void invoke_reallocate(GuestRegisters&);
private:
    struct Block { uint64_t bytes; bool free; uint32_t requested=0; };
    GuestMemory& memory_;
    uint32_t handle_;
    std::map<uint32_t,Block> blocks_;
    void check_handle(uint32_t handle) const;
};
}
