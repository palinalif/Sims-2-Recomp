#pragma once
#include "ts2/guest_dispatch.hpp"

namespace ts2 {
// Opt-in Legacy 8461B8 integer ABI. Explicit heap/HeapFree/GetLastError slots,
// mapper and accessor targets; no automatic bindings or actual heap supplied.
// Endpoints must preserve nonvolatiles/caller frames and use stdcall12,
// cdecl0, cdecl1, cdecl0 respectively. Stable single-owner memory required.
// Failure is NOT transactional; heap/endpoint/stack effects may remain.
// Destination is checked by GuestMemory at store time, not prevalidated before
// HeapFree. Caller must exclude aliases with stack/layout/code/table memory.
// Only integer state and defined flags modeled; FP/SEH/lifecycle excluded.
struct GuestReleaseAbi {
    uint32_t heap_address, free_slot, get_slot, mapper, accessor;
    void invoke(GuestRegisters&, GuestMemory&, const GuestDispatch&) const;
};
}
