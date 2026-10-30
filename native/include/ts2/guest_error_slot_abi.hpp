#pragma once
#include "ts2/guest_dispatch.hpp"

namespace ts2 {
// Opt-in integer ABI of Legacy 831B17. Calls an explicitly bound cdecl0
// provider and returns pointer+16 modulo 2^32, or fallback on null. Neither
// returned address is dereferenced. No thread storage or IAT binding supplied.
// Provider preserves nonvolatiles and the caller frame; volatile GPRs/flags may
// change. Only defined TEST/ADD flags are modeled; FP/SEH/reentry excluded.
// Failure is not transactional: nested endpoint/stack effects can remain.
struct GuestErrorSlotAbi {
    uint32_t provider, fallback;
    void invoke(GuestRegisters&, GuestMemory&, const GuestDispatch&) const;
};
}
