#pragma once
#include "ts2/guest_dispatch.hpp"

namespace ts2 {
// Opt-in bounded integer ABI model for Legacy selector RVA 8480BF. Not an
// automatic binding, original-body lift, complete x86 context or OS service.
// Resolver is cdecl(33,name,begin,end); guard preserves all state; providers
// are stdcall(index). Endpoints must preserve nonvolatile registers and flags
// except explicit volatile/provider effects. They must not mutate caller/saved
// stack words or the selector layout. No reentry/concurrency/SEH support.
// The oracle covers caller state, scratch stack and event frames/ECX, NOT the
// unobserved internal register values at each endpoint. Exceptions stop in place;
// memory/endpoint effects are NOT rolled back. Invalid cleanup throws.
struct GuestStorageAbi {
    uint32_t resolver, guard_slot, tls_slot, name, begin, end;
    void invoke(GuestRegisters&, GuestMemory&, const GuestDispatch&) const;
};
}
