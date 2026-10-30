#pragma once
#include "ts2/guest_dispatch.hpp"

namespace ts2 {
// Opt-in integer ABI model of Legacy 84601E's existing-slot path only.
// Explicit layout/dispatch, no automatic IAT binding or actual Windows storage.
// GetLastError is stdcall0; selector stdcall4; SetLastError stdcall4. Endpoints
// preserve nonvolatiles/flags except documented volatile effects, and do not
// modify caller/saved stack or layout. Single owner, no reentry/SEH/FP model.
// All-ones index and null storage need unsupported cold initialization and throw.
// All-ones storage is a supported null result. Failure is NOT transactional:
// stack, register and endpoint effects can remain; last-error restoration is
// guaranteed only on success. Does not infer a cold CPU ABI from value policies.
struct GuestExistingProviderAbi {
    uint32_t index_address, get_slot, set_slot, selector;
    void invoke(GuestRegisters&, GuestMemory&, const GuestDispatch&) const;
};
}
