#pragma once
#include "ts2/guest_dispatch.hpp"
namespace ts2 {
// Opt-in 84601E NULL-storage/invalid-index integer ABI only. No bindings or
// actual Windows storage/object allocation. Selector must return zero; existing
// values reject (use GuestExistingProviderAbi). Index FFFFFFFF skips query, NOT
// object allocation. Setter is stdcall8, allocator/init/release cdecl, Get/Set
// stdcall0/4. Explicit locale ADDRESS is passed, never dereferenced here.
// Stable single-owner layout, no stack/layout alias, no reentry, FP or SEH.
// Endpoints preserve nonvolatiles/flags and saved/caller frames. Failure is not
// transactional; last-error restoration guaranteed only on successful completion.
struct GuestLazyProviderAbi {
    uint32_t index_address, get_slot, set_slot, selector;
    uint32_t setter, allocator, initializer, release, locale;
    void invoke(GuestRegisters&, GuestMemory&, const GuestDispatch&) const;
};
}
