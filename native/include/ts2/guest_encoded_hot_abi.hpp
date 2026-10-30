#pragma once
#include "ts2/guest_dispatch.hpp"

namespace ts2 {
// Opt-in authored integer ABI model for resolver RVA 847E6C, HOT CACHE ONLY.
// Explicit cookie address and base of a 64-word function table. Reads only the
// cdecl index argument; name/range arguments are not touched on the hot path.
// Decoded zero (cold initialization) throws before any state/memory change.
// No IAT binding, original-body lift, x87/SSE, SEH, threading or cold CPU ABI.
// Stack frame and cookie/cache words must not overlap. Single caller, stable
// cookie/cache required. Undefined AF is preserved, not a defined-flag promise.
struct GuestEncodedHotAbi {
    uint32_t cookie_address, cache_base;
    void invoke(GuestRegisters&, GuestMemory&) const;
};
}
