#pragma once
#include "ts2/guest_dispatch.hpp"

namespace ts2 {
// Opt-in authored integer ABI for Legacy 831A7A (cdecl error argument).
// Explicit 45-pair table, stable memory/single owner. Full table readability
// required even on early matches, as in the value policy. Stack touched range
// [ESP-8,ESP+8) must not overlap the table. Preflight failures do not mutate.
// Models GPRs, defined arithmetic flags and final stack only; no FP/SEH,
// transient-write trace, errno destination store, OS service or runtime binding.
struct GuestOsErrorAbi {
    uint32_t table;
    void invoke(GuestRegisters&, GuestMemory&) const;
};
}
