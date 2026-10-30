#pragma once
#include "ts2/guest_loader_policy.hpp"
#include <array>

namespace ts2 {
// Explicit caller-owned layout for the observed two-candidate resolver path.
// Cache slots must be distinct, non-overlapping words; names are guest pointers.
// No table parsing, inferred module indices, globals or ownership transfer.
struct GuestResolverCandidate { uint32_t cache_address, name; };
struct GuestResolverSlots {
    uint32_t function_cache_address;
    std::array<GuestResolverCandidate, 2> candidates;
};
class GuestExportServices {
public:
    virtual ~GuestExportServices() = default;
    virtual uint32_t lookup(uint32_t, uint32_t) {
        throw std::runtime_error("guest resolver: export unavailable");
    }
};
// Value/cache policy for Legacy RVA82A212's observed argument4 / indices1,2
// slice, composed with loader82A2B2. NOT an x86 ABI adapter or IAT binding.
// Cache0 is unresolved, FFFFFFFF is unavailable. First usable module stops
// search even if export lookup returns0. Cache hits read only the function word.
// Single caller only: no atomic XCHG, races, loser FreeLibrary or reentry while
// resolving. Providers must not mutate layout/cache memory. Effects on throw
// remain (including earlier module-cache writes); no guest SEH or rollback.
uint32_t legacy_resolve_two(GuestMemory& memory, const GuestResolverSlots& slots,
                            uint32_t export_name, GuestLoaderServices& loader,
                            GuestExportServices& exports);
}
