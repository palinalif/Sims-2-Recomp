#include "ts2/guest_resolver.hpp"
#include "ts2/guest_memory.hpp"

namespace ts2 {
uint32_t legacy_resolve_two(GuestMemory& memory, const GuestResolverSlots& slots,
                            uint32_t export_name, GuestLoaderServices& loader,
                            GuestExportServices& exports) {
    constexpr uint32_t unavailable = UINT32_MAX;
    const auto cached = memory.read32(slots.function_cache_address);
    if (cached != 0) return cached == unavailable ? 0 : cached;
    // Validate layout only on a cold lookup, without touching candidate memory.
    const std::array<uint32_t, 3> addresses{slots.function_cache_address,
        slots.candidates[0].cache_address, slots.candidates[1].cache_address};
    for (size_t i = 0; i < addresses.size(); ++i) {
        if (uint64_t(addresses[i]) + 4 > (uint64_t{1} << 32))
            throw std::out_of_range("guest resolver: cache overflow");
        for (size_t j = 0; j < i; ++j)
            if (uint64_t(addresses[i]) < uint64_t(addresses[j]) + 4 &&
                uint64_t(addresses[j]) < uint64_t(addresses[i]) + 4)
                throw std::invalid_argument("guest resolver: overlapping cache slots");
    }
    uint32_t result = 0;
    for (const auto& candidate : slots.candidates) {
        auto module = memory.read32(candidate.cache_address);
        if (module == unavailable) continue;
        if (module == 0) {
            module = legacy_loader_policy(candidate.name, loader);
            memory.write32(candidate.cache_address, module ? module : unavailable);
        }
        if (module != 0) {
            result = exports.lookup(module, export_name);
            break;
        }
    }
    memory.write32(slots.function_cache_address, result ? result : unavailable);
    return result;
}
}
