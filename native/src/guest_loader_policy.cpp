#include "ts2/guest_loader_policy.hpp"
#include "ts2/guest_memory.hpp"

namespace ts2 {
uint32_t guest_wide_compare(const GuestMemory& memory, uint32_t left,
                            uint32_t right, uint32_t count) {
    // Use wide offsets so advancing past 0xffffffff cannot wrap into another
    // committed span. Validate only units actually reached by the comparison.
    uint64_t a = left, b = right;
    for (uint32_t i = 0; i < count; ++i, a += 2, b += 2) {
        if (a > UINT32_MAX || b > UINT32_MAX)
            throw std::out_of_range("guest wide comparison: address overflow");
        const uint32_t x = memory.read16(static_cast<uint32_t>(a));
        const uint32_t y = memory.read16(static_cast<uint32_t>(b));
        if (x != y || x == 0) return x - y;
    }
    return 0;
}
uint32_t CheckedGuestLoaderServices::compare(uint32_t left, uint32_t right,
                                             uint32_t count) {
    return guest_wide_compare(memory_, left, right, count);
}
uint32_t legacy_loader_policy(uint32_t name, GuestLoaderServices& services) {
    const uint32_t module = services.load(name, 0, 0x800);
    if (module != 0) return module;
    if (services.last_error() != 87) return 0;
    // The comparator/string semantics are deliberately provider-owned.
    if (services.compare(name, 0xa0e06e20u, 7) == 0) return 0;
    return services.load(name, 0, 0);
}
}
