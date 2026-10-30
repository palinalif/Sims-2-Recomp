#include "ts2/guest_encoded_resolver.hpp"
#include "ts2/guest_memory.hpp"
#include <bit>
#include <vector>

namespace ts2 {
uint32_t guest_encode_pointer(uint32_t value, uint32_t cookie) {
    return std::rotl(value, static_cast<int>(cookie & 31)) ^ cookie;
}
uint32_t guest_decode_pointer(uint32_t value, uint32_t cookie) {
    return std::rotr(value ^ cookie, static_cast<int>(cookie & 31));
}
uint32_t legacy_resolve_encoded(GuestMemory& memory, uint32_t cookie_address,
    uint32_t function_cache_address, std::span<const GuestResolverCandidate> candidates,
    uint32_t export_name, GuestLoaderServices& loader, GuestExportServices& exports) {
    constexpr uint32_t unavailable = UINT32_MAX;
    const auto cookie = memory.read32(cookie_address);
    const auto cached = guest_decode_pointer(memory.read32(function_cache_address), cookie);
    if (cached) return cached == unavailable ? 0 : cached;
    if (candidates.size() > 64) throw std::invalid_argument("encoded resolver: range budget");
    std::vector<uint32_t> addresses{cookie_address, function_cache_address};
    for (const auto& candidate : candidates) addresses.push_back(candidate.cache_address);
    for (size_t i = 0; i < addresses.size(); ++i) {
        if (uint64_t(addresses[i]) + 4 > (uint64_t{1} << 32))
            throw std::out_of_range("encoded resolver: word overflow");
        for (size_t j = 0; j < i; ++j)
            if (uint64_t(addresses[i]) < uint64_t(addresses[j]) + 4 &&
                uint64_t(addresses[j]) < uint64_t(addresses[i]) + 4)
                throw std::invalid_argument("encoded resolver: overlapping words");
    }
    uint32_t result = 0;
    for (const auto& candidate : candidates) {
        auto module = memory.read32(candidate.cache_address);
        if (module == unavailable) continue;
        if (!module) {
            module = loader.load(candidate.name, 0, 0x800);
            if (!module && loader.last_error() == 87 &&
                loader.compare(candidate.name, 0xa0e06e20u, 7) != 0 &&
                loader.compare(candidate.name, 0xa0e09e5cu, 7) != 0)
                module = loader.load(candidate.name, 0, 0);
            if (module == unavailable)
                throw std::runtime_error("encoded resolver: reserved module response");
            memory.write32(candidate.cache_address, module ? module : unavailable);
        }
        if (module) {
            result = exports.lookup(module, export_name);
            if (result == unavailable)
                throw std::runtime_error("encoded resolver: reserved export response");
            break; // Export failure does not advance to a different module.
        }
    }
    memory.write32(function_cache_address, guest_encode_pointer(result ? result : unavailable, cookie));
    return result;
}
}
