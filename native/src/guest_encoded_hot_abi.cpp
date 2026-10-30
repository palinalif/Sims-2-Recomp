#include "ts2/guest_encoded_hot_abi.hpp"
#include "ts2/guest_encoded_resolver.hpp"
#include "ts2/guest_memory.hpp"
#include <bit>
#include <stdexcept>

namespace ts2 {
void GuestEncodedHotAbi::invoke(GuestRegisters& r, GuestMemory& m) const {
    const auto sp=r.esp;
    if (sp<12 || uint64_t(sp)+8>UINT32_MAX)
        throw std::out_of_range("encoded hot ABI: stack bounds");
    const auto index=m.read32(sp+4);
    if (index>=64 || uint64_t(cache_base)+4*index+4>(uint64_t{1}<<32))
        throw std::out_of_range("encoded hot ABI: cache bounds");
    const auto slot=cache_base+4*index;
    for (const auto address : {cookie_address,slot}) {
        if (uint64_t(address)<uint64_t(sp)+8 && uint64_t(address)+4>sp-12)
            throw std::invalid_argument("encoded hot ABI: stack aliases cache");
    }
    const auto cookie=m.read32(cookie_address);
    const auto value=guest_decode_pointer(m.read32(slot),cookie);
    if (!value) throw std::runtime_error("encoded hot ABI: cold path unsupported");
    // Check the complete touched stack before stores. No unused cdecl argument
    // or cold dependency is read. GuestMemory provides checked data, not code.
    (void)m.read32(sp); (void)m.read32(sp-4);
    (void)m.read32(sp-8); (void)m.read32(sp-12);
    m.write32(sp-4,r.ebp); m.write32(sp-8,r.ebx); m.write32(sp-12,r.esi);
    r.eax=value==UINT32_MAX?0:value;
    r.ecx=cookie&31; r.edx=value; r.esp=sp+4;
    const auto tested=value==UINT32_MAX?0:value;
    r.eflags=(r.eflags & ~0x8c5u) | (tested==0?0x40u:0u) |
        (tested & 0x80000000u?0x80u:0u) |
        (std::popcount(tested & 255u)%2==0?4u:0u);
}
}
