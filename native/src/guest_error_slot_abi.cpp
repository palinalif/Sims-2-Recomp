#include "ts2/guest_error_slot_abi.hpp"
#include "ts2/guest_memory.hpp"
#include <bit>
#include <stdexcept>

namespace ts2 {
void GuestErrorSlotAbi::invoke(GuestRegisters& r, GuestMemory& m,
                               const GuestDispatch& d) const {
    const auto sp=r.esp;
    if (sp<4 || uint64_t(sp)+4>UINT32_MAX)
        throw std::out_of_range("error slot caller stack bounds");
    const auto caller=m.read32(sp);
    (void)m.read32(sp-4);
    m.write32(sp-4,0xa0831b1cu); r.esp=sp-4;
    d.invoke(provider,r,m);
    if (r.esp!=sp || m.read32(sp)!=caller)
        throw std::runtime_error("error slot provider frame mismatch");
    const auto pointer=r.eax;
    const uint32_t value=pointer+16u;
    // TEST EAX,EAX precedes the null branch; ADD defines AF only if nonnull.
    uint32_t flags=4u|0x40u;
    if (pointer) {
        flags=(uint64_t(pointer)+16>UINT32_MAX?1u:0u) |
            (std::popcount(value & 255u)%2==0?4u:0u) |
            ((pointer ^ 16u ^ value) & 16u) | (value==0?0x40u:0u) |
            (value & 0x80000000u?0x80u:0u) |
            ((~(pointer ^ 16u) & (pointer ^ value) & 0x80000000u)?0x800u:0u);
    }
    const uint32_t mask=pointer?0x8d5u:0x8c5u;
    r.eflags=(r.eflags & ~mask)|flags;
    r.eax=pointer?value:fallback; r.esp=sp+4;
}
}
