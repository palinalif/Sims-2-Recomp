#include "ts2/guest_release_abi.hpp"
#include "ts2/guest_memory.hpp"
#include <bit>
#include <stdexcept>

namespace ts2 {
namespace {
void push(GuestRegisters& r, GuestMemory& m, uint32_t v) {
    if (r.esp<4) throw std::out_of_range("release stack underflow");
    m.write32(r.esp-4,v); r.esp-=4;
}
void call(uint32_t target, uint32_t ret, uint32_t pop, GuestRegisters& r,
          GuestMemory& m, const GuestDispatch& d) {
    const auto sp=r.esp;
    if (uint64_t(sp)+pop>UINT32_MAX) throw std::out_of_range("release stack overflow");
    push(r,m,ret); d.invoke(target,r,m);
    if (r.esp!=sp+pop) throw std::runtime_error("release endpoint cleanup mismatch");
}
void test(GuestRegisters& r, uint32_t v) {
    r.eflags=(r.eflags & ~0x8c5u) | (v==0?0x40u:0u) |
        (v & 0x80000000u?0x80u:0u) | (std::popcount(v & 255u)%2==0?4u:0u);
}
}
void GuestReleaseAbi::invoke(GuestRegisters& r, GuestMemory& m,
                            const GuestDispatch& d) const {
    const auto sp=r.esp;
    if (sp<20 || uint64_t(sp)+8>(uint64_t{1}<<32))
        throw std::out_of_range("release caller stack bounds");
    const auto caller=m.read32(sp), context=m.read32(sp+4), esi=r.esi, ebp=r.ebp;
    // Check the immediate wrapper frame, not all nested callee requirements.
    for (uint32_t i=4;i<=20;i+=4) (void)m.read32(sp-i);
    push(r,m,ebp); r.ebp=sp-4;
    if (!context) {
        // CMP context,0 defines AF as zero as well as the TEST-equivalent bits.
        test(r,0); r.eflags &= ~0x10u;
    } else {
        push(r,m,context); push(r,m,0); push(r,m,m.read32(heap_address));
        call(m.read32(free_slot),0xa08461d4u,12,r,m,d);
        test(r,r.eax);
        if (!r.eax) {
            push(r,m,esi);
            call(m.read32(get_slot),0xa08461dfu,0,r,m,d);
            push(r,m,r.eax); call(mapper,0xa08461e5u,0,r,m,d);
            r.ecx=m.read32(r.esp); r.esp+=4; r.esi=r.eax;
            call(accessor,0xa08461edu,0,r,m,d);
            m.write32(r.eax,r.esi);
        }
    }
    r.esi=esi; r.ebp=ebp;
    if (m.read32(sp)!=caller) throw std::runtime_error("release caller frame changed");
    r.esp=sp+4;
}
}
