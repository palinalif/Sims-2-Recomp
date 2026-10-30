#include "ts2/guest_existing_provider_abi.hpp"
#include "ts2/guest_memory.hpp"
#include <bit>
#include <stdexcept>

namespace ts2 {
namespace {
void push(GuestRegisters& r, GuestMemory& m, uint32_t value) {
    if (r.esp < 4) throw std::out_of_range("provider stack underflow");
    m.write32(r.esp-4,value); r.esp-=4;
}
void call(uint32_t target, uint32_t ret, uint32_t pop, GuestRegisters& r,
          GuestMemory& m, const GuestDispatch& d) {
    const auto before=r.esp;
    if (uint64_t(before)+pop>UINT32_MAX) throw std::out_of_range("provider stack overflow");
    push(r,m,ret); d.invoke(target,r,m);
    if (r.esp!=before+pop) throw std::runtime_error("provider endpoint cleanup mismatch");
}
}
void GuestExistingProviderAbi::invoke(GuestRegisters& r, GuestMemory& m,
                                     const GuestDispatch& d) const {
    const auto sp=r.esp;
    if (sp<16 || uint64_t(sp)+4>UINT32_MAX)
        throw std::out_of_range("provider caller stack bounds");
    const auto caller=m.read32(sp), index=m.read32(index_address);
    if (index==UINT32_MAX) throw std::runtime_error("provider cold index unsupported");
    const auto ebx=r.ebx, edi=r.edi;
    push(r,m,ebx); push(r,m,edi);
    call(m.read32(get_slot),0xa0846028u,0,r,m,d); r.edi=r.eax;
    r.eax=index; push(r,m,index);
    call(selector,0xa084603au,4,r,m,d); r.ebx=r.eax;
    if (!r.ebx) throw std::runtime_error("provider cold allocation unsupported");
    if (r.ebx==UINT32_MAX) r.ebx=0;
    // The supported original return paths end in TEST result,result (AF undefined).
    r.eflags=(r.eflags & ~0x8c5u) | (r.ebx==0?0x40u:0u) |
        (r.ebx & 0x80000000u?0x80u:0u) |
        (std::popcount(r.ebx & 255u)%2==0?4u:0u);
    push(r,m,r.edi); call(m.read32(set_slot),0xa08460cau,4,r,m,d);
    r.eax=r.ebx; r.edi=edi; r.ebx=ebx;
    if (m.read32(sp)!=caller) throw std::runtime_error("provider return frame changed");
    r.esp=sp+4;
}
}
