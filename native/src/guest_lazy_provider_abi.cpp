#include "ts2/guest_lazy_provider_abi.hpp"
#include "ts2/guest_memory.hpp"
#include <bit>
#include <stdexcept>
namespace ts2 {
namespace {
void push(GuestRegisters& r, GuestMemory& m, uint32_t v) {
    if (r.esp<4) throw std::out_of_range("lazy stack underflow");
    m.write32(r.esp-4,v); r.esp-=4;
}
void call(uint32_t target,uint32_t ret,uint32_t pop,GuestRegisters& r,
          GuestMemory& m,const GuestDispatch& d) {
    const auto sp=r.esp;
    if (uint64_t(sp)+pop>UINT32_MAX) throw std::out_of_range("lazy stack overflow");
    push(r,m,ret); d.invoke(target,r,m);
    if (r.esp!=sp+pop) throw std::runtime_error("lazy endpoint cleanup mismatch");
}
uint32_t add12(uint32_t a) {
    const uint32_t b=a+12;
    return (b<a?1u:0u) | (std::popcount(b&255u)%2==0?4u:0u) |
        ((a^12u^b)&16u) | (b==0?64u:0u) | (b&0x80000000u?128u:0u) |
        ((~(a^12u)&(a^b)&0x80000000u)?2048u:0u);
}
}
void GuestLazyProviderAbi::invoke(GuestRegisters& r,GuestMemory& m,
                                 const GuestDispatch& d) const {
    const auto sp=r.esp;
    if (sp<36 || uint64_t(sp)+4>UINT32_MAX)
        throw std::out_of_range("lazy caller stack bounds");
    // Validate the entire bounded scratch frame before any endpoint effects.
    for (uint32_t n=4;n<=36;n+=4) (void)m.read32(sp-n);
    const auto caller=m.read32(sp), index=m.read32(index_address);
    const auto get=m.read32(get_slot), set=m.read32(set_slot);
    const auto ebx=r.ebx, edi=r.edi, esi=r.esi;
    push(r,m,ebx); push(r,m,edi);
    call(get,0xa0846028u,0,r,m,d); r.edi=r.eax;
    if (index!=UINT32_MAX) {
        r.eax=index; push(r,m,index);
        call(selector,0xa084603au,4,r,m,d);
        if (r.eax) throw std::runtime_error("lazy existing storage unsupported");
    }
    push(r,m,UINT32_MAX); push(r,m,index);
    call(setter,0xa0846056u,8,r,m,d);
    uint32_t result=0;
    // Slow failure paths end in XOR EBX,EBX; AF undefined.
    r.ebx=0; r.eflags=(r.eflags&~0x8c5u)|0x44u;
    if (r.eax) {
        push(r,m,esi); push(r,m,0x364); push(r,m,1);
        call(allocator,0xa084606bu,0,r,m,d);
        r.esp+=8; r.ecx=0x364; const auto pointer=r.eax;
        bool published=false;
        if (pointer) {
            push(r,m,pointer); push(r,m,index);
            call(setter,0xa0846090u,8,r,m,d); published=r.eax!=0;
        }
        if (!pointer || !published) {
            push(r,m,0); push(r,m,index);
            call(setter,pointer?0xa08460a2u:0xa0846081u,8,r,m,d);
            push(r,m,pointer); call(release,0xa08460a8u,0,r,m,d);
            r.ecx=pointer; r.esp+=4;
        } else {
            push(r,m,locale); push(r,m,pointer);
            call(initializer,0xa08460b6u,0,r,m,d);
            push(r,m,0); call(release,0xa08460bdu,0,r,m,d);
            r.eflags=(r.eflags&~0x8d5u)|add12(r.esp); r.esp+=12;
            result=pointer;
        }
        r.esp+=4; r.esi=esi;
    }
    push(r,m,r.edi); call(set,0xa08460cau,4,r,m,d);
    r.eax=result; r.ebx=ebx; r.edi=edi;
    if (m.read32(sp)!=caller) throw std::runtime_error("lazy caller frame changed");
    r.esp=sp+4;
}
}
