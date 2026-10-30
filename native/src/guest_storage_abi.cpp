#include "ts2/guest_storage_abi.hpp"
#include "ts2/guest_memory.hpp"
#include <bit>
#include <stdexcept>

namespace ts2 {
namespace {
void push(GuestRegisters& r, GuestMemory& m, uint32_t v) {
    if (r.esp < 4) throw std::out_of_range("selector stack underflow");
    m.write32(r.esp-4,v); r.esp-=4;
}
void call(uint32_t target, uint32_t ret, uint32_t pop, GuestRegisters& r,
          GuestMemory& m, const GuestDispatch& d) {
    const auto before=r.esp;
    if (uint64_t(before)+pop > UINT32_MAX) throw std::out_of_range("selector stack overflow");
    push(r,m,ret);
    d.invoke(target,r,m);
    if (r.esp!=before+pop) throw std::runtime_error("selector endpoint cleanup mismatch");
}
}
void GuestStorageAbi::invoke(GuestRegisters& r, GuestMemory& m, const GuestDispatch& d) const {
    const auto sp=r.esp;
    if (sp<28 || uint64_t(sp)+8>UINT32_MAX)
        throw std::out_of_range("selector caller stack bounds");
    const auto caller=m.read32(sp), index=m.read32(sp+4);
    const auto esi=r.esi, ebp=r.ebp;
    push(r,m,ebp); r.ebp=r.esp; push(r,m,esi);
    push(r,m,end); push(r,m,begin); push(r,m,name); push(r,m,33);
    call(resolver,0xa08480dbu,0,r,m,d);
    r.esp+=16;
    const auto target=r.eax; r.esi=target;
    // TEST target,target: AF undefined and deliberately not normalized here.
    r.eflags=(r.eflags & ~0x8c5u) | (target==0?0x40u:0u) |
        (target & 0x80000000u?0x80u:0u) |
        (std::popcount(target & 255u)%2==0?4u:0u);
    if (target) {
        push(r,m,index); r.ecx=target;
        call(m.read32(guard_slot),0xa08480efu,0,r,m,d);
        // Guard is a checked explicit contract, never a silent no-op default.
        if (r.ecx!=target) throw std::runtime_error("selector guard changed target");
        call(target,0xa08480f1u,4,r,m,d);
        r.ebp=ebp; r.esi=esi; r.esp=sp;
        // Dispatch has no EIP field: consume the modeled RET 4 caller frame.
        if (m.read32(sp)!=caller) throw std::runtime_error("selector return frame changed");
        r.esp=sp+8;
    } else {
        r.ebp=ebp; r.esi=esi; r.esp=sp;
        d.invoke(m.read32(tls_slot),r,m);
        if (r.esp!=sp+8) throw std::runtime_error("selector TLS cleanup mismatch");
    }
}
}
