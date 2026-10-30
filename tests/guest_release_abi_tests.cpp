#include "ts2/guest_release_abi.hpp"
#include "ts2/guest_memory.hpp"
#include <iostream>
#include <stdexcept>

namespace {
constexpr uint32_t sp=0xb8000800u, slot=0xc0000100u;
void require(bool value) { if (!value) throw std::runtime_error("release check"); }
void free_ok(ts2::GuestRegisters& r,ts2::GuestMemory& m,const ts2::GuestDispatch&) {
    require(r.ebp==sp-4 && r.esp==sp-20);
    require(m.read32(r.esp)==0xa08461d4u && m.read32(r.esp+4)==7);
    require(m.read32(r.esp+8)==0 && m.read32(r.esp+12)==9);
    r.eax=1; r.esp+=16;
}
void free_bad(ts2::GuestRegisters& r,ts2::GuestMemory&,const ts2::GuestDispatch&) { r.esp+=4; }
void free_fail(ts2::GuestRegisters& r,ts2::GuestMemory&,const ts2::GuestDispatch&) { r.eax=0; r.esp+=16; }
void get(ts2::GuestRegisters& r,ts2::GuestMemory&,const ts2::GuestDispatch&) { r.eax=203; r.esp+=4; }
void mapper(ts2::GuestRegisters& r,ts2::GuestMemory& m,const ts2::GuestDispatch&) {
    require(r.esp==sp-16 && m.read32(r.esp+4)==203);
    r.eax=0x80000000u; r.ecx=14; r.esp+=4;
}
void accessor(ts2::GuestRegisters& r,ts2::GuestMemory& m,const ts2::GuestDispatch&) {
    require(r.esp==sp-12 && r.ecx==203 && r.esi==0x80000000u);
    require(m.read32(r.esp)==0xa08461edu); r.eax=slot; r.esp+=4;
}
}
int main() {
    try {
        ts2::GuestMemory m; m.commit(0xb8000000u,4096); m.commit(0xc0000000u,4096);
        m.write32(0xc0000000u,7); m.write32(0xc0000004u,1); m.write32(0xc0000008u,2);
        ts2::GuestReleaseAbi abi{0xc0000000u,0xc0000004u,0xc0000008u,3,4};
        auto initial=[&](uint32_t context) {
            m.write32(sp,0xba000000u); m.write32(sp+4,context); m.write32(slot,77);
            ts2::GuestRegisters r{}; r.esp=sp; r.eax=17; r.ebp=23; r.esi=31; r.eflags=0xcd7; return r;
        };
        ts2::GuestDispatch empty;
        auto r=initial(0); abi.invoke(r,m,empty);
        require(r.eax==17 && r.esp==sp+4 && r.ebp==23 && r.esi==31);
        require(m.read32(sp-4)==23 && m.read32(slot)==77 && (r.eflags & 0xcd5)==0x444);
        ts2::GuestDispatch success; success.bind(1,free_ok);
        r=initial(9); abi.invoke(r,m,success);
        require(r.eax==1 && r.esp==sp+4 && r.ebp==23 && r.esi==31 && m.read32(slot)==77);
        ts2::GuestDispatch bad; bad.bind(1,free_bad);
        r=initial(9); bool failed=false;
        try { abi.invoke(r,m,bad); } catch (const std::runtime_error&) { failed=true; }
        require(failed && m.read32(slot)==77);
        ts2::GuestDispatch chain; chain.bind(1,free_fail); chain.bind(2,get);
        chain.bind(3,mapper); chain.bind(4,accessor);
        r=initial(9); abi.invoke(r,m,chain);
        require(r.eax==slot && r.esp==sp+4 && r.ebp==23 && r.esi==31);
        require(m.read32(slot)==0x80000000u && m.read32(sp-8)==31);
        for (uint32_t invalid : {0u,16u,0xfffffffcu,0xb8000004u}) {
            r=initial(0); r.esp=invalid; const auto before=r;
            failed=false; try { abi.invoke(r,m,empty); } catch (const std::out_of_range&) { failed=true; }
            require(failed && r.esp==before.esp && r.ebp==before.ebp && m.read32(slot)==77);
        }
        std::cout<<"release ABI boundary checks passed\n";
        return 0;
    } catch (const std::exception&) { return 1; }
}
