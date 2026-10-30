// Diagnostic transport with an authored provider; no Windows services.
#include "ts2/guest_error_slot_abi.hpp"
#include "ts2/guest_memory.hpp"
#include <array>
#include <iostream>
#include <stdexcept>
namespace {
constexpr uint32_t stack=0xb8000000u;
std::array<uint32_t*,9> words(ts2::GuestRegisters& r) {
    return {&r.eax,&r.ebx,&r.ecx,&r.edx,&r.esi,&r.edi,&r.ebp,&r.esp,&r.eflags};
}
uint32_t word() {
    uint64_t n; if (!(std::cin>>n) || n>UINT32_MAX) throw std::runtime_error("input");
    return static_cast<uint32_t>(n);
}
uint32_t pointer,clobber,mode,calls,ret,endpoint_sp;
void provider(ts2::GuestRegisters& r,ts2::GuestMemory& m,const ts2::GuestDispatch&) {
    ++calls; ret=m.read32(r.esp); endpoint_sp=r.esp;
    if (mode==3) throw std::runtime_error("provider rejects");
    r.eax=pointer;
    if (clobber) { r.ecx=0xfeedfaceu; r.edx=0xdeadbeefu; r.eflags=0xc97u; }
    if (mode==4) m.write32(r.esp+4,0);
    r.esp+=mode==2?8:4;
}
}
int main() {
    try {
        unsigned n=0;
        while (true) {
            std::cin>>std::ws; if (std::cin.eof()) break;
            if (++n>4096) return 2;
            pointer=word(); clobber=word(); mode=word();
            if (clobber>1 || mode>4) return 2;
            ts2::GuestRegisters r; for (auto p:words(r)) *p=word();
            ts2::GuestMemory m; m.commit(stack,4096);
            for (uint32_t i=0;i<4096;i+=4) m.write32(stack+i,word());
            ts2::GuestDispatch d;
            if (mode!=1) d.bind(0xa084601eu,provider);
            calls=ret=endpoint_sp=0; bool failed=false;
            try { ts2::GuestErrorSlotAbi{0xa084601eu,0xa104f750u}.invoke(r,m,d); }
            catch (const std::exception&) { failed=true; }
            std::cout<<(failed?1:0);
            for (auto p:words(r)) std::cout<<' '<<*p;
            for (uint32_t i=0;i<4096;i+=4) std::cout<<' '<<m.read32(stack+i);
            std::cout<<' '<<calls<<' '<<ret<<' '<<endpoint_sp<<'\n';
        }
        return n?0:2;
    } catch (const std::exception&) { return 2; }
}
