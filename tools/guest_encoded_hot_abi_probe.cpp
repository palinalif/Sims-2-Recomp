// Public bounded transport; no game code, one isolated case per request.
#include "ts2/guest_encoded_hot_abi.hpp"
#include "ts2/guest_memory.hpp"
#include <array>
#include <iostream>
#include <stdexcept>
namespace {
constexpr uint32_t stack=0xb8000000u, cookie=0xa104f540u, cache=0xa10e02b0u;
uint32_t word() {
    uint64_t n; if (!(std::cin>>n) || n>UINT32_MAX) throw std::runtime_error("input");
    return static_cast<uint32_t>(n);
}
std::array<uint32_t*,9> words(ts2::GuestRegisters& r) {
    return {&r.eax,&r.ebx,&r.ecx,&r.edx,&r.esi,&r.edi,&r.ebp,&r.esp,&r.eflags};
}
void hot(ts2::GuestRegisters& r,ts2::GuestMemory& m,const ts2::GuestDispatch&) {
    ts2::GuestEncodedHotAbi{cookie,cache}.invoke(r,m);
}
}
int main() {
    try {
        unsigned n=0;
        while (true) {
            std::cin>>std::ws; if (std::cin.eof()) break;
            if (++n>4096) return 2;
            const auto c=word(), encoded=word(), mode=word();
            if (mode>3) return 2;
            ts2::GuestRegisters r; for (auto p:words(r)) *p=word();
            ts2::GuestMemory m; m.commit(stack,4096);
            m.commit(cookie & ~4095u,4096); m.commit(cache & ~4095u,4096);
            for (uint32_t i=0;i<4096;i+=4) m.write32(stack+i,word());
            m.write32(cookie,c);
            // Test all indices without out-of-range setup writes.
            const auto index=m.read32(stack+2048+4);
            const auto slot=cache+4*(index<64?index:0);
            m.write32(slot,encoded);
            ts2::GuestDispatch d; d.bind(0xa0847e6cu,hot);
            bool failed=false;
            try {
                if (mode==1) ts2::GuestEncodedHotAbi{0,cache}.invoke(r,m);
                else if (mode==2) ts2::GuestEncodedHotAbi{cookie,0xfffffffeu}.invoke(r,m);
                else if (mode==3) ts2::GuestEncodedHotAbi{stack+2048,cookie}.invoke(r,m);
                else d.invoke(0xa0847e6cu,r,m);
            } catch (const std::exception&) { failed=true; }
            std::cout<<(failed?1:0);
            for (auto p:words(r)) std::cout<<' '<<*p;
            for (uint32_t i=0;i<4096;i+=4) std::cout<<' '<<m.read32(stack+i);
            // Full immutable pages, not just the selected words.
            for (auto page : {cookie & ~4095u,cache & ~4095u})
                for (uint32_t i=0;i<4096;i+=4) std::cout<<' '<<m.read32(page+i);
            std::cout<<'\n';
        }
        return n?0:2;
    } catch (const std::exception&) { return 2; }
}
