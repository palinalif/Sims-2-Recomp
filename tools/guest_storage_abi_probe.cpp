// Authored diagnostic transport. Single active case, not linked to Android.
#include "ts2/guest_storage_abi.hpp"
#include "ts2/guest_memory.hpp"
#include <array>
#include <iostream>
#include <vector>
#include <stdexcept>
namespace {
constexpr uint32_t stack=0xb8000000u, base=0xa0000000u;
struct Case { uint32_t target,result,clobber,wrong; std::vector<std::vector<uint32_t>> events; };
Case* active=nullptr;
uint32_t word() {
    uint64_t n; if (!(std::cin>>n) || n>UINT32_MAX) throw std::runtime_error("input");
    return static_cast<uint32_t>(n);
}
void endpoint(uint32_t kind,ts2::GuestRegisters& r,ts2::GuestMemory& m) {
    auto& c=*active;
    const auto sp=r.esp, ret=m.read32(sp);
    std::vector<uint32_t> e{kind,ret-base,sp,r.ecx};
    const auto count=kind==1?4u:(kind==2?0u:1u);
    for (uint32_t i=0;i<count;++i) e.push_back(m.read32(sp+4+4*i));
    c.events.push_back(e);
    if ((kind==2 && c.wrong==7) || (kind==3 && c.wrong==8))
        throw std::runtime_error("endpoint rejects");
    if (kind!=2) {
        r.eax=kind==1?(c.wrong==5?0xc7000030u:c.target):c.result;
        if (c.clobber) { r.ecx=0xfeedfaceu; r.edx=0xdeadbeefu; }
    }
    r.esp+=4+((kind>=3 && c.wrong!=1)?4u:0u)+(kind==1 && c.wrong==2?16u:0u);
}
void resolve(ts2::GuestRegisters& r,ts2::GuestMemory& m,const ts2::GuestDispatch&) { endpoint(1,r,m); }
void guard(ts2::GuestRegisters& r,ts2::GuestMemory& m,const ts2::GuestDispatch&) { endpoint(2,r,m); }
void fls(ts2::GuestRegisters& r,ts2::GuestMemory& m,const ts2::GuestDispatch&) { endpoint(3,r,m); }
void tls(ts2::GuestRegisters& r,ts2::GuestMemory& m,const ts2::GuestDispatch&) { endpoint(4,r,m); }
std::array<uint32_t*,9> words(ts2::GuestRegisters& r) {
    return {&r.eax,&r.ebx,&r.ecx,&r.edx,&r.esi,&r.edi,&r.ebp,&r.esp,&r.eflags};
}
}
int main() {
    try {
        ts2::GuestMemory m;
        m.commit(stack,4096); m.commit(0xa0d9a000u,4096);
        ts2::GuestDispatch d;
        d.bind(0xa0847e6cu,resolve); d.bind(0xc7000000u,guard);
        d.bind(0xc7000010u,tls); d.bind(0xc7000020u,fls);
        m.write32(0xa0d9a71cu,0xc7000000u); m.write32(0xa0d9a2c8u,0xc7000010u);
        const ts2::GuestStorageAbi abi{0xa0847e6cu,0xa0d9a71cu,0xa0d9a2c8u,
            0xa0e06e5cu,0xa0e0a05cu,0xa0e0a064u};
        unsigned n=0;
        while (true) {
            std::cin>>std::ws; if (std::cin.eof()) break;
            if (++n>4096) return 2;
            Case c{word(),word(),word(),word(),{}}; active=&c;
            if ((c.target!=0 && c.target!=0xc7000020u) || c.clobber>1 || c.wrong>8) return 2;
            ts2::GuestRegisters r;
            for (auto p:words(r)) *p=word();
            for (uint32_t i=0;i<4096;i+=4) m.write32(stack+i,word());
            // Negative paths: absent resolver/guard/provider and bad cleanup.
            m.write32(0xa0d9a2c8u,c.wrong==6?1u:0xc7000010u);
            auto a=abi;
            if (c.wrong==3) a.resolver=1;
            if (c.wrong==4) a.guard_slot=0;
            bool failed=false;
            try { a.invoke(r,m,d); } catch (const std::exception&) { failed=true; }
            std::cout<<(failed?1:0);
            for (auto p:words(r)) std::cout<<' '<<*p;
            for (uint32_t i=0;i<4096;i+=4) std::cout<<' '<<m.read32(stack+i);
            std::cout<<' '<<c.events.size();
            for (const auto& e:c.events) { std::cout<<' '<<e.size(); for (auto v:e) std::cout<<' '<<v; }
            std::cout<<'\n';
        }
        return n?0:2;
    } catch (const std::exception&) { return 2; }
}
