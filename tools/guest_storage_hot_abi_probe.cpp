// Diagnostic-only composition of existing opt-in ABI models. No Android binding.
#include "ts2/guest_storage_abi.hpp"
#include "ts2/guest_encoded_hot_abi.hpp"
#include "ts2/guest_memory.hpp"
#include <array>
#include <iostream>
#include <stdexcept>
#include <vector>
namespace {
constexpr uint32_t stack=0xb8000000u, base=0xa0000000u;
constexpr uint32_t cookie=0xa104f540u, cache=0xa10e02b0u;
std::array<uint32_t*,9> words(ts2::GuestRegisters& r) {
    return {&r.eax,&r.ebx,&r.ecx,&r.edx,&r.esi,&r.edi,&r.ebp,&r.esp,&r.eflags};
}
uint32_t word() {
    uint64_t n; if (!(std::cin>>n) || n>UINT32_MAX) throw std::runtime_error("input");
    return static_cast<uint32_t>(n);
}
struct Case { uint32_t result,clobber,mode; std::vector<std::vector<uint32_t>> events; };
Case* active=nullptr; // Single-threaded trusted transport, not a service runtime.
void observe(uint32_t kind,ts2::GuestRegisters& r,ts2::GuestMemory& m) {
    const auto count=kind==1?4u:(kind==2?0u:1u);
    std::vector<uint32_t> e{kind,m.read32(r.esp)-base};
    for (auto p:words(r)) e.push_back(*p);
    for (uint32_t i=0;i<count;++i) e.push_back(m.read32(r.esp+4+4*i));
    active->events.push_back(e);
}
void hot(ts2::GuestRegisters& r,ts2::GuestMemory& m,const ts2::GuestDispatch&) {
    observe(1,r,m);
    ts2::GuestEncodedHotAbi{cookie,cache}.invoke(r,m);
}
void guard(ts2::GuestRegisters& r,ts2::GuestMemory& m,const ts2::GuestDispatch&) {
    observe(2,r,m); r.esp+=4;
}
void storage(uint32_t kind,ts2::GuestRegisters& r,ts2::GuestMemory& m) {
    observe(kind,r,m);
    if (active->mode==4) throw std::runtime_error("storage rejects");
    r.eax=active->result;
    if (active->clobber) { r.ecx=0xfeedfaceu; r.edx=0xdeadbeefu; }
    r.esp+=active->mode==3?4:8;
}
void fls(ts2::GuestRegisters& r,ts2::GuestMemory& m,const ts2::GuestDispatch&) { storage(3,r,m); }
void tls(ts2::GuestRegisters& r,ts2::GuestMemory& m,const ts2::GuestDispatch&) { storage(4,r,m); }
void selector(ts2::GuestRegisters& r,ts2::GuestMemory& m,const ts2::GuestDispatch& d) {
    ts2::GuestStorageAbi{0xa0847e6cu,0xa0d9a71cu,0xa0d9a2c8u,
        0xa0e06e5cu,0xa0e0a05cu,0xa0e0a064u}.invoke(r,m,d);
}
}
int main() {
    try {
        unsigned n=0;
        while (true) {
            std::cin>>std::ws; if (std::cin.eof()) break;
            if (++n>4096) return 2;
            const auto c=word(),encoded=word();
            Case a{word(),word(),word(),{}}; active=&a;
            if (a.clobber>1 || a.mode>4) return 2;
            ts2::GuestRegisters r; for (auto p:words(r)) *p=word();
            ts2::GuestMemory m; m.commit(stack,4096); m.commit(0xa0d9a000u,4096);
            m.commit(cookie & ~4095u,4096); m.commit(cache & ~4095u,4096);
            for (uint32_t i=0;i<4096;i+=4) m.write32(stack+i,word());
            m.write32(cookie,c); m.write32(cache+33*4,encoded);
            m.write32(0xa0d9a71cu,0xc7000000u); m.write32(0xa0d9a2c8u,0xc7000010u);
            ts2::GuestDispatch d; d.bind(0xa08480bfu,selector);
            if (a.mode!=1) d.bind(0xa0847e6cu,hot);
            if (a.mode!=2) d.bind(0xc7000000u,guard);
            d.bind(0xc7000010u,tls); d.bind(0xc7000020u,fls);
            bool failed=false;
            try { d.invoke(0xa08480bfu,r,m); } catch (const std::exception&) { failed=true; }
            std::cout<<(failed?1:0);
            for (auto p:words(r)) std::cout<<' '<<*p;
            for (auto page : {stack,cookie & ~4095u,cache & ~4095u})
                for (uint32_t i=0;i<4096;i+=4) std::cout<<' '<<m.read32(page+i);
            std::cout<<' '<<a.events.size();
            for (const auto& e:a.events) for (auto v:e) std::cout<<' '<<v;
            std::cout<<'\n';
        }
        return n?0:2;
    } catch (const std::exception&) { return 2; }
}
