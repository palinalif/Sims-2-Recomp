// Diagnostic-only four-model composition; no runtime bindings or Windows heap.
#include "ts2/guest_release_abi.hpp"
#include "ts2/guest_os_error_abi.hpp"
#include "ts2/guest_error_slot_abi.hpp"
#include "ts2/guest_existing_provider_abi.hpp"
#include "ts2/guest_memory.hpp"
#include <array>
#include <iostream>
#include <map>
#include <stdexcept>
#include <vector>
namespace {
constexpr uint32_t base=0xa0000000u, stack=0xb8000000u, table=0xa0e073f0u;
constexpr uint32_t ptd=0xc2345100u, fallback=0xa104f750u;
std::array<uint32_t*,9> words(ts2::GuestRegisters& r) {
    return {&r.eax,&r.ebx,&r.ecx,&r.edx,&r.esi,&r.edi,&r.ebp,&r.esp,&r.eflags};
}
uint32_t word() {
    uint64_t n; if (!(std::cin>>n) || n>UINT32_MAX) throw std::runtime_error("input");
    return static_cast<uint32_t>(n);
}
struct Case { uint32_t result,error,pointer,clobber,mode,last; std::vector<std::vector<uint32_t>> events; };
Case* active=nullptr;
void endpoint(uint32_t kind,uint32_t count,uint32_t response,uint32_t pop,
              ts2::GuestRegisters& r,ts2::GuestMemory& m) {
    std::vector<uint32_t> e{kind,m.read32(r.esp)-base,r.esp};
    for (uint32_t i=0;i<count;++i) e.push_back(m.read32(r.esp+4+4*i));
    active->events.push_back(e); r.eax=response;
    if (active->clobber) { r.ecx=0xfeedfaceu; r.edx=0xdeadbeefu; }
    r.esp+=4+pop;
}
void free_api(ts2::GuestRegisters& r,ts2::GuestMemory& m,const ts2::GuestDispatch&) {
    endpoint(1,3,active->result,active->mode==1?0:12,r,m);
}
void get(ts2::GuestRegisters& r,ts2::GuestMemory& m,const ts2::GuestDispatch&) {
    endpoint(2,0,active->last,0,r,m);
}
void query(ts2::GuestRegisters& r,ts2::GuestMemory& m,const ts2::GuestDispatch&) {
    ++active->last;
    endpoint(3,1,active->pointer,active->mode==2?0:4,r,m);
}
void set(ts2::GuestRegisters& r,ts2::GuestMemory& m,const ts2::GuestDispatch&) {
    active->last=m.read32(r.esp+4);
    endpoint(4,1,0xbaadf00du,active->mode==3?0:4,r,m);
}
void mapper(ts2::GuestRegisters& r,ts2::GuestMemory& m,const ts2::GuestDispatch&) {
    ts2::GuestOsErrorAbi{table}.invoke(r,m);
}
void provider(ts2::GuestRegisters& r,ts2::GuestMemory& m,const ts2::GuestDispatch& d) {
    ts2::GuestExistingProviderAbi{0xa104f89cu,0xa0d9a118u,0xa0d9a140u,0xa08480bfu}.invoke(r,m,d);
}
void accessor(ts2::GuestRegisters& r,ts2::GuestMemory& m,const ts2::GuestDispatch& d) {
    ts2::GuestErrorSlotAbi{0xa084601eu,fallback}.invoke(r,m,d);
}
}
int main() {
    std::ios::sync_with_stdio(false); std::cin.tie(nullptr);
    try {
        unsigned n=0;
        while (true) {
            std::cin>>std::ws; if (std::cin.eof()) break;
            if (++n>4096) return 2;
            const auto heap=word(),index=word();
            Case a{word(),word(),word(),word(),word(),0,{}}; a.last=a.error; active=&a;
            if (a.clobber>1 || a.mode>9) return 2;
            std::array<uint32_t,90> pairs; for (auto& v:pairs) v=word();
            ts2::GuestRegisters r; for (auto p:words(r)) *p=word();
            ts2::GuestMemory m;
            const std::array<uint32_t,5> pages{0xa10e0000u,0xa0d9a000u,0xa104f000u,0xa0e07000u,0xc2345000u};
            m.commit(stack,4096); for (auto page:pages) m.commit(page,4096);
            for (uint32_t i=0;i<4096;i+=4) m.write32(stack+i,word());
            m.write32(0xa10e0380u,heap); m.write32(0xa0d9a1dcu,0xc7000000u);
            m.write32(0xa0d9a118u,0xc7000010u); m.write32(0xa0d9a140u,0xc7000020u);
            m.write32(0xa104f89cu,index);
            m.write32(ptd+16,0x96969696u); m.write32(fallback,0x96969696u);
            for (uint32_t i=0;i<90;++i) m.write32(table+4*i,pairs[i]);
            std::map<uint32_t,std::array<uint32_t,1024>> before;
            for (auto page:pages) for (uint32_t i=0;i<1024;++i) before[page][i]=m.read32(page+4*i);
            ts2::GuestDispatch d;
            if (a.mode!=4) d.bind(0xc7000000u,free_api);
            d.bind(0xc7000010u,get); d.bind(0xc7000020u,set);
            if (a.mode!=5) d.bind(0xa0831a7au,mapper);
            if (a.mode!=6) d.bind(0xa0831b17u,accessor);
            if (a.mode!=7) d.bind(0xa084601eu,provider);
            if (a.mode!=8) d.bind(0xa08480bfu,query);
            // Mode9 supplies an unmapped destination via a valid provider value.
            if (a.mode==9) a.pointer=0xd0000000u;
            bool failed=false;
            try { ts2::GuestReleaseAbi{0xa10e0380u,0xa0d9a1dcu,0xa0d9a118u,0xa0831a7au,0xa0831b17u}.invoke(r,m,d); }
            catch (const std::exception&) { failed=true; }
            for (auto page:pages) for (uint32_t i=0;i<1024;++i) {
                auto address=page+4*i;
                if (address!=ptd+16 && address!=fallback && m.read32(address)!=before[page][i]) return 2;
            }
            std::cout<<(failed?1:0); for (auto p:words(r)) std::cout<<' '<<*p;
            for (uint32_t i=0;i<4096;i+=4) std::cout<<' '<<m.read32(stack+i);
            std::cout<<' '<<m.read32(ptd+16)<<' '<<m.read32(fallback)<<' '<<a.last<<' '<<a.events.size();
            for (const auto& e:a.events) for (auto v:e) std::cout<<' '<<v;
            std::cout<<'\n';
        }
        return n?0:2;
    } catch (const std::exception&) { return 2; }
}
