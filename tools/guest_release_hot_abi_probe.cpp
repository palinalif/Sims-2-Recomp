// Diagnostic-only six-model composition; no runtime bindings or Windows heap.
#include "ts2/guest_release_abi.hpp"
#include "ts2/guest_os_error_abi.hpp"
#include "ts2/guest_error_slot_abi.hpp"
#include "ts2/guest_existing_provider_abi.hpp"
#include "ts2/guest_memory.hpp"
#include "ts2/guest_storage_abi.hpp"
#include "ts2/guest_encoded_hot_abi.hpp"
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
void hot(ts2::GuestRegisters& r,ts2::GuestMemory& m,const ts2::GuestDispatch&) {
    std::vector<uint32_t> e{3,m.read32(r.esp)-base,r.esp};
    for (uint32_t i=0;i<4;++i) e.push_back(m.read32(r.esp+4+4*i));
    active->events.push_back(e);
    ts2::GuestEncodedHotAbi{0xa104f540u,0xa10e02b0u}.invoke(r,m);
}
void guard(ts2::GuestRegisters& r,ts2::GuestMemory& m,const ts2::GuestDispatch&) {
    if (r.ecx!=0xc7000050u) throw std::runtime_error("guard target");
    active->events.push_back({5,m.read32(r.esp)-base,r.esp}); r.esp+=4;
}
void storage(uint32_t kind,ts2::GuestRegisters& r,ts2::GuestMemory& m) {
    if (kind==6 && r.ecx!=0xc7000050u) throw std::runtime_error("FLS target");
    if (active->mode==13) throw std::runtime_error("storage rejects");
    ++active->last;
    endpoint(kind,1,active->pointer,active->mode==2?0:4,r,m);
}
void fls(ts2::GuestRegisters& r,ts2::GuestMemory& m,const ts2::GuestDispatch&) { storage(6,r,m); }
void tls(ts2::GuestRegisters& r,ts2::GuestMemory& m,const ts2::GuestDispatch&) { storage(7,r,m); }
void query(ts2::GuestRegisters& r,ts2::GuestMemory& m,const ts2::GuestDispatch& d) {
    ts2::GuestStorageAbi{0xa0847e6cu,0xa0d9a71cu,0xa0d9a2c8u,
        0xa0e06e5cu,0xa0e0a05cu,0xa0e0a064u}.invoke(r,m,d);
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
            const auto heap=word(),index=word(),cookie=word(),encoded=word();
            Case a{word(),word(),word(),word(),word(),0,{}}; a.last=a.error; active=&a;
            if (a.clobber>1 || a.mode>14) return 2;
            std::array<uint32_t,90> pairs; for (auto& v:pairs) v=word();
            ts2::GuestRegisters r; for (auto p:words(r)) *p=word();
            ts2::GuestMemory m;
            const std::array<uint32_t,5> pages{0xa10e0000u,0xa0d9a000u,0xa104f000u,0xa0e07000u,0xc2345000u};
            m.commit(stack,4096); for (auto page:pages) m.commit(page,4096);
            for (uint32_t i=0;i<4096;i+=4) m.write32(stack+i,word());
            m.write32(0xa10e0380u,heap); m.write32(0xa0d9a1dcu,0xc7000000u);
            m.write32(0xa0d9a118u,0xc7000010u); m.write32(0xa0d9a140u,0xc7000020u);
            m.write32(0xa104f89cu,a.mode==14?UINT32_MAX:index);
            m.write32(0xa104f540u,cookie); m.write32(0xa10e02b0u+33*4,encoded);
            m.write32(0xa0d9a71cu,0xc7000030u); m.write32(0xa0d9a2c8u,0xc7000040u);
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
            if (a.mode!=10) d.bind(0xa0847e6cu,hot);
            if (a.mode!=11) d.bind(0xc7000030u,guard);
            if (a.mode!=12) { d.bind(0xc7000040u,tls); d.bind(0xc7000050u,fls); }
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
            std::cout<<' '<<m.read32(ptd+16)<<' '<<m.read32(fallback)<<' '<<a.last
                     <<' '<<m.read32(0xa104f540u)<<' '<<m.read32(0xa10e02b0u+33*4)
                     <<' '<<a.events.size();
            for (const auto& e:a.events) for (auto v:e) std::cout<<' '<<v;
            std::cout<<'\n';
        }
        return n?0:2;
    } catch (const std::exception&) { return 2; }
}
