// Diagnostic-only bridge: private compiled caller on real GuestMemory/GuestDispatch.
// No original bytes, emulator, service responses or Android runtime binding.
#include "ts2/guest_memory.hpp"
#include "ts2/guest_dispatch.hpp"
#include <array>
#include <memory>
#include <stdexcept>

namespace {
constexpr std::array<uint32_t,6> bases{0x70000000u,0x72000000u,0xA104F000u,0xA10DF000u,0xA0009000u,0xA0E17000u};
constexpr std::array<uint32_t,8> targets{0xA01ABD40u,0xA0001240u,0xA0001250u,0xA0001270u,0xA0001290u,0xA00012D0u,0xA000FCF0u,0xA0009550u};
std::unique_ptr<ts2::GuestMemory> memory;
ts2::GuestDispatch dispatcher;
using Callback=void (*)(uint32_t*);
Callback current{};
unsigned depth{};
void check(uint32_t a,unsigned size,bool write) {
    if (!memory || (size!=1 && size!=4) || a%size) throw std::runtime_error("access");
    for (unsigned p=0;p<(write?4u:6u);++p)
        if (a>=bases[p] && uint64_t(a)+size<=uint64_t(bases[p])+4096) return;
    throw std::runtime_error("range");
}
void adapter(ts2::GuestRegisters& r,ts2::GuestMemory& m,const ts2::GuestDispatch&) {
    if (&m!=memory.get() || !current) throw std::runtime_error("context");
    std::array<uint32_t,8> s{r.eax,r.ebx,r.ecx,r.edx,r.esi,r.edi,r.ebp,r.esp};
    current(s.data());
    r={s[0],s[2],s[3],s[1],s[7],s[6],s[4],s[5],r.eflags};
}
}
extern "C" void cache_reset(const uint8_t* data) {
    if (depth) throw std::runtime_error("reentry");
    memory=std::make_unique<ts2::GuestMemory>();
    dispatcher=ts2::GuestDispatch{};
    for (auto va:targets) dispatcher.bind(va,adapter);
    for (unsigned p=0;p<6;++p) {
        auto page=memory->page_size();
        auto start=uint64_t(bases[p])/page*page;
        auto end=(uint64_t(bases[p])+4096+page-1)/page*page;
        memory->commit(uint32_t(start),end-start);
        memory->write_bytes(bases[p],{data+p*4096,4096});
    }
}
extern "C" uint32_t cache_read(uint32_t a,unsigned size) {
    check(a,size,false);
    return size==1?memory->read8(a):memory->read32(a);
}
extern "C" void cache_write(uint32_t a,unsigned size,uint32_t v) {
    check(a,size,true);
    if (size==4) memory->write32(a,v);
    else { uint8_t b=uint8_t(v);memory->write_bytes(a,{&b,1}); }
}
extern "C" void cache_copy(uint8_t* out) {
    for (unsigned p=0;p<6;++p) for (unsigned k=0;k<4096;++k)
        out[p*4096+k]=memory->read8(bases[p]+k);
}
extern "C" void cache_invoke(uint32_t va,uint32_t* s,Callback callback) {
    if (!memory || !callback || depth>=8) throw std::runtime_error("invoke");
    auto old=current;
    current=callback;
    ++depth;
    try {
        ts2::GuestRegisters r{s[0],s[2],s[3],s[1],s[7],s[6],s[4],s[5],0};
        dispatcher.invoke(va,r,*memory);
        std::array<uint32_t,8> out{r.eax,r.ebx,r.ecx,r.edx,r.esi,r.edi,r.ebp,r.esp};
        for (unsigned k=0;k<8;++k) s[k]=out[k];
    } catch (...) { --depth;current=old;throw; }
    --depth;current=old;
}
