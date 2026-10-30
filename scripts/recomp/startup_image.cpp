// Bounded development adapter, not shipped startup/Windows services or a sandbox.
// Trusted single-owner compiled callbacks; exceptions unwind all invocation scopes.
#include "startup_image.h"
#include "ts2/guest_image.hpp"
#include "ts2/guest_dispatch.hpp"
#include <array>
#include <algorithm>
#include <fstream>
#include <iostream>
#include <stdexcept>

namespace {
constexpr uint32_t entry=0xa08248a3u, tail=0xa0824727u;
constexpr uint32_t init=0xa08258a9u, helper=0xa082585cu;
struct Observation { std::array<uint32_t,9> state; };
constexpr uint32_t cookie=0xa104f540u, complement=0xa104f580u;
constexpr std::array<uint32_t,4> slots{0xa0d9a2a4u,0xa0d9a194u,0xa0d9a1bcu,0xa0d9a24cu};
ts2::GuestImage* image{};
ts2::GuestDispatch dispatcher;
void (*initial)(uint32_t*){};
void (*nested)(uint32_t*){};
void (*entry_callback)(uint32_t*){};
bool observing{};
uint32_t stack_base{}, original_sp{}, current{};
bool ready{};
void require(bool value) { if (!value) throw std::runtime_error("startup scope"); }
bool global(uint32_t a) { return a==cookie || a==complement; }
bool stack_word(uint32_t a) {
    return a>=stack_base && uint64_t(a)+4<=uint64_t(stack_base)+4096;
}
struct Scope {
    uint32_t previous;
    explicit Scope(uint32_t va): previous(current) { current=va; }
    ~Scope() { current=previous; }
};
void adapter(ts2::GuestRegisters& r, ts2::GuestMemory& m, const ts2::GuestDispatch&) {
    require(&m==image->memory.get() && current);
    std::array<uint32_t,9> s{r.eax,r.ecx,r.edx,r.ebx,r.esp,r.ebp,r.esi,r.edi,r.eflags};
    (current==entry?entry_callback:current==init?initial:nested)(s.data());
    require(current!=entry); // Entry must stop nonlocally, never return.
    r={s[0],s[1],s[2],s[3],s[4],s[5],s[6],s[7],s[8]};
}
}
void ts2_startup_bind(void (*a)(uint32_t*), void (*b)(uint32_t*)) {
    require(image && !current && !initial && a && b);
    initial=a; nested=b;
}
void ts2_startup_bind_entry(void (*callback)(uint32_t*)) {
    require(image && !current && initial && !entry_callback && callback);
    entry_callback=callback;
}
[[noreturn]] void ts2_startup_stop(uint32_t va, const uint32_t s[9]) {
    require(image && ready && observing && current==entry && va==tail && s);
    Observation stop{};
    std::copy(s,s+9,stop.state.begin());
    throw stop; // No tail target binding, instruction execution or stack cleanup.
}
uint32_t ts2_startup_observe_entry(uint32_t s[9]) {
    require(image && ready && !current && !observing && entry_callback && s);
    struct ObserveScope {
        ObserveScope() { observing=true; }
        ~ObserveScope() { observing=false; }
    } scope;
    try { ts2_startup_invoke(entry,s); }
    catch(const Observation& stop) {
        require(!current);
        std::copy(stop.state.begin(),stop.state.end(),s);
        return tail;
    }
    throw std::runtime_error("entry returned");
}
void ts2_startup_begin(uint32_t stack, uint32_t sp, uint32_t value) {
    require(image && !current && initial && !(stack&4095u) && stack &&
            uint64_t(stack)+4096<=0x100000000ull && uint64_t(stack)+0x800==sp);
    const uint64_t end=uint64_t(stack)+4096;
    require(!(stack<uint64_t(image->image_base)+image->image_size && end>image->image_base));
    auto& m=*image->memory;
    // Setup mutates only these declared globals and external stack, never a data page.
    m.commit(stack,4096);
    std::array<uint8_t,4096> bytes; bytes.fill(0xa5);
    m.write_bytes(stack,bytes);
    m.write32(sp,0x71000000u);
    m.write32(cookie,value); m.write32(complement,0xa5a5a5a5u);
    stack_base=stack; original_sp=sp; ready=true;
}
uint32_t ts2_startup_read(uint32_t a) {
    require(image && ready && current && !(a&3u));
    if (stack_word(a) || global(a)) return image->memory->read32(a);
    // Explicit diagnostic IAT binding overlay: physical image slots never change.
    for (size_t k=0;k<slots.size();++k) if(a==slots[k]) return 0x72000000u+uint32_t(k*16);
    throw std::runtime_error("startup read");
}
void ts2_startup_write(uint32_t a,uint32_t value) {
    require(image && ready && current && !(a&3u));
    require(global(a) || (stack_word(a) && a>=original_sp-(observing?48u:44u) && uint64_t(a)+4<=original_sp));
    image->memory->write32(a,value);
}
uint32_t ts2_startup_peek(uint32_t a) {
    require(image && ready && !current && !(a&3u));
    require(stack_word(a) || global(a));
    return image->memory->read32(a);
}
void ts2_startup_invoke(uint32_t va,uint32_t s[9]) {
    require(image && ready && s && initial && nested);
    require((!current && va==init && !observing) ||
            (!current && va==entry && observing && entry_callback) ||
            (current==entry && va==init) || (current==init && va==helper));
    ts2::GuestRegisters r{s[0],s[1],s[2],s[3],s[4],s[5],s[6],s[7],s[8]};
    Scope scope(va);
    dispatcher.invoke(va,r,*image->memory);
    const std::array<uint32_t,9> out{r.eax,r.ecx,r.edx,r.ebx,r.esp,r.ebp,r.esi,r.edi,r.eflags};
    std::copy(out.begin(),out.end(),s);
}
extern "C" int fixture_main();
int main(int argc,char** argv) {
    try {
        require(argc==2);
        std::ifstream in(argv[1],std::ios::binary|std::ios::ate);
        const auto size=in.tellg();
        require(in && size>0 && size<=256*1024*1024);
        std::vector<uint8_t> bytes(static_cast<size_t>(size));
        in.seekg(0); require(bool(in.read(reinterpret_cast<char*>(bytes.data()),size)));
        auto loaded=ts2::load_guest_image(bytes); image=&loaded;
        dispatcher.bind(init,adapter); dispatcher.bind(helper,adapter);
        dispatcher.bind(entry,adapter); // Tail deliberately NOT bound.
        // Compare the complete mapped image, including headers, BSS and gaps.
        std::vector<uint32_t> before(loaded.image_size/4);
        for(size_t i=0;i<before.size();++i) before[i]=loaded.memory->read32(loaded.image_base+uint32_t(i*4));
        const int result=fixture_main();
        require(!current);
        for(size_t i=0;i<before.size();++i) {
            const uint32_t a=loaded.image_base+uint32_t(i*4);
            require(global(a) || before[i]==loaded.memory->read32(a));
        }
        require(result==0);
        image=nullptr; return 0;
    } catch (...) { std::cerr<<"Scoped startup image failed\n"; return 1; }
}
