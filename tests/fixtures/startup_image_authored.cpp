// Authored boundary controls, no original function implementation.
#include "startup_image.h"
#include <array>
#include <stdexcept>
#define CHECK(x) do { if(!(x)) throw std::runtime_error("authored check"); } while(false)
namespace {
constexpr uint32_t stack=0x70000000u, sp=stack+0x800u;
constexpr uint32_t cookie=0xa104f540u, complement=0xa104f580u, slot=0xa0d9a2a4u;
unsigned mode{}, entry_mode{}, calls{}, helpers{}, entries{};
void helper(uint32_t* s) {
    ++helpers;
    Ts2StartupWord{complement}=~uint32_t(Ts2StartupWord{cookie});
    ++s[0];
}
void outer(uint32_t* s) {
    ++calls;
    switch(mode) {
    case 1: ts2_startup_write(slot,1); break;
    case 2: ts2_startup_write(cookie+4,1); break;
    case 3: ts2_startup_write(sp,1); break;
    case 4: ts2_startup_write(sp-48,1); break;
    case 5: (void)ts2_startup_read(stack+4096); break;
    case 6: (void)ts2_startup_read(0xfffffffeu); break;
    case 7: ts2_startup_invoke(0xa08258a9u,s); break;
    case 8: ts2_startup_begin(stack,sp,1); break;
    case 9: (void)ts2_startup_peek(cookie); break;
    case 10: throw std::runtime_error("callback");
    case 11: ts2_startup_write(0xa0001000u,1); break;
    case 12: (void)ts2_startup_read(cookie+4); break;
    case 13: ts2_startup_stop(0xa0824727u,s); break;
    default:
        CHECK(ts2_startup_read(slot)==0x72000000u);
        CHECK(ts2_startup_read(0xa0d9a194u)==0x72000010u);
        CHECK(ts2_startup_read(0xa0d9a1bcu)==0x72000020u);
        CHECK(ts2_startup_read(0xa0d9a24cu)==0x72000030u);
        Ts2StartupWord{sp-4}=Ts2StartupWord{cookie};
        ts2_startup_invoke(0xa082585cu,s);
        CHECK(ts2_startup_read(sp-4)==ts2_startup_read(cookie));
        break;
    }
}
void entry(uint32_t* s) {
    ++entries;
    switch(entry_mode) {
    case 1: return; // Returning entry cannot satisfy an observation.
    case 2: ts2_startup_stop(0xa0824728u,s);
    case 3: ts2_startup_invoke(0xa082585cu,s); break;
    case 4: (void)ts2_startup_observe_entry(s); break;
    case 5: ts2_startup_write(sp-52,1); break;
    case 6: throw std::runtime_error("entry callback");
    default:
        ts2_startup_write(sp-48,0x2468ace0u);
        ts2_startup_invoke(0xa08258a9u,s);
        ts2_startup_stop(0xa0824727u,s);
    }
    throw std::runtime_error("invalid entry resumed");
}
template<class F> void rejects(F fn) {
    bool rejected=false;
    try { fn(); } catch(const std::exception&) { rejected=true; }
    CHECK(rejected);
}
}
extern "C" int fixture_main() {
    std::array<uint32_t,9> state{1,2,3,4,sp,6,7,8,9};
    ts2_startup_bind(outer,helper);
    rejects([&]{ts2_startup_bind(outer,helper);});
    rejects([&]{ts2_startup_invoke(0xa08258a9u,state.data());});
    for(auto bad : {0xa0000000u,0xfffff800u,stack+1})
        rejects([&]{ts2_startup_begin(bad,bad+0x800u,1);});
    ts2_startup_begin(stack,sp,0x12345678u);
    auto before=state;
    for(auto va : {0xa082585cu,0xa0824727u,0u}) {
        rejects([&]{ts2_startup_invoke(va,state.data());});
        CHECK(state==before && calls==0);
    }
    rejects([&]{ts2_startup_read(cookie);});
    rejects([&]{ts2_startup_write(cookie,1);});
    for(mode=1;mode<=13;++mode) {
        rejects([&]{ts2_startup_invoke(0xa08258a9u,state.data());});
        CHECK(state==before && helpers==0);
        CHECK(ts2_startup_peek(cookie)==0x12345678u);
        CHECK(ts2_startup_peek(complement)==0xa5a5a5a5u);
        CHECK(ts2_startup_peek(sp)==0x71000000u);
    }
    mode=0;
    for(unsigned n=0;n<3;++n) {
        ts2_startup_invoke(0xa08258a9u,state.data());
        CHECK(state[0]==n+2 && helpers==n+1);
        CHECK(ts2_startup_peek(complement)==~0x12345678u);
        CHECK(ts2_startup_peek(sp-4)==0x12345678u);
        for(unsigned j=1;j<9;++j) CHECK(state[j]==before[j]);
    }
    rejects([&]{ts2_startup_observe_entry(state.data());}); // Unbound.
    rejects([&]{ts2_startup_stop(0xa0824727u,state.data());}); // Not observing.
    ts2_startup_bind_entry(entry);
    rejects([&]{ts2_startup_bind_entry(entry);});
    rejects([&]{ts2_startup_invoke(0xa08248a3u,state.data());}); // No observer.
    rejects([&]{ts2_startup_observe_entry(nullptr);});
    const auto entry_before=state;
    for(entry_mode=1;entry_mode<=6;++entry_mode) {
        rejects([&]{ts2_startup_observe_entry(state.data());});
        CHECK(state==entry_before && entries==entry_mode);
        CHECK(ts2_startup_peek(cookie)==0x12345678u); // Scope unwound.
    }
    entry_mode=0;
    for(unsigned n=0;n<3;++n) {
        CHECK(ts2_startup_observe_entry(state.data())==0xa0824727u);
        CHECK(state[0]==entry_before[0]+n+1 && helpers==n+4);
        CHECK(ts2_startup_peek(sp-48)==0x2468ace0u);
        rejects([&]{ts2_startup_invoke(0xa0824727u,state.data());}); // Tail never bound.
    }
    mode=4; // Entry-only extra stack word is rejected again after observation.
    rejects([&]{ts2_startup_invoke(0xa08258a9u,state.data());});
    // Same persistent globals across calls; new case setup touches only declared bytes.
    ts2_startup_begin(stack+0x10000,sp+0x10000,0xfedcba98u);
    CHECK(ts2_startup_peek(cookie)==0xfedcba98u);
    return 0;
}
