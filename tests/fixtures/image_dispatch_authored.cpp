// Authored boundary controls, not lifted game code.
#include "image_dispatch.h"
#include <array>
#include <stdexcept>
#define CHECK(x) do { if (!(x)) throw std::runtime_error("authored check"); } while (false)
namespace {
constexpr uint32_t address=0xf0000100u;
void read(uint32_t* s) { s[0]=ts2_image_read32(address); }
void gap(uint32_t* s) { s[0]=ts2_image_read32(address+4); }
void crossing(uint32_t* s) { s[0]=ts2_image_read32(address+1); }
void overflow(uint32_t* s) { s[0]=ts2_image_read32(0xfffffffeu); }
unsigned startup_calls{};
void startup(uint32_t*) { ++startup_calls; }
void throws(uint32_t*) { throw std::runtime_error("endpoint"); }
void reentry(uint32_t* s) {
    const auto old=*s;
    CHECK(ts2_image_dispatch(0,s,nullptr,0,nullptr,0)==TS2_READ_REENTRY);
    CHECK(*s==old);
}
}
extern "C" int fixture_main() {
    std::array<uint32_t,9> state{1,2,3,4,5,6,7,8,9};
    uint8_t bytes[]{0x78,0x56,0x34,0x12};
    Ts2ReadSpan span{address,4,bytes};
    Ts2ReadEntry entry{0xa0001250u,read};
    for (unsigned repeat=0;repeat<3;++repeat) {
        bytes[0]=uint8_t(0x78+repeat);
        CHECK(ts2_image_dispatch(entry.va,state.data(),&span,1,&entry,1)==TS2_READ_OK);
        CHECK(state[0]==0x12345678u+repeat);
        for (unsigned i=1;i<9;++i) CHECK(state[i]==i+1);
    }
    auto before=state;
    for (auto fn : {gap,crossing,overflow,reentry}) {
        entry.call=fn;
        CHECK(ts2_image_dispatch(entry.va,state.data(),&span,1,&entry,1)==TS2_READ_FAULT);
        CHECK(state==before);
    }
    entry.call=throws;
    CHECK(ts2_image_dispatch(entry.va,state.data(),&span,1,&entry,1)==TS2_READ_EXCEPTION);
    CHECK(state==before);
    entry.call=read;
    CHECK(ts2_image_dispatch(entry.va+1,state.data(),&span,1,&entry,1)==TS2_READ_UNRESOLVED);
    CHECK(state==before);
    const auto saved=span;
    span.address=0xa0001000u;
    CHECK(ts2_image_dispatch(entry.va,state.data(),&span,1,&entry,1)==TS2_READ_INVALID);
    CHECK(state==before);
    span=saved;
    // The verified startup pair is NOT bound by the read-only seam, even when
    // the caller supplies its exact VAs and valid non-image stack storage.
    for (auto va : {0xa08258a9u,0xa082585cu}) {
        Ts2ReadEntry candidate{va,startup};
        CHECK(ts2_image_dispatch(va,state.data(),&span,1,&candidate,1)==TS2_READ_UNRESOLVED);
        CHECK(state==before && startup_calls==0);
    }
    Ts2ReadEntry duplicates[]{entry,entry};
    CHECK(ts2_image_dispatch(entry.va,state.data(),&span,1,duplicates,2)==TS2_READ_INVALID);
    CHECK(state==before);
    CHECK(ts2_image_dispatch(entry.va,state.data(),&span,1,&entry,1)==TS2_READ_OK);
    CHECK(state==before);
    return 0;
}
