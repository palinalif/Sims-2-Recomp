#include "../tools/scoped_dispatch_bridge.h"
#include <array>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#define CHECK(x) do { if (!(x)) throw std::runtime_error(#x); } while (false)
namespace {
constexpr uint32_t root=0xa0002000, leafva=root+0x20;
constexpr uint32_t obj=0xe1000000, stack=0xf1000000;
void put(unsigned char* p, uint32_t x) {
    for (unsigned i=0;i<4;++i) p[i]=static_cast<unsigned char>(x>>(8*i));
}
uint32_t get(const unsigned char* p) {
    return uint32_t(p[0]) | uint32_t(p[1])<<8 | uint32_t(p[2])<<16 | uint32_t(p[3])<<24;
}
void leaf(uint32_t* s) {
    CHECK(ts2_scoped_read32(s[4])==0xa0002010);
    const auto arg=ts2_scoped_read32(s[4]+4);
    s[0]=ts2_scoped_read32(arg)+7u;
    s[4]+=4; // authored cdecl RET; caller owns argument
}
void wrapper(uint32_t* s) {
    const auto ptr=ts2_scoped_read32(obj);
    if (ptr) {
        s[4]-=4; ts2_scoped_write32(s[4],ptr);
        s[4]-=4; ts2_scoped_write32(s[4],0xa0002010);
        CHECK(ts2_scoped_call(leafva,s)==TS2_SCOPED_OK);
        s[4]+=4;
        ts2_scoped_write32(obj+4,s[0]);
    } else s[0]=ts2_scoped_read32(obj+4);
    s[4]+=4;
}
void badwrite(uint32_t*) { ts2_scoped_write32(obj+8,123); }
void gap(uint32_t*) { (void)ts2_scoped_read32(obj+12); }
void cross(uint32_t*) { ts2_scoped_write32(obj+5,123); }
void wrapping(uint32_t*) { ts2_scoped_write32(0xfffffffe,123); }
void unknown(uint32_t* s) { (void)ts2_scoped_call(leafva+1,s); }
void recurse(uint32_t* s) { (void)ts2_scoped_call(root,s); }
void fanout(uint32_t* s) { for (int i=0;i<64;++i) (void)ts2_scoped_call(leafva,s); }
void noop(uint32_t*) {}
void depthlimit(uint32_t* s) { if (--s[0]) (void)ts2_scoped_call(root,s); }
void calllimit(uint32_t* s) { for (int i=0;i<63;++i) CHECK(ts2_scoped_call(leafva,s)==TS2_SCOPED_OK); }
void writelimit(uint32_t*) { for (int i=0;i<256;++i) ts2_scoped_write32(obj,static_cast<uint32_t>(i)); }
void manywrites(uint32_t*) { for (int i=0;i<257;++i) ts2_scoped_write32(obj,1); }
void latefault(uint32_t* s) {
    ts2_scoped_write32(obj,123); s[0]=999; (void)ts2_scoped_read32(obj+12);
    ts2_scoped_write32(obj,456); // fault latch prevents subsequent store
}
void throws(uint32_t*) { ts2_scoped_write32(obj,123); throw std::runtime_error("fixture"); }
void nestedthrow(uint32_t* s) { (void)ts2_scoped_call(leafva,s); }
void reentry(uint32_t* s) {
    Ts2ScopedReport report{};
    CHECK(ts2_scoped_dispatch(root,s,nullptr,0,nullptr,0,&report)==TS2_SCOPED_REENTRY);
}
void overlap(uint32_t*) {
    ts2_scoped_write32(obj,0x12345678);
    ts2_scoped_write32(obj,0x12345678);
    ts2_scoped_write32(obj+1,0xaabbccdd);
}
void top(uint32_t* s) { s[0]=ts2_scoped_read32(0xfffffffc); ts2_scoped_write32(0xfffffffc,s[0]+1); }
}
int main() {
    try {
        unsigned cases=0;
        for (uint32_t value : {0u,1u,0xfffffff9u,0xffffffffu,0x80000000u})
        for (bool live : {false,true}) {
            std::array<unsigned char,20> input{}, output;
            std::array<unsigned char,16> stk{}, stkout;
            put(input.data(),live?obj+16:0); put(input.data()+4,0x87654321);
            put(input.data()+16,value); stk.fill(0x5a);
            output.fill(0xcc); stkout.fill(0xcc);
            const Ts2ScopedSpan spans[]{{obj,8,input.data(),output.data()},
                {obj+16,4,input.data()+16,nullptr},{stack,16,stk.data(),stkout.data()}};
            const Ts2ScopedEntry entries[]{{root,wrapper},{leafva,leaf}};
            std::array<uint32_t,9> state{1,2,3,4,stack+8,6,7,8,0x602};
            auto expected=state;
            expected[0]=live?value+7u:0x87654321; expected[4]+=4;
            Ts2ScopedReport report{};
            CHECK(ts2_scoped_dispatch(root,state.data(),spans,3,entries,2,&report)==TS2_SCOPED_OK);
            CHECK(state==expected);
            CHECK(get(output.data())==(live?obj+16:0));
            CHECK(get(output.data()+4)==expected[0]);
            CHECK(report.calls==(live?2u:1u) && report.writes==(live?3u:0u));
            if (live) {
                CHECK(report.journal[0].address==stack+4 && report.journal[0].before==0x5a5a5a5a && report.journal[0].after==obj+16);
                CHECK(report.journal[1].address==stack && report.journal[1].before==0x5a5a5a5a && report.journal[1].after==0xa0002010);
                CHECK(report.journal[2].address==obj+4 && report.journal[2].before==0x87654321 && report.journal[2].after==expected[0]);
            }
            auto stack_expected=stk;
            if (live) { put(stack_expected.data(),0xa0002010); put(stack_expected.data()+4,obj+16); }
            CHECK(stkout==stack_expected && get(input.data()+4)==0x87654321);
            ++cases;
        }
        std::array<unsigned char,8> input{}, output;
        const Ts2ScopedSpan span{obj,8,input.data(),output.data()};
        Ts2ScopedEntry entries[]{{root,noop},{leafva,noop}};
        const std::array<uint32_t,9> initial{1,2,3,4,5,6,7,8,9};
        for (auto fn : {badwrite,gap,cross,wrapping,unknown,recurse,fanout,manywrites,latefault,throws,nestedthrow,reentry}) {
            entries[0].call=fn; entries[1].call=fn==nestedthrow?throws:noop;
            auto state=initial; output.fill(0xcc);
            Ts2ScopedReport report; std::memset(&report,0x5a,sizeof(report));
            const auto before=report;
            const int result=ts2_scoped_dispatch(root,state.data(),&span,1,entries,2,&report);
            CHECK(result!=TS2_SCOPED_OK && state==initial);
            CHECK(std::memcmp(&report,&before,sizeof(report))==0);
            for (auto b : output) CHECK(b==0xcc);
            entries[0].call=noop;
            CHECK(ts2_scoped_dispatch(root,state.data(),&span,1,entries,2,&report)==TS2_SCOPED_OK);
            CHECK(state==initial && report.calls==1 && report.writes==0 && output==input);
        }
        auto state=initial; Ts2ScopedReport report{};
        entries[0].call=overlap;
        CHECK(ts2_scoped_dispatch(root,state.data(),&span,1,entries,2,&report)==TS2_SCOPED_OK);
        CHECK(report.writes==3 && report.journal[1].before==0x12345678);
        CHECK(report.journal[2].before==0x00123456 && report.journal[2].after==0xaabbccdd);
        CHECK(get(output.data())==0xbbccdd78 && output[4]==0xaa);
        const Ts2ScopedSpan end{0xfffffffc,4,input.data(),output.data()};
        entries[0].call=top;
        CHECK(ts2_scoped_dispatch(root,state.data(),&end,1,entries,2,&report)==TS2_SCOPED_OK);
        CHECK(state[0]==0 && get(output.data())==1);
        entries[0].call=depthlimit; state=initial; state[0]=8;
        CHECK(ts2_scoped_dispatch(root,state.data(),&span,1,entries,2,&report)==TS2_SCOPED_OK);
        CHECK(state[0]==0 && report.calls==8);
        state=initial; state[0]=9; const auto deep=state;
        CHECK(ts2_scoped_dispatch(root,state.data(),&span,1,entries,2,&report)==TS2_SCOPED_FAULT);
        CHECK(state==deep);
        entries[0].call=calllimit;
        CHECK(ts2_scoped_dispatch(root,state.data(),&span,1,entries,2,&report)==TS2_SCOPED_OK);
        CHECK(report.calls==64);
        entries[0].call=writelimit;
        CHECK(ts2_scoped_dispatch(root,state.data(),&span,1,entries,2,&report)==TS2_SCOPED_OK);
        CHECK(report.writes==256 && get(output.data())==255);
        for (unsigned i=0;i<256;++i) {
            CHECK(report.journal[i].address==obj && report.journal[i].after==i);
            CHECK(report.journal[i].before==(i?i-1:0));
        }
        entries[0].call=overlap;
        const Ts2ScopedSpan readonly{obj,8,input.data(),nullptr};
        CHECK(ts2_scoped_dispatch(root,state.data(),&readonly,1,entries,2,&report)!=TS2_SCOPED_OK);
        const Ts2ScopedSpan duplicate[]{span,span};
        CHECK(ts2_scoped_dispatch(root,state.data(),duplicate,2,entries,2,&report)==TS2_SCOPED_INVALID);
        entries[1]=entries[0];
        CHECK(ts2_scoped_dispatch(root,state.data(),&span,1,entries,2,&report)==TS2_SCOPED_INVALID);
        CHECK(ts2_scoped_dispatch(root,nullptr,&span,1,entries,2,&report)==TS2_SCOPED_INVALID);
        CHECK(ts2_scoped_dispatch(root,state.data(),&span,17,entries,2,&report)==TS2_SCOPED_INVALID);
        CHECK(ts2_scoped_dispatch(root,state.data(),&span,1,entries,17,&report)==TS2_SCOPED_INVALID);
        entries[1]={leafva,noop};
        for (Ts2ScopedSpan bad : {Ts2ScopedSpan{obj,0,input.data(),output.data()},
             {0xfffffffe,4,input.data(),output.data()}, {obj,4,nullptr,output.data()},
             {obj,1024*1024+1,input.data(),output.data()}})
            CHECK(ts2_scoped_dispatch(root,state.data(),&bad,1,entries,2,&report)==TS2_SCOPED_INVALID);
        CHECK(ts2_scoped_dispatch(root,state.data(),&span,1,entries,2,nullptr)==TS2_SCOPED_INVALID);
        entries[0]={0,noop};
        CHECK(ts2_scoped_dispatch(root,state.data(),&span,1,entries,2,&report)==TS2_SCOPED_INVALID);
        entries[0]={root,nullptr};
        CHECK(ts2_scoped_dispatch(root,state.data(),&span,1,entries,2,&report)==TS2_SCOPED_INVALID);
        CHECK(ts2_scoped_call(root,state.data())==TS2_SCOPED_INVALID);
        std::printf("scoped-dispatch: %u authored cache cases; nested ABI, journal, faults, budgets, recovery passed\n",cases);
    } catch (const std::exception& e) { std::fprintf(stderr,"FAIL %s\n",e.what()); return 1; }
}
