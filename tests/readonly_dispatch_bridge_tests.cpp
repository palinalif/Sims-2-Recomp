#include "../tools/readonly_dispatch_bridge.h"
#include <array>
#include <cstdio>
#include <stdexcept>
#define CHECK(x) do { if (!(x)) throw std::runtime_error(#x); } while (false)
namespace {
constexpr uint32_t va = 0xa0001240, address = 0xfffff003;
unsigned calls;
void leaf(uint32_t* s) { ++calls; s[0] = ts2_bridge_read32(s[4]); s[4] += 4; s[8] ^= 0x800; }
void fault(uint32_t* s) { s[0] = ts2_bridge_read32(address + 1); }
void wrap(uint32_t* s) { s[0] = ts2_bridge_read32(0xfffffffe); }
void throws(uint32_t*) { throw std::runtime_error("fixture"); }
void nested(uint32_t* s) {
    const unsigned char b[4]{};
    const Ts2ReadSpan span{address,4,b};
    const Ts2ReadEntry entry{va,leaf};
    CHECK(ts2_read_dispatch(va,s,&span,1,&entry,1) == TS2_READ_REENTRY);
}
}
int main() {
    try {
        const unsigned char bytes[]{0x78,0x56,0x34,0x92};
        Ts2ReadSpan span{address,4,bytes};
        Ts2ReadEntry entry{va,leaf};
        const std::array<uint32_t,9> initial{1,2,3,4,address,6,7,8,0x602};
        auto s = initial;
        CHECK(ts2_read_dispatch(va+1,s.data(),&span,1,&entry,1) == TS2_READ_UNRESOLVED);
        CHECK(s == initial && calls == 0);
        CHECK(ts2_read_dispatch(va,s.data(),&span,1,&entry,1) == TS2_READ_OK);
        auto expected = initial; expected[0]=0x92345678; expected[4]+=4; expected[8]^=0x800;
        CHECK(s == expected && calls == 1 && bytes[0] == 0x78);
        for (auto fn : {fault,wrap,nested,throws}) {
            s=initial; entry.call=fn;
            const int want = fn == throws ? TS2_READ_EXCEPTION : TS2_READ_FAULT;
            CHECK(ts2_read_dispatch(va,s.data(),&span,1,&entry,1) == want);
            CHECK(s == initial);
            // Exception/fault/reentry must not poison the next context.
            entry.call=leaf;
            CHECK(ts2_read_dispatch(va,s.data(),&span,1,&entry,1) == TS2_READ_OK);
            CHECK(s == expected);
        }
        // Two spans on one host page must not grant access through their gap.
        const Ts2ReadSpan separate[]{span, {address+8,4,bytes}};
        s=initial; s[4]=address+8;
        CHECK(ts2_read_dispatch(va,s.data(),separate,2,&entry,1) == TS2_READ_OK);
        CHECK(s[0] == 0x92345678);
        s=initial; s[4]=address+4;
        const auto gap=s;
        CHECK(ts2_read_dispatch(va,s.data(),separate,2,&entry,1) == TS2_READ_FAULT);
        CHECK(s == gap);
        const Ts2ReadSpan top{0xfffffffc,4,bytes};
        s=initial; s[4]=0xfffffffc;
        CHECK(ts2_read_dispatch(va,s.data(),&top,1,&entry,1) == TS2_READ_OK);
        CHECK(s[0] == 0x92345678 && s[4] == 0); // valid final word, uint32 RET wrap
        s=initial;
        Ts2ReadSpan overlaps[]{span,span};
        Ts2ReadEntry duplicate[]{entry,entry};
        CHECK(ts2_read_dispatch(va,s.data(),overlaps,2,&entry,1) == TS2_READ_INVALID);
        CHECK(ts2_read_dispatch(va,s.data(),&span,1,duplicate,2) == TS2_READ_INVALID);
        for (Ts2ReadSpan bad : {Ts2ReadSpan{address,0,bytes}, {0xfffffffe,4,bytes},
             {address,4,nullptr}, {0x10000,1024*1024+1,bytes}})
            CHECK(ts2_read_dispatch(va,s.data(),&bad,1,&entry,1) == TS2_READ_INVALID);
        CHECK(ts2_read_dispatch(va,nullptr,&span,1,&entry,1) == TS2_READ_INVALID);
        CHECK(ts2_read_dispatch(va,s.data(),&span,17,&entry,1) == TS2_READ_INVALID);
        CHECK(ts2_read_dispatch(va,s.data(),&span,1,&entry,17) == TS2_READ_INVALID);
        entry.call=nullptr;
        CHECK(ts2_read_dispatch(va,s.data(),&span,1,&entry,1) == TS2_READ_INVALID);
        CHECK(s == initial);
        std::puts("readonly-dispatch-bridge: state bounds faults reentry recovery passed");
    } catch (const std::exception& e) { std::fprintf(stderr,"FAIL %s\n",e.what()); return 1; }
}
