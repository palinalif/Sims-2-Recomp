// Development-only: existing compiled leaves on ONE persistent mapped PE image.
// Original code pages remain data. No x86 interpreter, runtime decoding or IAT
// binding. Trusted single-owner callbacks must return normally and use read32.
#include "image_dispatch.h"
#include "ts2/guest_image.hpp"
#include "ts2/guest_dispatch.hpp"
#include <algorithm>
#include <array>
#include <fstream>
#include <iostream>
#include <set>

namespace {
ts2::GuestImage* image{};
ts2::GuestDispatch dispatch;
struct Context {
    const Ts2ReadSpan* spans;
    size_t count;
    void (*call)(uint32_t*);
    bool fault{};
};
Context* active{};
struct Scope {
    explicit Scope(Context& c) { active = &c; }
    ~Scope() { active = nullptr; }
};
void adapter(ts2::GuestRegisters& r, ts2::GuestMemory& m, const ts2::GuestDispatch&) {
    if (!active || &m != image->memory.get()) throw std::runtime_error("context");
    std::array<uint32_t,9> s{r.eax,r.ecx,r.edx,r.ebx,r.esp,r.ebp,r.esi,r.edi,r.eflags};
    active->call(s.data());
    r = {s[0],s[1],s[2],s[3],s[4],s[5],s[6],s[7],s[8]};
}
}
extern "C" uint32_t ts2_image_read32(uint32_t address) {
    if (!active) return 0;
    try {
        for (size_t i=0; i<active->count; ++i) {
            const auto& s = active->spans[i];
            if (address >= s.address && uint64_t(address)+4 <= uint64_t(s.address)+s.size)
                return image->memory->read32(address);
        }
    } catch (...) { }
    active->fault = true;
    return 0;
}
extern "C" int ts2_image_dispatch(uint32_t va, uint32_t state[9],
    const Ts2ReadSpan* spans, size_t n, const Ts2ReadEntry* entries, size_t count) {
    if (active) { active->fault = true; return TS2_READ_REENTRY; }
    if (!image || !state || !spans || !n || n>16 || !entries || !count || count>16)
        return TS2_READ_INVALID;
    try {
        uint64_t total=0;
        // Validate everything before touching the persistent memory. Inputs must
        // be outside the mapped image; committed same-page gaps are NOT readable.
        for (size_t i=0; i<n; ++i) {
            const auto& s=spans[i];
            const uint64_t end=uint64_t(s.address)+s.size;
            if (!s.bytes || !s.size || end>0x100000000ull) return TS2_READ_INVALID;
            if (s.address<uint64_t(image->image_base)+image->image_size && end>image->image_base) {
                std::cerr << "Image input span overlaps mapped image; rejected before copy/dispatch\n";
                return TS2_READ_INVALID;
            }
            total+=s.size;
            if (total>1024*1024) return TS2_READ_INVALID;
            for (size_t j=0; j<i; ++j)
                if (s.address<uint64_t(spans[j].address)+spans[j].size && spans[j].address<end)
                    return TS2_READ_INVALID;
        }
        std::set<uint32_t> keys;
        void (*selected)(uint32_t*)=nullptr;
        for (size_t i=0; i<count; ++i) {
            if (!entries[i].call || !keys.insert(entries[i].va).second) return TS2_READ_INVALID;
            if (entries[i].va==va) selected=entries[i].call;
        }
        if (!selected) return TS2_READ_UNRESOLVED;
        // Only the fixed historical group is bound; other entries cannot extend
        // the persistent dispatcher. Unlike the old bridge, it is not recreated.
        if (va!=0xa0001240u && va!=0xa0001250u && va!=0xa0001270u)
            return TS2_READ_UNRESOLVED;
        auto& m=*image->memory;
        const uint64_t page=m.page_size();
        for (size_t i=0; i<n; ++i) {
            const auto& s=spans[i];
            // GuestMemory::commit is idempotent and preserves existing bytes.
            const uint64_t start=uint64_t(s.address)/page*page;
            const uint64_t end=(uint64_t(s.address)+s.size+page-1)/page*page;
            m.commit(uint32_t(start),end-start);
            m.write_bytes(s.address,{s.bytes,s.size});
        }
        ts2::GuestRegisters r{state[0],state[1],state[2],state[3],state[4],state[5],state[6],state[7],state[8]};
        Context context{spans,n,selected};
        Scope scope(context);
        dispatch.invoke(va,r,m);
        if (context.fault) return TS2_READ_FAULT;
        const std::array<uint32_t,9> out{r.eax,r.ecx,r.edx,r.ebx,r.esp,r.ebp,r.esi,r.edi,r.eflags};
        std::copy(out.begin(),out.end(),state);
        return TS2_READ_OK;
    } catch (...) { return TS2_READ_EXCEPTION; }
}
extern "C" int fixture_main(void);
int main(int argc,char** argv) {
    try {
        if (argc!=2) throw std::runtime_error("image argument");
        std::ifstream in(argv[1],std::ios::binary|std::ios::ate);
        const auto size=in.tellg();
        if (!in || size<=0 || size>256*1024*1024) throw std::runtime_error("image size");
        std::vector<uint8_t> bytes(static_cast<size_t>(size));
        in.seekg(0);
        if (!in.read(reinterpret_cast<char*>(bytes.data()),size)) throw std::runtime_error("image read");
        auto loaded=ts2::load_guest_image(bytes);
        image=&loaded;
        for (auto va : {0xa0001240u,0xa0001250u,0xa0001270u}) dispatch.bind(va,adapter);
        // Complete mapped image comparison, including BSS, gaps and headers.
        std::vector<uint32_t> before(loaded.image_size/4);
        for (size_t i=0;i<before.size();++i) before[i]=loaded.memory->read32(loaded.image_base+uint32_t(i*4));
        const int code=fixture_main();
        if (code) throw std::runtime_error("fixture");
        for (size_t i=0;i<before.size();++i)
            if (before[i]!=loaded.memory->read32(loaded.image_base+uint32_t(i*4))) throw std::runtime_error("image mutation");
        image=nullptr;
        return 0;
    } catch (...) { std::cerr << "Image-backed dispatch failed\n"; return 1; }
}
