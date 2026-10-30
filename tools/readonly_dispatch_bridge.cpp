#include "readonly_dispatch_bridge.h"
#include "ts2/guest_dispatch.hpp"
#include "ts2/guest_memory.hpp"
#include <algorithm>
#include <array>
#include <set>

namespace {
struct Context {
    ts2::GuestMemory& memory;
    const Ts2ReadSpan* spans;
    size_t count;
    void (*call)(uint32_t*);
    bool fault{};
};
thread_local Context* active = nullptr;
struct Scope {
    explicit Scope(Context& c) { active = &c; }
    ~Scope() { active = nullptr; }
};
void adapter(ts2::GuestRegisters& r, ts2::GuestMemory&, const ts2::GuestDispatch&) {
    std::array<uint32_t, 9> s{r.eax,r.ecx,r.edx,r.ebx,r.esp,r.ebp,r.esi,r.edi,r.eflags};
    active->call(s.data());
    r = {s[0],s[1],s[2],s[3],s[4],s[5],s[6],s[7],s[8]};
}
}
extern "C" uint32_t ts2_bridge_read32(uint32_t address) {
    if (!active) return 0; // Only meaningful during a dispatch callback.
    try {
        const uint64_t end = uint64_t(address) + 4;
        for (size_t i = 0; i < active->count; ++i) {
            const auto& s = active->spans[i];
            if (address >= s.address && end <= uint64_t(s.address) + s.size)
                return active->memory.read32(address);
        }
    } catch (...) { /* Latch below; never unwind through C. */ }
    active->fault = true;
    return 0;
}
extern "C" int ts2_read_dispatch(uint32_t va, uint32_t state[9],
    const Ts2ReadSpan* spans, size_t n, const Ts2ReadEntry* entries, size_t count) {
    if (active) { active->fault = true; return TS2_READ_REENTRY; }
    if (!state || !spans || !n || n > 16 || !entries || !count || count > 16)
        return TS2_READ_INVALID;
    try {
        uint64_t total = 0;
        for (size_t i = 0; i < n; ++i) {
            const auto& s = spans[i];
            if (!s.bytes || !s.size || uint64_t(s.address) + s.size > 0x100000000ull)
                return TS2_READ_INVALID;
            total += s.size;
            if (total > 1024*1024) return TS2_READ_INVALID;
            for (size_t j = 0; j < i; ++j)
                if (uint64_t(s.address) < uint64_t(spans[j].address) + spans[j].size &&
                    uint64_t(spans[j].address) < uint64_t(s.address) + s.size)
                    return TS2_READ_INVALID;
        }
        ts2::GuestDispatch dispatch;
        void (*selected)(uint32_t*) = nullptr;
        std::set<uint32_t> keys;
        for (size_t i = 0; i < count; ++i) {
            if (!entries[i].call || !keys.insert(entries[i].va).second)
                return TS2_READ_INVALID;
            dispatch.bind(entries[i].va, adapter);
            if (entries[i].va == va) selected = entries[i].call;
        }
        if (!selected) return TS2_READ_UNRESOLVED;
        ts2::GuestMemory memory;
        std::set<uint32_t> pages;
        const uint64_t page = memory.page_size();
        for (size_t i = 0; i < n; ++i) {
            const auto& s = spans[i];
            for (uint64_t p = uint64_t(s.address) / page * page;
                 p < uint64_t(s.address) + s.size; p += page)
                if (pages.insert(uint32_t(p)).second) memory.commit(uint32_t(p), page);
            memory.write_bytes(s.address, {s.bytes, s.size});
        }
        ts2::GuestRegisters r{state[0],state[1],state[2],state[3],state[4],
                              state[5],state[6],state[7],state[8]};
        Context context{memory,spans,n,selected};
        Scope scope(context);
        dispatch.invoke(va, r, memory);
        if (context.fault) return TS2_READ_FAULT;
        const std::array<uint32_t, 9> result{r.eax,r.ecx,r.edx,r.ebx,r.esp,r.ebp,r.esi,r.edi,r.eflags};
        std::copy(result.begin(), result.end(), state);
        return TS2_READ_OK;
    } catch (...) { return TS2_READ_EXCEPTION; }
}
