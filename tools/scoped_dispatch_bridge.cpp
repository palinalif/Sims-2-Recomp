#include "scoped_dispatch_bridge.h"
#include "ts2/guest_dispatch.hpp"
#include "ts2/guest_memory.hpp"
#include <algorithm>
#include <array>
#include <map>
#include <set>
#include <vector>

namespace {
struct Context {
    ts2::GuestMemory memory;
    ts2::GuestDispatch dispatch;
    std::vector<Ts2ScopedSpan> spans;
    std::map<uint32_t, void (*)(uint32_t*)> entries;
    Ts2ScopedReport report{};
    unsigned depth{};
    bool fault{};
    void (*selected)(uint32_t*){};
    bool allows(uint32_t address, bool write) const {
        for (const auto& s : spans)
            if ((!write || s.output) && address >= s.address &&
                uint64_t(address) + 4 <= uint64_t(s.address) + s.size) return true;
        return false;
    }
};
thread_local Context* active{};
struct Scope {
    explicit Scope(Context& c) { active = &c; }
    ~Scope() { active = nullptr; }
};
void adapter(ts2::GuestRegisters& r, ts2::GuestMemory&, const ts2::GuestDispatch&) {
    std::array<uint32_t,9> s{r.eax,r.ecx,r.edx,r.ebx,r.esp,r.ebp,r.esi,r.edi,r.eflags};
    active->selected(s.data());
    r = {s[0],s[1],s[2],s[3],s[4],s[5],s[6],s[7],s[8]};
}
}
extern "C" uint32_t ts2_scoped_read32(uint32_t address) {
    if (!active || active->fault) return 0;
    try {
        if (active->allows(address,false)) return active->memory.read32(address);
    } catch (...) {}
    active->fault = true;
    return 0;
}
extern "C" void ts2_scoped_write32(uint32_t address, uint32_t value) {
    if (!active || active->fault) return;
    try {
        if (active->allows(address,true) && active->report.writes < 256) {
            const auto before = active->memory.read32(address);
            active->memory.write32(address,value);
            active->report.journal[active->report.writes++] = {address,before,value};
            return;
        }
    } catch (...) {}
    active->fault = true;
}
extern "C" int ts2_scoped_call(uint32_t va, uint32_t state[9]) {
    if (!active) return TS2_SCOPED_INVALID;
    if (active->fault) return TS2_SCOPED_FAULT;
    const auto found = active->entries.find(va);
    if (!state || found == active->entries.end() || active->depth == 8 ||
        active->report.calls == 64) {
        active->fault = true;
        return TS2_SCOPED_FAULT;
    }
    auto* previous = active->selected;
    active->selected = found->second;
    ++active->depth;
    ++active->report.calls;
    int result = TS2_SCOPED_OK;
    try {
        ts2::GuestRegisters r{state[0],state[1],state[2],state[3],state[4],
                              state[5],state[6],state[7],state[8]};
        active->dispatch.invoke(va,r,active->memory);
        if (!active->fault) {
            const std::array<uint32_t,9> out{r.eax,r.ecx,r.edx,r.ebx,r.esp,
                                            r.ebp,r.esi,r.edi,r.eflags};
            std::copy(out.begin(),out.end(),state);
        }
    } catch (...) { active->fault = true; result = TS2_SCOPED_EXCEPTION; }
    --active->depth;
    active->selected = previous;
    return active->fault && result == TS2_SCOPED_OK ? TS2_SCOPED_FAULT : result;
}
extern "C" int ts2_scoped_dispatch(uint32_t va, uint32_t state[9],
    const Ts2ScopedSpan* spans, size_t n, const Ts2ScopedEntry* entries, size_t count,
    Ts2ScopedReport* report) {
    if (active) { active->fault = true; return TS2_SCOPED_REENTRY; }
    if (!state || !report || !spans || !n || n > 16 || !entries || !count || count > 16)
        return TS2_SCOPED_INVALID;
    try {
        uint64_t total = 0;
        for (size_t i=0; i<n; ++i) {
            const auto& s = spans[i];
            total += s.size;
            if (!s.input || !s.size || total > 1024*1024 ||
                uint64_t(s.address)+s.size > 0x100000000ull) return TS2_SCOPED_INVALID;
            for (size_t j=0; j<i; ++j)
                if (uint64_t(s.address) < uint64_t(spans[j].address)+spans[j].size &&
                    uint64_t(spans[j].address) < uint64_t(s.address)+s.size)
                    return TS2_SCOPED_INVALID;
        }
        Context c;
        c.spans.assign(spans,spans+n);
        for (size_t i=0; i<count; ++i) {
            if (!entries[i].va || !entries[i].call ||
                !c.entries.emplace(entries[i].va,entries[i].call).second)
                return TS2_SCOPED_INVALID;
            c.dispatch.bind(entries[i].va,adapter);
        }
        std::set<uint32_t> pages;
        const uint64_t page = c.memory.page_size();
        for (const auto& s : c.spans) {
            for (uint64_t p=uint64_t(s.address)/page*page;
                 p<uint64_t(s.address)+s.size; p+=page)
                if (pages.insert(uint32_t(p)).second) c.memory.commit(uint32_t(p),page);
            c.memory.write_bytes(s.address,{s.input,s.size});
        }
        std::array<uint32_t,9> local;
        std::copy_n(state,9,local.begin());
        Scope scope(c);
        const int result = ts2_scoped_call(va,local.data());
        if (result != TS2_SCOPED_OK) return result;
        // Stage all outputs before publishing anything to caller buffers.
        std::vector<std::vector<unsigned char>> outputs(n);
        for (size_t i=0; i<n; ++i) if (c.spans[i].output) {
            outputs[i].resize(c.spans[i].size);
            for (uint32_t j=0; j<c.spans[i].size; ++j)
                outputs[i][j]=c.memory.read8(c.spans[i].address+j);
        }
        for (size_t i=0; i<n; ++i) if (c.spans[i].output)
            std::copy(outputs[i].begin(),outputs[i].end(),c.spans[i].output);
        std::copy(local.begin(),local.end(),state);
        *report = c.report;
        return TS2_SCOPED_OK;
    } catch (...) { return TS2_SCOPED_EXCEPTION; }
}
