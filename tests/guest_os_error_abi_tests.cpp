#include "ts2/guest_os_error_abi.hpp"
#include "ts2/guest_memory.hpp"
#include <iostream>
#include <stdexcept>
#include <vector>

namespace {
void check(bool ok) { if (!ok) throw std::runtime_error("ABI check"); }
void fill(ts2::GuestMemory& m, uint32_t table) {
    for (uint32_t i=0; i<90; ++i) m.write32(table+i*4, 10000+i);
}
}
int main() {
    try {
        ts2::GuestMemory m;
        const uint32_t page=static_cast<uint32_t>(m.page_size());
        const uint32_t base=0xa1000000, stack=0xb8000000;
        m.commit(base,page*2); m.commit(stack,page);
        const auto table=base+page-359;
        fill(m,table);
        ts2::GuestRegisters r;
        r.esp=stack+64; r.ebp=0x81234567; r.eflags=0xabcdef02;
        m.write32(r.esp,0x12345678); m.write32(r.esp+4,19);
        ts2::GuestOsErrorAbi{table}.invoke(r,m);
        check(r.eax==13 && r.ecx==19 && r.esp==stack+68);
        check(m.read32(stack+60)==r.ebp && m.read32(stack+56)==13);
        check((r.eflags & ~0x8d5u)==(0xabcdef02u & ~0x8d5u));
        // Rejections must leave all registers and stack/table memory intact.
        const auto snapshot=[&]() {
            std::vector<uint8_t> bytes;
            for (uint32_t i=0;i<page*2;++i) bytes.push_back(m.read8(base+i));
            for (uint32_t i=0;i<page;++i) bytes.push_back(m.read8(stack+i));
            return bytes;
        };
        const auto rejects=[&](uint32_t address,uint32_t sp) {
            const auto before=snapshot();
            ts2::GuestRegisters state;
            state.esp=sp; state.eax=0x1234; state.eflags=0xcd7;
            bool rejected=false;
            try { ts2::GuestOsErrorAbi{address}.invoke(state,m); }
            catch (const std::exception&) { rejected=true; }
            check(rejected && state.esp==sp && state.eax==0x1234 && state.eflags==0xcd7);
            check(state.ecx==0 && state.edx==0 && state.ebx==0 && state.ebp==0 && state.esi==0 && state.edi==0);
            check(snapshot()==before);
        };
        for (auto sp : {0u,7u,0xfffffffcu,stack,stack+page-4}) rejects(table,sp);
        for (auto bad : {0u,0xffffff00u,base-page,base+page*2-8,stack+60})
            rejects(bad,stack+64);
        // Highest legal caller frame ends at 2^32, no wrapping argument read.
        const auto top=static_cast<uint32_t>((uint64_t{1}<<32)-page);
        m.commit(top,page); r.esp=0xfffffff8;
        m.write32(r.esp,0x12345678); m.write32(r.esp+4,188);
        ts2::GuestOsErrorAbi{table}.invoke(r,m);
        check(r.eax==8 && r.ecx==14 && r.esp==0xfffffffc);
        check(m.read32(0xfffffff0)==14 && m.read32(0xfffffff4)==r.ebp);
        // Unaligned table and stack supported; no host-pointer casts.
        r.esp=stack+65; m.write32(r.esp+4,10000);
        m.write32(r.esp-8,0x5a5a5a5a);
        ts2::GuestOsErrorAbi{table}.invoke(r,m);
        check(r.eax==10001 && m.read32(stack+57)==0x5a5a5a5a);
        std::cout<<"OS-error integer ABI checks passed\n";
        return 0;
    } catch (const std::exception&) { std::cerr<<"OS-error ABI tests failed\n"; return 1; }
}
