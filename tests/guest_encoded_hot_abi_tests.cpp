#include "ts2/guest_encoded_hot_abi.hpp"
#include "ts2/guest_encoded_resolver.hpp"
#include "ts2/guest_memory.hpp"
#include <iostream>
#include <stdexcept>

namespace {
void check(bool ok) { if (!ok) throw std::runtime_error("hot ABI check"); }
}
int main() {
    try {
        ts2::GuestMemory m,peer;
        constexpr uint32_t page=0xb8000000u, sp=page+4088, cookie=0xa1000000u, cache=cookie+4;
        m.commit(page,4096); m.commit(cookie,4096);
        peer.commit(cookie,4096); peer.write32(cookie,123);
        m.write32(sp,0xc0000000u); m.write32(sp+4,0);
        m.write32(cookie,31); m.write32(cache,ts2::guest_encode_pointer(0xc7000020u,31));
        // name/begin/end arguments would cross into an uncommitted page. Hot
        // resolution must not read them or require any provider/cold layout.
        ts2::GuestEncodedHotAbi abi{cookie,cache};
        ts2::GuestRegisters r{.eax=1,.ecx=2,.edx=3,.ebx=4,.esp=sp,.ebp=5,.esi=6,.edi=7,.eflags=0x602};
        abi.invoke(r,m);
        check(r.eax==0xc7000020u && r.ecx==31 && r.edx==r.eax && r.esp==sp+4);
        check(r.ebx==4 && r.ebp==5 && r.esi==6 && r.edi==7);
        check(m.read32(sp-4)==5 && m.read32(sp-8)==4 && m.read32(sp-12)==6);
        check(m.read32(cookie)==31 && peer.read32(cookie)==123);
        // A cold failure must not consume the caller frame or touch saved words.
        m.write32(cache,ts2::guest_encode_pointer(0,31));
        r.esp=sp; r.eax=9; m.write32(sp-4,42);
        bool rejected=false;
        try { abi.invoke(r,m); } catch (const std::runtime_error&) { rejected=true; }
        check(rejected && r.esp==sp && r.eax==9 && m.read32(sp-4)==42);
        // A lower-page saved-frame fault also rejects before the first store.
        r.esp=page+8; m.write32(page+12,0); m.write32(page+4,99);
        m.write32(cache,ts2::guest_encode_pointer(1,31)); rejected=false;
        try { abi.invoke(r,m); } catch (const std::out_of_range&) { rejected=true; }
        check(rejected && r.esp==page+8 && r.eax==9 && m.read32(page+4)==99);
        std::cout<<"encoded hot ABI checks passed\n"; return 0;
    } catch (const std::exception&) { return 1; }
}
