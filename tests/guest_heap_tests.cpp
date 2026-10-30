#include "ts2/guest_heap.hpp"
#include "ts2/guest_dispatch.hpp"
#include "ts2/guest_memory.hpp"
#include <algorithm>
#include <array>
#include <iostream>
#include <map>
#include <random>
#include <stdexcept>
#include <vector>

namespace {
#define CHECK(x) do { if (!(x)) throw std::runtime_error(#x); } while (false)
template<class F> void rejects(F f) {
    bool caught=false; try { f(); } catch (const std::exception&) { caught=true; }
    CHECK(caught);
}
constexpr uint32_t base=0xb2000000u, handle=0xf1234567u;
void configuration() {
    ts2::GuestMemory m;
    const auto page=static_cast<uint32_t>(m.page_size());
    rejects([&]{ts2::GuestHeap h(m,handle,base,page);}); // No implicit mapping.
    m.commit(base,3*page);
    rejects([&]{ts2::GuestHeap h(m,0,base,page);});
    rejects([&]{ts2::GuestHeap h(m,handle,0,page);});
    rejects([&]{ts2::GuestHeap h(m,handle,base+8,page);});
    rejects([&]{ts2::GuestHeap h(m,handle,base,0);});
    rejects([&]{ts2::GuestHeap h(m,handle,base,page-1);});
    rejects([&]{ts2::GuestHeap h(m,handle,base,uint64_t{1}<<32);});
    // Checking endpoints alone would miss a hole in the middle.
    ts2::GuestMemory hole;
    hole.commit(base,page); hole.commit(base+2*page,page);
    rejects([&]{ts2::GuestHeap h(hole,handle,base,3*page);});
}
void allocation() {
    ts2::GuestMemory m; const auto page=static_cast<uint32_t>(m.page_size());
    m.commit(base,page); ts2::GuestHeap h(m,handle,base,page);
    CHECK(h.allocate(handle,0,0)==base);
    CHECK(h.allocate(handle,0,1)==base+8);
    CHECK(h.allocate(handle,0,9)==base+16);
    CHECK(h.allocate(handle,0,page-32)==base+32);
    CHECK(h.allocate(handle,0,1)==0);
    CHECK(h.allocate(handle,0,UINT32_MAX)==0);
    rejects([&]{h.allocate(handle^1,0,1);});
    for (uint32_t flags:{1u,4u,16u,UINT32_MAX})
        rejects([&]{h.allocate(handle,flags,1);});
    CHECK(h.release(handle,0,base+8));
    CHECK(h.allocate(handle,0,8)==base+8); // Invalid requests did not consume space.
    CHECK(!h.release(handle,0,base+1));
    CHECK(!h.release(handle,0,0));
    rejects([&]{h.release(0,0,base);});
    rejects([&]{h.release(handle,8,base);});
    CHECK(h.release(handle,0,base)); CHECK(!h.release(handle,0,base));
}
void reuse_and_zero() {
    ts2::GuestMemory m; const auto page=static_cast<uint32_t>(m.page_size());
    m.commit(base,page); ts2::GuestHeap h(m,handle,base,page);
    const auto p=h.allocate(handle,0,16), q=h.allocate(handle,0,16);
    m.write32(p,0xdeadbeefu); m.write32(q,0xabcdef01u);
    CHECK(h.release(handle,0,p));
    CHECK(m.read32(p)==0xdeadbeefu); // Free changes ownership, not bytes.
    CHECK(h.allocate(handle,0,16)==p); CHECK(m.read32(p)==0xdeadbeefu);
    CHECK(h.release(handle,0,p));
    CHECK(h.allocate(handle,8,16)==p); CHECK(m.read32(p)==0);
    CHECK(m.read32(q)==0xabcdef01u); // Neighbor stays live and untouched.
    CHECK(h.release(handle,0,q)); CHECK(h.release(handle,0,p));
    // Both left and right coalescing are required to satisfy an arena-sized request.
    CHECK(h.allocate(handle,8,page)==base);
    for (uint32_t i=0;i<page;++i) CHECK(m.read8(base+i)==0);
}
void fragmentation() {
    ts2::GuestMemory m; const auto page=static_cast<uint32_t>(m.page_size());
    m.commit(base,page); ts2::GuestHeap h(m,handle,base,page);
    const auto a=h.allocate(handle,0,page/4), b=h.allocate(handle,0,page/4);
    const auto c=h.allocate(handle,0,page/4), d=h.allocate(handle,0,page/4);
    CHECK(h.release(handle,0,a)); CHECK(h.release(handle,0,c));
    CHECK(h.allocate(handle,0,page/2)==0); // Total free is not contiguous free.
    CHECK(h.release(handle,0,b));
    CHECK(h.allocate(handle,0,3*page/4)==base);
    CHECK(h.release(handle,0,d));
}
void high_end_and_isolation() {
    ts2::GuestMemory m, peer; const auto page=static_cast<uint32_t>(m.page_size());
    const auto top=static_cast<uint32_t>((uint64_t{1}<<32)-page);
    m.commit(top,page); peer.commit(top,page);
    ts2::GuestHeap a(m,handle,top,page), b(peer,handle,top,page);
    CHECK(a.allocate(handle,0,page)==top);
    m.write32(UINT32_MAX-3,0x12345678u);
    CHECK(b.allocate(handle,0,page)==top); CHECK(peer.read32(UINT32_MAX-3)==0);
    CHECK(a.allocate(handle,0,1)==0); CHECK(a.release(handle,0,top));
    CHECK(a.allocate(handle,8,page)==top); CHECK(m.read32(UINT32_MAX-3)==0);
}
// Independent unit-occupancy oracle, not the service's extent map/merge algorithm.
void model_sequence() {
    ts2::GuestMemory m; const auto page=static_cast<uint32_t>(m.page_size());
    m.commit(base,page); ts2::GuestHeap h(m,handle,base,page);
    std::vector<bool> used(page/8,false);
    std::map<uint32_t,uint32_t> live;
    std::mt19937 rng(0x8461f2u);
    for (unsigned step=0;step<4000;++step) {
        if (!live.empty() && rng()%3==0) {
            auto it=live.begin(); std::advance(it,rng()%live.size());
            CHECK(h.release(handle,0,it->first));
            const auto index=(it->first-base)/8;
            for (uint32_t i=0;i<it->second;++i) used[index+i]=false;
            live.erase(it);
        } else {
            const uint32_t bytes=rng()%(page/2), units=(std::max(bytes,1u)+7)/8;
            uint32_t expected=0, index=0;
            for (uint32_t start=0;start+units<=used.size();++start) {
                bool clear=true;
                for (uint32_t i=0;i<units;++i) if (used[start+i]) { clear=false; break; }
                if (clear) { index=start; expected=base+8*start; break; }
            }
            const auto actual=h.allocate(handle,8,bytes);
            CHECK(actual==expected);
            if (actual) {
                for (uint32_t i=0;i<units;++i) used[index+i]=true;
                for (uint32_t i=0;i<bytes;++i) CHECK(m.read8(actual+i)==0);
                live.emplace(actual,units); m.write32(actual,step+1);
            }
        }
    }
    for (const auto& [p,n]:live) { (void)n; CHECK(h.release(handle,0,p)); }
    CHECK(h.allocate(handle,0,page)==base);
}
void reallocation() {
    ts2::GuestMemory m; const auto page=static_cast<uint32_t>(m.page_size());
    m.commit(base,page); ts2::GuestHeap h(m,handle,base,page);
    const auto a=h.allocate(handle,0,9), b=h.allocate(handle,0,16);
    m.write32(a,0x12345678u); m.write32(a+4,0xabcdef01u);
    const std::array<uint8_t,8> padding{9,10,11,12,13,14,15,16};
    m.write_bytes(a+8,padding);
    CHECK(h.reallocate(handle,0,a,9)==a); // Same rounded extent.
    CHECK(h.reallocate(handle,0,a,24)==base+32); // Neighbor forces move.
    CHECK(m.read32(base+32)==0x12345678u && m.read32(base+36)==0xabcdef01u);
    CHECK(m.read8(base+40)==9 && m.read8(base+41)==0); // Requested bytes only, not padding.
    CHECK(!h.release(handle,0,a)); // Old ownership really ended.
    CHECK(h.reallocate(handle,0,a,8)==0); // A freed base is not reallocatable.
    CHECK(h.allocate(handle,0,16)==a);
    CHECK(h.reallocate(handle,0,base+32,UINT32_MAX)==0);
    CHECK(m.read32(base+32)==0x12345678u);
    CHECK(h.reallocate(handle,0,base+32,0)==base+32);
    CHECK(h.reallocate(handle,0,base+32,page-32)==base+32); // Coalesced shrink tail.
    CHECK(h.reallocate(handle,0,base+32,page)==0);
    for (uint32_t p:{0u,base+1,base+40,base+page}) CHECK(h.reallocate(handle,0,p,8)==0);
    rejects([&]{h.reallocate(0,0,a,8);});
    for (uint32_t flags:{1u,4u,8u,16u,UINT32_MAX}) rejects([&]{h.reallocate(handle,flags,a,8);});
    CHECK(h.release(handle,0,b)); CHECK(h.release(handle,0,a));
    CHECK(h.release(handle,0,base+32));
    CHECK(h.allocate(handle,0,page)==base);
}
void reallocation_boundaries() {
    ts2::GuestMemory m; const auto page=static_cast<uint32_t>(m.page_size());
    m.commit(base,5*page); ts2::GuestHeap h(m,handle,base,5*page);
    const auto a=h.allocate(handle,0,page+9);
    CHECK(h.allocate(handle,0,page)==base+page+16); // Force a non-overlapping move.
    std::vector<uint8_t> data(page+9);
    for (size_t i=0;i<data.size();++i) data[i]=static_cast<uint8_t>(i*17+3);
    m.write_bytes(a,data);
    const auto moved=h.reallocate(handle,0,a,2*page+9);
    CHECK(moved==base+2*page+16);
    for (size_t i=0;i<data.size();++i) {
        CHECK(m.read8(moved+static_cast<uint32_t>(i))==data[i]);
        CHECK(m.read8(a+static_cast<uint32_t>(i))==data[i]); // Free retains bytes.
    }
    ts2::GuestMemory top_memory;
    const auto top=static_cast<uint32_t>((uint64_t{1}<<32)-page);
    top_memory.commit(top,page); ts2::GuestHeap at_top(top_memory,handle,top,page);
    CHECK(at_top.allocate(handle,0,8)==top);
    CHECK(at_top.reallocate(handle,0,top,page)==top); // End exactly 2^32, no wrap.
    CHECK(at_top.reallocate(handle,0,top,UINT32_MAX)==0);
    CHECK(at_top.reallocate(handle,0,top,0)==top);
    CHECK(at_top.allocate(handle,0,page-8)==top+8);
}
// Independent cell-occupancy + byte-array oracle. Realloc decisions are computed
// without extents/coalescing; every byte, including free storage, is compared.
void reallocation_model() {
    ts2::GuestMemory m; const auto page=static_cast<uint32_t>(m.page_size());
    m.commit(base,page); ts2::GuestHeap h(m,handle,base,page);
    std::vector<bool> used(page/8,false);
    std::vector<uint8_t> data(page,0);
    std::map<uint32_t,uint32_t> live; // requested sizes, not rounded extents
    std::mt19937 rng(0x85217fu);
    auto units=[](uint32_t n) { return (std::max(uint64_t(n),uint64_t{1})+7)/8; };
    auto clear=[&](uint64_t start,uint64_t count) {
        if (start+count>used.size()) return false;
        for (uint64_t i=0;i<count;++i) if (used[start+i]) return false;
        return true;
    };
    auto first=[&](uint64_t count) {
        for (uint64_t i=0;i+count<=used.size();++i) if (clear(i,count)) return base+static_cast<uint32_t>(8*i);
        return 0u;
    };
    auto mark=[&](uint32_t p,uint64_t count,bool value) {
        for (uint64_t i=0;i<count;++i) used[(p-base)/8+i]=value;
    };
    unsigned moves=0, grows=0, shrinks=0, failures=0;
    for (unsigned step=0;step<1600;++step) {
        const uint32_t size=step%17==0 ? UINT32_MAX : rng()%(page/2);
        const auto count=units(size);
        if (live.empty() || rng()%3==0) {
            const auto expected=first(count), actual=h.allocate(handle,0,size);
            CHECK(actual==expected);
            if (actual) { mark(actual,count,true); live.emplace(actual,size); }
        } else {
            auto it=live.begin(); std::advance(it,rng()%live.size());
            const auto old=it->first, old_size=it->second;
            const auto old_count=units(old_size);
            if (rng()%5==0) {
                CHECK(h.release(handle,0,old)); mark(old,old_count,false); live.erase(it);
            } else {
                uint32_t expected=old;
                if (count>old_count && !clear((old-base)/8+old_count,count-old_count)) expected=first(count);
                const auto actual=h.reallocate(handle,0,old,size);
                CHECK(actual==expected);
                if (!actual) ++failures;
                else {
                    if (actual!=old) {
                        ++moves;
                        std::copy_n(data.begin()+(old-base),std::min(old_size,size),data.begin()+(actual-base));
                    } else if (count>old_count) ++grows; else if (count<old_count) ++shrinks;
                    mark(old,old_count,false); live.erase(it);
                    mark(actual,count,true); live.emplace(actual,size);
                }
            }
        }
        // Touch requested bytes only, making stale/cross-allocation copies visible.
        if (!live.empty()) {
            auto it=live.begin(); std::advance(it,rng()%live.size());
            if (it->second) {
                const auto offset=rng()%it->second;
                const std::array<uint8_t,1> value{static_cast<uint8_t>(step)};
                m.write_bytes(it->first+offset,value); data[it->first-base+offset]=value[0];
            }
        }
        for (uint32_t i=0;i<page;++i) CHECK(m.read8(base+i)==data[i]);
    }
    CHECK(moves && grows && shrinks && failures);
    for (const auto& [p,n]:live) { (void)n; CHECK(h.release(handle,0,p)); }
    CHECK(h.allocate(handle,0,page)==base);
}
ts2::GuestHeap* active=nullptr;
void allocate_endpoint(ts2::GuestRegisters& r,ts2::GuestMemory&,const ts2::GuestDispatch&) {
    active->invoke_allocate(r);
}
void reallocate_endpoint(ts2::GuestRegisters& r,ts2::GuestMemory&,const ts2::GuestDispatch&) {
    active->invoke_reallocate(r);
}
void reallocation_abi() {
    ts2::GuestMemory m; const auto page=static_cast<uint32_t>(m.page_size());
    constexpr uint32_t stack=0xc2000000u, target=0xf0002000u;
    m.commit(base,page); m.commit(stack,page);
    ts2::GuestHeap h(m,handle,base,page); active=&h;
    ts2::GuestDispatch d; d.bind(target,reallocate_endpoint);
    CHECK(h.allocate(handle,0,8)==base); m.write32(base,0xaabbccddu);
    ts2::GuestRegisters r{11,22,33,44,stack+16,55,66,77,0x246};
    auto frame=[&](uint32_t size) {
        r.esp=stack+16; m.write32(r.esp,0x11223344u); m.write32(r.esp+4,handle);
        m.write32(r.esp+8,0); m.write32(r.esp+12,base); m.write32(r.esp+16,size);
    };
    frame(24); d.invoke(target,r,m);
    CHECK(r.eax==base && r.esp==stack+36 && m.read32(base)==0xaabbccddu);
    CHECK(r.ecx==22 && r.edx==33 && r.ebx==44 && r.ebp==55 && r.esi==66 && r.edi==77 && r.eflags==0x246);
    CHECK(m.read32(stack+16)==0x11223344u && m.read32(stack+32)==24);
    frame(UINT32_MAX); d.invoke(target,r,m); CHECK(r.eax==0 && r.esp==stack+36);
    frame(32); r.eax=99; m.write32(r.esp+8,8);
    rejects([&]{d.invoke(target,r,m);}); CHECK(r.eax==99 && r.esp==stack+16);
    frame(32); m.write32(r.esp+4,handle^1);
    rejects([&]{d.invoke(target,r,m);}); CHECK(r.eax==99 && r.esp==stack+16);
    frame(32); m.write32(r.esp+12,base+1); d.invoke(target,r,m);
    CHECK(r.eax==0 && r.esp==stack+36);
    // The final size word is unmapped; reading only a stdcall12 frame is unsafe.
    r.esp=stack+page-16; r.eax=99;
    m.write32(r.esp,0); m.write32(r.esp+4,handle); m.write32(r.esp+8,0); m.write32(r.esp+12,base);
    rejects([&]{d.invoke(target,r,m);}); CHECK(r.eax==99 && r.esp==stack+page-16);
    r.esp=UINT32_MAX-15; rejects([&]{d.invoke(target,r,m);});
    CHECK(h.allocate(handle,0,page-24)==base+24); // Invalid frames did not grow the allocation.
    active=nullptr;
}
void live_capacity_abi() {
    // Authored service-boundary replay of live prefix ownership, not game execution.
    ts2::GuestMemory m; const auto page=static_cast<uint32_t>(m.page_size());
    constexpr uint32_t stack=0xc2000000u, target=0xf0001000u;
    m.commit(base,2*page); m.commit(stack,page);
    ts2::GuestHeap h(m,handle,base,2*page); active=&h;
    uint32_t offset=0;
    for (uint32_t bytes:{528u,256u,1024u,1032u,256u,8u}) {
        CHECK(h.allocate(handle,0,bytes)==base+offset); offset+=bytes;
    }
    CHECK(offset==3104);
    std::vector<uint8_t> dirty(2*page);
    for (size_t i=0;i<dirty.size();++i) dirty[i]=static_cast<uint8_t>(i*13+7);
    m.write_bytes(base,dirty);
    ts2::GuestDispatch d; d.bind(target,allocate_endpoint);
    ts2::GuestRegisters r{11,22,33,44,stack+16,55,66,77,0x246};
    m.write32(r.esp,0x11223344u); m.write32(r.esp+4,handle);
    m.write32(r.esp+8,0); m.write32(r.esp+12,1032);
    d.invoke(target,r,m);
    CHECK(r.eax==base+3104 && r.esp==stack+32);
    CHECK(r.ecx==22 && r.edx==33 && r.ebx==44 && r.ebp==55 && r.esi==66 && r.edi==77 && r.eflags==0x246);
    // Dirty allocation preserves every byte, especially old input and live nodes.
    for (uint32_t i=0;i<2*page;++i) CHECK(m.read8(base+i)==dirty[i]);
    CHECK(h.allocate(handle,0,2*page-4136)==base+4136);
    CHECK(h.allocate(handle,0,1)==0); // No overlapping or invented free space.
    active=nullptr;
}
void abi() {
    ts2::GuestMemory m; const auto page=static_cast<uint32_t>(m.page_size());
    constexpr uint32_t stack=0xc2000000u, target=0xf0001000u;
    m.commit(base,page); m.commit(stack,page);
    ts2::GuestHeap h(m,handle,base,page); active=&h;
    ts2::GuestDispatch d; d.bind(target,allocate_endpoint);
    ts2::GuestRegisters r{11,22,33,44,stack+16,55,66,77,0x246};
    m.write32(r.esp,0x11223344u); m.write32(r.esp+4,handle);
    m.write32(r.esp+8,8); m.write32(r.esp+12,0x210);
    d.invoke(target,r,m);
    CHECK(r.eax==base && r.esp==stack+32);
    CHECK(r.ecx==22 && r.edx==33 && r.ebx==44 && r.ebp==55 && r.esi==66 && r.edi==77 && r.eflags==0x246);
    CHECK(m.read32(stack+16)==0x11223344u && m.read32(stack+20)==handle);
    rejects([&]{d.invoke(target+4,r,m);});
    // Exhaustion returns NULL through the same boundary, with stdcall12 cleanup.
    r.esp=stack+16; m.write32(r.esp+12,UINT32_MAX); d.invoke(target,r,m);
    CHECK(r.eax==0 && r.esp==stack+32);
    // Unsupported flags and truncated frames fail BEFORE heap or register effects.
    r.esp=stack+16; r.eax=99; m.write32(r.esp+8,4);
    rejects([&]{d.invoke(target,r,m);}); CHECK(r.esp==stack+16 && r.eax==99);
    r.esp=stack+page-12; m.write32(r.esp+4,handle); m.write32(r.esp+8,0);
    rejects([&]{d.invoke(target,r,m);}); CHECK(r.esp==stack+page-12 && r.eax==99);
    r.esp=UINT32_MAX-7; rejects([&]{d.invoke(target,r,m);});
    CHECK(h.allocate(handle,0,page-0x210)==base+0x210);
    active=nullptr;
}
}
int main() {
    try {
        configuration(); allocation(); reuse_and_zero(); fragmentation();
        high_end_and_isolation(); model_sequence(); abi(); live_capacity_abi();
        reallocation(); reallocation_boundaries(); reallocation_model(); reallocation_abi();
        std::cout<<"guest heap: 12 groups, 5600 model operations, bounded ownership and stdcall12/16 passed\n";
    } catch (const std::exception& e) { std::cerr<<e.what()<<'\n'; return 1; }
}
