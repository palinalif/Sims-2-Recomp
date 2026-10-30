#include "ts2/guest_encoded_resolver.hpp"
#include "ts2/guest_memory.hpp"
#include <array>
#include <iostream>
#include <vector>
namespace {
#define CHECK(x) do { if (!(x)) throw std::runtime_error(#x); } while (false)
constexpr uint32_t base=0xb1000000u;
const std::array<ts2::GuestResolverCandidate,2> candidates{{{base+8,42},{base+12,43}}};
struct Provider : ts2::GuestLoaderServices, ts2::GuestExportServices {
    uint32_t module=23, result=31;
    uint32_t load(uint32_t, uint32_t, uint32_t) override { return module; }
    uint32_t lookup(uint32_t, uint32_t) override { return result; }
};
template<class F> void rejects(F f) {
    bool caught=false; try { f(); } catch (const std::exception&) { caught=true; } CHECK(caught);
}
}
int main() {
    try {
        ts2::GuestMemory m, peer;
        m.commit(base,m.page_size()); peer.commit(base,peer.page_size());
        Provider p;
        ts2::GuestLoaderServices absent; ts2::GuestExportServices no_export;
        auto init = [&] { m.write32(base,31); m.write32(base+4,31); m.write32(base+8,0); m.write32(base+12,0); };
        auto run = [&](std::span<const ts2::GuestResolverCandidate> range) {
            return ts2::legacy_resolve_encoded(m,base,base+4,range,99,p,p);
        };
        // Independent rotate-free bit placement for all 32 rotation counts.
        for (uint32_t count=0; count<32; ++count) for (auto value : {0u,1u,0x80000001u,UINT32_MAX}) {
            uint32_t rotated=0, cookie=0x12345660u | count;
            for (unsigned bit=0; bit<32; ++bit) if ((value>>bit)&1) rotated |= uint32_t{1}<<((bit+count)%32);
            CHECK(ts2::guest_encode_pointer(value,cookie)==(rotated^cookie));
            CHECK(ts2::guest_decode_pointer(rotated^cookie,cookie)==value);
        }
        init(); CHECK(run(candidates)==31); CHECK(m.read32(base+8)==23);
        CHECK(peer.read32(base)==0 && peer.read32(base+8)==0);
        // Hot success/failure ignores invalid range; needs no providers.
        const std::array<ts2::GuestResolverCandidate,1> invalid{{{0,0}}};
        for (auto value : {31u,UINT32_MAX}) {
            m.write32(base+4,ts2::guest_encode_pointer(value,31));
            CHECK(ts2::legacy_resolve_encoded(m,base,base+4,invalid,0,absent,no_export)==(value==UINT32_MAX?0:value));
        }
        init(); CHECK(run({})==0); CHECK(m.read32(base+4)==ts2::guest_encode_pointer(UINT32_MAX,31));
        // Missing providers fail, not cached null. Module publication survives export throw.
        init(); rejects([&]{ts2::legacy_resolve_encoded(m,base,base+4,candidates,0,absent,no_export);});
        CHECK(m.read32(base+4)==31 && m.read32(base+8)==0);
        init(); rejects([&]{ts2::legacy_resolve_encoded(m,base,base+4,candidates,0,p,no_export);});
        CHECK(m.read32(base+4)==31 && m.read32(base+8)==23);
        init(); p.module=UINT32_MAX; rejects([&]{run(candidates);}); CHECK(m.read32(base+8)==0);
        init(); p.module=23; p.result=UINT32_MAX; rejects([&]{run(candidates);}); CHECK(m.read32(base+4)==31);
        // Cold malformed layout rejects before any service/cache publication.
        for (auto address : {base,base+2,base+4,base+6,base+8,0xfffffffeu}) {
            init(); auto bad=candidates; bad[1].cache_address=address;
            rejects([&]{run(bad);}); CHECK(m.read32(base+8)==0 && m.read32(base+4)==31);
        }
        init(); std::vector<ts2::GuestResolverCandidate> excessive(65);
        rejects([&]{run(excessive);});
        std::vector<ts2::GuestResolverCandidate> maximum;
        for (uint32_t i=0; i<64; ++i) {
            maximum.push_back({base+16+4*i,0}); m.write32(base+16+4*i,UINT32_MAX);
        }
        CHECK(run(maximum)==0); // Full budget, cached failures require no providers.
        // Same word for cookie/function is invalid on a cold resolution.
        init(); rejects([&]{ts2::legacy_resolve_encoded(m,base,base,{},0,p,p);});
        init(); auto bad=candidates; bad[0].cache_address=0; rejects([&]{run(bad);});
        // Unreached later words are not read, but overlap is always rejected.
        init(); p.result=31; bad=candidates; bad[1].cache_address=0; CHECK(run(bad)==31);
        rejects([&]{ts2::legacy_resolve_encoded(m,0,base+4,{},0,absent,no_export);});
        rejects([&]{ts2::legacy_resolve_encoded(m,base,0xfffffffeu,{},0,absent,no_export);});
        std::cout << "encoded resolver: rotations, hot paths, layout, failures and isolation passed\n";
    } catch (const std::exception& e) { std::cerr<<e.what()<<'\n'; return 1; }
}
