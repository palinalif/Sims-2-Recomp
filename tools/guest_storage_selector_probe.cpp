// Authored bounded value/request transport, no Windows services or original code.
#include "ts2/guest_storage_selector.hpp"
#include "ts2/guest_memory.hpp"
#include <array>
#include <iostream>
#include <vector>
namespace {
constexpr uint32_t base=0xb1000000u, name=0xc1234567u;
struct Provider : ts2::GuestLoaderServices, ts2::GuestExportServices, ts2::GuestStorageServices {
    uint32_t module=0, target=0, result=0;
    std::vector<std::array<uint32_t,4>> calls;
    uint32_t load(uint32_t n,uint32_t file,uint32_t flags) override {
        calls.push_back({1,n,file,flags}); return module;
    }
    uint32_t last_error() override { calls.push_back({2,0,0,0}); return 5; }
    uint32_t lookup(uint32_t h,uint32_t n) override {
        calls.push_back({3,h,n,0}); return target;
    }
    void check_target(uint32_t t) override { calls.push_back({5,t,0,0}); }
    uint32_t read_fls(uint32_t t,uint32_t i) override {
        calls.push_back({6,t,i,0}); return result;
    }
    uint32_t read_tls(uint32_t i) override { calls.push_back({7,i,0,0}); return result; }
};
uint32_t word(uint32_t max=UINT32_MAX) {
    uint64_t v; if (!(std::cin>>v) || v>max) throw std::runtime_error("input");
    return static_cast<uint32_t>(v);
}
}
int main() {
    try {
        ts2::GuestMemory m; m.commit(base,m.page_size());
        unsigned count=0;
        while (true) {
            std::cin>>std::ws; if (std::cin.eof()) break;
            if (++count>8192) return 2;
            Provider p;
            const auto cookie=word(), state=word(2), module=word();
            p.module=word(); p.target=word(); const auto index=word(); p.result=word();
            const auto initial=state==0?0:(state==1?p.target:UINT32_MAX);
            if (state==1 && (!p.target || p.target==UINT32_MAX)) return 2;
            m.write32(base,cookie); m.write32(base+4,ts2::guest_encode_pointer(initial,cookie));
            m.write32(base+8,module);
            const std::array<ts2::GuestResolverCandidate,1> candidates{{{base+8,name}}};
            const auto value=ts2::legacy_query_storage(m,base,base+4,candidates,name,index,p,p,p);
            ts2::GuestLoaderServices absent; ts2::GuestExportServices no_export;
            const std::array<ts2::GuestResolverCandidate,1> invalid{{{0,0}}};
            const auto again=ts2::legacy_query_storage(m,base,base+4,invalid,0,index,absent,no_export,p);
            if (m.read32(base)!=cookie) return 2;
            for (size_t i=12;i<m.page_size();++i) if (m.read8(base+static_cast<uint32_t>(i))) return 2;
            std::cout<<value<<' '<<again<<' '<<m.read32(base+4)<<' '<<m.read32(base+8)<<' '<<p.calls.size();
            for (const auto& call:p.calls) for (auto v:call) std::cout<<' '<<v;
            std::cout<<'\n';
        }
        return count?0:2;
    } catch (const std::exception&) { return 2; }
}
