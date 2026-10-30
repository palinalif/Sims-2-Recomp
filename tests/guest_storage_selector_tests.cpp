#include "ts2/guest_storage_selector.hpp"
#include "ts2/guest_memory.hpp"
#include <array>
#include <iostream>
#include <vector>
namespace {
#define CHECK(x) do { if (!(x)) throw std::runtime_error(#x); } while (false)
constexpr uint32_t base=0xb1000000u, target=0xf1234567u;
template<class F> void rejects(F f) {
    bool caught=false; try { f(); } catch (const std::exception&) { caught=true; } CHECK(caught);
}
struct Storage : ts2::GuestStorageServices {
    std::vector<unsigned> events;
    uint32_t result=0;
    bool fail_guard=false, fail_fls=false;
    void check_target(uint32_t t) override {
        CHECK(t==target); events.push_back(1);
        if (fail_guard) throw std::runtime_error("guard rejects");
    }
    uint32_t read_fls(uint32_t t,uint32_t index) override {
        CHECK(t==target && index==UINT32_MAX); events.push_back(2);
        if (fail_fls) throw std::runtime_error("FLS rejects");
        return result;
    }
    uint32_t read_tls(uint32_t index) override {
        CHECK(index==UINT32_MAX); events.push_back(3); return result;
    }
};
struct Export : ts2::GuestExportServices {
    uint32_t lookup(uint32_t module,uint32_t name) override {
        CHECK(module==42 && name==99); return target;
    }
};
}
int main() {
    try {
        ts2::GuestMemory m, peer; m.commit(base,m.page_size()); peer.commit(base,peer.page_size());
        ts2::GuestLoaderServices absent; ts2::GuestExportServices no_export;
        ts2::GuestStorageServices missing; Storage storage; Export exports;
        const std::array<ts2::GuestResolverCandidate,1> candidate{{{base+8,123}}};
        auto init=[&](uint32_t decoded) { m.write32(base,31); m.write32(base+4,ts2::guest_encode_pointer(decoded,31)); m.write32(base+8,42); storage.events.clear(); };
        auto run=[&](ts2::GuestStorageServices& s) { return ts2::legacy_query_storage(m,base,base+4,candidate,99,UINT32_MAX,absent,exports,s); };
        // Cold cached module -> publication BEFORE guard/FLS, including throwing endpoints.
        init(0); CHECK(run(storage)==0); CHECK((storage.events==std::vector<unsigned>{1,2}));
        CHECK(m.read32(base+4)==ts2::guest_encode_pointer(target,31));
        init(0); storage.fail_guard=true; rejects([&]{run(storage);});
        CHECK((storage.events==std::vector<unsigned>{1})); CHECK(m.read32(base+4)==ts2::guest_encode_pointer(target,31));
        storage.fail_guard=false; storage.fail_fls=true; init(0); rejects([&]{run(storage);});
        CHECK((storage.events==std::vector<unsigned>{1,2})); CHECK(m.read32(base+4)==ts2::guest_encode_pointer(target,31));
        storage.fail_fls=false;
        for (auto result:{0u,1u,0x80000000u,UINT32_MAX}) {
            storage.result=result;
            init(target); CHECK(run(storage)==result); CHECK((storage.events==std::vector<unsigned>{1,2}));
            init(UINT32_MAX); CHECK(run(storage)==result); CHECK((storage.events==std::vector<unsigned>{3}));
        }
        // Only the function address is cached, never the returned storage value.
        init(0); storage.result=17; CHECK(run(storage)==17);
        storage.result=23; CHECK(run(storage)==23);
        CHECK((storage.events==std::vector<unsigned>{1,2,1,2}));
        init(0); rejects([&]{run(missing);}); // Default guard throws after cache publication.
        CHECK(m.read32(base+4)==ts2::guest_encode_pointer(target,31));
        init(UINT32_MAX); rejects([&]{run(missing);});
        rejects([&]{missing.read_fls(target,0);});
        // Failed resolver must not reach any storage endpoint.
        init(0); rejects([&]{ts2::legacy_query_storage(m,base,base+4,candidate,99,0,absent,no_export,storage);});
        CHECK(storage.events.empty()); CHECK(m.read32(base+4)==31);
        CHECK(peer.read32(base)==0 && peer.read32(base+4)==0);
        rejects([&]{ts2::legacy_query_storage(m,0,base+4,{},0,0,absent,no_export,storage);});
        std::cout<<"storage selector: ordering, zero values, guards, failures, isolation passed\n";
    } catch (const std::exception& e) { std::cerr<<e.what()<<'\n'; return 1; }
}
