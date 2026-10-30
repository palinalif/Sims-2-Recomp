// Authored endpoint transport, not heap/storage services. No original bytes.
#include "ts2/guest_lazy_provider_abi.hpp"
#include "ts2/guest_memory.hpp"
#include <array>
#include <iostream>
#include <stdexcept>
#include <vector>
namespace {
constexpr uint32_t stack=0xb8000000u, data=0xa1000000u;
constexpr std::array<uint32_t,7> targets={0xf0000100u,0xf0000200u,0xf0000300u,
    0xa08480feu,0xa0849a00u,0xa0845cf9u,0xa08461b8u};
constexpr std::array<uint32_t,7> counts={0,1,1,2,2,2,1};
constexpr std::array<uint32_t,7> pops={0,4,4,8,0,0,0};
std::array<uint32_t*,9> words(ts2::GuestRegisters& r) {
    return {&r.eax,&r.ebx,&r.ecx,&r.edx,&r.esi,&r.edi,&r.ebp,&r.esp,&r.eflags};
}
uint32_t word() {
    uint64_t v; if (!(std::cin>>v) || v>UINT32_MAX) throw std::runtime_error("input");
    return static_cast<uint32_t>(v);
}
struct Event { uint32_t kind,ret,sp; std::vector<uint32_t> args; };
std::vector<Event> events;
uint32_t claim,pointer,publish,error,clobber,mode,writes;
void endpoint(ts2::GuestRegisters& r,ts2::GuestMemory& m,uint32_t k) {
    if (events.size()>=9) throw std::runtime_error("event budget");
    Event e{k,m.read32(r.esp),r.esp,{}};
    for (uint32_t i=0;i<counts[k];++i) e.args.push_back(m.read32(r.esp+4+4*i));
    events.push_back(e);
    if (mode==8) throw std::runtime_error("endpoint failure");
    uint32_t response=0xbaadf00du;
    if (k==0) response=error;
    if (k==1) response=mode==9?1:0;
    if (k==2) error=e.args[0];
    if (k==3) { response=writes==0?claim:writes==1&&pointer?publish:0xbaadf00du; ++writes; }
    if (k==4) response=pointer;
    r.eax=response;
    if (clobber) { r.ecx=0xfeedfaceu; r.edx=0xdeadbeefu; }
    if (mode==10) m.write32(stack+0x800,0);
    r.esp+=4+pops[k]+(mode==k+1?4:0);
}
#define ENDPOINT(N) void ep##N(ts2::GuestRegisters& r,ts2::GuestMemory& m,const ts2::GuestDispatch&) { endpoint(r,m,N); }
ENDPOINT(0) ENDPOINT(1) ENDPOINT(2) ENDPOINT(3) ENDPOINT(4) ENDPOINT(5) ENDPOINT(6)
}
int main() {
    std::ios::sync_with_stdio(false); std::cin.tie(nullptr);
    try {
        unsigned n=0;
        while (true) {
            std::cin>>std::ws; if (std::cin.eof()) break;
            if (++n>4096) return 2;
            const auto index=word(); claim=word(); pointer=word(); publish=word();
            error=word(); clobber=word(); mode=word();
            if (clobber>1 || mode>11) return 2;
            ts2::GuestRegisters r; for (auto p:words(r)) *p=word();
            ts2::GuestMemory m; m.commit(stack,4096); m.commit(data,4096);
            for (uint32_t i=0;i<4096;i+=4) m.write32(stack+i,word());
            m.write32(data,index); m.write32(data+4,targets[0]); m.write32(data+8,targets[2]);
            ts2::GuestDispatch d;
            std::array<ts2::GuestDispatch::Function,7> endpoints={ep0,ep1,ep2,ep3,ep4,ep5,ep6};
            for (unsigned i=0;i<7;++i) if (!(mode==11&&i==3)) d.bind(targets[i],endpoints[i]);
            events.clear(); writes=0; bool failed=false;
            try { ts2::GuestLazyProviderAbi{data,data+4,data+8,targets[1],targets[3],
                targets[4],targets[5],targets[6],0xa10e002cu}.invoke(r,m,d); }
            catch (const std::exception&) { failed=true; }
            for (uint32_t i=0;i<4096;i+=4) {
                const auto expected=i==0?index:i==4?targets[0]:i==8?targets[2]:0;
                if (m.read32(data+i)!=expected) return 3;
            }
            std::cout<<failed;
            for (auto p:words(r)) std::cout<<' '<<*p;
            for (uint32_t i=0;i<4096;i+=4) std::cout<<' '<<m.read32(stack+i);
            std::cout<<' '<<error<<' '<<events.size();
            for (const auto& e:events) {
                std::cout<<' '<<e.kind<<' '<<e.ret<<' '<<e.sp;
                for (auto a:e.args) std::cout<<' '<<a;
            }
            std::cout<<'\n';
        }
        return n?0:2;
    } catch (const std::exception&) { return 2; }
}
