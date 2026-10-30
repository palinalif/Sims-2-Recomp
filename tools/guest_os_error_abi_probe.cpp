// Diagnostic-only full integer frame transport. Tables arrive only on stdin.
#include "ts2/guest_os_error_abi.hpp"
#include "ts2/guest_memory.hpp"
#include <array>
#include <charconv>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace {
std::array<uint32_t*,9> words(ts2::GuestRegisters& r) {
    return {&r.eax,&r.ebx,&r.ecx,&r.edx,&r.esi,&r.edi,&r.ebp,&r.esp,&r.eflags};
}
}
int main() {
    // Numeric full-frame transport must not synchronize each token with stdio.
    // No interactive prompt or C stdio is used by this bounded batch protocol.
    std::ios::sync_with_stdio(false);
    std::cin.tie(nullptr);
    try {
        ts2::GuestMemory m;
        constexpr uint32_t base=0xa1000000, stack=0xb8000000;
        const auto page=static_cast<uint32_t>(m.page_size());
        const auto table=base+page-359;
        m.commit(base,page*2); m.commit(stack,4096);
        std::string line; uint32_t sequence=0;
        while (std::getline(std::cin,line)) {
            if (line.size()>16384 || sequence>=4096) return 2;
            std::array<uint32_t,1123> input{};
            std::istringstream stream(line); std::string token;
            for (auto& value:input) {
                if (!(stream>>token) || token.empty()) return 2;
                const auto [end,ec]=std::from_chars(token.data(),token.data()+token.size(),value);
                if (ec!=std::errc{} || end!=token.data()+token.size()) return 2;
            }
            if (stream>>token) return 2;
            for (uint32_t i=0;i<90;++i) m.write32(table+i*4,input[i]);
            ts2::GuestRegisters r; uint32_t pos=90;
            for (auto p:words(r)) *p=input[pos++];
            for (uint32_t i=0;i<4096;i+=4) m.write32(stack+i,input[pos++]);
            // Compare every byte, using one checked little-endian word read
            // rather than four separate map lookups per word under QEMU.
            std::vector<uint32_t> before(page*2/4);
            for (uint32_t i=0;i<page*2;i+=4) before[i/4]=m.read32(base+i);
            ts2::GuestOsErrorAbi{table}.invoke(r,m);
            for (uint32_t i=0;i<page*2;i+=4) if (m.read32(base+i)!=before[i/4]) return 3;
            std::cout<<sequence++;
            for (auto p:words(r)) std::cout<<' '<<*p;
            for (uint32_t i=0;i<4096;i+=4) std::cout<<' '<<m.read32(stack+i);
            std::cout<<'\n';
        }
        return sequence && std::cin.eof()?0:2;
    } catch (const std::exception&) {
        std::cerr<<"OS-error ABI probe failed; details suppressed\n"; return 2;
    }
}
