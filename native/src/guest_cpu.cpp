#include "ts2/guest_cpu.hpp"
#include <cstdio>
#include <stdexcept>

namespace ts2 {
GuestCpu::GuestCpu(std::initializer_list<GuestCpuidResponse> cpuid,
                   std::initializer_list<GuestXcrResponse> xcr) {
    for (const auto& response : cpuid) {
        if (!cpuid_.emplace(std::make_pair(response.leaf, response.subleaf),
                            response.result).second)
            throw std::invalid_argument("Duplicate guest CPUID leaf/subleaf");
    }
    for (const auto& response : xcr) {
        if (!xcr_.emplace(response.index, response.value).second)
            throw std::invalid_argument("Duplicate guest XCR index");
    }
}

void GuestCpu::cpuid(GuestRegisters& registers) const {
    const auto entry = cpuid_.find({registers.eax, registers.ecx});
    if (entry == cpuid_.end()) {
        char message[96];
        std::snprintf(message, sizeof(message),
                      "Unconfigured guest CPUID leaf=0x%08x subleaf=0x%08x",
                      static_cast<unsigned>(registers.eax),
                      static_cast<unsigned>(registers.ecx));
        throw std::out_of_range(message);
    }
    const auto& result = entry->second;
    registers.eax = result.eax;
    registers.ebx = result.ebx;
    registers.ecx = result.ecx;
    registers.edx = result.edx;
}

void GuestCpu::xgetbv(GuestRegisters& registers) const {
    const auto entry = xcr_.find(registers.ecx);
    if (entry == xcr_.end()) {
        char message[80];
        std::snprintf(message, sizeof(message),
                      "Unconfigured guest XGETBV index=0x%08x",
                      static_cast<unsigned>(registers.ecx));
        throw std::out_of_range(message);
    }
    registers.eax = static_cast<uint32_t>(entry->second);
    registers.edx = static_cast<uint32_t>(entry->second >> 32);
}
}
