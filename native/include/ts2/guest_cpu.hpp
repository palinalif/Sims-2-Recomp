#pragma once
#include "ts2/guest_dispatch.hpp"
#include <initializer_list>
#include <map>
#include <utility>

namespace ts2 {
struct GuestCpuidResult {
    uint32_t eax{}, ebx{}, ecx{}, edx{};
};
struct GuestCpuidResponse {
    uint32_t leaf{}, subleaf{};
    GuestCpuidResult result;
};
struct GuestXcrResponse {
    uint32_t index{};
    uint64_t value{};
};

// Explicit guest-x86 responses, never host feature detection. Construct before
// use and pass by const reference per execution context; no global CPU policy.
// Missing requests throw std::out_of_range before changing registers. This is
// a stop/diagnostic boundary, NOT guest #UD/#GP delivery or ISA implementation.
class GuestCpu {
public:
    explicit GuestCpu(std::initializer_list<GuestCpuidResponse> cpuid,
                      std::initializer_list<GuestXcrResponse> xcr = {});
    void cpuid(GuestRegisters& registers) const;
    void xgetbv(GuestRegisters& registers) const;
private:
    std::map<std::pair<uint32_t, uint32_t>, GuestCpuidResult> cpuid_;
    std::map<uint32_t, uint64_t> xcr_;
};
}
