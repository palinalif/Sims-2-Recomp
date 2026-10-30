#pragma once
#include <cstdint>
#include <map>
#include <stdexcept>

namespace ts2 {
class GuestMemory;

// Integer-only call state, not a complete x86 thread context. No host pointers,
// implicit argument marshalling, stack cleanup, or flag normalization.
struct GuestRegisters {
    uint32_t eax{}, ecx{}, edx{}, ebx{}, esp{}, ebp{}, esi{}, edi{};
    uint32_t eflags{};
};

class UnresolvedGuestCall : public std::runtime_error {
    uint32_t target_;
public:
    explicit UnresolvedGuestCall(uint32_t target);
    uint32_t target() const noexcept { return target_; }
};

// Populate before execution; concurrent registration/execution is unsupported.
// Entries are authored adapters or privately compiled functions, never guest
// executable bytes or host vtables. ABI effects belong to each tested adapter.
class GuestDispatch {
public:
    using Function = void (*)(GuestRegisters&, GuestMemory&, const GuestDispatch&);
    void bind(uint32_t va, Function function);
    void invoke(uint32_t va, GuestRegisters& registers, GuestMemory& memory) const;
private:
    std::map<uint32_t, Function> entries_;
};
}
