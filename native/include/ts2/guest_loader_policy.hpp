#pragma once
#include <cstdint>
#include <stdexcept>

namespace ts2 {
class GuestMemory;
// Raw unsigned little-endian 16-bit units, exact subtraction modulo 2^32.
// Zero count reads no memory. Stops at mismatch/equal NUL/count, without
// prevalidating unused suffixes. Unmapped/wrapping reads throw; no guest SEH.
// No host wchar_t, case folding, locale or pointer conversion.
uint32_t guest_wide_compare(const GuestMemory& memory, uint32_t left,
                            uint32_t right, uint32_t count);
// Explicit dependencies for the pinned Legacy helper at RVA 82A2B2.
// All addresses/results are guest-width words, never host pointers. Defaults
// STOP on unavailable services; zero is a real provider response, not absence.
class GuestLoaderServices {
public:
    virtual ~GuestLoaderServices() = default;
    virtual uint32_t load(uint32_t, uint32_t, uint32_t) {
        throw std::runtime_error("guest loader: load unavailable");
    }
    virtual uint32_t last_error() {
        throw std::runtime_error("guest loader: error unavailable");
    }
    virtual uint32_t compare(uint32_t, uint32_t, uint32_t) {
        throw std::runtime_error("guest loader: comparison unavailable");
    }
};

// Explicit opt-in comparator binding; memory must outlive this non-owning adapter.
// Load/error remain fail-closed unless supplied by a derived service. No OS calls,
// module ownership or implicit mapping of the helper's fixed comparison operand.
class CheckedGuestLoaderServices : public GuestLoaderServices {
public:
    explicit CheckedGuestLoaderServices(const GuestMemory& memory) : memory_(memory) {}
    uint32_t compare(uint32_t left, uint32_t right, uint32_t count) final;
private:
    const GuestMemory& memory_;
};

// Policy only: no guest ABI/stack/flags adapter, IAT binding, name decoding,
// comparator binding, host dlopen, error storage or handle ownership.
// Provider effects before an exception are NOT rolled back. No retry on throw.
uint32_t legacy_loader_policy(uint32_t name, GuestLoaderServices& services);
}
