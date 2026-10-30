#pragma once
#include "ts2/guest_encoded_resolver.hpp"

namespace ts2 {
// Explicit value-level endpoints for the 8480BF selection contract. Guest target
// addresses are opaque uint32 values, NEVER host function pointers. Defaults
// throw. A nonzero resolved target must pass check_target before read_fls;
// missing/throwing FLS does NOT fall back to TLS. Zero storage values are valid.
struct GuestStorageServices {
    virtual ~GuestStorageServices() = default;
    virtual void check_target(uint32_t target);
    virtual uint32_t read_fls(uint32_t target, uint32_t index);
    virtual uint32_t read_tls(uint32_t index);
};
// Composes the actual encoded-resolver policy with explicit materialized layout.
// Same single-caller/stable-cookie/nonmutating-provider preconditions as resolver.
// Not x86 ABI/guard dispatch, Windows storage, lazy allocation or ownership.
// Resolver publication survives endpoint exceptions; no rollback.
uint32_t legacy_query_storage(GuestMemory& memory, uint32_t cookie_address,
    uint32_t function_cache_address, std::span<const GuestResolverCandidate> candidates,
    uint32_t export_name, uint32_t index, GuestLoaderServices& loader,
    GuestExportServices& exports, GuestStorageServices& storage);
}
