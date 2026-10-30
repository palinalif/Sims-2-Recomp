#pragma once
#include "ts2/guest_resolver.hpp"
#include <span>

namespace ts2 {
// Value/cache policy for 847E6C + 847DA1 + 82F3EC, NOT an ABI adapter,
// compiled original body or IAT binding. Explicit caller-materialized range;
// no inferred globals, module indices, name decoding or ownership transfer.
// Cookie must remain stable. Cache initializes to encode(0,cookie), not zero.
uint32_t guest_encode_pointer(uint32_t value, uint32_t cookie);
uint32_t guest_decode_pointer(uint32_t value, uint32_t cookie);
// Hot paths read only cookie and function word, ignoring the range/providers.
// Cold ranges: at most 64 distinct nonoverlapping cache words, disjoint from
// cookie/function. Empty range is valid. Only reached module words are read.
// All-ones is reserved: cached module failures skip; provider all-ones throws.
// Single caller, no provider mutation of memory/layout/cookie; no races, loser
// FreeLibrary, SEH, recursive resolution or atomic publication guarantees.
// Effects before throws (including module-cache writes) remain; no rollback.
// Default providers throw, never report silent success.
uint32_t legacy_resolve_encoded(GuestMemory& memory, uint32_t cookie_address,
    uint32_t function_cache_address, std::span<const GuestResolverCandidate> candidates,
    uint32_t export_name, GuestLoaderServices& loader, GuestExportServices& exports);
}
