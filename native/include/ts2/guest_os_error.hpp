#pragma once
#include "ts2/guest_memory.hpp"
#include <cstdint>

namespace ts2 {
// Value-only Legacy 831A7A policy. The caller supplies exactly 45 uint32
// key/value pairs in guest memory, in priority order; duplicates are legal.
// Validates/reads the entire 360-byte span before selection. Unaligned tables
// are supported; null, wrapping and uncommitted spans throw. No writes occur.
// Caller must provide stable memory/single ownership during this call.
// No globals, dispatch binding, CPU ABI, errno store or OS service is supplied.
uint32_t legacy_map_os_error(const GuestMemory& memory, uint32_t table,
                             uint32_t error);
}
