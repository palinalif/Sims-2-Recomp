// Diagnostic-only existing-lift adapter; not linked into Android.
#pragma once
#include "readonly_dispatch_bridge.h"
#ifdef __cplusplus
extern "C" {
#endif
uint32_t ts2_image_read32(uint32_t address);
int ts2_image_dispatch(uint32_t va, uint32_t state[9],
    const Ts2ReadSpan* spans, size_t n, const Ts2ReadEntry* entries, size_t count);
#ifdef __cplusplus
}
#endif
