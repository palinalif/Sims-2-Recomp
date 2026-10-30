#ifndef TS2_GUEST_QUERY_GUARD_H
#define TS2_GUEST_QUERY_GUARD_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct {
    uint32_t guest_start;
    uint32_t byte_count;
    const unsigned char *host;
} Ts2GuestSpan;

typedef struct {
    const Ts2GuestSpan *spans;
    size_t span_count;
} Ts2GuestView;

typedef struct {
    uint32_t va;
    void (*function)(void);
} Ts2GuestEntry;

static inline uint32_t ts2_checked_read32(const Ts2GuestView *view, uint32_t address) {
    const uint64_t read_end = (uint64_t)address + 4u;
    if (view != NULL && view->spans != NULL && read_end <= UINT64_C(0x100000000)) {
        for (size_t i = 0; i < view->span_count; ++i) {
            const Ts2GuestSpan *span = &view->spans[i];
            const uint64_t span_end = (uint64_t)span->guest_start + span->byte_count;
            if (span->host != NULL && span_end <= UINT64_C(0x100000000)
                    && address >= span->guest_start && read_end <= span_end) {
                const unsigned char *p = span->host + (size_t)(address - span->guest_start);
                return (uint32_t)p[0] | ((uint32_t)p[1] << 8)
                     | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
            }
        }
    }
    fprintf(stderr, "TS2_GUEST_READ_REJECT address=%08x\n", (unsigned)address);
    exit(102);
}

/* Lvalue view for fixtures that execute writer functions: an out-of-span
 * write lands in a zeroed sink, which cannot silently agree with the
 * independent reference (the reference either faults or records the write). */
static uint32_t ts2_checked_sink32;
static inline uint32_t *ts2_checked_view32(const Ts2GuestView *view, uint32_t address) {
    const uint64_t end = (uint64_t)address + 4u;
    if (view != NULL && view->spans != NULL && end <= UINT64_C(0x100000000)) {
        for (size_t i = 0; i < view->span_count; ++i) {
            const Ts2GuestSpan *span = &view->spans[i];
            const uint64_t span_end = (uint64_t)span->guest_start + span->byte_count;
            if (span->host != NULL && span_end <= UINT64_C(0x100000000)
                    && address >= span->guest_start && end <= span_end) {
                return (uint32_t *)(void *)(span->host + (size_t)(address - span->guest_start));
            }
        }
    }
    ts2_checked_sink32 = 0u;
    return &ts2_checked_sink32;
}

static inline void ts2_dispatch(uint32_t va, const Ts2GuestEntry *entries, size_t count) {
    if (entries != NULL) {
        for (size_t i = 0; i < count; ++i) {
            if (entries[i].va == va && entries[i].function != NULL) {
                entries[i].function();
                return;
            }
        }
    }
    fprintf(stderr, "TS2_UNRESOLVED_FUNCTION va=%08x\n", (unsigned)va);
    exit(103);
}

#endif
