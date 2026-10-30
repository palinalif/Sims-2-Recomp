/* Diagnostic fixture bridge, NOT a general lifter/OS ABI or Android runtime.
 * All callback memory accesses/calls must use this API. Callbacks must return
 * normally and have no external effects. Host buffers must be valid and not
 * alias state, report, descriptors, or one another; concurrent use of the same
 * buffers/callback globals is unsupported. No rollback of callback globals.
 */
#ifndef TS2_SCOPED_DISPATCH_BRIDGE_H
#define TS2_SCOPED_DISPATCH_BRIDGE_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef struct {
    uint32_t address, size;
    const unsigned char *input;
    unsigned char *output; /* NULL = read-only; otherwise exact allowed-write span */
} Ts2ScopedSpan;
typedef struct { uint32_t va; void (*call)(uint32_t state[9]); } Ts2ScopedEntry;
typedef struct { uint32_t address, before, after; } Ts2ScopedWrite;
typedef struct {
    uint32_t calls, writes;
    Ts2ScopedWrite journal[256]; /* ordered stores, including unchanged values */
} Ts2ScopedReport;
enum { TS2_SCOPED_OK, TS2_SCOPED_INVALID, TS2_SCOPED_FAULT,
       TS2_SCOPED_REENTRY, TS2_SCOPED_EXCEPTION };
/* <=16 disjoint spans, <=1 MiB; <=16 unique nonzero VAs. Depth <=8,
 * total calls <=64, stores <=256. No automatic CALL/RET stack/flag effects.
 * State order eax ecx edx ebx esp ebp esi edi eflags. On any failure, state,
 * outputs and report are unpublished. Input snapshots are always copied.
 * Only explicit nested ts2_scoped_call shares this transaction. Starting
 * another top-level transaction inside a callback poisons the current one.
 */
int ts2_scoped_dispatch(uint32_t va, uint32_t state[9], const Ts2ScopedSpan *spans,
    size_t span_count, const Ts2ScopedEntry *entries, size_t entry_count,
    Ts2ScopedReport *report);
uint32_t ts2_scoped_read32(uint32_t address);
void ts2_scoped_write32(uint32_t address, uint32_t value);
int ts2_scoped_call(uint32_t va, uint32_t state[9]);
#ifdef __cplusplus
}
#endif
#endif
