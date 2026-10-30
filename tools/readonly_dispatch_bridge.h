/* Diagnostic-only C bridge for bounded read-only lifted fixtures. Not an OS ABI.
 * State order: eax ecx edx ebx esp ebp esi edi eflags. Callbacks must return
 * normally, use bridge_read32 for every read, and have no external effects.
 * No writes, nesting, general lifter support or rollback of callback globals.
 */
#ifndef TS2_READONLY_DISPATCH_BRIDGE_H
#define TS2_READONLY_DISPATCH_BRIDGE_H
#include <stdint.h>
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef struct { uint32_t address, size; const unsigned char *bytes; } Ts2ReadSpan;
typedef struct { uint32_t va; void (*call)(uint32_t state[9]); } Ts2ReadEntry;
enum { TS2_READ_OK, TS2_READ_INVALID, TS2_READ_UNRESOLVED,
       TS2_READ_FAULT, TS2_READ_REENTRY, TS2_READ_EXCEPTION };
/* <=16 disjoint nonempty spans, <=1 MiB total; <=16 unique entries. State is
 * published only on success. Span buffers remain caller-owned and immutable.
 * read32 returns zero AND latches failure on invalid access, so zero is never
 * reported as a successful substitute. No C++ exception crosses the C boundary.
 */
int ts2_read_dispatch(uint32_t va, uint32_t state[9], const Ts2ReadSpan *spans,
                      size_t span_count, const Ts2ReadEntry *entries, size_t count);
uint32_t ts2_bridge_read32(uint32_t address);
#ifdef __cplusplus
}
#endif
#endif
