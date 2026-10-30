# Startup critical path toward the first real menu (living graph)

Status: SEED (2026-10-26, FAST FORWARD deliverable C). Maintained by Lane A
(`startup-path` objective). Every node carries a status and cited evidence —
commit hash, `docs/VERIFIED_LEDGER.md` row, or receipt path. **Unknowns are
listed as unknowns; nothing here is inferred from names or decompiler
pseudocode.** RVAs are image-relative (Steam Legacy 1.18.0.187, SHA-256
`63a545db…9985`). This graph is about reaching the first real menu; it is not
Phase 1 acceptance and cites no claims about gameplay.

Reading order: `docs/OBJECT_QUERY_CALLER.md` (allocator chain evidence),
`docs/VERIFIED_LEDGER.md` (per-function tier evidence), the engineering handoff (private record)
(entry-point notes), `docs/ARCHITECTURE.md`.

## Legend

- **V** verified (ledger T1/T3 discipline; see ledger row for scope)
- **S** synthesized service (portable replacement, differential-tested)
- **P** pinned but not yet verified/executed
- **?** mapped dependency, evidence not yet compiled here (cite in row)

## Verified frontier (leaves → inward)

| Node | Role on startup path | Status | Evidence |
|---|---|---|---|
| 0x1A00, 0x1A40 | opener buffer dependencies | V | commits a0624c3, 8969743 |
| 0x2570 | composed opener initializer | V | commit d759593 |
| 0x1AB770, 0x1AB78C | init-chain helpers (owner ARM64 phone rows) | V | ledger rows (2026-10-21) |
| 0x20D0 | object-query input contract | V (contract) | docs/OBJECT_QUERY_CALLER.md; work/recomp-bench/input20d0-receipt |
| 0x1AF0 (partial) | descriptor spare-chain consumption inside 0x2790→0x26B0→0x1AF0 composition | V (composed path, 63/231 coverage) | docs/OBJECT_QUERY_CALLER.md; capacity-reuse-final/result.json |
| 0x2790, 0x26B0 | string-publication composition over 0x1AF0 | V (composed, same receipt) | same |
| 0x8413B0, 0x85217F | realloc-eligibility family | P/V-partial | docs/OBJECT_QUERY_CALLER.md hypothesis + ledger rows |
| guest heap | portable allocator service boundary | S | commits b7b8f3c, b5ff28f, 220cc51, 1869308 (realloc service), e809ee9 |
| 7 factory functions (leaf-getter/small-leaf class) | misc leaf reads | V | work/ghidra-index/verified-ledger.jsonl (factory receipts 2026-10-26) |

## Init-chain spine (interior)

- **0x1AB665** — composed initialization caller. Composition exists with
  verified dependency leaves above; whole-function composed verification is
  the current Lane-A target (do not claim until a receipt says
  `whole_function_verified: true` with host + AArch64 + x86 reference).
- **0x20D0 query callers** — mapped in docs/OBJECT_QUERY_CALLER.md; edges to
  descriptor lifetime producers remain **?**.

## Frontier (explicit unknowns — Lane A work queue)

1. **Entrypoint frame ?**: the image entry-point function and its first-level
   calls to the init spine are not yet pinned into this graph. Cite HANDOFF
   entry-point notes; produce a pinned call-edge list with disassembly
   evidence under work/.
2. **Win32/NT dependency surface ?**: which imports the startup prefix
   actually executes (heap, TLS, SEH registration, file/mapper) has no
   inventory receipt yet. Needed before host-service work can be sequenced.
3. **Descriptor lifetime producers ?** (who creates/resets the descriptor
   that 0x1AF0 consumes) — OBJECT_QUERY_CALLER.md marks this unestablished.
4. **FCB0/opener-to-spine edges ?** — opener dependencies verified
   individually; their wiring into 0x1AB665's frame needs a composed receipt.

## Rules for updating

- One row = one node; add edges as `caller → callee (evidence)`.
- Verification upgrades cite receipts, never this file's own prose.
- The fail-closed acceptance gate (78) is about FINAL acceptance only; it is
  **not** a blocker for graph, lifting, or service work and must not be cited
  as a human-blocker here.
