# Ghidra analysis workflow for the autonomous Sims 2 port

**Status:** Ghidra 12.2 is installed locally and the pinned Legacy analysis image **is imported** into the persistent private project `work/ghidra/Sims2Legacy118` (2026-10-22), with a bounded read-only JSON query interface at `scripts/ghidra-query.sh` + `scripts/ghidra/Sims2Query.java`. The four documented probe RVAs reproduce prior evidence (see "Current state"), which validates address mapping only, not any new reconstruction claim. See see `AGENTS.md` and the `VERIFIED_LEDGER.md`.

## Purpose and division of responsibilities

Ghidra is a **first-class, persistent reverse-engineering index**, not the compiler or a game-reconstruction oracle. Use it for x86 function boundary evidence, disassembly, decompiler pseudocode, callers/callees, vtables, imports, data types, memory references and the critical startup/render/resource paths. Keep the existing pinned `pcrecomp` lifter for bounded native recompilation and preserve independent Unicorn/reference-state/oracle comparisons for correctness. Ghidra pseudocode, automatic function names and decompiler types are **hypotheses**, not validated source.

Do not launch another wholesale analysis of every function for each question. Import once, keep a persistent Ghidra project, reprocess narrowly with scripts, and expose small structured queries to Pi.

## Startup checklist

1. Detect an existing compatible installation, Java runtime, available RAM/disk and previously imported Ghidra project. Record actual paths, versions, checksums and startup commands in the local campaign status.
2. If needed, obtain a compatible Ghidra release **from the official NSA Ghidra release source**, verify provenance and checksums where available, and install into an isolated, versioned tools directory. Do not alter a system-wide JDK or unrelated Unraid containers as a shortcut.
3. Identify the already-authorized **private recovered analysis image** described in the engineering handoff (private record) and `docs/INTEROP_EXPERIMENT.md`; the recorded SHA-256 is `63a545db48a9cf5ce5f5cdca467ed49728ea3c79132fa0eff8abf10e91659985`. Verify the on-disk hash **before** import. The source is not in GitHub; if absent, note the missing private transfer and continue unrelated host-side work. Do not search for pirated binaries, repeat protection recovery beyond authorization, or run the modified analysis image.
4. Store all imported programs, Ghidra project databases, scripts that contain recovered code, temporary results and logs under ignored `work/ghidra/` or another **private, persistent, access-controlled** location. Do not commit `.gpr`, `.rep`, original/recovered bytes, decompiler dumps, screenshots or raw logs. Import a copy of the authorized image; preserve originals unchanged.
5. When importing, confirm **Windows x86 PE32** format, preferred image base `0xA0000000`, import table and code regions against the pinned Legacy evidence. Because the recovered PE retains its original wrapped entry point and is not a runnable executable, **do not assume Ghidra's detected program entry is the true game entry**; reconcile it with `docs/INTEROP_EXPERIMENT.md`. Maintain exact RVA/VA mappings.
6. Run initial headless analysis once with bounded CPU/time/memory and save the project. Capture analysis warnings and limitations. Avoid aggressive auto-fixups, blanket signature imports or scripts that change original reference data without evidence.

Official documentation: [Ghidra headless analyzer README](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/RuntimeScripts/support/analyzeHeadlessREADME.md).

## Headless commands (this machine)

Ghidra and its JDK live in the ignored sibling `../.local-tools/` directory (`ghidra-12.2`, `jdk25`); `scripts/campaign/worker-env.sh` puts them on `PATH`. Both the import and the query wrappers accept overrides (`GHIDRA_HEADLESS_HOME`, `JAVA_HOME`, `TOOLS_ROOT`).

Import (idempotent: refuses to re-import over a recorded successful import, verifies the image hash first, fails loudly on analyzer OOM):

```sh
scripts/ghidra-import.sh            # ~9 min, writes work/ghidra/import.log
```

The default 2 GB headless heap is **not enough** for this PE32 image: analysis died at ~9 minutes with `OutOfMemoryError` and `analyzeHeadless` still exited 0. The wrapper therefore passes `GHIDRA_HEADLESS_MAXMEM=12G` (override per host) and greps the log for `OutOfMemoryError`/`Abort due to`, because the exit code cannot be trusted alone.

Routine narrow queries go through the wrapper, never a raw re-import:

```sh
scripts/ghidra-query.sh --rva 1AB665 --instructions 40   # summary to stderr-ish, JSON path on stdout
scripts/ghidra-query.sh --va 0xa001ab665 --pseudo 40 --quiet
```

Ghidra provides `support/analyzeHeadless` on Linux. Import and processing are distinct modes, **not** combined in one invocation. Underneath, a query is:

```sh
"$GHIDRA_HOME/support/analyzeHeadless" "$PROJECT_DIR" Sims2Legacy118 \
  -process Sims2EP9-1.18.0.187-analysis-image.bin -readOnly -noanalysis \
  -scriptPath scripts/ghidra -postScript Sims2Query.java -- out=... rva=1ab665
```

Two `analyzeHeadless` quirks confirmed here: `-process` takes the stored program name **without** a leading project-root slash (`/Foo.bin` yields `invalid filename specified`), and a bare `-list` is rejected (`Bad argument: -list`) — list with `-process '*' -list`. Script paths and the stored program name must be resolved from the actual imported project. **Do not use `-import -readOnly` to create an allegedly persistent index:** the official analyzer does not save imports in that mode. Keep write-mode annotations in a controlled single-owner project, and use read-only queries for routine agent inspection.

### Query interface contract

`scripts/ghidra/Sims2Query.java` (schema `sims2-ghidra-query/1`) accepts `out`, `rva` or `va`, `maxInstructions`, `maxRefs`, `maxCallers`, `maxCallees`, `maxPseudoLines` (pseudocode is **off by default**; opt in explicitly). It returns function resolution (including data-vs-code and nearest-function context), calling convention/parameters/thunk/external flags, a **capped linear instruction walk** for extent (Ghidra 12 `Function` has no `getBody()`, so extent is labelled a lower bound for non-contiguous bodies), direct callers/callees, references to the address with data-origin types where present, optional bounded pseudocode, and explicit `truncation` flags plus per-section counts. The wrapper wraps it in a `sims2-ghidra-query-envelope/1` envelope carrying source image SHA-256, Ghidra version, program path, `readOnly`/`analysisPerformed` flags, headless exit code, query-log warning/error counts and the standing interpretation policy, and it **fails (exit 5) if the script output is not valid JSON** so a malformed query can never be read as evidence. Queries serialize on `work/ghidra/.query.lock`; results stay under ignored `work/ghidra/query-out/`.

**Current state (2026-10-22):** the image imported cleanly at image base `0xA0000000` / `x86:LE:32:default`, and querying RVAs `0x1070`, `0x1250`, `0x1AB665`, `0x1ABD40` independently reproduced `docs/OBJECT_QUERY_CALLER.md` — the early-return guards on `+0x34`/`+0x1C` with the `+0x7C` mode byte and `+0x60` string, `0x1AB665` having exactly two direct callers, and `0x1ABD40` passing `[+0x34]` to five direct accessors including `0x1250`. That is mapping and xref agreement with existing evidence, obtained through a second toolchain; it is **not** new behavioural proof and promotes no function contract.

Start with a small bounded script that, given one exact RVA/VA and a depth/result limit, returns machine-readable JSON containing: discovered function extent, instructions/blocks, direct references/callers, callee targets, import interactions, relevant structure/vtable refs, analysis warnings, and **an explicitly bounded pseudocode excerpt** if needed. Include image SHA-256, tool version, address-space interpretation, and truncation flags. Do not feed full-program decompiler dumps into model context.

Useful first targeted probes (verify mapping before interpretation): the previously analyzed original helpers near RVAs `0x1070` / `0x1250`, object-query callers around `0x1AB665` / `0x1ABD40`, and resource-precedence routines recorded in `docs/RESOURCE_PRECEDENCE.md`. Reuse earlier evidence before interpreting new results. Focus subsequent queries on startup dependencies and Android port blockers.

## Pi integration: optional MCP, mandatory headless fallback

Investigate a **maintained and compatible** Ghidra MCP bridge **after** the headless project works. MCP is optional because deployment ecosystems change and Pi Web UI may not expose the same tools as Pi's autonomous CLI/RPC worker. **No MCP bridge is installed on this machine; the headless JSON interface above is the implemented and tested path, and nothing is blocked on MCP.**

- Confirm the MCP bridge is actually usable **inside the Pi worker/Ralph child sessions**, not only in an interactive UI.
- Prefer read-only query tools for functions, disassembly, callers, xrefs and decompilation. Smoke-test one known pinned RVA against existing evidence; check returned address/base accuracy and output size.
- Keep the Ghidra server/bridge reachable **only inside a private container/host network**. Do not expose it through Cloudflare tunnels, public interfaces or remote MCP services.
- Review source, dependencies and permissions before installing third-party bridges. Do not route private recovered code/disassembly to an unapproved remote model, website or service.
- If MCP is unreliable or unsupported, make an executable local interface over `analyzeHeadless` scripts returning bounded JSON. **Do not block all decompilation work merely because MCP cannot be configured.**

## Correctness and progress discipline

- Treat existing documentation, exact image hash and differential tests as source-of-evidence. Verify any Ghidra finding before promoting it to a recovered-symbol/function contract.
- Tie each recovered function to its **exact RVA, dependencies, call ABI, guest-width pointers, side effects and verification status**. Distinguish static observations from actual x86 execution and real Android integration.
- Version analysis scripts and documented interface schemas **without committing proprietary extracted outputs**. Place private generated results under ignored `work/`, not `docs/` or GitHub Actions artifacts.
- Serialize project mutations: Ghidra project locks and concurrent writers can corrupt/race state. Multiple agents may perform isolated read-only queries but must not simultaneously rewrite the same database.
- Keep the work vertical: enough correct code and guest services to reach real game startup/menu/gameplay matters more than a large count of auto-discovered functions.
- Log Ghidra failure modes and environment blockers. If the import/image is unavailable, continue safe host tests, emulator preparation and code review until a legitimate private transfer is available.
