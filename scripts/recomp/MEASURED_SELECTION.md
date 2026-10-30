# Run 5: all 25 selected candidates — bounded evidence, not game startup

Checkpoint: `c456a2b` (run5-055); synthesis: run5-056. This is the single
sanitized selection/cost/stage table. Original bytes, lifted bodies, disassembly,
register/memory states and raw results remain private. No new candidate was
selected or executed for this synthesis. The immediately preceding tested
artifact is `measure_setter.py` + `tests/test_recomp_setter.py` in `c456a2b`;
reproduce with the commands in [README.md](README.md#fresh-selected-callback-setter-measurement-run5-055).

## Scope and selection

The deterministic manifest is **base 21 plus four existing supplements**, NOT
25 entries returned by `select_candidates.select_candidates()` alone:

```sh
. scripts/campaign/worker-env.sh
python3 - <<'PY'
import json, sys
sys.path.insert(0, 'scripts/recomp')
from select_candidates import select_candidates, verify_image
from measure_module_acquisition import selection
from pathlib import Path
verify_image(Path('work/interop-legacy-002/analysis-image.bin'))
a, b = select_candidates(), selection()
assert a['counts']['selected'] == 21 and b['counts']['selected'] == 25
assert len({x['rva'] for x in b['selected']}) == 25
assert len(b['rejected']) == 2
print(json.dumps(b, indent=2))  # metadata only; no recovered code or states
PY
```

Supplement chain: `measure_resource_return.selection` adds `82A528`, then
`measure_storage_selector.selection` adds `8480BF`, `measure_encoded_resolver.selection`
adds `847E6C`, and `measure_module_acquisition.selection` adds `847DA1`.
The owner cap remains 25; no failed candidate is replaced. Historical assertions
that the base manifest itself had 25 entries were wrong; the full union has 25.

Category keys (overlapping **selection stress HYPOTHESES**, not recovered roles):
L=simple leaf/no calls; B=branching arithmetic; S=stack; M=pointer memory;
D=direct call; I=indirect call/vtable; R=startup/resource path.
All addresses below are RVAs, hexadecimal. Selection rank is fixed, not a result
ranking. `?` means incomplete/unknown, never zero or absent. Dependency inventories
are local static operands/calls, not a recursively closed service graph.

| # | RVA | Categories | Deterministic selection rule | Dependencies / boundary qualification |
| ---: | --- | --- | --- | --- |
|1|9B52C0|R,D|Resource attachment funnel|Direct 1D4740/824632; 4 indirect sites; indexed + independent normal flow|
|2|1E36F0|R,I|Sole funnel caller, indirect entry|Partial only: 12 distinct direct targets, 10 indirect sites; escaping flow, no complete extent|
|3|1E95C0|R,D|Candidate rebuild, nine callers|6 distinct direct targets/7 sites; 1 indirect; 3 FS operands; indexed normal flow|
|4|1ABD40|M,D|Five-query cache refresh caller|1240/1290/12D0/1250/1270; indexed normal flow|
|5|1D3E20|R,M|Resource constructor seed|824632/1D8B90/14323F; 6 indirect; 3 FS operands; indexed normal flow|
|6|1DA310|R,M|Second resource constructor seed|1D9CB0/824624; indexed normal flow|
|7|8248A3|R,D|Original entry metadata, not wrapped PE entry|8258A9; tail 824727 NOT executed; 10-byte boundary only|
|8|8258A9|R|First entry-connected dependency|82585C; 2 absolute globals; independent normal flow|
|9|82585C|R,I,S|Measured dependency of 8258A9|4 IAT calls: time/thread/process/counter; independent normal flow|
|10|824727|R,D,S|Original-entry tail, not implemented|INT without nonreturn policy; full extent/dependency inventory unknown|
|11|1460|I,S,M|Callback producer/failure cleanup|102D0/831A6F; 4 indirect; 1 ES operand; indexed normal flow|
|12|1AB7E0|D,I|Cache consumer of jump-table helper|1240/1AB8A9; no indirect site in THIS caller; indexed normal flow|
|13|1070|L,M|Historical pointer-store helper|Object/stack only; exact 19-byte pin, 6 indexed instructions, advisory index|
|14|1240|L,M|Reuse pinned group reference|Object/stack only; pinned 11-byte range; 3 indexed instructions|
|15|1250|B,M|Reuse branching group reference|Object/stack only; pinned 27-byte range, independent CFG|
|16|1270|B,M|Reuse guarded group reference|Object/stack only; pinned 30-byte range, independent CFG|
|17|1AB770|S,M,D|Historical cache wrapper/reference|1270; exact 28-byte pin/independent CFG, address-only capped index NOT extent|
|18|1AB78C|S,M,D|Paired cache wrapper/reference|1250; exact 28-byte pin/independent CFG, address-only capped index NOT extent|
|19|825BB0|R,S,M|First tail helper, composed FS reference|FS chain/cookie; 69-byte bounded helper, not full caller or SEH|
|20|82A6D3|R,D,S|First resource-failure callee|82A47B/82A70A/82A4C3; indexed normal flow|
|21|82A47B|R,B,S,M|First direct dependency of 82A6D3|3 absolute globals; indexed normal flow|
|22|82A528|R,D,S|First dependency of null-pointee branch|8460CF; Get/SetLastError IAT; indexed normal flow|
|23|8480BF|R,I,S,D|First dependency of 8460CF; existing selector reference|847E6C; 2 indirect sites; 2 absolute operands; indexed normal flow|
|24|847E6C|R,D,I,S|Actual selected selector's resolver, whole body|847DA1/82F3EC; GetProcAddress IAT/cookie; indexed normal flow|
|25|847DA1|R,D,I,S,M|Actual resolver's cold module dependency|845B53 comparison; 4 IAT sites (load/error/free); indexed normal flow|

Rejected, not counted among 25: `1AB79C` is a call instruction inside a wrapper;
`C261A1` is a table-immediate site/address-only index result, not a function entry.
Standing Ghidra ERROR1 remains in query evidence. Boundary agreement is not
operand/ABI correctness; normal-flow analysis assumes returning calls and excludes
exception/nonreturn paths. No general claim that Ghidra boundaries are reliable.
Pinned historical rigs, not generic index coverage, own the leaf/wrapper extents.

## Distinct stages and costs

**Selected 25; rejected 2; attempted 25; lifted 23; AArch64 compiled 23;
bounded x86-reference matched 14; successful QEMU execution 14.** Of 23 compiled,
9 are object-only: never linked, behaviorally compared or executed. The other 14
have DIFFERENT comparison scopes, not 14 full-machine proofs. No Android result.

A/T = analysis/translation wall seconds. `A+` includes index crosscheck; otherwise
index/preflight is separate. H/A = host/ARM object-only compile seconds.
V denotes a bounded matched/executed fixture, O object-only, F analysis rejection.
For V, C points to shared **fixture** costs below; do not divide them by body count.
Costs are observed warm `-O0` runs, not repeat-sample statistics, cold tool startup,
Android build time, production optimizer cost or linked-game runtime performance.

| # / RVA | Bytes | A seconds | T seconds | H/A object seconds OR fixture | Lift / ARM / x86 / QEMU | Record source under work/recomp-bench/ |
| --- | ---: | ---: | ---: | --- | --- | --- |
|1 9B52C0|190|.003171|.000321|.518490/.167190|yes/yes/no/no O|run5-047-attachment/metrics.jsonl|
|2 1E36F0|?|.005443|—|—|no/no/no/no F|run5-024-resource-recheck/metrics.jsonl|
|3 1E95C0|323|.021008|.000418|.468114/.167075|yes/yes/no/no O|run5-048-rebuild/metrics.jsonl|
|4 1ABD40|88|.002924|.000135|.518158/.167579|yes/yes/no/no O|run5-046-cache-refresh/metrics.jsonl|
|5 1D3E20|185|.003622|.000289|.518606/.217806|yes/yes/no/no O|run5-049-factory/metrics.jsonl|
|6 1DA310|35|.001647|.000120|.517533/.167671|yes/yes/no/no O|run5-050-sibling/metrics.jsonl|
|7 8248A3|10|.002720|.000046|C1|yes/yes/limited/yes V|run5-011-entry-reviewed/metrics.jsonl + run5-012-entry/result.json|
|8 8258A9|75|.003106|.000179|C2|yes/yes/limited/yes V|run5-004-startup/metrics.jsonl + run5-009-native/result.json|
|9 82585C|77|.002615|.000169|C2|yes/yes/limited/yes V|run5-005-helper/metrics.jsonl + run5-009-native/result.json|
|10 824727|?|.005276|—|—|no/no/no/no F|run5-018-tail-timed/metrics.jsonl|
|11 1460|279|.004116|.000421|.567808/.216943|yes/yes/no/no O|run5-051-callback/metrics.jsonl|
|12 1AB7E0|39|.001920|.000125|.518905/.167818|yes/yes/no/no O|run5-052-mapping/metrics.jsonl|
|13 1070|19|.000305|.000057|C3|yes/yes/limited/yes V|run5-055-setter-verified/metrics.jsonl|
|14 1240|11|.002004|.000589|C4|yes/yes/limited/yes V|run5-054-group-final/metrics.jsonl|
|15 1250|27|.000704|.000429|C4|yes/yes/limited/yes V|run5-054-group-final/metrics.jsonl|
|16 1270|30|.000601|.000363|C4|yes/yes/limited/yes V|run5-054-group-final/metrics.jsonl|
|17 1AB770|28|.000439|.000302|C5|yes/yes/limited/yes V|run5-053-wrappers-final/metrics.jsonl|
|18 1AB78C|28|.000444|.000306|C5|yes/yes/limited/yes V|run5-053-wrappers-final/metrics.jsonl|
|19 825BB0|69|.003191|.000123|C6|yes/yes/limited/yes V|run5-022-frame/metrics.jsonl + run5-022-pinned/result.json|
|20 82A6D3|55|.002150|.000164|.569590/.218055|yes/yes/no/no O|run5-025-handler/metrics.jsonl|
|21 82A47B|72|.002685|.000216|C7|yes/yes/limited/yes V|run5-028-final-default/metrics.jsonl (nested lift)|
|22 82A528|70|.005322+|.000220|.771213/.268752|yes/yes/no/no O|run5-031-lift/metrics.jsonl|
|23 8480BF|63|.002353+|.000302|C8|yes/yes/limited/yes V|run5-034-selector-final/metrics.jsonl (nested lift)|
|24 847E6C|133|.003792+|.000312|C9|yes/yes/limited/yes V|run5-036-resolver-final/metrics.jsonl (nested lift)|
|25 847DA1|203|.005555+|.000436|C10|yes/yes/limited/yes V|run5-039-module-final/metrics.jsonl (nested lift)|

The selected T/A source and later correctness source are deliberately distinguished
for 7–9/19; do not attach later fixture times to the earlier measured run as if
one invocation produced both. `metrics.jsonl`/`result.json` retain exact interpreter,
compiler argv, pcrecomp invocation/revision and provenance. Translator revision:
`c0cbd3e3653010782b17e8a87b58953608ea411c`; unchanged pinned private lifter.

### Matched fixtures: costs and actual observations

Compile/link shown together when harness did not time them separately. Execute is
native process/QEMU wall time, not comparator Python time. Reference = reference
execution wall time except where explicitly marked saved; shared work is not additive.

| Fixture | Host compile / link / run seconds | ARM compile / link / QEMU seconds | Reference seconds; matches per ISA | Compared / NOT compared |
| --- | --- | --- | --- | --- |
|C1 entry boundary|.568650 combined / .115256|.317468 combined / 1.116599|10.382932 subprocess; 320|EAX/nonvolatiles/ESP/full stack/data/events/frames; NO final flags/ECX/EDX/FP/PC; stop BEFORE tail|
|C2 startup pair|.568421 combined / .115258|.317528 combined / 1.116185|6.577561 subprocess; 320|Same partial CPU scope as C1; authored API responses; no Windows/time/entropy service|
|C3 setter|.568352/.367845/.065266|.317361/.267742/.465573|1.484930 incl oracle; 64 NEW|8 GPR/full flags at initial202/full256KiB final deltas/empty FP transport; NO native PC/transient journal|
|C4 group|.669911/.468947/.115832|.419050/.318194/.716166|saved; 16/32/48 standalone|8 GPR/defined flags/stack/full tracked final deltas/FP transport; NO native PC/transient writes/FP arithmetic|
|C5 wrappers|.668559/.520351/.065589|.367882/.317808/.516251|saved; 32 per wrapper|8 GPR/defined flags/stack/full tracked final deltas/FP transport; leaves through wrappers, NO native PC/transient writes|
|C6 frame helper|.820931 combined / .054207|.419801 combined / .534488|3.626127; 64|8 GPR/full stack/FS/cookie pages; NO native flags/PC/RET/FP/SEH or caller execution|
|C7 resource leaf|.771095 combined / .073176|.420186 combined / .808844|see private command timing; 64|8 GPR/four full data pages; NO native flags/PC/FP/transient writes, real global ownership|
|C8 selector|.668914 combined / .075539|.522122 combined / 1.307518|see private lift/reference; 256|8 caller GPR/full4096 stack/ordered endpoint args/return RVA/SP/ECX; NO native flags/PC/FP/full endpoint CPU|
|C9 hot resolver|.527310 combined / .219257|.317172 combined / 2.763593|22.072003; 1332|8 GPR/full stack/immutable cookie+cache pages; NO native flags/PC/FP/cold paths in THIS fixture|
|C10 module|.568252 combined / .024654|.317926 combined / .600102|39.900596; 1944|EAX/ESP/nonvolatiles/events/module words/immutable pages/stack outside36B scratch; NO ECX/EDX/flags/scratch/PC/FP|

C4 also checks existing library builds 1.068734/1.120219s, C5 1.219200/1.218901s;
these are not per-body compiler costs. C3 preflight .084264s/fixture .012244s;
C4 preflight 1.706821s/lift+fixture .021987s; C5 1.804327s/.019471s.
Group leaves are counted ONCE despite wrapper/standalone repeats. C1 reuses C2
bodies without counting them again. Historical Android passes remain historical,
not a result of these Linux/QEMU runs. Later cold/composed/reentry experiments
(run5-037/040/041/043/044/045) add narrower scenario evidence but no new unique
selected bodies; see task report for their ordered-event/cache/publication limits.
They are not silently collapsed into full-machine coverage in this table.

## Failures, bottlenecks and interpretation

- `1E36F0`: `escaping-normal-flow`, rejected at `1E394F` after adjacent call to
  `82A797`; partial traversal 180 instructions/8 pending addresses. This is an
  analysis/return-policy failure, **not a proven unsupported pcrecomp instruction**.
  No fabricated complete size or successful lift. Nonreturn/exception policy open.
- `824727`: `interrupt-without-nonreturn-policy`; rejection before translation.
  Helper `825BB0` success does NOT repair or count as the full tail.
- Nine O rows compile only, all explicitly blocked on reference/runtime
  dependencies. They need ABI/callback/service/ownership evidence, not another
  compilation pass. `82A6D3`/`82A528` have partial/reference-only investigations,
  not a whole native behavioral comparison. FS/ES operands are not SEH support.
- Reproduced hooked-Unicorn SIGBUS, setter's first missing POSIX macro failure,
  cold-transport/reference-audit failures and source-pin rejections remain in
  historical task reports/private paths. Final success never erases these attempts.
- Measured body translation is sub-millisecond for these successful cases;
  compiler startup, fixtures, references and verification dominate these warm
  experiments. This is NOT evidence of cheap whole-game compilation/integration.
  HYPOTHESIS: the 9 object-only + 2 analysis-rejected cases dominate remaining
  feasibility uncertainty. Runtime services and indirect targets remain unclosed.

Overlapping category counts below derive from the full manifest, not a random
sample; numerators mean bounded matches with the limits above:

| Category | Selected | Lifted/ARM compiled | Bounded matched/QEMU |
| --- | ---: | ---: | ---: |
|L|2|2|2|
|B|3|3|3|
|S|12|11|8|
|M|13|13|9|
|D|13|12|6|
|I|7|6|4|
|R|16|14|8|

Categories overlap; do not sum them. This purposive 25-function shortlist cannot
support a statistical pass rate or time estimate for 44,151 indexed functions.
Small sizes, authored endpoints, known references and synthetic memory bias the
results; shared fixtures and differing comparisons invalidate a common seconds-per-
function figure. No extrapolated whole-executable cost is offered.

## Reproduce using EXISTING harnesses (owner-only inputs required)

All output directories must be exclusive **NEW** ignored paths; do not overwrite
record sources above. Long jobs use detached `setsid timeout`/private logs as in
AGENTS.md. Bootstrap uses bash. No recovery/import/PE launch is needed. Query an
existing persistent index for the exact RVA before a fresh measurement:

```sh
scripts/ghidra-query.sh --rva "$RVA" --instructions 400 --out "$NEW_INDEX"
# NEW_INDEX is raw JSON; required provenance is "$NEW_INDEX.env.json".
python3 scripts/recomp/measure_startup.py --rva "$RVA" \
  --index "$NEW_INDEX.env.json" --output "$NEW_OUTPUT"
```

This is the existing object/failure harness for rows 1–12/19–21, NOT an assurance
that every selected case passes its gates. Intended object-only exit is 2;
analysis rejection is nonzero. Do not relax own-index, bound, trap or nonreturn
gates. Entry/tail early records predate the stricter current index requirement;
exact historical invocations remain in the named records, not rewritten as current.

Existing behavioral harness commands (each `NEW_OUTPUT` must differ):

```sh
python3 scripts/recomp/execute_startup.py --call-returns --entry-boundary --output "$NEW_OUTPUT" # C1
python3 scripts/recomp/execute_startup.py --call-returns --output "$NEW_OUTPUT" # C2
python3 scripts/recomp/measure_setter.py --index-1070 "$INDEX_1070" --output "$NEW_OUTPUT" # C3
python3 scripts/recomp/measure_group.py --index-1240 "$INDEX_1240" --output "$NEW_OUTPUT" # C4
python3 scripts/recomp/measure_wrappers.py --index-1270 "$INDEX_1270" \
  --index-1ab770 "$INDEX_1AB770" --index-1ab78c "$INDEX_1AB78C" --output "$NEW_OUTPUT" # C5
python3 scripts/recomp/execute_frame.py --index "$INDEX_825BB0" --output "$NEW_OUTPUT" # C6
python3 scripts/recomp/execute_resource_leaf.py --index "$INDEX_82A47B" --output "$NEW_OUTPUT" # C7
python3 scripts/recomp/execute_storage_selector.py --index "$INDEX_8480BF" --output "$NEW_OUTPUT" # C8
python3 scripts/recomp/execute_encoded_resolver.py --index "$INDEX_847E6C" --output "$NEW_OUTPUT" # C9
python3 scripts/recomp/execute_module_acquisition.py --index "$INDEX_847DA1" --output "$NEW_OUTPUT" # C10
python3 scripts/recomp/measure_resource_return.py --index "$INDEX_82A528" --output "$NEW_OUTPUT" # row22 object
```

`INDEX_*` means the private `.env.json` envelope, not raw query output. Commands
reuse existing pinned image/private rig/pristine lifter and strict comparisons.
C4/C5 compare saved states, C3 generates NEW cases, not missing historical inputs.
No self-authored replacement game functions count as translations.

### Read-only table audit

This checks committed table values against the named private records and checks
both native results for each of the 14 bounded-matched candidates. It writes no
fixture or replacement metric. Missing private inputs are an error, not a pass.

```python
# Read-only table audit (run from repository root after worker-env.sh)
import json, sys
from pathlib import Path
sys.path.insert(0, 'scripts/recomp')
from measure_module_acquisition import selection
from measure_setter import complete
from measure_group import require_complete as complete_group
from measure_wrappers import require_complete as complete_wrappers
manifest = selection()
root = Path('work/recomp-bench')
text = Path('scripts/recomp/MEASURED_SELECTION.md').read_text()
rows = [line.split('|')[1:-1] for line in text.splitlines()
        if line.startswith('|') and ' O|' in line or
        line.startswith('|') and ' F|' in line or
        line.startswith('|') and ' V|' in line]
assert len(rows) == len(manifest['selected']) == 25
verified = {
    7: 'run5-012-entry', 8: 'run5-009-native', 9: 'run5-009-native',
    13: 'run5-055-setter-verified',
    14: 'run5-054-group-final', 15: 'run5-054-group-final', 16: 'run5-054-group-final',
    17: 'run5-053-wrappers-final', 18: 'run5-053-wrappers-final',
    19: 'run5-022-pinned', 21: 'run5-028-final-default',
    23: 'run5-034-selector-final', 24: 'run5-036-resolver-final',
    25: 'run5-039-module-final',
}
counts = dict(attempted=0, lifted=0, arm=0, matched=0, qemu=0)
for number, (cells, selected) in enumerate(zip(rows, manifest['selected']), 1):
    entry, size, analysis, translation, cost, stages, source = map(str.strip, cells)
    assert entry.split() == [str(number), selected['rva'][2:]]
    source = source.split(' + ')[0].split(' (')[0]
    records = [json.loads(line) for line in (root/source).read_text().splitlines()]
    outer = next(r for r in records if int(r['rva'], 16) == int(selected['rva'], 16))
    r = outer.get('lift', outer)
    assert r['attempted']
    counts['attempted'] += 1
    counts['lifted'] += r['lifted']
    assert size == str(r.get('size_bytes', r.get('size', '?')))
    t = r['timings']
    a = t.get('analysis', t.get('analysis_and_index'))
    assert abs(float(analysis.rstrip('+')) - a) <= .00000051
    if r['lifted']:
        assert abs(float(translation) - t['translation']) <= .00000051
    else:
        assert translation == '—' and stages.endswith(' F')
    if number in verified:
        d = root/verified[number]
        p = d/('result.json' if (d/'result.json').exists() else 'metrics.jsonl')
        v = json.loads(p.read_text())
        assert v['success'] and not v['android_executed']
        if number == 13:
            complete(v)  # setter/group/wrapper schemas have no runs.*.cases
        elif number in (14, 15, 16):
            complete_group(v)
        elif number in (17, 18):
            complete_wrappers(v)
        else:
            for isa in ('host', 'arm64'):
                run = v['runs'][isa]
                assert run['cases'] > 0 and run['matched'] == run['cases']
                assert run.get('compiled', True) and run.get('executed', True)
        assert stages.endswith(' V')
        counts['arm'] += 1
        counts['matched'] += 1
        counts['qemu'] += 1
    else:
        counts['arm'] += r['compiled_for_aarch64']
        assert not r['matched_x86_reference'] and not r['executed_under_qemu']
assert counts == dict(attempted=25, lifted=23, arm=23, matched=14, qemu=14)
print('PASS: table selection, sizes, A/T timings and bounded-stage counts', counts)
```

Next decision (resolved by tested artifact `86600cb`, run5-057): **STOP this
1ABD40 composition pending explicit scoped owner approval** for native bodies and
bounded reference work at `1290` and `12D0`. The immediate selection union would
be27, not25 or26; retain every original candidate and failure. The existing pinned
catalogs lack both bodies. Reference-only dependencies cannot supply native
implementations. Reproduce the measured gate with `inspect_cache_contract.py`
using the existing run5-046 index as documented in [README.md](README.md).
Even after approval, require a new independent composed caller reference/oracle
before claiming native correctness; standalone catalogs do not prove its ABI.
Never substitute zero/no-op endpoints or label partial-cache coverage a whole-
function pass. No new selection or production callback binding is authorized.
Already-selected work is not globally forbidden, but another object compilation
or equivalent scope preflight would add no new behavioral evidence.

Phase 1 remains incomplete: real reconstructed APK/menu/assets/renderer/input/
neighborhood/lot/120-second gameplay and independently trusted acceptance are
absent. Android SDK/NDK/compatible target/external validator provisioning remains
operator-owned: [provisioning brief](../../docs/PHASE1_PROVISIONING_BRIEF.md).
