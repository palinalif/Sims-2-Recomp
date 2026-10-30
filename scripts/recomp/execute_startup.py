#!/usr/bin/env python3
"""Measure unchanged startup bodies; optional decoded call ABI, private output only.

A rejected endpoint or state mismatch is a measured failure, never a match.
No generated instruction, upstream source, oracle or acceptance gate is changed.
"""
import argparse
import json
from pathlib import Path
import struct
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from measure_leaf import ROOT, digest
from reference_startup import cases, oracle, entry_oracle, require, verify_state

TEMPLATE = Path(__file__).with_name('startup_transport.c.in')


def assemble(bodies, call_metadata=None, *, entry=False):
    require(type(entry) is bool and (not entry or call_metadata is not None))
    require(set(bodies) == ({0x8258A9, 0x82585C, 0x8248A3} if entry else {0x8258A9, 0x82585C}))
    require(all(isinstance(b, str) and b for b in bodies.values()))
    template = TEMPLATE.read_text()
    require(template.count('\n@BODIES@\n') == 1)
    from call_returns import seam
    adapter = '' if call_metadata is None else seam(call_metadata)
    result = template.replace('\n@BODIES@\n', '\n' + adapter + '\n'.join(bodies.values()) + '\n')
    require(all(body in result for body in bodies.values()))
    return ('#define ENTRY_BOUNDARY 1\n' if entry else '') + result


def input_bytes():
    return b''.join(struct.pack('<14I', c['stack'], c['sp'], c['cookie'],
        *c['values'], *c['saved'], c['qpc']) for c in cases())


def compare_stream(text, reference, *, entry=False):
    require(type(entry) is bool)
    records = [json.loads(line) for line in text.splitlines()]
    require(len(records) == len(reference) == 320)
    matched, rejected, mismatched = 0, {}, []
    for n, (record, saved, case) in enumerate(zip(records, reference, cases())):
        require(saved['case'] == case and record.get('case') == n)
        # Saved states must still satisfy the independent oracle. A fake/stale
        # reference cannot simply authorize a lying native stream.
        expected = dict(saved['state'])
        for key in ('stack', 'data'):
            expected[key] = bytes.fromhex(expected[key])
        verify_state(expected, (entry_oracle if entry else oracle)(case))
        if set(record) == {'case', 'rejected'}:
            reason = record['rejected']
            require(reason in ('unaligned-memory', 'unmapped-memory', 'endpoint-order',
                'endpoint-frame', 'endpoint-return-address', 'endpoint-output-pointer',
                'endpoint-zeroing', 'endpoint-cleanup', 'unresolved-target', 'call-metadata',
                'tail-boundary'))
            rejected[reason] = rejected.get(reason, 0) + 1
        else:
            require(set(record) == {'case', 'state'} and isinstance(record['state'], dict))
            actual = dict(record['state'])
            require(set(actual) == set(expected))
            for key in ('stack', 'data'):
                require(isinstance(actual[key], str) and len(actual[key]) == 8192)
                actual[key] = bytes.fromhex(actual[key])
            if actual == expected:
                matched += 1
            else:
                mismatched.append(n)
    return dict(cases=320, matched=matched, rejected=rejected,
                mismatched_cases=mismatched, verified=matched == 320)


def run(output, call_returns=False, *, entry=False):
    require(type(entry) is bool and (not entry or call_returns))
    output = output.resolve()
    require(output.is_relative_to((ROOT/'work/recomp-bench').resolve()))
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    row = dict(schema='ts2-startup-native/1', success=False, android_executed=False,
        startup_executed=False, entry_boundary=entry, tail_target_executed=False,
        fresh_unique_candidates=0, runs={}, commands=[],
        timings={}, invocation=[sys.executable, *sys.argv],
        harness_sha256=digest(Path(__file__)), template_sha256=digest(TEMPLATE),
        limits=['upstream dummy CALL return addresses retained; strict endpoint/stack oracle',
                'authored deterministic APIs, not Windows/time/entropy/security',
                'EAX/nonvolatile GPRs/return ESP/full stack/data/order/frames only',
                'no final flags/ECX/EDX/FP/SIMD/SEH/transient writes/concurrency',
                'checked MEM32 lvalue spans, not access-mode isolation or a sandbox',
                'diagnostic seam, NOT GuestMemory/GuestDispatch runtime integration'])
    stage = 'reference'

    def command(name, argv, expected=0, stdin=None):
        start = time.monotonic()
        rec = dict(name=name, argv=[str(x) for x in argv], exit_code=None)
        row['commands'].append(rec)
        try:
            with (output/(name+'.stdout')).open('xb') as out, (output/(name+'.stderr')).open('xb') as err:
                p = subprocess.run(rec['argv'], input=stdin, stdout=out, stderr=err,
                                   cwd=ROOT, timeout=120)
            rec['exit_code'] = p.returncode
            require(p.returncode == expected)
        finally:
            rec['seconds'] = time.monotonic()-start

    try:
        command('reference', [sys.executable, ROOT/'scripts/recomp/reference_startup.py',
                             '--output', output/'reference', *(['--entry-boundary'] if entry else [])])
        result = json.loads((output/'reference/result.json').read_text())
        require(result['success'] and result['cases'] == 320 and result['rejected_controls'] == 4)
        reference_path = output/'reference/reference.json'
        reference = json.loads(reference_path.read_text())
        row['reference_sha256'] = digest(reference_path)
        row['fresh_x86_reference_cases'] = 320
        bodies = {}
        row['lifts'] = {}
        for rva in ((0x8258A9, 0x82585C, 0x8248A3) if entry else (0x8258A9, 0x82585C)):
            stage = 'lift-' + format(rva, 'X')
            directory = output/format(rva, 'X')
            command(stage, [sys.executable, ROOT/'scripts/recomp/measure_startup.py',
                    '--rva', format(rva, 'X'), '--output', directory], expected=2)
            metric = json.loads((directory/'metrics.jsonl').read_text())
            require(metric['lifted'] and metric['compiled_for_aarch64'])
            require(digest(directory/'lifted.c') == metric['lifted_sha256'])
            bodies[rva] = (directory/'lifted.c').read_text()
            row['lifts'][hex(rva)] = metric
        stage = 'assembly'
        metadata = None
        if call_returns:
            from call_returns import derive
            start = time.monotonic()
            metadata = derive(entry=entry)
            row['timings']['call_metadata'] = time.monotonic()-start
            row['call_metadata'] = metadata
            row['limits'][0] = 'decoded unique caller/target return-VA seam; strict endpoint/stack oracle'
        row['call_return_adapter'] = call_returns
        if entry:
            row['limits'].append('non-returning observation stop BEFORE external tail; no tail body execution')
        (output/'probe.c').write_text(assemble(bodies, metadata, entry=entry))
        row['source_sha256'] = digest(output/'probe.c')
        upstream = ROOT/'work/interop-legacy-002/pcrecomp/runtime/recomp32'
        for isa in ('host', 'arm64'):
            stage = isa+'-compile'
            run = row['runs'][isa] = dict(compiled=False, executed=False, verified=False)
            exe = output/isa
            opts = [] if isa == 'host' else ['-target', 'aarch64-linux-musl', '-static']
            command(stage, ['zig-cc', *opts, '-D_POSIX_C_SOURCE=200809L', '-std=c11',
                '-O0', '-Werror=implicit-function-declaration', '-I'+str(upstream),
                output/'probe.c', '-lm', '-o', exe])
            header = exe.read_bytes()[:20]
            require(header[:6] == b'\x7fELF\x02\x01' and
                    int.from_bytes(header[18:20], 'little') == (62 if isa == 'host' else 183))
            run['compiled'] = True
            stage = isa+'-execute'
            command(stage, [exe] if isa == 'host' else [ROOT/'scripts/campaign/arm64-run.sh', exe],
                    stdin=input_bytes())
            run['executed'] = True
            stage = isa+'-compare'
            start = time.monotonic()
            run.update(compare_stream((output/(isa+'-execute.stdout')).read_text(), reference, entry=entry))
            row['timings'][stage] = time.monotonic()-start
            run['stdout_sha256'] = digest(output/(isa+'-execute.stdout'))
        row['cross_isa_stdout_equal'] = row['runs']['host']['stdout_sha256'] == row['runs']['arm64']['stdout_sha256']
        row['success'] = all(r['verified'] for r in row['runs'].values()) and row['cross_isa_stdout_equal']
        if not row['success']:
            row['blocked_stage'] = 'native-ABI-or-state-comparison'
    except Exception as exc:
        row.update(failed_stage=stage, error_type=type(exc).__name__)
        raise
    finally:
        (output/'result.json').write_text(json.dumps(row, indent=2)+'\n')
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--call-returns', action='store_true',
                        help='Use decoded unique caller/target return-VA diagnostic seam')
    parser.add_argument('--entry-boundary', action='store_true',
                        help='Require --call-returns; include entry and stop BEFORE external tail')
    args = parser.parse_args()
    if args.entry_boundary and not args.call_returns:
        parser.error('--entry-boundary requires --call-returns')
    try:
        row = run(args.output, args.call_returns, entry=args.entry_boundary)
    except Exception:
        parser.exit(1, 'Startup native measurement failed; inspect private logs/result.\n')
    print('Startup %s: host matched %d/320; QEMU matched %d/320; verified=%s; not Android' %
          ('entry boundary' if args.entry_boundary else 'pair',
           row['runs']['host']['matched'], row['runs']['arm64']['matched'], row['success']))
    return 0 if row['success'] else 2


if __name__ == '__main__':
    sys.exit(main())
