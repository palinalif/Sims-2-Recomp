#!/usr/bin/env python3
"""Sequential isolated measurement of the existing three allowlisted candidates.

Private outputs only. This is orchestration, not a new lifter or runtime service.
Exit 0 requires every selected pipeline to be verified; object-only exits 2.
"""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
JOBS = {
    0x1250: ('measure_leaf.py', []),
    0x8258A9: ('measure_startup.py', ['--rva', '8258A9']),
    0x82585C: ('measure_startup.py', ['--rva', '82585C']),
}
STAGES = ('attempted', 'lifted', 'compiled_for_aarch64',
          'matched_x86_reference', 'executed_under_qemu')


def normalize(row, rva, exit_code):
    """Validate child evidence before counting it; never infer execution from compile."""
    if row.get('rva') != hex(rva) or row.get('android_executed') is not False:
        raise ValueError('Wrong candidate or Android claim')
    if rva == 0x1250:
        if row.get('schema') != 'ts2-fresh-leaf/1':
            raise ValueError('Wrong leaf schema')
        runs = row.get('runs', {})
        success = row.get('success')
        if type(success) is not bool:
            raise ValueError('Invalid success')
        compiled = runs.get('arm64', {}).get('compiled', False)
        executed = runs.get('arm64', {}).get('executed', False)
        verified = success and exit_code == 0
        if success:
            if exit_code != 0 or set(runs) != {'host', 'arm64'}:
                raise ValueError('Invalid successful leaf')
            for run in runs.values():
                if (run.get('compiled') is not True or run.get('executed') is not True
                        or type(run.get('matched')) is not int or run['matched'] != 32):
                    raise ValueError('Incomplete leaf verification')
            hashes = [runs[i].get('stdout_sha256') for i in ('host', 'arm64')]
            if (not isinstance(hashes[0], str) or len(hashes[0]) != 64 or
                    any(c not in '0123456789abcdef' for c in hashes[0]) or hashes[0] != hashes[1]):
                raise ValueError('Missing cross-ISA comparison')
        elif exit_code == 0:
            raise ValueError('False successful exit')
        result = dict(attempted=row.get('attempted'), lifted=row.get('lifted'),
                      compiled_for_aarch64=compiled, matched_x86_reference=verified,
                      executed_under_qemu=executed)
        status = 'verified' if verified else 'failed'
    else:
        if row.get('schema') != 'ts2-startup-attempt/1':
            raise ValueError('Wrong startup schema')
        result = {key: row.get(key) for key in STAGES}
        if any(row.get(key) is not False for key in
               ('linked', 'matched_x86_reference', 'executed_under_qemu')):
            raise ValueError('Object-only child claimed execution')
        if exit_code == 2:
            if (not all(result[key] is True for key in STAGES[:3]) or
                    row.get('blocked_stage') != 'reference-and-runtime-dependencies' or
                    any(row.get('runs', {}).get(isa, {}).get('object_compiled') is not True
                        for isa in ('host', 'arm64'))):
                raise ValueError('Incomplete object evidence')
            status = 'incomplete'
        elif exit_code == 0:
            raise ValueError('Object-only pipeline cannot succeed')
        else:
            status = 'failed'
    if any(type(value) is not bool for value in result.values()):
        raise ValueError('Nonboolean stage')
    if (result['lifted'] and not result['attempted'] or
            result['compiled_for_aarch64'] and not result['lifted'] or
            result['matched_x86_reference'] and not result['compiled_for_aarch64'] or
            result['executed_under_qemu'] and not result['compiled_for_aarch64']):
        raise ValueError('Contradictory stage')
    return status, result


def batch(output, rvas, seconds=300):
    if (not rvas or len(set(rvas)) != len(rvas) or any(rva not in JOBS for rva in rvas)
            or type(seconds) is not int or not 1 <= seconds <= 600):
        raise ValueError('Invalid bounded selection')
    output = output.resolve()
    if not output.is_relative_to((ROOT / 'work/recomp-bench').resolve()):
        raise ValueError('Private output required')
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    summary = dict(schema='ts2-recomp-batch/1', selected=[hex(rva) for rva in rvas],
                   success=False, counts={key: 0 for key in STAGES}, records=[],
                   limits=['fresh process and output per candidate, sequential; shared filesystem/compiler cache',
                           'trusted measurement children, not a sandbox; no retries',
                           'saved x86 states for leaf; startup objects are unverified; not Android'])
    started = time.monotonic()
    try:
        with (output / 'metrics.jsonl').open('x') as stream:
            for index, rva in enumerate(rvas):
                script, opts = JOBS[rva]
                child_output = output / ('%02d-%x' % (index, rva))
                argv = [sys.executable, str(ROOT / 'scripts/recomp' / script), *opts,
                        '--output', str(child_output)]
                record = dict(rva=hex(rva), argv=argv, status='failed', exit_code=None,
                              timed_out=False, stages={key: False for key in STAGES})
                start = time.monotonic()
                try:
                    with (output / ('%02d.stdout' % index)).open('xb') as out, \
                         (output / ('%02d.stderr' % index)).open('xb') as err:
                        process = subprocess.Popen(argv, cwd=ROOT, stdout=out, stderr=err,
                                                   start_new_session=True)
                        record['pid'] = process.pid
                        try:
                            record['exit_code'] = process.wait(timeout=seconds)
                        except subprocess.TimeoutExpired:
                            record['timed_out'] = True
                        finally:
                            # Also clean up a compiler left behind by a crashed child.
                            try:
                                os.killpg(process.pid, signal.SIGKILL)
                            except ProcessLookupError:
                                pass
                            process.wait()
                    if record['timed_out']:
                        raise ValueError('Child timeout; partial evidence not counted')
                    metrics = child_output / 'metrics.jsonl'
                    if metrics.is_symlink() or metrics.stat().st_size > 1024 * 1024:
                        raise ValueError('Invalid child metrics')
                    lines = metrics.read_text().splitlines()
                    if len(lines) != 1:
                        raise ValueError('Exactly one child record required')
                    row = json.loads(lines[0])
                    record['status'], record['stages'] = normalize(row, rva, record['exit_code'])
                    record['child_metrics'] = str(metrics.relative_to(output))
                except Exception as exc:
                    record['error_type'] = type(exc).__name__
                record['seconds'] = time.monotonic() - start
                for key in STAGES:
                    summary['counts'][key] += int(record['stages'][key])
                summary['records'].append(record)
                stream.write(json.dumps(record) + '\n')
                stream.flush()
        summary['success'] = all(r['status'] == 'verified' for r in summary['records'])
    finally:
        summary['seconds'] = time.monotonic() - started
        (output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--rva', type=lambda s: int(s, 16), choices=JOBS, action='append', required=True)
    parser.add_argument('--seconds', type=int, default=300)
    args = parser.parse_args()
    try:
        result = batch(args.output, args.rva, args.seconds)
    except Exception:
        parser.exit(1, 'Batch preflight failed; private new output and bounded allowlist required.\n')
    print('Candidates %d; verified %d; incomplete %d; failed %d; not Android' %
          (len(result['records']), *(sum(r['status'] == s for r in result['records'])
                                   for s in ('verified', 'incomplete', 'failed'))))
    return 0 if result['success'] else (1 if any(r['status'] == 'failed' for r in result['records']) else 2)


if __name__ == '__main__':
    sys.exit(main())
