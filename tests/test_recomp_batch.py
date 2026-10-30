"""Authored child-process controls, no game bytes or replacement external tools."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[1] / 'scripts/recomp/batch.py'
spec = importlib.util.spec_from_file_location('recomp_batch', PATH)
bench = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bench)


def startup(rva=0x82585C):
    return dict(schema='ts2-startup-attempt/1', rva=hex(rva), android_executed=False,
                attempted=True, lifted=True, compiled_for_aarch64=True, linked=False,
                matched_x86_reference=False, executed_under_qemu=False,
                blocked_stage='reference-and-runtime-dependencies',
                runs={isa: dict(object_compiled=True) for isa in ('host', 'arm64')})


class BatchTests(unittest.TestCase):
    def test_stage_claims_fail_closed(self):
        row = startup()
        status, stages = bench.normalize(row, 0x82585C, 2)
        self.assertEqual(status, 'incomplete')
        self.assertFalse(stages['executed_under_qemu'])
        for key in ('linked', 'matched_x86_reference', 'executed_under_qemu', 'android_executed'):
            corrupt = copy.deepcopy(row)
            corrupt[key] = True
            with self.subTest(key=key), self.assertRaises(ValueError):
                bench.normalize(corrupt, 0x82585C, 2)
        for key in bench.STAGES[:3]:
            corrupt = copy.deepcopy(row)
            corrupt[key] = 1
            with self.subTest(key=key), self.assertRaises(ValueError):
                bench.normalize(corrupt, 0x82585C, 2)
        for code in (0,):
            with self.assertRaises(ValueError):
                bench.normalize(row, 0x82585C, code)
        with self.assertRaises(ValueError):
            bench.normalize(row, 0x8258A9, 2)

    def test_leaf_requires_both_isa_comparisons(self):
        row = dict(schema='ts2-fresh-leaf/1', rva='0x1250', android_executed=False,
                   attempted=True, lifted=True, success=True,
                   runs={isa: dict(compiled=True, executed=True, matched=32,
                                   stdout_sha256='a' * 64) for isa in ('host', 'arm64')})
        self.assertEqual(bench.normalize(row, 0x1250, 0)[0], 'verified')
        for key, value in (('matched', 31), ('compiled', False), ('executed', False),
                           ('stdout_sha256', 'b' * 64)):
            corrupt = copy.deepcopy(row)
            corrupt['runs']['arm64'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                bench.normalize(corrupt, 0x1250, 0)
        with self.assertRaises(ValueError):
            bench.normalize(row, 0x1250, 1)
        row['success'] = False
        status, stages = bench.normalize(row, 0x1250, 1)
        self.assertEqual(status, 'failed')
        self.assertTrue(stages['executed_under_qemu'])
        self.assertFalse(stages['matched_x86_reference'])

    def child(self, root, name, content):
        path = root / 'scripts/recomp' / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        return name, []

    def test_crash_containment_process_state_and_order(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            good = """import builtins, json, os, pathlib, sys
assert not hasattr(builtins, 'recomp_test_state')
builtins.recomp_test_state = 1
out = pathlib.Path(sys.argv[-1]); out.mkdir()
row = json.loads(%r)
row['pid'] = os.getpid()
(out / 'metrics.jsonl').write_text(json.dumps(row) + '\\n')
sys.exit(2)
"""
            jobs = {
                0x1250: self.child(root, 'crash.py', 'raise RuntimeError("authored crash")'),
                0x8258A9: self.child(root, 'first.py', good % json.dumps(startup(0x8258A9))),
                0x82585C: self.child(root, 'second.py', good % json.dumps(startup())),
            }
            out = root / 'work/recomp-bench/batch'
            with patch.object(bench, 'ROOT', root), patch.object(bench, 'JOBS', jobs):
                result = bench.batch(out, list(jobs), 5)
                self.assertEqual([r['status'] for r in result['records']], ['failed', 'incomplete', 'incomplete'])
                self.assertEqual(result['counts']['attempted'], 2)
                self.assertEqual(result['counts']['executed_under_qemu'], 0)
                self.assertEqual(len({r['pid'] for r in result['records']}), 3)
                self.assertEqual(len((out / 'metrics.jsonl').read_text().splitlines()), 3)
                saved = (out / 'summary.json').read_bytes()
                with self.assertRaises(FileExistsError):
                    bench.batch(out, list(jobs), 5)
                self.assertEqual(saved, (out / 'summary.json').read_bytes())

    def test_timeout_and_malformed_record_do_not_stop_next_candidate(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            jobs = {
                0x1250: self.child(root, 'timeout.py', 'import time; time.sleep(30)'),
                0x8258A9: self.child(root, 'bad.py', "import pathlib, sys\np=pathlib.Path(sys.argv[-1]); p.mkdir(); (p/'metrics.jsonl').write_text('{}\\n{}\\n')"),
                0x82585C: self.child(root, 'exit.py', 'import sys; sys.exit(7)'),
            }
            with patch.object(bench, 'ROOT', root), patch.object(bench, 'JOBS', jobs):
                result = bench.batch(root / 'work/recomp-bench/batch', list(jobs), 1)
            self.assertTrue(result['records'][0]['timed_out'])
            self.assertEqual(result['records'][2]['exit_code'], 7)
            self.assertTrue(all(r['status'] == 'failed' for r in result['records']))
            self.assertTrue(all(value == 0 for value in result['counts'].values()))
            self.assertFalse(result['success'])

    def test_timeout_cleans_up_same_process_group_descendant(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            code = """import pathlib, subprocess, sys, time
out = pathlib.Path(sys.argv[-1]); out.mkdir()
child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])
(out / 'descendant.pid').write_text(str(child.pid))
time.sleep(30)
"""
            jobs = {0x1250: self.child(root, 'descendant.py', code)}
            out = root / 'work/recomp-bench/batch'
            with patch.object(bench, 'ROOT', root), patch.object(bench, 'JOBS', jobs):
                result = bench.batch(out, [0x1250], 1)
            self.assertTrue(result['records'][0]['timed_out'])
            pid = int((out / '00-1250/descendant.pid').read_text())
            stat = Path('/proc') / str(pid) / 'stat'
            if stat.exists():
                # Containers may retain an orphan zombie; it must not be running.
                self.assertIn(stat.read_text().split(')')[1].split()[0], ('Z', 'X'))

    def test_selection_and_output_guards(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(bench, 'ROOT', Path(temp)):
            root = Path(temp)
            out = root / 'work/recomp-bench/new'
            for rvas, seconds in (([], 1), ([0x1250, 0x1250], 1), ([0x1070], 1), ([0x1250], 0), ([0x1250], 601)):
                with self.assertRaises(ValueError):
                    bench.batch(out, rvas, seconds)
                self.assertFalse(out.exists())
            outside = root / 'outside'
            outside.mkdir()
            out.parent.mkdir(parents=True)
            (out.parent / 'link').symlink_to(outside)
            for path in (outside / 'new', out.parent / 'link/new'):
                with self.assertRaises(ValueError):
                    bench.batch(path, [0x1250], 1)
            self.assertEqual(list(outside.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
