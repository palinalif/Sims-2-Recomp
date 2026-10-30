"""Public fail-closed controls; no proprietary inputs needed."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[1] / 'scripts/recomp/measure_group.py'
spec = importlib.util.spec_from_file_location('readonly_group_bench', PATH)
bench = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bench)


class ReadonlyGroupBenchmarkTests(unittest.TestCase):
    def test_complete_requires_fresh_bodies_and_both_isa_comparisons(self):
        good = dict(functions={hex(r): {'lifted': True} for r in bench.RVAS},
                    generated_source_sha256=bench.SOURCE_SHA,
                    runs={isa: dict(compiled=True, executed=True, exit_code=0,
                                    matched=96, stdout_sha256='same')
                          for isa in ('host', 'arm64')})
        bench.require_complete(good)
        for isa in good['runs']:
            for key, value in (('compiled', False), ('executed', False),
                               ('exit_code', 1), ('matched', 95),
                               ('stdout_sha256', 'other')):
                bad = copy.deepcopy(good)
                bad['runs'][isa][key] = value
                with self.subTest(isa=isa, key=key), self.assertRaises(ValueError):
                    bench.require_complete(bad)
            bad = copy.deepcopy(good)
            del bad['runs'][isa]
            with self.assertRaises(ValueError):
                bench.require_complete(bad)
        for rva in bench.RVAS:
            bad = copy.deepcopy(good)
            bad['functions'][hex(rva)]['lifted'] = False
            with self.assertRaises(ValueError):
                bench.require_complete(bad)
        bad = copy.deepcopy(good)
        bad['generated_source_sha256'] = 'not the original artifact'
        with self.assertRaises(ValueError):
            bench.require_complete(bad)

    def test_standalone_coverage_rejects_same_total_with_wrong_entry_distribution(self):
        selected = [(rva, None, None) for rva, count in bench.ENTRY_CASES.items()
                    for _ in range(count)]
        bench.require_case_counts(selected)
        for replacement in (0x1250, 0x1070):
            bad = list(selected)
            bad[0] = (replacement, None, None)
            with self.subTest(replacement=replacement), self.assertRaises(ValueError):
                bench.require_case_counts(bad)
        with self.assertRaises(ValueError):
            bench.require_case_counts(selected[:-1])

    def test_index_gaps_and_caps_are_retained_not_promoted_to_boundaries(self):
        envelope = dict(schema='sims2-ghidra-query-envelope/1',
            provenance=dict(sourceImageSha256=bench.IMAGE_SHA, mode='readOnly',
                            analysisPerformed=False, headlessExitCode=0,
                            outputParseError=None, ghidraVersion='test'),
            result=dict(query={'rva': '0x1240'},
                        program={'imageBaseVa': '0xa0000000'},
                        function={'resolution': 'address-only'},
                        truncation={'instructions': True}),
            queryLogSignals={'errors': 1})
        context = bench.index_context(envelope, 0x1240)
        self.assertFalse(context['reliable_boundaries'])
        self.assertEqual(context['resolution'], 'address-only')
        self.assertTrue(context['truncation']['instructions'])
        self.assertEqual(context['log_signals'], {'errors': 1})
        for key, value in (('sourceImageSha256', 'wrong'), ('mode', 'write'),
                           ('analysisPerformed', True), ('headlessExitCode', 1),
                           ('outputParseError', 'bad')):
            bad = copy.deepcopy(envelope)
            bad['provenance'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                bench.index_context(bad, 0x1240)
        with self.assertRaises(ValueError):
            bench.index_context(envelope, 0x1270)

    def test_private_output_and_query_set_are_required_before_writes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with patch.object(bench, 'ROOT', root):
                for out, indexes in ((root/'outside', {}),
                                     (root/'work/recomp-bench/result', {})):
                    with self.assertRaises(ValueError):
                        bench.measure(out, indexes)
                    self.assertFalse(out.exists())
                (root/'work/recomp-bench').mkdir(parents=True)
                (root/'outside').mkdir()
                (root/'work/recomp-bench/link').symlink_to(root/'outside')
                with self.assertRaises(ValueError):
                    bench.measure(root/'work/recomp-bench/link/result', {})
                self.assertEqual(list((root/'outside').iterdir()), [])

    def test_missing_inputs_leave_failure_record_and_do_not_clobber(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(bench, 'ROOT', Path(temp)):
            output = Path(temp)/'work/recomp-bench/result'
            indexes = {0x1240: Path('missing')}
            with self.assertRaises(OSError):
                bench.measure(output, indexes)
            record = (output/'result.json').read_bytes()
            report = json.loads(record)
            self.assertFalse(report['success'])
            self.assertEqual(report['failed_stage'], 'preflight')
            self.assertEqual(report['runs'], {})
            with self.assertRaises(FileExistsError):
                bench.measure(output, indexes)
            self.assertEqual((output/'result.json').read_bytes(), record)
