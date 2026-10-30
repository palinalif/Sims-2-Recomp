"""Authored control flow only; no proprietary functions or query dumps."""
import copy
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[1]/'scripts/recomp/measure_resource_return.py'
spec = importlib.util.spec_from_file_location('resource_return_measurement', PATH)
bench = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bench)


def authored():
    # Three authored calls, plus enough reachable NOPs to test the 70-byte bound.
    prefix = (b'\x55\x8b\xec\xff\x15'+struct.pack('<I', bench.BASE+0x9000)+
              b'\xe8'+struct.pack('<i', 0x1000)+b'\xff\xd0')
    return prefix+b'\x90'*(bench.SIZE-len(prefix)-2)+b'\xc9\xc3'


def envelope(code):
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    nodes = list(Cs(CS_ARCH_X86, CS_MODE_32).disasm(code, bench.BASE+bench.RVA))
    return dict(schema='sims2-ghidra-query-envelope/1', provenance=dict(
        sourceImageSha256=bench.IMAGE_SHA, mode='readOnly', analysisPerformed=False,
        headlessExitCode=0, outputParseError=None, ghidraVersion='authored'),
        queryLogSignals=dict(errorLines=1), result=dict(query=dict(rva=hex(bench.RVA)),
        program=dict(imageBaseVa=hex(bench.BASE)), truncation=dict(instructions=False),
        function=dict(resolution='function-at', entryRva=hex(bench.RVA), disassembly=dict(
            items=[dict(rva=hex(i.address-bench.BASE)) for i in nodes],
            instructionCount=len(nodes), extentBytes=len(code),
            extentEndVa=hex(bench.BASE+bench.RVA+len(code)-1)))))


class ResourceReturnMeasurementTests(unittest.TestCase):
    def test_supplement_is_deterministic_preserves_historical_candidates_and_cap(self):
        old = bench.select_candidates()
        new = bench.selection()
        self.assertEqual(new, bench.selection())
        self.assertEqual(new['selected'][:-1], old['selected'])
        self.assertEqual(new['rejected'], old['rejected'])
        self.assertEqual(new['counts']['selected'], 22)
        self.assertLessEqual(new['counts']['selected'], 25)
        self.assertEqual(new['selected'][-1]['rva'], '0x82A528')
        self.assertEqual(bench.select_candidates(), old)
        with patch.object(bench, 'MAX_FUNCTIONS', 21), self.assertRaises(ValueError):
            bench.selection()

    def test_authored_calls_are_dependencies_not_executed_or_return_proofs(self):
        code = authored()
        _, nodes, _, analysis, index, deps = bench.characterize(code, envelope(code), SimpleNamespace())
        self.assertEqual(analysis['size_bytes'], 70)
        self.assertEqual(len(analysis['calls']), 3)
        self.assertEqual(deps['indirect_calls'], 2)
        self.assertEqual(len(deps['direct_calls']), 1)
        self.assertIsNone(deps['indirect_call_sites'][0]['import_metadata'])
        self.assertIsNone(deps['indirect_call_sites'][1]['slot_rva'])
        self.assertTrue(index['boundaries_agree'])
        self.assertFalse(index['operand_semantics_compared'])
        self.assertEqual(index['log_signals']['errorLines'], 1)
        self.assertEqual(sum(i.mnemonic=='ret' for i in nodes.values()), 1)

    def test_bad_provenance_boundaries_caps_and_extent_reject(self):
        code = authored()
        paths = [('provenance','sourceImageSha256'), ('provenance','analysisPerformed'),
                 ('result','function','entryRva'), ('result','truncation','instructions'),
                 ('result','function','disassembly','extentEndVa')]
        values = ['bad', True, '0x1', True, hex(bench.BASE+bench.RVA+70)]
        for path, value in zip(paths, values):
            e = copy.deepcopy(envelope(code))
            node = e
            for part in path[:-1]:
                node = node[part]
            node[path[-1]] = value
            with self.subTest(path=path), self.assertRaises(ValueError):
                bench.characterize(code, e, SimpleNamespace())
        for code2 in (code[:-1], code+b'\x90'):
            with self.assertRaises(ValueError):
                bench.characterize(code2, envelope(code2), SimpleNamespace())

    def test_trap_and_escaping_flow_not_pruned_to_obtain_return(self):
        for code in (b'\xcc'+authored()[1:], b'\xeb\x7f'+authored()[2:]):
            with self.assertRaises(ValueError):
                bench.characterize(code, envelope(code), SimpleNamespace())

    def test_generated_body_is_inserted_verbatim_and_markers_reject(self):
        body = 'void authored(void) { /* public test fixture */ }'
        self.assertEqual(bench.assemble(body).count(body), 1)
        for bad in ('', '/* UNIMPLEMENTED */', '/* unhandled */', '/* unresolved */'):
            with self.assertRaises(ValueError):
                bench.assemble(bad)

    def test_private_pin_symlink_and_exclusive_output_guards(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(bench, 'ROOT', Path(tmp)):
            root = Path(tmp)
            private = root/'work/recomp-bench'
            private.mkdir(parents=True)
            outside = root/'outside'
            outside.mkdir()
            (private/'link').symlink_to(outside)
            for output in (outside/'out', private/'link/out'):
                with self.assertRaises(ValueError):
                    bench.measure(root/'index', output)
            output = private/'out'
            with patch.object(bench, 'digest', return_value='bad'), self.assertRaises(ValueError):
                bench.measure(root/'index', output)
            row = json.loads((output/'metrics.jsonl').read_text())
            for flag in ('attempted','lifted','compiled_for_aarch64','linked',
                         'matched_x86_reference','executed_under_qemu','android_executed'):
                self.assertFalse(row[flag])
            self.assertEqual(row['failed_stage'], 'preflight')
            with self.assertRaises(FileExistsError):
                bench.measure(root/'index', output)

    def test_cli_object_only_is_incomplete_and_errors_are_sanitized(self):
        with patch('sys.argv', ['measure', '--index','private-index','--output','private-output']):
            with patch.object(bench, 'measure', return_value=dict(lifted=True, compiled_for_aarch64=True)):
                self.assertEqual(bench.main(), 2)
            with patch.object(bench, 'measure', side_effect=ValueError('secret')):
                self.assertEqual(bench.main(), 1)


if __name__ == '__main__':
    unittest.main()
