"""Authored x86 only; no original bytes, bodies or reference states."""
import copy
import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[1] / 'scripts/recomp/inspect_startup_dependency.py'
spec = importlib.util.spec_from_file_location('startup_dependency', PATH)
bench = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bench)
BASE = bench.BASE + 0x1000


class StartupDependencyTests(unittest.TestCase):
    def test_first_call_is_contiguous_and_direct(self):
        code = b'\x90\xe8' + struct.pack('<i', 0x2000-0x1000-6)
        self.assertEqual(bench.first_direct_call(code, BASE), (BASE+1, bench.BASE+0x2000))
        for prefix in (b'\xff\xd0', b'\xeb\x00', b'\x74\x00', b'\xc3', b'\xcc', b'\xe2\x00', b'\x0f\xff', b'\x0f\x0b'):
            with self.subTest(prefix=prefix), self.assertRaises(ValueError):
                bench.first_direct_call(prefix+code, BASE)
        with self.assertRaises(ValueError):
            bench.first_direct_call(b'\x90\xe8\x00', BASE)

    def test_segment_and_frame_obligations_not_an_abi(self):
        # Authored FS load, GS store, explicit ESP/EBP moves, RET-immediate.
        body = bench.inspect_body(bytes.fromhex('64a10000000065a30000000089c489e5c20800'), BASE)
        self.assertEqual(body['instructions'], 5)
        self.assertEqual(body['segment_accesses'], [
            dict(rva='0x1000', segment='fs', read=True, write=False),
            dict(rva='0x1006', segment='gs', read=False, write=True)])
        self.assertEqual(body['explicit_frame_register_writes'], [
            dict(rva='0x100c', register='esp'), dict(rva='0x100e', register='ebp')])
        self.assertEqual(body['returns'], [dict(rva='0x1010', encoded_cleanup_bytes=8)])
        self.assertFalse(body['abi_established'])
        self.assertIsNone(body['net_stack_delta'])
        self.assertFalse(body['exception_semantics_verified'])
        self.assertNotIn('mnemonic', str(body))
        self.assertNotIn('operands', str(body))

    def test_flow_and_call_limits_preserved(self):
        body = bench.inspect_body(bytes.fromhex('e8fb000000ffd0c3'), BASE)
        self.assertEqual(body['direct_call_count'], 1)
        self.assertEqual(body['indirect_call_count'], 1)
        self.assertEqual(body['returns'][0]['encoded_cleanup_bytes'], 0)
        for text in ('ccc3', 'eb7fc3', 'ffe0', '7401b800000000c3', '0f0bc3'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                bench.inspect_body(bytes.fromhex(text), BASE)

    def envelope(self, body):
        return dict(schema='sims2-ghidra-query-envelope/1', provenance=dict(
            sourceImageSha256=bench.IMAGE_SHA, mode='readOnly', analysisPerformed=False,
            headlessExitCode=0, outputParseError=None, ghidraVersion='authored'),
            queryLogSignals=dict(warnLines=0, errorLines=1), result=dict(
                query=dict(rva='0x1000'), program=dict(imageBaseVa=hex(bench.BASE)),
                function=dict(resolution='function-at', entryRva='0x1000', disassembly=dict(
                    items=[dict(rva=a) for a in body['instruction_rvas']],
                    instructionCount=body['instructions'], extentEndVa=hex(BASE+body['size_bytes']-1),
                    extentBytes=body['size_bytes'])),
                truncation=dict(instructions=False, callers=True)))

    def test_index_comparison_is_boundary_only_and_retains_warnings(self):
        body = bench.inspect_body(b'\x90\xc3', BASE)
        env = self.envelope(body)
        result = bench.crosscheck_index(env, body, 0x1000)
        self.assertTrue(result['boundaries_agree'])
        self.assertFalse(result['operand_semantics_compared'])
        self.assertEqual(result['log_signals']['errorLines'], 1)
        self.assertTrue(result['truncation']['callers'])
        mutations = [
            ('provenance', 'sourceImageSha256', '0'*64),
            ('provenance', 'mode', 'write'), ('provenance', 'analysisPerformed', True),
            ('provenance', 'headlessExitCode', 1), ('provenance', 'outputParseError', 'error')]
        for parent, field, value in mutations:
            changed = copy.deepcopy(env)
            changed[parent][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                bench.crosscheck_index(changed, body, 0x1000)
        for field, value in [('items', [dict(rva='0x1001')]), ('instructionCount', 3),
                             ('extentEndVa', hex(BASE+body['size_bytes'])), ('extentBytes', 1)]:
            changed = copy.deepcopy(env)
            changed['result']['function']['disassembly'][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                bench.crosscheck_index(changed, body, 0x1000)
        for section, field, value in [('query', 'rva', '0x2000'),
                ('program', 'imageBaseVa', '0'), ('function', 'resolution', 'address-only'),
                ('function', 'entryRva', '0x1001'), ('truncation', 'instructions', True)]:
            changed = copy.deepcopy(env)
            changed['result'][section][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                bench.crosscheck_index(changed, body, 0x1000)

    def test_missing_pin_and_output_guards_publish_nothing(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(bench, 'ROOT', Path(temp)):
            root = Path(temp)
            private = root / 'work/recomp-bench'
            private.mkdir(parents=True)
            outside = root / 'outside'
            outside.mkdir()
            (private / 'link').symlink_to(outside)
            for output in (outside / 'out.json', private / 'link/out.json'):
                with self.assertRaisesRegex(ValueError, 'Private'):
                    bench.inspect(output, root / 'index.json')
            output = private / 'result.json'
            with patch.object(bench, 'digest', return_value='wrong'):
                with self.assertRaisesRegex(ValueError, 'pin'):
                    bench.inspect(output, root / 'index.json')
            self.assertFalse(output.exists())
            output.write_text('preserved')
            with self.assertRaises(FileExistsError):
                bench.inspect(output, root / 'index.json')
            self.assertEqual(output.read_text(), 'preserved')


if __name__ == '__main__':
    unittest.main()
