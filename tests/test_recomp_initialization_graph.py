"""Authored x86/metadata only; no game input or optional/skipped checks."""
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[1]/'scripts/recomp/inspect_initialization_graph.py'
spec = importlib.util.spec_from_file_location('initialization_graph', PATH)
bench = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bench)


def row(direct=(), indirect=(), tails=(), complete=True):
    return dict(complete=complete, direct=[hex(r) for r in direct],
                indirect=list(indirect), tails=[hex(r) for r in tails])


def envelope(code, rva=0x1030):
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    instructions = list(Cs(CS_ARCH_X86, CS_MODE_32).disasm(code, bench.BASE+rva))
    return dict(schema='sims2-ghidra-query-envelope/1', provenance=dict(
        sourceImageSha256=bench.IMAGE_SHA, mode='readOnly', analysisPerformed=False,
        headlessExitCode=0, outputParseError=None, ghidraVersion='authored'),
        queryLogSignals=dict(scriptCompileError=False, errorLines=1, warnLines=0),
        result=dict(query=dict(rva=hex(rva)), program=dict(imageBaseVa=hex(bench.BASE)),
            truncation=dict(instructions=False), function=dict(resolution='function-at',
                entryRva=hex(rva), disassembly=dict(items=[dict(rva=hex(i.address-bench.BASE))
                for i in instructions], instructionCount=len(instructions), extentBytes=len(code),
                extentEndVa=hex(bench.BASE+rva+len(code)-1)))))


class InitializationGraphTests(unittest.TestCase):
    def test_deterministic_reuse_and_stop_at_every_external_target(self):
        seed = row((0x1070, 0x3a50, 0x1030, 0x9999))
        loaded = []
        def load(rva):
            loaded.append(rva)
            return row((0x3a50,)) if rva == 0x1030 else row((0x831a6f,)) if rva == 0x3a50 else row(tails=(0xdead,))
        g = bench.graph(seed, load)
        self.assertEqual(loaded, [0x1030, 0x3a50, 0x831a6f])
        self.assertEqual(g['external_frontier'], ['0x9999', '0xdead'])
        self.assertEqual([e['target'] for e in g['edges'] if e['classification']=='already_verified'], ['0x1070'])
        self.assertTrue(g['bounded_decodes_complete'])
        self.assertFalse(g['composed_execution_ready'])
        self.assertEqual(g, bench.graph(row(reversed((0x1070, 0x3a50, 0x1030, 0x9999))), load))

    def test_cycles_budget_indirect_and_incomplete_are_not_passes(self):
        with self.assertRaises(ValueError):
            bench.graph(row((0x1030,)), lambda r: row(), budget=1)
        g = bench.graph(row((0x1030,)), lambda r: row((0x1030,), complete=False))
        self.assertFalse(g['bounded_decodes_complete'])
        self.assertEqual(len(g['nodes']), 2)
        g = bench.graph(row(indirect=[dict(call_rva='0x11', slot_rva=None, import_metadata=None)]),
                        lambda r: self.fail('indirect must not load'))
        self.assertEqual(g['edges'][0]['classification'], 'unresolved_indirect')
        self.assertEqual(g['candidate_leaf_units'], [])
        self.assertFalse(g['composed_execution_ready'])

    def test_authored_leaf_direct_and_import_dependencies(self):
        # Authored store+return, not a game setter.
        code = bytes.fromhex('8901 c3')
        r = bench.inspect_code(code, 0x1030, SimpleNamespace(), envelope(code))
        self.assertTrue(r['index']['boundaries_agree'])
        self.assertEqual(r['index']['log_signals']['errorLines'], 1)
        g = bench.graph(row((0x1030,)), lambda _: r)
        self.assertEqual(g['candidate_leaf_units'], ['0x1030'])
        # CALL [absolute IAT]; RET, with authored import metadata.
        code = bytes.fromhex('ff15001000a0 c3')
        pe = SimpleNamespace(DIRECTORY_ENTRY_IMPORT=[SimpleNamespace(dll=b'authored.dll',
            imports=[SimpleNamespace(address=bench.BASE+0x1000, name=b'alloc', ordinal=None)])])
        r = bench.inspect_code(code, 0x1030, pe, envelope(code))
        self.assertEqual(r['indirect'][0]['import_metadata']['name'], 'alloc')
        self.assertEqual(r['indirect'][0]['slot_rva'], '0x1000')
        self.assertEqual(r['direct'], [])

    def test_external_tail_never_followed_and_index_disagreement_rejects(self):
        code = b'\xe9'+(0x9999-0x1030-5).to_bytes(4,'little')
        r = bench.inspect_code(code, 0x1030, SimpleNamespace(), envelope(code))
        self.assertEqual(r['tails'], ['0x9999'])
        self.assertTrue(r['entry_tail'])
        bad = envelope(code)
        bad['result']['function']['disassembly']['items'][0]['rva'] = '0x1031'
        with self.assertRaises(ValueError):
            bench.inspect_code(code, 0x1030, SimpleNamespace(), bad)

    def test_index_gap_caps_bad_provenance_and_partial_flow(self):
        code = b'\xc3'
        e = envelope(code)
        e['result']['function']['resolution'] = 'address-only'
        self.assertFalse(bench.inspect_code(code, 0x1030, SimpleNamespace(), e)['index']['boundaries_agree'])
        e = envelope(code)
        e['result']['truncation']['instructions'] = True
        self.assertFalse(bench.inspect_code(code, 0x1030, SimpleNamespace(), e)['index']['boundaries_agree'])
        for key, value in (('sourceImageSha256','wrong'), ('mode','write'),
                           ('analysisPerformed',True), ('headlessExitCode',1)):
            e = envelope(code)
            e['provenance'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                bench.inspect_code(code, 0x1030, SimpleNamespace(), e)
        e = envelope(code)
        e['queryLogSignals']['scriptCompileError'] = True
        with self.assertRaises(ValueError):
            bench.inspect_code(code, 0x1030, SimpleNamespace(), e)
        # A direct call followed by a branch escaping the window: partial only.
        code = bytes.fromhex('e800000000 eb7f')
        r = bench.inspect_code(code, 0x1030, SimpleNamespace(), envelope(code))
        self.assertFalse(r['complete'])
        self.assertFalse(r['index']['boundaries_agree'])
        self.assertEqual(r['direct'], ['0x1035'])
        g = bench.graph(row((0x1030,)), lambda _: r)
        escaped = [e for e in g['edges'] if e['kind']=='normal_flow_escape']
        self.assertEqual(escaped[0]['target'], '0x10b6')
        self.assertEqual(escaped[0]['classification'], 'external_frontier')
        self.assertFalse(g['bounded_decodes_complete'])

    def test_inspection_reuses_seed_and_never_reads_known_or_external_bodies(self):
        reads = []
        def get_data(rva, bound):
            reads.append((rva, bound))
            return b'\xc3'+bytes(bound-1)
        pe = SimpleNamespace(OPTIONAL_HEADER=SimpleNamespace(ImageBase=bench.BASE),
            FILE_HEADER=SimpleNamespace(Machine=0x14c), get_data=get_data)
        with tempfile.TemporaryDirectory() as temp, patch.object(bench,'ROOT',Path(temp)), \
                patch.object(bench,'digest',return_value=bench.IMAGE_SHA), \
                patch.object(bench,'seed_receipt',return_value=row((0x1030,0x1070,0x9999))) as seed, \
                patch('pefile.PE',return_value=pe), patch.object(bench.subprocess,'run') as query:
            root = Path(temp)
            image = root/'work/interop-legacy-002/analysis-image.bin'
            image.parent.mkdir(parents=True)
            image.write_bytes(b'authored placeholder')
            cache = root/'work/recomp-bench/cache'
            cache.mkdir(parents=True)
            (cache/'1030.json.env.json').write_text(json.dumps(envelope(b'\xc3')))
            out = root/'work/recomp-bench/new'
            result = bench.inspect(out,cache)
            seed.assert_called_once()
            query.assert_not_called()  # Cached persistent-index metadata reused.
            self.assertEqual(reads,[(0x1030,bench.BOUND)])
            self.assertTrue(result['inspection_complete'])
            self.assertEqual(result['graph']['external_frontier'],['0x9999'])
            self.assertFalse(result['graph']['composed_execution_ready'])
            self.assertEqual(json.loads((out/'result.json').read_text()),result)

    def test_private_exclusive_and_pin_failure_receipt(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(bench,'ROOT',Path(temp)):
            root = Path(temp)
            index = root/'work/recomp-bench/cache'
            with self.assertRaises(ValueError):
                bench.inspect(root/'public',index)
            out = root/'work/recomp-bench/new'
            with patch.object(bench,'digest',return_value='wrong'), self.assertRaises(ValueError):
                bench.inspect(out,index)
            receipt = json.loads((out/'result.json').read_text())
            self.assertFalse(receipt['inspection_complete'])
            for key in ('lifted','host_executed','arm64_executed','android_executed'):
                self.assertFalse(receipt[key])
            saved = (out/'result.json').read_bytes()
            with self.assertRaises(FileExistsError):
                bench.inspect(out,index)
            self.assertEqual((out/'result.json').read_bytes(),saved)
            outside = root/'outside'
            outside.mkdir()
            (out.parent/'link').symlink_to(outside)
            with self.assertRaises(ValueError):
                bench.inspect(out.parent/'link/new',index)
            with patch.object(bench,'digest',return_value='wrong'), self.assertRaises(ValueError):
                bench.seed_receipt(root/'missing-seed')


if __name__ == '__main__':
    unittest.main()
