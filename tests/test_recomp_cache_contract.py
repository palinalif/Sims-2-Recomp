"""Authored operand metadata, not game bytes, lifted bodies or CPU states."""
import copy
import importlib.util
from pathlib import Path
import tempfile
from types import SimpleNamespace as N
import unittest
from unittest.mock import patch

from capstone.x86 import X86_OP_REG, X86_OP_IMM, X86_OP_MEM

PATH = Path(__file__).resolve().parents[1]/'scripts/recomp/inspect_cache_contract.py'
spec = importlib.util.spec_from_file_location('cache_contract', PATH)
bench = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bench)


def fixture():
    # Abstract authored instructions exercise validation; no x86 encodings.
    names = ('esi', 'ecx', 'eax', 'esp', 'al', 'edi')
    ids = {name: n+1 for n, name in enumerate(names)}
    r = lambda name: N(type=X86_OP_REG, reg=ids[name], size=4)
    v = lambda value: N(type=X86_OP_IMM, imm=value, size=4)
    m = lambda offset: N(type=X86_OP_MEM, size=4,
        mem=N(base=ids['esi'], index=0, segment=0, disp=offset))
    result = {}

    def add(mnemonic, *operands):
        address = bench.BASE+bench.RVA+len(result)
        result[address] = N(address=address, mnemonic=mnemonic, operands=list(operands),
                            reg_name=lambda number: {v: k for k, v in ids.items()}.get(number))
    add('push', r('esi'))
    add('mov', r('esi'), r('ecx'))
    for n, callee in enumerate(bench.CALLEES):
        add('push', m(0x34))
        if n:
            add('mov', m(bench.CACHES[n-1]), r('eax'))
        add('call', v(bench.BASE+callee))
    add('add', r('esp'), v(20))
    add('mov', m(bench.CACHES[-1]), r('eax'))
    add('cmp', m(bench.CACHES[0]), v(0))
    add('setne', r('al'))
    add('pop', r('esi'))
    add('ret')
    return result


class CacheContractTests(unittest.TestCase):
    def test_retained_argument_words_and_partial_eax_result_are_explicit(self):
        row = bench.caller_contract(fixture())
        self.assertEqual([c['retained_argument_words'] for c in row['calls']], [1, 2, 3, 4, 5])
        self.assertEqual([c['callee_rva'] for c in row['calls']], [hex(r) for r in bench.CALLEES])
        self.assertEqual(row['caller_argument_cleanup_bytes'], 20)
        self.assertIn('upper EAX retains', row['result'])
        self.assertFalse(row['null_guard'])
        self.assertFalse(row['callee_contracts_verified'])
        self.assertFalse(row['composed_reference_available'])

    def test_every_operation_operand_and_missing_or_extra_node_rejects(self):
        original = fixture()
        for address, instruction in original.items():
            bad = copy.deepcopy(original)
            bad[address].mnemonic = 'nop'
            with self.subTest(address=address), self.assertRaises(ValueError):
                bench.caller_contract(bad)
            bad = copy.deepcopy(original)
            del bad[address]
            with self.assertRaises(ValueError):
                bench.caller_contract(bad)
            for n, op in enumerate(instruction.operands):
                bad = copy.deepcopy(original)
                operand = bad[address].operands[n]
                if op.type == X86_OP_REG:
                    operand.reg = 999
                elif op.type == X86_OP_IMM:
                    operand.imm ^= 4
                else:
                    operand.mem.disp ^= 4
                with self.subTest(address=address, operand=n), self.assertRaises(ValueError):
                    bench.caller_contract(bad)
        bad = copy.deepcopy(original)
        bad[max(bad)+1] = N(address=max(bad)+1, mnemonic='nop', operands=[])
        with self.assertRaises(ValueError):
            bench.caller_contract(bad)

    def test_segment_index_width_and_interleaved_store_order_reject(self):
        for field, value in (('segment', 1), ('index', 1), ('base', 999)):
            bad = fixture()
            operand = list(bad.values())[2].operands[0]
            setattr(operand.mem, field, value)
            with self.assertRaises(ValueError):
                bench.caller_contract(bad)
        bad = fixture()
        list(bad.values())[2].operands[0].size = 1
        with self.assertRaises(ValueError):
            bench.caller_contract(bad)
        bad = fixture()
        # The second PUSH must precede the first store, not follow it.
        a, b = list(bad.values())[4:6]
        a.mnemonic, b.mnemonic = b.mnemonic, a.mnemonic
        a.operands, b.operands = b.operands, a.operands
        with self.assertRaises(ValueError):
            bench.caller_contract(bad)

    def test_scope_gap_and_catalogs_cannot_establish_composed_correctness(self):
        manifest = bench.selection()
        catalogs = [dict(analysis_image_sha256=bench.IMAGE_SHA, states=[{}],
                         function_sha256_by_rva={hex(r)[2:]: 'test' for r in (0x1240, 0x1250, 0x1270)})]
        row = bench.coverage(manifest, catalogs)
        self.assertEqual(row['selected_count'], 25)
        self.assertEqual(row['unselected_callee_rvas'], ['0x1290', '0x12d0'])
        self.assertEqual(row['missing_catalog_callee_rvas'], ['0x1290', '0x12d0'])
        self.assertEqual(row['closed_native_body_count'], 27)
        self.assertEqual(row['additional_native_bodies_needed'], 2)
        self.assertFalse(row['whole_caller_native_comparison_ready'])
        # Even invented complete catalogs cannot prove composed CPU behavior.
        catalogs[0]['function_sha256_by_rva'].update({'1290': 'test', '12d0': 'test'})
        self.assertFalse(bench.coverage(manifest, catalogs)['whole_caller_native_comparison_ready'])
        bad = copy.deepcopy(manifest)
        bad['selected'].append(bad['selected'][0])
        with self.assertRaises(ValueError):
            bench.coverage(bad, catalogs)
        for key, value in (('analysis_image_sha256', 'wrong'), ('states', [])):
            bad = copy.deepcopy(catalogs)
            bad[0][key] = value
            with self.assertRaises(ValueError):
                bench.coverage(manifest, bad)

    def test_private_output_no_clobber_missing_inputs_and_symlink_escape(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(bench, 'ROOT', Path(temp)):
            root = Path(temp)
            outside = root/'outside'
            with self.assertRaises(ValueError):
                bench.inspect(root/'missing', outside)
            self.assertFalse(outside.exists())
            output = root/'work/recomp-bench/result.json'
            output.parent.mkdir(parents=True)
            with self.assertRaises(OSError):
                bench.inspect(root/'missing', output)
            self.assertFalse(output.exists())
            output.write_text('preserve')
            with self.assertRaises(ValueError):
                bench.inspect(root/'missing', output)
            self.assertEqual(output.read_text(), 'preserve')
            outside.mkdir()
            link = output.parent/'link'
            link.symlink_to(outside, target_is_directory=True)
            with self.assertRaises(ValueError):
                bench.inspect(root/'missing', link/'result.json')
            self.assertEqual(list(outside.iterdir()), [])
