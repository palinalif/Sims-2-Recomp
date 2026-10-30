"""Authored encodings only: independent storage first-call frame contracts."""
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[1]/'scripts/recomp/reference_resource_storage.py'
spec = importlib.util.spec_from_file_location('storage_reference', PATH)
bench = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bench)
ENTRY = bench.BASE+0x4000
SLOT = bench.BASE+0x9000


def call(displacement=0x20000):
    return b'\xe8'+struct.pack('<i', displacement)


def authored():
    # Two paths, different argument frames; not an original function fixture.
    return (b'\xa1'+struct.pack('<I', SLOT)+b'\x83\xf8\xff\x74\x06'
            b'\x50'+call()+b'\x6a\xff\x68\x78\x56\x34\x12'+call(0x30000))


class StorageReferenceTests(unittest.TestCase):
    def inputs(self):
        regs = {r: 0x87654320+n for n,r in enumerate(bench.REGS)}
        regs['esp'] = bench.STACK+1024
        return regs, bytes([0xA5])*4096

    def test_known_two_branch_frames_include_call_return_word(self):
        for value, offset, delta in ((0, 11, -8), (1, 11, -8), (0xFFFFFFFF, 23, -12)):
            regs, stack = self.inputs()
            plan = bench.exercise(authored(), ENTRY, regs, stack, 0xED7, SLOT, value)
            last = plan[-1]
            self.assertEqual(last['pc'], ENTRY+offset)
            self.assertEqual(last['regs']['esp'], regs['esp']+delta)
            self.assertEqual(struct.unpack_from('<I', last['stack'], 1024+delta)[0], ENTRY+offset+5)
            self.assertEqual(last['stack'][1024:], stack[1024:])
            self.assertEqual(last['regs']['eax'], value)
            if value == 0xFFFFFFFF:
                self.assertEqual(struct.unpack_from('<II', last['stack'], 1016), (0x12345678, value))

    def test_cmp_signed_immediate_flag_edges_independent_expected_bits(self):
        regs, stack = self.inputs()
        for value, imm, expected in ((0, 1, 0x95), (0x80000000, 1, 0x814),
                                     (0x7FFFFFFF, 0xFF, 0x885), (0xFFFFFFFF, 0xFF, 0x44)):
            code = b'\x83\xf8'+bytes([imm])+call()
            last = bench.exercise(code, ENTRY, dict(regs, eax=value), stack, 0x202, SLOT, 0)[-1]
            self.assertEqual(last['flags'] & 0x8D5, expected)
            self.assertEqual(last['flag_mask'], 0xCD5)

    def test_register_moves_xor_push_esp_sign_extension(self):
        regs, stack = self.inputs()
        code = b'\x89\xd8\x8b\xf0\x33\xc0\x54\x6a\x80'+call()
        last = bench.exercise(code, ENTRY, regs, stack, 0xED7, SLOT, 0)[-1]
        self.assertEqual(last['regs']['esi'], regs['ebx'])
        self.assertEqual(last['regs']['eax'], 0)
        self.assertEqual(last['flag_mask'], 0xCC5)
        self.assertEqual(struct.unpack_from('<II', last['stack'], 1016), (0xFFFFFF80, regs['esp']))
        # CMP restores AF's defined status after XOR.
        last = bench.exercise(b'\x31\xc0\x83\xf8\x01'+call(), ENTRY, regs, stack, 0x202, SLOT, 0)[-1]
        self.assertEqual(last['flag_mask'], 0xCD5)

    def test_unsupported_memory_loop_overlap_wrap_and_stack_budget_reject(self):
        regs, stack = self.inputs()
        for code in (b'\x90', b'\xc3', b'\xcc', b'\x8b\x03'+call(), b'\x8b\xe0'+call(),
                     b'\x83\xc0\x01'+call(), b'\x75\xfe', b'\x50\xe8\x00',
                     b'\xa1'+struct.pack('<I', SLOT+4)+call(), b'\xe8\xfb\xff\xff\xff'):
            with self.subTest(code=code), self.assertRaises(ValueError):
                bench.exercise(code, ENTRY, regs, stack, 0x202, SLOT, 0)
        with self.assertRaises(ValueError):
            bench.exercise(authored(), ENTRY, regs, stack, 0x202, SLOT, 0, budget=2)
        for sp in (bench.STACK, bench.STACK+3, bench.STACK+4100):
            with self.subTest(sp=sp), self.assertRaises(ValueError):
                bench.exercise(call(), ENTRY, dict(regs, esp=sp), stack, 0x202, SLOT, 0)
        for slot in (ENTRY, bench.STACK, SLOT+1, 0xFFFFFFFF):
            with self.assertRaises(ValueError):
                bench.frame_plan(call(), ENTRY, regs, stack, 0x202, slot, 0)
        with self.assertRaises(ValueError):
            bench.frame_plan(call(), 0xFFFFFFFE, regs, stack, 0x202, SLOT, 0)

    def test_mutated_oracle_cannot_self_certify(self):
        regs, stack = self.inputs()
        for field in ('regs', 'stack', 'flags', 'next_pc'):
            plan = bench.frame_plan(authored(), ENTRY, regs, stack, 0x202, SLOT, 0)
            if field == 'regs':
                plan[0][field]['edx'] ^= 1
            elif field == 'stack':
                plan[0][field] = bytes(4096)
            else:
                plan[0][field] ^= 1
            with self.subTest(field=field), patch.object(bench, 'frame_plan', return_value=plan):
                with self.assertRaises(ValueError):
                    bench.exercise(authored(), ENTRY, regs, stack, 0x202, SLOT, 0)

    def test_private_pin_exclusive_and_symlink_guards(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(bench, 'ROOT', Path(temp)):
            root = Path(temp)
            private = root/'work/recomp-bench'
            private.mkdir(parents=True)
            outside = root/'outside'
            outside.mkdir()
            (private/'link').symlink_to(outside)
            for output in (outside/'out', private/'link/out'):
                with self.assertRaises(ValueError):
                    bench.run(root/'index', output)
            output = private/'out'
            with patch.object(bench, 'digest', return_value='bad'):
                with self.assertRaises(ValueError):
                    bench.run(root/'index', output)
            self.assertFalse(json.loads((output/'metrics.json').read_text())['success'])
            with self.assertRaises(FileExistsError):
                bench.run(root/'index', output)


if __name__ == '__main__':
    unittest.main()
