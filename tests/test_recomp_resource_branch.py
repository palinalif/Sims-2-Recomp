"""Authored branch/frame encodings only, no proprietary bytes or states."""
import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[1]/'scripts/recomp/reference_resource_branch.py'
spec = importlib.util.spec_from_file_location('resource_branch', PATH)
bench = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bench)
ENTRY = bench.BASE+0x3000
SLOT = bench.BASE+0x9000


def authored():
    # Read first caller arg, TEST, branch to independent call cutpoints.
    # A zero arg reads explicit global; zero global chooses the third cutpoint.
    return (b'\x55\x8b\xec\x8b\x45\x08\x85\xc0\x75\x19'
            b'\x8b\x15'+struct.pack('<I', SLOT)+b'\x85\xd2\x74\x06'
            b'\x52\xe8'+struct.pack('<i', 0x100000)+
            b'\xff\x75\x08\xff\x15'+struct.pack('<I', SLOT)+
            b'\x50\xe8'+struct.pack('<i', 0x200000))


class ResourceBranchTests(unittest.TestCase):
    def inputs(self, arg=0):
        regs = {r: 0x81234560+n for n, r in enumerate(bench.REGS)}
        regs['esp'] = bench.STACK+1024
        stack = bytearray([0xA5]*4096)
        struct.pack_into('<I', stack, 1028, arg)
        return regs, bytes(stack)

    def test_three_authored_paths_have_known_frames_and_stop_before_call(self):
        for arg, value, offset in ((1, 0, 36), (0, 7, 21), (0, 0, 29)):
            regs, stack = self.inputs(arg)
            result = bench.exercise(authored(), ENTRY, regs, stack, SLOT, value, 0xED7)
            self.assertEqual(result['stop_pc'], ENTRY+offset)
            self.assertEqual(result['regs']['ebp'], regs['esp']-4)
            self.assertEqual(result['regs']['esp'], regs['esp']-8)
            self.assertEqual(struct.unpack_from('<I', result['stack'], 1020)[0], regs['ebp'])
            self.assertEqual(struct.unpack_from('<I', result['stack'], 1016)[0], arg if arg else value)
            self.assertEqual(result['stack'][1024:], stack[1024:])
            self.assertEqual(result['flag_mask'], 0xCC5)
            self.assertNotIn(ENTRY+offset, [s['pc'] for s in result['plan']])

    def test_defined_test_flags_edges_and_input_flags(self):
        for val in (0, 1, 0x80000000, 0xFFFFFFFF):
            for flags in (0x202, 0xED7):
                regs, stack = self.inputs()
                code = b'\x85\xc0\x50\xe8'+struct.pack('<i', 0x10000)
                result = bench.exercise(code, ENTRY, dict(regs, eax=val), stack, SLOT, 0, flags)
                expected = ((flags & ~0x8C5) | (int((val & 255).bit_count()%2 == 0) << 2)
                            | (int(val == 0) << 6) | ((val >> 31) << 7))
                self.assertEqual(result['flags'], expected)
                self.assertEqual(result['stack'][1024:], stack[1024:])

    def test_push_esp_and_unaligned_stack_reads(self):
        regs, stack = self.inputs()
        code = b'\x54\xe8'+struct.pack('<i', 0x10000)
        result = bench.exercise(code, ENTRY, regs, stack, SLOT, 0, 0x202)
        self.assertEqual(struct.unpack_from('<I', result['stack'], 1020)[0], regs['esp'])
        code = b'\x8b\x43\x01\xe8'+struct.pack('<i', 0x10000)
        result = bench.exercise(code, ENTRY, dict(regs, ebx=bench.STACK+1000), stack, SLOT, 0, 0x202)
        self.assertEqual(result['regs']['eax'], 0xA5A5A5A5)

    def test_explicit_pointer_word_required_not_blanket_payload_permission(self):
        regs, stack = self.inputs()
        code = b'\x8b\x03\xe8'+struct.pack('<i', 0x10000)
        regs['ebx'] = bench.PAYLOAD
        with self.assertRaises(ValueError):
            bench.exercise(code, ENTRY, regs, stack, SLOT, 0, 0x202)
        result = bench.exercise(code, ENTRY, regs, stack, SLOT, 0, 0x202,
                                extra_words={bench.PAYLOAD: 0x87654321})
        self.assertEqual(result['regs']['eax'], 0x87654321)
        with self.assertRaises(ValueError):
            bench.exercise(code, ENTRY, dict(regs, ebx=bench.PAYLOAD+4), stack,
                           SLOT, 0, 0x202, extra_words={bench.PAYLOAD: 1})
        # Independently authored two-word pointer chain, no adjacent-word access.
        chain = b'\x8b\x03\x8b\x40\x0c\xe8'+struct.pack('<i', 0x10000)
        result = bench.exercise(chain, ENTRY, regs, stack, SLOT, 0, 0x202,
                                extra_words={bench.PAYLOAD: bench.PAYLOAD+128,
                                             bench.PAYLOAD+140: 42})
        self.assertEqual(result['regs']['eax'], 42)
        with self.assertRaises(ValueError):
            bench.exercise(chain, ENTRY, regs, stack, SLOT, 0, 0x202,
                           extra_words={bench.PAYLOAD: bench.PAYLOAD+128})
        for addr in (ENTRY, SLOT, bench.STACK, bench.PAYLOAD+1, 0xFFFFFFFE):
            with self.subTest(addr=addr), self.assertRaises(ValueError):
                bench.exercise(code, ENTRY, regs, stack, SLOT, 0, 0x202, extra_words={addr: 1})

    def test_budget_loop_memory_wrap_and_unsupported_encodings_reject(self):
        regs, stack = self.inputs()
        for code in (b'\x90', b'\xc3', b'\xcc', b'\x8b\x04\x24', b'\x8b\xe0',
                     b'\x8b\x03', b'\x8b', b'\xff\xd0', b'\x75\xfe',
                     b'\x50\xe8\x00', b'\x8b\x43\x01', b'\x50'):
            with self.subTest(code=code), self.assertRaises(ValueError):
                bench.exercise(code, ENTRY, regs, stack, SLOT, 0, 0x202)
        with self.assertRaises(ValueError):
            bench.exercise(authored(), ENTRY, regs, stack, SLOT, 0, 0x202, budget=2)
        for sp in (bench.STACK, bench.STACK+3, bench.STACK+4100):
            with self.subTest(sp=sp), self.assertRaises(ValueError):
                bench.exercise(authored(), ENTRY, dict(regs, esp=sp), stack, SLOT, 0, 0x202)
        with self.assertRaises(ValueError):
            bench.branch_plan(b'\x8b\x03\xe8\x00\x00\x00\x00', ENTRY,
                              dict(regs, ebx=0xFFFFFFFE), stack, SLOT, 0, 0x202)

    def test_oracle_mutations_cannot_self_certify_x86(self):
        regs, stack = self.inputs()
        for field in ('regs', 'stack', 'flags', 'next_pc', 'stop_pc'):
            result = bench.branch_plan(authored(), ENTRY, regs, stack, SLOT, 0, 0x202)
            if field == 'regs':
                result['plan'][0]['regs']['eax'] ^= 1
            elif field == 'stack':
                result['plan'][0]['stack'] = bytes(4096)
            elif field == 'stop_pc':
                result[field] ^= 1
            else:
                result['plan'][0][field] ^= 1
            with self.subTest(field=field), patch.object(bench, 'branch_plan', return_value=result):
                with self.assertRaises(ValueError):
                    bench.exercise(authored(), ENTRY, regs, stack, SLOT, 0, 0x202)

    def test_private_exclusive_pin_and_symlink_guards(self):
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
            self.assertFalse(__import__('json').loads((output/'metrics.json').read_text())['success'])
            with self.assertRaises(FileExistsError):
                bench.run(root/'index', output)


if __name__ == '__main__':
    unittest.main()
