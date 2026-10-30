"""Authored instruction fixtures only; no proprietary bytes/states."""
import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[1]/'scripts/recomp/reference_startup_dependency.py'
spec = importlib.util.spec_from_file_location('dependency_reference', PATH)
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)


class DependencyReferenceTests(unittest.TestCase):
    def fixture(self):
        regs = {r: 0x100+n for n, r in enumerate(b.GPRS)}
        regs['esp'] = b.STACK+0x800
        stack = bytearray([0xA5]*4096)
        struct.pack_into('<I', stack, 0x800, b.RETURN)
        return regs, stack

    def test_actual_nonzero_fs_and_full_frame_against_known_authored_result(self):
        # Authored: load FS head; save old frame; establish EBP; save head in
        # frame; publish EBP via FS; restore SP/frame; return. No original body.
        code = bytes.fromhex('64a1000000005589e55064892d0000000089ec8b2c248d642404c3')
        for fs in (0x74000000, 0x75000000):
            for chain in (0xFFFFFFFF, 0x76000100):
                regs, stack = self.fixture()
                result = b.exercise(code, regs, stack, fs, chain, 0x12345678)
                self.assertEqual(result.regs, dict(regs, eax=chain, esp=regs['esp']+4))
                expected = bytearray(stack)
                struct.pack_into('<I', expected, 0x7FC, regs['ebp'])
                struct.pack_into('<I', expected, 0x7F8, chain)
                self.assertEqual(result.pages[b.STACK], expected)
                self.assertEqual(result.read(fs), b.STACK+0x7FC)
                self.assertEqual(result.read(b.COOKIE), 0x12345678)

    def test_integer_and_push_esp_semantics(self):
        # Authored modular arithmetic, PUSH ESP, then restore SP without POP.
        code = bytes.fromhex('b80000008083e80135000000ff548d642404c3')
        regs, stack = self.fixture()
        model = b.exercise(code, regs, stack, 0x74000000, 1, 2)
        self.assertEqual(model.regs['eax'], 0x80FFFFFF)
        self.assertEqual(model.regs['esp'], regs['esp']+4)
        self.assertEqual(model.read(regs['esp']-4), regs['esp'])

    def test_descriptor_has_nonzero_base_and_present_32bit_data_flags(self):
        raw = b.descriptor(0x74123000)
        limit, low, mid, access, flags, high = struct.unpack('<HHBBBB', raw)
        self.assertEqual(low | (mid << 16) | (high << 24), 0x74123000)
        self.assertEqual((limit, access, flags), (0xFFFF, 0x93, 0xCF))
        self.assertEqual(b.descriptor(0, True)[5], 0x9B)
        for base in (-1, 1 << 32):
            with self.assertRaises(ValueError):
                b.descriptor(base)

    def test_unsupported_control_and_bounds_reject(self):
        regs, stack = self.fixture()
        for code in (bytes.fromhex('e800000000c3'), bytes.fromhex('eb00c3'),
                     bytes.fromhex('ccc3'), bytes.fromhex('90c3'), b'\xc2\x04\x00', b'\xb8'):
            with self.subTest(code=code), self.assertRaises(ValueError):
                b.exercise(code, regs, stack, 0x74000000, 1, 2)
        # Unmapped data, FS beyond head, cookie store and underflowing PUSH.
        for code in ('a100000000c3', '64a104000000c3', 'a340f504a1c3',
                     'bc0000007050c3'):
            with self.subTest(code=code), self.assertRaises(ValueError):
                b.exercise(bytes.fromhex(code), regs, stack, 0x74000000, 1, 2)
        with self.assertRaises(ValueError):
            b.exercise(b'\xc3', regs, stack, 0, 1, 2)
        with self.assertRaises(ValueError):
            b.exercise(bytes.fromhex('508d642404c3'), regs, stack, 0x74000000, 1, 2, budget=1)

    def test_register_or_memory_oracle_corruption_cannot_match(self):
        regs, stack = self.fixture()
        original = b.Model.step
        for kind in ('reg', 'memory', 'pc'):
            def corrupt(model, insn):
                original(model, insn)
                if kind == 'reg':
                    model.regs['ebx'] ^= 1
                elif kind == 'memory':
                    model.pages[b.STACK][0] ^= 1
                else:
                    model.pc ^= 1
            with self.subTest(kind=kind), patch.object(b.Model, 'step', corrupt), self.assertRaises(ValueError):
                b.exercise(b'\xc3', regs, stack, 0x74000000, 1, 2)

    def test_private_output_and_pin_guards(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(b, 'ROOT', Path(temp)):
            root = Path(temp)
            private = root/'work/recomp-bench'
            private.mkdir(parents=True)
            outside = root/'outside'
            outside.mkdir()
            (private/'link').symlink_to(outside)
            for path in (outside/'out', private/'link/out'):
                with self.assertRaises(ValueError):
                    b.run(path, root/'index')
            output = private/'out'
            with patch.object(b, 'digest', return_value='wrong'), self.assertRaises(ValueError):
                b.run(output, root/'index')
            self.assertFalse(output.exists())
            output.write_text('preserved')
            with self.assertRaises(FileExistsError):
                b.run(output, root/'index')
            self.assertEqual(output.read_text(), 'preserved')


if __name__ == '__main__':
    unittest.main()
