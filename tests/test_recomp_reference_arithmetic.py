"""Authored instruction streams testing shared reference arithmetic composition.

No original code, private image, captured state or native-game claim.
"""
import importlib.util
from pathlib import Path
import struct
import unittest

PATH = Path(__file__).resolve().parents[1]/'scripts/recomp/execute_cache_dispatch.py'
spec = importlib.util.spec_from_file_location('reference_arithmetic', PATH)
c = importlib.util.module_from_spec(spec); spec.loader.exec_module(c)


class ReferenceArithmeticTests(unittest.TestCase):
    def execute(self, code, *, integer=False, calloc=False, value=21, pointer=None):
        from capstone import Cs, CS_ARCH_X86, CS_MODE_32
        entry = c.BASE+0x2000
        regs = dict.fromkeys(c.REGS, 0)
        regs.update(eax=value, ecx=3, esi=c.DATA_PAGES[2] if pointer is None else pointer,
                    esp=c.DATA_PAGES[0]+0x800)
        pages = {p:bytearray(4096) for p in c.PAGES}
        struct.pack_into('<I', pages[c.DATA_PAGES[0]], 0x800, c.RETURN)
        struct.pack_into('<I', pages[c.DATA_PAGES[2]], 0, 7)
        code += b'\xc3'
        md = Cs(CS_ARCH_X86, CS_MODE_32); md.detail = True
        nodes = {i.address:i for i in md.disasm(code, entry)}
        result, seen = c.reference(nodes, {entry:code+bytes(4096-len(code))},
            entry, regs, pages, checked_integer_multiply=integer,
            checked_calloc_arithmetic=calloc)
        expected = dict(regs, esp=regs['esp']+4)
        return result, seen, expected, pages

    def test_both_options_execute_mixed_forms_in_one_cpu(self):
        # Authored IMUL eax,eax,3; DIV ecx; IMUL eax,[esi].
        result, seen, expected, pages = self.execute(
            b'\x6b\xc0\x03\xf7\xf1\x0f\xaf\x06', integer=True, calloc=True)
        expected['eax'] = 147
        self.assertEqual(result['regs'], [expected[r] for r in c.REGS])
        self.assertEqual(len(seen), 4)
        self.assertEqual(result['pages'], b''.join(pages[p] for p in c.PAGES).hex())

    def test_both_options_accept_either_order_and_signed_immediates(self):
        for value in (0, 1, 0xffffffff, 0x7fffffff, 0x80000000):
            for code in (b'\x6b\xc0\xfd\x0f\xaf\x06',
                         b'\x0f\xaf\x06\x69\xc0\xfd\xff\xff\xff'):
                with self.subTest(value=value, code=code.hex()):
                    result, _, expected, _ = self.execute(code, integer=True, calloc=True, value=value)
                    expected['eax'] = (value*-3*7)&0xffffffff
                    self.assertEqual(result['regs'], [expected[r] for r in c.REGS])

    def test_single_options_retain_their_own_exact_form(self):
        for code, options, product in ((b'\x6b\xc0\x03', {'integer':True}, 63),
                                       (b'\x0f\xaf\x06', {'calloc':True}, 147),
                                       (b'\xf7\xf1', {'calloc':True}, 7)):
            result, _, expected, _ = self.execute(code, **options)
            expected['eax'] = product
            self.assertEqual(result['regs'], [expected[r] for r in c.REGS])

    def test_default_and_opposite_option_still_reject(self):
        for code, opposite in ((b'\x6b\xc0\x03', {'calloc':True}),
                               (b'\x0f\xaf\x06', {'integer':True}),
                               (b'\xf7\xf1', {'integer':True})):
            for options in ({}, opposite):
                with self.subTest(code=code.hex(), options=options), self.assertRaises(ValueError):
                    self.execute(code, **options)

    def test_both_options_do_not_admit_other_multiply_or_divide_forms(self):
        for code in (b'\xf7\xe8', b'\xf7\xe0', b'\x0f\xaf\xc1',
                     b'\x6b\x06\x03', b'\xf7\x36', b'\xf7\xf9',
                     b'\x66\x0f\xaf\x06', b'\x66\x6b\xc0\x03',
                     b'\x64\x0f\xaf\x06', b'\x67\x0f\xaf\x06'):
            with self.subTest(code=code.hex()), self.assertRaises(ValueError):
                self.execute(code, integer=True, calloc=True)

    def test_composed_memory_form_retains_span_and_segment_validation(self):
        for pointer in (0, c.DATA_PAGES[2]+1, c.DATA_PAGES[2]+4094,
                        c.DATA_PAGES[2]+4096):
            with self.subTest(pointer=pointer), self.assertRaises(ValueError):
                self.execute(b'\x6b\xc0\x03\x0f\xaf\x06',
                             integer=True, calloc=True, pointer=pointer)
        # Data pages aren't the only readable domain: image pages stay readable.
        result, _, expected, _ = self.execute(b'\x0f\xaf\x06', integer=True,
                                            calloc=True, pointer=c.IMAGE_PAGES[1])
        expected['eax'] = 0
        self.assertEqual(result['regs'], [expected[r] for r in c.REGS])


if __name__ == '__main__': unittest.main()
