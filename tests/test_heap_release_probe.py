"""Authored controls only; no original game fixture is opened."""
import contextlib
import copy
import io
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import heap_release_probe as p
r = p.r


class HeapReleaseProbeTests(unittest.TestCase):
    def test_null_preserves_eax_and_never_queries_errno(self):
        regs, _ = p.callback.inputs(0, 7)
        state = p.oracle(0, 0, 0, 5, 13, 7, clobber=True)
        self.assertEqual(state['events'], [])
        self.assertEqual(state['registers'][:7], regs[:7])
        self.assertEqual(state['slot'], 0x96969696)
        self.assertEqual(state['registers'][7], r.SP+4)

    def test_any_nonzero_result_succeeds_and_static_is_not_exempt(self):
        for context in (p.callback.STATIC, 1, 0x80000000, r.NEG):
            for result in (1, 0x80000000, r.NEG):
                state = p.oracle(context, 0, result, 5, 13)
                self.assertEqual(state['events'], [('heap_free', [0, 0, context], 0x8461D4, r.SP-20)])
                self.assertEqual(state['registers'][0], result)
                self.assertEqual(state['slot'], 0x96969696)

    def test_failure_order_mapping_store_and_not_boolean_return(self):
        for error, mapped in ((0, 0), (5, 13), (r.NEG, 0x80000000)):
            state = p.oracle(1, 7, 0, error, mapped)
            self.assertEqual([e[0] for e in state['events']],
                             ['heap_free', 'last_error', 'map_error', 'errno'])
            self.assertEqual(state['events'][2][1], [error])
            self.assertEqual(state['slot'], mapped)
            self.assertEqual(state['registers'][0], p.SLOT)
            self.assertEqual(state['registers'][2], error)
            clobbered = p.oracle(1, 7, 0, error, mapped, clobber=True)
            self.assertEqual(clobbered['registers'][2:4], [0xFEEDFACE, 0xDEADBEEF])
            self.assertEqual(clobbered['flags'], 0xC95 & 0xCC5)
            initial, _ = p.callback.inputs(1, 0)
            for index in (1, 4, 5, 6):
                self.assertEqual(clobbered['registers'][index], initial[index])

    def test_every_oracle_component_is_compared(self):
        state = p.oracle(1, 7, 0, 5, 13)
        for key in state:
            wrong = copy.deepcopy(state)
            if key == 'events':
                wrong[key].reverse()
            elif key == 'registers':
                wrong[key][4] ^= 1
            elif key == 'stack':
                value = bytearray(wrong[key]); value[0] ^= 1; wrong[key] = bytes(value)
            else:
                wrong[key] ^= 1
            with self.subTest(key=key), self.assertRaises(ValueError):
                r.verify(wrong, state)
        for value in (-1, r.NEG+1):
            with self.assertRaises(ValueError):
                p.oracle(1, 7, 0, 5, value)

    def test_authored_stdcall_and_cdecl_boundaries(self):
        # Synthetic caller pushes immediate 9/8/7, not the original body.
        code = b'\x6a\x09\x6a\x08\x6a\x07\xb8'+struct.pack('<I', p.FREE)+b'\xff\xd0\xc3'
        state = p.exercise(code, 1, 2, r.NEG, 5, 13)
        self.assertEqual(state['events'][0][1], [7, 8, 9])
        self.assertEqual(state['registers'][0], r.NEG)
        self.assertEqual(state['registers'][7], r.SP+4)
        with self.assertRaises((ValueError, p.UcError)):
            p.exercise(code, 1, 2, 0, 5, 13, free_pop=0)
        code = b'\x6a\x09\xb8'+struct.pack('<I', p.MAPPER)+b'\xff\xd0\x83\xc4\x04\xc3'
        self.assertEqual(p.exercise(code, 1, 2, 0, 5, 13)['registers'][7], r.SP+4)
        with self.assertRaises((ValueError, p.UcError)):
            p.exercise(code, 1, 2, 0, 5, 13, mapper_pop=4)

    def test_authored_budget_decode_and_errno_page_sentinels(self):
        self.assertEqual(p.exercise(b'\xc3', 1, 2, 0, 5, 13)['registers'][7], r.SP+4)
        for code in (b'\xeb\xfe', b'\xc2'):
            with self.assertRaises(ValueError):
                p.exercise(code, 1, 2, 0, 5, 13)
        for target in (p.ENTRY+128, p.HEAP, p.SLOT-4, p.SLOT+4):
            code = b'\xa3'+struct.pack('<I', target)+b'\xc3'
            with self.subTest(target=target), self.assertRaises(ValueError):
                p.exercise(code, 1, 2, 0, 5, 13)

    def test_pin_failure_sanitized_and_read_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            image = Path(tmp)/'private.bin'
            image.write_bytes(b'private fixture')
            out, err = io.StringIO(), io.StringIO()
            with patch.object(r, 'IMAGE', image), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                self.assertEqual(p.main([]), 2)
            self.assertEqual(out.getvalue(), '')
            self.assertNotIn(str(image), err.getvalue())
            self.assertNotIn('private fixture', err.getvalue())
            self.assertEqual(image.read_bytes(), b'private fixture')


if __name__ == '__main__':
    unittest.main()
