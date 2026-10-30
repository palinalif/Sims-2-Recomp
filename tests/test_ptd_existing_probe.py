"""Authored controls, no original-code fixture opened."""
import contextlib
import copy
import io
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'tools'))
import ptd_existing_probe as p
r = p.r


class ExistingProbeTests(unittest.TestCase):
    def test_sentinel_is_null_but_high_pointer_is_not(self):
        for pointer, result in ((1, 1), (0x80000000, 0x80000000),
                                (r.NEG-1, r.NEG-1), (r.NEG, 0)):
            state = p.oracle(0, pointer, 0x80000000)
            self.assertEqual(state['registers'][0], result)
            self.assertEqual(state['events'][1][1], [0])
            self.assertEqual(state['events'][2][1], [0x80000000])
        self.assertEqual(p.oracle(0, r.NEG, 0)['flags'], 0x444)
        self.assertEqual(p.oracle(0, 0x80000000, 0)['flags'], 0x484)

    def test_slow_paths_have_no_oracle(self):
        for index, pointer in ((r.NEG, 1), (0, 0)):
            with self.assertRaises(ValueError):
                p.oracle(index, pointer, 0)
        # Authored jump to slow-path region: reject, never silently return.
        target = r.BASE+0x84604E
        code = b'\xe9'+struct.pack('<i', target-p.ENTRY-5)
        with self.assertRaises(ValueError):
            p.exercise(code, 0, 1, 0)

    def test_saved_registers_and_full_stack(self):
        state = p.oracle(7, 1, r.NEG, 3, clobber=True)
        regs, stack, _ = p.init.inputs(3)
        for i in (1, 4, 5, 6):
            self.assertEqual(state['registers'][i], regs[i])
        self.assertEqual(state['registers'][2:4], [0xFEEDFACE, 0xDEADBEEF])
        self.assertEqual(state['registers'][7], r.SP+4)
        self.assertEqual(struct.unpack_from('<4I', state['stack'], r.SP-r.STACK-16),
                         (r.BASE+0x8460CA, r.NEG, regs[5], regs[1]))
        self.assertEqual(state['stack'][:r.SP-r.STACK-16], bytes(stack[:r.SP-r.STACK-16]))

    def test_authored_query_stdcall_and_volatile_effects(self):
        # Authored PUSH argument / CALL query / RET, not recovered body.
        code = b'\x6a\x07\xb8'+struct.pack('<I', p.QUERY)+b'\xff\xd0\xc3'
        state = p.exercise(code, 7, 0x80000000, 0, clobber=True)
        self.assertEqual(state['registers'][0], 0x80000000)
        self.assertEqual(state['registers'][7], r.SP+4)
        self.assertEqual(state['events'], [('query', [7], p.RVA+9, r.SP-8)])
        with self.assertRaises((ValueError, p.UcError)):
            p.exercise(code, 7, 1, 0, query_pop=0)

    def test_budget_decode_and_immutable_memory(self):
        self.assertEqual(p.exercise(b'\xc3', 0, 1, 0)['registers'][7], r.SP+4)
        for code in (b'\xeb\xfe', b'\xc2'):
            with self.assertRaises(ValueError):
                p.exercise(code, 0, 1, 0)
        with self.assertRaises(ValueError):
            p.exercise(b'\xa3'+struct.pack('<I', p.INDEX)+b'\xc3', 0, 1, 0)

    def test_every_state_component_compared(self):
        state = p.oracle(0, 1, 0)
        for key in state:
            wrong = copy.deepcopy(state)
            if key == 'events':
                wrong[key] = []
            elif key == 'registers':
                wrong[key][1] ^= 1
            elif key == 'stack':
                data = bytearray(wrong[key]); data[0] ^= 1; wrong[key] = bytes(data)
            else:
                wrong[key] ^= 1
            with self.subTest(key=key), self.assertRaises(ValueError):
                r.verify(wrong, state)

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
