"""Authored slow-path controls; no private original fixture opened."""
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
import ptd_lazy_probe as q
p, r = q.p, q.r


class LazyProbeTests(unittest.TestCase):
    def test_invalid_index_still_attempts_sentinel_without_query(self):
        state = q.oracle(r.NEG, 0, 0, 0, 7)
        self.assertEqual([e[0] for e in state['events']], ['get', 'write', 'set'])
        self.assertEqual(state['events'][1][1], [r.NEG, r.NEG])
        self.assertEqual(state['registers'][0], 0)
        self.assertEqual(state['flags'], 0x444)

    def test_allocation_failure_rolls_back_and_frees_null(self):
        state = q.oracle(3, 1, 0, 0, 7)
        self.assertEqual([(e[0], e[1]) for e in state['events']], [
            ('get', []), ('query', [3]), ('write', [3, r.NEG]),
            ('alloc', [1, 0x364]), ('write', [3, 0]), ('free', [0]), ('set', [7])])
        self.assertEqual(state['registers'][0], 0)

    def test_publish_failure_clears_before_free_and_skips_initialize(self):
        state = q.oracle(0, 1, 0x81234000, 0, r.NEG)
        self.assertEqual([(e[0], e[1]) for e in state['events'][4:]], [
            ('write', [0, 0x81234000]), ('write', [0, 0]),
            ('free', [0x81234000]), ('set', [r.NEG])])
        self.assertEqual(state['registers'][0], 0)

    def test_success_initializes_after_publication_and_frees_zero_not_pointer(self):
        for pointer in (0x81234000, r.NEG):
            state = q.oracle(0x80000000, 0x80000000, pointer, 0x80000000, 7)
            self.assertEqual([(e[0], e[1]) for e in state['events'][4:]], [
                ('write', [0x80000000, pointer]),
                ('initialize', [pointer, q.LOCALE]), ('free', [0]), ('set', [7])])
            # Unlike existing-value path, newly allocated FFFFFFFF is NOT normalized.
            self.assertEqual(state['registers'][0], pointer)

    def test_saved_state_and_volatile_clobbers(self):
        for claim, pointer, publish in ((0, 0, 0), (1, 0, 0), (1, 1, 0), (1, 1, 1)):
            regs, stack, _ = p.init.inputs(1)
            state = q.oracle(0, claim, pointer, publish, 7, 1, clobber=True)
            for n in (1, 4, 5, 6):
                self.assertEqual(state['registers'][n], regs[n])
            self.assertEqual(state['registers'][2:4], [0xFEEDFACE, 0xDEADBEEF])
            self.assertEqual(state['registers'][7], r.SP+4)
            self.assertEqual(state['stack'][:r.SP-r.STACK-32],
                             bytes(stack[:r.SP-r.STACK-32]))

    def test_authored_setter_stdcall_and_allocator_cdecl(self):
        for target, args, pop, kind in ((q.WRITE, [7, r.NEG], 8, 'write'),
                                        (q.ALLOC, [1, 0x364], 0, 'alloc')):
            code = b''.join(b'\x68'+struct.pack('<I', a) for a in reversed(args))
            code += b'\xb8'+struct.pack('<I', target)+b'\xff\xd0'
            if pop == 0:
                code += b'\x83\xc4\x08'
            code += b'\xc3'
            state = q.exercise(code, 7, 1, 0x81234000, 1, 0)
            self.assertEqual(state['events'][0][:2], (kind, args))
            self.assertEqual(state['registers'][7], r.SP+4)
            wrong = {'write_pop': 0} if pop else {'alloc_pop': 8}
            with self.assertRaises((ValueError, q.UcError)):
                q.exercise(code, 7, 1, 0x81234000, 1, 0, **wrong)

    def test_budget_decode_immutable_and_full_state_comparison(self):
        for code in (b'\xeb\xfe', b'\xc2', b'\xa3'+struct.pack('<I', p.INDEX)+b'\xc3'):
            with self.assertRaises(ValueError):
                q.exercise(code, 0, 1, 1, 1, 0)
        state = q.oracle(0, 1, 1, 1, 7)
        for key in state:
            wrong = copy.deepcopy(state)
            if key == 'events':
                wrong[key] = []
            elif key == 'registers':
                wrong[key][4] ^= 1
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
                self.assertEqual(q.main([]), 2)
            self.assertEqual(out.getvalue(), '')
            self.assertNotIn(str(image), err.getvalue())
            self.assertNotIn('private fixture', err.getvalue())
            self.assertEqual(image.read_bytes(), b'private fixture')


if __name__ == '__main__':
    unittest.main()
