"""Authored ABI controls only; no private original-code fixture opened."""
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
import ptd_query_probe as p
r = p.r


class QueryProbeTests(unittest.TestCase):
    def test_tail_fallback_keeps_original_frame(self):
        s = p.oracle(0, r.NEG, 0x80000000)
        self.assertEqual(s['events'][0][1], [33, p.NAME, p.BEGIN, p.END])
        self.assertEqual(s['events'][-1][0:4],
                         ('tls', [0x80000000], r.RETURN-r.BASE, r.SP))
        self.assertEqual(s['registers'][0], r.NEG)
        self.assertEqual(s['registers'][7], r.SP+8)
        self.assertEqual(s['flags'], 0x444)
        self.assertEqual(struct.unpack_from('<II', s['stack'], r.SP-r.STACK),
                         (r.RETURN, 0x80000000))

    def test_dynamic_guard_and_full_word_result(self):
        for result in (0, 1, 0x80000000, r.NEG):
            s = p.oracle(p.FLS, result, r.NEG, clobber=True)
            self.assertEqual([e[0] for e in s['events']], ['resolve', 'guard', 'fls'])
            self.assertEqual(s['events'][1][2:], (0x8480EF, r.SP-16, p.FLS))
            self.assertEqual(s['events'][2][1:], ([r.NEG], 0x8480F1, r.SP-16, p.FLS))
            self.assertEqual(s['registers'][0], result)
            self.assertEqual(s['registers'][2:4], [0xFEEDFACE, 0xDEADBEEF])
            original, _ = p.free.inputs(r.NEG, 0)
            for n in (1, 4, 5, 6):
                self.assertEqual(s['registers'][n], original[n])

    def test_authored_tail_provider_and_pop4(self):
        # Authored indirect jump: the provider must consume caller's one argument.
        code = b'\xff\x25'+struct.pack('<I', p.TLS_SLOT)
        state = p.exercise(code, 0, r.NEG, 0x80000000, clobber=True)
        self.assertEqual(state['events'], [('tls', [0x80000000], r.RETURN-r.BASE, r.SP,
                                           p.free.inputs(0x80000000, 0)[0][2])])
        self.assertEqual(state['registers'][7], r.SP+8)
        wrong = p.exercise(code, 0, r.NEG, 0x80000000, provider_pop=0, clobber=True)
        with self.assertRaises(ValueError):
            r.verify(wrong, state)

    def test_authored_dynamic_provider_and_guard(self):
        code = b'\x68'+struct.pack('<I', 0x80000000)
        code += b'\xb9'+struct.pack('<I', p.FLS)
        code += b'\xff\x15'+struct.pack('<I', p.GUARD_SLOT)
        code += b'\xff\xd1\xc2\x04\x00'
        s = p.exercise(code, p.FLS, r.NEG, 0, clobber=True)
        self.assertEqual([e[0] for e in s['events']], ['guard', 'fls'])
        self.assertEqual(s['events'][0][-1], p.FLS)
        self.assertEqual(s['events'][1][1], [0x80000000])
        self.assertEqual(s['registers'][7], r.SP+8)
        with self.assertRaises((ValueError, p.UcError)):
            p.exercise(code, p.FLS, 1, 0, provider_pop=0)

    def test_authored_resolver_cdecl_cleanup(self):
        code = b''.join(b'\x68'+struct.pack('<I', n) for n in (4, 3, 2, 1))
        code += b'\xb8'+struct.pack('<I', p.RESOLVE)+b'\xff\xd0\x83\xc4\x10\xc2\x04\x00'
        s = p.exercise(code, p.FLS, 0, 0)
        self.assertEqual(s['events'][0][1], [1, 2, 3, 4])
        self.assertEqual(s['registers'][7], r.SP+8)
        with self.assertRaises((ValueError, p.UcError)):
            p.exercise(code, p.FLS, 0, 0, resolver_pop=16)

    def test_every_state_component_compared(self):
        s = p.oracle(p.FLS, 0x80000000, 0)
        for key in s:
            wrong = copy.deepcopy(s)
            if key == 'registers':
                wrong[key][4] ^= 1
            elif key == 'stack':
                data = bytearray(wrong[key]); data[0] ^= 1; wrong[key] = bytes(data)
            elif key == 'events':
                wrong[key].reverse()
            else:
                wrong[key] ^= 1
            with self.subTest(key=key), self.assertRaises(ValueError):
                r.verify(wrong, s)

    def test_bounded_decode_memory_and_invalid_inputs(self):
        for code in (b'\xeb\xfe', b'\xc2', b'\xa3'+struct.pack('<I', p.GUARD_SLOT)+b'\xc3'):
            with self.assertRaises(ValueError):
                p.exercise(code, 0, 0, 0)
        for target, result, index in ((123, 0, 0), (0, -1, 0), (0, 0, -1)):
            with self.assertRaises(ValueError):
                p.oracle(target, result, index)
        # Authored TEST ESI,ESI independently checks both oracle logic flag paths.
        for value in (0, p.FLS):
            code = b'\xbe'+struct.pack('<I', value)+b'\x85\xf6\xc2\x04\x00'
            self.assertEqual(p.exercise(code, 0, 0, 0)['flags'],
                             p.oracle(value, 0, 0)['flags'])

    def test_pin_failure_is_sanitized_and_readonly(self):
        with tempfile.TemporaryDirectory() as tmp:
            image = Path(tmp)/'secret.bin'
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
