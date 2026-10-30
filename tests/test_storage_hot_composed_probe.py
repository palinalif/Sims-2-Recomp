"""Public independent authored bodies; no owner-only image required."""
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
import storage_hot_composed_probe as p
r = p.r


def word(value):
    return struct.pack('<I', value)


def fixtures(dynamic):
    # Path-specific authored selector, with NOPs to anchor observable returns.
    # No original bytes are read/copied; conditional selection is tested privately.
    code = bytearray(b'\x55\x89\xe5\x56\x90\x90')
    for value in (p.query.END, p.query.BEGIN, p.query.NAME):
        code += b'\x68'+word(value)
    code += b'\x6a\x21'
    call = p.query.ENTRY+len(code)
    code += b'\xe8'+word((p.hot.ENTRY-call-5) & r.NEG)
    assert p.query.ENTRY+len(code) == r.BASE+0x8480DB
    code += b'\x83\xc4\x10\x89\xc6\x85\xf6'
    if dynamic:
        code += b'\xff\x75\x08\x89\xf1\x90\x90'
        code += b'\xff\x15'+word(p.query.GUARD_SLOT)
        assert p.query.ENTRY+len(code) == r.BASE+0x8480EF
        code += b'\xff\xd1\x5e\x5d\xc2\x04\x00'
    else:
        code += b'\x5e\x5d\xff\x25'+word(p.query.TLS_SLOT)
    # Independent authored decoder: XOR before loading count, no cold branch.
    resolver = b'\x55\x89\xe5\x53\x56\x8b\x45\x08'
    resolver += b'\x8b\x14\x85'+word(p.hot.CACHE)
    resolver += b'\x33\x15'+word(p.hot.COOKIE)
    resolver += b'\x8b\x0d'+word(p.hot.COOKIE)+b'\x83\xe1\x1f\xd3\xca'
    resolver += b'\x89\xd0'
    if not dynamic:
        resolver += b'\x31\xc0'
    resolver += b'\x5e\x5b\x5d\xc3'
    return {p.query.ENTRY: bytes(code), p.hot.ENTRY: resolver}


class StorageHotComposedTests(unittest.TestCase):
    def test_authored_two_bodies_match_composed_full_state_oracle(self):
        for dynamic in (False, True):
            codes = fixtures(dynamic)
            value = p.query.FLS if dynamic else r.NEG
            for cookie in (0, 1, 31, 32, 0x12345678, r.NEG):
                for result in (0, 0x80000000, r.NEG):
                    for index in (0, 0x80000000, r.NEG):
                        for clobber in (False, True):
                            with self.subTest(dynamic=dynamic, cookie=cookie, result=result,
                                              index=index, clobber=clobber):
                                r.verify(p.exercise(codes, cookie, p.hot.encode(value, cookie),
                                                    result, index, 7, clobber=clobber),
                                         p.oracle(value, cookie, result, index, 7, clobber=clobber))

    def test_nested_saved_words_and_endpoint_volatile_state(self):
        for value in (p.query.FLS, r.NEG):
            s = p.oracle(value, 31, 7, 0x80000000, 7)
            initial, _ = p.query.free.inputs(0x80000000, 7)
            self.assertEqual(struct.unpack_from('<III', s['stack'], r.SP-r.STACK-40),
                             (initial[4], initial[1], r.SP-4))
            if value == r.NEG:
                self.assertEqual(s['events'][-1]['registers'][2:4], [31, r.NEG])
                self.assertEqual(s['events'][-1]['registers'][7], r.SP)
            else:
                self.assertEqual(s['events'][1]['registers'][2:4], [p.query.FLS, value])
                self.assertEqual(s['events'][-1]['registers'][7], r.SP-16)
            self.assertEqual(s['registers'][3], value)

    def test_every_observed_component_mutation_rejects(self):
        expected = p.oracle(p.query.FLS, 31, 1, 0)
        mutations = []
        for i in range(8):
            s = copy.deepcopy(expected); s['registers'][i] ^= 1; mutations.append(s)
        for bit in (1, 4, 64, 128, 1024, 2048):
            s = copy.deepcopy(expected); s['flags'] ^= bit; mutations.append(s)
        for offset in (0, 2048-40, 2048-28, 2048, 4095):
            s = copy.deepcopy(expected); b = bytearray(s['stack']); b[offset] ^= 1
            s['stack'] = bytes(b); mutations.append(s)
        for event in range(3):
            for reg in range(8):
                s = copy.deepcopy(expected); s['events'][event]['registers'][reg] ^= 1
                mutations.append(s)
            for key in ('flags', 'returnRva'):
                s = copy.deepcopy(expected); s['events'][event][key] ^= 1; mutations.append(s)
            s = copy.deepcopy(expected); s['events'][event]['kind'] = 'bad'; mutations.append(s)
            s = copy.deepcopy(expected); s['events'][event]['args'].append(1); mutations.append(s)
        for page in expected['dataPages']:
            for offset in (0, 4095):
                s = copy.deepcopy(expected); b = bytearray(s['dataPages'][page]); b[offset] ^= 1
                s['dataPages'][page] = bytes(b); mutations.append(s)
        s = copy.deepcopy(expected); s['events'].reverse(); mutations.append(s)
        for s in mutations:
            with self.assertRaises(ValueError): r.verify(s, expected)

    def test_cleanup_opaque_resolver_and_immutable_controls(self):
        for dynamic in (False, True):
            value = p.query.FLS if dynamic else r.NEG
            codes = fixtures(dynamic)
            with self.assertRaises((ValueError, p.UcError)):
                r.verify(p.exercise(codes, 31, p.hot.encode(value, 31), 1, 0, provider_pop=0),
                         p.oracle(value, 31, 1, 0))
            # An opaque value-only resolver leaves scratch/volatile state wrong.
            wrong = dict(codes)
            wrong[p.hot.ENTRY] = b'\xb8'+word(p.query.FLS if dynamic else 0)+b'\xc3'
            with self.assertRaises(ValueError):
                r.verify(p.exercise(wrong, 31, p.hot.encode(value, 31), 1, 0),
                         p.oracle(value, 31, 1, 0))
        for resolver in (b'\xeb\xfe', b'\xc2',
                         b'\xa3'+word(p.hot.COOKIE)+b'\xc3',
                         b'\xa3'+word(p.hot.CACHE)+b'\xc3',
                         b'\xb8'+word(r.BASE+0x847DA1)+b'\xff\xd0'):
            codes = fixtures(True); codes[p.hot.ENTRY] = resolver
            with self.assertRaises((ValueError, p.UcError)):
                p.exercise(codes, 31, 1, 1, 0)
        with self.assertRaises(ValueError): p.oracle(0, 31, 1, 0)
        with self.assertRaises(ValueError): p.exercise(fixtures(True), 0, 1, 1, 0, budget=1)

    def test_pin_failure_is_readonly_and_sanitized(self):
        with tempfile.TemporaryDirectory() as tmp:
            image = Path(tmp)/'secret.bin'; image.write_bytes(b'private fixture')
            out, err = io.StringIO(), io.StringIO()
            with patch.object(r, 'IMAGE', image), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                self.assertEqual(p.main([]), 2)
            self.assertEqual(out.getvalue(), '')
            self.assertNotIn(str(image), err.getvalue())
            self.assertNotIn('private fixture', err.getvalue())
            self.assertEqual(image.read_bytes(), b'private fixture')


if __name__ == '__main__':
    unittest.main()
