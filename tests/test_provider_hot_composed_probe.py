"""Public path-specific authored x86 fixtures; no original bytes required."""
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
import provider_hot_composed_probe as p
from test_storage_hot_composed_probe import fixtures as storage_fixtures
r = p.r


def word(value):
    return struct.pack('<I', value)


def fixtures(dynamic, sentinel=False):
    codes = storage_fixtures(dynamic)
    code = bytearray(b'\x53\x57\x90\x90\xff\x15'+word(p.provider.GET_SLOT))
    assert p.provider.ENTRY+len(code) == r.BASE+0x846028
    code += b'\x89\xc7\xa1'+word(p.provider.INDEX)+b'\x50'+b'\x90'*5
    call = p.provider.ENTRY+len(code)
    code += b'\xe8'+word((p.query.ENTRY-call-5) & r.NEG)
    assert p.provider.ENTRY+len(code) == r.BASE+0x84603A
    code += b'\x89\xc3'
    if sentinel:
        code += b'\x31\xdb'
    code += b'\x85\xdb'
    jump = p.provider.ENTRY+len(code)
    code += b'\xe9'+word((r.BASE+0x8460C3-jump-5) & r.NEG)
    code += b'\x90'*(0x8460C3-p.provider.RVA-len(code))
    code += b'\x57\xff\x15'+word(p.provider.SET_SLOT)
    assert p.provider.ENTRY+len(code) == r.BASE+0x8460CA
    code += b'\x89\xd8\x5f\x5b\xc3'
    codes[p.provider.ENTRY] = bytes(code)
    return codes


class ProviderHotComposedTests(unittest.TestCase):
    def test_authored_three_body_full_state(self):
        for dynamic in (False, True):
            value = p.query.FLS if dynamic else r.NEG
            for cookie in (0, 1, 31, 32, 0x80000000, r.NEG):
                for pointer in (1, 0x80000000, r.NEG):
                    for index in (0, 0x80000000, r.NEG-1):
                        for error in (0, r.NEG):
                            for clobber in (False, True):
                                codes = fixtures(dynamic, pointer == r.NEG)
                                r.verify(p.exercise(codes, cookie, p.hot.encode(value, cookie),
                                                    pointer, index, error, 7, clobber=clobber),
                                         p.oracle(value, cookie, pointer, index, error, 7,
                                                  clobber=clobber))

    def test_dead_saves_and_tls_volatiles_are_not_opaque_query(self):
        state = p.oracle(r.NEG, 31, 1, 0, 19, 7)
        regs, _, _ = p.provider.init.inputs(7)
        self.assertEqual(struct.unpack_from('<III', state['stack'], r.SP-r.STACK-56),
                         (regs[4], regs[1], r.SP-20))
        self.assertEqual(state['registers'][2:4], [31, r.NEG])
        self.assertEqual(state['lastError'], 19)
        self.assertEqual(state['events'][-1], ('set', [19], 0x8460CA, r.SP-16))
        codes = fixtures(False)
        codes[p.query.ENTRY] = b'\xb8'+word(1)+b'\xc2\x04\x00'
        with self.assertRaises(ValueError):
            r.verify(p.exercise(codes, 31, p.hot.encode(r.NEG, 31), 1, 0, 19, 7), state)

    def test_index_and_cookie_share_immutable_page(self):
        index, cookie = 0x80000000, 31
        expected = p.oracle(p.r.NEG, cookie, 1, index, 0)
        page = p.provider.INDEX & ~4095
        self.assertEqual(page, p.hot.COOKIE & ~4095)
        self.assertEqual(struct.unpack_from('<I', expected['dataPages'][page],
                                            p.provider.INDEX-page)[0], index)
        self.assertEqual(struct.unpack_from('<I', expected['dataPages'][page],
                                            p.hot.COOKIE-page)[0], cookie)
        r.verify(p.exercise(fixtures(False), cookie, p.hot.encode(r.NEG, cookie),
                            1, index, 0), expected)

    def test_cleanup_restore_budget_and_immutable_controls(self):
        for dynamic in (False, True):
            value = p.query.FLS if dynamic else r.NEG
            codes = fixtures(dynamic)
            expected = p.oracle(value, 31, 1, 0, 19)
            for options in ({'storage_pop': 0}, {'set_pop': 0}, {'restore': False}, {'budget': 1}):
                with self.assertRaises((ValueError, p.UcError)):
                    r.verify(p.exercise(codes, 31, p.hot.encode(value, 31), 1, 0, 19,
                                        **options), expected)
            wrong = dict(codes)
            wrong[p.hot.ENTRY] = b'\xa3'+word(p.hot.COOKIE)+b'\xc3'
            with self.assertRaises((ValueError, p.UcError)):
                p.exercise(wrong, 31, 1, 1, 0, 19)
        for pointer, index in ((0, 0), (1, r.NEG)):
            with self.assertRaises(ValueError): p.oracle(p.query.FLS, 0, pointer, index, 0)
        with self.assertRaises(ValueError): p.oracle(0, 0, 1, 0, 0)

    def test_every_observed_component_required(self):
        expected = p.oracle(p.query.FLS, 31, 1, 0, 19)
        mutations = []
        for reg in range(8):
            s = copy.deepcopy(expected); s['registers'][reg] ^= 1; mutations.append(s)
        for key in ('flags', 'lastError'):
            s = copy.deepcopy(expected); s[key] ^= 1; mutations.append(s)
        for offset in (0, 2048-56, 2048-44, 2048-16, 4095):
            s = copy.deepcopy(expected); b = bytearray(s['stack']); b[offset] ^= 1
            s['stack'] = bytes(b); mutations.append(s)
        for i in range(len(expected['events'])):
            for field in range(4):
                s = copy.deepcopy(expected); e = list(s['events'][i])
                e[field] = 'bad' if field == 0 else [1] if field == 1 else e[field]+1
                s['events'][i] = tuple(e); mutations.append(s)
        for page in expected['dataPages']:
            s = copy.deepcopy(expected); b = bytearray(s['dataPages'][page]); b[-1] ^= 1
            s['dataPages'][page] = bytes(b); mutations.append(s)
        for state in mutations:
            with self.assertRaises(ValueError): r.verify(state, expected)

    def test_private_pin_is_readonly_and_sanitized(self):
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
