"""Authored six-body controls, never reads proprietary inputs."""
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
import heap_hot_composed_probe as p
from test_heap_error_composed_probe import fixtures as four, args, call
from test_provider_hot_composed_probe import fixtures as provider_fixtures
r = p.r


def fixtures(dynamic):
    codes = four()
    codes.update(provider_fixtures(dynamic))
    return codes


class HeapHotComposedTests(unittest.TestCase):
    def test_authored_six_body_chain_hot_decode_and_error_store(self):
        for dynamic in (False, True):
            value = p.FLS if dynamic else r.NEG
            for cookie in (0, 1, 31, 32, 0x80000000, r.NEG):
                for clobber in (False, True):
                    state = p.exercise(fixtures(dynamic), *args(), cookie,
                                       p.hot.encode(value, cookie), 7, clobber=clobber)
                    self.assertEqual(state['registers'][0], p.chain.PTD+16)
                    self.assertEqual(state['registers'][7], r.SP+4)
                    self.assertEqual(state['slots'][p.chain.PTD+16], 0x80000000)
                    self.assertEqual(state['slots'][p.chain.accessor.FALLBACK], p.chain.SENTINEL)
                    self.assertEqual(state['lastError'], 19)
                    self.assertEqual(state['registers'][2:4], [0xFEEDFACE, 0xDEADBEEF]
                                     if clobber else [value if dynamic else cookie & 31, value])
                    self.assertEqual([e[0] for e in state['events']],
                                     ['get', 'resolve']+(['guard', 'fls'] if dynamic else ['tls'])+['set'])
                    self.assertEqual(state['cacheWords'], [cookie, p.hot.encode(value, cookie)])

    def test_oracle_deeper_saves_and_nonopaque_tls_scratch(self):
        for value in (p.FLS, r.NEG):
            state = p.oracle(*args(), value, 31, 7)
            initial, _ = p.chain.release.callback.inputs(1, 7)
            self.assertEqual(struct.unpack_from('<III', state['stack'], r.SP-r.STACK-72),
                             (0x80000000, initial[1], r.SP-36))
            self.assertEqual(state['registers'][2:4], [value if value == p.FLS else 31, value])
            self.assertEqual(state['events'][3],
                             ('resolve', [33, p.query.NAME, p.query.BEGIN, p.query.END],
                              0x8480DB, r.SP-60))
            self.assertEqual(state['lastError'], 19)
            self.assertEqual(state['slots'][p.chain.PTD+16], 0x80000000)

    def test_nonerror_paths_do_not_gain_nested_frames(self):
        for context, result in ((0, 0), (1, 1)):
            inputs = list(args()); inputs[0], inputs[2] = context, result
            state = p.oracle(*inputs, r.NEG, 31)
            cache = state.pop('cacheWords')
            self.assertEqual(cache, [31, p.hot.encode(r.NEG, 31)])
            self.assertEqual(state, p.chain.oracle(*inputs))

    def test_cleanup_restore_and_budget_controls(self):
        codes = fixtures(True)
        state = p.exercise(codes, *args(), 31, p.hot.encode(p.FLS, 31))
        for options in ({'storage_pop': 0}, {'set_pop': 0}, {'restore': False}, {'budget': 1}):
            with self.assertRaises((ValueError, p.UcError)):
                r.verify(p.exercise(codes, *args(), 31, p.hot.encode(p.FLS, 31), **options), state)
        for index, pointer in ((r.NEG, p.chain.PTD), (0, 0)):
            inputs = list(args()); inputs[4:6] = index, pointer
            with self.assertRaises(ValueError):
                p.exercise(codes, *inputs, 31, p.hot.encode(p.FLS, 31))

    def test_cold_unknown_and_instruction_boundaries_reject(self):
        codes = fixtures(True)
        for value in (0, p.FLS+4):
            with self.assertRaises((ValueError, p.UcError)):
                p.exercise(codes, *args(), 31, p.hot.encode(value, 31))
        for code in (b'\xeb\xfe', b'\xc2',
                     call(p.hot.ENTRY, r.BASE+0x82A212)):
            wrong = dict(codes); wrong[p.hot.ENTRY] = code
            with self.assertRaises((ValueError, p.UcError)):
                p.exercise(wrong, *args(), 31, p.hot.encode(p.FLS, 31))
        # A target inside a decoded MOV must not become an instruction entry.
        wrong = dict(codes)
        wrong[p.hot.ENTRY] = b'\xb8\x90\x90\xc3\x90'+b'\xeb\xfa'
        with self.assertRaises(ValueError):
            p.exercise(wrong, *args(), 31, p.hot.encode(p.FLS, 31))

    def test_immutable_pages_and_every_output_component(self):
        codes = fixtures(True)
        for address in (p.hot.COOKIE, p.hot.CACHE+33*4, p.chain.PTD+12,
                        p.chain.accessor.FALLBACK+4, p.chain.provider.INDEX):
            wrong = dict(codes)
            wrong[p.hot.ENTRY] = b'\xa3'+struct.pack('<I', address)+b'\xc3'
            with self.assertRaises((ValueError, p.UcError)):
                p.exercise(wrong, *args(), 31, p.hot.encode(p.FLS, 31))
        state = p.oracle(*args(), p.FLS, 31)
        for key in state:
            wrong = copy.deepcopy(state)
            if key in ('registers', 'cacheWords'):
                wrong[key][0] ^= 1
            elif key == 'stack':
                data = bytearray(wrong[key]); data[r.SP-r.STACK-72] ^= 1
                wrong[key] = bytes(data)
            elif key == 'events':
                wrong[key].reverse()
            elif key == 'slots':
                wrong[key][p.chain.accessor.FALLBACK] ^= 1
            else:
                wrong[key] ^= 1
            with self.subTest(key=key), self.assertRaises(ValueError):
                r.verify(wrong, state)

    def test_private_pin_is_readonly_sanitized(self):
        with tempfile.TemporaryDirectory() as tmp:
            image = Path(tmp)/'secret.bin'; image.write_bytes(b'private fixture')
            out, err = io.StringIO(), io.StringIO()
            with patch.object(r, 'IMAGE', image), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                self.assertEqual(p.main([]), 2)
            self.assertEqual(out.getvalue(), '')
            self.assertNotIn(str(image), err.getvalue())
            self.assertEqual(image.read_bytes(), b'private fixture')


if __name__ == '__main__':
    unittest.main()
