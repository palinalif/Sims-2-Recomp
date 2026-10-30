"""Public authored five-body composition controls; no private game input."""
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
import heap_storage_composed_probe as p
from test_heap_error_composed_probe import fixtures as four, args, call
r = p.r


def fixtures(dynamic=False):
    codes = four()
    if dynamic:
        code = b'\x6a\x03\xb9'+struct.pack('<I', p.FLS)
        code += b'\xff\x15'+struct.pack('<I', p.query.GUARD_SLOT)
        code += b'\xff\xd1\xc2\x04\x00'
    else:
        code = b'\xff\x25'+struct.pack('<I', p.query.TLS_SLOT)
    codes[p.query.ENTRY] = code
    return codes


class HeapStorageComposedTests(unittest.TestCase):
    def test_authored_five_body_chain_nested_and_tail_frames(self):
        for dynamic in (False, True):
            state = p.exercise(fixtures(dynamic), *args(), p.FLS if dynamic else 0,
                               clobber=True)
            self.assertEqual(state['registers'][0], p.chain.PTD+16)
            self.assertEqual(state['registers'][7], r.SP+4)
            self.assertEqual(state['slots'][p.chain.PTD+16], 0x80000000)
            self.assertEqual(state['slots'][p.chain.accessor.FALLBACK], p.chain.SENTINEL)
            self.assertEqual(state['lastError'], 20)  # authored caller has no restore
            self.assertEqual(state['events'][-1][1], [3])
            # Tail path uses provider's original return; dynamic has its own call.
            self.assertEqual(state['events'][-1][2],
                             p.query.RVA+15 if dynamic else p.chain.provider.RVA+7)
            self.assertEqual(state['events'][-1][3], r.SP-(28 if dynamic else 20))
            if dynamic:
                preserved = p.exercise(fixtures(True), *args(), p.FLS)
                self.assertEqual(preserved['registers'][2], p.FLS)
            with self.assertRaises((ValueError, p.UcError)):
                p.exercise(fixtures(dynamic), *args(), p.FLS if dynamic else 0,
                           provider_pop=0)

    def test_authored_resolver_cdecl_and_guard_target_contract(self):
        codes = fixtures()
        code = b''.join(b'\x68'+struct.pack('<I', n) for n in
                        (p.query.END, p.query.BEGIN, p.query.NAME, 33))
        code += call(p.query.ENTRY+len(code), p.query.RESOLVE)
        code += b'\x83\xc4\x10\xff\x25'+struct.pack('<I', p.query.TLS_SLOT)
        codes[p.query.ENTRY] = code
        state = p.exercise(codes, *args(), 0)
        self.assertEqual(state['events'][0][1],
                         [33, p.query.NAME, p.query.BEGIN, p.query.END])
        self.assertEqual(state['lastError'], 21)  # resolver AND storage disturbance
        with self.assertRaises((ValueError, p.UcError)):
            p.exercise(codes, *args(), 0, resolver_pop=16)
        codes = fixtures(True)
        codes[p.query.ENTRY] = codes[p.query.ENTRY].replace(
            struct.pack('<I', p.FLS), struct.pack('<I', p.FLS+4))
        with self.assertRaises(ValueError):
            p.exercise(codes, *args(), p.FLS)

    def test_oracle_frames_and_restored_error(self):
        for target in (0, p.FLS):
            state = p.oracle(*args(), target)
            self.assertEqual(state['lastError'], 19)
            self.assertEqual(state['registers'][2], target if target else 19)
            self.assertEqual(p.oracle(*args(), target, clobber=True)['registers'][2],
                             0xFEEDFACE)
            self.assertEqual(state['events'][-1], ('set', [19], 0x8460CA, r.SP-32))
            self.assertEqual(state['events'][3],
                             ('resolve', [33, p.query.NAME, p.query.BEGIN, p.query.END],
                              0x8480DB, r.SP-60))
            event = state['events'][-2]
            self.assertEqual(event, ('fls', [3], 0x8480F1, r.SP-48) if target else
                             ('tls', [3], 0x84603A, r.SP-32))
            self.assertEqual(struct.unpack_from('<II', state['stack'], r.SP-r.STACK-40),
                             (0x80000000, r.SP-4))

    def test_authored_last_error_disturbance_and_restore(self):
        codes = fixtures()
        # Public caller explicitly restores error after the query path.
        code = call(p.chain.release.ENTRY, p.chain.provider.ENTRY)
        code += b'\x6a\x13\xb8'+struct.pack('<I', p.SET)+b'\xff\xd0\xc3'
        codes[p.chain.release.ENTRY] = code
        state = p.exercise(codes, *args(), 0)
        self.assertEqual(state['lastError'], 19)
        wrong = p.exercise(codes, *args(), 0, restore=False)
        self.assertEqual(wrong['lastError'], 20)
        with self.assertRaises(ValueError):
            r.verify(wrong, state)

    def test_oracle_nonerror_paths_have_no_storage_events(self):
        for context, result in ((0, 0), (1, 0x80000000)):
            inputs = list(args()); inputs[0], inputs[2] = context, result
            for target in (0, p.FLS):
                self.assertEqual(p.oracle(*inputs, target), p.chain.oracle(*inputs))

    def test_every_component_compared_and_slow_paths_reject(self):
        state = p.oracle(*args(), p.FLS)
        for key in state:
            wrong = copy.deepcopy(state)
            if key == 'registers':
                wrong[key][0] ^= 1
            elif key == 'stack':
                data = bytearray(wrong[key]); data[-1] ^= 1; wrong[key] = bytes(data)
            elif key == 'events':
                wrong[key].reverse()
            elif key == 'slots':
                wrong[key][p.chain.accessor.FALLBACK] ^= 1
            else:
                wrong[key] ^= 1
            with self.subTest(key=key), self.assertRaises(ValueError):
                r.verify(wrong, state)
        for index, pointer in ((r.NEG, p.chain.PTD), (0, 0)):
            inputs = list(args()); inputs[4:6] = index, pointer
            with self.assertRaises(ValueError):
                p.exercise(fixtures(), *inputs, 0)

    def test_bounds_immutable_neighbors_and_unknown_resolver_reject(self):
        for code in (b'\xeb\xfe', b'\xc2',
                     b'\xa3'+struct.pack('<I', p.chain.PTD+12)+b'\xc3',
                     call(p.query.ENTRY, r.BASE+0x82A212)):
            codes = fixtures(); codes[p.query.ENTRY] = code
            with self.assertRaises((ValueError, p.UcError)):
                p.exercise(codes, *args(), 0)
        codes = fixtures(); del codes[p.query.ENTRY]
        with self.assertRaises(ValueError):
            p.exercise(codes, *args(), 0)

    def test_pin_failure_is_sanitized_readonly(self):
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
