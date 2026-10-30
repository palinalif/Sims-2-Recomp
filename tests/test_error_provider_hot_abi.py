"""Public native accessor/provider ABI composition; originals not required."""
import contextlib
import copy
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'tools'))
import check_error_provider_hot_abi as c
from test_provider_hot_composed_probe import fixtures as provider_fixtures
import struct
p, r = c.p, c.r


class ErrorProviderHotAbiTests(unittest.TestCase):
    native = os.environ.get('TS2_GUEST_ERROR_PROVIDER_HOT_ABI_PROBE', 'build/host/ts2_guest_error_provider_hot_abi_probe')
    runner = os.environ.get('TS2_GUEST_ERROR_PROVIDER_HOT_ABI_RUNNER')

    def run_cases(self, sweep, **kwargs):
        return c.run(sweep, self.native, self.runner, **kwargs)

    def test_full_composed_frame_all_counts_and_last_error(self):
        sweep = p.cases(); states = self.run_cases(sweep)
        self.assertEqual(len(sweep), len(states))
        for case, state in zip(sweep, states): c.verify(state, case)

    def test_authored_four_body_reference_and_wrap(self):
        for value in (p.query.FLS, r.NEG):
            for pointer in (1, 0x7FFFFFF0, 0xFFFFFFF0, r.NEG):
                for clobber in (False, True):
                    codes = provider_fixtures(value == p.query.FLS, pointer == r.NEG)
                    # Authored CALL/TEST/JZ/ADD/RET/MOV/RET fixture, no game bytes.
                    rel = (p.provider.ENTRY-p.accessor.ENTRY-5) & r.NEG
                    codes[p.accessor.ENTRY] = (b'\xe8'+struct.pack('<I', rel)+
                        b'\x85\xc0\x74\x04\x83\xc0\x10\xc3\xb8'+
                        struct.pack('<I', p.accessor.FALLBACK)+b'\xc3')
                    case = (value, 31, pointer, 0x80000000, 19, 7, clobber)
                    expected = p.oracle(*case[:-1], clobber=clobber)
                    r.verify(p.exercise(codes, 31, p.hot.encode(value, 31), pointer,
                                        0x80000000, 19, 7, clobber=clobber), expected)
                    c.verify(self.run_cases([case])[0], case)
                    if pointer == 1 and not clobber:
                        for options in ({'storage_pop': 0}, {'set_pop': 0},
                                        {'restore': False}, {'budget': 1}):
                            with self.assertRaises((ValueError, p.UcError)):
                                r.verify(p.exercise(codes, 31, p.hot.encode(value, 31),
                                                    pointer, 0x80000000, 19, 7,
                                                    **options), expected)
                    if pointer == 0xFFFFFFF0:
                        self.assertEqual(expected['registers'][0], 0)
                    if pointer == r.NEG:
                        self.assertEqual(expected['registers'][0], p.accessor.FALLBACK)

    def test_unavailable_endpoints_cleanup_exceptions_and_bounds_reject(self):
        for value in (p.query.FLS, r.NEG):
            case = (value, 31, 1, 0, 19, 7, False)
            for mode in (1, 3, 4, 5, 7, 8, 9):
                failed, state = self.run_cases([case], mode=mode)[0]
                self.assertEqual(failed, 1)
                kinds = [e[0] for e in state['events']]
                self.assertFalse('fls' in kinds and 'tls' in kinds)
                if mode in (1, 3, 4, 7, 8, 9): self.assertNotIn('set', kinds)
            for sp in (0, r.NEG-3, r.STACK, r.STACK+12):
                self.assertEqual(self.run_cases([case], sp=sp)[0][0], 1)
            # A lying authored Set endpoint cannot pass the independent oracle.
            bad = self.run_cases([case], mode=6)[0]
            with self.assertRaises(ValueError): c.verify(bad, case)
        case = (p.query.FLS, 31, 1, 0, 19, 7, False)
        failed, state = self.run_cases([case], mode=2)[0]
        self.assertEqual(failed, 1)
        self.assertEqual([e[0] for e in state['events']], ['get', 'resolve'])

    def test_cold_paths_fail_closed_without_restoration_claim(self):
        for value, pointer, index in ((0, 1, 0), (p.query.FLS+4, 1, 0),
                                       (p.query.FLS, 0, 0), (p.query.FLS, 1, r.NEG)):
            case = (value, 31, pointer, index, 19, 7, False)
            failed, state = self.run_cases([case])[0]
            self.assertEqual(failed, 1)
            self.assertNotIn('set', [e[0] for e in state['events']])
            self.assertEqual(state['dataPages'], p.pages(31, p.hot.encode(value, 31), index))
            if index == r.NEG:
                self.assertEqual(state['events'], [])
                _, stack, _ = p.provider.init.inputs(7)
                struct.pack_into('<I', stack, r.SP-r.STACK-4, r.BASE+0x831B1C)
                self.assertEqual(state['stack'], bytes(stack))
            if not value: self.assertNotIn('tls', [e[0] for e in state['events']])

    def test_every_observed_component_mutation_rejects(self):
        case = (p.query.FLS, 31, 1, 0x80000000, 19, 7, False)
        state = self.run_cases([case])[0]; c.verify(state, case)
        mutations = []
        for reg in range(8):
            s = copy.deepcopy(state); s[1]['registers'][reg] ^= 1; mutations.append(s)
        for bit in (1, 4, 16, 64, 128, 1024, 2048):
            s = copy.deepcopy(state); s[1]['flags'] ^= bit; mutations.append(s)
        s = copy.deepcopy(state); s[1]['lastError'] ^= 1; mutations.append(s)
        for i in range(len(state[1]['events'])):
            for field in range(4):
                s = copy.deepcopy(state); e = list(s[1]['events'][i])
                e[field] = 'bad' if field == 0 else [1] if field == 1 else e[field]+1
                s[1]['events'][i] = tuple(e); mutations.append(s)
        for key, address in (('stack', None), *(('dataPages', a) for a in state[1]['dataPages'])):
            for offset in (0, 2048-60, 2048-52, 2048-20, 2048-4, 4095):
                s = copy.deepcopy(state)
                b = bytearray(s[1][key] if address is None else s[1][key][address]); b[offset] ^= 1
                if address is None: s[1][key] = bytes(b)
                else: s[1][key][address] = bytes(b)
                mutations.append(s)
        for s in mutations:
            with self.assertRaises(ValueError): c.verify(s, case)

    def test_parser_rejects_partial_duplicate_extra_malformed(self):
        case = (r.NEG, 31, 1, 0, 19, 7, False)
        command = ([self.runner] if self.runner else [])+[str(Path(self.native).resolve())]
        done = subprocess.run(command, input=c.request(case), capture_output=True, text=True, timeout=60)
        self.assertEqual(done.returncode, 0); c.parse(done.stdout, 1)
        tokens = done.stdout.split()
        for bad in ('', done.stdout+done.stdout, done.stdout+' 0', ' '.join(tokens[:-1]),
                    '-1 '+' '.join(tokens[1:]), '4294967296 '+' '.join(tokens[1:]),
                    'nan '+' '.join(tokens[1:])):
            with self.assertRaises(ValueError): c.parse(bad, 1)
        for offset, value in ((3083, '6'), (3084, '7')):
            bad = tokens[:]; bad[offset] = value
            with self.assertRaises(ValueError): c.parse(' '.join(bad), 1)

    def test_private_pin_readonly_sanitized_and_missing_states_reject(self):
        with tempfile.TemporaryDirectory() as tmp:
            image = Path(tmp)/'secret.bin'; image.write_bytes(b'private input')
            out, err = io.StringIO(), io.StringIO()
            case = (r.NEG, 31, 1, 0, 19, 7, False)
            with patch.object(r, 'IMAGE', image), patch.object(c, 'run', return_value=[(0,{})]), \
                    patch.object(p, 'cases', return_value=[case]), \
                    contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                self.assertEqual(c.main(['--private-x86']), 2)
            self.assertEqual(out.getvalue(), '')
            self.assertNotIn(str(image), err.getvalue())
            self.assertEqual(image.read_bytes(), b'private input')
        with patch.object(c, 'run', return_value=[]), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(c.main([]), 2)


if __name__ == '__main__':
    unittest.main()
