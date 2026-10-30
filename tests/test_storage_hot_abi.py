"""Public full-frame native composition regression; no private inputs needed."""
import contextlib
import copy
import io
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'tools'))
import check_storage_hot_abi as c
p = c.p
r = c.r


class StorageHotAbiTests(unittest.TestCase):
    native = os.environ.get('TS2_GUEST_STORAGE_HOT_ABI_PROBE', 'build/host/ts2_guest_storage_hot_abi_probe')
    runner = os.environ.get('TS2_GUEST_STORAGE_HOT_ABI_RUNNER')

    def run_cases(self, sweep, **kwargs):
        return c.run(sweep, self.native, self.runner, **kwargs)

    def test_composed_full_frame_all_counts_and_endpoints(self):
        sweep = p.cases()
        for case, state in zip(sweep, self.run_cases(sweep)):
            c.verify(state, case)

    def test_cold_unresolved_cleanup_exception_and_bounds_reject(self):
        dynamic = (p.query.FLS, 31, 1, 0, 7, False)
        fallback = (r.NEG, 31, 1, 0, 7, False)
        for case in (dynamic, fallback):
            for mode in (1, 3, 4):
                state = self.run_cases([case], mode=mode)[0]
                self.assertEqual(state[0], 1)
                # No endpoint failure may trigger an alternate storage service.
                expected = [] if mode == 1 else (
                    ['resolve', 'guard', 'fls'] if case == dynamic else ['resolve', 'tls'])
                self.assertEqual([e['kind'] for e in state[1]['events']], expected)
            for sp in (0, r.NEG-3, r.STACK):
                self.assertEqual(self.run_cases([case], sp=sp)[0][0], 1)
        state = self.run_cases([dynamic], mode=2)[0]
        self.assertEqual(state[0], 1)
        self.assertEqual([e['kind'] for e in state[1]['events']], ['resolve'])
        for value in (0, p.query.FLS+4):
            case = (value, 31, 1, 0, 7, False)
            failed, actual = self.run_cases([case])[0]
            self.assertEqual(failed, 1)
            self.assertNotIn('tls', [e['kind'] for e in actual['events']])
            self.assertEqual(actual['dataPages'], p.pages(31, p.hot.encode(value, 31)))
            if not value:
                # Selector has built a frame; hot resolver itself must not save
                # any scratch words or invent cold policy register effects.
                initial, stack = p.query.free.inputs(0, 7)
                self.assertEqual(actual['stack'][r.SP-r.STACK-40:r.SP-r.STACK-28],
                                 stack[r.SP-r.STACK-40:r.SP-r.STACK-28])
                self.assertEqual(actual['registers'][2:4], initial[2:4])

    def test_observed_endpoint_and_final_component_mutations_reject(self):
        case = (p.query.FLS, 31, 1, 0, 7, False)
        state = self.run_cases([case])[0]; c.verify(state, case)
        mutations = []
        for i in range(8):
            s = copy.deepcopy(state); s[1]['registers'][i] ^= 1; mutations.append(s)
        for bit in (1, 4, 64, 128, 1024, 2048):
            s = copy.deepcopy(state); s[1]['flags'] ^= bit; mutations.append(s)
        for event in range(3):
            for reg in range(8):
                s = copy.deepcopy(state); s[1]['events'][event]['registers'][reg] ^= 1
                mutations.append(s)
            for key in ('flags', 'returnRva'):
                s = copy.deepcopy(state); s[1]['events'][event][key] ^= 1; mutations.append(s)
            s = copy.deepcopy(state); s[1]['events'][event]['args'].append(0); mutations.append(s)
        for key, address in (('stack', None), *(('dataPages', a) for a in state[1]['dataPages'])):
            for offset in (0, 2008, 4095):
                s = copy.deepcopy(state)
                data = bytearray(s[1][key] if address is None else s[1][key][address]); data[offset] ^= 1
                if address is None: s[1][key] = bytes(data)
                else: s[1][key][address] = bytes(data)
                mutations.append(s)
        s = copy.deepcopy(state); s[1]['events'].reverse(); mutations.append(s)
        for s in mutations:
            with self.assertRaises(ValueError): c.verify(s, case)

    def test_parser_rejects_partial_duplicate_extra_and_malformed(self):
        case = (r.NEG, 31, 1, 0, 7, False)
        # Capture real valid transport, not a fabricated expected-state encoder.
        import subprocess
        command = ([self.runner] if self.runner else [])+[str(Path(self.native).resolve())]
        done = subprocess.run(command, input=c.request(case), capture_output=True, text=True, timeout=60)
        self.assertEqual(done.returncode, 0)
        c.parse(done.stdout, 1)
        tokens = done.stdout.split()
        for bad in ('', done.stdout+done.stdout, done.stdout+' 0',
                    ' '.join(tokens[:-1]), '-1 '+' '.join(tokens[1:]),
                    '4294967296 '+' '.join(tokens[1:]), 'nan '+' '.join(tokens[1:])):
            with self.assertRaises(ValueError): c.parse(bad, 1)
        tokens[3082] = '4'
        with self.assertRaises(ValueError): c.parse(' '.join(tokens), 1)

    def test_wrong_private_pin_is_sanitized_and_readonly(self):
        with tempfile.TemporaryDirectory() as tmp:
            image = Path(tmp)/'secret.bin'; image.write_bytes(b'private input')
            out, err = io.StringIO(), io.StringIO()
            with patch.object(r, 'IMAGE', image), patch.object(c, 'run', return_value=[]), \
                    contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                self.assertEqual(c.main(['--private-x86']), 2)
            self.assertEqual(out.getvalue(), '')
            self.assertNotIn(str(image), err.getvalue())
            self.assertEqual(image.read_bytes(), b'private input')


if __name__ == '__main__':
    unittest.main()
