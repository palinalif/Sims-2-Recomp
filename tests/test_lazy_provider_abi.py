"""Public slow-provider integer frames; no original input required."""
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
import check_lazy_provider_abi as c
r = c.r


class LazyProviderAbiTests(unittest.TestCase):
    native = os.environ.get('TS2_GUEST_LAZY_PROVIDER_ABI_PROBE', 'build/host/ts2_guest_lazy_provider_abi_probe')
    runner = os.environ.get('TS2_GUEST_LAZY_PROVIDER_ABI_RUNNER')

    def run_cases(self, sweep, **kwargs):
        return c.run(sweep, self.native, self.runner, **kwargs)

    def test_full_frame_and_ordered_publication_rollback(self):
        sweep = c.cases(); states = self.run_cases(sweep)
        self.assertEqual(len(states), len(sweep))
        for case, state in zip(sweep, states): c.verify(state, case)
        case = (r.NEG, 1, r.NEG, 1, 7, 1, True)
        state = self.run_cases([case])[0]; c.verify(state, case)
        self.assertNotIn('query', [e[0] for e in state[1]['events']])
        self.assertEqual(state[1]['registers'][0], r.NEG)
        self.assertEqual(state[1]['events'][-2][1], [0])  # free(NULL), NOT pointer

    def test_cleanup_missing_throw_existing_storage_and_frames_reject(self):
        case = (3, 1, 0x81234000, 1, 7, 0, True)
        for mode in range(1, 12):
            with self.subTest(mode=mode):
                self.assertEqual(self.run_cases([case], mode=mode)[0][0], 1)
        for sp in (0, r.NEG-3, r.STACK, r.STACK+4094):
            failed, state, _ = self.run_cases([case], sp=sp)[0]
            self.assertEqual(failed, 1); self.assertEqual(state['events'], [])
            self.assertEqual(state['stack'], bytes(c.p.p.init.inputs(0)[1]))
        # Rollback is followed by caller-cleaned free(pointer), not success free(NULL).
        case = (3, 1, 0x81234000, 0, 7, 0, True)
        self.assertEqual(self.run_cases([case], mode=7)[0][0], 1)

    def test_every_observed_component_mutation_rejects(self):
        case = (0, 1, r.NEG, 1, r.NEG, 1, True)
        state = self.run_cases([case])[0]; c.verify(state, case)
        mutations = []
        for i in range(8):
            s = copy.deepcopy(state); s[1]['registers'][i] ^= 1; mutations.append(s)
        for bit in (1, 4, 64, 128, 1024, 2048):
            s = copy.deepcopy(state); s[1]['flags'] ^= bit; mutations.append(s)
        for offset in (0, r.SP-r.STACK-32, 4095):
            s = copy.deepcopy(state); b = bytearray(s[1]['stack']); b[offset] ^= 1
            s[1]['stack'] = bytes(b); mutations.append(s)
        for i, event in enumerate(state[1]['events']):
            for field in range(4):
                s = copy.deepcopy(state); e = list(event)
                e[field] = 'bad' if field == 0 else [99] if field == 1 else e[field]+1
                s[1]['events'][i] = tuple(e); mutations.append(s)
        s = list(copy.deepcopy(state)); s[2] ^= 1; mutations.append(s)
        for s in mutations:
            with self.assertRaises(ValueError): c.verify(s, case)

    def test_strict_transport(self):
        command = ([self.runner] if self.runner else [])+[str(Path(self.native).resolve())]
        done = subprocess.run(command, input=c.request((0, 1, 1, 1, 0, 0, False)),
                              capture_output=True, text=True, timeout=60)
        self.assertEqual(done.returncode, 0); c.parse(done.stdout, 1)
        tokens = done.stdout.split()
        for bad in ('', done.stdout+done.stdout, done.stdout+' 0', ' '.join(tokens[:-1]),
                    '-1 '+' '.join(tokens[1:]), '4294967296 '+' '.join(tokens[1:]),
                    'nan '+' '.join(tokens[1:])):
            with self.assertRaises(ValueError): c.parse(bad, 1)
        for offset, value in ((0, '2'), (1035, '10'), (1036, '7')):
            bad = tokens[:]; bad[offset] = value
            with self.assertRaises(ValueError): c.parse(' '.join(bad), 1)

    def test_private_pin_sanitized_readonly_and_missing_states_reject(self):
        with tempfile.TemporaryDirectory() as tmp:
            image = Path(tmp)/'private.bin'; image.write_bytes(b'private fixture')
            out, err = io.StringIO(), io.StringIO()
            with patch.object(r, 'IMAGE', image), patch.object(c, 'run', return_value=[None]), \
                    patch.object(c, 'cases', return_value=[None]), \
                    contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                self.assertEqual(c.main(['--private-x86']), 2)
            self.assertEqual(out.getvalue(), ''); self.assertNotIn(str(image), err.getvalue())
            self.assertEqual(image.read_bytes(), b'private fixture')
        with patch.object(c, 'run', return_value=[]), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(c.main([]), 2)


if __name__ == '__main__':
    unittest.main()
