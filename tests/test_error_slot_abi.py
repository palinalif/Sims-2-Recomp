"""Native integer ABI checks; original fixtures are optional and private."""
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
import check_error_slot_abi as c
p, r = c.p, c.r


class ErrorSlotAbiTests(unittest.TestCase):
    native = os.environ.get('TS2_GUEST_ERROR_SLOT_ABI_PROBE', 'build/host/ts2_guest_error_slot_abi_probe')
    runner = os.environ.get('TS2_GUEST_ERROR_SLOT_ABI_RUNNER')

    def run_cases(self, sweep, **kwargs):
        return c.run(sweep, self.native, self.runner, **kwargs)

    def test_full_frame_flags_and_unmapped_return_addresses(self):
        sweep = c.cases()
        states = self.run_cases(sweep)
        self.assertEqual(len(states), len(sweep))
        for case, state in zip(sweep, states):
            c.verify(state, case)
        # Only the stack is mapped: fallback and wrapped/nonnull destinations
        # must be returned as addresses, never read or conflated with null input.
        case = (0xfffffff0, 0, False)
        self.assertEqual(self.run_cases([case])[0][1]['registers'][0], 0)
        case = (0, 0, False)
        self.assertEqual(self.run_cases([case])[0][1]['registers'][0], p.FALLBACK)

    def test_unresolved_cleanup_throw_and_corrupt_frame_reject(self):
        case = (1, 7, True)
        for mode in (1, 2, 3, 4):
            failed, state = self.run_cases([case], mode=mode)[0]
            self.assertEqual(failed, 1)
            self.assertEqual(len(state['events']), 0 if mode == 1 else 1)
        for sp in (0, r.NEG-3, r.STACK, r.STACK+4096-2):
            failed, state = self.run_cases([case], sp=sp)[0]
            self.assertEqual(failed, 1)
            self.assertEqual(state['events'], [])
            _, stack, _ = p.init.inputs(7)
            self.assertEqual(state['stack'], bytes(stack))

    def test_every_observed_component_mutation_rejects(self):
        for pointer in (0, 0x7ffffff0, 0xfffffff0):
            case = (pointer, 7, True)
            state = self.run_cases([case])[0]; c.verify(state, case)
            mutations = []
            for i in range(8):
                s = copy.deepcopy(state); s[1]['registers'][i] ^= 1; mutations.append(s)
            for bit in (1, 4, 64, 128, 1024, 2048, *((16,) if pointer else ())):
                s = copy.deepcopy(state); s[1]['flags'] ^= bit; mutations.append(s)
            for offset in (0, r.SP-r.STACK-4, 4095):
                s = copy.deepcopy(state); b = bytearray(s[1]['stack']); b[offset] ^= 1
                s[1]['stack'] = bytes(b); mutations.append(s)
            for field in range(4):
                s = copy.deepcopy(state); e = list(s[1]['events'][0])
                e[field] = 'bad' if field == 0 else [1] if field == 1 else e[field]+1
                s[1]['events'][0] = tuple(e); mutations.append(s)
            for s in mutations:
                with self.assertRaises(ValueError): c.verify(s, case)

    def test_strict_transport(self):
        command = ([self.runner] if self.runner else [])+[str(Path(self.native).resolve())]
        done = subprocess.run(command, input=c.request((0, 0, False)),
                              capture_output=True, text=True, timeout=60)
        self.assertEqual(done.returncode, 0); c.parse(done.stdout, 1)
        tokens = done.stdout.split()
        for bad in ('', done.stdout+done.stdout, done.stdout+' 0', ' '.join(tokens[:-1]),
                    '-1 '+' '.join(tokens[1:]), '4294967296 '+' '.join(tokens[1:]),
                    'nan '+' '.join(tokens[1:])):
            with self.assertRaises(ValueError): c.parse(bad, 1)
        for offset, value in ((1034, '2'), (1034, '0')):
            bad = tokens[:]; bad[offset] = value
            with self.assertRaises(ValueError): c.parse(' '.join(bad), 1)

    def test_private_pin_readonly_sanitized_and_missing_states_reject(self):
        with tempfile.TemporaryDirectory() as tmp:
            image = Path(tmp)/'secret.bin'; image.write_bytes(b'private input')
            out, err = io.StringIO(), io.StringIO()
            with patch.object(r, 'IMAGE', image), patch.object(c, 'run', return_value=[(0,{})]), \
                    patch.object(c, 'cases', return_value=[(0, 0, False)]), \
                    contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                self.assertEqual(c.main(['--private-x86']), 2)
            self.assertEqual(out.getvalue(), '')
            self.assertNotIn(str(image), err.getvalue())
            self.assertEqual(image.read_bytes(), b'private input')
        with patch.object(c, 'run', return_value=[]), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(c.main([]), 2)


if __name__ == '__main__':
    unittest.main()
