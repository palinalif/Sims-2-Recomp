"""Public four-model composition checks; original fixtures are never opened."""
import contextlib
import copy
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import check_release_error_abi as c
p, r = c.p, c.r


def failure_case():
    return (1, 2, 0, 203, 3, p.PTD, [(10000+i, i) for i in range(45)], 1, False)


class ReleaseErrorAbiTests(unittest.TestCase):
    def test_full_composed_integer_frame_and_destination_store(self):
        sweep = c.cases()
        self.assertEqual(c.verify(c.run(sweep), sweep), 732)

    def test_cleanup_missing_dispatch_destination_and_stack_fail_closed(self):
        case = failure_case()
        for mode in range(1, 10):
            with self.subTest(mode=mode):
                state = c.run([case], mode=mode)[0]
                self.assertEqual(state['failed'], 1)
                self.assertTrue(all(v == p.SENTINEL for v in state['slots'].values()))
        for sp in (0, 16, 0xfffffffc, r.STACK+4):
            with self.subTest(sp=sp):
                state = c.run([case], sp=sp)[0]
                self.assertEqual(state['failed'], 1)
                self.assertEqual(state['events'], [])

    def test_null_success_bypass_unbound_error_dependencies(self):
        for context, result in ((0, 0), (1, 0x80000000)):
            case = list(failure_case()); case[0], case[2] = context, result
            for mode in (5, 6, 7, 8, 9):
                state = c.run([case], mode=mode)[0]
                c.verify([state], [case])
                self.assertTrue(all(v == p.SENTINEL for v in state['slots'].values()))

    def test_every_observed_component_is_required(self):
        case = failure_case(); actual = c.run([case])[0]
        c.verify([actual], [case])
        for index in range(8):
            wrong = copy.deepcopy(actual); wrong['registers'][index] ^= 1
            with self.assertRaises(ValueError): c.verify([wrong], [case])
        for bit in (1, 4, 16, 64, 128, 1024, 2048):
            wrong = copy.deepcopy(actual); wrong['flags'] ^= bit
            with self.assertRaises(ValueError): c.verify([wrong], [case])
        for key in ('failed', 'lastError', 'stack', 'slots', 'events'):
            wrong = copy.deepcopy(actual)
            if key == 'stack':
                value = bytearray(wrong[key]); value[0] ^= 1; wrong[key] = bytes(value)
            elif key == 'slots': wrong[key][p.accessor.FALLBACK] ^= 1
            elif key == 'events': wrong[key][-1][1][0] ^= 1
            else: wrong[key] ^= 1
            with self.subTest(key=key), self.assertRaises(ValueError): c.verify([wrong], [case])
        for address in (p.PTD+16, p.accessor.FALLBACK):
            wrong = copy.deepcopy(actual); wrong['slots'][address] ^= 1
            with self.assertRaises(ValueError): c.verify([wrong], [case])

    def test_strict_transport(self):
        # Produce one valid minimal record with no endpoint events.
        case = list(failure_case()); case[0] = 0
        state = c.run([case])[0]
        import struct
        values = [0, *state['registers'], state['flags'],
                  *struct.unpack('<1024I', state['stack']),
                  state['slots'][p.PTD+16], state['slots'][p.accessor.FALLBACK],
                  state['lastError'], 0]
        text = ' '.join(map(str, values))+'\n'
        self.assertEqual(c.parse(text, 1), [state])
        for bad in ('', text+text, text.rstrip()+' 0\n', text.replace('0', '-1', 1),
                    text.replace('0', '4294967296', 1), text.replace('0', '０', 1),
                    ' '.join(map(str, values[:-1]))+'\n'):
            with self.assertRaises(ValueError): c.parse(bad, 1)
        for states, sweep in (([], [case]), ([state], [])):
            with self.assertRaises(ValueError): c.verify(states, sweep)

    def test_private_wrong_pin_sanitized_and_readonly(self):
        with tempfile.TemporaryDirectory() as tmp:
            image = Path(tmp)/'private.bin'; image.write_bytes(b'private input')
            out, err = io.StringIO(), io.StringIO()
            with patch.object(r, 'IMAGE', image), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                self.assertEqual(c.main(['--private-x86']), 2)
            self.assertEqual(out.getvalue(), '')
            self.assertNotIn(str(image), err.getvalue())
            self.assertNotIn('private input', err.getvalue())
            self.assertEqual(image.read_bytes(), b'private input')


if __name__ == '__main__':
    unittest.main()
