"""Public six-model composition; original fixtures are never opened."""
import contextlib
import copy
import io
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import check_release_hot_abi as c
p, r, chain = c.p, c.r, c.chain


def failure_case(value=p.FLS):
    return (1, 2, 0, 19, 3, chain.PTD, [(10000+i, i) for i in range(45)],
            value, 31, 1, False)


class ReleaseHotAbiTests(unittest.TestCase):
    def test_full_six_model_frame_and_destination_store(self):
        sweep = c.cases()
        self.assertEqual(c.verify(c.run(sweep), sweep), 3072)

    def test_cleanup_missing_dispatch_cold_destination_and_stack_reject(self):
        for value in (p.FLS, r.NEG):
            for mode in range(1, 15):
                if mode == 11 and value == r.NEG:
                    continue  # TLS does not invoke the dynamic-target guard.
                with self.subTest(value=value, mode=mode):
                    state = c.run([failure_case(value)], mode=mode)[0]
                    self.assertEqual(state['failed'], 1)
                    self.assertTrue(all(v == chain.SENTINEL for v in state['slots'].values()))
        for value in (0, p.FLS+4):
            self.assertEqual(c.run([failure_case(value)])[0]['failed'], 1)
        for sp in (0, 16, 0xfffffffc, r.STACK+4):
            state = c.run([failure_case()], sp=sp)[0]
            self.assertEqual(state['failed'], 1)
            self.assertEqual(state['events'], [])

    def test_null_success_bypass_unbound_and_cold_dependencies(self):
        for context, result in ((0, 0), (1, 0x80000000)):
            case = list(failure_case(0)); case[0], case[2] = context, result
            # The hot oracle intentionally accepts only hot values. Use a hot
            # expectation to check unchanged cold cache separately on bypass.
            expected = list(case); expected[7] = p.FLS
            for mode in (5, 6, 7, 8, 9, 10, 11, 12, 13):
                state = c.run([case], mode=mode)[0]
                self.assertEqual(state['failed'], 0)
                self.assertEqual(state['cacheWords'], [31, p.hot.encode(0, 31)])
                state['cacheWords'] = [31, p.hot.encode(p.FLS, 31)]
                c.verify([state], [expected])

    def test_every_observed_component_is_required(self):
        for value in (p.FLS, r.NEG):
            case = failure_case(value); actual = c.run([case])[0]
            c.verify([actual], [case])
            for index in range(8):
                wrong = copy.deepcopy(actual); wrong['registers'][index] ^= 1
                with self.assertRaises(ValueError): c.verify([wrong], [case])
            for bit in (1, 4, 16, 64, 128, 1024, 2048):
                wrong = copy.deepcopy(actual); wrong['flags'] ^= bit
                with self.assertRaises(ValueError): c.verify([wrong], [case])
            for key in ('failed', 'lastError', 'stack', 'slots', 'events', 'cacheWords'):
                wrong = copy.deepcopy(actual)
                if key == 'stack':
                    v = bytearray(wrong[key]); v[r.SP-r.STACK-72] ^= 1; wrong[key] = bytes(v)
                elif key == 'slots': wrong[key][chain.PTD+16] ^= 1
                elif key == 'events': wrong[key][-1][1][0] ^= 1
                elif key == 'cacheWords': wrong[key][1] ^= 1
                else: wrong[key] ^= 1
                with self.subTest(key=key), self.assertRaises(ValueError): c.verify([wrong], [case])
            for index, event in enumerate(actual['events']):
                for component in (0, 2, 3):
                    wrong = copy.deepcopy(actual); e = list(event)
                    e[component] = 'unknown' if component == 0 else e[component] ^ 1
                    wrong['events'][index] = tuple(e)
                    with self.assertRaises(ValueError): c.verify([wrong], [case])
                for arg in range(len(event[1])):
                    wrong = copy.deepcopy(actual); wrong['events'][index][1][arg] ^= 1
                    with self.assertRaises(ValueError): c.verify([wrong], [case])

    def test_strict_transport(self):
        case = list(failure_case()); case[0] = 0
        state = c.run([case])[0]
        values = [0, *state['registers'], state['flags'],
                  *struct.unpack('<1024I', state['stack']),
                  state['slots'][chain.PTD+16], state['slots'][chain.accessor.FALLBACK],
                  state['lastError'], *state['cacheWords'], 0]
        text = ' '.join(map(str, values))+'\n'
        self.assertEqual(c.parse(text, 1), [state])
        for bad in ('', text+text, text.rstrip()+' 0\n', text.replace('0', '-1', 1),
                    text.replace('0', '4294967296', 1), text.replace('0', '０', 1),
                    ' '.join(map(str, values[:-1]))+'\n',
                    ' '.join(map(str, values[:-1]+[8]))+'\n',
                    ' '.join(map(str, values[:-1]+[1, 99, 0, 0]))+'\n'):
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
