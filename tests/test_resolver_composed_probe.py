"""Public authored controls; never require original fixtures."""
import contextlib
import io
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import resolver_composed_probe as c
r = c.r


class ResolverCompositionTests(unittest.TestCase):
    def test_retry_failure_advances_but_export_failure_stops(self):
        operands = ((1,), (2,), c.PREFIX)
        expected, loads, selected = c.expected_for((0, 0),
            ((0, 87, 0), (0, 87, r.H2)), 0, operands)
        self.assertEqual(loads, [0, r.H2])
        self.assertEqual(selected, 1)
        self.assertEqual(expected['modules'], [r.NEG, r.H2])
        self.assertEqual(expected['cache'], r.NEG)
        self.assertEqual([e[0] for e in expected['events']],
            ['load', 'api_load', 'error', 'compare', 'api_load',
             'load', 'api_load', 'error', 'compare', 'api_load', 'export'])
        self.assertEqual(expected['events'][1],
            ('api_load', [r.NAME, 0, 0x800], 0x82A2C5, r.SP - 52))
        self.assertEqual(expected['events'][-2][1], [r.NAME + 128, 0, 0])

    def test_seventh_unit_bound_and_negative_module_bypass(self):
        equal7 = c.PREFIX[:7] + (999,)
        expected, loads, selected = c.expected_for((0, r.NEG),
            ((0, 87, r.H1), (r.H2, 0, 0)), r.H2,
            (equal7, (1,), c.PREFIX))
        self.assertIsNone(selected)
        self.assertEqual(loads[0], 0)
        self.assertEqual([e[0] for e in expected['events']],
                         ['load', 'api_load', 'error', 'compare'])
        self.assertEqual(expected['modules'], [r.NEG, r.NEG])

    def test_authored_composed_runner_and_reentry_controls(self):
        # Authored resolver calls authored helper, saves result in cache, ret.
        # Neither body is a transcription of game bytes.
        code = b'\xb8' + struct.pack('<I', r.HELPER) + b'\xff\xd0'
        code += b'\xa3' + struct.pack('<I', r.CACHE) + b'\xc3'
        helper = b'\xb8' + struct.pack('<I', r.H1) + b'\xc3'
        expected = {'events': [('load', [r.RETURN], 0x82A219, r.SP - 4)],
                    'eax': r.H1, 'cache': r.H1,
                    'modules': [0, r.H2], 'esp': r.SP + 4}
        # Reentry deliberately lacks a cache branch and must reject the second
        # helper call even though its code page is still mapped.
        with self.assertRaises(ValueError):
            r.exercise(code, bytes(4096), (0, r.H2), (r.H1, 0), 0, 0,
                expected, composition=(helper, b'\xc3',
                    ((1,), (2,), (3,)), ((r.H1, 0, 0), (0, 0, 0))))
        # Positive caller executes the helper once, then bypasses it on cache.
        code = b'\xa1' + struct.pack('<I', r.CACHE) + b'\x85\xc0\x75\x0c' + code
        r.exercise(code, bytes(4096), (0, r.H2), (r.H1, 0), 0, 0,
            {**expected, 'events': [('load', [r.RETURN], 0x82A222, r.SP - 4)]},
            composition=(helper, b'\xc3',
                ((1,), (2,), (3,)), ((0, 0, 0), (0, 0, 0))))
        for bad in (b'\x43' + helper, helper[:-1] + b'\xc2\x04\x00',
                    b'\xff\x05' + struct.pack('<I', r.NAME) + helper,
                    b'\xff\x05' + struct.pack('<I', r.BASE + 0xD9A118) + helper,
                    b'\xeb\xfe'):
            with self.subTest(helper=bad), self.assertRaises((ValueError, c.UcError)):
                r.exercise(code, bytes(4096), (0, r.H2), (r.H1, 0), 0, 0,
                    {**expected, 'events': [('load', [r.RETURN], 0x82A222, r.SP - 4)]},
                    composition=(bad, b'\xc3', ((1,), (2,), (3,)),
                                 ((0, 0, 0), (0, 0, 0))))

    def test_vector_count_and_sanitized_pin_failure(self):
        self.assertEqual(len(list(c.vectors())), 720)
        with tempfile.TemporaryDirectory() as tmp:
            image = Path(tmp) / 'private.bin'
            image.write_bytes(b'private input')
            out, err = io.StringIO(), io.StringIO()
            with patch.object(r, 'IMAGE', image), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                self.assertEqual(c.main(), 2)
            self.assertEqual(out.getvalue(), '')
            self.assertNotIn('private', err.getvalue())
            self.assertEqual(image.read_bytes(), b'private input')


if __name__ == '__main__':
    unittest.main()
