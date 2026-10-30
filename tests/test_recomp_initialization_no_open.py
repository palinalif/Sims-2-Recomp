"""Authored no-open/trace tests; no private game bytes or fixtures required.

These check the zero-+0x1C no-open return arm (AL=0) is correctly modelled and is
genuinely distinct from the settled +0x34-populated guard arm (AL=1). They never
load original-game bytes; the original-x86 differential itself runs only in the
private harness (execute_initialization_no_open.py) against the pinned image.
"""
import copy
import importlib.util
import json
from pathlib import Path
import struct
import sys
import unittest

SCRIPT = Path(__file__).resolve().parents[1]/'scripts/recomp/execute_initialization_no_open.py'
sys.path.insert(0, str(SCRIPT.parent))
spec = importlib.util.spec_from_file_location('no_open_test', SCRIPT)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
GUARD = importlib.util.spec_from_file_location('guard_ref', SCRIPT.parent/'execute_initialization_guard.py')
gm = importlib.util.module_from_spec(GUARD); GUARD.loader.exec_module(gm)


class NoOpenFragmentTests(unittest.TestCase):
    def test_state_is_deterministic_and_clears_both_gates(self):
        for n in range(64):
            regs, pages = m.state(n)
            self.assertEqual((regs, pages), m.state(n))
            self.assertEqual(set(pages), set(m.probe.PAGES))
            off = regs['ecx'] - m.c.DATA_PAGES[1]
            self.assertLessEqual(off + 0x38, 4096)
            # Both the +0x34 handle and the +0x1C gate are clear (the no-open arm).
            self.assertEqual(struct.unpack_from('<I', pages[m.c.DATA_PAGES[1]], off+0x34)[0], 0)
            self.assertEqual(struct.unpack_from('<I', pages[m.c.DATA_PAGES[1]], off+0x1c)[0], 0)
            # Upper EAX retained and, on odd n, a visible AL=0xff that must be zeroed.
            self.assertEqual(regs['eax'] & 255, 0xff if n % 2 else 0x00)
        for bad in (-1, 64, True):
            with self.assertRaises(ValueError):
                m.state(bad)

    def test_no_open_path_is_distinct_from_populated_guard(self):
        self.assertNotEqual(list(m.NO_OPEN_PATH), list(gm.GUARD_PATH))
        # The no-open arm reaches the +0x1C gate (0x1ab74/0x1ab77) and the AL=0
        # return stub (0x1ab76c); the guard diverts at 0x1ab66e to 0x1ab766 (AL=1).
        self.assertIn(0x1ab76c, m.NO_OPEN_PATH)
        self.assertNotIn(0x1ab76c, gm.GUARD_PATH)
        self.assertIn(0x1ab766, gm.GUARD_PATH)
        self.assertNotIn(0x1ab766, m.NO_OPEN_PATH)
        self.assertEqual(m.NO_OPEN_PATH[-3:], (0x1ab769, 0x1ab76a, 0x1ab76b))

    def test_oracle_zeroes_al_retains_upper_eax_and_restores_frame(self):
        for n in range(64):
            regs, pages = m.state(n); before = copy.deepcopy((regs, pages))
            out = m.oracle(regs, pages)
            # eax is exactly upper-24 retained, AL forced to zero.
            self.assertEqual(out['regs'][0], regs['eax'] & 0xffffff00)
            self.assertEqual(out['regs'][m.c.REGS.index('esp')], regs['esp'] + 4)
            # Only eax/esp change; every other callee-saved GPR is preserved.
            for r in m.c.REGS:
                if r not in ('eax', 'esp'):
                    self.assertEqual(out['regs'][m.c.REGS.index(r)], regs[r])
            expected = bytearray(b''.join(pages[p] for p in m.probe.PAGES))
            struct.pack_into('<II', expected, regs['esp']-m.c.DATA_PAGES[0]-8, regs['edi'], regs['esi'])
            self.assertEqual(out['pages'], expected.hex())
            self.assertEqual((regs, pages), before)  # oracle is pure

    def test_oracle_rejects_populated_handle_or_set_1c_gate(self):
        regs, pages = m.state(0)
        off = regs['ecx'] - m.c.DATA_PAGES[1]
        # A populated +0x34 belongs to the guard arm, not this one: oracle must reject.
        for field, value in ((0x34, 1), (0x1c, 0xffffffff)):
            bad = copy.deepcopy(pages)
            struct.pack_into('<I', bad[m.c.DATA_PAGES[1]], off + field, value)
            with self.assertRaises(ValueError):
                m.oracle(regs, bad)
        for value in (0, m.c.DATA_PAGES[1] + 1, m.c.DATA_PAGES[1] + 4092):
            with self.assertRaises(ValueError):
                m.oracle(dict(regs, ecx=value), pages)
        bad = copy.deepcopy(pages)
        struct.pack_into('<I', bad[m.c.DATA_PAGES[0]], regs['esp']-m.c.DATA_PAGES[0], 0)
        with self.assertRaises(ValueError):
            m.oracle(regs, bad)

    def test_guard_and_no_open_oracles_diverge_on_the_same_inputs(self):
        # Feed the guard's oracle the no-open state: it demands a non-zero +0x34.
        regs, pages = m.state(0)
        with self.assertRaises(ValueError):
            gm.oracle(regs, pages)
        # And the AL byte each predicts is opposite (guard AL=1, no-open AL=0).
        guard_state, guard_pages = gm.state(0)
        self.assertEqual(gm.oracle(guard_state, guard_pages)['regs'][0] & 0xff, 1)
        self.assertEqual(m.oracle(regs, pages)['regs'][0] & 0xff, 0)


class NoOpenComparisonTests(unittest.TestCase):
    def test_full_comparison_accepts_prediction_and_rejects_perturbations(self):
        expected = [dict(case=n, **m.oracle(*m.state(n))) for n in range(64)]
        encode = lambda rows: '\n'.join(map(json.dumps, rows))
        self.assertEqual(m.c.assess(encode(expected), expected, 'valid')['matched'], 64)
        for mode in m.MODES[1:]:
            with self.assertRaises(ValueError):
                m.c.assess(encode(expected), expected, mode)
            bad = copy.deepcopy(expected)
            for row in bad:
                if mode == 'wrong-result':
                    row['regs'][0] |= 1  # AL must stay zero on this arm
                else:
                    row['regs'][7] += 8
            self.assertEqual(m.c.assess(encode(bad), expected, mode)['differing_cases'], 64)
        for reg in range(8):
            bad = copy.deepcopy(expected); bad[0]['regs'][reg] ^= 1
            with self.assertRaises(ValueError):
                m.c.assess(encode(bad), expected, 'valid')
        for page in range(6):
            bad = copy.deepcopy(expected); data = bytearray.fromhex(bad[0]['pages']); data[page*4096] ^= 1
            bad[0]['pages'] = data.hex()
            with self.assertRaises(ValueError):
                m.c.assess(encode(bad), expected, 'valid')


if __name__ == '__main__':
    unittest.main()
