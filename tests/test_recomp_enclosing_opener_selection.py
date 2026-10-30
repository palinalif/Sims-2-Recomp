"""Public authored selection/prediction tests; no private game fixture required."""
import importlib.util
from pathlib import Path
import struct
import unittest

PATH = Path(__file__).resolve().parents[1] / \
    'scripts/recomp/execute_enclosing_opener_selection.py'
spec = importlib.util.spec_from_file_location('enclosing_selection', PATH)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
c = m.c


class EnclosingOpenerSelectionTests(unittest.TestCase):
    def state(self, n, mode=None):
        return m.state(n, mode)

    def test_predicted_path_matches_three_input_gates(self):
        base = m.layout(2)  # family 2 inputs: +34 zero, +1C nonzero, mode 0
        self.assertEqual(m.predicted_path(base), 2)
        self.assertEqual(m.predicted_path(dict(base, mode=7)), 3)
        self.assertEqual(m.predicted_path(dict(base, gate1c=0)), 1)
        self.assertEqual(m.predicted_path(dict(base, gate1c=0, mode=9)), 1)
        self.assertEqual(m.predicted_path(dict(base, handle34=0x1234)), 0)
        # Populated +34 outranks both the +1C gate and the selector byte.
        self.assertEqual(m.predicted_path(dict(base, handle34=1, gate1c=0, mode=5)), 0)

    def test_boundary_visited_sequence_excludes_call_and_inserts_heap_load(self):
        for fam in (2, 3):
            inline, heap = m.visited_for(fam, False), m.visited_for(fam, True)
            self.assertEqual(inline[-1], 0x1ab6a0 if fam == 2 else 0x1ab68e)
            self.assertEqual(inline, m.visited_for(fam, False))
            load = 0x1ab69c if fam == 2 else 0x1ab68c
            self.assertEqual([a for a in heap if a != load], list(inline))
            self.assertLess(heap.index(load), len(heap) - 1)
            self.assertNotIn(0x1ab6a1, inline + heap)
            self.assertNotIn(0x1ab68f, inline + heap)
        self.assertEqual(m.visited_for(0, False)[:2], (0x1ab665, 0x1ab666))

    def test_state_is_deterministic_and_mode_override_changes_one_byte(self):
        for n in range(4, 8):  # opener families
            ra, pa, la = self.state(n)
            rb, pb, lb = self.state(n)
            self.assertEqual((ra, b''.join(pa[p] for p in sorted(pa))),
                             (rb, b''.join(pb[p] for p in sorted(pb))))
            flipped_mode = 0x5a if la['mode'] == 0 else 0
            _, pc, lc = self.state(n, flipped_mode)
            page_a, page_b = pa[c.DATA_PAGES[1]], pc[c.DATA_PAGES[1]]
            off = la['obj'] - c.DATA_PAGES[1]
            self.assertEqual([o for o in range(4096) if page_a[o] != page_b[o]],
                             [off + 0x7c])
            self.assertEqual(lc['mode'], flipped_mode)
            self.assertEqual(m.predicted_path(la), la['fam'])

    def test_prediction_binds_actual_opener_arguments_per_selector(self):
        for n in range(4, 64):
            regs, pages, loc = self.state(n)
            if loc['fam'] < 2:
                continue
            prediction = m.predict(loc, regs, pages)
            esp = loc['esp']
            # predict is pure: the argument words must appear in its own page
            # image (page 0 of probe.PAGES order == the stack page).
            stack = bytes.fromhex(prediction['pages'])[0:4096]
            reg = lambda name: prediction['regs'][c.REGS.index(name)]
            string = loc['data'] if loc['heap'] else loc['obj'] + 0x60
            if loc['mode'] == 0:
                self.assertEqual(prediction['pc'], m.SITE_3C50)
                words = struct.unpack_from('<4I', stack, esp - 16 - c.DATA_PAGES[0])
                self.assertEqual(
                    words, (string, 0x40, regs['edi'], regs['esi']))
                self.assertEqual(reg('esp'), esp - 16)
            else:
                self.assertEqual(prediction['pc'], m.SITE_3A50)
                words = struct.unpack_from('<2I', stack, esp - 12 - c.DATA_PAGES[0])
                self.assertEqual(words[0], string)
                self.assertEqual(reg('esp'), esp - 12)
            self.assertEqual(reg('eax'), string)
            self.assertEqual(reg('edi'), 0)
            self.assertEqual(reg('esi'), loc['obj'])

    def test_controls_are_ineffective_and_differ_from_the_prediction(self):
        n = 6  # family 2 (mode 0 -> 3C50), heap string form
        regs, pages, loc = self.state(n)
        prediction = m.predict(loc, regs, pages)
        swapped = m.mutate('swapped-target', prediction, 2)
        self.assertEqual(swapped['pc'], m.SITE_3A50)
        self.assertNotEqual(swapped, prediction)
        dropped = m.mutate('dropped-argument', prediction, 2)
        self.assertNotEqual(dropped['regs'], prediction['regs'])
        self.assertEqual(dropped['pages'], prediction['pages'])
        with self.assertRaises(ValueError):
            m.mutate('swapped-target', prediction, 1)

    def test_returned_paths_predict_visible_al_and_restored_callee_registers(self):
        for fam, al in ((0, 1), (1, 0)):
            n = fam  # families 0 and 1 use the same layouts
            regs, pages, loc = self.state(n)
            prediction = m.predict(loc, regs, pages)
            reg = lambda name: prediction['regs'][c.REGS.index(name)]
            self.assertEqual(prediction['outcome'], 'returned')
            self.assertEqual(prediction['pc'], c.RETURN)
            self.assertEqual(reg('eax') & 0xff, al)
            self.assertEqual(reg('esi'), regs['esi'])
            self.assertEqual(reg('edi'), regs['edi'])
            self.assertEqual(reg('esp'), loc['esp'] + 4)


if __name__ == '__main__':
    unittest.main()
