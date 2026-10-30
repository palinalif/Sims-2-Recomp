"""Fail-closed control accounting for the authored heap; no private fixtures."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('heap_controls', ROOT/'scripts/recomp/check_guest_heap_service.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class GuestHeapControlTests(unittest.TestCase):
    def test_mutations_are_single_and_distinct(self):
        source = m.SOURCE.read_text()
        variants = m.variants(source)
        self.assertEqual(variants['valid'], source)
        self.assertEqual(len(set(variants.values())), 3)
        self.assertIn('r.esp=sp+12;', variants['wrong-cleanup'])
        self.assertIn('if (false) {', variants['lost-zero'])
        with self.assertRaises(ValueError):
            m.variants(source.replace('if (flags==8) {', 'if (flags!=0) {'))

    def test_controls_require_the_expected_executed_failure(self):
        for mode, error in [('wrong-cleanup', 'r.eax==base && r.esp==stack+32'),
                            ('lost-zero', 'm.read32(p)==0')]:
            self.assertTrue(m.accepted(mode, 1, '', error+'\n'))
            for rc in (0, 2, 78, 124, -11):
                self.assertFalse(m.accepted(mode, rc, '', error))
            self.assertFalse(m.accepted(mode, 1, '', 'unrelated error'))
            self.assertFalse(m.accepted(mode, 1, 'partial output', error))

    def test_valid_requires_completed_model_and_no_error(self):
        self.assertTrue(m.accepted('valid', 0, '4000 model operations', ''))
        self.assertFalse(m.accepted('valid', 0, '', ''))
        self.assertFalse(m.accepted('valid', 1, '4000 model operations', ''))
        self.assertFalse(m.accepted('valid', 0, '4000 model operations', 'failure'))


if __name__ == '__main__':
    unittest.main()
