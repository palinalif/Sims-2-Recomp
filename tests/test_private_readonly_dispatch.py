import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import prepare_private_readonly_dispatch as bridge
import check_private_readonly_dispatch as checker
from android_probe import REGS


class PrivateReadonlyComparisonTests(unittest.TestCase):
    def test_strict_full_state_and_reference_pin(self):
        state = {'regs': dict.fromkeys(REGS, 0), 'eflags': 0x602,
                 'mem': {'2684420096': 165}, 'fp_depth': 0, 'st': []}
        record = 'R' + ' 00000000'*8 + '\nF 00000602\nT 0\nM A0010000 A5\nENDCASE\n'
        text = ''.join(f'CASE {i}\n' + record for i in range(96))
        with tempfile.TemporaryDirectory() as d:
            ref, out = Path(d)/'reference.json', Path(d)/'stdout.txt'
            ref.write_text(json.dumps({'states': [state]*96}))
            out.write_text(text)
            with self.assertRaisesRegex(ValueError, 'pin mismatch'):
                checker.check(ref, out)
            with patch.object(checker, 'REFERENCE_SHA', hashlib.sha256(ref.read_bytes()).hexdigest()):
                self.assertEqual(checker.check(ref, out), 96)
                register_changes = []
                for index in range(8):
                    fields = ['00000000']*8
                    fields[index] = '00000001'
                    register_changes.append(text.replace('R' + ' 00000000'*8,
                                                         'R ' + ' '.join(fields), 1))
                for changed in register_changes + [text.replace('00000602', '00000603', 1),
                                text.replace('A5', 'A4', 1),
                                text + 'extra\n', text[:-8],
                                text.replace('CASE 1\n', 'CASE 0\n', 1)]:
                    out.write_text(changed)
                    with self.assertRaises(ValueError):
                        checker.check(ref, out)


class PrivateReadonlyPreparationTests(unittest.TestCase):
    def test_public_scaffold_transforms_only_bridge_sites(self):
        # Authored scaffold, NOT private original code or saved input states.
        fixture = ('#include "guest_query_guard.h"\n'
                   '#define MEM32(addr) ts2_checked_read32(&query_view, (uint32_t)(addr))\n'
                   '/* public body marker preserved */\nstatic void case_0(void) {\n'
                   + 'ts2_dispatch(1, query_entries, 3);\n' * 96 + '}\n')
        with tempfile.TemporaryDirectory(dir=ROOT/'work') as d:
            source, output = Path(d)/'source.c', Path(d)/'output.c'
            source.write_text(fixture)
            with patch.object(bridge, 'SOURCE_SHA', hashlib.sha256(source.read_bytes()).hexdigest()):
                bridge.prepare(source, output)
                result = output.read_text()
                self.assertIn('/* public body marker preserved */', result)
                self.assertEqual(result.count('runtime_dispatch(1, query_entries, 3);'), 96)
                self.assertIn('ts2_bridge_read32((uint32_t)(addr))', result)
                self.assertEqual(output.stat().st_mode & 0o777, 0o600)
                self.assertEqual(source.read_text(), fixture)
                with self.assertRaises(FileExistsError):
                    bridge.prepare(source, output)

    def test_pin_failure_leaves_no_output(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'work') as d:
            source, output = Path(d)/'source.c', Path(d)/'output.c'
            source.write_text('public not the authorized fixture')
            with self.assertRaisesRegex(ValueError, 'pin mismatch'):
                bridge.prepare(source, output)
            self.assertFalse(output.exists())

    def test_external_or_symlinked_output_rejects_before_read(self):
        with tempfile.TemporaryDirectory() as external, tempfile.TemporaryDirectory(dir=ROOT/'work') as private:
            output = Path(external)/'output.c'
            with self.assertRaisesRegex(ValueError, 'private work'):
                bridge.prepare(Path('absent'), output)
            link = Path(private)/'link'
            link.symlink_to(external, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, 'private work'):
                bridge.prepare(Path('absent'), link/'output.c')
            self.assertFalse(output.exists())

    def test_structure_pin_is_independent(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'work') as d:
            source, output = Path(d)/'source.c', Path(d)/'output.c'
            source.write_text('public wrong shape')
            with patch.object(bridge, 'SOURCE_SHA', hashlib.sha256(source.read_bytes()).hexdigest()):
                with self.assertRaisesRegex(ValueError, 'structure'):
                    bridge.prepare(source, output)
            self.assertFalse(output.exists())
