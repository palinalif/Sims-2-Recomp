import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'tools'))
import prepare_private_scoped_dispatch as bridge
import check_private_scoped_dispatch as checker
from android_probe import REGS


def fixture():
    # Public authored scaffold, not recovered code or private saved inputs.
    return ('#define MEM32(addr) (*checked_ptr32((uint32_t)(addr)))\n'
            '/* authored body marker */\n'
            'void public_store(void) { MEM32(destination) = value; }\n'
            'void public_store2(void) { MEM32(other) = word; }\n'
            'static void case_0(void) {\n' +
            '    cache_1ab770();\n'*32 + '    cache_1ab78c();\n'*32 + '}\n')


class PrivateScopedPreparationTests(unittest.TestCase):
    def test_only_explicit_access_and_dispatch_sites_change(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'work') as d:
            source, output = Path(d)/'source.c', Path(d)/'out.c'
            original = fixture()
            source.write_text(original)
            with patch.object(bridge, 'SOURCE_SHA', hashlib.sha256(source.read_bytes()).hexdigest()):
                bridge.prepare(source, output)
                text = output.read_text()
                self.assertEqual(source.read_text(), original)
                self.assertEqual(output.stat().st_mode & 0o777, 0o600)
                self.assertIn('/* authored body marker */', text)
                self.assertIn('ts2_scoped_write32(destination,value);', text)
                self.assertIn('ts2_scoped_write32(other,word);', text)
                self.assertEqual(text.count('    runtime_dispatch(0xA01AB770u);'), 32)
                self.assertEqual(text.count('    runtime_dispatch(0xA01AB78Cu);'), 32)
                self.assertIn('ts2_scoped_call(va,s)', text)
                self.assertIn('runtime_nested(bridge_va_##func)', text)
                self.assertIn('report.journal[i].before!=expected[i].before', text)
                with self.assertRaises(FileExistsError):
                    bridge.prepare(source, output)

    def test_pin_and_store_shape_reject_without_output(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'work') as d:
            source, output = Path(d)/'source.c', Path(d)/'out.c'
            source.write_text(fixture())
            with self.assertRaisesRegex(ValueError, 'pin mismatch'):
                bridge.prepare(source, output)
            for text in (fixture().replace('MEM32(other) = word;', ''),
                         fixture().replace('    cache_1ab770();', 'unexpected();', 1),
                         fixture().replace('static void case_0(void) {', 'wrong')):
                source.write_text(text)
                with patch.object(bridge, 'SOURCE_SHA', hashlib.sha256(source.read_bytes()).hexdigest()):
                    with self.assertRaisesRegex(ValueError, 'structure'):
                        bridge.prepare(source, output)
                self.assertFalse(output.exists())

    def test_output_escape_rejects_before_private_source_read(self):
        with tempfile.TemporaryDirectory() as external, tempfile.TemporaryDirectory(dir=ROOT/'work') as private:
            output = Path(external)/'out.c'
            link = Path(private)/'link'
            link.symlink_to(external, target_is_directory=True)
            for target in (output, link/'out.c'):
                with self.assertRaisesRegex(ValueError, 'private work'):
                    bridge.prepare(Path('absent'), target)
            self.assertFalse(output.exists())


class PrivateScopedComparisonTests(unittest.TestCase):
    def test_all_state_components_and_stream_completeness(self):
        state = {'regs': dict.fromkeys(REGS, 0), 'eflags': 0x602,
                 'mem': {'2684420096': 165}, 'fp_depth': 0, 'st': []}
        record = 'R'+' 00000000'*8+'\nF 00000602\nT 0\nM A0010000 A5\nENDCASE\n'
        text = ''.join(f'CASE {i}\n'+record for i in range(64))
        with tempfile.TemporaryDirectory() as d:
            ref, out = Path(d)/'ref.json', Path(d)/'out.txt'
            ref.write_text(json.dumps({'states': [state]*64}))
            out.write_text(text)
            with self.assertRaisesRegex(ValueError, 'pin mismatch'):
                checker.check(ref, out)
            with patch.object(checker, 'REFERENCE_SHA', hashlib.sha256(ref.read_bytes()).hexdigest()):
                self.assertEqual(checker.check(ref, out), 64)
                mutations = []
                for i in range(8):
                    regs = ['00000000']*8
                    regs[i] = '00000001'
                    mutations.append(text.replace('R'+' 00000000'*8, 'R '+' '.join(regs), 1))
                mutations += [text.replace('00000602', '00000603', 1),
                              text.replace('A5', 'A4', 1), text+'extra\n', text[:-8],
                              text.replace('CASE 1\n', 'CASE 0\n', 1),
                              text.replace('T 0\n', 'T 1 1.0\n', 1)]
                for changed in mutations:
                    out.write_text(changed)
                    with self.assertRaises(ValueError):
                        checker.check(ref, out)
