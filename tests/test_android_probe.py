"""Authored result/device fixtures only. These tests never contact hardware."""
import copy
import pathlib
import sys
import unittest
import json
import subprocess
import tempfile
from unittest.mock import patch

sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'tools'))
import android_probe as probe

OUTPUT='''CASE 0
R A0010040 FFFFFFFF 80000000 13579BDF A0020004 9ABCDEF0 2468ACE0 87654321
F 00000202
T 0
M A0010068 FF
ENDCASE
'''


class AndroidProbeTests(unittest.TestCase):
    def test_parse_preserves_high_addresses_flags_and_memory(self):
        self.assertTrue(hasattr(probe,'parse_output'),'Missing strict output parser')
        state=probe.parse_output(OUTPUT)[0]
        self.assertEqual(state['regs']['eax'],0xa0010040)
        self.assertEqual(state['regs']['ecx'],0xffffffff)
        self.assertEqual(state['eflags'],0x202)
        self.assertEqual(state['mem'],{str(0xa0010068):255})

    def test_partial_duplicate_or_malformed_output_cannot_pass(self):
        self.assertTrue(hasattr(probe,'parse_output'),'Missing strict output parser')
        for text in ['',OUTPUT.replace('ENDCASE\n',''),OUTPUT.replace('T 0\n',''),
                     OUTPUT.replace('CASE 0','CASE 1'),OUTPUT+'junk\n',
                     OUTPUT.replace('F 00000202','F 00000202\nF 00000202'),
                     OUTPUT.replace('M A0010068 FF','M A0010068 FF\nM A0010068 FF'),
                     OUTPUT.replace('T 0','T 1'),OUTPUT.replace('FFFFFFFF','-0000001')]:
            with self.subTest(text=text):
                with self.assertRaises(ValueError):probe.parse_output(text)

    def test_compare_detects_register_flag_and_memory_divergences(self):
        self.assertTrue(hasattr(probe,'parse_output'),'Missing strict output parser')
        expected=probe.parse_output(OUTPUT)
        self.assertEqual(probe.compare(expected,expected)['matched'],1)
        for field in ['regs','eflags','mem']:
            changed=copy.deepcopy(expected)
            if field=='regs':changed[0]['regs']['ebx']^=1
            elif field=='mem':changed[0]['mem'][str(0xa0010068)]=0
            else:changed[0]['eflags']^=1
            result=probe.compare(expected,changed)
            self.assertEqual(result['matched'],0)
            self.assertIn(field,result['differences'][0]['fields'])
        with self.assertRaises(ValueError):probe.compare(expected,[])

    def test_device_checks_require_android_arm64_and_reject_emulator_indicators(self):
        self.assertTrue(hasattr(probe,'validate_device'),'Missing hardware preconditions')
        device={'architecture':'aarch64','abi_list':'arm64-v8a,armeabi-v7a','sdk':'35',
                'qemu':'','boot_qemu':'','hardware':'qcom','model':'Thor','manufacturer':'AYN'}
        probe.validate_device(device)
        for key,value in [('architecture','x86_64'),('abi_list','x86_64'),('sdk','25'),
                          ('sdk',''),('qemu','1'),('boot_qemu','1'),('hardware','ranchu'),
                          ('model','sdk_gphone64_arm64')]:
            with self.subTest(key=key,value=value):
                with self.assertRaises(ValueError):probe.validate_device(dict(device,**{key:value}))

    def test_incomplete_reference_cannot_match_itself(self):
        state=probe.parse_output(OUTPUT)
        del state[0]['regs']['edi']
        with self.assertRaises(ValueError):probe.compare(state,state)

    def test_selection_requires_usb_and_never_defaults_to_network_transport(self):
        self.assertTrue(hasattr(probe,'select_usb_device'),'Missing USB transport gate')
        listing='List of devices attached\nphysical\tdevice\n192.0.2.1:5555\tdevice\n'
        replies=[subprocess.CompletedProcess([],0,listing,''),
                 subprocess.CompletedProcess([],0,'physical\n','')]
        with patch.object(probe.subprocess,'run',side_effect=replies) as run:
            self.assertEqual(probe.select_usb_device('adb',None),'physical')
            self.assertEqual(run.call_args_list[-1].args[0],['adb','-d','get-serialno'])
        with patch.object(probe.subprocess,'run',side_effect=replies):
            with self.assertRaises(ValueError):probe.select_usb_device('adb','192.0.2.1:5555')
        with patch.object(probe.subprocess,'run',side_effect=[replies[0],subprocess.CalledProcessError(1,['adb','-d'])]):
            with self.assertRaises(subprocess.CalledProcessError):probe.select_usb_device('adb',None)

    def test_failed_adb_run_is_reported_and_only_created_remote_directory_removed(self):
        replies=[b'aarch64\n',b'arm64-v8a\n',b'35\n',b'\n',b'\n',b'qcom\n',
                 b'Thor\n',b'AYN\n',b'fingerprint\n',b'15\n',b'16384\n',b'',b'',b'',b'a'*64+b'  leaf-arm64\n']
        calls=[]
        def fake_run(argv,**kwargs):
            calls.append(argv)
            if len(calls)<=len(replies):return subprocess.CompletedProcess(argv,0,replies[len(calls)-1],b'')
            if argv[-1].endswith('/leaf-arm64'):
                return subprocess.CompletedProcess(argv,126,b'',b'permission denied')
            return subprocess.CompletedProcess(argv,0,b'',b'')
        with tempfile.TemporaryDirectory() as tmp,patch.object(probe.subprocess,'run',side_effect=fake_run):
            path=pathlib.Path(tmp)
            report=probe.run_device('adb','serial',path,path,{'sha256':{'leaf-arm64':'a'*64}},probe.parse_output(OUTPUT))
            self.assertFalse(report['hardware_gate_passed'])
            self.assertFalse(report['arm64_executed'])
            self.assertEqual(report['remote_exit_code'],126)
            self.assertEqual(calls[-1][2:5],['shell','rm','-rf'])
            self.assertRegex(calls[-1][-1],r'^/data/local/tmp/ts2-probe-[a-f0-9]{32}$')
            self.assertFalse(json.loads((path/'result.json').read_text())['hardware_gate_passed'])


if __name__=='__main__':unittest.main()
