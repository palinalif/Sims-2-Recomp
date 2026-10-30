from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import analyze_install as analysis
from test_analysis import synthetic_pe


def detailed_pe():
    data=bytearray(synthetic_pe());data.extend(b'\0'*(0xa00-len(data)))
    opt=0x98;sec=opt+224
    struct.pack_into('<I',data,sec+8,0x800);struct.pack_into('<I',data,sec+16,0x800)
    # All data is authored; addresses use one deliberately simple test section.
    for index,rva,size in [(1,0x1100,40),(13,0x1200,64),(9,0x1300,24)]:
        struct.pack_into('<II',data,opt+96+index*8,rva,size)
    struct.pack_into('<IIIII',data,0x300,0x1180,0,0,0x1160,0x1190)
    data[0x360:0x36d]=b'KERNEL32.dll\0'
    struct.pack_into('<III',data,0x380,0x11a0,0x80000007,0)
    struct.pack_into('<III',data,0x390,0x11a0,0x80000007,0)
    data[0x3a0:0x3af]=b'\0\0GetTickCount\0'
    struct.pack_into('<IIIIIIII',data,0x400,1,0x1260,0,0x1290,0x1280,0,0,0)
    data[0x460:0x46b]=b'USER32.dll\0'
    struct.pack_into('<II',data,0x480,0x12a0,0)
    struct.pack_into('<II',data,0x490,0x12a0,0)
    data[0x4a0:0x4ae]=b'\0\0MessageBoxA\0'
    struct.pack_into('<IIIIII',data,0x500,0x401370,0x401374,0x401360,0x401340,4,0)
    struct.pack_into('<III',data,0x540,0x401010,0x401020,0)
    return bytes(data)


def tls_pe64():
    data=bytearray(0xa00);data[:0x98]=synthetic_pe()[:0x98]
    struct.pack_into('<H',data,0x84,0x8664);struct.pack_into('<H',data,0x94,240)
    opt=0x98;struct.pack_into('<H',data,opt,0x20b)
    struct.pack_into('<IIQII',data,opt+16,0x1000,0x1000,0x140000000,0x1000,0x200)
    struct.pack_into('<II',data,opt+56,0x2000,0x200);struct.pack_into('<I',data,opt+108,16)
    struct.pack_into('<II',data,opt+112+9*8,0x1300,40)
    sec=opt+240;data[sec:sec+8]=b'.text\0\0\0'
    struct.pack_into('<IIII',data,sec+8,0x800,0x1000,0x800,0x200)
    struct.pack_into('<I',data,sec+36,0x60000020)
    struct.pack_into('<QQQQII',data,0x500,0x140001370,0x140001374,0x140001360,0x140001340,4,0)
    struct.pack_into('<QQQ',data,0x540,0x140001010,0x140001020,0)
    return bytes(data)


class PEDetailTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.exe=self.root/'Sims2.exe';self.exe.write_bytes(detailed_pe())
    def tearDown(self):self.temp.cleanup()
    def test_named_ordinal_and_delay_imports_include_guest_iat_addresses(self):
        report=analysis.inspect_pe(self.exe)
        direct=report['imports'][0]
        self.assertEqual(direct['dll'],'KERNEL32.dll')
        self.assertEqual(direct['symbols'],['GetTickCount','ordinal:7'])
        self.assertEqual(direct['entries'][0]['iat_va'],0x401190)
        self.assertEqual(direct['entries'][1]['ordinal'],7)
        delayed=report['delay_imports'][0]
        self.assertEqual(delayed['symbols'],['MessageBoxA'])
        self.assertEqual(delayed['entries'][0]['iat_va'],0x401290)
    def test_tls_callbacks_are_bounded_and_reported_without_execution(self):
        report=analysis.inspect_pe(self.exe)
        self.assertEqual(report['tls']['callbacks'],[0x401010,0x401020])
        self.assertFalse(report['tls']['callbacks_truncated'])
        self.assertFalse(report['execution_supported'])
        data=bytearray(detailed_pe());struct.pack_into('<I',data,0x500+12,0x401600)
        for i in range(65):struct.pack_into('<I',data,0x800+4*i,0x401010)
        self.exe.write_bytes(data);report=analysis.inspect_pe(self.exe)
        self.assertEqual(len(report['tls']['callbacks']),64)
        self.assertTrue(report['tls']['callbacks_truncated'])
    def test_unmapped_tls_callbacks_report_problem(self):
        data=bytearray(detailed_pe());struct.pack_into('<I',data,0x500+12,0x90000000);self.exe.write_bytes(data)
        report=analysis.inspect_pe(self.exe)
        self.assertEqual(report['tls']['callbacks'],[])
        self.assertTrue(report['tls']['callback_errors'])
    def test_pe64_tls_callback_addresses_keep_upper_bits(self):
        self.exe.write_bytes(tls_pe64());report=analysis.inspect_pe(self.exe)
        self.assertEqual(report['machine'],'x86_64')
        self.assertEqual(report['image_base'],0x140000000)
        self.assertEqual(report['tls']['callbacks'],[0x140001010,0x140001020])
        self.assertFalse(report['execution_supported'])
    def test_tls_raw_backing_does_not_require_full_virtual_size(self):
        for size in [0,0x20]:
            data=bytearray(detailed_pe());struct.pack_into('<I',data,0x98+224+8,size);self.exe.write_bytes(data)
            report=analysis.inspect_pe(self.exe)
            self.assertEqual(report['tls']['callbacks'],[0x401010,0x401020])
            self.assertFalse(report['tls']['callback_errors'])
    def test_dll_census_can_be_included_and_is_budgeted(self):
        (self.root/'helper.dll').write_bytes(detailed_pe())
        discovery=analysis.discover(self.root)
        self.assertEqual(discovery['libraries'],['helper.dll'])
        report=analysis.analyze_tree(self.root,include_dlls=True)
        self.assertEqual(len(report['binaries']),2)
        self.assertFalse(report['analysis_truncated'])
        limited=analysis.analyze_tree(self.root,include_dlls=True,max_binaries=1)
        self.assertEqual(len(limited['binaries']),1)
        self.assertTrue(limited['analysis_truncated'])
        self.assertTrue(analysis.analyze_tree(self.root,max_binary_bytes=1)['analysis_truncated'])
    def test_invalid_files_also_consume_inspection_budget(self):
        self.exe.write_bytes(b'MZ-invalid')
        (self.root/'Sims2EP9.exe').write_bytes(detailed_pe())
        report=analysis.analyze_tree(self.root,max_binary_bytes=len(detailed_pe()))
        self.assertEqual(len(report['binaries']),1)
        self.assertIn('error',report['binaries'][0])
        self.assertTrue(report['analysis_truncated'])
        self.assertEqual(report['binary_bytes_inspected'],len(b'MZ-invalid'))


if __name__=='__main__':unittest.main()
