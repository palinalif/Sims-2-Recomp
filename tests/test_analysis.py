import hashlib
import json
import pathlib
import struct
import sys
import tempfile
import unittest
import subprocess

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'tools'))
import analyze_install as analysis


def synthetic_pe():
    # Authored test fixture, not derived from a game. One section and no imports.
    data = bytearray(0x400)
    data[:2] = b'MZ'
    struct.pack_into('<I', data, 0x3c, 0x80)
    data[0x80:0x84] = b'PE\0\0'
    struct.pack_into('<HHIIIHH', data, 0x84, 0x14c, 1, 0, 0, 0, 224, 0x102)
    opt = 0x98
    struct.pack_into('<H', data, opt, 0x10b)
    struct.pack_into('<III', data, opt+16, 0x1000, 0x1000, 0x2000)
    struct.pack_into('<III', data, opt+28, 0x400000, 0x1000, 0x200)
    struct.pack_into('<II', data, opt+56, 0x2000, 0x200)
    struct.pack_into('<H', data, opt+68, 2)
    struct.pack_into('<I', data, opt+92, 16)
    sec = opt+224
    data[sec:sec+8] = b'.text\0\0\0'
    struct.pack_into('<IIII', data, sec+8, 0x200, 0x1000, 0x200, 0x200)
    struct.pack_into('<I', data, sec+36, 0x60000020)
    data[0x200:0x209] = bytes.fromhex('8b44240483c007c390')
    return bytes(data)


class AnalysisTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
    def tearDown(self):
        self.tmp.cleanup()
    def test_unknown_pe_is_report_only_and_hash_is_exact(self):
        p = self.root/'Sims2.exe'; p.write_bytes(synthetic_pe())
        result = analysis.inspect_pe(p, {'schema': 1, 'versions': []})
        self.assertEqual(result['machine'], 'x86')
        self.assertEqual(result['sha256'], hashlib.sha256(synthetic_pe()).hexdigest())
        self.assertEqual(result['entry_rva'], 0x1000)
        self.assertEqual(result['status'], 'unknown')
        self.assertFalse(result['execution_supported'])
        self.assertEqual(result['imports'], [])
        self.assertEqual(result['sections'][0]['name'], '.text')
        self.assertEqual(p.read_bytes(), synthetic_pe())
    def test_hash_recognition_does_not_enable_execution(self):
        p=self.root/'Sims2.exe'; p.write_bytes(synthetic_pe())
        r=analysis.inspect_pe(p, {'schema':1,'versions':[{'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'id':'fixture'}]})
        self.assertEqual(r['version_id'],'fixture')
        self.assertFalse(r['execution_supported'])
    def test_malformed_binary_fails(self):
        for content in [b'',b'MZ',b'MZ'+b'\0'*62,b'not a PE']:
            p=self.root/'broken.exe';p.write_bytes(content)
            with self.assertRaises(ValueError): analysis.inspect_pe(p)
    def test_case_insensitive_discovery_and_no_symlinks(self):
        folder=self.root/'TSBin';folder.mkdir()
        (folder/'SIMS2.EXE').write_bytes(synthetic_pe())
        (self.root/'loop').symlink_to(self.root,target_is_directory=True)
        result=analysis.discover(self.root)
        self.assertEqual(len(result['executables']),1)
        self.assertFalse(result['truncated'])
        self.assertTrue(analysis.discover(self.root,max_entries=1)['truncated'])
    def test_dbpf_bounds_and_index_metadata(self):
        p=self.root/'fixture.package'; data=bytearray(96+20)
        struct.pack_into('<4sII',data,0,b'DBPF',1,1)
        struct.pack_into('<IIII',data,32,7,1,96,20)
        struct.pack_into('<I',data,60,0)
        p.write_bytes(data)
        result=analysis.inspect_dbpf(p)
        self.assertEqual(result['entries'],1)
        self.assertEqual(result['index_major'],7)
        struct.pack_into('<I',data,60,1);p.write_bytes(data)
        self.assertEqual(analysis.inspect_dbpf(p)['entries'],1)
        struct.pack_into('<I',data,60,2);p.write_bytes(data)
        with self.assertRaises(ValueError):analysis.inspect_dbpf(p)
        struct.pack_into('<I',data,40,0xfffffff0);p.write_bytes(data)
        with self.assertRaises(ValueError):analysis.inspect_dbpf(p)
    def test_leaf_probe_is_hash_and_range_gated(self):
        from probe_function import extract
        p=self.root/'Sims2.exe';p.write_bytes(synthetic_pe())
        sha=hashlib.sha256(p.read_bytes()).hexdigest()
        code=extract(p,sha,0x1000,8)
        self.assertEqual(code,bytes.fromhex('8b44240483c007c3'))
        for digest,rva,size in [('0'*64,0x1000,8),(sha,0x2000,8),(sha,0x1000,100000)]:
            with self.assertRaises(ValueError):extract(p,digest,rva,size)

    def test_known_protected_build_is_rejected_before_leaf_decoding(self):
        from probe_function import extract
        p=self.root/'Sims2.exe';p.write_bytes(synthetic_pe())
        sha=hashlib.sha256(p.read_bytes()).hexdigest()
        catalog={'versions':[{'sha256':sha,'recompilation_ready':False,
                              'blocker':'Protected executable requires a different code input'}]}
        with self.assertRaisesRegex(ValueError,'Protected executable'):
            extract(p,sha,0x1000,8,catalog=catalog)
        catalog['versions'][0]['recompilation_ready']=True
        self.assertEqual(extract(p,sha,0x1000,8,catalog=catalog),bytes.fromhex('8b44240483c007c3'))

    def test_report_output_does_not_clobber_inputs_or_install(self):
        project=pathlib.Path(__file__).resolve().parents[1]
        (project/'work').mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=project/'work') as tmp:
            install=pathlib.Path(tmp);p=install/'Sims2.exe';p.write_bytes(synthetic_pe())
            alias=install/'alias';alias.hardlink_to(p)
            link=install/'symlink';link.symlink_to(p)
            for dest in [p,alias,link,install/'new-report.json']:
                r=subprocess.run([sys.executable,str(project/'tools/analyze_install.py'),'--install',str(install),'--output',str(dest)],capture_output=True)
                self.assertNotEqual(r.returncode,0)
                self.assertEqual(p.read_bytes(),synthetic_pe())
            for dest in [p,alias,link]:
                r=subprocess.run([sys.executable,str(project/'tools/probe_function.py'),'--exe',str(p),'--sha256',hashlib.sha256(p.read_bytes()).hexdigest(),
                    '--rva','0x1000','--size','8','--out',str(dest)],capture_output=True)
                self.assertNotEqual(r.returncode,0)
                self.assertEqual(p.read_bytes(),synthetic_pe())

    def test_execution_contract_rejects_unchecked_memory_and_control_flow(self):
        from leaf_contract import validate
        validate(bytes.fromhex('8b442404034424088944240cc3'))
        for code in ['a100000000c3','8901c3','89c48b442404c3','eb00c3','50c3','c20800','8b442414c3','64a100000000c3','90'*4097+'c3']:
            with self.assertRaises(ValueError,msg=code[:40]):validate(bytes.fromhex(code))

    def test_probe_record_is_bound_to_original_bytes(self):
        from probe_function import verify_record
        p=self.root/'Sims2.exe';p.write_bytes(synthetic_pe())
        record={'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'rva':0x1000,'size':8,
                'code_hex':'8b44240483c007c3'}
        self.assertEqual(verify_record(p,record),bytes.fromhex(record['code_hex']))
        for key,value in [('code_hex','90'*8),('sha256','0'*64),('size',9)]:
            with self.assertRaises(ValueError):verify_record(p,dict(record,**{key:value}))


if __name__ == '__main__': unittest.main()
