import hashlib
import json
from pathlib import Path
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import archive_intake as intake


class ArchiveIntakeTests(unittest.TestCase):
    def setUp(self):
        (ROOT/'work').mkdir(exist_ok=True)
        self.temp=tempfile.TemporaryDirectory(dir=ROOT/'work')
        self.root=Path(self.temp.name)
        self.archive=self.root/'legacy.zip'
    def tearDown(self):self.temp.cleanup()
    def make_zip(self,entries):
        with zipfile.ZipFile(self.archive,'w',compression=zipfile.ZIP_DEFLATED) as z:
            for name,data in entries:z.writestr(name,data)
        return self.archive
    def test_preview_is_read_only_and_lists_binary_candidates(self):
        self.make_zip([('Legacy/TSBin/Sims2EP9.exe',b'MZ-fixture'),
                       ('Legacy/TSBin/helper.DLL',b'dll-fixture'),
                       ('Legacy/TSData/Res/Objects.package',b'DBPF-fixture')])
        before=self.archive.read_bytes();report=intake.inspect_archive(self.archive)
        self.assertTrue(report['safe_to_extract_binaries'])
        self.assertEqual(report['analysis_files'],['Legacy/TSBin/Sims2EP9.exe','Legacy/TSBin/helper.DLL'])
        self.assertEqual(report['package_count'],1)
        self.assertEqual(report['analysis_bytes'],len(b'MZ-fixture')+len(b'dll-fixture'))
        self.assertFalse(report['crc_verified'])
        self.assertEqual(self.archive.read_bytes(),before)
        self.assertEqual(sorted(p.name for p in self.root.iterdir()),['legacy.zip'])
    def test_extract_only_binaries_preserves_tree_and_archive(self):
        self.make_zip([('Legacy/TSBin/Sims2.exe',b'MZ-fixture'),('Legacy/TSBin/Helper.dll',b'dll'),
                       ('Legacy/TSData/objects.package',b'assets'),('Legacy/notes.txt',b'notes')])
        before=hashlib.sha256(self.archive.read_bytes()).hexdigest();dest=self.root/'binaries'
        report=intake.extract_binaries(self.archive,dest)
        self.assertEqual(report['status'],'complete')
        self.assertEqual((dest/'Legacy/TSBin/Sims2.exe').read_bytes(),b'MZ-fixture')
        self.assertFalse((dest/'Legacy/TSData').exists())
        self.assertEqual(report['files'][0]['sha256'],hashlib.sha256(b'MZ-fixture').hexdigest())
        self.assertTrue(all(item['crc_verified'] for item in report['files']))
        self.assertEqual(hashlib.sha256(self.archive.read_bytes()).hexdigest(),before)
        self.assertEqual(json.loads((dest/'intake-manifest.json').read_text())['status'],'complete')
    def test_reject_unsafe_names_before_creating_destination(self):
        names=['../escape.exe','/tmp/escape.exe',r'C:\game\evil.exe',r'\\server\share\evil.exe',
               'folder/../evil.exe','a//b.exe','a/./b.exe','CON.dll','dir/file.exe:stream',
               'dir/trailing./file.exe','dir/a?.dll','folder/new\nline.exe']
        for i,name in enumerate(names):
            with self.subTest(name=name):
                self.make_zip([(name,b'payload')]);dest=self.root/f'bad-{i}'
                self.assertFalse(intake.inspect_archive(self.archive)['safe_to_extract_binaries'])
                with self.assertRaises(ValueError):intake.extract_binaries(self.archive,dest)
                self.assertFalse(dest.exists())
    def test_reject_case_unicode_and_file_directory_collisions(self):
        for entries in [[('TSBin/A.dll',b'a'),('tsbin/a.DLL',b'b')],
                        [('caf\u00e9.dll',b'a'),('cafe\u0301.dll',b'b')],
                        [('TSBin',b'a'),('TSBin/A.dll',b'b')],
                        [('TSBin/A.dll',b'a'),('TSBin',b'b')]]:
            self.make_zip(entries)
            self.assertFalse(intake.inspect_archive(self.archive)['safe_to_extract_binaries'])
    def test_parent_directory_aliases_with_different_children_are_rejected(self):
        for entries in [[('Legacy/TSBin/a.exe',b'a'),('Legacy/tsbin/b.dll',b'b')],
                        [('caf\u00e9/a.exe',b'a'),('cafe\u0301/b.dll',b'b')]]:
            self.make_zip(entries)
            self.assertFalse(intake.inspect_archive(self.archive)['safe_to_extract_binaries'])
    def test_path_complexity_is_bounded_before_indexing(self):
        self.make_zip([('a/'*2000+'x.exe',b'fixture')])
        self.assertFalse(intake.inspect_archive(self.archive)['safe_to_extract_binaries'])
        self.make_zip([('one/two/a.exe',b'fixture')])
        self.assertFalse(intake.inspect_archive(self.archive,intake.Limits(max_path_depth=2))['safe_to_extract_binaries'])
        self.assertFalse(intake.inspect_archive(self.archive,intake.Limits(max_path_nodes=2))['safe_to_extract_binaries'])
        self.assertFalse(intake.inspect_archive(self.archive,intake.Limits(max_total_path_bytes=5))['safe_to_extract_binaries'])
    def test_reject_symlinks_and_special_files(self):
        for kind in [stat.S_IFLNK,stat.S_IFIFO,stat.S_IFCHR]:
            info=zipfile.ZipInfo('link.dll');info.create_system=3;info.external_attr=(kind|0o777)<<16
            self.make_zip([(info,b'/some/target')])
            self.assertFalse(intake.inspect_archive(self.archive)['safe_to_extract_binaries'])
    def test_windows_separators_are_normalized_and_detected_as_duplicates(self):
        self.make_zip([(r'Legacy\TSBin\Sims2.exe',b'fixture')])
        self.assertEqual(intake.inspect_archive(self.archive)['analysis_files'],['Legacy/TSBin/Sims2.exe'])
        intake.extract_binaries(self.archive,self.root/'normalized')
        self.assertTrue((self.root/'normalized/Legacy/TSBin/Sims2.exe').is_file())
        self.make_zip([(r'Legacy\TSBin\Sims2.exe',b'a'),('Legacy/TSBin/Sims2.exe',b'b')])
        self.assertFalse(intake.inspect_archive(self.archive)['safe_to_extract_binaries'])
    def test_limits_and_existing_destination_reject_without_overwrite(self):
        self.make_zip([('a.exe',b'1234'),('b.dll',b'5678')])
        for limits in [intake.Limits(max_members=1),intake.Limits(max_total_bytes=7),
                       intake.Limits(max_analysis_bytes=7),intake.Limits(max_binary_bytes=3)]:
            self.assertFalse(intake.inspect_archive(self.archive,limits)['safe_to_extract_binaries'])
        dest=self.root/'existing';dest.mkdir();marker=dest/'marker';marker.write_text('preserve')
        with self.assertRaises((ValueError,FileExistsError)):intake.extract_binaries(self.archive,dest)
        self.assertEqual(marker.read_text(),'preserve')
        with tempfile.TemporaryDirectory() as external:
            with self.assertRaises(ValueError):intake.extract_binaries(self.archive,Path(external)/'out')
    def test_corrupt_payload_never_reports_success(self):
        with zipfile.ZipFile(self.archive,'w',compression=zipfile.ZIP_STORED) as z:z.writestr('a.exe',b'original-bytes')
        with zipfile.ZipFile(self.archive) as z:offset=z.infolist()[0].header_offset
        data=bytearray(self.archive.read_bytes());name,extra=struct.unpack_from('<HH',data,offset+26)
        data[offset+30+name+extra]^=1;self.archive.write_bytes(data)
        dest=self.root/'corrupt'
        with self.assertRaises((ValueError,zipfile.BadZipFile)):intake.extract_binaries(self.archive,dest)
        self.assertNotEqual(json.loads((dest/'intake-manifest.json').read_text())['status'],'complete')
    def test_cli_defaults_to_preview(self):
        self.make_zip([('Sims2.exe',b'fixture')])
        result=subprocess.run([sys.executable,str(ROOT/'tools/archive_intake.py'),str(self.archive)],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(result.stdout)['binary_count'],1)
        self.assertEqual(len(list(self.root.iterdir())),1)
    def test_space_preflight_leaves_no_output_directory(self):
        self.make_zip([('a.exe',b'fixture')]);dest=self.root/'no-space'
        with self.assertRaisesRegex(ValueError,'free space'):
            intake.extract_binaries(self.archive,dest,intake.Limits(reserve_free_bytes=10**30))
        self.assertFalse(dest.exists())
    def test_encrypted_flags_reject_before_staging(self):
        self.make_zip([('a.exe',b'fixture')]);data=bytearray(self.archive.read_bytes())
        central=data.index(b'PK\x01\x02');struct.pack_into('<H',data,central+8,1)
        self.archive.write_bytes(data)
        self.assertFalse(intake.inspect_archive(self.archive)['safe_to_extract_binaries'])
        with self.assertRaises(ValueError):intake.extract_binaries(self.archive,self.root/'encrypted')
        self.assertFalse((self.root/'encrypted').exists())


if __name__=='__main__':unittest.main()
