"""Public authored controls; never open owner-only code."""
import contextlib
import copy
import io
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import encoded_cache_probe as p
r = p.r


def imm(value):
    return struct.pack('<I',value)


def authored(value,cookie,index):
    # Public fixture: explicit frame saves and immediate return-state assignment.
    # This tests the harness/oracle ABI, not original instruction equivalence.
    code = b'\x55\x89\xe5\x53\x56'
    code += b'\xb9'+imm(cookie & 31)+b'\xba'+imm(value)
    code += b'\xb8'+imm(0 if value==r.NEG else value)
    code += b'\x85\xc0\x5e\x5b\x5d\xc3'
    return code


class EncodedCacheTests(unittest.TestCase):
    def test_encode_decode_all_counts_and_edges(self):
        for count in range(32):
            cookie = 0x12345660 | count
            for value in (0,1,31,32,0x7FFFFFFF,0x80000000,r.NEG):
                encoded = p.encode(value,cookie)
                self.assertEqual(p.rotate(encoded^cookie,count),value)
        self.assertEqual(p.encode(0,0x12345678),0x12345678)
        # Independent known vectors, including wraparound and count zero.
        self.assertEqual(p.rotate(0x80000001,1),0xC0000000)
        self.assertEqual(p.rotate(0x80000001,31),3)
        self.assertEqual(p.encode(0x80000001,1),2)
        self.assertEqual(p.encode(0x80000001,32),0x80000021)

    def test_authored_hot_abi_matches_full_oracle(self):
        for value in (1,0x80000000,r.NEG):
            for cookie in (0,31,0x12345678,r.NEG):
                observed = p.exercise(authored(value,cookie,33),cookie,p.encode(value,cookie))
                r.verify(observed,p.oracle(value,cookie))
                self.assertEqual(observed['stack'][r.SP-r.STACK-16:r.SP-r.STACK-12],b'\x5a'*4)

    def test_authored_decode_reads_actual_cookie_and_indexed_slot(self):
        # Independent authored leaf using EAX, ECX only (not original ABI).
        code = b'\xa1'+imm(p.CACHE+4*33)+b'\x33\x05'+imm(p.COOKIE)
        code += b'\x8b\x0d'+imm(p.COOKIE)+b'\xd3\xc8\xc3'
        for cookie in (0,31,32,33,r.NEG):
            for value in (0,1,0x80000000,r.NEG):
                s=p.exercise(code,cookie,p.encode(value,cookie))
                self.assertEqual(s['registers'][0],value)
                self.assertEqual(s['registers'][7],r.SP+4)
        # Read a neighboring untouched slot: must not match the selected value.
        wrong=code.replace(imm(p.CACHE+4*33),imm(p.CACHE+4*32))
        self.assertNotEqual(p.exercise(wrong,0,1)['registers'][0],1)

    def test_full_probe_with_independent_authored_decoder(self):
        # Different instruction schedule/addressing from the private original.
        code=bytearray(b'\x55\x89\xe5\x53\x56\x8b\x45\x08')
        code+=b'\x8b\x14\x85'+imm(p.CACHE)
        code+=b'\x33\x15'+imm(p.COOKIE)+b'\x8b\x0d'+imm(p.COOKIE)
        code+=b'\x83\xe1\x1f\xd3\xca\x83\xfa\xff'
        sentinel=len(code);code+=b'\x74\x00'
        code+=b'\x85\xd2'
        nonzero=len(code);code+=b'\x75\x00'
        code+=b'\xb8'+imm(r.BASE+0x847DA1)+b'\xff\xd0'
        live=len(code);code+=b'\x89\xd0'
        endjump=len(code);code+=b'\xeb\x00'
        zero=len(code);code+=b'\x31\xc0'
        end=len(code);code+=b'\x5e\x5b\x5d\xc3'
        for offset,target in ((sentinel,zero),(nonzero,live),(endjump,end)):
            code[offset+1]=target-offset-2
        code+=b'\x90'*(p.SIZE-len(code))
        class AuthoredPe:
            def get_data(self,rva,size):
                self_assert=(rva==p.RVA and size==p.SIZE)
                if not self_assert:raise AssertionError('unexpected range')
                return bytes(code)
        result=p.probe(AuthoredPe())
        self.assertEqual(result['cases'],288)
        self.assertEqual(result['coldPathsRejected'],4)
        self.assertEqual(result['wrongDecodeModelsRejected'],4)
        self.assertFalse(result['externalServicesExecuted'])

    def test_full_state_mutations_reject(self):
        s=p.oracle(0xC7000020,31)
        for n in range(8):
            bad=copy.deepcopy(s); bad['registers'][n]^=1
            with self.assertRaises(ValueError):r.verify(bad,s)
        for bit in (0,2,6,7,10,11):
            bad=copy.deepcopy(s);bad['flags']^=1<<bit
            with self.assertRaises(ValueError):r.verify(bad,s)
        for offset in (0,r.SP-r.STACK-16,r.SP-r.STACK,4095):
            bad=copy.deepcopy(s);b=bytearray(bad['stack']);b[offset]^=1;bad['stack']=bytes(b)
            with self.assertRaises(ValueError):r.verify(bad,s)

    def test_wrong_cleanup_and_sentinel_models_reject(self):
        good=authored(r.NEG,31,33)
        for code in (good[:-1]+b'\xc2\x10\x00',good.replace(b'\xb8'+imm(0),b'\xb8'+imm(r.NEG))):
            with self.assertRaises(ValueError):
                r.verify(p.exercise(code,31,p.encode(r.NEG,31)),p.oracle(r.NEG,31))
        with self.assertRaises(ValueError):p.oracle(0,0)

    def test_bounds_external_and_immutable_controls(self):
        external=b'\xb8'+imm(r.BASE+0x847DA1)+b'\xff\xd0\xc3'
        for code in (b'\xeb\xfe',b'\xc2',external,
                     b'\xa3'+imm(p.COOKIE)+b'\xc3',
                     b'\xa3'+imm(p.CACHE)+b'\xc3'):
            with self.assertRaises((ValueError,p.UcError)):p.exercise(code,0,1)
        for args in ((b'\xc3',-1,0),(b'\xc3',0,-1),(b'\xc3',0,1,64)):
            with self.assertRaises(ValueError):p.exercise(*args)

    def test_wrong_pin_is_sanitized_and_readonly(self):
        with tempfile.TemporaryDirectory() as tmp:
            image=Path(tmp)/'secret.bin';image.write_bytes(b'private fixture')
            out,err=io.StringIO(),io.StringIO()
            with patch.object(r,'IMAGE',image),contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):
                self.assertEqual(p.main([]),2)
            self.assertEqual(out.getvalue(),'')
            self.assertNotIn(str(image),err.getvalue())
            self.assertNotIn('private fixture',err.getvalue())
            self.assertEqual(image.read_bytes(),b'private fixture')


if __name__=='__main__':unittest.main()
