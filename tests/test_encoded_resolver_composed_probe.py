"""Public authored composition controls; no owner image is opened."""
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
import encoded_resolver_composed_probe as p
r,c,m = p.r,p.c,p.m


def word(value): return struct.pack('<I',value)


def fixture(cookie, export):
    # Independent authored test schedule, not a copy of original game bodies.
    code=bytearray(b'\x55\x89\xe5\x53\x56')
    code+=b'\x8b\x15'+word(c.CACHE+4*33)+b'\x33\x15'+word(c.COOKIE)
    code+=b'\x8b\x0d'+word(c.COOKIE)+b'\x83\xe1\x1f\xd3\xca\x85\xd2'
    jump=len(code);code+=b'\x75\x00'
    code+=b'\x57\xff\x75\x14\xff\x75\x10\xb8'+word(m.ENTRY)+b'\xff\xd0\x83\xc4\x08'
    code+=b'\x68'+word(r.NAME)+b'\x50\xff\x15'+word(m.IAT+0x124)
    export_return=c.RVA+len(code)
    code+=b'\x89\xc7\x68'+word(export or r.NEG)
    code+=b'\xb8'+word(p.ENCODER)+b'\xff\xd0\x83\xc4\x04'
    code+=b'\xa3'+word(c.CACHE+4*33)+b'\x89\xf8\x5f\x5e\x5b\x5d\xc3'
    hot=len(code);code+=b'\x83\xfa\xff'
    sentinel=len(code);code+=b'\x74\x00\x89\xd0\x85\xc0'
    finishjump=len(code);code+=b'\xeb\x00'
    zero=len(code);code+=b'\x31\xc0'
    finish=len(code);code+=b'\x5e\x5b\x5d\xc3'
    for off,target in ((jump,hot),(sentinel,zero),(finishjump,finish)):
        code[off+1]=target-off-2
    helper=b'\xb8'+word(r.H1)+b'\xc3'
    encoder=b'\xb8'+word(c.encode(export or r.NEG,cookie))+b'\xc3'
    return bytes(code),helper,encoder,export_return


class EncodedResolverComposedTests(unittest.TestCase):
    def test_oracle_export_failure_stops_and_encodes_sentinel(self):
        responses=((0,5,1,1,0),(r.H2,0,0,0,0))
        s=p.oracle(31,(r.H1,0),responses,0)
        self.assertEqual(s['modules'],[r.H1,0])
        self.assertEqual(s['events'],[('export',[r.H1,r.NAME],0x847EC0,r.SP-28)])
        self.assertEqual(s['cache'],c.encode(r.NEG,31))
        self.assertEqual(s['eax'],0)

    def test_oracle_nested_frames_retry_veto_and_continuation(self):
        responses=((0,87,1,0,r.H1),(r.H2,0,0,0,0))
        s=p.oracle(1,(0,0),responses,0x80000000)
        self.assertEqual(s['modules'],[r.NEG,r.H2])
        self.assertEqual([e[0] for e in s['events']],['load','error','compare','compare','load','export'])
        self.assertEqual(s['events'][0][3],r.SP-64)
        self.assertEqual(s['events'][1][3],r.SP-52)
        self.assertEqual(s['cache'],c.encode(0x80000000,1))
        self.assertEqual(p.oracle(1,(0,0),responses,1,0)['events'],[])

    def test_authored_three_body_publication_and_same_memory_reentry(self):
        responses=((0,0,0,0,0),)*2
        for cookie in (0,1,31,0x12345678,r.NEG):
            for export in (0,1,0x80000000):
                resolver,helper,encoder,ret=fixture(cookie,export)
                observed=p.exercise(resolver,helper,encoder,cookie,(r.H1,0),responses,export)
                expected=p.oracle(cookie,(r.H1,0),responses,export)
                expected['events'][0]=('export',[r.H1,r.NAME],ret,r.SP-28)
                self.assertEqual(observed,expected)

    def test_bad_publication_and_cleanup_cannot_pass_reentry(self):
        resolver,helper,encoder,_=fixture(31,0x80000000)
        responses=((0,0,0,0,0),)*2
        bad_encoder=b'\xb8'+word(123)+b'\xc3'
        with self.assertRaises((ValueError,p.UcError)):
            p.exercise(resolver,helper,bad_encoder,31,(r.H1,0),responses,0x80000000)
        # LEAVE could hide stack drift; saved nonvolatile registers must agree too.
        bad=resolver.replace(b'\x83\xc4\x04',b'\x90\x90\x90')
        with self.assertRaises((ValueError,p.UcError)):
            p.exercise(bad,helper,encoder,31,(r.H1,0),responses,0x80000000)

    def test_memory_budget_and_unresolved_targets_reject(self):
        _,helper,encoder,_=fixture(0,1)
        responses=((0,0,0,0,0),)*2
        for code in (b'\xeb\xfe',b'\xc2',b'\xa3'+word(c.COOKIE)+b'\xc3',
                     b'\xa3'+word(m.MODULES)+b'\xc3',
                     b'\xc7\x04\x24'+word(0)+b'\xc3',
                     b'\xb8'+word(r.BASE+0x82A212)+b'\xff\xd0\xc3'):
            with self.assertRaises((ValueError,p.UcError)):
                p.exercise(code,helper,encoder,0,(0,0),responses,1)
        for args in ((-1,(0,0),responses,1),(0,(0,),responses,1),
                     (0,(0,0),responses,r.NEG)):
            with self.assertRaises(ValueError):p.oracle(*args)

    def test_every_observed_component_mutation_rejects(self):
        s=p.oracle(31,(0,0),((r.H1,0,0,0,0),)*2,1)
        for field in ('eax','esp','cache','modules','events'):
            b=copy.deepcopy(s)
            if field=='modules':b[field][0]^=1
            elif field=='events':b[field]=[]
            else:b[field]^=1
            with self.assertRaises(ValueError):r.verify(b,s)

    def test_encoder_index_contract_and_pin_rejection(self):
        code=b'\x90'*12+b'\xc3'
        d=dict(program=dict(executableSha256=r.PIN,imageBaseVa=hex(r.BASE)),
               function=dict(entryRva=hex(p.ENCODER-r.BASE),disassembly=dict(items=[
                   dict(rva=hex(p.ENCODER-r.BASE+n),text='NOP' if n<12 else 'RET') for n in range(13)])),
               truncation={k:False for k in ('instructions','references','callers','callees')})
        self.assertEqual(p.compare_encoder_index(code,d),13)
        for key in ('pin','base','entry','boundary','mnemonic','truncation'):
            b=copy.deepcopy(d)
            if key=='pin':b['program']['executableSha256']='0'*64
            elif key=='base':b['program']['imageBaseVa']='0x400000'
            elif key=='entry':b['function']['entryRva']='0'
            elif key=='boundary':b['function']['disassembly']['items'][0]['rva']='0'
            elif key=='mnemonic':b['function']['disassembly']['items'][0]['text']='RET'
            else:b['truncation']['instructions']=True
            with self.assertRaises(ValueError):p.compare_encoder_index(code,b)
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'private.bin';path.write_bytes(b'private fixture')
            out,err=io.StringIO(),io.StringIO()
            with patch.object(r,'IMAGE',path),contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):
                self.assertEqual(p.main([]),2)
            self.assertEqual(out.getvalue(),'')
            self.assertNotIn(str(path),err.getvalue())
            self.assertEqual(path.read_bytes(),b'private fixture')


if __name__=='__main__':unittest.main()
