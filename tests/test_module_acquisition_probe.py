"""Authored x86 harness controls: no owner input is read."""
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
import module_acquisition_probe as p
r = p.r


def word(value):
    return struct.pack('<I',value)


def fixture(target, args, *, cleanup=0, publish=False):
    # Public fixture deliberately has no original loop or branch structure.
    code = bytearray(b'\x55\x89\xe5\x51\x53\x56\x57')
    for value in reversed(args):
        code += b'\x68'+word(value)
    code += b'\xb8'+word(target)+b'\xff\xd0'
    ret = p.RVA+len(code)
    if cleanup:
        code += b'\x83\xc4'+bytes([cleanup])
    if publish:
        code += b'\xa3'+word(p.MODULES+4)
    code += b'\x5f\x5e\x5b\xc9\xc3'
    return bytes(code),ret


class ModuleAcquisitionTests(unittest.TestCase):
    def test_oracle_empty_hot_and_negative_ranges(self):
        responses=((r.H1,87,1,1,r.H2),)*2
        self.assertEqual(p.oracle((0,0),responses,0),
                         dict(events=[],eax=0,esp=r.SP+4,modules=[0,0]))
        self.assertEqual(p.oracle((r.H1,0),responses)['events'],[])
        negative=p.oracle((r.NEG,r.H2),responses)
        self.assertEqual(negative['eax'],r.H2)
        self.assertEqual(negative['modules'],[r.NEG,r.H2])
        self.assertEqual(negative['events'],[])
        self.assertEqual(p.oracle((r.NEG,r.NEG),responses)['eax'],0)

    def test_oracle_both_prefixes_veto_retry_independently(self):
        for cmp1,cmp2,kinds in ((0,1,['load','error','compare']),
                                (1,0,['load','error','compare','compare']),
                                (r.NEG,1,['load','error','compare','compare','load'])):
            s=p.oracle((0,r.NEG),((0,87,cmp1,cmp2,r.H1),(0,0,0,0,0)))
            self.assertEqual([e[0] for e in s['events']],kinds)
            self.assertEqual(s['eax'],r.H1 if cmp1 and cmp2 else 0)
            self.assertEqual(s['modules'][0],s['eax'] or r.NEG)
            self.assertEqual(s['events'][2],('compare',[r.NAME,p.PREFIXES[0],7],0x847E03,r.SP-36))
            if cmp1:
                self.assertEqual(s['events'][3],('compare',[r.NAME,p.PREFIXES[1],7],0x847E17,r.SP-36))
            if cmp1 and cmp2:
                self.assertEqual(s['events'][-1],('load',[r.NAME,0,0],0x847E27,r.SP-36))

    def test_oracle_error_filter_and_failed_first_module_continue(self):
        s=p.oracle((0,0),((0,5,1,1,r.H1),(r.H2,0,0,0,0)))
        self.assertEqual(s,dict(events=[('load',[r.NAME,0,0x800],0x847DE5,r.SP-36),
                    ('error',[],0x847DF1,r.SP-24),
                    ('load',[r.NAME+128,0,0x800],0x847DE5,r.SP-36)],
                    eax=r.H2,esp=r.SP+4,modules=[r.NEG,r.H2]))
        s=p.oracle((0,0),((r.H1,0,0,0,0),(r.H2,0,0,0,0)))
        self.assertEqual(len(s['events']),1)
        self.assertEqual(s['modules'],[r.H1,0])

    def test_authored_stdcall_load_and_publication(self):
        args=[r.NAME,0,0x800]
        code,ret=fixture(r.TRAPS,args,publish=True)
        for salt in (0,7):
            for result in (1,0x80000000,r.H1):
                observed=p.exercise(code,(0,r.NEG),((result,0,0,0,0),(0,0,0,0,0)),salt=salt)
                self.assertEqual(observed,dict(events=[('load',args,ret,r.SP-36)],
                    eax=result,esp=r.SP+4,modules=[result,r.NEG]))

    def test_authored_cdecl_comparator_and_cleanup(self):
        args=[r.NAME,p.PREFIXES[0],7]
        # First call establishes module response context, then independent compare.
        first,_=fixture(r.TRAPS,[r.NAME,0,0x800])
        code=bytearray(first[:-5])
        for a in reversed(args):code+=b'\x68'+word(a)
        code+=b'\xb8'+word(p.COMPARE)+b'\xff\xd0'
        ret=p.RVA+len(code)
        code+=b'\x83\xc4\x0c\x5f\x5e\x5b\xc9\xc3'
        observed=p.exercise(bytes(code),(0,0),((0,87,r.NEG,0,0),(0,0,0,0,0)))
        self.assertEqual(observed['events'][-1],('compare',args,ret,r.SP-36))
        self.assertEqual(observed['eax'],r.NEG)
        # Missing cdecl cleanup corrupts saved nonvolatile registers; rejects.
        bad=bytes(code).replace(b'\x83\xc4\x0c',b'\x90\x90\x90')
        with self.assertRaises((ValueError,p.UcError)):
            p.exercise(bad,(0,0),((0,87,1,0,0),(0,0,0,0,0)))

    def test_every_compared_component_mutation_rejects(self):
        s=p.oracle((0,r.NEG),((r.H1,0,0,0,0),(0,0,0,0,0)))
        mutations=[]
        for field in ('eax','esp'):
            b=copy.deepcopy(s);b[field]^=1;mutations.append(b)
        for n in range(2):
            b=copy.deepcopy(s);b['modules'][n]^=1;mutations.append(b)
        b=copy.deepcopy(s);b['events']=[];mutations.append(b)
        for field in range(4):
            b=copy.deepcopy(s);event=list(b['events'][0])
            event[field]=('wrong' if field==0 else [0,0,0] if field==1 else event[field]+4)
            b['events'][0]=tuple(event);mutations.append(b)
        for b in mutations:
            with self.assertRaises(ValueError):r.verify(s,b)

    def test_boundaries_immutable_frame_nonvolatile_and_unknown_calls(self):
        responses=((0,0,0,0,0),)*2
        for code in (b'\xeb\xfe',b'\xc2',b'\xbb'+word(1)+b'\xc3',
                     b'\xa3'+word(p.NAMES)+b'\xc3',
                     b'\xa3'+word(p.MODULES)+b'\xc3',
                     b'\xc7\x04\x24'+word(0)+b'\xc3',
                     b'\xb8'+word(r.BASE+0x82A212)+b'\xff\xd0\xc3'):
            with self.assertRaises((ValueError,p.UcError)):
                p.exercise(code,(0,0),responses)
        for modules,resp,length in (((0,),responses,2),((0,-1),responses,2),
                                    ((0,0),((0,),)*2,2),((0,0),responses,3)):
            with self.assertRaises(ValueError):p.exercise(b'\xc3',modules,resp,length)

    def test_index_boundary_mnemonic_and_provenance_controls(self):
        # Authored 74-instruction body; not an original instruction fixture.
        code=b'\x90'*73+b'\xc3'
        doc=dict(program=dict(executableSha256=r.PIN,imageBaseVa=hex(r.BASE)),
                 function=dict(entryRva=hex(p.RVA),disassembly=dict(items=[
                     dict(rva=hex(p.RVA+n),text='NOP' if n<73 else 'RET') for n in range(74)])),
                 truncation={k:False for k in ('instructions','references','callers','callees')})
        self.assertEqual(p.compare_index(code,doc),74)
        for field in ('pin','base','entry','boundary','mnemonic','truncated'):
            bad=copy.deepcopy(doc)
            if field=='pin':bad['program']['executableSha256']='0'*64
            elif field=='base':bad['program']['imageBaseVa']='0x400000'
            elif field=='entry':bad['function']['entryRva']='0x82a212'
            elif field=='boundary':bad['function']['disassembly']['items'][20]['rva']='0x1'
            elif field=='mnemonic':bad['function']['disassembly']['items'][20]['text']='RET'
            else:bad['truncation']['instructions']=True
            with self.assertRaises(ValueError):p.compare_index(code,bad)

    def test_pin_failure_sanitized_readonly(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'secret.bin';path.write_bytes(b'private fixture')
            out,err=io.StringIO(),io.StringIO()
            with patch.object(r,'IMAGE',path),contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):
                self.assertEqual(p.main([]),2)
            self.assertEqual(out.getvalue(),'')
            self.assertNotIn(str(path),err.getvalue())
            self.assertNotIn('private fixture',err.getvalue())
            self.assertEqual(path.read_bytes(),b'private fixture')


if __name__=='__main__':unittest.main()
