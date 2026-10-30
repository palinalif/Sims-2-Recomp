"""Authored two-page fixture, occupancy ABI, and checked reference-domain tests."""
import copy
import importlib.util
from pathlib import Path
import struct
import unittest
from unittest.mock import patch

from test_recomp_live_capacity import fixture as capacity_fixture

PATH = Path(__file__).resolve().parents[1]/'scripts/recomp/probe_live_growth.py'
spec = importlib.util.spec_from_file_location('live_growth',PATH)
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
c, b = m.c, m.b


def fixture():
    _, before = capacity_fixture()
    regs, pages = m.resume(before)
    arena = pages[m.heap.ARENA]+pages[m.EXTRA]
    raw = m.heap.ARENA+m.p.OCCUPIED
    arena[m.DESCRIPTOR:m.DESCRIPTOR+20] = bytes(20)
    # Also declare the incoming descriptor empty in the authored fixture.
    incoming = bytearray.fromhex(before['pages'])
    offset = m.p.node.ORDER.index(m.heap.ARENA)*4096+m.DESCRIPTOR
    incoming[offset:offset+20] = bytes(20)
    before['pages'] = incoming.hex()
    key=struct.unpack_from('<I',arena,0x1e0)[0]-m.heap.ARENA
    # Authored fixture has a bounded three-byte key plus terminator.
    arena[key:key+4]=b'key\0'
    incoming=bytearray.fromhex(before['pages'])
    pos=m.p.node.ORDER.index(m.heap.ARENA)*4096+key
    incoming[pos:pos+4]=b'key\0';before['pages']=incoming.hex()
    struct.pack_into('<II',arena,m.p.OCCUPIED,0,1024)
    arena[m.p.OCCUPIED+8:m.p.OCCUPIED+12]=arena[key:key+4]
    struct.pack_into('<5I',arena,m.DESCRIPTOR,raw,0,raw+1032,raw+12,raw+12)
    pages[m.heap.ARENA],pages[m.EXTRA] = arena[:4096],arena[4096:]
    outregs=list(regs.values()); outregs[7]+=32
    after = dict(stop_pc=m.STOP_PC,regs=outregs,
                 pages=b''.join(pages[p] for p in m.ORDER).hex())
    service = m.ArenaModel(); service.calls = 1
    service.occupied[:(m.p.OCCUPIED+1032)//8] = [True]*((m.p.OCCUPIED+1032)//8)
    return before,after,service


class LiveGrowthTests(unittest.TestCase):
    def test_contract_and_ten_mutations(self):
        before,after,service = fixture(); saved = copy.deepcopy((before,after))
        m.contract(before,after,service); m.reject_controls(before,after,service)
        self.assertEqual((before,after),saved)

    def test_resume_preserves_every_existing_page_and_has_explicit_new_page(self):
        before,_,_ = fixture(); _,pages = m.resume(before)
        self.assertEqual(b''.join(pages[p] for p in m.p.node.ORDER).hex(),before['pages'])
        self.assertEqual(pages[m.EXTRA],bytes([0xa5])*4096)
        pages[m.EXTRA][0] = 0
        self.assertEqual(m.resume(before)[1][m.EXTRA][0],0xa5)
        for key in ('pages','regs','boundary'):
            bad = copy.deepcopy(before)
            if key == 'pages': bad[key] = bad[key][:-2]
            elif key == 'regs': bad[key].pop()
            else: bad[key]['site'] ^= 4
            with self.subTest(key=key),self.assertRaises(ValueError): m.resume(bad)

    def test_service_independent_first_fit_crosses_boundary_preserves_bytes(self):
        import unicorn.x86_const as x
        sp,ret = c.DATA_PAGES[0]+128,0x12345678
        class Cpu:
            def __init__(self): self.regs = {'esp':sp}; self.flags=0; self.size=1032
            def reg_read(self,key): return self.regs[key]
            def reg_write(self,key,value): self.regs[key] = value
            def mem_read(self,addr,size):
                self_check = (addr,size)
                if self_check != (sp,16): raise AssertionError(self_check)
                return struct.pack('<4I',ret,m.heap.HANDLE,self.flags,self.size)
            def mem_write(self,*args): raise AssertionError('dirty allocation must not write')
        service = m.ArenaModel(); cpu = Cpu()
        service.invoke(cpu,{'esp':'esp','eax':'eax'},ret)
        self.assertEqual(cpu.regs,{'esp':sp+16,'eax':m.heap.ARENA+3104,x.UC_X86_REG_EIP:ret})
        self.assertEqual(service.occupied,[True]*517+[False]*507)
        cpu.regs['esp']=sp
        with self.assertRaises(ValueError): service.invoke(cpu,{'esp':'esp','eax':'eax'},ret)
        for flags,size in ((8,1032),(0,1031)):
            cpu=Cpu(); cpu.flags=flags; cpu.size=size
            with self.assertRaises(ValueError): m.ArenaModel().invoke(cpu,{'esp':'esp','eax':'eax'},ret)

    def test_advance_explicit_page_and_service_options(self):
        before,after,_=fixture()
        with patch.object(c,'reference',return_value=(after,set())) as ref:
            _,_,service=m.advance(before,{}, {})
        args,opts=ref.call_args
        self.assertEqual(args[2],m.p.STOP[0])
        self.assertEqual(opts['extra_data_pages'],(m.EXTRA,))
        self.assertIs(opts['heap_service'],service)
        self.assertEqual(opts['stop_before_pc'],m.STOP_PC)

    def reference(self,code,extras=(),repeat=False,extra_pages=None,**options):
        from capstone import Cs,CS_ARCH_X86,CS_MODE_32
        md=Cs(CS_ARCH_X86,CS_MODE_32); md.detail=True
        entry=c.BASE+0x1100
        nodes={i.address:i for i in md.disasm(code,entry)}
        regs={r:0 for r in c.REGS}; regs['esp']=c.DATA_PAGES[0]+128
        regs.update(esi=m.heap.ARENA+4092,edi=m.heap.ARENA+4088,ecx=16)
        pages={p:bytearray(4096) for p in (*c.DATA_PAGES,*b.IMAGES)}
        struct.pack_into('<I',pages[c.DATA_PAGES[0]],128,c.RETURN)
        if extra_pages is None: extra_pages=extras
        pages.update({p:bytearray([0xa5])*4096 for p in extra_pages})
        block=bytearray(4096);block[256:256+len(code)]=code
        return c.reference(nodes,{c.BASE+0x1000:block},entry,regs,pages,
            image_pages=b.IMAGES,extra_data_pages=extras,checked_repeat_copy=repeat,**options)

    def test_exact_instruction_boundary_is_not_completion_or_call_response(self):
        entry=c.BASE+0x1100
        result,seen=self.reference(b'\x90\xc3',stop_before_pc=entry+1)
        self.assertEqual(result['stop_pc'],entry+1)
        self.assertEqual(seen,{entry})
        self.assertEqual(result['regs'][7],c.DATA_PAGES[0]+128)
        self.assertNotIn('boundary',result)
        for options in (dict(stop_before_pc=entry+2),dict(stop_before_pc=True),
                        dict(stop_before_pc=entry,stop_before_call=(entry,entry))):
            with self.subTest(options=options),self.assertRaises(ValueError):
                self.reference(b'\x90\xc3',**options)

    def test_explicit_writable_page_default_rejects(self):
        code=b'\xc7\x05'+struct.pack('<II',m.EXTRA,0x12345678)+b'\xc3'
        result,_=self.reference(code,(m.EXTRA,))
        raw=bytes.fromhex(result['pages'])
        self.assertEqual(struct.unpack_from('<I',raw,4*4096)[0],0x12345678)
        with self.assertRaises(Exception): self.reference(code)

    def test_extra_alias_invalid_unmapped_and_excess_pages_reject(self):
        for extras in ((m.EXTRA,m.EXTRA),(c.RETURN,), (b.IMAGES[0],),
                       (c.DATA_PAGES[0],),(m.EXTRA+1,),(-4096,),
                       (0x100000000,),tuple(0x50000000+4096*i for i in range(5)),[m.EXTRA]):
            with self.subTest(extras=extras),self.assertRaises(Exception): self.reference(b'\xc3',extras)
        with self.assertRaises(Exception): self.reference(b'\xc3',(m.EXTRA,),extra_pages=())

    def test_cross_page_repeat_requires_contiguous_owned_pages(self):
        code=b'\xf3\xa4\xc3' # authored rep movsb; both spans cross boundary
        self.reference(code,(m.EXTRA,),True)
        with self.assertRaises(Exception): self.reference(code,(),True)
        with self.assertRaises(Exception): self.reference(code,(m.EXTRA+4096,),True)
        with self.assertRaises(Exception): self.reference(code,(m.EXTRA,),False)

    def test_output_extent_and_service_ownership_reject(self):
        before,after,service=fixture()
        for key in ('pages','regs','calls','occupied'):
            bad=copy.deepcopy(after);model=copy.deepcopy(service)
            if key=='pages':bad[key]=bad[key][:-2]
            elif key=='regs':bad[key].pop()
            elif key=='calls':model.calls=0
            else:model.occupied[0]=False
            with self.subTest(key=key),self.assertRaises(ValueError):m.contract(before,bad,model)


if __name__ == '__main__': unittest.main()
