"""Authored CPU fixtures only; no original game bytes or private inputs."""
import copy
import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest

PATH = Path(__file__).resolve().parents[1]/'scripts/recomp/probe_capacity_service.py'
spec = importlib.util.spec_from_file_location('capacity_service',PATH)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
c = m.c


def fixture(code):
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    md = Cs(CS_ARCH_X86,CS_MODE_32);md.detail=True
    entry = c.BASE+m.h.ROOT_RVA
    nodes = {i.address:i for i in md.disasm(code,entry)}
    p = entry//4096*4096
    data = bytearray(4096);data[entry-p:entry-p+len(code)]=code
    return nodes,{p:data}


def call(target):
    return b'\xe8'+struct.pack('<i',target-(c.BASE+m.h.ROOT_RVA+5))


class CapacityServiceTests(unittest.TestCase):
    def test_corpus_full_and_empty_are_deterministic(self):
        for n in range(64):
            regs,pages=m.state(n)
            self.assertEqual((regs,pages),m.state(n))
            sp=regs['esp']-c.DATA_PAGES[0]
            obj=struct.unpack_from('<I',pages[c.DATA_PAGES[0]],sp+4)[0]
            end,cur,start=struct.unpack_from('<III',pages[c.DATA_PAGES[1]],obj-c.DATA_PAGES[1]+0x1d8)
            self.assertEqual(end,cur)
            # Capacity entry reads the descriptor's allocator selector, unlike
            # the sufficient-capacity path. Never leave it random/unmapped.
            self.assertEqual(struct.unpack_from('<I',pages[c.DATA_PAGES[1]],
                             obj-c.DATA_PAGES[1]+0x1d4)[0],0)
            if n%2:self.assertEqual(cur,start);self.assertNotEqual(cur,0)
            else:self.assertEqual((end,cur,start),(0,0,0))
        for n in (-1,64,True,1.0):
            with self.assertRaises(ValueError):m.state(n)

    def test_stops_before_external_call_without_stack_response(self):
        regs,pages=m.state(0)
        before=copy.deepcopy((regs,pages))
        target=c.BASE+0x831a6f
        result,seen=m.trace(*fixture(call(target)),regs,pages)
        self.assertEqual(result['target'],target)
        self.assertEqual(result['site'],c.BASE+m.h.ROOT_RVA)
        self.assertEqual(result['regs'],regs)
        self.assertEqual(result['pages'],{p:bytes(b) for p,b in pages.items()})
        self.assertEqual(seen,set())
        self.assertEqual((regs,pages),before)

    def test_unknown_transfer_rejects_not_stubbed(self):
        regs,pages=m.state(0)
        with self.assertRaises(ValueError):m.trace(*fixture(call(c.BASE+0x8888)),regs,pages)
        # An indirect target is never silently admitted.
        with self.assertRaises(ValueError):m.trace(*fixture(b'\xff\xd0'),regs,pages)

    def test_budget_exhaustion_rejects(self):
        regs,pages=m.state(0)
        with self.assertRaises(ValueError):m.trace(*fixture(b'\xeb\xfe'),regs,pages,budget=8)
        for budget in (0,4097,True,1.0):
            with self.assertRaises(ValueError):m.trace(*fixture(b'\xeb\xfe'),regs,pages,budget=budget)

    def test_code_write_and_immutable_page_write_reject(self):
        regs,pages=m.state(0)
        # mov [absolute],eax -- authored test instruction.
        for target in (c.BASE+0x2000,c.IMAGE_PAGES[0]):
            code=b'\xa3'+struct.pack('<I',target)
            with self.subTest(target=target),self.assertRaises(ValueError):
                m.trace(*fixture(code),regs,pages)

    def test_checked_read_rejects_code_as_data(self):
        regs,pages=m.state(0)
        code=b'\xa1'+struct.pack('<I',c.BASE+0x2000)
        with self.assertRaises(ValueError):m.trace(*fixture(code),regs,pages)

    def test_bad_page_shapes_and_aliases_reject(self):
        regs,pages=m.state(0)
        nodes,code=fixture(call(c.BASE+0x831a6f))
        bad=copy.deepcopy(pages);bad[c.DATA_PAGES[0]]=b'x'
        with self.assertRaises(ValueError):m.trace(nodes,code,regs,bad)
        with self.assertRaises(ValueError):m.trace(nodes,{**code,c.DATA_PAGES[0]:bytes(4096)},regs,pages)

    def test_internal_call_executes_real_authored_body_and_returns(self):
        regs,pages=m.state(0)
        entry=c.BASE+m.h.ROOT_RVA
        # call local helper; call external; helper: inc eax; ret
        code=call(entry+10)+b'\xe8'+struct.pack('<i',c.BASE+0x831a6f-(entry+10))+b'\x40\xc3'
        result,seen=m.trace(*fixture(code),regs,pages)
        self.assertEqual(result['regs']['eax'],(regs['eax']+1)&0xffffffff)
        self.assertEqual(result['regs']['esp'],regs['esp'])
        self.assertEqual(result['site'],entry+5)
        self.assertEqual(len(seen),3)

    def test_implicit_stack_access_is_checked_before_execution(self):
        regs,pages=m.state(0)
        regs['esp']=c.DATA_PAGES[0]
        with self.assertRaises(ValueError):
            m.trace(*fixture(b'\x50'+call(c.BASE+0x831a6f)),regs,pages)
        regs['esp']=c.IMAGE_PAGES[0]+8
        with self.assertRaises(ValueError):
            m.trace(*fixture(b'\x50'+call(c.BASE+0x831a6f)),regs,pages)

    def test_measured_boundary_contract_and_mutations(self):
        regs,pages=m.state(0)
        observed=dict(target=c.BASE+0x831a6f,site=c.BASE+0x1c00,
            regs=dict(regs,esp=regs['esp']-36),
            pages=copy.deepcopy(pages),calls=[(0,t) for t in
            (c.BASE+0x26b0,c.BASE+m.RVA,c.BASE+0x831a6f)])
        pos=observed['regs']['esp']-c.DATA_PAGES[0]
        struct.pack_into('<I',observed['pages'][c.DATA_PAGES[0]],pos,1032)
        m.boundary_contract(regs,pages,observed)
        mutations=[]
        bad=copy.deepcopy(observed);bad['target']=c.BASE+0x8413b0;mutations.append(bad)
        bad=copy.deepcopy(observed);bad['site']+=1;mutations.append(bad)
        bad=copy.deepcopy(observed);bad['regs']['esp']+=4;mutations.append(bad)
        bad=copy.deepcopy(observed);bad['calls'].reverse();mutations.append(bad)
        bad=copy.deepcopy(observed);struct.pack_into('<I',bad['pages'][c.DATA_PAGES[0]],pos,1024);mutations.append(bad)
        bad=copy.deepcopy(observed);bad['pages'][c.DATA_PAGES[1]][0]^=1;mutations.append(bad)
        for n,bad in enumerate(mutations):
            with self.subTest(mutation=n),self.assertRaises(ValueError):
                m.boundary_contract(regs,pages,bad)

    def test_public_output_rejected_before_private_access(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)
            with self.assertRaises(ValueError):m.run(p,p/'output',p/'caller',p/'buffer')
            self.assertFalse((p/'output').exists())


if __name__ == '__main__':unittest.main()
