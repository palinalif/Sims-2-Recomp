"""Authored lookup-table contracts; no original bytes or captured states."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest

PATH = Path(__file__).resolve().parents[1]/'scripts/recomp/execute_table_lookup.py'
spec = importlib.util.spec_from_file_location('table_lookup',PATH)
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
c = m.c


def authored_result(n):
    regs,pages = m.state(n)
    out = dict(regs,eax=c.DATA_PAGES[3]+64 if 16 <= n < 48 else 0,esp=regs['esp']+4)
    return dict(regs=[out[r] for r in c.REGS],pages=b''.join(pages[p] for p in c.PAGES).hex())


class TableLookupTests(unittest.TestCase):
    def test_corpus_is_deterministic_disjoint_and_covers_four_domains(self):
        offsets=set()
        for n in range(64):
            regs,pages=m.state(n)
            self.assertEqual((regs,pages),m.state(n))
            self.assertEqual(set(pages),set(c.PAGES))
            self.assertTrue(all(len(b)==4096 for b in pages.values()))
            offset=regs['edi']-c.DATA_PAGES[1]; offsets.add(offset)
            slots,capacity,count,threshold=struct.unpack_from('<4I',pages[c.DATA_PAGES[1]],offset)
            self.assertEqual((capacity,count,threshold),(0 if n < 8 else 4,3,4))
            buckets=struct.unpack_from('<4I',pages[c.DATA_PAGES[3]],slots-c.DATA_PAGES[3])
            node=c.DATA_PAGES[3]+64
            self.assertEqual(buckets,(node,)*4 if 16 <= n < 48 else (node,node,node,0) if n >= 48 else (0,)*4)
            sp=regs['esp']-c.DATA_PAGES[0]
            self.assertEqual(struct.unpack_from('<3I',pages[c.DATA_PAGES[0]],sp),(c.RETURN,c.DATA_PAGES[2]+64,0))
        self.assertEqual(offsets,{0,128,1024,4080})
        for n in (-1,64,True,1.5):
            with self.assertRaises(ValueError): m.state(n)

    def test_independent_subset_accepts_only_expected_lookup_and_preservation(self):
        for n in range(64):
            regs,pages=m.state(n); before=copy.deepcopy((regs,pages))
            m.contract(n,regs,pages,authored_result(n))
            self.assertEqual((regs,pages),before)
            for register in ('eax','esp','ebx','ebp','esi','edi'):
                bad=authored_result(n); bad['regs'][c.REGS.index(register)]^=4
                with self.assertRaises(ValueError,msg=register): m.contract(n,regs,pages,bad)

    def test_contract_rejects_table_string_slack_image_and_caller_argument_writes(self):
        for n in range(64):
            regs,pages=m.state(n)
            for i,offset in ((0,regs['esp']-c.DATA_PAGES[0]+8),(1,4095),(2,64),(3,128),(4,1),(5,4095)):
                bad=authored_result(n); data=bytearray.fromhex(bad['pages']); data[i*4096+offset]^=1; bad['pages']=data.hex()
                with self.assertRaises(ValueError): m.contract(n,regs,pages,bad)
            bad=authored_result(n); bad['pages']=bad['pages'][:-2]
            with self.assertRaises(ValueError): m.contract(n,regs,pages,bad)

    def test_contract_does_not_claim_volatile_register_or_stack_scratch_oracle(self):
        regs,pages=m.state(0); result=authored_result(0)
        for r in ('ecx','edx'): result['regs'][c.REGS.index(r)]^=0x1234
        data=bytearray.fromhex(result['pages']); data[0]^=1; result['pages']=data.hex()
        m.contract(0,regs,pages,result)

    def test_transport_retains_each_body_and_fails_closed_on_allocator_targets(self):
        bodies={r:f'static void lookup_{r:X}(void) {{ /* authored {r} */ }}' for r in m.UNITS}
        text=m.assemble(bodies)
        for r,body in bodies.items():
            self.assertEqual(text.count(body),1)
            self.assertIn(f'case 0x{c.BASE+r:08X}u:',text)
        for r in m.EXTERNAL:
            self.assertIn(f'address_sub_{c.BASE+r:08X}',text)
            self.assertNotIn(f'case 0x{c.BASE+r:08X}u:',text)
        self.assertIn('cache_invoke(0xA0001820u,in,adapter_1820)',text)
        self.assertIn('target==0xA0001800u) return 0xA0001879u;',text)
        self.assertIn('target==0xA00017D0u) return 0xA000189Eu;',text)
        with self.assertRaises(ValueError): m.assemble({0x1820:'body'})
        with self.assertRaises(ValueError): m.assemble(bodies|{0x1800:''})

    def test_bridge_controls_and_registered_exact_targets(self):
        for mode in m.m.MODES:
            bridge=m.bridge_source(mode)
            self.assertIn('std::array<uint32_t,3> targets{0xA0001820u,0xA0001800u,0xA00017D0u}',bridge)
            self.assertNotIn('0xA083A371u',bridge)
        self.assertIn('if(depth==1) s[0]^=4;',m.bridge_source('wrong-result'))
        self.assertIn('if(depth==1) s[7]+=8;',m.bridge_source('wrong-cleanup'))
        with self.assertRaises(ValueError): m.bridge_source('stub')

    def test_opt_in_multiply_executes_signed_overflow_without_weakening_default(self):
        from capstone import Cs, CS_ARCH_X86, CS_MODE_32
        md=Cs(CS_ARCH_X86,CS_MODE_32); md.detail=True
        entry=c.BASE+0x1000
        # Authored IMUL EAX,EDX,-3; RET, independent modular signed oracle.
        code=b'\x6b\xc2\xfd\xc3'; cp=code+bytes(4096-len(code))
        nodes={i.address:i for i in md.disasm(code,entry)}
        for value in (0,1,0xffffffff,0x7fffffff,0x80000000,0x55555555):
            regs,pages=m.state(0); regs['edx']=value
            with self.assertRaises(ValueError): c.reference(nodes,{entry:cp},entry,regs,pages)
            result,_=c.reference(nodes,{entry:cp},entry,regs,pages,checked_integer_multiply=True)
            expected=dict(regs,eax=(value*-3)&0xffffffff,esp=regs['esp']+4)
            self.assertEqual(result['regs'],[expected[r] for r in c.REGS])
            self.assertEqual(result['pages'],b''.join(pages[p] for p in c.PAGES).hex())

    def test_multiply_opt_in_still_rejects_memory_implicit_and_two_operand_forms(self):
        from capstone import Cs, CS_ARCH_X86, CS_MODE_32
        md=Cs(CS_ARCH_X86,CS_MODE_32); md.detail=True
        entry=c.BASE+0x1000
        for code in (b'\xf7\xea\xc3',b'\x0f\xaf\xc2\xc3',b'\x6b\x02\x03\xc3'):
            regs,pages=m.state(0); regs['edx']=c.DATA_PAGES[2]
            nodes={i.address:i for i in md.disasm(code,entry)}
            with self.assertRaises(ValueError):
                c.reference(nodes,{entry:code+bytes(4096-len(code))},entry,regs,pages,checked_integer_multiply=True)

    def test_native_wrap_policy_matches_modulo32(self):
        values=(0,1,0xffffffff,0x7fffffff,0x80000000,132191765)
        source='''#include <cstdint>
#include <cstdio>
int main() {
  volatile int32_t values[]={0,1,-1,2147483647,(-2147483647-1),132191765};
  for(int32_t v:values) {
    volatile int32_t result=v*33;
    std::printf("%u\\n",uint32_t(result));
  }
}
'''
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); path=root/'multiply.cpp'; path.write_text(source)
            binary=root/'multiply'
            options=os.environ.get('TS2_LOOKUP_TEST_TARGET','').split()
            compiler=('zig-cxx' if options else os.environ.get('CXX') or
                      shutil.which('c++') or shutil.which('clang++') or 'g++')
            subprocess.run([compiler,*options,'-std=c++20','-O0','-fwrapv',
                str(path),'-o',str(binary)],check=True,capture_output=True,timeout=60)
            runner=os.environ.get('TS2_LOOKUP_TEST_RUNNER')
            result=subprocess.run([*([runner] if runner else []),str(binary)],
                check=True,capture_output=True,text=True,timeout=30)
            self.assertEqual([int(v) for v in result.stdout.splitlines()],[(v*33)&0xffffffff for v in values])

    def test_full_comparator_rejects_volatile_stack_and_truncated_output(self):
        expected=[dict(case=n,**authored_result(n)) for n in range(64)]
        good='\n'.join(json.dumps(row) for row in expected)
        c.assess(good,expected,'valid')
        for field in ('volatile','stack'):
            bad=copy.deepcopy(expected)
            if field=='volatile': bad[0]['regs'][c.REGS.index('edx')]^=1
            else:
                raw=bytearray.fromhex(bad[0]['pages']); raw[0]^=1; bad[0]['pages']=raw.hex()
            with self.assertRaises(ValueError): c.assess('\n'.join(json.dumps(row) for row in bad),expected,'valid')
        with self.assertRaises(ValueError): c.assess(good.rsplit('\n',1)[0],expected,'valid')
        for mode in ('wrong-result','wrong-cleanup'):
            with self.assertRaises(ValueError): c.assess(good,expected,mode)


if __name__=='__main__': unittest.main()
