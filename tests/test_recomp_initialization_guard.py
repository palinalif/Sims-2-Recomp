"""Authored guard/trace tests; no private game bytes or fixtures required."""
import copy
import importlib.util
import json
from pathlib import Path
import struct
import sys
import unittest

SCRIPT = Path(__file__).resolve().parents[1]/'scripts/recomp/execute_initialization_guard.py'
sys.path.insert(0,str(SCRIPT.parent))
spec = importlib.util.spec_from_file_location('guard_test',SCRIPT)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class InitializationGuardTests(unittest.TestCase):
    def test_deterministic_isolated_populated_inputs_include_both_secondary_guards(self):
        secondary,opaque=set(),set()
        for n in range(64):
            regs,pages=m.state(n)
            self.assertEqual((regs,pages),m.state(n))
            off=regs['ecx']-m.c.DATA_PAGES[1]
            opaque.add(struct.unpack_from('<I',pages[m.c.DATA_PAGES[1]],off+0x34)[0])
            secondary.add(struct.unpack_from('<I',pages[m.c.DATA_PAGES[1]],off+0x1c)[0])
            self.assertEqual(set(pages),set(m.probe.PAGES))
            self.assertLessEqual(off+0x38,4096)
            self.assertNotEqual(regs['eax']&255,1)
            pages[m.c.DATA_PAGES[1]][0]^=1
            self.assertNotEqual(pages,m.state(n)[1])
        self.assertEqual(secondary,{0,0xffffffff})
        self.assertNotIn(0,opaque);self.assertIn(0x80000000,opaque)
        for bad in (-1,64,True):
            with self.assertRaises(ValueError):m.state(bad)

    def test_independent_partial_register_return_and_retained_frames(self):
        for n in range(64):
            regs,pages=m.state(n);before=copy.deepcopy((regs,pages))
            out=m.oracle(regs,pages)
            wanted=dict(regs,eax=(regs['eax']&0xffffff00)|1,esp=regs['esp']+4)
            self.assertEqual(out['regs'],[wanted[r] for r in m.c.REGS])
            self.assertNotEqual(out['regs'][0],1)
            expected=bytearray(b''.join(pages[p] for p in m.probe.PAGES))
            struct.pack_into('<II',expected,regs['esp']-m.c.DATA_PAGES[0]-8,regs['edi'],regs['esi'])
            self.assertEqual(out['pages'],expected.hex())
            self.assertEqual((regs,pages),before)

    def test_zero_handle_invalid_receiver_and_return_reject(self):
        regs,pages=m.state(0)
        for field,value in ((0x34,0),):
            bad=copy.deepcopy(pages)
            struct.pack_into('<I',bad[m.c.DATA_PAGES[1]],regs['ecx']-m.c.DATA_PAGES[1]+field,value)
            with self.assertRaises(ValueError):m.oracle(regs,bad)
        for value in (0,m.c.DATA_PAGES[1]+1,m.c.DATA_PAGES[1]+4092):
            with self.assertRaises(ValueError):m.oracle(dict(regs,ecx=value),pages)
        bad=copy.deepcopy(pages)
        struct.pack_into('<I',bad[m.c.DATA_PAGES[0]],regs['esp']-m.c.DATA_PAGES[0],0)
        with self.assertRaises(ValueError):m.oracle(regs,bad)

    def test_dependency_inventory_order_is_not_behavior_but_membership_is(self):
        deps=dict(direct_calls=['0x3a50','0x1030'],indirect_calls=0,absolute_memory_va=[],segmented_memory_operands=[])
        seed=dict(direct=['0x1030','0x3a50'])
        m.check_dependencies(deps,seed)
        for key,value in (('direct_calls',['0x20d0','0x1030']),('direct_calls',['0x1030','0x1030']),
                          ('indirect_calls',1),('absolute_memory_va',['0x80000000']),('segmented_memory_operands',['fs'])):
            bad=copy.deepcopy(deps);bad[key]=value
            with self.assertRaises(ValueError):m.check_dependencies(bad,seed)

    def test_verbatim_lift_only_root_bound_no_opener_response(self):
        callees=['0x1030','0x1070','0x1090','0x10a0','0x10b0','0x10c0','0x10e0',
                 '0x1100','0x1110','0x1120','0x1130','0x1140','0x3a50','0x3c50']
        body='static void initialization_guard_1AB665(void) { /* authored test */ }'
        text=m.assemble(body,callees)
        self.assertEqual(text.count(body),1)
        self.assertIn('cache_invoke(0xA01AB665u,in,adapter_1AB665)',text)
        for rva in callees:
            self.assertIn(f'address_sub_{m.c.BASE+int(rva,16):08X}',text)
            self.assertNotIn(f'case 0x{m.c.BASE+int(rva,16):08X}u:',text)
        self.assertIn('reject();return 0;',text)
        with self.assertRaises(ValueError):m.assemble(body,callees+['0x20d0'])
        valid=m.bridge_source('valid')
        self.assertIn('targets{0xA01AB665u}',valid)
        self.assertIn('0xA1050000u',valid)
        for mode,mutation in (('wrong-result','s[0]=1;'),('wrong-cleanup','s[7]+=8;')):
            self.assertIn(mutation,m.bridge_source(mode))
        with self.assertRaises(ValueError):m.bridge_source('opener-stub')

    def test_complete_comparison_rejects_bool_only_cleanup_and_page_faults(self):
        expected=[dict(case=n,**m.oracle(*m.state(n))) for n in range(64)]
        encode=lambda rows:'\n'.join(map(json.dumps,rows))
        self.assertEqual(m.c.assess(encode(expected),expected,'valid')['matched'],64)
        for mode in m.MODES[1:]:
            with self.assertRaises(ValueError):m.c.assess(encode(expected),expected,mode)
            bad=copy.deepcopy(expected)
            for row in bad:
                if mode=='wrong-result':row['regs'][0]=1
                else:row['regs'][7]+=8
            self.assertEqual(m.c.assess(encode(bad),expected,mode)['differing_cases'],64)
        for reg in range(8):
            bad=copy.deepcopy(expected);bad[0]['regs'][reg]^=1
            with self.assertRaises(ValueError):m.c.assess(encode(bad),expected,'valid')
        for page in range(6):
            bad=copy.deepcopy(expected);data=bytearray.fromhex(bad[0]['pages']);data[page*4096]^=1
            bad[0]['pages']=data.hex()
            with self.assertRaises(ValueError):m.c.assess(encode(bad),expected,'valid')


class ClassifierTraceTests(unittest.TestCase):
    def fixture(self,code):
        # Independently authored x86 fixture programs, NOT original-game bytes.
        from capstone import Cs,CS_ARCH_X86,CS_MODE_32
        md=Cs(CS_ARCH_X86,CS_MODE_32);md.detail=True
        entry=0x80000000
        nodes={i.address:i for i in md.disasm(code,entry)}
        regs,pages=m.state(0)
        return nodes,{entry:code+bytes(4096-len(code))},entry,regs,pages

    def test_trace_return_budget_and_unsafe_read(self):
        # MOV EAX,1; RET. One instruction budget must not invent a return.
        args=self.fixture(bytes.fromhex('b801000000c3'))
        out=m.probe.trace(*args)
        self.assertEqual(out['outcome'],'returned')
        self.assertEqual(out['regs'][0],1)
        self.assertEqual(m.probe.trace(*args,budget=1)['outcome'],'budget')
        self.assertEqual(m.probe.trace(*args,budget=2)['outcome'],'returned')
        # MOV EAX,[0]; RET must stop before the read, not map guest zero.
        args=self.fixture(bytes.fromhex('a100000000c3'))
        out=m.probe.trace(*args)
        self.assertEqual(out['outcome'],'unsafe-access')
        self.assertEqual(out['visited'],[])
        self.assertEqual(out['regs'],[args[3][r] for r in m.c.REGS])
        for budget in (0,129,True):
            with self.assertRaises(ValueError):m.probe.trace(*args,budget=budget)

    def test_external_call_stops_before_stack_write_and_never_supplies_response(self):
        # CALL 0x80000100 (outside authored node set); RET.
        args=self.fixture(bytes.fromhex('e8fb000000c3'))
        out=m.probe.trace(*args)
        self.assertEqual(out['outcome'],'external-call')
        self.assertEqual(out['visited'],[])
        self.assertEqual(out['regs'],[args[3][r] for r in m.c.REGS])
        self.assertEqual(out['pages'],b''.join(args[4][p] for p in m.probe.PAGES).hex())

    def test_readonly_table_writes_reject_before_mutation_and_inputs_are_isolated(self):
        # MOV [0xA1050000],EAX; RET cannot modify the image-backed table page.
        args=self.fixture(bytes.fromhex('a3000005a1c3'))
        out=m.probe.trace(*args)
        self.assertEqual(out['outcome'],'unsafe-access');self.assertEqual(out['visited'],[])
        for n in range(64):
            regs,pages=m.probe.state(n,bytes(4096))
            self.assertNotEqual(regs['edi'],0)
            self.assertEqual(set(pages),set(m.probe.PAGES))
            pages[m.probe.TABLE_PAGE][0]=1
            self.assertEqual(m.probe.state(n,bytes(4096))[1][m.probe.TABLE_PAGE][0],0)
        with self.assertRaises(ValueError):m.probe.state(0,b'')

if __name__=='__main__':unittest.main()
