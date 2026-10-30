"""Public authored fixtures only: no original image, lifter, compiler or skips."""
import copy
import importlib.util
import json
from pathlib import Path
import struct
import sys
import unittest

SCRIPT = Path(__file__).resolve().parents[1]/'scripts/recomp/execute_initialization_setter.py'
sys.path.insert(0,str(SCRIPT.parent))
spec = importlib.util.spec_from_file_location('initialization_setter_test',SCRIPT)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class InitializationSetterTests(unittest.TestCase):
    def expected(self):
        return [dict(case=n,**m.oracle(*m.state(n))) for n in range(64)]

    def test_deterministic_inputs_edges_and_isolation(self):
        values = set()
        for n in range(64):
            a,p = m.state(n); b,q = m.state(n)
            self.assertEqual((a,p),(b,q))
            values.add(struct.unpack_from('<I',p[m.DATA_PAGES[0]],a['esp']-m.DATA_PAGES[0]+8)[0])
            p[m.PAGES[0]][0] ^= 1
            self.assertNotEqual(p,q)
        self.assertTrue({0,1,0xffffffff,0x80000000,0xa01ab979} <= values)
        for bad in (-1,64,True):
            with self.assertRaises(ValueError): m.state(bad)

    def test_oracle_exact_slot_registers_cleanup_and_no_input_mutation(self):
        for n in range(64):
            regs,pages = m.state(n); before = copy.deepcopy(pages)
            result = m.oracle(regs,pages)
            self.assertEqual(pages,before)
            obj,value = struct.unpack_from('<II',pages[m.DATA_PAGES[0]],regs['esp']-m.DATA_PAGES[0]+4)
            self.assertEqual(result['regs'],[value,regs['ebx'],obj,regs['edx'],regs['esi'],regs['edi'],regs['ebp'],regs['esp']+4])
            final = bytes.fromhex(result['pages'])
            offset = 4096+obj-m.DATA_PAGES[1]+0x30
            wanted = bytearray(b''.join(pages[p] for p in m.PAGES))
            struct.pack_into('<I',wanted,offset,value)
            self.assertEqual(final,wanted)

    def test_strict_complete_matching_and_behavioral_controls(self):
        expected = self.expected()
        text = '\n'.join(map(json.dumps,expected))
        self.assertEqual(m.assess(text,expected,'valid')['matched'],64)
        for mode in ('wrong-slot','wrong-cleanup'):
            with self.assertRaises(ValueError): m.assess(text,expected,mode)
            bad = copy.deepcopy(expected)
            for row in bad:
                if mode == 'wrong-cleanup': row['regs'][-1] += 8
                else: row['pages'] = ('00' if row['pages'][:2]!='00' else '01')+row['pages'][2:]
            killed = m.assess('\n'.join(map(json.dumps,bad)),expected,mode)
            self.assertEqual(killed['differing_cases'],64)
            with self.assertRaises(ValueError): m.assess('\n'.join(map(json.dumps,bad)),expected,'valid')

    def test_partial_rejected_duplicate_and_malformed_are_not_kills(self):
        expected = self.expected()
        rows = [json.dumps(r) for r in expected]
        for bad in ('\n'.join(rows[:-1]),'\n'.join(rows+rows[:1]),
                    '\n'.join(['{"case":0,"rejected":true}',*rows[1:]]),
                    '\n'.join(['{"case":0,"case":0}',*rows[1:]])):
            with self.assertRaises(ValueError): m.assess(bad,expected,'wrong-slot')
        for field,value in [('regs',[-1]*8),('pages','z'*len(expected[0]['pages']))]:
            bad = copy.deepcopy(expected); bad[0][field] = value
            with self.assertRaises(ValueError): m.assess('\n'.join(map(json.dumps,bad)),expected,'wrong-slot')

    def test_every_final_component_mutation_rejects(self):
        expected = self.expected()
        for k in range(8):
            bad = copy.deepcopy(expected); bad[0]['regs'][k] ^= 1
            with self.assertRaises(ValueError): m.assess('\n'.join(map(json.dumps,bad)),expected,'valid')
        for p in range(6):
            bad = copy.deepcopy(expected); b = bytearray.fromhex(bad[0]['pages']); b[p*4096+31] ^= 1
            bad[0]['pages'] = b.hex()
            with self.assertRaises(ValueError): m.assess('\n'.join(map(json.dumps,bad)),expected,'valid')

    def test_verbatim_authored_body_and_single_dispatch_target(self):
        body = 'static void initialization_setter_1090(void) { /* authored fixture */ }'
        text = m.assemble(body)
        self.assertEqual(text.count(body),1)
        self.assertNotIn('@BODY@',text)
        self.assertIn('cache_invoke(0xA0001090u,in,adapter_1090)',text)
        bridge = m.bridge_source(m.BRIDGE.read_text(),'valid')
        self.assertIn('std::array<uint32_t,1> targets{0xA0001090u}',bridge)
        self.assertIn('dispatcher.invoke(va,r,*memory)',bridge)
        for mode in m.MODES[1:]:
            self.assertNotEqual(m.bridge_source(m.BRIDGE.read_text(),mode),bridge)
        with self.assertRaises(ValueError): m.bridge_source('missing anchors','valid')
        with self.assertRaises(ValueError): m.assemble('')

    def test_10a0_oracle_slot_edges_and_isolation(self):
        for n in range(64):
            regs,pages = m.state(n,0x10a0)
            self.assertEqual((regs,pages),m.state(n,0x10a0))
            before = copy.deepcopy(pages)
            obj,value = struct.unpack_from('<II',pages[m.DATA_PAGES[0]],regs['esp']-m.DATA_PAGES[0]+4)
            result = m.oracle(regs,pages,0x10a0)
            wanted = bytearray(b''.join(pages[p] for p in m.PAGES))
            struct.pack_into('<I',wanted,4096+obj-m.DATA_PAGES[1]+0x34,value)
            self.assertEqual(bytes.fromhex(result['pages']),wanted)
            self.assertEqual(result['regs'],[value,regs['ebx'],obj,regs['edx'],regs['esi'],regs['edi'],regs['ebp'],regs['esp']+4])
            self.assertEqual(pages,before)
            self.assertNotEqual(result,m.oracle(regs,pages,0x1090))

    def test_10a0_verbatim_transport_target_and_both_controls(self):
        # A deliberate old-name marker proves body text is not rewritten.
        body = 'static void initialization_setter_10A0(void) { /* 1090 stays */ }'
        transport = m.assemble(body,0x10a0)
        self.assertEqual(transport.count(body),1)
        self.assertIn('cache_invoke(0xA00010A0u,in,adapter_10A0)',transport)
        self.assertIn('case 0xA00010A0u: initialization_setter_10A0();',transport)
        bridge = m.bridge_source(m.BRIDGE.read_text(),'valid',0x10a0)
        self.assertIn('targets{0xA00010A0u}',bridge)
        expected = [dict(case=n,**m.oracle(*m.state(n,0x10a0),0x10a0)) for n in range(64)]
        self.assertEqual(m.assess('\n'.join(map(json.dumps,expected)),expected,'valid')['matched'],64)
        for mode in m.MODES[1:]:
            self.assertNotEqual(m.bridge_source(m.BRIDGE.read_text(),mode,0x10a0),bridge)
            bad = copy.deepcopy(expected)
            for row in bad:
                if mode == 'wrong-cleanup': row['regs'][-1] += 8
                else: row['pages'] = ('00' if row['pages'][:2]!='00' else '01')+row['pages'][2:]
            self.assertEqual(m.assess('\n'.join(map(json.dumps,bad)),expected,mode)['differing_cases'],64)
            with self.assertRaises(ValueError): m.assess('\n'.join(map(json.dumps,bad)),expected,'valid')

    def test_association_both_paths_full_oracle_and_input_isolation(self):
        counts = {True:0, False:0}
        placements = {True:set(), False:set()}
        for n in range(64):
            regs,pages = m.state(n,0x1030)
            self.assertEqual((regs,pages),m.state(n,0x1030))
            before = copy.deepcopy(pages)
            obj,value = struct.unpack_from('<II',pages[m.DATA_PAGES[0]],regs['esp']-m.DATA_PAGES[0]+4)
            offset = obj-m.DATA_PAGES[1]
            old,context = struct.unpack_from('<II',pages[m.DATA_PAGES[1]],offset)
            equal = old == context
            counts[equal] += 1
            placements[equal].add(offset)
            wanted = copy.deepcopy(pages)
            struct.pack_into('<I',wanted[m.DATA_PAGES[1]],offset,value)
            if equal:
                struct.pack_into('<I',wanted[m.DATA_PAGES[1]],offset+4,value)
            expected_regs = dict(regs,eax=obj,ecx=value if equal else context,esp=regs['esp']+4)
            if not equal: expected_regs['edx'] = value
            out = m.oracle(regs,pages,0x1030)
            self.assertEqual(out['regs'],[expected_regs[r] for r in m.REGS])
            self.assertEqual(bytes.fromhex(out['pages']),b''.join(wanted[p] for p in m.PAGES))
            self.assertEqual(pages,before)
        self.assertEqual(counts,{True:32,False:32})
        self.assertEqual(placements[True],placements[False])
        self.assertEqual(len(placements[True]),2)

    def test_association_transport_is_verbatim_and_exact_target(self):
        body = 'static void initialization_association_1030(void) { /* 1090 setter stays */ }'
        text = m.assemble(body,0x1030)
        self.assertEqual(text.count(body),1)
        self.assertIn('case 0xA0001030u: initialization_association_1030();',text)
        self.assertIn('cache_invoke(0xA0001030u,in,adapter_1030)',text)
        bridge = m.bridge_source(m.BRIDGE.read_text(),'valid',0x1030)
        self.assertIn('targets{0xA0001030u}',bridge)
        self.assertEqual(m.unit(0x1030)[2:],(28,11,((0,11),(11,21),(21,28))))
        for mode in m.MODES[1:]:
            self.assertNotEqual(m.bridge_source(m.BRIDGE.read_text(),mode,0x1030),bridge)

    def test_association_wrong_conditional_context_and_cleanup_reject(self):
        expected = [dict(case=n,**m.oracle(*m.state(n,0x1030),0x1030)) for n in range(64)]
        self.assertEqual(m.assess('\n'.join(map(json.dumps,expected)),expected,'valid')['matched'],64)
        for equal in (True,False):
            bad = copy.deepcopy(expected)
            for n,row in enumerate(bad):
                regs,pages = m.state(n,0x1030)
                obj,value = struct.unpack_from('<II',pages[m.DATA_PAGES[0]],regs['esp']-m.DATA_PAGES[0]+4)
                if (n % 4 < 2) != equal: continue
                offset = 4096+obj-m.DATA_PAGES[1]+4
                final = bytearray.fromhex(row['pages'])
                # Force the opposite branch's context effect, even when value
                # equals the initial context and suppressing a write is invisible.
                struct.pack_into('<I',final,offset,value ^ 0xffffffff)
                row['pages'] = final.hex()
            with self.assertRaises(ValueError): m.assess('\n'.join(map(json.dumps,bad)),expected,'valid')
        bad = copy.deepcopy(expected)
        for row in bad: row['regs'][-1] += 8
        self.assertEqual(m.assess('\n'.join(map(json.dumps,bad)),expected,'wrong-cleanup')['differing_cases'],64)

    def test_association_index_requires_exact_target_size_count_and_end(self):
        env = dict(schema='sims2-ghidra-query-envelope/1',provenance=dict(
            sourceImageSha256=m.IMAGE_SHA,mode='readOnly',analysisPerformed=False,
            headlessExitCode=0,outputParseError=None,ghidraVersion='authored'),
            queryLogSignals={'error':1},result=dict(query={'rva':'0x1030'},
            program={'imageBaseVa':hex(m.BASE)},truncation={},function=dict(
                resolution='function-at',entryRva='0x1030',disassembly=dict(
                    instructionCount=11,extentBytes=28,extentEndVa='0xa000104b',
                    items=[{'va':'0xa0001030'}]*11))))
        self.assertTrue(m.check_index(env,0x1030)['reliable_boundaries'])
        for key,value in [('instructionCount',10),('extentBytes',29),('extentEndVa','0xa000104c')]:
            bad = copy.deepcopy(env); bad['result']['function']['disassembly'][key] = value
            with self.assertRaises(ValueError): m.check_index(bad,0x1030)
        with self.assertRaises(ValueError): m.check_index(env,0x1090)
        for bad in (True,0x1040,0x20d0,'1030'):
            with self.assertRaises(ValueError): m.unit(bad)

    def test_dual_effect_complete_oracle_and_initial_state_edges(self):
        initial_states = set()
        placements = set()
        for n in range(64):
            regs,pages = m.state(n,0x10e0)
            self.assertEqual((regs,pages),m.state(n,0x10e0))
            before = copy.deepcopy(pages)
            obj,value = struct.unpack_from('<II',pages[m.DATA_PAGES[0]],regs['esp']-m.DATA_PAGES[0]+4)
            offset = obj-m.DATA_PAGES[1]
            placements.add(offset)
            initial_states.add(struct.unpack_from('<I',pages[m.DATA_PAGES[1]],offset+0x110)[0])
            wanted = copy.deepcopy(pages)
            struct.pack_into('<I',wanted[m.DATA_PAGES[1]],offset+0x44,value)
            struct.pack_into('<I',wanted[m.DATA_PAGES[1]],offset+0x110,1)
            out = m.oracle(regs,pages,0x10e0)
            self.assertEqual(out['regs'],[obj,regs['ebx'],value,regs['edx'],regs['esi'],regs['edi'],regs['ebp'],regs['esp']+4])
            self.assertEqual(bytes.fromhex(out['pages']),b''.join(wanted[p] for p in m.PAGES))
            self.assertEqual(pages,before)
        self.assertTrue({0,1,0xffffffff,2} <= initial_states)
        self.assertEqual(len(placements),2)

    def test_dual_effect_verbatim_transport_and_exact_inventory(self):
        body = 'static void initialization_setter_10E0(void) { /* 1090 stays */ }'
        text = m.assemble(body,0x10e0)
        self.assertEqual(text.count(body),1)
        self.assertIn('case 0xA00010E0u: initialization_setter_10E0();',text)
        self.assertIn('cache_invoke(0xA00010E0u,in,adapter_10E0)',text)
        bridge = m.bridge_source(m.BRIDGE.read_text(),'valid',0x10e0)
        self.assertIn('targets{0xA00010E0u}',bridge)
        self.assertEqual(m.unit(0x10e0)[2:],(22,5,((0,22),)))
        for mode in m.MODES[1:]:
            self.assertNotEqual(m.bridge_source(m.BRIDGE.read_text(),mode,0x10e0),bridge)
        with self.assertRaises(ValueError): m.unit(0x10f0)

    def test_dual_effect_each_independent_write_and_register_fault_rejects(self):
        expected = [dict(case=n,**m.oracle(*m.state(n,0x10e0),0x10e0)) for n in range(64)]
        self.assertEqual(m.assess('\n'.join(map(json.dumps,expected)),expected,'valid')['matched'],64)
        for slot in (0x44,0x110):
            bad = copy.deepcopy(expected)
            for n,row in enumerate(bad):
                regs,pages = m.state(n,0x10e0)
                obj = struct.unpack_from('<I',pages[m.DATA_PAGES[0]],regs['esp']-m.DATA_PAGES[0]+4)[0]
                b = bytearray.fromhex(row['pages'])
                b[4096+obj-m.DATA_PAGES[1]+slot] ^= 1
                row['pages'] = b.hex()
            self.assertEqual(m.assess('\n'.join(map(json.dumps,bad)),expected,'wrong-slot')['differing_cases'],64)
            with self.assertRaises(ValueError): m.assess('\n'.join(map(json.dumps,bad)),expected,'valid')
        bad = copy.deepcopy(expected)
        for row in bad: row['regs'][0],row['regs'][2] = row['regs'][2],row['regs'][0]
        with self.assertRaises(ValueError): m.assess('\n'.join(map(json.dumps,bad)),expected,'valid')

    def test_dual_effect_index_size_count_and_target_fail_closed(self):
        env = dict(schema='sims2-ghidra-query-envelope/1',provenance=dict(
            sourceImageSha256=m.IMAGE_SHA,mode='readOnly',analysisPerformed=False,
            headlessExitCode=0,outputParseError=None,ghidraVersion='authored'),
            queryLogSignals={'error':1},result=dict(query={'rva':'0x10e0'},
            program={'imageBaseVa':hex(m.BASE)},truncation={},function=dict(
                resolution='function-at',entryRva='0x10e0',disassembly=dict(
                    instructionCount=5,extentBytes=22,extentEndVa='0xa00010f5',
                    items=[{'va':'0xa00010e0'}]*5))))
        self.assertTrue(m.check_index(env,0x10e0)['reliable_boundaries'])
        for key,value in [('instructionCount',4),('extentBytes',21),('extentEndVa','0xa00010f6')]:
            bad = copy.deepcopy(env); bad['result']['function']['disassembly'][key] = value
            with self.assertRaises(ValueError): m.check_index(bad,0x10e0)
        with self.assertRaises(ValueError): m.check_index(env,0x1090)

    def test_paired_full_oracle_independent_arguments_and_isolation(self):
        equal, placements, values = 0, set(), [set(),set()]
        for n in range(64):
            regs,pages = m.state(n,0x10c0)
            self.assertEqual((regs,pages),m.state(n,0x10c0))
            before = copy.deepcopy(pages)
            obj,first,second = struct.unpack_from('<III',pages[m.DATA_PAGES[0]],regs['esp']-m.DATA_PAGES[0]+4)
            equal += first == second
            values[0].add(first); values[1].add(second)
            offset = obj-m.DATA_PAGES[1]; placements.add(offset)
            wanted = copy.deepcopy(pages)
            struct.pack_into('<II',wanted[m.DATA_PAGES[1]],offset+0x3c,first,second)
            out = m.oracle(regs,pages,0x10c0)
            self.assertEqual(out['regs'],[obj,regs['ebx'],first,second,regs['esi'],regs['edi'],regs['ebp'],regs['esp']+4])
            self.assertEqual(bytes.fromhex(out['pages']),b''.join(wanted[p] for p in m.PAGES))
            self.assertEqual(pages,before)
        self.assertEqual(equal,16)
        self.assertEqual(len(placements),2)
        for v in values: self.assertTrue({0,1,0xffffffff,0x80000000} <= v)

    def test_paired_each_write_swapped_arguments_and_cleanup_reject(self):
        expected = [dict(case=n,**m.oracle(*m.state(n,0x10c0),0x10c0)) for n in range(64)]
        self.assertEqual(m.assess('\n'.join(map(json.dumps,expected)),expected,'valid')['matched'],64)
        for slot in (0x3c,0x40):
            bad = copy.deepcopy(expected)
            for n,row in enumerate(bad):
                regs,pages = m.state(n,0x10c0)
                obj = struct.unpack_from('<I',pages[m.DATA_PAGES[0]],regs['esp']-m.DATA_PAGES[0]+4)[0]
                b = bytearray.fromhex(row['pages']); b[4096+obj-m.DATA_PAGES[1]+slot] ^= 1
                row['pages'] = b.hex()
            self.assertEqual(m.assess('\n'.join(map(json.dumps,bad)),expected,'wrong-slot')['differing_cases'],64)
        bad = copy.deepcopy(expected)
        for row in bad: row['regs'][2],row['regs'][3] = row['regs'][3],row['regs'][2]
        with self.assertRaises(ValueError): m.assess('\n'.join(map(json.dumps,bad)),expected,'valid')
        bad = copy.deepcopy(expected)
        for row in bad: row['regs'][-1] += 8
        self.assertEqual(m.assess('\n'.join(map(json.dumps,bad)),expected,'wrong-cleanup')['differing_cases'],64)

    def test_paired_verbatim_transport_and_index_contract(self):
        body = 'static void initialization_setter_10C0(void) { /* 1090 unchanged */ }'
        text = m.assemble(body,0x10c0)
        self.assertEqual(text.count(body),1)
        self.assertIn('cache_invoke(0xA00010C0u,in,adapter_10C0)',text)
        self.assertIn('case 0xA00010C0u: initialization_setter_10C0();',text)
        bridge = m.bridge_source(m.BRIDGE.read_text(),'valid',0x10c0)
        self.assertIn('targets{0xA00010C0u}',bridge)
        for mode in m.MODES[1:]:
            self.assertNotEqual(m.bridge_source(m.BRIDGE.read_text(),mode,0x10c0),bridge)
        self.assertEqual(m.unit(0x10c0)[2:],(19,6,((0,19),)))
        env = dict(schema='sims2-ghidra-query-envelope/1',provenance=dict(
            sourceImageSha256=m.IMAGE_SHA,mode='readOnly',analysisPerformed=False,
            headlessExitCode=0,outputParseError=None,ghidraVersion='authored'),
            queryLogSignals={'error':1},result=dict(query={'rva':'0x10c0'},
            program={'imageBaseVa':hex(m.BASE)},truncation={},function=dict(
                resolution='function-at',entryRva='0x10c0',disassembly=dict(
                    instructionCount=6,extentBytes=19,extentEndVa='0xa00010d2',
                    items=[{'va':'0xa00010c0'}]*6))))
        self.assertTrue(m.check_index(env,0x10c0)['reliable_boundaries'])
        for key,value in [('instructionCount',5),('extentBytes',20),('extentEndVa','0xa00010d3')]:
            bad = copy.deepcopy(env); bad['result']['function']['disassembly'][key] = value
            with self.assertRaises(ValueError): m.check_index(bad,0x10c0)
        with self.assertRaises(ValueError): m.check_index(env,0x1090)

    def test_1100_full_oracle_edges_placements_and_isolation(self):
        values, placements = set(), set()
        for n in range(64):
            regs,pages = m.state(n,0x1100)
            self.assertEqual((regs,pages),m.state(n,0x1100))
            before = copy.deepcopy(pages)
            obj,value = struct.unpack_from('<II',pages[m.DATA_PAGES[0]],regs['esp']-m.DATA_PAGES[0]+4)
            values.add(value); placements.add((obj,regs['esp']))
            wanted = bytearray(b''.join(pages[p] for p in m.PAGES))
            struct.pack_into('<I',wanted,4096+obj-m.DATA_PAGES[1]+0x50,value)
            out = m.oracle(regs,pages,0x1100)
            self.assertEqual(out['regs'],[value,regs['ebx'],obj,regs['edx'],regs['esi'],regs['edi'],regs['ebp'],regs['esp']+4])
            self.assertEqual(bytes.fromhex(out['pages']),wanted)
            self.assertEqual(pages,before)
        self.assertTrue({0,1,0xffffffff,0x80000000,0xa01ab979} <= values)
        self.assertEqual(len(placements),2)

    def test_1100_wrong_slot_cleanup_and_volatile_registers_reject(self):
        expected = [dict(case=n,**m.oracle(*m.state(n,0x1100),0x1100)) for n in range(64)]
        self.assertEqual(m.assess('\n'.join(map(json.dumps,expected)),expected,'valid')['matched'],64)
        for mode in m.MODES[1:]:
            bad = copy.deepcopy(expected)
            for n,row in enumerate(bad):
                if mode == 'wrong-cleanup': row['regs'][-1] += 8
                else:
                    regs,pages = m.state(n,0x1100)
                    obj = struct.unpack_from('<I',pages[m.DATA_PAGES[0]],regs['esp']-m.DATA_PAGES[0]+4)[0]
                    b = bytearray.fromhex(row['pages']); b[4096+obj-m.DATA_PAGES[1]+0x50] ^= 1
                    row['pages'] = b.hex()
            self.assertEqual(m.assess('\n'.join(map(json.dumps,bad)),expected,mode)['differing_cases'],64)
            with self.assertRaises(ValueError): m.assess('\n'.join(map(json.dumps,bad)),expected,'valid')
        for register in (0,2):
            bad = copy.deepcopy(expected); bad[0]['regs'][register] ^= 1
            with self.assertRaises(ValueError): m.assess('\n'.join(map(json.dumps,bad)),expected,'valid')

    def test_1100_verbatim_exact_dispatch_and_index_contract(self):
        body = 'static void initialization_setter_1100(void) { /* 1090 unchanged */ }'
        text = m.assemble(body,0x1100)
        self.assertEqual(text.count(body),1)
        self.assertIn('cache_invoke(0xA0001100u,in,adapter_1100)',text)
        self.assertIn('case 0xA0001100u: initialization_setter_1100();',text)
        bridge = m.bridge_source(m.BRIDGE.read_text(),'valid',0x1100)
        self.assertIn('targets{0xA0001100u}',bridge)
        for mode in m.MODES[1:]:
            self.assertNotEqual(m.bridge_source(m.BRIDGE.read_text(),mode,0x1100),bridge)
        self.assertEqual(m.unit(0x1100)[2:],(12,4,((0,12),)))
        env = dict(schema='sims2-ghidra-query-envelope/1',provenance=dict(
            sourceImageSha256=m.IMAGE_SHA,mode='readOnly',analysisPerformed=False,
            headlessExitCode=0,outputParseError=None,ghidraVersion='authored'),
            queryLogSignals={'error':1},result=dict(query={'rva':'0x1100'},
            program={'imageBaseVa':hex(m.BASE)},truncation={},function=dict(
                resolution='function-at',entryRva='0x1100',disassembly=dict(
                    instructionCount=4,extentBytes=12,extentEndVa='0xa000110b',
                    items=[{'va':'0xa0001100'}]*4))))
        self.assertTrue(m.check_index(env,0x1100)['reliable_boundaries'])
        for key,value in [('instructionCount',3),('extentBytes',13),('extentEndVa','0xa000110c')]:
            bad = copy.deepcopy(env); bad['result']['function']['disassembly'][key] = value
            with self.assertRaises(ValueError): m.check_index(bad,0x1100)
        with self.assertRaises(ValueError): m.check_index(env,0x1090)

    def test_1110_full_oracle_edges_placements_and_isolation(self):
        values, placements = set(), set()
        for n in range(64):
            regs,pages = m.state(n,0x1110)
            self.assertEqual((regs,pages),m.state(n,0x1110))
            before = copy.deepcopy(pages)
            obj,value = struct.unpack_from('<II',pages[m.DATA_PAGES[0]],regs['esp']-m.DATA_PAGES[0]+4)
            values.add(value); placements.add((obj,regs['esp']))
            wanted = bytearray(b''.join(pages[p] for p in m.PAGES))
            struct.pack_into('<I',wanted,4096+obj-m.DATA_PAGES[1]+0x5c,value)
            out = m.oracle(regs,pages,0x1110)
            self.assertEqual(out['regs'],[value,regs['ebx'],obj,regs['edx'],regs['esi'],regs['edi'],regs['ebp'],regs['esp']+4])
            self.assertEqual(bytes.fromhex(out['pages']),wanted)
            self.assertEqual(pages,before)
            self.assertNotEqual(out,m.oracle(regs,pages,0x1100))
        self.assertTrue({0,1,0xffffffff,0x80000000,0xa01ab979} <= values)
        self.assertEqual(len(placements),2)

    def test_1110_slot_cleanup_and_volatile_register_faults_reject(self):
        expected = [dict(case=n,**m.oracle(*m.state(n,0x1110),0x1110)) for n in range(64)]
        self.assertEqual(m.assess('\n'.join(map(json.dumps,expected)),expected,'valid')['matched'],64)
        for mode in m.MODES[1:]:
            bad = copy.deepcopy(expected)
            for n,row in enumerate(bad):
                if mode == 'wrong-cleanup': row['regs'][-1] += 8
                else:
                    regs,pages = m.state(n,0x1110)
                    obj = struct.unpack_from('<I',pages[m.DATA_PAGES[0]],regs['esp']-m.DATA_PAGES[0]+4)[0]
                    b = bytearray.fromhex(row['pages']); b[4096+obj-m.DATA_PAGES[1]+0x5c] ^= 1
                    row['pages'] = b.hex()
            self.assertEqual(m.assess('\n'.join(map(json.dumps,bad)),expected,mode)['differing_cases'],64)
            with self.assertRaises(ValueError): m.assess('\n'.join(map(json.dumps,bad)),expected,'valid')
        for register in (0,2):
            bad = copy.deepcopy(expected); bad[0]['regs'][register] ^= 1
            with self.assertRaises(ValueError): m.assess('\n'.join(map(json.dumps,bad)),expected,'valid')

    def test_1110_verbatim_exact_dispatch_and_index_contract(self):
        body = 'static void initialization_setter_1110(void) { /* 1090 unchanged */ }'
        text = m.assemble(body,0x1110)
        self.assertEqual(text.count(body),1)
        self.assertIn('cache_invoke(0xA0001110u,in,adapter_1110)',text)
        self.assertIn('case 0xA0001110u: initialization_setter_1110();',text)
        bridge = m.bridge_source(m.BRIDGE.read_text(),'valid',0x1110)
        self.assertIn('targets{0xA0001110u}',bridge)
        for mode in m.MODES[1:]:
            self.assertNotEqual(m.bridge_source(m.BRIDGE.read_text(),mode,0x1110),bridge)
        self.assertEqual(m.unit(0x1110)[2:],(12,4,((0,12),)))
        env = dict(schema='sims2-ghidra-query-envelope/1',provenance=dict(
            sourceImageSha256=m.IMAGE_SHA,mode='readOnly',analysisPerformed=False,
            headlessExitCode=0,outputParseError=None,ghidraVersion='authored'),
            queryLogSignals={'error':1},result=dict(query={'rva':'0x1110'},
            program={'imageBaseVa':hex(m.BASE)},truncation={},function=dict(
                resolution='function-at',entryRva='0x1110',disassembly=dict(
                    instructionCount=4,extentBytes=12,extentEndVa='0xa000111b',
                    items=[{'va':'0xa0001110'}]*4))))
        self.assertTrue(m.check_index(env,0x1110)['reliable_boundaries'])
        for key,value in [('instructionCount',3),('extentBytes',13),('extentEndVa','0xa000111c')]:
            bad = copy.deepcopy(env); bad['result']['function']['disassembly'][key] = value
            with self.assertRaises(ValueError): m.check_index(bad,0x1110)
        with self.assertRaises(ValueError): m.check_index(env,0x1100)

    def test_1120_complete_oracle_isolation_and_distinct_callback_slot(self):
        values, placements = set(), set()
        for n in range(64):
            regs,pages = m.state(n,0x1120)
            self.assertEqual((regs,pages),m.state(n,0x1120))
            before = copy.deepcopy(pages)
            obj,value = struct.unpack_from('<II',pages[m.DATA_PAGES[0]],regs['esp']-m.DATA_PAGES[0]+4)
            values.add(value); placements.add((obj,regs['esp']))
            wanted = bytearray(b''.join(pages[p] for p in m.PAGES))
            struct.pack_into('<I',wanted,4096+obj-m.DATA_PAGES[1]+0x54,value)
            out = m.oracle(regs,pages,0x1120)
            self.assertEqual(out['regs'],[value,regs['ebx'],obj,regs['edx'],regs['esi'],regs['edi'],regs['ebp'],regs['esp']+4])
            self.assertEqual(bytes.fromhex(out['pages']),wanted)
            self.assertEqual(pages,before)
            for other in (0x1100,0x1110):
                self.assertNotEqual(out,m.oracle(regs,pages,other))
        self.assertTrue({0,1,0xffffffff,0x80000000,0xa01ab979} <= values)
        self.assertEqual(len(placements),2)

    def test_1120_wrong_slot_cleanup_and_volatile_registers_reject(self):
        expected = [dict(case=n,**m.oracle(*m.state(n,0x1120),0x1120)) for n in range(64)]
        self.assertEqual(m.assess('\n'.join(map(json.dumps,expected)),expected,'valid')['matched'],64)
        for mode in m.MODES[1:]:
            bad = copy.deepcopy(expected)
            for n,row in enumerate(bad):
                if mode == 'wrong-cleanup': row['regs'][-1] += 8
                else:
                    regs,pages = m.state(n,0x1120)
                    obj = struct.unpack_from('<I',pages[m.DATA_PAGES[0]],regs['esp']-m.DATA_PAGES[0]+4)[0]
                    b = bytearray.fromhex(row['pages']); b[4096+obj-m.DATA_PAGES[1]+0x54] ^= 1
                    row['pages'] = b.hex()
            self.assertEqual(m.assess('\n'.join(map(json.dumps,bad)),expected,mode)['differing_cases'],64)
            with self.assertRaises(ValueError): m.assess('\n'.join(map(json.dumps,bad)),expected,'valid')
        for register in (0,2):
            bad = copy.deepcopy(expected); bad[0]['regs'][register] ^= 1
            with self.assertRaises(ValueError): m.assess('\n'.join(map(json.dumps,bad)),expected,'valid')

    def test_1120_verbatim_transport_exact_target_and_index_rejection(self):
        body = 'static void initialization_setter_1120(void) { /* 1090 unchanged */ }'
        text = m.assemble(body,0x1120)
        self.assertEqual(text.count(body),1)
        self.assertIn('cache_invoke(0xA0001120u,in,adapter_1120)',text)
        self.assertIn('case 0xA0001120u: initialization_setter_1120();',text)
        bridge = m.bridge_source(m.BRIDGE.read_text(),'valid',0x1120)
        self.assertIn('targets{0xA0001120u}',bridge)
        for mode in m.MODES[1:]:
            self.assertNotEqual(m.bridge_source(m.BRIDGE.read_text(),mode,0x1120),bridge)
        self.assertEqual(m.unit(0x1120)[2:],(12,4,((0,12),)))
        env = dict(schema='sims2-ghidra-query-envelope/1',provenance=dict(
            sourceImageSha256=m.IMAGE_SHA,mode='readOnly',analysisPerformed=False,
            headlessExitCode=0,outputParseError=None,ghidraVersion='authored'),
            queryLogSignals={'error':1},result=dict(query={'rva':'0x1120'},
            program={'imageBaseVa':hex(m.BASE)},truncation={},function=dict(
                resolution='function-at',entryRva='0x1120',disassembly=dict(
                    instructionCount=4,extentBytes=12,extentEndVa='0xa000112b',
                    items=[{'va':'0xa0001120'}]*4))))
        self.assertTrue(m.check_index(env,0x1120)['reliable_boundaries'])
        for key,value in [('instructionCount',3),('extentBytes',13),('extentEndVa','0xa000112c')]:
            bad = copy.deepcopy(env); bad['result']['function']['disassembly'][key] = value
            with self.assertRaises(ValueError): m.check_index(bad,0x1120)
        with self.assertRaises(ValueError): m.check_index(env,0x1110)

    def test_1130_full_oracle_and_distinct_callback_slot(self):
        values, placements = set(), set()
        for n in range(64):
            regs,pages = m.state(n,0x1130)
            self.assertEqual((regs,pages),m.state(n,0x1130))
            before = copy.deepcopy(pages)
            obj,value = struct.unpack_from('<II',pages[m.DATA_PAGES[0]],regs['esp']-m.DATA_PAGES[0]+4)
            values.add(value); placements.add((obj,regs['esp']))
            wanted = bytearray(b''.join(pages[p] for p in m.PAGES))
            struct.pack_into('<I',wanted,4096+obj-m.DATA_PAGES[1]+0x6c,value)
            out = m.oracle(regs,pages,0x1130)
            self.assertEqual(out['regs'],[value,regs['ebx'],obj,regs['edx'],regs['esi'],regs['edi'],regs['ebp'],regs['esp']+4])
            self.assertEqual(bytes.fromhex(out['pages']),wanted)
            self.assertEqual(pages,before)
            for other in (0x1100,0x1110,0x1120):
                self.assertNotEqual(out,m.oracle(regs,pages,other))
        self.assertTrue({0,1,0xffffffff,0x80000000,0xa01ab979} <= values)
        self.assertEqual(len(placements),2)

    def test_1130_slot_cleanup_and_register_faults_reject(self):
        expected = [dict(case=n,**m.oracle(*m.state(n,0x1130),0x1130)) for n in range(64)]
        self.assertEqual(m.assess('\n'.join(map(json.dumps,expected)),expected,'valid')['matched'],64)
        for mode in m.MODES[1:]:
            bad = copy.deepcopy(expected)
            for n,row in enumerate(bad):
                if mode == 'wrong-cleanup': row['regs'][-1] += 8
                else:
                    regs,pages = m.state(n,0x1130)
                    obj = struct.unpack_from('<I',pages[m.DATA_PAGES[0]],regs['esp']-m.DATA_PAGES[0]+4)[0]
                    b = bytearray.fromhex(row['pages']); b[4096+obj-m.DATA_PAGES[1]+0x6c] ^= 1
                    row['pages'] = b.hex()
            self.assertEqual(m.assess('\n'.join(map(json.dumps,bad)),expected,mode)['differing_cases'],64)
            with self.assertRaises(ValueError): m.assess('\n'.join(map(json.dumps,bad)),expected,'valid')
        for register in (0,2):
            bad = copy.deepcopy(expected); bad[0]['regs'][register] ^= 1
            with self.assertRaises(ValueError): m.assess('\n'.join(map(json.dumps,bad)),expected,'valid')

    def test_1130_transport_and_index_fail_closed(self):
        body = 'static void initialization_setter_1130(void) { /* 1090 unchanged */ }'
        text = m.assemble(body,0x1130)
        self.assertEqual(text.count(body),1)
        self.assertIn('cache_invoke(0xA0001130u,in,adapter_1130)',text)
        self.assertIn('case 0xA0001130u: initialization_setter_1130();',text)
        bridge = m.bridge_source(m.BRIDGE.read_text(),'valid',0x1130)
        self.assertIn('targets{0xA0001130u}',bridge)
        for mode in m.MODES[1:]:
            self.assertNotEqual(m.bridge_source(m.BRIDGE.read_text(),mode,0x1130),bridge)
        self.assertEqual(m.unit(0x1130)[2:],(12,4,((0,12),)))
        env = dict(schema='sims2-ghidra-query-envelope/1',provenance=dict(
            sourceImageSha256=m.IMAGE_SHA,mode='readOnly',analysisPerformed=False,
            headlessExitCode=0,outputParseError=None,ghidraVersion='authored'),
            queryLogSignals={'error':1},result=dict(query={'rva':'0x1130'},
            program={'imageBaseVa':hex(m.BASE)},truncation={},function=dict(
                resolution='function-at',entryRva='0x1130',disassembly=dict(
                    instructionCount=4,extentBytes=12,extentEndVa='0xa000113b',
                    items=[{'va':'0xa0001130'}]*4))))
        self.assertTrue(m.check_index(env,0x1130)['reliable_boundaries'])
        for key,value in [('instructionCount',3),('extentBytes',13),('extentEndVa','0xa000113c')]:
            bad = copy.deepcopy(env); bad['result']['function']['disassembly'][key] = value
            with self.assertRaises(ValueError): m.check_index(bad,0x1130)
        with self.assertRaises(ValueError): m.check_index(env,0x1120)

    def test_1140_status_oracle_bounds_and_input_isolation(self):
        values, placements = set(), set()
        for n in range(64):
            regs,pages = m.state(n,0x1140)
            self.assertEqual((regs,pages),m.state(n,0x1140))
            before = copy.deepcopy(pages)
            obj,value = struct.unpack_from('<II',pages[m.DATA_PAGES[0]],regs['esp']-m.DATA_PAGES[0]+4)
            offset = obj-m.DATA_PAGES[1]
            values.add(value); placements.add(offset)
            self.assertGreaterEqual(offset,0)
            self.assertLessEqual(offset+0x208+4,4096)
            self.assertEqual({p:len(b) for p,b in pages.items()},{p:4096 for p in m.PAGES})
            self.assertNotEqual(struct.unpack_from('<I',pages[m.DATA_PAGES[1]],offset+0x208)[0],value)
            wanted = bytearray(b''.join(pages[p] for p in m.PAGES))
            struct.pack_into('<I',wanted,4096+offset+0x208,value)
            out = m.oracle(regs,pages,0x1140)
            self.assertEqual(out['regs'],[1,regs['ebx'],obj,regs['edx'],regs['esi'],regs['edi'],regs['ebp'],regs['esp']+4])
            self.assertEqual(bytes.fromhex(out['pages']),wanted)
            self.assertEqual(pages,before)
        self.assertEqual(placements,{0x80,0xc00})
        self.assertTrue({0,1,0xffffffff,0x80000000,0xa01ab979} <= values)

    def test_1140_status_return_slot_cleanup_and_register_faults_reject(self):
        expected = [dict(case=n,**m.oracle(*m.state(n,0x1140),0x1140)) for n in range(64)]
        self.assertEqual(m.assess('\n'.join(map(json.dumps,expected)),expected,'valid')['matched'],64)
        for mode in m.MODES[1:]:
            bad = copy.deepcopy(expected)
            for n,row in enumerate(bad):
                if mode == 'wrong-cleanup': row['regs'][-1] += 8
                else:
                    regs,pages = m.state(n,0x1140)
                    obj = struct.unpack_from('<I',pages[m.DATA_PAGES[0]],regs['esp']-m.DATA_PAGES[0]+4)[0]
                    b = bytearray.fromhex(row['pages']); b[4096+obj-m.DATA_PAGES[1]+0x208] ^= 1
                    row['pages'] = b.hex()
            self.assertEqual(m.assess('\n'.join(map(json.dumps,bad)),expected,mode)['differing_cases'],64)
            with self.assertRaises(ValueError): m.assess('\n'.join(map(json.dumps,bad)),expected,'valid')
        # Reusing the value-returning setter contract must fail on non-one inputs.
        bad = copy.deepcopy(expected)
        for n,row in enumerate(bad):
            regs,pages = m.state(n,0x1140)
            row['regs'][0] = struct.unpack_from('<I',pages[m.DATA_PAGES[0]],regs['esp']-m.DATA_PAGES[0]+8)[0]
        with self.assertRaises(ValueError): m.assess('\n'.join(map(json.dumps,bad)),expected,'valid')
        for register in (0,2):
            bad = copy.deepcopy(expected); bad[0]['regs'][register] ^= 1
            with self.assertRaises(ValueError): m.assess('\n'.join(map(json.dumps,bad)),expected,'valid')

    def test_1140_verbatim_transport_and_index_fail_closed(self):
        body = 'static void initialization_setter_1140(void) { /* 1090 unchanged */ }'
        text = m.assemble(body,0x1140)
        self.assertEqual(text.count(body),1)
        self.assertIn('cache_invoke(0xA0001140u,in,adapter_1140)',text)
        self.assertIn('case 0xA0001140u: initialization_setter_1140();',text)
        bridge = m.bridge_source(m.BRIDGE.read_text(),'valid',0x1140)
        self.assertIn('targets{0xA0001140u}',bridge)
        for mode in m.MODES[1:]:
            self.assertNotEqual(m.bridge_source(m.BRIDGE.read_text(),mode,0x1140),bridge)
        self.assertEqual(m.unit(0x1140)[2:],(20,5,((0,20),)))
        env = dict(schema='sims2-ghidra-query-envelope/1',provenance=dict(
            sourceImageSha256=m.IMAGE_SHA,mode='readOnly',analysisPerformed=False,
            headlessExitCode=0,outputParseError=None,ghidraVersion='authored'),
            queryLogSignals={'error':1},result=dict(query={'rva':'0x1140'},
            program={'imageBaseVa':hex(m.BASE)},truncation={},function=dict(
                resolution='function-at',entryRva='0x1140',disassembly=dict(
                    instructionCount=5,extentBytes=20,extentEndVa='0xa0001153',
                    items=[{'va':'0xa0001140'}]*5))))
        self.assertTrue(m.check_index(env,0x1140)['reliable_boundaries'])
        for key,value in [('instructionCount',4),('extentBytes',19),('extentEndVa','0xa0001154')]:
            bad = copy.deepcopy(env); bad['result']['function']['disassembly'][key] = value
            with self.assertRaises(ValueError): m.check_index(bad,0x1140)
        with self.assertRaises(ValueError): m.check_index(env,0x1130)
        with self.assertRaises(ValueError): m.unit(0x1150)

    def test_10b0_oracle_complete_poststate_and_isolation(self):
        values, placements = set(), set()
        for n in range(64):
            regs,pages = m.state(n,0x10b0)
            self.assertEqual((regs,pages),m.state(n,0x10b0))
            before = copy.deepcopy(pages)
            obj,value = struct.unpack_from('<II',pages[m.DATA_PAGES[0]],regs['esp']-m.DATA_PAGES[0]+4)
            offset = obj-m.DATA_PAGES[1]
            values.add(value); placements.add(offset)
            self.assertLessEqual(offset+0x38+4,4096)
            self.assertNotEqual(struct.unpack_from('<I',pages[m.DATA_PAGES[1]],offset+0x38)[0],value)
            wanted = bytearray(b''.join(pages[p] for p in m.PAGES))
            struct.pack_into('<I',wanted,4096+offset+0x38,value)
            out = m.oracle(regs,pages,0x10b0)
            self.assertEqual(out['regs'],[value,regs['ebx'],obj,regs['edx'],regs['esi'],regs['edi'],regs['ebp'],regs['esp']+4])
            self.assertEqual(bytes.fromhex(out['pages']),wanted)
            self.assertEqual(pages,before)
        self.assertEqual(placements,{0x80,0xe00})
        self.assertTrue({0,1,0xffffffff,0x80000000,0xa01ab979} <= values)

    def test_10b0_slot_cleanup_and_register_faults_reject(self):
        expected = [dict(case=n,**m.oracle(*m.state(n,0x10b0),0x10b0)) for n in range(64)]
        self.assertEqual(m.assess('\n'.join(map(json.dumps,expected)),expected,'valid')['matched'],64)
        for mode in m.MODES[1:]:
            bad = copy.deepcopy(expected)
            for n,row in enumerate(bad):
                if mode == 'wrong-cleanup': row['regs'][-1] += 8
                else:
                    regs,pages = m.state(n,0x10b0)
                    obj = struct.unpack_from('<I',pages[m.DATA_PAGES[0]],regs['esp']-m.DATA_PAGES[0]+4)[0]
                    b = bytearray.fromhex(row['pages']); b[4096+obj-m.DATA_PAGES[1]+0x38] ^= 1
                    row['pages'] = b.hex()
            self.assertEqual(m.assess('\n'.join(map(json.dumps,bad)),expected,mode)['differing_cases'],64)
            with self.assertRaises(ValueError): m.assess('\n'.join(map(json.dumps,bad)),expected,'valid')
        for register in range(8):
            bad = copy.deepcopy(expected); bad[0]['regs'][register] ^= 1
            with self.assertRaises(ValueError): m.assess('\n'.join(map(json.dumps,bad)),expected,'valid')

    def test_10b0_verbatim_transport_and_index_fail_closed(self):
        body = 'static void initialization_setter_10B0(void) { /* 1090 unchanged */ }'
        text = m.assemble(body,0x10b0)
        self.assertEqual(text.count(body),1)
        self.assertIn('cache_invoke(0xA00010B0u,in,adapter_10B0)',text)
        self.assertIn('case 0xA00010B0u: initialization_setter_10B0();',text)
        bridge = m.bridge_source(m.BRIDGE.read_text(),'valid',0x10b0)
        self.assertIn('targets{0xA00010B0u}',bridge)
        for mode in m.MODES[1:]:
            self.assertNotEqual(m.bridge_source(m.BRIDGE.read_text(),mode,0x10b0),bridge)
        self.assertEqual(m.unit(0x10b0)[2:],(12,4,((0,12),)))
        env = dict(schema='sims2-ghidra-query-envelope/1',provenance=dict(
            sourceImageSha256=m.IMAGE_SHA,mode='readOnly',analysisPerformed=False,
            headlessExitCode=0,outputParseError=None,ghidraVersion='authored'),
            queryLogSignals={'error':1},result=dict(query={'rva':'0x10b0'},
            program={'imageBaseVa':hex(m.BASE)},truncation={},function=dict(
                resolution='function-at',entryRva='0x10b0',disassembly=dict(
                    instructionCount=4,extentBytes=12,extentEndVa='0xa00010bb',
                    items=[{'va':'0xa00010b0'}]*4))))
        self.assertTrue(m.check_index(env,0x10b0)['reliable_boundaries'])
        for key,value in [('instructionCount',3),('extentBytes',13),('extentEndVa','0xa00010bc')]:
            bad = copy.deepcopy(env); bad['result']['function']['disassembly'][key] = value
            with self.assertRaises(ValueError): m.check_index(bad,0x10b0)
        with self.assertRaises(ValueError): m.check_index(env,0x10a0)

    def test_setter_inventory_rejects_unapproved_targets(self):
        for bad in (True,0x10d0,0x20d0,'10a0'):
            with self.assertRaises(ValueError): m.setter(bad)
            with self.assertRaises(ValueError): m.state(0,bad)
            with self.assertRaises(ValueError): m.assemble('authored',bad)
            with self.assertRaises(ValueError): m.bridge_source(m.BRIDGE.read_text(),'valid',bad)

    def test_index_provenance_and_boundaries_fail_closed(self):
        env = dict(schema='sims2-ghidra-query-envelope/1',provenance=dict(
            sourceImageSha256=m.IMAGE_SHA,mode='readOnly',analysisPerformed=False,
            headlessExitCode=0,outputParseError=None,ghidraVersion='authored'),
            queryLogSignals={'error':1},result=dict(query={'rva':'0x1090'},
            program={'imageBaseVa':hex(m.BASE)},truncation={},function=dict(
                resolution='function-at',entryRva='0x1090',disassembly=dict(
                    instructionCount=4,extentBytes=12,extentEndVa=hex(m.BASE+0x109b),items=[{'va':hex(m.BASE+0x1090)}]*4))))
        self.assertTrue(m.check_index(env)['reliable_boundaries'])
        other = copy.deepcopy(env)
        other['result']['query']['rva'] = '0x10a0'
        f = other['result']['function']; f['entryRva'] = '0x10a0'
        f['disassembly'].update(extentEndVa='0xa00010ab',items=[{'va':'0xa00010a0'}]*4)
        self.assertTrue(m.check_index(other,0x10a0)['reliable_boundaries'])
        with self.assertRaises(ValueError): m.check_index(env,0x10a0)
        with self.assertRaises(ValueError): m.check_index(other,0x1090)
        for section,key,value in [('provenance','mode','write'),('provenance','sourceImageSha256','0'*64),
                                  ('provenance','analysisPerformed',True),('provenance','headlessExitCode',1)]:
            bad = copy.deepcopy(env); bad[section][key] = value
            with self.assertRaises(ValueError): m.check_index(bad)
        for key,value in [('instructionCount',3),('extentBytes',13),('extentEndVa','0xa000109c')]:
            bad = copy.deepcopy(env); bad['result']['function']['disassembly'][key] = value
            with self.assertRaises(ValueError): m.check_index(bad)


if __name__ == '__main__': unittest.main()
