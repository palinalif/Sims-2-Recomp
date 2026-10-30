"""Authored allocator-policy fixtures; no original bytes or private inputs."""
import copy
import importlib.util
from pathlib import Path
import struct
import unittest

PATH = Path(__file__).resolve().parents[1]/'scripts/recomp/execute_initialization_setter.py'
spec = importlib.util.spec_from_file_location('allocator_policy', PATH)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
RVA = 0x8437c6
GLOBAL = 0xa10dff54


class AllocatorPolicyTests(unittest.TestCase):
    def test_reference_accepts_authored_nop_without_state_effect(self):
        from capstone import Cs, CS_ARCH_X86, CS_MODE_32
        md = Cs(CS_ARCH_X86, CS_MODE_32); md.detail = True
        entry = m.BASE+0x2000
        code = b'\x90\xc3'  # Authored NOP; RET, unrelated to original body.
        nodes = {i.address:i for i in md.disasm(code,entry)}
        page = bytearray(4096); page[:len(code)] = code
        regs,pages = m.state(0,m.SIZE_QUERY)
        result,seen = m.reference(nodes,{entry:page},entry,regs,pages)
        out = dict(regs,esp=regs['esp']+4)
        self.assertEqual(result,dict(regs=[out[r] for r in m.REGS],
            pages=b''.join(pages[p] for p in m.PAGES).hex()))
        self.assertEqual(seen,{entry,entry+1})

    def test_pinned_unit_and_modes(self):
        slot,pin,size,count,blocks = m.unit(RVA)
        self.assertIsNone(slot)
        self.assertEqual((size,count,blocks),(7,3,((0,7),)))
        self.assertEqual(len(pin),64)
        self.assertEqual(m.modes(RVA),('valid','wrong-result','wrong-cleanup'))
        self.assertIn('allocator_policy',m.body_name(RVA))

    def test_deterministic_global_corpus_and_full_oracle(self):
        values = set()
        for n in range(64):
            regs,pages = m.state(n,RVA)
            self.assertEqual((regs,pages),m.state(n,RVA))
            before = copy.deepcopy((regs,pages))
            value = struct.unpack_from('<I',pages[m.DATA_PAGES[3]],GLOBAL-m.DATA_PAGES[3])[0]
            values.add(value)
            expected = m.oracle(regs,pages,RVA)
            self.assertEqual(expected['regs'],[value if r=='eax' else regs[r]+(4 if r=='esp' else 0) for r in m.REGS])
            self.assertEqual(expected['pages'],b''.join(pages[p] for p in m.PAGES).hex())
            self.assertEqual((regs,pages),before)
        self.assertTrue({0,1,0xffffffff,0x80000000,0x7fffffff} <= values)
        self.assertGreater(len(values),32)

    def test_getter_observes_global_not_receiver_or_old_eax(self):
        regs,pages = m.state(0,RVA)
        expected = m.oracle(regs,pages,RVA)
        regs['eax'] ^= 0xffffffff
        self.assertEqual(m.oracle(regs,pages,RVA)['regs'][0],expected['regs'][0])
        struct.pack_into('<I',pages[m.DATA_PAGES[3]],GLOBAL-m.DATA_PAGES[3],0x12345678)
        self.assertEqual(m.oracle(regs,pages,RVA)['regs'][0],0x12345678)

    def test_transport_only_registers_exact_policy_entry(self):
        body = '/* authored placeholder used only to test transport assembly */'
        text = m.assemble(body,RVA)
        self.assertEqual(text.count(body),1)
        self.assertIn('0xA08437C6u',text)
        bridge = m.bridge_source(m.BRIDGE.read_text(),'valid',RVA)
        self.assertIn('targets{0xA08437C6u}',bridge)
        self.assertNotIn('targets{0xA01ABD40u',bridge)
        for mode,statement in [('wrong-result','s[0]^=4;'),('wrong-cleanup','s[7]+=8;')]:
            self.assertIn(statement,m.bridge_source(m.BRIDGE.read_text(),mode,RVA))

    def test_bad_corpus_index_rejects(self):
        for n in (-1,64,True,1.0):
            with self.assertRaises(ValueError):m.state(n,RVA)


if __name__ == '__main__':unittest.main()
