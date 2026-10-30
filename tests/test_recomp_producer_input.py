"""Authored first-call fixtures only; never original game instruction bytes."""
import copy
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts/recomp'))
import probe_producer_input as m


def fixture():
    # Authored ABI exerciser: save ESI, bind receiver, choose two endpoints,
    # push a field input plus two receiver-relative arguments. Endpoints are
    # unmapped: a test cannot accidentally execute them as success stubs.
    code = (b'\x56\x89\xc6\x8b\x86'+struct.pack('<I', 0xd4)+b'\x85\xc0\xb8'+
            struct.pack('<I', m.BASE+0x109d0)+b'\x74\x05\xb8'+
            struct.pack('<I', m.BASE+0x10b60)+b'\xff\xb6'+struct.pack('<I', 0xd0)+
            b'\x8d\x56\x78\x52\x8d\x4e\x7c\x51')
    entry = m.BASE+0x20f6-len(code)
    code += b'\xff\xd0'
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    nodes = {i.address:i for i in md.disasm(code, entry)}
    page = bytearray(4096)
    page[entry%4096:entry%4096+len(code)] = code
    return nodes, entry, {m.BASE+0x2000:page}


class ProducerInputTests(unittest.TestCase):
    def execute(self, n=0, budget=64):
        regs, pages = m.state(n)
        result, visited = m.prefix_reference(*fixture(), regs, pages, budget)
        return regs, pages, result, visited

    def test_authored_both_selectors_and_nonzero_incoming_edi(self):
        counts = {}
        for n in range(64):
            regs, pages, result, visited = self.execute(n)
            target = m.contract(regs, pages, result)
            counts[target] = counts.get(target, 0)+1
            self.assertNotEqual(regs['edi'], 0)
            self.assertNotIn(m.BASE+0x20f6, visited)
        self.assertEqual(counts, {m.BASE+0x109d0:16, m.BASE+0x10b60:48})

    def test_field_not_incoming_edi_controls_third_argument(self):
        regs, pages = m.state(1)
        first, _ = m.prefix_reference(*fixture(), regs, pages)
        regs['edi'] ^= 0xffffffff
        second, _ = m.prefix_reference(*fixture(), regs, pages)
        m.contract(regs, pages, second)
        offset = regs['esp']-m.STACK-8
        self.assertEqual(first['pages'][m.STACK][offset:offset+4],
                         second['pages'][m.STACK][offset:offset+4])
        struct.pack_into('<I', pages[m.OBJECT], regs['eax']-m.OBJECT+0xd0, 0)
        third, _ = m.prefix_reference(*fixture(), regs, pages)
        m.contract(regs, pages, third)
        self.assertEqual(third['pages'][m.STACK][offset:offset+4], bytes(4))
        self.assertNotEqual(first['pages'][m.STACK][offset:offset+4], bytes(4))

    def test_oracle_rejects_input_argument_regression_and_order(self):
        regs, pages, result, _ = self.execute()
        for offset in (0, 4, 8, 12):
            bad = copy.deepcopy(result)
            stack = bytearray(bad['pages'][m.STACK])
            at = regs['esp']-m.STACK-16+offset
            stack[at] ^= 1
            bad['pages'][m.STACK] = bytes(stack)
            with self.assertRaises(ValueError): m.contract(regs, pages, bad)

    def test_oracle_rejects_target_cleanup_receiver_and_nonvolatile(self):
        regs, pages, result, _ = self.execute()
        for field in ('esp', 'ebx', 'edi', 'ebp', 'esi'):
            bad = copy.deepcopy(result)
            bad['regs'][field] ^= 4
            with self.assertRaises(ValueError): m.contract(regs, pages, bad)
        for field in ('target', 'site'):
            bad = copy.deepcopy(result)
            bad[field] ^= 4
            with self.assertRaises(ValueError): m.contract(regs, pages, bad)

    def test_nonstack_write_and_truncated_page_reject(self):
        regs, pages, result, _ = self.execute()
        for page in m.PAGES:
            bad = copy.deepcopy(result)
            bad['pages'][page] = bad['pages'][page][:-1]
            with self.assertRaises(ValueError): m.contract(regs, pages, bad)
        bad = copy.deepcopy(result)
        data = bytearray(bad['pages'][m.OBJECT]); data[0] ^= 1
        bad['pages'][m.OBJECT] = bytes(data)
        with self.assertRaises(ValueError): m.contract(regs, pages, bad)

    def test_budget_and_missing_instruction_fail_closed(self):
        for budget in (0, 1, 257, True):
            with self.assertRaises(ValueError): self.execute(budget=budget)
        nodes, entry, code_pages = fixture()
        del nodes[entry]
        with self.assertRaises(ValueError):
            m.prefix_reference(nodes, entry, code_pages, *m.state(0))

    def test_invalid_receiver_and_stack_ranges_reject_before_execution(self):
        for reg, value in (('eax', m.OBJECT+4096-0xd4), ('esp', m.STACK)):
            regs, pages = m.state(0); regs[reg] = value
            with self.assertRaises(ValueError):
                m.prefix_reference(*fixture(), regs, pages)

    def test_code_mutation_and_unsupported_instruction_reject(self):
        nodes, entry, code_pages = fixture()
        code_pages[m.BASE+0x2000][entry%4096] ^= 1
        with self.assertRaises(ValueError):
            m.prefix_reference(nodes, entry, code_pages, *m.state(0))
        from capstone import Cs, CS_ARCH_X86, CS_MODE_32
        md = Cs(CS_ARCH_X86, CS_MODE_32); md.detail = True
        nodes = {i.address:i for i in md.disasm(b'\x90', entry)}
        code_pages[m.BASE+0x2000][entry%4096] = 0x90
        with self.assertRaises(ValueError):
            m.prefix_reference(nodes, entry, code_pages, *m.state(0))


if __name__ == '__main__': unittest.main()
