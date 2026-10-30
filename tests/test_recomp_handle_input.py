"""Authored contract/transport controls; no private game code required."""
import copy
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import unittest

PATH = Path(__file__).resolve().parents[1]/'scripts/recomp/execute_handle_input.py'
spec = importlib.util.spec_from_file_location('handle_input', PATH)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
c = m.c


def authored_result(regs, pages):
    """Public fixture, not an original reference or counted translation."""
    sp = regs['esp']-c.DATA_PAGES[0]
    _, h, src = struct.unpack_from('<III', pages[c.DATA_PAGES[0]], sp)
    off = h-c.DATA_PAGES[1]
    _, cursor, start = struct.unpack_from('<III', pages[c.DATA_PAGES[1]], off+0x1d8)
    source = bytes(pages[c.DATA_PAGES[2]])[src-c.DATA_PAGES[2]:]
    sample = source[:source.index(0)+1]
    after = {p:bytearray(b) for p,b in pages.items()}
    struct.pack_into('<I', after[c.DATA_PAGES[1]], off+0xd0, start)
    for field in (0x1dc, 0x1e0):
        struct.pack_into('<I', after[c.DATA_PAGES[1]], off+field, cursor+len(sample))
    pos = cursor-c.DATA_PAGES[2]
    after[c.DATA_PAGES[2]][pos:pos+len(sample)] = sample
    out = dict(regs, eax=1, esp=regs['esp']+4)
    return dict(regs=[out[r] for r in c.REGS], pages=b''.join(after[p] for p in c.PAGES).hex())


class HandleInputTests(unittest.TestCase):
    def test_corpus_contract_and_determinism(self):
        lengths, stacks, objects = set(), set(), set()
        for n in range(64):
            regs, pages = m.state(n)
            self.assertEqual((regs, pages), m.state(n))
            result = authored_result(regs, pages)
            m.contract(regs, pages, result)
            stacks.add(regs['esp'])
            _, h, src = struct.unpack_from('<III', pages[c.DATA_PAGES[0]], regs['esp']-c.DATA_PAGES[0])
            objects.add(h)
            data = bytes(pages[c.DATA_PAGES[2]])[src-c.DATA_PAGES[2]:]
            lengths.add(data.index(0))
        self.assertEqual(lengths, set(range(17)))
        self.assertEqual(len(stacks), 2)
        self.assertEqual(len(objects), 2)

    def test_reject_result_cleanup_and_nonvolatile_mutations(self):
        regs, pages = m.state(3)
        good = authored_result(regs, pages)
        for slot in (0, 1, 4, 5, 6, 7):
            bad = copy.deepcopy(good); bad['regs'][slot] ^= 1
            with self.subTest(slot=slot), self.assertRaises(ValueError):
                m.contract(regs, pages, bad)

    def test_reject_each_nonstack_page_mutation(self):
        regs, pages = m.state(4)
        good = authored_result(regs, pages)
        for index, page in enumerate(c.PAGES):
            if page == c.DATA_PAGES[0]:
                continue
            raw = bytearray.fromhex(good['pages']); raw[index*4096] ^= 1
            bad = dict(good, pages=raw.hex())
            with self.subTest(page=page), self.assertRaises(ValueError):
                m.contract(regs, pages, bad)

    def test_reject_wrong_publication_and_cursor_fields(self):
        regs, pages = m.state(7)
        good = authored_result(regs, pages)
        h = struct.unpack_from('<I', pages[c.DATA_PAGES[0]], regs['esp']-c.DATA_PAGES[0]+4)[0]
        base = c.PAGES.index(c.DATA_PAGES[1])*4096+h-c.DATA_PAGES[1]
        for field in (0xd0, 0x1d8, 0x1dc, 0x1e0):
            raw = bytearray.fromhex(good['pages']); raw[base+field] ^= 1
            with self.subTest(field=field), self.assertRaises(ValueError):
                m.contract(regs, pages, dict(good, pages=raw.hex()))

    def test_scope_rejects_insufficient_capacity(self):
        regs, pages = m.state(7)
        h = struct.unpack_from('<I', pages[c.DATA_PAGES[0]], regs['esp']-c.DATA_PAGES[0]+4)[0]
        off = h-c.DATA_PAGES[1]
        cursor = struct.unpack_from('<I', pages[c.DATA_PAGES[1]], off+0x1dc)[0]
        result = authored_result(regs, pages)
        struct.pack_into('<I', pages[c.DATA_PAGES[1]], off+0x1d8, cursor+1)
        with self.assertRaises(ValueError): m.contract(regs, pages, result)

    def test_transport_retains_bodies_and_rejects_external_calls(self):
        bodies = {r:f'static void input_{r:X}(void) {{ /* authored fixture */ }}' for r in m.UNITS}
        text = m.assemble(bodies, c.BASE+0x27b0)
        for body in bodies.values(): self.assertEqual(text.count(body), 1)
        self.assertIn('caller==0xA0002790u && target==0xA00026B0u', text)
        self.assertNotIn('target==0xA0001AF0u', text)
        bridge = m.bridge_source('valid')
        self.assertIn('targets{0xA0002790u,0xA00026B0u}', bridge)
        self.assertNotIn('targets{0xA0001AF0u', bridge)
        with self.assertRaises(ValueError): m.assemble({0x2790:'x'}, c.BASE+0x27b0)

    def test_fault_controls_are_distinct_and_root_scoped(self):
        good = m.bridge_source('valid')
        wrong = m.bridge_source('wrong-slot')
        self.assertIn('if(depth==1)', wrong)
        self.assertIn('memory->write32(h+0xd0,0)', wrong)
        self.assertIn('s[7]+=8', m.bridge_source('wrong-cleanup'))
        self.assertNotIn('memory->write32(h+0xd0,0)', good)
        with self.assertRaises(ValueError): m.bridge_source('stub')

    def test_strict_comparison_rejects_changed_state_and_truncation(self):
        expected = [dict(case=n, **authored_result(*m.state(n))) for n in range(64)]
        text = '\n'.join(json.dumps(r) for r in expected)
        m.c.assess(text, expected, 'valid')
        bad = copy.deepcopy(expected)
        for row in bad: row['regs'][7] += 8
        m.c.assess('\n'.join(json.dumps(r) for r in bad), expected, 'wrong-cleanup')
        with self.assertRaises(ValueError): m.c.assess(text.rsplit('\n', 1)[0], expected, 'valid')
        with self.assertRaises(ValueError): m.c.assess(text, expected, 'wrong-slot')

    def test_private_output_rejected_before_input_access(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)/'result'
            with self.assertRaises(ValueError): m.run(Path(tmp), out)
            self.assertFalse(out.exists())

    def test_corpus_rejects_invalid_indices(self):
        for n in (-1, 64, True, 1.0):
            with self.subTest(n=n), self.assertRaises(ValueError): m.state(n)


if __name__ == '__main__': unittest.main()
