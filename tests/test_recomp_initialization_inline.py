"""Inline producer storage contract, authored states only (not lifetime proof)."""
import copy
import struct
import unittest
from test_recomp_initialization_producer import m


class InitializationInlineTests(unittest.TestCase):
    def test_inline_handle_layout_and_complete_poststate(self):
        for n in range(64):
            regs, pages = m.state(n, 'inline')
            self.assertEqual((regs, pages), m.state(n, 'inline'))
            before = copy.deepcopy((regs, pages))
            obj, link = m.arguments(regs, pages, 'inline')
            handle = link - 0x78
            self.assertEqual(obj, handle + 0x7c)
            self.assertGreaterEqual(handle, m.PAGES[1])
            self.assertLessEqual(handle + 0x210, m.PAGES[1] + 4096)
            expected = copy.deepcopy(pages)
            def put(page, address, value):
                struct.pack_into('<I', expected[page], address-page, value)
            for off, value in ((0, m.BASE+0x10970), (4, m.BASE+0x109a0),
                               (0x34, m.BASE+0xfcf0), (0x4c, link)):
                put(m.PAGES[1], obj+off, value)
            expected[m.PAGES[1]][obj-m.PAGES[1]+0x49] = 6
            put(m.PAGES[1], link, obj)
            put(m.PAGES[0], regs['esp']-4, regs['edi'])
            put(m.PAGES[0], regs['esp']-8, m.BASE+0x109da)
            out = dict(regs, eax=1, ecx=obj, esp=regs['esp']+4)
            result = m.oracle(regs, pages, 'inline')
            self.assertEqual(result, dict(regs=[out[r] for r in m.REGS],
                pages=b''.join(expected[p] for p in m.PAGES).hex()))
            self.assertEqual((regs, pages), before)
            # The old separate-storage assumption must remain fail-closed.
            with self.assertRaises(ValueError): m.oracle(regs, pages)

    def test_inline_contract_rejects_wrong_overlap_and_out_of_handle(self):
        regs, pages = m.state(0, 'inline')
        obj, link = m.arguments(regs, pages, 'inline')
        for offset, value in ((8, obj), (8, link-4), (8, m.PAGES[2]),
                              (4, obj+4), (4, m.PAGES[1]+0x7c-4)):
            bad = copy.deepcopy(pages)
            struct.pack_into('<I', bad[m.PAGES[0]], regs['esp']-m.PAGES[0]+offset, value)
            with self.assertRaises(ValueError): m.oracle(regs, bad, 'inline')
        for layout in ('unknown', None, True):
            with self.assertRaises(ValueError): m.state(0, layout)

    def test_inline_publication_and_backpointer_mutations_reject(self):
        expected = [dict(case=n, **m.oracle(*m.state(n, 'inline'), 'inline')) for n in range(64)]
        for field in ('publication', 'backpointer'):
            bad = copy.deepcopy(expected)
            for n, row in enumerate(bad):
                regs, pages = m.state(n, 'inline')
                obj, link = m.arguments(regs, pages, 'inline')
                address = link if field == 'publication' else obj+0x4c
                raw = bytearray.fromhex(row['pages'])
                struct.pack_into('<I', raw, 4096+address-m.PAGES[1], 0)
                row['pages'] = raw.hex()
            with self.assertRaises(ValueError):
                m.common.assess('\n'.join(map(m.json.dumps, bad)), expected, 'valid')


if __name__ == '__main__': unittest.main()
