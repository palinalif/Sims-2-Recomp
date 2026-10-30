"""Authored opener-result/trace tests; no private game bytes or fixtures required.

These check the `0x1AB665` opener-result segment (the exact `0x3C50` call-return
boundary: two pops, `store [ESI+0x34]=EAX`, `TEST/JE`, then the shared `0x1AB763`
CMP/SETNE tail) is correctly modelled and is genuinely distinct from the two
settled early-return arms (the `+0x34`-populated guard, AL=1, and the zero-`+0x1C`
no-open arm, AL=0). They never load original-game bytes; the original-x86
differential itself runs only in the private harness
(`execute_initialization_opener_result.py`) against the pinned analysis image.
"""
import copy
import importlib.util
import json
from pathlib import Path
import struct
import sys
import unittest

SCRIPT = Path(__file__).resolve().parents[1]/'scripts/recomp/execute_initialization_opener_result.py'
sys.path.insert(0, str(SCRIPT.parent))


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, SCRIPT.parent/filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


m = load('opener_result_test', SCRIPT.name)
guard = load('opener_result_guard', 'execute_initialization_guard.py')
no_open = load('opener_result_no_open', 'execute_initialization_no_open.py')


class OpenerResultStateTests(unittest.TestCase):
    def test_state_is_deterministic_and_binds_the_opener_return_boundary(self):
        results, slots, alignment = set(), set(), set()
        for n in range(64):
            regs, pages = m.state(n)
            self.assertEqual((regs, pages), m.state(n))
            self.assertEqual(set(pages), set(m.probe.PAGES))
            off = regs['esi'] - m.c.DATA_PAGES[1]
            self.assertLessEqual(off + 0x38, 4096)
            alignment.add(regs['esi'] & 3)
            # EAX is the opener result; this fragment completes only on zero.
            results.add(regs['eax'])
            # The result slot starts non-zero so the [ESI+0x34] store is observable.
            slots.add(struct.unpack_from('<I', pages[m.c.DATA_PAGES[1]], off+0x34)[0])
            # EDI is callee-saved zero on 32 cases and non-zero on the other 32,
            # which is what makes the CMP/SETNE operand semantics observable.
            self.assertEqual(regs['edi'] == 0, n < 32)
            # Stack: [sp] string word, [sp+4] 0x40 word, [sp+8] saved EDI,
            # [sp+0xC] saved ESI (the receiver), [sp+0x10] the return sentinel.
            words = struct.unpack_from('<5I', pages[m.c.DATA_PAGES[0]],
                                       regs['esp']-m.c.DATA_PAGES[0])
            self.assertEqual(words[4], m.c.RETURN)
            self.assertEqual(words[3], regs['esi'])
            pages[m.c.DATA_PAGES[1]][0] ^= 1
            self.assertNotEqual(pages, m.state(n)[1])
        self.assertEqual(results, {0})
        self.assertNotIn(0, slots)
        self.assertEqual(len(slots), 64)
        self.assertEqual(alignment, {0})
        for bad in (-1, 64, True):
            with self.assertRaises(ValueError):
                m.state(bad)

    def test_oracle_stores_the_zero_result_and_derives_al_from_the_cmp_operand(self):
        saw_zero_al = saw_one_al = False
        for n in range(64):
            regs, pages = m.state(n)
            before = copy.deepcopy((regs, pages))
            out = m.oracle(regs, pages)
            eax = out['regs'][m.c.REGS.index('eax')]
            self.assertIn(eax, (0, 1))
            self.assertEqual(eax, 1 if regs['edi'] else 0)
            saw_zero_al |= eax == 0
            saw_one_al |= eax == 1
            # The two argument pops, the EDI/ESI restoration and the ret pop.
            self.assertEqual(out['regs'][m.c.REGS.index('esp')], regs['esp'] + 0x14)
            # Only the return-value/argument/frame registers change; ESI is
            # restored to the same receiver and EBX/EDX/EBP are untouched.
            for r in m.c.REGS:
                if r not in ('eax', 'ecx', 'edi', 'esp'):
                    self.assertEqual(out['regs'][m.c.REGS.index(r)], regs[r])
            # Observable memory effect: exactly one word, the stored result 0 at
            # [receiver+0x34]; nothing else in the six pages moves.
            expected = bytearray(b''.join(pages[p] for p in m.probe.PAGES))
            index = m.probe.PAGES.index(m.c.DATA_PAGES[1])*4096
            struct.pack_into('<I', expected, index + regs['esi'] - m.c.DATA_PAGES[1] + 0x34, 0)
            self.assertEqual(out['pages'], expected.hex())
            self.assertEqual((regs, pages), before)  # the oracle is pure
        self.assertTrue(saw_zero_al and saw_one_al)

    def test_oracle_rejects_nonzero_result_foreign_frames_and_missing_pages(self):
        regs, pages = m.state(0)
        # A non-zero opener result diverts to `push ESI; push EAX; call 0x1030`,
        # which this segment never executes or responds to.
        for eax in (1, 0x80000000, 0xffffffff):
            with self.assertRaises(ValueError):
                m.oracle(dict(regs, eax=eax), pages)
        for esi in (m.c.DATA_PAGES[1]-4, m.c.DATA_PAGES[1]+4096-0x34, regs['esi']+1):
            with self.assertRaises(ValueError):
                m.oracle(dict(regs, esi=esi), pages)
        for esp in (m.c.DATA_PAGES[0]+0x804, m.c.DATA_PAGES[0]+0x400, regs['esi']):
            with self.assertRaises(ValueError):
                m.oracle(dict(regs, esp=esp), pages)
        for name in m.probe.PAGES:
            missing = {k: v for k, v in pages.items() if k != name}
            with self.assertRaises(ValueError):
                m.oracle(regs, missing)
        # Corrupt the frame contract: the sentinel, or a saved ESI that is not the
        # receiver whose +0x34 slot this segment writes.
        sp = regs['esp']-m.c.DATA_PAGES[0]
        for offset, value in ((0x10, 0), (0xc, regs['esi']+4)):
            bad = copy.deepcopy(pages)
            struct.pack_into('<I', bad[m.c.DATA_PAGES[0]], sp+offset, value)
            with self.assertRaises(ValueError):
                m.oracle(regs, bad)

    def test_segment_lies_inside_the_settled_enclosing_function(self):
        self.assertEqual(guard.RVA, 0x1ab665)
        self.assertEqual(guard.SIZE, 267)
        self.assertLessEqual(guard.RVA, m.RVA)
        self.assertLessEqual(m.RVA+m.SIZE, guard.RVA+guard.SIZE)
        self.assertEqual(m.SEGMENT_NODES, 60)
        self.assertEqual(len(m.RESULT_PATH), 10)  # 10 of 83 whole-function instructions
        self.assertEqual(len(m.NEW_SITES), 6)
        self.assertEqual(len(m.SEGMENT_CALLEES), len(set(m.SEGMENT_CALLEES)))
        # Every segment callee is a helper below the enclosing function; this edge
        # executes none of them (the zero-result completion has callee_calls == 0).
        for callee in m.SEGMENT_CALLEES:
            self.assertLess(int(callee, 16), guard.RVA)


class OpenerResultArmDistinctnessTests(unittest.TestCase):
    def test_executed_sites_are_new_relative_to_both_early_return_arms(self):
        guard_path, open_path = set(guard.GUARD_PATH), set(no_open.NO_OPEN_PATH)
        self.assertEqual(set(m.NEW_SITES), set(m.RESULT_PATH[:6]))
        self.assertFalse(set(m.NEW_SITES) & guard_path)
        self.assertFalse(set(m.NEW_SITES) & open_path)
        # The tail is shared: this arm joins the guard's AL=1 return at 0x1AB766
        # through the CMP/SETNE node 0x1AB763 that neither early-return arm reaches.
        self.assertIn(0x1ab766, guard_path & set(m.RESULT_PATH))
        self.assertNotIn(0x1ab766, open_path)
        for site in (0x1ab769, 0x1ab76a, 0x1ab76b):
            self.assertIn(site, guard_path & open_path & set(m.RESULT_PATH))
        self.assertIn(0x1ab763, m.RESULT_PATH)
        self.assertNotIn(0x1ab763, guard_path | open_path)
        # And it is not simply a re-run of an early-return arm.
        self.assertNotEqual(list(m.RESULT_PATH), list(guard.GUARD_PATH))
        self.assertNotEqual(list(m.RESULT_PATH), list(no_open.NO_OPEN_PATH))

    def test_al_semantics_differ_from_both_early_return_arms(self):
        # The guard always returns AL=1 and the no-open arm always AL=0; this arm
        # derives AL from ([+0x34] != EDI) so both values occur across the space.
        guard_al = {guard.oracle(*guard.state(n))['regs'][0] & 0xff for n in range(64)}
        open_al = {no_open.oracle(*no_open.state(n))['regs'][0] & 0xff for n in range(64)}
        result_al = {m.oracle(*m.state(n))['regs'][0] for n in range(64)}
        self.assertEqual(guard_al, {1})
        self.assertEqual(open_al, {0})
        self.assertEqual(result_al, {0, 1})


class OpenerResultWiringTests(unittest.TestCase):
    def test_transport_targets_only_the_segment_body(self):
        body = 'static void segment_marker_1ab6a6(void) { recomp32_marker(); }'
        text = m.assemble(body, list(m.SEGMENT_CALLEES))
        self.assertIn('case 0xA01AB6A6u: initialization_opener_result_1AB6A6();break;', text)
        self.assertIn('static void adapter_1AB6A6(uint32_t* s) {select_body(0xA01AB6A6u,s);}', text)
        self.assertIn('case 0xA01AB6A6u:callback=adapter_1AB6A6;break;', text)
        self.assertIn('cache_invoke(0xA01AB6A6u,in,adapter_1AB6A6)', text)
        self.assertIn(body, text)
        self.assertEqual(text.count('initialization_opener_result_1AB6A6'), 2)  # proto+select
        for placeholder in ('@PROTOTYPES@', '@SELECT@', '@ADAPTERS@', '@CALLBACKS@',
                            '@DIRECT_RETURNS@', '@INDIRECT_RETURNS@', '@BODY@'):
            self.assertNotIn(placeholder, text)
        self.assertEqual(text.count('cache_invoke(0xA01AB6A6u,in,adapter_1AB6A6)'), 1)
        self.assertNotIn('cache_invoke(0xA01ABD40u', text)  # the settled caller is gone
        for callee in m.SEGMENT_CALLEES:
            self.assertIn(f'0x{m.c.BASE+int(callee,16):08X}', text)
        # A callee set that is not exactly the segment's own inventory is rejected.
        with self.assertRaises(ValueError):
            m.assemble(body, list(m.SEGMENT_CALLEES[:-1]))
        with self.assertRaises(ValueError):
            m.assemble(body, list(m.SEGMENT_CALLEES)+[m.SEGMENT_CALLEES[0]])
        for bad in ('', 0, None):
            with self.assertRaises(ValueError):
                m.assemble(bad, list(m.SEGMENT_CALLEES))

    def test_bridge_dispatches_one_target_and_injects_only_the_named_controls(self):
        valid = m.bridge_source('valid')
        self.assertIn('constexpr std::array<uint32_t,1> targets{0xA01AB6A6u};', valid)
        self.assertNotIn('0xA01ABD40u', valid)
        self.assertNotIn('s[0]^=1;', valid)
        self.assertNotIn('s[7]+=8;', valid)
        # wrong-result flips AL (SETE-for-SETNE polarity), wrong-cleanup corrupts
        # the returned ESP; each must be able to differ on every case.
        self.assertIn('s[0]^=1;', m.bridge_source('wrong-result'))
        self.assertIn('s[7]+=8;', m.bridge_source('wrong-cleanup'))
        self.assertNotIn('s[7]+=8;', m.bridge_source('wrong-result'))
        for bad in ('wrong-slot', 'valid-but-different', '', None):
            with self.assertRaises(ValueError):
                m.bridge_source(bad)

    def test_full_comparison_accepts_prediction_and_rejects_perturbations(self):
        expected = [dict(case=n, **m.oracle(*m.state(n))) for n in range(64)]
        encode = lambda rows: '\n'.join(map(json.dumps, rows))
        self.assertEqual(m.c.assess(encode(expected), expected, 'valid')['matched'], 64)
        for mode in m.MODES[1:]:
            with self.assertRaises(ValueError):
                m.c.assess(encode(expected), expected, mode)
            bad = copy.deepcopy(expected)
            for row in bad:
                if mode == 'wrong-result':
                    row['regs'][0] ^= 1  # inverted CMP/SETNE polarity
                else:
                    row['regs'][7] += 8  # returned ESP does not match the pops
            # Both controls must be rejected on every case, not merely some.
            self.assertEqual(m.c.assess(encode(bad), expected, mode)['differing_cases'], 64)
        for reg in range(8):
            bad = copy.deepcopy(expected)
            bad[0]['regs'][reg] ^= 1
            with self.assertRaises(ValueError):
                m.c.assess(encode(bad), expected, 'valid')
        for page in range(len(m.probe.PAGES)):
            bad = copy.deepcopy(expected)
            data = bytearray.fromhex(bad[0]['pages'])
            data[page*4096] ^= 1
            bad[0]['pages'] = data.hex()
            with self.assertRaises(ValueError):
                m.c.assess(encode(bad), expected, 'valid')


if __name__ == '__main__':
    unittest.main()
