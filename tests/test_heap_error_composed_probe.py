"""Authored composition controls; no private original fixture is opened."""
import contextlib
import copy
import io
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import heap_error_composed_probe as p
r = p.r


def call(at, target):
    return b'\xe8'+struct.pack('<I', (target-at-5) & r.NEG)


def fixtures():
    # Authored nested chain with different frames/return sites from the game.
    release = bytearray(b'\x53\x6a\x13')  # save EBX; push 19
    release += call(p.release.ENTRY+len(release), p.mapper.ENTRY)
    release += b'\x83\xc4\x04\x89\xc3'  # cleanup; retain mapping in EBX
    release += call(p.release.ENTRY+len(release), p.accessor.ENTRY)
    release += b'\x89\x18\x5b\xc3'  # store at returned address; restore EBX
    accessor = call(p.accessor.ENTRY, p.provider.ENTRY)+b'\x83\xc0\x10\xc3'
    provider = b'\x6a\x03'+call(p.provider.ENTRY+2, p.provider.QUERY)+b'\xc3'
    mapper = b'\xb8'+struct.pack('<I', 0x80000000)+b'\xc3'
    return {p.release.ENTRY: bytes(release), p.mapper.ENTRY: mapper,
            p.accessor.ENTRY: accessor, p.provider.ENTRY: provider}


def args(pointer=p.PTD):
    return (1, 2, 0, 19, 3, pointer,
            [(19, 0x80000000)]+[(10000+n, n) for n in range(p.mapper.COUNT-1)])


class HeapErrorComposedTests(unittest.TestCase):
    def test_authored_four_body_chain_and_slot_store(self):
        state = p.exercise(fixtures(), *args())
        self.assertEqual(state['registers'][0], p.PTD+16)
        self.assertEqual(state['registers'][7], r.SP+4)
        self.assertEqual(state['slots'], {p.PTD+16: 0x80000000,
                                         p.accessor.FALLBACK: p.SENTINEL})
        self.assertEqual([(e[0], e[1]) for e in state['events']], [('query', [3])])
        # Deliberately synthetic query disturbs last-error, with no restore here.
        self.assertEqual(state['lastError'], 20)
        with self.assertRaises((ValueError, p.UcError)):
            p.exercise(fixtures(), *args(), query_pop=0)

    def test_oracle_existing_and_sentinel_use_distinct_destinations(self):
        for pointer, slot in ((p.PTD, p.PTD+16), (r.NEG, p.accessor.FALLBACK)):
            state = p.oracle(*args(pointer))
            self.assertEqual(state['registers'][0], slot)
            self.assertEqual(state['slots'][slot], 0x80000000)
            self.assertEqual(state['lastError'], 19)
            self.assertEqual([e[0] for e in state['events']],
                             ['heap_free', 'get', 'get', 'query', 'set'])
            self.assertEqual(state['events'][-1][1], [19])
            # Existing provider saves EDI, not the release wrapper's ESI mapping.
            initial, _ = p.release.callback.inputs(1, 0)
            self.assertEqual(struct.unpack_from('<I', state['stack'], r.SP-r.STACK-24)[0],
                             initial[5])

    def test_caller_cleanup_overwrites_mapper_ecx_scratch(self):
        # 203 misses this authored table and both fallback intervals.
        inputs = list(args()); inputs[3] = 203
        self.assertEqual(p.mapper.oracle(203, inputs[6])['registers'][2], 14)
        self.assertEqual(p.oracle(*inputs)['registers'][2], 203)
        self.assertEqual(p.oracle(*inputs, clobber=True)['registers'][2], 0xFEEDFACE)
        # Independent authored x86 caller: its pop ECX must override callee ECX.
        codes = fixtures()
        codes[p.mapper.ENTRY] = b'\xb9\x0e\x00\x00\x00\xc3'
        code = b'\x68'+struct.pack('<I', 203)
        code += call(p.release.ENTRY+len(code), p.mapper.ENTRY)+b'\x59\xc3'
        codes[p.release.ENTRY] = code
        state = p.exercise(codes, *inputs)
        self.assertEqual(state['registers'][2], 203)
        self.assertEqual(state['registers'][7], r.SP+4)

    def test_oracle_null_success_do_not_write_error_slots(self):
        for context, result, count in ((0, 0, 0), (1, 0x80000000, 1)):
            inputs = list(args()); inputs[0] = context; inputs[2] = result
            state = p.oracle(*inputs)
            self.assertEqual(len(state['events']), count)
            self.assertTrue(all(v == p.SENTINEL for v in state['slots'].values()))

    def test_every_component_and_both_error_slots_are_compared(self):
        state = p.oracle(*args())
        for key in state:
            wrong = copy.deepcopy(state)
            if key == 'registers':
                wrong[key][4] ^= 1
            elif key == 'stack':
                value = bytearray(wrong[key]); value[0] ^= 1; wrong[key] = bytes(value)
            elif key == 'events':
                wrong[key].reverse()
            elif key == 'slots':
                wrong[key][p.accessor.FALLBACK] ^= 1
            else:
                wrong[key] ^= 1
            with self.subTest(key=key), self.assertRaises(ValueError):
                r.verify(wrong, state)

    def test_slow_path_and_unchecked_pointer_inputs_reject(self):
        for index, pointer in ((r.NEG, p.PTD), (0, 0), (0, 1)):
            inputs = list(args()); inputs[4:6] = index, pointer
            with self.assertRaises(ValueError):
                p.exercise(fixtures(), *inputs)
        codes = fixtures()
        codes[p.release.ENTRY] = call(p.release.ENTRY, r.BASE+0x846049)
        with self.assertRaises(ValueError):
            p.exercise(codes, *args())

    def test_immutable_neighbors_code_and_bounded_execution(self):
        for target in (p.PTD+12, p.PTD+20, p.accessor.FALLBACK+4,
                       p.provider.INDEX, p.mapper.TABLE, p.release.ENTRY+128):
            codes = fixtures()
            codes[p.release.ENTRY] = b'\xa3'+struct.pack('<I', target)+b'\xc3'
            with self.subTest(target=target), self.assertRaises(ValueError):
                p.exercise(codes, *args())
        for code in (b'\xeb\xfe', b'\xc2'):
            codes = fixtures(); codes[p.release.ENTRY] = code
            with self.assertRaises(ValueError):
                p.exercise(codes, *args())
        codes = fixtures(); del codes[p.mapper.ENTRY]
        with self.assertRaises(ValueError):
            p.exercise(codes, *args())

    def test_pin_failure_is_sanitized_and_read_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            image = Path(tmp)/'private.bin'; image.write_bytes(b'private fixture')
            out, err = io.StringIO(), io.StringIO()
            with patch.object(r, 'IMAGE', image), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                self.assertEqual(p.main([]), 2)
            self.assertEqual(out.getvalue(), '')
            self.assertNotIn(str(image), err.getvalue())
            self.assertNotIn('private fixture', err.getvalue())
            self.assertEqual(image.read_bytes(), b'private fixture')


if __name__ == '__main__':
    unittest.main()
