"""Strict public lifted-dispatch vs independent bounded x86 and arithmetic oracles.

Build first. TS2_GUEST_DISPATCH_SMOKE selects an artifact;
TS2_GUEST_DISPATCH_RUNNER selects arm64-run.sh. Missing artifacts fail, not skip.
Unicorn is a development reference only, never linked into the shipped runtime.
"""
import os
from pathlib import Path
import struct
import subprocess
import unittest
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32
from unicorn import x86_const as X

ROOT = Path(__file__).resolve().parents[1]
VA, STACK = 0xA0001000, 0xFFFE0000
CODE = bytes.fromhex('8b442404034424088944240cc3')
PAIRS = [(0, 0), (1, 2), (0xffffffff, 1), (0x7fffffff, 1),
         (0x80000000, 0xffffffff), (0xffffffff, 0xffffffff),
         (0x80000000, 0x80000000), (15, 1), (0x12345678, 0x87654321),
         (0xdeadbeef, 0x10203040), (255, 1), (0x7ffffffe, 1)]
REGS = [X.UC_X86_REG_EAX, X.UC_X86_REG_ECX, X.UC_X86_REG_EDX,
        X.UC_X86_REG_EBX, X.UC_X86_REG_ESP, X.UC_X86_REG_EBP,
        X.UC_X86_REG_ESI, X.UC_X86_REG_EDI, X.UC_X86_REG_EFLAGS]
SUMMARY = 'synthetic-dispatch: exact VA checked lift guards isolation passed'


def initial(index):
    return [0x11111111, 0x92345678, 0x33333333, 0x44444444, STACK,
            0x66666666, 0x87777777, 0x98888888, 0xed7 if index % 2 else 0x202]


def seed(a, b):
    data = bytearray(b'\xa5' * 4096)
    struct.pack_into('<III', data, 0, VA + len(CODE), a, b)
    return data


def oracle(index, a, b):
    r = initial(index)
    total = a + b
    value = total & 0xffffffff
    # Independent signed-range and low-nibble arithmetic, not the C++ formula.
    signed = lambda v: v if v < 0x80000000 else v - 0x100000000
    flags = int(total > 0xffffffff)
    flags |= 4 if value.to_bytes(4, 'little')[0].bit_count() % 2 == 0 else 0
    flags |= 16 if (a & 15) + (b & 15) > 15 else 0
    flags |= 64 if value == 0 else 0
    flags |= 128 if signed(value) < 0 else 0
    flags |= 2048 if not -0x80000000 <= signed(a) + signed(b) <= 0x7fffffff else 0
    r[0], r[4], r[8] = value, STACK + 4, (r[8] & ~0x8d5) | flags
    data = seed(a, b)
    struct.pack_into('<I', data, 12, value)
    return r, bytes(data)


def reference(index, a, b):
    machine = Uc(UC_ARCH_X86, UC_MODE_32)
    machine.mem_map(VA, 4096)
    machine.mem_map(STACK, 4096)
    machine.mem_write(VA, CODE)
    machine.mem_write(STACK, bytes(seed(a, b)))
    for reg, value in zip(REGS, initial(index)):
        machine.reg_write(reg, value)
    machine.emu_start(VA, VA + len(CODE), timeout=1_000_000, count=16)
    if machine.reg_read(X.UC_X86_REG_EIP) != VA + len(CODE):
        raise ValueError('Reference did not reach return marker')
    return [machine.reg_read(reg) for reg in REGS], bytes(machine.mem_read(STACK, 4096))


def compare(text, states):
    lines = text.splitlines()
    if len(lines) != len(states) + 1 or lines[-1] != SUMMARY:
        raise ValueError('Incomplete or malformed result stream')
    for index, ((registers, memory), line) in enumerate(zip(states, lines)):
        expected = (f'case={index}' + ''.join(f' {v:08x}' for v in registers)
                    + ' ' + memory[:32].hex())
        if line != expected:
            raise ValueError(f'State mismatch at case {index}')


class GuestDispatchSmokeTests(unittest.TestCase):
    def test_lifted_dispatch_matches_x86_and_independent_oracle(self):
        states = []
        for index, (a, b) in enumerate(PAIRS):
            expected = oracle(index, a, b)
            self.assertEqual(reference(index, a, b), expected)
            states.append(expected)
        binary = os.environ.get('TS2_GUEST_DISPATCH_SMOKE',
                                str(ROOT / 'build/host/ts2_guest_dispatch_smoke'))
        runner = os.environ.get('TS2_GUEST_DISPATCH_RUNNER')
        result = subprocess.run(([runner] if runner else []) + [binary],
                                capture_output=True, timeout=75, check=False)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
        self.assertEqual(result.stderr, b'')
        compare(result.stdout.decode(), states)

    def test_every_register_flag_and_memory_component_checked(self):
        r, m = oracle(2, *PAIRS[2])
        # One-state transport exercises the very same comparison as native output.
        line = 'case=0' + ''.join(f' {v:08x}' for v in r) + ' ' + m[:32].hex()
        text = line + '\n' + SUMMARY + '\n'
        compare(text, [(r, m)])
        for i in range(9):
            corrupt = r.copy()
            corrupt[i] ^= 1
            with self.assertRaises(ValueError):
                compare(text, [(corrupt, m)])
        for bit in [0, 2, 4, 6, 7, 10, 11]:
            corrupt = r.copy()
            corrupt[8] ^= 1 << bit
            with self.assertRaises(ValueError):
                compare(text, [(corrupt, m)])
        for i in range(32):
            corrupt = bytearray(m)
            corrupt[i] ^= 1
            with self.assertRaises(ValueError):
                compare(text, [(r, bytes(corrupt))])

    def test_partial_duplicate_extra_and_malformed_stream_reject(self):
        r, m = oracle(0, *PAIRS[0])
        line = 'case=0' + ''.join(f' {v:08x}' for v in r) + ' ' + m[:32].hex()
        for text in ['', line, SUMMARY, line + '\n' + line + '\n' + SUMMARY,
                     line.replace('case=0', 'case=1') + '\n' + SUMMARY,
                     line + '\n' + SUMMARY + '\nextra']:
            with self.assertRaises(ValueError):
                compare(text, [(r, m)])


if __name__ == '__main__':
    unittest.main()
