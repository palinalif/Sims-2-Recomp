#!/usr/bin/env python3
"""Bounded original startup-pair reference; APIs are authored, NOT Windows.

No lift, PE launch, recovery or runtime binding. All states/output stay private.
Reuses the run3 frame/value hypothesis, with explicit endpoint cleanup checks.
"""
import argparse
import hashlib
import json
from pathlib import Path
import random
import struct
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from measure_leaf import ROOT, IMAGE_SHA
from measure_startup import decode_flow, dependencies, BASE

M = 0xFFFFFFFF
DEFAULT = 0xBB40E64E
INIT, HELPER = BASE + 0x8258A9, BASE + 0x82585C
ENTRY, TAIL = BASE + 0x8248A3, BASE + 0x824727
DATA = BASE + 0x104F000
COOKIE, COMPLEMENT = DATA + 0x540, DATA + 0x580
RETURN, API = 0x71000000, 0x72000000
# Metadata only: independently checked against PE imports before execution.
IMPORTS = ('GetSystemTimeAsFileTime', 'GetCurrentThreadId',
           'GetCurrentProcessId', 'QueryPerformanceCounter')
SLOTS = (0xD9A2A4, 0xD9A194, 0xD9A1BC, 0xD9A24C)
CALLS = (0x82586E, 0x82587D, 0x825886, 0x825893)
RETURNS = tuple(BASE + r + 6 for r in CALLS)


def require(condition):
    if not condition:
        raise ValueError('Startup reference contract rejected')


def put(page, offset, value):
    struct.pack_into('<I', page, offset, value & M)


def cookie_value(cookie, entropy):
    used = cookie == DEFAULT or cookie < 0x10000
    value = entropy if used else cookie
    if used:
        if value == DEFAULT:
            value += 1
        elif value < 0x10000:
            value = (value | ((value | 0x4711) << 16)) & M
    return value, used


def cases():
    rng = random.Random(140118187)
    edges = (DEFAULT, 0, 1, 0xFFFF, 0x10000, 0x80000000, M, 0x12345678)
    result = []
    for n in range(320):
        stack = 0x70000000 + (n % 4) * 0x10000
        sp = stack + 0x800
        cookie = edges[n % 8]
        target = edges[(n // 8) % 8] if n < 256 else rng.getrandbits(32)
        values = [rng.getrandbits(32) for _ in range(6)]
        # Helper entry SP is outer SP-12, not SP-4. Force reduction branches.
        values[5] = target ^ values[0] ^ values[1] ^ values[2] ^ values[3] ^ values[4] ^ (sp-20)
        result.append(dict(stack=stack, sp=sp, cookie=cookie, values=values,
                           saved=[rng.getrandbits(32) for _ in range(4)], qpc=n & 1))
    return result


def endpoint(k, sp, ret, arg, case, read, write, *, cleanup=None):
    """Authored stdcall endpoints, checked before and AFTER cleanup.

    This catches wrong QPC cleanup even when the helper's LEAVE masks it.
    read/write have exact byte ranges, independent of Unicorn page permissions.
    """
    require(type(k) is int and 0 <= k < 4)
    hs = case['sp'] - 12
    pop = 4 if k in (0, 3) else 0
    require(sp == hs - (32 if pop else 28) and ret == RETURNS[k])
    ptr = hs - (16 if k == 0 else 24)
    if pop:
        require(arg == ptr)
        if k == 0:
            require(read(ptr, 8) == bytes(8))
        values = case['values'][:2] if k == 0 else case['values'][4:]
        write(ptr, struct.pack('<II', *values))
    else:
        require(arg is None)
    after = sp + 4 + (pop if cleanup is None else cleanup)
    require(after == hs - 24)
    return [0xDEADBEEF, case['values'][2], case['values'][3], case['qpc']][k], after


def oracle(case):
    sp, stack, saved, v = (case[k] for k in ('sp', 'stack', 'saved', 'values'))
    hs = sp - 12
    entropy = v[0] ^ v[1] ^ v[2] ^ v[3] ^ v[4] ^ v[5] ^ (hs-8)
    value, used = cookie_value(case['cookie'], entropy)
    memory = bytearray(b'\xA5' * 4096)
    put(memory, sp-stack, RETURN)
    put(memory, sp-stack-4, saved[1])
    put(memory, sp-stack-8, saved[2])
    if used:
        words = {hs: BASE+0x8258C8, hs-4: saved[3],
                 hs-8: v[0]^v[1]^v[2]^v[3], hs-12: v[1], hs-16: v[0],
                 hs-20: v[5], hs-24: v[4], hs-28: hs-24, hs-32: RETURNS[3]}
        for address, word in words.items():
            put(memory, address-stack, word)
    data = bytearray(b'\xA5' * 4096)
    put(data, COOKIE-DATA, value)
    put(data, COMPLEMENT-DATA, ~value)
    # Return scratch is not the published complement: bypass preserves EAX;
    # collision keeps raw entropy; low normalization leaves the shifted term.
    eax = 0x13579BDF
    if used:
        eax = ((entropy | 0x4711) << 16)&M if entropy < 0x10000 else entropy
    return dict(eax=eax, saved=saved, sp=sp+4, stack=bytes(memory),
                data=bytes(data), events=list(range(4)) if used else [])


def entry_flow(code):
    """Accept only the selected CALL initializer / external direct tail boundary.

    The tail target is a stop, NOT an implemented service or returning stub.
    Keep this separate from decode_flow's normal-return-only contract.
    """
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    from capstone.x86 import X86_OP_IMM
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    nodes = list(md.disasm(code, ENTRY))
    require(len(code) == 10 and len(nodes) == 2)
    for insn, mnemonic, target in zip(nodes, ('call', 'jmp'), (INIT, TAIL)):
        require(insn.mnemonic == mnemonic and insn.size == 5 and
                len(insn.operands) == 1 and insn.operands[0].type == X86_OP_IMM and
                (insn.operands[0].imm & M) == target)
    return nodes


def entry_oracle(case):
    """Compose the independently checked pair frame with the outer caller frame."""
    inner = dict(case, sp=case['sp']-4)
    state = oracle(inner)
    memory = bytearray(state['stack'])
    put(memory, case['sp']-case['stack'], RETURN)
    put(memory, inner['sp']-case['stack'], ENTRY+5)
    state.update(sp=case['sp'], stack=bytes(memory), eip=TAIL)
    return state


def exercise(codes, case, *, cleanup=None, budget=140, slots=SLOTS, entry=False,
             accesses=None):
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_AC_READ, CS_AC_WRITE
    from capstone.x86 import X86_OP_MEM
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32
    from unicorn.x86_const import (UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX,
        UC_X86_REG_EDX, UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_EBP,
        UC_X86_REG_ESP, UC_X86_REG_EIP, UC_X86_REG_EFLAGS)
    require(type(entry) is bool and
            set(codes) == ({INIT, HELPER, ENTRY} if entry else {INIT, HELPER}) and
            0 < budget <= 140)
    if entry:
        entry_flow(codes[ENTRY])
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    nodes = {}
    for start, code in codes.items():
        instructions = list(md.disasm(code, start))
        require(sum(i.size for i in instructions) == len(code))
        nodes.update({i.address: i for i in instructions})
    u = Uc(UC_ARCH_X86, UC_MODE_32)
    stack, sp = case['stack'], case['sp']
    require(stack in (0x70000000, 0x70010000, 0x70020000, 0x70030000) and sp == stack+0x800)
    for page in (BASE+0x824000, BASE+0x825000, BASE+0xD9A000, stack, DATA, RETURN, API):
        u.mem_map(page, 4096)
    for start, code in codes.items():
        u.mem_write(start, code)
    u.mem_write(stack, b'\xA5'*4096)
    u.mem_write(sp, struct.pack('<I', RETURN))
    u.mem_write(DATA, b'\xA5'*4096)
    u.mem_write(COOKIE, struct.pack('<I', case['cookie']))
    for k, slot in enumerate(slots):
        u.mem_write(BASE+slot, struct.pack('<I', API+16*k))
    immutable = {p: bytes(u.mem_read(p, 4096)) for p in
                 (BASE+0x824000, BASE+0x825000, BASE+0xD9A000, RETURN, API)}
    saved_regs = (UC_X86_REG_EBX, UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_EBP)
    for reg, value in zip(saved_regs, case['saved']):
        u.reg_write(reg, value)
    u.reg_write(UC_X86_REG_EAX, 0x13579BDF)
    u.reg_write(UC_X86_REG_ESP, sp)
    u.reg_write(UC_X86_REG_EIP, ENTRY if entry else INIT)
    u.reg_write(UC_X86_REG_EFLAGS, 0x202)
    events = []
    pair_case = dict(case, sp=sp-4) if entry else case

    def access(kind, address, size):
        if accesses is not None:
            accesses.append((kind, address, size))

    def stack_read(address, size):
        require(stack <= address and address+size <= stack+4096)
        access('read', address, size)
        return bytes(u.mem_read(address, size))

    def output_write(address, payload):
        # Endpoints may ONLY write their independently checked output pair.
        k = len(events)-1
        require(k in (0, 3) and len(payload) == 8)
        require(address == pair_case['sp']-12-(16 if k == 0 else 24))
        access('endpoint-write', address, len(payload))
        u.mem_write(address, payload)

    for _ in range(budget):
        ip = u.reg_read(UC_X86_REG_EIP)
        if ip == (TAIL if entry else RETURN):
            break
        if ip in tuple(API+16*k for k in range(4)):
            k = (ip-API)//16
            require(k == len(events))
            events.append(k)
            s = u.reg_read(UC_X86_REG_ESP)
            ret = int.from_bytes(stack_read(s, 4), 'little')
            arg = int.from_bytes(stack_read(s+4, 4), 'little') if k in (0, 3) else None
            # Fault injection targets QPC specifically: its bad cleanup used to
            # be hidden by helper frame teardown in the historical private rig.
            eax, after = endpoint(k, s, ret, arg, pair_case, stack_read, output_write,
                                  cleanup=cleanup if k == 3 else None)
            for reg, value in ((UC_X86_REG_EAX, eax), (UC_X86_REG_ECX, 0xCCCCCCCC),
                               (UC_X86_REG_EDX, 0xDDDDDDDD), (UC_X86_REG_ESP, after),
                               (UC_X86_REG_EIP, ret)):
                u.reg_write(reg, value)
            continue
        require(ip in nodes)
        insn = nodes[ip]
        s = u.reg_read(UC_X86_REG_ESP)
        require(stack+64 <= s <= stack+4092)
        # Validate explicit memory operands before single stepping (no hooks).
        for op in insn.operands:
            if op.type != X86_OP_MEM:
                continue
            require(not op.mem.segment)
            def regval(reg):
                return u.reg_read(getattr(__import__('unicorn.x86_const', fromlist=['x']),
                    'UC_X86_REG_'+insn.reg_name(reg).upper())) if reg else 0
            address = (regval(op.mem.base)+regval(op.mem.index)*op.mem.scale+op.mem.disp)&M
            if insn.mnemonic == 'lea':
                continue
            require((stack <= address and address+op.size <= stack+4096) or
                    (address in (COOKIE, COMPLEMENT) and op.size == 4) or
                    (address in tuple(BASE+x for x in SLOTS) and op.size == 4))
            if accesses is not None:
                require(op.access and not op.access & ~(CS_AC_READ | CS_AC_WRITE))
                if op.access & CS_AC_READ:
                    access('read', address, op.size)
                if op.access & CS_AC_WRITE:
                    access('write', address, op.size)
        if accesses is not None:
            # Only these decoded implicit stack operations are supported by this
            # diagnostic journal. Do not infer stores from final changed bytes:
            # same-value stores and nested CALL return words matter too.
            if insn.mnemonic in ('push', 'call'):
                access('write', s-4, 4)
            elif insn.mnemonic in ('pop', 'ret'):
                access('read', s, 4)
            elif insn.mnemonic == 'leave':
                access('read', u.reg_read(UC_X86_REG_EBP), 4)
            require(insn.mnemonic not in ('enter', 'pushal', 'popal', 'pushfd', 'popfd',
                                         'iret', 'retf', 'lcall', 'ljmp'))
        u.emu_start(ip, 0, count=1)
    else:
        raise ValueError('Startup reference instruction budget')
    require(all(bytes(u.mem_read(p, 4096)) == data for p, data in immutable.items()))
    state = dict(eax=u.reg_read(UC_X86_REG_EAX), saved=[u.reg_read(r) for r in saved_regs],
                 sp=u.reg_read(UC_X86_REG_ESP), stack=bytes(u.mem_read(stack, 4096)),
                 data=bytes(u.mem_read(DATA, 4096)), events=events)
    if entry:
        state['eip'] = u.reg_read(UC_X86_REG_EIP)
    return state


def verify_state(actual, expected):
    require(set(actual) == set(expected) and actual == expected)


def run(output, *, entry=False):
    output = output.resolve()
    require(output.is_relative_to((ROOT/'work/recomp-bench').resolve()))
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    row = dict(schema='ts2-startup-reference/1', success=False, fresh_x86_reference=False,
               lifted=False, compiled_for_aarch64=False, executed_under_qemu=False,
               android_executed=False, startup_executed=False, cases=0, timings={},
               entry_boundary=entry, tail_target_executed=False,
               invocation=[sys.executable, *sys.argv],
               harness_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), limits=[
                   'authored API outputs and preserving-flags stdcall endpoints, not Windows',
                   'EAX/nonvolatile GPRs/return ESP/full stack and data pages/order/frames only',
                   'final ECX/EDX/flags/FP/SIMD/transient writes/SEH/concurrency NOT compared',
                   'no lifter execution or original-game runtime integration'])
    stage = 'preflight'
    try:
        start = time.monotonic()
        import pefile
        image = ROOT/'work/interop-legacy-002/analysis-image.bin'
        require(hashlib.sha256(image.read_bytes()).hexdigest() == IMAGE_SHA)
        pe = pefile.PE(data=image.read_bytes())
        require(pe.OPTIONAL_HEADER.ImageBase == BASE and pe.FILE_HEADER.Machine == 0x14C)
        # Reuse persistent private index evidence; no import/query/recovery.
        envelope = ROOT/'work/recomp-bench/run5-005-logs/helper.json.env.json'
        provenance = json.loads(envelope.read_text())['provenance']
        require(provenance['sourceImageSha256'] == IMAGE_SHA and
                provenance['mode'] == 'readOnly' and not provenance['analysisPerformed'] and
                provenance['headlessExitCode'] == 0)
        row['index_envelope_sha256'] = hashlib.sha256(envelope.read_bytes()).hexdigest()
        row['index_warning'] = 'Known OS CA-bundle ERROR; index is not behavioral evidence'
        row['image_sha256'] = IMAGE_SHA
        codes = {INIT: pe.get_data(INIT-BASE, 75), HELPER: pe.get_data(HELPER-BASE, 77)}
        if entry:
            envelope = ROOT/'work/phase1-run3-010/caller.json.env.json'
            provenance = json.loads(envelope.read_text())['provenance']
            require(provenance['sourceImageSha256'] == IMAGE_SHA and
                    provenance['mode'] == 'readOnly' and not provenance['analysisPerformed'] and
                    provenance['headlessExitCode'] == 0)
            row['entry_index_envelope_sha256'] = hashlib.sha256(envelope.read_bytes()).hexdigest()
            row['limits'].append('stop BEFORE external tail; no target body or startup execution')
            entry_code = pe.get_data(ENTRY-BASE, 10)
            entry_flow(entry_code)
        for body_entry, code in codes.items():
            _, nodes, _, analysis = decode_flow(code, body_entry, lambda i: i)
            require(analysis['reachable_bytes'] == len(code))
            if body_entry == HELPER:
                sites = dependencies(nodes, pe)['indirect_call_sites']
                require(len(sites) == 4)
                for site, slot, name, call in zip(sites, SLOTS, IMPORTS, CALLS):
                    require(site['slot_rva'] == hex(slot) and site['call_rva'] == hex(call) and
                            site['import_metadata']['dll'] == 'KERNEL32.dll' and
                            site['import_metadata']['name'] == name)
        if entry:
            codes[ENTRY] = entry_code
        row['body_sha256'] = {hex(e-BASE): hashlib.sha256(c).hexdigest() for e,c in codes.items()}
        row['timings']['preflight'] = time.monotonic()-start
        stage = 'reference'
        start = time.monotonic()
        states = []
        expected = entry_oracle if entry else oracle
        for case in cases():
            actual = exercise(codes, case, entry=entry)
            verify_state(actual, expected(case))
            states.append(dict(case=case, state={k: v.hex() if isinstance(v, bytes) else v
                                               for k,v in actual.items()}))
            row['cases'] += 1
        row['timings']['reference_and_oracle'] = time.monotonic()-start
        # Wrong stdcall cleanup must fail at boundary, not merely at final ESP.
        rejected = 0
        for options in ({'cleanup': 0}, {'cleanup': 8}, {'budget': 1},
                        {'slots': (SLOTS[1], SLOTS[0], *SLOTS[2:])}):
            try:
                verify_state(exercise(codes, cases()[0], entry=entry, **options), expected(cases()[0]))
            except ValueError:
                rejected += 1
        require(rejected == 4)
        row['rejected_controls'] = rejected
        (output/'reference.json').write_text(json.dumps(states)+'\n')
        row['helper_invoked'] = sum(bool(s['state']['events']) for s in states)
        row['helper_bypassed'] = len(states)-row['helper_invoked']
        row['fresh_x86_reference'] = row['success'] = True
    except Exception as exc:
        row.update(failed_stage=stage, error_type=type(exc).__name__)
        raise
    finally:
        (output/'result.json').write_text(json.dumps(row, indent=2)+'\n')
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--entry-boundary', action='store_true',
                        help='include selected entry, stop BEFORE its external tail target')
    args = parser.parse_args()
    try:
        row = run(args.output, entry=args.entry_boundary)
    except Exception:
        parser.exit(1, 'Startup reference failed; inspect private result/logs.\n')
    print('Startup %s: %d bounded x86 cases; no native translation or startup claim' %
          ('entry boundary' if args.entry_boundary else 'pair', row['cases']))


if __name__ == '__main__':
    main()
