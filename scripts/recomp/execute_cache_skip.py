#!/usr/bin/env python3
"""Fresh 1290/12D0 lifts and skip-path differentials; NOT complete milestone M1.

Only H+100==0 is admitted. Dispatch is rejected, never supplied a response.
Derived bodies, pages and states must remain under ignored work/recomp-bench/.
"""
import argparse
import json
from pathlib import Path
import random
import struct
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from measure_leaf import ROOT, IMAGE_SHA, REVISION, digest, verify
from measure_startup import BASE, decode_flow, supported
from inspect_startup_dependency import crosscheck_index
from execute_resource_leaf import REGS, PAGES, RETURN, compare as compare_states, require, TEMPLATE

RVAS = (0x1290, 0x12d0)
CLOSURE = (0x1abd40, 0x1240, 0x1250, 0x1270, *RVAS, 0xfcf0, 0x9550)


def compare(text, expected):
    def unique(pairs):
        result = {}
        for key,value in pairs:
            require(key not in result)
            result[key] = value
        return result
    for line in text.splitlines():
        json.loads(line,object_pairs_hook=unique)
    return compare_states(text,expected)


def private_output(output):
    output = output.resolve()
    require(output.is_relative_to((ROOT/'work/recomp-bench').resolve()))
    output.mkdir(parents=True, mode=0o700, exist_ok=False)
    return output


def reference(code, entry, regs, pages):
    """Hook-free bounded original x86; validate every access before single-step.

    Actual CALL/JMP-indirect is forbidden: no endpoint hooks or authored returns.
    All four complete data pages and eight GPRs are observed, flags are NOT compared.
    """
    from capstone import CS_GRP_CALL
    from capstone.x86 import X86_OP_MEM
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32
    import unicorn.x86_const as x
    require(set(pages) == set(PAGES) and all(len(p) == 4096 for p in pages.values()))
    require(set(regs) == set(REGS))
    _, nodes, _, _ = decode_flow(code, entry, lambda i: i)
    u = Uc(UC_ARCH_X86, UC_MODE_32)
    cp = entry & ~4095
    require(cp not in PAGES and cp != RETURN and entry+len(code) <= cp+4096)
    for p, data in pages.items():
        u.mem_map(p, 4096)
        u.mem_write(p, bytes(data))
    u.mem_map(cp, 4096)
    u.mem_write(entry, code)
    immutable = bytes(u.mem_read(cp, 4096))
    u.mem_map(RETURN, 4096)
    ids = {r:getattr(x, 'UC_X86_REG_'+r.upper()) for r in REGS}
    for r in REGS:
        u.reg_write(ids[r], regs[r])
    u.reg_write(x.UC_X86_REG_EFLAGS, 0x202)

    def check(a, size):
        require(size == 4 and a % 4 == 0 and any(p <= a <= p+4096-size for p in PAGES))

    pc, visited = entry, set()
    for _ in range(64):
        require(pc in nodes)
        i = nodes[pc]
        require(not i.group(CS_GRP_CALL))
        require(i.mnemonic in ('mov', 'push', 'pop', 'cmp', 'test', 'je', 'jne', 'inc', 'ret', 'lea', 'add'))
        for op in i.operands:
            if op.type != X86_OP_MEM or i.mnemonic == 'lea':
                continue
            m = op.mem
            require(not m.segment)
            a = m.disp
            for reg, scale in ((m.base,1), (m.index,m.scale)):
                if reg:
                    name = i.reg_name(reg)
                    require(name in ids)
                    a += u.reg_read(ids[name])*scale
            check(a & 0xffffffff, op.size)
        sp = u.reg_read(ids['esp'])
        if i.mnemonic in ('push','pop','ret'):
            check((sp-4 if i.mnemonic == 'push' else sp) & 0xffffffff,4)
        visited.add(pc)
        u.emu_start(pc,0,count=1)
        pc = u.reg_read(x.UC_X86_REG_EIP)
        require(bytes(u.mem_read(cp,4096)) == immutable)
        require(bytes(u.mem_read(RETURN,4096)) == bytes(4096))
        if i.mnemonic == 'ret':
            require(pc == RETURN)
            return dict(regs=[u.reg_read(ids[r]) for r in REGS],
                        pages=b''.join(bytes(u.mem_read(p,4096)) for p in PAGES).hex()), visited
    raise ValueError('Reference budget exhausted')


def lift(output, rva, index):
    require(rva in RVAS)
    output = private_output(output)
    row = dict(schema='ts2-cache-skip-lift/1', rva=hex(rva), lifted=False,
               pcrecomp_revision=REVISION, image_sha256=IMAGE_SHA,
               invocation=[sys.executable,*sys.argv], harness_sha256=digest(Path(__file__)))
    try:
        image = ROOT/'work/interop-legacy-002/analysis-image.bin'
        require(digest(image) == IMAGE_SHA)
        upstream = ROOT/'work/interop-legacy-002/pcrecomp'
        pristine = ROOT/'work/deps/pcrecomp/sp00nznet-pcrecomp-c0cbd3e'
        verify(pristine)
        lock = json.loads((ROOT/'config/dependencies.lock.json').read_text())['pcrecomp']
        used = [n for n in lock['files'] if '/drm/' not in n]
        used += ['tools/lift/generate.py','tools/disasm/disasm32.py']
        require(all(digest(upstream/n) == digest(pristine/n) for n in used))
        row['upstream_files'] = {n:digest(upstream/n) for n in used}
        sys.path.insert(0,str(upstream))
        from tools.lift.lift32 import Lifter
        from tools.lift.generate import LinearInstruction
        require(Path(sys.modules[Lifter.__module__].__file__).resolve() == (upstream/'tools/lift/lift32.py').resolve())
        import pefile
        pe = pefile.PE(data=image.read_bytes())
        require(pe.OPTIONAL_HEADER.ImageBase == BASE and pe.FILE_HEADER.Machine == 0x14c)
        function,nodes,_,flow = decode_flow(pe.get_data(rva,64),BASE+rva,LinearInstruction)
        row['index'] = crosscheck_index(json.loads(index.read_text()),
            dict(flow,instruction_rvas=[hex(a-BASE) for a in sorted(nodes)]),rva)
        row['index_sha256'] = digest(index)
        start = time.monotonic()
        body = Lifter(precise_carry=True,lifted={function.address}).lift_function(function)
        row['translation_seconds'] = time.monotonic()-start
        row['lift_api'] = 'Lifter(precise_carry=True,lifted={entry_va}).lift_function(function)'
        require(supported(body))
        (output/'lifted.c').write_text(body)
        row.update(lifted=True, lifted_sha256=digest(output/'lifted.c'), flow=flow)
        require(digest(image) == IMAGE_SHA)
    finally:
        (output/'lift.json').write_text(json.dumps(row,indent=2)+'\n')
    return row


def assemble(body, rva):
    require(rva in RVAS and type(body) is str and bool(body.strip()) and supported(body))
    # No behavior response: any reached call aborts this isolated fixture.
    guard = '\n#undef RECOMP_ICALL\n#define RECOMP_ICALL(target) do { (void)(target); rejected=1; longjmp(escape,1); } while(0)\n'
    text = TEMPLATE.read_text()
    require(text.count('@BODY@') == 1 and text.count('startup_82A47B()') == 1)
    return text.replace('@BODY@',guard+body).replace('startup_82A47B()',f'startup_{rva:06X}()')


def run(output, rva, index):
    require(rva in RVAS)
    output = private_output(output)
    row = dict(schema='ts2-cache-skip-native/1',rva=hex(rva), success=False,
        caller_closure=[hex(r) for r in CLOSURE], survey_expanded=False,
        invocation=[sys.executable,*sys.argv],harness_sha256=digest(Path(__file__)),
        template_sha256=digest(TEMPLATE), commands=[],runs={},
        arm64_executed=False,android_executed=False,m1_complete=False,
        limits=['H+100==0 only; dispatch path explicitly rejected, NOT stubbed',
                'eight GPRs and four full data pages; no flags/FP/native PC/transient-write comparison',
                'synthetic entry state; no lifetime, producer execution, caller composition or runtime integration'])
    def command(name, argv, data=None):
        start = time.monotonic()
        record = dict(name=name,argv=[str(a) for a in argv])
        row['commands'].append(record)
        with (output/(name+'.stdout')).open('xb') as out, (output/(name+'.stderr')).open('xb') as err:
            p = subprocess.run(record['argv'],input=data,stdout=out,stderr=err,cwd=ROOT,timeout=120)
        record.update(exit_code=p.returncode,seconds=time.monotonic()-start)
        require(p.returncode == 0)
    stage = 'lift'
    try:
        command('lift',[sys.executable,Path(__file__),'--lift-only','--rva',hex(rva),'--index',index,'--output',output/'lift'])
        lifted = json.loads((output/'lift/lift.json').read_text())
        require(lifted['lifted'] and digest(output/'lift/lifted.c') == lifted['lifted_sha256'])
        row['lift'] = lifted
        import pefile
        image = ROOT/'work/interop-legacy-002/analysis-image.bin'
        require(digest(image) == IMAGE_SHA)
        pe = pefile.PE(data=image.read_bytes())
        code = pe.get_data(rva,lifted['flow']['size_bytes'])
        stage = 'reference'
        rng = random.Random(118187+rva)
        inputs,expected,visited = bytearray(),[],set()
        for n in range(64):
            regs = {r:rng.getrandbits(32) for r in REGS}
            regs['esp'] = PAGES[0]+(0x800 if n%2 else 0xc00)
            pages = {p:bytearray(rng.randbytes(4096)) for p in PAGES}
            handle = PAGES[1]+128
            struct.pack_into('<II',pages[PAGES[0]],regs['esp']-PAGES[0],RETURN,handle)
            struct.pack_into('<I',pages[PAGES[1]],128+0x100,0)
            value = (0,1,0x7fffffff,0xffffffff,rng.getrandbits(32))[n%5]
            slot = 0x1c8 if rva == 0x1290 else 0x1cc
            struct.pack_into('<I',pages[PAGES[1]],128+slot,value)
            state,seen = reference(code,BASE+rva,regs,pages)
            # Independent value/cleanup oracle in addition to full x86-state comparison.
            require(state['regs'][0] == ((value+1)&0xffffffff if rva == 0x1290 else value))
            require(state['regs'][-1] == regs['esp']+4)
            require(bytes.fromhex(state['pages'])[4096:] == b''.join(bytes(pages[p]) for p in PAGES[1:]))
            visited.update(seen)
            expected.append(dict(case=n,**state))
            inputs.extend(struct.pack('<8I',*(regs[r] for r in REGS)))
            inputs.extend(b''.join(bytes(pages[p]) for p in PAGES))
        (output/'reference.json').write_text(json.dumps(expected))
        (output/'input.bin').write_bytes(inputs)
        row['reference_sha256'] = digest(output/'reference.json')
        row['visited_instruction_rvas'] = [hex(a-BASE) for a in sorted(visited)]
        (output/'transport.c').write_text(assemble((output/'lift/lifted.c').read_text(),rva))
        for isa in ('host','arm64'):
            stage = isa+'-compile'
            binary = output/isa
            command(stage,['zig-cc',* ([] if isa == 'host' else ['-target','aarch64-linux-musl','-static']),
                '-D_POSIX_C_SOURCE=200809L','-std=c11','-O0','-Werror=implicit-function-declaration',
                '-I'+str(ROOT/'work/interop-legacy-002/pcrecomp/runtime/recomp32'),output/'transport.c','-lm','-o',binary])
            header = binary.read_bytes()[:20]
            require(header[:6] == b'\x7fELF\x02\x01' and int.from_bytes(header[18:20],'little') == (62 if isa == 'host' else 183))
            stage = isa+'-execute'
            command(stage,[binary] if isa == 'host' else [ROOT/'scripts/campaign/arm64-run.sh',binary],bytes(inputs))
            row['runs'][isa] = compare((output/(stage+'.stdout')).read_text(),expected)
            if isa == 'arm64':
                row['arm64_executed'] = True
        require(digest(image) == IMAGE_SHA)
        row['success'] = True
    except Exception as exc:
        row.update(failed_stage=stage,error_type=type(exc).__name__)
        raise
    finally:
        (output/'result.json').write_text(json.dumps(row,indent=2)+'\n')
    return row


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--rva',type=lambda s:int(s,16),choices=RVAS,required=True)
    p.add_argument('--index',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--lift-only',action='store_true')
    a = p.parse_args()
    try:
        (lift if a.lift_only else run)(a.output,a.rva,a.index)
    except Exception:
        p.exit(1,'Cache skip experiment failed; inspect private outputs.\n')
    print('Fresh lift OK' if a.lift_only else 'Skip path only: host and AArch64 64/64; M1 incomplete, not Android')
    return 0


if __name__ == '__main__':
    sys.exit(main())
