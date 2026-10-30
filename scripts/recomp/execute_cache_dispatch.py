#!/usr/bin/env python3
"""Authorized cache closure dispatch differential, NOT game/runtime integration.

Fresh unchanged pcrecomp bodies; bounded original x86 reference; image-backed
read-only tables. All derived artifacts stay in ignored work/recomp-bench/.
"""
import argparse
import json
from pathlib import Path
import random
import struct
import subprocess
import sys
import time
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))
from execute_cache_skip import private_output, require, RVAS, CLOSURE
from execute_resource_leaf import REGS, PAGES as DATA_PAGES, RETURN
from measure_leaf import ROOT, IMAGE_SHA, REVISION, digest
from measure_startup import BASE, decode_flow, supported
from measure_local_switch import decode_switch

IMAGE_PAGES = (BASE+0x9000, BASE+0xe17000)
PAGES = (*DATA_PAGES, *IMAGE_PAGES)
TEMPLATE = Path(__file__).with_name('cache_dispatch_transport.c.in')


def compare(text, expected):
    def unique(pairs):
        out = {}
        for k,v in pairs:
            require(k not in out)
            out[k] = v
        return out
    rows = [json.loads(line, object_pairs_hook=unique) for line in text.splitlines()]
    require(len(rows) == len(expected) == 64)
    for n,(row,wanted) in enumerate(zip(rows,expected)):
        require(type(row) is dict and set(row) == {'case','regs','pages'})
        require(type(row['case']) is int and row['case'] == n)
        require(type(row['regs']) is list and len(row['regs']) == 8 and
                all(type(v) is int and 0 <= v <= 0xffffffff for v in row['regs']))
        require(type(row['pages']) is str and len(row['pages']) == len(PAGES)*8192)
        require(row == wanted)
    return dict(cases=64, matched=64)


def thunk_function(code, wrapper):
    """Two-instruction authorized tail hop only; no external target inference."""
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_ESP
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    ins = list(md.disasm(code, BASE+0xfcf0))
    require(len(code) <= 32 and len(ins) == 2 and sum(i.size for i in ins) == len(code))
    a,b = ins
    require(a.mnemonic == 'mov' and len(a.operands) == 2)
    dst,src = a.operands
    require(dst.type == X86_OP_MEM and dst.size == 4 and not dst.mem.segment and
            dst.mem.base == X86_REG_ESP and not dst.mem.index and dst.mem.disp == 4 and
            src.type == X86_OP_IMM and (src.imm & 0xffffffff) == BASE+0xe17ab0)
    require(b.mnemonic == 'jmp' and len(b.operands) == 1 and
            b.operands[0].type == X86_OP_IMM and (b.operands[0].imm & 0xffffffff) == BASE+0x9550)
    return SimpleNamespace(name='startup_00FCF0',address=a.address,
        blocks={a.address:SimpleNamespace(start=a.address,instructions=[wrapper(i) for i in ins])}), {i.address:i for i in ins}


def reference(nodes, code_pages, entry, regs, pages, budget=4096, *, image_pages=IMAGE_PAGES,
              heap_service=None, checked_repeat_copy=False, checked_integer_multiply=False,
              stop_before_call=None, checked_calloc_arithmetic=False, extra_data_pages=(),
              stop_before_pc=None, call_trace=None):
    """Hook-free original x86 single-step; no implicit endpoint responses.

    Optional explicit heap_service is a portable allocation MODEL, not original
    Windows execution. Callers using it must label that boundary in their receipt.
    Default callers still reject every address outside the original node set.
    checked_repeat_copy opts into bounded forward REP MOVS only, validating the
    entire source/destination span (including byte copies) before execution.
    Direction-flag backward copies, oversized spans and immutable writes reject.
    checked_integer_multiply admits only three-operand 32-bit register/immediate
    IMUL (no implicit EDX:EAX or memory operand); default remains fail-closed.
    checked_calloc_arithmetic separately admits DIV reg32 and IMUL reg32,mem32;
    memory reads retain the normal span/segment checks. Divide traps propagate.
    Both options compose as the union of these exact forms, not as simultaneous
    constraints on every IMUL. Neither option alone admits the other's form.

    stop_before_pc optionally captures BEFORE one exact original instruction
    (including a caller continuation after RET), with stop_pc metadata. It is
    mutually exclusive with stop_before_call; neither is a whole-function result.
    extra_data_pages explicitly admits at most four additional writable pages;
    code/image/return aliases and holes in repeated-copy spans remain rejected.

    stop_before_call optionally names one exact (site, direct-target) pair.
    It captures state BEFORE that CALL, without a return push or callee response;
    the result then has boundary metadata and is NOT a completed function match.

    call_trace optionally receives (site, actual target PC, return PC) after each
    executed CALL. It must be an empty plain list. Observation only: no hook,
    response, return override or additional instruction admission is supplied.

    Validate PC and explicit/implicit accesses before each instruction. Each case
    has a fresh CPU and finite budget. Code/image pages remain immutable. Hooks
    are deliberately avoided: this host faults on Unicorn Python callbacks.
    Complete final GPRs and all six pages are captured; flags are not.
    """
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32
    from capstone import CS_AC_READ, CS_AC_WRITE, CS_GRP_CALL
    from capstone.x86 import X86_OP_MEM
    import unicorn.x86_const as x
    require(len(image_pages) in (2, 3) and
            len(set((*DATA_PAGES, *image_pages))) == 4+len(image_pages) and RETURN not in image_pages)
    require(all(type(p) is int and 0 <= p <= 0xfffff000 and p % 4096 == 0 for p in image_pages))
    # Explicit bounded fixture extension; defaults preserve the historical domain.
    # Never mutate DATA_PAGES or allow writable code/image/return aliases.
    require(type(extra_data_pages) is tuple and len(extra_data_pages) <= 4)
    require(all(type(p) is int and 0 <= p <= 0xfffff000 and p % 4096 == 0
                for p in extra_data_pages))
    writable_pages = (*DATA_PAGES, *extra_data_pages)
    require(len(set((*writable_pages, *image_pages, RETURN))) ==
            len(writable_pages)+len(image_pages)+1)
    page_bases = (*writable_pages, *image_pages)
    require(set(pages) == set(page_bases) and set(regs) == set(REGS))
    require(all(len(p) == 4096 for p in pages.values()))
    require(0 < budget <= 4096 and entry in nodes)
    require(call_trace is None or (type(call_trace) is list and not call_trace))
    require(not set(code_pages) & (set(writable_pages) | {RETURN}))
    u = Uc(UC_ARCH_X86, UC_MODE_32)
    mapped = dict(code_pages)
    for p,data in pages.items():
        if p in mapped:
            require(bytes(data) == bytes(mapped[p]))
        mapped[p] = data
    mapped[RETURN] = bytes(4096)
    for p,data in mapped.items():
        require(p % 4096 == 0 and len(data) == 4096)
        u.mem_map(p,4096)
        u.mem_write(p,bytes(data))
    ids = {r:getattr(x,'UC_X86_REG_'+r.upper()) for r in REGS}
    for r in REGS:
        require(type(regs[r]) is int and 0 <= regs[r] <= 0xffffffff)
        u.reg_write(ids[r],regs[r])
    u.reg_write(x.UC_X86_REG_EFLAGS,0x202)
    require(stop_before_call is None or
            (type(stop_before_call) is tuple and len(stop_before_call) == 2 and
             all(type(a) is int and 0 <= a <= 0xffffffff for a in stop_before_call) and
             stop_before_call[0] in nodes))
    require(stop_before_pc is None or
            (stop_before_call is None and type(stop_before_pc) is int and stop_before_pc in nodes))
    boundary = None
    stopped_pc = None
    visited, pc = set(), entry
    def check(a,size,write=False):
        allowed = writable_pages if write else page_bases
        require(size in (1,4) and a % size == 0 and
                any(p <= a <= p+4096-size for p in allowed))
    for _ in range(budget):
        if heap_service is not None and pc == heap_service.target:
            # Only a real, validated original CALL may enter the service. Never
            # permit an entry-point/tail jump or an unrecognized import target.
            require(visited and previous.group(CS_GRP_CALL))
            heap_service.invoke(u, ids, previous.address + previous.size)
            pc = u.reg_read(x.UC_X86_REG_EIP)
            require(pc == previous.address + previous.size and pc in nodes)
        require(pc in nodes)
        i = nodes[pc]
        require(bytes(u.mem_read(pc, i.size)) == bytes(i.bytes))
        if stop_before_pc is not None and pc == stop_before_pc:
            stopped_pc = pc
            break
        if stop_before_call is not None and pc == stop_before_call[0]:
            from capstone.x86 import X86_OP_IMM
            require(i.group(CS_GRP_CALL) and len(i.operands) == 1 and
                    i.operands[0].type == X86_OP_IMM and
                    (i.operands[0].imm & 0xffffffff) == stop_before_call[1])
            boundary = dict(site=pc, target=stop_before_call[1])
            break
        repeated = checked_repeat_copy and i.mnemonic in ('rep movsd','rep movsb')
        if repeated:
            # Validate the entire forward-copy span BEFORE Unicorn executes it.
            # Zero count performs no access, even with unmapped ESI/EDI.
            # The span calculation below models ECX/ESI/EDI in flat 32-bit
            # memory only, never segment overrides or 16-bit address registers.
            require(list(i.prefix) == [0xf3,0,0,0] and i.addr_size == 4)
            require(not u.reg_read(x.UC_X86_REG_EFLAGS) & 0x400)
            count = u.reg_read(ids['ecx'])
            width = 4 if i.mnemonic == 'rep movsd' else 1
            require(count <= 4096 // width)
            span = count * width
            for name, allowed in (('esi',page_bases),('edi',writable_pages)):
                address = u.reg_read(ids[name])
                # A contiguous span may cross only explicitly mapped pages.
                require(not span or (address+span <= 0x100000000 and
                    all(p in allowed for p in range(address & ~4095,
                        ((address+span-1) & ~4095)+4096, 4096))))
        multiply = (checked_integer_multiply and i.mnemonic == 'imul' and
                    len(i.operands) == 3)
        if multiply:
            from capstone.x86 import X86_OP_REG, X86_OP_IMM
            require(len(i.operands) == 3 and
                    all(op.type == X86_OP_REG and op.size == 4 and i.reg_name(op.reg) in ids
                        for op in i.operands[:2]) and i.operands[2].type == X86_OP_IMM)
        calloc_arithmetic = (checked_calloc_arithmetic and
            (i.mnemonic == 'div' or (i.mnemonic == 'imul' and len(i.operands) == 2)))
        if calloc_arithmetic:
            from capstone.x86 import X86_OP_REG
            require(not any(i.prefix) and i.addr_size == 4)
            require(i.operands[0].type == X86_OP_REG and i.operands[0].size == 4 and
                    i.reg_name(i.operands[0].reg) in ids)
            if i.mnemonic == 'div':
                require(len(i.operands) == 1)
            else:
                require(len(i.operands) == 2 and i.operands[1].type == X86_OP_MEM and
                        i.operands[1].size == 4)
        require(repeated or multiply or calloc_arithmetic or i.mnemonic in ('nop','mov','movzx','movsx','lea','push','pop','ret','call',
            'cmp','test','add','sub','inc','dec','and','or','xor','shl','shr','sar',
            'jmp','je','jne','ja','jae','jb','jbe','jg','jge','jl','jle','js','jns','jo','jno','jp','jnp','setne'))
        for op in i.operands:
            if repeated or op.type != X86_OP_MEM or i.mnemonic == 'lea':
                continue
            m = op.mem
            require(not m.segment and op.access & (CS_AC_READ | CS_AC_WRITE))
            a = m.disp
            for reg,scale in ((m.base,1),(m.index,m.scale)):
                if reg:
                    name = i.reg_name(reg)
                    require(name in ids)
                    a += u.reg_read(ids[name])*scale
            check(a & 0xffffffff,op.size,bool(op.access & CS_AC_WRITE))
        sp = u.reg_read(ids['esp'])
        if i.mnemonic in ('push','pop','ret') or i.group(CS_GRP_CALL):
            pushing = i.mnemonic == 'push' or i.group(CS_GRP_CALL)
            check((sp-4 if pushing else sp) & 0xffffffff,4,pushing)
        visited.add(pc)
        previous = i
        u.emu_start(pc,0,count=1)
        pc = u.reg_read(x.UC_X86_REG_EIP)
        if call_trace is not None and i.group(CS_GRP_CALL):
            call_trace.append((i.address, pc, i.address+i.size))
        if pc == RETURN:
            require(i.mnemonic == 'ret')
            break
    require(stopped_pc is not None if stop_before_pc is not None else
            (pc == RETURN if stop_before_call is None else boundary is not None))
    for p in set(code_pages) | set(image_pages) | {RETURN}:
        require(bytes(u.mem_read(p,4096)) == bytes(mapped[p]))
    result = dict(regs=[u.reg_read(ids[r]) for r in REGS],
        pages=b''.join(bytes(u.mem_read(p,4096)) for p in page_bases).hex())
    if boundary is not None:
        result['boundary'] = boundary
    if stopped_pc is not None:
        result['stop_pc'] = stopped_pc
    return result, visited


def entry_state(n,rva,rng,image_pages,*,complete_units=False):
    """Synthetic range ownership; inline service fields equal verified producer writes.

    No encoding semantics invented: byte corpus is test input, image supplies
    classification behavior. Nonzero ranges cover empty and 1..16-byte windows.
    """
    require(0 <= n < 64 and rva in RVAS and set(image_pages) == set(IMAGE_PAGES))
    regs = {r:rng.getrandbits(32) for r in REGS}
    regs['esp'] = DATA_PAGES[0]+(0x800 if n%2 else 0xc00)
    pages = {p:bytearray(rng.randbytes(4096)) for p in DATA_PAGES}
    pages.update({p:bytearray(data) for p,data in image_pages.items()})
    h, text = DATA_PAGES[1]+128, DATA_PAGES[2]+128
    struct.pack_into('<II',pages[DATA_PAGES[0]],regs['esp']-DATA_PAGES[0],RETURN,h)
    def put(off,value):
        struct.pack_into('<I',pages[DATA_PAGES[1]],128+off,value)
    # Inline service, function slots, class byte, and back pointer from producer.
    put(0x78,h+0x7c)
    put(0x7c,BASE+0x10970)
    put(0x80,BASE+0x109a0)
    put(0xb0,BASE+0xfcf0)
    pages[DATA_PAGES[1]][128+0x7c+0x49] = 6
    put(0xc8,h+0x78)
    length = 0 if n < 8 else 1+(n%16)
    corpus = (b'A',b'\x00',b'\x7f',b'\x80',b'\xc2\xa2',b'\xe2\x82\xac',b'\xf0\x9f\x98\x80',bytes(range(256)))
    sample = corpus[n%len(corpus)]
    if complete_units and n >= 8:
        # Separate named input domain, not a silent retry/drop of raw failures.
        # No encoding interpretation: repeat whole test samples up to 16 bytes.
        sample = sample[:16]
        length = max(1,length//len(sample))*len(sample)
    pages[DATA_PAGES[2]][128:128+length] = (sample*16)[:length]
    put(0x100,0 if n < 4 else text+length)
    put(0x108,text)
    for off in (0x1c8,0x1cc):
        put(off,(0,1,0x7fffffff,0xffffffff)[n%4])
    return regs,pages


def assemble(bodies,rva,return_va):
    require(rva in RVAS and set(bodies) == {rva,0xfcf0,0x9550})
    require(all(type(b) is str and b.strip() and supported(b) for b in bodies.values()))
    text = TEMPLATE.read_text()
    for key,value in {'@BODY@':'\n'.join(bodies[a] for a in (0x9550,0xfcf0,rva)),
                      '@ENTRY@':f'startup_{rva:06X}', '@RETURN@':f'0x{return_va:08X}u'}.items():
        require(text.count(key) == 1)
        text = text.replace(key,value)
    return text


def run(output,rva,index,switch_index,thunk_index,*,complete_units=False):
    output = private_output(output)
    row = dict(schema='ts2-cache-dispatch-native/1',success=False,rva=hex(rva),
        caller_closure=[hex(r) for r in CLOSURE],survey_expanded=False,
        invocation=[sys.executable,*sys.argv],harness_sha256=digest(Path(__file__)),
        template_sha256=digest(TEMPLATE),image_sha256=IMAGE_SHA,pcrecomp_revision=REVISION,
        commands=[],runs={},arm64_executed=False,android_executed=False,m1_complete=False,
        range_corpus='whole-samples' if complete_units else 'raw-truncated-samples',
        limits=['synthetic owned ranges/receiver; producer fields authored from verified writes, no behavior responses',
                'eight GPRs and six complete pages; no flags/FP/native PC/transient-write comparison',
                'bounded fixture, NOT GuestMemory runtime integration, whole caller, ownership or game execution'])
    def command(name,argv,data=None):
        rec = dict(name=name,argv=[str(a) for a in argv])
        row['commands'].append(rec)
        t = time.monotonic()
        with (output/(name+'.stdout')).open('xb') as out,(output/(name+'.stderr')).open('xb') as err:
            p = subprocess.run(rec['argv'],input=data,stdout=out,stderr=err,cwd=ROOT,timeout=120)
        rec.update(exit_code=p.returncode,seconds=time.monotonic()-t)
        require(p.returncode == 0)
    stage = 'fresh-lifts'
    try:
        require(rva in RVAS)
        command('accessor-lift',[sys.executable,Path(__file__).with_name('execute_cache_skip.py'),
            '--lift-only','--rva',hex(rva),'--index',index,'--output',output/'accessor'])
        command('switch-lift',[sys.executable,Path(__file__).with_name('measure_local_switch.py'),
            '--index',switch_index,'--output',output/'switch'])
        image = ROOT/'work/interop-legacy-002/analysis-image.bin'
        require(digest(image) == IMAGE_SHA)
        import pefile
        pe = pefile.PE(data=image.read_bytes())
        require(pe.OPTIONAL_HEADER.ImageBase == BASE and pe.FILE_HEADER.Machine == 0x14c)
        upstream = ROOT/'work/interop-legacy-002/pcrecomp'
        # Child lift verified all pinned upstream files; check again in this process.
        pins = json.loads((output/'accessor/lift.json').read_text())['upstream_files']
        require(all(digest(upstream/n) == sha for n,sha in pins.items()))
        row['upstream_files'] = pins
        sys.path.insert(0,str(upstream))
        from tools.lift.lift32 import Lifter
        from tools.lift.generate import LinearInstruction
        require(Path(sys.modules[Lifter.__module__].__file__).resolve() == (upstream/'tools/lift/lift32.py').resolve())
        # Thunk span is derived by decoding exactly two instructions, not guessed ret extent.
        from capstone import Cs, CS_ARCH_X86, CS_MODE_32
        raw = pe.get_data(0xfcf0,32)
        span = sum(i.size for i in Cs(CS_ARCH_X86,CS_MODE_32).disasm(raw,BASE+0xfcf0,count=2))
        thunk,tnodes = thunk_function(raw[:span],LinearInstruction)
        env = json.loads(thunk_index.read_text())
        p,q = env['provenance'],env['result']
        require(env['schema'] == 'sims2-ghidra-query-envelope/1' and p['sourceImageSha256'] == IMAGE_SHA and
                p['mode'] == 'readOnly' and p['analysisPerformed'] is False and p['headlessExitCode'] == 0 and
                p['outputParseError'] is None and int(q['query']['rva'],16) == 0xfcf0 and
                int(q['program']['imageBaseVa'],16) == BASE)
        require(all(BASE+int(i['rva'],16) in tnodes for i in q['function']['disassembly']['items']))
        row['thunk_index'] = dict(sha256=digest(thunk_index),resolution=q['function']['resolution'],
            log_signals=env['queryLogSignals'],truncation=q['truncation'])
        t = time.monotonic()
        body = Lifter(precise_carry=True,lifted={thunk.address,BASE+0x9550}).lift_function(thunk)
        require(supported(body))
        (output/'thunk.c').write_text(body)
        row['thunk_lift'] = dict(seconds=time.monotonic()-t,sha256=digest(output/'thunk.c'),
            api='Lifter(precise_carry=True,lifted={thunk_va,leaf_va}).lift_function(two_instruction_thunk)')
        arow = json.loads((output/'accessor/lift.json').read_text())
        srow = json.loads((output/'switch/result.json').read_text())
        require(arow['lifted'] and srow['success'])
        require(digest(output/'accessor/lifted.c') == arow['lifted_sha256'] and
                digest(output/'switch/lifted.c') == srow['lifted_sha256'])
        _,anodes,_,_ = decode_flow(pe.get_data(rva,64),BASE+rva,lambda i:i)
        targets = struct.unpack('<6I',pe.get_data(0x95c8,24))
        _,snodes,_ = decode_switch(pe.get_data(0x9550,0x78),BASE+0x9550,BASE+0x95c8,targets,lambda i:i)
        from capstone import CS_GRP_CALL
        calls = [i for i in anodes.values() if i.group(CS_GRP_CALL)]
        require(len(calls) == 1)
        ret = calls[0].address+calls[0].size
        nodes = dict(anodes)
        nodes.update(tnodes)
        nodes.update(snodes)
        code_pages = {p:pe.get_data(p-BASE,4096) for p in (BASE+0x1000,BASE+0xf000,BASE+0x9000)}
        image_pages = {p:pe.get_data(p-BASE,4096) for p in IMAGE_PAGES}
        row['image_page_sha256'] = {hex(p):__import__('hashlib').sha256(data).hexdigest() for p,data in image_pages.items()}
        stage = 'reference'
        rng = random.Random(118187+rva)
        inputs,expected,visited = bytearray(),[],set()
        for n in range(64):
            row['current_reference_case'] = n
            regs,pages = entry_state(n,rva,rng,image_pages,complete_units=complete_units)
            state,seen = reference(nodes,code_pages,BASE+rva,regs,pages)
            require(state['regs'][-1] == regs['esp']+4)
            visited.update(seen)
            expected.append(dict(case=n,**state))
            inputs.extend(struct.pack('<8I',*(regs[r] for r in REGS)))
            inputs.extend(b''.join(bytes(pages[p]) for p in PAGES))
        row.pop('current_reference_case')
        require(BASE+0xfcf0 in visited and BASE+0x9550 in visited)
        (output/'reference.json').write_text(json.dumps(expected))
        (output/'input.bin').write_bytes(inputs)
        row['reference_sha256'] = digest(output/'reference.json')
        row['coverage'] = dict(visited=len(visited),total=len(nodes),
            visited_switch_arms=len(set(targets)&visited),total_switch_arms=len(set(targets)),
            uncovered_rvas=[hex(a-BASE) for a in sorted(set(nodes)-visited)])
        bodies = {rva:(output/'accessor/lifted.c').read_text(),0x9550:(output/'switch/lifted.c').read_text(),0xfcf0:body}
        (output/'transport.c').write_text(assemble(bodies,rva,ret))
        row['transport_sha256'] = digest(output/'transport.c')
        for isa in ('host','arm64'):
            stage = isa+'-compile'
            binary = output/isa
            command(stage,['zig-cc',* ([] if isa == 'host' else ['-target','aarch64-linux-musl','-static']),
                '-D_POSIX_C_SOURCE=200809L','-std=c11','-O0','-Werror=implicit-function-declaration',
                '-I'+str(upstream/'runtime/recomp32'),output/'transport.c','-lm','-o',binary])
            h = binary.read_bytes()[:20]
            require(h[:6] == b'\x7fELF\x02\x01' and int.from_bytes(h[18:20],'little') == (62 if isa == 'host' else 183))
            stage = isa+'-execute'
            command(stage,[binary] if isa == 'host' else [ROOT/'scripts/campaign/arm64-run.sh',binary],bytes(inputs))
            row['runs'][isa] = compare((output/(stage+'.stdout')).read_text(),expected)
            if isa == 'arm64':
                row['arm64_executed'] = True
        require(digest(image) == IMAGE_SHA)
        row['success'] = True
    except Exception as exc:
        import traceback
        row.update(failed_stage=stage,error_type=type(exc).__name__,
            harness_failure_lines=[f.lineno for f in traceback.extract_tb(exc.__traceback__)
                                   if Path(f.filename).resolve() == Path(__file__).resolve()])
        raise
    finally:
        (output/'result.json').write_text(json.dumps(row,indent=2)+'\n')
    return row


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--rva',type=lambda s:int(s,16),choices=RVAS,required=True)
    for name in ('index','switch-index','thunk-index','output'):
        p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--whole-samples',action='store_true',
        help='Explicit separate corpus: repeat complete byte samples; raw failures are not silently retried')
    a = p.parse_args()
    try:
        run(a.output,a.rva,a.index,a.switch_index,a.thunk_index,complete_units=a.whole_samples)
    except Exception:
        p.exit(1,'Cache dispatch experiment failed; inspect private outputs.\n')
    print('64/64 host and AArch64 dispatch comparisons; NOT Android or caller integration')


if __name__ == '__main__':
    main()
