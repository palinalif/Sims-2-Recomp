#!/usr/bin/env python3
"""Reuse pinned startup pair/optional entry on persistent production guest memory.

No new translation, PE launch or Windows service. Private outputs only.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from measure_leaf import ROOT, IMAGE_SHA, digest, verify
from reference_startup import cases, oracle, entry_oracle, verify_state, require, run as reference_run
from execute_startup import TEMPLATE, input_bytes
from call_returns import derive, seam

BODY_SHA = {0x8258A9: '45ccd587fb7a519b86ef9e3372afb59ad58664aa02c48270ec71c39b8457410f',
            0x82585C: '96b62d575828bf933088a6855f2bf70acd0959222322f1ee476b5376099105ed'}
ENTRY_SHA = '11e9c18c2206bdc05500b0d88822bbecc15b1dfa5f081347ca1363cefc95d06e'
FIXTURE = ROOT/'work/recomp-bench/run5-012-pair'


def assemble(bodies, metadata, *, entry=False):
    require(type(entry) is bool)
    pins = dict(BODY_SHA)
    if entry: pins[0x8248A3]=ENTRY_SHA
    require(set(bodies)==set(pins))
    for rva, body in bodies.items():
        require(hashlib.sha256(body.encode()).hexdigest()==pins[rva])
    text = TEMPLATE.read_text()
    prefix, _ = text.split('int main(void) {', 1)
    start = prefix.index('static uint32_t *word(')
    end = prefix.index('static void endpoint(', start)
    prefix = prefix[:start] + '''#undef MEM32
#define MEM32(a) Ts2StartupWord{(uint32_t)(a)}
''' + prefix[end:]
    old = 'static void reject(const char *reason) { failure=reason; longjmp(escape,1); }'
    require(prefix.count(old)==1)
    prefix = prefix.replace(old, 'static void reject(const char *reason) { throw std::runtime_error(reason); }')
    prefix = prefix.replace('\n@BODIES@\n', '\n'+seam(metadata)+'\n'.join(bodies.values())+'''
static void load(uint32_t *s) {
    g_eax=s[0];g_ecx=s[1];g_edx=s[2];g_ebx=s[3];g_esp=s[4];g_ebp=s[5];g_esi=s[6];g_edi=s[7];
}
static void save(uint32_t *s) {
    s[0]=g_eax;s[1]=g_ecx;s[2]=g_edx;s[3]=g_ebx;s[4]=g_esp;s[5]=g_ebp;s[6]=g_esi;s[7]=g_edi;
}
static void outer(uint32_t *s) { load(s); startup_8258A9(); save(s); }
static void inner(uint32_t *s) { load(s); startup_82585C(); save(s); }
static void nested_dispatch(void) {
    uint32_t s[9]={}; save(s);
    ts2_startup_invoke(0xA082585Cu,s); load(s);
}
''')
    if entry:
        start=prefix.index('static void tail_stop(void) {')
        end=prefix.index('\n}',start)+2
        prefix=prefix[:start]+'''static void tail_stop(void) {
    if(g_cur_func!=0xA08248A3u) reject("tail-boundary");
    uint32_t s[9]={g_eax,g_ecx,g_edx,g_ebx,g_esp,g_ebp,g_esi,g_edi,0x202};
    ts2_startup_stop(0xA0824727u,s);
}'''+prefix[end:]
        prefix=prefix.replace('recomp_func_t recomp_lookup(uint32_t va) {',
                              'static void initial_dispatch(void);\nrecomp_func_t recomp_lookup(uint32_t va) {')
        prefix+='''
static void entry_callback(uint32_t *s) { load(s); startup_8248A3(); reject("entry-returned"); }
static void initial_dispatch(void) {
    uint32_t s[9]={}; save(s);
    ts2_startup_invoke(0xA08258A9u,s); load(s);
}
'''
        old='case 0xA08258A9u: return startup_8258A9;'
        require(prefix.count(old)==1)
        prefix=prefix.replace(old,'case 0xA08258A9u: return initial_dispatch;')
    require(prefix.count('case 0xA082585Cu: return startup_82585C;')==1)
    prefix=prefix.replace('case 0xA082585Cu: return startup_82585C;',
                          'case 0xA082585Cu: return nested_dispatch;')
    text = '#include "startup_image.h"\n#include <stdexcept>\n'+prefix+'''
extern "C" int fixture_main(void) {
    ts2_startup_bind(outer,inner);
    for(unsigned n=0;n<320;n++) {
        if(fread(input,sizeof input,1,stdin)!=1) return 90;
        stack_base=input[0];
        if(stack_base!=0x70000000u && stack_base!=0x70010000u &&
           stack_base!=0x70020000u && stack_base!=0x70030000u) return 91;
        if(input[1]!=stack_base+0x800u) return 92;
        ts2_startup_begin(stack_base,input[1],input[2]);
        uint32_t s[9]={0x13579BDFu,0,0,input[9],input[1],input[12],input[10],input[11],0x202};
        g_flag_k=g_flag_a=g_flag_b=g_flag_cf=0;
        g_cur_func=g_icall_trace_idx=g_icall_count=event_count=0;
        memset(g_icall_trace,0,sizeof g_icall_trace); memset(g_icall_from,0,sizeof g_icall_from);
        ts2_startup_invoke(0xA08258A9u,s);
        for(unsigned j=0;j<1024;j++) stack_page[j]=ts2_startup_peek(stack_base+4*j);
        printf("{\\"case\\":%u,\\"state\\":{\\"eax\\":%u,\\"saved\\":[%u,%u,%u,%u],\\"sp\\":%u,\\"events\\":[",n,s[0],s[3],s[6],s[7],s[5],s[4]);
        for(unsigned k=0;k<event_count;k++) printf("%s%u",k?",":"",k);
        printf("],\\"stack\\":");page_hex(stack_page);
        printf(",\\"globals\\":[%u,%u]}}\\n",ts2_startup_peek(0xA104F540u),ts2_startup_peek(0xA104F580u));
        // Re-enter SAME memory without begin/setup. The normalized cookie
        // bypasses APIs and retains first-call stack/global bytes (oracle).
        const uint32_t cookie=ts2_startup_peek(0xA104F540u), comp=ts2_startup_peek(0xA104F580u);
        s[0]=0x13579BDFu; s[1]=s[2]=0; s[3]=input[9];s[4]=input[1];
        s[5]=input[12];s[6]=input[10];s[7]=input[11];s[8]=0x202;
        event_count=0; g_flag_k=g_flag_a=g_flag_b=g_flag_cf=0;
        ts2_startup_invoke(0xA08258A9u,s);
        if(event_count || s[0]!=0x13579BDFu || s[4]!=input[1]+4 || s[3]!=input[9] ||
           s[6]!=input[10] || s[7]!=input[11] || s[5]!=input[12] ||
           ts2_startup_peek(0xA104F540u)!=cookie || ts2_startup_peek(0xA104F580u)!=comp) return 95;
        for(unsigned j=0;j<1024;j++) if(stack_page[j]!=ts2_startup_peek(stack_base+4*j)) return 96;
    }
    return getchar()==EOF?0:94;
}
'''
    if entry:
        text='#define ENTRY_BOUNDARY 1\n'+text
        text=text.replace('ts2_startup_bind(outer,inner);',
                          'ts2_startup_bind(outer,inner); ts2_startup_bind_entry(entry_callback);')
        text=text.replace('ts2_startup_invoke(0xA08258A9u,s);\n        for(unsigned j=',
                          'const uint32_t stop=ts2_startup_observe_entry(s);\n        for(unsigned j=',1)
        old='ts2_startup_peek(0xA104F580u));'
        require(text.count(old)==1)
        # Add the observed stop PC to the strict primary-state record.
        text=text.replace('\\\"globals\\\":[%u,%u]}}', '\\\"globals\\\":[%u,%u],\\\"eip\\\":%u}}')
        text=text.replace(old,'ts2_startup_peek(0xA104F580u),stop);')
        # Reentry overwrites only the original call-return and saved-register
        # stack words with the same values: full first-call bytes must persist.
        text=text.replace('ts2_startup_invoke(0xA08258A9u,s);\n        if(event_count',
                          'if(ts2_startup_observe_entry(s)!=0xA0824727u) return 97;\n        if(event_count')
        text=text.replace('s[4]!=input[1]+4','s[4]!=input[1]')
    require(all(text.count(body)==1 for body in bodies.values()))
    return text


def compare_stream(text, reference, *, entry=False):
    require(type(entry) is bool)
    def unique(pairs):
        result={}
        for key,value in pairs:
            require(key not in result)
            result[key]=value
        return result
    def exact(actual, expected):
        require(type(actual) is type(expected))
        if isinstance(expected,dict):
            require(actual.keys()==expected.keys())
            for key in expected: exact(actual[key],expected[key])
        elif isinstance(expected,list):
            require(len(actual)==len(expected))
            for a,b in zip(actual,expected): exact(a,b)
        else: require(actual==expected)
    records=[json.loads(line,object_pairs_hook=unique) for line in text.splitlines()]
    require(len(records)==len(reference)==320)
    for n,(record,saved,case) in enumerate(zip(records,reference,cases())):
        require(saved['case']==case)
        expected=dict(saved['state'])
        for key in ('stack','data'): expected[key]=bytes.fromhex(expected[key])
        verify_state(expected,(entry_oracle if entry else oracle)(case))
        data=expected.pop('data')
        expected['globals']=[struct.unpack_from('<I',data,o)[0] for o in (0x540,0x580)]
        expected['stack']=expected['stack'].hex()
        exact(record,dict(case=n,state=expected))
    return 320


def run(output, *, entry=False):
    require(type(entry) is bool)
    output=output.resolve()
    require(output.is_relative_to((ROOT/'work/recomp-bench').resolve()))
    output.mkdir(mode=0o700,parents=True,exist_ok=False)
    row=dict(schema='ts2-startup-image/1',success=False,new_functions=0,
             android_executed=False,arm64_executed=False,runs={},commands=[],timings={},
             entry_boundary=entry,tail_target_executed=False,
             limits=['diagnostic-only persistent production GuestImage/GuestMemory/GuestDispatch',
                     'unchanged C lifts compiled as C++ with checked word conversion/assignment',
                     'four explicit read-only IAT binding overlays, not physical IAT writes or Windows',
                     'fixture setup writes exactly two globals plus external stack per case',
                     'full actual stack and two globals compared to x86/oracle; synthetic data page NOT copied',
                     'full mapped image except exactly two globals compared before/after all cases',
                     '320 same-memory native replays use normalized-cookie oracle, no second x86 run',
                     'optional entry uses typed nonlocal observation stop before unbound external tail',
                     'EAX/nonvolatile registers/SP/events only; no flags/volatile/FP/SIMD/SEH/concurrency',
                     'trusted callbacks, nontransactional writes; not a sandbox or Android startup'])
    def command(name,argv,stdin=None):
        rec=dict(name=name,argv=[str(a) for a in argv],exit_code=None)
        row['commands'].append(rec); start=time.monotonic()
        try:
            with (output/(name+'.stdout')).open('xb') as out,(output/(name+'.stderr')).open('xb') as err:
                p=subprocess.run(rec['argv'],cwd=ROOT,input=stdin,stdout=out,stderr=err,timeout=180)
            rec['exit_code']=p.returncode
            require(p.returncode==0)
        finally: rec['seconds']=time.monotonic()-start
    try:
        image=ROOT/'work/interop-legacy-002/analysis-image.bin'
        require(digest(image)==IMAGE_SHA)
        start=time.monotonic(); ref=reference_run(output/'reference',entry=entry)
        require(ref['success'] and ref['cases']==320 and ref['rejected_controls']==4)
        row['timings']['fresh_reference']=time.monotonic()-start
        reference=json.loads((output/'reference/reference.json').read_text())
        fixture=ROOT/'work/recomp-bench/run5-012-entry' if entry else FIXTURE
        pins=dict(BODY_SHA)
        if entry: pins[0x8248A3]=ENTRY_SHA
        bodies={rva:(fixture/format(rva,'X')/'lifted.c').read_text() for rva in pins}
        # Reuse the prior recorded translator provenance, never relift to inflate counts.
        prior=json.loads((fixture/'result.json').read_text())
        require(prior['success'])
        row['prior_lifts']={hex(r):prior['lifts'][hex(r)] for r in pins}
        metadata=derive(entry=entry)
        (output/'probe.cpp').write_text(assemble(bodies,metadata,entry=entry))
        row.update(image_sha256=IMAGE_SHA,body_sha256={hex(r):s for r,s in pins.items()},
                   reference_sha256=digest(output/'reference/reference.json'),
                   source_sha256=digest(output/'probe.cpp'),call_metadata=metadata)
        # The historical private tree contains an isolated recovery patch.
        # Do not relax reviewed-file verification: use the existing pristine pin.
        upstream_root=ROOT/'work/deps/pcrecomp/sp00nznet-pcrecomp-c0cbd3e'
        verify(upstream_root)
        upstream=upstream_root/'runtime/recomp32'
        row['adapter_sha256']=digest(ROOT/'scripts/recomp/startup_image.cpp')
        row['header_sha256']=digest(ROOT/'scripts/recomp/startup_image.h')
        row['runtime_header_sha256']=digest(upstream/'recomp_types.h')
        for isa in ('host','arm64'):
            command(isa+'-build',['cmake','--build',ROOT/'build'/isa,'-j4'])
            opts=[] if isa=='host' else ['-target','aarch64-linux-musl','-static']
            exe=output/isa
            command(isa+'-compile',['zig-cxx',*opts,'-std=c++20','-O0','-I'+str(upstream),
                    '-I'+str(ROOT/'scripts/recomp'),'-I'+str(ROOT/'native/include'),
                    output/'probe.cpp',ROOT/'scripts/recomp/startup_image.cpp',
                    ROOT/'build'/isa/'libts2_core.a','-lm','-o',exe])
            header=exe.read_bytes()[:20]
            require(header[:6]==b'\x7fELF\x02\x01' and int.from_bytes(header[18:20],'little')==(62 if isa=='host' else 183))
            argv=[exe,image] if isa=='host' else [ROOT/'scripts/campaign/arm64-run.sh',exe,image]
            command(isa+'-execute',argv,stdin=input_bytes())
            matched=compare_stream((output/(isa+'-execute.stdout')).read_text(),reference,entry=entry)
            row['runs'][isa]=dict(matched=matched,persistent_replays_oracle_checked=320,binary_sha256=digest(exe),
                                 stdout_sha256=digest(output/(isa+'-execute.stdout')))
        require(row['runs']['host']['stdout_sha256']==row['runs']['arm64']['stdout_sha256'])
        require(digest(image)==IMAGE_SHA)
        verify(upstream_root)
        require(all(digest(fixture/format(r,'X')/'lifted.c')==sha for r,sha in pins.items()))
        row.update(success=True,arm64_executed=True,unrelated_image_unchanged=True)
    finally:
        (output/'result.json').write_text(json.dumps(row,indent=2)+'\n')
    return row


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--entry-boundary',action='store_true',help='Stop BEFORE external tail, never execute it')
    args=p.parse_args()
    try: run(args.output,entry=args.entry_boundary)
    except Exception: p.exit(1,'Startup image comparison failed; inspect private report.\n')
    print('Persistent startup %s: x86/oracle320; host320; Linux/AArch64320; NOT Android' %
          ('entry boundary' if args.entry_boundary else 'pair'))
