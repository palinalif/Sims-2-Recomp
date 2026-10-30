#!/usr/bin/env python3
"""Bounded pinned-upstream lift -> host C execution -> Unicorn comparison.

Synthetic by default. An explicitly extracted local leaf may be supplied; this
does not discover functions, resolve imports or initialize the game.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
from types import SimpleNamespace
from fetch_pcrecomp import ROOT, verify
from leaf_contract import validate
from probe_function import verify_record


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pcrecomp',type=Path,required=True)
    parser.add_argument('--probe',type=Path,help='Local probe JSON from probe_function.py')
    parser.add_argument('--exe',type=Path,help='Required with --probe to revalidate original hash and bytes')
    parser.add_argument('--ndk',type=Path,help='Also cross-compile generated C to an ARM64 Android shared library (not executed)')
    parser.add_argument('--out',type=Path,default=ROOT/'work/probe')
    args=parser.parse_args();source=args.pcrecomp.resolve();verify(source)
    out=args.out.resolve()
    if not out.is_relative_to((ROOT/'work').resolve()):parser.error('--out must be within ignored work/')
    out.mkdir(parents=True,exist_ok=True)
    # Import the exact reviewed upstream harness, without copying it into our code.
    sys.path.insert(0,str(source))
    module_path=source/'tools/lift/difftest.py'
    spec=importlib.util.spec_from_file_location('pcrecomp_difftest',module_path)
    harness=importlib.util.module_from_spec(spec);sys.modules[spec.name]=harness;spec.loader.exec_module(harness)
    code=bytes.fromhex('8b442404034424088944240cc3') # uint32 sum(a,b); store to stack scratch; ret
    proprietary=False;origin='authored synthetic leaf'
    if args.probe:
        if not args.exe:parser.error('--probe requires --exe for hash/range revalidation')
        if args.probe.stat().st_size>32768:parser.error('Probe JSON over budget')
        info=json.loads(args.probe.read_text());code=verify_record(args.exe,info)
        proprietary=True;origin=f"user-selected leaf from sha256:{info['sha256']} rva:{info['rva']:#x}"
    try:instructions=validate(code)
    except ValueError as e:parser.error(str(e))
    # Fixed arithmetic boundary inputs include wraparound. Other original leaf
    # signatures/memory must be manually reviewed and supplied in a later fixture.
    pairs=[(0,0),(1,2),(0xffffffff,1),(0x7fffffff,1),(0x80000000,0xffffffff)]
    cases=[]
    for i,(a,b) in enumerate(pairs):
        # ret targets exactly end-of-code so Unicorn stops outside the function.
        seed=struct.pack('<IIII',harness.BASE+len(code),a,b,0)
        cases.append(harness.Case(f'leaf.{i}',code,mem={harness.STACK:seed}))
    functions=[]
    for i,case in enumerate(cases):
        block=SimpleNamespace(start=harness.BASE,instructions=instructions)
        func=SimpleNamespace(name=f'leaf_{i}',address=harness.BASE,blocks={harness.BASE:block})
        functions.append(harness.Lifter(precise_carry=True).lift_function(func))
    # build_c provides the upstream state/memory output protocol. Replace just its
    # case functions with full lift_function output and capture flags AFTER ret.
    generated=harness.build_c(cases)
    start=generated.index('static void case_0(')
    end=generated.index('int main(void)')
    wrappers=[]
    for i in range(len(cases)):
        wrappers.append(f'''static void case_{i}(void) {{
    g_flag_k=FK_NONE; g_flag_a=g_flag_b=g_flag_cf=0;
    leaf_{i}();
    out_eflags=recomp_eflags(g_flag_k,g_flag_a,g_flag_b,g_flag_cf,1);
}}''')
    generated=generated[:start]+'\n'.join(functions+wrappers)+'\n'+generated[end:]
    # Fail closed if upstream reports an unsupported operation in emitted output.
    if 'UNIMPLEMENTED' in generated or 'unhandled' in generated.lower():parser.error('Upstream could not fully lift probe')
    c=out/'leaf.c';c.write_text(generated)
    cc=os.environ.get('CC','cc');binary=out/'leaf-host'
    command=[cc,'-std=c11','-O0','-g','-I',str(source/'runtime/recomp32'),str(c),'-lm','-o',str(binary)]
    subprocess.run(command,check=True,timeout=60)
    run=subprocess.run([str(binary)],check=True,capture_output=True,text=True,timeout=10)
    got=harness.parse_output(run.stdout)
    if len(got)!=len(cases):raise SystemExit('Incomplete host result stream')
    differences=[]
    for case,result in zip(cases,got):
        real=harness.run_unicorn(case)
        fields=harness.diff(case,result,real)
        if fields: differences.append({'case':case.name,'fields':fields})
    report={'upstream_revision':json.loads((ROOT/'config/dependencies.lock.json').read_text())['pcrecomp']['revision'],
        'origin':origin,'proprietary':proprietary,'cases':len(cases),'differences':differences,
        'host_compile_command':command,'reference':'Unicorn x86-32; defined integer flags, GPRs, stack/memory changes',
        'arm64_compiled':False,'arm64_executed':False,'game_initialized':False}
    if args.ndk:
        compiler=args.ndk/'toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android26-clang'
        android_command=[str(compiler),'-std=c11','-O0','-fPIC','-shared','-I',str(source/'runtime/recomp32'),str(c),'-lm',
                         '-Wl,-z,max-page-size=16384','-o',str(out/'leaf-arm64.so')]
        subprocess.run(android_command,check=True,timeout=60);report['arm64_compiled']=True;report['arm64_compile_command']=android_command
    (out/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))
    return 1 if differences else 0


if __name__=='__main__':raise SystemExit(main())
