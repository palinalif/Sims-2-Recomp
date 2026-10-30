"""Authored x86 only; never opens owner game fixtures."""
import importlib.util
from pathlib import Path
import unittest
import subprocess
import tempfile
import shutil
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

PATH = Path(__file__).resolve().parents[1]/'scripts/recomp/execute_startup.py'
spec = importlib.util.spec_from_file_location('call_return_transport', PATH)
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)
from call_returns import call_sites, seam


def decode(code):
    md = Cs(CS_ARCH_X86, CS_MODE_32); md.detail = True
    return {i.address:i for i in md.disasm(code, 0xA0001000)}


class CallReturnsTests(unittest.TestCase):
    def test_decoded_direct_and_absolute_indirect_returns(self):
        rows = call_sites(0xA0001000, decode(bytes.fromhex(
            'e810000000 ff15000000a1 c3')))
        self.assertEqual(rows, [dict(caller=0xA0001000,target=0xA0001015,
            slot=False,return_va=0xA0001005),dict(caller=0xA0001000,
            target=0xA1000000,slot=True,return_va=0xA000100B)])

    def test_repeated_direct_or_slot_reject_not_order_inference(self):
        for code in ('e810000000 e80b000000 c3',
                     'ff15000000a1 ff15000000a1 c3'):
            with self.assertRaisesRegex(ValueError,'Ambiguous'):
                call_sites(0xA0001000,decode(bytes.fromhex(code)))

    def test_register_and_based_calls_reject(self):
        for code in ('ffd0 c3','ff5004 c3','ff1485000000a1 c3'):
            with self.assertRaisesRegex(ValueError,'Unresolved'):
                call_sites(0xA0001000,decode(bytes.fromhex(code)))

    def test_compiled_seam_rejects_runtime_alias_and_missing_metadata(self):
        # Public authored transport, independent of pcrecomp/game inputs.
        rows=[dict(caller=0x1000,target=0x2000,slot=True,return_va=0x1006),
              dict(caller=0x1000,target=0x2004,slot=True,return_va=0x100C)]
        source=r'''
#include <stdint.h>
#include <setjmp.h>
#include <string.h>
static jmp_buf escape;
static uint32_t slots[2]={0x3000,0x3010},g_cur_func=0x1000,esp=0x8000,pushed;
static const char *reason;
static void reject(const char *r){reason=r;longjmp(escape,1);}
#define MEM32(a) slots[((a)-0x2000)/4]
typedef void (*recomp_func_t)(void);
static void endpoint(void){g_cur_func=0x3000;esp+=4;}
static recomp_func_t recomp_lookup(uint32_t va){return va==0x3000?endpoint:0;}
#define PUSH32(sp,v) ((sp)-=4,pushed=(v))
#define RECOMP_FLAGS_OUT() ((void)0)
#define RECOMP_REGS_OUT() ((void)0)
#define RECOMP_REGS_IN() ((void)0)
''' + seam(rows) + r'''
int main(void){
    if(setjmp(escape)) return 1;
    RECOMP_ICALL(0x3000);
    if(pushed!=0x1006 || esp!=0x8000 || g_cur_func!=0x1000) return 2;
    slots[1]=slots[0];
    if(!setjmp(escape)){RECOMP_ICALL(0x3000);return 3;}
    if(strcmp(reason,"call-metadata") || esp!=0x8000) return 4;
    slots[1]=0x3010;
    if(!setjmp(escape)){RECOMP_ICALL(0x3020);return 5;}
    if(strcmp(reason,"call-metadata") || esp!=0x8000) return 6;
    if(!setjmp(escape)){RECOMP_ICALL(0x3010);return 7;}
    if(strcmp(reason,"unresolved-target") || esp!=0x8000) return 8;
    g_cur_func=0x9999;
    if(!setjmp(escape)){RECOMP_ICALL(0x3000);return 9;}
    return strcmp(reason,"call-metadata")?10:0;
}
'''
        compiler=shutil.which('cc')
        self.assertIsNotNone(compiler,'Real C compiler required')
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); (root/'fixture.c').write_text(source)
            result=subprocess.run([compiler,'-std=c11','-O0',str(root/'fixture.c'),
                '-o',str(root/'fixture')],capture_output=True,timeout=60)
            self.assertEqual(result.returncode,0,result.stderr.decode())
            result=subprocess.run([root/'fixture'],capture_output=True,timeout=10)
            self.assertEqual(result.returncode,0)

    def test_nonreturning_tail_observer_preserves_caller_stack_and_rejects_wrong_owner(self):
        # Compile the actual public observer, not a replacement implementation.
        template = b.TEMPLATE.read_text()
        observer = template.split('static void tail_stop(void) {', 1)[1].split('\n@BODIES@', 1)[0]
        source = r'''
#include <stdint.h>
#include <setjmp.h>
#include <string.h>
#define ENTRY_BOUNDARY 1
static jmp_buf escape;
static uint32_t g_cur_func,tail_observed,sp=0x70000800,frame=0x71000000;
static const char *failure;
static void reject(const char *s){failure=s;longjmp(escape,1);}
static void tail_stop(void) {''' + observer + r'''
int main(void) {
    g_cur_func=0xA08248A3;
    int result=setjmp(escape);
    if(!result) {tail_stop();return 10;}
    if(result!=2 || failure || tail_observed!=0xA0824727 || sp!=0x70000800 || frame!=0x71000000) return 11;
    if(!setjmp(escape)){tail_stop();return 12;}
    if(!failure || strcmp(failure,"tail-boundary")) return 13;
    tail_observed=0;failure=0;g_cur_func++;
    if(!setjmp(escape)){tail_stop();return 14;}
    return !failure || strcmp(failure,"tail-boundary") || tail_observed ? 15:0;
}
'''
        compiler=shutil.which('cc')
        self.assertIsNotNone(compiler, 'Real C compiler required')
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); (root/'tail.c').write_text(source)
            result=subprocess.run([compiler,'-std=c11','-O0',str(root/'tail.c'),
                '-o',str(root/'tail')],capture_output=True,timeout=60)
            self.assertEqual(result.returncode,0,result.stderr.decode())
            result=subprocess.run([root/'tail'],capture_output=True,timeout=10)
            self.assertEqual(result.returncode,0)

    def test_opt_in_preserves_every_body_and_strict_endpoint(self):
        bodies={0x8258A9:'void fixture_a(void) {}',0x82585C:'void fixture_b(void) {}'}
        rows=call_sites(0xA0001000,decode(bytes.fromhex('e810000000 c3')))
        old=b.assemble(bodies); new=b.assemble(bodies,rows)
        for body in bodies.values():
            self.assertEqual(new.count(body),1)
        self.assertNotIn('#undef RECOMP_ICALL',old)
        self.assertIn('#undef RECOMP_ICALL',new)
        self.assertNotIn('#undef RECOMP_CALL',new)
        self.assertIn('if(found!=1) reject("call-metadata")',new)
        self.assertIn('if(MEM32(g_esp)!=returns[k]) reject("endpoint-return-address")',new)
        with self.assertRaises(ValueError):
            seam([])


if __name__=='__main__':
    unittest.main()
