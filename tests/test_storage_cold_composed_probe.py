"""Authored composition tests: no original inputs, states or bodies opened."""
import contextlib
import copy
import io
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import storage_cold_composed_probe as p
from test_storage_hot_composed_probe import fixtures as hot_fixtures
from test_encoded_resolver_composed_probe import fixture as cold_fixture


def fixture(cookie,export):
    resolver,helper,encoder,ret = cold_fixture(cookie,export)
    # Authored fixture has a different name pointer/return offset than originals.
    resolver = resolver.replace(struct.pack('<I',p.r.NAME),struct.pack('<I',p.query.NAME))
    selector = hot_fixtures(bool(export))[p.query.ENTRY]
    return {p.query.ENTRY:selector,p.c.ENTRY:resolver,p.m.ENTRY:helper,
            p.cold.ENCODER:encoder},ret


def expected(cookie,export,result,index,ret):
    s = p.oracle(cookie,(p.r.H1,0),((0,0,0,0,0),)*2,export,result,index)
    e = s['events'][1]
    s['events'][1] = (e[0],e[1],ret,e[3])
    return s


class StorageColdComposedTests(unittest.TestCase):
    def test_authored_four_body_nested_frames_and_publication(self):
        for cookie in (0,1,31,0x12345678,p.r.NEG):
            for export in (0,p.query.FLS):
                codes,ret = fixture(cookie,export)
                for result in (0,0x80000000,p.r.NEG):
                    for index in (0,p.r.NEG):
                        args = (cookie,(p.r.H1,0),((0,0,0,0,0),)*2,export,result,index)
                        p.r.verify(p.exercise(codes,*args,salt=7),
                                   expected(cookie,export,result,index,ret))

    def test_independent_policy_nested_retry_veto_and_tail_frame(self):
        responses = ((0,87,1,0,p.r.H1),(p.r.H2,0,0,0,0))
        s = p.oracle(31,(0,0),responses,0,7,p.r.NEG)
        self.assertEqual([e[0] for e in s['events']],
                         ['resolve','load','error','compare','compare','load','export','tls'])
        self.assertEqual(s['events'][1][3],p.r.SP-92)
        self.assertEqual(s['events'][-2][1],[p.r.H2,p.query.NAME])
        self.assertEqual(s['events'][-1][3],p.r.SP)
        self.assertEqual(s['modules'],[p.r.NEG,p.r.H2])
        self.assertEqual(s['cache'],p.c.encode(p.r.NEG,31))
        self.assertEqual(len(list(p.cases())),1504)

    def test_wrong_cleanup_opaque_body_and_forbidden_mutation_reject(self):
        for export in (0,p.query.FLS):
            codes,ret = fixture(31,export)
            args = (31,(p.r.H1,0),((0,0,0,0,0),)*2,export,1,0)
            with self.assertRaises((ValueError,p.UcError)):
                p.r.verify(p.exercise(codes,*args,provider_pop=0),expected(31,export,1,0,ret))
            for address in (p.c.ENTRY,p.m.ENTRY):
                bad = dict(codes);bad[address] = b'\xb8'+struct.pack('<I',export)+b'\xc3'
                with self.assertRaises((ValueError,p.UcError)):
                    p.r.verify(p.exercise(bad,*args),expected(31,export,1,0,ret))
        for body in (b'\xeb\xfe',b'\xc2',b'\xa3'+struct.pack('<I',p.c.COOKIE)+b'\xc3',
                     b'\xb8'+struct.pack('<I',p.r.BASE+0x82A212)+b'\xff\xd0'):
            bad = dict(codes);bad[p.c.ENTRY] = body
            with self.assertRaises((ValueError,p.UcError)):p.exercise(bad,*args)
        with self.assertRaises(ValueError):p.exercise(codes,*args,budget=1)

    def test_every_compared_component_mutation_rejects(self):
        s = p.oracle(31,(p.r.H1,0),((0,0,0,0,0),)*2,p.query.FLS,1,0)
        for key in s:
            bad = copy.deepcopy(s)
            if key == 'events':bad[key].reverse()
            elif key == 'modules':bad[key][0] ^= 1
            else:bad[key] ^= 1
            with self.assertRaises(ValueError):p.r.verify(bad,s)
        for n,event in enumerate(s['events']):
            for component in range(4):
                bad = copy.deepcopy(s);e = list(event)
                e[component] = 'bad' if component == 0 else ([1] if component == 1 else e[component]^1)
                bad['events'][n] = tuple(e)
                with self.assertRaises(ValueError):p.r.verify(bad,s)

    def test_index_envelope_requires_pinned_readonly_success(self):
        doc = dict(schema='sims2-ghidra-query-envelope/1',result={'test':True},
                   provenance=dict(sourceImageSha256=p.r.PIN,mode='readOnly',
                       analysisPerformed=False,headlessExitCode=0,outputParseError=None))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'index.json';path.write_text(json.dumps(doc))
            self.assertEqual(p.load_index(path),{'test':True})
            for field,value in (('sourceImageSha256','0'*64),('mode','write'),
                                ('analysisPerformed',True),('headlessExitCode',1),
                                ('headlessExitCode',False),('outputParseError','bad')):
                bad = copy.deepcopy(doc);bad['provenance'][field] = value
                path.write_text(json.dumps(bad))
                with self.assertRaises(ValueError):p.load_index(path)

    def test_wrong_pin_is_readonly_and_sanitized(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'private.bin';path.write_bytes(b'private fixture')
            out,err = io.StringIO(),io.StringIO()
            with patch.object(p.r,'IMAGE',path),contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):
                self.assertEqual(p.main([]),2)
            self.assertEqual(out.getvalue(),'')
            self.assertNotIn(str(path),err.getvalue())
            self.assertEqual(path.read_bytes(),b'private fixture')


if __name__ == '__main__':unittest.main()
