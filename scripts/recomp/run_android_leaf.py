#!/usr/bin/env python3
"""Owner-only opt-in JNI differential batch. Default is local preflight, no ADB.

Installs/updates the diagnostic APK ONLY with --run. Never a gameplay validator.
Device logs/identity and the proprietary APK must remain private.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import time
import uuid

PACKAGE = 'org.ts2native.diagnostic'


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def preflight(bundle):
    manifest = json.loads((bundle/'manifest.json').read_text())
    if (manifest.get('schema') != 'ts2-jni-device-bundle/1' or
        manifest.get('cases') != 64 or manifest.get('rva') != '0x9550' or
        set(manifest.get('sha256', {})) != {'probe.apk', 'run_probe.py', 'android_probe.py'}):
        raise ValueError('invalid bundle manifest')
    for name, wanted in manifest['sha256'].items():
        if sha(bundle/name) != wanted:
            raise ValueError('bundle hash mismatch: '+name)
    return manifest


def parse_result(text, nonce):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate JSON key')
            result[key] = value
        return result
    found = []
    for line in text.splitlines():
        try:
            row = json.loads(line, object_pairs_hook=unique)
        except ValueError:
            continue
        if isinstance(row, dict) and row.get('event') == 'private_leaf_probe' and row.get('nonce') == nonce:
            found.append(row)
    if not found:
        return None
    if len(found) != 1:
        raise ValueError('duplicate probe completion')
    result = found[0].get('result')
    if (not isinstance(result, dict) or set(result) != {'available', 'cases', 'matched', 'passed'} or
        result['available'] is not True or result['passed'] is not True or
        type(result['cases']) is not int or result['cases'] != 64 or
        type(result['matched']) is not int or result['matched'] != 64):
        raise ValueError('JNI differential unavailable, incomplete or mismatched')
    return result


def device_helpers(bundle):
    # Load exactly the copied, preflight-hashed dependency, including --bundle.
    spec = importlib.util.spec_from_file_location('ts2_bundle_android_probe', bundle/'android_probe.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run(bundle, adb, serial=None):
    manifest = preflight(bundle)
    helpers = device_helpers(bundle)
    output = bundle/('results-'+uuid.uuid4().hex)
    output.mkdir(mode=0o700)
    nonce = uuid.uuid4().hex
    report = dict(schema='ts2-jni-device-result/1', android_executed=False,
                  differential_passed=False, phase1_complete=False, nonce=nonce,
                  apk_sha256=manifest['sha256']['probe.apk'])

    def command(*args):
        return subprocess.run([adb, '-d', *args], check=True, capture_output=True,
                              text=True, timeout=60).stdout.strip()
    try:
        report['serial'] = helpers.select_usb_device(adb, serial)
        device = {'architecture': command('shell', 'uname', '-m')}
        for key, prop in {'abi_list': 'ro.product.cpu.abilist', 'sdk': 'ro.build.version.sdk',
                          'qemu': 'ro.kernel.qemu', 'boot_qemu': 'ro.boot.qemu',
                          'hardware': 'ro.hardware', 'model': 'ro.product.model',
                          'manufacturer': 'ro.product.manufacturer'}.items():
            device[key] = command('shell', 'getprop', prop)
        device['page_size'] = command('shell', 'getconf', 'PAGESIZE')
        report['device'] = device
        helpers.validate_device(device)
        command('install', '-r', str(bundle/'probe.apk'))
        installed = command('shell', 'pm', 'path', PACKAGE)
        if not installed.startswith('package:/') or '\n' in installed:
            raise ValueError('expected one installed base APK')
        remote = installed[len('package:'):]
        # Android package path is used as one argv item, never a local shell command.
        command('pull', remote, str(output/'installed.apk'))
        if sha(output/'installed.apk') != report['apk_sha256']:
            raise ValueError('installed APK hash differs')
        (output/'installed.apk').unlink()
        command('shell', 'am', 'force-stop', PACKAGE)
        command('shell', 'am', 'start', '-W', '-n', PACKAGE+'/.MainActivity',
                '--es', 'ts2_leaf_probe', nonce)
        deadline = time.monotonic()+60
        while time.monotonic() < deadline:
            pid = command('shell', 'pidof', PACKAGE)
            if not pid.isdecimal():
                raise ValueError('missing or ambiguous diagnostic process')
            text = command('logcat', '-d', '--pid='+pid, '-v', 'raw', '-s', 'TS2Native:I', '*:S')
            (output/'logcat.txt').write_text(text+'\n')
            result = parse_result(text, nonce)
            if result is not None:
                report.update(android_executed=True, differential_passed=True, result=result)
                break
            time.sleep(1)
        else:
            raise ValueError('no nonce-bound JNI result within 60 seconds')
    except Exception as exc:
        report['failure'] = str(exc)
    finally:
        (output/'result.json').write_text(json.dumps(report, indent=2)+'\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument('--run', action='store_true', help='explicitly install/update private diagnostic APK and run JNI')
    parser.add_argument('--adb', default='adb')
    parser.add_argument('--serial')
    a = parser.parse_args()
    preflight(a.bundle)
    if not a.run:
        print('Preflight PASS; android_executed: false; no device command issued')
    else:
        executable = shutil.which(a.adb)
        if not executable:
            parser.error('ADB is missing')
        result = run(a.bundle, executable, a.serial)
        print('JNI differential:', result['differential_passed'], '; Phase 1: false')
        raise SystemExit(0 if result['differential_passed'] else 1)
