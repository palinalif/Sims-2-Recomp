"""Standalone ADB runner for a private integer-function probe bundle (stdlib only)."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import uuid

REGS = ('eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi')
FIELDS = ('regs', 'eflags', 'mem', 'fp_depth', 'st')


def parse_output(text):
    """Parse the bounded, integer-only difftest protocol; fail closed."""
    if len(text) > 2 * 1024 * 1024:
        raise ValueError('Probe output exceeds limit')
    states, current = [], None
    for line in text.splitlines():
        if re.fullmatch(r'CASE [0-9]+', line):
            if current is not None or int(line[5:]) != len(states) or len(states) >= 256:
                raise ValueError('Nonsequential or nested case')
            current = {'mem': {}, 'st': []}
        elif line == 'ENDCASE':
            if current is None or set(current) != set(FIELDS):
                raise ValueError('Incomplete case')
            states.append(current)
            current = None
        elif current is None:
            raise ValueError('Output outside a case')
        elif re.fullmatch(r'R(?: [0-9a-fA-F]{8}){8}', line) and 'regs' not in current:
            current['regs'] = dict(zip(REGS, (int(x, 16) for x in line.split()[1:])))
        elif re.fullmatch(r'F [0-9a-fA-F]{8}', line) and 'eflags' not in current:
            current['eflags'] = int(line[2:], 16)
        elif line == 'T 0' and 'fp_depth' not in current:
            current['fp_depth'] = 0
        elif re.fullmatch(r'M [0-9a-fA-F]{8} [0-9a-fA-F]{2}', line):
            _, address, value = line.split()
            key = str(int(address, 16))
            if key in current['mem']:
                raise ValueError('Duplicate memory address')
            current['mem'][key] = int(value, 16)
        else:
            raise ValueError('Malformed or duplicate field: ' + line[:80])
    if current is not None or not states:
        raise ValueError('Truncated or empty output')
    return states


def validate_states(states):
    if not isinstance(states, list) or not 1 <= len(states) <= 256:
        raise ValueError('Invalid reference case count')
    for state in states:
        if not isinstance(state, dict) or set(state) != set(FIELDS):
            raise ValueError('Incomplete reference state')
        regs = state['regs']
        if not isinstance(regs, dict) or set(regs) != set(REGS):
            raise ValueError('Incomplete register set')
        if any(type(v) is not int or not 0 <= v <= 0xffffffff
               for v in [*regs.values(), state['eflags']]):
            raise ValueError('Invalid uint32 state')
        memory = state['mem']
        if not isinstance(memory, dict) or len(memory) > 0x40000:
            raise ValueError('Invalid memory delta')
        for key, value in memory.items():
            if (not isinstance(key, str) or not key.isascii() or not key.isdecimal()
                    or str(int(key)) != key or not 0 <= int(key) <= 0xffffffff
                    or type(value) is not int or not 0 <= value <= 255):
                raise ValueError('Invalid memory byte')
        if type(state['fp_depth']) is not int or state['fp_depth'] != 0 or state['st'] != []:
            raise ValueError('This probe supports integer-only states')


def compare(expected, actual):
    validate_states(expected)
    validate_states(actual)
    if len(expected) != len(actual):
        raise ValueError('Case count differs from reference')
    differences = []
    for index, (left, right) in enumerate(zip(expected, actual)):
        changed = [field for field in FIELDS if left[field] != right[field]]
        if changed:
            differences.append({'case': index, 'fields': changed})
    return {'cases': len(expected), 'matched': len(expected) - len(differences),
            'differences': differences}


def validate_device(device):
    if (device.get('architecture') != 'aarch64'
            or 'arm64-v8a' not in device.get('abi_list', '').split(',')):
        raise ValueError('Requires an Android ARM64 device')
    try:
        sdk = int(device.get('sdk', ''))
    except ValueError as error:
        raise ValueError('Missing Android SDK level') from error
    if sdk < 26:
        raise ValueError('Requires Android API 26 or newer')
    if device.get('qemu') == '1' or device.get('boot_qemu') == '1':
        raise ValueError('Emulator does not satisfy the hardware gate')
    identity = ' '.join(device.get(k, '') for k in ('hardware', 'model', 'manufacturer')).lower()
    if any(token in identity for token in ('ranchu', 'goldfish', 'cuttlefish', 'sdk_gphone', 'emulator')):
        raise ValueError('Emulator identity does not satisfy the hardware gate')


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def load_bundle(directory):
    manifest = json.loads((directory / 'manifest.json').read_text(encoding='utf-8'))
    if manifest.get('schema') != 1 or manifest.get('cases') != 64:
        raise ValueError('Unsupported bundle')
    binary = (directory / 'leaf-arm64').read_bytes()
    reference_bytes = (directory / 'reference.json').read_bytes()
    for name, data in [('leaf-arm64', binary), ('reference.json', reference_bytes)]:
        if sha256(data) != manifest['sha256'][name]:
            raise ValueError('Bundle hash mismatch: ' + name)
    if (len(binary) < 64 or binary[:6] != b'\x7fELF\x02\x01'
            or struct.unpack_from('<HH', binary, 16) != (3, 183)):
        raise ValueError('Expected AArch64 ELF64 little-endian PIE')
    reference = json.loads(reference_bytes)
    validate_states(reference['states'])
    if len(reference['states']) != manifest['cases']:
        raise ValueError('Reference case count mismatch')
    for key in ('original_executable_sha256', 'original_function_sha256', 'generated_c_sha256'):
        if reference[key] != manifest[key]:
            raise ValueError('Provenance mismatch: ' + key)
    return manifest, reference['states']


def private_write(path, contents):
    with path.open('x', encoding='utf-8', newline='\n') as stream:
        stream.write(contents)
    path.chmod(0o600)


def select_usb_device(adb, requested):
    listing = subprocess.run([adb, 'devices'], check=True, capture_output=True, text=True, timeout=30)
    devices = [line.split() for line in listing.stdout.splitlines()[1:] if line.strip()]
    authorized = [item[0] for item in devices if len(item) == 2 and item[1] == 'device']
    # -d is ADB's USB-only transport selector; it fails for zero/multiple USB devices.
    selection = subprocess.run([adb, '-d', 'get-serialno'], check=True,
                               capture_output=True, text=True, timeout=30)
    serial = selection.stdout.strip()
    if serial not in authorized or (requested is not None and requested != serial):
        raise ValueError('Connect/unlock/authorize exactly one USB device; --serial must identify that device')
    return serial


def run_device(adb, serial, bundle, results, manifest, expected):
    remote = '/data/local/tmp/ts2-probe-' + uuid.uuid4().hex
    report = {'schema': 1, 'arm64_executed': False, 'hardware_gate_passed': False,
              'bundle_sha256': manifest['sha256'], 'device': {}, 'serial': serial,
              'device_identity_source': 'ADB properties; not hardware attestation'}

    def command(*args, timeout=30):
        return subprocess.run([adb, '-d', *args], check=True,
                              capture_output=True, timeout=timeout)

    created = False
    try:
        props = {'abi_list': 'ro.product.cpu.abilist', 'sdk': 'ro.build.version.sdk',
                 'qemu': 'ro.kernel.qemu', 'boot_qemu': 'ro.boot.qemu',
                 'hardware': 'ro.hardware', 'model': 'ro.product.model',
                 'manufacturer': 'ro.product.manufacturer',
                 'fingerprint': 'ro.build.fingerprint', 'android': 'ro.build.version.release'}
        device = report['device']
        device['architecture'] = command('shell', 'uname', '-m').stdout.decode().strip()
        for key, prop in props.items():
            device[key] = command('shell', 'getprop', prop).stdout.decode().strip()
        device['page_size'] = command('shell', 'getconf', 'PAGESIZE').stdout.decode().strip()
        validate_device(device)
        # Only generated alphanumeric paths enter adb's remote shell command text.
        command('shell', 'mkdir', '-m', '700', remote)
        created = True
        command('push', str(bundle / 'leaf-arm64'), remote + '/leaf-arm64', timeout=60)
        command('shell', 'chmod', '700', remote + '/leaf-arm64')
        remote_hash = command('shell', 'sha256sum', remote + '/leaf-arm64').stdout.decode().split()[0]
        if remote_hash != manifest['sha256']['leaf-arm64']:
            raise ValueError('Device binary hash differs')
        report['device_binary_sha256'] = remote_hash
        # adb shell propagates the remote exit code. No PTY, no APK or PE launch.
        process = subprocess.run([adb, '-d', 'shell', '-T', remote + '/leaf-arm64'],
                                 capture_output=True, timeout=15)
        report['execution_attempted'] = True
        report['remote_exit_code'] = process.returncode
        private_write(results / 'stdout.txt', process.stdout.decode('ascii', errors='replace'))
        private_write(results / 'stderr.txt', process.stderr.decode('utf-8', errors='replace'))
        process.check_returncode()
        actual = parse_output(process.stdout.decode('ascii'))
        report['arm64_executed'] = True
        report.update(compare(expected, actual))
        report['hardware_gate_passed'] = report['matched'] == report['cases']
    except (OSError, ValueError, KeyError, IndexError, subprocess.SubprocessError) as error:
        report['error'] = str(error)
    finally:
        if created:
            try:
                command('shell', 'rm', '-rf', remote)
            except (OSError, subprocess.SubprocessError) as error:
                report['cleanup_error'] = str(error)
                report['remote_directory'] = remote
        private_write(results / 'result.json', json.dumps(report, indent=2) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument('--adb', default='adb')
    parser.add_argument('--serial')
    parser.add_argument('--preflight', action='store_true', help='Validate bundle only; never a hardware pass')
    args = parser.parse_args()
    try:
        bundle = args.bundle.resolve()
        manifest, expected = load_bundle(bundle)
        if args.preflight:
            print(json.dumps({'bundle_valid': True, 'cases': len(expected), 'arm64_executed': False}))
            return 0
        adb = shutil.which(args.adb)
        if adb is None:
            raise ValueError('ADB not found. Install Android SDK Platform Tools and add to PATH, or use --adb PATH.')
        serial = select_usb_device(adb, args.serial)
        results = bundle / ('results-' + uuid.uuid4().hex)
        results.mkdir(mode=0o700)
        report = run_device(adb, serial, bundle, results, manifest, expected)
        print(json.dumps({'hardware_gate_passed': report['hardware_gate_passed'],
                          'matched': report.get('matched'), 'cases': report.get('cases'),
                          'error': report.get('error'), 'report': str(results / 'result.json')}, indent=2))
        return 0 if report['hardware_gate_passed'] else 1
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print('Probe stopped: ' + str(error), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
