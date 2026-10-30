"""Read-only Android build prerequisite inventory; never claims build/runtime success."""
import argparse
import json
import os
from pathlib import Path
import re


def probe(sdk, java, gradle_home, kvm=Path('/dev/kvm')):
    sdk, java, gradle_home = map(Path, (sdk, java, gradle_home))
    checks = {}

    def check(name, path, executable=False):
        checks[name] = {'path': str(path), 'present': path.is_file() and
                        (not executable or os.access(path, os.X_OK))}

    check('platform_35', sdk / 'platforms/android-35/android.jar')
    for tool in ('aapt2', 'apksigner', 'zipalign'):
        check('build_tools_35_' + tool, sdk / 'build-tools/35.0.0' / tool, True)
    check('cmake_3_31_6', sdk / 'cmake/3.31.6/bin/cmake', True)
    ndk = sdk / 'ndk/27.2.12479018'
    check('ndk_clang', ndk / 'toolchains/llvm/prebuilt/linux-x86_64/bin/clang', True)
    check('ndk_api26', ndk / 'toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android26-clang', True)
    check('ndk_cmake', ndk / 'build/cmake/android.toolchain.cmake')
    props = ndk / 'source.properties'
    revision = None
    if props.is_file():
        match = re.search(r'^Pkg.Revision\s*=\s*(\S+)', props.read_text(), re.M)
        revision = match.group(1) if match else None
    checks['ndk_revision'] = {'present': revision == '27.2.12479018', 'observed': revision}
    check('javac', java / 'bin/javac', True)
    version = None
    release = java / 'release'
    if release.is_file():
        match = re.search(r'^JAVA_VERSION="(\d+)', release.read_text(), re.M)
        version = int(match.group(1)) if match else None
    checks['jdk_17_plus'] = {'present': version is not None and version >= 17,
                             'observed_major': version}
    return {
        'schema': 'ts2-android-env/1',
        'sdk': str(sdk), 'java_home': str(java), 'checks': checks,
        'installed_build_tools': sorted(p.name for p in (sdk / 'build-tools').glob('*') if p.is_dir()),
        'prerequisites_present': all(c['present'] for c in checks.values()),
        'jdk_note': 'Java source/target remain 17; inventory does not prove Gradle compatibility.',
        'adb_present': os.access(sdk / 'platform-tools/adb', os.X_OK),
        'sdkmanager_candidates': [str(p) for p in sorted(sdk.glob('cmdline-tools/*/bin/sdkmanager')) if p.is_file()],
        'gradle_8_13_cached': any(gradle_home.glob('wrapper/dists/gradle-8.13-bin/*/gradle-8.13/bin/gradle')),
        'kvm_present': kvm.exists(),
        'kvm_accessible': kvm.exists() and os.access(kvm, os.R_OK | os.W_OK),
        'android_executed': False,
        'limits': 'File/permission inventory only, not package integrity, compilation, APK assembly, emulator viability or gameplay acceptance.',
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sdk', default=os.environ.get('ANDROID_HOME') or os.environ.get('ANDROID_SDK_ROOT'))
    parser.add_argument('--java-home', default=os.environ.get('JAVA_HOME'))
    parser.add_argument('--gradle-home', default=os.environ.get('GRADLE_USER_HOME', str(Path.home() / '.gradle')))
    args = parser.parse_args()
    if not args.sdk or not args.java_home:
        parser.error('provide --sdk/ANDROID_HOME and --java-home/JAVA_HOME explicitly (local.properties is not parsed)')
    result = probe(args.sdk, args.java_home, args.gradle_home)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result['prerequisites_present'] else 78


if __name__ == '__main__':
    raise SystemExit(main())
