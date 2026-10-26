#!/usr/bin/env python3
"""Link the external receive and send drivers against the retained, unchanged SDK build.

Runs inside the regtest build container. It neither compiles nor patches SDK
sources. An ambiguous cached crate set fails closed rather than mixing ABIs.
`--check-send` type-checks the send driver only (metadata to a temporary
directory) and writes no helper.
"""
from pathlib import Path
import subprocess
import json
import os
import sys
import tempfile

DEPS = Path('/src/open-ssp/e2e/breez/target/debug/deps')
SOURCE = Path(os.environ.get('ZARK_SPARK_INTEGRATION_SOURCE', '/integration')).resolve()
OUTPUT_DIRECTORY = Path('/src/open-ssp/.regtest/native-tools')
if (not OUTPUT_DIRECTORY.is_absolute()
        or '..' in OUTPUT_DIRECTORY.parts
        or (OUTPUT_DIRECTORY != Path('/src/open-ssp/.regtest/native-tools')
            and OUTPUT_DIRECTORY.parent != Path('/src/open-ssp/.regtest/native-tools'))):
    raise ValueError('native helper output must stay in its isolated tools directory')
DRIVERS = {'receive': 'zark-sdk-receive', 'send': 'zark-sdk-send'}
EXTERNS = ('anyhow', 'bitcoin', 'frost_secp256k1_tr', 'serde_json',
           'spark', 'hex', 'tokio', 'async_trait')


def check_sources():
    sources = json.loads((SOURCE / 'sources.json').read_text())
    for name in ('vendor/breez-sdk', 'vendor/spark'):
        source = Path('/src/open-ssp') / name
        actual = subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip()
        if actual != sources['submodules'][name]:
            raise RuntimeError(f'wrong pinned source: {name}')
        subprocess.run(['git', '-C', str(source), 'diff', '--quiet', 'HEAD'], check=True)


def externs():
    """The exact crate files the retained SDK build linked, or an error."""
    sdk = list(DEPS.glob('libspark-*.rlib'))
    if len(sdk) != 1:
        raise RuntimeError('ambiguous cached Spark SDK')
    sdk_hash = sdk[0].stem.removeprefix('libspark-')
    fingerprints = DEPS.parent / '.fingerprint'
    metadata = json.loads((fingerprints / f'spark-{sdk_hash}' / 'lib-spark.json').read_text())
    pinned = {d[1]: d[3] for d in metadata['deps']}
    args = ['-L', f'dependency={DEPS}']
    for name in EXTERNS:
        suffix = 'so' if name == 'async_trait' else 'rlib'
        files = list(DEPS.glob(f'lib{name}-*.{suffix}'))
        if len(files) > 1 and name in pinned:
            def matches(path):
                crate_hash = path.stem.removeprefix(f'lib{name}-')
                value = fingerprints / f'{name}-{crate_hash}' / f'lib-{name}'
                return value.is_file() and int.from_bytes(bytes.fromhex(value.read_text()), 'little') == pinned[name]
            files = [f for f in files if matches(f)]
        if len(files) != 1:
            raise RuntimeError(f'ambiguous SDK dependency {name}: {len(files)} candidates')
        args.extend(['--extern', f'{name}={files[0]}'])
    return args


def rustc(driver, *output):
    return ['/usr/local/cargo/bin/rustc', '--edition=2024',
            str(SOURCE / f'sdk/{driver}.rs'), *externs(), *output]


def check_send():
    with tempfile.TemporaryDirectory(prefix='zark-sdk-send-check-') as scratch:
        subprocess.run(rustc('send', '--emit=metadata', '--out-dir', scratch), check=True)
    print('send driver type-checks against the retained SDK')


def main():
    check_sources()
    if sys.argv[1:] == ['--check-send']:
        return check_send()
    if sys.argv[1:]:
        raise ValueError('usage: build.py [--check-send]')
    OUTPUT_DIRECTORY.mkdir(mode=0o700, parents=True, exist_ok=True)
    for driver, name in DRIVERS.items():
        output = OUTPUT_DIRECTORY / name
        subprocess.run(rustc(driver, '-o', str(output)), check=True)
        print(output)
    environment = os.environ.copy()
    environment.update(GOTOOLCHAIN='local', GOPROXY='off', GOSUMDB='off',
                       GOCACHE='/home/regtest/.cache/go-build', GOPATH='/home/regtest/go', GOMAXPROCS='2')
    native = OUTPUT_DIRECTORY / 'zark-ordinary-receive'
    files = [str(SOURCE / f'rpc/{name}.go') for name in
             ('main', 'client', 'protocol', 'prepare', 'claim', 'ordinary_receive_test', 'ordinary_exit_test',
              'ordinary_exit_template_test', 'ordinary_exit_claim_test', 'ordinary_share_exit_test',
              'ordinary_public_test', 'ordinary_public_swap_test')]
    subprocess.run(['/usr/local/go/bin/go', 'test', '-mod=readonly', '-p', '1', '-c',
                    '-o', str(native), *files], env=environment,
                   cwd='/src/open-ssp/vendor/spark/spark', check=True)
    print(native)


if __name__ == '__main__':
    main()
