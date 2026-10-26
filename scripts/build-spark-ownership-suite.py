#!/usr/bin/env python3
"""Compile and pin the demo's Spark ownership, receive, native exit or auth proof roles.

Each suite is written to work/spark-suites/<name>, where the desktop launcher
looks for it; an existing suite is never replaced, because wallet networks are
bound to their manifests. The manifest contains no signing keys or wallet state
and does not qualify native Spark ingress or exit.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
SUITES = ROOT / "work" / "spark-suites"
ROLES = (
    ("deposit", "spark-deposit-authorize", 1036),
    ("sender_from_origin", "spark-sender-from-origin", 588),
    ("sender_from_transfer", "spark-sender-from-transfer", 588),
    ("receiver", "spark-receiver-authorize", 1036),
)
ORDINARY_NATIVE_ROLES = (
    ("exit_from_origin", "spark-native-ordinary-exit-from-origin", 812),
    ("exit_from_transfer", "spark-native-ordinary-exit-from-transfer", 812),
)
RECEIVE_ROLES = (("receive", "spark-receive-authorize", 812),)
AUTH_ROLES = (("auth", "spark-auth-authorize", 268),)
# profile: (directory under work/spark-suites, manifest schema, registry, roles)
PROFILES = {
    "ownership": ("ownership", "zark-spark-real-proof-suite",
                  "zark-spark-private-ownership-four-role-v1", ROLES),
    "ordinary_native": ("ordinary-native", "zark-spark-native-proof-suite",
                        "zark-spark-native-initial-root-ordinary-user-v1", ORDINARY_NATIVE_ROLES),
    "receive": ("receive", "zark-spark-receive-proof-suite",
                "zark-spark-receive-root-ordinary-user-v1", RECEIVE_ROLES),
    "auth": ("auth", "zark-spark-auth-proof-suite", "zark-spark-auth-schnorr-v1", AUTH_ROLES),
}
CRS_PINS = {
    "bn254_g1.dat": "d777711ae9fb1951c47a0eaf7e0ebcaccc39e6731d9b3a560d7ff0c2fcdf2f0d",
    "bn254_g1_compressed.dat": "bf9f1cdbe7b7bb2667c8ee5b887f6ce8b07ec99d60944e17da880ad3717e141b",
}


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").digest()


def require_pin(path, expected):
    if digest(path).hex() != expected:
        raise ValueError("tool or CRS pin mismatch: " + str(path))


def run(command, directory, log, environment, timeout):
    started = time.monotonic()
    with log.open("wb") as stream:
        result = subprocess.run(list(map(str, command)), cwd=directory, env=environment,
                                stdin=subprocess.DEVNULL, stdout=stream,
                                stderr=subprocess.STDOUT, timeout=timeout)
    print(f"{log.stem}: exit={result.returncode}, {time.monotonic()-started:.1f}s", flush=True)
    if result.returncode:
        raise ValueError("failed; inspect " + str(log))


def build(args):
    directory, schema, registry, roles = PROFILES[next(
        (name for name in PROFILES if getattr(args, name, False)), "ownership")]
    host = {("Darwin", "arm64"): "darwin-arm64", ("Linux", "x86_64"): "linux-x64",
            ("Linux", "aarch64"): "linux-arm64"}.get((platform.system(), platform.machine()))
    pins = json.loads((ROOT / "runtime/toolchains.json").read_text())[host]
    require_pin(args.nargo, pins["nargo_sha256"])
    require_pin(args.bb, pins["verifier_sha256"])
    for name, pin in CRS_PINS.items():
        require_pin(args.crs / name, pin)
    if shutil.disk_usage(ROOT).free < 2 * 1024 ** 3:
        raise ValueError("ownership suite disk guard: less than 2 GiB available")
    output = SUITES / directory
    if output.exists():
        raise ValueError("suite already exists; networks are bound to it: " + str(output))
    SUITES.mkdir(parents=True, exist_ok=True)
    output.mkdir()
    print("Proof suite: " + str(output), flush=True)
    try:
        compile_suite(args, output, schema, registry, roles)
    except BaseException:
        shutil.rmtree(output)
        raise


def compile_suite(args, output, schema, registry, roles):
    circuits = output / "circuits"
    shutil.copytree(ROOT / "circuits", circuits,
                    ignore=shutil.ignore_patterns("target", "Prover*.toml", ".git"))
    logs = output / "logs"
    logs.mkdir()
    environment = dict(os.environ)
    for key in ("HARDWARE_CONCURRENCY", "BB_HARDWARE_CONCURRENCY", "RAYON_NUM_THREADS", "OMP_NUM_THREADS"):
        environment[key] = str(args.threads)
    manifest = dict(schema=schema, version=1, registry=registry,
                    nargo=dict(path=str(args.nargo), sha256=list(digest(args.nargo))),
                    bb=dict(path=str(args.bb), sha256=list(digest(args.bb))), crs=str(args.crs),
                    role_hashes=[], programs={}, sources={
                        str(p.relative_to(circuits)): digest(p).hex()
                        for p in sorted(circuits.rglob("*")) if p.is_file()})
    for role, package, public_bytes in roles:
        program = circuits / package
        artifact = program / "target" / (package.replace("-", "_") + ".json")
        run([args.nargo, "compile", "--force"], program, logs / (role + "-compile.log"), environment, args.timeout)
        dest = output / role
        dest.mkdir()
        for fmt in ("binary", "json"):
            run([args.bb, "write_vk", "-b", artifact, "-o", dest, "-t", "noir-recursive",
                 "-c", args.crs, "--output_format", fmt], output,
                logs / (role + "-vk-" + fmt + ".log"), environment, args.timeout)
        vk = dest / "vk"
        if vk.stat().st_size != 115 * 32:
            raise ValueError("unexpected recursive key shape: " + role)
        recursive_hash = bytes.fromhex(json.loads((dest / "vk.json").read_text())["hash"].removeprefix("0x"))
        if len(recursive_hash) != 32 or not any(recursive_hash):
            raise ValueError("invalid recursive key hash: " + role)
        manifest["role_hashes"].append(list(recursive_hash))
        manifest["programs"][role] = dict(directory=str(program), public_bytes=public_bytes,
            artifact=dict(path=str(artifact), sha256=list(digest(artifact))),
            vk=dict(path=str(vk), sha256=list(digest(vk))),
            metadata_sha256=digest(dest / "vk.json").hex())
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print("Pinned suite manifest: " + str(output / "manifest.json"), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("nargo", "bb", "crs"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--threads", type=int, choices=range(1, 9), default=2)
    parser.add_argument("--timeout", type=int, default=1200)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--ordinary-native", action="store_true", help="build ordinary USER two-refund native exit registry")
    group.add_argument("--receive", action="store_true", help="build the fresh ordinary USER receive registry")
    group.add_argument("--auth", action="store_true", help="build the blind Schnorr Spark login registry")
    args = parser.parse_args()
    if not 1 <= args.timeout <= 3600:
        parser.error("timeout must be between 1 and 3600 seconds")
    for name in ("nargo", "bb", "crs"):
        setattr(args, name, getattr(args, name).resolve(strict=True))
    os.umask(0o077)
    build(args)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
