#!/usr/bin/env python3
"""Authenticate a Spark ownership suite and prepare a fresh accelerated runtime.

This only reads assets and writes configuration. It runs no compiler, witness
executor or prover, and is not evidence of compatibility or speed. The suite
and both executables require explicit hashes; nothing inherits compatibility
from a filename. runtime/fast-prover/ holds the patches the executables are
built from.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform

ROOT = Path(__file__).resolve().parents[1]
ROLES = {"deposit": 1036, "sender_from_origin": 588,
         "sender_from_transfer": 588, "receiver": 1036}
CRS = {
    "bn254_g1.dat": "d777711ae9fb1951c47a0eaf7e0ebcaccc39e6731d9b3a560d7ff0c2fcdf2f0d",
    "bn254_g1_compressed.dat": "bf9f1cdbe7b7bb2667c8ee5b887f6ce8b07ec99d60944e17da880ad3717e141b",
}


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def digest(value):
    if not isinstance(value, str) or len(value) != 64:
        raise ValueError("expected an exact SHA256 hex digest")
    result = bytes.fromhex(value)
    if len(result) != 32 or result == bytes(32):
        raise ValueError("expected a nonzero SHA256 digest")
    return result.hex()


def check(path, expected):
    if sha(path) != digest(expected):
        raise ValueError("asset changed: " + str(path))


def pin(path, expected):
    path = path.resolve(strict=True)
    check(path, expected)
    return {"path": str(path), "sha256": list(bytes.fromhex(expected))}


def pin_digest(value):
    raw = value["sha256"]
    if (not isinstance(raw, list) or len(raw) != 32
            or any(type(n) is not int or not 0 <= n <= 255 for n in raw)):
        raise ValueError("expected a 32-byte asset pin")
    return digest(bytes(raw).hex())


def unique_object(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate JSON field: " + key)
        result[key] = value
    return result


def read_json(path):
    return json.loads(path.read_text(), object_pairs_hook=unique_object)


def checked_pin(value):
    if set(value) != {"path", "sha256"} or not Path(value["path"]).is_absolute():
        raise ValueError("expected an absolute pinned asset")
    check(Path(value["path"]), pin_digest(value))


def check_sources(suite):
    circuits = Path(suite["programs"]["deposit"]["directory"]).parent
    if not suite["sources"]:
        raise ValueError("suite source pins missing")
    for name, expected_hash in suite["sources"].items():
        relative = Path(name)
        if relative.is_absolute() or not relative.parts or any(p in (".", "..") for p in relative.parts):
            raise ValueError("invalid pinned source path")
        if expected_hash != digest(expected_hash):
            raise ValueError("noncanonical source digest")
        check(circuits / relative, expected_hash)


def authenticate_suite(path, expected):
    check(path, expected)
    suite = read_json(path)
    if (set(suite) != {"schema", "version", "registry", "sources", "role_hashes", "nargo", "bb", "crs", "programs"}
            or suite["schema"] != "zark-spark-real-proof-suite"
            or type(suite["version"]) is not int or suite["version"] != 1
            or suite["registry"] != "zark-spark-private-ownership-four-role-v1"
            or set(suite["programs"]) != set(ROLES) or len(suite["role_hashes"]) != 4):
        raise ValueError("select the four-role Spark ownership suite")
    host = {"Darwin-arm64": "darwin-arm64", "Linux-x86_64": "linux-x64",
            "Linux-aarch64": "linux-arm64"}.get(platform.system() + "-" + platform.machine())
    toolchains = read_json(ROOT / "runtime/toolchains.json")
    if host not in toolchains:
        raise ValueError("unsupported native build host")
    for name, field in (("nargo", "nargo_sha256"), ("bb", "verifier_sha256")):
        checked_pin(suite[name])
        if pin_digest(suite[name]) != toolchains[host][field]:
            raise ValueError("unqualified stock compiler/verifier: " + name)
    crs = Path(suite["crs"])
    if not crs.is_absolute():
        raise ValueError("absolute CRS directory required")
    for name, expected_hash in CRS.items():
        check(crs / name, expected_hash)
    role_evidence = {}
    for index, (role, size) in enumerate(ROLES.items()):
        program = suite["programs"][role]
        if (set(program) != {"directory", "artifact", "vk", "public_bytes", "metadata_sha256"}
                or program["metadata_sha256"] != digest(program["metadata_sha256"])):
            raise ValueError("unsupported role fields or noncanonical metadata digest: " + role)
        directory = Path(program["directory"])
        if not directory.is_absolute() or not (directory / "Nargo.toml").is_file():
            raise ValueError("missing role source directory: " + role)
        for name in ("artifact", "vk"):
            checked_pin(program[name])
        metadata_path = Path(program["vk"]["path"]).parent / "vk.json"
        check(metadata_path, program["metadata_sha256"])
        metadata = read_json(metadata_path)
        fields = metadata["vk"] + [metadata["hash"]]
        if any(not isinstance(field, str) or not field.startswith("0x")
               or len(field) != 66 or field[2:] != bytes.fromhex(field[2:]).hex() for field in fields):
            raise ValueError("noncanonical VK field encoding: " + role)
        binary = b"".join(bytes.fromhex(field[2:]) for field in metadata["vk"])
        recursive_hash = digest(metadata["hash"][2:])
        if (program["public_bytes"] != size or len(metadata["vk"]) != 115
                or len(binary) != 115 * 32 or metadata["scheme"] != "ultra_honk"
                or metadata["bb_version"] != "5.2.0"
                or binary != Path(program["vk"]["path"]).read_bytes()
                or binary[32:64] != ((size + 30) // 31 + 8).to_bytes(32, "big")
                or pin_digest({"sha256": suite["role_hashes"][index]}) != recursive_hash):
            raise ValueError("Spark role/VK metadata differs: " + role)
        role_evidence[role] = {"artifact_sha256": pin_digest(program["artifact"]),
            "vk_sha256": pin_digest(program["vk"]), "metadata_sha256": program["metadata_sha256"],
            "recursive_hash": recursive_hash, "public_bytes": size}
    check_sources(suite)
    check(path, expected)
    return suite, role_evidence, host


def prepare(args):
    suite_path = args.suite.resolve(strict=True)
    suite, roles, host = authenticate_suite(suite_path, args.suite_sha256)
    runtime = {name: pin(getattr(args, name), digest(getattr(args, name + "_sha256")))
               for name in ("executor", "prover")}
    runtime.update(witness_threads=args.witness_threads, prove_threads=args.prove_threads)
    if args.fast_msm:
        runtime["fast_msm"] = True
    # Fresh private output prevents overwriting a frozen runtime or retained run.
    output = args.output.resolve()
    if not output.is_relative_to((ROOT / "work").resolve()):
        raise ValueError("select a fresh output directory under ignored work/")
    if output.is_relative_to(suite_path.parent):
        raise ValueError("runtime output must be outside the frozen suite directory")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.mkdir(mode=0o700)
    runtime_path = output / "runtime.json"
    runtime_path.write_text(json.dumps(runtime, indent=2) + "\n")
    evidence = {"schema": "zark-spark-fast-runtime-preparation", "version": 1,
        "qualification": "configuration only; no proof generation, compatibility or speed qualification",
        "host": host, "suite": {"path": str(suite_path), "sha256": digest(args.suite_sha256)},
        "runtime": {"path": str(runtime_path), "sha256": sha(runtime_path)},
        "toolchains_sha256": sha(ROOT / "runtime/toolchains.json"),
        "original_verifier": suite["bb"],
        "compiler": suite["nargo"], "roles": roles, "source_pins": suite["sources"],
        "crs": {"path": suite["crs"], "sha256": CRS},
        "worker_profile": {"witness": args.witness_threads, "prove": args.prove_threads},
        "backend_environment": {"prove": {"BB_MSM_NEW": "1"} if args.fast_msm else {},
                                "execute": {}, "verify": {}}}
    (output / "preparation.json").write_text(json.dumps(evidence, indent=2) + "\n")
    print("Prepared unqualified runtime: " + str(runtime_path))
    print("Authentication evidence: " + str(output / "preparation.json"))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("suite", "executor", "prover", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("suite", "executor", "prover"):
        parser.add_argument("--" + name + "-sha256", required=True)
    for phase in ("witness", "prove"):
        parser.add_argument("--" + phase + "-threads", type=int, choices=range(1, 9), default=2)
    parser.add_argument("--fast-msm", action="store_true", help="set BB_MSM_NEW=1 only for proving")
    os.umask(0o077)
    prepare(parser.parse_args())
