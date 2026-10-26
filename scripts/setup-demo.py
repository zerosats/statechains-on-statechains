#!/usr/bin/env python3
"""Prepare a fresh clone for the blinded Spark regtest demo.

    python3 scripts/setup-demo.py

Steps, each skipped when its result is already present so a failed run can be
repeated: download the pinned Nargo, BB and CRS into work/tools, build the four
proof suites into work/spark-suites, build cb-mpc, fetch the Rust dependencies
the offline worker build needs into work/cargo, and create the regtest stack.
Every download is checked against its pinned SHA-256 before it is used.
"""
import hashlib
import json
import os
from pathlib import Path
import platform
import runpy
import shutil
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / "work"
TOOLS = WORK / "tools"
CRS_DIR = TOOLS / "crs"
NATIVE = WORK / "zark-spark/sources/open-ssp/.regtest/zark-spark-acceptance/native"
NETWORKS = WORK / "zark-spark/blinded-networks"
SUITE_BUILDER = ROOT / "scripts/build-spark-ownership-suite.py"

NARGO_URL = "https://github.com/noir-lang/noir/releases/download/v1.0.0-beta.25/nargo-{}.tar.gz"
BB_URL = "https://github.com/AztecProtocol/aztec-packages/releases/download/v5.2.0/barretenberg-{}.tar.gz"
# host: (Nargo release target, BB release target)
RELEASE_TARGETS = {
    "darwin-arm64": ("aarch64-apple-darwin", "arm64-darwin"),
    "linux-x64": ("x86_64-unknown-linux-gnu", "amd64-linux"),
    "linux-arm64": ("aarch64-unknown-linux-gnu", "arm64-linux"),
}
# The suites pin the first 2^22 points of Aztec's published BN254 CRS.
CRS_DOWNLOADS = {
    "bn254_g1.dat": ("https://crs.aztec-cdn.foundation/g1.dat", 64 << 22),
    "bn254_g1_compressed.dat": ("https://crs.aztec-cdn.foundation/g1_compressed.dat", 32 << 22),
}


def step(title):
    print(f"\n== {title}", flush=True)


def run(*command, env=None):
    command = [str(part) for part in command]
    print("$ " + " ".join(command), flush=True)
    subprocess.run(command, cwd=ROOT, env=env, check=True)


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def pinned(path, expected):
    return path.is_file() and sha256(path) == expected


def install(part, destination, expected, source):
    if sha256(part) != expected:
        part.unlink()
        raise SystemExit(f"{source} does not match its pinned SHA-256; nothing was installed")
    part.replace(destination)


def host():
    name = {("Darwin", "arm64"): "darwin-arm64", ("Linux", "x86_64"): "linux-x64",
            ("Linux", "aarch64"): "linux-arm64"}.get((platform.system(), platform.machine()))
    if name is None:
        raise SystemExit(f"unsupported host {platform.system()} {platform.machine()}")
    return name


def docker():
    """Resolves Docker the way scripts/spark-dev.sh does."""
    if os.environ.get("ZARK_SPARK_DOCKER"):
        return os.environ["ZARK_SPARK_DOCKER"]
    if os.access("/usr/local/bin/docker", os.X_OK):
        return "/usr/local/bin/docker"
    return shutil.which("docker")


def check_prerequisites():
    step("prerequisites")
    if sys.version_info < (3, 11):
        raise SystemExit("Python 3.11 or newer is required")
    missing = [tool for tool in ("git", "curl", "node", "cargo") if shutil.which(tool) is None]
    if docker() is None:
        missing.append("docker")
    if missing:
        raise SystemExit("missing on PATH: " + ", ".join(missing))
    if subprocess.run([docker(), "info"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
        raise SystemExit("the Docker daemon is unreachable; start Docker Desktop first")
    print("python3, git, curl, node, cargo and a running Docker daemon found")


def fetch_proof_tools(platform_name):
    step("proof tools: Nargo 1.0.0-beta.25, BB 5.2.0 and the BN254 CRS")
    pins = json.loads((ROOT / "runtime/toolchains.json").read_text())[platform_name]
    nargo_target, bb_target = RELEASE_TARGETS[platform_name]
    CRS_DIR.mkdir(parents=True, exist_ok=True)
    for name, url, expected in (("nargo", NARGO_URL.format(nargo_target), pins["nargo_sha256"]),
                                ("bb", BB_URL.format(bb_target), pins["verifier_sha256"])):
        destination = TOOLS / name
        if pinned(destination, expected):
            print(f"{destination}: present")
            continue
        archive = TOOLS / f"{name}.tar.gz"
        run("curl", "-fL", "--retry", "3", "-o", archive, url)
        part = TOOLS / f"{name}.part"
        with tarfile.open(archive) as release:
            member = next((m for m in release.getmembers() if m.isfile() and Path(m.name).name == name), None)
            if member is None:
                raise SystemExit(f"{url} contains no {name} binary")
            part.write_bytes(release.extractfile(member).read())
        archive.unlink()
        part.chmod(0o755)
        install(part, destination, expected, url)
    crs_pins = runpy.run_path(str(SUITE_BUILDER))["CRS_PINS"]
    for name, (url, size) in CRS_DOWNLOADS.items():
        destination = CRS_DIR / name
        if pinned(destination, crs_pins[name]):
            print(f"{destination}: present")
            continue
        part = CRS_DIR / f"{name}.part"
        run("curl", "-fL", "--retry", "3", "-r", f"0-{size - 1}", "-o", part, url)
        install(part, destination, crs_pins[name], url)


def build_proof_suites():
    step("proof suites (compiles each circuit and writes its verification keys)")
    builder = runpy.run_path(str(SUITE_BUILDER))
    for profile, (directory, *_) in builder["PROFILES"].items():
        manifest = builder["SUITES"] / directory / "manifest.json"
        if manifest.exists():
            print(f"{manifest}: present")
            continue
        flag = [] if profile == "ownership" else ["--" + profile.replace("_", "-")]
        run(sys.executable, SUITE_BUILDER, *flag, "--nargo", TOOLS / "nargo", "--bb", TOOLS / "bb",
            "--crs", CRS_DIR, "--threads", min(os.cpu_count() or 2, 8))


def build_cbmpc():
    step("cb-mpc (two-party ECDSA library)")
    if (WORK / "cbmpc/BUILD-INFO").exists():
        print("work/cbmpc: present")
        return
    run("sh", "scripts/build-cbmpc.sh")


def fetch_rust_dependencies():
    step("Rust dependencies for the offline worker build (work/cargo)")
    env = {**os.environ, "CARGO_HOME": str(WORK / "cargo")}
    for manifest in ("Cargo.toml", "integrations/spark/cosigner/Cargo.toml"):
        run("cargo", "fetch", "--locked", "--manifest-path", manifest, env=env)


def create_regtest_stack():
    step("regtest stack (zark-spark-acceptance)")
    if (NATIVE / "operators.json").exists():
        print("acceptance project: present")
        return
    # `spark-regtest.py test` creates the project from scratch. Wallets on an
    # existing network belong to the chain it would replace.
    if NETWORKS.is_dir() and any(NETWORKS.iterdir()):
        raise SystemExit(f"wallet networks exist in {NETWORKS} but the acceptance project is missing; "
                         "restore the project instead of creating a new chain under those wallets")
    # One container name per Docker host; spark-regtest.py refuses a container
    # mounted from another checkout, but only after cloning several GB of sources.
    mounted = subprocess.run(
        [docker(), "container", "inspect", "-f",
         '{{range .Mounts}}{{if eq .Destination "/src/open-ssp"}}{{.Source}}{{end}}{{end}}', "zark-spark-regtest"],
        capture_output=True, text=True)
    own_source = str((WORK / "zark-spark/sources/open-ssp").resolve())
    if mounted.returncode == 0 and mounted.stdout.strip() != own_source:
        raise SystemExit(f"Docker already has a zark-spark-regtest container for another checkout "
                         f"({mounted.stdout.strip()}); only one regtest stack can exist per Docker host. "
                         "Its chain lives in that checkout's work/, so once its stack is stopped you can "
                         "set the container aside with: docker rename zark-spark-regtest zark-spark-regtest-old")
    env = {**os.environ, "ZARK_SPARK_DOCKER": docker()}
    print("First-time build in a linux/amd64 container; this takes a long time, especially on Apple Silicon.")
    for command in ("init", "image-build", "test"):
        run(sys.executable, "scripts/spark-regtest.py", command, env=env)


def main():
    check_prerequisites()
    fetch_proof_tools(host())
    build_proof_suites()
    build_cbmpc()
    fetch_rust_dependencies()
    create_regtest_stack()
    print("""
Setup complete. Run the demo, which opens Alice's and Bob's wallets:

  python3 scripts/run-demo.py""")


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as error:
        sys.exit(f"step failed ({error.cmd[0]} exited with {error.returncode}); fix the cause and rerun")
