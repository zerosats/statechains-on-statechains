"""Exact upstream source pins and the one explicit regtest configuration overlay."""
import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]
INTEGRATION = ROOT / "integrations" / "spark"
WORK = ROOT / "work" / "zark-spark"
SOURCE = WORK / "sources" / "open-ssp"
CONFIG = "e2e/upstream/operator.config.yaml"
MPC_DISABLED = "    spark.so.mpc_transfer.enabled: 0"
MPC_ENABLED = "    spark.so.mpc_transfer.enabled: 1"


def executable(name):
    override = os.environ.get(f"ZARK_SPARK_{name.upper()}")
    result = override or shutil.which(name)
    if not result:
        raise RuntimeError(f"missing {name}; set ZARK_SPARK_{name.upper()} to its executable")
    return result


def run(argv, *, cwd=None, capture=False):
    result = subprocess.run(
        [str(a) for a in argv], cwd=cwd, check=True, text=True,
        stdout=subprocess.PIPE if capture else None,
    )
    return result.stdout.rstrip("\n") if capture else None


def git(path, *args):
    return run([executable("git"), "-C", path, *args], capture=True)


def pins():
    value = json.loads((INTEGRATION / "sources.json").read_text())
    if value["version"] != 1:
        raise RuntimeError("unsupported Spark source-lock version")
    return value


def enabled_config(original):
    if original.splitlines().count(MPC_DISABLED) != 1:
        raise RuntimeError("pinned operator configuration does not have the expected MPC gate")
    return original.replace(MPC_DISABLED, MPC_ENABLED, 1)


def verify(source=SOURCE, *, require_overlay=True):
    lock = pins()
    if git(source, "rev-parse", "HEAD") != lock["open_ssp"]["commit"]:
        raise RuntimeError("OpenSSP revision differs from sources.json; refusing to build")
    for path, commit in lock["submodules"].items():
        if git(source / path, "rev-parse", "HEAD") != commit:
            raise RuntimeError(f"{path} revision differs from sources.json")
        if git(source / path, "status", "--porcelain", "--untracked-files=normal"):
            raise RuntimeError(f"{path} has local changes; refusing to silently exclude them")
    original = git(source, "show", f"HEAD:{CONFIG}") + "\n"
    actual = (source / CONFIG).read_text()
    expected = enabled_config(original)
    allowed = {f" M {CONFIG}"}
    changes = set(git(source, "status", "--porcelain", "--untracked-files=normal").splitlines())
    if changes - allowed:
        raise RuntimeError("OpenSSP has changes beyond the documented MPC configuration overlay")
    if actual != expected and (require_overlay or actual != original):
        raise RuntimeError("operator configuration differs from the exact permitted overlay")
    proto = (source / "vendor/spark/protos/spark.proto").read_text()
    if "rpc start_transfer_mpc(" not in proto:
        raise RuntimeError("pinned Spark fork lacks the required user-side MPC endpoint")
    return expected


def initialize():
    lock = pins()
    SOURCE.parent.mkdir(parents=True, exist_ok=True)
    if not SOURCE.exists():
        run([executable("git"), "clone", "--no-checkout", lock["open_ssp"]["url"], SOURCE])
        git(SOURCE, "checkout", "--detach", lock["open_ssp"]["commit"])
    if git(SOURCE, "rev-parse", "HEAD") != lock["open_ssp"]["commit"]:
        raise RuntimeError("existing source checkout has a different revision; leaving it untouched")
    run([executable("git"), "-C", SOURCE, "submodule", "update", "--init", "--recursive", "--depth", "1"])
    expected = verify(require_overlay=False)
    (SOURCE / CONFIG).write_text(expected)
    verify()
    print("Pinned OpenSSP/Spark/SDK/LDK sources verified; regtest MPC enabled.", flush=True)
