"""Readable lifecycle orchestration around OpenSSP's native acceptance runner."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

from .resources import guarded_run, require_space
from .sources import INTEGRATION, ROOT, SOURCE, WORK, executable, initialize, run, verify

TOOLS = Path(__file__).resolve().parent

CONTAINER = "zark-spark-regtest"
IMAGE = "zark-spark-regtest:toolchain-v1"
PROJECT = "zark-spark"
OWNER_LABEL = "dev.zark.spark-regtest"


def docker(*args, capture=False):
    return run([executable("docker"), *args], capture=capture)


def fingerprint():
    return hashlib.sha256(
        (INTEGRATION / "sources.json").read_bytes()
        + (INTEGRATION / "Dockerfile").read_bytes()
        + str(os.getuid()).encode()
        + (TOOLS / "resources.py").read_bytes()
    ).hexdigest()


def inspect():
    result = subprocess.run(
        [executable("docker"), "container", "inspect", CONTAINER],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    if result.returncode:
        if "No such container" in result.stderr or "No such object" in result.stderr:
            return None
        raise RuntimeError("cannot inspect Docker container: " + result.stderr.strip())
    state = json.loads(result.stdout)[0]
    if state["Config"].get("Labels", {}).get(OWNER_LABEL) != fingerprint():
        raise RuntimeError("container name belongs to another source/build configuration")
    mounts = {m["Destination"]: m["Source"] for m in state["Mounts"]}
    if mounts.get("/src/open-ssp") != str(SOURCE.resolve()):
        raise RuntimeError("container belongs to a different source directory")
    return state


def image_build():
    verify()
    if os.getuid() == 0:
        raise RuntimeError("run the fixture as a regular user; PostgreSQL refuses root")
    guarded_run([executable("docker"), "build", "--platform", "linux/amd64",
                 "--tag", IMAGE, "--build-arg", f"RUNNER_UID={os.getuid()}",
                 "--label", f"{OWNER_LABEL}={fingerprint()}", INTEGRATION],
                path=ROOT, minimum_gib=12, reserve_gib=4,
                log_path=WORK / "logs" / f"image-build-{time.time_ns()}.log")


def ensure_container():
    verify()
    state = inspect()
    if state:
        if not state["State"]["Running"]:
            docker("start", CONTAINER)
        return
    image = json.loads(docker("image", "inspect", IMAGE, capture=True))[0]
    if image["Config"].get("Labels", {}).get(OWNER_LABEL) != fingerprint():
        raise RuntimeError("toolchain image is stale; run image-build")
    docker("run", "--detach", "--init", "--platform", "linux/amd64",
           "--name", CONTAINER, "--label", f"{OWNER_LABEL}={fingerprint()}",
           "--mount", f"type=bind,source={SOURCE.resolve()},target=/src/open-ssp",
           "--mount", f"type=bind,source={INTEGRATION.resolve()},target=/integration,readonly",
           "--mount", f"type=bind,source={TOOLS.resolve()},target=/integration-tools,readonly",
           IMAGE)


def upstream(*args):
    ensure_container()
    command = ["cargo", "regtest", "--project", PROJECT, *args]
    if args[0] in ("build", "up"):
        require_space(ROOT, 8)
        command = ["python3", "/integration-tools/resources.py", "--path", "/src/open-ssp",
                   "--minimum-gib", "8", "--reserve-gib", "4",
                   "--log", f"/src/open-ssp/.regtest/{PROJECT}/logs/{args[0]}-{time.time_ns()}.log",
                   "--", *command]
    docker("exec", CONTAINER, *command)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("init", "doctor", "image-build", "build", "up", "start", "status", "stop", "test", "claim-overlay-prepare"):
        commands.add_parser(name)
    logs = commands.add_parser("logs")
    logs.add_argument("services", nargs="*")
    fund = commands.add_parser("fund")
    fund.add_argument("ssp", choices=("a", "b"))
    fund.add_argument("sats", type=int)
    execute = commands.add_parser("exec", help="execute a client inside the isolated network")
    execute.add_argument("args", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            initialize()
        elif args.command == "claim-overlay-prepare":
            from .claim_overlay import prepare
            prepare()
        elif args.command == "doctor":
            verify()
            docker("info", "--format", "{{.OSType}} {{.Architecture}} {{.MemTotal}}")
            print(f"Source: {SOURCE}\nState: {SOURCE / '.regtest' / PROJECT}\nPlatform: linux/amd64")
        elif args.command == "image-build":
            image_build()
        elif args.command == "test":
            # Upstream test resets its project. Never give it the development name.
            ensure_container()
            require_space(ROOT, 8)
            upstream("stop")
            try:
                docker("exec", CONTAINER, "python3", "/integration-tools/resources.py",
                       "--path", "/src/open-ssp", "--minimum-gib", "8", "--reserve-gib", "4", "--",
                       "cargo", "regtest", "--project", PROJECT + "-acceptance", "test", "--keep")
            finally:
                docker("exec", CONTAINER, "cargo", "regtest", "--project", PROJECT + "-acceptance", "stop")
        elif args.command == "stop":
            state = inspect()
            if state and state["State"]["Running"]:
                upstream("stop")
                docker("stop", CONTAINER)
        elif args.command == "logs":
            upstream("logs", *args.services)
        elif args.command == "fund":
            if args.sats <= 0:
                raise RuntimeError("funding amount must be positive")
            upstream("fund", args.ssp, str(args.sats))
        elif args.command == "exec":
            if not args.args:
                raise RuntimeError("exec requires a command")
            ensure_container()
            docker("exec", CONTAINER, *args.args)
        else:
            upstream(args.command)
        return 0
    except (RuntimeError, subprocess.CalledProcessError, OSError) as error:
        print(f"spark-regtest: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
