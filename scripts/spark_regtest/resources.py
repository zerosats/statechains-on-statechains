"""Bound build disk use and stop only the child process group we started."""
import argparse
from pathlib import Path
import os
import shutil
import signal
import subprocess
import time

GIB = 1024 ** 3


def require_space(path, minimum_gib):
    free = shutil.disk_usage(path).free
    if free < minimum_gib * GIB:
        raise RuntimeError(
            f"{free / GIB:.1f} GiB free at {path}; need {minimum_gib} GiB before this build"
        )
    return free


def guarded_run(argv, *, path, minimum_gib, reserve_gib=2, log_path=None):
    require_space(path, minimum_gib)
    log = None
    if log_path is not None:
        log_path = Path(log_path)
        log_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        log = open(os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb")
        print(f"Build log: {log_path}", flush=True)
    process = None
    try:
        process = subprocess.Popen([str(a) for a in argv], start_new_session=True,
                                   stdout=log, stderr=subprocess.STDOUT if log else None)
        while process.poll() is None:
            if shutil.disk_usage(path).free < reserve_gib * GIB:
                raise RuntimeError(f"build stopped to preserve {reserve_gib} GiB of free disk space")
            time.sleep(0.5)
        if process.returncode:
            raise subprocess.CalledProcessError(process.returncode, argv)
    finally:
        if process is not None and process.poll() is None:
            # SIGTERM lets Cargo/BuildKit cancel their own work and release locks.
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
        if log:
            log.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--path", type=Path, required=True)
    parser.add_argument("--minimum-gib", type=int, default=6)
    parser.add_argument("--reserve-gib", type=int, default=2)
    parser.add_argument("--log", type=Path)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command or not 0 < args.reserve_gib < args.minimum_gib:
        parser.error("provide a command and 0 < reserve-gib < minimum-gib")
    try:
        guarded_run(command, path=args.path, minimum_gib=args.minimum_gib,
                    reserve_gib=args.reserve_gib, log_path=args.log)
    except (RuntimeError, OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"disk-guard: {error}\n")


if __name__ == "__main__":
    main()
