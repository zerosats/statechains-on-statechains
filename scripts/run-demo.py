#!/usr/bin/env python3
"""Run the blinded Spark demo on a checkout prepared by scripts/setup-demo.py.

    python3 scripts/run-demo.py                          # alice and bob on network demo
    python3 scripts/run-demo.py alice bob carol --network demo-2

Starts the regtest stack, opens one wallet window per name and, once every
window has closed, stops the stack cleanly. Press Ctrl-C once to close all
windows. Each wallet's output is prefixed with its name and saved to
work/logs/run-demo-<network>-<wallet>.log.
"""
import argparse
import contextlib
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
ACCEPTANCE = ROOT / "work/zark-spark/sources/open-ssp/.regtest/zark-spark-acceptance/native/operators.json"
HELPERS = ROOT / "work/zark-spark/sources/open-ssp/.regtest/native-tools"
LOGS = ROOT / "work/logs"
NAME = re.compile(r"[a-z][a-z0-9_-]{0,31}")


def helpers_current():
    """True when every helper exists and is newer than the sources it is built from."""
    helpers = [HELPERS / name for name in ("zark-sdk-send", "zark-sdk-receive", "zark-ordinary-receive")]
    if not all(os.access(helper, os.X_OK) for helper in helpers):
        return False
    sources = [*(ROOT / "integrations/spark/rpc").glob("*.go"), *(ROOT / "integrations/spark/sdk").iterdir()]
    return max(path.stat().st_mtime for path in sources) < min(helper.stat().st_mtime for helper in helpers)


def group_members(group):
    """(pid, executable name) of every process in one process group."""
    listing = subprocess.run(["ps", "-A", "-o", "pid=,pgid=,comm="],
                             capture_output=True, text=True, check=True).stdout
    for line in listing.splitlines():
        pid, pgid, command = line.split(None, 2)
        if int(pgid) == group:
            yield int(pid), Path(command.strip()).name


class Wallet:
    """One wallet: launcher, window, runtime and worker in one process group."""

    def __init__(self, name, command, env, log):
        self.name = name
        self.closed = False
        self.log = log.open("w")
        # A separate process group keeps terminal Ctrl-C away from the worker,
        # which must never be interrupted mid-operation.
        self.process = subprocess.Popen(command, cwd=ROOT, env=env, stdin=subprocess.DEVNULL,
                                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                        start_new_session=True, text=True)
        self.relay = threading.Thread(target=self._relay, daemon=True)
        self.relay.start()

    def _relay(self):
        for line in self.process.stdout:
            print(f"{self.name} | {line}", end="", flush=True)
            self.log.write(line)
            self.log.flush()

    def running(self):
        """True while any of its processes remains, including a draining worker."""
        self.process.poll()
        try:
            os.killpg(self.process.pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            pass
        return True

    def close(self):
        """Ends the window process. Its runtime then sees its input close and
        drains the current operation, as when the window is closed by hand.
        A wallet without a window is still building and has nothing in flight.
        A wallet that has already exited is left as it is, so its status stays."""
        if not self.running():
            return
        self.closed = True
        windows = [pid for pid, name in group_members(self.process.pid) if name == "zark-desktop"]
        with contextlib.suppress(ProcessLookupError):
            if windows:
                for pid in windows:
                    os.kill(pid, signal.SIGTERM)
            else:
                os.killpg(self.process.pid, signal.SIGINT)

    def finish(self):
        self.relay.join(timeout=5)
        self.process.stdout.close()
        self.log.close()
        return self.closed or self.process.returncode == 0


def wait_for(wallets):
    while any(wallet.running() for wallet in wallets):
        time.sleep(1)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("wallets", nargs="*", default=["alice", "bob"], help="wallet names (default: alice bob)")
    parser.add_argument("--network", default=os.environ.get("ZARK_SPARK_NETWORK", "demo"))
    parser.add_argument("--keep-stack", action="store_true", help="leave the regtest stack running afterwards")
    args = parser.parse_args()
    for name in (*args.wallets, args.network):
        if not NAME.fullmatch(name):
            parser.error(f"invalid name {name!r}: use lowercase letters, digits, - and _")
    if len(set(args.wallets)) != len(args.wallets):
        parser.error("each wallet can be opened only once")
    if not ACCEPTANCE.exists():
        sys.exit(f"This checkout has no regtest stack ({ROOT}/work). Run python3 scripts/setup-demo.py first.")

    up = ["sh", "scripts/spark-dev.sh", "up", *(["--skip-helpers"] if helpers_current() else [])]
    try:
        if subprocess.run(up, cwd=ROOT).returncode:
            sys.exit("The stack did not start; see the output above. No wallet was opened.")
    except KeyboardInterrupt:
        sys.exit("\nInterrupted while starting; run scripts/spark-dev.sh down before trying again.")

    LOGS.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, "ZARK_SPARK_NETWORK": args.network}
    wallets = [Wallet(name, ["./run-wallet.sh", "--blinded", name], env,
                      LOGS / f"run-demo-{args.network}-{name}.log") for name in args.wallets]
    print(f"\nOpening {', '.join(args.wallets)} on network {args.network}. "
          "Close the windows to finish, or press Ctrl-C once to close them all.", flush=True)
    try:
        wait_for(wallets)
    except KeyboardInterrupt:
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        print("\nClosing the wallets; each finishes its current operation first.", flush=True)
        for wallet in wallets:
            wallet.close()
        wait_for(wallets)
    # Ignored from here on, and inherited by spark-dev.sh: an interrupted
    # stop can leave bitcoind unflushed and lose the chain.
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    failed = [wallet.name for wallet in wallets if not wallet.finish()]
    if failed:
        print(f"Wallet(s) {', '.join(failed)} exited with an error; see work/logs/.", flush=True)

    if args.keep_stack:
        print("The stack is still running; stop it with scripts/spark-dev.sh down.")
        return
    print("All wallets closed; stopping the stack.", flush=True)
    if subprocess.run(["sh", "scripts/spark-dev.sh", "down"], cwd=ROOT).returncode:
        sys.exit("Stopping the stack failed; see above, then run scripts/spark-dev.sh down again.")


if __name__ == "__main__":
    main()
