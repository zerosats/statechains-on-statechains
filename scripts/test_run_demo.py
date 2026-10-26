"""Wallet shutdown in run-demo.py, with stand-in processes instead of a stack."""
import importlib.util
import os
from pathlib import Path
import shutil
import tempfile
import time
import unittest

spec = importlib.util.spec_from_file_location("run_demo", Path(__file__).with_name("run-demo.py"))
run_demo = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run_demo)


def settled(wallet, seconds=10):
    deadline = time.monotonic() + seconds
    while wallet.running():
        if time.monotonic() > deadline:
            return False
        time.sleep(0.1)
    return True


class WalletShutdownTests(unittest.TestCase):
    def setUp(self):
        self.directory = Path(tempfile.mkdtemp(prefix="run-demo-test-"))
        self.addCleanup(shutil.rmtree, self.directory)
        # Named like the desktop shell so close() recognises it as the window. A
        # symlink, because macOS stalls copies of signed system binaries.
        self.window = self.directory / "zark-desktop"
        self.window.symlink_to(shutil.which("sleep"))

    def start(self, script):
        wallet = run_demo.Wallet("alice", ["sh", "-c", script], dict(os.environ), self.directory / "alice.log")
        self.addCleanup(lambda: wallet.running() and os.killpg(wallet.process.pid, 9))
        return wallet

    def test_close_ends_the_window_and_waits_for_the_drain_after_it(self):
        wallet = self.start(f"'{self.window}' 60; sleep 1; echo drained")
        time.sleep(0.5)
        wallet.close()
        time.sleep(0.3)
        self.assertTrue(wallet.running(), "the drain after the window must still be awaited")
        self.assertTrue(settled(wallet))
        self.assertTrue(wallet.finish())
        self.assertIn("drained", (self.directory / "alice.log").read_text())

    def test_close_interrupts_a_wallet_that_has_no_window_yet(self):
        wallet = self.start("sleep 60")
        time.sleep(0.5)
        wallet.close()
        self.assertTrue(settled(wallet, 5))
        self.assertTrue(wallet.finish())

    def test_a_wallet_closed_by_hand_reports_its_exit_status(self):
        failing = self.start("exit 3")
        self.assertTrue(settled(failing))
        self.assertFalse(failing.finish())

    def test_close_after_an_exit_keeps_the_failed_status(self):
        failing = self.start("exit 3")
        self.assertTrue(settled(failing))
        failing.close()
        self.assertFalse(failing.finish())


if __name__ == "__main__":
    unittest.main()
