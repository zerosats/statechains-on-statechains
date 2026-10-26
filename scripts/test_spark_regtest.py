"""Fail-closed pin/overlay checks without downloading or starting services."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

from spark_regtest import cli, resources, sources


class SourceTests(unittest.TestCase):
    def test_mpc_overlay_is_exact_and_rejects_ambiguous_gate(self):
        original = "knobs:\n  static_values:\n" + sources.MPC_DISABLED + "\n"
        self.assertEqual(sources.enabled_config(original), original.replace(": 0", ": 1"))
        for invalid in ("", original + sources.MPC_DISABLED + "\n", original.replace(": 0", ": 2")):
            with self.assertRaises(RuntimeError):
                sources.enabled_config(invalid)

    def test_source_validation_rejects_revision_changes_dirty_dependencies_and_extra_edits(self):
        work = sources.ROOT / "work"
        work.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="spark-source-test-", dir=work) as directory:
            root = Path(directory)
            config = root / sources.CONFIG
            config.parent.mkdir(parents=True)
            original = "knobs:\n  static_values:\n" + sources.MPC_DISABLED + "\n"
            config.write_text(sources.enabled_config(original))
            proto = root / "vendor/spark/protos/spark.proto"
            proto.parent.mkdir(parents=True)
            proto.write_text("rpc start_transfer_mpc(StartTransferMpcRequest)")
            lock = sources.pins()
            edits = {root: f" M {sources.CONFIG}"}
            revisions = {root: lock["open_ssp"]["commit"], **{
                root / path: commit for path, commit in lock["submodules"].items()
            }}

            def git(path, *args):
                if args[0] == "rev-parse":
                    return revisions[path]
                if args[0] == "status":
                    return edits.get(path, "")
                if args[0] == "show":
                    return original.rstrip("\n")
                self.fail(f"unexpected Git arguments: {args}")

            with patch.object(sources, "git", side_effect=git):
                sources.verify(root)
                revisions[root] = "0" * 40
                with self.assertRaisesRegex(RuntimeError, "OpenSSP revision"):
                    sources.verify(root)
                revisions[root] = lock["open_ssp"]["commit"]
                edits[root / "vendor/spark"] = " M spark/so/handler.go"
                with self.assertRaisesRegex(RuntimeError, "local changes"):
                    sources.verify(root)
                del edits[root / "vendor/spark"]
                edits[root] += "\n?? unexpected-source.rs"
                with self.assertRaisesRegex(RuntimeError, "beyond"):
                    sources.verify(root)
                edits[root] = f" M {sources.CONFIG}"
                config.write_text(config.read_text() + "unreviewed: true\n")
                with self.assertRaisesRegex(RuntimeError, "permitted overlay"):
                    sources.verify(root)

    def test_acceptance_never_resets_development_project_and_stops_on_failure(self):
        calls = []

        def docker(*args, **kwargs):
            calls.append(args)
            if "test" in args:
                raise RuntimeError("acceptance failed")

        with patch.object(cli, "ensure_container"), patch.object(cli, "upstream") as upstream, patch.object(cli, "require_space"):
            with patch.object(cli, "docker", side_effect=docker):
                self.assertEqual(cli.main(["test"]), 1)
        upstream.assert_called_once_with("stop")
        self.assertEqual(calls[0][-3:], ("zark-spark-acceptance", "test", "--keep"))
        self.assertEqual(calls[1][-2:], ("zark-spark-acceptance", "stop"))

    def test_low_disk_refuses_to_launch_or_terminates_only_its_child_group(self):
        with patch.object(resources.shutil, "disk_usage", return_value=SimpleNamespace(free=resources.GIB)):
            with patch.object(resources.subprocess, "Popen") as spawn:
                with self.assertRaisesRegex(RuntimeError, "need 4 GiB"):
                    resources.guarded_run(["build"], path="/fixture", minimum_gib=4)
                spawn.assert_not_called()
        with patch.object(resources.subprocess, "Popen") as spawn:
            child = spawn.return_value
            child.pid = 1234
            child.poll.side_effect = [None, None]
            with patch.object(resources.shutil, "disk_usage", side_effect=[
                SimpleNamespace(free=5 * resources.GIB), SimpleNamespace(free=resources.GIB)
            ]), patch.object(resources.os, "killpg") as terminate:
                with self.assertRaisesRegex(RuntimeError, "preserve 2 GiB"):
                    resources.guarded_run(["build"], path="/fixture", minimum_gib=4)
                terminate.assert_called_once_with(1234, resources.signal.SIGTERM)
                child.wait.assert_called_once_with(timeout=10)


if __name__ == "__main__":
    unittest.main()
