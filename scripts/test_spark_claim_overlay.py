"""The claim extension must never mutate a retained source/runtime checkout."""
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from spark_regtest import claim_overlay, cli, sources


class ClaimOverlayTests(unittest.TestCase):
    def test_prepare_command_does_not_start_or_reset_services(self):
        with patch.object(claim_overlay, "prepare") as prepare, patch.object(cli, "docker") as docker, patch.object(cli, "upstream") as upstream:
            self.assertEqual(cli.main(["claim-overlay-prepare"]), 0)
        prepare.assert_called_once_with()
        docker.assert_not_called()
        upstream.assert_not_called()

    def test_archive_rejects_escape_links_and_existing_files(self):
        sources.WORK.mkdir(parents=True, exist_ok=True)
        for name, link in [("../escape", None), ("/escape", None), ("inside", "../../escape"), ("existing", None)]:
            with self.subTest(name=name), tempfile.TemporaryDirectory(dir=sources.WORK) as directory:
                root = Path(directory)
                destination = root / "export"
                destination.mkdir()
                (destination / "existing").write_text("retain")
                archive = root / "source.tar"
                with tarfile.open(archive, "w") as tar:
                    entry = tarfile.TarInfo(name)
                    if link:
                        entry.type, entry.linkname = tarfile.SYMTYPE, link
                        tar.addfile(entry)
                    else:
                        entry.size = 3
                        tar.addfile(entry, io.BytesIO(b"new"))
                with self.assertRaises((RuntimeError, FileExistsError)):
                    claim_overlay.extract_archive(archive, destination)
                self.assertEqual((destination / "existing").read_text(), "retain")


if __name__ == "__main__":
    unittest.main()
