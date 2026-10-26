"""Export the pinned Spark source for isolated MPC-claim extension qualification."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tarfile
import tempfile

from .sources import INTEGRATION, SOURCE, WORK, executable, pins, run, verify

OVERLAY = INTEGRATION / "operator-overlay"
FILES = ("claim-v1.patch", "zark_mpc_claim.go", "zark_mpc_claim_wire.go", "zark_mpc_claim_test.go")


def extract_archive(archive, destination):
    # The committed source may contain symlinks. Reject links leaving the
    # isolated export and never follow an earlier archive entry while writing.
    with tarfile.open(archive) as source:
        for entry in source.getmembers():
            path = PurePosixPath(entry.name)
            if path.is_absolute() or ".." in path.parts or not path.parts:
                raise RuntimeError("unsafe pinned source archive path")
            target = destination.joinpath(*path.parts)
            if any(parent.is_symlink() for parent in target.parents):
                raise RuntimeError("source archive writes through a symlink")
            if entry.isdir():
                target.mkdir(parents=True, exist_ok=True)
            elif entry.isfile():
                target.parent.mkdir(parents=True, exist_ok=True)
                with target.open("xb") as output, source.extractfile(entry) as input_:
                    shutil.copyfileobj(input_, output)
                target.chmod(entry.mode & 0o777)
            elif entry.issym():
                # Permit only links whose normalized target stays in the export.
                resolved = (target.parent / entry.linkname).resolve()
                if not resolved.is_relative_to(destination.resolve()):
                    raise RuntimeError("source archive symlink escapes export")
                target.parent.mkdir(parents=True, exist_ok=True)
                target.symlink_to(entry.linkname)
            else:
                raise RuntimeError("unsupported pinned source archive entry")


def prepare():
    """Never alter the verified checkout, retained services, or wallet files."""
    verify()
    overlay = {name: (OVERLAY / name).read_bytes() for name in FILES}
    revision = pins()["submodules"]["vendor/spark"]
    WORK.mkdir(exist_ok=True, parents=True)
    root = Path(tempfile.mkdtemp(prefix="claim-overlay-", dir=WORK))
    source = root / "spark-source"
    source.mkdir()
    archive = root / "source.tar"
    with archive.open("xb") as output:
        subprocess.run([executable("git"), "-C", str(SOURCE / "vendor/spark"),
                        "archive", "--format=tar", revision], stdout=output, check=True)
    extract_archive(archive, source)
    patch = root / "claim-v1.patch"
    patch.write_bytes(overlay["claim-v1.patch"])
    run([executable("git"), "-C", source, "apply", "--check", patch])
    run([executable("git"), "-C", source, "apply", patch])
    for name in FILES[1:]:
        with (source / "spark/so/handler" / name).open("xb") as output:
            output.write(overlay[name])
    # Detect changes to the retained checkout during export as well.
    verify()
    provenance = {
        "schema": "zark-spark/claim-overlay/v1", "spark_commit": revision,
        "overlay_sha256": {name: hashlib.sha256(data).hexdigest() for name, data in overlay.items()},
        "source_archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
        "source_directory": str(source),
        "qualification": "source preparation only; no services started or funds admitted",
    }
    (root / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    archive.unlink()  # The immutable export and its archive digest are retained.
    print(f"Isolated claim extension source: {source}")
    print(f"Provenance: {root / 'provenance.json'}")
    return source
