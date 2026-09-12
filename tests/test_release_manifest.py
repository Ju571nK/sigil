"""Release completeness and archive-handling regressions for #221."""

import io
import json
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "packaging"))
import release_manifest as release


class ReleaseManifestTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.dist = self.root / "dist"
        self.dist.mkdir()
        self.version = "0.8.1"

    def archive(self, target, names=release.BINARIES, duplicate=False, symlink=False,
                windows_separators=False):
        path = self.dist / release.archive_name(self.version, target)
        prefix = f"sigil-{self.version}-{target}"
        entries = list(names) + ([names[0]] if duplicate else [])
        if path.suffix == ".zip":
            with zipfile.ZipFile(path, "w") as bundle:
                for name in entries:
                    member = f"{prefix}/{name}.exe"
                    if windows_separators:
                        member = member.replace("/", "\\")
                    info = zipfile.ZipInfo(member)
                    if symlink:
                        info.external_attr = (stat.S_IFLNK | 0o777) << 16
                    bundle.writestr(info, name.encode())
        else:
            with tarfile.open(path, "w:gz") as bundle:
                for name in entries:
                    info = tarfile.TarInfo(f"{prefix}/{name}")
                    info.size = len(name)
                    if symlink:
                        info.type = tarfile.SYMTYPE
                        info.linkname = "../../outside"
                    bundle.addfile(info, io.BytesIO(name.encode()))
                outside = tarfile.TarInfo("../../outside")
                outside.size = 1
                bundle.addfile(outside, io.BytesIO(b"x"))
        return path

    def manifest(self):
        return {"manifest": {"schema_version": 1, "git_sha": "test-sha", "artifacts": [
            {"name": name, "target": target, "blake3": "a" * 64}
            for target in release.TARGETS for name in release.BINARIES
        ]}, "signature": "test-signature"}

    def test_all_tar_and_zip_binaries_keep_canonical_names(self):
        for target in release.TARGETS:
            self.archive(target, windows_separators=True)
            files = release.extract_binaries(self.dist, self.version, target, self.root / "out")
            self.assertEqual(set(files), set(release.BINARIES))
            for name, path in files.items():
                self.assertEqual(path.read_bytes(), name.encode())
                self.assertEqual(path.suffix, ".exe" if "windows" in target else "")
        self.assertFalse((self.root / "outside").exists())

    def test_missing_binary_fails_for_each_archive_format(self):
        for target in (release.TARGETS[0], release.TARGETS[-1]):
            self.archive(target, names=release.BINARIES[:-1])
            with self.assertRaisesRegex(ValueError, "missing binaries"):
                release.extract_binaries(self.dist, self.version, target, self.root / "out")

    def test_duplicate_or_symlink_binary_is_rejected(self):
        for target in (release.TARGETS[0], release.TARGETS[-1]):
            with self.subTest(target=target):
                self.archive(target, duplicate=True)
                with self.assertRaisesRegex(ValueError, "duplicate binary"):
                    release.extract_binaries(self.dist, self.version, target, self.root / "duplicate")
                self.archive(target, symlink=True)
                with self.assertRaisesRegex(ValueError, "invalid binary member"):
                    release.extract_binaries(self.dist, self.version, target, self.root / "link")

    def test_missing_archive_never_invokes_signer(self):
        for target in release.TARGETS[:-1]:
            self.archive(target)
        with patch.object(release.subprocess, "run") as run:
            with self.assertRaisesRegex(ValueError, "archive set mismatch"):
                release.sign(self.dist, self.version, self.root / "key", "test-sha", "test-url")
            run.assert_not_called()

    def test_signer_receives_30_pairs_and_output_is_validated(self):
        for target in release.TARGETS:
            self.archive(target)

        def sign(command, **kwargs):
            artifacts = [command[i + 1] for i, arg in enumerate(command) if arg == "--artifact"]
            self.assertEqual(len(artifacts), 30)
            for artifact in artifacts:
                spec = dict(part.split("=", 1) for part in artifact.split(","))
                self.assertIn(spec["name"], release.BINARIES)
                self.assertEqual(Path(spec["file"]).read_bytes(), spec["name"].encode())
            self.assertNotIn("SIGNING_KEY", kwargs["env"])
            Path(command[command.index("--out") + 1]).write_text(json.dumps(self.manifest()))

        with patch.object(release.subprocess, "run", side_effect=sign):
            release.sign(self.dist, self.version, self.root / "key", "test-sha", "test-url")
        release.validate_manifest(self.dist / "build-manifest.json", "test-sha")

    def test_manifest_rejects_missing_duplicate_wrong_commit_and_bad_hash(self):
        path = self.dist / "build-manifest.json"
        for case in ("missing", "duplicate", "commit", "hash", "exe-name"):
            with self.subTest(case=case):
                signed = self.manifest()
                manifest = signed["manifest"]
                if case == "missing":
                    manifest["artifacts"].pop()
                elif case == "duplicate":
                    manifest["artifacts"][-1] = manifest["artifacts"][0]
                elif case == "commit":
                    manifest["git_sha"] = "wrong"
                elif case == "hash":
                    manifest["artifacts"][0]["blake3"] = "bad"
                else:
                    manifest["artifacts"][-1]["name"] += ".exe"
                path.write_text(json.dumps(signed))
                with self.assertRaises(ValueError):
                    release.validate_manifest(path, "test-sha")

    def test_native_verification_requires_explicit_signature_rejection(self):
        target = release.TARGETS[-1]
        self.archive(target)
        manifest = self.dist / "build-manifest.json"
        manifest.write_text(json.dumps(self.manifest()))
        for code, message, accepted in (
            (1, "manifest verification failed: bad signature", True),
            (0, "manifest verification failed", False),
            (1, "unrelated failure", False),
        ):
            with self.subTest(code=code, message=message):
                def run(command, **kwargs):
                    self.assertTrue(command[0].endswith("sigil.exe"))
                    if command[1] == "--version":
                        return subprocess.CompletedProcess(command, 0, f"sigil {self.version}\n")
                    if Path(command[-1]) == manifest.resolve():
                        self.assertTrue(kwargs["check"])
                        return subprocess.CompletedProcess(command, 0)
                    modified = json.loads(Path(command[-1]).read_text())
                    self.assertNotEqual(modified["manifest"], self.manifest()["manifest"])
                    self.assertEqual(modified["signature"], self.manifest()["signature"])
                    return subprocess.CompletedProcess(command, code, message)

                with patch.object(release.subprocess, "run", side_effect=run):
                    if accepted:
                        release.verify(self.dist, self.version, target, "test-sha")
                    else:
                        with self.assertRaisesRegex(ValueError, "did not explicitly reject"):
                            release.verify(self.dist, self.version, target, "test-sha")

    def test_native_verification_stops_on_wrong_version_or_failed_signature(self):
        target = release.TARGETS[0]
        self.archive(target)
        (self.dist / "build-manifest.json").write_text(json.dumps(self.manifest()))
        with patch.object(release.subprocess, "run", return_value=
                          subprocess.CompletedProcess([], 0, "sigil 0.8.0")) as run:
            with self.assertRaisesRegex(ValueError, "version mismatch"):
                release.verify(self.dist, self.version, target, "test-sha")
            self.assertEqual(run.call_count, 1)
        with patch.object(release.subprocess, "run", side_effect=[
            subprocess.CompletedProcess([], 0, f"sigil {self.version}"),
            subprocess.CalledProcessError(1, ["sigil", "doctor"]),
        ]) as run:
            with self.assertRaises(subprocess.CalledProcessError):
                release.verify(self.dist, self.version, target, "test-sha")
            self.assertEqual(run.call_count, 2)


if __name__ == "__main__":
    unittest.main()
