"""Collect all release binaries and verify signed manifests on native runners."""

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import zipfile


TARGETS = (
    "x86_64-unknown-linux-musl",
    "aarch64-unknown-linux-musl",
    "aarch64-apple-darwin",
    "x86_64-pc-windows-msvc",
    "aarch64-pc-windows-msvc",
)
BINARIES = ("sigil", "sigil-sender", "sigil-server", "sigil-sign", "sigil-mcp", "sigil-hook")
MAX_BINARY_BYTES = 256 * 1024 * 1024


def archive_name(version, target):
    if not re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]+)?", version):
        raise ValueError("invalid release version")
    if target not in TARGETS:
        raise ValueError("unsupported release target")
    suffix = ".zip" if target.endswith("-windows-msvc") else ".tar.gz"
    return f"sigil-{version}-{target}{suffix}"


def extract_binaries(dist, version, target, work):
    """Read only exact regular-file members; never extract archive-supplied paths."""
    archive = dist / archive_name(version, target)
    prefix = f"sigil-{version}-{target}"
    suffix = ".exe" if target.endswith("-windows-msvc") else ""
    expected = {f"{prefix}/{name}{suffix}": name for name in BINARIES}
    files = {}

    def copy_member(name, size, regular, reader):
        name = name.replace("\\", "/")
        if name not in expected:
            return
        binary = expected[name]
        if binary in files:
            raise ValueError(f"duplicate binary: {target}/{binary}")
        if not regular or not 0 < size <= MAX_BINARY_BYTES:
            raise ValueError(f"invalid binary member: {target}/{binary}")
        destination = work / target / (binary + suffix)
        destination.parent.mkdir(parents=True, exist_ok=True)
        with reader() as source, destination.open("xb") as output:
            shutil.copyfileobj(source, output)
        if destination.stat().st_size != size:
            raise ValueError(f"binary size mismatch: {target}/{binary}")
        destination.chmod(0o700)
        files[binary] = destination

    if archive.suffix == ".zip":
        with zipfile.ZipFile(archive) as bundle:
            for member in bundle.infolist():
                mode = stat.S_IFMT(member.external_attr >> 16)
                copy_member(member.filename, member.file_size,
                            not member.is_dir() and mode in (0, stat.S_IFREG),
                            lambda member=member: bundle.open(member))
    else:
        with tarfile.open(archive, "r:gz") as bundle:
            for member in bundle:
                copy_member(member.name, member.size, member.isfile(),
                            lambda member=member: bundle.extractfile(member))
    if set(files) != set(BINARIES):
        raise ValueError(f"missing binaries for {target}: {sorted(set(BINARIES) - set(files))}")
    return files


def validate_manifest(path, git_sha=None):
    signed = json.loads(path.read_text(encoding="utf-8"))
    manifest = signed["manifest"]
    if manifest["schema_version"] != 1:
        raise ValueError("unsupported manifest schema")
    if git_sha is not None and manifest["git_sha"] != git_sha:
        raise ValueError("manifest commit mismatch")
    entries = manifest["artifacts"]
    pairs = [(entry["name"], entry["target"]) for entry in entries]
    expected = {(name, target) for target in TARGETS for name in BINARIES}
    if len(pairs) != len(expected) or set(pairs) != expected:
        raise ValueError("manifest must contain exactly 30 unique name/target pairs")
    if any(not re.fullmatch(r"[0-9a-f]{64}", entry["blake3"]) for entry in entries):
        raise ValueError("invalid artifact digest")
    return signed


def sign(dist, version, key, git_sha, run_url, signer=None):
    expected = {archive_name(version, target) for target in TARGETS}
    found = {path.name for path in dist.iterdir() if path.name.endswith((".tar.gz", ".zip"))}
    if found != expected:
        raise ValueError(f"archive set mismatch: missing={sorted(expected - found)}, extra={sorted(found - expected)}")
    # Nothing is signed until every archive and every binary has been checked.
    with tempfile.TemporaryDirectory(prefix="sigil-manifest-") as temp:
        work = Path(temp)
        artifacts = {target: extract_binaries(dist, version, target, work) for target in TARGETS}
        executable = signer or artifacts["x86_64-unknown-linux-musl"]["sigil-sign"]
        output = work / "build-manifest.json"
        command = [str(executable), "manifest", "--key", str(key),
                   "--git-sha", git_sha, "--run-url", run_url, "--out", str(output)]
        for target, files in artifacts.items():
            for name, path in files.items():
                if "," in str(path):
                    raise ValueError("artifact paths cannot contain commas")
                command.extend(["--artifact", f"name={name},target={target},file={path}"])
        # The signer needs the protected key file, not a second copy in its environment.
        environment = {k: v for k, v in os.environ.items() if k != "SIGNING_KEY"}
        subprocess.run(command, check=True, env=environment)
        validate_manifest(output, git_sha)
        shutil.copyfile(output, dist / "build-manifest.json")
    print("Signed manifest covers all 30 release binaries")


def verify(dist, version, target, git_sha):
    manifest = (dist / "build-manifest.json").resolve()
    signed = validate_manifest(manifest, git_sha)
    with tempfile.TemporaryDirectory(prefix="sigil-verify-") as temp:
        work = Path(temp)
        executable = extract_binaries(dist, version, target, work)["sigil"]
        result = subprocess.run([str(executable), "--version"], check=True,
                                capture_output=True, text=True)
        if result.stdout.strip() != f"sigil {version}":
            raise ValueError("downloaded binary version mismatch")
        command = [str(executable), "doctor", "--verify-self", "--manifest"]
        subprocess.run(command + [str(manifest)], check=True)
        # Verify that the same native binary rejects a modified signed payload.
        entry = next(e for e in signed["manifest"]["artifacts"]
                     if e["name"] == "sigil" and e["target"] == target)
        entry["blake3"] = ("1" if entry["blake3"][0] == "0" else "0") + entry["blake3"][1:]
        tampered = work / "tampered-manifest.json"
        tampered.write_text(json.dumps(signed), encoding="utf-8")
        rejected = subprocess.run(command + [str(tampered)], capture_output=True, text=True)
        if rejected.returncode == 0 or "manifest verification failed" not in rejected.stdout:
            raise ValueError("native verifier did not explicitly reject the tampered signature")
    print(f"Verified {target}: version, signed hash, and signature tamper rejection")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("sign", "verify"):
        command = commands.add_parser(name)
        command.add_argument("--dist", required=True, type=Path)
        command.add_argument("--version", required=True)
        command.add_argument("--git-sha", required=True)
        if name == "sign":
            command.add_argument("--key", required=True, type=Path)
            command.add_argument("--run-url", required=True)
            command.add_argument("--signer", type=Path)
        else:
            command.add_argument("--target", choices=TARGETS, required=True)
    args = vars(parser.parse_args())
    operation = args.pop("command")
    try:
        (sign if operation == "sign" else verify)(**args)
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError,
            tarfile.TarError, zipfile.BadZipFile) as error:
        parser.exit(1, f"release manifest failed: {error}\n")


if __name__ == "__main__":
    main()
