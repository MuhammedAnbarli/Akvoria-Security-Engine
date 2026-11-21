#!/usr/bin/env python3
"""Build and verify the AKVORIA ASE release archives.

Produces:
  AKVORIA-ASE-SOURCE.zip      complete GitHub-ready source tree
  AKVORIA-ASE-USER-TEST.zip   user acceptance test kit
  SHA256SUMS.txt              checksums for both archives

Excludes runtime state, credentials, caches and temporary files, then scans the
resulting archives to prove nothing sensitive was packaged.
"""
from __future__ import annotations

import hashlib
import re
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCE_ZIP = ROOT / "AKVORIA-ASE-SOURCE.zip"
USER_ZIP = ROOT / "AKVORIA-ASE-USER-TEST.zip"
SUMS = ROOT / "SHA256SUMS.txt"

EXCLUDED_DIRS = {"__pycache__", ".git", ".venv", "venv", "dist", "build",
                 "storage", ".pytest_cache", ".mypy_cache", "node_modules",
                 ".idea", ".vscode", ".agent_tmp"}
EXCLUDED_SUFFIXES = {".pyc", ".pyo", ".db", ".db-journal", ".db-wal", ".db-shm",
                     ".log", ".pid", ".key", ".pem", ".zip", ".sha256"}
EXCLUDED_NAMES = {"ase_api.key", "ase.json", "quarantine.json", "SHA256SUMS.txt"}

# A packaged file must not contain any of these.
SECRET_PATTERNS = [
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"sk-[A-Za-z0-9]{32,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
]

# Fixture hashes and placeholder keys used by the test suite are not secrets.
ALLOWED_CONTEXT = ("tests/", "docs/", "examples/", "scripts/", "README")


def is_excluded(path: Path) -> bool:
    if any(part in EXCLUDED_DIRS for part in path.parts):
        return True
    if path.suffix in EXCLUDED_SUFFIXES:
        return True
    if path.name in EXCLUDED_NAMES:
        return True
    return False


def collect_source_files():
    files = []
    for path in sorted(ROOT.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(ROOT)
        if is_excluded(relative):
            continue
        if path.name in {"AKVORIA-ASE-SOURCE.zip", "AKVORIA-ASE-USER-TEST.zip"}:
            continue
        files.append(relative)
    return files


def scan_for_secrets(files):
    findings = []
    for relative in files:
        if relative.suffix not in {".py", ".md", ".txt", ".json", ".yml",
                                   ".yaml", ".toml", ".sh", ".ps1", ""}:
            continue
        try:
            text = (ROOT / relative).read_text("utf-8", errors="ignore")
        except OSError:
            continue
        for pattern in SECRET_PATTERNS:
            for match in pattern.finditer(text):
                findings.append((relative, match.group(0)[:12]))
    return findings


def write_archive(target, files):
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
        for relative in files:
            archive.write(ROOT / relative, relative.as_posix())
    return target


def verify_archive(target):
    """Reopen the archive and prove it holds no excluded or sensitive member."""
    problems = []
    with zipfile.ZipFile(target) as archive:
        names = archive.namelist()
        if not names:
            problems.append("%s is empty" % target.name)
        for name in names:
            member = Path(name)
            if any(part in EXCLUDED_DIRS for part in member.parts):
                problems.append("%s contains excluded dir: %s" % (target.name, name))
            if member.suffix in EXCLUDED_SUFFIXES:
                problems.append("%s contains excluded type: %s" % (target.name, name))
            if member.name in EXCLUDED_NAMES:
                problems.append("%s contains runtime file: %s" % (target.name, name))
            if member.name.endswith(("ase_api.key", ".db", ".log")):
                problems.append("%s contains runtime artifact: %s" % (target.name, name))
        bad = archive.testzip()
        if bad:
            problems.append("%s has a corrupt member: %s" % (target.name, bad))
    return problems, len(names)


def sha256_of(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_user_kit():
    """Assemble the user acceptance test kit in a temporary directory."""
    import shutil
    import tempfile

    staging = Path(tempfile.mkdtemp(prefix="ase-user-kit-"))
    try:
        (staging / "akvoria-ase").mkdir()
        keep = ["main.py", "pyproject.toml", "requirements.txt",
                "requirements-optional.txt", "README.md", "LICENSE",
                "SECURITY.md", "CHANGELOG.md", "RELEASE-NOTES-0.1.0-BETA.md"]
        for name in keep:
            source = ROOT / name
            if source.exists():
                shutil.copy2(source, staging / "akvoria-ase" / name)

        for directory in ("core", "modules", "config", "platform", "examples", "docs"):
            source = ROOT / directory
            if not source.is_dir():
                continue
            destination = staging / "akvoria-ase" / directory
            destination.mkdir(parents=True, exist_ok=True)
            for path in sorted(source.rglob("*")):
                if not path.is_file():
                    continue
                relative = path.relative_to(source)
                if is_excluded(relative):
                    continue
                target = destination / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(path, target)

        shutil.copy2(ROOT / "scripts" / "verify_install.py",
                     staging / "akvoria-ase" / "verify_install.py")

        with zipfile.ZipFile(USER_ZIP, "w", zipfile.ZIP_DEFLATED) as archive:
            for path in sorted(staging.rglob("*")):
                if path.is_file():
                    archive.write(path, path.relative_to(staging).as_posix())
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    return USER_ZIP


def main():
    print("== collecting source files ==")
    files = collect_source_files()
    print("   %d files" % len(files))

    print("== scanning for secrets ==")
    findings = scan_for_secrets(files)
    if findings:
        print("   REFUSING TO PACKAGE — potential secrets:", file=sys.stderr)
        for relative, snippet in findings:
            print("   %s: %s..." % (relative, snippet), file=sys.stderr)
        return 1
    print("   clean")

    print("== building %s ==" % SOURCE_ZIP.name)
    write_archive(SOURCE_ZIP, files)

    print("== building %s ==" % USER_ZIP.name)
    build_user_kit()

    print("== verifying archives ==")
    failures = []
    for archive in (SOURCE_ZIP, USER_ZIP):
        problems, count = verify_archive(archive)
        if problems:
            failures.extend(problems)
            print("   %s: %d problems" % (archive.name, len(problems)))
        else:
            print("   %s: %d members, integrity OK" % (archive.name, count))
    if failures:
        for item in failures:
            print("   - %s" % item, file=sys.stderr)
        return 1

    print("== checksums ==")
    lines = []
    for archive in (SOURCE_ZIP, USER_ZIP):
        digest = sha256_of(archive)
        lines.append("%s  %s" % (digest, archive.name))
        print("   %s  %s" % (digest, archive.name))
    SUMS.write_text("\n".join(lines) + "\n", "utf-8")

    print("\nRelease artifacts ready in %s" % ROOT)
    return 0


if __name__ == "__main__":
    sys.exit(main())
