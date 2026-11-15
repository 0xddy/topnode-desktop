#!/usr/bin/env python3
"""Publish verified desktop candidates as a GitHub prerelease using gh."""

import argparse
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile


SPEC = importlib.util.spec_from_file_location("publish_dufs", Path(__file__).with_name("publish-dufs.py"))
assets_helper = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(assets_helper)
PublishError = assets_helper.PublishError


class GitHub:
    def __init__(self, repository):
        if re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) is None:
            raise PublishError("--repository must use OWNER/REPO")
        self.repository = repository

    def release(self, *arguments):
        subprocess.run(["gh", "release", *arguments, "--repo", self.repository], check=True)

    def api(self, path, *, missing_ok=False):
        result = subprocess.run(
            ["gh", "api", f"repos/{self.repository}/{path}"],
            capture_output=True, text=True, check=False,
        )
        if result.returncode:
            if missing_ok and "(HTTP 404)" in result.stderr:
                return None
            raise PublishError(f"GitHub API request failed: {path}")
        return json.loads(result.stdout)


def check_tag(client, tag, commit, *, required=False):
    reference = client.api(f"git/ref/tags/{tag}", missing_ok=not required)
    if reference is None:
        if required:
            raise PublishError("Published release tag is missing")
        return
    obj = reference["object"]
    # Resolve annotated tags as well as the lightweight tags created by GitHub.
    for _ in range(10):
        if obj["type"] == "commit":
            if obj["sha"] != commit:
                raise PublishError("Release tag targets a different Git commit")
            return
        if obj["type"] != "tag":
            break
        obj = client.api(f"git/tags/{obj['sha']}")["object"]
    raise PublishError("Release tag does not resolve to a commit")


def verify_downloads(client, tag, checksums):
    with tempfile.TemporaryDirectory(prefix="topnode-release-") as temporary:
        client.release("download", tag, "--dir", temporary)
        files = {path.name: path for path in Path(temporary).iterdir()}
        if files.keys() != checksums.keys():
            raise PublishError("GitHub Release must contain exactly the eight packages and checksum file")
        for name, expected in checksums.items():
            path = files[name]
            if path.is_symlink() or not path.is_file():
                raise PublishError(f"Invalid GitHub Release asset: {name}")
            with path.open("rb") as source:
                if assets_helper.digest_stream(source) != expected:
                    raise PublishError(f"GitHub Release asset differs from this build: {name}")


def publish(client, assets, version_code, version_name, commit, core_version, source_run_id):
    tag = assets_helper.validate_release(version_code, version_name, commit)
    if re.fullmatch(r"[1-9][0-9]*", source_run_id or "") is None:
        raise PublishError("--source-run-id must be a positive Actions run ID")
    checksums = assets_helper.prepare_assets(assets, version_code, version_name, commit, candidate=True)
    existing = client.api(f"releases/tags/{tag}", missing_ok=True)
    check_tag(client, tag, commit, required=existing is not None and not existing["draft"])
    url = f"https://github.com/{client.repository}/releases/tag/{tag}"
    if existing is not None and not existing["draft"]:
        verify_downloads(client, tag, checksums)
        return url
    if existing is not None and existing["target_commitish"] != commit:
        raise PublishError("Existing draft targets a different Git commit")

    notes = (
        f"TOPNODE Desktop {version_name} ({version_code}) — candidate build\n\n"
        f"Source commit: {commit}\n\n"
        f"Bundled sing-box-acp: {core_version} (Naive enabled).\n\n"
        f"Build and native TCP/UoT evidence: https://github.com/{client.repository}/actions/runs/{source_run_id}\n\n"
        "Assets: six portable archives, two Ubuntu installers, and SHA256SUMS.txt.\n\n"
        "These packages retain supportTier=candidate; full system acceptance is pending. "
        "Check the packaged app's Info.plist for this build's minimum macOS version. "
        "macOS 12.7.6 runtime testing has not been completed. "
        "The macOS TUN authorization chain requires Developer ID signing and a notarized installation; "
        "these archives are unsigned candidates.\n"
    )
    with tempfile.TemporaryDirectory(prefix="topnode-release-notes-") as temporary:
        notes_file = Path(temporary) / "notes.md"
        notes_file.write_text(notes, encoding="utf-8", newline="\n")
        command = "create" if existing is None else "edit"
        client.release(command, tag, "--draft", "--prerelease", "--latest=false", "--target", commit,
                       "--title", f"TOPNODE Desktop {version_name} (candidate)", "--notes-file", str(notes_file))
    client.release("upload", tag, *(str(assets / name) for name in checksums), "--clobber")
    verify_downloads(client, tag, checksums)
    check_tag(client, tag, commit)
    client.release("edit", tag, "--draft=false", "--prerelease", "--latest=false")
    check_tag(client, tag, commit, required=True)
    return url


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--assets", type=Path, required=True)
    parser.add_argument("--version-code", type=int, required=True)
    parser.add_argument("--version-name", required=True)
    parser.add_argument("--git-commit", required=True)
    parser.add_argument("--core-version", required=True)
    parser.add_argument("--source-run-id", required=True)
    arguments = parser.parse_args()
    try:
        url = publish(GitHub(arguments.repository), arguments.assets, arguments.version_code,
                      arguments.version_name, arguments.git_commit, arguments.core_version, arguments.source_run_id)
        print(url)
    except (PublishError, OSError, ValueError, subprocess.CalledProcessError) as error:
        message = str(error) if isinstance(error, PublishError) else "Unable to publish GitHub Release"
        print(f"Error: {message}", file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
