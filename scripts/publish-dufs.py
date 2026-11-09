#!/usr/bin/env python3
"""Publish verified portable archives; prune old versions only after config publication."""

from __future__ import annotations

import argparse
import base64
from contextlib import nullcontext
from datetime import datetime
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import sys
import tarfile
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
import zipfile


ROOT = "/soft/desktop/"
VERSION_NAME = r"[0-9]{4}\.[0-9]{2}\.[0-9]{2}-[0-9a-f]{8}"
DIRECTORY_PATTERN = re.compile(rf"desktop-v([1-9][0-9]{{0,9}})-({VERSION_NAME})")
PLATFORMS = {
    "windows-x86_64": ("x86_64-pc-windows-msvc", ".zip"),
    "windows-aarch64": ("aarch64-pc-windows-msvc", ".zip"),
    "linux-x86_64": ("x86_64-unknown-linux-gnu", ".tar.gz"),
    "linux-aarch64": ("aarch64-unknown-linux-gnu", ".tar.gz"),
    "macos-x86_64": ("x86_64-apple-darwin", ".tar.gz"),
    "macos-aarch64": ("aarch64-apple-darwin", ".tar.gz"),
}
RETRY_STATUS = {408, 425, 429, 500, 502, 503, 504}
CHUNK_SIZE = 1024 * 1024


class PublishError(RuntimeError):
    pass


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        # Never forward credentials or trust an alternate public download origin.
        return None


def digest_stream(source) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    while chunk := source.read(CHUNK_SIZE):
        digest.update(chunk)
        size += len(chunk)
    return digest.hexdigest(), size


class DufsClient:
    def __init__(self, base_url: str, username: str, password: str):
        parsed = urlsplit(base_url)
        if (parsed.scheme != "https" or not parsed.hostname
                or parsed.username is not None or parsed.password is not None
                or parsed.path not in {"", "/"} or parsed.query or parsed.fragment
                or any(character.isspace() for character in base_url)):
            raise PublishError("--base-url must be an HTTPS origin without credentials or a path")
        if not username or not password or ":" in username:
            raise PublishError("Set TOPNODE_DUFS_USERNAME and TOPNODE_DUFS_PASSWORD")
        self.base_url = base_url.rstrip("/")
        self.authorization = "Basic " + base64.b64encode(
            f"{username}:{password}".encode("utf-8")
        ).decode("ascii")
        self.opener = build_opener(NoRedirect())

    def request(self, method, path, consume=lambda response: None, *,
                source=None, anonymous=False, allowed_statuses=()):
        for attempt in range(4):
            try:
                with source.open("rb") if source else nullcontext(None) as body:
                    headers = {"User-Agent": "TOPNODE-Desktop-Publisher/1", "Cache-Control": "no-cache"}
                    if not anonymous:
                        headers["Authorization"] = self.authorization
                    if source:
                        headers["Content-Length"] = str(source.stat().st_size)
                        headers["Content-Type"] = "application/octet-stream"
                    request = Request(self.base_url + path, data=body, headers=headers, method=method)
                    with self.opener.open(request, timeout=120) as response:
                        return consume(response)
            except HTTPError as error:
                status = error.code
                error.close()
                if status in allowed_statuses:
                    return None
                if status not in RETRY_STATUS or attempt == 3:
                    # Omit response text/URLs/exception details: servers can echo credentials.
                    raise PublishError(f"dufs {method} failed (HTTP {status})") from None
            except (URLError, OSError, http.client.HTTPException):
                if attempt == 3:
                    raise PublishError(f"dufs {method} failed after four attempts") from None
            time.sleep(2 ** attempt)
        raise AssertionError("unreachable")

    def directories(self, *, missing_ok=False) -> dict[str, int]:
        data = self.request("GET", ROOT + "?json", lambda response: response.read(4 * CHUNK_SIZE + 1),
                            allowed_statuses=(404,) if missing_ok else ())
        if data is None:
            return {}
        try:
            listing = json.loads(data)
            if not isinstance(listing, dict) or not isinstance(listing.get("paths"), list):
                raise ValueError
            result = {}
            for entry in listing["paths"]:
                if not isinstance(entry, dict):
                    raise ValueError
                name = entry.get("name")
                if not isinstance(name, str) or not isinstance(entry.get("path_type"), str):
                    raise ValueError
                match = DIRECTORY_PATTERN.fullmatch(name)
                if entry["path_type"] == "Dir" and match and int(match[1]) <= 2_100_000_000:
                    result[name] = int(match[1])
            return result
        except (ValueError, TypeError):
            raise PublishError("dufs returned an invalid directory listing; refusing cleanup") from None

    def create_directory(self, path):
        # WebDAV reports Method Not Allowed when a collection already exists.
        self.request("MKCOL", path, allowed_statuses=(405,))

    def upload(self, path, source):
        self.request("PUT", path, source=source)

    def verify(self, path, expected):
        actual = self.request("GET", path, digest_stream, anonymous=True)
        if actual != expected:
            raise PublishError("Anonymous download does not match the local archive/checksum file")

    def completion_checksums(self, directory):
        """The checksum file is written only after all six packages pass verification."""
        match = DIRECTORY_PATTERN.fullmatch(directory)
        if match is None:
            raise PublishError("Invalid desktop release directory")
        data = self.request("GET", ROOT + directory + "/SHA256SUMS.txt",
                            lambda response: response.read(8193), anonymous=True, allowed_statuses=(404,))
        if data is None or len(data) > 8192:
            return None
        expected = {
            f"topnode-desktop-{match[2]}-{platform}{extension}"
            for platform, (_, extension) in PLATFORMS.items()
        }
        try:
            checksums = {}
            for line in data.decode("ascii").splitlines():
                digest, filename = line.split("  ", maxsplit=1)
                if re.fullmatch(r"[0-9a-f]{64}", digest) is None or filename in checksums:
                    return None
                checksums[filename] = digest
            return checksums if set(checksums) == expected else None
        except (UnicodeDecodeError, ValueError):
            return None

    def delete(self, name):
        if DIRECTORY_PATTERN.fullmatch(name) is None:
            raise PublishError("Refusing to delete an unmanaged directory")
        self.request("DELETE", ROOT + name + "/", allowed_statuses=(404,))


def archive_manifest(path: Path, stem: str) -> dict:
    manifest_name = stem + "/BUILD-INFO.json"
    try:
        if path.suffix == ".zip":
            with zipfile.ZipFile(path) as archive:
                members = archive.infolist()
                if sum(item.filename == manifest_name for item in members) != 1:
                    raise ValueError
                info = archive.getinfo(manifest_name)
                if info.file_size > CHUNK_SIZE or archive.testzip() is not None:
                    raise ValueError
                raw = archive.read(info)
        else:
            with tarfile.open(path, mode="r|gz") as archive:
                raw = None
                for member in archive:
                    if member.isfile():
                        with archive.extractfile(member) as content:
                            if member.name == manifest_name:
                                if raw is not None or member.size > CHUNK_SIZE:
                                    raise ValueError
                                raw = content.read()
                            else:
                                digest_stream(content)
                if raw is None:
                    raise ValueError
        manifest = json.loads(raw)
        if not isinstance(manifest, dict) or manifest.get("schemaVersion") != 1:
            raise ValueError
        return manifest
    except (OSError, ValueError, KeyError, zipfile.BadZipFile, tarfile.TarError, EOFError):
        raise PublishError(f"Invalid archive or BUILD-INFO.json: {path.name}") from None


def validate_release(version_code: int, version_name: str, git_commit: str) -> str:
    if not 1 <= version_code <= 2_100_000_000:
        raise PublishError("--version-code must be between 1 and 2100000000")
    if re.fullmatch(VERSION_NAME, version_name) is None:
        raise PublishError("--version-name must use YYYY.MM.DD-8sha")
    try:
        datetime.strptime(version_name[:10], "%Y.%m.%d")
    except ValueError:
        raise PublishError("--version-name contains an invalid date") from None
    if (re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", git_commit) is None
            or version_name[-8:] != git_commit[:8]):
        raise PublishError("--git-commit must be a full Git SHA matching --version-name")
    return f"desktop-v{version_code}-{version_name}"


def prepare_assets(assets: Path, version_code: int, version_name: str, git_commit: str):
    expected = {
        f"topnode-desktop-{version_name}-{platform}{extension}": target
        for platform, (target, extension) in PLATFORMS.items()
    }
    if not assets.is_dir():
        raise PublishError("--assets must be an existing directory")
    actual = {path.name for path in assets.iterdir()}
    if actual - {"SHA256SUMS.txt"} != set(expected):
        raise PublishError("Expected exactly the six portable archives in --assets")
    checksums = {}
    for filename, target in sorted(expected.items()):
        path = assets / filename
        if not path.is_file() or path.is_symlink():
            raise PublishError(f"Expected an archive file: {filename}")
        stem = filename.removesuffix(".zip").removesuffix(".tar.gz")
        application = archive_manifest(path, stem).get("application")
        if (not isinstance(application, dict)
                or type(application.get("versionCode")) is not int
                or application.get("versionCode") != version_code
                or application.get("versionName") != version_name
                or application.get("gitCommit") != git_commit
                or application.get("target") != target
                or application.get("supportTier") != "supported"):
            raise PublishError(f"BUILD-INFO.json does not match this release: {filename}")
        with path.open("rb") as source:
            checksums[filename] = digest_stream(source)
    checksum_file = assets / "SHA256SUMS.txt"
    if checksum_file.is_symlink():
        raise PublishError("SHA256SUMS.txt must not be a symbolic link")
    checksum_file.write_text(
        "".join(f"{digest}  {filename}\n" for filename, (digest, _) in checksums.items()),
        encoding="utf-8", newline="\n",
    )
    with checksum_file.open("rb") as source:
        checksums[checksum_file.name] = digest_stream(source)
    return checksums


def reject_version_conflicts(directories: dict[str, int], directory: str, version_code: int):
    if any(code == version_code and name != directory
           for name, code in directories.items()):
        raise PublishError("A conflicting version already exists on dufs; refusing this release")


def publish(client, command, assets, version_code, version_name, git_commit):
    directory = validate_release(version_code, version_name, git_commit)
    checksums = prepare_assets(assets, version_code, version_name, git_commit)
    directories = client.directories(missing_ok=command == "upload")
    reject_version_conflicts(directories, directory, version_code)
    release_path = ROOT + directory + "/"
    completed = client.completion_checksums(directory) if directory in directories else None
    archive_checksums = {name: digest for name, (digest, _) in checksums.items() if name != "SHA256SUMS.txt"}
    if completed is not None and completed != archive_checksums:
        raise PublishError("A complete release already exists with different bytes; refusing to overwrite it")
    if command == "upload":
        if completed is None:
            for path in ("/soft/", ROOT, release_path):
                client.create_directory(path)
            for filename in archive_checksums:
                client.upload(release_path + filename, assets / filename)
                client.verify(release_path + filename, checksums[filename])
            reject_version_conflicts(client.directories(), directory, version_code)
            client.upload(release_path + "SHA256SUMS.txt", assets / "SHA256SUMS.txt")
            client.verify(release_path + "SHA256SUMS.txt", checksums["SHA256SUMS.txt"])
    elif command != "cleanup":
        raise PublishError("Unknown publish command")
    elif directory not in directories:
        raise PublishError("Current release directory is missing; refusing cleanup")
    elif completed is None:
        raise PublishError("Current release is incomplete; refusing cleanup")
    # Anonymous, streaming SHA256 checks guard both config publication and deletion.
    if completed is not None:
        for filename, expected in checksums.items():
            client.verify(release_path + filename, expected)
    directories = client.directories()
    reject_version_conflicts(directories, directory, version_code)
    if directory not in directories:
        raise PublishError("Current release directory disappeared")
    if command == "cleanup":
        completed_directories = [
            name for name in directories if client.completion_checksums(name) is not None
        ]
        if directory not in completed_directories:
            raise PublishError("Current release completion marker disappeared; refusing cleanup")
        # The bootstrap now points to this release, even when its code is lower.
        retained = {directory}
        retained.update(sorted(
            (name for name in completed_directories if name != directory),
            key=directories.get, reverse=True,
        )[:1])
        for name, code in sorted(directories.items(), key=lambda item: item[1]):
            if name not in retained:
                reject_version_conflicts(client.directories(), directory, version_code)
                client.delete(name)
                print(f"Deleted old desktop version: {name}")
    print(f"{command}: verified {len(checksums)} files in {directory}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("upload", "cleanup"))
    parser.add_argument("--assets", type=Path, required=True)
    parser.add_argument("--base-url", default="https://soft.topstatic.top")
    parser.add_argument("--version-code", type=int, required=True)
    parser.add_argument("--version-name", required=True)
    parser.add_argument("--git-commit", required=True)
    arguments = parser.parse_args()
    try:
        client = DufsClient(arguments.base_url, os.environ.get("TOPNODE_DUFS_USERNAME", ""),
                            os.environ.get("TOPNODE_DUFS_PASSWORD", ""))
        publish(client, arguments.command, arguments.assets, arguments.version_code,
                arguments.version_name, arguments.git_commit)
    except (PublishError, OSError) as error:
        message = str(error) if isinstance(error, PublishError) else "Unable to read or write release assets"
        print(f"Error: {message}", file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
