#!/usr/bin/env python3
"""Fetch one exact official sing-box release asset and verify its digest."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import urllib.request
import zipfile


MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_MEMBER_BYTES = 256 * 1024 * 1024
MAX_CHECK_CONFIGURATION_BYTES = 1024 * 1024
VERSION_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
DIGEST_PATTERN = re.compile(r"^sha256:([0-9a-f]{64})$")


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--asset", required=True)
    parser.add_argument("--check-config", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args()


def api_request(url: str) -> urllib.request.Request:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "TOPNODE-Desktop-release-builder",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return urllib.request.Request(url, headers=headers)


def load_release(version: str) -> dict[str, object]:
    url = f"https://api.github.com/repos/SagerNet/sing-box/releases/tags/v{version}"
    with urllib.request.urlopen(api_request(url), timeout=30) as response:
        if response.status != 200:
            raise RuntimeError(f"sing-box release API returned HTTP {response.status}")
        return json.load(response)


def select_asset(release: dict[str, object], asset_name: str) -> dict[str, object]:
    assets = release.get("assets")
    if not isinstance(assets, list):
        raise RuntimeError("sing-box release API did not return an asset list")
    matches = [asset for asset in assets if isinstance(asset, dict) and asset.get("name") == asset_name]
    if len(matches) != 1:
        raise RuntimeError(f"expected exactly one official asset named {asset_name!r}")
    return matches[0]


def download_asset(url: str, destination: Path) -> str:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "TOPNODE-Desktop-release-builder"},
    )
    digest = hashlib.sha256()
    total = 0
    with urllib.request.urlopen(request, timeout=60) as response, destination.open("wb") as output:
        length = response.headers.get("Content-Length")
        if length is not None and int(length) > MAX_ARCHIVE_BYTES:
            raise RuntimeError("sing-box release asset exceeds the size limit")
        while chunk := response.read(1024 * 1024):
            total += len(chunk)
            if total > MAX_ARCHIVE_BYTES:
                raise RuntimeError("sing-box release asset exceeds the size limit")
            digest.update(chunk)
            output.write(chunk)
    return digest.hexdigest()


def selected_basename(name: str, binary_name: str) -> str | None:
    basename = PurePosixPath(name.replace("\\", "/")).name
    if basename == binary_name or basename == "LICENSE" or basename.startswith("libcronet."):
        return basename
    return None


def extract_zip(archive: Path, output: Path, binary_name: str) -> list[str]:
    extracted: list[str] = []
    with zipfile.ZipFile(archive) as bundle:
        for member in bundle.infolist():
            basename = selected_basename(member.filename, binary_name)
            if basename is None or member.is_dir():
                continue
            mode = member.external_attr >> 16
            if stat.S_ISLNK(mode) or member.file_size > MAX_MEMBER_BYTES:
                raise RuntimeError(f"unsafe sing-box archive member: {member.filename}")
            destination = output / ("LICENSE" if basename == "LICENSE" else f"core/{basename}")
            destination.parent.mkdir(parents=True, exist_ok=True)
            with bundle.open(member) as source, destination.open("wb") as target:
                shutil.copyfileobj(source, target)
            extracted.append(basename)
    return extracted


def extract_tar(archive: Path, output: Path, binary_name: str) -> list[str]:
    extracted: list[str] = []
    with tarfile.open(archive, "r:gz") as bundle:
        for member in bundle:
            basename = selected_basename(member.name, binary_name)
            if basename is None or member.isdir():
                continue
            if not member.isfile() or member.size > MAX_MEMBER_BYTES:
                raise RuntimeError(f"unsafe sing-box archive member: {member.name}")
            source = bundle.extractfile(member)
            if source is None:
                raise RuntimeError(f"unable to read sing-box archive member: {member.name}")
            destination = output / ("LICENSE" if basename == "LICENSE" else f"core/{basename}")
            destination.parent.mkdir(parents=True, exist_ok=True)
            with source, destination.open("wb") as target:
                shutil.copyfileobj(source, target)
            extracted.append(basename)
    return extracted


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def core_environment(binary: Path) -> dict[str, str]:
    environment = os.environ.copy()
    core_directory = str(binary.parent)
    for name in ("PATH", "LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH"):
        previous = environment.get(name, "")
        environment[name] = core_directory if not previous else core_directory + os.pathsep + previous
    return environment


def probe_version(binary: Path, expected_version: str) -> str:
    result = subprocess.run(
        [str(binary), "version"],
        cwd=binary.parent,
        env=core_environment(binary),
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    version_output = (result.stdout + "\n" + result.stderr).strip()
    if result.returncode != 0:
        raise RuntimeError(f"downloaded sing-box version probe failed: {version_output[:4096]}")
    expected = re.compile(rf"(?<![0-9.]){re.escape(expected_version)}(?![0-9.])")
    if expected.search(version_output) is None:
        raise RuntimeError(
            f"downloaded sing-box does not report version {expected_version}: {version_output[:4096]}"
        )
    return version_output[:4096]


def probe_configuration(binary: Path, configuration: Path) -> tuple[str, str]:
    if not configuration.is_file():
        raise RuntimeError("--check-config must be an existing file")
    payload = configuration.read_bytes()
    if not payload or len(payload) > MAX_CHECK_CONFIGURATION_BYTES:
        raise RuntimeError("--check-config must contain 1-1048576 bytes")
    result = subprocess.run(
        [str(binary), "check", "-c", "stdin"],
        cwd=binary.parent,
        env=core_environment(binary),
        input=payload,
        capture_output=True,
        timeout=15,
        check=False,
    )
    check_output = (result.stdout + b"\n" + result.stderr).decode("utf-8", errors="replace").strip()
    if result.returncode != 0:
        raise RuntimeError(
            f"downloaded sing-box rejected the compatibility configuration: {check_output[:4096]}"
        )
    return sha256_file(configuration), check_output[:4096]


def main() -> None:
    arguments = parse_arguments()
    version = arguments.version.strip()
    asset_name = arguments.asset.strip()
    if VERSION_PATTERN.fullmatch(version) is None:
        raise RuntimeError("--version must use major.minor.patch without a leading v")
    expected_suffix = ".zip" if "windows" in asset_name else ".tar.gz"
    expected_name = re.compile(
        rf"^sing-box-{re.escape(version)}-(windows|linux|darwin)-(amd64|arm64)"
        rf"{re.escape(expected_suffix)}$"
    )
    if expected_name.fullmatch(asset_name) is None:
        raise RuntimeError("--asset is not an expected stable sing-box desktop asset name")
    output = arguments.output.resolve()
    if output.exists() and any(output.iterdir()):
        raise RuntimeError(f"refusing to use non-empty output directory: {output}")
    output.mkdir(parents=True, exist_ok=True)

    release = load_release(version)
    asset = select_asset(release, asset_name)
    digest_match = DIGEST_PATTERN.fullmatch(str(asset.get("digest", "")))
    if digest_match is None:
        raise RuntimeError("official GitHub asset is missing a usable sha256 digest")
    download_url = str(asset.get("browser_download_url", ""))
    if not download_url.startswith("https://github.com/SagerNet/sing-box/releases/download/"):
        raise RuntimeError("official GitHub asset returned an unexpected download URL")

    with tempfile.TemporaryDirectory(prefix="topnode-sing-box-") as temporary:
        archive = Path(temporary) / asset_name
        actual_digest = download_asset(download_url, archive)
        if actual_digest != digest_match.group(1):
            raise RuntimeError("sing-box archive SHA-256 does not match the GitHub release digest")
        binary_name = "sing-box.exe" if "windows" in asset_name else "sing-box"
        extracted = (
            extract_zip(archive, output, binary_name)
            if asset_name.endswith(".zip")
            else extract_tar(archive, output, binary_name)
        )

    if extracted.count(binary_name) != 1 or extracted.count("LICENSE") != 1:
        raise RuntimeError("sing-box archive does not contain exactly one binary and LICENSE")
    binary = output / "core" / binary_name
    if os.name != "nt":
        binary.chmod(0o755)
        for companion in binary.parent.glob("libcronet.*"):
            companion.chmod(0o755)
    version_output = probe_version(binary, version)
    runtime_names = {
        path.name for path in (output / "core").iterdir() if path.is_file()
    }
    if "with_purego" in version_output and not any(
        name.startswith("libcronet.") for name in runtime_names
    ):
        raise RuntimeError("this sing-box build requires a libcronet companion")
    check_sha256, check_output = probe_configuration(binary, arguments.check_config.resolve())
    runtime_files = [
        {"name": path.name, "sha256": sha256_file(path)}
        for path in sorted((output / "core").iterdir())
        if path.is_file()
    ]
    metadata = {
        "repository": "SagerNet/sing-box",
        "releaseTag": f"v{version}",
        "version": version,
        "asset": asset_name,
        "assetSha256": actual_digest,
        "assetUrl": download_url,
        "licenseSha256": sha256_file(output / "LICENSE"),
        "runtimeFiles": runtime_files,
        "versionOutput": version_output,
        "compatibilityCheck": {
            "configurationSha256": check_sha256,
            "output": check_output,
        },
    }
    (output / "source.json").write_text(
        json.dumps(metadata, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(metadata, ensure_ascii=False))


if __name__ == "__main__":
    main()
