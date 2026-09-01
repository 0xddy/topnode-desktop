#!/usr/bin/env python3
"""Create a deterministic TOPNODE Desktop portable archive and build manifest."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import gzip
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import zipfile


VERSION_NAME_PATTERN = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._-]{0,63}$")
TARGET_PATTERN = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._-]{0,63}$")
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40,64}$")
REQUIRED_STAGE_FILES = (
    "THIRD_PARTY_NOTICES.md",
    "runtime/startup.json",
)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stage", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--cargo-lock", required=True, type=Path)
    parser.add_argument("--sing-box-metadata", required=True, type=Path)
    parser.add_argument("--target", required=True)
    parser.add_argument("--platform-label", required=True)
    parser.add_argument("--version-code", required=True, type=int)
    parser.add_argument("--version-name", required=True)
    parser.add_argument("--git-commit", required=True)
    parser.add_argument("--source-date-epoch", required=True, type=int)
    return parser.parse_args()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def validate_arguments(arguments: argparse.Namespace) -> None:
    if not arguments.stage.is_dir():
        raise RuntimeError("--stage must be an existing directory")
    if not arguments.cargo_lock.is_file() or not arguments.sing_box_metadata.is_file():
        raise RuntimeError("Cargo.lock and sing-box metadata must exist")
    if not 1 <= arguments.version_code <= 2_100_000_000:
        raise RuntimeError("--version-code must be between 1 and 2100000000")
    if VERSION_NAME_PATTERN.fullmatch(arguments.version_name) is None:
        raise RuntimeError("--version-name is not URL-safe")
    if TARGET_PATTERN.fullmatch(arguments.target) is None:
        raise RuntimeError("--target is invalid")
    if TARGET_PATTERN.fullmatch(arguments.platform_label) is None:
        raise RuntimeError("--platform-label is invalid")
    if COMMIT_PATTERN.fullmatch(arguments.git_commit) is None:
        raise RuntimeError("--git-commit must be a full hexadecimal Git commit")
    if arguments.source_date_epoch < 315532800:
        raise RuntimeError("--source-date-epoch must be on or after 1980-01-01")


def validate_stage_contents(stage: Path, target: str) -> None:
    application_name = "topnode.exe" if "windows-msvc" in target else "topnode-desktop"
    core_name = "sing-box.exe" if "windows-msvc" in target else "sing-box"
    required_files = (application_name, f"runtime/core/{core_name}", *REQUIRED_STAGE_FILES)
    missing_files = [name for name in required_files if not (stage / name).is_file()]
    if missing_files:
        raise RuntimeError(f"stage is missing required package files: {', '.join(missing_files)}")
    text_files = sorted(
        path.relative_to(stage).as_posix()
        for path in stage.rglob("*.txt")
        if path.is_file()
    )
    if text_files:
        raise RuntimeError(f"stage contains forbidden text files: {', '.join(text_files)}")


def copy_stage(stage: Path, root: Path, target: str, version_name: str, version_code: int) -> Path | None:
    if "apple-darwin" not in target:
        shutil.copytree(stage, root)
        return None

    root.mkdir(parents=True)
    app = root / "TOPNODE Desktop.app"
    macos = app / "Contents" / "MacOS"
    macos.mkdir(parents=True)
    shutil.copy2(stage / "topnode-desktop", macos / "topnode-desktop")
    shutil.copytree(stage / "runtime", macos / "runtime")
    for source in sorted(stage.iterdir()):
        if source.name in {"topnode-desktop", "runtime"}:
            continue
        if source.is_file():
            shutil.copy2(source, root / source.name)
    short_version = version_name.split("-", maxsplit=1)[0]
    info = {
        "CFBundleDevelopmentRegion": "zh_CN",
        "CFBundleDisplayName": "TOPNODE Desktop",
        "CFBundleExecutable": "topnode-desktop",
        "CFBundleIdentifier": "cc.topnode.desktop",
        "CFBundleInfoDictionaryVersion": "6.0",
        "CFBundleName": "TOPNODE Desktop",
        "CFBundlePackageType": "APPL",
        "CFBundleShortVersionString": short_version,
        "CFBundleVersion": str(version_code),
        "LSMinimumSystemVersion": "11.0",
        "NSHighResolutionCapable": True,
    }
    with (app / "Contents" / "Info.plist").open("wb") as output:
        plistlib.dump(info, output, sort_keys=True)
    subprocess.run(
        ["codesign", "--force", "--deep", "--sign", "-", str(app)],
        check=True,
        timeout=60,
    )
    return app


def payload_hashes(root: Path) -> list[dict[str, object]]:
    hashes = []
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.name != "BUILD-INFO.json":
            hashes.append(
                {
                    "path": path.relative_to(root).as_posix(),
                    "size": path.stat().st_size,
                    "sha256": sha256_file(path),
                }
            )
    return hashes


def normalized_mode(path: Path) -> int:
    return 0o755 if path.is_dir() or path.stat().st_mode & stat.S_IXUSR else 0o644


def create_zip(root: Path, archive: Path, epoch: int) -> None:
    timestamp = datetime.fromtimestamp(epoch, timezone.utc)
    zip_time = (timestamp.year, timestamp.month, timestamp.day, timestamp.hour, timestamp.minute, timestamp.second)
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as bundle:
        for path in sorted(item for item in root.rglob("*") if item.is_file()):
            relative = Path(root.name) / path.relative_to(root)
            info = zipfile.ZipInfo(relative.as_posix(), date_time=zip_time)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = normalized_mode(path) << 16
            with path.open("rb") as source, bundle.open(info, "w") as target:
                shutil.copyfileobj(source, target)


def create_tar_gz(root: Path, archive: Path, epoch: int) -> None:
    with archive.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=epoch, compresslevel=9) as compressed:
            with tarfile.open(fileobj=compressed, mode="w") as bundle:
                paths = [root, *sorted(root.rglob("*"))]
                for path in paths:
                    relative = Path(root.name) if path == root else Path(root.name) / path.relative_to(root)
                    info = bundle.gettarinfo(str(path), arcname=relative.as_posix())
                    info.uid = 0
                    info.gid = 0
                    info.uname = ""
                    info.gname = ""
                    info.mtime = epoch
                    info.mode = normalized_mode(path)
                    if path.is_file():
                        with path.open("rb") as source:
                            bundle.addfile(info, source)
                    else:
                        bundle.addfile(info)


def main() -> None:
    arguments = parse_arguments()
    validate_arguments(arguments)
    stage = arguments.stage.resolve()
    output = arguments.output.resolve()
    validate_stage_contents(stage, arguments.target)
    output.mkdir(parents=True, exist_ok=True)
    extension = ".zip" if "windows-msvc" in arguments.target else ".tar.gz"
    archive_stem = f"topnode-desktop-{arguments.version_name}-{arguments.platform_label}"
    archive = output / f"{archive_stem}{extension}"
    if archive.exists():
        raise RuntimeError(f"refusing to overwrite existing archive: {archive}")

    sing_box = json.loads(arguments.sing_box_metadata.read_text(encoding="utf-8"))
    with tempfile.TemporaryDirectory(prefix="topnode-portable-") as temporary:
        root = Path(temporary) / archive_stem
        copy_stage(stage, root, arguments.target, arguments.version_name, arguments.version_code)
        build_time = datetime.fromtimestamp(arguments.source_date_epoch, timezone.utc).isoformat()
        manifest = {
            "schemaVersion": 1,
            "application": {
                "versionCode": arguments.version_code,
                "versionName": arguments.version_name,
                "gitCommit": arguments.git_commit,
                "target": arguments.target,
                "supportTier": "supported" if "windows-msvc" in arguments.target else "preview",
            },
            "build": {
                "sourceDateEpoch": arguments.source_date_epoch,
                "sourceDate": build_time,
                "rustc": subprocess.check_output(["rustc", "-vV"], text=True, timeout=15).strip(),
                "cargoProfile": "release",
                "rustFlags": os.environ.get("RUSTFLAGS", ""),
                "cargoLockSha256": sha256_file(arguments.cargo_lock),
            },
            "singBox": sing_box,
            "payload": payload_hashes(root),
        }
        (root / "BUILD-INFO.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        if extension == ".zip":
            create_zip(root, archive, arguments.source_date_epoch)
        else:
            create_tar_gz(root, archive, arguments.source_date_epoch)

    result = {"archive": str(archive), "sha256": sha256_file(archive)}
    print(json.dumps(result))


if __name__ == "__main__":
    main()
