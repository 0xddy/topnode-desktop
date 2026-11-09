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

from naive_qualification import validate_report


VERSION_NAME_PATTERN = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._-]{0,63}$")
TARGET_PATTERN = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._-]{0,63}$")
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40,64}$")
ROOT = Path(__file__).resolve().parents[1]


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--application", required=True, type=Path)
    parser.add_argument("--core-build", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--cargo-lock", required=True, type=Path)
    parser.add_argument("--target", required=True)
    parser.add_argument("--platform-label", required=True)
    parser.add_argument("--version-code", required=True, type=int)
    parser.add_argument("--version-name", required=True)
    parser.add_argument("--git-commit", required=True)
    parser.add_argument("--source-date-epoch", required=True, type=int)
    parser.add_argument("--support-build", type=Path, help="native platform helper executables")
    parser.add_argument("--candidate", action="store_true", help="produce an explicitly unqualified candidate")
    parser.add_argument("--system-acceptance", type=Path, help="artifact-bound installed-system test report")
    parser.add_argument("--signing-identity", help="Developer ID Application identity for the final macOS bundle")
    return parser.parse_args()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def validate_arguments(arguments: argparse.Namespace) -> None:
    if not arguments.application.is_file() or not arguments.cargo_lock.is_file():
        raise RuntimeError("the built desktop executable and Cargo.lock must exist")
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


def validate_core_build(build: Path, target: str, candidate: bool = False) -> tuple[Path, dict]:
    lock = dict(line.split("=", 1) for line in (ROOT / "config/sing-box-acp.lock").read_text().splitlines())
    metadata = json.loads((build / "source.json").read_text(encoding="utf-8"))
    expected = {
        "repository": lock["repository"],
        "commit": lock["commit"],
        "version": lock["version"],
        "goVersion": lock["go"],
        "target": target,
    }
    if any(metadata.get(key) != value for key, value in expected.items()):
        raise RuntimeError("ACP core metadata does not match the lock and native release target")
    if not candidate and metadata.get("nativeCheck") is not True:
        raise RuntimeError("release requires native execution on the target architecture")
    binary = build / "core" / ("sing-box-acp.exe" if "windows-msvc" in target else "sing-box-acp")
    if sha256_file(binary) != metadata.get("binarySha256"):
        raise RuntimeError("ACP core binary does not match its build metadata")
    if "with_naive_outbound" not in metadata.get("tags", []):
        raise RuntimeError("complete Naive releases require a qualified Naive core")
    if not candidate or (binary.parent / "naive-validation.json").exists():
        validate_report(binary, metadata, complete=not candidate)
    required_library = {"windows": "libcronet.dll", "linux": "libcronet.so"}.get(metadata.get("goos"))
    if required_library and not any(item.get("file") == required_library for item in metadata.get("libraries", [])):
        raise RuntimeError("Naive candidate is missing its required Cronet library")
    for library in metadata.get("libraries", []):
        name = library["file"]
        if not name or name.startswith(".") or any(char in name for char in "/\\:"):
            raise RuntimeError("invalid bundled library filename")
        if sha256_file(binary.parent / name) != library["sha256"]:
            raise RuntimeError("bundled library hash mismatch")
    return binary, metadata


def assemble_payload(root: Path, arguments: argparse.Namespace, binary: Path) -> None:
    target = arguments.target
    app = root / "TOPNODE Desktop.app"
    is_macos = "apple-darwin" in target
    executable_dir = app / "Contents" / "MacOS" if is_macos else root
    core_dir = executable_dir / "runtime" / "core"
    core_dir.mkdir(parents=True)
    application_name = "topnode.exe" if "windows-msvc" in target else "topnode-desktop"
    shutil.copy2(arguments.application, executable_dir / application_name)
    shutil.copy2(binary, core_dir / binary.name)
    metadata = json.loads((arguments.core_build / "source.json").read_text(encoding="utf-8"))
    for library in metadata.get("libraries", []):
        shutil.copy2(binary.parent / library["file"], core_dir / library["file"])
    if (binary.parent / "naive-validation.json").exists():
        shutil.copy2(binary.parent / "naive-validation.json", core_dir / "naive-validation.json")
    shutil.copy2(arguments.core_build / "source.json", core_dir / "source.json")
    if "linux" in target or is_macos:
        if arguments.support_build is None:
            raise RuntimeError("platform helpers are required for the installed product")
        names = ("topnode-network-daemon", "topnode-network-bridge", "topnode-proxy-settings") if is_macos else ("topnode-net-helper",)
        for name in names:
            shutil.copy2(arguments.support_build / name, executable_dir / name)
    shutil.copy2(ROOT / "config/startup.json", executable_dir / "runtime/startup.json")
    shutil.copy2(ROOT / "THIRD_PARTY_NOTICES.md", root)
    shutil.copy2(ROOT / "docs/PORTABLE-README.txt", root / "README.txt")
    shutil.copy2(arguments.core_build / "LICENSE.sing-box-acp", root)
    if not is_macos:
        return

    short_version = arguments.version_name.split("-", maxsplit=1)[0]
    info = {
        "CFBundleDevelopmentRegion": "zh_CN",
        "CFBundleDisplayName": "TOPNODE Desktop",
        "CFBundleExecutable": "topnode-desktop",
        "CFBundleIdentifier": "cc.topnode.desktop",
        "CFBundleInfoDictionaryVersion": "6.0",
        "CFBundleName": "TOPNODE Desktop",
        "CFBundlePackageType": "APPL",
        "CFBundleShortVersionString": short_version,
        "CFBundleVersion": str(arguments.version_code),
        "LSMinimumSystemVersion": "13.0",
        "NSHighResolutionCapable": True,
    }
    with (app / "Contents" / "Info.plist").open("wb") as output:
        plistlib.dump(info, output, sort_keys=True)
    daemon_directory = app / "Contents/Library/LaunchDaemons"
    daemon_directory.mkdir(parents=True)
    shutil.copy2(ROOT / "platform/macos/cc.topnode.network.plist", daemon_directory)
    if not arguments.signing_identity and not arguments.candidate:
        raise RuntimeError("macOS release requires Developer ID signing")
    if arguments.signing_identity:
        # Core and helpers must already be signed before their native tests.
        # Signing the outer bundle must not rewrite the qualified nested code.
        for nested in [core_dir / binary.name, *(executable_dir / name for name in names)]:
            subprocess.run(["codesign", "--verify", "--strict", str(nested)], check=True, timeout=30)
        subprocess.run(["codesign", "--force", "--options", "runtime", "--timestamp", "--sign", arguments.signing_identity, str(app)], check=True, timeout=60)


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


def validate_system_acceptance(arguments, binary):
    if arguments.system_acceptance is None:
        raise RuntimeError("release requires an installed-system acceptance report; use --candidate until qualified")
    report = json.loads(arguments.system_acceptance.read_text(encoding="utf-8"))
    expected = {"schema_version": 1, "target": arguments.target,
                "application_sha256": sha256_file(arguments.application), "core_sha256": sha256_file(binary)}
    if any(report.get(key) != value for key, value in expected.items()):
        raise RuntimeError("system acceptance does not match the candidate artifacts")
    names = ("topnode-network-daemon", "topnode-network-bridge", "topnode-proxy-settings") if "apple-darwin" in arguments.target else (("topnode-net-helper",) if "linux" in arguments.target else ())
    expected_helpers = {name: sha256_file(arguments.support_build / name) for name in names}
    if report.get("helpers", {}) != expected_helpers:
        raise RuntimeError("system acceptance does not match platform helper artifacts")
    checks = ("system_proxy", "tun_udp", "udp_disabled", "dns_detour", "permission_denied",
              "process_exit_cleanup", "external_proxy_change", "network_switch", "sleep_wake", "upgrade", "uninstall")
    if any(report.get("checks", {}).get(check) is not True for check in checks):
        raise RuntimeError("system takeover acceptance matrix is incomplete")
    if report.get("soak_seconds", 0) < 3600 or report.get("mixed_traffic_seconds", 0) < 1800 or report.get("connection_cycles", 0) < 100:
        raise RuntimeError("stability acceptance is incomplete")
    if "apple-darwin" in arguments.target and report.get("notarized_install") is not True:
        raise RuntimeError("macOS requires notarized installed-system acceptance")


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
    output = arguments.output.resolve()
    binary, sing_box = validate_core_build(arguments.core_build, arguments.target, arguments.candidate)
    if not arguments.candidate:
        validate_system_acceptance(arguments, binary)
    output.mkdir(parents=True, exist_ok=True)
    extension = ".zip" if "windows-msvc" in arguments.target else ".tar.gz"
    archive_stem = f"topnode-desktop-{arguments.version_name}-{arguments.platform_label}"
    archive = output / f"{archive_stem}{extension}"
    if archive.exists():
        raise RuntimeError(f"refusing to overwrite existing archive: {archive}")

    with tempfile.TemporaryDirectory(prefix="topnode-portable-") as temporary:
        root = Path(temporary) / archive_stem
        assemble_payload(root, arguments, binary)
        build_time = datetime.fromtimestamp(arguments.source_date_epoch, timezone.utc).isoformat()
        manifest = {
            "schemaVersion": 1,
            "application": {
                "versionCode": arguments.version_code,
                "versionName": arguments.version_name,
                "gitCommit": arguments.git_commit,
                "target": arguments.target,
                "supportTier": "candidate" if arguments.candidate else "supported",
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
