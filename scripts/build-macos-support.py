#!/usr/bin/env python3
"""Build macOS proxy helpers and the version-gated SMAppService executables."""
import argparse
from pathlib import Path
import platform
import subprocess
import tempfile

from macos_compatibility import DEPLOYMENT_TARGETS, verify_binary

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, choices=("x86_64-apple-darwin", "aarch64-apple-darwin"))
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if platform.system() != "Darwin":
        raise RuntimeError("macOS support binaries require Xcode on macOS")
    args.output.mkdir(parents=True, exist_ok=True)
    architecture = "arm64" if args.target.startswith("aarch64") else "x86_64"
    lock = dict(line.split("=", 1) for line in (ROOT / "config/sing-box-acp.lock").read_text().splitlines())
    source = ROOT / "platform/macos"
    with tempfile.TemporaryDirectory(prefix="topnode-macos-") as temporary:
        constants = Path(temporary) / "CoreLock.swift"
        constants.write_text(f'enum CoreLock {{ static let commit = "{lock["commit"]}"; static let version = "{lock["version"]}" }}\n')
        minimum = DEPLOYMENT_TARGETS[args.target]
        common = ["xcrun", "swiftc", "-O", "-swift-version", "5", "-target", f"{architecture}-apple-macos{minimum}"]
        subprocess.run([*common, "-framework", "SystemConfiguration", "-framework", "Security",
                        source / "ProxySettings.swift", "-o", args.output / "topnode-proxy-settings"], check=True)
        for component, name in (("NetworkDaemon.swift", "daemon"), ("NetworkBridge.swift", "bridge")):
            extra = [source / "LegacyService.swift"] if name == "bridge" else []
            subprocess.run([*common, "-framework", "ServiceManagement", "-framework", "Security",
                            source / "NetworkShared.swift", source / component, constants, *extra,
                            "-o", args.output / f"topnode-network-{name}"], check=True)
    for name in ("topnode-proxy-settings", "topnode-network-daemon", "topnode-network-bridge"):
        verify_binary(args.output / name, args.target)


if __name__ == "__main__":
    main()
