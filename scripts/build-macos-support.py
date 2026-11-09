#!/usr/bin/env python3
"""Build the macOS 13 SystemConfiguration and SMAppService executables."""
import argparse
from pathlib import Path
import platform
import subprocess
import tempfile

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
        common = ["xcrun", "swiftc", "-O", "-swift-version", "5", "-target", f"{architecture}-apple-macos13.0"]
        subprocess.run([*common, "-framework", "SystemConfiguration", "-framework", "Security",
                        source / "ProxySettings.swift", "-o", args.output / "topnode-proxy-settings"], check=True)
        for component, name in (("NetworkDaemon.swift", "daemon"), ("NetworkBridge.swift", "bridge")):
            subprocess.run([*common, "-framework", "ServiceManagement", "-framework", "Security",
                            source / "NetworkShared.swift", source / component, constants,
                            "-o", args.output / f"topnode-network-{name}"], check=True)


if __name__ == "__main__":
    main()
