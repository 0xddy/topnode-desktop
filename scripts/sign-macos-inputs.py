#!/usr/bin/env python3
"""Sign native inputs before qualification; never reuse a pre-signing report."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core-build", type=Path, required=True)
    parser.add_argument("--support-build", type=Path, required=True)
    parser.add_argument("--application", type=Path, required=True)
    parser.add_argument("--identity", required=True)
    args = parser.parse_args()
    if platform.system() != "Darwin":
        parser.error("Developer ID signing requires macOS")
    core = args.core_build / "core/sing-box-acp"
    report = core.parent / "naive-validation.json"
    if report.exists():
        parser.error("sign a fresh build before running native qualification")
    metadata_path = args.core_build / "source.json"
    metadata = json.loads(metadata_path.read_text())
    inputs = [(core, "cc.topnode.core"), (args.application, "cc.topnode.desktop")]
    inputs += [(args.support_build / f"topnode-network-{name}", f"cc.topnode.network.{name}") for name in ("daemon", "bridge")]
    inputs += [(args.support_build / "topnode-proxy-settings", "cc.topnode.proxy-settings")]
    inputs += [(core.parent / library["file"], "cc.topnode.core.dependency") for library in metadata["libraries"]]
    for executable, identifier in inputs:
        subprocess.run(["codesign", "--force", "--options", "runtime", "--timestamp", "--sign", args.identity,
                        "--identifier", identifier, str(executable)], check=True, timeout=120)
        subprocess.run(["codesign", "--verify", "--strict", str(executable)], check=True, timeout=30)
    def digest(path):
        with path.open("rb") as stream:
            return hashlib.file_digest(stream, "sha256").hexdigest()
    metadata["binarySha256"] = digest(core)
    for library in metadata["libraries"]:
        library["sha256"] = digest(core.parent / library["file"])
    metadata["signedInputs"] = True
    metadata_path.write_text(json.dumps(metadata, indent=2) + "\n")
    print("Signed inputs. Run native qualification on these exact files before packaging.")


if __name__ == "__main__":
    main()
