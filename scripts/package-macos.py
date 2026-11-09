#!/usr/bin/env python3
"""Create a root-owned signed macOS installer from an assembled signed app."""
import argparse
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--version", required=True, type=int)
    parser.add_argument("--installer-identity", required=True)
    parser.add_argument("--notary-profile", help="existing notarytool keychain profile; submission only when supplied")
    args = parser.parse_args()
    if platform.system() != "Darwin" or args.app.name != "TOPNODE Desktop.app" or args.version < 1:
        parser.error("requires macOS, the assembled TOPNODE Desktop.app, and a positive version")
    if args.output.exists():
        parser.error("refusing to overwrite an installer")
    subprocess.run(["codesign", "--verify", "--deep", "--strict", str(args.app)], check=True)
    with tempfile.TemporaryDirectory(prefix="topnode-pkg-") as temporary:
        root = Path(temporary)
        applications = root / "payload/Applications"
        applications.mkdir(parents=True)
        shutil.copytree(args.app, applications / args.app.name)
        scripts = root / "scripts"
        scripts.mkdir()
        # Stop the user process first so its proxy lease is restored. Refuse to
        # replace a running application instead of deleting its cleanup tools.
        (scripts / "preinstall").write_text("""#!/bin/sh
set -eu
/usr/bin/pkill -TERM -f '^/Applications/TOPNODE Desktop.app/Contents/MacOS/topnode-desktop( |$)' || true
count=0
while /usr/bin/pgrep -f '^/Applications/TOPNODE Desktop.app/Contents/MacOS/topnode-desktop( |$)' >/dev/null; do
 count=$((count + 1))
 if [ "$count" -ge 15 ]; then echo 'Close TOPNODE before upgrading.' >&2; exit 1; fi
 sleep 1
done
# Unload the old root session before replacement; the GUI registers the new
# SMAppService on the next explicit TUN authorization.
/bin/launchctl bootout system/cc.topnode.network 2>/dev/null || true
""", encoding="utf-8")
        (scripts / "preinstall").chmod(0o755)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["pkgbuild", "--root", str(root / "payload"), "--ownership", "recommended", "--scripts", str(scripts),
                        "--identifier", "cc.topnode.desktop", "--version", str(args.version), "--install-location", "/",
                        "--sign", args.installer_identity, str(args.output)], check=True)
    if args.notary_profile:
        subprocess.run(["xcrun", "notarytool", "submit", str(args.output), "--keychain-profile", args.notary_profile, "--wait"], check=True)
        subprocess.run(["xcrun", "stapler", "staple", str(args.output)], check=True)
        subprocess.run(["xcrun", "stapler", "validate", str(args.output)], check=True)
        subprocess.run(["spctl", "--assess", "--type", "install", str(args.output)], check=True)
    print("Installer created; installed-system acceptance is still required.")


if __name__ == "__main__":
    main()
