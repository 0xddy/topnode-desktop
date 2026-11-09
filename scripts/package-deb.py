#!/usr/bin/env python3
"""Assemble a root-owned Ubuntu 24.04 package without installing it."""
import argparse
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("portable", ROOT / "scripts/package-portable.py")
portable = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(portable)


def tar_gz(root, epoch):
    data = io.BytesIO()
    with gzip.GzipFile(fileobj=data, mode="wb", mtime=epoch, filename="") as compressed:
        with tarfile.open(fileobj=compressed, mode="w") as archive:
            for file in sorted(root.rglob("*")):
                info = archive.gettarinfo(str(file), arcname="./" + file.relative_to(root).as_posix())
                info.uid = info.gid = 0
                info.uname = info.gname = "root"
                info.mtime = epoch
                info.mode = 0o755 if file.is_dir() or file.name in {"topnode-desktop", "topnode-net-helper", "sing-box-acp", "postinst", "prerm", "postrm"} else 0o644
                if file.is_file():
                    with file.open("rb") as stream:
                        archive.addfile(info, stream)
                else:
                    archive.addfile(info)
    return data.getvalue()


def ar_member(stream, name, data, epoch):
    header = f"{name + '/':<16}{epoch:<12}{0:<6}{0:<6}{'100644':<8}{len(data):<10}`\n".encode("ascii")
    if len(header) != 60:
        raise ValueError("invalid Debian archive header")
    stream.write(header)
    stream.write(data)
    if len(data) % 2:
        stream.write(b"\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--application", type=Path, required=True)
    parser.add_argument("--support-build", type=Path, required=True)
    parser.add_argument("--core-build", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--target", choices=("x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"), required=True)
    parser.add_argument("--version-name", required=True)
    parser.add_argument("--source-date-epoch", type=int, required=True)
    parser.add_argument("--candidate", action="store_true")
    parser.add_argument("--system-acceptance", type=Path)
    args = parser.parse_args()
    if not portable.VERSION_NAME_PATTERN.fullmatch(args.version_name):
        parser.error("invalid version name")
    core, metadata = portable.validate_core_build(args.core_build, args.target, args.candidate)
    if not args.candidate:
        portable.validate_system_acceptance(args, core)
    architecture = "arm64" if args.target.startswith("aarch64") else "amd64"
    with tempfile.TemporaryDirectory(prefix="topnode-deb-") as temporary:
        root = Path(temporary)
        control, data = root / "control", root / "data"
        control.mkdir()
        install = data / "usr/lib/topnode"
        portable.assemble_payload(install, args, core)
        metadata = {"schemaVersion": 1, "supportTier": "candidate" if args.candidate else "supported",
                    "target": args.target, "versionName": args.version_name, "payload": portable.payload_hashes(install)}
        (install / "BUILD-INFO.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
        for source, destination in (("topnode-network.service", "usr/lib/systemd/system"), ("cc.topnode.network.policy", "usr/share/polkit-1/actions")):
            path = data / destination
            path.mkdir(parents=True)
            shutil.copy2(ROOT / "platform/linux" / source, path / source)
        desktop = data / "usr/share/applications"
        desktop.mkdir(parents=True)
        (desktop / "topnode.desktop").write_text("[Desktop Entry]\nType=Application\nName=TOPNODE\nExec=/usr/lib/topnode/topnode-desktop\nTerminal=false\nCategories=Network;\n", encoding="utf-8")
        (control / "control").write_text(f"Package: topnode-desktop\nVersion: {args.version_name}\nArchitecture: {architecture}\nMaintainer: TOPNODE\nDepends: systemd, polkitd, libglib2.0-bin, dconf-cli, libfontconfig1, libxkbcommon0, libgl1\nDescription: TOPNODE desktop client with restricted TUN service\n", encoding="utf-8")
        (control / "postinst").write_text("#!/bin/sh\nset -eu\nif [ -d /run/systemd/system ]; then\n systemctl daemon-reload\n systemctl enable --now topnode-network.service\nfi\n", encoding="utf-8")
        (control / "prerm").write_text("""#!/bin/sh
set -eu
# Ask the GUI to restore its per-user proxy lease before removing executables.
pkill -TERM -f '^/usr/lib/topnode/topnode-desktop( |$)' || true
count=0
while pgrep -f '^/usr/lib/topnode/topnode-desktop( |$)' >/dev/null; do
 count=$((count + 1))
 if [ "$count" -ge 10 ]; then echo 'Close TOPNODE before continuing removal or upgrade.' >&2; exit 1; fi
 sleep 1
done
if [ -d /run/systemd/system ]; then systemctl stop topnode-network.service; fi
""", encoding="utf-8")
        (control / "postrm").write_text("#!/bin/sh\nset -eu\nif [ -d /run/systemd/system ]; then systemctl daemon-reload; fi\n", encoding="utf-8")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("xb") as output:
            output.write(b"!<arch>\n")
            for name, contents in (("debian-binary", b"2.0\n"), ("control.tar.gz", tar_gz(control, args.source_date_epoch)), ("data.tar.gz", tar_gz(data, args.source_date_epoch))):
                ar_member(output, name, contents, args.source_date_epoch)
    print(json.dumps({"package": str(args.output), "sha256": portable.sha256_file(args.output)}))


if __name__ == "__main__":
    main()
