#!/usr/bin/env python3
"""Compile the locked ACP sidecar from a clean checkout."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
LOCK = dict(line.split("=", 1) for line in (ROOT / "config/sing-box-acp.lock").read_text().splitlines())
TARGETS = {
    "x86_64-pc-windows-msvc": ("windows", "amd64"),
    "aarch64-pc-windows-msvc": ("windows", "arm64"),
    "x86_64-unknown-linux-gnu": ("linux", "amd64"),
    "aarch64-unknown-linux-gnu": ("linux", "arm64"),
    "x86_64-apple-darwin": ("darwin", "amd64"),
    "aarch64-apple-darwin": ("darwin", "arm64"),
}
TAGS = "with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_clash_api,badlinkname,tfogo_checklinkname0"
LICENSES = (
    "LICENSE",
    "third_party/mieru-acp/LICENSE",
    "third_party/sing-quic-acp/LICENSE",
    "third_party/sing-vmess-acp/LICENSE",
    "third_party/utls-acp/LICENSE",
)


def git(*args, cwd=None, capture=False):
    return subprocess.run(
        ["git", "-c", "core.autocrlf=false", *args],
        cwd=cwd, check=True, text=True, capture_output=capture,
    ).stdout


def checkout(source, directory):
    if source is not None:
        # Work from committed files only, even if the sibling checkout is dirty.
        git("clone", "--quiet", "--no-tags", "--shared", "--no-checkout", "--", str(source), str(directory))
    else:
        directory.mkdir()
        git("init", "--quiet", cwd=directory)
        fetch = ("fetch", "--quiet", "--no-tags", "--depth=1", LOCK["repository"], LOCK["commit"])
        if os.environ.get("GITHUB_ACTIONS") == "true":
            git(*fetch, cwd=directory)
        else:
            try:
                git("-c", "http.proxy=http://127.0.0.1:10886", *fetch, cwd=directory)
            except subprocess.CalledProcessError:
                git(*fetch, cwd=directory)
    git("checkout", "--quiet", "--detach", LOCK["commit"], cwd=directory)
    if git("rev-parse", "HEAD", cwd=directory, capture=True).strip() != LOCK["commit"]:
        raise RuntimeError("checked-out ACP commit does not match the lock")


def validate_core(binary):
    version = subprocess.check_output([binary, "version"], text=True, timeout=30)
    lines = version.splitlines()
    if not lines or lines[0] != f"sing-box version {LOCK['version']}" or f"Revision: {LOCK['commit']}" not in lines:
        raise RuntimeError("built ACP version does not match the lock")
    for fixture in ("config/sing-box.example.json", "scripts/tests/fixtures/sing-box-acp-protocols.json"):
        subprocess.run(
            [binary, "check", "-c", "stdin"], input=(ROOT / fixture).read_bytes(),
            check=True, timeout=30,
        )
    print(version, end="")


def copy_cronet(source, directory, go_env, goos, goarch):
    module = f"github.com/sagernet/cronet-go/lib/{goos}_{goarch}"
    metadata = subprocess.check_output(
        ["go", "mod", "download", "-json", module], cwd=source, env=go_env, text=True,
    )
    library = Path(json.loads(metadata)["Dir"])
    filename = "libcronet.dll" if goos == "windows" else "libcronet.so"
    # Go's module cache marks files read-only. Copy bytes so Windows builds
    # can replace the staged DLL on subsequent runs.
    shutil.copyfile(library / filename, directory / filename)
    return filename, (library / "LICENSE").read_text(encoding="utf-8").strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, help="use this local ACP Git checkout instead of fetching")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--target", choices=TARGETS, required=True)
    parser.add_argument("--require-native", action="store_true", help="require native execution of the built core")
    parser.add_argument("--with-naive", action="store_true", help="build a Windows/Linux core for Naive testing")
    args = parser.parse_args()
    sibling = ROOT.parent / "third_party/sing-box-acp"
    local_source = args.source or (sibling if sibling.is_dir() else None)
    if local_source is not None:
        local_source = local_source.resolve(strict=True)

    if not re.fullmatch(r"[0-9a-f]{40}", LOCK["commit"]) or not re.fullmatch(
        rf"[0-9]+\.[0-9]+\.[0-9]+-{LOCK['commit'][:9]}", LOCK["version"]
    ):
        raise RuntimeError("invalid ACP commit or version lock")
    go_env = dict(os.environ, GOENV="off", GOWORK="off", GOFLAGS="", GOTOOLCHAIN=f"go{LOCK['go']}")
    goos, goarch = TARGETS[args.target]
    if args.with_naive and goos not in ("windows", "linux"):
        parser.error("--with-naive currently supports Windows and Linux test builds")
    tags = f"{TAGS},with_naive_outbound,with_purego" if args.with_naive else TAGS
    host = subprocess.check_output(["go", "env", "GOHOSTOS", "GOHOSTARCH"], env=go_env, text=True).split()
    native = host == [goos, goarch]
    if args.require_native and not native:
        raise RuntimeError(f"{args.target} requires a native runner; Go host is {'/'.join(host)}")
    binary_name = "sing-box-acp.exe" if goos == "windows" else "sing-box-acp"
    output = args.output.resolve()

    with tempfile.TemporaryDirectory(prefix="topnode-acp-") as temporary:
        directory = Path(temporary)
        source = directory / "src"
        checkout(local_source, source)
        binary = directory / binary_name
        shared_flags = (source / "release/LDFLAGS").read_text().strip()
        flags = f"-X github.com/sagernet/sing-box/constant.Version={LOCK['version']} {shared_flags} -s -w -buildid="
        subprocess.run(
            ["go", "build", "-mod=readonly", "-trimpath", "-buildvcs=true", "-tags", tags,
             "-ldflags", flags, "-o", binary, "./cmd/sing-box"],
            cwd=source, env=dict(go_env, CGO_ENABLED="0", GOOS=goos, GOARCH=goarch), check=True,
        )
        if args.with_naive:
            cronet_name, cronet_license = copy_cronet(source, directory, go_env, goos, goarch)
        if native:
            validate_core(binary)
        core_dir = output / "core"
        core_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(binary, core_dir / binary_name)
        notices = "\n\n".join(
            f"{path}\n{'=' * len(path)}\n{(source / path).read_text(encoding='utf-8').strip()}"
            for path in LICENSES
        )
        if args.with_naive:
            shutil.copyfile(directory / cronet_name, core_dir / cronet_name)
            notices += f"\n\n{cronet_name}\n{'=' * len(cronet_name)}\n{cronet_license}"
        (output / "LICENSE.sing-box-acp").write_text(notices + "\n", encoding="utf-8")
        with binary.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        metadata = {
            "repository": LOCK["repository"],
            "commit": LOCK["commit"],
            "version": LOCK["version"],
            "goVersion": LOCK["go"],
            "goSumSha256": hashlib.sha256((source / "go.sum").read_bytes()).hexdigest(),
            "goos": goos,
            "goarch": goarch,
            "target": args.target,
            "tags": tags.split(","),
            "naiveTest": args.with_naive,
            "nativeCheck": native,
            "binarySha256": digest,
        }
        (output / "source.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    print(f"Built {output / 'core' / binary_name} for {args.target}")


if __name__ == "__main__":
    main()
