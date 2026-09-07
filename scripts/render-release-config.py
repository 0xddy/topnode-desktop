#!/usr/bin/env python3
"""Update desktop version fields while preserving deployment configuration."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
from urllib.parse import quote, urlsplit


DOWNLOADS = {
    "x86_64-pc-windows-msvc": ("windows-x86_64", ".zip", "application/zip"),
    "aarch64-pc-windows-msvc": ("windows-aarch64", ".zip", "application/zip"),
    "x86_64-unknown-linux-gnu": ("linux-x86_64", ".tar.gz", "application/gzip"),
    "aarch64-unknown-linux-gnu": ("linux-aarch64", ".tar.gz", "application/gzip"),
    "x86_64-apple-darwin": ("macos-x86_64", ".tar.gz", "application/gzip"),
    "aarch64-apple-darwin": ("macos-aarch64", ".tar.gz", "application/gzip"),
}
VERSION_NAME_PATTERN = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._-]{0,63}$")
REPOSITORY_PATTERN = re.compile(r"^[0-9A-Za-z_.-]+/[0-9A-Za-z_.-]+$")
TAG_PATTERN = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._-]{0,127}$")


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--template", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--repository")
    source.add_argument("--download-base-url")
    parser.add_argument("--tag")
    parser.add_argument("--version-code", required=True, type=int)
    parser.add_argument("--version-name", required=True)
    parser.add_argument("--update-info")
    return parser.parse_args()


def render_configuration(configuration: dict, arguments: argparse.Namespace) -> dict:
    if not 1 <= arguments.version_code <= 2_100_000_000:
        raise RuntimeError("--version-code must be between 1 and 2100000000")
    if VERSION_NAME_PATTERN.fullmatch(arguments.version_name) is None:
        raise RuntimeError("--version-name is invalid")
    if arguments.download_base_url:
        parsed = urlsplit(arguments.download_base_url)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
                or parsed.password is not None or parsed.query or parsed.fragment
                or any(character.isspace() for character in arguments.download_base_url)):
            raise RuntimeError("--download-base-url must be an HTTPS URL without credentials or query")
        direct_root = arguments.download_base_url.rstrip("/")
        release_page = direct_root + "/"
    else:
        if REPOSITORY_PATTERN.fullmatch(arguments.repository or "") is None:
            raise RuntimeError("--repository must use owner/name")
        if TAG_PATTERN.fullmatch(arguments.tag or "") is None:
            raise RuntimeError("--tag is required with --repository and must be URL-safe")
        encoded_tag = quote(arguments.tag, safe="")
        release_root = f"https://github.com/{arguments.repository}/releases"
        release_page = f"{release_root}/tag/{encoded_tag}"
        direct_root = f"{release_root}/download/{encoded_tag}"
    version = configuration["version"]
    metadata = version["metadata"]
    previous_code = metadata["versionCode"]
    if type(previous_code) is not int or previous_code < 1:
        raise RuntimeError("Existing versionCode is invalid")
    if previous_code > arguments.version_code:
        raise RuntimeError("Refusing to replace a newer desktop version")
    if previous_code == arguments.version_code and metadata["versionName"] != arguments.version_name:
        raise RuntimeError("The same versionCode belongs to a different versionName")
    metadata.update(versionCode=arguments.version_code, versionName=arguments.version_name)
    if arguments.update_info is not None:
        metadata["updateInfo"] = arguments.update_info.strip()
    version["download"] = {
        "downType": "Browser",
        "url": release_page,
        "fileName": f"topnode-desktop-{arguments.version_name}",
        "mimeType": "text/html",
    }
    version["downloads"] = {}
    for target, (platform_label, extension, mime_type) in DOWNLOADS.items():
        filename = f"topnode-desktop-{arguments.version_name}-{platform_label}{extension}"
        version["downloads"][target] = {
            "downType": "Browser",
            "url": f"{direct_root}/{filename}",
            "fileName": filename,
            "mimeType": mime_type,
        }
    return configuration


def main() -> None:
    arguments = parse_arguments()
    configuration = render_configuration(
        json.loads(arguments.template.read_text(encoding="utf-8")), arguments
    )
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(
        json.dumps(configuration, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
