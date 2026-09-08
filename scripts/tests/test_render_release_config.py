"""Regression coverage for publishing updates to a deployment-owned config."""

from __future__ import annotations

import argparse
import copy
import importlib.util
import json
from pathlib import Path
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[2]
MODULE_SPEC = importlib.util.spec_from_file_location(
    "render_release_config", PROJECT_ROOT / "scripts" / "render-release-config.py"
)
assert MODULE_SPEC is not None and MODULE_SPEC.loader is not None
renderer = importlib.util.module_from_spec(MODULE_SPEC)
MODULE_SPEC.loader.exec_module(renderer)

VERSION_NAME = "2026.09.08-a1b2c3d4"
DUFS_ROOT = f"https://soft.topstatic.top/soft/desktop/{VERSION_NAME}"
EXPECTED_PACKAGES = {
    "x86_64-pc-windows-msvc": ("windows-x86_64.zip", "application/zip"),
    "aarch64-pc-windows-msvc": ("windows-aarch64.zip", "application/zip"),
    "x86_64-unknown-linux-gnu": ("linux-x86_64.tar.gz", "application/gzip"),
    "aarch64-unknown-linux-gnu": ("linux-aarch64.tar.gz", "application/gzip"),
    "x86_64-apple-darwin": ("macos-x86_64.tar.gz", "application/gzip"),
    "aarch64-apple-darwin": ("macos-aarch64.tar.gz", "application/gzip"),
}


def arguments(**overrides: object) -> argparse.Namespace:
    values = {
        "download_base_url": DUFS_ROOT,
        "repository": None,
        "tag": None,
        "version_code": 100,
        "version_name": VERSION_NAME,
        "update_info": None,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def deployed_configuration() -> dict:
    configuration = json.loads(
        (PROJECT_ROOT / "config" / "desktop-config.json").read_text(encoding="utf-8")
    )
    configuration["baseApiServer"] = ["https://production.example/api"]
    configuration["website"] = "https://website.example/official"
    configuration["apiProbe"]["requestTimeoutMs"] = 45000
    configuration["fake"] = {
        "enable": True,
        "fakeSNI": "production.example",
        "real": ["edge.example"],
    }
    configuration["payment"] = {"presentation": "browser", "customOption": True}
    configuration["deploymentExtension"] = {"region": "asia", "enabled": True}
    configuration["version"]["rollout"] = {"percentage": 25}
    configuration["version"]["metadata"].update(
        versionCode=99,
        versionName="2026.09.07-1234abcd",
        updateInfo="部署方维护的更新说明\n保留换行。",
        forceUpdate=True,
        customMetadata={"channel": "stable", "minimumVersion": 40},
    )
    return configuration


class RenderReleaseConfigurationTests(unittest.TestCase):
    def assert_packages(self, configuration: dict, root: str) -> None:
        downloads = configuration["version"]["downloads"]
        self.assertEqual(set(EXPECTED_PACKAGES), set(downloads))
        for target, (suffix, mime_type) in EXPECTED_PACKAGES.items():
            with self.subTest(target=target):
                filename = f"topnode-desktop-{VERSION_NAME}-{suffix}"
                self.assertEqual(
                    {
                        "downType": "Browser",
                        "url": f"{root}/{filename}",
                        "fileName": filename,
                        "mimeType": mime_type,
                    },
                    downloads[target],
                )

    def test_dufs_downloads_cover_every_platform_and_legacy_fallback(self) -> None:
        for base_url in (DUFS_ROOT, DUFS_ROOT + "/"):
            with self.subTest(base_url=base_url):
                configuration = renderer.render_configuration(
                    deployed_configuration(), arguments(download_base_url=base_url)
                )
                self.assert_packages(configuration, DUFS_ROOT)
                self.assertEqual(
                    {
                        "downType": "Browser",
                        "url": DUFS_ROOT + "/",
                        "fileName": f"topnode-desktop-{VERSION_NAME}",
                        "mimeType": "text/html",
                    },
                    configuration["version"]["download"],
                )

    def test_deployment_settings_and_operator_metadata_are_preserved(self) -> None:
        before = deployed_configuration()
        result = renderer.render_configuration(copy.deepcopy(before), arguments())

        self.assertEqual(
            {key: value for key, value in before.items() if key != "version"},
            {key: value for key, value in result.items() if key != "version"},
        )
        self.assertEqual(before["version"]["rollout"], result["version"]["rollout"])
        expected_metadata = copy.deepcopy(before["version"]["metadata"])
        expected_metadata.update(versionCode=100, versionName=VERSION_NAME)
        self.assertEqual(expected_metadata, result["version"]["metadata"])

    def test_explicit_update_info_changes_only_requested_metadata(self) -> None:
        for supplied, expected in (("  新版本\n修复问题。  ", "新版本\n修复问题。"), ("", "")):
            with self.subTest(update_info=supplied):
                before = deployed_configuration()
                result = renderer.render_configuration(
                    copy.deepcopy(before), arguments(update_info=supplied)
                )
                metadata = copy.deepcopy(before["version"]["metadata"])
                metadata.update(versionCode=100, versionName=VERSION_NAME, updateInfo=expected)
                self.assertEqual(metadata, result["version"]["metadata"])

    def test_retrying_the_same_release_is_idempotent(self) -> None:
        initial = renderer.render_configuration(deployed_configuration(), arguments())
        retried = renderer.render_configuration(copy.deepcopy(initial), arguments())
        self.assertEqual(initial, retried)

    def test_older_release_cannot_replace_current_configuration(self) -> None:
        configuration = deployed_configuration()
        original = copy.deepcopy(configuration)
        with self.assertRaisesRegex(RuntimeError, "newer desktop version"):
            renderer.render_configuration(configuration, arguments(version_code=98))
        self.assertEqual(original, configuration)

    def test_version_code_cannot_be_reused_for_a_different_release(self) -> None:
        configuration = deployed_configuration()
        original = copy.deepcopy(configuration)
        with self.assertRaisesRegex(RuntimeError, "different versionName"):
            renderer.render_configuration(configuration, arguments(version_code=99))
        self.assertEqual(original, configuration)

    def test_rejects_unsafe_download_roots_without_modifying_configuration(self) -> None:
        for base_url in (
            "http://soft.topstatic.top/soft/desktop",
            "https://user@soft.topstatic.top/soft/desktop",
            "https://user:secret@soft.topstatic.top/soft/desktop",
            "https://soft.topstatic.top/soft/desktop?token=example",
            "https://soft.topstatic.top/soft/desktop#fragment",
            "https://soft.topstatic.top/soft/desktop /release",
            "https:///soft/desktop",
        ):
            with self.subTest(base_url=base_url):
                configuration = deployed_configuration()
                original = copy.deepcopy(configuration)
                with self.assertRaisesRegex(RuntimeError, "HTTPS URL"):
                    renderer.render_configuration(
                        configuration, arguments(download_base_url=base_url)
                    )
                self.assertEqual(original, configuration)

    def test_github_release_download_mode_remains_supported(self) -> None:
        repository = "0xddy/topnode-client-desktop"
        tag = f"v{VERSION_NAME}"
        result = renderer.render_configuration(
            deployed_configuration(),
            arguments(download_base_url=None, repository=repository, tag=tag),
        )
        self.assert_packages(result, f"https://github.com/{repository}/releases/download/{tag}")
        self.assertEqual(
            f"https://github.com/{repository}/releases/tag/{tag}",
            result["version"]["download"]["url"],
        )


if __name__ == "__main__":
    unittest.main()
