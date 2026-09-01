#!/usr/bin/env sh
set -eu

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
    echo "usage: $0 <sing-box-path> <sing-box-license-path> [rust-target]" >&2
    exit 2
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
core_path=$(CDPATH= cd -- "$(dirname -- "$1")" && pwd)/$(basename -- "$1")
license_path=$(CDPATH= cd -- "$(dirname -- "$2")" && pwd)/$(basename -- "$2")
rust_target=${3-}
expected_core_version=${TOPNODE_SING_BOX_VERSION:-1.13.19}

case "$rust_target" in
    *[!A-Za-z0-9._-]*)
        echo "rust target must contain only letters, digits, dot, underscore, and hyphen" >&2
        exit 2
        ;;
esac

case "$expected_core_version" in
    ''|*[!0-9.]*|.*|*.|*..*)
        echo "TOPNODE_SING_BOX_VERSION must use major.minor.patch" >&2
        exit 2
        ;;
esac
if [ "$(printf '%s' "$expected_core_version" | awk -F. '{ print NF }')" -ne 3 ]; then
    echo "TOPNODE_SING_BOX_VERSION must use major.minor.patch" >&2
    exit 2
fi
export TOPNODE_SING_BOX_VERSION="$expected_core_version"

case "$rust_target" in
    *windows*)
        echo "stage.sh stages native Unix targets only; use stage.ps1 on Windows" >&2
        exit 2
        ;;
esac

if [ -n "$rust_target" ]; then
    cargo build --manifest-path "$project_root/Cargo.toml" --release --locked \
        -p topnode-desktop --target "$rust_target"
    build_root="$project_root/target/$rust_target/release"
    stage="$project_root/dist/$rust_target"
else
    cargo build --manifest-path "$project_root/Cargo.toml" --release --locked \
        -p topnode-desktop
    build_root="$project_root/target/release"
    stage="$project_root/dist/host"
fi

dist_root="$project_root/dist"
case "$stage" in
    "$dist_root"/*) ;;
    *)
        echo "resolved stage directory is outside the project dist directory" >&2
        exit 2
        ;;
esac
rm -rf -- "$stage"
core_stage="$stage/runtime/core"
mkdir -p "$core_stage"
cp "$build_root/topnode-desktop" "$stage/topnode-desktop"
cp "$project_root/config/startup.json" "$stage/runtime/startup.json"
cp "$core_path" "$core_stage/sing-box"
for dependency in "$(dirname -- "$core_path")"/libcronet.*; do
    [ -f "$dependency" ] || continue
    cp "$dependency" "$core_stage/$(basename -- "$dependency")"
done
cp "$license_path" "$stage/LICENSE.sing-box.txt"
cp "$project_root/LICENSE.Sora-OFL-1.1.txt" "$stage/LICENSE.Sora-OFL-1.1.txt"
cp "$project_root/apps/desktop/ui/assets/flags/LICENSE.country-flags-MIT.txt" \
    "$stage/LICENSE.country-flags-MIT.txt"
cp "$project_root/THIRD_PARTY_NOTICES.md" "$stage/THIRD_PARTY_NOTICES.md"
cp "$project_root/docs/PORTABLE-README.txt" "$stage/PORTABLE-README.txt"
chmod 0755 "$stage/topnode-desktop" "$core_stage/sing-box"
version_output=$("$core_stage/sing-box" version 2>&1) || {
    echo "staged sing-box failed its version probe" >&2
    exit 1
}
core_version=$(printf '%s\n' "$version_output" | awk '
    NR == 1 {
        for (field_number = 1; field_number <= NF; field_number++) {
            if ($field_number ~ /^[0-9]+\.[0-9]+\.[0-9]+$/) {
                print $field_number
                exit
            }
        }
    }
')
if [ "$core_version" != "$expected_core_version" ]; then
    echo "expected sing-box $expected_core_version, got: $version_output" >&2
    exit 1
fi
printf '%s\n' "$version_output"

echo "Staged release: $stage"
