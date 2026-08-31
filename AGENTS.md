# TOPNODE Desktop Development Guidelines

These rules apply below client-desktop in addition to the workspace root rules.

## Dependency direction

- domain contains business types and runtime ports. It must not import Slint,
  filesystem, HTTP, keyring, or process APIs.
- application contains use cases and serialization gates. It depends only on
  domain.
- infrastructure implements ports for the OS, Panel, settings, and sidecars.
- apps/desktop is the sole composition root and the only crate that imports
  Slint-generated types.
- Slint callbacks express user intent. They must not block, wait on Tokio, read
  files, make HTTP calls, or launch child processes directly.

## Security boundaries

- Treat the server-provided sing-box JSON as opaque above the runtime adapter.
  Never derive Debug for a type that can print its payload and never log it.
- Resolve sing-box only relative to current_exe. Do not add PATH or current
  working directory fallback.
- Keep credentials out of TOML settings. A future session adapter must use the
  OS credential store and implement single-flight refresh.
- Do not silently rewrite runtime JSON in UI/application code. Any required
  normalization belongs to a versioned engine-boundary transform with tests.

## Verification

Run cargo fmt --all --check, cargo test --workspace, cargo clippy --workspace
--all-targets -- -D warnings, and cargo build -p topnode-desktop after changes.
When changing platform code, check every installed desktop target that can be
compiled from the current host.
