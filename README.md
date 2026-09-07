# TOPNODE Desktop

TOPNODE Desktop is a cross-platform Rust + Slint client. The UI is written in
Slint's declarative language with the Fluent widget style; Rust owns account
state, Panel communication, persistence, and the external sing-box process.

The current framework connects the desktop shell to the real Panel and
implements the authenticated resource-to-runtime path, single-instance desktop
lifecycle, a supervised sing-box sidecar, and Windows traffic takeover. The
user-facing **System Proxy mode** is the default: it starts a private Mixed
listener and transactionally points the current user's WinINet proxy at it only
after both the sidecar and listener are ready. **Global mode** is the
user-facing name for the TUN-based capture path.

## What is included

- A Cargo workspace with domain, application, infrastructure, and Slint UI
  boundaries.
- A Fluent desktop shell with session restore, login/logout, account resource
  loading and refresh, server-group and node selection, subscription purchase,
  personal center and software-settings pages.
- An HTTPS Panel client using the real `auth/login`, `auth/refresh`,
  `auth/logout`, `users/me`,
  `users/client/resources`, `users/client/config`, shop-plan, payment-method,
  and order contracts under `/api/v1/`. The cold-start contract below selects
  the logical Panel endpoint and transport route before this client is used;
  the packaged application does not define a production API fallback.
- Rotating-token handling with one automatic refresh and one request replay
  after an authenticated request receives HTTP 401. Refresh is single-flight;
  logout removes the local session before best-effort remote revocation.
- Session persistence as a versioned XChaCha20-Poly1305 envelope under the OS
  application-data directory. A random data-encryption key is stored in the
  platform credential vault; tokens are not written to `settings.toml`.
- The Android connection-preference model: rule/global mode, mainland/LAN
  bypass, TUN (off by default), UDP forwarding, multiplexing, serialized
  connect/stop operations, and generation-scoped cancellation that interrupts
  configuration fetch, core check, stdin delivery, and readiness without
  waiting for their full timeout.
- An Android-equivalent engine-boundary normalizer for the server's opaque rt1
  JSON. It cleans redundant direct detours, applies LAN private rule sets and
  local direct routes, applies the local UDP-disabled rule, and limits local
  multiplex policy changes to generated VLESS endpoint outbounds. In normal
  proxy mode it removes server-selected Mixed/SOCKS listeners and injects one
  client-owned Mixed listener on a random `127.0.0.1` port; TUN mode does not
  create that listener.
- A sing-box sidecar adapter that discovers the binary under the executable's
  fixed `runtime/core` directory, runs version/check/run without a shell,
  drains both output streams, redacts
  credential-like log lines, and observes unexpected exits. The adapter injects
  a random authenticated loopback Clash API, keeps the normalized configuration
  in zeroizing memory, sends the exact same bytes to `check` and `run` over
  standard input, waits for the exact core version, and publishes bounded
  aggregate traffic, connection-count, and memory telemetry.
- A recoverable Windows WinINet proxy lease. It preserves the complete previous
  flags, manual proxy/bypass, PAC, and auto-detection values in a private atomic
  `Prepared`/`Active` journal with a random owner ID. Apply and restore are
  queried back; disconnect and explicit exit restore only when the current
  settings still match TOPNODE's applied snapshot, so another application's
  changes are never overwritten. Startup reconciles a journal left by a crash
  before normal initialization continues.
- A Windows Global-mode permission handoff. Selecting Global mode from Settings
  requests UAC because that mode uses TUN internally. A fixed-argument hidden
  launcher explicitly leaves the old GUI's containment Job before invoking
  UAC, so orderly shutdown of the old process cannot terminate the elevated
  replacement. The authenticated replacement acquires the single-instance
  lock and preflights its controller, window, tray, and activation channel
  before the old window is allowed to close. The enabled preference is written
  only after the commit message; an abort restores the previous settings.
  Cancelling or rejecting UAC keeps System Proxy mode. Connect performs a
  controller permission check and the sidecar repeats it immediately before
  launch.
- An OS-level single-instance lock. A later launch authenticates to a loopback
  activation channel, restores the existing window, and exits before touching
  settings, credentials, runtime files, or the sidecar. A separate handoff lock
  prevents another launch from taking ownership while an authenticated UAC
  replacement is assuming the primary lock.
- A native Slint system tray: closing the window hides it while the sidecar
  remains supervised; explicit tray exit performs orderly shutdown. Windows
  places the GUI and ordinary children in a kill-on-close Job Object; only the
  fixed internal UAC launcher may explicitly break away. Unix and macOS run the
  long-lived core through a hidden mode of the same desktop executable; that
  guardian reclaims the complete process group when its GUI parent dies.
- OS-specific writable data paths, persisted non-secret settings, 4 MiB
  size-rotated app logs (at most seven files and about 32 MiB total), tests,
  staging scripts, and multi-platform CI configuration.

## Current security and networking boundary

The Panel client requires HTTPS, disables redirects and environment/system
proxy discovery, sends per-request IDs, applies connection/request timeouts,
and rejects responses larger than 8 MiB. The cold-start selection described
below never weakens normal WebPKI chain, hostname, validity, or signature
validation. The configuration request contains:

    group_id
    selected_endpoint_id
    route_mode
    bypass_mainland
    bypass_lan
    ipv6=false
    multiplex_enabled
    runtime_id=rt1
    supported_schema_versions=[1]

UDP is intentionally not a Panel request field. Its local policy is applied
only inside the sing-box adapter. Above that boundary, configuration JSON is
opaque and its debug representation is redacted.

On Windows, `Connected` is published only after the validated sidecar answers
the authenticated loopback `/version` probe with the exact core version
compiled into that release (`1.13.19` by default) and the chosen
traffic path is ready. In the default mode that additionally means the random
Mixed listener accepted a loopback connection and the WinINet lease was applied
and read back. In TUN mode it means both privilege gates passed and the checked
TUN configuration reached authenticated sidecar readiness.

A narrowly privileged TUN broker is not implemented yet. The current Windows
TUN handoff restarts the entire GUI as Administrator; this is an explicit
temporary safety tradeoff, not the long-term privilege boundary. Linux and
macOS system-proxy adapters and TUN permission adapters are also not
implemented, so those modes fail closed rather than reporting a
traffic-capturing connection.

## Cold-start bootstrap contract

The bootstrap implementation performs these steps on every cold start.
Bootstrap sources are requested sequentially in this exact order, and
fetching stops at the first structurally valid document:

1. `https://0x10.topboot.top/desktop.config.json`
2. `https://0x11.boot1.top/desktop.config.json`
3. `https://0x12.boot2.top/desktop.config.json`

A transport, HTTP, size, JSON, or schema failure advances to the next source.
Once a valid document is accepted, later bootstrap sources are not consulted.
There is no fixed Panel API fallback and no cached or packaged copy of a remote
bootstrap document to fall back to. If all three sources fail, startup remains
blocked on a visible error window. Retry repeats the complete discovery
sequence from the first source; Exit closes the client, and a later launch also
starts again from the first source.

The accepted document uses the Android bootstrap semantics. All valid HTTPS
entries in `baseApiServer` are probed concurrently with the configured
`apiProbe` policy. A candidate wins as soon as TLS completes and any HTTP
response is received, including a non-2xx response. DNS, connection, TLS, and
timeout failures do not count as connectivity. The first successful candidate
wins and all remaining probes are cancelled. If no candidate wins, the client
does not fall back to a fixed API, a later bootstrap source, or a remote
configuration saved on disk.

Both direct and `fake` fronted candidates are supported. Direct candidates use
the logical `baseApiServer` host for connection routing, TLS identity, and HTTP
authority. For an enabled `fake` route, an exact `real.domain` mapping connects
to its literal `ip`, sends `fakeSNI` in TLS, verifies the certificate against
the logical domain and configured SPKI pin, and keeps the logical domain as the
HTTP authority. Unmatched logical hosts remain direct candidates, and multiple
matching `real` entries are independent concurrent candidates. A host with a
matching `real` entry does not also add a direct candidate. The winning route,
including connection IP, SNI, certificate identity, HTTP authority, and pin
policy, is reused unchanged by the authenticated Panel client.

The Android-shaped `version` object remains structurally required. Desktop
builds use the same Git-derived identity as Android: the complete-history commit
count is `versionCode`, and `YYYY.MM.DD-<8-char-SHA>` is `versionName`. After a
valid bootstrap and API route are selected, a strictly greater remote
`versionCode` opens the exact current-target entry from `version.downloads` in
the default browser. Entries must use `downType=Browser` and HTTPS. Target keys
are restricted to the six published Rust triples; Windows entries must use
ZIP/application-zip and Linux/macOS entries tar.gz/application-gzip. Equality or
a lower code never triggers an update, and a missing target entry only logs a
warning. The legacy singular `version.download` remains required for older
clients but is never used by the desktop updater, preventing the live Android
APK entry from being opened on desktop. `updateInfo` and `forceUpdate` remain
contract-compatible metadata; desktop currently opens the browser and continues
startup rather than implementing a blocking native updater.

`payment.presentation` is an optional presentation-only policy with the values
`qr_code` and `browser`. When present remotely it overrides the packaged
`runtime/startup.json` default; when absent, the local default remains in
effect. It does not define available payment methods. The desktop already
loads those methods after authentication from
`GET /api/v1/users/payment-methods`, matching the Web and Android clients, and
continues to use the returned method ID when creating or paying an order.
Public bootstrap documents must never contain a payment gateway secret,
merchant credential, signing key, or other provider configuration.
The checked-in `config/desktop-config.json` is a schema example for publishing
that remote document; it is not copied into the application distribution and
editing it does not update any live bootstrap domain. The same document,
including `payment.presentation` when a remote override is desired, must be
published independently to the configured HTTPS sources.

## Prerequisites

- Rust 1.92.0, pinned by the checked-in toolchain file.
- A platform build toolchain supported by Slint/winit.
- sing-box 1.13.19 by default, matching client-android. A controlled release
  may set `TOPNODE_SING_BOX_VERSION`; that same exact value is compiled into the
  runtime probe and enforced again by release staging.

Slint and `slint-build` are pinned to 1.17.1. This version supplies the native
cross-platform `SystemTrayIcon` used by the desktop lifecycle.

## Build and test

From this directory:

    cargo fmt --all --check
    cargo test --workspace
    cargo clippy --workspace --all-targets -- -D warnings
    cargo build -p topnode-desktop

When complete Git metadata is available, `apps/desktop/build.rs` derives the
same commit-count/date/SHA version used by Android. Source archives without Git
metadata fall back to version code `1` and the Cargo package version. Controlled
builds can set `TOPNODE_VERSION_CODE`, `TOPNODE_VERSION_NAME`, and
`TOPNODE_GIT_COMMIT`; invalid or shallow automatic version inputs fail closed.

## UI preview

The checked-in preview gallery uses production page components with fixed,
non-sensitive sample data. It lets `slint-viewer` render every customer page
and important state without starting the Panel client or sing-box:

    ./scripts/preview-ui.ps1

The script compiles every `.slint` source with the Fluent style, then writes
the login, connection, node, subscription, purchase, profile, settings, and design-system
screenshots to `target/ui-preview`. To run only the full compile check:

    ./scripts/preview-ui.ps1 -CheckOnly

For interactive inspection with automatic reload:

    slint-viewer --style fluent --auto-reload --component ConnectedPreview apps/desktop/ui/preview/gallery.slint

Other exported preview components include `LoginPreview`,
`LoginErrorPreview`, `HomePreview`, `CoreUnavailablePreview`, `ConnectingPreview`, `NodeSelectorPreview`,
`SubscriptionsPreview`, `PurchasePreview`, `ProfilePreview`, `BalanceDetailsPreview`, `SettingsPreview`,
and `DesignSystemPreview`.

For a development launch, place the platform core files in the workspace
`runtime/core/` staging directory before building. The desktop build script
copies them into the actual executable directory:

- Windows: `target/debug/runtime/core/sing-box.exe`
- Linux/macOS: `target/debug/runtime/core/sing-box`

The application never searches `PATH` or the shell working directory. It
resolves the sidecar as
`current_exe().parent()/runtime/core/sing-box[.exe]`, so shortcuts and app
bundles cannot accidentally select a different executable.

The read-only deployment configuration is loaded from
`current_exe().parent()/runtime/startup.json`. Payment presentation is selected
with `payment.presentation`: `qr_code` (the default when the file or field is
missing) keeps the user in the desktop app and displays a scannable code, while
`browser` opens the payment session in the system default browser. A valid
remote bootstrap document may override only this presentation policy. The
local file is not a Panel API fallback and never stores a remote bootstrap
document or payment-provider credentials.

Packaged release layouts continue to use the explicit staging scripts below.

On first launch, the client creates and persists a stable installation device
ID in non-secret settings, restores an encrypted session when present, and
otherwise shows the login page. After login it fetches resource groups and
nodes; selecting a connectable group and selectable node enables the runtime
configuration request.

`DevelopmentConfigurationSource` and `config/sing-box.example.json` remain in
the repository for isolated adapter tests and manual sidecar development. They
are not wired into the desktop application's default startup path, which uses
the authenticated Panel configuration endpoint.

## Distribution layout

The release directory must contain at least:

    topnode-desktop[.exe]
    runtime/
      startup.json
      core/
        sing-box[.exe]
        libcronet.[dll|so]  # when supplied by the official core archive
    BUILD-INFO.json
    PORTABLE-README.txt
    THIRD_PARTY_NOTICES.md
    LICENSE.Sora-OFL-1.1.txt
    LICENSE.country-flags-MIT.txt
    LICENSE.sing-box.txt

Use `scripts/stage.ps1` on Windows or `scripts/stage.sh` on Unix. Both require
an explicit core binary and GPL license path, copy official `libcronet.*`
companions, and require the staged core to report the exact
`TOPNODE_SING_BOX_VERSION` (default `1.13.19`).

The manual `desktop-portable-release` workflow accepts that sing-box version,
requires the repository default branch and complete Git history, verifies the
exact official SagerNet asset against the SHA-256 digest returned by GitHub,
requires any core build that advertises the relevant pure-Go/Naive features to
include `libcronet.*`, runs the same stdin-based `sing-box check` CLI against a
representative configuration, and builds six native targets: Windows/Linux
x86_64 and ARM64, plus macOS Intel
and Apple Silicon. Windows archives use a static Rust CRT; Unix archives are
tarballs so executable modes survive extraction. Each package contains a build
manifest, and the release contains `SHA256SUMS.txt`. The workflow publishes a
draft only after every matrix build succeeds, uploads all assets, then makes the
Release visible.

The separate `publish` job downloads the saved build artifacts and publishes all
six packages plus checksums to:

    https://soft.topstatic.top/soft/desktop/desktop-v<VERSION_CODE>-<VERSION_NAME>/

It verifies each package by anonymously downloading and comparing its SHA-256
hash, then writes and verifies `SHA256SUMS.txt` as the completion marker. Only
then does it update `desktop.config.json` on `main` in
`0xddy/topnode-bootstrap-config`, using the latest production document as its
input. It updates `version.metadata.versionCode`, `version.metadata.versionName`,
the legacy `version.download` directory link, and all six `version.downloads`
URLs. It preserves `updateInfo`, `forceUpdate`, other metadata, and all unrelated
API/probe/fake/payment settings. Push conflicts cause a fresh fetch and render;
older versions and conflicting reuse of a version code are refused.

After the configuration commit succeeds, cleanup keeps the two latest complete
desktop version directories by numeric `versionCode`. It verifies the current
release again before deleting older managed directories and incomplete uploads.
An interrupted upload does not displace the previous complete version. Files and directories outside
the strict desktop release naming scheme are left alone, including everything
under `/soft/android/`. Upload, verification, or configuration failures stop
before cleanup. The single release concurrency group serializes publication.
The bootstrap repository's existing deployment remains responsible for serving
its configuration at all three boot domains.

Configure these Actions secrets in `0xddy/topnode-desktop`:

- `TOPNODE_DUFS_PASSWORD`: password for dufs user `admin`; the URL and username
  are set in the publish job.
- `BOOTSTRAP_CONFIG_SSH_KEY`: private key of a dedicated SSH Deploy Key with
  write access to `0xddy/topnode-bootstrap-config`. That repository's `main`
  branch must permit the key to push configuration commits.

Builds, GitHub Release publication, and dufs/config publication are separate
jobs. If publication fails, use **Re-run failed jobs** on the same Actions run;
the completed matrix builds are reused. Artifacts are retained for 14 days, so
retry within that period. Re-running a successful publish is safe: the same
version reuses matching completed assets and an unchanged configuration creates
no commit. Different bytes cannot replace an already completed version.
Re-running an older release after a newer version exists is refused.
If a GitHub Release was already published, the release job checks its source
commit and exact asset bytes before allowing the retry to continue.

A core-only rebuild must use a new Git commit because clients compare only
`versionCode`. The verify job renders dufs URLs over the schema fixture, so the
Rust parser used at startup must accept the release document before any
platform build begins. Release helper tests run in CI and can be run locally
with `python -m unittest discover -s scripts/tests -v`.

Windows is currently the complete traffic-routing target. Linux and macOS
archives are explicit previews: the UI starts, but their system-proxy and TUN
adapters still fail closed. Linux also requires common glibc/Fontconfig/XKB and
Secret Service libraries. The macOS workflow creates an ad-hoc-signed `.app`,
but production still needs Developer ID signing/notarization; Windows production
should add Authenticode signing to avoid SmartScreen warnings.

The checked-in workflow assumes `client-desktop` is the Git repository root.
If this directory remains inside an umbrella repository, place the workflow in
that repository's root `.github/workflows` directory and set its Cargo working
directory to `client-desktop`.

See `docs/architecture.md` for design boundaries and
`docs/security-and-packaging.md` before changing bootstrap/fronted routing,
extending traffic takeover or privilege boundaries, updates, or release
packaging.
